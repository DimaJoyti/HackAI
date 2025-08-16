package providers

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var managerTracer = otel.Tracer("hackai/llm/providers/manager")

// DefaultProviderManager implements ProviderManager interface
type DefaultProviderManager struct {
	providers map[string]LLMProvider
	configs   map[string]ProviderConfig
	stats     map[string]*ProviderMetrics
	logger    *logger.Logger
	mutex     sync.RWMutex
	running   bool
	stopChan  chan struct{}

	// Load balancing
	loadBalancer LoadBalancer

	// Circuit breaker
	circuitBreakers map[string]*CircuitBreaker
}

// ProviderMetrics tracks provider performance metrics
type ProviderMetrics struct {
	TotalRequests   int64         `json:"total_requests"`
	SuccessfulReqs  int64         `json:"successful_requests"`
	FailedRequests  int64         `json:"failed_requests"`
	AverageLatency  time.Duration `json:"average_latency"`
	LastRequestTime time.Time     `json:"last_request_time"`
	ErrorRate       float64       `json:"error_rate"`
	TokensProcessed int64         `json:"tokens_processed"`

	// Rate limiting
	RequestsThisMinute int64     `json:"requests_this_minute"`
	TokensThisMinute   int64     `json:"tokens_this_minute"`
	LastMinuteReset    time.Time `json:"last_minute_reset"`

	// Health
	IsHealthy         bool      `json:"is_healthy"`
	LastHealthCheck   time.Time `json:"last_health_check"`
	ConsecutiveErrors int       `json:"consecutive_errors"`
}

// LoadBalancer defines load balancing strategies
type LoadBalancer interface {
	SelectProvider(providers []LLMProvider, request GenerationRequest) (LLMProvider, error)
}

// CircuitBreaker implements circuit breaker pattern for providers
type CircuitBreaker struct {
	failureThreshold int
	resetTimeout     time.Duration
	state            CircuitState
	failures         int
	lastFailureTime  time.Time
	mutex            sync.RWMutex
}

// CircuitState represents circuit breaker states
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// NewDefaultProviderManager creates a new provider manager
func NewDefaultProviderManager(logger *logger.Logger) *DefaultProviderManager {
	return &DefaultProviderManager{
		providers:       make(map[string]LLMProvider),
		configs:         make(map[string]ProviderConfig),
		stats:           make(map[string]*ProviderMetrics),
		logger:          logger,
		stopChan:        make(chan struct{}),
		loadBalancer:    NewRoundRobinBalancer(),
		circuitBreakers: make(map[string]*CircuitBreaker),
	}
}

// RegisterProvider registers a new LLM provider
func (pm *DefaultProviderManager) RegisterProvider(name string, provider LLMProvider) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Validate provider
	if err := provider.Health(context.Background()); err != nil {
		return fmt.Errorf("provider health check failed: %w", err)
	}

	pm.providers[name] = provider
	pm.stats[name] = &ProviderMetrics{
		IsHealthy:       true,
		LastHealthCheck: time.Now(),
	}

	// Initialize circuit breaker
	pm.circuitBreakers[name] = NewCircuitBreaker(5, 30*time.Second)

	pm.logger.Info("Provider registered successfully",
		"name", name,
		"type", provider.GetType(),
		"model", provider.GetModel().Name,
	)

	return nil
}

// UnregisterProvider removes a provider
func (pm *DefaultProviderManager) UnregisterProvider(name string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	provider, exists := pm.providers[name]
	if !exists {
		return fmt.Errorf("provider %s not found", name)
	}

	// Close provider connection
	if err := provider.Close(); err != nil {
		pm.logger.Warn("Error closing provider", "name", name, "error", err)
	}

	delete(pm.providers, name)
	delete(pm.configs, name)
	delete(pm.stats, name)
	delete(pm.circuitBreakers, name)

	pm.logger.Info("Provider unregistered", "name", name)
	return nil
}

// GetProvider returns a specific provider
func (pm *DefaultProviderManager) GetProvider(name string) (LLMProvider, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	provider, exists := pm.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", name)
	}

	// Check circuit breaker
	cb := pm.circuitBreakers[name]
	if cb != nil && !cb.CanExecute() {
		return nil, fmt.Errorf("provider %s circuit breaker is open", name)
	}

	return provider, nil
}

// ListProviders returns all registered provider names
func (pm *DefaultProviderManager) ListProviders() []string {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	names := make([]string, 0, len(pm.providers))
	for name := range pm.providers {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// GetBestProvider selects the best provider for a request
func (pm *DefaultProviderManager) GetBestProvider(ctx context.Context, request GenerationRequest) (LLMProvider, error) {
	ctx, span := managerTracer.Start(ctx, "provider_manager.get_best_provider")
	defer span.End()

	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	// Get healthy providers
	healthyProviders := make([]LLMProvider, 0)
	for name, provider := range pm.providers {
		stats := pm.stats[name]
		cb := pm.circuitBreakers[name]

		if stats.IsHealthy && cb.CanExecute() {
			// Check rate limits
			if pm.isWithinRateLimits(name, 1) {
				healthyProviders = append(healthyProviders, provider)
			}
		}
	}

	if len(healthyProviders) == 0 {
		return nil, fmt.Errorf("no healthy providers available")
	}

	// Use load balancer to select provider
	provider, err := pm.loadBalancer.SelectProvider(healthyProviders, request)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("load balancer failed: %w", err)
	}

	span.SetAttributes(
		attribute.String("selected_provider", string(provider.GetType())),
		attribute.Int("healthy_providers", len(healthyProviders)),
	)

	return provider, nil
}

// RouteRequest routes a request to the best available provider
func (pm *DefaultProviderManager) RouteRequest(ctx context.Context, request GenerationRequest) (GenerationResponse, error) {
	ctx, span := managerTracer.Start(ctx, "provider_manager.route_request")
	defer span.End()

	provider, err := pm.GetBestProvider(ctx, request)
	if err != nil {
		span.RecordError(err)
		return GenerationResponse{}, err
	}

	// Find provider name for stats tracking
	var providerName string
	pm.mutex.RLock()
	for name, p := range pm.providers {
		if p == provider {
			providerName = name
			break
		}
	}
	pm.mutex.RUnlock()

	// Execute request with stats tracking
	startTime := time.Now()
	response, err := pm.executeWithStats(ctx, provider, providerName, request)

	span.SetAttributes(
		attribute.String("provider_name", providerName),
		attribute.String("duration", time.Since(startTime).String()),
		attribute.Bool("success", err == nil),
	)

	return response, err
}

// executeWithStats executes a request and updates provider statistics
func (pm *DefaultProviderManager) executeWithStats(ctx context.Context, provider LLMProvider, providerName string, request GenerationRequest) (GenerationResponse, error) {
	startTime := time.Now()

	// Update request count
	pm.updateRequestStats(providerName, true)

	// Execute request
	response, err := provider.Generate(ctx, request)

	// Update completion stats
	duration := time.Since(startTime)
	success := err == nil

	pm.updateCompletionStats(providerName, duration, success, response.TokensUsed.TotalTokens)

	// Update circuit breaker
	cb := pm.circuitBreakers[providerName]
	if cb != nil {
		if success {
			cb.RecordSuccess()
		} else {
			cb.RecordFailure()
		}
	}

	return response, err
}

// updateRequestStats updates request statistics
func (pm *DefaultProviderManager) updateRequestStats(providerName string, increment bool) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	stats := pm.stats[providerName]
	if stats == nil {
		return
	}

	now := time.Now()

	// Reset minute counters if needed
	if now.Sub(stats.LastMinuteReset) >= time.Minute {
		stats.RequestsThisMinute = 0
		stats.TokensThisMinute = 0
		stats.LastMinuteReset = now
	}

	if increment {
		stats.TotalRequests++
		stats.RequestsThisMinute++
		stats.LastRequestTime = now
	}
}

// updateCompletionStats updates completion statistics
func (pm *DefaultProviderManager) updateCompletionStats(providerName string, duration time.Duration, success bool, tokensUsed int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	stats := pm.stats[providerName]
	if stats == nil {
		return
	}

	if success {
		stats.SuccessfulReqs++
		stats.TokensProcessed += int64(tokensUsed)
		stats.TokensThisMinute += int64(tokensUsed)
		stats.ConsecutiveErrors = 0
	} else {
		stats.FailedRequests++
		stats.ConsecutiveErrors++
	}

	// Update average latency
	if stats.TotalRequests > 0 {
		stats.AverageLatency = time.Duration(
			(int64(stats.AverageLatency)*stats.SuccessfulReqs + int64(duration)) / (stats.SuccessfulReqs + 1),
		)
	}

	// Update error rate
	if stats.TotalRequests > 0 {
		stats.ErrorRate = float64(stats.FailedRequests) / float64(stats.TotalRequests)
	}

	// Update health status based on consecutive errors
	stats.IsHealthy = stats.ConsecutiveErrors < 5
}

// isWithinRateLimits checks if provider is within rate limits
func (pm *DefaultProviderManager) isWithinRateLimits(providerName string, tokensNeeded int) bool {
	stats := pm.stats[providerName]
	if stats == nil {
		return false
	}

	provider := pm.providers[providerName]
	if provider == nil {
		return false
	}

	limits := provider.GetLimits()

	// Check requests per minute
	if stats.RequestsThisMinute >= int64(limits.RequestsPerMinute) {
		return false
	}

	// Check tokens per minute
	if stats.TokensThisMinute+int64(tokensNeeded) > int64(limits.TokensPerMinute) {
		return false
	}

	return true
}

// HealthCheck performs health checks on all providers
func (pm *DefaultProviderManager) HealthCheck(ctx context.Context) map[string]error {
	pm.mutex.RLock()
	providers := make(map[string]LLMProvider)
	for name, provider := range pm.providers {
		providers[name] = provider
	}
	pm.mutex.RUnlock()

	results := make(map[string]error)

	for name, provider := range providers {
		err := provider.Health(ctx)
		results[name] = err

		// Update health status
		pm.mutex.Lock()
		if stats := pm.stats[name]; stats != nil {
			stats.IsHealthy = err == nil
			stats.LastHealthCheck = time.Now()
		}
		pm.mutex.Unlock()
	}

	return results
}

// GetStats returns provider statistics
func (pm *DefaultProviderManager) GetStats() map[string]*ProviderMetrics {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	// Create a copy to avoid race conditions
	statsCopy := make(map[string]*ProviderMetrics)
	for name, stats := range pm.stats {
		statsCopy[name] = &ProviderMetrics{
			TotalRequests:      stats.TotalRequests,
			SuccessfulReqs:     stats.SuccessfulReqs,
			FailedRequests:     stats.FailedRequests,
			AverageLatency:     stats.AverageLatency,
			LastRequestTime:    stats.LastRequestTime,
			ErrorRate:          stats.ErrorRate,
			TokensProcessed:    stats.TokensProcessed,
			RequestsThisMinute: stats.RequestsThisMinute,
			TokensThisMinute:   stats.TokensThisMinute,
			LastMinuteReset:    stats.LastMinuteReset,
			IsHealthy:          stats.IsHealthy,
			LastHealthCheck:    stats.LastHealthCheck,
			ConsecutiveErrors:  stats.ConsecutiveErrors,
		}
	}

	return statsCopy
}

// Start starts the provider manager
func (pm *DefaultProviderManager) Start(ctx context.Context) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if pm.running {
		return fmt.Errorf("provider manager already running")
	}

	pm.running = true
	pm.logger.Info("Provider manager started")

	// Start background health checking
	go pm.backgroundHealthCheck(ctx)

	return nil
}

// Stop stops the provider manager
func (pm *DefaultProviderManager) Stop(ctx context.Context) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.running {
		return nil
	}

	pm.running = false
	close(pm.stopChan)

	// Close all providers
	for name, provider := range pm.providers {
		if err := provider.Close(); err != nil {
			pm.logger.Error("Error closing provider", "name", name, "error", err)
		}
	}

	pm.logger.Info("Provider manager stopped")
	return nil
}

// backgroundHealthCheck performs periodic health checks
func (pm *DefaultProviderManager) backgroundHealthCheck(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.HealthCheck(ctx)
		case <-pm.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}
