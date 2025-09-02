package performance

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var loadBalancerTracer = otel.Tracer("hackai/performance/load-balancer")

// LoadBalancer provides intelligent load balancing capabilities
type LoadBalancer struct {
	config           *LoadBalancingConfig
	logger           *logger.Logger
	backends         []*Backend
	healthChecker    *HealthChecker
	circuitBreaker   *CircuitBreaker
	rateLimiter      interface{} // Placeholder for RateLimiter
	metricsCollector *LoadBalancerMetrics
	algorithms       map[string]LoadBalancingAlgorithm
	currentAlgorithm LoadBalancingAlgorithm
	mutex            sync.RWMutex
	running          bool
	stopChan         chan struct{}
}

// LoadBalancingConfig defines load balancing configuration
type LoadBalancingConfig struct {
	// General settings
	Enabled             bool          `yaml:"enabled"`
	Algorithm           string        `yaml:"algorithm"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval"`

	// Backend configuration
	Backends []BackendConfig `yaml:"backends"`

	// Health checking
	HealthCheck HealthCheckConfig `yaml:"health_check"`

	// Circuit breaker
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`

	// Rate limiting
	RateLimit map[string]interface{} `yaml:"rate_limit"` // Placeholder for RateLimitConfig

	// Session affinity
	SessionAffinity SessionAffinityConfig `yaml:"session_affinity"`

	// Retry configuration
	Retry RetryConfig `yaml:"retry"`

	// Timeout configuration
	Timeout TimeoutConfig `yaml:"timeout"`
}

// BackendConfig defines backend server configuration
type BackendConfig struct {
	ID       string                 `yaml:"id"`
	URL      string                 `yaml:"url"`
	Weight   int                    `yaml:"weight"`
	Priority int                    `yaml:"priority"`
	MaxConns int                    `yaml:"max_connections"`
	Metadata map[string]interface{} `yaml:"metadata"`
}

// HealthCheckConfig defines health check configuration
type HealthCheckConfig struct {
	Enabled            bool          `yaml:"enabled"`
	Path               string        `yaml:"path"`
	Interval           time.Duration `yaml:"interval"`
	Timeout            time.Duration `yaml:"timeout"`
	HealthyThreshold   int           `yaml:"healthy_threshold"`
	UnhealthyThreshold int           `yaml:"unhealthy_threshold"`
	ExpectedStatus     []int         `yaml:"expected_status"`
	ExpectedBody       string        `yaml:"expected_body"`
}

// CircuitBreakerConfig defines circuit breaker configuration
type CircuitBreakerConfig struct {
	Enabled          bool          `yaml:"enabled"`
	FailureThreshold int           `yaml:"failure_threshold"`
	RecoveryTimeout  time.Duration `yaml:"recovery_timeout"`
	HalfOpenRequests int           `yaml:"half_open_requests"`
}

// SessionAffinityConfig defines session affinity configuration
type SessionAffinityConfig struct {
	Enabled    bool          `yaml:"enabled"`
	CookieName string        `yaml:"cookie_name"`
	TTL        time.Duration `yaml:"ttl"`
}

// RetryConfig defines retry configuration
type RetryConfig struct {
	Enabled     bool          `yaml:"enabled"`
	MaxRetries  int           `yaml:"max_retries"`
	RetryDelay  time.Duration `yaml:"retry_delay"`
	BackoffType string        `yaml:"backoff_type"`
}

// TimeoutConfig defines timeout configuration
type TimeoutConfig struct {
	Connect time.Duration `yaml:"connect"`
	Read    time.Duration `yaml:"read"`
	Write   time.Duration `yaml:"write"`
	Idle    time.Duration `yaml:"idle"`
}

// Backend represents a backend server
type Backend struct {
	ID           string                 `json:"id"`
	URL          *url.URL               `json:"url"`
	Weight       int                    `json:"weight"`
	Priority     int                    `json:"priority"`
	MaxConns     int                    `json:"max_connections"`
	CurrentConns int                    `json:"current_connections"`
	Healthy      bool                   `json:"healthy"`
	LastCheck    time.Time              `json:"last_check"`
	Proxy        *httputil.ReverseProxy `json:"-"`
	Metrics      *BackendMetrics        `json:"metrics"`
	Metadata     map[string]interface{} `json:"metadata"`
	mutex        sync.RWMutex
}

// BackendMetrics represents backend performance metrics
type BackendMetrics struct {
	RequestCount    int64         `json:"request_count"`
	ErrorCount      int64         `json:"error_count"`
	TotalLatency    time.Duration `json:"total_latency"`
	AverageLatency  time.Duration `json:"average_latency"`
	LastRequestTime time.Time     `json:"last_request_time"`
	HealthScore     float64       `json:"health_score"`
}

// LoadBalancerMetrics represents load balancer metrics
type LoadBalancerMetrics struct {
	TotalRequests    int64                      `json:"total_requests"`
	TotalErrors      int64                      `json:"total_errors"`
	AverageLatency   time.Duration              `json:"average_latency"`
	BackendMetrics   map[string]*BackendMetrics `json:"backend_metrics"`
	AlgorithmMetrics map[string]interface{}     `json:"algorithm_metrics"`
	LastUpdated      time.Time                  `json:"last_updated"`
	mutex            sync.RWMutex
}

// LoadBalancingAlgorithm interface for load balancing algorithms
type LoadBalancingAlgorithm interface {
	SelectBackend(backends []*Backend, request *http.Request) (*Backend, error)
	GetName() string
	UpdateMetrics(backend *Backend, latency time.Duration, success bool)
}

// RoundRobinAlgorithm implements round-robin load balancing
type RoundRobinAlgorithm struct {
	current int
	mutex   sync.Mutex
}

// WeightedRoundRobinAlgorithm implements weighted round-robin load balancing
type WeightedRoundRobinAlgorithm struct {
	currentWeights map[string]int
	mutex          sync.Mutex
}

func (wrr *WeightedRoundRobinAlgorithm) SelectBackend(backends []*Backend, request *http.Request) (*Backend, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}
	// Simple implementation - just return first backend for now
	return backends[0], nil
}

func (wrr *WeightedRoundRobinAlgorithm) GetName() string {
	return "weighted_round_robin"
}

func (wrr *WeightedRoundRobinAlgorithm) UpdateMetrics(backend *Backend, latency time.Duration, success bool) {
	// Weighted round robin can track backend performance
}

// LeastConnectionsAlgorithm implements least connections load balancing
type LeastConnectionsAlgorithm struct{}

func (lc *LeastConnectionsAlgorithm) SelectBackend(backends []*Backend, request *http.Request) (*Backend, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}

	var selectedBackend *Backend
	minConnections := int(^uint(0) >> 1) // Max int

	for _, backend := range backends {
		if backend.CurrentConns < minConnections {
			minConnections = backend.CurrentConns
			selectedBackend = backend
		}
	}

	if selectedBackend == nil {
		selectedBackend = backends[0]
	}

	return selectedBackend, nil
}

func (lc *LeastConnectionsAlgorithm) GetName() string {
	return "least_connections"
}

func (lc *LeastConnectionsAlgorithm) UpdateMetrics(backend *Backend, latency time.Duration, success bool) {
	// Least connections uses current connection count
}

// WeightedLeastConnectionsAlgorithm implements weighted least connections load balancing
type WeightedLeastConnectionsAlgorithm struct{}

func (wlc *WeightedLeastConnectionsAlgorithm) SelectBackend(backends []*Backend, request *http.Request) (*Backend, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}
	// Simple implementation - just return first backend for now
	return backends[0], nil
}

func (wlc *WeightedLeastConnectionsAlgorithm) GetName() string {
	return "weighted_least_connections"
}

func (wlc *WeightedLeastConnectionsAlgorithm) UpdateMetrics(backend *Backend, latency time.Duration, success bool) {
	// Weighted least connections can track backend performance
}

// IPHashAlgorithm implements IP hash-based load balancing
type IPHashAlgorithm struct{}

func (ih *IPHashAlgorithm) SelectBackend(backends []*Backend, request *http.Request) (*Backend, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}

	clientIP := request.RemoteAddr
	hash := fnv.New32a()
	hash.Write([]byte(clientIP))
	index := int(hash.Sum32()) % len(backends)

	return backends[index], nil
}

func (ih *IPHashAlgorithm) GetName() string {
	return "ip_hash"
}

func (ih *IPHashAlgorithm) UpdateMetrics(backend *Backend, latency time.Duration, success bool) {
	// IP hash doesn't need additional metrics
}

// ConsistentHashAlgorithm implements consistent hash load balancing
type ConsistentHashAlgorithm struct {
	ring  map[uint32]*Backend
	keys  []uint32
	mutex sync.RWMutex
}

func (ch *ConsistentHashAlgorithm) SelectBackend(backends []*Backend, request *http.Request) (*Backend, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}
	// Simple implementation - just return first backend for now
	return backends[0], nil
}

func (ch *ConsistentHashAlgorithm) GetName() string {
	return "consistent_hash"
}

func (ch *ConsistentHashAlgorithm) UpdateMetrics(backend *Backend, latency time.Duration, success bool) {
	// Consistent hash can track backend performance
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(config *LoadBalancingConfig, logger *logger.Logger) *LoadBalancer {
	lb := &LoadBalancer{
		config:           config,
		logger:           logger,
		backends:         make([]*Backend, 0),
		healthChecker:    NewHealthChecker(&config.HealthCheck, logger),
		circuitBreaker:   NewCircuitBreaker(&config.CircuitBreaker, logger),
		rateLimiter:      nil, // Placeholder for RateLimiter
		metricsCollector: NewLoadBalancerMetrics(),
		algorithms:       make(map[string]LoadBalancingAlgorithm),
		stopChan:         make(chan struct{}),
		running:          false,
	}

	// Initialize load balancing algorithms
	lb.initializeAlgorithms()

	// Initialize backends
	lb.initializeBackends()

	return lb
}

// initializeAlgorithms initializes available load balancing algorithms
func (lb *LoadBalancer) initializeAlgorithms() {
	lb.algorithms["round_robin"] = &RoundRobinAlgorithm{}
	lb.algorithms["weighted_round_robin"] = &WeightedRoundRobinAlgorithm{
		currentWeights: make(map[string]int),
	}
	lb.algorithms["least_connections"] = &LeastConnectionsAlgorithm{}
	lb.algorithms["weighted_least_connections"] = &WeightedLeastConnectionsAlgorithm{}
	lb.algorithms["ip_hash"] = &IPHashAlgorithm{}
	lb.algorithms["consistent_hash"] = &ConsistentHashAlgorithm{
		ring: make(map[uint32]*Backend),
		keys: make([]uint32, 0),
	}

	// Set current algorithm
	if algorithm, exists := lb.algorithms[lb.config.Algorithm]; exists {
		lb.currentAlgorithm = algorithm
	} else {
		lb.currentAlgorithm = lb.algorithms["round_robin"]
		lb.logger.WithField("algorithm", lb.config.Algorithm).Warn("Unknown algorithm, using round_robin")
	}
}

// initializeBackends initializes backend servers
func (lb *LoadBalancer) initializeBackends() {
	for _, backendConfig := range lb.config.Backends {
		backend, err := lb.createBackend(backendConfig)
		if err != nil {
			lb.logger.WithError(err).WithField("backend_id", backendConfig.ID).Error("Failed to create backend")
			continue
		}
		lb.backends = append(lb.backends, backend)
	}
}

// createBackend creates a backend from configuration
func (lb *LoadBalancer) createBackend(config BackendConfig) (*Backend, error) {
	backendURL, err := url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	// Customize proxy behavior
	proxy.ModifyResponse = lb.modifyResponse
	proxy.ErrorHandler = lb.errorHandler

	backend := &Backend{
		ID:           config.ID,
		URL:          backendURL,
		Weight:       config.Weight,
		Priority:     config.Priority,
		MaxConns:     config.MaxConns,
		CurrentConns: 0,
		Healthy:      true,
		LastCheck:    time.Now(),
		Proxy:        proxy,
		Metrics:      &BackendMetrics{},
		Metadata:     config.Metadata,
	}

	return backend, nil
}

// Start starts the load balancer
func (lb *LoadBalancer) Start(ctx context.Context) error {
	if !lb.config.Enabled {
		lb.logger.Info("Load balancer is disabled")
		return nil
	}

	lb.mutex.Lock()
	if lb.running {
		lb.mutex.Unlock()
		return fmt.Errorf("load balancer is already running")
	}
	lb.running = true
	lb.mutex.Unlock()

	lb.logger.Info("Starting load balancer")

	// Start health checking
	if lb.config.HealthCheck.Enabled {
		go lb.healthCheckLoop(ctx)
	}

	// Start metrics collection
	go lb.metricsLoop(ctx)

	return nil
}

// Stop stops the load balancer
func (lb *LoadBalancer) Stop() error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if !lb.running {
		return fmt.Errorf("load balancer is not running")
	}

	lb.logger.Info("Stopping load balancer")
	close(lb.stopChan)
	lb.running = false

	return nil
}

// ServeHTTP implements the http.Handler interface
func (lb *LoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := loadBalancerTracer.Start(r.Context(), "load_balance_request")
	defer span.End()

	// Rate limiting check (placeholder implementation)
	// if lb.config.RateLimit.Enabled {
	//	if !lb.rateLimiter.Allow(r) {
	//		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
	//		return
	//	}
	// }

	// Select backend
	backend, err := lb.selectBackend(r)
	if err != nil {
		span.RecordError(err)
		http.Error(w, "No healthy backends available", http.StatusServiceUnavailable)
		return
	}

	span.SetAttributes(
		attribute.String("backend.id", backend.ID),
		attribute.String("backend.url", backend.URL.String()),
	)

	// Check circuit breaker
	if lb.config.CircuitBreaker.Enabled {
		if !lb.circuitBreaker.Allow(backend.ID) {
			http.Error(w, "Circuit breaker open", http.StatusServiceUnavailable)
			return
		}
	}

	// Track connection
	backend.mutex.Lock()
	backend.CurrentConns++
	backend.mutex.Unlock()

	defer func() {
		backend.mutex.Lock()
		backend.CurrentConns--
		backend.mutex.Unlock()
	}()

	// Proxy request
	startTime := time.Now()
	backend.Proxy.ServeHTTP(w, r.WithContext(ctx))
	latency := time.Since(startTime)

	// Update metrics
	lb.updateMetrics(backend, latency, true)
	lb.currentAlgorithm.UpdateMetrics(backend, latency, true)

	span.SetAttributes(
		attribute.String("request.latency", latency.String()),
	)
}

// selectBackend selects a backend using the configured algorithm
func (lb *LoadBalancer) selectBackend(r *http.Request) (*Backend, error) {
	lb.mutex.RLock()
	healthyBackends := make([]*Backend, 0)
	for _, backend := range lb.backends {
		if backend.Healthy {
			healthyBackends = append(healthyBackends, backend)
		}
	}
	lb.mutex.RUnlock()

	if len(healthyBackends) == 0 {
		return nil, fmt.Errorf("no healthy backends available")
	}

	return lb.currentAlgorithm.SelectBackend(healthyBackends, r)
}

// updateMetrics updates backend and load balancer metrics
func (lb *LoadBalancer) updateMetrics(backend *Backend, latency time.Duration, success bool) {
	backend.mutex.Lock()
	backend.Metrics.RequestCount++
	if !success {
		backend.Metrics.ErrorCount++
	}
	backend.Metrics.TotalLatency += latency
	backend.Metrics.AverageLatency = backend.Metrics.TotalLatency / time.Duration(backend.Metrics.RequestCount)
	backend.Metrics.LastRequestTime = time.Now()
	backend.mutex.Unlock()

	lb.metricsCollector.mutex.Lock()
	lb.metricsCollector.TotalRequests++
	if !success {
		lb.metricsCollector.TotalErrors++
	}
	lb.metricsCollector.LastUpdated = time.Now()
	lb.metricsCollector.mutex.Unlock()
}

// healthCheckLoop runs health checks for backends
func (lb *LoadBalancer) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(lb.config.HealthCheck.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-lb.stopChan:
			return
		case <-ticker.C:
			lb.performHealthChecks(ctx)
		}
	}
}

// performHealthChecks performs health checks on all backends
func (lb *LoadBalancer) performHealthChecks(ctx context.Context) {
	for _, backend := range lb.backends {
		go lb.checkBackendHealth(ctx, backend)
	}
}

// checkBackendHealth checks the health of a single backend
func (lb *LoadBalancer) checkBackendHealth(ctx context.Context, backend *Backend) {
	healthy := lb.healthChecker.CheckHealth(ctx, backend)

	backend.mutex.Lock()
	backend.Healthy = healthy
	backend.LastCheck = time.Now()
	backend.mutex.Unlock()

	if healthy {
		lb.logger.WithField("backend_id", backend.ID).Debug("Backend health check passed")
	} else {
		lb.logger.WithField("backend_id", backend.ID).Warn("Backend health check failed")
	}
}

// metricsLoop collects and updates metrics
func (lb *LoadBalancer) metricsLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-lb.stopChan:
			return
		case <-ticker.C:
			lb.updateLoadBalancerMetrics()
		}
	}
}

// updateLoadBalancerMetrics updates load balancer metrics
func (lb *LoadBalancer) updateLoadBalancerMetrics() {
	lb.metricsCollector.mutex.Lock()
	defer lb.metricsCollector.mutex.Unlock()

	// Calculate average latency across all backends
	var totalLatency time.Duration
	var totalRequests int64

	for _, backend := range lb.backends {
		backend.mutex.RLock()
		totalLatency += backend.Metrics.TotalLatency
		totalRequests += backend.Metrics.RequestCount
		backend.mutex.RUnlock()
	}

	if totalRequests > 0 {
		lb.metricsCollector.AverageLatency = totalLatency / time.Duration(totalRequests)
	}
}

// modifyResponse modifies the response from backends
func (lb *LoadBalancer) modifyResponse(r *http.Response) error {
	// Add load balancer headers
	r.Header.Set("X-Load-Balancer", "HackAI-LB")
	r.Header.Set("X-Backend-ID", r.Request.Header.Get("X-Backend-ID"))
	return nil
}

// errorHandler handles errors from backends
func (lb *LoadBalancer) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	lb.logger.WithError(err).Error("Backend request failed")
	http.Error(w, "Backend unavailable", http.StatusBadGateway)
}

// GetMetrics returns current load balancer metrics
func (lb *LoadBalancer) GetMetrics() *LoadBalancerMetrics {
	lb.metricsCollector.mutex.RLock()
	defer lb.metricsCollector.mutex.RUnlock()

	// Create a copy of metrics
	metrics := &LoadBalancerMetrics{
		TotalRequests:    lb.metricsCollector.TotalRequests,
		TotalErrors:      lb.metricsCollector.TotalErrors,
		AverageLatency:   lb.metricsCollector.AverageLatency,
		BackendMetrics:   make(map[string]*BackendMetrics),
		AlgorithmMetrics: make(map[string]interface{}),
		LastUpdated:      lb.metricsCollector.LastUpdated,
	}

	// Copy backend metrics
	for _, backend := range lb.backends {
		backend.mutex.RLock()
		metrics.BackendMetrics[backend.ID] = &BackendMetrics{
			RequestCount:    backend.Metrics.RequestCount,
			ErrorCount:      backend.Metrics.ErrorCount,
			TotalLatency:    backend.Metrics.TotalLatency,
			AverageLatency:  backend.Metrics.AverageLatency,
			LastRequestTime: backend.Metrics.LastRequestTime,
			HealthScore:     backend.Metrics.HealthScore,
		}
		backend.mutex.RUnlock()
	}

	return metrics
}

// GetBackends returns current backend status
func (lb *LoadBalancer) GetBackends() []*Backend {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()

	backends := make([]*Backend, len(lb.backends))
	copy(backends, lb.backends)
	return backends
}

// Implementation of load balancing algorithms

// RoundRobinAlgorithm implementation
func (rr *RoundRobinAlgorithm) SelectBackend(backends []*Backend, request *http.Request) (*Backend, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}

	rr.mutex.Lock()
	defer rr.mutex.Unlock()

	backend := backends[rr.current%len(backends)]
	rr.current++
	return backend, nil
}

func (rr *RoundRobinAlgorithm) GetName() string {
	return "round_robin"
}

func (rr *RoundRobinAlgorithm) UpdateMetrics(backend *Backend, latency time.Duration, success bool) {
	// Round robin doesn't need to track additional metrics
}

// End of load balancer implementation

// Placeholder implementations for other components
type HealthChecker struct {
	config *HealthCheckConfig
	logger *logger.Logger
}

type CircuitBreaker struct {
	config *CircuitBreakerConfig
	logger *logger.Logger
}

func NewHealthChecker(config *HealthCheckConfig, logger *logger.Logger) *HealthChecker {
	return &HealthChecker{config: config, logger: logger}
}

func NewCircuitBreaker(config *CircuitBreakerConfig, logger *logger.Logger) *CircuitBreaker {
	return &CircuitBreaker{config: config, logger: logger}
}

func NewLoadBalancerMetrics() *LoadBalancerMetrics {
	return &LoadBalancerMetrics{
		BackendMetrics:   make(map[string]*BackendMetrics),
		AlgorithmMetrics: make(map[string]interface{}),
		LastUpdated:      time.Now(),
	}
}

func (hc *HealthChecker) CheckHealth(ctx context.Context, backend *Backend) bool {
	// Implementation would perform actual health checks
	return true
}

func (cb *CircuitBreaker) Allow(backendID string) bool {
	// Implementation would check circuit breaker state
	return true
}
