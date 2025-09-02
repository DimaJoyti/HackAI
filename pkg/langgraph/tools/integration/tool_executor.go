package integration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var executorTracer = otel.Tracer("hackai/langgraph/tools/executor")

// ToolExecutor handles tool execution with advanced features
type ToolExecutor struct {
	config          *IntegrationConfig
	rateLimiters    map[string]*RateLimiter
	circuitBreakers map[string]*CircuitBreaker
	cache           *ExecutionCache
	semaphore       chan struct{}
	logger          *logger.Logger
	mutex           sync.RWMutex
}

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	tokens     chan struct{}
	refillRate time.Duration
	lastRefill time.Time
	mutex      sync.Mutex
}

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	state           CircuitState
	failures        int
	lastFailureTime time.Time
	config          *CircuitBreakerConfig
	mutex           sync.RWMutex
}

// CircuitState represents the state of a circuit breaker
type CircuitState string

const (
	CircuitStateClosed   CircuitState = "closed"
	CircuitStateOpen     CircuitState = "open"
	CircuitStateHalfOpen CircuitState = "half_open"
)

// ExecutionCache caches tool execution results
type ExecutionCache struct {
	cache   map[string]*CacheEntry
	maxSize int
	ttl     time.Duration
	mutex   sync.RWMutex
}

// CacheEntry represents a cached execution result
type CacheEntry struct {
	Result    interface{} `json:"result"`
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	HitCount  int64       `json:"hit_count"`
}

// ExecutionContext holds context for tool execution
type ExecutionContext struct {
	ToolID    string                 `json:"tool_id"`
	UserID    string                 `json:"user_id"`
	RequestID string                 `json:"request_id"`
	StartTime time.Time              `json:"start_time"`
	Timeout   time.Duration          `json:"timeout"`
	Metadata  map[string]interface{} `json:"metadata"`
	Trace     trace.Span             `json:"-"`
}

// NewToolExecutor creates a new tool executor
func NewToolExecutor(config *IntegrationConfig, logger *logger.Logger) *ToolExecutor {
	executor := &ToolExecutor{
		config:          config,
		rateLimiters:    make(map[string]*RateLimiter),
		circuitBreakers: make(map[string]*CircuitBreaker),
		cache:           NewExecutionCache(1000, time.Hour),
		semaphore:       make(chan struct{}, config.MaxConcurrentTools),
		logger:          logger,
	}

	// Fill semaphore
	for i := 0; i < config.MaxConcurrentTools; i++ {
		executor.semaphore <- struct{}{}
	}

	return executor
}

// Execute executes a tool with advanced features
func (te *ToolExecutor) Execute(ctx context.Context, integration *ToolIntegration, input map[string]interface{}, options *ExecutionOptions) (*ExecutionResult, error) {
	ctx, span := executorTracer.Start(ctx, "tool_executor.execute",
		trace.WithAttributes(
			attribute.String("tool.id", integration.Tool.ID()),
			attribute.String("tool.name", integration.Tool.Name()),
		),
	)
	defer span.End()

	startTime := time.Now()

	// Create execution context
	execCtx := &ExecutionContext{
		ToolID:    integration.Tool.ID(),
		UserID:    options.UserID,
		RequestID: fmt.Sprintf("req_%d", time.Now().UnixNano()),
		StartTime: startTime,
		Timeout:   te.getTimeout(integration, options),
		Metadata:  options.Metadata,
		Trace:     span,
	}

	// Check cache first
	if integration.Config.Caching != nil && integration.Config.Caching.Enabled {
		if cached := te.checkCache(integration, input); cached != nil {
			span.SetAttributes(attribute.Bool("cache.hit", true))
			return &ExecutionResult{
				Success:   true,
				Result:    cached.Result,
				Duration:  time.Since(startTime),
				Metadata:  map[string]interface{}{"cached": true},
				Timestamp: time.Now(),
			}, nil
		}
		span.SetAttributes(attribute.Bool("cache.hit", false))
	}

	// Apply rate limiting
	if err := te.applyRateLimit(integration); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("rate limit exceeded: %w", err)
	}

	// Check circuit breaker
	if err := te.checkCircuitBreaker(integration); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("circuit breaker open: %w", err)
	}

	// Acquire semaphore for concurrency control
	select {
	case <-te.semaphore:
		defer func() { te.semaphore <- struct{}{} }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Execute with timeout and retries
	result, err := te.executeWithRetries(ctx, integration, input, execCtx)

	duration := time.Since(startTime)

	if err != nil {
		// Record failure in circuit breaker
		te.recordCircuitBreakerFailure(integration)
		span.RecordError(err)

		return &ExecutionResult{
			Success:   false,
			Error:     err.Error(),
			Duration:  duration,
			Timestamp: time.Now(),
		}, err
	}

	// Record success in circuit breaker
	te.recordCircuitBreakerSuccess(integration)

	// Cache result if caching is enabled
	if integration.Config.Caching != nil && integration.Config.Caching.Enabled {
		te.cacheResult(integration, input, result)
	}

	span.SetAttributes(
		attribute.Bool("execution.success", true),
		attribute.Float64("execution.duration", duration.Seconds()),
	)

	return &ExecutionResult{
		Success:   true,
		Result:    result,
		Duration:  duration,
		Metadata:  execCtx.Metadata,
		Timestamp: time.Now(),
	}, nil
}

// executeWithRetries executes a tool with retry logic
func (te *ToolExecutor) executeWithRetries(ctx context.Context, integration *ToolIntegration, input map[string]interface{}, execCtx *ExecutionContext) (interface{}, error) {
	var lastErr error
	maxAttempts := integration.Config.RetryAttempts + 1

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Create timeout context
		timeoutCtx, cancel := context.WithTimeout(ctx, execCtx.Timeout)

		// Execute tool
		result, err := te.executeSingle(timeoutCtx, integration, input, execCtx, attempt)
		cancel()

		if err == nil {
			return result, nil
		}

		lastErr = err

		// Don't retry on certain errors
		if !te.shouldRetry(err, attempt, maxAttempts) {
			break
		}

		// Wait before retry
		if attempt < maxAttempts {
			retryDelay := te.calculateRetryDelay(integration, attempt)
			te.logger.Debug("Retrying tool execution",
				"tool_id", integration.Tool.ID(),
				"attempt", attempt,
				"delay", retryDelay,
				"error", err)

			select {
			case <-time.After(retryDelay):
				// Continue to next attempt
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return nil, fmt.Errorf("tool execution failed after %d attempts: %w", maxAttempts, lastErr)
}

// executeSingle executes a tool once
func (te *ToolExecutor) executeSingle(ctx context.Context, integration *ToolIntegration, input map[string]interface{}, execCtx *ExecutionContext, attempt int) (interface{}, error) {
	te.logger.Debug("Executing tool",
		"tool_id", integration.Tool.ID(),
		"attempt", attempt,
		"timeout", execCtx.Timeout)

	// Validate input if tool supports validation
	if validatable, ok := integration.Tool.(tools.ValidatableTool); ok {
		if err := validatable.Validate(input); err != nil {
			return nil, fmt.Errorf("input validation failed: %w", err)
		}
	}

	// Execute tool
	result, err := integration.Tool.Execute(ctx, input)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Helper methods for rate limiting

func (te *ToolExecutor) applyRateLimit(integration *ToolIntegration) error {
	if integration.Config.RateLimit == nil {
		return nil
	}

	te.mutex.Lock()
	defer te.mutex.Unlock()

	toolID := integration.Tool.ID()
	rateLimiter, exists := te.rateLimiters[toolID]

	if !exists {
		rateLimiter = NewRateLimiter(integration.Config.RateLimit)
		te.rateLimiters[toolID] = rateLimiter
	}

	return rateLimiter.Allow()
}

func (te *ToolExecutor) checkCircuitBreaker(integration *ToolIntegration) error {
	if integration.Config.CircuitBreaker == nil {
		return nil
	}

	te.mutex.Lock()
	defer te.mutex.Unlock()

	toolID := integration.Tool.ID()
	circuitBreaker, exists := te.circuitBreakers[toolID]

	if !exists {
		circuitBreaker = NewCircuitBreaker(integration.Config.CircuitBreaker)
		te.circuitBreakers[toolID] = circuitBreaker
	}

	return circuitBreaker.Allow()
}

func (te *ToolExecutor) recordCircuitBreakerFailure(integration *ToolIntegration) {
	if integration.Config.CircuitBreaker == nil {
		return
	}

	te.mutex.Lock()
	defer te.mutex.Unlock()

	toolID := integration.Tool.ID()
	if circuitBreaker, exists := te.circuitBreakers[toolID]; exists {
		circuitBreaker.RecordFailure()
	}
}

func (te *ToolExecutor) recordCircuitBreakerSuccess(integration *ToolIntegration) {
	if integration.Config.CircuitBreaker == nil {
		return
	}

	te.mutex.Lock()
	defer te.mutex.Unlock()

	toolID := integration.Tool.ID()
	if circuitBreaker, exists := te.circuitBreakers[toolID]; exists {
		circuitBreaker.RecordSuccess()
	}
}

// Helper methods for caching

func (te *ToolExecutor) checkCache(integration *ToolIntegration, input map[string]interface{}) *CacheEntry {
	cacheKey := te.generateCacheKey(integration.Tool.ID(), input)
	return te.cache.Get(cacheKey)
}

func (te *ToolExecutor) cacheResult(integration *ToolIntegration, input map[string]interface{}, result interface{}) {
	cacheKey := te.generateCacheKey(integration.Tool.ID(), input)
	te.cache.Set(cacheKey, result, integration.Config.Caching.TTL)
}

func (te *ToolExecutor) generateCacheKey(toolID string, input map[string]interface{}) string {
	// Simple cache key generation - in production, use proper hashing
	return fmt.Sprintf("%s:%v", toolID, input)
}

// Helper methods

func (te *ToolExecutor) getTimeout(integration *ToolIntegration, options *ExecutionOptions) time.Duration {
	if options.Timeout != nil {
		return *options.Timeout
	}
	if integration.Config.Timeout > 0 {
		return integration.Config.Timeout
	}
	return te.config.DefaultTimeout
}

func (te *ToolExecutor) shouldRetry(err error, attempt, maxAttempts int) bool {
	if attempt >= maxAttempts {
		return false
	}

	// Don't retry validation errors
	if fmt.Sprintf("%v", err) == "input validation failed" {
		return false
	}

	// Don't retry context cancellation
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}

	return true
}

func (te *ToolExecutor) calculateRetryDelay(integration *ToolIntegration, attempt int) time.Duration {
	baseDelay := integration.Config.RetryDelay
	if baseDelay == 0 {
		baseDelay = te.config.RetryDelay
	}

	// Exponential backoff
	delay := baseDelay * time.Duration(1<<uint(attempt-1))

	// Cap at 30 seconds
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}

	return delay
}

// RateLimiter implementation

func NewRateLimiter(config *RateLimit) *RateLimiter {
	rl := &RateLimiter{
		tokens:     make(chan struct{}, config.BurstSize),
		refillRate: time.Second / time.Duration(config.RequestsPerSecond),
		lastRefill: time.Now(),
	}

	// Fill initial tokens
	for i := 0; i < config.BurstSize; i++ {
		rl.tokens <- struct{}{}
	}

	// Start refill goroutine
	go rl.refillTokens()

	return rl
}

func (rl *RateLimiter) Allow() error {
	select {
	case <-rl.tokens:
		return nil
	default:
		return fmt.Errorf("rate limit exceeded")
	}
}

func (rl *RateLimiter) refillTokens() {
	ticker := time.NewTicker(rl.refillRate)
	defer ticker.Stop()

	for range ticker.C {
		select {
		case rl.tokens <- struct{}{}:
			// Token added
		default:
			// Bucket full
		}
	}
}

// CircuitBreaker implementation

func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		state:  CircuitStateClosed,
		config: config,
	}
}

func (cb *CircuitBreaker) Allow() error {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	switch cb.state {
	case CircuitStateClosed:
		return nil
	case CircuitStateOpen:
		if time.Since(cb.lastFailureTime) > cb.config.RecoveryTimeout {
			cb.state = CircuitStateHalfOpen
			return nil
		}
		return fmt.Errorf("circuit breaker is open")
	case CircuitStateHalfOpen:
		return nil
	default:
		return fmt.Errorf("unknown circuit breaker state")
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	if cb.failures >= cb.config.FailureThreshold {
		cb.state = CircuitStateOpen
	}
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failures = 0
	cb.state = CircuitStateClosed
}

// ExecutionCache implementation

func NewExecutionCache(maxSize int, ttl time.Duration) *ExecutionCache {
	cache := &ExecutionCache{
		cache:   make(map[string]*CacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

func (ec *ExecutionCache) Get(key string) *CacheEntry {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()

	entry, exists := ec.cache[key]
	if !exists {
		return nil
	}

	if time.Now().After(entry.ExpiresAt) {
		delete(ec.cache, key)
		return nil
	}

	entry.HitCount++
	return entry
}

func (ec *ExecutionCache) Set(key string, result interface{}, ttl time.Duration) {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	// Evict if cache is full
	if len(ec.cache) >= ec.maxSize {
		ec.evictOldest()
	}

	now := time.Now()
	ec.cache[key] = &CacheEntry{
		Result:    result,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		HitCount:  0,
	}
}

func (ec *ExecutionCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range ec.cache {
		if oldestKey == "" || entry.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.CreatedAt
		}
	}

	if oldestKey != "" {
		delete(ec.cache, oldestKey)
	}
}

func (ec *ExecutionCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ec.mutex.Lock()
		now := time.Now()

		for key, entry := range ec.cache {
			if now.After(entry.ExpiresAt) {
				delete(ec.cache, key)
			}
		}
		ec.mutex.Unlock()
	}
}
