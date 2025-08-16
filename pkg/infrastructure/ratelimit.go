package infrastructure

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var rateLimitTracer = otel.Tracer("hackai/infrastructure/ratelimit")

// RateLimiter interface for rate limiting implementations
type RateLimiter interface {
	Allow(ctx context.Context, key string) (bool, error)
	AllowN(ctx context.Context, key string, n int) (bool, error)
	Reset(ctx context.Context, key string) error
	GetLimit(key string) (int, time.Duration)
}

// TokenBucketLimiter implements rate limiting using token bucket algorithm
type TokenBucketLimiter struct {
	limiters map[string]*rate.Limiter
	config   *RateLimitConfig
	mutex    sync.RWMutex
	logger   *logger.Logger
	
	// Cleanup
	lastCleanup time.Time
}

// NewTokenBucketLimiter creates a new token bucket rate limiter
func NewTokenBucketLimiter(config *RateLimitConfig, logger *logger.Logger) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		limiters:    make(map[string]*rate.Limiter),
		config:      config,
		logger:      logger,
		lastCleanup: time.Now(),
	}
}

// getLimiter gets or creates a limiter for a key
func (rl *TokenBucketLimiter) getLimiter(key string) *rate.Limiter {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	// Cleanup old limiters periodically
	if time.Since(rl.lastCleanup) > rl.config.CleanupInterval {
		rl.cleanup()
		rl.lastCleanup = time.Now()
	}

	limiter, exists := rl.limiters[key]
	if !exists {
		// Create new limiter
		rps := rate.Limit(rl.config.RequestsPerSecond)
		burst := rl.config.BurstSize
		limiter = rate.NewLimiter(rps, burst)
		rl.limiters[key] = limiter
	}

	return limiter
}

// Allow checks if a request is allowed
func (rl *TokenBucketLimiter) Allow(ctx context.Context, key string) (bool, error) {
	limiter := rl.getLimiter(key)
	return limiter.Allow(), nil
}

// AllowN checks if N requests are allowed
func (rl *TokenBucketLimiter) AllowN(ctx context.Context, key string, n int) (bool, error) {
	limiter := rl.getLimiter(key)
	return limiter.AllowN(time.Now(), n), nil
}

// Reset resets the limiter for a key
func (rl *TokenBucketLimiter) Reset(ctx context.Context, key string) error {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	delete(rl.limiters, key)
	return nil
}

// GetLimit returns the limit configuration for a key
func (rl *TokenBucketLimiter) GetLimit(key string) (int, time.Duration) {
	return rl.config.RequestsPerSecond, time.Second
}

// cleanup removes old unused limiters
func (rl *TokenBucketLimiter) cleanup() {
	// Simple cleanup - in production, you'd track last access time
	if len(rl.limiters) > 10000 { // Arbitrary threshold
		rl.limiters = make(map[string]*rate.Limiter)
		rl.logger.Info("Rate limiter cache cleared")
	}
}

// RedisRateLimiter implements distributed rate limiting using Redis
type RedisRateLimiter struct {
	redis  *RedisClient
	config *RateLimitConfig
	logger *logger.Logger
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
func NewRedisRateLimiter(redis *RedisClient, config *RateLimitConfig, logger *logger.Logger) *RedisRateLimiter {
	return &RedisRateLimiter{
		redis:  redis,
		config: config,
		logger: logger,
	}
}

// Allow checks if a request is allowed using Redis sliding window
func (rl *RedisRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return rl.AllowN(ctx, key, 1)
}

// AllowN checks if N requests are allowed using Redis sliding window
func (rl *RedisRateLimiter) AllowN(ctx context.Context, key string, n int) (bool, error) {
	ctx, span := rateLimitTracer.Start(ctx, "redis_rate_limiter.allow_n",
		trace.WithAttributes(
			attribute.String("rate_limit.key", key),
			attribute.Int("rate_limit.requests", n),
		),
	)
	defer span.End()

	now := time.Now()
	window := time.Minute // Use per-minute window
	windowStart := now.Truncate(window)
	
	redisKey := fmt.Sprintf("rate_limit:%s:%d", key, windowStart.Unix())

	// Use Redis pipeline for atomic operations
	pipe := rl.redis.client.Pipeline()
	
	// Increment counter
	incrCmd := pipe.IncrBy(ctx, redisKey, int64(n))
	
	// Set expiration
	pipe.Expire(ctx, redisKey, window+time.Second) // Add buffer
	
	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		span.RecordError(err)
		return false, fmt.Errorf("failed to execute rate limit check: %w", err)
	}

	// Check if limit exceeded
	currentCount := incrCmd.Val()
	allowed := currentCount <= int64(rl.config.RequestsPerMinute)

	span.SetAttributes(
		attribute.Int64("rate_limit.current", currentCount),
		attribute.Int("rate_limit.limit", rl.config.RequestsPerMinute),
		attribute.Bool("rate_limit.allowed", allowed),
	)

	if !allowed {
		rl.logger.Warn("Rate limit exceeded",
			"key", key,
			"current", currentCount,
			"limit", rl.config.RequestsPerMinute,
		)
	}

	return allowed, nil
}

// Reset resets the rate limit for a key
func (rl *RedisRateLimiter) Reset(ctx context.Context, key string) error {
	pattern := fmt.Sprintf("rate_limit:%s:*", key)
	
	// Get all keys matching pattern
	keys, err := rl.redis.client.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get rate limit keys: %w", err)
	}

	if len(keys) > 0 {
		// Delete all matching keys
		err = rl.redis.client.Del(ctx, keys...).Err()
		if err != nil {
			return fmt.Errorf("failed to reset rate limit: %w", err)
		}
	}

	return nil
}

// GetLimit returns the limit configuration
func (rl *RedisRateLimiter) GetLimit(key string) (int, time.Duration) {
	return rl.config.RequestsPerMinute, time.Minute
}

// RateLimitMiddleware provides HTTP middleware for rate limiting
type RateLimitMiddleware struct {
	limiter RateLimiter
	config  *RateLimitConfig
	logger  *logger.Logger
}

// NewRateLimitMiddleware creates a new rate limit middleware
func NewRateLimitMiddleware(limiter RateLimiter, config *RateLimitConfig, logger *logger.Logger) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		limiter: limiter,
		config:  config,
		logger:  logger,
	}
}

// Handler returns the HTTP middleware handler
func (m *RateLimitMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		ctx, span := rateLimitTracer.Start(r.Context(), "rate_limit_middleware",
			trace.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.url", r.URL.Path),
			),
		)
		defer span.End()

		// Determine rate limit key
		key := m.getRateLimitKey(r)
		
		// Check rate limit
		allowed, err := m.limiter.Allow(ctx, key)
		if err != nil {
			span.RecordError(err)
			m.logger.Error("Rate limit check failed", "error", err, "key", key)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Set rate limit headers
		limit, window := m.limiter.GetLimit(key)
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
		w.Header().Set("X-RateLimit-Window", window.String())

		if !allowed {
			span.SetAttributes(
				attribute.Bool("rate_limit.exceeded", true),
				attribute.String("rate_limit.key", key),
			)

			w.Header().Set("X-RateLimit-Exceeded", "true")
			w.Header().Set("Retry-After", strconv.Itoa(int(window.Seconds())))
			
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		span.SetAttributes(
			attribute.Bool("rate_limit.allowed", true),
			attribute.String("rate_limit.key", key),
		)

		next.ServeHTTP(w, r)
	})
}

// getRateLimitKey determines the rate limit key based on configuration
func (m *RateLimitMiddleware) getRateLimitKey(r *http.Request) string {
	// Priority: User ID > IP Address > Global
	
	// Try to get user ID from context (set by auth middleware)
	if m.config.PerUserEnabled {
		if userID := getUserIDFromContext(r.Context()); userID != "" {
			return fmt.Sprintf("user:%s", userID)
		}
	}

	// Fall back to IP address
	if m.config.PerIPEnabled {
		ip := getClientIP(r)
		return fmt.Sprintf("ip:%s", ip)
	}

	// Global rate limit
	return "global"
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if ip := net.ParseIP(xff); ip != nil {
			return ip.String()
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip.String()
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	
	return host
}

// getUserIDFromContext extracts user ID from request context
func getUserIDFromContext(ctx context.Context) string {
	if userID, ok := ctx.Value("user_id").(string); ok {
		return userID
	}
	return ""
}

// RateLimitHealthChecker checks rate limiter health
type RateLimitHealthChecker struct {
	limiter RateLimiter
	logger  *logger.Logger
}

// NewRateLimitHealthChecker creates a new rate limit health checker
func NewRateLimitHealthChecker(limiter RateLimiter, logger *logger.Logger) *RateLimitHealthChecker {
	return &RateLimitHealthChecker{
		limiter: limiter,
		logger:  logger,
	}
}

// Name returns the checker name
func (c *RateLimitHealthChecker) Name() string {
	return "rate_limiter"
}

// Check performs the rate limiter health check
func (c *RateLimitHealthChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()

	// Test rate limiter with a health check key
	testKey := "health_check"
	allowed, err := c.limiter.Allow(ctx, testKey)
	if err != nil {
		return ComponentHealth{
			Name:        c.Name(),
			Status:      HealthStatusUnhealthy,
			Message:     fmt.Sprintf("Rate limiter test failed: %v", err),
			LastChecked: time.Now(),
			Duration:    time.Since(start),
		}
	}

	// Clean up test key
	if err := c.limiter.Reset(ctx, testKey); err != nil {
		c.logger.Warn("Failed to clean up rate limiter health check", "error", err)
	}

	status := HealthStatusHealthy
	message := "Rate limiter is healthy"
	
	if !allowed {
		// This shouldn't happen for a health check, but handle it gracefully
		status = HealthStatusDegraded
		message = "Rate limiter is functional but may be under load"
	}

	return ComponentHealth{
		Name:        c.Name(),
		Status:      status,
		Message:     message,
		LastChecked: time.Now(),
		Duration:    time.Since(start),
		Metadata: map[string]interface{}{
			"test_allowed": allowed,
		},
	}
}
