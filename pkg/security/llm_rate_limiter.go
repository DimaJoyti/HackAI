package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var rateLimiterTracer = otel.Tracer("hackai/security/llm_rate_limiter")

// LLMRateLimiter provides rate limiting for LLM requests
type LLMRateLimiter struct {
	logger       *logger.Logger
	config       *RateLimiterConfig
	securityRepo domain.LLMSecurityRepository

	// In-memory rate limiting
	userLimits   map[uuid.UUID]*UserRateLimit
	globalLimits *GlobalRateLimit
	mu           sync.RWMutex

	// Token bucket implementation
	tokenBuckets map[string]*TokenBucket
	bucketMu     sync.RWMutex
}

// RateLimiterConfig holds configuration for rate limiting
type RateLimiterConfig struct {
	// Global Settings
	Enabled    bool `json:"enabled"`
	StrictMode bool `json:"strict_mode"`

	// Global Rate Limits
	GlobalRequestsPerMinute int `json:"global_requests_per_minute"`
	GlobalRequestsPerHour   int `json:"global_requests_per_hour"`
	GlobalTokensPerMinute   int `json:"global_tokens_per_minute"`
	GlobalTokensPerHour     int `json:"global_tokens_per_hour"`

	// User Rate Limits
	UserRequestsPerMinute int `json:"user_requests_per_minute"`
	UserRequestsPerHour   int `json:"user_requests_per_hour"`
	UserRequestsPerDay    int `json:"user_requests_per_day"`
	UserTokensPerMinute   int `json:"user_tokens_per_minute"`
	UserTokensPerHour     int `json:"user_tokens_per_hour"`
	UserTokensPerDay      int `json:"user_tokens_per_day"`

	// Provider-specific Limits
	ProviderLimits map[string]ProviderLimit `json:"provider_limits"`

	// Model-specific Limits
	ModelLimits map[string]ModelLimit `json:"model_limits"`

	// Cost Limits
	UserCostPerHour  float64 `json:"user_cost_per_hour"`
	UserCostPerDay   float64 `json:"user_cost_per_day"`
	UserCostPerMonth float64 `json:"user_cost_per_month"`

	// Burst Settings
	AllowBurst         bool    `json:"allow_burst"`
	BurstMultiplier    float64 `json:"burst_multiplier"`
	BurstWindowSeconds int     `json:"burst_window_seconds"`

	// Sliding Window Settings
	WindowSize        time.Duration `json:"window_size"`
	WindowGranularity time.Duration `json:"window_granularity"`
}

// ProviderLimit represents rate limits for a specific provider
type ProviderLimit struct {
	RequestsPerMinute int     `json:"requests_per_minute"`
	RequestsPerHour   int     `json:"requests_per_hour"`
	TokensPerMinute   int     `json:"tokens_per_minute"`
	TokensPerHour     int     `json:"tokens_per_hour"`
	CostPerHour       float64 `json:"cost_per_hour"`
}

// ModelLimit represents rate limits for a specific model
type ModelLimit struct {
	RequestsPerMinute   int     `json:"requests_per_minute"`
	RequestsPerHour     int     `json:"requests_per_hour"`
	TokensPerMinute     int     `json:"tokens_per_minute"`
	TokensPerHour       int     `json:"tokens_per_hour"`
	CostPerHour         float64 `json:"cost_per_hour"`
	MaxTokensPerRequest int     `json:"max_tokens_per_request"`
}

// UserRateLimit tracks rate limiting for a user
type UserRateLimit struct {
	UserID             uuid.UUID `json:"user_id"`
	RequestsThisMinute int       `json:"requests_this_minute"`
	RequestsThisHour   int       `json:"requests_this_hour"`
	RequestsThisDay    int       `json:"requests_this_day"`
	TokensThisMinute   int       `json:"tokens_this_minute"`
	TokensThisHour     int       `json:"tokens_this_hour"`
	TokensThisDay      int       `json:"tokens_this_day"`
	CostThisHour       float64   `json:"cost_this_hour"`
	CostThisDay        float64   `json:"cost_this_day"`
	CostThisMonth      float64   `json:"cost_this_month"`
	LastMinuteReset    time.Time `json:"last_minute_reset"`
	LastHourReset      time.Time `json:"last_hour_reset"`
	LastDayReset       time.Time `json:"last_day_reset"`
	LastMonthReset     time.Time `json:"last_month_reset"`
}

// GlobalRateLimit tracks global rate limiting
type GlobalRateLimit struct {
	RequestsThisMinute int       `json:"requests_this_minute"`
	RequestsThisHour   int       `json:"requests_this_hour"`
	TokensThisMinute   int       `json:"tokens_this_minute"`
	TokensThisHour     int       `json:"tokens_this_hour"`
	LastMinuteReset    time.Time `json:"last_minute_reset"`
	LastHourReset      time.Time `json:"last_hour_reset"`
}

// TokenBucket implements token bucket rate limiting
type TokenBucket struct {
	Capacity     int           `json:"capacity"`
	Tokens       int           `json:"tokens"`
	RefillRate   int           `json:"refill_rate"`
	RefillPeriod time.Duration `json:"refill_period"`
	LastRefill   time.Time     `json:"last_refill"`
	mu           sync.Mutex
}

// RateLimitResult represents the result of rate limit checking
type RateLimitResult struct {
	Allowed        bool                   `json:"allowed"`
	Reason         string                 `json:"reason"`
	RetryAfter     time.Duration          `json:"retry_after"`
	RemainingQuota map[string]interface{} `json:"remaining_quota"`
	UsedQuota      map[string]interface{} `json:"used_quota"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// NewLLMRateLimiter creates a new LLM rate limiter
func NewLLMRateLimiter(
	logger *logger.Logger,
	config *RateLimiterConfig,
	securityRepo domain.LLMSecurityRepository,
) *LLMRateLimiter {
	return &LLMRateLimiter{
		logger:       logger,
		config:       config,
		securityRepo: securityRepo,
		userLimits:   make(map[uuid.UUID]*UserRateLimit),
		globalLimits: &GlobalRateLimit{},
		tokenBuckets: make(map[string]*TokenBucket),
	}
}

// CheckLimit checks if a request is within rate limits
func (rl *LLMRateLimiter) CheckLimit(ctx context.Context, req *LLMRequest) (bool, error) {
	ctx, span := rateLimiterTracer.Start(ctx, "llm_rate_limiter.check_limit")
	defer span.End()

	span.SetAttributes(
		attribute.String("request.id", req.ID),
		attribute.String("request.provider", req.Provider),
		attribute.String("request.model", req.Model),
	)

	if !rl.config.Enabled {
		return true, nil
	}

	startTime := time.Now()

	// Check global limits first
	if !rl.checkGlobalLimits(ctx, req) {
		span.SetAttributes(
			attribute.Bool("rate_limit.allowed", false),
			attribute.String("rate_limit.reason", "global_limit_exceeded"),
		)
		return false, nil
	}

	// Check user limits if user is authenticated
	if req.UserID != nil {
		if !rl.checkUserLimits(ctx, req) {
			span.SetAttributes(
				attribute.Bool("rate_limit.allowed", false),
				attribute.String("rate_limit.reason", "user_limit_exceeded"),
			)
			return false, nil
		}
	}

	// Check provider limits
	if !rl.checkProviderLimits(ctx, req) {
		span.SetAttributes(
			attribute.Bool("rate_limit.allowed", false),
			attribute.String("rate_limit.reason", "provider_limit_exceeded"),
		)
		return false, nil
	}

	// Check model limits
	if !rl.checkModelLimits(ctx, req) {
		span.SetAttributes(
			attribute.Bool("rate_limit.allowed", false),
			attribute.String("rate_limit.reason", "model_limit_exceeded"),
		)
		return false, nil
	}

	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Bool("rate_limit.allowed", true),
		attribute.Int64("rate_limit.check_duration_ms", duration.Milliseconds()),
	)

	rl.logger.WithFields(map[string]interface{}{
		"request_id":  req.ID,
		"user_id":     req.UserID,
		"provider":    req.Provider,
		"model":       req.Model,
		"allowed":     true,
		"duration_ms": duration.Milliseconds(),
	}).Debug("Rate limit check completed")

	return true, nil
}

// GetQuota returns the current quota for a user
func (rl *LLMRateLimiter) GetQuota(ctx context.Context, userID uuid.UUID) (*domain.LLMUsageQuota, error) {
	// Get quota from database
	quotas, err := rl.securityRepo.GetUserQuotas(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user quotas: %w", err)
	}

	// Return the first active quota (simplified)
	for _, quota := range quotas {
		if quota.Enabled {
			return quota, nil
		}
	}

	return nil, fmt.Errorf("no active quota found for user")
}

// IncrementUsage increments usage for a user
func (rl *LLMRateLimiter) IncrementUsage(ctx context.Context, userID uuid.UUID, tokens int, cost float64) error {
	// Update in-memory counters
	rl.mu.Lock()
	userLimit := rl.getUserLimit(userID)
	rl.updateUserUsage(userLimit, 1, tokens, cost)
	rl.mu.Unlock()

	// Update database quota
	quotas, err := rl.securityRepo.GetUserQuotas(ctx, userID)
	if err != nil {
		rl.logger.WithError(err).Error("Failed to get user quotas for increment")
		return nil // Don't fail the request
	}

	for _, quota := range quotas {
		if quota.Enabled {
			if err := rl.securityRepo.IncrementUsage(ctx, quota.ID, 1, tokens, cost); err != nil {
				rl.logger.WithError(err).Error("Failed to increment quota usage")
			}
		}
	}

	return nil
}

// Health checks the health of the rate limiter
func (rl *LLMRateLimiter) Health(ctx context.Context) error {
	if !rl.config.Enabled {
		return fmt.Errorf("rate limiter is disabled")
	}

	// Check database connectivity
	if _, err := rl.securityRepo.GetRequestLogStats(ctx, domain.RequestLogFilter{Limit: 1}); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	return nil
}

// checkGlobalLimits checks global rate limits
func (rl *LLMRateLimiter) checkGlobalLimits(ctx context.Context, req *LLMRequest) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Reset counters if needed
	if now.Sub(rl.globalLimits.LastMinuteReset) >= time.Minute {
		rl.globalLimits.RequestsThisMinute = 0
		rl.globalLimits.TokensThisMinute = 0
		rl.globalLimits.LastMinuteReset = now
	}

	if now.Sub(rl.globalLimits.LastHourReset) >= time.Hour {
		rl.globalLimits.RequestsThisHour = 0
		rl.globalLimits.TokensThisHour = 0
		rl.globalLimits.LastHourReset = now
	}

	// Check limits
	if rl.config.GlobalRequestsPerMinute > 0 && rl.globalLimits.RequestsThisMinute >= rl.config.GlobalRequestsPerMinute {
		return false
	}

	if rl.config.GlobalRequestsPerHour > 0 && rl.globalLimits.RequestsThisHour >= rl.config.GlobalRequestsPerHour {
		return false
	}

	// Increment counters
	rl.globalLimits.RequestsThisMinute++
	rl.globalLimits.RequestsThisHour++

	return true
}

// checkUserLimits checks user-specific rate limits
func (rl *LLMRateLimiter) checkUserLimits(ctx context.Context, req *LLMRequest) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	userLimit := rl.getUserLimit(*req.UserID)
	rl.resetUserCountersIfNeeded(userLimit)

	// Check limits
	if rl.config.UserRequestsPerMinute > 0 && userLimit.RequestsThisMinute >= rl.config.UserRequestsPerMinute {
		return false
	}

	if rl.config.UserRequestsPerHour > 0 && userLimit.RequestsThisHour >= rl.config.UserRequestsPerHour {
		return false
	}

	if rl.config.UserRequestsPerDay > 0 && userLimit.RequestsThisDay >= rl.config.UserRequestsPerDay {
		return false
	}

	return true
}

// checkProviderLimits checks provider-specific rate limits
func (rl *LLMRateLimiter) checkProviderLimits(ctx context.Context, req *LLMRequest) bool {
	providerLimit, exists := rl.config.ProviderLimits[req.Provider]
	if !exists {
		return true // No limits configured for this provider
	}

	// Use token bucket for provider limits
	bucketKey := fmt.Sprintf("provider:%s", req.Provider)
	bucket := rl.getOrCreateTokenBucket(bucketKey, providerLimit.RequestsPerMinute, time.Minute)

	return bucket.TryConsume(1)
}

// checkModelLimits checks model-specific rate limits
func (rl *LLMRateLimiter) checkModelLimits(ctx context.Context, req *LLMRequest) bool {
	modelLimit, exists := rl.config.ModelLimits[req.Model]
	if !exists {
		return true // No limits configured for this model
	}

	// Use token bucket for model limits
	bucketKey := fmt.Sprintf("model:%s", req.Model)
	bucket := rl.getOrCreateTokenBucket(bucketKey, modelLimit.RequestsPerMinute, time.Minute)

	return bucket.TryConsume(1)
}

// getUserLimit gets or creates a user rate limit tracker
func (rl *LLMRateLimiter) getUserLimit(userID uuid.UUID) *UserRateLimit {
	userLimit, exists := rl.userLimits[userID]
	if !exists {
		now := time.Now()
		userLimit = &UserRateLimit{
			UserID:          userID,
			LastMinuteReset: now,
			LastHourReset:   now,
			LastDayReset:    now,
			LastMonthReset:  now,
		}
		rl.userLimits[userID] = userLimit
	}
	return userLimit
}

// resetUserCountersIfNeeded resets user counters if time windows have passed
func (rl *LLMRateLimiter) resetUserCountersIfNeeded(userLimit *UserRateLimit) {
	now := time.Now()

	if now.Sub(userLimit.LastMinuteReset) >= time.Minute {
		userLimit.RequestsThisMinute = 0
		userLimit.TokensThisMinute = 0
		userLimit.LastMinuteReset = now
	}

	if now.Sub(userLimit.LastHourReset) >= time.Hour {
		userLimit.RequestsThisHour = 0
		userLimit.TokensThisHour = 0
		userLimit.CostThisHour = 0
		userLimit.LastHourReset = now
	}

	if now.Sub(userLimit.LastDayReset) >= 24*time.Hour {
		userLimit.RequestsThisDay = 0
		userLimit.TokensThisDay = 0
		userLimit.CostThisDay = 0
		userLimit.LastDayReset = now
	}

	if now.Sub(userLimit.LastMonthReset) >= 30*24*time.Hour {
		userLimit.CostThisMonth = 0
		userLimit.LastMonthReset = now
	}
}

// updateUserUsage updates user usage counters
func (rl *LLMRateLimiter) updateUserUsage(userLimit *UserRateLimit, requests, tokens int, cost float64) {
	userLimit.RequestsThisMinute += requests
	userLimit.RequestsThisHour += requests
	userLimit.RequestsThisDay += requests
	userLimit.TokensThisMinute += tokens
	userLimit.TokensThisHour += tokens
	userLimit.TokensThisDay += tokens
	userLimit.CostThisHour += cost
	userLimit.CostThisDay += cost
	userLimit.CostThisMonth += cost
}

// getOrCreateTokenBucket gets or creates a token bucket
func (rl *LLMRateLimiter) getOrCreateTokenBucket(key string, capacity int, refillPeriod time.Duration) *TokenBucket {
	rl.bucketMu.Lock()
	defer rl.bucketMu.Unlock()

	bucket, exists := rl.tokenBuckets[key]
	if !exists {
		bucket = &TokenBucket{
			Capacity:     capacity,
			Tokens:       capacity,
			RefillRate:   capacity,
			RefillPeriod: refillPeriod,
			LastRefill:   time.Now(),
		}
		rl.tokenBuckets[key] = bucket
	}

	return bucket
}

// TokenBucket methods

// TryConsume attempts to consume tokens from the bucket
func (tb *TokenBucket) TryConsume(tokens int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.Tokens >= tokens {
		tb.Tokens -= tokens
		return true
	}

	return false
}

// refill refills the token bucket based on elapsed time
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.LastRefill)

	if elapsed >= tb.RefillPeriod {
		periods := int(elapsed / tb.RefillPeriod)
		tokensToAdd := periods * tb.RefillRate

		tb.Tokens += tokensToAdd
		if tb.Tokens > tb.Capacity {
			tb.Tokens = tb.Capacity
		}

		tb.LastRefill = now
	}
}

// GetTokens returns the current number of tokens
func (tb *TokenBucket) GetTokens() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()
	return tb.Tokens
}

// DefaultRateLimiterConfig returns default configuration
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		Enabled:                 true,
		StrictMode:              false,
		GlobalRequestsPerMinute: 1000,
		GlobalRequestsPerHour:   10000,
		GlobalTokensPerMinute:   100000,
		GlobalTokensPerHour:     1000000,
		UserRequestsPerMinute:   60,
		UserRequestsPerHour:     1000,
		UserRequestsPerDay:      10000,
		UserTokensPerMinute:     10000,
		UserTokensPerHour:       100000,
		UserTokensPerDay:        1000000,
		ProviderLimits:          make(map[string]ProviderLimit),
		ModelLimits:             make(map[string]ModelLimit),
		UserCostPerHour:         100.0,
		UserCostPerDay:          500.0,
		UserCostPerMonth:        2000.0,
		AllowBurst:              true,
		BurstMultiplier:         2.0,
		BurstWindowSeconds:      60,
		WindowSize:              time.Hour,
		WindowGranularity:       time.Minute,
	}
}
