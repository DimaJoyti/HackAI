package redis

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// RateLimiter provides Redis-based rate limiting
type RateLimiter struct {
	client *Client
	logger *logger.Logger
	prefix string
}

// RateLimitResult represents the result of a rate limit check
type RateLimitResult struct {
	Allowed       bool          `json:"allowed"`
	Limit         int64         `json:"limit"`
	Remaining     int64         `json:"remaining"`
	ResetTime     time.Time     `json:"reset_time"`
	RetryAfter    time.Duration `json:"retry_after"`
	TotalRequests int64         `json:"total_requests"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Limit    int64         `json:"limit"`    // Number of requests allowed
	Window   time.Duration `json:"window"`   // Time window
	Burst    int64         `json:"burst"`    // Burst allowance (optional)
	Strategy string        `json:"strategy"` // "fixed_window", "sliding_window", "token_bucket"
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(client *Client, logger *logger.Logger) *RateLimiter {
	return &RateLimiter{
		client: client,
		logger: logger,
		prefix: "ratelimit:",
	}
}

// SetPrefix sets the rate limit key prefix
func (rl *RateLimiter) SetPrefix(prefix string) {
	rl.prefix = prefix
}

// CheckLimit checks if a request is allowed under the rate limit
func (rl *RateLimiter) CheckLimit(ctx context.Context, key string, config RateLimitConfig) (*RateLimitResult, error) {
	switch config.Strategy {
	case "sliding_window":
		return rl.checkSlidingWindow(ctx, key, config)
	case "token_bucket":
		return rl.checkTokenBucket(ctx, key, config)
	default: // "fixed_window"
		return rl.checkFixedWindow(ctx, key, config)
	}
}

// checkFixedWindow implements fixed window rate limiting
func (rl *RateLimiter) checkFixedWindow(ctx context.Context, key string, config RateLimitConfig) (*RateLimitResult, error) {
	now := time.Now()
	window := int64(config.Window.Seconds())
	windowStart := now.Unix() / window * window

	rateLimitKey := fmt.Sprintf("%s%s:%d", rl.prefix, key, windowStart)

	// Lua script for atomic increment and expiration
	luaScript := `
		local key = KEYS[1]
		local limit = tonumber(ARGV[1])
		local window = tonumber(ARGV[2])
		
		local current = redis.call('GET', key)
		if current == false then
			current = 0
		else
			current = tonumber(current)
		end
		
		if current < limit then
			local new_val = redis.call('INCR', key)
			if new_val == 1 then
				redis.call('EXPIRE', key, window)
			end
			return {1, new_val, limit - new_val}
		else
			return {0, current, 0}
		end
	`

	result, err := rl.client.Eval(ctx, luaScript, []string{rateLimitKey}, config.Limit, window).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to execute rate limit script: %w", err)
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 3 {
		return nil, fmt.Errorf("unexpected script result format")
	}

	allowed := resultSlice[0].(int64) == 1
	totalRequests := resultSlice[1].(int64)
	remaining := resultSlice[2].(int64)

	resetTime := time.Unix(windowStart+window, 0)
	retryAfter := time.Duration(0)
	if !allowed {
		retryAfter = resetTime.Sub(now)
	}

	return &RateLimitResult{
		Allowed:       allowed,
		Limit:         config.Limit,
		Remaining:     remaining,
		ResetTime:     resetTime,
		RetryAfter:    retryAfter,
		TotalRequests: totalRequests,
	}, nil
}

// checkSlidingWindow implements sliding window rate limiting
func (rl *RateLimiter) checkSlidingWindow(ctx context.Context, key string, config RateLimitConfig) (*RateLimitResult, error) {
	now := time.Now()
	windowStart := now.Add(-config.Window)

	rateLimitKey := fmt.Sprintf("%s%s:sliding", rl.prefix, key)

	// Lua script for sliding window
	luaScript := `
		local key = KEYS[1]
		local limit = tonumber(ARGV[1])
		local window_start = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])
		
		-- Remove old entries
		redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
		
		-- Count current entries
		local current = redis.call('ZCARD', key)
		
		if current < limit then
			-- Add current request
			redis.call('ZADD', key, now, now)
			redis.call('EXPIRE', key, math.ceil(tonumber(ARGV[4])))
			return {1, current + 1, limit - current - 1}
		else
			return {0, current, 0}
		end
	`

	result, err := rl.client.Eval(ctx, luaScript, []string{rateLimitKey},
		config.Limit, windowStart.Unix(), now.Unix(), config.Window.Seconds()).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to execute sliding window script: %w", err)
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 3 {
		return nil, fmt.Errorf("unexpected script result format")
	}

	allowed := resultSlice[0].(int64) == 1
	totalRequests := resultSlice[1].(int64)
	remaining := resultSlice[2].(int64)

	resetTime := now.Add(config.Window)
	retryAfter := time.Duration(0)
	if !allowed {
		// For sliding window, retry after is estimated
		retryAfter = config.Window / time.Duration(config.Limit)
	}

	return &RateLimitResult{
		Allowed:       allowed,
		Limit:         config.Limit,
		Remaining:     remaining,
		ResetTime:     resetTime,
		RetryAfter:    retryAfter,
		TotalRequests: totalRequests,
	}, nil
}

// checkTokenBucket implements token bucket rate limiting
func (rl *RateLimiter) checkTokenBucket(ctx context.Context, key string, config RateLimitConfig) (*RateLimitResult, error) {
	now := time.Now()
	rateLimitKey := fmt.Sprintf("%s%s:bucket", rl.prefix, key)

	// Token bucket parameters
	capacity := config.Limit
	if config.Burst > 0 {
		capacity = config.Burst
	}
	refillRate := float64(config.Limit) / config.Window.Seconds() // tokens per second

	// Lua script for token bucket
	luaScript := `
		local key = KEYS[1]
		local capacity = tonumber(ARGV[1])
		local refill_rate = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])
		local tokens_requested = tonumber(ARGV[4])
		
		local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
		local tokens = tonumber(bucket[1]) or capacity
		local last_refill = tonumber(bucket[2]) or now
		
		-- Calculate tokens to add based on time elapsed
		local time_elapsed = now - last_refill
		local tokens_to_add = time_elapsed * refill_rate
		tokens = math.min(capacity, tokens + tokens_to_add)
		
		if tokens >= tokens_requested then
			tokens = tokens - tokens_requested
			redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
			redis.call('EXPIRE', key, math.ceil(capacity / refill_rate * 2))
			return {1, tokens, capacity}
		else
			redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
			redis.call('EXPIRE', key, math.ceil(capacity / refill_rate * 2))
			return {0, tokens, capacity}
		end
	`

	result, err := rl.client.Eval(ctx, luaScript, []string{rateLimitKey},
		capacity, refillRate, now.Unix(), 1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to execute token bucket script: %w", err)
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 3 {
		return nil, fmt.Errorf("unexpected script result format")
	}

	allowed := resultSlice[0].(int64) == 1
	tokensRemaining := resultSlice[1].(int64)
	totalCapacity := resultSlice[2].(int64)

	retryAfter := time.Duration(0)
	if !allowed {
		// Calculate time needed to get one token
		retryAfter = time.Duration(1.0/refillRate) * time.Second
	}

	return &RateLimitResult{
		Allowed:       allowed,
		Limit:         config.Limit,
		Remaining:     tokensRemaining,
		ResetTime:     now.Add(time.Duration(float64(totalCapacity-tokensRemaining)/refillRate) * time.Second),
		RetryAfter:    retryAfter,
		TotalRequests: totalCapacity - tokensRemaining,
	}, nil
}

// Reset resets the rate limit for a key
func (rl *RateLimiter) Reset(ctx context.Context, key string) error {
	pattern := fmt.Sprintf("%s%s*", rl.prefix, key)
	keys, err := rl.client.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to find rate limit keys: %w", err)
	}

	if len(keys) > 0 {
		if err := rl.client.Del(ctx, keys...).Err(); err != nil {
			return fmt.Errorf("failed to reset rate limit: %w", err)
		}
	}

	rl.logger.Debugf("Rate limit reset for key: %s", key)
	return nil
}

// GetStatus returns the current status of a rate limit
func (rl *RateLimiter) GetStatus(ctx context.Context, key string, config RateLimitConfig) (*RateLimitResult, error) {
	// This is similar to CheckLimit but doesn't increment the counter
	switch config.Strategy {
	case "sliding_window":
		return rl.getStatusSlidingWindow(ctx, key, config)
	case "token_bucket":
		return rl.getStatusTokenBucket(ctx, key, config)
	default: // "fixed_window"
		return rl.getStatusFixedWindow(ctx, key, config)
	}
}

func (rl *RateLimiter) getStatusFixedWindow(ctx context.Context, key string, config RateLimitConfig) (*RateLimitResult, error) {
	now := time.Now()
	window := int64(config.Window.Seconds())
	windowStart := now.Unix() / window * window

	rateLimitKey := fmt.Sprintf("%s%s:%d", rl.prefix, key, windowStart)

	current, err := rl.client.Get(ctx, rateLimitKey).Result()
	if err != nil {
		if err == redis.Nil {
			current = "0"
		} else {
			return nil, fmt.Errorf("failed to get rate limit status: %w", err)
		}
	}

	totalRequests, _ := strconv.ParseInt(current, 10, 64)
	remaining := config.Limit - totalRequests
	if remaining < 0 {
		remaining = 0
	}

	resetTime := time.Unix(windowStart+window, 0)

	return &RateLimitResult{
		Allowed:       remaining > 0,
		Limit:         config.Limit,
		Remaining:     remaining,
		ResetTime:     resetTime,
		RetryAfter:    resetTime.Sub(now),
		TotalRequests: totalRequests,
	}, nil
}

func (rl *RateLimiter) getStatusSlidingWindow(ctx context.Context, key string, config RateLimitConfig) (*RateLimitResult, error) {
	now := time.Now()
	windowStart := now.Add(-config.Window)

	rateLimitKey := fmt.Sprintf("%s%s:sliding", rl.prefix, key)

	// Count entries in the current window
	count, err := rl.client.ZCount(ctx, rateLimitKey, fmt.Sprintf("%d", windowStart.Unix()), "+inf").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to count sliding window entries: %w", err)
	}

	remaining := config.Limit - count
	if remaining < 0 {
		remaining = 0
	}

	return &RateLimitResult{
		Allowed:       remaining > 0,
		Limit:         config.Limit,
		Remaining:     remaining,
		ResetTime:     now.Add(config.Window),
		RetryAfter:    config.Window / time.Duration(config.Limit),
		TotalRequests: count,
	}, nil
}

func (rl *RateLimiter) getStatusTokenBucket(ctx context.Context, key string, config RateLimitConfig) (*RateLimitResult, error) {
	now := time.Now()
	rateLimitKey := fmt.Sprintf("%s%s:bucket", rl.prefix, key)

	capacity := config.Limit
	if config.Burst > 0 {
		capacity = config.Burst
	}
	refillRate := float64(config.Limit) / config.Window.Seconds()

	bucket, err := rl.client.HMGet(ctx, rateLimitKey, "tokens", "last_refill").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get token bucket status: %w", err)
	}

	tokens := capacity
	lastRefill := now.Unix()

	if bucket[0] != nil {
		if t, err := strconv.ParseFloat(bucket[0].(string), 64); err == nil {
			tokens = int64(t)
		}
	}

	if bucket[1] != nil {
		if t, err := strconv.ParseInt(bucket[1].(string), 10, 64); err == nil {
			lastRefill = t
		}
	}

	// Calculate current tokens
	timeElapsed := float64(now.Unix() - lastRefill)
	tokensToAdd := timeElapsed * refillRate
	currentTokens := int64(math.Min(float64(capacity), float64(tokens)+tokensToAdd))

	return &RateLimitResult{
		Allowed:       currentTokens > 0,
		Limit:         config.Limit,
		Remaining:     currentTokens,
		ResetTime:     now.Add(time.Duration(float64(capacity-currentTokens)/refillRate) * time.Second),
		RetryAfter:    time.Duration(1.0/refillRate) * time.Second,
		TotalRequests: capacity - currentTokens,
	}, nil
}

// GetStats returns rate limiting statistics
func (rl *RateLimiter) GetStats(ctx context.Context) (map[string]interface{}, error) {
	pattern := rl.prefix + "*"
	keys, err := rl.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get rate limit keys: %w", err)
	}

	stats := map[string]interface{}{
		"total_rate_limits": len(keys),
		"prefix":            rl.prefix,
	}

	return stats, nil
}
