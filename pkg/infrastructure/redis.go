package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var redisTracer = otel.Tracer("hackai/infrastructure/redis")

// RedisClient wraps redis.Client with additional functionality
type RedisClient struct {
	client *redis.Client
	config *config.RedisConfig
	logger *logger.Logger
}

// NewRedisClient creates a new Redis client
func NewRedisClient(cfg *config.RedisConfig, logger *logger.Logger) (*RedisClient, error) {
	// Create Redis options
	opts := &redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info("Redis connection established successfully",
		"host", cfg.Host,
		"port", cfg.Port,
		"db", cfg.DB,
	)

	return &RedisClient{
		client: client,
		config: cfg,
		logger: logger,
	}, nil
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// Health checks Redis health
func (r *RedisClient) Health(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// LLMCache provides caching functionality for LLM operations
type LLMCache struct {
	redis  *RedisClient
	prefix string
	ttl    time.Duration
}

// NewLLMCache creates a new LLM cache
func NewLLMCache(redis *RedisClient, prefix string, ttl time.Duration) *LLMCache {
	return &LLMCache{
		redis:  redis,
		prefix: prefix,
		ttl:    ttl,
	}
}

// CacheKey generates a cache key with prefix
func (c *LLMCache) CacheKey(key string) string {
	return fmt.Sprintf("%s:%s", c.prefix, key)
}

// Set stores a value in cache
func (c *LLMCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	ctx, span := redisTracer.Start(ctx, "llm_cache.set",
		trace.WithAttributes(
			attribute.String("cache.key", key),
			attribute.String("cache.ttl", ttl.String()),
		),
	)
	defer span.End()

	data, err := json.Marshal(value)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	if ttl == 0 {
		ttl = c.ttl
	}

	err = c.redis.client.Set(ctx, c.CacheKey(key), data, ttl).Err()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to set cache value: %w", err)
	}

	span.SetAttributes(
		attribute.Int("cache.size", len(data)),
		attribute.Bool("success", true),
	)

	return nil
}

// Get retrieves a value from cache
func (c *LLMCache) Get(ctx context.Context, key string, dest interface{}) error {
	ctx, span := redisTracer.Start(ctx, "llm_cache.get",
		trace.WithAttributes(
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	data, err := c.redis.client.Get(ctx, c.CacheKey(key)).Result()
	if err != nil {
		if err == redis.Nil {
			span.SetAttributes(attribute.Bool("cache.hit", false))
			return ErrCacheMiss
		}
		span.RecordError(err)
		return fmt.Errorf("failed to get cache value: %w", err)
	}

	if err := json.Unmarshal([]byte(data), dest); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("cache.hit", true),
		attribute.Int("cache.size", len(data)),
	)

	return nil
}

// Delete removes a value from cache
func (c *LLMCache) Delete(ctx context.Context, key string) error {
	ctx, span := redisTracer.Start(ctx, "llm_cache.delete",
		trace.WithAttributes(
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	err := c.redis.client.Del(ctx, c.CacheKey(key)).Err()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to delete cache value: %w", err)
	}

	return nil
}

// Exists checks if a key exists in cache
func (c *LLMCache) Exists(ctx context.Context, key string) (bool, error) {
	ctx, span := redisTracer.Start(ctx, "llm_cache.exists",
		trace.WithAttributes(
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	count, err := c.redis.client.Exists(ctx, c.CacheKey(key)).Result()
	if err != nil {
		span.RecordError(err)
		return false, fmt.Errorf("failed to check cache existence: %w", err)
	}

	exists := count > 0
	span.SetAttributes(attribute.Bool("cache.exists", exists))

	return exists, nil
}

// SetNX sets a value only if the key doesn't exist (atomic)
func (c *LLMCache) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	ctx, span := redisTracer.Start(ctx, "llm_cache.setnx",
		trace.WithAttributes(
			attribute.String("cache.key", key),
			attribute.String("cache.ttl", ttl.String()),
		),
	)
	defer span.End()

	data, err := json.Marshal(value)
	if err != nil {
		span.RecordError(err)
		return false, fmt.Errorf("failed to marshal value: %w", err)
	}

	if ttl == 0 {
		ttl = c.ttl
	}

	success, err := c.redis.client.SetNX(ctx, c.CacheKey(key), data, ttl).Result()
	if err != nil {
		span.RecordError(err)
		return false, fmt.Errorf("failed to set cache value: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("cache.set", success),
		attribute.Int("cache.size", len(data)),
	)

	return success, nil
}

// SessionManager manages user sessions using Redis
type SessionManager struct {
	redis      *RedisClient
	prefix     string
	sessionTTL time.Duration
}

// NewSessionManager creates a new session manager
func NewSessionManager(redis *RedisClient, prefix string, sessionTTL time.Duration) *SessionManager {
	return &SessionManager{
		redis:      redis,
		prefix:     prefix,
		sessionTTL: sessionTTL,
	}
}

// SessionData represents session data
type SessionData struct {
	UserID    string                 `json:"user_id"`
	Username  string                 `json:"username"`
	Email     string                 `json:"email"`
	Roles     []string               `json:"roles"`
	CreatedAt time.Time              `json:"created_at"`
	LastSeen  time.Time              `json:"last_seen"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// CreateSession creates a new session
func (sm *SessionManager) CreateSession(ctx context.Context, sessionID string, data *SessionData) error {
	ctx, span := redisTracer.Start(ctx, "session_manager.create",
		trace.WithAttributes(
			attribute.String("session.id", sessionID),
			attribute.String("user.id", data.UserID),
		),
	)
	defer span.End()

	data.CreatedAt = time.Now()
	data.LastSeen = time.Now()

	sessionData, err := json.Marshal(data)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	key := fmt.Sprintf("%s:session:%s", sm.prefix, sessionID)
	err = sm.redis.client.Set(ctx, key, sessionData, sm.sessionTTL).Err()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetSession retrieves session data
func (sm *SessionManager) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	ctx, span := redisTracer.Start(ctx, "session_manager.get",
		trace.WithAttributes(
			attribute.String("session.id", sessionID),
		),
	)
	defer span.End()

	key := fmt.Sprintf("%s:session:%s", sm.prefix, sessionID)
	data, err := sm.redis.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			span.SetAttributes(attribute.Bool("session.found", false))
			return nil, ErrSessionNotFound
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var sessionData SessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	// Update last seen and extend TTL
	sessionData.LastSeen = time.Now()
	if err := sm.UpdateSession(ctx, sessionID, &sessionData); err != nil {
		sm.redis.logger.Error("Failed to update session last seen", "error", err)
	}

	span.SetAttributes(
		attribute.Bool("session.found", true),
		attribute.String("user.id", sessionData.UserID),
	)

	return &sessionData, nil
}

// UpdateSession updates session data
func (sm *SessionManager) UpdateSession(ctx context.Context, sessionID string, data *SessionData) error {
	ctx, span := redisTracer.Start(ctx, "session_manager.update",
		trace.WithAttributes(
			attribute.String("session.id", sessionID),
			attribute.String("user.id", data.UserID),
		),
	)
	defer span.End()

	data.LastSeen = time.Now()

	sessionData, err := json.Marshal(data)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	key := fmt.Sprintf("%s:session:%s", sm.prefix, sessionID)
	err = sm.redis.client.Set(ctx, key, sessionData, sm.sessionTTL).Err()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

// DeleteSession deletes a session
func (sm *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	ctx, span := redisTracer.Start(ctx, "session_manager.delete",
		trace.WithAttributes(
			attribute.String("session.id", sessionID),
		),
	)
	defer span.End()

	key := fmt.Sprintf("%s:session:%s", sm.prefix, sessionID)
	err := sm.redis.client.Del(ctx, key).Err()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

// RedisHealthChecker checks Redis health
type RedisHealthChecker struct {
	redis  *RedisClient
	logger *logger.Logger
}

// NewRedisHealthChecker creates a new Redis health checker
func NewRedisHealthChecker(redis *RedisClient, logger *logger.Logger) *RedisHealthChecker {
	return &RedisHealthChecker{
		redis:  redis,
		logger: logger,
	}
}

// Name returns the checker name
func (c *RedisHealthChecker) Name() string {
	return "redis"
}

// Check performs the Redis health check
func (c *RedisHealthChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()

	// Ping Redis
	if err := c.redis.Health(ctx); err != nil {
		return ComponentHealth{
			Name:        c.Name(),
			Status:      HealthStatusUnhealthy,
			Message:     fmt.Sprintf("Redis ping failed: %v", err),
			LastChecked: time.Now(),
			Duration:    time.Since(start),
		}
	}

	// Get Redis info
	info, err := c.redis.client.Info(ctx, "memory", "stats").Result()
	if err != nil {
		return ComponentHealth{
			Name:        c.Name(),
			Status:      HealthStatusDegraded,
			Message:     fmt.Sprintf("Failed to get Redis info: %v", err),
			LastChecked: time.Now(),
			Duration:    time.Since(start),
		}
	}

	metadata := map[string]interface{}{
		"info": info,
	}

	return ComponentHealth{
		Name:        c.Name(),
		Status:      HealthStatusHealthy,
		Message:     "Redis is healthy",
		LastChecked: time.Now(),
		Duration:    time.Since(start),
		Metadata:    metadata,
	}
}

// Publish publishes a message to a Redis channel
func (r *RedisClient) Publish(ctx context.Context, channel string, message interface{}) error {
	ctx, span := redisTracer.Start(ctx, "redis_publish")
	defer span.End()

	span.SetAttributes(
		attribute.String("channel", channel),
	)

	var data string
	switch v := message.(type) {
	case string:
		data = v
	case []byte:
		data = string(v)
	default:
		jsonData, err := json.Marshal(message)
		if err != nil {
			span.RecordError(err)
			return fmt.Errorf("failed to marshal message: %w", err)
		}
		data = string(jsonData)
	}

	result := r.client.Publish(ctx, channel, data)
	if err := result.Err(); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to publish message: %w", err)
	}

	span.SetAttributes(
		attribute.Int64("subscribers", result.Val()),
	)

	return nil
}

// Subscribe subscribes to Redis channels
func (r *RedisClient) Subscribe(ctx context.Context, channels ...string) *redis.PubSub {
	return r.client.Subscribe(ctx, channels...)
}

// Common errors
var (
	ErrCacheMiss       = fmt.Errorf("cache miss")
	ErrSessionNotFound = fmt.Errorf("session not found")
)
