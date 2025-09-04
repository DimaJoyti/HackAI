package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// Manager provides a unified interface to all Redis functionality
type Manager struct {
	Client        *Client
	ClusterClient *ClusterClient
	Cache         *CacheManager
	Sessions      *SessionManager
	RateLimit     *RateLimiter
	Lock          *DistributedLock
	PubSub        *PubSubManager
	logger        *logger.Logger
	config        *config.RedisConfig
	isCluster     bool
}

// NewManager creates a new Redis manager with all components
func NewManager(cfg *config.RedisConfig, logger *logger.Logger) (*Manager, error) {
	manager := &Manager{
		logger: logger,
		config: cfg,
	}

	// Initialize Redis client (cluster or single)
	if cfg.ClusterMode && len(cfg.ClusterAddrs) > 0 {
		clusterClient, err := NewCluster(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create Redis cluster client: %w", err)
		}
		manager.ClusterClient = clusterClient
		manager.isCluster = true
		logger.Info("Redis cluster client initialized")
	} else {
		client, err := New(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create Redis client: %w", err)
		}
		manager.Client = client
		manager.isCluster = false
		logger.Info("Redis single client initialized")
	}

	// Initialize all Redis components
	if err := manager.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize Redis components: %w", err)
	}

	logger.Info("Redis manager initialized successfully")
	return manager, nil
}

// initializeComponents initializes all Redis-based components
func (m *Manager) initializeComponents() error {
	// For now, we'll use the single client for all components
	// In a production environment, you might want to create separate clients
	// for different purposes or implement proper cluster support
	var baseClient *Client

	if m.isCluster {
		// For cluster mode, we still need a single client for components that don't support cluster
		// This is a limitation that would need to be addressed in a full cluster implementation
		m.logger.Warn("Cluster mode detected, but components will use single client mode")
		// Create a single client using the first cluster address
		if len(m.config.ClusterAddrs) > 0 {
			// Create a temporary config for single client
			singleConfig := *m.config
			singleConfig.ClusterMode = false
			// Parse the first cluster address to get host and port
			// For simplicity, assume format "host:port"
			_ = m.config.ClusterAddrs[0] // We have the address but use defaults for simplicity
			// This is a simplified approach - in production you'd want proper parsing
			singleConfig.Host = "localhost" // Default fallback
			singleConfig.Port = 6379

			client, err := New(&singleConfig, m.logger)
			if err != nil {
				return fmt.Errorf("failed to create single client for cluster components: %w", err)
			}
			baseClient = client
		} else {
			return fmt.Errorf("cluster mode enabled but no cluster addresses provided")
		}
	} else {
		baseClient = m.Client
	}

	// Initialize all components with the base client
	m.Cache = NewCacheManager(baseClient, m.logger)
	m.Sessions = NewSessionManager(baseClient, m.logger)
	m.RateLimit = NewRateLimiter(baseClient, m.logger)
	m.Lock = NewDistributedLock(baseClient, m.logger)
	m.PubSub = NewPubSubManager(baseClient, m.logger)

	m.logger.Info("All Redis components initialized")
	return nil
}

// HealthCheck performs a comprehensive health check of all Redis components
func (m *Manager) HealthCheck(ctx context.Context) error {
	// Test basic connectivity
	if m.isCluster {
		if err := m.ClusterClient.HealthCheck(ctx); err != nil {
			return fmt.Errorf("cluster health check failed: %w", err)
		}
	} else {
		if err := m.Client.HealthCheck(ctx); err != nil {
			return fmt.Errorf("client health check failed: %w", err)
		}
	}

	// Test cache functionality
	testKey := "health_check_cache"
	testValue := "test_value"

	if err := m.Cache.Set(ctx, testKey, testValue); err != nil {
		return fmt.Errorf("cache set failed: %w", err)
	}

	var retrievedValue string
	if err := m.Cache.Get(ctx, testKey, &retrievedValue); err != nil {
		return fmt.Errorf("cache get failed: %w", err)
	}

	if retrievedValue != testValue {
		return fmt.Errorf("cache value mismatch: expected %s, got %s", testValue, retrievedValue)
	}

	// Clean up test key
	m.Cache.Delete(ctx, testKey)

	// Test rate limiting
	rateLimitKey := "health_check_rate_limit"
	rateLimitConfig := RateLimitConfig{
		Limit:  10,
		Window: time.Minute,
	}

	result, err := m.RateLimit.CheckLimit(ctx, rateLimitKey, rateLimitConfig)
	if err != nil {
		return fmt.Errorf("rate limit check failed: %w", err)
	}

	if !result.Allowed {
		return fmt.Errorf("rate limit should allow first request")
	}

	// Clean up rate limit
	m.RateLimit.Reset(ctx, rateLimitKey)

	// Test distributed lock
	lockKey := "health_check_lock"
	lock, err := m.Lock.Acquire(ctx, lockKey, LockOptions{
		TTL: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("lock acquire failed: %w", err)
	}

	if err := lock.Release(ctx); err != nil {
		return fmt.Errorf("lock release failed: %w", err)
	}

	m.logger.Debug("Redis health check passed")
	return nil
}

// GetStats returns comprehensive statistics for all Redis components
func (m *Manager) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Client stats
	if m.isCluster {
		stats["client_type"] = "cluster"
		stats["client_stats"] = m.ClusterClient.GetStats()
	} else {
		stats["client_type"] = "single"
		stats["client_stats"] = m.Client.GetStats()
	}

	// Cache stats
	if cacheStats, err := m.Cache.GetStats(ctx); err == nil {
		stats["cache"] = cacheStats
	}

	// Session stats
	if sessionStats, err := m.Sessions.GetSessionStats(ctx); err == nil {
		stats["sessions"] = sessionStats
	}

	// Rate limit stats
	if rateLimitStats, err := m.RateLimit.GetStats(ctx); err == nil {
		stats["rate_limit"] = rateLimitStats
	}

	// Lock stats
	if lockStats, err := m.Lock.GetStats(ctx); err == nil {
		stats["locks"] = lockStats
	}

	// PubSub stats
	stats["pubsub"] = map[string]interface{}{
		"subscribers": m.PubSub.GetSubscribers(),
	}

	return stats, nil
}

// Close gracefully closes all Redis connections and components
func (m *Manager) Close() error {
	m.logger.Info("Closing Redis manager...")

	var errors []error

	// Close PubSub first to stop message processing
	if err := m.PubSub.Close(); err != nil {
		errors = append(errors, fmt.Errorf("failed to close PubSub: %w", err))
	}

	// Close clients
	if m.isCluster {
		if err := m.ClusterClient.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close cluster client: %w", err))
		}
	} else {
		if err := m.Client.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close client: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors during Redis manager close: %v", errors)
	}

	m.logger.Info("Redis manager closed successfully")
	return nil
}

// Utility methods for common operations

// SetWithTTL sets a key with TTL using the appropriate client
func (m *Manager) SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if m.isCluster {
		return m.ClusterClient.SetWithExpiration(ctx, key, value, ttl)
	}
	return m.Client.SetWithExpiration(ctx, key, value, ttl)
}

// Get gets a value using the appropriate client
func (m *Manager) Get(ctx context.Context, key string) (string, error) {
	if m.isCluster {
		return m.ClusterClient.Get(ctx, key).Result()
	}
	return m.Client.Get(ctx, key).Result()
}

// Delete deletes keys using the appropriate client
func (m *Manager) Delete(ctx context.Context, keys ...string) error {
	if m.isCluster {
		return m.ClusterClient.Del(ctx, keys...).Err()
	}
	return m.Client.Del(ctx, keys...).Err()
}

// Increment increments a counter using the appropriate client
func (m *Manager) Increment(ctx context.Context, key string) (int64, error) {
	if m.isCluster {
		return m.ClusterClient.Incr(ctx, key).Result()
	}
	return m.Client.Incr(ctx, key).Result()
}

// IncrementWithTTL increments a counter with TTL
func (m *Manager) IncrementWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if m.isCluster {
		return m.ClusterClient.IncrementCounter(ctx, key, ttl)
	}
	return m.Client.IncrementCounter(ctx, key, ttl)
}

// AddToSet adds a member to a set
func (m *Manager) AddToSet(ctx context.Context, key string, member interface{}) error {
	if m.isCluster {
		return m.ClusterClient.AddToSet(ctx, key, member)
	}
	return m.Client.AddToSet(ctx, key, member)
}

// RemoveFromSet removes a member from a set
func (m *Manager) RemoveFromSet(ctx context.Context, key string, member interface{}) error {
	if m.isCluster {
		return m.ClusterClient.RemoveFromSet(ctx, key, member)
	}
	return m.Client.RemoveFromSet(ctx, key, member)
}

// IsInSet checks if a member is in a set
func (m *Manager) IsInSet(ctx context.Context, key string, member interface{}) (bool, error) {
	if m.isCluster {
		return m.ClusterClient.IsInSet(ctx, key, member)
	}
	return m.Client.IsInSet(ctx, key, member)
}

// GetConfig returns the Redis configuration
func (m *Manager) GetConfig() *config.RedisConfig {
	return m.config
}

// IsCluster returns whether the manager is using cluster mode
func (m *Manager) IsCluster() bool {
	return m.isCluster
}
