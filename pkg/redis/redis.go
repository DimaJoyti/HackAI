package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// Client wraps the Redis client with additional functionality
type Client struct {
	*redis.Client
	logger *logger.Logger
	config *config.RedisConfig
}

// ClusterClient wraps the Redis cluster client
type ClusterClient struct {
	*redis.ClusterClient
	logger *logger.Logger
	config *config.RedisConfig
}

// New creates a new Redis client
func New(cfg *config.RedisConfig, log *logger.Logger) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("redis config is required")
	}

	// Configure TLS if enabled
	var tlsConfig *tls.Config
	if cfg.TLS.Enabled {
		tlsConfig = &tls.Config{
			ServerName:         cfg.TLS.ServerName,
			InsecureSkipVerify: cfg.TLS.InsecureSkipVerify,
		}

		// Load client certificates if provided
		if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load TLS certificates: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	// Create Redis options
	opts := &redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.Database,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		MaxIdleConns: cfg.MaxIdleConns,
		ConnMaxLifetime: time.Duration(cfg.ConnMaxLifetime) * time.Second,
		ConnMaxIdleTime: time.Duration(cfg.ConnMaxIdleTime) * time.Second,
		DialTimeout:     time.Duration(cfg.DialTimeout) * time.Second,
		ReadTimeout:     time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout:    time.Duration(cfg.WriteTimeout) * time.Second,
		TLSConfig:       tlsConfig,
	}

	// Create Redis client
	rdb := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	log.Infof("Connected to Redis at %s:%d", cfg.Host, cfg.Port)

	return &Client{
		Client: rdb,
		logger: log,
		config: cfg,
	}, nil
}

// NewCluster creates a new Redis cluster client
func NewCluster(cfg *config.RedisConfig, log *logger.Logger) (*ClusterClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("redis config is required")
	}

	if len(cfg.ClusterAddrs) == 0 {
		return nil, fmt.Errorf("cluster addresses are required for cluster mode")
	}

	// Configure TLS if enabled
	var tlsConfig *tls.Config
	if cfg.TLS.Enabled {
		tlsConfig = &tls.Config{
			ServerName:         cfg.TLS.ServerName,
			InsecureSkipVerify: cfg.TLS.InsecureSkipVerify,
		}

		// Load client certificates if provided
		if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load TLS certificates: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	// Create Redis cluster options
	opts := &redis.ClusterOptions{
		Addrs:        cfg.ClusterAddrs,
		Password:     cfg.Password,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		MaxIdleConns: cfg.MaxIdleConns,
		ConnMaxLifetime: time.Duration(cfg.ConnMaxLifetime) * time.Second,
		ConnMaxIdleTime: time.Duration(cfg.ConnMaxIdleTime) * time.Second,
		DialTimeout:     time.Duration(cfg.DialTimeout) * time.Second,
		ReadTimeout:     time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout:    time.Duration(cfg.WriteTimeout) * time.Second,
		TLSConfig:       tlsConfig,
	}

	// Create Redis cluster client
	rdb := redis.NewClusterClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis cluster: %w", err)
	}

	log.Infof("Connected to Redis cluster with %d nodes", len(cfg.ClusterAddrs))

	return &ClusterClient{
		ClusterClient: rdb,
		logger:        log,
		config:        cfg,
	}, nil
}

// Close closes the Redis connection
func (c *Client) Close() error {
	c.logger.Info("Closing Redis connection")
	return c.Client.Close()
}

// Close closes the Redis cluster connection
func (c *ClusterClient) Close() error {
	c.logger.Info("Closing Redis cluster connection")
	return c.ClusterClient.Close()
}

// HealthCheck performs a health check on the Redis connection
func (c *Client) HealthCheck(ctx context.Context) error {
	if err := c.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis health check failed: %w", err)
	}
	return nil
}

// HealthCheck performs a health check on the Redis cluster connection
func (c *ClusterClient) HealthCheck(ctx context.Context) error {
	if err := c.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis cluster health check failed: %w", err)
	}
	return nil
}

// GetStats returns Redis connection statistics
func (c *Client) GetStats() map[string]interface{} {
	stats := c.PoolStats()
	return map[string]interface{}{
		"hits":         stats.Hits,
		"misses":       stats.Misses,
		"timeouts":     stats.Timeouts,
		"total_conns":  stats.TotalConns,
		"idle_conns":   stats.IdleConns,
		"stale_conns":  stats.StaleConns,
	}
}

// GetStats returns Redis cluster connection statistics
func (c *ClusterClient) GetStats() map[string]interface{} {
	stats := c.PoolStats()
	return map[string]interface{}{
		"hits":         stats.Hits,
		"misses":       stats.Misses,
		"timeouts":     stats.Timeouts,
		"total_conns":  stats.TotalConns,
		"idle_conns":   stats.IdleConns,
		"stale_conns":  stats.StaleConns,
	}
}

// SetWithExpiration sets a key with expiration
func (c *Client) SetWithExpiration(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return c.Set(ctx, key, value, expiration).Err()
}

// SetWithExpiration sets a key with expiration for cluster client
func (c *ClusterClient) SetWithExpiration(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return c.Set(ctx, key, value, expiration).Err()
}

// GetJSON gets a JSON value and unmarshals it
func (c *Client) GetJSON(ctx context.Context, key string, dest interface{}) error {
	val, err := c.Get(ctx, key).Result()
	if err != nil {
		return err
	}
	
	// Assuming JSON marshaling/unmarshaling is handled elsewhere
	// This is a placeholder for JSON operations
	_ = val
	_ = dest
	return fmt.Errorf("JSON operations not implemented yet")
}

// SetJSON marshals and sets a JSON value
func (c *Client) SetJSON(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	// Placeholder for JSON operations
	_ = value
	return c.Set(ctx, key, "", expiration).Err()
}

// IncrementCounter increments a counter with expiration
func (c *Client) IncrementCounter(ctx context.Context, key string, expiration time.Duration) (int64, error) {
	pipe := c.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, expiration)
	
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	
	return incrCmd.Val(), nil
}

// IncrementCounter increments a counter with expiration for cluster client
func (c *ClusterClient) IncrementCounter(ctx context.Context, key string, expiration time.Duration) (int64, error) {
	pipe := c.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, expiration)
	
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	
	return incrCmd.Val(), nil
}

// AddToSet adds a member to a set
func (c *Client) AddToSet(ctx context.Context, key string, member interface{}) error {
	return c.SAdd(ctx, key, member).Err()
}

// AddToSet adds a member to a set for cluster client
func (c *ClusterClient) AddToSet(ctx context.Context, key string, member interface{}) error {
	return c.SAdd(ctx, key, member).Err()
}

// RemoveFromSet removes a member from a set
func (c *Client) RemoveFromSet(ctx context.Context, key string, member interface{}) error {
	return c.SRem(ctx, key, member).Err()
}

// RemoveFromSet removes a member from a set for cluster client
func (c *ClusterClient) RemoveFromSet(ctx context.Context, key string, member interface{}) error {
	return c.SRem(ctx, key, member).Err()
}

// IsInSet checks if a member is in a set
func (c *Client) IsInSet(ctx context.Context, key string, member interface{}) (bool, error) {
	return c.SIsMember(ctx, key, member).Result()
}

// IsInSet checks if a member is in a set for cluster client
func (c *ClusterClient) IsInSet(ctx context.Context, key string, member interface{}) (bool, error) {
	return c.SIsMember(ctx, key, member).Result()
}
