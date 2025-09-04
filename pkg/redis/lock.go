package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// DistributedLock provides Redis-based distributed locking
type DistributedLock struct {
	client *Client
	logger *logger.Logger
	prefix string
}

// Lock represents a distributed lock
type Lock struct {
	key        string
	value      string
	ttl        time.Duration
	client     *Client
	logger     *logger.Logger
	acquired   bool
	renewStop  chan struct{}
	autoRenew  bool
}

// LockOptions represents lock configuration options
type LockOptions struct {
	TTL       time.Duration `json:"ttl"`        // Lock expiration time
	Retry     bool          `json:"retry"`      // Whether to retry acquiring the lock
	RetryDelay time.Duration `json:"retry_delay"` // Delay between retry attempts
	MaxRetries int           `json:"max_retries"` // Maximum number of retry attempts
	AutoRenew  bool          `json:"auto_renew"`  // Automatically renew the lock before expiration
}

// NewDistributedLock creates a new distributed lock manager
func NewDistributedLock(client *Client, logger *logger.Logger) *DistributedLock {
	return &DistributedLock{
		client: client,
		logger: logger,
		prefix: "lock:",
	}
}

// SetPrefix sets the lock key prefix
func (dl *DistributedLock) SetPrefix(prefix string) {
	dl.prefix = prefix
}

// Acquire attempts to acquire a distributed lock
func (dl *DistributedLock) Acquire(ctx context.Context, key string, options ...LockOptions) (*Lock, error) {
	opts := dl.mergeOptions(options...)
	lockKey := dl.prefix + key
	lockValue := dl.generateLockValue()
	
	lock := &Lock{
		key:       lockKey,
		value:     lockValue,
		ttl:       opts.TTL,
		client:    dl.client,
		logger:    dl.logger,
		acquired:  false,
		renewStop: make(chan struct{}),
		autoRenew: opts.AutoRenew,
	}
	
	// Try to acquire the lock
	acquired, err := dl.tryAcquire(ctx, lockKey, lockValue, opts.TTL)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	
	if acquired {
		lock.acquired = true
		dl.logger.Debugf("Lock acquired: %s", lockKey)
		
		// Start auto-renewal if enabled
		if opts.AutoRenew {
			go lock.autoRenewLoop()
		}
		
		return lock, nil
	}
	
	// If retry is disabled, return immediately
	if !opts.Retry {
		return nil, fmt.Errorf("failed to acquire lock: %s", lockKey)
	}
	
	// Retry logic
	retryCount := 0
	ticker := time.NewTicker(opts.RetryDelay)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			retryCount++
			if opts.MaxRetries > 0 && retryCount > opts.MaxRetries {
				return nil, fmt.Errorf("failed to acquire lock after %d retries: %s", opts.MaxRetries, lockKey)
			}
			
			acquired, err := dl.tryAcquire(ctx, lockKey, lockValue, opts.TTL)
			if err != nil {
				return nil, fmt.Errorf("failed to acquire lock on retry %d: %w", retryCount, err)
			}
			
			if acquired {
				lock.acquired = true
				dl.logger.Debugf("Lock acquired after %d retries: %s", retryCount, lockKey)
				
				// Start auto-renewal if enabled
				if opts.AutoRenew {
					go lock.autoRenewLoop()
				}
				
				return lock, nil
			}
		}
	}
}

// tryAcquire attempts to acquire a lock using SET NX EX
func (dl *DistributedLock) tryAcquire(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	// Use SET with NX (only if not exists) and EX (expiration)
	result, err := dl.client.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		return false, err
	}
	
	return result, nil
}

// Release releases the distributed lock
func (l *Lock) Release(ctx context.Context) error {
	if !l.acquired {
		return fmt.Errorf("lock not acquired")
	}
	
	// Stop auto-renewal
	if l.autoRenew {
		close(l.renewStop)
	}
	
	// Lua script to safely release the lock (only if we own it)
	luaScript := `
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("DEL", KEYS[1])
		else
			return 0
		end
	`
	
	result, err := l.client.Eval(ctx, luaScript, []string{l.key}, l.value).Result()
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}
	
	released := result.(int64) == 1
	if !released {
		l.logger.Warnf("Lock was not owned by this instance: %s", l.key)
		return fmt.Errorf("lock was not owned by this instance")
	}
	
	l.acquired = false
	l.logger.Debugf("Lock released: %s", l.key)
	return nil
}

// Renew extends the lock's TTL
func (l *Lock) Renew(ctx context.Context, ttl time.Duration) error {
	if !l.acquired {
		return fmt.Errorf("lock not acquired")
	}
	
	// Lua script to safely renew the lock (only if we own it)
	luaScript := `
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("EXPIRE", KEYS[1], ARGV[2])
		else
			return 0
		end
	`
	
	result, err := l.client.Eval(ctx, luaScript, []string{l.key}, l.value, int64(ttl.Seconds())).Result()
	if err != nil {
		return fmt.Errorf("failed to renew lock: %w", err)
	}
	
	renewed := result.(int64) == 1
	if !renewed {
		l.acquired = false
		return fmt.Errorf("lock was not owned by this instance, marking as released")
	}
	
	l.ttl = ttl
	l.logger.Debugf("Lock renewed: %s (TTL: %v)", l.key, ttl)
	return nil
}

// IsAcquired returns whether the lock is currently acquired
func (l *Lock) IsAcquired() bool {
	return l.acquired
}

// TTL returns the current TTL of the lock
func (l *Lock) TTL(ctx context.Context) (time.Duration, error) {
	if !l.acquired {
		return 0, fmt.Errorf("lock not acquired")
	}
	
	ttl, err := l.client.TTL(ctx, l.key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get lock TTL: %w", err)
	}
	
	if ttl == -2 {
		// Key doesn't exist
		l.acquired = false
		return 0, fmt.Errorf("lock has expired")
	}
	
	return ttl, nil
}

// autoRenewLoop automatically renews the lock before it expires
func (l *Lock) autoRenewLoop() {
	// Renew at 1/3 of the TTL to ensure we don't lose the lock
	renewInterval := l.ttl / 3
	if renewInterval < time.Second {
		renewInterval = time.Second
	}
	
	ticker := time.NewTicker(renewInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-l.renewStop:
			l.logger.Debugf("Auto-renewal stopped for lock: %s", l.key)
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := l.Renew(ctx, l.ttl)
			cancel()
			
			if err != nil {
				l.logger.Errorf("Failed to auto-renew lock %s: %v", l.key, err)
				return
			}
			
			l.logger.Debugf("Auto-renewed lock: %s", l.key)
		}
	}
}

// WithLock executes a function while holding a distributed lock
func (dl *DistributedLock) WithLock(ctx context.Context, key string, fn func() error, options ...LockOptions) error {
	lock, err := dl.Acquire(ctx, key, options...)
	if err != nil {
		return fmt.Errorf("failed to acquire lock for WithLock: %w", err)
	}
	
	defer func() {
		if releaseErr := lock.Release(ctx); releaseErr != nil {
			dl.logger.Errorf("Failed to release lock in WithLock: %v", releaseErr)
		}
	}()
	
	return fn()
}

// ForceRelease forcefully releases a lock (use with caution)
func (dl *DistributedLock) ForceRelease(ctx context.Context, key string) error {
	lockKey := dl.prefix + key
	
	result, err := dl.client.Del(ctx, lockKey).Result()
	if err != nil {
		return fmt.Errorf("failed to force release lock: %w", err)
	}
	
	if result == 0 {
		return fmt.Errorf("lock does not exist: %s", lockKey)
	}
	
	dl.logger.Warnf("Lock forcefully released: %s", lockKey)
	return nil
}

// GetLockInfo returns information about a lock
func (dl *DistributedLock) GetLockInfo(ctx context.Context, key string) (map[string]interface{}, error) {
	lockKey := dl.prefix + key
	
	// Get lock value and TTL
	pipe := dl.client.Pipeline()
	getCmd := pipe.Get(ctx, lockKey)
	ttlCmd := pipe.TTL(ctx, lockKey)
	
	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("failed to get lock info: %w", err)
	}
	
	info := map[string]interface{}{
		"key":    lockKey,
		"exists": false,
	}
	
	if getCmd.Err() == nil {
		info["exists"] = true
		info["value"] = getCmd.Val()
		
		if ttlCmd.Err() == nil {
			info["ttl"] = ttlCmd.Val().String()
		}
	}
	
	return info, nil
}

// GetStats returns distributed lock statistics
func (dl *DistributedLock) GetStats(ctx context.Context) (map[string]interface{}, error) {
	pattern := dl.prefix + "*"
	keys, err := dl.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get lock keys: %w", err)
	}
	
	stats := map[string]interface{}{
		"total_locks": len(keys),
		"prefix":      dl.prefix,
	}
	
	return stats, nil
}

// Helper methods

func (dl *DistributedLock) mergeOptions(options ...LockOptions) LockOptions {
	opts := LockOptions{
		TTL:        30 * time.Second, // Default TTL
		Retry:      false,
		RetryDelay: 100 * time.Millisecond,
		MaxRetries: 10,
		AutoRenew:  false,
	}
	
	for _, opt := range options {
		if opt.TTL != 0 {
			opts.TTL = opt.TTL
		}
		if opt.Retry {
			opts.Retry = opt.Retry
		}
		if opt.RetryDelay != 0 {
			opts.RetryDelay = opt.RetryDelay
		}
		if opt.MaxRetries != 0 {
			opts.MaxRetries = opt.MaxRetries
		}
		if opt.AutoRenew {
			opts.AutoRenew = opt.AutoRenew
		}
	}
	
	return opts
}

func (dl *DistributedLock) generateLockValue() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
