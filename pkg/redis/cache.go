package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// CacheManager handles Redis-based caching operations
type CacheManager struct {
	client *Client
	logger *logger.Logger
	prefix string
	defaultTTL time.Duration
}

// CacheOptions represents cache operation options
type CacheOptions struct {
	TTL        time.Duration
	Namespace  string
	Compress   bool
	Tags       []string
}

// NewCacheManager creates a new cache manager
func NewCacheManager(client *Client, logger *logger.Logger) *CacheManager {
	return &CacheManager{
		client:     client,
		logger:     logger,
		prefix:     "cache:",
		defaultTTL: 1 * time.Hour,
	}
}

// SetPrefix sets the cache key prefix
func (cm *CacheManager) SetPrefix(prefix string) {
	cm.prefix = prefix
}

// SetDefaultTTL sets the default TTL for cache entries
func (cm *CacheManager) SetDefaultTTL(ttl time.Duration) {
	cm.defaultTTL = ttl
}

// Set stores a value in cache with optional TTL
func (cm *CacheManager) Set(ctx context.Context, key string, value interface{}, options ...CacheOptions) error {
	opts := cm.mergeOptions(options...)
	cacheKey := cm.buildKey(key, opts.Namespace)
	
	// Serialize value
	data, err := cm.serialize(value)
	if err != nil {
		return fmt.Errorf("failed to serialize cache value: %w", err)
	}
	
	// Set in Redis
	ttl := opts.TTL
	if ttl == 0 {
		ttl = cm.defaultTTL
	}
	
	if err := cm.client.Set(ctx, cacheKey, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to set cache key %s: %w", cacheKey, err)
	}
	
	// Add tags if specified
	if len(opts.Tags) > 0 {
		if err := cm.addTags(ctx, cacheKey, opts.Tags); err != nil {
			cm.logger.Warnf("Failed to add cache tags for key %s: %v", cacheKey, err)
		}
	}
	
	cm.logger.Debugf("Cache set: %s (TTL: %v)", cacheKey, ttl)
	return nil
}

// Get retrieves a value from cache
func (cm *CacheManager) Get(ctx context.Context, key string, dest interface{}, options ...CacheOptions) error {
	opts := cm.mergeOptions(options...)
	cacheKey := cm.buildKey(key, opts.Namespace)
	
	// Get from Redis
	data, err := cm.client.Get(ctx, cacheKey).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("cache miss for key: %s", cacheKey)
		}
		return fmt.Errorf("failed to get cache key %s: %w", cacheKey, err)
	}
	
	// Deserialize value
	if err := cm.deserialize(data, dest); err != nil {
		return fmt.Errorf("failed to deserialize cache value: %w", err)
	}
	
	cm.logger.Debugf("Cache hit: %s", cacheKey)
	return nil
}

// GetOrSet retrieves a value from cache, or sets it using the provided function if not found
func (cm *CacheManager) GetOrSet(ctx context.Context, key string, dest interface{}, setter func() (interface{}, error), options ...CacheOptions) error {
	// Try to get from cache first
	err := cm.Get(ctx, key, dest, options...)
	if err == nil {
		return nil // Cache hit
	}
	
	// Cache miss, call setter function
	value, err := setter()
	if err != nil {
		return fmt.Errorf("setter function failed: %w", err)
	}
	
	// Set in cache
	if err := cm.Set(ctx, key, value, options...); err != nil {
		cm.logger.Warnf("Failed to set cache after setter: %v", err)
	}
	
	// Copy value to destination
	if err := cm.copyValue(value, dest); err != nil {
		return fmt.Errorf("failed to copy value to destination: %w", err)
	}
	
	return nil
}

// Delete removes a key from cache
func (cm *CacheManager) Delete(ctx context.Context, key string, options ...CacheOptions) error {
	opts := cm.mergeOptions(options...)
	cacheKey := cm.buildKey(key, opts.Namespace)
	
	if err := cm.client.Del(ctx, cacheKey).Err(); err != nil {
		return fmt.Errorf("failed to delete cache key %s: %w", cacheKey, err)
	}
	
	cm.logger.Debugf("Cache deleted: %s", cacheKey)
	return nil
}

// DeleteByPattern deletes all keys matching a pattern
func (cm *CacheManager) DeleteByPattern(ctx context.Context, pattern string, options ...CacheOptions) (int, error) {
	opts := cm.mergeOptions(options...)
	searchPattern := cm.buildKey(pattern, opts.Namespace)
	
	// Scan for matching keys
	keys, err := cm.client.Keys(ctx, searchPattern).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to scan keys with pattern %s: %w", searchPattern, err)
	}
	
	if len(keys) == 0 {
		return 0, nil
	}
	
	// Delete all matching keys
	deleted, err := cm.client.Del(ctx, keys...).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to delete keys: %w", err)
	}
	
	cm.logger.Debugf("Cache pattern delete: %s (%d keys)", searchPattern, deleted)
	return int(deleted), nil
}

// DeleteByTags deletes all keys with specified tags
func (cm *CacheManager) DeleteByTags(ctx context.Context, tags []string) (int, error) {
	if len(tags) == 0 {
		return 0, nil
	}
	
	var allKeys []string
	for _, tag := range tags {
		tagKey := cm.buildTagKey(tag)
		keys, err := cm.client.SMembers(ctx, tagKey).Result()
		if err != nil {
			cm.logger.Warnf("Failed to get keys for tag %s: %v", tag, err)
			continue
		}
		allKeys = append(allKeys, keys...)
	}
	
	if len(allKeys) == 0 {
		return 0, nil
	}
	
	// Remove duplicates
	uniqueKeys := make(map[string]bool)
	for _, key := range allKeys {
		uniqueKeys[key] = true
	}
	
	keys := make([]string, 0, len(uniqueKeys))
	for key := range uniqueKeys {
		keys = append(keys, key)
	}
	
	// Delete all keys
	deleted, err := cm.client.Del(ctx, keys...).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to delete tagged keys: %w", err)
	}
	
	// Clean up tag sets
	for _, tag := range tags {
		tagKey := cm.buildTagKey(tag)
		cm.client.Del(ctx, tagKey)
	}
	
	cm.logger.Debugf("Cache tag delete: %v (%d keys)", tags, deleted)
	return int(deleted), nil
}

// Exists checks if a key exists in cache
func (cm *CacheManager) Exists(ctx context.Context, key string, options ...CacheOptions) (bool, error) {
	opts := cm.mergeOptions(options...)
	cacheKey := cm.buildKey(key, opts.Namespace)
	
	exists, err := cm.client.Exists(ctx, cacheKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check cache key existence %s: %w", cacheKey, err)
	}
	
	return exists > 0, nil
}

// TTL returns the remaining TTL for a key
func (cm *CacheManager) TTL(ctx context.Context, key string, options ...CacheOptions) (time.Duration, error) {
	opts := cm.mergeOptions(options...)
	cacheKey := cm.buildKey(key, opts.Namespace)
	
	ttl, err := cm.client.TTL(ctx, cacheKey).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get TTL for cache key %s: %w", cacheKey, err)
	}
	
	return ttl, nil
}

// Extend extends the TTL of a cache key
func (cm *CacheManager) Extend(ctx context.Context, key string, extension time.Duration, options ...CacheOptions) error {
	opts := cm.mergeOptions(options...)
	cacheKey := cm.buildKey(key, opts.Namespace)
	
	if err := cm.client.Expire(ctx, cacheKey, extension).Err(); err != nil {
		return fmt.Errorf("failed to extend TTL for cache key %s: %w", cacheKey, err)
	}
	
	cm.logger.Debugf("Cache TTL extended: %s (+%v)", cacheKey, extension)
	return nil
}

// GetStats returns cache statistics
func (cm *CacheManager) GetStats(ctx context.Context) (map[string]interface{}, error) {
	pattern := cm.prefix + "*"
	keys, err := cm.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache keys: %w", err)
	}
	
	stats := map[string]interface{}{
		"total_keys": len(keys),
		"prefix":     cm.prefix,
		"default_ttl": cm.defaultTTL.String(),
	}
	
	return stats, nil
}

// Helper methods

func (cm *CacheManager) buildKey(key, namespace string) string {
	if namespace != "" {
		return fmt.Sprintf("%s%s:%s", cm.prefix, namespace, key)
	}
	return cm.prefix + key
}

func (cm *CacheManager) buildTagKey(tag string) string {
	return fmt.Sprintf("%stag:%s", cm.prefix, tag)
}

func (cm *CacheManager) mergeOptions(options ...CacheOptions) CacheOptions {
	opts := CacheOptions{}
	for _, opt := range options {
		if opt.TTL != 0 {
			opts.TTL = opt.TTL
		}
		if opt.Namespace != "" {
			opts.Namespace = opt.Namespace
		}
		if opt.Compress {
			opts.Compress = opt.Compress
		}
		if len(opt.Tags) > 0 {
			opts.Tags = append(opts.Tags, opt.Tags...)
		}
	}
	return opts
}

func (cm *CacheManager) serialize(value interface{}) (string, error) {
	if str, ok := value.(string); ok {
		return str, nil
	}
	
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	
	return string(data), nil
}

func (cm *CacheManager) deserialize(data string, dest interface{}) error {
	if str, ok := dest.(*string); ok {
		*str = data
		return nil
	}
	
	return json.Unmarshal([]byte(data), dest)
}

func (cm *CacheManager) copyValue(src, dest interface{}) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	
	return json.Unmarshal(data, dest)
}

func (cm *CacheManager) addTags(ctx context.Context, key string, tags []string) error {
	for _, tag := range tags {
		tagKey := cm.buildTagKey(tag)
		if err := cm.client.SAdd(ctx, tagKey, key).Err(); err != nil {
			return err
		}
		// Set expiration for tag set (longer than cache entries)
		cm.client.Expire(ctx, tagKey, cm.defaultTTL*2)
	}
	return nil
}
