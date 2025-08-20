package fraud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// RedisCache interface for Redis operations (stub for now)
type RedisCache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
}

// EnhancedCacheManager provides intelligent caching for fraud detection
type EnhancedCacheManager struct {
	redis  RedisCache
	config *EngineConfig
	logger *logger.Logger
	stats  *CacheStats
}

// CacheStats tracks cache performance metrics
type CacheStats struct {
	Hits        int64     `json:"hits"`
	Misses      int64     `json:"misses"`
	Sets        int64     `json:"sets"`
	Deletes     int64     `json:"deletes"`
	Errors      int64     `json:"errors"`
	HitRate     float64   `json:"hit_rate"`
	LastUpdated time.Time `json:"last_updated"`
}

// NewEnhancedCacheManager creates a new enhanced cache manager
func NewEnhancedCacheManager(redis RedisCache, config *EngineConfig, logger *logger.Logger) *EnhancedCacheManager {
	return &EnhancedCacheManager{
		redis:  redis,
		config: config,
		logger: logger,
		stats: &CacheStats{
			LastUpdated: time.Now(),
		},
	}
}

// GetFraudResponse retrieves a cached fraud detection response
func (ecm *EnhancedCacheManager) GetFraudResponse(ctx context.Context, requestID string) (*FraudDetectionResponse, error) {
	key := ecm.buildCacheKey("fraud_response", requestID)

	value, err := ecm.redis.Get(ctx, key)
	if err != nil {
		ecm.stats.Misses++
		ecm.stats.Errors++
		ecm.updateStats()
		return nil, err
	}

	if value == "" {
		ecm.stats.Misses++
		ecm.updateStats()
		return nil, nil
	}

	var response FraudDetectionResponse
	if err := json.Unmarshal([]byte(value), &response); err != nil {
		ecm.stats.Errors++
		ecm.updateStats()
		return nil, fmt.Errorf("failed to unmarshal cached response: %w", err)
	}

	ecm.stats.Hits++
	ecm.updateStats()
	return &response, nil
}

// SetFraudResponse caches a fraud detection response
func (ecm *EnhancedCacheManager) SetFraudResponse(ctx context.Context, requestID string, response *FraudDetectionResponse, ttl time.Duration) error {
	key := ecm.buildCacheKey("fraud_response", requestID)

	data, err := json.Marshal(response)
	if err != nil {
		ecm.stats.Errors++
		ecm.updateStats()
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if err := ecm.redis.Set(ctx, key, string(data), ttl); err != nil {
		ecm.stats.Errors++
		ecm.updateStats()
		return err
	}

	ecm.stats.Sets++
	ecm.updateStats()
	return nil
}

// GetUserFeatures retrieves cached user features
func (ecm *EnhancedCacheManager) GetUserFeatures(ctx context.Context, userID string) (map[string]float64, error) {
	key := ecm.buildCacheKey("user_features", userID)

	value, err := ecm.redis.Get(ctx, key)
	if err != nil || value == "" {
		ecm.stats.Misses++
		ecm.updateStats()
		return nil, err
	}

	var features map[string]float64
	if err := json.Unmarshal([]byte(value), &features); err != nil {
		ecm.stats.Errors++
		ecm.updateStats()
		return nil, fmt.Errorf("failed to unmarshal cached features: %w", err)
	}

	ecm.stats.Hits++
	ecm.updateStats()
	return features, nil
}

// SetUserFeatures caches user features
func (ecm *EnhancedCacheManager) SetUserFeatures(ctx context.Context, userID string, features map[string]float64, ttl time.Duration) error {
	key := ecm.buildCacheKey("user_features", userID)

	data, err := json.Marshal(features)
	if err != nil {
		ecm.stats.Errors++
		ecm.updateStats()
		return fmt.Errorf("failed to marshal features: %w", err)
	}

	if err := ecm.redis.Set(ctx, key, string(data), ttl); err != nil {
		ecm.stats.Errors++
		ecm.updateStats()
		return err
	}

	ecm.stats.Sets++
	ecm.updateStats()
	return nil
}

// GetStats returns cache performance statistics
func (ecm *EnhancedCacheManager) GetStats() *CacheStats {
	ecm.updateStats()
	return ecm.stats
}

// buildCacheKey builds a cache key from components
func (ecm *EnhancedCacheManager) buildCacheKey(prefix string, components ...string) string {
	key := "hackai:fraud:" + prefix
	for _, component := range components {
		key += ":" + component
	}
	return key
}

// updateStats updates cache statistics
func (ecm *EnhancedCacheManager) updateStats() {
	total := ecm.stats.Hits + ecm.stats.Misses
	if total > 0 {
		ecm.stats.HitRate = float64(ecm.stats.Hits) / float64(total)
	}
	ecm.stats.LastUpdated = time.Now()
}

// Stub Redis implementation for testing
type StubRedisCache struct {
	data map[string]string
}

// NewStubRedisCache creates a new stub Redis cache
func NewStubRedisCache() *StubRedisCache {
	return &StubRedisCache{
		data: make(map[string]string),
	}
}

func (src *StubRedisCache) Get(ctx context.Context, key string) (string, error) {
	value, exists := src.data[key]
	if !exists {
		return "", nil
	}
	return value, nil
}

func (src *StubRedisCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	src.data[key] = value
	return nil
}

func (src *StubRedisCache) Del(ctx context.Context, key string) error {
	delete(src.data, key)
	return nil
}

func (src *StubRedisCache) Exists(ctx context.Context, key string) (bool, error) {
	_, exists := src.data[key]
	return exists, nil
}
