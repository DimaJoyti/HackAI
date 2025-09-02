package state

import (
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// StateCacheManager manages state caching for performance optimization
type StateCacheManager struct {
	cache    map[string]*CacheEntry
	maxSize  int
	ttl      time.Duration
	logger   *logger.Logger
	mutex    sync.RWMutex
	stats    *CacheStats
	eviction EvictionPolicy
}

// CacheEntry represents a cached state entry
type CacheEntry struct {
	Key         StateKey      `json:"key"`
	Value       *StateEntry   `json:"value"`
	CreatedAt   time.Time     `json:"created_at"`
	AccessedAt  time.Time     `json:"accessed_at"`
	AccessCount int64         `json:"access_count"`
	Size        int64         `json:"size"`
	TTL         time.Duration `json:"ttl"`
	ExpiresAt   time.Time     `json:"expires_at"`
}

// CacheStats holds cache statistics
type CacheStats struct {
	Hits        int64      `json:"hits"`
	Misses      int64      `json:"misses"`
	Evictions   int64      `json:"evictions"`
	Size        int        `json:"size"`
	MaxSize     int        `json:"max_size"`
	HitRatio    float64    `json:"hit_ratio"`
	TotalSize   int64      `json:"total_size"`
	AverageSize float64    `json:"average_size"`
	OldestEntry *time.Time `json:"oldest_entry,omitempty"`
	NewestEntry *time.Time `json:"newest_entry,omitempty"`
}

// EvictionPolicy defines cache eviction policies
type EvictionPolicy string

const (
	EvictionLRU    EvictionPolicy = "lru"    // Least Recently Used
	EvictionLFU    EvictionPolicy = "lfu"    // Least Frequently Used
	EvictionFIFO   EvictionPolicy = "fifo"   // First In, First Out
	EvictionRandom EvictionPolicy = "random" // Random eviction
	EvictionTTL    EvictionPolicy = "ttl"    // Time To Live based
)

// NewStateCacheManager creates a new state cache manager
func NewStateCacheManager(maxSize int, ttl time.Duration, logger *logger.Logger) *StateCacheManager {
	return &StateCacheManager{
		cache:    make(map[string]*CacheEntry),
		maxSize:  maxSize,
		ttl:      ttl,
		logger:   logger,
		stats:    &CacheStats{MaxSize: maxSize},
		eviction: EvictionLRU, // Default eviction policy
	}
}

// Get retrieves an entry from cache
func (scm *StateCacheManager) Get(key StateKey) (*StateEntry, bool) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	keyStr := scm.keyToString(key)
	entry, exists := scm.cache[keyStr]

	if !exists {
		scm.stats.Misses++
		scm.updateHitRatio()
		return nil, false
	}

	// Check if entry has expired
	if time.Now().After(entry.ExpiresAt) {
		delete(scm.cache, keyStr)
		scm.stats.Misses++
		scm.stats.Evictions++
		scm.updateHitRatio()
		return nil, false
	}

	// Update access information
	entry.AccessedAt = time.Now()
	entry.AccessCount++

	scm.stats.Hits++
	scm.updateHitRatio()

	return entry.Value, true
}

// Set stores an entry in cache
func (scm *StateCacheManager) Set(key StateKey, value *StateEntry) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	keyStr := scm.keyToString(key)

	// Check if we need to evict entries
	if len(scm.cache) >= scm.maxSize {
		scm.evictEntry()
	}

	// Calculate entry size
	size := scm.calculateSize(value)

	// Create cache entry
	entry := &CacheEntry{
		Key:         key,
		Value:       value,
		CreatedAt:   time.Now(),
		AccessedAt:  time.Now(),
		AccessCount: 1,
		Size:        size,
		TTL:         scm.ttl,
		ExpiresAt:   time.Now().Add(scm.ttl),
	}

	scm.cache[keyStr] = entry
	scm.stats.Size = len(scm.cache)
	scm.updateStats()

	scm.logger.Debug("Cache entry stored",
		"key", key,
		"size", size,
		"expires_at", entry.ExpiresAt)
}

// Delete removes an entry from cache
func (scm *StateCacheManager) Delete(key StateKey) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	keyStr := scm.keyToString(key)
	if _, exists := scm.cache[keyStr]; exists {
		delete(scm.cache, keyStr)
		scm.stats.Size = len(scm.cache)
		scm.updateStats()
	}
}

// Clear clears all cache entries
func (scm *StateCacheManager) Clear() {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	scm.cache = make(map[string]*CacheEntry)
	scm.stats.Size = 0
	scm.updateStats()

	scm.logger.Info("Cache cleared")
}

// GetStats returns cache statistics
func (scm *StateCacheManager) GetStats() *CacheStats {
	scm.mutex.RLock()
	defer scm.mutex.RUnlock()

	// Create a copy of stats
	stats := *scm.stats
	return &stats
}

// SetEvictionPolicy sets the cache eviction policy
func (scm *StateCacheManager) SetEvictionPolicy(policy EvictionPolicy) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	scm.eviction = policy
	scm.logger.Info("Cache eviction policy changed", "policy", policy)
}

// Close closes the cache manager
func (scm *StateCacheManager) Close() error {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	scm.cache = nil
	scm.logger.Info("Cache manager closed")
	return nil
}

// Helper methods

func (scm *StateCacheManager) keyToString(key StateKey) string {
	return key.Namespace + ":" + key.GraphID + ":" + key.NodeID + ":" + key.Key
}

func (scm *StateCacheManager) calculateSize(entry *StateEntry) int64 {
	// Simplified size calculation
	// In production, implement proper size calculation
	return int64(len(entry.Key.Key) + 100) // Approximate size
}

func (scm *StateCacheManager) updateHitRatio() {
	total := scm.stats.Hits + scm.stats.Misses
	if total > 0 {
		scm.stats.HitRatio = float64(scm.stats.Hits) / float64(total)
	}
}

func (scm *StateCacheManager) updateStats() {
	var totalSize int64
	var oldestTime *time.Time
	var newestTime *time.Time

	for _, entry := range scm.cache {
		totalSize += entry.Size

		if oldestTime == nil || entry.CreatedAt.Before(*oldestTime) {
			oldestTime = &entry.CreatedAt
		}
		if newestTime == nil || entry.CreatedAt.After(*newestTime) {
			newestTime = &entry.CreatedAt
		}
	}

	scm.stats.TotalSize = totalSize
	scm.stats.OldestEntry = oldestTime
	scm.stats.NewestEntry = newestTime

	if scm.stats.Size > 0 {
		scm.stats.AverageSize = float64(totalSize) / float64(scm.stats.Size)
	}
}

func (scm *StateCacheManager) evictEntry() {
	if len(scm.cache) == 0 {
		return
	}

	var keyToEvict string

	switch scm.eviction {
	case EvictionLRU:
		keyToEvict = scm.findLRUKey()
	case EvictionLFU:
		keyToEvict = scm.findLFUKey()
	case EvictionFIFO:
		keyToEvict = scm.findFIFOKey()
	case EvictionTTL:
		keyToEvict = scm.findExpiredKey()
	default:
		keyToEvict = scm.findRandomKey()
	}

	if keyToEvict != "" {
		delete(scm.cache, keyToEvict)
		scm.stats.Evictions++
		scm.stats.Size = len(scm.cache)
	}
}

func (scm *StateCacheManager) findLRUKey() string {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range scm.cache {
		if oldestKey == "" || entry.AccessedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.AccessedAt
		}
	}

	return oldestKey
}

func (scm *StateCacheManager) findLFUKey() string {
	var leastUsedKey string
	var leastCount int64 = -1

	for key, entry := range scm.cache {
		if leastCount == -1 || entry.AccessCount < leastCount {
			leastUsedKey = key
			leastCount = entry.AccessCount
		}
	}

	return leastUsedKey
}

func (scm *StateCacheManager) findFIFOKey() string {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range scm.cache {
		if oldestKey == "" || entry.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.CreatedAt
		}
	}

	return oldestKey
}

func (scm *StateCacheManager) findExpiredKey() string {
	now := time.Now()
	for key, entry := range scm.cache {
		if now.After(entry.ExpiresAt) {
			return key
		}
	}
	// If no expired entries, fall back to LRU
	return scm.findLRUKey()
}

func (scm *StateCacheManager) findRandomKey() string {
	// Simple random selection - just return the first key
	for key := range scm.cache {
		return key
	}
	return ""
}

// CleanupExpired removes expired entries from cache
func (scm *StateCacheManager) CleanupExpired() {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	now := time.Now()
	expiredKeys := make([]string, 0)

	for key, entry := range scm.cache {
		if now.After(entry.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(scm.cache, key)
		scm.stats.Evictions++
	}

	if len(expiredKeys) > 0 {
		scm.stats.Size = len(scm.cache)
		scm.updateStats()
		scm.logger.Debug("Expired cache entries cleaned up", "count", len(expiredKeys))
	}
}

// Resize changes the maximum cache size
func (scm *StateCacheManager) Resize(newSize int) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	oldSize := scm.maxSize
	scm.maxSize = newSize
	scm.stats.MaxSize = newSize

	// If new size is smaller, evict entries
	for len(scm.cache) > newSize {
		scm.evictEntry()
	}

	scm.logger.Info("Cache resized",
		"old_size", oldSize,
		"new_size", newSize,
		"current_entries", len(scm.cache))
}
