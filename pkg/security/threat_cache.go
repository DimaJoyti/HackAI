package security

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// ThreatCache provides caching for threat intelligence data
type ThreatCache struct {
	config     *ThreatIntelligenceConfig
	logger     Logger
	cache      map[string]*CacheEntry
	accessTime map[string]time.Time
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
}

// CacheEntry represents a cached threat report
type CacheEntry struct {
	Key         string        `json:"key"`
	Report      *ThreatReport `json:"report"`
	CreatedAt   time.Time     `json:"created_at"`
	ExpiresAt   time.Time     `json:"expires_at"`
	AccessCount int           `json:"access_count"`
	LastAccess  time.Time     `json:"last_access"`
	Size        int           `json:"size"`
}

// NewThreatCache creates a new threat cache
func NewThreatCache(config *ThreatIntelligenceConfig, logger Logger) *ThreatCache {
	ctx, cancel := context.WithCancel(context.Background())

	return &ThreatCache{
		config:     config,
		logger:     logger,
		cache:      make(map[string]*CacheEntry),
		accessTime: make(map[string]time.Time),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the threat cache
func (tc *ThreatCache) Start() error {
	tc.logger.Info("Starting threat cache")

	// Start cleanup worker
	tc.wg.Add(1)
	go tc.cleanupWorker()

	return nil
}

// Stop stops the threat cache
func (tc *ThreatCache) Stop() error {
	tc.logger.Info("Stopping threat cache")

	tc.cancel()
	tc.wg.Wait()

	return nil
}

// Get retrieves a threat report from cache
func (tc *ThreatCache) Get(target string) *ThreatReport {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	key := tc.generateKey(target)
	entry, exists := tc.cache[key]
	if !exists {
		return nil
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		// Mark for cleanup but don't remove immediately to avoid lock issues
		return nil
	}

	// Update access statistics
	entry.AccessCount++
	entry.LastAccess = time.Now()
	tc.accessTime[key] = time.Now()

	tc.logger.Debug("Cache hit", "target", target, "key", key)

	return entry.Report
}

// Set stores a threat report in cache
func (tc *ThreatCache) Set(target string, report *ThreatReport) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Check cache size limit
	if len(tc.cache) >= tc.config.MaxCacheSize {
		tc.evictLRU()
	}

	key := tc.generateKey(target)
	now := time.Now()

	entry := &CacheEntry{
		Key:         key,
		Report:      report,
		CreatedAt:   now,
		ExpiresAt:   now.Add(tc.config.CacheTimeout),
		AccessCount: 1,
		LastAccess:  now,
		Size:        tc.calculateSize(report),
	}

	tc.cache[key] = entry
	tc.accessTime[key] = now

	tc.logger.Debug("Cache set", "target", target, "key", key, "expires_at", entry.ExpiresAt)
}

// Delete removes a threat report from cache
func (tc *ThreatCache) Delete(target string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	key := tc.generateKey(target)
	delete(tc.cache, key)
	delete(tc.accessTime, key)

	tc.logger.Debug("Cache delete", "target", target, "key", key)
}

// Clear clears all cached data
func (tc *ThreatCache) Clear() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.cache = make(map[string]*CacheEntry)
	tc.accessTime = make(map[string]time.Time)

	tc.logger.Info("Cache cleared")
}

// GetStatistics returns cache statistics
func (tc *ThreatCache) GetStatistics() map[string]interface{} {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_entries"] = len(tc.cache)
	stats["max_size"] = tc.config.MaxCacheSize
	stats["cache_timeout"] = tc.config.CacheTimeout.String()

	// Calculate cache usage
	totalSize := 0
	totalAccess := 0
	expiredCount := 0
	now := time.Now()

	for _, entry := range tc.cache {
		totalSize += entry.Size
		totalAccess += entry.AccessCount

		if now.After(entry.ExpiresAt) {
			expiredCount++
		}
	}

	stats["total_size_bytes"] = totalSize
	stats["total_access_count"] = totalAccess
	stats["expired_entries"] = expiredCount

	if len(tc.cache) > 0 {
		stats["average_size_bytes"] = totalSize / len(tc.cache)
		stats["average_access_count"] = float64(totalAccess) / float64(len(tc.cache))
	}

	// Cache utilization
	utilization := float64(len(tc.cache)) / float64(tc.config.MaxCacheSize) * 100
	stats["utilization_percent"] = utilization

	return stats
}

// GetCacheEntries returns all cache entries (for debugging)
func (tc *ThreatCache) GetCacheEntries() []*CacheEntry {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	entries := make([]*CacheEntry, 0, len(tc.cache))
	for _, entry := range tc.cache {
		entries = append(entries, entry)
	}

	return entries
}

// generateKey generates a cache key for a target
func (tc *ThreatCache) generateKey(target string) string {
	h := sha256.Sum256([]byte(target))
	return fmt.Sprintf("%x", h)[:16] // Use first 16 characters
}

// calculateSize estimates the size of a threat report
func (tc *ThreatCache) calculateSize(report *ThreatReport) int {
	// Simplified size calculation
	// In production, this could use more sophisticated methods

	size := 0

	// Base report size
	size += len(report.ID) + len(report.Target) + len(report.TargetType)
	size += len(report.RiskLevel)

	// Indicators
	for _, indicator := range report.Indicators {
		size += len(indicator.ID) + len(indicator.Type) + len(indicator.Value)
		size += len(indicator.Source) + len(indicator.Description)
		size += len(indicator.Tags) * 10 // Estimate for tags
	}

	// Related threats
	for _, threat := range report.RelatedThreats {
		size += len(threat.ID) + len(threat.Type) + len(threat.Value)
		size += len(threat.Source) + len(threat.Description)
	}

	// Recommendations and actions
	for _, rec := range report.Recommendations {
		size += len(rec)
	}
	for _, action := range report.Actions {
		size += len(action)
	}

	// Sources
	for _, source := range report.Sources {
		size += len(source)
	}

	return size
}

// evictLRU evicts the least recently used cache entry
func (tc *ThreatCache) evictLRU() {
	if len(tc.cache) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time

	// Find the least recently accessed entry
	for key, accessTime := range tc.accessTime {
		if oldestKey == "" || accessTime.Before(oldestTime) {
			oldestKey = key
			oldestTime = accessTime
		}
	}

	if oldestKey != "" {
		delete(tc.cache, oldestKey)
		delete(tc.accessTime, oldestKey)

		tc.logger.Debug("Cache LRU eviction", "key", oldestKey, "last_access", oldestTime)
	}
}

// cleanupWorker background worker for cache cleanup
func (tc *ThreatCache) cleanupWorker() {
	defer tc.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-tc.ctx.Done():
			return
		case <-ticker.C:
			tc.cleanupExpired()
		}
	}
}

// cleanupExpired removes expired cache entries
func (tc *ThreatCache) cleanupExpired() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	now := time.Now()
	var expiredKeys []string

	for key, entry := range tc.cache {
		if now.After(entry.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(tc.cache, key)
		delete(tc.accessTime, key)
	}

	if len(expiredKeys) > 0 {
		tc.logger.Debug("Cache cleanup", "expired_entries", len(expiredKeys))
	}
}

// Warmup pre-loads cache with common threat intelligence data
func (tc *ThreatCache) Warmup(targets []string) error {
	tc.logger.Info("Starting cache warmup", "targets", len(targets))

	// This would typically pre-load common indicators
	// For now, just log the warmup request

	for _, target := range targets {
		// In production, this would trigger threat analysis for each target
		// and cache the results
		tc.logger.Debug("Warmup target", "target", target)
	}

	tc.logger.Info("Cache warmup completed")

	return nil
}

// GetHitRate calculates cache hit rate
func (tc *ThreatCache) GetHitRate() float64 {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	if len(tc.cache) == 0 {
		return 0.0
	}

	totalAccess := 0
	for _, entry := range tc.cache {
		totalAccess += entry.AccessCount
	}

	// Simplified hit rate calculation
	// In production, this would track hits vs misses more accurately
	return float64(totalAccess) / float64(len(tc.cache))
}

// Optimize performs cache optimization
func (tc *ThreatCache) Optimize() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	now := time.Now()

	// Remove entries that haven't been accessed recently
	cutoff := now.Add(-24 * time.Hour)
	var removedCount int

	for key, entry := range tc.cache {
		if entry.LastAccess.Before(cutoff) && entry.AccessCount < 2 {
			delete(tc.cache, key)
			delete(tc.accessTime, key)
			removedCount++
		}
	}

	if removedCount > 0 {
		tc.logger.Info("Cache optimization completed", "removed_entries", removedCount)
	}
}
