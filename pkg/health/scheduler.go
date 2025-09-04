package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// ScheduledChecker represents a checker with scheduling configuration
type ScheduledChecker struct {
	Checker    Checker
	Interval   time.Duration
	LastRun    time.Time
	LastResult *CheckResult
	Enabled    bool
	mutex      sync.RWMutex
}

// HealthScheduler manages scheduled health checks
type HealthScheduler struct {
	checkers map[string]*ScheduledChecker
	cache    *HealthCache
	logger   *logger.Logger
	stopChan chan struct{}
	wg       sync.WaitGroup
	mutex    sync.RWMutex
	running  bool
}

// HealthCache caches health check results
type HealthCache struct {
	results    map[string]*CachedResult
	mutex      sync.RWMutex
	defaultTTL time.Duration
}

// CachedResult represents a cached health check result
type CachedResult struct {
	Result    CheckResult
	ExpiresAt time.Time
	Hits      int64
}

// SchedulerConfig configures the health scheduler
type SchedulerConfig struct {
	DefaultInterval time.Duration `json:"default_interval"`
	CacheTTL        time.Duration `json:"cache_ttl"`
	MaxConcurrent   int           `json:"max_concurrent"`
}

// NewHealthScheduler creates a new health scheduler
func NewHealthScheduler(config SchedulerConfig, logger *logger.Logger) *HealthScheduler {
	if config.DefaultInterval == 0 {
		config.DefaultInterval = 30 * time.Second
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 10 * time.Second
	}

	cache := &HealthCache{
		results:    make(map[string]*CachedResult),
		defaultTTL: config.CacheTTL,
	}

	return &HealthScheduler{
		checkers: make(map[string]*ScheduledChecker),
		cache:    cache,
		logger:   logger,
		stopChan: make(chan struct{}),
	}
}

// AddChecker adds a checker with scheduling configuration
func (hs *HealthScheduler) AddChecker(checker Checker, interval time.Duration) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	if interval == 0 {
		interval = 30 * time.Second // Default interval
	}

	hs.checkers[checker.Name()] = &ScheduledChecker{
		Checker:  checker,
		Interval: interval,
		Enabled:  true,
	}

	hs.logger.Infof("Added scheduled health checker: %s (interval: %v)", checker.Name(), interval)
}

// RemoveChecker removes a scheduled checker
func (hs *HealthScheduler) RemoveChecker(name string) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	delete(hs.checkers, name)
	hs.cache.Delete(name)

	hs.logger.Infof("Removed scheduled health checker: %s", name)
}

// EnableChecker enables a scheduled checker
func (hs *HealthScheduler) EnableChecker(name string) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	if checker, exists := hs.checkers[name]; exists {
		checker.Enabled = true
		hs.logger.Infof("Enabled health checker: %s", name)
	}
}

// DisableChecker disables a scheduled checker
func (hs *HealthScheduler) DisableChecker(name string) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	if checker, exists := hs.checkers[name]; exists {
		checker.Enabled = false
		hs.logger.Infof("Disabled health checker: %s", name)
	}
}

// Start starts the health scheduler
func (hs *HealthScheduler) Start(ctx context.Context) {
	hs.mutex.Lock()
	if hs.running {
		hs.mutex.Unlock()
		return
	}
	hs.running = true
	hs.mutex.Unlock()

	hs.logger.Info("Starting health scheduler")

	hs.wg.Add(1)
	go hs.schedulerLoop(ctx)
}

// Stop stops the health scheduler
func (hs *HealthScheduler) Stop() {
	hs.mutex.Lock()
	if !hs.running {
		hs.mutex.Unlock()
		return
	}
	hs.running = false
	hs.mutex.Unlock()

	hs.logger.Info("Stopping health scheduler")

	close(hs.stopChan)
	hs.wg.Wait()

	hs.logger.Info("Health scheduler stopped")
}

// GetCachedResult returns a cached result if available and not expired
func (hs *HealthScheduler) GetCachedResult(name string) (*CheckResult, bool) {
	return hs.cache.Get(name)
}

// GetAllCachedResults returns all cached results
func (hs *HealthScheduler) GetAllCachedResults() map[string]CheckResult {
	hs.cache.mutex.RLock()
	defer hs.cache.mutex.RUnlock()

	results := make(map[string]CheckResult)
	now := time.Now()

	for name, cached := range hs.cache.results {
		if cached.ExpiresAt.After(now) {
			results[name] = cached.Result
		}
	}

	return results
}

// ForceCheck forces an immediate check for a specific checker
func (hs *HealthScheduler) ForceCheck(ctx context.Context, name string) (*CheckResult, error) {
	hs.mutex.RLock()
	scheduledChecker, exists := hs.checkers[name]
	hs.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("checker not found: %s", name)
	}

	result := hs.runCheck(ctx, scheduledChecker)
	return &result, nil
}

// GetSchedulerStats returns scheduler statistics
func (hs *HealthScheduler) GetSchedulerStats() map[string]interface{} {
	hs.mutex.RLock()
	defer hs.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_checkers":    len(hs.checkers),
		"enabled_checkers":  0,
		"disabled_checkers": 0,
		"cache_entries":     hs.cache.Size(),
		"running":           hs.running,
	}

	for _, checker := range hs.checkers {
		if checker.Enabled {
			stats["enabled_checkers"] = stats["enabled_checkers"].(int) + 1
		} else {
			stats["disabled_checkers"] = stats["disabled_checkers"].(int) + 1
		}
	}

	return stats
}

// schedulerLoop runs the main scheduler loop
func (hs *HealthScheduler) schedulerLoop(ctx context.Context) {
	defer hs.wg.Done()

	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-hs.stopChan:
			return
		case <-ticker.C:
			hs.runScheduledChecks(ctx)
		}
	}
}

// runScheduledChecks runs checks that are due
func (hs *HealthScheduler) runScheduledChecks(ctx context.Context) {
	hs.mutex.RLock()
	checkersToRun := make([]*ScheduledChecker, 0)
	now := time.Now()

	for _, checker := range hs.checkers {
		if checker.Enabled && now.Sub(checker.LastRun) >= checker.Interval {
			checkersToRun = append(checkersToRun, checker)
		}
	}
	hs.mutex.RUnlock()

	// Run checks concurrently
	for _, checker := range checkersToRun {
		go func(sc *ScheduledChecker) {
			result := hs.runCheck(ctx, sc)
			hs.cache.Set(sc.Checker.Name(), result, 0) // Use default TTL
		}(checker)
	}
}

// runCheck runs a single health check
func (hs *HealthScheduler) runCheck(ctx context.Context, scheduledChecker *ScheduledChecker) CheckResult {
	start := time.Now()

	// Create a timeout context for the check
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result := scheduledChecker.Checker.Check(checkCtx)

	// Update scheduled checker state
	scheduledChecker.mutex.Lock()
	scheduledChecker.LastRun = start
	scheduledChecker.LastResult = &result
	scheduledChecker.mutex.Unlock()

	// Log the result
	fields := logger.Fields{
		"checker":     result.Name,
		"status":      result.Status,
		"duration_ms": result.Duration.Milliseconds(),
		"critical":    result.Critical,
	}

	if result.Error != "" {
		fields["error"] = result.Error
	}

	switch result.Status {
	case StatusUnhealthy:
		hs.logger.WithFields(fields).Error("Health check failed")
	case StatusDegraded:
		hs.logger.WithFields(fields).Warn("Health check degraded")
	default:
		hs.logger.WithFields(fields).Debug("Health check passed")
	}

	return result
}

// HealthCache methods

// Get retrieves a cached result
func (hc *HealthCache) Get(name string) (*CheckResult, bool) {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	cached, exists := hc.results[name]
	if !exists {
		return nil, false
	}

	if time.Now().After(cached.ExpiresAt) {
		// Expired
		delete(hc.results, name)
		return nil, false
	}

	cached.Hits++
	result := cached.Result
	return &result, true
}

// Set stores a result in cache
func (hc *HealthCache) Set(name string, result CheckResult, ttl time.Duration) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	if ttl == 0 {
		ttl = hc.defaultTTL
	}

	hc.results[name] = &CachedResult{
		Result:    result,
		ExpiresAt: time.Now().Add(ttl),
		Hits:      0,
	}
}

// Delete removes a cached result
func (hc *HealthCache) Delete(name string) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	delete(hc.results, name)
}

// Size returns the number of cached results
func (hc *HealthCache) Size() int {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	return len(hc.results)
}

// Cleanup removes expired entries
func (hc *HealthCache) Cleanup() {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	now := time.Now()
	for name, cached := range hc.results {
		if now.After(cached.ExpiresAt) {
			delete(hc.results, name)
		}
	}
}

// GetStats returns cache statistics
func (hc *HealthCache) GetStats() map[string]interface{} {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	totalHits := int64(0)
	expiredCount := 0
	now := time.Now()

	for _, cached := range hc.results {
		totalHits += cached.Hits
		if now.After(cached.ExpiresAt) {
			expiredCount++
		}
	}

	return map[string]interface{}{
		"total_entries":   len(hc.results),
		"expired_entries": expiredCount,
		"total_hits":      totalHits,
		"default_ttl":     hc.defaultTTL.String(),
	}
}

// HealthAggregator aggregates health check results from multiple sources
type HealthAggregator struct {
	managers  map[string]*Manager
	scheduler *HealthScheduler
	mutex     sync.RWMutex
}

// NewHealthAggregator creates a new health aggregator
func NewHealthAggregator() *HealthAggregator {
	return &HealthAggregator{
		managers: make(map[string]*Manager),
	}
}

// AddManager adds a health manager to the aggregator
func (ha *HealthAggregator) AddManager(name string, manager *Manager) {
	ha.mutex.Lock()
	defer ha.mutex.Unlock()

	ha.managers[name] = manager
}

// SetScheduler sets the health scheduler
func (ha *HealthAggregator) SetScheduler(scheduler *HealthScheduler) {
	ha.mutex.Lock()
	defer ha.mutex.Unlock()

	ha.scheduler = scheduler
}

// GetAggregatedHealth returns aggregated health from all sources
func (ha *HealthAggregator) GetAggregatedHealth(ctx context.Context) map[string]HealthResponse {
	ha.mutex.RLock()
	defer ha.mutex.RUnlock()

	results := make(map[string]HealthResponse)

	// Get health from all managers
	for name, manager := range ha.managers {
		results[name] = manager.Check(ctx)
	}

	// Add scheduled/cached results if available
	if ha.scheduler != nil {
		cachedResults := ha.scheduler.GetAllCachedResults()
		if len(cachedResults) > 0 {
			// Create a synthetic health response from cached results
			overallStatus := StatusHealthy
			for _, result := range cachedResults {
				if result.Status == StatusUnhealthy && result.Critical {
					overallStatus = StatusUnhealthy
				} else if result.Status == StatusDegraded && overallStatus == StatusHealthy {
					overallStatus = StatusDegraded
				}
			}

			results["scheduled"] = HealthResponse{
				Status:    overallStatus,
				Timestamp: time.Now(),
				Checks:    cachedResults,
			}
		}
	}

	return results
}
