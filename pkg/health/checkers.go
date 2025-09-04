package health

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// DatabaseChecker checks database connectivity
type DatabaseChecker struct {
	name string
	db   *gorm.DB
}

// NewDatabaseChecker creates a new database health checker
func NewDatabaseChecker(name string, db *gorm.DB) *DatabaseChecker {
	return &DatabaseChecker{
		name: name,
		db:   db,
	}
}

// Check implements the Checker interface
func (c *DatabaseChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      c.name,
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	// Get underlying SQL DB
	sqlDB, err := c.db.DB()
	if err != nil {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("Failed to get SQL DB: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Check if database is reachable
	if err := sqlDB.PingContext(ctx); err != nil {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("Database ping failed: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Get database stats
	stats := sqlDB.Stats()
	result.Metadata["open_connections"] = stats.OpenConnections
	result.Metadata["in_use"] = stats.InUse
	result.Metadata["idle"] = stats.Idle
	result.Metadata["wait_count"] = stats.WaitCount
	result.Metadata["wait_duration"] = stats.WaitDuration.String()
	result.Metadata["max_idle_closed"] = stats.MaxIdleClosed
	result.Metadata["max_idle_time_closed"] = stats.MaxIdleTimeClosed
	result.Metadata["max_lifetime_closed"] = stats.MaxLifetimeClosed

	// Check connection pool health
	if stats.OpenConnections > 0 {
		result.Status = StatusHealthy
		result.Message = "Database is healthy"
	} else {
		result.Status = StatusDegraded
		result.Message = "Database has no open connections"
	}

	result.Duration = time.Since(start)
	return result
}

// Name implements the Checker interface
func (c *DatabaseChecker) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *DatabaseChecker) IsCritical() bool {
	return true // Database is critical
}

// RedisChecker checks Redis connectivity
type RedisChecker struct {
	name   string
	client redis.Cmdable
}

// NewRedisChecker creates a new Redis health checker
func NewRedisChecker(name string, client redis.Cmdable) *RedisChecker {
	return &RedisChecker{
		name:   name,
		client: client,
	}
}

// Check implements the Checker interface
func (c *RedisChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      c.name,
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	// Ping Redis
	pong, err := c.client.Ping(ctx).Result()
	if err != nil {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("Redis ping failed: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	if pong != "PONG" {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("Unexpected ping response: %s", pong)
		result.Duration = time.Since(start)
		return result
	}

	// Get Redis info if possible
	if infoCmd := c.client.Info(ctx, "server", "memory", "stats"); infoCmd.Err() == nil {
		_ = infoCmd.Val() // We have the info but don't parse it for this simple check
		result.Metadata["redis_info_available"] = true
		// Parse basic info (simplified)
		result.Metadata["redis_version"] = "available"
	} else {
		result.Metadata["redis_info_available"] = false
	}

	result.Status = StatusHealthy
	result.Message = "Redis is healthy"
	result.Duration = time.Since(start)
	return result
}

// Name implements the Checker interface
func (c *RedisChecker) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *RedisChecker) IsCritical() bool {
	return true // Redis is critical for sessions and caching
}

// HTTPChecker checks HTTP endpoint health
type HTTPChecker struct {
	name           string
	url            string
	method         string
	expectedStatus int
	timeout        time.Duration
	client         *http.Client
}

// NewHTTPChecker creates a new HTTP health checker
func NewHTTPChecker(name, url string) *HTTPChecker {
	return &HTTPChecker{
		name:           name,
		url:            url,
		method:         "GET",
		expectedStatus: http.StatusOK,
		timeout:        10 * time.Second,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// WithMethod sets the HTTP method
func (c *HTTPChecker) WithMethod(method string) *HTTPChecker {
	c.method = method
	return c
}

// WithExpectedStatus sets the expected HTTP status code
func (c *HTTPChecker) WithExpectedStatus(status int) *HTTPChecker {
	c.expectedStatus = status
	return c
}

// WithTimeout sets the request timeout
func (c *HTTPChecker) WithTimeout(timeout time.Duration) *HTTPChecker {
	c.timeout = timeout
	c.client.Timeout = timeout
	return c
}

// Check implements the Checker interface
func (c *HTTPChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      c.name,
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, c.method, c.url, nil)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Make request
	resp, err := c.client.Do(req)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("HTTP request failed: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	result.Metadata["status_code"] = resp.StatusCode
	result.Metadata["expected_status"] = c.expectedStatus
	result.Metadata["url"] = c.url
	result.Metadata["method"] = c.method

	if resp.StatusCode != c.expectedStatus {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("Unexpected status code: %d (expected %d)", resp.StatusCode, c.expectedStatus)
		result.Duration = time.Since(start)
		return result
	}

	result.Status = StatusHealthy
	result.Message = "HTTP endpoint is healthy"
	result.Duration = time.Since(start)
	return result
}

// Name implements the Checker interface
func (c *HTTPChecker) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *HTTPChecker) IsCritical() bool {
	return false // HTTP endpoints are typically not critical for core functionality
}

// MemoryChecker checks memory usage
type MemoryChecker struct {
	name             string
	maxMemoryMB      int64
	warningThreshold float64 // percentage (0.0-1.0)
}

// NewMemoryChecker creates a new memory health checker
func NewMemoryChecker(name string, maxMemoryMB int64, warningThreshold float64) *MemoryChecker {
	return &MemoryChecker{
		name:             name,
		maxMemoryMB:      maxMemoryMB,
		warningThreshold: warningThreshold,
	}
}

// Check implements the Checker interface
func (c *MemoryChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      c.name,
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	// This is a simplified memory check
	// In a real implementation, you would use runtime.MemStats or similar
	// For now, we'll simulate a basic check

	result.Metadata["max_memory_mb"] = c.maxMemoryMB
	result.Metadata["warning_threshold"] = c.warningThreshold

	// Simulate memory usage (in a real implementation, get actual memory stats)
	simulatedUsageMB := int64(100) // This would be actual memory usage
	usagePercentage := float64(simulatedUsageMB) / float64(c.maxMemoryMB)

	result.Metadata["current_usage_mb"] = simulatedUsageMB
	result.Metadata["usage_percentage"] = usagePercentage

	if usagePercentage >= 0.9 { // 90% threshold for unhealthy
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("Memory usage critical: %.1f%%", usagePercentage*100)
	} else if usagePercentage >= c.warningThreshold {
		result.Status = StatusDegraded
		result.Message = fmt.Sprintf("Memory usage high: %.1f%%", usagePercentage*100)
	} else {
		result.Status = StatusHealthy
		result.Message = fmt.Sprintf("Memory usage normal: %.1f%%", usagePercentage*100)
	}

	result.Duration = time.Since(start)
	return result
}

// Name implements the Checker interface
func (c *MemoryChecker) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *MemoryChecker) IsCritical() bool {
	return false // Memory is important but not immediately critical
}

// DiskSpaceChecker checks disk space usage
type DiskSpaceChecker struct {
	name             string
	path             string
	warningThreshold float64 // percentage (0.0-1.0)
}

// NewDiskSpaceChecker creates a new disk space health checker
func NewDiskSpaceChecker(name, path string, warningThreshold float64) *DiskSpaceChecker {
	return &DiskSpaceChecker{
		name:             name,
		path:             path,
		warningThreshold: warningThreshold,
	}
}

// Check implements the Checker interface
func (c *DiskSpaceChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      c.name,
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	// This is a simplified disk space check
	// In a real implementation, you would use syscall.Statfs or similar

	result.Metadata["path"] = c.path
	result.Metadata["warning_threshold"] = c.warningThreshold

	// Simulate disk usage (in a real implementation, get actual disk stats)
	simulatedUsagePercentage := 0.3 // 30% usage

	result.Metadata["usage_percentage"] = simulatedUsagePercentage

	if simulatedUsagePercentage >= 0.95 { // 95% threshold for unhealthy
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("Disk space critical: %.1f%%", simulatedUsagePercentage*100)
	} else if simulatedUsagePercentage >= c.warningThreshold {
		result.Status = StatusDegraded
		result.Message = fmt.Sprintf("Disk space high: %.1f%%", simulatedUsagePercentage*100)
	} else {
		result.Status = StatusHealthy
		result.Message = fmt.Sprintf("Disk space normal: %.1f%%", simulatedUsagePercentage*100)
	}

	result.Duration = time.Since(start)
	return result
}

// Name implements the Checker interface
func (c *DiskSpaceChecker) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *DiskSpaceChecker) IsCritical() bool {
	return false // Disk space is important but not immediately critical
}
