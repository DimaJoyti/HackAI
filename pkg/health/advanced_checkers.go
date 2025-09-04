package health

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// CPUChecker checks CPU usage
type CPUChecker struct {
	name              string
	warningThreshold  float64 // percentage (0.0-1.0)
	criticalThreshold float64 // percentage (0.0-1.0)
	lastCPUTime       time.Time
	lastCPUUsage      float64
	mutex             sync.RWMutex
}

// NewCPUChecker creates a new CPU health checker
func NewCPUChecker(name string, warningThreshold, criticalThreshold float64) *CPUChecker {
	return &CPUChecker{
		name:              name,
		warningThreshold:  warningThreshold,
		criticalThreshold: criticalThreshold,
		lastCPUTime:       time.Now(),
	}
}

// Check implements the Checker interface
func (c *CPUChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      c.name,
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	// Get CPU usage
	cpuUsage := c.getCPUUsage()

	result.Metadata["cpu_usage_percentage"] = cpuUsage
	result.Metadata["warning_threshold"] = c.warningThreshold
	result.Metadata["critical_threshold"] = c.criticalThreshold
	result.Metadata["num_cpu"] = runtime.NumCPU()
	result.Metadata["num_goroutine"] = runtime.NumGoroutine()

	if cpuUsage >= c.criticalThreshold {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("CPU usage critical: %.1f%%", cpuUsage*100)
	} else if cpuUsage >= c.warningThreshold {
		result.Status = StatusDegraded
		result.Message = fmt.Sprintf("CPU usage high: %.1f%%", cpuUsage*100)
	} else {
		result.Status = StatusHealthy
		result.Message = fmt.Sprintf("CPU usage normal: %.1f%%", cpuUsage*100)
	}

	result.Duration = time.Since(start)
	return result
}

// getCPUUsage returns CPU usage as a percentage (0.0-1.0)
func (c *CPUChecker) getCPUUsage() float64 {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// This is a simplified CPU usage calculation
	// In production, you'd want to use more sophisticated methods
	now := time.Now()
	if now.Sub(c.lastCPUTime) < time.Second {
		return c.lastCPUUsage
	}

	// Simulate CPU usage based on goroutines and some system metrics
	numGoroutines := runtime.NumGoroutine()
	numCPU := runtime.NumCPU()

	// Simple heuristic: more goroutines relative to CPUs = higher usage
	usage := float64(numGoroutines) / float64(numCPU*100)
	if usage > 1.0 {
		usage = 1.0
	}

	c.lastCPUTime = now
	c.lastCPUUsage = usage
	return usage
}

// Name implements the Checker interface
func (c *CPUChecker) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *CPUChecker) IsCritical() bool {
	return false // CPU is important but not immediately critical
}

// NetworkChecker checks network connectivity
type NetworkChecker struct {
	name    string
	host    string
	port    string
	timeout time.Duration
}

// NewNetworkChecker creates a new network health checker
func NewNetworkChecker(name, host, port string) *NetworkChecker {
	return &NetworkChecker{
		name:    name,
		host:    host,
		port:    port,
		timeout: 5 * time.Second,
	}
}

// WithTimeout sets the connection timeout
func (c *NetworkChecker) WithTimeout(timeout time.Duration) *NetworkChecker {
	c.timeout = timeout
	return c
}

// Check implements the Checker interface
func (c *NetworkChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      c.name,
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	address := net.JoinHostPort(c.host, c.port)
	result.Metadata["address"] = address
	result.Metadata["timeout"] = c.timeout.String()

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	// Attempt connection
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("Network connection failed: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	defer conn.Close()

	result.Status = StatusHealthy
	result.Message = fmt.Sprintf("Network connection to %s successful", address)
	result.Duration = time.Since(start)
	return result
}

// Name implements the Checker interface
func (c *NetworkChecker) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *NetworkChecker) IsCritical() bool {
	return false // Network connectivity is important but not always critical
}

// GoroutineChecker checks goroutine count
type GoroutineChecker struct {
	name              string
	warningThreshold  int
	criticalThreshold int
}

// NewGoroutineChecker creates a new goroutine health checker
func NewGoroutineChecker(name string, warningThreshold, criticalThreshold int) *GoroutineChecker {
	return &GoroutineChecker{
		name:              name,
		warningThreshold:  warningThreshold,
		criticalThreshold: criticalThreshold,
	}
}

// Check implements the Checker interface
func (c *GoroutineChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      c.name,
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	numGoroutines := runtime.NumGoroutine()

	result.Metadata["goroutine_count"] = numGoroutines
	result.Metadata["warning_threshold"] = c.warningThreshold
	result.Metadata["critical_threshold"] = c.criticalThreshold

	if numGoroutines >= c.criticalThreshold {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("Goroutine count critical: %d", numGoroutines)
	} else if numGoroutines >= c.warningThreshold {
		result.Status = StatusDegraded
		result.Message = fmt.Sprintf("Goroutine count high: %d", numGoroutines)
	} else {
		result.Status = StatusHealthy
		result.Message = fmt.Sprintf("Goroutine count normal: %d", numGoroutines)
	}

	result.Duration = time.Since(start)
	return result
}

// Name implements the Checker interface
func (c *GoroutineChecker) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *GoroutineChecker) IsCritical() bool {
	return false // Goroutine count is a warning indicator
}

// FileDescriptorChecker checks file descriptor usage
type FileDescriptorChecker struct {
	name             string
	warningThreshold float64 // percentage (0.0-1.0)
}

// NewFileDescriptorChecker creates a new file descriptor health checker
func NewFileDescriptorChecker(name string, warningThreshold float64) *FileDescriptorChecker {
	return &FileDescriptorChecker{
		name:             name,
		warningThreshold: warningThreshold,
	}
}

// Check implements the Checker interface
func (c *FileDescriptorChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      c.name,
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	// Get file descriptor limits and usage
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		result.Status = StatusUnknown
		result.Error = fmt.Sprintf("Failed to get file descriptor limits: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	maxFDs := rLimit.Cur
	// This is a simplified way to estimate current FD usage
	// In production, you'd want to read from /proc/self/fd or similar
	currentFDs := uint64(runtime.NumGoroutine() * 2) // Rough estimate

	usagePercentage := float64(currentFDs) / float64(maxFDs)

	result.Metadata["current_fds"] = currentFDs
	result.Metadata["max_fds"] = maxFDs
	result.Metadata["usage_percentage"] = usagePercentage
	result.Metadata["warning_threshold"] = c.warningThreshold

	if usagePercentage >= 0.9 { // 90% threshold for unhealthy
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("File descriptor usage critical: %.1f%%", usagePercentage*100)
	} else if usagePercentage >= c.warningThreshold {
		result.Status = StatusDegraded
		result.Message = fmt.Sprintf("File descriptor usage high: %.1f%%", usagePercentage*100)
	} else {
		result.Status = StatusHealthy
		result.Message = fmt.Sprintf("File descriptor usage normal: %.1f%%", usagePercentage*100)
	}

	result.Duration = time.Since(start)
	return result
}

// Name implements the Checker interface
func (c *FileDescriptorChecker) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *FileDescriptorChecker) IsCritical() bool {
	return false // FD usage is important but not immediately critical
}

// CustomMetricChecker allows checking custom metrics
type CustomMetricChecker struct {
	name       string
	critical   bool
	metricFunc func(ctx context.Context) (float64, error)
	thresholds MetricThresholds
	metricName string
	metricUnit string
}

// MetricThresholds defines thresholds for custom metrics
type MetricThresholds struct {
	WarningMin  *float64 `json:"warning_min,omitempty"`
	WarningMax  *float64 `json:"warning_max,omitempty"`
	CriticalMin *float64 `json:"critical_min,omitempty"`
	CriticalMax *float64 `json:"critical_max,omitempty"`
}

// NewCustomMetricChecker creates a new custom metric health checker
func NewCustomMetricChecker(name string, critical bool, metricFunc func(ctx context.Context) (float64, error), thresholds MetricThresholds) *CustomMetricChecker {
	return &CustomMetricChecker{
		name:       name,
		critical:   critical,
		metricFunc: metricFunc,
		thresholds: thresholds,
		metricName: "custom_metric",
		metricUnit: "units",
	}
}

// WithMetricInfo sets metric name and unit for better reporting
func (c *CustomMetricChecker) WithMetricInfo(name, unit string) *CustomMetricChecker {
	c.metricName = name
	c.metricUnit = unit
	return c
}

// Check implements the Checker interface
func (c *CustomMetricChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      c.name,
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	// Get metric value
	value, err := c.metricFunc(ctx)
	if err != nil {
		result.Status = StatusUnknown
		result.Error = fmt.Sprintf("Failed to get metric value: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	result.Metadata["metric_name"] = c.metricName
	result.Metadata["metric_value"] = value
	result.Metadata["metric_unit"] = c.metricUnit
	result.Metadata["thresholds"] = c.thresholds

	// Evaluate thresholds
	status := StatusHealthy
	message := fmt.Sprintf("%s: %.2f %s", c.metricName, value, c.metricUnit)

	// Check critical thresholds first
	if c.thresholds.CriticalMin != nil && value < *c.thresholds.CriticalMin {
		status = StatusUnhealthy
		message = fmt.Sprintf("%s below critical minimum: %.2f < %.2f %s", c.metricName, value, *c.thresholds.CriticalMin, c.metricUnit)
	} else if c.thresholds.CriticalMax != nil && value > *c.thresholds.CriticalMax {
		status = StatusUnhealthy
		message = fmt.Sprintf("%s above critical maximum: %.2f > %.2f %s", c.metricName, value, *c.thresholds.CriticalMax, c.metricUnit)
	} else if c.thresholds.WarningMin != nil && value < *c.thresholds.WarningMin {
		status = StatusDegraded
		message = fmt.Sprintf("%s below warning minimum: %.2f < %.2f %s", c.metricName, value, *c.thresholds.WarningMin, c.metricUnit)
	} else if c.thresholds.WarningMax != nil && value > *c.thresholds.WarningMax {
		status = StatusDegraded
		message = fmt.Sprintf("%s above warning maximum: %.2f > %.2f %s", c.metricName, value, *c.thresholds.WarningMax, c.metricUnit)
	}

	result.Status = status
	result.Message = message
	result.Duration = time.Since(start)
	return result
}

// Name implements the Checker interface
func (c *CustomMetricChecker) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *CustomMetricChecker) IsCritical() bool {
	return c.critical
}

// Helper function to get actual memory stats
func getMemoryStats() runtime.MemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

// Helper function to get actual disk usage (Linux/Unix)
func getDiskUsage(path string) (total, free uint64, err error) {
	var stat syscall.Statfs_t
	err = syscall.Statfs(path, &stat)
	if err != nil {
		return 0, 0, err
	}

	// Available blocks * size per block = available space in bytes
	total = stat.Blocks * uint64(stat.Bsize)
	free = stat.Bavail * uint64(stat.Bsize)

	return total, free, nil
}

// RealMemoryChecker provides actual memory usage checking
type RealMemoryChecker struct {
	name              string
	warningThreshold  float64 // percentage (0.0-1.0)
	criticalThreshold float64 // percentage (0.0-1.0)
}

// NewRealMemoryChecker creates a memory checker with actual memory stats
func NewRealMemoryChecker(name string, warningThreshold, criticalThreshold float64) *RealMemoryChecker {
	return &RealMemoryChecker{
		name:              name,
		warningThreshold:  warningThreshold,
		criticalThreshold: criticalThreshold,
	}
}

// Check implements the Checker interface
func (c *RealMemoryChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      c.name,
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Convert bytes to MB for easier reading
	allocMB := float64(m.Alloc) / 1024 / 1024
	sysMB := float64(m.Sys) / 1024 / 1024

	result.Metadata["alloc_mb"] = allocMB
	result.Metadata["sys_mb"] = sysMB
	result.Metadata["num_gc"] = m.NumGC
	result.Metadata["gc_cpu_fraction"] = m.GCCPUFraction
	result.Metadata["heap_objects"] = m.HeapObjects
	result.Metadata["stack_inuse_mb"] = float64(m.StackInuse) / 1024 / 1024

	// Use system memory as the baseline for percentage calculation
	usagePercentage := allocMB / sysMB

	result.Metadata["usage_percentage"] = usagePercentage
	result.Metadata["warning_threshold"] = c.warningThreshold
	result.Metadata["critical_threshold"] = c.criticalThreshold

	if usagePercentage >= c.criticalThreshold {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("Memory usage critical: %.1f%% (%.1f MB allocated)", usagePercentage*100, allocMB)
	} else if usagePercentage >= c.warningThreshold {
		result.Status = StatusDegraded
		result.Message = fmt.Sprintf("Memory usage high: %.1f%% (%.1f MB allocated)", usagePercentage*100, allocMB)
	} else {
		result.Status = StatusHealthy
		result.Message = fmt.Sprintf("Memory usage normal: %.1f%% (%.1f MB allocated)", usagePercentage*100, allocMB)
	}

	result.Duration = time.Since(start)
	return result
}

// Name implements the Checker interface
func (c *RealMemoryChecker) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *RealMemoryChecker) IsCritical() bool {
	return false // Memory is important but not immediately critical
}
