package monitoring

import (
	"context"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var systemTracer = otel.Tracer("hackai/monitoring/system")

// SystemMonitor monitors system-level metrics
type SystemMonitor struct {
	metrics      *SystemMetrics
	history      []*SystemSnapshot
	startTime    time.Time
	lastCPUTime  time.Time
	lastCPUUsage float64
	config       *MonitoringConfig
	logger       *logger.Logger
	mutex        sync.RWMutex
}

// SystemSnapshot represents a point-in-time system snapshot
type SystemSnapshot struct {
	Timestamp           time.Time              `json:"timestamp"`
	CPUUsagePercent     float64                `json:"cpu_usage_percent"`
	MemoryUsagePercent  float64                `json:"memory_usage_percent"`
	DiskUsagePercent    float64                `json:"disk_usage_percent"`
	NetworkInMBPS       float64                `json:"network_in_mbps"`
	NetworkOutMBPS      float64                `json:"network_out_mbps"`
	LoadAverage         []float64              `json:"load_average"`
	ProcessCount        int64                  `json:"process_count"`
	ThreadCount         int64                  `json:"thread_count"`
	FileDescriptorCount int64                  `json:"file_descriptor_count"`
	UptimeSeconds       int64                  `json:"uptime_seconds"`
	MemoryStats         *MemoryStats           `json:"memory_stats"`
	DiskStats           *DiskStats             `json:"disk_stats"`
	NetworkStats        *NetworkStats          `json:"network_stats"`
	CustomMetrics       map[string]interface{} `json:"custom_metrics"`
}

// MemoryStats holds detailed memory statistics
type MemoryStats struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	UsedPercent    float64 `json:"used_percent"`
	FreeBytes      uint64  `json:"free_bytes"`
	BuffersBytes   uint64  `json:"buffers_bytes"`
	CachedBytes    uint64  `json:"cached_bytes"`
	SwapTotal      uint64  `json:"swap_total"`
	SwapUsed       uint64  `json:"swap_used"`
	SwapFree       uint64  `json:"swap_free"`
}

// DiskStats holds disk usage statistics
type DiskStats struct {
	TotalBytes       uint64                `json:"total_bytes"`
	UsedBytes        uint64                `json:"used_bytes"`
	FreeBytes        uint64                `json:"free_bytes"`
	UsedPercent      float64               `json:"used_percent"`
	InodesTotal      uint64                `json:"inodes_total"`
	InodesUsed       uint64                `json:"inodes_used"`
	InodesFree       uint64                `json:"inodes_free"`
	ReadOpsPerSec    float64               `json:"read_ops_per_sec"`
	WriteOpsPerSec   float64               `json:"write_ops_per_sec"`
	ReadBytesPerSec  float64               `json:"read_bytes_per_sec"`
	WriteBytesPerSec float64               `json:"write_bytes_per_sec"`
	MountPoints      map[string]*DiskUsage `json:"mount_points"`
}

// DiskUsage holds usage for a specific mount point
type DiskUsage struct {
	Path        string  `json:"path"`
	TotalBytes  uint64  `json:"total_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

// NetworkStats holds network statistics
type NetworkStats struct {
	BytesReceivedPerSec   float64                    `json:"bytes_received_per_sec"`
	BytesSentPerSec       float64                    `json:"bytes_sent_per_sec"`
	PacketsReceivedPerSec float64                    `json:"packets_received_per_sec"`
	PacketsSentPerSec     float64                    `json:"packets_sent_per_sec"`
	ErrorsPerSec          float64                    `json:"errors_per_sec"`
	DroppedPerSec         float64                    `json:"dropped_per_sec"`
	Interfaces            map[string]*InterfaceStats `json:"interfaces"`
}

// InterfaceStats holds statistics for a network interface
type InterfaceStats struct {
	Name            string `json:"name"`
	BytesReceived   uint64 `json:"bytes_received"`
	BytesSent       uint64 `json:"bytes_sent"`
	PacketsReceived uint64 `json:"packets_received"`
	PacketsSent     uint64 `json:"packets_sent"`
	ErrorsIn        uint64 `json:"errors_in"`
	ErrorsOut       uint64 `json:"errors_out"`
	DroppedIn       uint64 `json:"dropped_in"`
	DroppedOut      uint64 `json:"dropped_out"`
}


// NewSystemMonitor creates a new system monitor
func NewSystemMonitor(config *MonitoringConfig, logger *logger.Logger) (*SystemMonitor, error) {
	return &SystemMonitor{
		metrics: &SystemMetrics{
			LoadAverage:   make([]float64, 3),
			CustomMetrics: make(map[string]interface{}),
		},
		history:   make([]*SystemSnapshot, 0),
		startTime: time.Now(),
		config:    config,
		logger:    logger,
	}, nil
}

// CollectMetrics collects current system metrics
func (sm *SystemMonitor) CollectMetrics(ctx context.Context) error {
	ctx, span := systemTracer.Start(ctx, "system_monitor.collect_metrics")
	defer span.End()

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Collect CPU metrics
	cpuUsage, err := sm.getCPUUsage()
	if err != nil {
		sm.logger.Warn("Failed to get CPU usage", "error", err)
		cpuUsage = 0
	}

	// Collect memory metrics
	memoryStats, err := sm.getMemoryStats()
	if err != nil {
		sm.logger.Warn("Failed to get memory stats", "error", err)
		memoryStats = &MemoryStats{}
	}

	// Collect disk metrics
	diskStats, err := sm.getDiskStats()
	if err != nil {
		sm.logger.Warn("Failed to get disk stats", "error", err)
		diskStats = &DiskStats{MountPoints: make(map[string]*DiskUsage)}
	}

	// Collect network metrics
	networkStats, err := sm.getNetworkStats()
	if err != nil {
		sm.logger.Warn("Failed to get network stats", "error", err)
		networkStats = &NetworkStats{Interfaces: make(map[string]*InterfaceStats)}
	}

	// Collect process metrics
	processCount, threadCount := sm.getProcessMetrics()

	// Collect file descriptor count
	fdCount := sm.getFileDescriptorCount()

	// Calculate uptime
	uptime := time.Since(sm.startTime)

	// Update system metrics
	sm.metrics.CPUUsagePercent = cpuUsage
	sm.metrics.MemoryUsagePercent = memoryStats.UsedPercent
	sm.metrics.DiskUsagePercent = diskStats.UsedPercent
	sm.metrics.NetworkInMBPS = networkStats.BytesReceivedPerSec / (1024 * 1024)
	sm.metrics.NetworkOutMBPS = networkStats.BytesSentPerSec / (1024 * 1024)
	sm.metrics.LoadAverage = sm.getLoadAverage()
	sm.metrics.ProcessCount = processCount
	sm.metrics.ThreadCount = threadCount
	sm.metrics.FileDescriptorCount = fdCount
	sm.metrics.UptimeSeconds = int64(uptime.Seconds())

	// Create system snapshot
	snapshot := &SystemSnapshot{
		Timestamp:           time.Now(),
		CPUUsagePercent:     cpuUsage,
		MemoryUsagePercent:  memoryStats.UsedPercent,
		DiskUsagePercent:    diskStats.UsedPercent,
		NetworkInMBPS:       sm.metrics.NetworkInMBPS,
		NetworkOutMBPS:      sm.metrics.NetworkOutMBPS,
		LoadAverage:         sm.metrics.LoadAverage,
		ProcessCount:        processCount,
		ThreadCount:         threadCount,
		FileDescriptorCount: fdCount,
		UptimeSeconds:       sm.metrics.UptimeSeconds,
		MemoryStats:         memoryStats,
		DiskStats:           diskStats,
		NetworkStats:        networkStats,
		CustomMetrics:       make(map[string]interface{}),
	}

	// Copy custom metrics
	for k, v := range sm.metrics.CustomMetrics {
		snapshot.CustomMetrics[k] = v
	}

	// Add to history
	sm.history = append(sm.history, snapshot)

	// Keep only last 1000 snapshots
	if len(sm.history) > 1000 {
		sm.history = sm.history[1:]
	}

	span.SetAttributes(
		attribute.Float64("system.cpu_usage", cpuUsage),
		attribute.Float64("system.memory_usage", memoryStats.UsedPercent),
		attribute.Float64("system.disk_usage", diskStats.UsedPercent),
		attribute.Int64("system.process_count", processCount),
		attribute.Int64("system.uptime", sm.metrics.UptimeSeconds),
	)

	sm.logger.Debug("System metrics collected",
		"cpu_usage", cpuUsage,
		"memory_usage", memoryStats.UsedPercent,
		"disk_usage", diskStats.UsedPercent,
		"process_count", processCount,
		"uptime", uptime)

	return nil
}

// GetCurrentMetrics returns current system metrics
func (sm *SystemMonitor) GetCurrentMetrics(ctx context.Context) (*SystemMetrics, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// Create a copy to avoid race conditions
	metrics := &SystemMetrics{
		CPUUsagePercent:     sm.metrics.CPUUsagePercent,
		MemoryUsagePercent:  sm.metrics.MemoryUsagePercent,
		DiskUsagePercent:    sm.metrics.DiskUsagePercent,
		NetworkInMBPS:       sm.metrics.NetworkInMBPS,
		NetworkOutMBPS:      sm.metrics.NetworkOutMBPS,
		LoadAverage:         make([]float64, len(sm.metrics.LoadAverage)),
		ProcessCount:        sm.metrics.ProcessCount,
		ThreadCount:         sm.metrics.ThreadCount,
		FileDescriptorCount: sm.metrics.FileDescriptorCount,
		UptimeSeconds:       sm.metrics.UptimeSeconds,
		CustomMetrics:       make(map[string]interface{}),
	}

	// Copy load average
	copy(metrics.LoadAverage, sm.metrics.LoadAverage)

	// Copy custom metrics
	for k, v := range sm.metrics.CustomMetrics {
		metrics.CustomMetrics[k] = v
	}

	return metrics, nil
}

// GetSystemHistory returns system metrics history
func (sm *SystemMonitor) GetSystemHistory(ctx context.Context, duration time.Duration) ([]*SystemSnapshot, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	cutoff := time.Now().Add(-duration)
	var history []*SystemSnapshot

	for _, snapshot := range sm.history {
		if snapshot.Timestamp.After(cutoff) {
			history = append(history, snapshot)
		}
	}

	return history, nil
}

// RecordCustomMetric records a custom system metric
func (sm *SystemMonitor) RecordCustomMetric(name string, value interface{}) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.metrics.CustomMetrics[name] = value
}

// Helper methods for collecting system metrics

func (sm *SystemMonitor) getCPUUsage() (float64, error) {
	// Simplified CPU usage calculation using runtime
	// In production, you'd want to use more accurate system calls
	var rusage syscall.Rusage
	err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage)
	if err != nil {
		return 0, err
	}

	// This is a simplified calculation
	// Real CPU usage would require reading /proc/stat on Linux
	return float64(runtime.NumGoroutine()) / 100.0, nil
}

func (sm *SystemMonitor) getMemoryStats() (*MemoryStats, error) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Get system memory info (simplified)
	stats := &MemoryStats{
		TotalBytes:     memStats.Sys,
		UsedBytes:      memStats.HeapAlloc,
		FreeBytes:      memStats.Sys - memStats.HeapAlloc,
		AvailableBytes: memStats.Sys - memStats.HeapAlloc,
	}

	if stats.TotalBytes > 0 {
		stats.UsedPercent = float64(stats.UsedBytes) / float64(stats.TotalBytes) * 100
	}

	return stats, nil
}

func (sm *SystemMonitor) getDiskStats() (*DiskStats, error) {
	// Get disk usage for root filesystem
	var stat syscall.Statfs_t
	err := syscall.Statfs("/", &stat)
	if err != nil {
		return nil, err
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	used := total - free

	stats := &DiskStats{
		TotalBytes:  total,
		UsedBytes:   used,
		FreeBytes:   free,
		MountPoints: make(map[string]*DiskUsage),
	}

	if total > 0 {
		stats.UsedPercent = float64(used) / float64(total) * 100
	}

	// Add root mount point
	stats.MountPoints["/"] = &DiskUsage{
		Path:        "/",
		TotalBytes:  total,
		UsedBytes:   used,
		FreeBytes:   free,
		UsedPercent: stats.UsedPercent,
	}

	return stats, nil
}

func (sm *SystemMonitor) getNetworkStats() (*NetworkStats, error) {
	// Simplified network stats
	// In production, you'd read from /proc/net/dev on Linux
	stats := &NetworkStats{
		Interfaces: make(map[string]*InterfaceStats),
	}

	return stats, nil
}

func (sm *SystemMonitor) getProcessMetrics() (int64, int64) {
	// Simplified process counting
	// In production, you'd read from /proc on Linux
	processCount := int64(runtime.NumGoroutine())
	threadCount := int64(runtime.NumGoroutine())

	return processCount, threadCount
}

func (sm *SystemMonitor) getFileDescriptorCount() int64 {
	// Simplified FD counting
	// In production, you'd read from /proc/self/fd on Linux
	return 0
}

func (sm *SystemMonitor) getLoadAverage() []float64 {
	// Simplified load average
	// In production, you'd read from /proc/loadavg on Linux
	return []float64{0.0, 0.0, 0.0}
}

// GetSystemInfo returns static system information
func (sm *SystemMonitor) GetSystemInfo() *SystemInfo {
	return &SystemInfo{
		Hostname:     sm.getHostname(),
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		CPUCores:     runtime.NumCPU(),
		GoVersion:    runtime.Version(),
		StartTime:    sm.startTime,
		Uptime:       time.Since(sm.startTime),
	}
}

// SystemInfo holds static system information
type SystemInfo struct {
	Hostname     string        `json:"hostname"`
	OS           string        `json:"os"`
	Architecture string        `json:"architecture"`
	CPUCores     int           `json:"cpu_cores"`
	GoVersion    string        `json:"go_version"`
	StartTime    time.Time     `json:"start_time"`
	Uptime       time.Duration `json:"uptime"`
}

func (sm *SystemMonitor) getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
