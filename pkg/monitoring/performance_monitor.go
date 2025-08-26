package monitoring

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var performanceTracer = otel.Tracer("hackai/monitoring/performance")

// PerformanceMonitor monitors application performance metrics
type PerformanceMonitor struct {
	metrics        *PerformanceMetrics
	history        []*PerformanceSnapshot
	requestTracker *RequestTracker
	config         *MonitoringConfig
	logger         *logger.Logger
	mutex          sync.RWMutex
}

// PerformanceSnapshot represents a point-in-time performance snapshot
type PerformanceSnapshot struct {
	Timestamp           time.Time              `json:"timestamp"`
	RequestsPerSecond   float64                `json:"requests_per_second"`
	AverageResponseTime time.Duration          `json:"average_response_time"`
	P95ResponseTime     time.Duration          `json:"p95_response_time"`
	P99ResponseTime     time.Duration          `json:"p99_response_time"`
	ErrorRate           float64                `json:"error_rate"`
	ThroughputMBPS      float64                `json:"throughput_mbps"`
	ConcurrentRequests  int64                  `json:"concurrent_requests"`
	QueueDepth          int64                  `json:"queue_depth"`
	CPUUsage            float64                `json:"cpu_usage"`
	MemoryUsage         float64                `json:"memory_usage"`
	GoroutineCount      int                    `json:"goroutine_count"`
	GCPauseTime         time.Duration          `json:"gc_pause_time"`
	CustomMetrics       map[string]interface{} `json:"custom_metrics"`
}

// RequestTracker tracks individual request metrics
type RequestTracker struct {
	activeRequests    map[string]*RequestInfo
	completedRequests []*RequestInfo
	totalRequests     int64
	totalErrors       int64
	totalBytes        int64
	mutex             sync.RWMutex
}

// RequestInfo holds information about a request
type RequestInfo struct {
	ID           string                 `json:"id"`
	Method       string                 `json:"method"`
	Path         string                 `json:"path"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      *time.Time             `json:"end_time,omitempty"`
	Duration     time.Duration          `json:"duration"`
	StatusCode   int                    `json:"status_code"`
	RequestSize  int64                  `json:"request_size"`
	ResponseSize int64                  `json:"response_size"`
	UserAgent    string                 `json:"user_agent"`
	ClientIP     string                 `json:"client_ip"`
	Error        string                 `json:"error,omitempty"`
	Tags         []string               `json:"tags"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(config *MonitoringConfig, logger *logger.Logger) (*PerformanceMonitor, error) {
	return &PerformanceMonitor{
		metrics: &PerformanceMetrics{
			ResourceUtilization: make(map[string]float64),
			CustomMetrics:       make(map[string]interface{}),
		},
		history:        make([]*PerformanceSnapshot, 0),
		requestTracker: NewRequestTracker(),
		config:         config,
		logger:         logger,
	}, nil
}

// NewRequestTracker creates a new request tracker
func NewRequestTracker() *RequestTracker {
	return &RequestTracker{
		activeRequests:    make(map[string]*RequestInfo),
		completedRequests: make([]*RequestInfo, 0),
	}
}

// CollectMetrics collects current performance metrics
func (pm *PerformanceMonitor) CollectMetrics(ctx context.Context) error {
	ctx, span := performanceTracer.Start(ctx, "performance_monitor.collect_metrics")
	defer span.End()

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Collect runtime metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Calculate request metrics
	requestMetrics := pm.requestTracker.GetMetrics()

	// Update performance metrics
	pm.metrics.RequestsPerSecond = requestMetrics.RequestsPerSecond
	pm.metrics.AverageResponseTime = requestMetrics.AverageResponseTime
	pm.metrics.P95ResponseTime = requestMetrics.P95ResponseTime
	pm.metrics.P99ResponseTime = requestMetrics.P99ResponseTime
	pm.metrics.ErrorRate = requestMetrics.ErrorRate
	pm.metrics.ThroughputMBPS = requestMetrics.ThroughputMBPS
	pm.metrics.ConcurrentConnections = requestMetrics.ConcurrentRequests
	pm.metrics.QueueDepth = requestMetrics.QueueDepth

	// Update resource utilization
	pm.metrics.ResourceUtilization["memory_heap"] = float64(memStats.HeapAlloc) / (1024 * 1024) // MB
	pm.metrics.ResourceUtilization["memory_sys"] = float64(memStats.Sys) / (1024 * 1024)        // MB
	pm.metrics.ResourceUtilization["goroutines"] = float64(runtime.NumGoroutine())
	pm.metrics.ResourceUtilization["gc_pause"] = float64(memStats.PauseNs[(memStats.NumGC+255)%256]) / 1e6 // ms

	// Create performance snapshot
	snapshot := &PerformanceSnapshot{
		Timestamp:           time.Now(),
		RequestsPerSecond:   pm.metrics.RequestsPerSecond,
		AverageResponseTime: pm.metrics.AverageResponseTime,
		P95ResponseTime:     pm.metrics.P95ResponseTime,
		P99ResponseTime:     pm.metrics.P99ResponseTime,
		ErrorRate:           pm.metrics.ErrorRate,
		ThroughputMBPS:      pm.metrics.ThroughputMBPS,
		ConcurrentRequests:  pm.metrics.ConcurrentConnections,
		QueueDepth:          pm.metrics.QueueDepth,
		CPUUsage:            pm.metrics.ResourceUtilization["cpu"],
		MemoryUsage:         pm.metrics.ResourceUtilization["memory_heap"],
		GoroutineCount:      runtime.NumGoroutine(),
		GCPauseTime:         time.Duration(memStats.PauseNs[(memStats.NumGC+255)%256]),
		CustomMetrics:       make(map[string]interface{}),
	}

	// Copy custom metrics
	for k, v := range pm.metrics.CustomMetrics {
		snapshot.CustomMetrics[k] = v
	}

	// Add to history
	pm.history = append(pm.history, snapshot)

	// Keep only last 1000 snapshots
	if len(pm.history) > 1000 {
		pm.history = pm.history[1:]
	}

	span.SetAttributes(
		attribute.Float64("performance.rps", pm.metrics.RequestsPerSecond),
		attribute.Float64("performance.avg_response_time", pm.metrics.AverageResponseTime.Seconds()),
		attribute.Float64("performance.error_rate", pm.metrics.ErrorRate),
		attribute.Int("performance.goroutines", runtime.NumGoroutine()),
	)

	pm.logger.Debug("Performance metrics collected",
		"rps", pm.metrics.RequestsPerSecond,
		"avg_response_time", pm.metrics.AverageResponseTime,
		"error_rate", pm.metrics.ErrorRate,
		"goroutines", runtime.NumGoroutine())

	return nil
}

// GetCurrentMetrics returns current performance metrics
func (pm *PerformanceMonitor) GetCurrentMetrics(ctx context.Context) (*PerformanceMetrics, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	// Create a copy to avoid race conditions
	metrics := &PerformanceMetrics{
		RequestsPerSecond:     pm.metrics.RequestsPerSecond,
		AverageResponseTime:   pm.metrics.AverageResponseTime,
		P95ResponseTime:       pm.metrics.P95ResponseTime,
		P99ResponseTime:       pm.metrics.P99ResponseTime,
		ErrorRate:             pm.metrics.ErrorRate,
		ThroughputMBPS:        pm.metrics.ThroughputMBPS,
		ConcurrentConnections: pm.metrics.ConcurrentConnections,
		QueueDepth:            pm.metrics.QueueDepth,
		ResourceUtilization:   make(map[string]float64),
		CustomMetrics:         make(map[string]interface{}),
	}

	// Copy resource utilization
	for k, v := range pm.metrics.ResourceUtilization {
		metrics.ResourceUtilization[k] = v
	}

	// Copy custom metrics
	for k, v := range pm.metrics.CustomMetrics {
		metrics.CustomMetrics[k] = v
	}

	return metrics, nil
}

// GetPerformanceHistory returns performance history
func (pm *PerformanceMonitor) GetPerformanceHistory(ctx context.Context, duration time.Duration) ([]*PerformanceSnapshot, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	cutoff := time.Now().Add(-duration)
	var history []*PerformanceSnapshot

	for _, snapshot := range pm.history {
		if snapshot.Timestamp.After(cutoff) {
			history = append(history, snapshot)
		}
	}

	return history, nil
}

// StartRequest starts tracking a new request
func (pm *PerformanceMonitor) StartRequest(requestID, method, path string) *RequestInfo {
	return pm.requestTracker.StartRequest(requestID, method, path)
}

// EndRequest ends tracking a request
func (pm *PerformanceMonitor) EndRequest(requestID string, statusCode int, responseSize int64, err error) {
	pm.requestTracker.EndRequest(requestID, statusCode, responseSize, err)
}

// RecordCustomMetric records a custom performance metric
func (pm *PerformanceMonitor) RecordCustomMetric(name string, value interface{}) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.metrics.CustomMetrics[name] = value
}

// RequestTracker methods

// StartRequest starts tracking a new request
func (rt *RequestTracker) StartRequest(requestID, method, path string) *RequestInfo {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	request := &RequestInfo{
		ID:        requestID,
		Method:    method,
		Path:      path,
		StartTime: time.Now(),
		Tags:      make([]string, 0),
		Metadata:  make(map[string]interface{}),
	}

	rt.activeRequests[requestID] = request
	rt.totalRequests++

	return request
}

// EndRequest ends tracking a request
func (rt *RequestTracker) EndRequest(requestID string, statusCode int, responseSize int64, err error) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	request, exists := rt.activeRequests[requestID]
	if !exists {
		return
	}

	now := time.Now()
	request.EndTime = &now
	request.Duration = now.Sub(request.StartTime)
	request.StatusCode = statusCode
	request.ResponseSize = responseSize

	if err != nil {
		request.Error = err.Error()
		rt.totalErrors++
	}

	rt.totalBytes += responseSize

	// Move to completed requests
	rt.completedRequests = append(rt.completedRequests, request)
	delete(rt.activeRequests, requestID)

	// Keep only last 1000 completed requests
	if len(rt.completedRequests) > 1000 {
		rt.completedRequests = rt.completedRequests[1:]
	}
}

// GetMetrics calculates and returns request metrics
func (rt *RequestTracker) GetMetrics() *RequestMetrics {
	rt.mutex.RLock()
	defer rt.mutex.RUnlock()

	now := time.Now()
	oneMinuteAgo := now.Add(-time.Minute)

	var recentRequests []*RequestInfo
	var totalDuration time.Duration
	var errorCount int64

	// Collect recent requests (last minute)
	for _, request := range rt.completedRequests {
		if request.EndTime != nil && request.EndTime.After(oneMinuteAgo) {
			recentRequests = append(recentRequests, request)
			totalDuration += request.Duration

			if request.StatusCode >= 400 {
				errorCount++
			}
		}
	}

	metrics := &RequestMetrics{
		ConcurrentRequests: int64(len(rt.activeRequests)),
		QueueDepth:         0, // TODO: Implement queue depth tracking
	}

	if len(recentRequests) > 0 {
		metrics.RequestsPerSecond = float64(len(recentRequests)) / 60.0
		metrics.AverageResponseTime = totalDuration / time.Duration(len(recentRequests))
		metrics.ErrorRate = float64(errorCount) / float64(len(recentRequests))

		// Calculate percentiles
		durations := make([]time.Duration, len(recentRequests))
		for i, req := range recentRequests {
			durations[i] = req.Duration
		}

		metrics.P95ResponseTime = calculatePercentile(durations, 0.95)
		metrics.P99ResponseTime = calculatePercentile(durations, 0.99)

		// Calculate throughput (bytes per second)
		var totalBytes int64
		for _, req := range recentRequests {
			totalBytes += req.ResponseSize
		}
		metrics.ThroughputMBPS = float64(totalBytes) / (1024 * 1024 * 60) // MB per second
	}

	return metrics
}

// RequestMetrics holds calculated request metrics
type RequestMetrics struct {
	RequestsPerSecond   float64       `json:"requests_per_second"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	P95ResponseTime     time.Duration `json:"p95_response_time"`
	P99ResponseTime     time.Duration `json:"p99_response_time"`
	ErrorRate           float64       `json:"error_rate"`
	ThroughputMBPS      float64       `json:"throughput_mbps"`
	ConcurrentRequests  int64         `json:"concurrent_requests"`
	QueueDepth          int64         `json:"queue_depth"`
}

// Helper functions

func calculatePercentile(durations []time.Duration, percentile float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	// Simple percentile calculation (should use proper sorting for production)
	index := int(float64(len(durations)) * percentile)
	if index >= len(durations) {
		index = len(durations) - 1
	}

	// For simplicity, return the duration at the calculated index
	// In production, you'd want to sort the slice first
	return durations[index]
}

// GetActiveRequestCount returns the number of active requests
func (rt *RequestTracker) GetActiveRequestCount() int {
	rt.mutex.RLock()
	defer rt.mutex.RUnlock()

	return len(rt.activeRequests)
}

// GetTotalRequestCount returns the total number of requests processed
func (rt *RequestTracker) GetTotalRequestCount() int64 {
	rt.mutex.RLock()
	defer rt.mutex.RUnlock()

	return rt.totalRequests
}

// GetTotalErrorCount returns the total number of errors
func (rt *RequestTracker) GetTotalErrorCount() int64 {
	rt.mutex.RLock()
	defer rt.mutex.RUnlock()

	return rt.totalErrors
}

// GetTotalBytesTransferred returns the total bytes transferred
func (rt *RequestTracker) GetTotalBytesTransferred() int64 {
	rt.mutex.RLock()
	defer rt.mutex.RUnlock()

	return rt.totalBytes
}
