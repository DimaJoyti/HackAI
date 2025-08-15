package testing

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// PerformanceTester provides comprehensive performance testing capabilities
type PerformanceTester struct {
	logger *logger.Logger
	config *PerformanceTestConfig
}

// PerformanceTestConfig configuration for performance testing
type PerformanceTestConfig struct {
	LoadTestDuration    time.Duration       `json:"load_test_duration"`
	StressTestDuration  time.Duration       `json:"stress_test_duration"`
	SpikeTestDuration   time.Duration       `json:"spike_test_duration"`
	VolumeTestDuration  time.Duration       `json:"volume_test_duration"`
	MaxConcurrentUsers  int                 `json:"max_concurrent_users"`
	RampUpDuration      time.Duration       `json:"ramp_up_duration"`
	RampDownDuration    time.Duration       `json:"ramp_down_duration"`
	ThinkTime           time.Duration       `json:"think_time"`
	RequestTimeout      time.Duration       `json:"request_timeout"`
	AcceptableErrorRate float64             `json:"acceptable_error_rate"`
	ResponseTimeP95     time.Duration       `json:"response_time_p95"`
	ResponseTimeP99     time.Duration       `json:"response_time_p99"`
	ThroughputThreshold float64             `json:"throughput_threshold"`
	ResourceThresholds  *ResourceThresholds `json:"resource_thresholds"`
}

// ResourceThresholds defines acceptable resource usage limits
type ResourceThresholds struct {
	CPUUsagePercent    float64 `json:"cpu_usage_percent"`
	MemoryUsagePercent float64 `json:"memory_usage_percent"`
	DiskUsagePercent   float64 `json:"disk_usage_percent"`
	NetworkBandwidth   float64 `json:"network_bandwidth"`
}

// PerformanceMetrics represents performance test metrics
type PerformanceMetrics struct {
	TestType            string                 `json:"test_type"`
	StartTime           time.Time              `json:"start_time"`
	EndTime             time.Time              `json:"end_time"`
	Duration            time.Duration          `json:"duration"`
	TotalRequests       int64                  `json:"total_requests"`
	SuccessfulRequests  int64                  `json:"successful_requests"`
	FailedRequests      int64                  `json:"failed_requests"`
	ErrorRate           float64                `json:"error_rate"`
	Throughput          float64                `json:"throughput"`
	AverageResponseTime time.Duration          `json:"average_response_time"`
	MinResponseTime     time.Duration          `json:"min_response_time"`
	MaxResponseTime     time.Duration          `json:"max_response_time"`
	P50ResponseTime     time.Duration          `json:"p50_response_time"`
	P95ResponseTime     time.Duration          `json:"p95_response_time"`
	P99ResponseTime     time.Duration          `json:"p99_response_time"`
	ConcurrentUsers     int                    `json:"concurrent_users"`
	ResourceUsage       *ResourceUsage         `json:"resource_usage"`
	ResponseTimes       []time.Duration        `json:"response_times"`
	ErrorDetails        map[string]int         `json:"error_details"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// ResourceUsage represents system resource usage during testing
type ResourceUsage struct {
	CPUUsage    *MetricSeries `json:"cpu_usage"`
	MemoryUsage *MetricSeries `json:"memory_usage"`
	DiskUsage   *MetricSeries `json:"disk_usage"`
	NetworkIO   *MetricSeries `json:"network_io"`
}

// MetricSeries represents a time series of metric values
type MetricSeries struct {
	Timestamps []time.Time `json:"timestamps"`
	Values     []float64   `json:"values"`
	Average    float64     `json:"average"`
	Min        float64     `json:"min"`
	Max        float64     `json:"max"`
	P95        float64     `json:"p95"`
	P99        float64     `json:"p99"`
}

// LoadTestScenario defines a load testing scenario
type LoadTestScenario struct {
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	UserCount       int                    `json:"user_count"`
	Duration        time.Duration          `json:"duration"`
	RampUpDuration  time.Duration          `json:"ramp_up_duration"`
	ThinkTime       time.Duration          `json:"think_time"`
	RequestPattern  *RequestPattern        `json:"request_pattern"`
	ExpectedMetrics *ExpectedMetrics       `json:"expected_metrics"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// RequestPattern defines the pattern of requests to be made
type RequestPattern struct {
	Endpoints []EndpointConfig `json:"endpoints"`
	Sequence  []string         `json:"sequence"`
	Weight    map[string]int   `json:"weight"`
}

// EndpointConfig defines configuration for testing an endpoint
type EndpointConfig struct {
	Name     string            `json:"name"`
	URL      string            `json:"url"`
	Method   string            `json:"method"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	Timeout  time.Duration     `json:"timeout"`
	Weight   int               `json:"weight"`
	Validate func([]byte) bool `json:"-"`
}

// ExpectedMetrics defines expected performance metrics
type ExpectedMetrics struct {
	MaxResponseTime time.Duration `json:"max_response_time"`
	MaxErrorRate    float64       `json:"max_error_rate"`
	MinThroughput   float64       `json:"min_throughput"`
	MaxCPUUsage     float64       `json:"max_cpu_usage"`
	MaxMemoryUsage  float64       `json:"max_memory_usage"`
}

// PerformanceTestResult represents the complete result of performance testing
type PerformanceTestResult struct {
	TestID          string                 `json:"test_id"`
	TestType        string                 `json:"test_type"`
	Scenario        *LoadTestScenario      `json:"scenario"`
	Metrics         *PerformanceMetrics    `json:"metrics"`
	Passed          bool                   `json:"passed"`
	Issues          []string               `json:"issues"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// NewPerformanceTester creates a new performance tester instance
func NewPerformanceTester(logger *logger.Logger) *PerformanceTester {
	config := &PerformanceTestConfig{
		LoadTestDuration:    10 * time.Minute,
		StressTestDuration:  15 * time.Minute,
		SpikeTestDuration:   5 * time.Minute,
		VolumeTestDuration:  30 * time.Minute,
		MaxConcurrentUsers:  1000,
		RampUpDuration:      2 * time.Minute,
		RampDownDuration:    1 * time.Minute,
		ThinkTime:           1 * time.Second,
		RequestTimeout:      30 * time.Second,
		AcceptableErrorRate: 1.0,
		ResponseTimeP95:     500 * time.Millisecond,
		ResponseTimeP99:     1000 * time.Millisecond,
		ThroughputThreshold: 100.0,
		ResourceThresholds: &ResourceThresholds{
			CPUUsagePercent:    80.0,
			MemoryUsagePercent: 85.0,
			DiskUsagePercent:   90.0,
			NetworkBandwidth:   100.0,
		},
	}

	return &PerformanceTester{
		logger: logger,
		config: config,
	}
}

// RunLoadTest executes a load test scenario
func (pt *PerformanceTester) RunLoadTest(ctx context.Context, scenario *LoadTestScenario) (*PerformanceTestResult, error) {
	pt.logger.WithFields(map[string]interface{}{
		"scenario": scenario.Name,
		"users":    scenario.UserCount,
		"duration": scenario.Duration,
	}).Info("Starting load test")

	startTime := time.Now()

	// Initialize metrics collection
	metrics := &PerformanceMetrics{
		TestType:      "load_test",
		StartTime:     startTime,
		ResponseTimes: make([]time.Duration, 0),
		ErrorDetails:  make(map[string]int),
		Metadata:      make(map[string]interface{}),
	}

	// Start resource monitoring
	resourceMonitor := pt.startResourceMonitoring(ctx)

	// Execute the load test
	err := pt.executeLoadTest(ctx, scenario, metrics)
	if err != nil {
		return nil, fmt.Errorf("load test execution failed: %w", err)
	}

	// Stop resource monitoring
	resourceUsage := pt.stopResourceMonitoring(resourceMonitor)
	metrics.ResourceUsage = resourceUsage

	// Calculate final metrics
	pt.calculateMetrics(metrics)

	// Create test result
	result := &PerformanceTestResult{
		TestID:   fmt.Sprintf("load-test-%d", startTime.Unix()),
		TestType: "load_test",
		Scenario: scenario,
		Metrics:  metrics,
		Metadata: make(map[string]interface{}),
	}

	// Evaluate test results
	pt.evaluateResults(result, scenario.ExpectedMetrics)

	pt.logger.WithFields(map[string]interface{}{
		"test_id":    result.TestID,
		"duration":   metrics.Duration,
		"throughput": metrics.Throughput,
		"error_rate": metrics.ErrorRate,
		"passed":     result.Passed,
	}).Info("Load test completed")

	return result, nil
}

// RunStressTest executes a stress test to find breaking points
func (pt *PerformanceTester) RunStressTest(ctx context.Context, scenario *LoadTestScenario) (*PerformanceTestResult, error) {
	pt.logger.Info("Starting stress test")

	// Modify scenario for stress testing
	stressScenario := *scenario
	stressScenario.UserCount = pt.config.MaxConcurrentUsers
	stressScenario.Duration = pt.config.StressTestDuration

	result, err := pt.RunLoadTest(ctx, &stressScenario)
	if err != nil {
		return nil, err
	}

	result.TestType = "stress_test"
	result.Metrics.TestType = "stress_test"

	return result, nil
}

// RunSpikeTest executes a spike test with sudden load increases
func (pt *PerformanceTester) RunSpikeTest(ctx context.Context, scenario *LoadTestScenario) (*PerformanceTestResult, error) {
	pt.logger.Info("Starting spike test")

	// Implement spike test logic with sudden load increases
	spikeScenario := *scenario
	spikeScenario.Duration = pt.config.SpikeTestDuration
	spikeScenario.RampUpDuration = 10 * time.Second // Very fast ramp-up

	result, err := pt.RunLoadTest(ctx, &spikeScenario)
	if err != nil {
		return nil, err
	}

	result.TestType = "spike_test"
	result.Metrics.TestType = "spike_test"

	return result, nil
}

// RunVolumeTest executes a volume test with large amounts of data
func (pt *PerformanceTester) RunVolumeTest(ctx context.Context, scenario *LoadTestScenario) (*PerformanceTestResult, error) {
	pt.logger.Info("Starting volume test")

	volumeScenario := *scenario
	volumeScenario.Duration = pt.config.VolumeTestDuration

	result, err := pt.RunLoadTest(ctx, &volumeScenario)
	if err != nil {
		return nil, err
	}

	result.TestType = "volume_test"
	result.Metrics.TestType = "volume_test"

	return result, nil
}

// executeLoadTest executes the actual load test
func (pt *PerformanceTester) executeLoadTest(ctx context.Context, scenario *LoadTestScenario, metrics *PerformanceMetrics) error {
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Create channels for coordination
	// userChan := make(chan int, scenario.UserCount) // Commented out as not used
	resultChan := make(chan *RequestResult, scenario.UserCount*100)

	// Start result collector
	go pt.collectResults(resultChan, metrics, &mu)

	// Ramp up users
	rampUpInterval := scenario.RampUpDuration / time.Duration(scenario.UserCount)

	for i := 0; i < scenario.UserCount; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(rampUpInterval):
			wg.Add(1)
			go pt.simulateUser(ctx, &wg, i, scenario, resultChan)
		}
	}

	// Wait for test duration
	testTimer := time.NewTimer(scenario.Duration)
	defer testTimer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-testTimer.C:
		// Test duration completed
	}

	// Wait for all users to complete
	wg.Wait()
	close(resultChan)

	metrics.EndTime = time.Now()
	metrics.Duration = metrics.EndTime.Sub(metrics.StartTime)

	return nil
}

// RequestResult represents the result of a single request
type RequestResult struct {
	StartTime    time.Time
	EndTime      time.Time
	Duration     time.Duration
	Success      bool
	Error        string
	StatusCode   int
	ResponseSize int64
}

// simulateUser simulates a single user's behavior
func (pt *PerformanceTester) simulateUser(ctx context.Context, wg *sync.WaitGroup, userID int, scenario *LoadTestScenario, resultChan chan<- *RequestResult) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Execute request pattern
			for _, endpointName := range scenario.RequestPattern.Sequence {
				result := pt.executeRequest(ctx, scenario.RequestPattern, endpointName)
				resultChan <- result

				// Think time between requests
				time.Sleep(scenario.ThinkTime)
			}
		}
	}
}

// executeRequest executes a single HTTP request
func (pt *PerformanceTester) executeRequest(ctx context.Context, pattern *RequestPattern, endpointName string) *RequestResult {
	startTime := time.Now()

	// Find endpoint configuration
	var endpoint *EndpointConfig
	for _, ep := range pattern.Endpoints {
		if ep.Name == endpointName {
			endpoint = &ep
			break
		}
	}

	if endpoint == nil {
		return &RequestResult{
			StartTime: startTime,
			EndTime:   time.Now(),
			Duration:  time.Since(startTime),
			Success:   false,
			Error:     "endpoint not found",
		}
	}

	// Simulate HTTP request execution
	// In a real implementation, this would make actual HTTP requests
	randomDelay := 50 + (startTime.UnixNano() % 100)
	time.Sleep(time.Duration(randomDelay) * time.Millisecond) // Simulate variable response time

	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Simulate occasional failures
	success := (startTime.UnixNano() % 100) != 0 // 1% failure rate

	result := &RequestResult{
		StartTime:    startTime,
		EndTime:      endTime,
		Duration:     duration,
		Success:      success,
		StatusCode:   200,
		ResponseSize: 1024,
	}

	if !success {
		result.Error = "simulated error"
		result.StatusCode = 500
	}

	return result
}

// collectResults collects and aggregates request results
func (pt *PerformanceTester) collectResults(resultChan <-chan *RequestResult, metrics *PerformanceMetrics, mu *sync.Mutex) {
	for result := range resultChan {
		mu.Lock()

		metrics.TotalRequests++
		metrics.ResponseTimes = append(metrics.ResponseTimes, result.Duration)

		if result.Success {
			metrics.SuccessfulRequests++
		} else {
			metrics.FailedRequests++
			if result.Error != "" {
				metrics.ErrorDetails[result.Error]++
			}
		}

		mu.Unlock()
	}
}

// calculateMetrics calculates final performance metrics
func (pt *PerformanceTester) calculateMetrics(metrics *PerformanceMetrics) {
	if metrics.TotalRequests == 0 {
		return
	}

	// Calculate error rate
	metrics.ErrorRate = float64(metrics.FailedRequests) / float64(metrics.TotalRequests) * 100

	// Calculate throughput (requests per second)
	metrics.Throughput = float64(metrics.TotalRequests) / metrics.Duration.Seconds()

	// Calculate response time statistics
	if len(metrics.ResponseTimes) > 0 {
		pt.calculateResponseTimeStats(metrics)
	}
}

// calculateResponseTimeStats calculates response time statistics
func (pt *PerformanceTester) calculateResponseTimeStats(metrics *PerformanceMetrics) {
	responseTimes := metrics.ResponseTimes
	n := len(responseTimes)

	if n == 0 {
		return
	}

	// Sort response times for percentile calculations
	// Simple bubble sort for demonstration - use a proper sort in production
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if responseTimes[j] > responseTimes[j+1] {
				responseTimes[j], responseTimes[j+1] = responseTimes[j+1], responseTimes[j]
			}
		}
	}

	// Calculate min, max, average
	metrics.MinResponseTime = responseTimes[0]
	metrics.MaxResponseTime = responseTimes[n-1]

	var total time.Duration
	for _, rt := range responseTimes {
		total += rt
	}
	metrics.AverageResponseTime = total / time.Duration(n)

	// Calculate percentiles
	metrics.P50ResponseTime = responseTimes[int(float64(n)*0.5)]
	metrics.P95ResponseTime = responseTimes[int(float64(n)*0.95)]
	metrics.P99ResponseTime = responseTimes[int(float64(n)*0.99)]
}

// startResourceMonitoring starts monitoring system resources
func (pt *PerformanceTester) startResourceMonitoring(ctx context.Context) chan *ResourceUsage {
	resourceChan := make(chan *ResourceUsage, 1)

	go func() {
		defer close(resourceChan)

		usage := &ResourceUsage{
			CPUUsage:    &MetricSeries{},
			MemoryUsage: &MetricSeries{},
			DiskUsage:   &MetricSeries{},
			NetworkIO:   &MetricSeries{},
		}

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				resourceChan <- usage
				return
			case <-ticker.C:
				// Simulate resource monitoring
				timestamp := time.Now()

				usage.CPUUsage.Timestamps = append(usage.CPUUsage.Timestamps, timestamp)
				usage.CPUUsage.Values = append(usage.CPUUsage.Values, 45.0+math.Sin(float64(timestamp.Unix()))*10)

				usage.MemoryUsage.Timestamps = append(usage.MemoryUsage.Timestamps, timestamp)
				usage.MemoryUsage.Values = append(usage.MemoryUsage.Values, 60.0+math.Cos(float64(timestamp.Unix()))*5)
			}
		}
	}()

	return resourceChan
}

// stopResourceMonitoring stops resource monitoring and returns the collected data
func (pt *PerformanceTester) stopResourceMonitoring(resourceChan chan *ResourceUsage) *ResourceUsage {
	select {
	case usage := <-resourceChan:
		// Calculate statistics for each metric
		pt.calculateMetricStats(usage.CPUUsage)
		pt.calculateMetricStats(usage.MemoryUsage)
		pt.calculateMetricStats(usage.DiskUsage)
		pt.calculateMetricStats(usage.NetworkIO)
		return usage
	case <-time.After(5 * time.Second):
		// Timeout waiting for resource data
		return &ResourceUsage{}
	}
}

// calculateMetricStats calculates statistics for a metric series
func (pt *PerformanceTester) calculateMetricStats(series *MetricSeries) {
	if len(series.Values) == 0 {
		return
	}

	// Calculate min, max, average
	min := series.Values[0]
	max := series.Values[0]
	sum := 0.0

	for _, value := range series.Values {
		if value < min {
			min = value
		}
		if value > max {
			max = value
		}
		sum += value
	}

	series.Min = min
	series.Max = max
	series.Average = sum / float64(len(series.Values))

	// Calculate percentiles (simplified)
	n := len(series.Values)
	if n > 0 {
		series.P95 = series.Values[int(float64(n)*0.95)]
		series.P99 = series.Values[int(float64(n)*0.99)]
	}
}

// evaluateResults evaluates test results against expected metrics
func (pt *PerformanceTester) evaluateResults(result *PerformanceTestResult, expected *ExpectedMetrics) {
	result.Passed = true
	result.Issues = []string{}
	result.Recommendations = []string{}

	if expected == nil {
		return
	}

	metrics := result.Metrics

	// Check response time
	if expected.MaxResponseTime > 0 && metrics.P95ResponseTime > expected.MaxResponseTime {
		result.Passed = false
		result.Issues = append(result.Issues, fmt.Sprintf("P95 response time (%v) exceeds threshold (%v)",
			metrics.P95ResponseTime, expected.MaxResponseTime))
		result.Recommendations = append(result.Recommendations, "Optimize application performance or increase infrastructure capacity")
	}

	// Check error rate
	if expected.MaxErrorRate > 0 && metrics.ErrorRate > expected.MaxErrorRate {
		result.Passed = false
		result.Issues = append(result.Issues, fmt.Sprintf("Error rate (%.2f%%) exceeds threshold (%.2f%%)",
			metrics.ErrorRate, expected.MaxErrorRate))
		result.Recommendations = append(result.Recommendations, "Investigate and fix application errors")
	}

	// Check throughput
	if expected.MinThroughput > 0 && metrics.Throughput < expected.MinThroughput {
		result.Passed = false
		result.Issues = append(result.Issues, fmt.Sprintf("Throughput (%.2f req/s) below threshold (%.2f req/s)",
			metrics.Throughput, expected.MinThroughput))
		result.Recommendations = append(result.Recommendations, "Scale infrastructure or optimize application performance")
	}

	// Check resource usage
	if metrics.ResourceUsage != nil {
		if expected.MaxCPUUsage > 0 && metrics.ResourceUsage.CPUUsage.Average > expected.MaxCPUUsage {
			result.Issues = append(result.Issues, fmt.Sprintf("CPU usage (%.2f%%) exceeds threshold (%.2f%%)",
				metrics.ResourceUsage.CPUUsage.Average, expected.MaxCPUUsage))
			result.Recommendations = append(result.Recommendations, "Consider CPU optimization or scaling")
		}

		if expected.MaxMemoryUsage > 0 && metrics.ResourceUsage.MemoryUsage.Average > expected.MaxMemoryUsage {
			result.Issues = append(result.Issues, fmt.Sprintf("Memory usage (%.2f%%) exceeds threshold (%.2f%%)",
				metrics.ResourceUsage.MemoryUsage.Average, expected.MaxMemoryUsage))
			result.Recommendations = append(result.Recommendations, "Investigate memory leaks or increase memory allocation")
		}
	}

	// Add general recommendations
	if !result.Passed {
		result.Recommendations = append(result.Recommendations, "Run additional performance tests to identify bottlenecks")
		result.Recommendations = append(result.Recommendations, "Monitor application performance in production")
	}
}
