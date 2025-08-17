package chains

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var monitorTracer = otel.Tracer("hackai/llm/chains/monitor")

// ChainMonitor provides monitoring and health checking for chains
type ChainMonitor interface {
	// Lifecycle management
	InitializeChain(ctx context.Context, chainID string) error
	CleanupChain(ctx context.Context, chainID string) error

	// Execution monitoring
	RecordExecution(ctx context.Context, chainID string, duration time.Duration, success bool, metadata map[string]interface{}) error
	RecordError(ctx context.Context, chainID string, err error, metadata map[string]interface{}) error

	// Metrics retrieval
	GetMetrics(ctx context.Context, chainID string) (ChainMetrics, error)
	GetAggregatedMetrics(ctx context.Context, chainIDs []string, timeRange TimeRange) (AggregatedMetrics, error)

	// Health monitoring
	CheckHealth(ctx context.Context, chainID string) (ChainHealth, error)
	GetHealthStatus(ctx context.Context) (map[string]ChainHealth, error)
	SetHealthThresholds(ctx context.Context, chainID string, thresholds HealthThresholds) error

	// Alerting
	SetAlertRules(ctx context.Context, chainID string, rules []AlertRule) error
	GetActiveAlerts(ctx context.Context, chainID string) ([]Alert, error)
	AcknowledgeAlert(ctx context.Context, alertID string) error

	// Performance analysis
	GetPerformanceTrends(ctx context.Context, chainID string, timeRange TimeRange) (PerformanceTrends, error)
	GetBottlenecks(ctx context.Context, chainID string) ([]Bottleneck, error)
	GetRecommendations(ctx context.Context, chainID string) ([]Recommendation, error)
}

// DefaultChainMonitor implements the ChainMonitor interface
type DefaultChainMonitor struct {
	metrics          map[string]*ChainMetricsData
	healthStatus     map[string]*ChainHealthData
	alertRules       map[string][]AlertRule
	activeAlerts     map[string][]Alert
	healthThresholds map[string]HealthThresholds
	logger           *logger.Logger
	meter            metric.Meter
	mutex            sync.RWMutex

	// OpenTelemetry metrics
	executionCounter  metric.Int64Counter
	executionDuration metric.Float64Histogram
	errorCounter      metric.Int64Counter
	healthGauge       metric.Float64ObservableGauge
}

// ChainMetricsData stores detailed metrics for a chain
type ChainMetricsData struct {
	ChainID              string
	TotalExecutions      int64
	SuccessfulExecutions int64
	FailedExecutions     int64
	ExecutionTimes       []time.Duration
	Errors               []ErrorRecord
	LastExecuted         time.Time
	CreatedAt            time.Time
	mutex                sync.RWMutex
}

// ChainHealthData stores health information for a chain
type ChainHealthData struct {
	ChainID    string
	Status     string
	LastCheck  time.Time
	Issues     []HealthIssue
	Metrics    map[string]interface{}
	Thresholds HealthThresholds
	mutex      sync.RWMutex
}

// ErrorRecord represents an error occurrence
type ErrorRecord struct {
	Error     string                 `json:"error"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// TimeRange represents a time range for queries
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// AggregatedMetrics represents aggregated metrics across multiple chains
type AggregatedMetrics struct {
	TotalChains     int                     `json:"total_chains"`
	TotalExecutions int64                   `json:"total_executions"`
	AverageLatency  time.Duration           `json:"average_latency"`
	ErrorRate       float64                 `json:"error_rate"`
	ChainMetrics    map[string]ChainMetrics `json:"chain_metrics"`
	TimeRange       TimeRange               `json:"time_range"`
}

// HealthThresholds defines health check thresholds
type HealthThresholds struct {
	MaxErrorRate         float64       `json:"max_error_rate"`
	MaxLatency           time.Duration `json:"max_latency"`
	MinSuccessRate       float64       `json:"min_success_rate"`
	MaxConsecutiveErrors int           `json:"max_consecutive_errors"`
}

// AlertRule defines an alerting rule
type AlertRule struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Condition string                 `json:"condition"`
	Threshold float64                `json:"threshold"`
	Duration  time.Duration          `json:"duration"`
	Severity  string                 `json:"severity"`
	Enabled   bool                   `json:"enabled"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// Alert represents an active alert
type Alert struct {
	ID        string                 `json:"id"`
	RuleID    string                 `json:"rule_id"`
	ChainID   string                 `json:"chain_id"`
	Message   string                 `json:"message"`
	Severity  string                 `json:"severity"`
	Status    string                 `json:"status"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// PerformanceTrends represents performance trends over time
type PerformanceTrends struct {
	ChainID         string               `json:"chain_id"`
	TimeRange       TimeRange            `json:"time_range"`
	LatencyTrend    []DataPoint          `json:"latency_trend"`
	ThroughputTrend []DataPoint          `json:"throughput_trend"`
	ErrorRateTrend  []DataPoint          `json:"error_rate_trend"`
	Insights        []PerformanceInsight `json:"insights"`
}

// DataPoint represents a data point in a trend
type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// PerformanceInsight represents a performance insight
type PerformanceInsight struct {
	Type        string    `json:"type"`
	Message     string    `json:"message"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
	Suggestions []string  `json:"suggestions"`
}

// Bottleneck represents a performance bottleneck
type Bottleneck struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Impact      string                 `json:"impact"`
	Severity    string                 `json:"severity"`
	Suggestions []string               `json:"suggestions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Recommendation represents a performance recommendation
type Recommendation struct {
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Priority    string                 `json:"priority"`
	Impact      string                 `json:"impact"`
	Effort      string                 `json:"effort"`
	Actions     []string               `json:"actions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewDefaultChainMonitor creates a new default chain monitor
func NewDefaultChainMonitor(logger *logger.Logger) (*DefaultChainMonitor, error) {
	meter := otel.Meter("hackai/llm/chains/monitor")

	// Create OpenTelemetry metrics
	executionCounter, err := meter.Int64Counter(
		"chain_executions_total",
		metric.WithDescription("Total number of chain executions"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create execution counter: %w", err)
	}

	executionDuration, err := meter.Float64Histogram(
		"chain_execution_duration_seconds",
		metric.WithDescription("Chain execution duration in seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create execution duration histogram: %w", err)
	}

	errorCounter, err := meter.Int64Counter(
		"chain_errors_total",
		metric.WithDescription("Total number of chain errors"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create error counter: %w", err)
	}

	healthGauge, err := meter.Float64ObservableGauge(
		"chain_health_score",
		metric.WithDescription("Chain health score (0-1)"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create health gauge: %w", err)
	}

	return &DefaultChainMonitor{
		metrics:           make(map[string]*ChainMetricsData),
		healthStatus:      make(map[string]*ChainHealthData),
		alertRules:        make(map[string][]AlertRule),
		activeAlerts:      make(map[string][]Alert),
		healthThresholds:  make(map[string]HealthThresholds),
		logger:            logger,
		meter:             meter,
		executionCounter:  executionCounter,
		executionDuration: executionDuration,
		errorCounter:      errorCounter,
		healthGauge:       healthGauge,
	}, nil
}

// InitializeChain initializes monitoring for a new chain
func (m *DefaultChainMonitor) InitializeChain(ctx context.Context, chainID string) error {
	ctx, span := monitorTracer.Start(ctx, "monitor.initialize_chain",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Initialize metrics data
	m.metrics[chainID] = &ChainMetricsData{
		ChainID:              chainID,
		TotalExecutions:      0,
		SuccessfulExecutions: 0,
		FailedExecutions:     0,
		ExecutionTimes:       make([]time.Duration, 0),
		Errors:               make([]ErrorRecord, 0),
		CreatedAt:            time.Now(),
	}

	// Initialize health data
	m.healthStatus[chainID] = &ChainHealthData{
		ChainID:   chainID,
		Status:    "healthy",
		LastCheck: time.Now(),
		Issues:    make([]HealthIssue, 0),
		Metrics:   make(map[string]interface{}),
		Thresholds: HealthThresholds{
			MaxErrorRate:         0.05, // 5%
			MaxLatency:           30 * time.Second,
			MinSuccessRate:       0.95, // 95%
			MaxConsecutiveErrors: 5,
		},
	}

	// Initialize alert rules and active alerts
	m.alertRules[chainID] = make([]AlertRule, 0)
	m.activeAlerts[chainID] = make([]Alert, 0)

	span.SetAttributes(attribute.Bool("success", true))
	m.logger.Info("Chain monitoring initialized", "chain_id", chainID)

	return nil
}

// CleanupChain cleans up monitoring data for a chain
func (m *DefaultChainMonitor) CleanupChain(ctx context.Context, chainID string) error {
	ctx, span := monitorTracer.Start(ctx, "monitor.cleanup_chain",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Remove all monitoring data
	delete(m.metrics, chainID)
	delete(m.healthStatus, chainID)
	delete(m.alertRules, chainID)
	delete(m.activeAlerts, chainID)
	delete(m.healthThresholds, chainID)

	span.SetAttributes(attribute.Bool("success", true))
	m.logger.Info("Chain monitoring cleaned up", "chain_id", chainID)

	return nil
}

// RecordExecution records a chain execution
func (m *DefaultChainMonitor) RecordExecution(ctx context.Context, chainID string, duration time.Duration, success bool, metadata map[string]interface{}) error {
	ctx, span := monitorTracer.Start(ctx, "monitor.record_execution",
		trace.WithAttributes(
			attribute.String("chain.id", chainID),
			attribute.Bool("execution.success", success),
			attribute.String("execution.duration", duration.String()),
		),
	)
	defer span.End()

	m.mutex.RLock()
	metricsData, exists := m.metrics[chainID]
	m.mutex.RUnlock()

	if !exists {
		err := fmt.Errorf("chain %s not initialized for monitoring", chainID)
		span.RecordError(err)
		return err
	}

	metricsData.mutex.Lock()
	defer metricsData.mutex.Unlock()

	// Update metrics
	metricsData.TotalExecutions++
	if success {
		metricsData.SuccessfulExecutions++
	} else {
		metricsData.FailedExecutions++
	}
	metricsData.ExecutionTimes = append(metricsData.ExecutionTimes, duration)
	metricsData.LastExecuted = time.Now()

	// Keep only last 1000 execution times to prevent memory growth
	if len(metricsData.ExecutionTimes) > 1000 {
		metricsData.ExecutionTimes = metricsData.ExecutionTimes[len(metricsData.ExecutionTimes)-1000:]
	}

	// Record OpenTelemetry metrics
	m.executionCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("chain_id", chainID),
		attribute.Bool("success", success),
	))

	m.executionDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		attribute.String("chain_id", chainID),
	))

	// Update health status
	m.updateHealthStatus(ctx, chainID)

	// Check alert rules
	m.checkAlertRules(ctx, chainID)

	span.SetAttributes(attribute.Bool("success", true))

	return nil
}

// RecordError records an error for a chain
func (m *DefaultChainMonitor) RecordError(ctx context.Context, chainID string, err error, metadata map[string]interface{}) error {
	ctx, span := monitorTracer.Start(ctx, "monitor.record_error",
		trace.WithAttributes(
			attribute.String("chain.id", chainID),
			attribute.String("error", err.Error()),
		),
	)
	defer span.End()

	m.mutex.RLock()
	metricsData, exists := m.metrics[chainID]
	m.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("chain %s not initialized for monitoring", chainID)
	}

	metricsData.mutex.Lock()
	defer metricsData.mutex.Unlock()

	// Record error
	errorRecord := ErrorRecord{
		Error:     err.Error(),
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
	metricsData.Errors = append(metricsData.Errors, errorRecord)

	// Keep only last 100 errors to prevent memory growth
	if len(metricsData.Errors) > 100 {
		metricsData.Errors = metricsData.Errors[len(metricsData.Errors)-100:]
	}

	// Record OpenTelemetry metric
	m.errorCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("chain_id", chainID),
		attribute.String("error_type", "execution_error"),
	))

	// Update health status
	m.updateHealthStatus(ctx, chainID)

	span.SetAttributes(attribute.Bool("success", true))

	return nil
}

// GetMetrics retrieves metrics for a chain
func (m *DefaultChainMonitor) GetMetrics(ctx context.Context, chainID string) (ChainMetrics, error) {
	m.mutex.RLock()
	metricsData, exists := m.metrics[chainID]
	m.mutex.RUnlock()

	if !exists {
		return ChainMetrics{}, fmt.Errorf("chain %s not found", chainID)
	}

	metricsData.mutex.RLock()
	defer metricsData.mutex.RUnlock()

	// Calculate metrics
	var avgLatency time.Duration
	var p95Latency time.Duration
	var p99Latency time.Duration

	if len(metricsData.ExecutionTimes) > 0 {
		avgLatency = m.calculateAverageLatency(metricsData.ExecutionTimes)
		p95Latency = m.calculatePercentileLatency(metricsData.ExecutionTimes, 0.95)
		p99Latency = m.calculatePercentileLatency(metricsData.ExecutionTimes, 0.99)
	}

	errorRate := float64(0)
	if metricsData.TotalExecutions > 0 {
		errorRate = float64(metricsData.FailedExecutions) / float64(metricsData.TotalExecutions)
	}

	throughputPerMin := float64(0)
	if !metricsData.CreatedAt.IsZero() {
		minutes := time.Since(metricsData.CreatedAt).Minutes()
		if minutes > 0 {
			throughputPerMin = float64(metricsData.TotalExecutions) / minutes
		}
	}

	return ChainMetrics{
		ChainID:              chainID,
		TotalExecutions:      metricsData.TotalExecutions,
		SuccessfulExecutions: metricsData.SuccessfulExecutions,
		FailedExecutions:     metricsData.FailedExecutions,
		AverageLatency:       avgLatency,
		P95Latency:           p95Latency,
		P99Latency:           p99Latency,
		LastExecuted:         metricsData.LastExecuted,
		ErrorRate:            errorRate,
		ThroughputPerMin:     throughputPerMin,
	}, nil
}

// CheckHealth checks the health of a chain
func (m *DefaultChainMonitor) CheckHealth(ctx context.Context, chainID string) (ChainHealth, error) {
	ctx, span := monitorTracer.Start(ctx, "monitor.check_health",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	m.mutex.RLock()
	healthData, exists := m.healthStatus[chainID]
	m.mutex.RUnlock()

	if !exists {
		return ChainHealth{}, fmt.Errorf("chain %s not found", chainID)
	}

	healthData.mutex.RLock()
	defer healthData.mutex.RUnlock()

	// Update health gauge (observable gauges are updated via callbacks)
	healthScore := m.calculateHealthScore(ctx, chainID)

	span.SetAttributes(
		attribute.String("health.status", healthData.Status),
		attribute.Float64("health.score", healthScore),
		attribute.Bool("success", true),
	)

	return ChainHealth{
		ChainID:   chainID,
		Status:    healthData.Status,
		LastCheck: healthData.LastCheck,
		Issues:    healthData.Issues,
		Metrics:   healthData.Metrics,
	}, nil
}

// Helper methods

// updateHealthStatus updates the health status of a chain
func (m *DefaultChainMonitor) updateHealthStatus(ctx context.Context, chainID string) {
	healthData, exists := m.healthStatus[chainID]
	if !exists {
		return
	}

	healthData.mutex.Lock()
	defer healthData.mutex.Unlock()

	healthData.LastCheck = time.Now()
	healthData.Issues = []HealthIssue{} // Reset issues

	// Get current metrics
	metrics, err := m.GetMetrics(ctx, chainID)
	if err != nil {
		return
	}

	thresholds := healthData.Thresholds

	// Check error rate
	if metrics.ErrorRate > thresholds.MaxErrorRate {
		healthData.Issues = append(healthData.Issues, HealthIssue{
			Type:      "high_error_rate",
			Severity:  "warning",
			Message:   fmt.Sprintf("Error rate %.2f%% exceeds threshold %.2f%%", metrics.ErrorRate*100, thresholds.MaxErrorRate*100),
			Timestamp: time.Now(),
			Suggestions: []string{
				"Check recent error logs",
				"Review chain configuration",
				"Monitor dependencies",
			},
		})
	}

	// Check latency
	if metrics.AverageLatency > thresholds.MaxLatency {
		healthData.Issues = append(healthData.Issues, HealthIssue{
			Type:      "high_latency",
			Severity:  "warning",
			Message:   fmt.Sprintf("Average latency %v exceeds threshold %v", metrics.AverageLatency, thresholds.MaxLatency),
			Timestamp: time.Now(),
			Suggestions: []string{
				"Optimize chain logic",
				"Check provider performance",
				"Review resource allocation",
			},
		})
	}

	// Determine overall status
	if len(healthData.Issues) == 0 {
		healthData.Status = "healthy"
	} else {
		hasError := false
		for _, issue := range healthData.Issues {
			if issue.Severity == "error" || issue.Severity == "critical" {
				hasError = true
				break
			}
		}
		if hasError {
			healthData.Status = "unhealthy"
		} else {
			healthData.Status = "degraded"
		}
	}

	// Update metrics
	healthData.Metrics["error_rate"] = metrics.ErrorRate
	healthData.Metrics["average_latency"] = metrics.AverageLatency.Seconds()
	healthData.Metrics["total_executions"] = metrics.TotalExecutions
}

// checkAlertRules checks alert rules for a chain
func (m *DefaultChainMonitor) checkAlertRules(ctx context.Context, chainID string) {
	// This would implement alert rule checking logic
	// For brevity, this is a placeholder
}

// calculateAverageLatency calculates the average latency from execution times
func (m *DefaultChainMonitor) calculateAverageLatency(times []time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}

	var total time.Duration
	for _, t := range times {
		total += t
	}
	return total / time.Duration(len(times))
}

// calculatePercentileLatency calculates the percentile latency
func (m *DefaultChainMonitor) calculatePercentileLatency(times []time.Duration, percentile float64) time.Duration {
	if len(times) == 0 {
		return 0
	}

	// Simple percentile calculation (in production, you'd use a more sophisticated method)
	index := int(float64(len(times)) * percentile)
	if index >= len(times) {
		index = len(times) - 1
	}
	return times[index]
}

// calculateHealthScore calculates a health score for a chain
func (m *DefaultChainMonitor) calculateHealthScore(ctx context.Context, chainID string) float64 {
	metrics, err := m.GetMetrics(ctx, chainID)
	if err != nil {
		return 0.0
	}

	score := 1.0

	// Penalize high error rates
	if metrics.ErrorRate > 0 {
		score -= metrics.ErrorRate * 2 // Error rate penalty
	}

	// Penalize high latency (simplified)
	if metrics.AverageLatency > 10*time.Second {
		score -= 0.2
	}

	// Ensure score is between 0 and 1
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score
}

// GetAggregatedMetrics returns aggregated metrics across multiple chains
func (m *DefaultChainMonitor) GetAggregatedMetrics(ctx context.Context, chainIDs []string, timeRange TimeRange) (AggregatedMetrics, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	aggregated := AggregatedMetrics{
		TotalChains:     len(chainIDs),
		TotalExecutions: 0,
		ChainMetrics:    make(map[string]ChainMetrics),
		TimeRange:       timeRange,
	}

	var totalLatency time.Duration
	var totalErrors int64

	for _, chainID := range chainIDs {
		metrics, err := m.GetMetrics(ctx, chainID)
		if err != nil {
			continue // Skip chains that don't exist
		}

		aggregated.ChainMetrics[chainID] = metrics
		aggregated.TotalExecutions += metrics.TotalExecutions
		totalLatency += metrics.AverageLatency * time.Duration(metrics.TotalExecutions)
		totalErrors += metrics.FailedExecutions
	}

	// Calculate aggregated values
	if aggregated.TotalExecutions > 0 {
		aggregated.AverageLatency = totalLatency / time.Duration(aggregated.TotalExecutions)
		aggregated.ErrorRate = float64(totalErrors) / float64(aggregated.TotalExecutions)
	}

	return aggregated, nil
}

// GetHealthStatus returns health status for all chains
func (m *DefaultChainMonitor) GetHealthStatus(ctx context.Context) (map[string]ChainHealth, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	healthStatus := make(map[string]ChainHealth)

	for chainID := range m.healthStatus {
		health, err := m.CheckHealth(ctx, chainID)
		if err != nil {
			continue
		}
		healthStatus[chainID] = health
	}

	return healthStatus, nil
}

// SetHealthThresholds sets health check thresholds for a chain
func (m *DefaultChainMonitor) SetHealthThresholds(ctx context.Context, chainID string, thresholds HealthThresholds) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.healthThresholds[chainID] = thresholds

	// Update health data if it exists
	if healthData, exists := m.healthStatus[chainID]; exists {
		healthData.mutex.Lock()
		healthData.Thresholds = thresholds
		healthData.mutex.Unlock()
	}

	m.logger.Info("Health thresholds updated", "chain_id", chainID)
	return nil
}

// SetAlertRules sets alert rules for a chain
func (m *DefaultChainMonitor) SetAlertRules(ctx context.Context, chainID string, rules []AlertRule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.alertRules[chainID] = rules
	m.logger.Info("Alert rules updated", "chain_id", chainID, "rules_count", len(rules))
	return nil
}

// GetActiveAlerts returns active alerts for a chain
func (m *DefaultChainMonitor) GetActiveAlerts(ctx context.Context, chainID string) ([]Alert, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	alerts, exists := m.activeAlerts[chainID]
	if !exists {
		return []Alert{}, nil
	}

	// Return a copy to prevent modification
	result := make([]Alert, len(alerts))
	copy(result, alerts)
	return result, nil
}

// AcknowledgeAlert acknowledges an alert
func (m *DefaultChainMonitor) AcknowledgeAlert(ctx context.Context, alertID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Find and update the alert
	for chainID, alerts := range m.activeAlerts {
		for i, alert := range alerts {
			if alert.ID == alertID {
				alert.Status = "acknowledged"
				alert.UpdatedAt = time.Now()
				m.activeAlerts[chainID][i] = alert
				m.logger.Info("Alert acknowledged", "alert_id", alertID, "chain_id", chainID)
				return nil
			}
		}
	}

	return fmt.Errorf("alert %s not found", alertID)
}

// GetPerformanceTrends returns performance trends for a chain
func (m *DefaultChainMonitor) GetPerformanceTrends(ctx context.Context, chainID string, timeRange TimeRange) (PerformanceTrends, error) {
	// This would implement trend analysis
	// For now, return a placeholder
	return PerformanceTrends{
		ChainID:   chainID,
		TimeRange: timeRange,
		Insights:  []PerformanceInsight{},
	}, nil
}

// GetBottlenecks identifies performance bottlenecks for a chain
func (m *DefaultChainMonitor) GetBottlenecks(ctx context.Context, chainID string) ([]Bottleneck, error) {
	metrics, err := m.GetMetrics(ctx, chainID)
	if err != nil {
		return nil, err
	}

	var bottlenecks []Bottleneck

	// Check for high latency
	if metrics.AverageLatency > 10*time.Second {
		bottlenecks = append(bottlenecks, Bottleneck{
			Type:        "high_latency",
			Description: fmt.Sprintf("Average latency is %v, which is above recommended threshold", metrics.AverageLatency),
			Impact:      "high",
			Severity:    "warning",
			Suggestions: []string{
				"Optimize chain logic",
				"Check provider performance",
				"Review resource allocation",
			},
		})
	}

	// Check for high error rate
	if metrics.ErrorRate > 0.05 { // 5%
		bottlenecks = append(bottlenecks, Bottleneck{
			Type:        "high_error_rate",
			Description: fmt.Sprintf("Error rate is %.2f%%, which is above recommended threshold", metrics.ErrorRate*100),
			Impact:      "high",
			Severity:    "error",
			Suggestions: []string{
				"Review error logs",
				"Check input validation",
				"Monitor dependencies",
			},
		})
	}

	return bottlenecks, nil
}

// GetRecommendations provides performance recommendations for a chain
func (m *DefaultChainMonitor) GetRecommendations(ctx context.Context, chainID string) ([]Recommendation, error) {
	metrics, err := m.GetMetrics(ctx, chainID)
	if err != nil {
		return nil, err
	}

	var recommendations []Recommendation

	// Low usage recommendation
	if metrics.TotalExecutions < 10 {
		recommendations = append(recommendations, Recommendation{
			Type:        "usage_optimization",
			Title:       "Low Usage Detected",
			Description: "This chain has very low usage. Consider promoting it or reviewing its utility.",
			Priority:    "low",
			Impact:      "medium",
			Effort:      "low",
			Actions: []string{
				"Review chain documentation",
				"Add usage examples",
				"Promote to relevant teams",
			},
		})
	}

	// Performance optimization
	if metrics.AverageLatency > 5*time.Second {
		recommendations = append(recommendations, Recommendation{
			Type:        "performance_optimization",
			Title:       "Performance Optimization Needed",
			Description: "Chain latency is higher than optimal. Consider optimization strategies.",
			Priority:    "high",
			Impact:      "high",
			Effort:      "medium",
			Actions: []string{
				"Profile chain execution",
				"Optimize prompt templates",
				"Consider caching strategies",
			},
		})
	}

	return recommendations, nil
}
