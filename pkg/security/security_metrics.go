package security

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// SecurityMetricsCollector collects and manages security metrics
type SecurityMetricsCollector struct {
	// Prometheus metrics
	threatDetections     *prometheus.CounterVec
	blockedRequests      *prometheus.CounterVec
	securityEvents       *prometheus.CounterVec
	threatScores         *prometheus.HistogramVec
	processingDuration   *prometheus.HistogramVec
	componentHealth      *prometheus.GaugeVec
	alertsTriggered      *prometheus.CounterVec
	falsePositives       *prometheus.CounterVec
	modelAccuracy        *prometheus.GaugeVec
	ruleEffectiveness    *prometheus.GaugeVec
	
	// Internal metrics storage
	metrics              *SecurityMetrics
	componentMetrics     map[string]*ComponentMetrics
	threatIntelMetrics   *ThreatIntelligenceMetrics
	performanceMetrics   *PerformanceMetrics
	
	// Configuration
	config               *MetricsConfig
	logger               Logger
	
	// Synchronization
	mu                   sync.RWMutex
	
	// Channels for real-time updates
	eventChan            chan *SecurityEvent
	metricsChan          chan *MetricUpdate
	
	// Background workers
	ctx                  context.Context
	cancel               context.CancelFunc
	wg                   sync.WaitGroup
}

// SecurityMetrics comprehensive security metrics
type SecurityMetrics struct {
	// Request metrics
	TotalRequests         int64                  `json:"total_requests"`
	BlockedRequests       int64                  `json:"blocked_requests"`
	AllowedRequests       int64                  `json:"allowed_requests"`
	
	// Threat detection metrics
	ThreatsDetected       int64                  `json:"threats_detected"`
	ThreatsByType         map[string]int64       `json:"threats_by_type"`
	ThreatsBySeverity     map[string]int64       `json:"threats_by_severity"`
	ThreatsBySource       map[string]int64       `json:"threats_by_source"`
	
	// Component-specific metrics
	PromptInjections      int64                  `json:"prompt_injections"`
	InputViolations       int64                  `json:"input_violations"`
	OutputSanitizations   int64                  `json:"output_sanitizations"`
	FirewallBlocks        int64                  `json:"firewall_blocks"`
	AgenticActions        int64                  `json:"agentic_actions"`
	
	// Performance metrics
	AverageProcessingTime time.Duration          `json:"average_processing_time"`
	MaxProcessingTime     time.Duration          `json:"max_processing_time"`
	MinProcessingTime     time.Duration          `json:"min_processing_time"`
	
	// Risk assessment metrics
	AverageRiskScore      float64                `json:"average_risk_score"`
	MaxRiskScore          float64                `json:"max_risk_score"`
	RiskDistribution      map[string]int64       `json:"risk_distribution"`
	
	// Alert metrics
	AlertsTriggered       int64                  `json:"alerts_triggered"`
	AlertsByChannel       map[string]int64       `json:"alerts_by_channel"`
	AlertsBySeverity      map[string]int64       `json:"alerts_by_severity"`
	
	// Accuracy metrics
	TruePositives         int64                  `json:"true_positives"`
	FalsePositives        int64                  `json:"false_positives"`
	TrueNegatives         int64                  `json:"true_negatives"`
	FalseNegatives        int64                  `json:"false_negatives"`
	
	// Temporal metrics
	StartTime             time.Time              `json:"start_time"`
	LastUpdated           time.Time              `json:"last_updated"`
	UptimeSeconds         int64                  `json:"uptime_seconds"`
}

// ComponentMetrics metrics for individual security components
type ComponentMetrics struct {
	ComponentName         string                 `json:"component_name"`
	Enabled               bool                   `json:"enabled"`
	RequestsProcessed     int64                  `json:"requests_processed"`
	ThreatsDetected       int64                  `json:"threats_detected"`
	ActionsExecuted       int64                  `json:"actions_executed"`
	AverageProcessingTime time.Duration          `json:"average_processing_time"`
	ErrorCount            int64                  `json:"error_count"`
	HealthStatus          string                 `json:"health_status"`
	LastHealthCheck       time.Time              `json:"last_health_check"`
	Configuration         map[string]interface{} `json:"configuration"`
}

// ThreatIntelligenceMetrics threat intelligence specific metrics
type ThreatIntelligenceMetrics struct {
	FeedsActive           int64                  `json:"feeds_active"`
	IndicatorsTotal       int64                  `json:"indicators_total"`
	IndicatorsByType      map[string]int64       `json:"indicators_by_type"`
	LastUpdate            time.Time              `json:"last_update"`
	UpdateFrequency       time.Duration          `json:"update_frequency"`
	MatchesFound          int64                  `json:"matches_found"`
	FalsePositiveRate     float64                `json:"false_positive_rate"`
	CoverageScore         float64                `json:"coverage_score"`
}

// PerformanceMetrics performance and resource utilization metrics
type PerformanceMetrics struct {
	CPUUsage              float64                `json:"cpu_usage"`
	MemoryUsage           int64                  `json:"memory_usage"`
	DiskUsage             int64                  `json:"disk_usage"`
	NetworkIO             int64                  `json:"network_io"`
	ConcurrentRequests    int64                  `json:"concurrent_requests"`
	QueueDepth            int64                  `json:"queue_depth"`
	CacheHitRate          float64                `json:"cache_hit_rate"`
	DatabaseConnections   int64                  `json:"database_connections"`
}

// SecurityEvent represents a security event for metrics
type SecurityEvent struct {
	ID                    string                 `json:"id"`
	Type                  string                 `json:"type"`
	Severity              string                 `json:"severity"`
	Source                string                 `json:"source"`
	Component             string                 `json:"component"`
	ThreatScore           float64                `json:"threat_score"`
	ProcessingTime        time.Duration          `json:"processing_time"`
	Action                string                 `json:"action"`
	Timestamp             time.Time              `json:"timestamp"`
	Metadata              map[string]interface{} `json:"metadata"`
}

// MetricUpdate represents a metric update
type MetricUpdate struct {
	MetricName            string                 `json:"metric_name"`
	Value                 float64                `json:"value"`
	Labels                map[string]string      `json:"labels"`
	Timestamp             time.Time              `json:"timestamp"`
}

// MetricsConfig configuration for metrics collection
type MetricsConfig struct {
	Enabled               bool                   `json:"enabled"`
	CollectionInterval    time.Duration          `json:"collection_interval"`
	RetentionPeriod       time.Duration          `json:"retention_period"`
	PrometheusEnabled     bool                   `json:"prometheus_enabled"`
	PrometheusNamespace   string                 `json:"prometheus_namespace"`
	BufferSize            int                    `json:"buffer_size"`
	ExportInterval        time.Duration          `json:"export_interval"`
	HealthCheckInterval   time.Duration          `json:"health_check_interval"`
	EnableDetailedMetrics bool                   `json:"enable_detailed_metrics"`
}

// Logger interface for metrics logging
type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

// NewSecurityMetricsCollector creates a new security metrics collector
func NewSecurityMetricsCollector(config *MetricsConfig, logger Logger) *SecurityMetricsCollector {
	ctx, cancel := context.WithCancel(context.Background())
	
	collector := &SecurityMetricsCollector{
		config:             config,
		logger:             logger,
		ctx:                ctx,
		cancel:             cancel,
		eventChan:          make(chan *SecurityEvent, config.BufferSize),
		metricsChan:        make(chan *MetricUpdate, config.BufferSize),
		componentMetrics:   make(map[string]*ComponentMetrics),
		metrics: &SecurityMetrics{
			ThreatsByType:     make(map[string]int64),
			ThreatsBySeverity: make(map[string]int64),
			ThreatsBySource:   make(map[string]int64),
			RiskDistribution:  make(map[string]int64),
			AlertsByChannel:   make(map[string]int64),
			AlertsBySeverity:  make(map[string]int64),
			StartTime:         time.Now(),
		},
		threatIntelMetrics: &ThreatIntelligenceMetrics{
			IndicatorsByType: make(map[string]int64),
		},
		performanceMetrics: &PerformanceMetrics{},
	}
	
	if config.PrometheusEnabled {
		collector.initPrometheusMetrics()
	}
	
	return collector
}

// initPrometheusMetrics initializes Prometheus metrics
func (smc *SecurityMetricsCollector) initPrometheusMetrics() {
	namespace := smc.config.PrometheusNamespace
	if namespace == "" {
		namespace = "security"
	}
	
	smc.threatDetections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "threat_detections_total",
			Help:      "Total number of threats detected",
		},
		[]string{"type", "severity", "component", "source"},
	)
	
	smc.blockedRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "blocked_requests_total",
			Help:      "Total number of blocked requests",
		},
		[]string{"reason", "component", "source"},
	)
	
	smc.securityEvents = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "security_events_total",
			Help:      "Total number of security events",
		},
		[]string{"event_type", "severity", "component"},
	)
	
	smc.threatScores = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "threat_scores",
			Help:      "Distribution of threat scores",
			Buckets:   []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
		},
		[]string{"component", "threat_type"},
	)
	
	smc.processingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "processing_duration_seconds",
			Help:      "Time spent processing security checks",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0},
		},
		[]string{"component", "operation"},
	)
	
	smc.componentHealth = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "component_health",
			Help:      "Health status of security components (1=healthy, 0=unhealthy)",
		},
		[]string{"component", "status"},
	)
	
	smc.alertsTriggered = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "alerts_triggered_total",
			Help:      "Total number of security alerts triggered",
		},
		[]string{"severity", "channel", "rule"},
	)
	
	smc.falsePositives = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "false_positives_total",
			Help:      "Total number of false positive detections",
		},
		[]string{"component", "threat_type"},
	)
	
	smc.modelAccuracy = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "model_accuracy",
			Help:      "Accuracy of security detection models",
		},
		[]string{"model", "component"},
	)
	
	smc.ruleEffectiveness = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "rule_effectiveness",
			Help:      "Effectiveness of security rules",
		},
		[]string{"rule_id", "component"},
	)
}

// Start starts the metrics collection
func (smc *SecurityMetricsCollector) Start() error {
	if !smc.config.Enabled {
		return nil
	}
	
	smc.logger.Info("Starting security metrics collector")
	
	// Start background workers
	smc.wg.Add(3)
	go smc.eventProcessor()
	go smc.metricsProcessor()
	go smc.healthChecker()
	
	return nil
}

// Stop stops the metrics collection
func (smc *SecurityMetricsCollector) Stop() error {
	smc.logger.Info("Stopping security metrics collector")
	
	smc.cancel()
	smc.wg.Wait()
	
	close(smc.eventChan)
	close(smc.metricsChan)
	
	return nil
}

// RecordSecurityEvent records a security event
func (smc *SecurityMetricsCollector) RecordSecurityEvent(event *SecurityEvent) {
	if !smc.config.Enabled {
		return
	}
	
	select {
	case smc.eventChan <- event:
	default:
		smc.logger.Warn("Security event channel full, dropping event", "event_id", event.ID)
	}
}

// RecordThreatDetection records a threat detection
func (smc *SecurityMetricsCollector) RecordThreatDetection(threatType, severity, component, source string, score float64) {
	event := &SecurityEvent{
		ID:          fmt.Sprintf("threat_%d", time.Now().UnixNano()),
		Type:        "threat_detection",
		Severity:    severity,
		Source:      source,
		Component:   component,
		ThreatScore: score,
		Timestamp:   time.Now(),
		Metadata: map[string]interface{}{
			"threat_type": threatType,
		},
	}
	
	smc.RecordSecurityEvent(event)
}

// RecordBlockedRequest records a blocked request
func (smc *SecurityMetricsCollector) RecordBlockedRequest(reason, component, source string) {
	event := &SecurityEvent{
		ID:        fmt.Sprintf("block_%d", time.Now().UnixNano()),
		Type:      "request_blocked",
		Severity:  "medium",
		Source:    source,
		Component: component,
		Timestamp: time.Now(),
		Action:    "block",
		Metadata: map[string]interface{}{
			"reason": reason,
		},
	}
	
	smc.RecordSecurityEvent(event)
}

// RecordProcessingTime records processing time for a component
func (smc *SecurityMetricsCollector) RecordProcessingTime(component, operation string, duration time.Duration) {
	if smc.processingDuration != nil {
		smc.processingDuration.WithLabelValues(component, operation).Observe(duration.Seconds())
	}
	
	update := &MetricUpdate{
		MetricName: "processing_time",
		Value:      duration.Seconds(),
		Labels: map[string]string{
			"component": component,
			"operation": operation,
		},
		Timestamp: time.Now(),
	}
	
	select {
	case smc.metricsChan <- update:
	default:
		// Channel full, skip this update
	}
}

// UpdateComponentHealth updates the health status of a component
func (smc *SecurityMetricsCollector) UpdateComponentHealth(component, status string, healthy bool) {
	if smc.componentHealth != nil {
		value := 0.0
		if healthy {
			value = 1.0
		}
		smc.componentHealth.WithLabelValues(component, status).Set(value)
	}
	
	smc.mu.Lock()
	if smc.componentMetrics[component] == nil {
		smc.componentMetrics[component] = &ComponentMetrics{
			ComponentName: component,
			Configuration: make(map[string]interface{}),
		}
	}
	smc.componentMetrics[component].HealthStatus = status
	smc.componentMetrics[component].LastHealthCheck = time.Now()
	smc.mu.Unlock()
}

// eventProcessor processes security events in the background
func (smc *SecurityMetricsCollector) eventProcessor() {
	defer smc.wg.Done()

	for {
		select {
		case <-smc.ctx.Done():
			return
		case event := <-smc.eventChan:
			smc.processSecurityEvent(event)
		}
	}
}

// metricsProcessor processes metric updates in the background
func (smc *SecurityMetricsCollector) metricsProcessor() {
	defer smc.wg.Done()

	ticker := time.NewTicker(smc.config.CollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-smc.ctx.Done():
			return
		case <-ticker.C:
			smc.collectSystemMetrics()
		case update := <-smc.metricsChan:
			smc.processMetricUpdate(update)
		}
	}
}

// healthChecker performs periodic health checks
func (smc *SecurityMetricsCollector) healthChecker() {
	defer smc.wg.Done()

	ticker := time.NewTicker(smc.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-smc.ctx.Done():
			return
		case <-ticker.C:
			smc.performHealthChecks()
		}
	}
}

// processSecurityEvent processes a single security event
func (smc *SecurityMetricsCollector) processSecurityEvent(event *SecurityEvent) {
	smc.mu.Lock()
	defer smc.mu.Unlock()

	// Update Prometheus metrics
	if smc.securityEvents != nil {
		smc.securityEvents.WithLabelValues(event.Type, event.Severity, event.Component).Inc()
	}

	// Update internal metrics
	switch event.Type {
	case "threat_detection":
		smc.metrics.ThreatsDetected++
		if threatType, ok := event.Metadata["threat_type"].(string); ok {
			smc.metrics.ThreatsByType[threatType]++
		}
		smc.metrics.ThreatsBySeverity[event.Severity]++
		smc.metrics.ThreatsBySource[event.Source]++

		// Record threat score
		if smc.threatScores != nil && event.ThreatScore > 0 {
			threatType := "unknown"
			if t, ok := event.Metadata["threat_type"].(string); ok {
				threatType = t
			}
			smc.threatScores.WithLabelValues(event.Component, threatType).Observe(event.ThreatScore)
		}

		// Update risk score statistics
		smc.updateRiskScoreStats(event.ThreatScore)

	case "request_blocked":
		smc.metrics.BlockedRequests++
		if reason, ok := event.Metadata["reason"].(string); ok && smc.blockedRequests != nil {
			smc.blockedRequests.WithLabelValues(reason, event.Component, event.Source).Inc()
		}

	case "alert_triggered":
		smc.metrics.AlertsTriggered++
		if channel, ok := event.Metadata["channel"].(string); ok {
			smc.metrics.AlertsByChannel[channel]++
		}
		smc.metrics.AlertsBySeverity[event.Severity]++
	}

	// Update component metrics
	if smc.componentMetrics[event.Component] == nil {
		smc.componentMetrics[event.Component] = &ComponentMetrics{
			ComponentName: event.Component,
			Configuration: make(map[string]interface{}),
		}
	}

	componentMetric := smc.componentMetrics[event.Component]
	componentMetric.RequestsProcessed++

	if event.Type == "threat_detection" {
		componentMetric.ThreatsDetected++
	}

	if event.Action != "" {
		componentMetric.ActionsExecuted++
	}

	// Update processing time
	if event.ProcessingTime > 0 {
		smc.updateProcessingTimeStats(componentMetric, event.ProcessingTime)
	}

	smc.metrics.LastUpdated = time.Now()
}

// processMetricUpdate processes a metric update
func (smc *SecurityMetricsCollector) processMetricUpdate(update *MetricUpdate) {
	smc.mu.Lock()
	defer smc.mu.Unlock()

	switch update.MetricName {
	case "processing_time":
		if component, ok := update.Labels["component"]; ok {
			if smc.componentMetrics[component] == nil {
				smc.componentMetrics[component] = &ComponentMetrics{
					ComponentName: component,
					Configuration: make(map[string]interface{}),
				}
			}

			duration := time.Duration(update.Value * float64(time.Second))
			smc.updateProcessingTimeStats(smc.componentMetrics[component], duration)
		}
	}
}

// updateRiskScoreStats updates risk score statistics
func (smc *SecurityMetricsCollector) updateRiskScoreStats(score float64) {
	if smc.metrics.AverageRiskScore == 0 {
		smc.metrics.AverageRiskScore = score
	} else {
		// Exponential moving average
		alpha := 0.1
		smc.metrics.AverageRiskScore = alpha*score + (1-alpha)*smc.metrics.AverageRiskScore
	}

	if score > smc.metrics.MaxRiskScore {
		smc.metrics.MaxRiskScore = score
	}

	// Update risk distribution
	riskLevel := smc.getRiskLevel(score)
	smc.metrics.RiskDistribution[riskLevel]++
}

// updateProcessingTimeStats updates processing time statistics
func (smc *SecurityMetricsCollector) updateProcessingTimeStats(componentMetric *ComponentMetrics, duration time.Duration) {
	if componentMetric.AverageProcessingTime == 0 {
		componentMetric.AverageProcessingTime = duration
	} else {
		// Exponential moving average
		alpha := 0.1
		avgNanos := float64(componentMetric.AverageProcessingTime.Nanoseconds())
		newAvg := alpha*float64(duration.Nanoseconds()) + (1-alpha)*avgNanos
		componentMetric.AverageProcessingTime = time.Duration(newAvg)
	}

	// Update global processing time stats
	if smc.metrics.AverageProcessingTime == 0 {
		smc.metrics.AverageProcessingTime = duration
		smc.metrics.MinProcessingTime = duration
		smc.metrics.MaxProcessingTime = duration
	} else {
		// Update average
		alpha := 0.1
		avgNanos := float64(smc.metrics.AverageProcessingTime.Nanoseconds())
		newAvg := alpha*float64(duration.Nanoseconds()) + (1-alpha)*avgNanos
		smc.metrics.AverageProcessingTime = time.Duration(newAvg)

		// Update min/max
		if duration < smc.metrics.MinProcessingTime {
			smc.metrics.MinProcessingTime = duration
		}
		if duration > smc.metrics.MaxProcessingTime {
			smc.metrics.MaxProcessingTime = duration
		}
	}
}

// getRiskLevel converts a risk score to a risk level
func (smc *SecurityMetricsCollector) getRiskLevel(score float64) string {
	switch {
	case score >= 0.8:
		return "critical"
	case score >= 0.6:
		return "high"
	case score >= 0.4:
		return "medium"
	case score >= 0.2:
		return "low"
	default:
		return "minimal"
	}
}

// collectSystemMetrics collects system performance metrics
func (smc *SecurityMetricsCollector) collectSystemMetrics() {
	// This would typically collect actual system metrics
	// For now, we'll simulate some basic metrics
	smc.mu.Lock()
	defer smc.mu.Unlock()

	smc.performanceMetrics.ConcurrentRequests = int64(len(smc.eventChan))
	smc.performanceMetrics.QueueDepth = int64(len(smc.metricsChan))

	// Update uptime
	smc.metrics.UptimeSeconds = int64(time.Since(smc.metrics.StartTime).Seconds())
}

// performHealthChecks performs health checks on components
func (smc *SecurityMetricsCollector) performHealthChecks() {
	smc.mu.RLock()
	components := make([]string, 0, len(smc.componentMetrics))
	for component := range smc.componentMetrics {
		components = append(components, component)
	}
	smc.mu.RUnlock()

	for _, component := range components {
		// Simulate health check - in real implementation, this would check actual component health
		healthy := true
		status := "healthy"

		smc.UpdateComponentHealth(component, status, healthy)
	}
}

// GetMetrics returns current security metrics
func (smc *SecurityMetricsCollector) GetMetrics() *SecurityMetrics {
	smc.mu.RLock()
	defer smc.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := *smc.metrics

	// Deep copy maps
	metrics.ThreatsByType = make(map[string]int64)
	for k, v := range smc.metrics.ThreatsByType {
		metrics.ThreatsByType[k] = v
	}

	metrics.ThreatsBySeverity = make(map[string]int64)
	for k, v := range smc.metrics.ThreatsBySeverity {
		metrics.ThreatsBySeverity[k] = v
	}

	metrics.ThreatsBySource = make(map[string]int64)
	for k, v := range smc.metrics.ThreatsBySource {
		metrics.ThreatsBySource[k] = v
	}

	metrics.RiskDistribution = make(map[string]int64)
	for k, v := range smc.metrics.RiskDistribution {
		metrics.RiskDistribution[k] = v
	}

	metrics.AlertsByChannel = make(map[string]int64)
	for k, v := range smc.metrics.AlertsByChannel {
		metrics.AlertsByChannel[k] = v
	}

	metrics.AlertsBySeverity = make(map[string]int64)
	for k, v := range smc.metrics.AlertsBySeverity {
		metrics.AlertsBySeverity[k] = v
	}

	return &metrics
}

// GetComponentMetrics returns metrics for a specific component
func (smc *SecurityMetricsCollector) GetComponentMetrics(component string) *ComponentMetrics {
	smc.mu.RLock()
	defer smc.mu.RUnlock()

	if metrics, exists := smc.componentMetrics[component]; exists {
		// Create a copy
		result := *metrics
		result.Configuration = make(map[string]interface{})
		for k, v := range metrics.Configuration {
			result.Configuration[k] = v
		}
		return &result
	}

	return nil
}

// GetAllComponentMetrics returns metrics for all components
func (smc *SecurityMetricsCollector) GetAllComponentMetrics() map[string]*ComponentMetrics {
	smc.mu.RLock()
	defer smc.mu.RUnlock()

	result := make(map[string]*ComponentMetrics)
	for component, metrics := range smc.componentMetrics {
		// Create a copy
		copied := *metrics
		copied.Configuration = make(map[string]interface{})
		for k, v := range metrics.Configuration {
			copied.Configuration[k] = v
		}
		result[component] = &copied
	}

	return result
}

// GetThreatIntelligenceMetrics returns threat intelligence metrics
func (smc *SecurityMetricsCollector) GetThreatIntelligenceMetrics() *ThreatIntelligenceMetrics {
	smc.mu.RLock()
	defer smc.mu.RUnlock()

	// Create a copy
	result := *smc.threatIntelMetrics
	result.IndicatorsByType = make(map[string]int64)
	for k, v := range smc.threatIntelMetrics.IndicatorsByType {
		result.IndicatorsByType[k] = v
	}

	return &result
}

// GetPerformanceMetrics returns performance metrics
func (smc *SecurityMetricsCollector) GetPerformanceMetrics() *PerformanceMetrics {
	smc.mu.RLock()
	defer smc.mu.RUnlock()

	return &PerformanceMetrics{
		CPUUsage:            smc.performanceMetrics.CPUUsage,
		MemoryUsage:         smc.performanceMetrics.MemoryUsage,
		DiskUsage:           smc.performanceMetrics.DiskUsage,
		NetworkIO:           smc.performanceMetrics.NetworkIO,
		ConcurrentRequests:  smc.performanceMetrics.ConcurrentRequests,
		QueueDepth:          smc.performanceMetrics.QueueDepth,
		CacheHitRate:        smc.performanceMetrics.CacheHitRate,
		DatabaseConnections: smc.performanceMetrics.DatabaseConnections,
	}
}

// ExportMetrics exports metrics in JSON format
func (smc *SecurityMetricsCollector) ExportMetrics() ([]byte, error) {
	metrics := smc.GetMetrics()
	return json.MarshalIndent(metrics, "", "  ")
}

// ResetMetrics resets all metrics
func (smc *SecurityMetricsCollector) ResetMetrics() {
	smc.mu.Lock()
	defer smc.mu.Unlock()

	smc.metrics = &SecurityMetrics{
		ThreatsByType:     make(map[string]int64),
		ThreatsBySeverity: make(map[string]int64),
		ThreatsBySource:   make(map[string]int64),
		RiskDistribution:  make(map[string]int64),
		AlertsByChannel:   make(map[string]int64),
		AlertsBySeverity:  make(map[string]int64),
		StartTime:         time.Now(),
	}

	smc.componentMetrics = make(map[string]*ComponentMetrics)
	smc.threatIntelMetrics = &ThreatIntelligenceMetrics{
		IndicatorsByType: make(map[string]int64),
	}
	smc.performanceMetrics = &PerformanceMetrics{}

	smc.logger.Info("Security metrics reset")
}
