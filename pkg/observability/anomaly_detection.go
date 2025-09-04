package observability

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var anomalyTracer = otel.Tracer("hackai/observability/anomaly")

// AnomalyDetector detects anomalies in metrics and system behavior
type AnomalyDetector struct {
	id     string
	config *EnhancedMonitoringConfig
	logger *logger.Logger

	// Detection algorithms
	algorithms     map[string]AnomalyAlgorithm
	detectionRules map[string]*AnomalyDetectionRule

	// Historical data for baseline
	historicalData map[string]*HistoricalMetrics
	baselines      map[string]*Baseline

	// Anomaly tracking
	detectedAnomalies map[string]*Anomaly
	anomalyHistory    []*Anomaly

	// Machine learning models
	mlModels map[string]*MLModel

	// Configuration
	sensitivity         float64
	confidenceThreshold float64

	mutex sync.RWMutex
}

// AnomalyAlgorithm defines the interface for anomaly detection algorithms
type AnomalyAlgorithm interface {
	Name() string
	Detect(ctx context.Context, data []float64, baseline *Baseline) (*AnomalyResult, error)
	Train(ctx context.Context, historicalData []float64) error
	GetConfidence() float64
}

// AnomalyDetectionRule defines rules for anomaly detection
type AnomalyDetectionRule struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	MetricPattern string            `json:"metric_pattern"`
	Algorithm     string            `json:"algorithm"`
	Sensitivity   float64           `json:"sensitivity"`
	WindowSize    time.Duration     `json:"window_size"`
	MinDataPoints int               `json:"min_data_points"`
	Enabled       bool              `json:"enabled"`
	Filters       map[string]string `json:"filters"`
	Actions       []AnomalyAction   `json:"actions"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// AnomalyAction defines actions to take when anomaly is detected
type AnomalyAction struct {
	Type       ActionType             `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
	Enabled    bool                   `json:"enabled"`
}

// ActionType defines the type of action
type ActionType string

const (
	ActionAlert   ActionType = "alert"
	ActionNotify  ActionType = "notify"
	ActionScale   ActionType = "scale"
	ActionRestart ActionType = "restart"
	ActionLog     ActionType = "log"
	ActionWebhook ActionType = "webhook"
)

// Anomaly represents a detected anomaly
type Anomaly struct {
	ID            string                 `json:"id"`
	RuleID        string                 `json:"rule_id"`
	MetricName    string                 `json:"metric_name"`
	Algorithm     string                 `json:"algorithm"`
	Severity      AnomalySeverity        `json:"severity"`
	Confidence    float64                `json:"confidence"`
	Value         float64                `json:"value"`
	ExpectedValue float64                `json:"expected_value"`
	Deviation     float64                `json:"deviation"`
	Timestamp     time.Time              `json:"timestamp"`
	Duration      time.Duration          `json:"duration"`
	Status        AnomalyStatus          `json:"status"`
	Description   string                 `json:"description"`
	Context       map[string]interface{} `json:"context"`
	Actions       []AnomalyAction        `json:"actions"`
	Resolved      bool                   `json:"resolved"`
	ResolvedAt    *time.Time             `json:"resolved_at,omitempty"`
}

// AnomalySeverity defines the severity of an anomaly
type AnomalySeverity string

const (
	SeverityLow      AnomalySeverity = "low"
	SeverityMedium   AnomalySeverity = "medium"
	SeverityHigh     AnomalySeverity = "high"
	SeverityCritical AnomalySeverity = "critical"
)

// AnomalyStatus defines the status of an anomaly
type AnomalyStatus string

const (
	StatusDetected      AnomalyStatus = "detected"
	StatusInvestigating AnomalyStatus = "investigating"
	StatusConfirmed     AnomalyStatus = "confirmed"
	StatusResolved      AnomalyStatus = "resolved"
	StatusFalsePositive AnomalyStatus = "false_positive"
)

// AnomalyResult represents the result of anomaly detection
type AnomalyResult struct {
	IsAnomaly     bool                   `json:"is_anomaly"`
	Confidence    float64                `json:"confidence"`
	Severity      AnomalySeverity        `json:"severity"`
	Score         float64                `json:"score"`
	ExpectedValue float64                `json:"expected_value"`
	ActualValue   float64                `json:"actual_value"`
	Deviation     float64                `json:"deviation"`
	Algorithm     string                 `json:"algorithm"`
	Context       map[string]interface{} `json:"context"`
}

// HistoricalMetrics stores historical data for baseline calculation
type HistoricalMetrics struct {
	MetricName  string            `json:"metric_name"`
	Values      []TimeSeriesPoint `json:"values"`
	WindowSize  time.Duration     `json:"window_size"`
	LastUpdated time.Time         `json:"last_updated"`
}

// TimeSeriesPoint represents a point in time series
type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// Baseline represents the baseline for a metric
type Baseline struct {
	MetricName        string              `json:"metric_name"`
	Mean              float64             `json:"mean"`
	StandardDeviation float64             `json:"standard_deviation"`
	Min               float64             `json:"min"`
	Max               float64             `json:"max"`
	Percentiles       map[string]float64  `json:"percentiles"`
	Seasonality       *SeasonalityPattern `json:"seasonality,omitempty"`
	Trend             *TrendPattern       `json:"trend,omitempty"`
	LastCalculated    time.Time           `json:"last_calculated"`
	DataPoints        int                 `json:"data_points"`
}

// SeasonalityPattern represents seasonal patterns in data
type SeasonalityPattern struct {
	Period     time.Duration `json:"period"`
	Amplitude  float64       `json:"amplitude"`
	Phase      float64       `json:"phase"`
	Confidence float64       `json:"confidence"`
}

// TrendPattern represents trend patterns in data
type TrendPattern struct {
	Direction  TrendDirection `json:"direction"`
	Slope      float64        `json:"slope"`
	Confidence float64        `json:"confidence"`
}

// TrendDirection defines the direction of a trend
type TrendDirection string

const (
	TrendIncreasing TrendDirection = "increasing"
	TrendDecreasing TrendDirection = "decreasing"
	TrendStable     TrendDirection = "stable"
)

// MLModel represents a machine learning model for anomaly detection
type MLModel struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         MLModelType            `json:"type"`
	Parameters   map[string]interface{} `json:"parameters"`
	TrainingData []float64              `json:"training_data"`
	Accuracy     float64                `json:"accuracy"`
	LastTrained  time.Time              `json:"last_trained"`
	Version      string                 `json:"version"`
}

// MLModelType defines the type of ML model
type MLModelType string

const (
	ModelIsolationForest MLModelType = "isolation_forest"
	ModelOneClassSVM     MLModelType = "one_class_svm"
	ModelLSTM            MLModelType = "lstm"
	ModelAutoencoder     MLModelType = "autoencoder"
	ModelStatistical     MLModelType = "statistical"
)

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(config *EnhancedMonitoringConfig, logger *logger.Logger) (*AnomalyDetector, error) {
	detector := &AnomalyDetector{
		id:                  uuid.New().String(),
		config:              config,
		logger:              logger,
		algorithms:          make(map[string]AnomalyAlgorithm),
		detectionRules:      make(map[string]*AnomalyDetectionRule),
		historicalData:      make(map[string]*HistoricalMetrics),
		baselines:           make(map[string]*Baseline),
		detectedAnomalies:   make(map[string]*Anomaly),
		anomalyHistory:      make([]*Anomaly, 0),
		mlModels:            make(map[string]*MLModel),
		sensitivity:         0.95,
		confidenceThreshold: 0.8,
	}

	// Initialize algorithms
	detector.initializeAlgorithms()

	// Register default detection rules
	detector.registerDefaultDetectionRules()

	logger.Info("Anomaly detector created", "detector_id", detector.id)
	return detector, nil
}

// initializeAlgorithms initializes anomaly detection algorithms
func (ad *AnomalyDetector) initializeAlgorithms() {
	// Statistical algorithms
	ad.algorithms["zscore"] = NewZScoreAlgorithm(ad.sensitivity)
	ad.algorithms["iqr"] = NewIQRAlgorithm(ad.sensitivity)
	ad.algorithms["mad"] = NewMADAlgorithm(ad.sensitivity)
	ad.algorithms["grubbs"] = NewGrubbsAlgorithm(ad.sensitivity)

	// Time series algorithms
	ad.algorithms["seasonal_decomposition"] = NewSeasonalDecompositionAlgorithm()
	ad.algorithms["arima"] = NewARIMAAlgorithm()
	ad.algorithms["exponential_smoothing"] = NewExponentialSmoothingAlgorithm()

	// Machine learning algorithms
	ad.algorithms["isolation_forest"] = NewIsolationForestAlgorithm()
	ad.algorithms["one_class_svm"] = NewOneClassSVMAlgorithm()
	ad.algorithms["autoencoder"] = NewAutoencoderAlgorithm()
}

// registerDefaultDetectionRules registers default anomaly detection rules
func (ad *AnomalyDetector) registerDefaultDetectionRules() {
	defaultRules := []*AnomalyDetectionRule{
		{
			ID:            "high_cpu_usage",
			Name:          "High CPU Usage Anomaly",
			MetricPattern: "cpu_usage_percent",
			Algorithm:     "zscore",
			Sensitivity:   0.95,
			WindowSize:    10 * time.Minute,
			MinDataPoints: 10,
			Enabled:       true,
			Actions: []AnomalyAction{
				{
					Type:    ActionAlert,
					Enabled: true,
					Parameters: map[string]interface{}{
						"severity": "high",
						"channels": []string{"email", "slack"},
					},
				},
			},
		},
		{
			ID:            "high_memory_usage",
			Name:          "High Memory Usage Anomaly",
			MetricPattern: "memory_usage_percent",
			Algorithm:     "zscore",
			Sensitivity:   0.95,
			WindowSize:    10 * time.Minute,
			MinDataPoints: 10,
			Enabled:       true,
			Actions: []AnomalyAction{
				{
					Type:    ActionAlert,
					Enabled: true,
					Parameters: map[string]interface{}{
						"severity": "high",
						"channels": []string{"email", "slack"},
					},
				},
			},
		},
		{
			ID:            "high_error_rate",
			Name:          "High Error Rate Anomaly",
			MetricPattern: "error_rate",
			Algorithm:     "iqr",
			Sensitivity:   0.99,
			WindowSize:    5 * time.Minute,
			MinDataPoints: 5,
			Enabled:       true,
			Actions: []AnomalyAction{
				{
					Type:    ActionAlert,
					Enabled: true,
					Parameters: map[string]interface{}{
						"severity": "critical",
						"channels": []string{"email", "slack", "pagerduty"},
					},
				},
			},
		},
		{
			ID:            "response_time_spike",
			Name:          "Response Time Spike Anomaly",
			MetricPattern: "response_time_p99",
			Algorithm:     "seasonal_decomposition",
			Sensitivity:   0.9,
			WindowSize:    15 * time.Minute,
			MinDataPoints: 15,
			Enabled:       true,
			Actions: []AnomalyAction{
				{
					Type:    ActionAlert,
					Enabled: true,
					Parameters: map[string]interface{}{
						"severity": "medium",
						"channels": []string{"slack"},
					},
				},
			},
		},
		{
			ID:            "unusual_traffic_pattern",
			Name:          "Unusual Traffic Pattern",
			MetricPattern: "request_rate",
			Algorithm:     "isolation_forest",
			Sensitivity:   0.85,
			WindowSize:    30 * time.Minute,
			MinDataPoints: 30,
			Enabled:       true,
			Actions: []AnomalyAction{
				{
					Type:    ActionLog,
					Enabled: true,
					Parameters: map[string]interface{}{
						"level": "warn",
					},
				},
			},
		},
	}

	for _, rule := range defaultRules {
		rule.CreatedAt = time.Now()
		rule.UpdatedAt = time.Now()
		ad.detectionRules[rule.ID] = rule
	}
}

// DetectAnomalies detects anomalies in the provided metrics
func (ad *AnomalyDetector) DetectAnomalies(ctx context.Context, metrics []Metric) ([]*Anomaly, error) {
	ctx, span := anomalyTracer.Start(ctx, "anomaly_detector.detect_anomalies",
		trace.WithAttributes(
			attribute.Int("metrics.count", len(metrics)),
		),
	)
	defer span.End()

	var detectedAnomalies []*Anomaly

	ad.mutex.Lock()
	defer ad.mutex.Unlock()

	// Update historical data
	ad.updateHistoricalData(metrics)

	// Update baselines
	ad.updateBaselines(ctx)

	// Apply detection rules
	for _, rule := range ad.detectionRules {
		if !rule.Enabled {
			continue
		}

		anomalies, err := ad.applyDetectionRule(ctx, rule, metrics)
		if err != nil {
			ad.logger.Error("Failed to apply detection rule",
				"rule_id", rule.ID,
				"error", err)
			continue
		}

		detectedAnomalies = append(detectedAnomalies, anomalies...)
	}

	// Store detected anomalies
	for _, anomaly := range detectedAnomalies {
		ad.detectedAnomalies[anomaly.ID] = anomaly
		ad.anomalyHistory = append(ad.anomalyHistory, anomaly)

		// Execute actions
		ad.executeAnomalyActions(ctx, anomaly)
	}

	span.SetAttributes(
		attribute.Int("anomalies.detected", len(detectedAnomalies)),
	)

	ad.logger.Info("Anomaly detection completed",
		"metrics_processed", len(metrics),
		"anomalies_detected", len(detectedAnomalies))

	return detectedAnomalies, nil
}

// updateHistoricalData updates historical data with new metrics
func (ad *AnomalyDetector) updateHistoricalData(metrics []Metric) {
	for _, metric := range metrics {
		historical, exists := ad.historicalData[metric.Name]
		if !exists {
			historical = &HistoricalMetrics{
				MetricName:  metric.Name,
				Values:      make([]TimeSeriesPoint, 0),
				WindowSize:  24 * time.Hour, // Default 24 hour window
				LastUpdated: time.Now(),
			}
			ad.historicalData[metric.Name] = historical
		}

		// Add new data point
		point := TimeSeriesPoint{
			Timestamp: metric.Timestamp,
			Value:     metric.Value,
		}
		historical.Values = append(historical.Values, point)
		historical.LastUpdated = time.Now()

		// Apply retention policy
		cutoff := time.Now().Add(-historical.WindowSize)
		var retained []TimeSeriesPoint
		for _, p := range historical.Values {
			if p.Timestamp.After(cutoff) {
				retained = append(retained, p)
			}
		}
		historical.Values = retained
	}
}

// updateBaselines updates baselines for all metrics
func (ad *AnomalyDetector) updateBaselines(ctx context.Context) {
	for metricName, historical := range ad.historicalData {
		if len(historical.Values) < 10 { // Need minimum data points
			continue
		}

		baseline := ad.calculateBaseline(historical)
		ad.baselines[metricName] = baseline
	}
}

// calculateBaseline calculates baseline statistics for historical data
func (ad *AnomalyDetector) calculateBaseline(historical *HistoricalMetrics) *Baseline {
	values := make([]float64, len(historical.Values))
	for i, point := range historical.Values {
		values[i] = point.Value
	}

	// Sort for percentile calculations
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	// Calculate basic statistics
	mean := ad.calculateMean(values)
	stdDev := ad.calculateStandardDeviation(values, mean)
	min := sorted[0]
	max := sorted[len(sorted)-1]

	// Calculate percentiles
	percentiles := map[string]float64{
		"p25": ad.calculatePercentileFromSorted(sorted, 0.25),
		"p50": ad.calculatePercentileFromSorted(sorted, 0.50),
		"p75": ad.calculatePercentileFromSorted(sorted, 0.75),
		"p90": ad.calculatePercentileFromSorted(sorted, 0.90),
		"p95": ad.calculatePercentileFromSorted(sorted, 0.95),
		"p99": ad.calculatePercentileFromSorted(sorted, 0.99),
	}

	return &Baseline{
		MetricName:        historical.MetricName,
		Mean:              mean,
		StandardDeviation: stdDev,
		Min:               min,
		Max:               max,
		Percentiles:       percentiles,
		LastCalculated:    time.Now(),
		DataPoints:        len(values),
	}
}

// applyDetectionRule applies a detection rule to metrics
func (ad *AnomalyDetector) applyDetectionRule(ctx context.Context, rule *AnomalyDetectionRule, metrics []Metric) ([]*Anomaly, error) {
	var anomalies []*Anomaly

	// Find matching metrics
	matchingMetrics := ad.findMatchingMetrics(rule.MetricPattern, rule.Filters, metrics)

	for _, metric := range matchingMetrics {
		// Get baseline for this metric
		baseline, exists := ad.baselines[metric.Name]
		if !exists {
			continue // No baseline available
		}

		// Get algorithm
		algorithm, exists := ad.algorithms[rule.Algorithm]
		if !exists {
			continue // Algorithm not found
		}

		// Get recent values for detection
		historical := ad.historicalData[metric.Name]
		if historical == nil || len(historical.Values) < rule.MinDataPoints {
			continue // Not enough data
		}

		// Extract values from the detection window
		windowStart := time.Now().Add(-rule.WindowSize)
		var windowValues []float64
		for _, point := range historical.Values {
			if point.Timestamp.After(windowStart) {
				windowValues = append(windowValues, point.Value)
			}
		}

		if len(windowValues) < rule.MinDataPoints {
			continue // Not enough data in window
		}

		// Detect anomaly
		result, err := algorithm.Detect(ctx, windowValues, baseline)
		if err != nil {
			ad.logger.Error("Anomaly detection failed",
				"rule_id", rule.ID,
				"metric", metric.Name,
				"algorithm", rule.Algorithm,
				"error", err)
			continue
		}

		// Check if anomaly detected and confidence threshold met
		if result.IsAnomaly && result.Confidence >= ad.confidenceThreshold {
			anomaly := &Anomaly{
				ID:            uuid.New().String(),
				RuleID:        rule.ID,
				MetricName:    metric.Name,
				Algorithm:     rule.Algorithm,
				Severity:      result.Severity,
				Confidence:    result.Confidence,
				Value:         result.ActualValue,
				ExpectedValue: result.ExpectedValue,
				Deviation:     result.Deviation,
				Timestamp:     time.Now(),
				Status:        StatusDetected,
				Description:   fmt.Sprintf("Anomaly detected in %s using %s algorithm", metric.Name, rule.Algorithm),
				Context:       result.Context,
				Actions:       rule.Actions,
				Resolved:      false,
			}

			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies, nil
}

// executeAnomalyActions executes actions for detected anomalies
func (ad *AnomalyDetector) executeAnomalyActions(ctx context.Context, anomaly *Anomaly) {
	for _, action := range anomaly.Actions {
		if !action.Enabled {
			continue
		}

		switch action.Type {
		case ActionAlert:
			ad.executeAlertAction(ctx, anomaly, action)
		case ActionNotify:
			ad.executeNotifyAction(ctx, anomaly, action)
		case ActionLog:
			ad.executeLogAction(ctx, anomaly, action)
		case ActionWebhook:
			ad.executeWebhookAction(ctx, anomaly, action)
		default:
			ad.logger.Warn("Unknown action type", "type", action.Type)
		}
	}
}

// executeAlertAction executes alert action
func (ad *AnomalyDetector) executeAlertAction(ctx context.Context, anomaly *Anomaly, action AnomalyAction) {
	ad.logger.Warn("Anomaly alert",
		"anomaly_id", anomaly.ID,
		"metric", anomaly.MetricName,
		"severity", anomaly.Severity,
		"confidence", anomaly.Confidence,
		"value", anomaly.Value,
		"expected", anomaly.ExpectedValue)
}

// executeNotifyAction executes notify action
func (ad *AnomalyDetector) executeNotifyAction(ctx context.Context, anomaly *Anomaly, action AnomalyAction) {
	ad.logger.Info("Anomaly notification",
		"anomaly_id", anomaly.ID,
		"metric", anomaly.MetricName,
		"severity", anomaly.Severity)
}

// executeLogAction executes log action
func (ad *AnomalyDetector) executeLogAction(ctx context.Context, anomaly *Anomaly, action AnomalyAction) {
	level, _ := action.Parameters["level"].(string)
	if level == "" {
		level = "info"
	}

	message := fmt.Sprintf("Anomaly detected: %s", anomaly.Description)

	switch level {
	case "error":
		ad.logger.Error(message, "anomaly_id", anomaly.ID)
	case "warn":
		ad.logger.Warn(message, "anomaly_id", anomaly.ID)
	default:
		ad.logger.Info(message, "anomaly_id", anomaly.ID)
	}
}

// executeWebhookAction executes webhook action
func (ad *AnomalyDetector) executeWebhookAction(ctx context.Context, anomaly *Anomaly, action AnomalyAction) {
	// Implementation for webhook notifications
	ad.logger.Info("Webhook action executed", "anomaly_id", anomaly.ID)
}

// Helper methods

// findMatchingMetrics finds metrics that match the pattern and filters
func (ad *AnomalyDetector) findMatchingMetrics(pattern string, filters map[string]string, metrics []Metric) []Metric {
	var matching []Metric

	for _, metric := range metrics {
		// Simple pattern matching
		if metric.Name == pattern || pattern == "*" {
			// Check filters
			matches := true
			for filterKey, filterValue := range filters {
				if labelValue, exists := metric.Labels[filterKey]; !exists || labelValue != filterValue {
					matches = false
					break
				}
			}

			if matches {
				matching = append(matching, metric)
			}
		}
	}

	return matching
}

// calculateMean calculates the mean of values
func (ad *AnomalyDetector) calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// calculateStandardDeviation calculates standard deviation
func (ad *AnomalyDetector) calculateStandardDeviation(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}

	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(values))

	return math.Sqrt(variance)
}

// calculatePercentileFromSorted calculates percentile from sorted values
func (ad *AnomalyDetector) calculatePercentileFromSorted(sorted []float64, percentile float64) float64 {
	if len(sorted) == 0 {
		return 0
	}

	index := percentile * float64(len(sorted)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))

	if lower == upper {
		return sorted[lower]
	}

	weight := index - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}
