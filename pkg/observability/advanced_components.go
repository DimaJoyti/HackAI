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

var advancedTracer = otel.Tracer("hackai/observability/advanced")

// MetricsAggregator aggregates and processes metrics data
type MetricsAggregator struct {
	id                string
	config            *EnhancedMonitoringConfig
	provider          *Provider
	logger            *logger.Logger
	
	// Aggregation state
	metricsBuffer     map[string]*MetricSeries
	aggregationRules  map[string]*AggregationRule
	
	// Processing
	processor         *MetricsProcessor
	storage           *MetricsStorage
	
	mutex             sync.RWMutex
}

// MetricSeries represents a time series of metric values
type MetricSeries struct {
	Name              string                 `json:"name"`
	Labels            map[string]string      `json:"labels"`
	Values            []MetricValue          `json:"values"`
	Aggregations      map[string]float64     `json:"aggregations"`
	LastUpdated       time.Time              `json:"last_updated"`
	RetentionPolicy   time.Duration          `json:"retention_policy"`
}

// MetricValue represents a single metric value with timestamp
type MetricValue struct {
	Timestamp         time.Time              `json:"timestamp"`
	Value             float64                `json:"value"`
	Tags              map[string]string      `json:"tags,omitempty"`
}

// AggregationRule defines how metrics should be aggregated
type AggregationRule struct {
	ID                string                 `json:"id"`
	MetricPattern     string                 `json:"metric_pattern"`
	AggregationType   AggregationType        `json:"aggregation_type"`
	WindowSize        time.Duration          `json:"window_size"`
	GroupBy           []string               `json:"group_by"`
	Filters           map[string]string      `json:"filters"`
	Enabled           bool                   `json:"enabled"`
}

// AggregationType defines the type of aggregation
type AggregationType string

const (
	AggregationSum     AggregationType = "sum"
	AggregationAvg     AggregationType = "avg"
	AggregationMin     AggregationType = "min"
	AggregationMax     AggregationType = "max"
	AggregationCount   AggregationType = "count"
	AggregationP50     AggregationType = "p50"
	AggregationP90     AggregationType = "p90"
	AggregationP95     AggregationType = "p95"
	AggregationP99     AggregationType = "p99"
	AggregationStdDev  AggregationType = "stddev"
	AggregationRate    AggregationType = "rate"
)

// NewMetricsAggregator creates a new metrics aggregator
func NewMetricsAggregator(config *EnhancedMonitoringConfig, provider *Provider, logger *logger.Logger) (*MetricsAggregator, error) {
	aggregator := &MetricsAggregator{
		id:               uuid.New().String(),
		config:           config,
		provider:         provider,
		logger:           logger,
		metricsBuffer:    make(map[string]*MetricSeries),
		aggregationRules: make(map[string]*AggregationRule),
	}
	
	// Initialize processor and storage
	var err error
	aggregator.processor, err = NewMetricsProcessor(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics processor: %w", err)
	}
	
	aggregator.storage, err = NewMetricsStorage(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics storage: %w", err)
	}
	
	// Register default aggregation rules
	aggregator.registerDefaultAggregationRules()
	
	logger.Info("Metrics aggregator created", "aggregator_id", aggregator.id)
	return aggregator, nil
}

// registerDefaultAggregationRules registers default aggregation rules
func (ma *MetricsAggregator) registerDefaultAggregationRules() {
	defaultRules := []*AggregationRule{
		{
			ID:              "http_request_rate",
			MetricPattern:   "http_requests_total",
			AggregationType: AggregationRate,
			WindowSize:      5 * time.Minute,
			GroupBy:         []string{"method", "status"},
			Enabled:         true,
		},
		{
			ID:              "response_time_p99",
			MetricPattern:   "http_request_duration_seconds",
			AggregationType: AggregationP99,
			WindowSize:      1 * time.Minute,
			GroupBy:         []string{"endpoint"},
			Enabled:         true,
		},
		{
			ID:              "error_rate",
			MetricPattern:   "http_requests_total",
			AggregationType: AggregationRate,
			WindowSize:      5 * time.Minute,
			Filters:         map[string]string{"status": "5xx"},
			Enabled:         true,
		},
		{
			ID:              "cpu_usage_avg",
			MetricPattern:   "cpu_usage_percent",
			AggregationType: AggregationAvg,
			WindowSize:      1 * time.Minute,
			Enabled:         true,
		},
		{
			ID:              "memory_usage_max",
			MetricPattern:   "memory_usage_bytes",
			AggregationType: AggregationMax,
			WindowSize:      1 * time.Minute,
			Enabled:         true,
		},
	}
	
	for _, rule := range defaultRules {
		ma.aggregationRules[rule.ID] = rule
	}
}

// ProcessMetrics processes incoming metrics
func (ma *MetricsAggregator) ProcessMetrics(ctx context.Context, metrics []Metric) error {
	ctx, span := advancedTracer.Start(ctx, "metrics_aggregator.process_metrics",
		trace.WithAttributes(
			attribute.Int("metrics.count", len(metrics)),
		),
	)
	defer span.End()
	
	ma.mutex.Lock()
	defer ma.mutex.Unlock()
	
	for _, metric := range metrics {
		if err := ma.processMetric(ctx, metric); err != nil {
			ma.logger.Error("Failed to process metric",
				"metric_name", metric.Name,
				"error", err)
			continue
		}
	}
	
	// Apply aggregation rules
	if err := ma.applyAggregationRules(ctx); err != nil {
		return fmt.Errorf("failed to apply aggregation rules: %w", err)
	}
	
	span.SetAttributes(
		attribute.Int("metrics.processed", len(metrics)),
	)
	
	return nil
}

// processMetric processes a single metric
func (ma *MetricsAggregator) processMetric(ctx context.Context, metric Metric) error {
	seriesKey := ma.generateSeriesKey(metric.Name, metric.Labels)
	
	series, exists := ma.metricsBuffer[seriesKey]
	if !exists {
		series = &MetricSeries{
			Name:            metric.Name,
			Labels:          metric.Labels,
			Values:          make([]MetricValue, 0),
			Aggregations:    make(map[string]float64),
			LastUpdated:     time.Now(),
			RetentionPolicy: ma.config.MetricsRetention,
		}
		ma.metricsBuffer[seriesKey] = series
	}
	
	// Add new value
	value := MetricValue{
		Timestamp: metric.Timestamp,
		Value:     metric.Value,
		Tags:      metric.Tags,
	}
	
	series.Values = append(series.Values, value)
	series.LastUpdated = time.Now()
	
	// Apply retention policy
	ma.applyRetentionPolicy(series)
	
	return nil
}

// applyAggregationRules applies all enabled aggregation rules
func (ma *MetricsAggregator) applyAggregationRules(ctx context.Context) error {
	for _, rule := range ma.aggregationRules {
		if !rule.Enabled {
			continue
		}
		
		if err := ma.applyAggregationRule(ctx, rule); err != nil {
			ma.logger.Error("Failed to apply aggregation rule",
				"rule_id", rule.ID,
				"error", err)
		}
	}
	
	return nil
}

// applyAggregationRule applies a specific aggregation rule
func (ma *MetricsAggregator) applyAggregationRule(ctx context.Context, rule *AggregationRule) error {
	// Find matching series
	matchingSeries := ma.findMatchingSeries(rule.MetricPattern, rule.Filters)
	
	for _, series := range matchingSeries {
		// Get values within the window
		windowStart := time.Now().Add(-rule.WindowSize)
		values := ma.getValuesInWindow(series, windowStart, time.Now())
		
		if len(values) == 0 {
			continue
		}
		
		// Calculate aggregation
		aggregatedValue := ma.calculateAggregation(values, rule.AggregationType)
		
		// Store aggregation result
		aggregationKey := fmt.Sprintf("%s_%s", rule.ID, rule.AggregationType)
		series.Aggregations[aggregationKey] = aggregatedValue
	}
	
	return nil
}

// calculateAggregation calculates the aggregated value based on type
func (ma *MetricsAggregator) calculateAggregation(values []float64, aggType AggregationType) float64 {
	if len(values) == 0 {
		return 0
	}
	
	switch aggType {
	case AggregationSum:
		sum := 0.0
		for _, v := range values {
			sum += v
		}
		return sum
		
	case AggregationAvg:
		sum := 0.0
		for _, v := range values {
			sum += v
		}
		return sum / float64(len(values))
		
	case AggregationMin:
		min := values[0]
		for _, v := range values {
			if v < min {
				min = v
			}
		}
		return min
		
	case AggregationMax:
		max := values[0]
		for _, v := range values {
			if v > max {
				max = v
			}
		}
		return max
		
	case AggregationCount:
		return float64(len(values))
		
	case AggregationP50, AggregationP90, AggregationP95, AggregationP99:
		return ma.calculatePercentile(values, aggType)
		
	case AggregationStdDev:
		return ma.calculateStandardDeviation(values)
		
	case AggregationRate:
		// Calculate rate per second
		if len(values) < 2 {
			return 0
		}
		// Simple rate calculation - can be enhanced
		return values[len(values)-1] - values[0]
		
	default:
		return 0
	}
}

// calculatePercentile calculates the specified percentile
func (ma *MetricsAggregator) calculatePercentile(values []float64, aggType AggregationType) float64 {
	if len(values) == 0 {
		return 0
	}
	
	// Sort values
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	
	var percentile float64
	switch aggType {
	case AggregationP50:
		percentile = 0.5
	case AggregationP90:
		percentile = 0.9
	case AggregationP95:
		percentile = 0.95
	case AggregationP99:
		percentile = 0.99
	default:
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

// calculateStandardDeviation calculates the standard deviation
func (ma *MetricsAggregator) calculateStandardDeviation(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	// Calculate mean
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	
	// Calculate variance
	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	
	return math.Sqrt(variance)
}

// Helper methods

// generateSeriesKey generates a unique key for a metric series
func (ma *MetricsAggregator) generateSeriesKey(name string, labels map[string]string) string {
	key := name
	if len(labels) > 0 {
		// Sort labels for consistent key generation
		var labelPairs []string
		for k, v := range labels {
			labelPairs = append(labelPairs, fmt.Sprintf("%s=%s", k, v))
		}
		sort.Strings(labelPairs)
		
		for _, pair := range labelPairs {
			key += "," + pair
		}
	}
	return key
}

// findMatchingSeries finds series that match the pattern and filters
func (ma *MetricsAggregator) findMatchingSeries(pattern string, filters map[string]string) []*MetricSeries {
	var matching []*MetricSeries
	
	for _, series := range ma.metricsBuffer {
		// Simple pattern matching - can be enhanced with regex
		if series.Name == pattern || pattern == "*" {
			// Check filters
			matches := true
			for filterKey, filterValue := range filters {
				if labelValue, exists := series.Labels[filterKey]; !exists || labelValue != filterValue {
					matches = false
					break
				}
			}
			
			if matches {
				matching = append(matching, series)
			}
		}
	}
	
	return matching
}

// getValuesInWindow gets metric values within a time window
func (ma *MetricsAggregator) getValuesInWindow(series *MetricSeries, start, end time.Time) []float64 {
	var values []float64
	
	for _, value := range series.Values {
		if value.Timestamp.After(start) && value.Timestamp.Before(end) {
			values = append(values, value.Value)
		}
	}
	
	return values
}

// applyRetentionPolicy applies retention policy to a series
func (ma *MetricsAggregator) applyRetentionPolicy(series *MetricSeries) {
	if len(series.Values) == 0 {
		return
	}
	
	cutoff := time.Now().Add(-series.RetentionPolicy)
	
	// Remove old values
	var retained []MetricValue
	for _, value := range series.Values {
		if value.Timestamp.After(cutoff) {
			retained = append(retained, value)
		}
	}
	
	series.Values = retained
	
	// Limit number of values
	if len(series.Values) > ma.config.MaxMetricsPoints {
		// Keep the most recent values
		start := len(series.Values) - ma.config.MaxMetricsPoints
		series.Values = series.Values[start:]
	}
}
