package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/observability"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var metricsTracer = otel.Tracer("hackai/monitoring/metrics")

// MetricsCollector collects and aggregates metrics from various sources
type MetricsCollector struct {
	metrics       map[string]*MetricDefinition
	timeSeries    map[string]*TimeSeries
	aggregators   map[string]*MetricAggregator
	exporters     []MetricExporter
	observability *observability.Provider
	config        *MonitoringConfig
	logger        *logger.Logger
	mutex         sync.RWMutex
}

// MetricDefinition defines a metric
type MetricDefinition struct {
	Name        string                 `json:"name"`
	Type        MetricType             `json:"type"`
	Description string                 `json:"description"`
	Unit        string                 `json:"unit"`
	Labels      []string               `json:"labels"`
	Aggregation AggregationType        `json:"aggregation"`
	Retention   time.Duration          `json:"retention"`
	SampleRate  float64                `json:"sample_rate"`
	Enabled     bool                   `json:"enabled"`
	CreatedAt   time.Time              `json:"created_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// TimeSeries represents a time series of metric values
type TimeSeries struct {
	MetricName string                 `json:"metric_name"`
	Labels     map[string]string      `json:"labels"`
	Points     []*DataPoint           `json:"points"`
	LastUpdate time.Time              `json:"last_update"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// DataPoint represents a single data point in a time series
type DataPoint struct {
	Timestamp time.Time              `json:"timestamp"`
	Value     interface{}            `json:"value"`
	Labels    map[string]string      `json:"labels"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// MetricAggregator aggregates metric values
type MetricAggregator struct {
	MetricName string                 `json:"metric_name"`
	Type       AggregationType        `json:"type"`
	WindowSize time.Duration          `json:"window_size"`
	Values     []float64              `json:"values"`
	Count      int64                  `json:"count"`
	Sum        float64                `json:"sum"`
	Min        float64                `json:"min"`
	Max        float64                `json:"max"`
	LastUpdate time.Time              `json:"last_update"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// MetricExporter exports metrics to external systems
type MetricExporter interface {
	Export(ctx context.Context, metrics []*MetricData) error
	GetType() ExporterType
	GetConfig() map[string]interface{}
}

// MetricData represents metric data for export
type MetricData struct {
	Name      string                 `json:"name"`
	Type      MetricType             `json:"type"`
	Value     interface{}            `json:"value"`
	Labels    map[string]string      `json:"labels"`
	Timestamp time.Time              `json:"timestamp"`
	Unit      string                 `json:"unit"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// Enums for metrics
type MetricType string
type AggregationType string
type ExporterType string

const (
	// Metric Types
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"

	// Aggregation Types
	AggregationSum     AggregationType = "sum"
	AggregationAverage AggregationType = "average"
	AggregationMin     AggregationType = "min"
	AggregationMax     AggregationType = "max"
	AggregationCount   AggregationType = "count"
	AggregationP50     AggregationType = "p50"
	AggregationP95     AggregationType = "p95"
	AggregationP99     AggregationType = "p99"

	// Exporter Types
	ExporterTypePrometheus ExporterType = "prometheus"
	ExporterTypeInfluxDB   ExporterType = "influxdb"
	ExporterTypeCloudWatch ExporterType = "cloudwatch"
	ExporterTypeDatadog    ExporterType = "datadog"
	ExporterTypeOTLP       ExporterType = "otlp"
)

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(config *MonitoringConfig, observability *observability.Provider, logger *logger.Logger) (*MetricsCollector, error) {
	mc := &MetricsCollector{
		metrics:       make(map[string]*MetricDefinition),
		timeSeries:    make(map[string]*TimeSeries),
		aggregators:   make(map[string]*MetricAggregator),
		exporters:     make([]MetricExporter, 0),
		observability: observability,
		config:        config,
		logger:        logger,
	}

	// Initialize default metrics
	if err := mc.initializeDefaultMetrics(); err != nil {
		return nil, err
	}

	return mc, nil
}

// CollectMetrics collects metrics from all sources
func (mc *MetricsCollector) CollectMetrics(ctx context.Context) error {
	ctx, span := metricsTracer.Start(ctx, "metrics_collector.collect_metrics")
	defer span.End()

	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	now := time.Now()
	collectedCount := 0

	// Collect metrics from OpenTelemetry
	if mc.observability != nil {
		if err := mc.collectOTelMetrics(ctx); err != nil {
			mc.logger.Warn("Failed to collect OpenTelemetry metrics", "error", err)
		}
	}

	// Process aggregations
	for _, aggregator := range mc.aggregators {
		if err := mc.processAggregation(aggregator); err != nil {
			mc.logger.Warn("Failed to process aggregation",
				"metric", aggregator.MetricName,
				"error", err)
		}
	}

	// Clean up old data points
	mc.cleanupOldDataPoints(now)

	// Export metrics
	if len(mc.exporters) > 0 {
		if err := mc.exportMetrics(ctx); err != nil {
			mc.logger.Warn("Failed to export metrics", "error", err)
		}
	}

	span.SetAttributes(
		attribute.Int("metrics.collected", collectedCount),
		attribute.Int("metrics.total", len(mc.metrics)),
		attribute.Int("timeseries.total", len(mc.timeSeries)),
	)

	mc.logger.Debug("Metrics collection completed",
		"collected", collectedCount,
		"total_metrics", len(mc.metrics),
		"total_timeseries", len(mc.timeSeries))

	return nil
}

// RecordMetric records a metric value
func (mc *MetricsCollector) RecordMetric(ctx context.Context, name string, value interface{}, labels map[string]string) error {
	ctx, span := metricsTracer.Start(ctx, "metrics_collector.record_metric",
		trace.WithAttributes(
			attribute.String("metric.name", name),
		),
	)
	defer span.End()

	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	// Check if metric is defined
	metricDef, exists := mc.metrics[name]
	if !exists {
		return nil // Ignore undefined metrics
	}

	if !metricDef.Enabled {
		return nil // Ignore disabled metrics
	}

	// Apply sampling
	if metricDef.SampleRate < 1.0 && metricDef.SampleRate > 0 {
		// TODO: Implement proper sampling
	}

	// Create time series key
	timeSeriesKey := mc.createTimeSeriesKey(name, labels)

	// Get or create time series
	timeSeries, exists := mc.timeSeries[timeSeriesKey]
	if !exists {
		timeSeries = &TimeSeries{
			MetricName: name,
			Labels:     make(map[string]string),
			Points:     make([]*DataPoint, 0),
			Metadata:   make(map[string]interface{}),
		}

		// Copy labels
		for k, v := range labels {
			timeSeries.Labels[k] = v
		}

		mc.timeSeries[timeSeriesKey] = timeSeries
	}

	// Create data point
	dataPoint := &DataPoint{
		Timestamp: time.Now(),
		Value:     value,
		Labels:    make(map[string]string),
		Metadata:  make(map[string]interface{}),
	}

	// Copy labels
	for k, v := range labels {
		dataPoint.Labels[k] = v
	}

	// Add to time series
	timeSeries.Points = append(timeSeries.Points, dataPoint)
	timeSeries.LastUpdate = dataPoint.Timestamp

	// Limit time series size
	maxPoints := 1000
	if len(timeSeries.Points) > maxPoints {
		timeSeries.Points = timeSeries.Points[len(timeSeries.Points)-maxPoints:]
	}

	// Update aggregator if exists
	if aggregator, exists := mc.aggregators[name]; exists {
		mc.updateAggregator(aggregator, value)
	}

	span.SetAttributes(
		attribute.String("metric.type", string(metricDef.Type)),
		attribute.Int("timeseries.points", len(timeSeries.Points)),
	)

	return nil
}

// DefineMetric defines a new metric
func (mc *MetricsCollector) DefineMetric(definition *MetricDefinition) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if definition.Name == "" {
		return fmt.Errorf("metric name cannot be empty")
	}

	definition.CreatedAt = time.Now()
	mc.metrics[definition.Name] = definition

	// Create aggregator if needed
	if definition.Aggregation != "" {
		aggregator := &MetricAggregator{
			MetricName: definition.Name,
			Type:       definition.Aggregation,
			WindowSize: time.Minute, // Default window
			Values:     make([]float64, 0),
			Metadata:   make(map[string]interface{}),
		}
		mc.aggregators[definition.Name] = aggregator
	}

	mc.logger.Info("Metric defined",
		"name", definition.Name,
		"type", definition.Type,
		"aggregation", definition.Aggregation)

	return nil
}

// GetMetricData returns metric data for a specific metric
func (mc *MetricsCollector) GetMetricData(ctx context.Context, metricName string, duration time.Duration) ([]*TimeSeries, error) {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	var result []*TimeSeries
	cutoff := time.Now().Add(-duration)

	for _, timeSeries := range mc.timeSeries {
		if timeSeries.MetricName == metricName {
			// Filter points by time
			var filteredPoints []*DataPoint
			for _, point := range timeSeries.Points {
				if point.Timestamp.After(cutoff) {
					filteredPoints = append(filteredPoints, point)
				}
			}

			if len(filteredPoints) > 0 {
				filteredSeries := &TimeSeries{
					MetricName: timeSeries.MetricName,
					Labels:     make(map[string]string),
					Points:     filteredPoints,
					LastUpdate: timeSeries.LastUpdate,
					Metadata:   make(map[string]interface{}),
				}

				// Copy labels and metadata
				for k, v := range timeSeries.Labels {
					filteredSeries.Labels[k] = v
				}
				for k, v := range timeSeries.Metadata {
					filteredSeries.Metadata[k] = v
				}

				result = append(result, filteredSeries)
			}
		}
	}

	return result, nil
}

// GetAggregatedMetric returns aggregated metric value
func (mc *MetricsCollector) GetAggregatedMetric(ctx context.Context, metricName string, aggregationType AggregationType) (float64, error) {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	aggregator, exists := mc.aggregators[metricName]
	if !exists {
		return 0, fmt.Errorf("aggregator not found for metric: %s", metricName)
	}

	switch aggregationType {
	case AggregationSum:
		return aggregator.Sum, nil
	case AggregationAverage:
		if aggregator.Count > 0 {
			return aggregator.Sum / float64(aggregator.Count), nil
		}
		return 0, nil
	case AggregationMin:
		return aggregator.Min, nil
	case AggregationMax:
		return aggregator.Max, nil
	case AggregationCount:
		return float64(aggregator.Count), nil
	default:
		return 0, fmt.Errorf("unsupported aggregation type: %s", aggregationType)
	}
}

// Helper methods

func (mc *MetricsCollector) createTimeSeriesKey(metricName string, labels map[string]string) string {
	key := metricName
	for k, v := range labels {
		key += ":" + k + "=" + v
	}
	return key
}

func (mc *MetricsCollector) updateAggregator(aggregator *MetricAggregator, value interface{}) {
	floatValue, ok := mc.convertToFloat64(value)
	if !ok {
		return
	}

	aggregator.Values = append(aggregator.Values, floatValue)
	aggregator.Count++
	aggregator.Sum += floatValue
	aggregator.LastUpdate = time.Now()

	if aggregator.Count == 1 {
		aggregator.Min = floatValue
		aggregator.Max = floatValue
	} else {
		if floatValue < aggregator.Min {
			aggregator.Min = floatValue
		}
		if floatValue > aggregator.Max {
			aggregator.Max = floatValue
		}
	}

	// Keep only recent values for percentile calculations
	maxValues := 1000
	if len(aggregator.Values) > maxValues {
		aggregator.Values = aggregator.Values[len(aggregator.Values)-maxValues:]
	}
}

func (mc *MetricsCollector) convertToFloat64(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	default:
		return 0, false
	}
}

func (mc *MetricsCollector) processAggregation(aggregator *MetricAggregator) error {
	// Process aggregation based on window size
	now := time.Now()
	_ = now.Add(-aggregator.WindowSize) // windowStart for future use

	// Filter values within window
	// This is simplified - in production you'd want more sophisticated windowing
	aggregator.LastUpdate = now

	return nil
}

func (mc *MetricsCollector) cleanupOldDataPoints(now time.Time) {
	for _, timeSeries := range mc.timeSeries {
		// Get metric definition to check retention
		metricDef, exists := mc.metrics[timeSeries.MetricName]
		if !exists {
			continue
		}

		retention := metricDef.Retention
		if retention == 0 {
			retention = 24 * time.Hour // Default retention
		}

		cutoff := now.Add(-retention)

		// Filter out old points
		var filteredPoints []*DataPoint
		for _, point := range timeSeries.Points {
			if point.Timestamp.After(cutoff) {
				filteredPoints = append(filteredPoints, point)
			}
		}

		timeSeries.Points = filteredPoints
	}
}

func (mc *MetricsCollector) collectOTelMetrics(ctx context.Context) error {
	// TODO: Implement OpenTelemetry metrics collection
	return nil
}

func (mc *MetricsCollector) exportMetrics(ctx context.Context) error {
	// Prepare metrics for export
	var metricsData []*MetricData

	for _, timeSeries := range mc.timeSeries {
		if len(timeSeries.Points) == 0 {
			continue
		}

		// Get latest point
		latestPoint := timeSeries.Points[len(timeSeries.Points)-1]

		metricData := &MetricData{
			Name:      timeSeries.MetricName,
			Value:     latestPoint.Value,
			Labels:    latestPoint.Labels,
			Timestamp: latestPoint.Timestamp,
			Metadata:  latestPoint.Metadata,
		}

		// Get metric type from definition
		if metricDef, exists := mc.metrics[timeSeries.MetricName]; exists {
			metricData.Type = metricDef.Type
			metricData.Unit = metricDef.Unit
		}

		metricsData = append(metricsData, metricData)
	}

	// Export to all configured exporters
	for _, exporter := range mc.exporters {
		if err := exporter.Export(ctx, metricsData); err != nil {
			mc.logger.Error("Failed to export metrics",
				"exporter", exporter.GetType(),
				"error", err)
		}
	}

	return nil
}

func (mc *MetricsCollector) initializeDefaultMetrics() error {
	defaultMetrics := []*MetricDefinition{
		{
			Name:        "http_requests_total",
			Type:        MetricTypeCounter,
			Description: "Total number of HTTP requests",
			Unit:        "requests",
			Labels:      []string{"method", "status", "path"},
			Aggregation: AggregationSum,
			Retention:   24 * time.Hour,
			SampleRate:  1.0,
			Enabled:     true,
		},
		{
			Name:        "http_request_duration",
			Type:        MetricTypeHistogram,
			Description: "HTTP request duration",
			Unit:        "seconds",
			Labels:      []string{"method", "path"},
			Aggregation: AggregationAverage,
			Retention:   24 * time.Hour,
			SampleRate:  1.0,
			Enabled:     true,
		},
		{
			Name:        "system_cpu_usage",
			Type:        MetricTypeGauge,
			Description: "System CPU usage percentage",
			Unit:        "percent",
			Labels:      []string{},
			Aggregation: AggregationAverage,
			Retention:   7 * 24 * time.Hour,
			SampleRate:  1.0,
			Enabled:     true,
		},
		{
			Name:        "system_memory_usage",
			Type:        MetricTypeGauge,
			Description: "System memory usage percentage",
			Unit:        "percent",
			Labels:      []string{},
			Aggregation: AggregationAverage,
			Retention:   7 * 24 * time.Hour,
			SampleRate:  1.0,
			Enabled:     true,
		},
	}

	for _, metric := range defaultMetrics {
		if err := mc.DefineMetric(metric); err != nil {
			return err
		}
	}

	return nil
}
