package observability

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var enhancedMonitoringTracer = otel.Tracer("hackai/observability/enhanced")

// EnhancedMonitoringSystem provides comprehensive observability and monitoring
type EnhancedMonitoringSystem struct {
	id       string
	config   *EnhancedMonitoringConfig
	logger   *logger.Logger
	provider *Provider

	// Core monitoring components
	metricsAggregator *MetricsAggregator
	traceAnalyzer     *TraceAnalyzer
	logAnalyzer       *LogAnalyzer
	alertEngine       *AlertEngine
	anomalyDetector   *AnomalyDetector

	// Advanced features
	performanceProfiler *PerformanceProfiler
	securityMonitor     *SecurityMonitor
	businessMetrics     *BusinessMetricsCollector
	slaMonitor          *SLAMonitor
	capacityPlanner     *CapacityPlanner

	// Real-time monitoring
	realTimeProcessor      *RealTimeProcessor
	enhancedDashboard      *EnhancedDashboardManager
	reportGenerator        *ReportGenerator

	// System state
	startTime    time.Time
	isRunning    bool
	healthStatus SystemHealthStatus

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mutex  sync.RWMutex
}

// EnhancedMonitoringConfig configuration for enhanced monitoring
type EnhancedMonitoringConfig struct {
	// Basic configuration
	ServiceName string `yaml:"service_name"`
	Environment string `yaml:"environment"`
	Version     string `yaml:"version"`

	// Monitoring intervals
	MetricsInterval     time.Duration `yaml:"metrics_interval"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval"`
	AlertingInterval    time.Duration `yaml:"alerting_interval"`

	// Feature flags
	EnableMetrics              bool `yaml:"enable_metrics"`
	EnableTracing              bool `yaml:"enable_tracing"`
	EnableLogging              bool `yaml:"enable_logging"`
	EnableAlerting             bool `yaml:"enable_alerting"`
	EnableAnomalyDetection     bool `yaml:"enable_anomaly_detection"`
	EnablePerformanceProfiling bool `yaml:"enable_performance_profiling"`
	EnableSecurityMonitoring   bool `yaml:"enable_security_monitoring"`
	EnableBusinessMetrics      bool `yaml:"enable_business_metrics"`
	EnableSLAMonitoring        bool `yaml:"enable_sla_monitoring"`
	EnableCapacityPlanning     bool `yaml:"enable_capacity_planning"`
	EnableRealTimeProcessing   bool `yaml:"enable_real_time_processing"`

	// Retention and limits
	MetricsRetention time.Duration `yaml:"metrics_retention"`
	TracesRetention  time.Duration `yaml:"traces_retention"`
	LogsRetention    time.Duration `yaml:"logs_retention"`
	MaxMetricsPoints int           `yaml:"max_metrics_points"`
	MaxTraceSpans    int           `yaml:"max_trace_spans"`
	MaxLogEntries    int           `yaml:"max_log_entries"`

	// Alert configuration
	AlertChannels   []string           `yaml:"alert_channels"`
	AlertThresholds map[string]float64 `yaml:"alert_thresholds"`
	EscalationRules []EscalationRule   `yaml:"escalation_rules"`

	// Performance configuration
	SamplingRate  float64       `yaml:"sampling_rate"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`

	// Security configuration
	EnableEncryption     bool              `yaml:"enable_encryption"`
	EnableAuthentication bool              `yaml:"enable_authentication"`
	APIKeys              map[string]string `yaml:"api_keys"`
}

// NewEnhancedMonitoringSystem creates a new enhanced monitoring system
func NewEnhancedMonitoringSystem(config *EnhancedMonitoringConfig, provider *Provider, logger *logger.Logger) (*EnhancedMonitoringSystem, error) {
	if config == nil {
		config = DefaultEnhancedMonitoringConfig()
	}

	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	if provider == nil {
		return nil, fmt.Errorf("observability provider is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	system := &EnhancedMonitoringSystem{
		id:           uuid.New().String(),
		config:       config,
		logger:       logger,
		provider:     provider,
		ctx:          ctx,
		cancel:       cancel,
		startTime:    time.Now(),
		healthStatus: SystemHealthStatusHealthy,
	}

	// Initialize components
	if err := system.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	logger.Info("Enhanced monitoring system created",
		"system_id", system.id,
		"service_name", config.ServiceName,
		"environment", config.Environment)

	return system, nil
}

// initializeComponents initializes all monitoring components
func (ems *EnhancedMonitoringSystem) initializeComponents() error {
	var err error

	// Initialize metrics aggregator
	if ems.config.EnableMetrics {
		ems.metricsAggregator, err = NewMetricsAggregator(ems.config, ems.provider, ems.logger)
		if err != nil {
			return fmt.Errorf("failed to create metrics aggregator: %w", err)
		}
	}

	// Initialize trace analyzer
	if ems.config.EnableTracing {
		ems.traceAnalyzer, err = NewTraceAnalyzer(ems.config, ems.provider, ems.logger)
		if err != nil {
			return fmt.Errorf("failed to create trace analyzer: %w", err)
		}
	}

	// Initialize log analyzer
	if ems.config.EnableLogging {
		ems.logAnalyzer, err = NewLogAnalyzer(ems.config, ems.logger)
		if err != nil {
			return fmt.Errorf("failed to create log analyzer: %w", err)
		}
	}

	// Initialize alert engine
	if ems.config.EnableAlerting {
		ems.alertEngine, err = NewAlertEngine(ems.config, ems.logger)
		if err != nil {
			return fmt.Errorf("failed to create alert engine: %w", err)
		}
	}

	// Initialize anomaly detector
	if ems.config.EnableAnomalyDetection {
		ems.anomalyDetector, err = NewAnomalyDetector(ems.config, ems.logger)
		if err != nil {
			return fmt.Errorf("failed to create anomaly detector: %w", err)
		}
	}

	// Initialize performance profiler
	if ems.config.EnablePerformanceProfiling {
		ems.performanceProfiler, err = NewPerformanceProfiler(ems.config, ems.logger)
		if err != nil {
			return fmt.Errorf("failed to create performance profiler: %w", err)
		}
	}

	// Initialize security monitor
	if ems.config.EnableSecurityMonitoring {
		ems.securityMonitor, err = NewSecurityMonitor(ems.config, ems.logger)
		if err != nil {
			return fmt.Errorf("failed to create security monitor: %w", err)
		}
	}

	// Initialize business metrics collector
	if ems.config.EnableBusinessMetrics {
		ems.businessMetrics, err = NewBusinessMetricsCollector(ems.config, ems.logger)
		if err != nil {
			return fmt.Errorf("failed to create business metrics collector: %w", err)
		}
	}

	// Initialize SLA monitor
	if ems.config.EnableSLAMonitoring {
		ems.slaMonitor, err = NewSLAMonitor(ems.config, ems.logger)
		if err != nil {
			return fmt.Errorf("failed to create SLA monitor: %w", err)
		}
	}

	// Initialize capacity planner
	if ems.config.EnableCapacityPlanning {
		ems.capacityPlanner, err = NewCapacityPlanner(ems.config, ems.logger)
		if err != nil {
			return fmt.Errorf("failed to create capacity planner: %w", err)
		}
	}

	// Initialize real-time processor
	if ems.config.EnableRealTimeProcessing {
		ems.realTimeProcessor, err = NewRealTimeProcessor(ems.config, ems.logger)
		if err != nil {
			return fmt.Errorf("failed to create real-time processor: %w", err)
		}
	}

	// Initialize dashboard manager
	ems.enhancedDashboard, err = NewEnhancedDashboardManager(ems.config, ems.logger)
	if err != nil {
		return fmt.Errorf("failed to create dashboard manager: %w", err)
	}

	// Initialize report generator
	ems.reportGenerator, err = NewReportGenerator(ems.config, ems.logger)
	if err != nil {
		return fmt.Errorf("failed to create report generator: %w", err)
	}

	return nil
}

// Start starts the enhanced monitoring system
func (ems *EnhancedMonitoringSystem) Start(ctx context.Context) error {
	ctx, span := enhancedMonitoringTracer.Start(ctx, "enhanced_monitoring.start",
		trace.WithAttributes(
			attribute.String("system.id", ems.id),
			attribute.String("service.name", ems.config.ServiceName),
			attribute.String("environment", ems.config.Environment),
		),
	)
	defer span.End()

	ems.mutex.Lock()
	defer ems.mutex.Unlock()

	if ems.isRunning {
		return fmt.Errorf("enhanced monitoring system is already running")
	}

	ems.logger.Info("Starting enhanced monitoring system",
		"system_id", ems.id,
		"service_name", ems.config.ServiceName)

	// Start all components
	if err := ems.startComponents(ctx); err != nil {
		return fmt.Errorf("failed to start components: %w", err)
	}

	// Start background workers
	ems.startBackgroundWorkers()

	ems.isRunning = true
	ems.healthStatus = SystemHealthStatusHealthy

	span.SetAttributes(
		attribute.Bool("system.running", ems.isRunning),
		attribute.String("health.status", string(ems.healthStatus)),
	)

	ems.logger.Info("Enhanced monitoring system started successfully",
		"system_id", ems.id,
		"uptime", time.Since(ems.startTime))

	return nil
}

// DefaultEnhancedMonitoringConfig returns default configuration
func DefaultEnhancedMonitoringConfig() *EnhancedMonitoringConfig {
	return &EnhancedMonitoringConfig{
		ServiceName:                "hackai-service",
		Environment:                "development",
		Version:                    "1.0.0",
		MetricsInterval:            30 * time.Second,
		HealthCheckInterval:        10 * time.Second,
		AlertingInterval:           60 * time.Second,
		EnableMetrics:              true,
		EnableTracing:              true,
		EnableLogging:              true,
		EnableAlerting:             true,
		EnableAnomalyDetection:     true,
		EnablePerformanceProfiling: true,
		EnableSecurityMonitoring:   true,
		EnableBusinessMetrics:      true,
		EnableSLAMonitoring:        true,
		EnableCapacityPlanning:     true,
		EnableRealTimeProcessing:   true,
		MetricsRetention:           7 * 24 * time.Hour,
		TracesRetention:            24 * time.Hour,
		LogsRetention:              3 * 24 * time.Hour,
		MaxMetricsPoints:           100000,
		MaxTraceSpans:              50000,
		MaxLogEntries:              200000,
		AlertChannels:              []string{"email", "slack", "webhook"},
		AlertThresholds: map[string]float64{
			"cpu_usage":         80.0,
			"memory_usage":      85.0,
			"error_rate":        5.0,
			"response_time_p99": 2000.0,
		},
		SamplingRate:         0.1,
		BatchSize:            1000,
		FlushInterval:        10 * time.Second,
		EnableEncryption:     true,
		EnableAuthentication: true,
	}
}
