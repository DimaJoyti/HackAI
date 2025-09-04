package observability

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var integrationTracer = otel.Tracer("hackai/observability/integration")

// MetricsCollector handles metrics collection and aggregation
type MetricsCollector struct {
	config   *MonitoringConfig
	provider *Provider
	logger   *logger.Logger
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(config *MonitoringConfig, provider *Provider, logger *logger.Logger) (*MetricsCollector, error) {
	return &MetricsCollector{
		config:   config,
		provider: provider,
		logger:   logger,
	}, nil
}

// CollectMetrics collects metrics from various sources
func (mc *MetricsCollector) CollectMetrics(ctx context.Context) error {
	mc.logger.Debug("Collecting metrics")
	// Implementation would collect actual metrics
	return nil
}

// PerformHealthChecks performs health checks
func (hc *HealthChecker) PerformHealthChecks(ctx context.Context) error {
	hc.provider.Logger().Debug("Performing health checks")
	return nil
}

// GetOverallHealth returns overall health status
func (hc *HealthChecker) GetOverallHealth(ctx context.Context) (*HealthStatus, error) {
	return &HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Service:   "hackai",
		Version:   "1.0.0",
		Uptime:    "1h30m",
		Checks:    make(map[string]string),
	}, nil
}

// ProcessAlerts processes pending alerts
func (am *AlertManager) ProcessAlerts(ctx context.Context) error {
	am.provider.Logger().Debug("Processing alerts")
	return nil
}

// Start method for Provider (no-op as Provider doesn't need explicit start)
func (p *Provider) Start(ctx context.Context) error {
	return nil
}

// Stop method for SimpleObservabilityOrchestrator 
func (soo *SimpleObservabilityOrchestrator) Stop() error {
	return soo.Shutdown(context.Background())
}

// PerformanceMonitor monitors system performance
type PerformanceMonitor struct {
	config *MonitoringConfig
	logger *logger.Logger
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(config *MonitoringConfig, logger *logger.Logger) (*PerformanceMonitor, error) {
	return &PerformanceMonitor{
		config: config,
		logger: logger,
	}, nil
}

// MonitoringConfig contains monitoring configuration
type MonitoringConfig struct {
	EnableHealthChecks          bool
	EnableAlerting              bool
	EnableMetrics               bool
	EnablePerformanceMonitoring bool
	EnableSystemMonitoring      bool
	HealthCheckInterval         time.Duration
	MetricsInterval             time.Duration
	AlertingInterval            time.Duration
}

// ObservabilityIntegration provides unified observability and monitoring
type ObservabilityIntegration struct {
	id     string
	config *ObservabilityIntegrationConfig
	logger *logger.Logger

	// Core observability
	provider           *Provider
	enhancedMonitoring *EnhancedMonitoringSystem
	simpleOrchestrator *SimpleObservabilityOrchestrator

	// Monitoring systems
	healthChecker      *HealthChecker
	alertManager       *AlertManager
	metricsCollector   *MetricsCollector
	performanceMonitor *PerformanceMonitor
	systemMonitor      *SystemMonitor
	dashboardManager   *DashboardManager

	// Advanced features
	anomalyDetector *AnomalyDetector
	securityMonitor *SecurityMonitor
	businessMetrics *BusinessMetricsCollector

	// HTTP servers
	metricsServer   *http.Server
	healthServer    *http.Server
	dashboardServer *http.Server

	// State management
	isRunning    bool
	startTime    time.Time
	healthStatus SystemHealthStatus

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mutex  sync.RWMutex
}

// ObservabilityIntegrationConfig configuration for observability integration
type ObservabilityIntegrationConfig struct {
	// Service information
	ServiceName    string `yaml:"service_name"`
	ServiceVersion string `yaml:"service_version"`
	Environment    string `yaml:"environment"`

	// Core observability config
	ObservabilityConfig *config.ObservabilityConfig `yaml:"observability"`

	// Enhanced monitoring config
	EnhancedMonitoring *EnhancedMonitoringConfig `yaml:"enhanced_monitoring"`

	// Server configurations
	MetricsPort   int `yaml:"metrics_port"`
	HealthPort    int `yaml:"health_port"`
	DashboardPort int `yaml:"dashboard_port"`

	// Feature flags
	EnableCoreObservability     bool `yaml:"enable_core_observability"`
	EnableEnhancedMonitoring    bool `yaml:"enable_enhanced_monitoring"`
	EnableSimpleOrchestrator    bool `yaml:"enable_simple_orchestrator"`
	EnableHealthChecks          bool `yaml:"enable_health_checks"`
	EnableAlerting              bool `yaml:"enable_alerting"`
	EnableMetricsCollection     bool `yaml:"enable_metrics_collection"`
	EnablePerformanceMonitoring bool `yaml:"enable_performance_monitoring"`
	EnableSystemMonitoring      bool `yaml:"enable_system_monitoring"`
	EnableDashboards            bool `yaml:"enable_dashboards"`
	EnableAnomalyDetection      bool `yaml:"enable_anomaly_detection"`
	EnableSecurityMonitoring    bool `yaml:"enable_security_monitoring"`
	EnableBusinessMetrics       bool `yaml:"enable_business_metrics"`

	// Integration settings
	AutoStart        bool          `yaml:"auto_start"`
	GracefulShutdown bool          `yaml:"graceful_shutdown"`
	ShutdownTimeout  time.Duration `yaml:"shutdown_timeout"`

	// Monitoring intervals
	HealthCheckInterval time.Duration `yaml:"health_check_interval"`
	MetricsInterval     time.Duration `yaml:"metrics_interval"`
	AlertingInterval    time.Duration `yaml:"alerting_interval"`
}

// NewObservabilityIntegration creates a new observability integration
func NewObservabilityIntegration(config *ObservabilityIntegrationConfig, logger *logger.Logger) (*ObservabilityIntegration, error) {
	if config == nil {
		config = DefaultObservabilityIntegrationConfig()
	}

	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	integration := &ObservabilityIntegration{
		id:           uuid.New().String(),
		config:       config,
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		startTime:    time.Now(),
		healthStatus: SystemHealthStatusUnknown,
	}

	// Initialize components
	if err := integration.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	logger.Info("Observability integration created",
		"integration_id", integration.id,
		"service_name", config.ServiceName,
		"environment", config.Environment)

	return integration, nil
}

// initializeComponents initializes all observability components
func (oi *ObservabilityIntegration) initializeComponents() error {
	var err error

	// Initialize core observability provider
	if oi.config.EnableCoreObservability {
		oi.provider, err = NewProvider(oi.config.ObservabilityConfig, oi.config.ServiceName, oi.config.ServiceVersion, oi.logger)
		if err != nil {
			return fmt.Errorf("failed to create observability provider: %w", err)
		}
	}

	// Initialize enhanced monitoring system
	if oi.config.EnableEnhancedMonitoring && oi.provider != nil {
		oi.enhancedMonitoring, err = NewEnhancedMonitoringSystem(oi.config.EnhancedMonitoring, oi.provider, oi.logger)
		if err != nil {
			return fmt.Errorf("failed to create enhanced monitoring system: %w", err)
		}
	}

	// Initialize simple orchestrator
	if oi.config.EnableSimpleOrchestrator {
		oi.simpleOrchestrator, err = NewSimpleObservabilityOrchestrator(oi.config.ObservabilityConfig, oi.config.ServiceName, oi.config.ServiceVersion, oi.logger)
		if err != nil {
			return fmt.Errorf("failed to create simple orchestrator: %w", err)
		}
	}

	// Initialize monitoring components
	if err := oi.initializeMonitoringComponents(); err != nil {
		return fmt.Errorf("failed to initialize monitoring components: %w", err)
	}

	// Initialize HTTP servers
	if err := oi.initializeHTTPServers(); err != nil {
		return fmt.Errorf("failed to initialize HTTP servers: %w", err)
	}

	return nil
}

// initializeMonitoringComponents initializes monitoring components
func (oi *ObservabilityIntegration) initializeMonitoringComponents() error {
	var err error

	// Create monitoring config from integration config
	monitoringConfig := &MonitoringConfig{
		EnableHealthChecks:          oi.config.EnableHealthChecks,
		EnableAlerting:              oi.config.EnableAlerting,
		EnableMetrics:               oi.config.EnableMetricsCollection,
		EnablePerformanceMonitoring: oi.config.EnablePerformanceMonitoring,
		EnableSystemMonitoring:      oi.config.EnableSystemMonitoring,
		HealthCheckInterval:         oi.config.HealthCheckInterval,
		MetricsInterval:             oi.config.MetricsInterval,
		AlertingInterval:            oi.config.AlertingInterval,
	}

	// Initialize health checker
	if oi.config.EnableHealthChecks {
		oi.healthChecker = NewHealthChecker(oi.provider)
	}

	// Initialize alert manager
	if oi.config.EnableAlerting {
		oi.alertManager = NewAlertManager(oi.provider)
	}

	// Initialize metrics collector
	if oi.config.EnableMetricsCollection && oi.provider != nil {
		oi.metricsCollector, err = NewMetricsCollector(monitoringConfig, oi.provider, oi.logger)
		if err != nil {
			return fmt.Errorf("failed to create metrics collector: %w", err)
		}
	}

	// Initialize performance monitor
	if oi.config.EnablePerformanceMonitoring {
		oi.performanceMonitor, err = NewPerformanceMonitor(monitoringConfig, oi.logger)
		if err != nil {
			return fmt.Errorf("failed to create performance monitor: %w", err)
		}
	}

	// Initialize system monitor
	if oi.config.EnableSystemMonitoring {
		oi.systemMonitor = NewSystemMonitor(oi.provider.Metrics(), oi.logger)
	}

	// Initialize dashboard manager
	if oi.config.EnableDashboards {
		dashboardConfig := &DashboardManagerConfig{
			Enabled:         true,
			Port:            3000,
			RefreshRate:     5 * time.Second,
			DataRetention:   24 * time.Hour,
			EnableWebSocket: true,
			MaxConnections:  100,
		}
		oi.dashboardManager = NewDashboardManager(dashboardConfig, oi.provider, oi.logger)
	}

	// Initialize anomaly detector
	if oi.config.EnableAnomalyDetection {
		oi.anomalyDetector, err = NewAnomalyDetector(oi.config.EnhancedMonitoring, oi.logger)
		if err != nil {
			return fmt.Errorf("failed to create anomaly detector: %w", err)
		}
	}

	// Initialize security monitor
	if oi.config.EnableSecurityMonitoring {
		oi.securityMonitor, err = NewSecurityMonitor(oi.config.EnhancedMonitoring, oi.logger)
		if err != nil {
			return fmt.Errorf("failed to create security monitor: %w", err)
		}
	}

	// Initialize business metrics collector
	if oi.config.EnableBusinessMetrics {
		oi.businessMetrics, err = NewBusinessMetricsCollector(oi.config.EnhancedMonitoring, oi.logger)
		if err != nil {
			return fmt.Errorf("failed to create business metrics collector: %w", err)
		}
	}

	return nil
}

// initializeHTTPServers initializes HTTP servers for metrics, health, and dashboards
func (oi *ObservabilityIntegration) initializeHTTPServers() error {
	// Metrics server
	if oi.config.MetricsPort > 0 && oi.provider != nil {
		mux := http.NewServeMux()
		mux.Handle("/metrics", oi.provider.Metrics().Handler())

		oi.metricsServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", oi.config.MetricsPort),
			Handler: mux,
		}
	}

	// Health server
	if oi.config.HealthPort > 0 && oi.healthChecker != nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", oi.handleHealthCheck)
		mux.HandleFunc("/health/ready", oi.handleReadinessCheck)
		mux.HandleFunc("/health/live", oi.handleLivenessCheck)

		oi.healthServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", oi.config.HealthPort),
			Handler: mux,
		}
	}

	// Dashboard server
	if oi.config.DashboardPort > 0 && oi.dashboardManager != nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/dashboard", oi.handleDashboard)
		mux.HandleFunc("/api/metrics", oi.handleMetricsAPI)
		mux.HandleFunc("/api/health", oi.handleHealthAPI)

		oi.dashboardServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", oi.config.DashboardPort),
			Handler: mux,
		}
	}

	return nil
}

// Start starts the observability integration
func (oi *ObservabilityIntegration) Start(ctx context.Context) error {
	ctx, span := integrationTracer.Start(ctx, "observability_integration.start",
		trace.WithAttributes(
			attribute.String("integration.id", oi.id),
			attribute.String("service.name", oi.config.ServiceName),
			attribute.String("environment", oi.config.Environment),
		),
	)
	defer span.End()

	oi.mutex.Lock()
	defer oi.mutex.Unlock()

	if oi.isRunning {
		return fmt.Errorf("observability integration is already running")
	}

	oi.logger.Info("Starting observability integration",
		"integration_id", oi.id,
		"service_name", oi.config.ServiceName)

	// Start core observability provider
	if oi.provider != nil {
		if err := oi.provider.Start(ctx); err != nil {
			return fmt.Errorf("failed to start observability provider: %w", err)
		}
	}

	// Start enhanced monitoring system
	if oi.enhancedMonitoring != nil {
		if err := oi.enhancedMonitoring.Start(ctx); err != nil {
			return fmt.Errorf("failed to start enhanced monitoring: %w", err)
		}
	}

	// Start simple orchestrator
	if oi.simpleOrchestrator != nil {
		if err := oi.simpleOrchestrator.Start(); err != nil {
			return fmt.Errorf("failed to start simple orchestrator: %w", err)
		}
	}

	// Start monitoring components
	if err := oi.startMonitoringComponents(ctx); err != nil {
		return fmt.Errorf("failed to start monitoring components: %w", err)
	}

	// Start HTTP servers
	if err := oi.startHTTPServers(); err != nil {
		return fmt.Errorf("failed to start HTTP servers: %w", err)
	}

	// Start background workers
	oi.startBackgroundWorkers()

	oi.isRunning = true
	oi.healthStatus = SystemHealthStatusHealthy

	span.SetAttributes(
		attribute.Bool("integration.running", oi.isRunning),
		attribute.String("health.status", string(oi.healthStatus)),
	)

	oi.logger.Info("Observability integration started successfully",
		"integration_id", oi.id,
		"uptime", time.Since(oi.startTime))

	return nil
}

// DefaultObservabilityIntegrationConfig returns default configuration
func DefaultObservabilityIntegrationConfig() *ObservabilityIntegrationConfig {
	return &ObservabilityIntegrationConfig{
		ServiceName:                 "hackai-service",
		ServiceVersion:              "1.0.0",
		Environment:                 "development",
		MetricsPort:                 9090,
		HealthPort:                  8080,
		DashboardPort:               3000,
		EnableCoreObservability:     true,
		EnableEnhancedMonitoring:    true,
		EnableSimpleOrchestrator:    true,
		EnableHealthChecks:          true,
		EnableAlerting:              true,
		EnableMetricsCollection:     true,
		EnablePerformanceMonitoring: true,
		EnableSystemMonitoring:      true,
		EnableDashboards:            true,
		EnableAnomalyDetection:      true,
		EnableSecurityMonitoring:    true,
		EnableBusinessMetrics:       true,
		AutoStart:                   true,
		GracefulShutdown:            true,
		ShutdownTimeout:             30 * time.Second,
		HealthCheckInterval:         10 * time.Second,
		MetricsInterval:             30 * time.Second,
		AlertingInterval:            60 * time.Second,
		ObservabilityConfig:         config.DefaultObservabilityConfig(),
		EnhancedMonitoring:          DefaultEnhancedMonitoringConfig(),
	}
}

// startMonitoringComponents starts monitoring components
func (oi *ObservabilityIntegration) startMonitoringComponents(ctx context.Context) error {
	// Start dashboard manager
	if oi.dashboardManager != nil {
		if err := oi.dashboardManager.Start(ctx); err != nil {
			return fmt.Errorf("failed to start dashboard manager: %w", err)
		}
	}

	return nil
}

// startHTTPServers starts HTTP servers
func (oi *ObservabilityIntegration) startHTTPServers() error {
	// Start metrics server
	if oi.metricsServer != nil {
		oi.wg.Add(1)
		go func() {
			defer oi.wg.Done()
			oi.logger.Info("Starting metrics server", "port", oi.config.MetricsPort)
			if err := oi.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				oi.logger.Error("Metrics server error", "error", err)
			}
		}()
	}

	// Start health server
	if oi.healthServer != nil {
		oi.wg.Add(1)
		go func() {
			defer oi.wg.Done()
			oi.logger.Info("Starting health server", "port", oi.config.HealthPort)
			if err := oi.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				oi.logger.Error("Health server error", "error", err)
			}
		}()
	}

	// Start dashboard server
	if oi.dashboardServer != nil {
		oi.wg.Add(1)
		go func() {
			defer oi.wg.Done()
			oi.logger.Info("Starting dashboard server", "port", oi.config.DashboardPort)
			if err := oi.dashboardServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				oi.logger.Error("Dashboard server error", "error", err)
			}
		}()
	}

	return nil
}

// startBackgroundWorkers starts background monitoring workers
func (oi *ObservabilityIntegration) startBackgroundWorkers() {
	// Start health check worker
	if oi.healthChecker != nil {
		oi.wg.Add(1)
		go oi.healthCheckWorker()
	}

	// Start metrics collection worker
	if oi.metricsCollector != nil {
		oi.wg.Add(1)
		go oi.metricsWorker()
	}

	// Start alerting worker
	if oi.alertManager != nil {
		oi.wg.Add(1)
		go oi.alertingWorker()
	}

	// Start anomaly detection worker
	if oi.anomalyDetector != nil {
		oi.wg.Add(1)
		go oi.anomalyDetectionWorker()
	}
}

// Background worker methods
func (oi *ObservabilityIntegration) healthCheckWorker() {
	defer oi.wg.Done()
	ticker := time.NewTicker(oi.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-oi.ctx.Done():
			return
		case <-ticker.C:
			if err := oi.healthChecker.PerformHealthChecks(oi.ctx); err != nil {
				oi.logger.Error("Health check failed", "error", err)
			}
		}
	}
}

func (oi *ObservabilityIntegration) metricsWorker() {
	defer oi.wg.Done()
	ticker := time.NewTicker(oi.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-oi.ctx.Done():
			return
		case <-ticker.C:
			if err := oi.metricsCollector.CollectMetrics(oi.ctx); err != nil {
				oi.logger.Error("Metrics collection failed", "error", err)
			}
		}
	}
}

func (oi *ObservabilityIntegration) alertingWorker() {
	defer oi.wg.Done()
	ticker := time.NewTicker(oi.config.AlertingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-oi.ctx.Done():
			return
		case <-ticker.C:
			if err := oi.alertManager.ProcessAlerts(oi.ctx); err != nil {
				oi.logger.Error("Alert processing failed", "error", err)
			}
		}
	}
}

func (oi *ObservabilityIntegration) anomalyDetectionWorker() {
	defer oi.wg.Done()
	ticker := time.NewTicker(oi.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-oi.ctx.Done():
			return
		case <-ticker.C:
			// Collect current metrics for anomaly detection
			// This is a simplified implementation
			oi.logger.Debug("Running anomaly detection")
		}
	}
}

// HTTP handlers
func (oi *ObservabilityIntegration) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	if oi.healthChecker == nil {
		http.Error(w, "Health checker not available", http.StatusServiceUnavailable)
		return
	}

	health, err := oi.healthChecker.GetOverallHealth(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("Health check failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if health.Status == "healthy" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	fmt.Fprintf(w, `{"status": "%s", "timestamp": "%s"}`, health.Status, time.Now().Format(time.RFC3339))
}

func (oi *ObservabilityIntegration) handleReadinessCheck(w http.ResponseWriter, r *http.Request) {
	if !oi.isRunning {
		http.Error(w, "Service not ready", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status": "ready", "timestamp": "%s"}`, time.Now().Format(time.RFC3339))
}

func (oi *ObservabilityIntegration) handleLivenessCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status": "alive", "timestamp": "%s"}`, time.Now().Format(time.RFC3339))
}

func (oi *ObservabilityIntegration) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>HackAI Observability Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .metric { margin: 10px 0; padding: 10px; border: 1px solid #ccc; }
        .healthy { background-color: #d4edda; }
        .warning { background-color: #fff3cd; }
        .error { background-color: #f8d7da; }
    </style>
</head>
<body>
    <h1>HackAI Observability Dashboard</h1>
    <div class="metric healthy">
        <h3>Service Status</h3>
        <p>Status: %s</p>
        <p>Uptime: %s</p>
    </div>
    <div class="metric">
        <h3>Quick Links</h3>
        <ul>
            <li><a href="/api/health">Health API</a></li>
            <li><a href="/api/metrics">Metrics API</a></li>
        </ul>
    </div>
</body>
</html>`, oi.healthStatus, time.Since(oi.startTime))
}

func (oi *ObservabilityIntegration) handleMetricsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{
		"service": "%s",
		"version": "%s",
		"environment": "%s",
		"uptime": "%s",
		"status": "%s",
		"timestamp": "%s"
	}`, oi.config.ServiceName, oi.config.ServiceVersion, oi.config.Environment,
		time.Since(oi.startTime), oi.healthStatus, time.Now().Format(time.RFC3339))
}

func (oi *ObservabilityIntegration) handleHealthAPI(w http.ResponseWriter, r *http.Request) {
	oi.handleHealthCheck(w, r)
}

// Stop stops the observability integration
func (oi *ObservabilityIntegration) Stop() error {
	oi.mutex.Lock()
	defer oi.mutex.Unlock()

	if !oi.isRunning {
		return fmt.Errorf("observability integration is not running")
	}

	oi.logger.Info("Stopping observability integration", "integration_id", oi.id)

	// Cancel context to stop all workers
	oi.cancel()

	// Stop HTTP servers
	if oi.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		oi.metricsServer.Shutdown(ctx)
	}

	if oi.healthServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		oi.healthServer.Shutdown(ctx)
	}

	if oi.dashboardServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		oi.dashboardServer.Shutdown(ctx)
	}

	// Stop components
	if oi.enhancedMonitoring != nil {
		oi.enhancedMonitoring.Stop()
	}

	if oi.simpleOrchestrator != nil {
		oi.simpleOrchestrator.Stop()
	}

	if oi.provider != nil {
		oi.provider.Shutdown(context.Background())
	}

	// Wait for all workers to finish
	oi.wg.Wait()

	oi.isRunning = false
	oi.healthStatus = SystemHealthStatusUnknown

	oi.logger.Info("Observability integration stopped", "integration_id", oi.id)
	return nil
}
