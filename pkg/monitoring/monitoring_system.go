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

var monitoringTracer = otel.Tracer("hackai/monitoring")

// MonitoringSystem provides comprehensive monitoring and observability
type MonitoringSystem struct {
	id                 string
	name               string
	healthChecker      *HealthChecker
	alertManager       *AlertManager
	metricsCollector   *MetricsCollector
	performanceMonitor *PerformanceMonitor
	systemMonitor      *SystemMonitor
	dashboardManager   *DashboardManager
	reportGenerator    *ReportGenerator
	config             *MonitoringConfig
	observability      *observability.Provider
	logger             *logger.Logger
	mutex              sync.RWMutex
}

// MonitoringConfig holds configuration for the monitoring system
type MonitoringConfig struct {
	SystemID                    string        `json:"system_id"`
	EnableHealthChecks          bool          `json:"enable_health_checks"`
	EnableAlerting              bool          `json:"enable_alerting"`
	EnableMetrics               bool          `json:"enable_metrics"`
	EnablePerformanceMonitoring bool          `json:"enable_performance_monitoring"`
	EnableSystemMonitoring      bool          `json:"enable_system_monitoring"`
	EnableDashboards            bool          `json:"enable_dashboards"`
	EnableReporting             bool          `json:"enable_reporting"`
	HealthCheckInterval         time.Duration `json:"health_check_interval"`
	MetricsInterval             time.Duration `json:"metrics_interval"`
	AlertingInterval            time.Duration `json:"alerting_interval"`
	ReportingInterval           time.Duration `json:"reporting_interval"`
	RetentionPeriod             time.Duration `json:"retention_period"`
	MaxMetricsHistory           int           `json:"max_metrics_history"`
	MaxAlertsHistory            int           `json:"max_alerts_history"`
	AlertChannels               []string      `json:"alert_channels"`
	DashboardRefreshRate        time.Duration `json:"dashboard_refresh_rate"`
}

// MonitoringMetrics holds comprehensive monitoring metrics
type MonitoringMetrics struct {
	SystemID           string                   `json:"system_id"`
	Timestamp          time.Time                `json:"timestamp"`
	HealthStatus       OverallHealthStatus      `json:"health_status"`
	ComponentHealth    map[string]*HealthStatus `json:"component_health"`
	PerformanceMetrics *PerformanceMetrics      `json:"performance_metrics"`
	SystemMetrics      *SystemMetrics           `json:"system_metrics"`
	AlertSummary       *AlertSummary            `json:"alert_summary"`
	CustomMetrics      map[string]interface{}   `json:"custom_metrics"`
	Metadata           map[string]interface{}   `json:"metadata"`
}

// HealthStatus represents the health status of a component
type HealthStatus struct {
	ComponentID   string                 `json:"component_id"`
	ComponentName string                 `json:"component_name"`
	Status        ComponentStatus        `json:"status"`
	LastCheck     time.Time              `json:"last_check"`
	ResponseTime  time.Duration          `json:"response_time"`
	ErrorCount    int64                  `json:"error_count"`
	SuccessRate   float64                `json:"success_rate"`
	Details       map[string]interface{} `json:"details"`
	Dependencies  []string               `json:"dependencies"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// PerformanceMetrics holds performance-related metrics
type PerformanceMetrics struct {
	RequestsPerSecond     float64                `json:"requests_per_second"`
	AverageResponseTime   time.Duration          `json:"average_response_time"`
	P95ResponseTime       time.Duration          `json:"p95_response_time"`
	P99ResponseTime       time.Duration          `json:"p99_response_time"`
	ErrorRate             float64                `json:"error_rate"`
	ThroughputMBPS        float64                `json:"throughput_mbps"`
	ConcurrentConnections int64                  `json:"concurrent_connections"`
	QueueDepth            int64                  `json:"queue_depth"`
	ResourceUtilization   map[string]float64     `json:"resource_utilization"`
	CustomMetrics         map[string]interface{} `json:"custom_metrics"`
}

// SystemMetrics holds system-level metrics
type SystemMetrics struct {
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
	CustomMetrics       map[string]interface{} `json:"custom_metrics"`
}

// AlertSummary provides a summary of alerts
type AlertSummary struct {
	TotalAlerts       int64                  `json:"total_alerts"`
	CriticalAlerts    int64                  `json:"critical_alerts"`
	WarningAlerts     int64                  `json:"warning_alerts"`
	InfoAlerts        int64                  `json:"info_alerts"`
	ResolvedAlerts    int64                  `json:"resolved_alerts"`
	ActiveAlerts      int64                  `json:"active_alerts"`
	AlertsByType      map[string]int64       `json:"alerts_by_type"`
	AlertsByComponent map[string]int64       `json:"alerts_by_component"`
	RecentAlerts      []*Alert               `json:"recent_alerts"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// MonitoringReport represents a comprehensive monitoring report
type MonitoringReport struct {
	ID                  string                 `json:"id"`
	SystemID            string                 `json:"system_id"`
	ReportType          ReportType             `json:"report_type"`
	Period              ReportPeriod           `json:"period"`
	StartTime           time.Time              `json:"start_time"`
	EndTime             time.Time              `json:"end_time"`
	GeneratedAt         time.Time              `json:"generated_at"`
	Summary             *ReportSummary         `json:"summary"`
	HealthAnalysis      *HealthAnalysis        `json:"health_analysis"`
	PerformanceAnalysis *PerformanceAnalysis   `json:"performance_analysis"`
	AlertAnalysis       *AlertAnalysis         `json:"alert_analysis"`
	Recommendations     []*Recommendation      `json:"recommendations"`
	Trends              *TrendAnalysis         `json:"trends"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// Enums for monitoring
type OverallHealthStatus string
type ComponentStatus string
type ReportType string
type ReportPeriod string

const (
	// Overall Health Status
	HealthStatusHealthy   OverallHealthStatus = "healthy"
	HealthStatusDegraded  OverallHealthStatus = "degraded"
	HealthStatusUnhealthy OverallHealthStatus = "unhealthy"
	HealthStatusCritical  OverallHealthStatus = "critical"
	HealthStatusUnknown   OverallHealthStatus = "unknown"

	// Component Status
	ComponentStatusUp          ComponentStatus = "up"
	ComponentStatusDown        ComponentStatus = "down"
	ComponentStatusDegraded    ComponentStatus = "degraded"
	ComponentStatusMaintenance ComponentStatus = "maintenance"
	ComponentStatusUnknown     ComponentStatus = "unknown"

	// Report Types
	ReportTypeHealth      ReportType = "health"
	ReportTypePerformance ReportType = "performance"
	ReportTypeSecurity    ReportType = "security"
	ReportTypeCapacity    ReportType = "capacity"
	ReportTypeIncident    ReportType = "incident"
	ReportTypeCompliance  ReportType = "compliance"

	// Report Periods
	ReportPeriodHourly  ReportPeriod = "hourly"
	ReportPeriodDaily   ReportPeriod = "daily"
	ReportPeriodWeekly  ReportPeriod = "weekly"
	ReportPeriodMonthly ReportPeriod = "monthly"
	ReportPeriodCustom  ReportPeriod = "custom"
)

// NewMonitoringSystem creates a new monitoring system
func NewMonitoringSystem(id, name string, config *MonitoringConfig, observability *observability.Provider, logger *logger.Logger) (*MonitoringSystem, error) {
	if config == nil {
		config = &MonitoringConfig{
			SystemID:                    id,
			EnableHealthChecks:          true,
			EnableAlerting:              true,
			EnableMetrics:               true,
			EnablePerformanceMonitoring: true,
			EnableSystemMonitoring:      true,
			EnableDashboards:            true,
			EnableReporting:             true,
			HealthCheckInterval:         30 * time.Second,
			MetricsInterval:             10 * time.Second,
			AlertingInterval:            5 * time.Second,
			ReportingInterval:           time.Hour,
			RetentionPeriod:             7 * 24 * time.Hour, // 7 days
			MaxMetricsHistory:           10000,
			MaxAlertsHistory:            1000,
			AlertChannels:               []string{"email", "slack"},
			DashboardRefreshRate:        5 * time.Second,
		}
	}

	system := &MonitoringSystem{
		id:            id,
		name:          name,
		config:        config,
		observability: observability,
		logger:        logger,
	}

	// Initialize components
	var err error

	if config.EnableHealthChecks {
		system.healthChecker, err = NewHealthChecker(config, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create health checker: %w", err)
		}
	}

	if config.EnableAlerting {
		system.alertManager, err = NewAlertManager(config, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create alert manager: %w", err)
		}
	}

	if config.EnableMetrics {
		system.metricsCollector, err = NewMetricsCollector(config, observability, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create metrics collector: %w", err)
		}
	}

	if config.EnablePerformanceMonitoring {
		system.performanceMonitor, err = NewPerformanceMonitor(config, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create performance monitor: %w", err)
		}
	}

	if config.EnableSystemMonitoring {
		system.systemMonitor, err = NewSystemMonitor(config, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create system monitor: %w", err)
		}
	}

	if config.EnableDashboards {
		dashboardConfig := DefaultDashboardConfig()
		system.dashboardManager, err = NewDashboardManager(dashboardConfig, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create dashboard manager: %w", err)
		}
	}

	if config.EnableReporting {
		system.reportGenerator, err = NewReportGenerator(config, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create report generator: %w", err)
		}
	}

	logger.Info("Monitoring system initialized",
		"system_id", id,
		"name", name,
		"health_checks", config.EnableHealthChecks,
		"alerting", config.EnableAlerting,
		"metrics", config.EnableMetrics,
		"performance_monitoring", config.EnablePerformanceMonitoring,
		"system_monitoring", config.EnableSystemMonitoring,
		"dashboards", config.EnableDashboards,
		"reporting", config.EnableReporting)

	return system, nil
}

// Start starts the monitoring system
func (ms *MonitoringSystem) Start(ctx context.Context) error {
	ctx, span := monitoringTracer.Start(ctx, "monitoring_system.start",
		trace.WithAttributes(
			attribute.String("system.id", ms.id),
			attribute.String("system.name", ms.name),
		),
	)
	defer span.End()

	ms.logger.Info("Starting monitoring system", "system_id", ms.id)

	// Start health checking
	if ms.healthChecker != nil {
		go ms.startHealthChecking(ctx)
	}

	// Start metrics collection
	if ms.metricsCollector != nil {
		go ms.startMetricsCollection(ctx)
	}

	// Start performance monitoring
	if ms.performanceMonitor != nil {
		go ms.startPerformanceMonitoring(ctx)
	}

	// Start system monitoring
	if ms.systemMonitor != nil {
		go ms.startSystemMonitoring(ctx)
	}

	// Start alerting
	if ms.alertManager != nil {
		go ms.startAlerting(ctx)
	}

	// Start dashboard updates
	if ms.dashboardManager != nil {
		go ms.startDashboardUpdates(ctx)
	}

	// Start report generation
	if ms.reportGenerator != nil {
		go ms.startReportGeneration(ctx)
	}

	ms.logger.Info("Monitoring system started successfully", "system_id", ms.id)
	return nil
}

// GetCurrentMetrics returns current monitoring metrics
func (ms *MonitoringSystem) GetCurrentMetrics(ctx context.Context) (*MonitoringMetrics, error) {
	ctx, span := monitoringTracer.Start(ctx, "monitoring_system.get_current_metrics",
		trace.WithAttributes(
			attribute.String("system.id", ms.id),
		),
	)
	defer span.End()

	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	metrics := &MonitoringMetrics{
		SystemID:        ms.id,
		Timestamp:       time.Now(),
		ComponentHealth: make(map[string]*HealthStatus),
		CustomMetrics:   make(map[string]interface{}),
		Metadata:        make(map[string]interface{}),
	}

	// Collect health status
	if ms.healthChecker != nil {
		healthStatus, err := ms.healthChecker.GetOverallHealth(ctx)
		if err != nil {
			ms.logger.Warn("Failed to get health status", "error", err)
		} else {
			metrics.HealthStatus = healthStatus.Status
			metrics.ComponentHealth = healthStatus.Components
		}
	}

	// Collect performance metrics
	if ms.performanceMonitor != nil {
		perfMetrics, err := ms.performanceMonitor.GetCurrentMetrics(ctx)
		if err != nil {
			ms.logger.Warn("Failed to get performance metrics", "error", err)
		} else {
			metrics.PerformanceMetrics = perfMetrics
		}
	}

	// Collect system metrics
	if ms.systemMonitor != nil {
		sysMetrics, err := ms.systemMonitor.GetCurrentMetrics(ctx)
		if err != nil {
			ms.logger.Warn("Failed to get system metrics", "error", err)
		} else {
			metrics.SystemMetrics = sysMetrics
		}
	}

	// Collect alert summary
	if ms.alertManager != nil {
		alertSummary, err := ms.alertManager.GetAlertSummary(ctx)
		if err != nil {
			ms.logger.Warn("Failed to get alert summary", "error", err)
		} else {
			metrics.AlertSummary = alertSummary
		}
	}

	span.SetAttributes(
		attribute.String("health.status", string(metrics.HealthStatus)),
		attribute.Int("components.count", len(metrics.ComponentHealth)),
	)

	return metrics, nil
}

// Helper methods for starting background processes

func (ms *MonitoringSystem) startHealthChecking(ctx context.Context) {
	ticker := time.NewTicker(ms.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ms.healthChecker.PerformHealthChecks(ctx); err != nil {
				ms.logger.Error("Health check failed", "error", err)
			}
		}
	}
}

func (ms *MonitoringSystem) startMetricsCollection(ctx context.Context) {
	ticker := time.NewTicker(ms.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ms.metricsCollector.CollectMetrics(ctx); err != nil {
				ms.logger.Error("Metrics collection failed", "error", err)
			}
		}
	}
}

func (ms *MonitoringSystem) startPerformanceMonitoring(ctx context.Context) {
	ticker := time.NewTicker(ms.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ms.performanceMonitor.CollectMetrics(ctx); err != nil {
				ms.logger.Error("Performance monitoring failed", "error", err)
			}
		}
	}
}

func (ms *MonitoringSystem) startSystemMonitoring(ctx context.Context) {
	ticker := time.NewTicker(ms.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ms.systemMonitor.CollectMetrics(ctx); err != nil {
				ms.logger.Error("System monitoring failed", "error", err)
			}
		}
	}
}

func (ms *MonitoringSystem) startAlerting(ctx context.Context) {
	ticker := time.NewTicker(ms.config.AlertingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ms.alertManager.ProcessAlerts(ctx); err != nil {
				ms.logger.Error("Alert processing failed", "error", err)
			}
		}
	}
}

func (ms *MonitoringSystem) startDashboardUpdates(ctx context.Context) {
	ticker := time.NewTicker(ms.config.DashboardRefreshRate)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Update real-time data for dashboards
			ms.dashboardManager.updateRealTimeData(ctx)
		}
	}
}

func (ms *MonitoringSystem) startReportGeneration(ctx context.Context) {
	ticker := time.NewTicker(ms.config.ReportingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ms.reportGenerator.GenerateScheduledReports(ctx); err != nil {
				ms.logger.Error("Report generation failed", "error", err)
			}
		}
	}
}

// GetSystemStatus returns the overall system status
func (ms *MonitoringSystem) GetSystemStatus(ctx context.Context) (*SystemStatus, error) {
	metrics, err := ms.GetCurrentMetrics(ctx)
	if err != nil {
		return nil, err
	}

	status := &SystemStatus{
		SystemID:      ms.id,
		SystemName:    ms.name,
		OverallHealth: metrics.HealthStatus,
		Timestamp:     time.Now(),
		Components:    make(map[string]ComponentStatus),
		Metadata:      make(map[string]interface{}),
	}

	// Aggregate component statuses
	for componentID, health := range metrics.ComponentHealth {
		status.Components[componentID] = health.Status
	}

	return status, nil
}

// SystemStatus represents the overall system status
type SystemStatus struct {
	SystemID      string                     `json:"system_id"`
	SystemName    string                     `json:"system_name"`
	OverallHealth OverallHealthStatus        `json:"overall_health"`
	Timestamp     time.Time                  `json:"timestamp"`
	Components    map[string]ComponentStatus `json:"components"`
	Metadata      map[string]interface{}     `json:"metadata"`
}
