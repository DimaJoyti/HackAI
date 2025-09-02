package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/pprof"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// SimpleObservabilityOrchestrator manages the complete observability stack
type SimpleObservabilityOrchestrator struct {
	config         *config.ObservabilityConfig
	logger         *logger.Logger
	provider       *Provider
	healthServer   *http.Server
	metricsServer  *http.Server
	profilerServer *http.Server

	// Advanced features
	logAggregator    *LogAggregator
	alertManager     *AlertManager
	dashboardManager *DashboardManager

	// System status
	systemStatus  *SystemStatus
	systemMetrics *SystemMetrics
	startTime     time.Time

	// Lifecycle management
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	shutdownOnce sync.Once

	// OpenTelemetry
	tracer trace.Tracer
}

// SystemStatus represents system status information
type SystemStatus struct {
	SystemName    string                    `json:"system_name"`
	OverallHealth string                    `json:"overall_health"`
	Components    map[string]*ComponentInfo `json:"components"`
	Timestamp     time.Time                 `json:"timestamp"`
	Uptime        time.Duration             `json:"uptime"`
	Version       string                    `json:"version"`
}

// SystemMetrics represents system metrics
type SystemMetrics struct {
	Timestamp         time.Time              `json:"timestamp"`
	RequestsProcessed int64                  `json:"requests_processed"`
	ErrorsCount       int64                  `json:"errors_count"`
	ResponseTime      time.Duration          `json:"response_time"`
	MemoryUsage       float64                `json:"memory_usage"`
	CPUUsage          float64                `json:"cpu_usage"`
	GoroutineCount    int                    `json:"goroutine_count"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// NewSimpleObservabilityOrchestrator creates a new simple observability orchestrator
func NewSimpleObservabilityOrchestrator(
	cfg *config.ObservabilityConfig,
	serviceName, serviceVersion string,
	log *logger.Logger,
) (*SimpleObservabilityOrchestrator, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize observability provider
	provider, err := NewProvider(cfg, serviceName, serviceVersion, log)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create observability provider: %w", err)
	}

	orchestrator := &SimpleObservabilityOrchestrator{
		config:        cfg,
		logger:        log,
		provider:      provider,
		ctx:           ctx,
		cancel:        cancel,
		startTime:     time.Now(),
		systemStatus:  &SystemStatus{SystemName: serviceName, Version: serviceVersion},
		systemMetrics: &SystemMetrics{},
		tracer:        otel.Tracer("simple-observability-orchestrator"),
	}

	// Initialize advanced components
	if err := orchestrator.initializeAdvancedComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize advanced components: %w", err)
	}

	log.Info("Simple observability orchestrator initialized",
		"service", serviceName,
		"version", serviceVersion,
		"health_port", cfg.HealthCheck.Port,
		"metrics_port", cfg.Metrics.Port,
	)

	return orchestrator, nil
}

// initializeAdvancedComponents initializes advanced observability components
func (soo *SimpleObservabilityOrchestrator) initializeAdvancedComponents() error {
	// Initialize log aggregator
	logConfig := &LogAggregatorConfig{
		Enabled:            soo.config.Logging.Enabled,
		BufferSize:         1000,
		FlushInterval:      10 * time.Second,
		RetentionTime:      24 * time.Hour,
		CompressionEnabled: true,
		OutputFormat:       "json",
	}

	soo.logAggregator = NewLogAggregator(logConfig, soo.logger)

	// Initialize alert manager
	alertConfig := &AlertManagerConfig{
		Enabled:            soo.config.Alerting.Enabled,
		EvaluationInterval: 30 * time.Second,
		WebhookURL:         soo.config.Alerting.WebhookURL,
		EmailEnabled:       soo.config.Alerting.EmailEnabled,
		SlackEnabled:       soo.config.Alerting.SlackEnabled,
		SlackWebhookURL:    soo.config.Alerting.SlackWebhookURL,
	}

	soo.alertManager = NewAlertManager(alertConfig, soo.provider, soo.logger)

	// Initialize dashboard manager
	dashboardConfig := &DashboardManagerConfig{
		Enabled:         true,
		Port:            soo.config.Dashboard.Port,
		RefreshRate:     5 * time.Second,
		DataRetention:   7 * 24 * time.Hour,
		EnableWebSocket: true,
		MaxConnections:  100,
	}

	soo.dashboardManager = NewDashboardManager(dashboardConfig, soo.provider, soo.logger)

	return nil
}

// Start starts the simple observability orchestrator
func (soo *SimpleObservabilityOrchestrator) Start() error {
	ctx, span := soo.tracer.Start(soo.ctx, "simple_observability.start")
	defer span.End()

	soo.logger.Info("Starting simple observability orchestrator")

	// Start core observability provider
	if err := soo.provider.Start(ctx); err != nil {
		return fmt.Errorf("failed to start observability provider: %w", err)
	}

	// Start advanced components
	soo.wg.Add(4)
	go soo.startLogAggregator()
	go soo.startAlertManager()
	go soo.startDashboardManager()
	go soo.startServers()

	span.SetAttributes(
		attribute.Bool("started", true),
		attribute.String("health_endpoint", fmt.Sprintf(":%d/health", soo.config.HealthCheck.Port)),
		attribute.String("metrics_endpoint", fmt.Sprintf(":%s/metrics", soo.config.Metrics.Port)),
	)

	soo.logger.Info("Simple observability orchestrator started successfully")
	return nil
}

// startLogAggregator starts the log aggregation service
func (soo *SimpleObservabilityOrchestrator) startLogAggregator() {
	defer soo.wg.Done()

	if soo.logAggregator != nil {
		if err := soo.logAggregator.Start(soo.ctx); err != nil {
			soo.logger.Error("Failed to start log aggregator", "error", err)
		}
	}
}

// startAlertManager starts the alert management service
func (soo *SimpleObservabilityOrchestrator) startAlertManager() {
	defer soo.wg.Done()

	if soo.alertManager != nil {
		if err := soo.alertManager.Start(soo.ctx); err != nil {
			soo.logger.Error("Failed to start alert manager", "error", err)
		}
	}
}

// startDashboardManager starts the dashboard management service
func (soo *SimpleObservabilityOrchestrator) startDashboardManager() {
	defer soo.wg.Done()

	if soo.dashboardManager != nil {
		if err := soo.dashboardManager.Start(soo.ctx); err != nil {
			soo.logger.Error("Failed to start dashboard manager", "error", err)
		}
	}
}

// startServers starts the HTTP servers for health, metrics, and profiling
func (soo *SimpleObservabilityOrchestrator) startServers() {
	defer soo.wg.Done()

	// Start health check server
	soo.wg.Add(1)
	go soo.startHealthServer()

	// Start metrics server
	soo.wg.Add(1)
	go soo.startMetricsServer()

	// Start profiler server (if enabled)
	if soo.config.Profiling.Enabled {
		soo.wg.Add(1)
		go soo.startProfilerServer()
	}
}

// startHealthServer starts the health check HTTP server
func (soo *SimpleObservabilityOrchestrator) startHealthServer() {
	defer soo.wg.Done()

	router := mux.NewRouter()

	// Health check endpoints
	router.HandleFunc("/health", soo.handleHealthCheck).Methods("GET")
	router.HandleFunc("/health/live", soo.handleLivenessCheck).Methods("GET")
	router.HandleFunc("/health/ready", soo.handleReadinessCheck).Methods("GET")

	// System status endpoint
	router.HandleFunc("/status", soo.handleSystemStatus).Methods("GET")

	soo.healthServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", soo.config.HealthCheck.Port),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	soo.logger.Info("Starting health check server", "port", soo.config.HealthCheck.Port)

	if err := soo.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		soo.logger.Error("Health server error", "error", err)
	}
}

// startMetricsServer starts the Prometheus metrics HTTP server
func (soo *SimpleObservabilityOrchestrator) startMetricsServer() {
	defer soo.wg.Done()

	router := mux.NewRouter()

	// Prometheus metrics endpoint
	router.Handle("/metrics", promhttp.Handler()).Methods("GET")

	// Custom metrics endpoints
	router.HandleFunc("/metrics/custom", soo.handleCustomMetrics).Methods("GET")
	router.HandleFunc("/metrics/system", soo.handleSystemMetrics).Methods("GET")

	soo.metricsServer = &http.Server{
		Addr:         fmt.Sprintf(":%s", soo.config.Metrics.Port),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	soo.logger.Info("Starting metrics server", "port", soo.config.Metrics.Port)

	if err := soo.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		soo.logger.Error("Metrics server error", "error", err)
	}
}

// startProfilerServer starts the pprof profiling HTTP server
func (soo *SimpleObservabilityOrchestrator) startProfilerServer() {
	defer soo.wg.Done()

	router := mux.NewRouter()

	// pprof endpoints
	router.HandleFunc("/debug/pprof/", pprof.Index)
	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/debug/pprof/trace", pprof.Trace)
	router.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	router.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	router.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	router.Handle("/debug/pprof/block", pprof.Handler("block"))

	soo.profilerServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", soo.config.Profiling.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	soo.logger.Info("Starting profiler server", "port", soo.config.Profiling.Port)

	if err := soo.profilerServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		soo.logger.Error("Profiler server error", "error", err)
	}
}

// HTTP Handlers

// handleHealthCheck handles the main health check endpoint
func (soo *SimpleObservabilityOrchestrator) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	_, span := soo.tracer.Start(r.Context(), "health_check")
	defer span.End()

	status := soo.getSystemStatus()

	w.Header().Set("Content-Type", "application/json")

	if status.OverallHealth == "healthy" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	if err := json.NewEncoder(w).Encode(status); err != nil {
		soo.logger.Error("Failed to encode health response", "error", err)
	}
}

// handleLivenessCheck handles Kubernetes liveness probe
func (soo *SimpleObservabilityOrchestrator) handleLivenessCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":    "alive",
		"timestamp": time.Now(),
	}

	json.NewEncoder(w).Encode(response)
}

// handleReadinessCheck handles Kubernetes readiness probe
func (soo *SimpleObservabilityOrchestrator) handleReadinessCheck(w http.ResponseWriter, r *http.Request) {
	_, span := soo.tracer.Start(r.Context(), "readiness_check")
	defer span.End()

	// Check if all critical components are ready
	ready := soo.provider != nil && soo.logAggregator != nil

	w.Header().Set("Content-Type", "application/json")

	if ready {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	response := map[string]interface{}{
		"status":    map[string]bool{"ready": ready},
		"timestamp": time.Now(),
	}

	json.NewEncoder(w).Encode(response)
}

// handleSystemStatus handles detailed system status endpoint
func (soo *SimpleObservabilityOrchestrator) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	_, span := soo.tracer.Start(r.Context(), "system_status")
	defer span.End()

	metrics := soo.getSystemMetrics()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		soo.logger.Error("Failed to encode system status", "error", err)
	}
}

// handleCustomMetrics handles custom metrics endpoint
func (soo *SimpleObservabilityOrchestrator) handleCustomMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Return custom application metrics
	customMetrics := map[string]interface{}{
		"timestamp": time.Now(),
		"metrics": map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"memory": map[string]interface{}{
				"alloc":       memStats.Alloc,
				"total_alloc": memStats.TotalAlloc,
				"sys":         memStats.Sys,
				"heap_alloc":  memStats.HeapAlloc,
			},
			"gc": map[string]interface{}{
				"num_gc":      memStats.NumGC,
				"pause_total": memStats.PauseTotalNs,
				"last_gc":     time.Unix(0, int64(memStats.LastGC)),
			},
		},
	}

	json.NewEncoder(w).Encode(customMetrics)
}

// handleSystemMetrics handles system-level metrics endpoint
func (soo *SimpleObservabilityOrchestrator) handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	_, span := soo.tracer.Start(r.Context(), "system_metrics")
	defer span.End()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Get system metrics
	systemMetrics := map[string]interface{}{
		"timestamp": time.Now(),
		"uptime":    time.Since(soo.startTime).Seconds(),
		"version":   soo.systemStatus.Version,
		"system":    soo.systemStatus.SystemName,
	}

	json.NewEncoder(w).Encode(systemMetrics)
}

// Helper methods

// getSystemStatus returns current system status
func (soo *SimpleObservabilityOrchestrator) getSystemStatus() *SystemStatus {
	components := make(map[string]*ComponentInfo)

	// Check provider status
	components["observability_provider"] = &ComponentInfo{
		Name:      "Observability Provider",
		Status:    "healthy",
		Health:    1.0,
		LastCheck: time.Now(),
		Version:   "1.0.0",
		Metadata:  make(map[string]interface{}),
	}

	// Check log aggregator status
	if soo.logAggregator != nil {
		components["log_aggregator"] = &ComponentInfo{
			Name:      "Log Aggregator",
			Status:    "healthy",
			Health:    1.0,
			LastCheck: time.Now(),
			Version:   "1.0.0",
			Metadata:  make(map[string]interface{}),
		}
	}

	// Check alert manager status
	if soo.alertManager != nil {
		components["alert_manager"] = &ComponentInfo{
			Name:      "Alert Manager",
			Status:    "healthy",
			Health:    1.0,
			LastCheck: time.Now(),
			Version:   "1.0.0",
			Metadata:  make(map[string]interface{}),
		}
	}

	// Check dashboard manager status
	if soo.dashboardManager != nil {
		components["dashboard_manager"] = &ComponentInfo{
			Name:      "Dashboard Manager",
			Status:    "healthy",
			Health:    1.0,
			LastCheck: time.Now(),
			Version:   "1.0.0",
			Metadata:  make(map[string]interface{}),
		}
	}

	return &SystemStatus{
		SystemName:    soo.systemStatus.SystemName,
		OverallHealth: "healthy",
		Components:    components,
		Timestamp:     time.Now(),
		Uptime:        time.Since(soo.startTime),
		Version:       soo.systemStatus.Version,
	}
}

// getSystemMetrics returns current system metrics
func (soo *SimpleObservabilityOrchestrator) getSystemMetrics() *SystemMetrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &SystemMetrics{
		Timestamp:         time.Now(),
		RequestsProcessed: 0, // Would be tracked from actual metrics
		ErrorsCount:       0, // Would be tracked from actual metrics
		ResponseTime:      0, // Would be tracked from actual metrics
		MemoryUsage:       float64(memStats.Alloc) / float64(memStats.Sys),
		CPUUsage:          0.0, // Would require CPU monitoring
		GoroutineCount:    runtime.NumGoroutine(),
		Metadata:          make(map[string]interface{}),
	}
}

// GetProvider returns the observability provider
func (soo *SimpleObservabilityOrchestrator) GetProvider() *Provider {
	return soo.provider
}

// GetLogAggregator returns the log aggregator
func (soo *SimpleObservabilityOrchestrator) GetLogAggregator() *LogAggregator {
	return soo.logAggregator
}

// GetAlertManager returns the alert manager
func (soo *SimpleObservabilityOrchestrator) GetAlertManager() *AlertManager {
	return soo.alertManager
}

// GetDashboardManager returns the dashboard manager
func (soo *SimpleObservabilityOrchestrator) GetDashboardManager() *DashboardManager {
	return soo.dashboardManager
}

// CreateMiddleware creates observability middleware for HTTP handlers
func (soo *SimpleObservabilityOrchestrator) CreateMiddleware(serviceName string) func(http.Handler) http.Handler {
	return soo.provider.CreateMiddleware(serviceName)
}

// Shutdown gracefully shuts down the simple observability orchestrator
func (soo *SimpleObservabilityOrchestrator) Shutdown(ctx context.Context) error {
	var shutdownErr error

	soo.shutdownOnce.Do(func() {
		soo.logger.Info("Shutting down simple observability orchestrator")

		// Cancel context to stop background workers
		soo.cancel()

		// Shutdown HTTP servers
		if soo.healthServer != nil {
			if err := soo.healthServer.Shutdown(ctx); err != nil {
				soo.logger.Error("Failed to shutdown health server", "error", err)
				shutdownErr = err
			}
		}

		if soo.metricsServer != nil {
			if err := soo.metricsServer.Shutdown(ctx); err != nil {
				soo.logger.Error("Failed to shutdown metrics server", "error", err)
				shutdownErr = err
			}
		}

		if soo.profilerServer != nil {
			if err := soo.profilerServer.Shutdown(ctx); err != nil {
				soo.logger.Error("Failed to shutdown profiler server", "error", err)
				shutdownErr = err
			}
		}

		// Stop advanced components
		if soo.logAggregator != nil {
			soo.logAggregator.Stop()
		}

		if soo.alertManager != nil {
			soo.alertManager.Stop()
		}

		if soo.dashboardManager != nil {
			soo.dashboardManager.Stop()
		}

		// Wait for background workers to finish
		done := make(chan struct{})
		go func() {
			soo.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			soo.logger.Info("All background workers stopped")
		case <-ctx.Done():
			soo.logger.Warn("Shutdown timeout reached, forcing exit")
			shutdownErr = ctx.Err()
		}

		// Shutdown core components
		if soo.provider != nil {
			if err := soo.provider.Shutdown(ctx); err != nil {
				soo.logger.Error("Failed to shutdown observability provider", "error", err)
				shutdownErr = err
			}
		}

		soo.logger.Info("Simple observability orchestrator shutdown complete")
	})

	return shutdownErr
}
