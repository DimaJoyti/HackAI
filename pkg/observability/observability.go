package observability

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// Provider manages all observability components
type Provider struct {
	tracing *TracingProvider
	metrics *MetricsProvider
	logger  *logger.Logger
	config  *config.ObservabilityConfig

	// System monitoring
	startTime     time.Time
	systemMonitor *SystemMonitor

	// Graceful shutdown
	shutdownOnce sync.Once
}

// NewProvider creates a new observability provider
func NewProvider(cfg *config.ObservabilityConfig, serviceName, serviceVersion string, log *logger.Logger) (*Provider, error) {
	provider := &Provider{
		logger:    log,
		config:    cfg,
		startTime: time.Now(),
	}

	// Initialize tracing
	if cfg.Tracing.Enabled {
		tracingProvider, err := NewTracingProvider(&cfg.Tracing, serviceName, serviceVersion, log)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize tracing: %w", err)
		}
		provider.tracing = tracingProvider
	}

	// Initialize metrics
	if cfg.Metrics.Enabled {
		metricsProvider, err := NewMetricsProvider(&cfg.Metrics, serviceName, serviceVersion, log)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize metrics: %w", err)
		}
		provider.metrics = metricsProvider
	}

	// Initialize system monitoring
	provider.systemMonitor = NewSystemMonitor(provider.metrics, log)

	log.Info("Observability provider initialized",
		"service", serviceName,
		"version", serviceVersion,
		"tracing_enabled", cfg.Tracing.Enabled,
		"metrics_enabled", cfg.Metrics.Enabled,
	)

	return provider, nil
}

// Tracing returns the tracing provider
func (p *Provider) Tracing() *TracingProvider {
	return p.tracing
}

// Metrics returns the metrics provider
func (p *Provider) Metrics() *MetricsProvider {
	return p.metrics
}

// Logger returns the logger
func (p *Provider) Logger() *logger.Logger {
	return p.logger
}

// StartSpan starts a new trace span
func (p *Provider) StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if p.tracing != nil {
		return p.tracing.StartSpan(ctx, name, trace.WithAttributes(attrs...))
	}
	return ctx, trace.SpanFromContext(ctx)
}

// RecordMetric records a metric (helper method)
func (p *Provider) RecordMetric(metricType string, name string, value float64, labels map[string]string) {
	if p.metrics == nil {
		return
	}

	// This is a simplified metric recording - in practice, you'd have specific methods
	p.logger.Debug("Recording metric",
		"type", metricType,
		"name", name,
		"value", value,
		"labels", labels,
	)
}

// StartSystemMonitoring starts system resource monitoring
func (p *Provider) StartSystemMonitoring(ctx context.Context, interval time.Duration) {
	if p.systemMonitor != nil {
		go p.systemMonitor.Start(ctx, interval)
	}
}

// CreateMiddleware creates observability middleware for HTTP handlers
func (p *Provider) CreateMiddleware(serviceName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		var handler http.Handler = next

		// Apply metrics middleware
		if p.metrics != nil {
			handler = p.metrics.MetricsMiddleware(serviceName)(handler)
		}

		// Apply tracing middleware
		if p.tracing != nil {
			handler = p.tracing.TraceMiddleware(serviceName)(handler)
		}

		return handler
	}
}

// Shutdown gracefully shuts down all observability components
func (p *Provider) Shutdown(ctx context.Context) error {
	var err error
	p.shutdownOnce.Do(func() {
		p.logger.Info("Shutting down observability provider")

		// Stop system monitoring
		if p.systemMonitor != nil {
			p.systemMonitor.Stop()
		}

		// Shutdown tracing
		if p.tracing != nil {
			if shutdownErr := p.tracing.Shutdown(ctx); shutdownErr != nil {
				p.logger.WithError(shutdownErr).Error("Failed to shutdown tracing")
				err = shutdownErr
			}
		}

		p.logger.Info("Observability provider shutdown complete")
	})
	return err
}

// SystemMonitor monitors system resources
type SystemMonitor struct {
	metrics *MetricsProvider
	logger  *logger.Logger
	stopCh  chan struct{}
	stopped bool
	mu      sync.RWMutex
}

// NewSystemMonitor creates a new system monitor
func NewSystemMonitor(metrics *MetricsProvider, log *logger.Logger) *SystemMonitor {
	return &SystemMonitor{
		metrics: metrics,
		logger:  log,
		stopCh:  make(chan struct{}),
	}
}

// Start starts system monitoring
func (sm *SystemMonitor) Start(ctx context.Context, interval time.Duration) {
	sm.mu.Lock()
	if sm.stopped {
		sm.mu.Unlock()
		return
	}
	sm.mu.Unlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	sm.logger.Info("Starting system monitoring", "interval", interval)

	for {
		select {
		case <-ctx.Done():
			sm.logger.Info("System monitoring stopped due to context cancellation")
			return
		case <-sm.stopCh:
			sm.logger.Info("System monitoring stopped")
			return
		case <-ticker.C:
			sm.collectSystemMetrics()
		}
	}
}

// Stop stops system monitoring
func (sm *SystemMonitor) Stop() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.stopped {
		close(sm.stopCh)
		sm.stopped = true
	}
}

// collectSystemMetrics collects and records system metrics
func (sm *SystemMonitor) collectSystemMetrics() {
	if sm.metrics == nil {
		return
	}

	// Collect memory statistics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Record memory metrics
	sm.metrics.SetMemoryUsage(int64(memStats.Alloc))

	// Record uptime (simplified - would use actual service start time in production)
	uptime := time.Since(time.Now().Add(-time.Hour)) // Placeholder
	sm.metrics.SetUptime(uptime)

	// Record CPU usage (simplified - would use actual CPU monitoring in production)
	cpuUsage := float64(runtime.NumGoroutine()) / 100.0 // Placeholder metric
	sm.metrics.SetCPUUsage(cpuUsage)

	sm.logger.Debug("System metrics collected",
		"memory_alloc", memStats.Alloc,
		"goroutines", runtime.NumGoroutine(),
		"uptime", uptime,
	)
}

// HealthChecker provides health check functionality
type HealthChecker struct {
	provider *Provider
	checks   map[string]HealthCheck
	mu       sync.RWMutex
}

// HealthCheck represents a health check function
type HealthCheck func(ctx context.Context) error

// HealthStatus represents the health status
type HealthStatus struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Service   string            `json:"service"`
	Version   string            `json:"version"`
	Uptime    string            `json:"uptime"`
	Checks    map[string]string `json:"checks"`
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(provider *Provider) *HealthChecker {
	return &HealthChecker{
		provider: provider,
		checks:   make(map[string]HealthCheck),
	}
}

// AddCheck adds a health check
func (hc *HealthChecker) AddCheck(name string, check HealthCheck) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.checks[name] = check
}

// Check performs all health checks
func (hc *HealthChecker) Check(ctx context.Context, serviceName, serviceVersion string) *HealthStatus {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	status := &HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Service:   serviceName,
		Version:   serviceVersion,
		Uptime:    time.Since(hc.provider.startTime).String(),
		Checks:    make(map[string]string),
	}

	// Run all health checks
	for name, check := range hc.checks {
		if err := check(ctx); err != nil {
			status.Checks[name] = fmt.Sprintf("unhealthy: %v", err)
			status.Status = "unhealthy"
		} else {
			status.Checks[name] = "healthy"
		}
	}

	return status
}

// CreateHealthHandler creates an HTTP handler for health checks
func (hc *HealthChecker) CreateHealthHandler(serviceName, serviceVersion string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Start tracing span
		if hc.provider.tracing != nil {
			var span trace.Span
			ctx, span = hc.provider.StartSpan(ctx, "health_check",
				attribute.String("service", serviceName),
				attribute.String("endpoint", "/health"),
			)
			defer span.End()
		}

		// Perform health check
		health := hc.Check(ctx, serviceName, serviceVersion)

		// Set response headers
		w.Header().Set("Content-Type", "application/json")

		// Set status code based on health
		if health.Status == "healthy" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		// Write response
		response := fmt.Sprintf(`{
			"status": "%s",
			"timestamp": "%s",
			"service": "%s",
			"version": "%s",
			"uptime": "%s",
			"checks": %v
		}`, health.Status, health.Timestamp.Format(time.RFC3339), health.Service, health.Version, health.Uptime, formatChecks(health.Checks))

		w.Write([]byte(response))

		// Record metrics
		if hc.provider.metrics != nil {
			statusCode := "200"
			if health.Status != "healthy" {
				statusCode = "503"
			}
			hc.provider.metrics.RecordHTTPRequest(r.Method, r.URL.Path, statusCode, serviceName, time.Since(time.Now()), 0, int64(len(response)))
		}
	}
}

// formatChecks formats health checks for JSON response
func formatChecks(checks map[string]string) string {
	if len(checks) == 0 {
		return "{}"
	}

	result := "{"
	first := true
	for name, status := range checks {
		if !first {
			result += ","
		}
		result += fmt.Sprintf(`"%s":"%s"`, name, status)
		first = false
	}
	result += "}"
	return result
}

// AlertManager manages alerting based on metrics and traces
type AlertManager struct {
	provider *Provider
	rules    []AlertRule
	mu       sync.RWMutex
}

// AlertRule represents an alerting rule
type AlertRule struct {
	Name        string
	Description string
	Condition   func(ctx context.Context) bool
	Action      func(ctx context.Context, rule AlertRule)
}

// NewAlertManager creates a new alert manager
func NewAlertManager(provider *Provider) *AlertManager {
	return &AlertManager{
		provider: provider,
		rules:    make([]AlertRule, 0),
	}
}

// AddRule adds an alerting rule
func (am *AlertManager) AddRule(rule AlertRule) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.rules = append(am.rules, rule)
}

// EvaluateRules evaluates all alerting rules
func (am *AlertManager) EvaluateRules(ctx context.Context) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	for _, rule := range am.rules {
		if rule.Condition(ctx) {
			go rule.Action(ctx, rule)
		}
	}
}

// StartAlertEvaluation starts periodic alert rule evaluation
func (am *AlertManager) StartAlertEvaluation(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	am.provider.logger.Info("Starting alert evaluation", "interval", interval)

	for {
		select {
		case <-ctx.Done():
			am.provider.logger.Info("Alert evaluation stopped due to context cancellation")
			return
		case <-ticker.C:
			am.EvaluateRules(ctx)
		}
	}
}
