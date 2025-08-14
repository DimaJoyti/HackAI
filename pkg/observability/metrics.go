package observability

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// MetricsProvider manages Prometheus metrics
type MetricsProvider struct {
	registry *prometheus.Registry
	config   *config.MetricsConfig
	logger   *logger.Logger

	// HTTP metrics
	httpRequestsTotal   *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec
	httpRequestSize     *prometheus.HistogramVec
	httpResponseSize    *prometheus.HistogramVec

	// Database metrics
	dbConnectionsActive prometheus.Gauge
	dbConnectionsIdle   prometheus.Gauge
	dbConnectionsTotal  prometheus.Gauge
	dbQueryDuration     *prometheus.HistogramVec
	dbQueriesTotal      *prometheus.CounterVec

	// Authentication metrics
	authAttemptsTotal   *prometheus.CounterVec
	authDuration        *prometheus.HistogramVec
	activeSessionsTotal prometheus.Gauge

	// Security metrics
	securityEventsTotal  *prometheus.CounterVec
	rateLimitHitsTotal   *prometheus.CounterVec
	accountLockoutsTotal *prometheus.CounterVec

	// AI/ML metrics
	aiRequestsTotal      *prometheus.CounterVec
	aiProcessingDuration *prometheus.HistogramVec
	aiModelAccuracy      *prometheus.GaugeVec

	// System metrics
	systemInfo       *prometheus.GaugeVec
	uptimeSeconds    prometheus.Gauge
	memoryUsageBytes prometheus.Gauge
	cpuUsagePercent  prometheus.Gauge
}

// NewMetricsProvider creates a new metrics provider
func NewMetricsProvider(cfg *config.MetricsConfig, serviceName, serviceVersion string, log *logger.Logger) (*MetricsProvider, error) {
	if !cfg.Enabled {
		log.Info("Metrics collection is disabled")
		return &MetricsProvider{
			config: cfg,
			logger: log,
		}, nil
	}

	registry := prometheus.NewRegistry()

	mp := &MetricsProvider{
		registry: registry,
		config:   cfg,
		logger:   log,
	}

	// Initialize HTTP metrics
	mp.httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status_code", "service"},
	)

	mp.httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path", "status_code", "service"},
	)

	mp.httpRequestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_size_bytes",
			Help:    "HTTP request size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "path", "service"},
	)

	mp.httpResponseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_response_size_bytes",
			Help:    "HTTP response size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "path", "status_code", "service"},
	)

	// Initialize database metrics
	mp.dbConnectionsActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "db_connections_active",
			Help: "Number of active database connections",
		},
	)

	mp.dbConnectionsIdle = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "db_connections_idle",
			Help: "Number of idle database connections",
		},
	)

	mp.dbConnectionsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "db_connections_total",
			Help: "Total number of database connections",
		},
	)

	mp.dbQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "db_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0},
		},
		[]string{"operation", "table", "status"},
	)

	mp.dbQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "db_queries_total",
			Help: "Total number of database queries",
		},
		[]string{"operation", "table", "status"},
	)

	// Initialize authentication metrics
	mp.authAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"method", "status", "user_agent"},
	)

	mp.authDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_duration_seconds",
			Help:    "Authentication duration in seconds",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0},
		},
		[]string{"method", "status"},
	)

	mp.activeSessionsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_sessions_total",
			Help: "Total number of active user sessions",
		},
	)

	// Initialize security metrics
	mp.securityEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "security_events_total",
			Help: "Total number of security events",
		},
		[]string{"event_type", "severity", "source"},
	)

	mp.rateLimitHitsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rate_limit_hits_total",
			Help: "Total number of rate limit hits",
		},
		[]string{"endpoint", "client_ip"},
	)

	mp.accountLockoutsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "account_lockouts_total",
			Help: "Total number of account lockouts",
		},
		[]string{"reason", "user_type"},
	)

	// Initialize AI/ML metrics
	mp.aiRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_requests_total",
			Help: "Total number of AI/ML requests",
		},
		[]string{"model", "operation", "status"},
	)

	mp.aiProcessingDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ai_processing_duration_seconds",
			Help:    "AI/ML processing duration in seconds",
			Buckets: []float64{0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0},
		},
		[]string{"model", "operation"},
	)

	mp.aiModelAccuracy = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_model_accuracy",
			Help: "AI/ML model accuracy score",
		},
		[]string{"model", "dataset"},
	)

	// Initialize system metrics
	mp.systemInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "system_info",
			Help: "System information",
		},
		[]string{"service", "version", "go_version", "build_date"},
	)

	mp.uptimeSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "uptime_seconds",
			Help: "Service uptime in seconds",
		},
	)

	mp.memoryUsageBytes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "memory_usage_bytes",
			Help: "Memory usage in bytes",
		},
	)

	mp.cpuUsagePercent = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cpu_usage_percent",
			Help: "CPU usage percentage",
		},
	)

	// Register all metrics
	metrics := []prometheus.Collector{
		mp.httpRequestsTotal,
		mp.httpRequestDuration,
		mp.httpRequestSize,
		mp.httpResponseSize,
		mp.dbConnectionsActive,
		mp.dbConnectionsIdle,
		mp.dbConnectionsTotal,
		mp.dbQueryDuration,
		mp.dbQueriesTotal,
		mp.authAttemptsTotal,
		mp.authDuration,
		mp.activeSessionsTotal,
		mp.securityEventsTotal,
		mp.rateLimitHitsTotal,
		mp.accountLockoutsTotal,
		mp.aiRequestsTotal,
		mp.aiProcessingDuration,
		mp.aiModelAccuracy,
		mp.systemInfo,
		mp.uptimeSeconds,
		mp.memoryUsageBytes,
		mp.cpuUsagePercent,
	}

	for _, metric := range metrics {
		if err := registry.Register(metric); err != nil {
			return nil, fmt.Errorf("failed to register metric: %w", err)
		}
	}

	// Set system info
	mp.systemInfo.WithLabelValues(serviceName, serviceVersion, "go1.21", time.Now().Format("2006-01-02")).Set(1)

	log.Info("Metrics provider initialized",
		"service", serviceName,
		"metrics_path", cfg.Path,
		"metrics_port", cfg.Port,
	)

	return mp, nil
}

// HTTP Metrics

// RecordHTTPRequest records HTTP request metrics
func (mp *MetricsProvider) RecordHTTPRequest(method, path, statusCode, service string, duration time.Duration, requestSize, responseSize int64) {
	if mp.httpRequestsTotal == nil {
		return
	}

	mp.httpRequestsTotal.WithLabelValues(method, path, statusCode, service).Inc()
	mp.httpRequestDuration.WithLabelValues(method, path, statusCode, service).Observe(duration.Seconds())
	mp.httpRequestSize.WithLabelValues(method, path, service).Observe(float64(requestSize))
	mp.httpResponseSize.WithLabelValues(method, path, statusCode, service).Observe(float64(responseSize))
}

// Database Metrics

// SetDatabaseConnections sets database connection metrics
func (mp *MetricsProvider) SetDatabaseConnections(active, idle, total int) {
	if mp.dbConnectionsActive == nil {
		return
	}

	mp.dbConnectionsActive.Set(float64(active))
	mp.dbConnectionsIdle.Set(float64(idle))
	mp.dbConnectionsTotal.Set(float64(total))
}

// RecordDatabaseQuery records database query metrics
func (mp *MetricsProvider) RecordDatabaseQuery(operation, table, status string, duration time.Duration) {
	if mp.dbQueryDuration == nil {
		return
	}

	mp.dbQueriesTotal.WithLabelValues(operation, table, status).Inc()
	mp.dbQueryDuration.WithLabelValues(operation, table, status).Observe(duration.Seconds())
}

// Authentication Metrics

// RecordAuthAttempt records authentication attempt metrics
func (mp *MetricsProvider) RecordAuthAttempt(method, status, userAgent string, duration time.Duration) {
	if mp.authAttemptsTotal == nil {
		return
	}

	mp.authAttemptsTotal.WithLabelValues(method, status, userAgent).Inc()
	mp.authDuration.WithLabelValues(method, status).Observe(duration.Seconds())
}

// SetActiveSessions sets the number of active sessions
func (mp *MetricsProvider) SetActiveSessions(count int) {
	if mp.activeSessionsTotal == nil {
		return
	}

	mp.activeSessionsTotal.Set(float64(count))
}

// Security Metrics

// RecordSecurityEvent records security event metrics
func (mp *MetricsProvider) RecordSecurityEvent(eventType, severity, source string) {
	if mp.securityEventsTotal == nil {
		return
	}

	mp.securityEventsTotal.WithLabelValues(eventType, severity, source).Inc()
}

// RecordRateLimitHit records rate limit hit metrics
func (mp *MetricsProvider) RecordRateLimitHit(endpoint, clientIP string) {
	if mp.rateLimitHitsTotal == nil {
		return
	}

	mp.rateLimitHitsTotal.WithLabelValues(endpoint, clientIP).Inc()
}

// RecordAccountLockout records account lockout metrics
func (mp *MetricsProvider) RecordAccountLockout(reason, userType string) {
	if mp.accountLockoutsTotal == nil {
		return
	}

	mp.accountLockoutsTotal.WithLabelValues(reason, userType).Inc()
}

// AI/ML Metrics

// RecordAIRequest records AI/ML request metrics
func (mp *MetricsProvider) RecordAIRequest(model, operation, status string, duration time.Duration) {
	if mp.aiRequestsTotal == nil {
		return
	}

	mp.aiRequestsTotal.WithLabelValues(model, operation, status).Inc()
	mp.aiProcessingDuration.WithLabelValues(model, operation).Observe(duration.Seconds())
}

// SetAIModelAccuracy sets AI/ML model accuracy metrics
func (mp *MetricsProvider) SetAIModelAccuracy(model, dataset string, accuracy float64) {
	if mp.aiModelAccuracy == nil {
		return
	}

	mp.aiModelAccuracy.WithLabelValues(model, dataset).Set(accuracy)
}

// System Metrics

// SetUptime sets the service uptime
func (mp *MetricsProvider) SetUptime(uptime time.Duration) {
	if mp.uptimeSeconds == nil {
		return
	}

	mp.uptimeSeconds.Set(uptime.Seconds())
}

// SetMemoryUsage sets memory usage metrics
func (mp *MetricsProvider) SetMemoryUsage(bytes int64) {
	if mp.memoryUsageBytes == nil {
		return
	}

	mp.memoryUsageBytes.Set(float64(bytes))
}

// SetCPUUsage sets CPU usage metrics
func (mp *MetricsProvider) SetCPUUsage(percent float64) {
	if mp.cpuUsagePercent == nil {
		return
	}

	mp.cpuUsagePercent.Set(percent)
}

// Handler returns the Prometheus metrics HTTP handler
func (mp *MetricsProvider) Handler() http.Handler {
	if mp.registry == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(mp.registry, promhttp.HandlerOpts{})
}

// MetricsMiddleware creates HTTP middleware for metrics collection
func (mp *MetricsProvider) MetricsMiddleware(serviceName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create response writer wrapper to capture response details
			wrapper := &metricsResponseWriter{ResponseWriter: w, statusCode: 200}

			// Process request
			next.ServeHTTP(wrapper, r)

			// Record metrics
			duration := time.Since(start)
			statusCode := strconv.Itoa(wrapper.statusCode)

			mp.RecordHTTPRequest(
				r.Method,
				r.URL.Path,
				statusCode,
				serviceName,
				duration,
				r.ContentLength,
				int64(wrapper.bytesWritten),
			)
		})
	}
}

// metricsResponseWriter wraps http.ResponseWriter to capture response details
type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (mrw *metricsResponseWriter) WriteHeader(code int) {
	mrw.statusCode = code
	mrw.ResponseWriter.WriteHeader(code)
}

func (mrw *metricsResponseWriter) Write(b []byte) (int, error) {
	n, err := mrw.ResponseWriter.Write(b)
	mrw.bytesWritten += n
	return n, err
}

// StartMetricsServer starts the metrics HTTP server
func (mp *MetricsProvider) StartMetricsServer() error {
	if !mp.config.Enabled || mp.config.Port == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle(mp.config.Path, mp.Handler())

	server := &http.Server{
		Addr:    ":" + mp.config.Port,
		Handler: mux,
	}

	mp.logger.Info("Starting metrics server",
		"port", mp.config.Port,
		"path", mp.config.Path,
	)

	return server.ListenAndServe()
}
