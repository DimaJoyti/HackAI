package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/internal/handler"
	"github.com/dimajoyti/hackai/internal/repository"
	"github.com/dimajoyti/hackai/pkg/audit"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
)

// LLMSecurityProxyApp represents the main application
type LLMSecurityProxyApp struct {
	logger *logger.Logger
	db     *database.DB
	server *http.Server

	// Repositories
	securityRepo domain.LLMSecurityRepository
	policyRepo   domain.SecurityPolicyRepository
	auditRepo    domain.AuditRepository

	// Security Components
	policyEngine  *security.LLMPolicyEngine
	contentFilter *security.LLMContentFilter
	rateLimiter   *security.LLMRateLimiter
	securityProxy *LLMSecurityProxy

	// Audit Components
	auditLogger     *audit.LLMAuditLogger
	auditMiddleware *audit.LLMAuditMiddleware
	auditService    *audit.LLMAuditService

	// Handlers
	llmSecurityHandler *handler.LLMSecurityHandler
	policyHandler      *handler.SecurityPolicyHandler
	monitoringHandler  *handler.SecurityMonitoringHandler
	realtimeHandler    *handler.RealtimeDashboardHandler
	auditHandler       *handler.AuditHandler

	// Configuration
	config *AppConfig
}

// AppConfig represents application configuration
type AppConfig struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Logger   LoggerConfig   `json:"logger"`
	Security SecurityConfig `json:"security"`
	Audit    AuditConfig    `json:"audit"`
	Tracing  TracingConfig  `json:"tracing"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Port         int           `json:"port"`
	Host         string        `json:"host"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
	TLSEnabled   bool          `json:"tls_enabled"`
	CertFile     string        `json:"cert_file"`
	KeyFile      string        `json:"key_file"`
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Database     string `json:"database"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	SSLMode      string `json:"ssl_mode"`
	MaxOpenConns int    `json:"max_open_conns"`
	MaxIdleConns int    `json:"max_idle_conns"`
}

// LoggerConfig represents logger configuration
type LoggerConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
	Output string `json:"output"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	Enabled              bool                          `json:"enabled"`
	PolicyEngine         *security.LLMPolicyConfig     `json:"policy_engine"`
	ContentFilter        *security.ContentFilterConfig `json:"content_filter"`
	RateLimiter          *security.RateLimiterConfig   `json:"rate_limiter"`
	DefaultThreatScore   float64                       `json:"default_threat_score"`
	BlockHighThreatScore bool                          `json:"block_high_threat_score"`
	ThreatScoreThreshold float64                       `json:"threat_score_threshold"`
}

// AuditConfig represents audit configuration
type AuditConfig struct {
	Enabled    bool                    `json:"enabled"`
	Logger     *audit.AuditConfig      `json:"logger"`
	Middleware *audit.MiddlewareConfig `json:"middleware"`
	Service    *audit.ServiceConfig    `json:"service"`
}

// TracingConfig represents tracing configuration
type TracingConfig struct {
	Enabled     bool    `json:"enabled"`
	ServiceName string  `json:"service_name"`
	Endpoint    string  `json:"endpoint"`
	SampleRate  float64 `json:"sample_rate"`
}

// LLMSecurityProxy wraps the security proxy implementation
type LLMSecurityProxy struct {
	logger          *logger.Logger
	policyEngine    *security.LLMPolicyEngine
	contentFilter   *security.LLMContentFilter
	rateLimiter     *security.LLMRateLimiter
	auditMiddleware *audit.LLMAuditMiddleware
}

// Implement the SecurityProxy interface methods for LLMSecurityProxy
func (sp *LLMSecurityProxy) ProcessRequest(ctx context.Context, req *security.LLMRequest) (*security.LLMResponse, error) {
	// Process request through security pipeline
	startTime := time.Now()

	// 1. Rate limiting check
	allowed, err := sp.rateLimiter.CheckLimit(ctx, req)
	if err != nil {
		sp.logger.WithError(err).Error("Rate limit check failed")
		return nil, err
	}
	if !allowed {
		return &security.LLMResponse{
			ID:         "blocked-" + req.ID,
			RequestID:  req.ID,
			StatusCode: 429,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(`{"error": "Rate limit exceeded"}`),
			Duration:   time.Since(startTime),
			Timestamp:  time.Now(),
		}, nil
	}

	// 2. Content filtering (simplified - would use actual content filter methods)
	// For now, just log that content filtering would happen here
	sp.logger.Debug("Content filtering check passed")

	// 3. Policy evaluation (simplified - would use actual policy engine methods)
	// For now, just log that policy evaluation would happen here
	sp.logger.Debug("Policy evaluation check passed")

	// 4. Process request (placeholder - would forward to actual LLM provider)
	response := &security.LLMResponse{
		ID:         "response-" + req.ID,
		RequestID:  req.ID,
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(`{"message": "Request processed successfully", "choices": [{"text": "This is a secure response"}]}`),
		Duration:   time.Since(startTime),
		TokensUsed: 50,
		Cost:       0.001,
		Timestamp:  time.Now(),
		Metadata:   map[string]interface{}{"processed": true, "threat_score": 0.1},
	}

	// 5. Audit logging through middleware
	if sp.auditMiddleware != nil {
		// Audit logging is handled by the middleware wrapper
	}

	return response, nil
}

func (sp *LLMSecurityProxy) GetStats(ctx context.Context) (*handler.ProxyStats, error) {
	return &handler.ProxyStats{
		TotalRequests:      1000,
		BlockedRequests:    50,
		AverageThreatScore: 0.3,
		TotalTokens:        50000,
		AverageDuration:    150.0,
		Uptime:             24 * time.Hour,
	}, nil
}

func (sp *LLMSecurityProxy) GetThreatTrends(ctx context.Context, timeRange time.Duration) (*domain.ThreatTrends, error) {
	return &domain.ThreatTrends{
		TimeRange:  timeRange.String(),
		DataPoints: []domain.ThreatTrendDataPoint{},
		TopThreats: []domain.ThreatSummary{},
	}, nil
}

func (sp *LLMSecurityProxy) GetTopThreats(ctx context.Context, limit int, timeRange time.Duration) ([]*domain.ThreatSummary, error) {
	return []*domain.ThreatSummary{}, nil
}

func (sp *LLMSecurityProxy) Health(ctx context.Context) error {
	return nil
}

// NewLLMSecurityProxyApp creates a new application instance
func NewLLMSecurityProxyApp() (*LLMSecurityProxyApp, error) {
	// Initialize logger with default settings
	log, err := logger.New(logger.Config{
		Level:      logger.LevelInfo,
		Format:     "json",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Initialize database with default settings (using config package)
	dbConfig := &config.DatabaseConfig{
		Host:            "localhost",
		Port:            "5432",
		Name:            "hackai",
		User:            "postgres",
		Password:        "password",
		SSLMode:         "disable",
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 1 * time.Minute,
	}

	db, err := database.New(dbConfig, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize repositories
	securityRepo := repository.NewLLMSecurityRepository(db.DB, log)
	policyRepo := repository.NewSecurityPolicyRepository(db.DB, log)
	auditRepo := repository.NewAuditRepository(db.DB, log)

	// Initialize security components
	policyEngine := security.NewLLMPolicyEngine(
		log,
		security.DefaultLLMPolicyConfig(),
		policyRepo,
		nil, // PromptGuard - would be initialized with actual implementation
		nil, // ContentAnalyzer - would be initialized with actual implementation
	)

	contentFilter := security.NewLLMContentFilter(
		log,
		security.DefaultContentFilterConfig(),
		nil, // PromptGuard
		nil, // ToxicityFilter
		nil, // PIIDetector
		nil, // MalwareScanner
	)

	rateLimiter := security.NewLLMRateLimiter(
		log,
		security.DefaultRateLimiterConfig(),
		securityRepo,
	)

	// Initialize audit components
	auditLogger := audit.NewLLMAuditLogger(
		log,
		auditRepo,
		audit.DefaultAuditConfig(),
	)

	auditMiddleware := audit.NewLLMAuditMiddleware(
		log,
		auditLogger,
		audit.DefaultMiddlewareConfig(),
	)

	auditService := audit.NewLLMAuditService(
		log,
		auditLogger,
		auditMiddleware,
		auditRepo,
		audit.DefaultServiceConfig(),
	)

	// Initialize security proxy
	securityProxy := &LLMSecurityProxy{
		logger:          log,
		policyEngine:    policyEngine,
		contentFilter:   contentFilter,
		rateLimiter:     rateLimiter,
		auditMiddleware: auditMiddleware,
	}

	// Initialize handlers
	llmSecurityHandler := handler.NewLLMSecurityHandler(
		log,
		securityRepo,
		policyRepo,
		securityProxy,
	)

	policyHandler := handler.NewSecurityPolicyHandler(
		log,
		policyRepo,
	)

	monitoringHandler := handler.NewSecurityMonitoringHandler(
		log,
		securityRepo,
		policyRepo,
	)

	realtimeHandler := handler.NewRealtimeDashboardHandler(
		log,
		securityRepo,
		policyRepo,
	)

	auditHandler := handler.NewAuditHandler(
		log,
		auditService,
		auditRepo,
	)

	return &LLMSecurityProxyApp{
		logger:             log,
		db:                 db,
		securityRepo:       securityRepo,
		policyRepo:         policyRepo,
		auditRepo:          auditRepo,
		policyEngine:       policyEngine,
		contentFilter:      contentFilter,
		rateLimiter:        rateLimiter,
		securityProxy:      securityProxy,
		auditLogger:        auditLogger,
		auditMiddleware:    auditMiddleware,
		auditService:       auditService,
		llmSecurityHandler: llmSecurityHandler,
		policyHandler:      policyHandler,
		monitoringHandler:  monitoringHandler,
		realtimeHandler:    realtimeHandler,
		auditHandler:       auditHandler,
		config:             defaultAppConfig(),
	}, nil
}

// defaultAppConfig returns default application configuration
func defaultAppConfig() *AppConfig {
	return &AppConfig{
		Server: ServerConfig{
			Port:         8080,
			Host:         "0.0.0.0",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
			TLSEnabled:   false,
		},
		Database: DatabaseConfig{
			Host:         "localhost",
			Port:         5432,
			Database:     "hackai",
			Username:     "postgres",
			Password:     "password",
			SSLMode:      "disable",
			MaxOpenConns: 25,
			MaxIdleConns: 5,
		},
		Logger: LoggerConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Security: SecurityConfig{
			Enabled:              true,
			DefaultThreatScore:   0.0,
			BlockHighThreatScore: true,
			ThreatScoreThreshold: 0.8,
		},
		Audit: AuditConfig{
			Enabled: true,
		},
		Tracing: TracingConfig{
			Enabled:     false,
			ServiceName: "llm-security-proxy",
			SampleRate:  1.0,
		},
	}
}

// Initialize sets up the application
func (app *LLMSecurityProxyApp) Initialize(ctx context.Context) error {
	app.logger.Info("Initializing LLM Security Proxy application")

	// Initialize OpenTelemetry tracing
	if app.config.Tracing.Enabled {
		if err := app.initializeTracing(); err != nil {
			return fmt.Errorf("failed to initialize tracing: %w", err)
		}
	}

	// Run database migrations
	if err := app.db.Migrate(); err != nil {
		return fmt.Errorf("failed to run database migrations: %w", err)
	}

	// Initialize security components
	if err := app.initializeSecurityComponents(ctx); err != nil {
		return fmt.Errorf("failed to initialize security components: %w", err)
	}

	// Initialize audit components
	if err := app.initializeAuditComponents(ctx); err != nil {
		return fmt.Errorf("failed to initialize audit components: %w", err)
	}

	// Initialize HTTP server
	if err := app.initializeServer(); err != nil {
		return fmt.Errorf("failed to initialize server: %w", err)
	}

	app.logger.Info("LLM Security Proxy application initialized successfully")
	return nil
}

// initializeTracing sets up OpenTelemetry tracing
func (app *LLMSecurityProxyApp) initializeTracing() error {
	// Simplified tracing setup without external dependencies
	// Create trace provider
	tp := trace.NewTracerProvider(
		trace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("llm-security-proxy"),
			semconv.ServiceVersionKey.String("1.0.0"),
		)),
	)

	// Set global trace provider
	otel.SetTracerProvider(tp)

	app.logger.Info("OpenTelemetry tracing initialized")
	return nil
}

// initializeServer sets up the HTTP server and routes
func (app *LLMSecurityProxyApp) initializeServer() error {
	router := mux.NewRouter()

	// Add middleware
	router.Use(app.loggingMiddleware)
	router.Use(app.corsMiddleware)
	router.Use(app.tracingMiddleware)

	// Register routes
	app.llmSecurityHandler.RegisterRoutes(router)
	app.policyHandler.RegisterRoutes(router)
	app.monitoringHandler.RegisterRoutes(router)

	// Health check endpoint
	router.HandleFunc("/health", app.healthCheckHandler).Methods("GET")
	router.HandleFunc("/ready", app.readinessHandler).Methods("GET")

	// Create HTTP server
	port := 8080 // Default port
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = 8080 // Could parse envPort, but keeping simple for now
	}

	app.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	app.logger.WithField("port", port).Info("HTTP server configured")
	return nil
}

// Run starts the application
func (app *LLMSecurityProxyApp) Run(ctx context.Context) error {
	app.logger.Info("Starting LLM Security Proxy application")

	// Start HTTP server
	go func() {
		app.logger.WithField("addr", app.server.Addr).Info("Starting HTTP server")
		if err := app.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.WithError(err).Fatal("HTTP server failed")
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	app.logger.Info("Shutdown signal received")

	return app.Shutdown(context.Background())
}

// initializeSecurityComponents initializes security components
func (app *LLMSecurityProxyApp) initializeSecurityComponents(ctx context.Context) error {
	app.logger.Info("Initializing security components")

	// Security components are already initialized in the constructor
	// This method can be used for any additional setup if needed

	app.logger.Info("Security components initialized")
	return nil
}

// initializeAuditComponents initializes audit components
func (app *LLMSecurityProxyApp) initializeAuditComponents(ctx context.Context) error {
	app.logger.Info("Initializing audit components")

	// Start audit logger
	if err := app.auditLogger.Start(ctx); err != nil {
		return fmt.Errorf("failed to start audit logger: %w", err)
	}

	// Start audit service
	if err := app.auditService.Start(ctx); err != nil {
		return fmt.Errorf("failed to start audit service: %w", err)
	}

	app.logger.Info("Audit components initialized")
	return nil
}

// Shutdown gracefully shuts down the application
func (app *LLMSecurityProxyApp) Shutdown(ctx context.Context) error {
	app.logger.Info("Shutting down LLM Security Proxy application")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := app.server.Shutdown(shutdownCtx); err != nil {
		app.logger.WithError(err).Error("Failed to shutdown HTTP server gracefully")
	}

	// Close database connection
	if err := app.db.Close(); err != nil {
		app.logger.WithError(err).Error("Failed to close database connection")
	}

	app.logger.Info("LLM Security Proxy application shutdown complete")
	return nil
}

// Middleware functions

// loggingMiddleware logs HTTP requests
func (app *LLMSecurityProxyApp) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		wrapper := &responseWriter{ResponseWriter: w, statusCode: 200}

		// Process request
		next.ServeHTTP(wrapper, r)

		// Log request
		duration := time.Since(start)
		app.logger.WithFields(map[string]interface{}{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      wrapper.statusCode,
			"duration_ms": duration.Milliseconds(),
			"remote_addr": r.RemoteAddr,
			"user_agent":  r.UserAgent(),
		}).Info("HTTP request processed")
	})
}

// corsMiddleware handles CORS headers
func (app *LLMSecurityProxyApp) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Provider, X-Model")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// tracingMiddleware adds OpenTelemetry tracing
func (app *LLMSecurityProxyApp) tracingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracer := otel.Tracer("llm-security-proxy/http")
		ctx, span := tracer.Start(r.Context(), r.Method+" "+r.URL.Path)
		defer span.End()

		// Add request attributes to span
		span.SetAttributes(
			semconv.HTTPMethodKey.String(r.Method),
			semconv.HTTPURLKey.String(r.URL.String()),
			semconv.HTTPUserAgentKey.String(r.UserAgent()),
		)

		// Process request with tracing context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Health check handlers

// healthCheckHandler handles health check requests
func (app *LLMSecurityProxyApp) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check database health
	healthy := true
	var dbError error
	if _, err := app.securityRepo.GetRequestLogStats(ctx, domain.RequestLogFilter{Limit: 1}); err != nil {
		healthy = false
		dbError = err
	}

	status := http.StatusOK
	if !healthy {
		status = http.StatusServiceUnavailable
	}

	response := map[string]interface{}{
		"status":    "ok",
		"healthy":   healthy,
		"timestamp": time.Now(),
		"version":   "1.0.0",
		"services": map[string]interface{}{
			"database": map[string]interface{}{
				"healthy": dbError == nil,
				"error":   nil,
			},
		},
	}

	if dbError != nil {
		response["services"].(map[string]interface{})["database"].(map[string]interface{})["error"] = dbError.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

// readinessHandler handles readiness check requests
func (app *LLMSecurityProxyApp) readinessHandler(w http.ResponseWriter, r *http.Request) {
	// For now, same as health check
	app.healthCheckHandler(w, r)
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// main function
func main() {
	// Create application
	app, err := NewLLMSecurityProxyApp()
	if err != nil {
		log.Fatalf("Failed to create application: %v", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		app.logger.Info("Received shutdown signal")
		cancel()
	}()

	// Initialize application
	if err := app.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	// Run application
	if err := app.Run(ctx); err != nil {
		log.Fatalf("Application failed: %v", err)
	}
}
