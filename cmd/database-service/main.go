package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/internal/handler"
	"github.com/dimajoyti/hackai/internal/repository"
	"github.com/dimajoyti/hackai/internal/usecase"
	"github.com/dimajoyti/hackai/pkg/auth"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/middleware"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log, err := logger.New(logger.Config{
		Level:      logger.LogLevel(cfg.Observability.Logging.Level),
		Format:     cfg.Observability.Logging.Format,
		Output:     cfg.Observability.Logging.Output,
		FilePath:   cfg.Observability.Logging.FilePath,
		AddSource:  true,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	log.Info("Starting HackAI Database Service", "version", "1.0.0")

	// Initialize database
	db, err := database.New(&cfg.Database, log)
	if err != nil {
		log.Fatal("Failed to initialize database", "error", err)
	}
	defer db.Close()

	// Initialize storage manager
	storageManager := database.NewStorageManager(db, log)

	// Initialize repositories
	auditRepo := repository.NewAuditRepository(db.DB, log)

	// Initialize use cases
	dbManager := usecase.NewDatabaseManagerUseCase(db, storageManager, auditRepo, log)

	// Initialize additional repositories
	userRepo := repository.NewUserRepository(db.DB, log)

	// Initialize security configuration
	securityConfig := auth.DefaultSecurityConfig()

	// Override with environment-specific settings
	if cfg.Security.PasswordMinLength > 0 {
		securityConfig.MinPasswordLength = cfg.Security.PasswordMinLength
	}
	if cfg.Security.SessionTimeout > 0 {
		securityConfig.SessionTimeout = cfg.Security.SessionTimeout
	}
	if cfg.Security.MaxLoginAttempts > 0 {
		securityConfig.MaxFailedAttempts = cfg.Security.MaxLoginAttempts
	}

	// Initialize JWT configuration
	jwtConfig := &auth.JWTConfig{
		Secret:          cfg.JWT.Secret,
		AccessTokenTTL:  cfg.JWT.AccessTokenTTL,
		RefreshTokenTTL: cfg.JWT.RefreshTokenTTL,
		Issuer:          cfg.JWT.Issuer,
		Audience:        cfg.JWT.Audience,
	}

	// Initialize enhanced authentication service
	authService := auth.NewEnhancedAuthService(
		jwtConfig,
		securityConfig,
		userRepo,
		auditRepo,
		log,
	)

	// Initialize handlers
	dbHandler := handler.NewDatabaseHandler(dbManager, log)

	// Setup HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, "8083"), // Database service port
		Handler:      setupRoutes(cfg, log, authService, dbHandler),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start background maintenance tasks
	go startMaintenanceTasks(context.Background(), dbManager, storageManager, log)

	// Start server in a goroutine
	go func() {
		log.Info("Database service starting", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down Database service...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown", "error", err)
	}

	log.Info("Database service stopped")
}

// setupRoutes configures all routes and middleware for the database service
func setupRoutes(cfg *config.Config, log *logger.Logger, authService auth.AuthService, dbHandler *handler.DatabaseHandler) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoints
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"database","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	})

	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready","service":"database","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	})

	// Metrics endpoint
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"service":"database","version":"1.0.0","uptime":"` + time.Since(time.Now()).String() + `"}`))
	})

	// Protected API endpoints
	protectedMux := http.NewServeMux()

	// Database health and management
	protectedMux.HandleFunc("GET /api/v1/database/health", dbHandler.GetHealth)
	protectedMux.HandleFunc("POST /api/v1/database/maintenance", dbHandler.PerformMaintenance)
	protectedMux.HandleFunc("POST /api/v1/database/archive", dbHandler.ArchiveData)

	// Backup management
	protectedMux.HandleFunc("POST /api/v1/database/backups", dbHandler.CreateBackup)
	protectedMux.HandleFunc("GET /api/v1/database/backups", dbHandler.ListBackups)
	protectedMux.HandleFunc("GET /api/v1/database/backups/{id}", dbHandler.GetBackup)

	// Retention policy management
	protectedMux.HandleFunc("POST /api/v1/database/retention-policies", dbHandler.CreateRetentionPolicy)
	protectedMux.HandleFunc("GET /api/v1/database/retention-policies", dbHandler.ListRetentionPolicies)

	// Audit and monitoring
	protectedMux.HandleFunc("GET /api/v1/database/audit-logs", dbHandler.GetAuditLogs)
	protectedMux.HandleFunc("GET /api/v1/database/security-events", dbHandler.GetSecurityEvents)
	protectedMux.HandleFunc("GET /api/v1/database/metrics", dbHandler.GetSystemMetrics)

	// Apply authentication middleware to protected routes
	authMiddleware := middleware.Authentication(authService, log)
	mux.Handle("/api/v1/", authMiddleware(protectedMux))

	// Apply global middleware (in reverse order of execution)
	var handler http.Handler = mux
	handler = middleware.Recovery(log)(handler)
	handler = middleware.SecurityHeaders()(handler)
	handler = middleware.RateLimit(cfg.Server.RateLimit)(handler)
	handler = middleware.CORS(cfg.Server.CORS)(handler)
	handler = middleware.Logging(log)(handler)
	handler = middleware.RequestID(handler)

	return handler
}

// startMaintenanceTasks starts background maintenance tasks
func startMaintenanceTasks(ctx context.Context, dbManager *usecase.DatabaseManagerUseCase, storageManager *database.StorageManager, log *logger.Logger) {
	// Daily maintenance at 2 AM
	maintenanceTicker := time.NewTicker(24 * time.Hour)
	defer maintenanceTicker.Stop()

	// Hourly cleanup tasks
	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	// Metrics collection every 5 minutes
	metricsTicker := time.NewTicker(5 * time.Minute)
	defer metricsTicker.Stop()

	log.Info("Starting background maintenance tasks")

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping background maintenance tasks")
			return

		case <-maintenanceTicker.C:
			log.Info("Running daily maintenance tasks")

			// Run full maintenance
			if err := storageManager.PerformMaintenance(ctx); err != nil {
				log.WithError(err).Error("Daily maintenance failed")
			}

		case <-cleanupTicker.C:
			log.Debug("Running hourly cleanup tasks")

			// Cleanup expired sessions
			if err := storageManager.CleanupExpiredSessions(ctx); err != nil {
				log.WithError(err).Error("Session cleanup failed")
			}

			// Cleanup expired permissions
			if err := storageManager.CleanupExpiredPermissions(ctx); err != nil {
				log.WithError(err).Error("Permission cleanup failed")
			}

			// Cleanup expired threat intelligence
			if err := storageManager.CleanupExpiredThreatIntelligence(ctx); err != nil {
				log.WithError(err).Error("Threat intelligence cleanup failed")
			}

		case <-metricsTicker.C:
			log.Debug("Collecting system metrics")

			// Collect and store system metrics
			if err := collectSystemMetrics(ctx, dbManager, log); err != nil {
				log.WithError(err).Error("Metrics collection failed")
			}
		}
	}
}

// collectSystemMetrics collects and stores system metrics
func collectSystemMetrics(ctx context.Context, dbManager *usecase.DatabaseManagerUseCase, log *logger.Logger) error {
	// This would collect actual system metrics in a real implementation
	// For now, we'll create some sample metrics

	metrics := []*domain.SystemMetrics{
		{
			MetricType:  "database",
			MetricName:  "connections_active",
			Value:       10.0,
			Unit:        "count",
			Service:     "database-service",
			Instance:    "db-01",
			Environment: "production",
			Timestamp:   time.Now(),
		},
		{
			MetricType:  "database",
			MetricName:  "query_duration_avg",
			Value:       25.5,
			Unit:        "milliseconds",
			Service:     "database-service",
			Instance:    "db-01",
			Environment: "production",
			Timestamp:   time.Now(),
		},
		{
			MetricType:  "system",
			MetricName:  "memory_usage",
			Value:       75.2,
			Unit:        "percent",
			Service:     "database-service",
			Instance:    "db-01",
			Environment: "production",
			Timestamp:   time.Now(),
		},
		{
			MetricType:  "system",
			MetricName:  "cpu_usage",
			Value:       45.8,
			Unit:        "percent",
			Service:     "database-service",
			Instance:    "db-01",
			Environment: "production",
			Timestamp:   time.Now(),
		},
	}

	return dbManager.RecordSystemMetrics(ctx, metrics)
}
