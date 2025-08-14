package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	log.Info("Starting HackAI Scanner Service", "version", "1.0.0")

	// Initialize database
	db, err := database.New(&cfg.Database, log)
	if err != nil {
		log.Fatal("Failed to initialize database", "error", err)
	}
	defer db.Close()

	// Initialize repository
	repo := repository.NewSecurityRepository(db.DB, log)

	// Initialize use cases
	vulnScanner := usecase.NewVulnerabilityScannerUseCase(repo, log)
	networkAnalyzer := usecase.NewNetworkAnalyzerUseCase(repo, log)
	threatIntel := usecase.NewThreatIntelligenceUseCase(repo, log)
	logAnalyzer := usecase.NewLogAnalyzerUseCase(repo, log)

	// Initialize AI model service
	aiService := usecase.NewAIModelService(vulnScanner, networkAnalyzer, threatIntel, logAnalyzer, repo, log)

	// Initialize repositories
	userRepo := repository.NewUserRepository(db.DB, log)
	auditRepo := repository.NewAuditRepository(db.DB, log)

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
	scannerHandler := handler.NewScannerHandler(vulnScanner, networkAnalyzer, aiService, log)

	// Setup HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, "8082"), // Scanner service port
		Handler:      setupRoutes(cfg, log, authService, scannerHandler),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Info("Scanner service starting", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down Scanner service...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown", "error", err)
	}

	log.Info("Scanner service stopped")
}

// setupRoutes configures all routes and middleware for the scanner service
func setupRoutes(cfg *config.Config, log *logger.Logger, authService auth.AuthService, scannerHandler *handler.ScannerHandler) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoints
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"scanner","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	})

	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready","service":"scanner","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	})

	// Metrics endpoint
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"service":"scanner","version":"1.0.0","uptime":"` + time.Since(time.Now()).String() + `"}`))
	})

	// Protected API endpoints
	protectedMux := http.NewServeMux()

	// Vulnerability scanning endpoints
	protectedMux.HandleFunc("POST /api/v1/scans/vulnerability", scannerHandler.StartVulnerabilityScan)
	protectedMux.HandleFunc("GET /api/v1/scans/vulnerability", scannerHandler.ListVulnerabilityScans)
	protectedMux.HandleFunc("GET /api/v1/scans/vulnerability/{id}", scannerHandler.GetVulnerabilityScan)
	protectedMux.HandleFunc("DELETE /api/v1/scans/vulnerability/{id}", scannerHandler.CancelVulnerabilityScan)

	// Network scanning endpoints
	protectedMux.HandleFunc("POST /api/v1/scans/network", scannerHandler.StartNetworkScan)
	protectedMux.HandleFunc("GET /api/v1/scans/network", scannerHandler.ListNetworkScans)
	protectedMux.HandleFunc("GET /api/v1/scans/network/{id}", scannerHandler.GetNetworkScan)
	protectedMux.HandleFunc("DELETE /api/v1/scans/network/{id}", scannerHandler.CancelNetworkScan)

	// AI analysis endpoints
	protectedMux.HandleFunc("POST /api/v1/ai/analyze", scannerHandler.PerformAIAnalysis)
	protectedMux.HandleFunc("GET /api/v1/ai/analysis/{id}", scannerHandler.GetAIAnalysis)

	// Vulnerability management endpoints
	protectedMux.HandleFunc("GET /api/v1/vulnerabilities", scannerHandler.ListVulnerabilities)
	protectedMux.HandleFunc("GET /api/v1/vulnerabilities/{id}", scannerHandler.GetVulnerability)
	protectedMux.HandleFunc("PUT /api/v1/vulnerabilities/{id}/status", scannerHandler.UpdateVulnerabilityStatus)

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
