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

	log.Info("Starting HackAI API Gateway", "version", "1.0.0")

	// Initialize database
	db, err := database.New(&cfg.Database, log)
	if err != nil {
		log.Fatal("Failed to initialize database", "error", err)
	}
	defer db.Close()

	// Run database migrations
	if err := db.Migrate(); err != nil {
		log.Fatal("Failed to run database migrations", "error", err)
	}

	// Seed database (only in development)
	if os.Getenv("ENVIRONMENT") == "development" {
		if err := db.Seed(); err != nil {
			log.Warn("Failed to seed database", "error", err)
		}
	}

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

	// Initialize HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:      setupRoutes(cfg, log, authService, db),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Info("API Gateway server starting", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down API Gateway server...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown", "error", err)
	}

	log.Info("API Gateway server stopped")
}

// setupRoutes configures all routes and middleware
func setupRoutes(cfg *config.Config, log *logger.Logger, authService auth.AuthService, db *database.DB) http.Handler {
	mux := http.NewServeMux()

	// Initialize handlers
	gatewayHandler := handler.NewGatewayHandler(log, authService, db)

	// Health check endpoint (no middleware)
	mux.HandleFunc("GET /health", gatewayHandler.Health)
	mux.HandleFunc("GET /ready", gatewayHandler.Ready)

	// Metrics endpoint (no auth required)
	mux.HandleFunc("GET /metrics", gatewayHandler.Metrics)

	// API documentation
	mux.HandleFunc("GET /docs", gatewayHandler.APIDocs)
	mux.HandleFunc("GET /docs/", gatewayHandler.APIDocs)

	// Authentication endpoints (no auth required)
	mux.HandleFunc("POST /api/v1/auth/register", gatewayHandler.Register)
	mux.HandleFunc("POST /api/v1/auth/login", gatewayHandler.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", gatewayHandler.RefreshToken)

	// Protected API endpoints
	protectedMux := http.NewServeMux()

	// User management
	protectedMux.HandleFunc("GET /api/v1/users/profile", gatewayHandler.GetProfile)
	protectedMux.HandleFunc("PUT /api/v1/users/profile", gatewayHandler.UpdateProfile)
	protectedMux.HandleFunc("POST /api/v1/auth/logout", gatewayHandler.Logout)
	protectedMux.HandleFunc("POST /api/v1/auth/change-password", gatewayHandler.ChangePassword)

	// Vulnerability scanning
	protectedMux.HandleFunc("POST /api/v1/scans/vulnerability", gatewayHandler.StartVulnerabilityScan)
	protectedMux.HandleFunc("GET /api/v1/scans/vulnerability", gatewayHandler.ListVulnerabilityScans)
	protectedMux.HandleFunc("GET /api/v1/scans/vulnerability/{id}", gatewayHandler.GetVulnerabilityScan)
	protectedMux.HandleFunc("DELETE /api/v1/scans/vulnerability/{id}", gatewayHandler.CancelVulnerabilityScan)

	// Network scanning
	protectedMux.HandleFunc("POST /api/v1/scans/network", gatewayHandler.StartNetworkScan)
	protectedMux.HandleFunc("GET /api/v1/scans/network", gatewayHandler.ListNetworkScans)
	protectedMux.HandleFunc("GET /api/v1/scans/network/{id}", gatewayHandler.GetNetworkScan)
	protectedMux.HandleFunc("DELETE /api/v1/scans/network/{id}", gatewayHandler.CancelNetworkScan)

	// Vulnerability management
	protectedMux.HandleFunc("GET /api/v1/vulnerabilities", gatewayHandler.ListVulnerabilities)
	protectedMux.HandleFunc("GET /api/v1/vulnerabilities/{id}", gatewayHandler.GetVulnerability)
	protectedMux.HandleFunc("PUT /api/v1/vulnerabilities/{id}/status", gatewayHandler.UpdateVulnerabilityStatus)

	// Admin endpoints
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /api/v1/admin/users", gatewayHandler.ListUsers)
	adminMux.HandleFunc("GET /api/v1/admin/users/{id}", gatewayHandler.GetUser)
	adminMux.HandleFunc("PUT /api/v1/admin/users/{id}/role", gatewayHandler.UpdateUserRole)
	adminMux.HandleFunc("PUT /api/v1/admin/users/{id}/status", gatewayHandler.UpdateUserStatus)
	adminMux.HandleFunc("GET /api/v1/admin/stats", gatewayHandler.GetSystemStats)

	// WebSocket endpoints
	protectedMux.HandleFunc("GET /api/v1/ws/scans", gatewayHandler.WebSocketHandler)

	// Apply middleware chain
	var handler http.Handler = mux

	// Add protected routes with authentication middleware
	authMiddleware := middleware.Authentication(authService, log)
	mux.Handle("/api/v1/", authMiddleware(protectedMux))

	// Add admin routes with admin authorization
	adminAuthMiddleware := middleware.Authorization(domain.UserRoleAdmin)
	mux.Handle("/api/v1/admin/", authMiddleware(adminAuthMiddleware(adminMux)))

	// Apply global middleware (in reverse order of execution)
	handler = middleware.Recovery(log)(handler)
	handler = middleware.SecurityHeaders()(handler)
	handler = middleware.RateLimit(cfg.Server.RateLimit)(handler)
	handler = middleware.CORS(cfg.Server.CORS)(handler)
	handler = middleware.Logging(log)(handler)
	handler = middleware.RequestID(handler)

	return handler
}
