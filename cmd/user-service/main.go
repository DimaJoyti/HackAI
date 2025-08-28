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
	"github.com/dimajoyti/hackai/pkg/observability"
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

	log.Info("Starting HackAI User Service", "version", "1.0.0")

	// Initialize observability
	obs, err := observability.NewProvider(&cfg.Observability, "hackai-user-service", "1.0.0", log)
	if err != nil {
		log.Fatal("Failed to initialize observability", "error", err)
	}
	defer obs.Shutdown(context.Background())

	// Initialize database
	db, err := database.New(&cfg.Database, log)
	if err != nil {
		log.Fatal("Failed to initialize database", "error", err)
	}
	defer db.Close()

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

	// Initialize use cases
	userUseCase := usecase.NewUserUseCase(userRepo, authService, log)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService, log)
	userHandler := handler.NewUserHandler(userUseCase, log)

	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(authService, log)
	loggingMiddleware := middleware.Logging(log)

	// Setup HTTP server
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"user-service","version":"1.0.0"}`))
	})

	// Metrics endpoint (simplified)
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# User service metrics\nuser_service_up 1\n"))
	})

	// Public authentication endpoints (simplified - these would be implemented in auth handler)
	mux.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"error":"Authentication endpoints not implemented yet"}`))
	})

	// Protected user endpoints
	mux.Handle("GET /api/v1/auth/profile", authMiddleware.Authentication(http.HandlerFunc(authHandler.GetProfile)))
	mux.Handle("PUT /api/v1/auth/profile", authMiddleware.Authentication(http.HandlerFunc(userHandler.UpdateProfile)))

	// Admin endpoints
	mux.Handle("GET /api/v1/users", authMiddleware.RequireRole(domain.UserRoleAdmin)(http.HandlerFunc(userHandler.ListUsers)))
	mux.Handle("GET /api/v1/users/search", authMiddleware.RequireRole(domain.UserRoleAdmin)(http.HandlerFunc(userHandler.SearchUsers)))
	mux.Handle("PUT /api/v1/users/{id}/role", authMiddleware.RequireRole(domain.UserRoleAdmin)(http.HandlerFunc(userHandler.UpdateUserRole)))
	mux.Handle("PUT /api/v1/users/{id}/status", authMiddleware.RequireRole(domain.UserRoleAdmin)(http.HandlerFunc(userHandler.UpdateUserStatus)))

	// Apply middleware chain
	handler := loggingMiddleware(mux)

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Info("User service starting", "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down user service...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown server
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown", "error", err)
	}

	log.Info("User service stopped")
}
