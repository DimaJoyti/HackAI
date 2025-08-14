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

	log.Info("Starting HackAI Authentication Service", "version", "1.0.0")

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

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService, log)

	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(authService, log)

	// Setup HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, "8081"), // Auth service port
		Handler:      setupRoutes(cfg, log, authService, authHandler, authMiddleware),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Info("Authentication service starting", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down Authentication service...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown", "error", err)
	}

	log.Info("Authentication service stopped")
}

// setupRoutes configures all routes and middleware for the authentication service
func setupRoutes(
	cfg *config.Config,
	log *logger.Logger,
	authService *auth.EnhancedAuthService,
	authHandler *handler.AuthHandler,
	authMiddleware *middleware.AuthMiddleware,
) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoints
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"authentication","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	})

	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready","service":"authentication","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	})

	// Metrics endpoint
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"service":"authentication","version":"1.0.0","uptime":"` + time.Since(time.Now()).String() + `"}`))
	})

	// Public authentication endpoints (no auth required)
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("POST /api/v1/auth/login", authHandler.Login)
	publicMux.HandleFunc("POST /api/v1/auth/refresh", authHandler.RefreshToken)
	publicMux.HandleFunc("POST /api/v1/auth/validate", authHandler.ValidateToken)

	// Protected authentication endpoints (auth required)
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("POST /api/v1/auth/logout", authHandler.Logout)
	protectedMux.HandleFunc("GET /api/v1/auth/profile", authHandler.GetProfile)
	protectedMux.HandleFunc("POST /api/v1/auth/change-password", authHandler.ChangePassword)
	protectedMux.HandleFunc("POST /api/v1/auth/enable-totp", authHandler.EnableTOTP)
	protectedMux.HandleFunc("GET /api/v1/auth/permissions", authHandler.GetPermissions)

	// Apply authentication middleware to protected routes
	mux.Handle("/api/v1/auth/logout", authMiddleware.Authentication(protectedMux))
	mux.Handle("/api/v1/auth/profile", authMiddleware.Authentication(protectedMux))
	mux.Handle("/api/v1/auth/change-password", authMiddleware.Authentication(protectedMux))
	mux.Handle("/api/v1/auth/enable-totp", authMiddleware.Authentication(protectedMux))
	mux.Handle("/api/v1/auth/permissions", authMiddleware.Authentication(protectedMux))

	// Mount public routes
	mux.Handle("/api/v1/auth/login", publicMux)
	mux.Handle("/api/v1/auth/refresh", publicMux)
	mux.Handle("/api/v1/auth/validate", publicMux)

	// Admin endpoints (require admin role)
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /api/v1/admin/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Admin endpoint - list users"}`))
	})

	adminMux.HandleFunc("POST /api/v1/admin/users/{id}/permissions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Admin endpoint - grant permissions"}`))
	})

	// Apply admin middleware
	mux.Handle("/api/v1/admin/", authMiddleware.Authentication(authMiddleware.RequireAdmin(adminMux)))

	// Moderator endpoints (require moderator or admin role)
	moderatorMux := http.NewServeMux()
	moderatorMux.HandleFunc("GET /api/v1/moderator/reports", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Moderator endpoint - view reports"}`))
	})

	// Apply moderator middleware
	mux.Handle("/api/v1/moderator/", authMiddleware.Authentication(authMiddleware.RequireModerator(moderatorMux)))

	// Apply global middleware (in reverse order of execution)
	var handler http.Handler = mux
	handler = middleware.Recovery(log)(handler)
	handler = middleware.SecurityHeaders()(handler)
	handler = middleware.RateLimit(cfg.Server.RateLimit)(handler)
	handler = middleware.CORS(cfg.Server.CORS)(handler)
	handler = authMiddleware.AuditLog(handler) // Add audit logging
	handler = middleware.Logging(log)(handler)
	handler = middleware.RequestID(handler)

	return handler
}

// Example of how to use the authentication service programmatically
func demonstrateAuthService(authService *auth.EnhancedAuthService, log *logger.Logger) {
	ctx := context.Background()

	// Example authentication request
	authReq := &auth.AuthenticationRequest{
		EmailOrUsername: "admin@hackai.com",
		Password:        "SecurePassword123!",
		IPAddress:       "192.168.1.100",
		UserAgent:       "HackAI-Demo/1.0",
		RememberMe:      false,
	}

	// Authenticate user
	authResp, err := authService.Authenticate(ctx, authReq)
	if err != nil {
		log.Error("Authentication failed", "error", err)
		return
	}

	log.Info("Authentication successful",
		"user_id", authResp.User.ID,
		"username", authResp.User.Username,
		"session_id", authResp.SessionID,
	)

	// Validate token
	claims, err := authService.ValidateToken(authResp.AccessToken)
	if err != nil {
		log.Error("Token validation failed", "error", err)
		return
	}

	log.Info("Token validation successful",
		"user_id", claims.UserID,
		"role", claims.Role,
		"expires_at", claims.ExpiresAt.Time,
	)

	// Check permissions
	hasPermission, err := authService.CheckPermission(ctx, claims.UserID, "scans", "create")
	if err != nil {
		log.Error("Permission check failed", "error", err)
		return
	}

	log.Info("Permission check result",
		"user_id", claims.UserID,
		"resource", "scans",
		"action", "create",
		"allowed", hasPermission,
	)

	// Logout
	if err := authService.Logout(ctx, authResp.AccessToken, "192.168.1.100", "HackAI-Demo/1.0"); err != nil {
		log.Error("Logout failed", "error", err)
		return
	}

	log.Info("Logout successful", "user_id", claims.UserID)
}
