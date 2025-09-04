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

	// Dashboard v2 frontend (serve as static content for now)
	mux.HandleFunc("GET /dashboard", serveDashboardPage)
	mux.HandleFunc("GET /dashboard/", serveDashboardPage)

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

// serveDashboardPage serves the dashboard v2 frontend page
func serveDashboardPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HackAI Dashboard v2.0</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
            color: #00ff41;
            font-family: 'Courier New', monospace;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .dashboard-container {
            text-align: center;
            padding: 2rem;
            border: 1px solid #00ff41;
            border-radius: 10px;
            background: rgba(0, 255, 65, 0.1);
            max-width: 800px;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
        }
        .logo {
            font-size: 3rem;
            margin-bottom: 1rem;
            text-shadow: 0 0 10px #00ff41;
        }
        .version {
            font-size: 1.2rem;
            margin-bottom: 2rem;
            opacity: 0.8;
        }
        .feature-list {
            text-align: left;
            margin: 2rem 0;
        }
        .feature-item {
            margin: 0.5rem 0;
            padding: 0.5rem;
            border-left: 2px solid #00ff41;
            padding-left: 1rem;
        }
        .api-link {
            color: #00ff41;
            text-decoration: none;
            border: 1px solid #00ff41;
            padding: 0.5rem 1rem;
            margin: 0.5rem;
            display: inline-block;
            border-radius: 5px;
            transition: all 0.3s;
        }
        .api-link:hover {
            background: rgba(0, 255, 65, 0.2);
            text-shadow: 0 0 5px #00ff41;
        }
        .status {
            margin-top: 2rem;
            padding: 1rem;
            border: 1px solid #00ff41;
            border-radius: 5px;
            background: rgba(0, 255, 65, 0.05);
        }
        .upgrade-info {
            margin-top: 1rem;
            padding: 1rem;
            border: 1px solid #ff6b35;
            border-radius: 5px;
            background: rgba(255, 107, 53, 0.1);
            color: #ff6b35;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="logo">🚀 HackAI</div>
        <div class="version">Dashboard v2.0 - Advanced AI Security Platform</div>
        
        <div class="feature-list">
            <div class="feature-item">🤖 AI Autopilot - Autonomous system management</div>
            <div class="feature-item">🧠 Neural Analytics - Predictive insights engine</div>
            <div class="feature-item">⚡ Edge Computing - Distributed processing</div>
            <div class="feature-item">🔒 Quantum Security - Next-gen encryption</div>
            <div class="feature-item">🎨 Adaptive UI - Personalized interfaces</div>
            <div class="feature-item">🛡️ Zero Trust Architecture - Comprehensive security</div>
        </div>

        <div>
            <a href="/api/v1/admin/stats" class="api-link">System Stats</a>
            <a href="/docs" class="api-link">API Documentation</a>
            <a href="/health" class="api-link">Health Check</a>
            <a href="/metrics" class="api-link">Metrics</a>
        </div>

        <div class="upgrade-info">
            <strong>🔧 Upgrade Available!</strong><br>
            Run the dashboard upgrade utility:<br>
            <code>go run cmd/dashboard-upgrade/main.go</code>
        </div>

        <div class="status">
            <strong>Status:</strong> ✅ Dashboard v2.0 Available<br>
            <strong>API Gateway:</strong> ✅ Running<br>
            <strong>Upgrade Process:</strong> ✅ Ready to Execute
        </div>
    </div>

    <script>
        // Simple status check
        function updateStatus() {
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    console.log('System Status:', data);
                })
                .catch(error => {
                    console.log('Status check failed:', error);
                });
        }
        
        // Update status every 30 seconds
        setInterval(updateStatus, 30000);
        updateStatus();
    </script>
</body>
</html>`;

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}
