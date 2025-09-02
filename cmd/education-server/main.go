package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/internal/handlers"
	"github.com/dimajoyti/hackai/pkg/education"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func main() {
	// Initialize logger
	logger, err := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Initialize educational platform
	platformConfig := &education.PlatformConfig{
		MaxConcurrentSessions:  100,
		SessionTimeout:         30 * time.Minute,
		EnableInteractiveLabs:  true,
		EnableAssessments:      true,
		EnableCertifications:   true,
		EnableProgressTracking: true,
		EnableGamification:     true,
		EnableCollaboration:    true,
		DefaultLanguage:        "en",
		SupportedLanguages:     []string{"en", "es", "fr", "de"},
	}

	platform := education.NewEducationalPlatform(platformConfig, logger)

	// Initialize handlers
	educationHandler := handlers.NewEducationHandler(platform, logger)

	// Setup router
	router := mux.NewRouter()

	// Register routes
	educationHandler.RegisterRoutes(router)

	// Add health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"education-api","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	}).Methods("GET")

	// Add CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:3001", "https://hackai.dev"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	handler := c.Handler(router)

	// Add logging middleware
	handler = loggingMiddleware(logger)(handler)

	// Add authentication middleware (simplified for demo)
	handler = authMiddleware(logger)(handler)

	// Setup server
	port := getEnv("PORT", "8081")
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.WithField("port", port).Info("Starting education API server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	}

	logger.Info("Server exited")
}

// loggingMiddleware logs HTTP requests
func loggingMiddleware(logger *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a response writer wrapper to capture status code
			wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapper, r)

			logger.WithFields(map[string]interface{}{
				"method":      r.Method,
				"path":        r.URL.Path,
				"status_code": wrapper.statusCode,
				"duration":    time.Since(start).String(),
				"remote_addr": r.RemoteAddr,
				"user_agent":  r.UserAgent(),
			}).Info("HTTP request")
		})
	}
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

// authMiddleware provides simple authentication (demo purposes)
func authMiddleware(logger *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health check and OPTIONS requests
			if r.URL.Path == "/health" || r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}

			// For demo purposes, we'll use a simple token-based auth
			// In production, this would validate JWT tokens, API keys, etc.
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				// For demo, allow requests without auth but set a default user
				ctx := context.WithValue(r.Context(), "user_id", "demo-user")
				ctx = context.WithValue(ctx, "user_role", "student")
				r = r.WithContext(ctx)
			} else {
				// Parse token and set user context
				// This is simplified - in production you'd validate the token
				userID := "authenticated-user"
				userRole := "student"

				if authHeader == "Bearer admin-token" {
					userID = "admin-user"
					userRole = "admin"
				}

				ctx := context.WithValue(r.Context(), "user_id", userID)
				ctx = context.WithValue(ctx, "user_role", userRole)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Environment variable helpers
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := fmt.Sscanf(value, "%d", &defaultValue); err == nil && intValue == 1 {
			return defaultValue
		}
	}
	return defaultValue
}

func init() {
	// Set default environment variables if not set
	if os.Getenv("LOG_LEVEL") == "" {
		os.Setenv("LOG_LEVEL", "info")
	}
	if os.Getenv("PORT") == "" {
		os.Setenv("PORT", "8080")
	}
	if os.Getenv("CORS_ORIGINS") == "" {
		os.Setenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:3001")
	}
}
