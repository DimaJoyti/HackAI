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

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/health"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/redis"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	loggerInstance, err := logger.New(logger.Config{
		Level:          "info",
		Format:         "json",
		Output:         "stdout",
		ServiceName:    "hackai-infrastructure-test",
		ServiceVersion: "1.0.0",
		Environment:    cfg.Environment,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	loggerInstance.Info("Starting HackAI Infrastructure Test")

	// Initialize database
	db, err := database.New(&cfg.Database, loggerInstance)
	if err != nil {
		loggerInstance.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	loggerInstance.Info("Connected to database successfully")

	// Run database migrations
	if err := db.Migrate(); err != nil {
		loggerInstance.Fatalf("Failed to run database migrations: %v", err)
	}

	loggerInstance.Info("Database migrations completed successfully")

	// Initialize Redis
	redisClient, err := redis.New(&cfg.Redis, loggerInstance)
	if err != nil {
		loggerInstance.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisClient.Close()

	loggerInstance.Info("Connected to Redis successfully")

	// Test Redis functionality
	ctx := context.Background()
	testKey := "infrastructure-test"
	testValue := "Hello from HackAI!"
	
	if err := redisClient.Set(ctx, testKey, testValue, time.Minute).Err(); err != nil {
		loggerInstance.Errorf("Failed to set Redis key: %v", err)
	} else {
		loggerInstance.Info("Successfully set Redis key")
	}

	// Get the value back
	if val, err := redisClient.Get(ctx, testKey).Result(); err != nil {
		loggerInstance.Errorf("Failed to get Redis key: %v", err)
	} else {
		loggerInstance.Infof("Retrieved Redis value: %s", val)
	}

	// Initialize health check manager
	healthManager := health.NewManager(health.Config{
		Version:     "1.0.0",
		ServiceName: "hackai-infrastructure-test",
		Environment: cfg.Environment,
		Timeout:     30 * time.Second,
	}, loggerInstance)

	// Register health checkers
	healthManager.RegisterChecker(health.NewDatabaseChecker("database", db.DB))
	healthManager.RegisterChecker(health.NewRedisChecker("redis", redisClient))
	healthManager.RegisterChecker(health.NewMemoryChecker("memory", 1024, 0.8)) // 1GB max, 80% warning
	healthManager.RegisterChecker(health.NewDiskSpaceChecker("disk", "/", 0.8))  // 80% warning
	healthManager.RegisterChecker(health.NewHTTPChecker("external-api", "https://httpbin.org/status/200"))

	loggerInstance.Info("Registered health checkers")

	// Create HTTP server
	mux := http.NewServeMux()

	// Health check endpoints
	mux.HandleFunc("/health", healthManager.HTTPHandler())
	mux.HandleFunc("/health/ready", healthManager.ReadinessHandler())
	mux.HandleFunc("/health/live", healthManager.LivenessHandler())

	// Test endpoint
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		correlationID := r.Header.Get("X-Correlation-ID")
		if correlationID == "" {
			correlationID = fmt.Sprintf("test-%d", time.Now().UnixNano())
		}

		ctx := logger.WithCorrelationID(r.Context(), correlationID)
		ctx = logger.WithRequestID(ctx, fmt.Sprintf("req-%d", time.Now().UnixNano()))

		loggerInstance.WithContext(ctx).Info("Test endpoint called")

		// Test database query
		var count int64
		if err := db.DB.WithContext(ctx).Raw("SELECT COUNT(*) FROM schema_migrations").Scan(&count).Error; err != nil {
			loggerInstance.WithContext(ctx).Errorf("Database query failed: %v", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		// Test Redis operation
		testKey := fmt.Sprintf("test-%s", correlationID)
		if err := redisClient.Set(ctx, testKey, time.Now().String(), time.Minute).Err(); err != nil {
			loggerInstance.WithContext(ctx).Errorf("Redis operation failed: %v", err)
			http.Error(w, "Redis error", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"status":         "ok",
			"correlation_id": correlationID,
			"timestamp":      time.Now(),
			"database_migrations": count,
			"redis_test":     "success",
			"message":        "Infrastructure test successful",
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Correlation-ID", correlationID)
		
		loggerInstance.WithContext(ctx).WithFields(logger.Fields{
			"response": response,
		}).Info("Test endpoint response")

		fmt.Fprintf(w, `{
			"status": "%s",
			"correlation_id": "%s",
			"timestamp": "%s",
			"database_migrations": %d,
			"redis_test": "%s",
			"message": "%s"
		}`, 
			response["status"], 
			response["correlation_id"], 
			response["timestamp"], 
			response["database_migrations"], 
			response["redis_test"], 
			response["message"])
	})

	// Root endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"service": "hackai-infrastructure-test",
			"version": "1.0.0",
			"status": "running",
			"endpoints": {
				"/": "Service information",
				"/test": "Infrastructure test endpoint",
				"/health": "Comprehensive health check",
				"/health/ready": "Readiness check",
				"/health/live": "Liveness check"
			}
		}`)
	})

	// Create server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		loggerInstance.Infof("Starting HTTP server on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			loggerInstance.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Run initial health check
	loggerInstance.Info("Running initial health check...")
	healthResult := healthManager.Check(context.Background())
	loggerInstance.WithFields(logger.Fields{
		"overall_status": healthResult.Status,
		"checks_count":   len(healthResult.Checks),
		"duration_ms":    healthResult.Duration.Milliseconds(),
	}).Info("Initial health check completed")

	// Print service information
	loggerInstance.Info("=== HackAI Infrastructure Test Service ===")
	loggerInstance.Info("Service is running successfully!")
	loggerInstance.Info("Available endpoints:")
	loggerInstance.Info("  GET  /           - Service information")
	loggerInstance.Info("  GET  /test       - Infrastructure test")
	loggerInstance.Info("  GET  /health     - Health check")
	loggerInstance.Info("  GET  /health/ready - Readiness check")
	loggerInstance.Info("  GET  /health/live  - Liveness check")
	loggerInstance.Infof("Server listening on http://localhost%s", server.Addr)

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	loggerInstance.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		loggerInstance.Errorf("Server forced to shutdown: %v", err)
	}

	loggerInstance.Info("Server exited")
}
