package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/pkg/config"
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

	log.Info("Starting HackAI Log Management Service", "version", "1.0.0")

	// Initialize observability
	obs, err := observability.NewProvider(&cfg.Observability, "hackai-log-service", "1.0.0", log)
	if err != nil {
		log.Fatal("Failed to initialize observability", "error", err)
	}
	defer obs.Shutdown(context.Background())

	// Initialize middleware
	loggingMiddleware := middleware.Logging(log)

	// Setup HTTP server
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"log-service","version":"1.0.0"}`))
	})

	// Metrics endpoint
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# Log service metrics\nlog_service_up 1\nlog_entries_processed_total 1000\n"))
	})

	// Log ingestion endpoints
	mux.HandleFunc("POST /api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"message":"Log entry created","id":"log-123","status":"accepted"}`))
	})

	mux.HandleFunc("POST /api/v1/logs/batch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"message":"Batch log entries created","count":50,"status":"accepted"}`))
	})

	// Log retrieval endpoints
	mux.HandleFunc("GET /api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"logs":[{"id":"log-123","timestamp":"2024-01-01T00:00:00Z","level":"info","message":"System started","service":"api-gateway"}],"total":1,"page":1}`))
	})

	mux.HandleFunc("GET /api/v1/logs/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"log-123","timestamp":"2024-01-01T00:00:00Z","level":"info","message":"System started","service":"api-gateway","metadata":{"user_id":"user-456"}}`))
	})

	// Log search endpoints
	mux.HandleFunc("GET /api/v1/logs/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"results":[{"id":"log-123","timestamp":"2024-01-01T00:00:00Z","level":"error","message":"Authentication failed","service":"user-service"}],"total":1,"query":"level:error"}`))
	})

	// Log analytics endpoints
	mux.HandleFunc("GET /api/v1/logs/analytics/summary", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"total_logs":10000,"error_count":150,"warning_count":500,"info_count":9350,"time_range":"24h"}`))
	})

	mux.HandleFunc("GET /api/v1/logs/analytics/trends", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"trends":[{"hour":"00:00","count":100},{"hour":"01:00","count":120},{"hour":"02:00","count":90}]}`))
	})

	// Log aggregation endpoints
	mux.HandleFunc("GET /api/v1/logs/aggregate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"aggregations":{"by_service":{"api-gateway":1000,"user-service":800,"scanner-service":600},"by_level":{"error":150,"warning":500,"info":9350}}}`))
	})

	// Log alerts endpoints
	mux.HandleFunc("GET /api/v1/logs/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"alerts":[{"id":"alert-123","rule":"high_error_rate","triggered_at":"2024-01-01T00:00:00Z","severity":"high","message":"Error rate exceeded threshold"}]}`))
	})

	mux.HandleFunc("POST /api/v1/logs/alerts/rules", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"message":"Alert rule created","id":"rule-456","status":"active"}`))
	})

	// Log export endpoints
	mux.HandleFunc("POST /api/v1/logs/export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"export_id":"export-789","status":"pending","message":"Log export initiated"}`))
	})

	mux.HandleFunc("GET /api/v1/logs/export/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"export-789","status":"completed","download_url":"/api/v1/logs/export/export-789/download","expires_at":"2024-01-02T00:00:00Z"}`))
	})

	// Log retention endpoints
	mux.HandleFunc("GET /api/v1/logs/retention", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"retention_policy":{"default_days":30,"error_logs_days":90,"audit_logs_days":365},"storage_usage":"2.5GB"}`))
	})

	mux.HandleFunc("POST /api/v1/logs/retention/cleanup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"message":"Log cleanup initiated","job_id":"cleanup-101","estimated_duration":"30m"}`))
	})

	// Apply middleware chain
	handler := loggingMiddleware(mux)

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8085"
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
		log.Info("Log management service starting", "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down log management service...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown server
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown", "error", err)
	}

	log.Info("Log management service stopped")
}
