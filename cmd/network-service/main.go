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

	log.Info("Starting HackAI Network Service", "version", "1.0.0")

	// Initialize observability
	obs, err := observability.NewProvider(&cfg.Observability, "hackai-network-service", "1.0.0", log)
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
		w.Write([]byte(`{"status":"healthy","service":"network-service","version":"1.0.0"}`))
	})

	// Metrics endpoint
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# Network service metrics\nnetwork_service_up 1\n"))
	})

	// Network scanning endpoints
	mux.HandleFunc("POST /api/v1/network/scan", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Network scan initiated","status":"pending"}`))
	})

	mux.HandleFunc("GET /api/v1/network/scan/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"scan-123","status":"completed","results":{"hosts_found":5,"vulnerabilities":2}}`))
	})

	mux.HandleFunc("GET /api/v1/network/scans", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"scans":[{"id":"scan-123","status":"completed","created_at":"2024-01-01T00:00:00Z"}]}`))
	})

	// Port scanning endpoints
	mux.HandleFunc("POST /api/v1/network/port-scan", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Port scan initiated","status":"pending"}`))
	})

	// Network discovery endpoints
	mux.HandleFunc("POST /api/v1/network/discover", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Network discovery initiated","status":"pending"}`))
	})

	// Vulnerability assessment endpoints
	mux.HandleFunc("POST /api/v1/network/vulnerability-scan", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Vulnerability scan initiated","status":"pending"}`))
	})

	// Network monitoring endpoints
	mux.HandleFunc("GET /api/v1/network/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"network_status":"healthy","active_scans":2,"total_hosts":15}`))
	})

	// Apply middleware chain
	handler := loggingMiddleware(mux)

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8083"
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
		log.Info("Network service starting", "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down network service...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown server
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown", "error", err)
	}

	log.Info("Network service stopped")
}
