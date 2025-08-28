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

	log.Info("Starting HackAI Threat Intelligence Service", "version", "1.0.0")

	// Initialize observability
	obs, err := observability.NewProvider(&cfg.Observability, "hackai-threat-service", "1.0.0", log)
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
		w.Write([]byte(`{"status":"healthy","service":"threat-service","version":"1.0.0"}`))
	})

	// Metrics endpoint
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# Threat service metrics\nthreat_service_up 1\n"))
	})

	// Threat intelligence endpoints
	mux.HandleFunc("GET /api/v1/threats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"threats":[{"id":"threat-123","type":"malware","severity":"high","description":"Suspicious activity detected"}]}`))
	})

	mux.HandleFunc("GET /api/v1/threats/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"threat-123","type":"malware","severity":"high","description":"Suspicious activity detected","indicators":["192.168.1.100","malware.exe"]}`))
	})

	// Threat analysis endpoints
	mux.HandleFunc("POST /api/v1/threats/analyze", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"analysis_id":"analysis-456","status":"pending","message":"Threat analysis initiated"}`))
	})

	mux.HandleFunc("GET /api/v1/threats/analyze/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"analysis-456","status":"completed","risk_score":85,"threats_found":3}`))
	})

	// IOC (Indicators of Compromise) endpoints
	mux.HandleFunc("GET /api/v1/ioc", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"indicators":[{"type":"ip","value":"192.168.1.100","threat_level":"high"},{"type":"hash","value":"abc123","threat_level":"medium"}]}`))
	})

	mux.HandleFunc("POST /api/v1/ioc/check", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"indicator":"192.168.1.100","is_malicious":true,"threat_level":"high","sources":["threat_feed_1","threat_feed_2"]}`))
	})

	// Threat feeds endpoints
	mux.HandleFunc("GET /api/v1/threat-feeds", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"feeds":[{"name":"malware_feed","status":"active","last_updated":"2024-01-01T00:00:00Z"}]}`))
	})

	mux.HandleFunc("POST /api/v1/threat-feeds/update", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Threat feeds update initiated","status":"pending"}`))
	})

	// Threat hunting endpoints
	mux.HandleFunc("POST /api/v1/hunt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"hunt_id":"hunt-789","status":"pending","message":"Threat hunting session initiated"}`))
	})

	mux.HandleFunc("GET /api/v1/hunt/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"hunt-789","status":"completed","findings":5,"suspicious_activities":2}`))
	})

	// Risk assessment endpoints
	mux.HandleFunc("POST /api/v1/risk/assess", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"assessment_id":"risk-101","status":"pending","message":"Risk assessment initiated"}`))
	})

	mux.HandleFunc("GET /api/v1/risk/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"risk-101","overall_score":75,"critical_issues":2,"high_issues":5,"medium_issues":10}`))
	})

	// Apply middleware chain
	handler := loggingMiddleware(mux)

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8084"
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
		log.Info("Threat intelligence service starting", "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down threat intelligence service...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown server
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown", "error", err)
	}

	log.Info("Threat intelligence service stopped")
}
