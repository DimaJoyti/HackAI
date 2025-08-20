package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/middleware"
)

func main() {
	// Create logger
	appLogger, err := logger.New(logger.Config{
		Level:  "info",
		Output: "stdout",
	})
	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}

	// Create secure web layer configuration
	config := middleware.DefaultSecureWebConfig()

	// Customize configuration for production
	config.BlockThreshold = 0.8
	config.AlertThreshold = 0.6
	config.MaxRequestSize = 5 * 1024 * 1024 // 5MB
	config.RequestTimeout = 30 * time.Second
	config.StrictMode = false

	// Configure alerting (optional)
	config.EnableAlerting = true
	config.AlertConfig.EnableSlack = false
	config.AlertConfig.EnableEmail = false
	config.AlertConfig.EnableWebhook = false

	// Configure metrics export (optional)
	config.EnableMetricsExport = true
	config.MetricsConfig.EnablePrometheus = true
	config.MetricsConfig.PrometheusPort = 9090
	config.MetricsConfig.ExportInterval = 30 * time.Second

	// Create secure web layer
	secureLayer := middleware.NewSecureWebLayer(config, appLogger)

	// Create HTTP server with secure middleware
	mux := http.NewServeMux()

	// Add routes
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/api/data", dataHandler)
	mux.HandleFunc("/api/search", searchHandler)
	mux.HandleFunc("/api/upload", uploadHandler)
	mux.HandleFunc("/health", healthHandler(secureLayer))
	mux.HandleFunc("/metrics", metricsHandler(secureLayer))
	mux.HandleFunc("/security/events", securityEventsHandler(secureLayer))

	// Wrap with security middleware
	secureHandler := secureLayer.SecureMiddleware()(mux)

	// Add request ID middleware
	finalHandler := middleware.RequestIDMiddleware()(secureHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      finalHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		appLogger.Info("Starting secure web server on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.WithError(err).Fatal("Server failed to start")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	appLogger.Info("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown server
	if err := server.Shutdown(ctx); err != nil {
		appLogger.WithError(err).Fatal("Server forced to shutdown")
	}

	appLogger.Info("Server exited")
}

// homeHandler handles the home page
func homeHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message":   "Welcome to the Secure Web Server",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// dataHandler handles data requests
func dataHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		response := map[string]interface{}{
			"data":  []string{"item1", "item2", "item3"},
			"count": 3,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	case http.MethodPost:
		var requestData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		response := map[string]interface{}{
			"message": "Data received successfully",
			"data":    requestData,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// searchHandler handles search requests (vulnerable to SQL injection for testing)
func searchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var searchRequest struct {
		Query string `json:"query"`
	}

	if err := json.NewDecoder(r.Body).Decode(&searchRequest); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// This would normally be vulnerable to SQL injection
	// but the security layer should catch it
	response := map[string]interface{}{
		"query":   searchRequest.Query,
		"results": []string{"result1", "result2"},
		"message": "Search completed successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// uploadHandler handles file uploads
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// The security layer will check request size limits
	response := map[string]interface{}{
		"message":  "Upload endpoint - size limits enforced by security layer",
		"max_size": "5MB",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// healthHandler returns health status
func healthHandler(secureLayer *middleware.SecureWebLayer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		healthStatus := secureLayer.GetHealthStatus()

		w.Header().Set("Content-Type", "application/json")
		if healthStatus.Overall == "healthy" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(healthStatus)
	}
}

// metricsHandler returns security metrics
func metricsHandler(secureLayer *middleware.SecureWebLayer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics := secureLayer.GetSecurityMetrics()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics)
	}
}

// securityEventsHandler returns recent security events
func securityEventsHandler(secureLayer *middleware.SecureWebLayer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events := secureLayer.GetSecurityEvents(50) // Last 50 events

		response := map[string]interface{}{
			"events": events,
			"count":  len(events),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
