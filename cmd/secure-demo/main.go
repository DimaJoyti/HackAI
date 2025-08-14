package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/middleware"
)

// SecureDemo demonstrates the comprehensive security framework
func main() {
	// Initialize logger
	logConfig := logger.Config{
		Level:  logger.LevelInfo,
		Format: "json",
		Output: "stdout",
	}
	log, err := logger.New(logConfig)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}

	log.Info("Starting HackAI Secure Demo Server")

	// Create secure web layer configuration
	secureConfig := middleware.DefaultSecureWebConfig()
	secureConfig.LogSecurityEvents = true
	secureConfig.EnableAgenticSecurity = true
	secureConfig.EnableAIFirewall = true
	secureConfig.EnableInputFiltering = true
	secureConfig.EnableOutputFiltering = true
	secureConfig.EnablePromptProtection = true

	// Initialize secure web layer
	secureLayer := middleware.NewSecureWebLayer(secureConfig, log)

	// Create HTTP server with security middleware
	mux := http.NewServeMux()

	// Add demo endpoints
	setupDemoEndpoints(mux, log)

	// Apply security middleware
	var handler http.Handler = mux
	handler = secureLayer.SecureMiddleware()(handler)
	handler = middleware.Recovery(log)(handler)
	handler = middleware.Logging(log)(handler)
	handler = middleware.RequestID(handler)

	// Create server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.WithField("addr", server.Addr).Info("Starting secure demo server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.WithError(err).Error("Server forced to shutdown")
	}

	log.Info("Server exited")
}

// setupDemoEndpoints sets up demonstration endpoints
func setupDemoEndpoints(mux *http.ServeMux, log *logger.Logger) {
	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// AI chat endpoint (protected by prompt injection guard)
	mux.HandleFunc("/api/v1/ai/chat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			Message string `json:"message"`
			UserID  string `json:"user_id"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Simulate AI response
		response := map[string]interface{}{
			"response":  fmt.Sprintf("AI Response to: %s", request.Message),
			"user_id":   request.UserID,
			"timestamp": time.Now().UTC(),
			"model":     "secure-ai-v1",
			"filtered":  true,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Data submission endpoint (protected by input filtering)
	mux.HandleFunc("/api/v1/data/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			Data     string            `json:"data"`
			Metadata map[string]string `json:"metadata"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		response := map[string]interface{}{
			"status":    "processed",
			"data_size": len(request.Data),
			"timestamp": time.Now().UTC(),
			"processed": true,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Security metrics endpoint
	mux.HandleFunc("/api/v1/security/metrics", func(w http.ResponseWriter, r *http.Request) {
		// This would return real security metrics in production
		metrics := map[string]interface{}{
			"total_requests":     1000,
			"blocked_requests":   25,
			"threats_detected":   15,
			"prompt_injections":  5,
			"input_violations":   10,
			"average_risk_score": 0.15,
			"last_updated":       time.Now().UTC(),
			"uptime":             "24h",
			"security_level":     "high",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics)
	})

	// Test endpoint for security testing
	mux.HandleFunc("/api/v1/test/security", func(w http.ResponseWriter, r *http.Request) {
		testType := r.URL.Query().Get("type")

		var response map[string]interface{}

		switch testType {
		case "sql_injection":
			response = map[string]interface{}{
				"test_type": "sql_injection",
				"message":   "This endpoint tests SQL injection protection",
				"safe":      true,
			}
		case "xss":
			response = map[string]interface{}{
				"test_type": "xss",
				"message":   "This endpoint tests XSS protection",
				"safe":      true,
			}
		case "prompt_injection":
			response = map[string]interface{}{
				"test_type": "prompt_injection",
				"message":   "This endpoint tests prompt injection protection",
				"safe":      true,
			}
		default:
			response = map[string]interface{}{
				"available_tests": []string{"sql_injection", "xss", "prompt_injection"},
				"usage":           "Add ?type=<test_type> to test specific security features",
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// File upload endpoint (protected by file type validation)
	mux.HandleFunc("/api/v1/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse multipart form
		err := r.ParseMultipartForm(10 << 20) // 10 MB max
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "No file provided", http.StatusBadRequest)
			return
		}
		defer file.Close()

		response := map[string]interface{}{
			"filename":  header.Filename,
			"size":      header.Size,
			"status":    "uploaded",
			"timestamp": time.Now().UTC(),
			"safe":      true,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Admin endpoint (requires high-level authentication)
	mux.HandleFunc("/api/v1/admin/config", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]interface{}{
			"security_level":        "maximum",
			"ai_firewall_enabled":   true,
			"prompt_guard_enabled":  true,
			"input_filter_enabled":  true,
			"output_filter_enabled": true,
			"threat_detection":      "active",
			"auto_block_enabled":    true,
			"learning_mode":         true,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	})

	log.Info("Demo endpoints configured")
	log.Info("Available endpoints:")
	log.Info("  GET  /health - Health check")
	log.Info("  POST /api/v1/ai/chat - AI chat with prompt protection")
	log.Info("  POST /api/v1/data/submit - Data submission with input filtering")
	log.Info("  GET  /api/v1/security/metrics - Security metrics")
	log.Info("  GET  /api/v1/test/security - Security testing")
	log.Info("  POST /api/v1/upload - File upload")
	log.Info("  GET  /api/v1/admin/config - Admin configuration")
}
