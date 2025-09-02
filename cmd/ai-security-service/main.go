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
	"github.com/dimajoyti/hackai/internal/usecase"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/observability"
	"go.opentelemetry.io/otel"
)

var tracer = otel.Tracer("hackai/cmd/ai-security-service")

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

	log.Info("Starting HackAI AI Security Service", "version", "1.0.0")

	// Initialize observability
	obs, err := observability.NewProvider(&cfg.Observability, "hackai-ai-security-service", "1.0.0", log)
	if err != nil {
		log.Error("Failed to initialize observability", "error", err)
		os.Exit(1)
	}
	defer obs.Shutdown(context.Background())

	// Initialize database
	db, err := database.New(&cfg.Database, log)
	if err != nil {
		log.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}

	// Initialize repositories
	securityRepo := repository.NewLLMSecurityRepository(db.DB, log)
	auditRepo := repository.NewAuditRepository(db.DB, log)

	// Initialize AI Security Framework
	aiSecurityConfig := &usecase.AISecurityConfig{
		EnableMITREATLAS:         true,
		EnableOWASPAITop10:       true,
		EnablePromptInjection:    true,
		EnableThreatDetection:    true,
		EnableContentFiltering:   true,
		EnablePolicyEngine:       true,
		EnableRateLimiting:       true,
		EnableAIFirewall:         true,
		EnableThreatIntelligence: true,
		RealTimeMonitoring:       true,
		AutoMitigation:           false, // Set to false for safety in production
		ThreatThreshold:          0.7,
		ScanInterval:             5 * time.Minute,
		LogDetailedAnalysis:      true,
		EnableContinuousLearning: true,
		MaxConcurrentScans:       10,
		AlertingEnabled:          true,
		ComplianceReporting:      true,
	}

	aiSecurityFramework, err := usecase.NewAISecurityFramework(
		log,
		securityRepo,
		auditRepo,
		aiSecurityConfig,
	)
	if err != nil {
		log.Error("Failed to initialize AI Security Framework", "error", err)
		os.Exit(1)
	}

	// Initialize handlers
	aiSecurityHandler := handler.NewAISecurityFrameworkHandler(log, aiSecurityFramework)

	// Setup HTTP server
	mux := http.NewServeMux()

	// Register routes
	aiSecurityHandler.RegisterRoutes(mux)

	// Add health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","service":"ai-security-service","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
	})

	// Add readiness check endpoint
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ready","service":"ai-security-service","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
	})

	// Apply middleware chain
	var handler http.Handler = mux

	// Configure server
	port := os.Getenv("PORT")
	if port == "" {
		port = "9086" // Default port for AI Security Service
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Info("AI Security Service starting", "port", port)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("AI Security Service shutting down...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("Failed to gracefully shutdown server", "error", err)
	}

	log.Info("AI Security Service stopped")
}
