package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"

	"github.com/dimajoyti/hackai/internal/handler"
	"github.com/dimajoyti/hackai/internal/repository"
	"github.com/dimajoyti/hackai/internal/usecase"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/middleware"
	"github.com/dimajoyti/hackai/pkg/observability"
	"github.com/dimajoyti/hackai/pkg/ollama"
)

var ollamaTracer = otel.Tracer("hackai/cmd/ollama-service")

const (
	contentTypeJSON   = "application/json"
	contentTypeHeader = "Content-Type"
)

func main() {
	_, span := ollamaTracer.Start(context.Background(), "ollama_service.main")
	defer span.End()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log, err := logger.New(logger.Config{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	log.Info("Starting HackAI OLLAMA Service", "version", "1.0.0")

	// Initialize observability
	obs, err := observability.NewProvider(&cfg.Observability, "hackai-ollama-service", "1.0.0", log)
	if err != nil {
		log.Error("Failed to initialize observability", "error", err)
		os.Exit(1)
	}
	defer obs.Shutdown(context.Background())

	// Initialize database
	db, err := database.New(&cfg.Database, log)
	if err != nil {
		log.Fatal("Failed to initialize database", "error", err)
	}
	defer db.Close()

	// Initialize repositories
	auditRepo := repository.NewAuditRepository(db.DB, log)

	// Initialize OLLAMA manager with default config
	ollamaConfig := &ollama.Config{
		BaseURL:           "http://localhost:11434",
		Timeout:           60 * time.Second,
		MaxRetries:        3,
		Models:            []string{"llama2", "codellama", "mistral"},
		DefaultModel:      "llama2",
		AutoPull:          false,
		EmbeddingModel:    "nomic-embed-text",
		MaxConcurrent:     10,
		HealthCheckPeriod: 30 * time.Second,
	}
	ollamaManager, err := ollama.NewManager(ollamaConfig, log)
	if err != nil {
		log.Fatal("Failed to initialize OLLAMA manager", "error", err)
	}

	// Initialize OLLAMA orchestrator
	orchestrator, err := ollama.NewOrchestrator(ollamaManager, log)
	if err != nil {
		log.Fatal("Failed to initialize OLLAMA orchestrator", "error", err)
	}

	// Initialize use cases
	modelManagementUC := usecase.NewModelManagementUseCase(ollamaManager, auditRepo, log)
	inferenceUC := usecase.NewInferenceUseCase(orchestrator, auditRepo, log)

	// Initialize handlers
	ollamaHandler := handler.NewOLLAMAHandler(modelManagementUC, inferenceUC, log)

	// Setup HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, "9089"), // OLLAMA service port
		Handler:      setupRoutes(cfg, log, ollamaHandler),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in goroutine
	go func() {
		log.Info("Starting OLLAMA service server", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down OLLAMA service...")

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error("Failed to shutdown gracefully", "error", err)
	}

	// Shutdown OLLAMA manager
	if err := ollamaManager.Shutdown(shutdownCtx); err != nil {
		log.Error("Failed to shutdown OLLAMA manager", "error", err)
	}

	log.Info("OLLAMA service stopped")
}

// setupRoutes configures all routes and middleware for the OLLAMA service
func setupRoutes(
	cfg *config.Config,
	log *logger.Logger,
	ollamaHandler *handler.OLLAMAHandler,
) http.Handler {
	router := mux.NewRouter()

	// Health check endpoints
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(contentTypeHeader, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"ollama","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	}).Methods("GET")

	router.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(contentTypeHeader, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready","service":"ollama","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	}).Methods("GET")

	// Metrics endpoint
	router.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(contentTypeHeader, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"service":"ollama","version":"1.0.0","uptime":"24h"}`))
	}).Methods("GET")

	// API routes
	api := router.PathPrefix("/api/v1").Subrouter()

	// Model management endpoints
	api.HandleFunc("/models", ollamaHandler.ListModels).Methods("GET")
	api.HandleFunc("/models", ollamaHandler.PullModel).Methods("POST")
	api.HandleFunc("/models/{model}", ollamaHandler.GetModel).Methods("GET")
	api.HandleFunc("/models/{model}", ollamaHandler.DeleteModel).Methods("DELETE")
	api.HandleFunc("/models/{model}/info", ollamaHandler.GetModelInfo).Methods("GET")

	// Model operations endpoints
	api.HandleFunc("/models/pull", ollamaHandler.PullModel).Methods("POST")
	api.HandleFunc("/models/push", ollamaHandler.PushModel).Methods("POST")
	api.HandleFunc("/models/create", ollamaHandler.CreateModel).Methods("POST")
	api.HandleFunc("/models/copy", ollamaHandler.CopyModel).Methods("POST")

	// Inference endpoints
	api.HandleFunc("/generate", ollamaHandler.Generate).Methods("POST")
	api.HandleFunc("/chat", ollamaHandler.Chat).Methods("POST")
	api.HandleFunc("/embeddings", ollamaHandler.Embeddings).Methods("POST")

	// Streaming endpoints
	api.HandleFunc("/generate/stream", ollamaHandler.GenerateStream).Methods("POST")
	api.HandleFunc("/chat/stream", ollamaHandler.ChatStream).Methods("POST")

	// Management endpoints
	api.HandleFunc("/status", ollamaHandler.GetStatus).Methods("GET")
	api.HandleFunc("/stats", ollamaHandler.GetStats).Methods("GET")
	api.HandleFunc("/config", ollamaHandler.GetConfig).Methods("GET")
	api.HandleFunc("/config", ollamaHandler.UpdateConfig).Methods("PUT")

	// Batch operations
	api.HandleFunc("/batch/generate", ollamaHandler.BatchGenerate).Methods("POST")
	api.HandleFunc("/batch/embeddings", ollamaHandler.BatchEmbeddings).Methods("POST")

	// Model presets and templates
	api.HandleFunc("/presets", ollamaHandler.ListPresets).Methods("GET")
	api.HandleFunc("/presets", ollamaHandler.CreatePreset).Methods("POST")
	api.HandleFunc("/presets/{preset}", ollamaHandler.GetPreset).Methods("GET")
	api.HandleFunc("/presets/{preset}", ollamaHandler.UpdatePreset).Methods("PUT")
	api.HandleFunc("/presets/{preset}", ollamaHandler.DeletePreset).Methods("DELETE")

	// Security and monitoring
	api.HandleFunc("/security/scan", ollamaHandler.SecurityScan).Methods("POST")
	api.HandleFunc("/monitoring/performance", ollamaHandler.GetPerformanceMetrics).Methods("GET")
	api.HandleFunc("/monitoring/usage", ollamaHandler.GetUsageMetrics).Methods("GET")

	// Apply global middleware
	var httpHandler http.Handler = router
	httpHandler = middleware.Recovery(log)(httpHandler)
	httpHandler = middleware.Logging(log)(httpHandler)
	httpHandler = middleware.RequestID(httpHandler)

	log.Info("OLLAMA service routes configured")
	return httpHandler
}
