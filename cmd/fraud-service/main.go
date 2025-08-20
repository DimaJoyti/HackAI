package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/pkg/fraud"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	// Create logger
	loggerConfig := logger.Config{
		Level:  logger.LevelInfo,
		Format: "json",
		Output: "stdout",
	}

	appLogger, err := logger.New(loggerConfig)
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}

	// Create fraud detection engine
	engineConfig := fraud.DefaultEngineConfig()
	engine, err := fraud.NewFraudDetectionEngine("fraud-engine-001", "HackAI Fraud Detection Engine", engineConfig, appLogger)
	if err != nil {
		appLogger.Error("Failed to create fraud detection engine", "error", err)
		os.Exit(1)
	}

	// Start the engine
	ctx := context.Background()
	if err := engine.Start(ctx); err != nil {
		appLogger.Error("Failed to start fraud detection engine", "error", err)
		os.Exit(1)
	}

	// Create HTTP handler
	handler := fraud.NewFraudDetectionHandler(engine, appLogger)

	// Create HTTP server
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Add CORS middleware for development
	corsHandler := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}

	server := &http.Server{
		Addr:    ":8080",
		Handler: corsHandler(mux),
	}

	// Start server in a goroutine
	go func() {
		appLogger.Info("Starting fraud detection service", "port", 8080)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	appLogger.Info("Shutting down fraud detection service...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		appLogger.Error("Server forced to shutdown", "error", err)
	}

	// Stop fraud detection engine
	if err := engine.Stop(); err != nil {
		appLogger.Error("Failed to stop fraud detection engine", "error", err)
	}

	appLogger.Info("Fraud detection service stopped")
}
