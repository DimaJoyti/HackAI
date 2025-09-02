package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/observability"
)

func main() {
	// Initialize logger
	logger, err := logger.New(logger.Config{
		Level:  logger.LogLevel(getEnv("LOG_LEVEL", "info")),
		Format: "json",
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	logger.Info("Starting Observability & Monitoring Stack")

	// Load configuration
	cfg := loadObservabilityConfig()

	// Initialize observability orchestrator
	serviceName := getEnv("SERVICE_NAME", "hackai-observability")
	serviceVersion := getEnv("SERVICE_VERSION", "1.0.0")

	orchestrator, err := observability.NewSimpleObservabilityOrchestrator(
		cfg,
		serviceName,
		serviceVersion,
		logger,
	)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create observability orchestrator")
	}

	// Start the orchestrator
	if err := orchestrator.Start(); err != nil {
		logger.WithError(err).Fatal("Failed to start observability orchestrator")
	}

	logger.Info("Observability & Monitoring Stack started successfully")
	logger.Info("Health check endpoint: http://localhost:8090/health")
	logger.Info("Metrics endpoint: http://localhost:8091/metrics")
	logger.Info("Dashboard endpoint: http://localhost:8092/api/dashboard")
	logger.Info("Profiler endpoint: http://localhost:8093/debug/pprof/")

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down Observability & Monitoring Stack...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := orchestrator.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Observability orchestrator forced to shutdown")
	}

	logger.Info("Observability & Monitoring Stack shutdown complete")
}

// loadObservabilityConfig loads observability configuration
func loadObservabilityConfig() *config.ObservabilityConfig {
	return &config.ObservabilityConfig{
		Enabled: true,
		Tracing: config.TracingConfig{
			Enabled:     true,
			ServiceName: getEnv("SERVICE_NAME", "hackai-observability"),
			Endpoint:    getEnv("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
			SampleRate:  0.1,
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Port:    fmt.Sprintf("%d", getEnvInt("METRICS_PORT", 8091)),
		},
		Logging: config.LoggingConfig{
			Enabled: true,
			Level:   getEnv("LOG_LEVEL", "info"),
			Format:  "json",
		},
		HealthCheck: config.HealthCheckConfig{
			Enabled:  true,
			Port:     getEnvInt("HEALTH_PORT", 8090),
			Endpoint: "/health",
		},
		Profiling: config.ProfilingConfig{
			Enabled: getBoolEnv("PROFILING_ENABLED", true),
			Port:    getEnvInt("PROFILING_PORT", 8093),
		},
		Alerting: config.ObservabilityAlertingConfig {
			Enabled:         getBoolEnv("ALERTING_ENABLED", true),
			WebhookURL:      getEnv("ALERT_WEBHOOK_URL", ""),
			EmailEnabled:    getBoolEnv("EMAIL_ALERTS_ENABLED", false),
			SlackEnabled:    getBoolEnv("SLACK_ALERTS_ENABLED", false),
			SlackWebhookURL: getEnv("SLACK_WEBHOOK_URL", ""),
		},
		Dashboard: config.DashboardConfig{
			Enabled: true,
			Port:    getEnvInt("DASHBOARD_PORT", 8092),
		},
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
		var intValue int
		if _, err := fmt.Sscanf(value, "%d", &intValue); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}
