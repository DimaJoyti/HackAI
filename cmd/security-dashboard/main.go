package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
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

	logger.Info("Starting Security Dashboard & Monitoring System")

	// Initialize security metrics collector
	metricsConfig := &security.MetricsConfig{
		Enabled:               true,
		CollectionInterval:    30 * time.Second,
		RetentionPeriod:       24 * time.Hour,
		PrometheusEnabled:     true,
		PrometheusNamespace:   "security",
		BufferSize:            1000,
		ExportInterval:        60 * time.Second,
		HealthCheckInterval:   30 * time.Second,
		EnableDetailedMetrics: true,
	}

	metricsCollector := security.NewSecurityMetricsCollector(metricsConfig, logger)

	// Initialize security alert manager
	alertConfig := &security.AlertingConfig{
		Enabled:              true,
		MaxActiveAlerts:      1000,
		AlertRetentionPeriod: 7 * 24 * time.Hour,
		EvaluationInterval:   10 * time.Second,
		BufferSize:           500,
		Channels:             []*security.ChannelConfig{},
		Rules:                []*security.AlertRuleConfig{},
		Escalations:          []*security.EscalationConfig{},
		Suppressions:         []*security.SuppressionConfig{},
	}

	alertManager := security.NewSecurityAlertManager(alertConfig, logger)

	// Initialize threat intelligence engine
	threatIntelConfig := &security.ThreatIntelligenceConfig{
		Enabled:                true,
		UpdateInterval:         24 * time.Hour,
		CacheTimeout:           1 * time.Hour,
		MaxCacheSize:           10000,
		// EnableReputationScoring: true, // Field doesn't exist
		// EnableAutoBlocking:     false, // Field doesn't exist
		IOCTypes:               []string{"ip", "domain", "hash"},
		Sources:                []string{"internal"},
		APIKeys:                make(map[string]string),
	}

	threatIntelEngine := security.NewThreatIntelligenceEngine(threatIntelConfig, logger)

	// Initialize dashboard service
	_ = &security.DashboardConfig{ // dashboardConfig not used
		Enabled:              true,
		Port:                 getEnvInt("DASHBOARD_PORT", 8083),
		UpdateInterval:       10 * time.Second,
		MaxRecentThreats:     50,
		EnableWebSocket:      true,
		EnableRealTimeAlerts: true,
		ThreatRetentionTime:  24 * time.Hour,
		MetricsRetentionTime: 7 * 24 * time.Hour,
	}

	// Create security monitor instead of dashboard service
	monitoringConfig := &security.MonitoringConfig{
		Enabled:         true,
		UpdateInterval:  10 * time.Second,
		RetentionPeriod: 24 * time.Hour,
		EnableWebSocket: true,
		// Port:            getEnvInt("DASHBOARD_PORT", 8083), // Field doesn't exist in MonitoringConfig
	}

	securityMonitor := security.NewSecurityMonitor(
		metricsCollector,
		alertManager,
		monitoringConfig,
		logger,
	)

	// Initialize incident response system
	incidentConfig := &security.IncidentResponseConfig{
		Enabled:               true,
		AutoResponseEnabled:   true,
		EscalationEnabled:     true,
		MaxActiveIncidents:    100,
		IncidentRetentionTime: 30 * 24 * time.Hour,
		ResponseTimeout:       5 * time.Minute,
		EscalationThreshold:   30 * time.Minute,
		CriticalResponseTime:  5 * time.Minute,
	}

	incidentSystem := security.NewIncidentResponseSystem(
		incidentConfig,
		logger,
		nil, // securityMonitor type mismatch - would need proper DashboardService
		alertManager,
	)

	// Initialize security analytics engine
	analyticsConfig := &security.AnalyticsConfig{
		Enabled:                  true,
		AnalysisInterval:         5 * time.Minute,
		TrendAnalysisWindow:      24 * time.Hour,
		RiskAssessmentInterval:   6 * time.Hour,
		ComplianceReporting:      true,
		PerformanceTracking:      true,
		DataRetentionPeriod:      30 * 24 * time.Hour,
		EnablePredictiveAnalysis: true,
	}

	analyticsEngine := security.NewSecurityAnalyticsEngine(
		analyticsConfig,
		logger,
		metricsCollector,
		incidentSystem,
	)

	// Start all services
	logger.Info("Starting security services...")

	if err := metricsCollector.Start(); err != nil {
		logger.WithError(err).Fatal("Failed to start metrics collector")
	}

	if err := alertManager.Start(); err != nil {
		logger.WithError(err).Fatal("Failed to start alert manager")
	}

	if err := threatIntelEngine.Start(); err != nil {
		logger.WithError(err).Fatal("Failed to start threat intelligence engine")
	}

	if err := incidentSystem.Start(); err != nil {
		logger.WithError(err).Fatal("Failed to start incident response system")
	}

	if err := analyticsEngine.Start(); err != nil {
		logger.WithError(err).Fatal("Failed to start analytics engine")
	}

	if err := securityMonitor.Start(); err != nil {
		logger.WithError(err).Fatal("Failed to start security monitor")
	}

	// Setup main HTTP server for additional endpoints
	router := mux.NewRouter()

	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{
			"status": "healthy",
			"service": "security-dashboard",
			"timestamp": "%s",
			"version": "1.0.0"
		}`, time.Now().Format(time.RFC3339))))
	}).Methods("GET")

	// Metrics endpoint
	router.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		metrics := metricsCollector.GetMetrics()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := map[string]interface{}{
			"metrics":   metrics,
			"timestamp": time.Now(),
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger.WithError(err).Error("Failed to encode metrics response")
		}
	}).Methods("GET")

	// Analytics endpoint
	router.HandleFunc("/analytics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := map[string]interface{}{
			"threat_trends":       analyticsEngine.GetThreatTrends(),
			"risk_assessments":    analyticsEngine.GetRiskAssessments(),
			"compliance_data":     analyticsEngine.GetComplianceData(),
			"performance_metrics": analyticsEngine.GetPerformanceMetrics(),
			"timestamp":           time.Now(),
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger.WithError(err).Error("Failed to encode analytics response")
		}
	}).Methods("GET")

	// Incidents endpoint
	router.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
		incidents := incidentSystem.GetActiveIncidents()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := map[string]interface{}{
			"active_incidents": incidents,
			"total_count":      len(incidents),
			"timestamp":        time.Now(),
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger.WithError(err).Error("Failed to encode incidents response")
		}
	}).Methods("GET")

	// Add CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:3001", "https://hackai.dev"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	handler := c.Handler(router)

	// Add logging middleware
	handler = loggingMiddleware(logger)(handler)

	// Setup main server
	mainPort := getEnvInt("PORT", 8084)
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", mainPort),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start main server in a goroutine
	go func() {
		logger.WithField("port", mainPort).Info("Starting main security dashboard server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start main server")
		}
	}()

	logger.Info("Security Dashboard & Monitoring System started successfully")
	logger.Info("Dashboard available at: http://localhost:3000/security/dashboard")
	logger.Info("API endpoints available at: http://localhost:8084")
	logger.Info("Real-time dashboard API at: http://localhost:8083")

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down Security Dashboard & Monitoring System...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop all services
	analyticsEngine.Stop()
	incidentSystem.Stop()
	// dashboardService.Stop() // dashboardService not defined
	// threatDetector.Stop() // threatDetector not defined
	alertManager.Stop()
	metricsCollector.Stop()

	// Attempt graceful shutdown of main server
	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Main server forced to shutdown")
	}

	logger.Info("Security Dashboard & Monitoring System shutdown complete")
}

// loggingMiddleware logs HTTP requests
func loggingMiddleware(logger *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a response writer wrapper to capture status code
			wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapper, r)

			logger.WithFields(map[string]interface{}{
				"method":      r.Method,
				"path":        r.URL.Path,
				"status_code": wrapper.statusCode,
				"duration":    time.Since(start).String(),
				"remote_addr": r.RemoteAddr,
				"user_agent":  r.UserAgent(),
			}).Info("HTTP request")
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
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
