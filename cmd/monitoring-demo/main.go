package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/monitoring"
	"github.com/dimajoyti/hackai/pkg/observability"
	"github.com/google/uuid"
)

func main() {
	// Initialize logger
	logger := logger.NewDefault()
	logger.Info("Starting Comprehensive Monitoring and Observability Demo")

	fmt.Println("📊 Comprehensive Monitoring and Observability Demo")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("Demonstrating enterprise-grade monitoring capabilities")
	fmt.Println()

	ctx := context.Background()

	// Initialize observability provider
	observabilityConfig := &config.ObservabilityConfig{
		Tracing: config.TracingConfig{
			Enabled:    true,
			Endpoint:   "", // Use stdout for demo
			SampleRate: 1.0,
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Port:    "9090",
			Path:    "/metrics",
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "console",
		},
	}

	serviceName := "monitoring-demo"
	serviceVersion := "1.0.0"
	observabilityProvider, err := observability.NewProvider(observabilityConfig, serviceName, serviceVersion, logger)
	if err != nil {
		log.Fatalf("Failed to create observability provider: %v", err)
	}

	// Create monitoring configuration
	monitoringConfig := &monitoring.MonitoringConfig{
		SystemID:                    "demo-system-001",
		EnableHealthChecks:          true,
		EnableAlerting:              true,
		EnableMetrics:               true,
		EnablePerformanceMonitoring: true,
		EnableSystemMonitoring:      true,
		EnableDashboards:            true,
		EnableReporting:             true,
		HealthCheckInterval:         10 * time.Second,
		MetricsInterval:             5 * time.Second,
		AlertingInterval:            3 * time.Second,
		ReportingInterval:           30 * time.Second,
		RetentionPeriod:             24 * time.Hour,
		MaxMetricsHistory:           1000,
		MaxAlertsHistory:            100,
		AlertChannels:               []string{"console", "email"},
		DashboardRefreshRate:        5 * time.Second,
	}

	// Create monitoring system
	monitoringSystem, err := monitoring.NewMonitoringSystem(
		"demo-monitoring",
		"Demo Monitoring System",
		monitoringConfig,
		observabilityProvider,
		logger,
	)
	if err != nil {
		log.Fatalf("Failed to create monitoring system: %v", err)
	}

	// Demo 1: Health Checks
	fmt.Println("🏥 Demo 1: Health Checks and System Health Monitoring")
	fmt.Println(strings.Repeat("-", 60))

	// Register health checks
	healthChecks := []*monitoring.HealthCheck{
		{
			ID:             "http-api",
			Name:           "HTTP API Health",
			Type:           monitoring.HealthCheckTypeHTTP,
			Target:         "http://localhost:8080/health",
			Interval:       15 * time.Second,
			Timeout:        5 * time.Second,
			RetryCount:     3,
			Enabled:        true,
			Critical:       true,
			ExpectedStatus: 200,
		},
		{
			ID:       "database-connection",
			Name:     "Database Connection",
			Type:     monitoring.HealthCheckTypeDatabase,
			Target:   "postgresql://localhost:5432/demo",
			Interval: 30 * time.Second,
			Timeout:  10 * time.Second,
			Enabled:  true,
			Critical: true,
		},
		{
			ID:       "redis-cache",
			Name:     "Redis Cache",
			Type:     monitoring.HealthCheckTypeRedis,
			Target:   "redis://localhost:6379",
			Interval: 20 * time.Second,
			Timeout:  5 * time.Second,
			Enabled:  true,
			Critical: false,
		},
		{
			ID:       "system-memory",
			Name:     "System Memory Usage",
			Type:     monitoring.HealthCheckTypeMemory,
			Target:   "localhost",
			Interval: 30 * time.Second,
			Timeout:  5 * time.Second,
			Enabled:  true,
			Critical: true,
		},
	}

	// Note: In a real implementation, you would register these health checks
	// For demo purposes, we'll simulate the health check results
	fmt.Printf("✅ Registered %d health checks\n", len(healthChecks))
	for _, check := range healthChecks {
		fmt.Printf("   - %s (%s) - Critical: %v\n", check.Name, check.Type, check.Critical)
	}

	// Simulate health check results
	fmt.Println("\n🔍 Health Check Results:")
	healthResults := map[string]string{
		"http-api":            "✅ Healthy (200ms)",
		"database-connection": "✅ Healthy (45ms)",
		"redis-cache":         "⚠️  Degraded (timeout)",
		"system-memory":       "✅ Healthy (85% usage)",
	}

	for name, result := range healthResults {
		fmt.Printf("   %s: %s\n", name, result)
	}

	fmt.Println()

	// Demo 2: Alerting System
	fmt.Println("🚨 Demo 2: Intelligent Alerting System")
	fmt.Println(strings.Repeat("-", 60))

	// Create sample alert rules
	alertRules := []*monitoring.AlertRule{
		{
			ID:                   "high-cpu-usage",
			Name:                 "High CPU Usage",
			Description:          "CPU usage exceeds 80% for more than 5 minutes",
			Severity:             monitoring.SeverityCritical,
			Source:               "system-monitor",
			Component:            "cpu",
			Metric:               "cpu_usage_percent",
			Condition:            monitoring.ConditionGreaterThan,
			Threshold:            80.0,
			Duration:             5 * time.Minute,
			NotificationChannels: []string{"email", "slack"},
			Enabled:              true,
		},
		{
			ID:                   "high-error-rate",
			Name:                 "High Error Rate",
			Description:          "HTTP error rate exceeds 5% for more than 2 minutes",
			Severity:             monitoring.SeverityHigh,
			Source:               "performance-monitor",
			Component:            "http",
			Metric:               "http_error_rate",
			Condition:            monitoring.ConditionGreaterThan,
			Threshold:            0.05,
			Duration:             2 * time.Minute,
			NotificationChannels: []string{"email"},
			Enabled:              true,
		},
		{
			ID:                   "low-disk-space",
			Name:                 "Low Disk Space",
			Description:          "Disk usage exceeds 90%",
			Severity:             monitoring.SeverityMedium,
			Source:               "system-monitor",
			Component:            "disk",
			Metric:               "disk_usage_percent",
			Condition:            monitoring.ConditionGreaterThan,
			Threshold:            90.0,
			Duration:             time.Minute,
			NotificationChannels: []string{"email"},
			Enabled:              true,
		},
	}

	fmt.Printf("✅ Configured %d alert rules\n", len(alertRules))
	for _, rule := range alertRules {
		fmt.Printf("   - %s (%s) - Threshold: %.1f\n", rule.Name, rule.Severity, rule.Threshold)
	}

	// Simulate active alerts
	fmt.Println("\n🔥 Active Alerts:")
	activeAlerts := []*monitoring.Alert{
		{
			ID:          uuid.New().String(),
			RuleID:      "high-cpu-usage",
			Name:        "High CPU Usage",
			Severity:    monitoring.SeverityCritical,
			Status:      monitoring.StatusFiring,
			Component:   "web-server-01",
			Value:       85.2,
			Threshold:   80.0,
			FiredAt:     time.Now().Add(-10 * time.Minute),
			NotifyCount: 3,
		},
		{
			ID:          uuid.New().String(),
			RuleID:      "low-disk-space",
			Name:        "Low Disk Space",
			Severity:    monitoring.SeverityMedium,
			Status:      monitoring.StatusFiring,
			Component:   "database-server",
			Value:       92.5,
			Threshold:   90.0,
			FiredAt:     time.Now().Add(-5 * time.Minute),
			NotifyCount: 1,
		},
	}

	for _, alert := range activeAlerts {
		fmt.Printf("   🚨 %s - %s (%.1f > %.1f) - Fired: %s ago\n",
			alert.Severity,
			alert.Name,
			alert.Value,
			alert.Threshold,
			time.Since(alert.FiredAt).Round(time.Minute))
	}

	fmt.Println()

	// Demo 3: Performance Monitoring
	fmt.Println("⚡ Demo 3: Performance Monitoring and Analytics")
	fmt.Println(strings.Repeat("-", 60))

	// Simulate performance metrics
	performanceMetrics := &monitoring.PerformanceMetrics{
		RequestsPerSecond:     1250.5,
		AverageResponseTime:   85 * time.Millisecond,
		P95ResponseTime:       150 * time.Millisecond,
		P99ResponseTime:       300 * time.Millisecond,
		ErrorRate:             0.025, // 2.5%
		ThroughputMBPS:        45.2,
		ConcurrentConnections: 342,
		QueueDepth:            12,
		ResourceUtilization: map[string]float64{
			"cpu":     75.5,
			"memory":  68.2,
			"disk":    45.8,
			"network": 32.1,
		},
	}

	fmt.Printf("✅ Performance Metrics:\n")
	fmt.Printf("   Requests/sec: %.1f\n", performanceMetrics.RequestsPerSecond)
	fmt.Printf("   Avg Response Time: %v\n", performanceMetrics.AverageResponseTime)
	fmt.Printf("   P95 Response Time: %v\n", performanceMetrics.P95ResponseTime)
	fmt.Printf("   P99 Response Time: %v\n", performanceMetrics.P99ResponseTime)
	fmt.Printf("   Error Rate: %.2f%%\n", performanceMetrics.ErrorRate*100)
	fmt.Printf("   Throughput: %.1f MB/s\n", performanceMetrics.ThroughputMBPS)
	fmt.Printf("   Concurrent Connections: %d\n", performanceMetrics.ConcurrentConnections)

	fmt.Printf("\n📊 Resource Utilization:\n")
	for resource, usage := range performanceMetrics.ResourceUtilization {
		fmt.Printf("   %s: %.1f%%\n", toTitleCase(resource), usage)
	}

	fmt.Println()

	// Demo 4: System Monitoring
	fmt.Println("🖥️  Demo 4: System-Level Monitoring")
	fmt.Println(strings.Repeat("-", 60))

	// Simulate system metrics
	systemMetrics := &monitoring.SystemMetrics{
		CPUUsagePercent:     75.5,
		MemoryUsagePercent:  68.2,
		DiskUsagePercent:    45.8,
		NetworkInMBPS:       12.5,
		NetworkOutMBPS:      8.3,
		LoadAverage:         []float64{1.2, 1.5, 1.8},
		ProcessCount:        156,
		ThreadCount:         892,
		FileDescriptorCount: 1024,
		UptimeSeconds:       86400 * 7, // 7 days
	}

	fmt.Printf("✅ System Metrics:\n")
	fmt.Printf("   CPU Usage: %.1f%%\n", systemMetrics.CPUUsagePercent)
	fmt.Printf("   Memory Usage: %.1f%%\n", systemMetrics.MemoryUsagePercent)
	fmt.Printf("   Disk Usage: %.1f%%\n", systemMetrics.DiskUsagePercent)
	fmt.Printf("   Network In: %.1f MB/s\n", systemMetrics.NetworkInMBPS)
	fmt.Printf("   Network Out: %.1f MB/s\n", systemMetrics.NetworkOutMBPS)
	fmt.Printf("   Load Average: %.1f, %.1f, %.1f\n",
		systemMetrics.LoadAverage[0],
		systemMetrics.LoadAverage[1],
		systemMetrics.LoadAverage[2])
	fmt.Printf("   Processes: %d\n", systemMetrics.ProcessCount)
	fmt.Printf("   Threads: %d\n", systemMetrics.ThreadCount)
	fmt.Printf("   Uptime: %d days\n", systemMetrics.UptimeSeconds/(86400))

	fmt.Println()

	// Demo 5: Metrics Collection and Analysis
	fmt.Println("📈 Demo 5: Advanced Metrics Collection")
	fmt.Println(strings.Repeat("-", 60))

	// Simulate custom metrics
	customMetrics := map[string]interface{}{
		"business_transactions_per_minute": 1250,
		"user_sessions_active":             342,
		"cache_hit_rate":                   0.95,
		"database_query_time_avg":          25.5,
		"api_rate_limit_usage":             0.75,
		"background_jobs_queued":           12,
		"websocket_connections":            89,
		"cdn_cache_efficiency":             0.88,
	}

	fmt.Printf("✅ Custom Business Metrics:\n")
	for metric, value := range customMetrics {
		switch v := value.(type) {
		case int:
			fmt.Printf("   %s: %d\n", formatMetricName(metric), v)
		case float64:
			if v < 1.0 {
				fmt.Printf("   %s: %.2f%%\n", formatMetricName(metric), v*100)
			} else {
				fmt.Printf("   %s: %.1f\n", formatMetricName(metric), v)
			}
		}
	}

	fmt.Println()

	// Demo 6: Dashboard Overview
	fmt.Println("📊 Demo 6: Real-time Dashboards")
	fmt.Println(strings.Repeat("-", 60))

	dashboards := []string{
		"System Overview Dashboard",
		"Application Performance Dashboard",
		"Infrastructure Health Dashboard",
		"Security Monitoring Dashboard",
		"Business Metrics Dashboard",
		"Alert Management Dashboard",
	}

	fmt.Printf("✅ Available Dashboards:\n")
	for i, dashboard := range dashboards {
		fmt.Printf("   %d. %s\n", i+1, dashboard)
	}

	fmt.Printf("\n📱 Dashboard Features:\n")
	features := []string{
		"Real-time data updates (5s refresh)",
		"Interactive charts and graphs",
		"Customizable widgets and layouts",
		"Drill-down capabilities",
		"Export to PDF/PNG",
		"Mobile-responsive design",
		"Role-based access control",
		"Alerting integration",
	}

	for _, feature := range features {
		fmt.Printf("   ✓ %s\n", feature)
	}

	fmt.Println()

	// Demo 7: Reporting System
	fmt.Println("📋 Demo 7: Automated Reporting")
	fmt.Println(strings.Repeat("-", 60))

	reports := []string{
		"Daily Health Report",
		"Weekly Performance Summary",
		"Monthly Capacity Planning Report",
		"Security Compliance Report",
		"SLA Performance Report",
		"Incident Analysis Report",
	}

	fmt.Printf("✅ Available Reports:\n")
	for i, report := range reports {
		fmt.Printf("   %d. %s\n", i+1, report)
	}

	fmt.Printf("\n📊 Report Features:\n")
	reportFeatures := []string{
		"Automated generation and delivery",
		"Multiple formats (HTML, PDF, CSV)",
		"Customizable templates",
		"Trend analysis and predictions",
		"Executive summaries",
		"Actionable recommendations",
		"Historical comparisons",
		"Scheduled distribution",
	}

	for _, feature := range reportFeatures {
		fmt.Printf("   ✓ %s\n", feature)
	}

	fmt.Println()

	// Start monitoring system (simulation)
	fmt.Println("🚀 Starting Monitoring System...")
	if err := monitoringSystem.Start(ctx); err != nil {
		log.Printf("Failed to start monitoring system: %v", err)
	} else {
		fmt.Println("✅ Monitoring system started successfully!")
	}

	// Simulate running for a short time
	fmt.Println("\n⏱️  Monitoring system running... (simulating 10 seconds)")
	time.Sleep(2 * time.Second)

	// Get current metrics
	currentMetrics, err := monitoringSystem.GetCurrentMetrics(ctx)
	if err != nil {
		log.Printf("Failed to get current metrics: %v", err)
	} else {
		fmt.Printf("📊 Current System Status: %s\n", currentMetrics.HealthStatus)
		fmt.Printf("📈 Active Components: %d\n", len(currentMetrics.ComponentHealth))
	}

	// Demo Summary
	fmt.Println("\n🎉 Monitoring and Observability Demo Summary")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("✅ Health Monitoring: %d health checks configured\n", len(healthChecks))
	fmt.Printf("✅ Alert Management: %d alert rules, %d active alerts\n", len(alertRules), len(activeAlerts))
	fmt.Printf("✅ Performance Monitoring: Real-time metrics collection\n")
	fmt.Printf("✅ System Monitoring: Comprehensive system metrics\n")
	fmt.Printf("✅ Custom Metrics: %d business metrics tracked\n", len(customMetrics))
	fmt.Printf("✅ Dashboards: %d interactive dashboards\n", len(dashboards))
	fmt.Printf("✅ Reporting: %d automated report types\n", len(reports))
	fmt.Printf("✅ Observability: OpenTelemetry integration\n")
	fmt.Printf("✅ Enterprise Features: Alerting, Analytics, Compliance\n")

	fmt.Printf("\n🚀 Enterprise Monitoring System Ready!\n")
	fmt.Printf("   Comprehensive observability across all system layers\n")
	fmt.Printf("   Proactive alerting and intelligent notifications\n")
	fmt.Printf("   Real-time dashboards and automated reporting\n")
	fmt.Printf("   Production-ready monitoring and analytics\n")

	logger.Info("Monitoring and Observability Demo completed successfully")
}

// Helper function to format metric names
// toTitleCase converts a string to title case (replacement for deprecated strings.Title)
func toTitleCase(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	for i := 1; i < len(runes); i++ {
		runes[i] = unicode.ToLower(runes[i])
	}
	return string(runes)
}

func formatMetricName(name string) string {
	// Convert snake_case to Title Case
	parts := strings.Split(name, "_")
	for i, part := range parts {
		parts[i] = toTitleCase(part)
	}
	return strings.Join(parts, " ")
}
