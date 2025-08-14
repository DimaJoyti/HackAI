package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dimajoyti/hackai/pkg/security"
)

// SimpleLogger implements the security.Logger interface
type SimpleLogger struct{}

func (l *SimpleLogger) Info(msg string, fields ...interface{}) {
	fmt.Printf("[INFO] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func (l *SimpleLogger) Error(msg string, fields ...interface{}) {
	fmt.Printf("[ERROR] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func (l *SimpleLogger) Warn(msg string, fields ...interface{}) {
	fmt.Printf("[WARN] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func (l *SimpleLogger) Debug(msg string, fields ...interface{}) {
	fmt.Printf("[DEBUG] %s", msg)
	if len(fields) > 0 {
		fmt.Printf(" %v", fields)
	}
	fmt.Println()
}

func main() {
	var (
		command   = flag.String("command", "dashboard", "Command to execute (dashboard, metrics, alerts, health, simulate)")
		format    = flag.String("format", "json", "Output format (json, table)")
		component = flag.String("component", "", "Component name for component-specific operations")
		duration  = flag.Duration("duration", 30*time.Second, "Duration for simulation or monitoring")
		port      = flag.Int("port", 8080, "Port for dashboard server")
		help      = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	logger := &SimpleLogger{}

	switch *command {
	case "dashboard":
		runDashboard(logger, *port)
	case "metrics":
		showMetrics(logger, *format, *component)
	case "alerts":
		showAlerts(logger, *format)
	case "health":
		showHealth(logger, *format)
	case "simulate":
		runSimulation(logger, *duration)
	default:
		fmt.Printf("Unknown command: %s\n", *command)
		showHelp()
		os.Exit(1)
	}
}

func showHelp() {
	fmt.Println("Security Monitor CLI Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  security-monitor [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  dashboard    Start interactive dashboard server")
	fmt.Println("  metrics      Show security metrics")
	fmt.Println("  alerts       Show active alerts")
	fmt.Println("  health       Show component health status")
	fmt.Println("  simulate     Run security event simulation")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -command     Command to execute (default: dashboard)")
	fmt.Println("  -format      Output format: json, table (default: json)")
	fmt.Println("  -component   Component name for filtering")
	fmt.Println("  -duration    Duration for simulation (default: 30s)")
	fmt.Println("  -port        Port for dashboard server (default: 8080)")
	fmt.Println("  -help        Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  security-monitor -command=dashboard -port=8080")
	fmt.Println("  security-monitor -command=metrics -format=json")
	fmt.Println("  security-monitor -command=health -component=ai_firewall")
	fmt.Println("  security-monitor -command=simulate -duration=1m")
}

func runDashboard(logger security.Logger, port int) {
	fmt.Printf("[INFO] Starting security monitoring dashboard on port %d\n", port)

	// Create metrics collector
	metricsConfig := &security.MetricsConfig{
		Enabled:               true,
		CollectionInterval:    5 * time.Second,
		RetentionPeriod:       24 * time.Hour,
		PrometheusEnabled:     true,
		PrometheusNamespace:   "security",
		BufferSize:            1000,
		ExportInterval:        10 * time.Second,
		HealthCheckInterval:   30 * time.Second,
		EnableDetailedMetrics: true,
	}

	metricsCollector := security.NewSecurityMetricsCollector(metricsConfig, logger)

	// Create alert manager
	alertConfig := &security.AlertingConfig{
		Enabled:              true,
		MaxActiveAlerts:      1000,
		AlertRetentionPeriod: 7 * 24 * time.Hour,
		EvaluationInterval:   10 * time.Second,
		BufferSize:           500,
		Channels: []*security.ChannelConfig{
			{
				Type:          "log",
				Name:          "console",
				Enabled:       true,
				Config:        make(map[string]interface{}),
				Severities:    []string{"critical", "high", "medium", "low"},
				RetryAttempts: 3,
				RetryDelay:    5 * time.Second,
			},
		},
		Rules: []*security.AlertRuleConfig{
			{
				ID:             "high_threat_score",
				Name:           "High Threat Score Detected",
				Enabled:        true,
				Condition:      "threat_score > threshold",
				Threshold:      0.8,
				Severity:       "critical",
				Description:    "Alert when threat score exceeds 0.8",
				Component:      "security_monitor",
				MetricName:     "threat_score",
				Operator:       ">",
				TimeWindow:     5 * time.Minute,
				MinOccurrences: 1,
				Channels:       []string{"console"},
			},
		},
		Escalations:  []*security.EscalationConfig{},
		Suppressions: []*security.SuppressionConfig{},
	}

	alertManager := security.NewSecurityAlertManager(alertConfig, logger)

	// Create monitoring configuration
	monitoringConfig := &security.MonitoringConfig{
		Enabled:          true,
		DashboardEnabled: true,
		RealTimeUpdates:  true,
		UpdateInterval:   2 * time.Second,
		RetentionPeriod:  24 * time.Hour,
		MaxConnections:   100,
		EnableWebSocket:  true,
		DashboardPort:    port,
		MetricsEndpoint:  "/api/v1/metrics",
		HealthEndpoint:   "/api/v1/health",
		AlertsEndpoint:   "/api/v1/alerts",
	}

	monitor := security.NewSecurityMonitor(metricsCollector, alertManager, monitoringConfig, logger)

	// Start all components
	if err := metricsCollector.Start(); err != nil {
		fmt.Printf("[ERROR] Failed to start metrics collector: %v\n", err)
		os.Exit(1)
	}
	defer metricsCollector.Stop()

	if err := alertManager.Start(); err != nil {
		fmt.Printf("[ERROR] Failed to start alert manager: %v\n", err)
		os.Exit(1)
	}
	defer alertManager.Stop()

	if err := monitor.Start(); err != nil {
		fmt.Printf("[ERROR] Failed to start monitor: %v\n", err)
		os.Exit(1)
	}
	defer monitor.Stop()

	fmt.Printf("[INFO] Dashboard available at http://localhost:%d\n", port)
	fmt.Printf("[INFO] API endpoints:\n")
	fmt.Printf("  - Dashboard: http://localhost:%d/api/v1/dashboard\n", port)
	fmt.Printf("  - Metrics:   http://localhost:%d/api/v1/metrics\n", port)
	fmt.Printf("  - Health:    http://localhost:%d/api/v1/health\n", port)
	fmt.Printf("  - Alerts:    http://localhost:%d/api/v1/alerts\n", port)
	fmt.Printf("[INFO] Press Ctrl+C to stop\n")

	// Keep running
	select {}
}

func showMetrics(logger security.Logger, format, component string) {
	// Create a temporary metrics collector to demonstrate
	config := &security.MetricsConfig{
		Enabled:               true,
		CollectionInterval:    1 * time.Second,
		RetentionPeriod:       1 * time.Hour,
		PrometheusEnabled:     false,
		BufferSize:            100,
		ExportInterval:        10 * time.Second,
		HealthCheckInterval:   30 * time.Second,
		EnableDetailedMetrics: true,
	}

	collector := security.NewSecurityMetricsCollector(config, logger)
	collector.Start()
	defer collector.Stop()

	// Simulate some data
	collector.RecordThreatDetection("sql_injection", "critical", "ai_firewall", "192.168.1.100", 0.9)
	collector.RecordThreatDetection("xss", "high", "input_filter", "192.168.1.101", 0.7)
	collector.RecordBlockedRequest("malicious_payload", "firewall", "192.168.1.100")
	collector.UpdateComponentHealth("ai_firewall", "healthy", true)
	collector.UpdateComponentHealth("input_filter", "healthy", true)

	time.Sleep(100 * time.Millisecond)

	if component != "" {
		// Show component-specific metrics
		componentMetrics := collector.GetComponentMetrics(component)
		if componentMetrics == nil {
			fmt.Printf("[ERROR] Component '%s' not found\n", component)
			return
		}

		if format == "json" {
			data, _ := json.MarshalIndent(componentMetrics, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Component: %s\n", componentMetrics.ComponentName)
			fmt.Printf("Health Status: %s\n", componentMetrics.HealthStatus)
			fmt.Printf("Requests Processed: %d\n", componentMetrics.RequestsProcessed)
			fmt.Printf("Threats Detected: %d\n", componentMetrics.ThreatsDetected)
			fmt.Printf("Actions Executed: %d\n", componentMetrics.ActionsExecuted)
			fmt.Printf("Average Processing Time: %v\n", componentMetrics.AverageProcessingTime)
			fmt.Printf("Error Count: %d\n", componentMetrics.ErrorCount)
		}
	} else {
		// Show overall metrics
		metrics := collector.GetMetrics()

		if format == "json" {
			data, _ := json.MarshalIndent(metrics, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Security Metrics Summary\n")
			fmt.Printf("========================\n")
			fmt.Printf("Total Requests: %d\n", metrics.TotalRequests)
			fmt.Printf("Blocked Requests: %d\n", metrics.BlockedRequests)
			fmt.Printf("Threats Detected: %d\n", metrics.ThreatsDetected)
			fmt.Printf("Average Risk Score: %.2f\n", metrics.AverageRiskScore)
			fmt.Printf("Max Risk Score: %.2f\n", metrics.MaxRiskScore)
			fmt.Printf("Alerts Triggered: %d\n", metrics.AlertsTriggered)
			fmt.Printf("Uptime: %d seconds\n", metrics.UptimeSeconds)

			if len(metrics.ThreatsByType) > 0 {
				fmt.Printf("\nThreats by Type:\n")
				for threatType, count := range metrics.ThreatsByType {
					fmt.Printf("  %s: %d\n", threatType, count)
				}
			}

			if len(metrics.ThreatsBySeverity) > 0 {
				fmt.Printf("\nThreats by Severity:\n")
				for severity, count := range metrics.ThreatsBySeverity {
					fmt.Printf("  %s: %d\n", severity, count)
				}
			}
		}
	}
}

func showAlerts(logger security.Logger, format string) {
	// Create a temporary alert manager to demonstrate
	config := &security.AlertingConfig{
		Enabled:              true,
		MaxActiveAlerts:      100,
		AlertRetentionPeriod: 24 * time.Hour,
		EvaluationInterval:   10 * time.Second,
		BufferSize:           100,
		Channels:             []*security.ChannelConfig{},
		Rules:                []*security.AlertRuleConfig{},
		Escalations:          []*security.EscalationConfig{},
		Suppressions:         []*security.SuppressionConfig{},
	}

	alertManager := security.NewSecurityAlertManager(config, logger)
	alertManager.Start()
	defer alertManager.Stop()

	// Simulate some alerts
	metadata := map[string]interface{}{
		"source":       "192.168.1.100",
		"component":    "ai_firewall",
		"threat_score": 0.9,
	}
	alertManager.TriggerAlert("test_rule", "threat_detection", "critical", "High Threat Detected", "Threat score exceeded threshold", metadata)

	time.Sleep(100 * time.Millisecond)

	activeAlerts := alertManager.GetActiveAlerts()
	stats := alertManager.GetAlertStatistics()

	if format == "json" {
		result := map[string]interface{}{
			"active_alerts": activeAlerts,
			"statistics":    stats,
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Security Alerts\n")
		fmt.Printf("===============\n")
		fmt.Printf("Active Alerts: %v\n", stats["active_alerts"])
		fmt.Printf("Total Alerts: %v\n", stats["total_alerts"])

		if len(activeAlerts) > 0 {
			fmt.Printf("\nActive Alerts:\n")
			for _, alert := range activeAlerts {
				fmt.Printf("  ID: %s\n", alert.ID)
				fmt.Printf("  Type: %s\n", alert.Type)
				fmt.Printf("  Severity: %s\n", alert.Severity)
				fmt.Printf("  Title: %s\n", alert.Title)
				fmt.Printf("  Status: %s\n", alert.Status)
				fmt.Printf("  Created: %s\n", alert.CreatedAt.Format(time.RFC3339))
				fmt.Printf("  ---\n")
			}
		}
	}
}

func showHealth(logger security.Logger, format string) {
	// Create a temporary metrics collector to demonstrate
	config := &security.MetricsConfig{
		Enabled:               true,
		CollectionInterval:    1 * time.Second,
		RetentionPeriod:       1 * time.Hour,
		PrometheusEnabled:     false,
		BufferSize:            100,
		ExportInterval:        10 * time.Second,
		HealthCheckInterval:   30 * time.Second,
		EnableDetailedMetrics: true,
	}

	collector := security.NewSecurityMetricsCollector(config, logger)
	collector.Start()
	defer collector.Stop()

	// Simulate component health
	collector.UpdateComponentHealth("ai_firewall", "healthy", true)
	collector.UpdateComponentHealth("input_filter", "healthy", true)
	collector.UpdateComponentHealth("prompt_guard", "degraded", false)
	collector.UpdateComponentHealth("threat_scanner", "healthy", true)

	time.Sleep(100 * time.Millisecond)

	componentMetrics := collector.GetAllComponentMetrics()

	if format == "json" {
		data, _ := json.MarshalIndent(componentMetrics, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Component Health Status\n")
		fmt.Printf("=======================\n")

		healthyCount := 0
		totalCount := len(componentMetrics)

		for name, metrics := range componentMetrics {
			status := "❌"
			if metrics.HealthStatus == "healthy" {
				status = "✅"
				healthyCount++
			} else if metrics.HealthStatus == "degraded" {
				status = "⚠️"
			}

			fmt.Printf("%s %s: %s\n", status, name, metrics.HealthStatus)
		}

		fmt.Printf("\nOverall Health: %d/%d components healthy\n", healthyCount, totalCount)

		healthPercentage := float64(healthyCount) / float64(totalCount) * 100
		fmt.Printf("Health Percentage: %.1f%%\n", healthPercentage)
	}
}

func runSimulation(logger security.Logger, duration time.Duration) {
	fmt.Printf("[INFO] Running security event simulation for %v\n", duration)

	// Create metrics collector
	config := &security.MetricsConfig{
		Enabled:               true,
		CollectionInterval:    1 * time.Second,
		RetentionPeriod:       1 * time.Hour,
		PrometheusEnabled:     false,
		BufferSize:            1000,
		ExportInterval:        5 * time.Second,
		HealthCheckInterval:   10 * time.Second,
		EnableDetailedMetrics: true,
	}

	collector := security.NewSecurityMetricsCollector(config, logger)
	collector.Start()
	defer collector.Stop()

	// Simulation data
	threatTypes := []string{"sql_injection", "xss", "command_injection", "path_traversal", "malware", "anomaly"}
	severities := []string{"critical", "high", "medium", "low"}
	components := []string{"ai_firewall", "input_filter", "prompt_guard", "threat_scanner"}
	sources := []string{"192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.50", "external"}

	startTime := time.Now()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	eventCount := 0

	for {
		select {
		case <-ticker.C:
			// Simulate threat detection
			threatType := threatTypes[eventCount%len(threatTypes)]
			severity := severities[eventCount%len(severities)]
			component := components[eventCount%len(components)]
			source := sources[eventCount%len(sources)]
			score := 0.1 + (float64(eventCount%9) * 0.1)

			collector.RecordThreatDetection(threatType, severity, component, source, score)

			// Occasionally simulate blocked requests
			if eventCount%3 == 0 {
				collector.RecordBlockedRequest("malicious_payload", component, source)
			}

			// Update component health
			healthy := eventCount%10 != 0 // 90% healthy
			status := "healthy"
			if !healthy {
				status = "degraded"
			}
			collector.UpdateComponentHealth(component, status, healthy)

			// Record processing time
			processingTime := time.Duration(10+eventCount%50) * time.Millisecond
			collector.RecordProcessingTime(component, "analyze", processingTime)

			eventCount++

			if eventCount%10 == 0 {
				metrics := collector.GetMetrics()
				fmt.Printf("[INFO] Events: %d, Threats: %d, Blocked: %d, Avg Risk: %.2f\n",
					eventCount, metrics.ThreatsDetected, metrics.BlockedRequests, metrics.AverageRiskScore)
			}

		default:
			if time.Since(startTime) >= duration {
				fmt.Printf("[INFO] Simulation completed. Generated %d events\n", eventCount)

				// Show final metrics
				metrics := collector.GetMetrics()
				fmt.Printf("\nFinal Metrics:\n")
				fmt.Printf("  Total Events: %d\n", eventCount)
				fmt.Printf("  Threats Detected: %d\n", metrics.ThreatsDetected)
				fmt.Printf("  Blocked Requests: %d\n", metrics.BlockedRequests)
				fmt.Printf("  Average Risk Score: %.2f\n", metrics.AverageRiskScore)
				fmt.Printf("  Max Risk Score: %.2f\n", metrics.MaxRiskScore)

				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
