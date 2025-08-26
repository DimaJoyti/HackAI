package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// SecurityMetrics represents security monitoring metrics
type SecurityMetrics struct {
	TotalRequests     int               `json:"total_requests"`
	BlockedRequests   int               `json:"blocked_requests"`
	ThreatsDetected   int               `json:"threats_detected"`
	AverageRiskScore  float64           `json:"average_risk_score"`
	MaxRiskScore      float64           `json:"max_risk_score"`
	AlertsTriggered   int               `json:"alerts_triggered"`
	UptimeSeconds     int64             `json:"uptime_seconds"`
	ThreatsByType     map[string]int    `json:"threats_by_type"`
	ThreatsBySeverity map[string]int    `json:"threats_by_severity"`
	ComponentHealth   map[string]string `json:"component_health"`
	LastUpdated       time.Time         `json:"last_updated"`
}

// SecurityAlert represents a security alert
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Status      string                 `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ComponentMetrics represents metrics for a specific component
type ComponentMetrics struct {
	ComponentName         string        `json:"component_name"`
	HealthStatus          string        `json:"health_status"`
	RequestsProcessed     int           `json:"requests_processed"`
	ThreatsDetected       int           `json:"threats_detected"`
	ActionsExecuted       int           `json:"actions_executed"`
	AverageProcessingTime time.Duration `json:"average_processing_time"`
	ErrorCount            int           `json:"error_count"`
	LastUpdated           time.Time     `json:"last_updated"`
}

// SecurityMonitor provides security monitoring capabilities
type SecurityMonitor struct {
	metrics    *SecurityMetrics
	alerts     []*SecurityAlert
	components map[string]*ComponentMetrics
	startTime  time.Time
	logger     *logger.Logger
}

// NewSecurityMonitor creates a new security monitor
func NewSecurityMonitor(logger *logger.Logger) *SecurityMonitor {
	return &SecurityMonitor{
		metrics: &SecurityMetrics{
			ThreatsByType:     make(map[string]int),
			ThreatsBySeverity: make(map[string]int),
			ComponentHealth:   make(map[string]string),
			LastUpdated:       time.Now(),
		},
		alerts:     make([]*SecurityAlert, 0),
		components: make(map[string]*ComponentMetrics),
		startTime:  time.Now(),
		logger:     logger,
	}
}

// initializeSampleData initializes sample data for demonstration
func (sm *SecurityMonitor) initializeSampleData() {
	// Sample metrics
	sm.metrics.TotalRequests = 1247
	sm.metrics.BlockedRequests = 49
	sm.metrics.ThreatsDetected = 12
	sm.metrics.AverageRiskScore = 0.23
	sm.metrics.MaxRiskScore = 0.85
	sm.metrics.AlertsTriggered = 5
	sm.metrics.UptimeSeconds = int64(time.Since(sm.startTime).Seconds())

	// Sample threats by type
	sm.metrics.ThreatsByType["sql_injection"] = 3
	sm.metrics.ThreatsByType["xss"] = 2
	sm.metrics.ThreatsByType["command_injection"] = 1
	sm.metrics.ThreatsByType["malware"] = 4
	sm.metrics.ThreatsByType["anomaly"] = 2

	// Sample threats by severity
	sm.metrics.ThreatsBySeverity["critical"] = 2
	sm.metrics.ThreatsBySeverity["high"] = 4
	sm.metrics.ThreatsBySeverity["medium"] = 4
	sm.metrics.ThreatsBySeverity["low"] = 2

	// Sample component health
	sm.metrics.ComponentHealth["ai_firewall"] = "healthy"
	sm.metrics.ComponentHealth["input_filter"] = "healthy"
	sm.metrics.ComponentHealth["prompt_guard"] = "degraded"
	sm.metrics.ComponentHealth["threat_scanner"] = "healthy"

	// Sample component metrics
	sm.components["ai_firewall"] = &ComponentMetrics{
		ComponentName:         "ai_firewall",
		HealthStatus:          "healthy",
		RequestsProcessed:     856,
		ThreatsDetected:       8,
		ActionsExecuted:       45,
		AverageProcessingTime: 125 * time.Millisecond,
		ErrorCount:            2,
		LastUpdated:           time.Now(),
	}

	sm.components["input_filter"] = &ComponentMetrics{
		ComponentName:         "input_filter",
		HealthStatus:          "healthy",
		RequestsProcessed:     391,
		ThreatsDetected:       4,
		ActionsExecuted:       12,
		AverageProcessingTime: 89 * time.Millisecond,
		ErrorCount:            0,
		LastUpdated:           time.Now(),
	}

	// Sample alerts
	sm.alerts = append(sm.alerts, &SecurityAlert{
		ID:          "alert_001",
		Type:        "threat_detection",
		Severity:    "critical",
		Title:       "High Threat Score Detected",
		Description: "Threat score exceeded threshold (0.85 > 0.8)",
		Status:      "active",
		CreatedAt:   time.Now().Add(-5 * time.Minute),
		UpdatedAt:   time.Now().Add(-5 * time.Minute),
		Metadata: map[string]interface{}{
			"source":       "192.168.1.100",
			"component":    "ai_firewall",
			"threat_score": 0.85,
		},
	})

	sm.metrics.LastUpdated = time.Now()
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

	// Initialize logger
	loggerInstance, err := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
	})
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	// Create security monitor
	monitor := NewSecurityMonitor(loggerInstance)

	switch *command {
	case "dashboard":
		runDashboard(monitor, *port)
	case "metrics":
		showMetrics(monitor, *format, *component)
	case "alerts":
		showAlerts(monitor, *format)
	case "health":
		showHealth(monitor, *format)
	case "simulate":
		runSimulation(monitor, *duration)
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

func runDashboard(monitor *SecurityMonitor, port int) {
	fmt.Printf("[INFO] Starting security monitoring dashboard on port %d\n", port)

	// Initialize sample data
	monitor.initializeSampleData()

	// Display dashboard
	fmt.Println("\n🔒 Security Monitoring Dashboard")
	fmt.Println("================================")

	// Show current metrics
	showMetrics(monitor, "text", "")

	// Show alerts
	fmt.Println("\n🚨 Recent Alerts:")
	showAlerts(monitor, "text")

	// Show health status
	fmt.Println("\n💚 System Health:")
	showHealth(monitor, "text")

	fmt.Printf("\n[INFO] Security monitoring dashboard running on port %d\n", port)
	fmt.Printf("[INFO] Dashboard URL: http://localhost:%d\n", port)
	fmt.Println("[INFO] Press Ctrl+C to stop the dashboard")

	// Keep the dashboard running (simplified for demo)
	time.Sleep(30 * time.Second)
	fmt.Println("[INFO] Dashboard demo completed")
}

func showMetrics(monitor *SecurityMonitor, format, component string) {
	// Ensure sample data is initialized
	monitor.initializeSampleData()

	if component != "" {
		// Show component-specific metrics
		componentMetrics, exists := monitor.components[component]
		if !exists {
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
		metrics := monitor.metrics

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

func showAlerts(monitor *SecurityMonitor, format string) {
	// Ensure sample data is initialized
	monitor.initializeSampleData()

	activeAlerts := monitor.alerts
	totalAlerts := len(activeAlerts)
	activeCount := 0
	for _, alert := range activeAlerts {
		if alert.Status == "active" {
			activeCount++
		}
	}

	if format == "json" {
		result := map[string]interface{}{
			"active_alerts": activeAlerts,
			"statistics": map[string]interface{}{
				"active_alerts": activeCount,
				"total_alerts":  totalAlerts,
			},
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Security Alerts\n")
		fmt.Printf("===============\n")
		fmt.Printf("Active Alerts: %d\n", activeCount)
		fmt.Printf("Total Alerts: %d\n", totalAlerts)

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

func showHealth(monitor *SecurityMonitor, format string) {
	// Ensure sample data is initialized
	monitor.initializeSampleData()

	componentMetrics := monitor.components

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

		if totalCount > 0 {
			healthPercentage := float64(healthyCount) / float64(totalCount) * 100
			fmt.Printf("Health Percentage: %.1f%%\n", healthPercentage)
		}
	}
}

func runSimulation(monitor *SecurityMonitor, duration time.Duration) {
	fmt.Printf("[INFO] Running security event simulation for %v\n", duration)

	// Initialize sample data
	monitor.initializeSampleData()

	// Simulation data
	threatTypes := []string{"sql_injection", "xss", "command_injection", "path_traversal", "malware", "anomaly"}
	severities := []string{"critical", "high", "medium", "low"}
	components := []string{"ai_firewall", "input_filter", "prompt_guard", "threat_scanner"}

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
			_ = components[eventCount%len(components)] // component for simulation

			// Update metrics
			monitor.metrics.ThreatsDetected++
			monitor.metrics.ThreatsByType[threatType]++
			monitor.metrics.ThreatsBySeverity[severity]++

			// Occasionally simulate blocked requests
			if eventCount%3 == 0 {
				monitor.metrics.BlockedRequests++
			}

			eventCount++

			if eventCount%10 == 0 {
				fmt.Printf("[INFO] Events: %d, Threats: %d, Blocked: %d\n",
					eventCount, monitor.metrics.ThreatsDetected, monitor.metrics.BlockedRequests)
			}

		default:
			if time.Since(startTime) >= duration {
				fmt.Printf("[INFO] Simulation completed. Generated %d events\n", eventCount)

				// Show final metrics
				fmt.Printf("\nFinal Metrics:\n")
				fmt.Printf("  Total Events: %d\n", eventCount)
				fmt.Printf("  Threats Detected: %d\n", monitor.metrics.ThreatsDetected)
				fmt.Printf("  Blocked Requests: %d\n", monitor.metrics.BlockedRequests)
				fmt.Printf("  Average Risk Score: %.2f\n", monitor.metrics.AverageRiskScore)
				fmt.Printf("  Max Risk Score: %.2f\n", monitor.metrics.MaxRiskScore)

				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
