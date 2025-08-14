package security

import (
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockLogger implements the Logger interface for testing
type MockLogger struct {
	logs []LogEntry
}

type LogEntry struct {
	Level   string
	Message string
	Fields  map[string]interface{}
}

func (m *MockLogger) Info(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "info", Message: msg, Fields: m.parseFields(fields)})
}

func (m *MockLogger) Error(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "error", Message: msg, Fields: m.parseFields(fields)})
}

func (m *MockLogger) Warn(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "warn", Message: msg, Fields: m.parseFields(fields)})
}

func (m *MockLogger) Debug(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "debug", Message: msg, Fields: m.parseFields(fields)})
}

func (m *MockLogger) parseFields(fields []interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			result[key] = fields[i+1]
		}
	}
	return result
}

func TestSecurityMetricsCollector(t *testing.T) {
	logger := &MockLogger{}

	config := &security.MetricsConfig{
		Enabled:               true,
		CollectionInterval:    100 * time.Millisecond,
		RetentionPeriod:       24 * time.Hour,
		PrometheusEnabled:     false, // Disable for testing
		PrometheusNamespace:   "test_security",
		BufferSize:            100,
		ExportInterval:        1 * time.Second,
		HealthCheckInterval:   500 * time.Millisecond,
		EnableDetailedMetrics: true,
	}

	t.Run("Create Security Metrics Collector", func(t *testing.T) {
		collector := security.NewSecurityMetricsCollector(config, logger)
		require.NotNil(t, collector)

		err := collector.Start()
		require.NoError(t, err)
		defer collector.Stop()

		// Test basic functionality
		metrics := collector.GetMetrics()
		require.NotNil(t, metrics)
		assert.Equal(t, int64(0), metrics.TotalRequests)
		assert.Equal(t, int64(0), metrics.ThreatsDetected)
	})

	t.Run("Record Security Events", func(t *testing.T) {
		collector := security.NewSecurityMetricsCollector(config, logger)
		require.NotNil(t, collector)

		err := collector.Start()
		require.NoError(t, err)
		defer collector.Stop()

		// Record threat detection
		collector.RecordThreatDetection("sql_injection", "critical", "ai_firewall", "192.168.1.100", 0.9)

		// Record blocked request
		collector.RecordBlockedRequest("malicious_payload", "input_filter", "192.168.1.100")

		// Record processing time
		collector.RecordProcessingTime("ai_firewall", "analyze", 50*time.Millisecond)

		// Update component health
		collector.UpdateComponentHealth("ai_firewall", "healthy", true)

		// Wait for processing
		time.Sleep(200 * time.Millisecond)

		// Verify metrics
		metrics := collector.GetMetrics()
		assert.Equal(t, int64(1), metrics.ThreatsDetected)
		assert.Equal(t, int64(1), metrics.BlockedRequests)
		assert.Contains(t, metrics.ThreatsByType, "sql_injection")
		assert.Contains(t, metrics.ThreatsBySeverity, "critical")
		assert.Contains(t, metrics.ThreatsBySource, "192.168.1.100")
	})

	t.Run("Component Metrics", func(t *testing.T) {
		collector := security.NewSecurityMetricsCollector(config, logger)
		require.NotNil(t, collector)

		err := collector.Start()
		require.NoError(t, err)
		defer collector.Stop()

		// Update component health
		collector.UpdateComponentHealth("ai_firewall", "healthy", true)
		collector.UpdateComponentHealth("prompt_guard", "degraded", false)

		// Record some events for components
		collector.RecordThreatDetection("xss", "high", "ai_firewall", "test", 0.8)
		collector.RecordThreatDetection("prompt_injection", "medium", "prompt_guard", "test", 0.6)

		time.Sleep(200 * time.Millisecond)

		// Get component metrics
		componentMetrics := collector.GetAllComponentMetrics()
		require.Contains(t, componentMetrics, "ai_firewall")
		require.Contains(t, componentMetrics, "prompt_guard")

		firewallMetrics := componentMetrics["ai_firewall"]
		assert.Equal(t, "healthy", firewallMetrics.HealthStatus)
		assert.Equal(t, int64(1), firewallMetrics.ThreatsDetected)

		promptGuardMetrics := componentMetrics["prompt_guard"]
		assert.Equal(t, "degraded", promptGuardMetrics.HealthStatus)
		assert.Equal(t, int64(1), promptGuardMetrics.ThreatsDetected)
	})

	t.Run("Performance Metrics", func(t *testing.T) {
		collector := security.NewSecurityMetricsCollector(config, logger)
		require.NotNil(t, collector)

		err := collector.Start()
		require.NoError(t, err)
		defer collector.Stop()

		// Record processing times
		collector.RecordProcessingTime("ai_firewall", "analyze", 10*time.Millisecond)
		collector.RecordProcessingTime("ai_firewall", "analyze", 20*time.Millisecond)
		collector.RecordProcessingTime("ai_firewall", "analyze", 30*time.Millisecond)

		time.Sleep(200 * time.Millisecond)

		// Get performance metrics
		performanceMetrics := collector.GetPerformanceMetrics()
		require.NotNil(t, performanceMetrics)

		// Get overall metrics to check processing time stats
		metrics := collector.GetMetrics()
		assert.True(t, metrics.AverageProcessingTime > 0)
		assert.True(t, metrics.MaxProcessingTime > 0)
		assert.True(t, metrics.MinProcessingTime > 0)
	})

	t.Run("Export Metrics", func(t *testing.T) {
		collector := security.NewSecurityMetricsCollector(config, logger)
		require.NotNil(t, collector)

		err := collector.Start()
		require.NoError(t, err)
		defer collector.Stop()

		// Record some data
		collector.RecordThreatDetection("malware", "critical", "scanner", "test", 0.95)

		time.Sleep(100 * time.Millisecond)

		// Export metrics
		data, err := collector.ExportMetrics()
		require.NoError(t, err)
		require.NotEmpty(t, data)

		// Verify JSON format
		assert.Contains(t, string(data), "threats_detected")
		assert.Contains(t, string(data), "threats_by_type")
	})

	t.Run("Reset Metrics", func(t *testing.T) {
		collector := security.NewSecurityMetricsCollector(config, logger)
		require.NotNil(t, collector)

		err := collector.Start()
		require.NoError(t, err)
		defer collector.Stop()

		// Record some data
		collector.RecordThreatDetection("test_threat", "low", "test_component", "test", 0.3)

		time.Sleep(100 * time.Millisecond)

		// Verify data exists
		metrics := collector.GetMetrics()
		assert.Equal(t, int64(1), metrics.ThreatsDetected)

		// Reset metrics
		collector.ResetMetrics()

		// Verify reset
		metrics = collector.GetMetrics()
		assert.Equal(t, int64(0), metrics.ThreatsDetected)
		assert.Empty(t, metrics.ThreatsByType)
	})
}

func TestSecurityMonitor(t *testing.T) {
	logger := &MockLogger{}

	metricsConfig := &security.MetricsConfig{
		Enabled:               true,
		CollectionInterval:    100 * time.Millisecond,
		RetentionPeriod:       24 * time.Hour,
		PrometheusEnabled:     false,
		BufferSize:            100,
		ExportInterval:        1 * time.Second,
		HealthCheckInterval:   500 * time.Millisecond,
		EnableDetailedMetrics: true,
	}

	monitoringConfig := &security.MonitoringConfig{
		Enabled:          true,
		DashboardEnabled: false, // Disable for testing
		RealTimeUpdates:  true,
		UpdateInterval:   100 * time.Millisecond,
		RetentionPeriod:  24 * time.Hour,
		MaxConnections:   10,
		EnableWebSocket:  false,
		DashboardPort:    8080,
		MetricsEndpoint:  "/metrics",
		HealthEndpoint:   "/health",
		AlertsEndpoint:   "/alerts",
	}

	t.Run("Create Security Monitor", func(t *testing.T) {
		metricsCollector := security.NewSecurityMetricsCollector(metricsConfig, logger)
		require.NotNil(t, metricsCollector)

		monitor := security.NewSecurityMonitor(metricsCollector, nil, monitoringConfig, logger)
		require.NotNil(t, monitor)

		err := monitor.Start()
		require.NoError(t, err)
		defer monitor.Stop()

		// Test basic functionality
		dashboardData := monitor.GetDashboardData()
		require.NotNil(t, dashboardData)
		require.NotNil(t, dashboardData.Overview)
		require.NotNil(t, dashboardData.ThreatAnalysis)
		require.NotNil(t, dashboardData.ComponentStatus)
	})

	t.Run("Dashboard Data Updates", func(t *testing.T) {
		metricsCollector := security.NewSecurityMetricsCollector(metricsConfig, logger)
		require.NotNil(t, metricsCollector)

		err := metricsCollector.Start()
		require.NoError(t, err)
		defer metricsCollector.Stop()

		monitor := security.NewSecurityMonitor(metricsCollector, nil, monitoringConfig, logger)
		require.NotNil(t, monitor)

		err = monitor.Start()
		require.NoError(t, err)
		defer monitor.Stop()

		// Record some metrics
		metricsCollector.RecordThreatDetection("sql_injection", "critical", "ai_firewall", "test", 0.9)
		metricsCollector.RecordBlockedRequest("malicious", "firewall", "test")
		metricsCollector.UpdateComponentHealth("ai_firewall", "healthy", true)

		// Wait for updates
		time.Sleep(300 * time.Millisecond)

		// Check dashboard data
		overview := monitor.GetSecurityOverview()
		require.NotNil(t, overview)
		assert.Equal(t, int64(1), overview.ThreatsDetected)
		assert.Equal(t, int64(1), overview.BlockedRequests)
		// System health depends on component health percentage, so we'll check it's not unknown
		assert.NotEqual(t, "unknown", overview.SystemHealth)

		threatAnalysis := monitor.GetThreatAnalysis()
		require.NotNil(t, threatAnalysis)
		assert.Contains(t, threatAnalysis.ThreatsByType, "sql_injection")
		assert.Contains(t, threatAnalysis.ThreatsBySeverity, "critical")

		componentStatus := monitor.GetComponentStatus()
		require.NotNil(t, componentStatus)
		// Overall health depends on the percentage of healthy components
		assert.NotEqual(t, "unknown", componentStatus.OverallHealth)
		assert.True(t, componentStatus.HealthyComponents >= 1)
		assert.True(t, componentStatus.UnhealthyComponents >= 0)
	})
}

func TestSecurityAlertManager(t *testing.T) {
	logger := &MockLogger{}

	config := &security.AlertingConfig{
		Enabled:              true,
		MaxActiveAlerts:      100,
		AlertRetentionPeriod: 24 * time.Hour,
		EvaluationInterval:   100 * time.Millisecond,
		BufferSize:           100,
		Channels: []*security.ChannelConfig{
			{
				Type:          "log",
				Name:          "test_log",
				Enabled:       true,
				Config:        make(map[string]interface{}),
				Severities:    []string{"critical", "high", "medium", "low"},
				RetryAttempts: 3,
				RetryDelay:    5 * time.Second,
			},
		},
		Rules: []*security.AlertRuleConfig{
			{
				ID:             "test_rule_1",
				Name:           "High Threat Score",
				Enabled:        true,
				Condition:      "threat_score > threshold",
				Threshold:      0.8,
				Severity:       "critical",
				Description:    "Alert when threat score exceeds 0.8",
				Component:      "ai_firewall",
				MetricName:     "threat_score",
				Operator:       ">",
				TimeWindow:     5 * time.Minute,
				MinOccurrences: 1,
				Channels:       []string{"test_log"},
			},
		},
		Escalations:  []*security.EscalationConfig{},
		Suppressions: []*security.SuppressionConfig{},
	}

	t.Run("Create Alert Manager", func(t *testing.T) {
		alertManager := security.NewSecurityAlertManager(config, logger)
		require.NotNil(t, alertManager)

		err := alertManager.Start()
		require.NoError(t, err)
		defer alertManager.Stop()

		// Test basic functionality
		activeAlerts := alertManager.GetActiveAlerts()
		assert.Empty(t, activeAlerts)

		stats := alertManager.GetAlertStatistics()
		assert.Equal(t, 0, stats["active_alerts"])
	})

	t.Run("Trigger Alert", func(t *testing.T) {
		alertManager := security.NewSecurityAlertManager(config, logger)
		require.NotNil(t, alertManager)

		err := alertManager.Start()
		require.NoError(t, err)
		defer alertManager.Stop()

		// Trigger an alert
		metadata := map[string]interface{}{
			"source":       "test",
			"component":    "ai_firewall",
			"threat_score": 0.9,
		}

		alertManager.TriggerAlert("test_rule_1", "threat_detection", "critical", "Test Alert", "This is a test alert", metadata)

		// Wait for processing
		time.Sleep(200 * time.Millisecond)

		// Check active alerts
		activeAlerts := alertManager.GetActiveAlerts()
		assert.Len(t, activeAlerts, 1)

		alert := activeAlerts[0]
		assert.Equal(t, "test_rule_1", alert.RuleID)
		assert.Equal(t, "critical", alert.Severity)
		assert.Equal(t, "Test Alert", alert.Title)
		assert.Equal(t, "active", alert.Status)

		// Check statistics
		stats := alertManager.GetAlertStatistics()
		assert.Equal(t, 1, stats["active_alerts"])
	})

	t.Run("Resolve Alert", func(t *testing.T) {
		alertManager := security.NewSecurityAlertManager(config, logger)
		require.NotNil(t, alertManager)

		err := alertManager.Start()
		require.NoError(t, err)
		defer alertManager.Stop()

		// Trigger an alert
		metadata := map[string]interface{}{
			"source":    "test",
			"component": "ai_firewall",
		}

		alertManager.TriggerAlert("test_rule_1", "threat_detection", "critical", "Test Alert", "This is a test alert", metadata)

		time.Sleep(100 * time.Millisecond)

		// Get the alert ID
		activeAlerts := alertManager.GetActiveAlerts()
		require.Len(t, activeAlerts, 1)
		alertID := activeAlerts[0].ID

		// Resolve the alert
		err = alertManager.ResolveAlert(alertID, "False positive")
		require.NoError(t, err)

		// Check that alert is no longer active
		activeAlerts = alertManager.GetActiveAlerts()
		assert.Empty(t, activeAlerts)

		// Check alert history
		history := alertManager.GetAlertHistory(10)
		assert.Len(t, history, 1)
		assert.Equal(t, "resolved", history[0].Status)
		assert.NotNil(t, history[0].ResolvedAt)
	})

	t.Run("Suppress Alert", func(t *testing.T) {
		alertManager := security.NewSecurityAlertManager(config, logger)
		require.NotNil(t, alertManager)

		err := alertManager.Start()
		require.NoError(t, err)
		defer alertManager.Stop()

		// Suppress alerts for a rule
		err = alertManager.SuppressAlert("test_rule_1", "Maintenance window", 1*time.Hour)
		require.NoError(t, err)

		// Try to trigger an alert
		metadata := map[string]interface{}{
			"source":    "test",
			"component": "ai_firewall",
		}

		alertManager.TriggerAlert("test_rule_1", "threat_detection", "critical", "Test Alert", "This should be suppressed", metadata)

		time.Sleep(100 * time.Millisecond)

		// Check that no alerts were created
		activeAlerts := alertManager.GetActiveAlerts()
		assert.Empty(t, activeAlerts)
	})
}
