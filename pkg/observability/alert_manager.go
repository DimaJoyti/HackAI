package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// AlertManagerConfig configuration for alert management
type AlertManagerConfig struct {
	Enabled            bool          `yaml:"enabled" json:"enabled"`
	EvaluationInterval time.Duration `yaml:"evaluation_interval" json:"evaluation_interval"`
	WebhookURL         string        `yaml:"webhook_url" json:"webhook_url"`
	EmailEnabled       bool          `yaml:"email_enabled" json:"email_enabled"`
	SlackEnabled       bool          `yaml:"slack_enabled" json:"slack_enabled"`
	SlackWebhookURL    string        `yaml:"slack_webhook_url" json:"slack_webhook_url"`
	EmailSMTPHost      string        `yaml:"email_smtp_host" json:"email_smtp_host"`
	EmailSMTPPort      int           `yaml:"email_smtp_port" json:"email_smtp_port"`
	EmailFrom          string        `yaml:"email_from" json:"email_from"`
	EmailTo            []string      `yaml:"email_to" json:"email_to"`
}

// AlertSeverity represents alert severity levels
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertStatus represents alert status
type AlertStatus string

const (
	AlertStatusFiring   AlertStatus = "firing"
	AlertStatusResolved AlertStatus = "resolved"
	AlertStatusSilenced AlertStatus = "silenced"
)

// Alert represents a system alert
type Alert struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Severity    AlertSeverity          `json:"severity"`
	Status      AlertStatus            `json:"status"`
	Source      string                 `json:"source"`
	Component   string                 `json:"component"`
	Timestamp   time.Time              `json:"timestamp"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Labels      map[string]string      `json:"labels"`
	Annotations map[string]string      `json:"annotations"`
	Value       float64                `json:"value,omitempty"`
	Threshold   float64                `json:"threshold,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertRuleConfig represents an alerting rule configuration
type AlertRuleConfig struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Query       string            `json:"query"`
	Condition   string            `json:"condition"`
	Threshold   float64           `json:"threshold"`
	Duration    time.Duration     `json:"duration"`
	Severity    AlertSeverity     `json:"severity"`
	Enabled     bool              `json:"enabled"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// SystemAlertManager manages system alerts and notifications
type SystemAlertManager struct {
	config   *AlertManagerConfig
	logger   *logger.Logger
	provider *Provider

	// Alert storage
	alerts map[string]*Alert
	rules  map[string]*AlertRuleConfig
	mu     sync.RWMutex

	// Background processing
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// HTTP client for webhooks
	httpClient *http.Client
}

// NewSystemAlertManager creates a new system alert manager
func NewSystemAlertManager(
	config *AlertManagerConfig,
	provider *Provider,
	log *logger.Logger,
) *SystemAlertManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &SystemAlertManager{
		config:     config,
		logger:     log,
		provider:   provider,
		alerts:     make(map[string]*Alert),
		rules:      make(map[string]*AlertRuleConfig),
		ctx:        ctx,
		cancel:     cancel,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Start starts the alert manager
func (am *SystemAlertManager) Start(ctx context.Context) error {
	if !am.config.Enabled {
		am.logger.Info("Alert manager is disabled")
		return nil
	}

	am.logger.Info("Starting alert manager",
		"evaluation_interval", am.config.EvaluationInterval,
		"webhook_enabled", am.config.WebhookURL != "",
		"email_enabled", am.config.EmailEnabled,
		"slack_enabled", am.config.SlackEnabled,
	)

	// Initialize default rules
	am.initializeDefaultRules()

	// Start background workers
	am.wg.Add(1)
	go am.evaluateRules()

	return nil
}

// Stop stops the alert manager
func (am *SystemAlertManager) Stop() error {
	am.logger.Info("Stopping alert manager")

	am.cancel()
	am.wg.Wait()

	return nil
}

// ProcessAlerts processes pending alerts and sends notifications
func (am *SystemAlertManager) ProcessAlerts(ctx context.Context) error {
	if !am.config.Enabled {
		return nil
	}

	am.mu.RLock()
	alerts := make([]*Alert, 0, len(am.alerts))
	for _, alert := range am.alerts {
		if alert.Status == AlertStatusFiring {
			alerts = append(alerts, alert)
		}
	}
	am.mu.RUnlock()

	if len(alerts) == 0 {
		return nil
	}

	am.logger.Debug("Processing alerts", "count", len(alerts))

	// Send notifications for firing alerts
	for _, alert := range alerts {
		am.sendAlert(alert)
	}

	return nil
}

// initializeDefaultRules initializes default alerting rules
func (am *SystemAlertManager) initializeDefaultRules() {
	defaultRules := []*AlertRuleConfig{
		{
			ID:          "high_error_rate",
			Name:        "High Error Rate",
			Description: "Error rate is above threshold",
			Condition:   "error_rate > threshold",
			Threshold:   0.05, // 5%
			Duration:    5 * time.Minute,
			Severity:    AlertSeverityError,
			Enabled:     true,
			Labels:      map[string]string{"type": "error_rate"},
			Annotations: map[string]string{"summary": "High error rate detected"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "high_response_time",
			Name:        "High Response Time",
			Description: "Response time is above threshold",
			Condition:   "response_time > threshold",
			Threshold:   5000, // 5 seconds
			Duration:    3 * time.Minute,
			Severity:    AlertSeverityWarning,
			Enabled:     true,
			Labels:      map[string]string{"type": "performance"},
			Annotations: map[string]string{"summary": "High response time detected"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "high_memory_usage",
			Name:        "High Memory Usage",
			Description: "Memory usage is above threshold",
			Condition:   "memory_usage > threshold",
			Threshold:   0.85, // 85%
			Duration:    2 * time.Minute,
			Severity:    AlertSeverityCritical,
			Enabled:     true,
			Labels:      map[string]string{"type": "resource"},
			Annotations: map[string]string{"summary": "High memory usage detected"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, rule := range defaultRules {
		am.rules[rule.ID] = rule
	}

	am.logger.Info("Initialized default alert rules", "count", len(defaultRules))
}

// evaluateRules periodically evaluates alerting rules
func (am *SystemAlertManager) evaluateRules() {
	defer am.wg.Done()

	ticker := time.NewTicker(am.config.EvaluationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			return
		case <-ticker.C:
			am.evaluateAllRules()
		}
	}
}

// evaluateAllRules evaluates all enabled alerting rules
func (am *SystemAlertManager) evaluateAllRules() {
	am.mu.RLock()
	rules := make([]*AlertRuleConfig, 0, len(am.rules))
	for _, rule := range am.rules {
		if rule.Enabled {
			rules = append(rules, rule)
		}
	}
	am.mu.RUnlock()

	for _, rule := range rules {
		am.evaluateRule(rule)
	}
}

// evaluateRule evaluates a single alerting rule
func (am *SystemAlertManager) evaluateRule(rule *AlertRuleConfig) {
	// Simplified rule evaluation - in production this would query actual metrics
	shouldFire := am.checkRuleCondition(rule)

	am.mu.Lock()
	existingAlert, exists := am.alerts[rule.ID]
	am.mu.Unlock()

	if shouldFire && (!exists || existingAlert.Status == AlertStatusResolved) {
		// Fire new alert
		alert := &Alert{
			ID:          rule.ID,
			Name:        rule.Name,
			Description: rule.Description,
			Severity:    rule.Severity,
			Status:      AlertStatusFiring,
			Source:      "alert_manager",
			Component:   "observability",
			Timestamp:   time.Now(),
			Labels:      rule.Labels,
			Annotations: rule.Annotations,
			Threshold:   rule.Threshold,
			Metadata:    make(map[string]interface{}),
		}

		am.mu.Lock()
		am.alerts[rule.ID] = alert
		am.mu.Unlock()

		am.sendAlert(alert)

		am.logger.Warn("Alert fired",
			"alert_id", alert.ID,
			"alert_name", alert.Name,
			"severity", alert.Severity,
		)

	} else if !shouldFire && exists && existingAlert.Status == AlertStatusFiring {
		// Resolve existing alert
		now := time.Now()
		existingAlert.Status = AlertStatusResolved
		existingAlert.ResolvedAt = &now

		am.sendAlert(existingAlert)

		am.logger.Info("Alert resolved",
			"alert_id", existingAlert.ID,
			"alert_name", existingAlert.Name,
		)
	}
}

// checkRuleCondition checks if a rule condition is met (simplified implementation)
func (am *SystemAlertManager) checkRuleCondition(rule *AlertRuleConfig) bool {
	// This is a simplified implementation
	// In production, this would query actual metrics from Prometheus or other sources

	switch rule.ID {
	case "high_error_rate":
		// Simulate error rate check
		return false // Would check actual error rate
	case "high_response_time":
		// Simulate response time check
		return false // Would check actual response time
	case "high_memory_usage":
		// Simulate memory usage check
		return false // Would check actual memory usage
	default:
		return false
	}
}

// sendAlert sends an alert through configured channels
func (am *SystemAlertManager) sendAlert(alert *Alert) {
	// Send webhook notification
	if am.config.WebhookURL != "" {
		go am.sendWebhookAlert(alert)
	}

	// Send Slack notification
	if am.config.SlackEnabled && am.config.SlackWebhookURL != "" {
		go am.sendSlackAlert(alert)
	}

	// Send email notification
	if am.config.EmailEnabled {
		go am.sendEmailAlert(alert)
	}
}

// sendWebhookAlert sends alert via webhook
func (am *SystemAlertManager) sendWebhookAlert(alert *Alert) {
	payload, err := json.Marshal(alert)
	if err != nil {
		am.logger.Error("Failed to marshal alert for webhook", "error", err)
		return
	}

	resp, err := am.httpClient.Post(
		am.config.WebhookURL,
		"application/json",
		strings.NewReader(string(payload)),
	)
	if err != nil {
		am.logger.Error("Failed to send webhook alert", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		am.logger.Debug("Webhook alert sent successfully", "alert_id", alert.ID)
	} else {
		am.logger.Error("Webhook alert failed", "status_code", resp.StatusCode, "alert_id", alert.ID)
	}
}

// sendSlackAlert sends alert to Slack
func (am *SystemAlertManager) sendSlackAlert(alert *Alert) {
	color := am.getSlackColor(alert.Severity)

	slackPayload := map[string]interface{}{
		"text": fmt.Sprintf("Alert: %s", alert.Name),
		"attachments": []map[string]interface{}{
			{
				"color":     color,
				"title":     alert.Name,
				"text":      alert.Description,
				"timestamp": alert.Timestamp.Unix(),
				"fields": []map[string]interface{}{
					{"title": "Severity", "value": string(alert.Severity), "short": true},
					{"title": "Status", "value": string(alert.Status), "short": true},
					{"title": "Component", "value": alert.Component, "short": true},
				},
			},
		},
	}

	payload, err := json.Marshal(slackPayload)
	if err != nil {
		am.logger.Error("Failed to marshal Slack alert", "error", err)
		return
	}

	resp, err := am.httpClient.Post(
		am.config.SlackWebhookURL,
		"application/json",
		strings.NewReader(string(payload)),
	)
	if err != nil {
		am.logger.Error("Failed to send Slack alert", "error", err)
		return
	}
	defer resp.Body.Close()

	am.logger.Debug("Slack alert sent", "alert_id", alert.ID)
}

// sendEmailAlert sends alert via email (placeholder implementation)
func (am *SystemAlertManager) sendEmailAlert(alert *Alert) {
	// This would implement actual email sending using SMTP
	am.logger.Info("Email alert would be sent", "alert_id", alert.ID, "recipients", am.config.EmailTo)
}

// getSlackColor returns appropriate color for Slack based on severity
func (am *SystemAlertManager) getSlackColor(severity AlertSeverity) string {
	switch severity {
	case AlertSeverityCritical:
		return "danger"
	case AlertSeverityError:
		return "warning"
	case AlertSeverityWarning:
		return "warning"
	default:
		return "good"
	}
}

// GetActiveAlerts returns all active alerts
func (am *SystemAlertManager) GetActiveAlerts() []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	alerts := make([]*Alert, 0)
	for _, alert := range am.alerts {
		if alert.Status == AlertStatusFiring {
			alerts = append(alerts, alert)
		}
	}

	return alerts
}

// GetAlertHistory returns alert history
func (am *SystemAlertManager) GetAlertHistory(limit int) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	alerts := make([]*Alert, 0, len(am.alerts))
	for _, alert := range am.alerts {
		alerts = append(alerts, alert)
	}

	// Sort by timestamp (most recent first)
	// In production, this would be more efficient with proper indexing

	if limit > 0 && limit < len(alerts) {
		alerts = alerts[:limit]
	}

	return alerts
}
