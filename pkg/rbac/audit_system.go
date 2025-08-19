package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// TimeRange represents a time range (duplicate from rbac_manager.go for independence)
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// NewAccessAuditor creates a new access auditor
func NewAccessAuditor(config *AuditConfig, logger *logger.Logger) *AccessAuditor {
	if config == nil {
		config = DefaultAuditConfig()
	}

	return &AccessAuditor{
		logger: logger,
		config: config,
		events: make(chan *AuditEvent, config.BufferSize),
	}
}

// DefaultAuditConfig returns default audit configuration
func DefaultAuditConfig() *AuditConfig {
	return &AuditConfig{
		EnableLogging:   true,
		LogLevel:        "info",
		RetentionPeriod: 90 * 24 * time.Hour,
		BufferSize:      1000,
	}
}

// Start starts the access auditor
func (aa *AccessAuditor) Start(ctx context.Context) error {
	aa.logger.Info("Starting access auditor")

	go aa.eventProcessor(ctx)

	return nil
}

// LogEvent logs an audit event
func (aa *AccessAuditor) LogEvent(event *AuditEvent) {
	if !aa.config.EnableLogging {
		return
	}

	select {
	case aa.events <- event:
		// Event queued successfully
	default:
		// Buffer full, log warning
		aa.logger.Warn("Audit event buffer full, dropping event", "event_id", event.ID)
	}
}

// eventProcessor processes audit events from the queue
func (aa *AccessAuditor) eventProcessor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-aa.events:
			aa.processEvent(event)
		}
	}
}

// processEvent processes a single audit event
func (aa *AccessAuditor) processEvent(event *AuditEvent) {
	// Log the event based on configured log level
	switch aa.config.LogLevel {
	case "debug":
		aa.logger.Debug("Access audit event",
			"event_id", event.ID,
			"type", event.Type,
			"user_id", event.UserID,
			"resource", event.Resource,
			"action", event.Action,
			"result", event.Result,
			"ip_address", event.IPAddress,
			"user_agent", event.UserAgent,
			"timestamp", event.Timestamp,
			"details", event.Details)
	case "info":
		aa.logger.Info("Access audit event",
			"event_id", event.ID,
			"type", event.Type,
			"user_id", event.UserID,
			"resource", event.Resource,
			"action", event.Action,
			"result", event.Result,
			"ip_address", event.IPAddress,
			"timestamp", event.Timestamp)
	case "warn":
		// Only log failed access attempts as warnings
		if event.Result != "allowed=true" {
			aa.logger.Warn("Access denied",
				"event_id", event.ID,
				"user_id", event.UserID,
				"resource", event.Resource,
				"action", event.Action,
				"result", event.Result,
				"ip_address", event.IPAddress,
				"timestamp", event.Timestamp)
		}
	case "error":
		// Only log errors and critical security events
		if event.Type == "security_violation" || event.Result == "error" {
			aa.logger.Error("Security audit event",
				"event_id", event.ID,
				"type", event.Type,
				"user_id", event.UserID,
				"resource", event.Resource,
				"action", event.Action,
				"result", event.Result,
				"ip_address", event.IPAddress,
				"timestamp", event.Timestamp,
				"details", event.Details)
		}
	}

	// Additional processing could include:
	// - Storing events in a database
	// - Sending alerts for critical events
	// - Aggregating metrics
	// - Forwarding to SIEM systems
}

// GetAuditEvents retrieves audit events (placeholder for database implementation)
func (aa *AccessAuditor) GetAuditEvents(ctx context.Context, filters map[string]interface{}) ([]*AuditEvent, error) {
	// In a real implementation, this would query a database
	// For now, return empty slice
	return []*AuditEvent{}, nil
}

// GetAuditStatistics returns audit statistics
func (aa *AccessAuditor) GetAuditStatistics(ctx context.Context, timeRange *TimeRange) (*AuditStatistics, error) {
	// In a real implementation, this would aggregate data from storage
	return &AuditStatistics{
		TotalEvents:        0,
		SuccessfulAccess:   0,
		FailedAccess:       0,
		SecurityViolations: 0,
		UniqueUsers:        0,
		UniqueResources:    0,
		TimeRange:          timeRange,
		GeneratedAt:        time.Now(),
	}, nil
}

// AuditStatistics represents audit statistics
type AuditStatistics struct {
	TotalEvents        int64          `json:"total_events"`
	SuccessfulAccess   int64          `json:"successful_access"`
	FailedAccess       int64          `json:"failed_access"`
	SecurityViolations int64          `json:"security_violations"`
	UniqueUsers        int64          `json:"unique_users"`
	UniqueResources    int64          `json:"unique_resources"`
	TopUsers           []UserStat     `json:"top_users"`
	TopResources       []ResourceStat `json:"top_resources"`
	TimeRange          *TimeRange     `json:"time_range"`
	GeneratedAt        time.Time      `json:"generated_at"`
}

// UserStat represents user access statistics
type UserStat struct {
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	AccessCount int64     `json:"access_count"`
	FailedCount int64     `json:"failed_count"`
	LastAccess  time.Time `json:"last_access"`
}

// ResourceStat represents resource access statistics
type ResourceStat struct {
	Resource    string    `json:"resource"`
	AccessCount int64     `json:"access_count"`
	FailedCount int64     `json:"failed_count"`
	UniqueUsers int64     `json:"unique_users"`
	LastAccess  time.Time `json:"last_access"`
}

// SecurityAlert represents a security alert
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	UserID      string                 `json:"user_id"`
	Resource    string                 `json:"resource"`
	IPAddress   string                 `json:"ip_address"`
	Timestamp   time.Time              `json:"timestamp"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertManager manages security alerts
type AlertManager struct {
	logger *logger.Logger
	config *AlertConfig
	alerts map[string]*SecurityAlert
	rules  []*AlertRule
}

// AlertConfig configuration for alert manager
type AlertConfig struct {
	EnableAlerts         bool          `json:"enable_alerts"`
	MaxAlerts            int           `json:"max_alerts"`
	RetentionPeriod      time.Duration `json:"retention_period"`
	NotificationChannels []string      `json:"notification_channels"`
}

// AlertRule defines conditions for generating alerts
type AlertRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Conditions  []*AlertCondition      `json:"conditions"`
	Actions     []*AlertAction         `json:"actions"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertCondition defines a condition for triggering an alert
type AlertCondition struct {
	Field      string      `json:"field"`
	Operator   string      `json:"operator"`
	Value      interface{} `json:"value"`
	TimeWindow string      `json:"time_window"`
}

// AlertAction defines an action to take when an alert is triggered
type AlertAction struct {
	Type       string                 `json:"type"`
	Target     string                 `json:"target"`
	Parameters map[string]interface{} `json:"parameters"`
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config *AlertConfig, logger *logger.Logger) *AlertManager {
	if config == nil {
		config = DefaultAlertConfig()
	}

	return &AlertManager{
		logger: logger,
		config: config,
		alerts: make(map[string]*SecurityAlert),
		rules:  []*AlertRule{},
	}
}

// DefaultAlertConfig returns default alert configuration
func DefaultAlertConfig() *AlertConfig {
	return &AlertConfig{
		EnableAlerts:         true,
		MaxAlerts:            10000,
		RetentionPeriod:      30 * 24 * time.Hour,
		NotificationChannels: []string{"email", "slack"},
	}
}

// Start starts the alert manager
func (am *AlertManager) Start(ctx context.Context) error {
	am.logger.Info("Starting alert manager")

	// Initialize default alert rules
	am.initializeDefaultRules()

	return nil
}

// CreateAlert creates a new security alert
func (am *AlertManager) CreateAlert(alert *SecurityAlert) error {
	if len(am.alerts) >= am.config.MaxAlerts {
		return fmt.Errorf("maximum number of alerts reached: %d", am.config.MaxAlerts)
	}

	am.alerts[alert.ID] = alert
	am.logger.Warn("Security alert created",
		"alert_id", alert.ID,
		"type", alert.Type,
		"severity", alert.Severity,
		"user_id", alert.UserID,
		"resource", alert.Resource,
		"ip_address", alert.IPAddress)

	return nil
}

// GetAlert gets an alert by ID
func (am *AlertManager) GetAlert(alertID string) (*SecurityAlert, error) {
	alert, exists := am.alerts[alertID]
	if !exists {
		return nil, fmt.Errorf("alert not found: %s", alertID)
	}
	return alert, nil
}

// ListAlerts lists all alerts
func (am *AlertManager) ListAlerts() []*SecurityAlert {
	alerts := make([]*SecurityAlert, 0, len(am.alerts))
	for _, alert := range am.alerts {
		alerts = append(alerts, alert)
	}
	return alerts
}

// initializeDefaultRules creates default alert rules
func (am *AlertManager) initializeDefaultRules() {
	defaultRules := []*AlertRule{
		{
			ID:          "failed_login_attempts",
			Name:        "Multiple Failed Login Attempts",
			Description: "Alert when user has multiple failed login attempts",
			Type:        "security",
			Severity:    "high",
			Enabled:     true,
			Conditions: []*AlertCondition{
				{
					Field:      "result",
					Operator:   "eq",
					Value:      "allowed=false",
					TimeWindow: "5m",
				},
			},
			Actions: []*AlertAction{
				{
					Type:   "notification",
					Target: "security-team",
					Parameters: map[string]interface{}{
						"channel": "email",
						"subject": "Security Alert: Multiple Failed Login Attempts",
					},
				},
			},
		},
		{
			ID:          "privilege_escalation",
			Name:        "Privilege Escalation Attempt",
			Description: "Alert when user attempts to access resources above their privilege level",
			Type:        "security",
			Severity:    "critical",
			Enabled:     true,
			Conditions: []*AlertCondition{
				{
					Field:    "action",
					Operator: "in",
					Value:    []interface{}{"admin", "delete", "modify_permissions"},
				},
			},
			Actions: []*AlertAction{
				{
					Type:   "notification",
					Target: "security-team",
					Parameters: map[string]interface{}{
						"channel": "slack",
						"urgency": "high",
					},
				},
			},
		},
	}

	am.rules = append(am.rules, defaultRules...)
	am.logger.Info("Default alert rules initialized", "count", len(defaultRules))
}
