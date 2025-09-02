package monitoring

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var alertTracer = otel.Tracer("hackai/monitoring/alerts")

// AlertManager manages alerts and notifications
type AlertManager struct {
	alerts       map[string]*Alert
	rules        map[string]*AlertRule
	channels     map[string]AlertChannel
	suppressions map[string]*AlertSuppression
	escalations  map[string]*AlertEscalation
	config       *MonitoringConfig
	logger       *logger.Logger
	mutex        sync.RWMutex
}

// Alert represents an alert instance
type Alert struct {
	ID             string                 `json:"id"`
	RuleID         string                 `json:"rule_id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Severity       AlertSeverity          `json:"severity"`
	Status         AlertStatus            `json:"status"`
	Source         string                 `json:"source"`
	Component      string                 `json:"component"`
	Tags           []string               `json:"tags"`
	Labels         map[string]string      `json:"labels"`
	Annotations    map[string]string      `json:"annotations"`
	Value          interface{}            `json:"value"`
	Threshold      interface{}            `json:"threshold"`
	Condition      string                 `json:"condition"`
	FiredAt        time.Time              `json:"fired_at"`
	ResolvedAt     *time.Time             `json:"resolved_at,omitempty"`
	LastNotified   *time.Time             `json:"last_notified,omitempty"`
	NotifyCount    int                    `json:"notify_count"`
	Escalated      bool                   `json:"escalated"`
	Suppressed     bool                   `json:"suppressed"`
	Acknowledged   bool                   `json:"acknowledged"`
	AcknowledgedBy string                 `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time             `json:"acknowledged_at,omitempty"`
	History        []*AlertEvent          `json:"history"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// AlertRule defines conditions for triggering alerts
type AlertRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	Description          string                 `json:"description"`
	Enabled              bool                   `json:"enabled"`
	Severity             AlertSeverity          `json:"severity"`
	Source               string                 `json:"source"`
	Component            string                 `json:"component"`
	Metric               string                 `json:"metric"`
	Condition            AlertCondition         `json:"condition"`
	Threshold            interface{}            `json:"threshold"`
	Duration             time.Duration          `json:"duration"`
	EvaluationInterval   time.Duration          `json:"evaluation_interval"`
	Labels               map[string]string      `json:"labels"`
	Annotations          map[string]string      `json:"annotations"`
	NotificationChannels []string               `json:"notification_channels"`
	EscalationPolicy     string                 `json:"escalation_policy,omitempty"`
	SuppressionRules     []string               `json:"suppression_rules"`
	Dependencies         []string               `json:"dependencies"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// AlertEvent represents an event in alert history
type AlertEvent struct {
	ID        string                 `json:"id"`
	AlertID   string                 `json:"alert_id"`
	Type      AlertEventType         `json:"type"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details"`
	Timestamp time.Time              `json:"timestamp"`
	User      string                 `json:"user,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// AlertChannel defines notification channels
type AlertChannel interface {
	Send(ctx context.Context, alert *Alert) error
	GetType() AlertChannelType
	GetConfig() map[string]interface{}
}

// AlertSuppression defines alert suppression rules
type AlertSuppression struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Enabled     bool                    `json:"enabled"`
	Conditions  []*SuppressionCondition `json:"conditions"`
	StartTime   *time.Time              `json:"start_time,omitempty"`
	EndTime     *time.Time              `json:"end_time,omitempty"`
	Recurring   bool                    `json:"recurring"`
	Schedule    string                  `json:"schedule,omitempty"`
	CreatedBy   string                  `json:"created_by"`
	CreatedAt   time.Time               `json:"created_at"`
	Metadata    map[string]interface{}  `json:"metadata"`
}

// AlertEscalation defines escalation policies
type AlertEscalation struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Steps       []*EscalationStep      `json:"steps"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Supporting structures
type SuppressionCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

type EscalationStep struct {
	Level          int           `json:"level"`
	Delay          time.Duration `json:"delay"`
	Channels       []string      `json:"channels"`
	RequireAck     bool          `json:"require_ack"`
	AckTimeout     time.Duration `json:"ack_timeout"`
	RepeatInterval time.Duration `json:"repeat_interval,omitempty"`
	MaxRepeats     int           `json:"max_repeats,omitempty"`
}

// Enums for alerts
type AlertSeverity string
type AlertStatus string
type AlertCondition string
type AlertEventType string
type AlertChannelType string

const (
	// Alert Severities
	SeverityCritical AlertSeverity = "critical"
	SeverityHigh     AlertSeverity = "high"
	SeverityMedium   AlertSeverity = "medium"
	SeverityLow      AlertSeverity = "low"
	SeverityInfo     AlertSeverity = "info"

	// Alert Statuses
	StatusFiring       AlertStatus = "firing"
	StatusResolved     AlertStatus = "resolved"
	StatusSuppressed   AlertStatus = "suppressed"
	StatusAcknowledged AlertStatus = "acknowledged"

	// Alert Conditions
	ConditionGreaterThan AlertCondition = "greater_than"
	ConditionLessThan    AlertCondition = "less_than"
	ConditionEquals      AlertCondition = "equals"
	ConditionNotEquals   AlertCondition = "not_equals"
	ConditionContains    AlertCondition = "contains"
	ConditionNotContains AlertCondition = "not_contains"
	ConditionIncreaseBy  AlertCondition = "increase_by"
	ConditionDecreaseBy  AlertCondition = "decrease_by"

	// Alert Event Types
	EventTypeFired        AlertEventType = "fired"
	EventTypeResolved     AlertEventType = "resolved"
	EventTypeAcknowledged AlertEventType = "acknowledged"
	EventTypeEscalated    AlertEventType = "escalated"
	EventTypeSuppressed   AlertEventType = "suppressed"
	EventTypeNotified     AlertEventType = "notified"

	// Alert Channel Types
	ChannelTypeEmail     AlertChannelType = "email"
	ChannelTypeSlack     AlertChannelType = "slack"
	ChannelTypeWebhook   AlertChannelType = "webhook"
	ChannelTypeSMS       AlertChannelType = "sms"
	ChannelTypePagerDuty AlertChannelType = "pagerduty"
)

// NewAlertManager creates a new alert manager
func NewAlertManager(config *MonitoringConfig, logger *logger.Logger) (*AlertManager, error) {
	am := &AlertManager{
		alerts:       make(map[string]*Alert),
		rules:        make(map[string]*AlertRule),
		channels:     make(map[string]AlertChannel),
		suppressions: make(map[string]*AlertSuppression),
		escalations:  make(map[string]*AlertEscalation),
		config:       config,
		logger:       logger,
	}

	// Initialize default channels
	if err := am.initializeDefaultChannels(); err != nil {
		return nil, fmt.Errorf("failed to initialize default channels: %w", err)
	}

	return am, nil
}

// CreateAlert creates a new alert
func (am *AlertManager) CreateAlert(ctx context.Context, ruleID string, value interface{}) (*Alert, error) {
	ctx, span := alertTracer.Start(ctx, "alert_manager.create_alert",
		trace.WithAttributes(
			attribute.String("rule.id", ruleID),
		),
	)
	defer span.End()

	am.mutex.Lock()
	defer am.mutex.Unlock()

	rule, exists := am.rules[ruleID]
	if !exists {
		return nil, fmt.Errorf("alert rule not found: %s", ruleID)
	}

	alert := &Alert{
		ID:          uuid.New().String(),
		RuleID:      ruleID,
		Name:        rule.Name,
		Description: rule.Description,
		Severity:    rule.Severity,
		Status:      StatusFiring,
		Source:      rule.Source,
		Component:   rule.Component,
		Labels:      make(map[string]string),
		Annotations: make(map[string]string),
		Value:       value,
		Threshold:   rule.Threshold,
		Condition:   string(rule.Condition),
		FiredAt:     time.Now(),
		History:     make([]*AlertEvent, 0),
		Metadata:    make(map[string]interface{}),
	}

	// Copy labels and annotations from rule
	for k, v := range rule.Labels {
		alert.Labels[k] = v
	}
	for k, v := range rule.Annotations {
		alert.Annotations[k] = v
	}

	// Check if alert should be suppressed
	if am.shouldSuppressAlert(alert) {
		alert.Status = StatusSuppressed
		alert.Suppressed = true
	}

	// Add to alerts map
	am.alerts[alert.ID] = alert

	// Add fired event to history
	am.addAlertEvent(alert, EventTypeFired, "Alert fired", nil)

	span.SetAttributes(
		attribute.String("alert.id", alert.ID),
		attribute.String("alert.severity", string(alert.Severity)),
		attribute.String("alert.status", string(alert.Status)),
	)

	am.logger.Info("Alert created",
		"alert_id", alert.ID,
		"rule_id", ruleID,
		"severity", alert.Severity,
		"status", alert.Status,
		"component", alert.Component)

	return alert, nil
}

// ProcessAlerts processes all active alerts
func (am *AlertManager) ProcessAlerts(ctx context.Context) error {
	ctx, span := alertTracer.Start(ctx, "alert_manager.process_alerts")
	defer span.End()

	am.mutex.RLock()
	alerts := make([]*Alert, 0, len(am.alerts))
	for _, alert := range am.alerts {
		if alert.Status == StatusFiring && !alert.Suppressed {
			alerts = append(alerts, alert)
		}
	}
	am.mutex.RUnlock()

	for _, alert := range alerts {
		if err := am.processAlert(ctx, alert); err != nil {
			am.logger.Error("Failed to process alert",
				"alert_id", alert.ID,
				"error", err)
		}
	}

	span.SetAttributes(
		attribute.Int("alerts.processed", len(alerts)),
	)

	return nil
}

// processAlert processes a single alert
func (am *AlertManager) processAlert(ctx context.Context, alert *Alert) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	rule, exists := am.rules[alert.RuleID]
	if !exists {
		return fmt.Errorf("alert rule not found: %s", alert.RuleID)
	}

	// Check if alert needs notification
	shouldNotify := false
	now := time.Now()

	if alert.LastNotified == nil {
		// First notification
		shouldNotify = true
	} else {
		// Check if enough time has passed for repeat notification
		timeSinceLastNotification := now.Sub(*alert.LastNotified)
		if timeSinceLastNotification >= rule.EvaluationInterval {
			shouldNotify = true
		}
	}

	if shouldNotify {
		// Send notifications
		for _, channelID := range rule.NotificationChannels {
			if channel, exists := am.channels[channelID]; exists {
				if err := channel.Send(ctx, alert); err != nil {
					am.logger.Error("Failed to send alert notification",
						"alert_id", alert.ID,
						"channel", channelID,
						"error", err)
				} else {
					am.logger.Debug("Alert notification sent",
						"alert_id", alert.ID,
						"channel", channelID)
				}
			}
		}

		// Update notification tracking
		alert.LastNotified = &now
		alert.NotifyCount++

		// Add notification event
		am.addAlertEvent(alert, EventTypeNotified, "Alert notification sent", map[string]interface{}{
			"channels": rule.NotificationChannels,
			"count":    alert.NotifyCount,
		})

		// Check for escalation
		if rule.EscalationPolicy != "" && !alert.Escalated {
			if err := am.checkEscalation(ctx, alert, rule); err != nil {
				am.logger.Error("Failed to check escalation",
					"alert_id", alert.ID,
					"error", err)
			}
		}
	}

	return nil
}

// ResolveAlert resolves an alert
func (am *AlertManager) ResolveAlert(ctx context.Context, alertID string, resolvedBy string) error {
	ctx, span := alertTracer.Start(ctx, "alert_manager.resolve_alert",
		trace.WithAttributes(
			attribute.String("alert.id", alertID),
			attribute.String("resolved.by", resolvedBy),
		),
	)
	defer span.End()

	am.mutex.Lock()
	defer am.mutex.Unlock()

	alert, exists := am.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	if alert.Status == StatusResolved {
		return fmt.Errorf("alert already resolved: %s", alertID)
	}

	now := time.Now()
	alert.Status = StatusResolved
	alert.ResolvedAt = &now

	// Add resolved event
	am.addAlertEvent(alert, EventTypeResolved, "Alert resolved", map[string]interface{}{
		"resolved_by": resolvedBy,
	})

	am.logger.Info("Alert resolved",
		"alert_id", alertID,
		"resolved_by", resolvedBy)

	return nil
}

// AcknowledgeAlert acknowledges an alert
func (am *AlertManager) AcknowledgeAlert(ctx context.Context, alertID string, acknowledgedBy string) error {
	ctx, span := alertTracer.Start(ctx, "alert_manager.acknowledge_alert",
		trace.WithAttributes(
			attribute.String("alert.id", alertID),
			attribute.String("acknowledged.by", acknowledgedBy),
		),
	)
	defer span.End()

	am.mutex.Lock()
	defer am.mutex.Unlock()

	alert, exists := am.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	if alert.Acknowledged {
		return fmt.Errorf("alert already acknowledged: %s", alertID)
	}

	now := time.Now()
	alert.Acknowledged = true
	alert.AcknowledgedBy = acknowledgedBy
	alert.AcknowledgedAt = &now
	alert.Status = StatusAcknowledged

	// Add acknowledged event
	am.addAlertEvent(alert, EventTypeAcknowledged, "Alert acknowledged", map[string]interface{}{
		"acknowledged_by": acknowledgedBy,
	})

	am.logger.Info("Alert acknowledged",
		"alert_id", alertID,
		"acknowledged_by", acknowledgedBy)

	return nil
}

// GetAlertSummary returns a summary of alerts
func (am *AlertManager) GetAlertSummary(ctx context.Context) (*AlertSummary, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	summary := &AlertSummary{
		AlertsByType:      make(map[string]int64),
		AlertsByComponent: make(map[string]int64),
		RecentAlerts:      make([]*Alert, 0),
		Metadata:          make(map[string]interface{}),
	}

	var recentAlerts []*Alert

	for _, alert := range am.alerts {
		summary.TotalAlerts++

		switch alert.Status {
		case StatusFiring:
			summary.ActiveAlerts++
		case StatusResolved:
			summary.ResolvedAlerts++
		}

		switch alert.Severity {
		case SeverityCritical:
			summary.CriticalAlerts++
		case SeverityHigh, SeverityMedium:
			summary.WarningAlerts++
		case SeverityLow, SeverityInfo:
			summary.InfoAlerts++
		}

		// Count by type (severity)
		summary.AlertsByType[string(alert.Severity)]++

		// Count by component
		summary.AlertsByComponent[alert.Component]++

		// Collect recent alerts (last 24 hours)
		if time.Since(alert.FiredAt) <= 24*time.Hour {
			recentAlerts = append(recentAlerts, alert)
		}
	}

	// Sort recent alerts by fired time (newest first)
	sort.Slice(recentAlerts, func(i, j int) bool {
		return recentAlerts[i].FiredAt.After(recentAlerts[j].FiredAt)
	})

	// Limit to 10 most recent
	if len(recentAlerts) > 10 {
		recentAlerts = recentAlerts[:10]
	}

	summary.RecentAlerts = recentAlerts

	return summary, nil
}

// Helper methods

func (am *AlertManager) addAlertEvent(alert *Alert, eventType AlertEventType, message string, details map[string]interface{}) {
	event := &AlertEvent{
		ID:        uuid.New().String(),
		AlertID:   alert.ID,
		Type:      eventType,
		Message:   message,
		Details:   details,
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	if details == nil {
		event.Details = make(map[string]interface{})
	}

	alert.History = append(alert.History, event)

	// Keep only last 100 events
	if len(alert.History) > 100 {
		alert.History = alert.History[1:]
	}
}

func (am *AlertManager) shouldSuppressAlert(alert *Alert) bool {
	for _, suppression := range am.suppressions {
		if !suppression.Enabled {
			continue
		}

		// Check time-based suppression
		now := time.Now()
		if suppression.StartTime != nil && now.Before(*suppression.StartTime) {
			continue
		}
		if suppression.EndTime != nil && now.After(*suppression.EndTime) {
			continue
		}

		// Check conditions
		if am.matchesSuppressionConditions(alert, suppression.Conditions) {
			return true
		}
	}

	return false
}

func (am *AlertManager) matchesSuppressionConditions(alert *Alert, conditions []*SuppressionCondition) bool {
	for _, condition := range conditions {
		if !am.evaluateSuppressionCondition(alert, condition) {
			return false
		}
	}
	return true
}

func (am *AlertManager) evaluateSuppressionCondition(alert *Alert, condition *SuppressionCondition) bool {
	// Simplified condition evaluation
	switch condition.Field {
	case "severity":
		return string(alert.Severity) == condition.Value
	case "component":
		return alert.Component == condition.Value
	case "source":
		return alert.Source == condition.Value
	}
	return false
}

func (am *AlertManager) checkEscalation(ctx context.Context, alert *Alert, rule *AlertRule) error {
	// TODO: Implement escalation logic
	return nil
}

func (am *AlertManager) initializeDefaultChannels() error {
	// TODO: Initialize default notification channels
	return nil
}
