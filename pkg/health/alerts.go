package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// AlertLevel represents the severity of an alert
type AlertLevel string

const (
	AlertLevelInfo     AlertLevel = "info"
	AlertLevelWarning  AlertLevel = "warning"
	AlertLevelCritical AlertLevel = "critical"
)

// Alert represents a health check alert
type Alert struct {
	ID          string                 `json:"id"`
	CheckName   string                 `json:"check_name"`
	Level       AlertLevel             `json:"level"`
	Status      Status                 `json:"status"`
	Message     string                 `json:"message"`
	Error       string                 `json:"error,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Occurrences int                    `json:"occurrences"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
}

// AlertRule defines when to trigger alerts
type AlertRule struct {
	CheckName        string        `json:"check_name"`
	StatusTriggers   []Status      `json:"status_triggers"`
	MinOccurrences   int           `json:"min_occurrences"`
	TimeWindow       time.Duration `json:"time_window"`
	CooldownPeriod   time.Duration `json:"cooldown_period"`
	NotificationChannels []string  `json:"notification_channels"`
	Enabled          bool          `json:"enabled"`
}

// NotificationChannel defines how to send notifications
type NotificationChannel interface {
	Name() string
	Send(ctx context.Context, alert Alert) error
	IsEnabled() bool
}

// AlertManager manages health check alerts
type AlertManager struct {
	rules        map[string]*AlertRule
	alerts       map[string]*Alert
	channels     map[string]NotificationChannel
	history      []*Alert
	maxHistory   int
	logger       *logger.Logger
	mutex        sync.RWMutex
	occurrences  map[string]*AlertOccurrence
}

// AlertOccurrence tracks alert occurrences for rules
type AlertOccurrence struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
	LastAlert *time.Time
}

// AlertManagerConfig configures the alert manager
type AlertManagerConfig struct {
	MaxHistory int `json:"max_history"`
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config AlertManagerConfig, logger *logger.Logger) *AlertManager {
	if config.MaxHistory == 0 {
		config.MaxHistory = 1000
	}

	return &AlertManager{
		rules:       make(map[string]*AlertRule),
		alerts:      make(map[string]*Alert),
		channels:    make(map[string]NotificationChannel),
		history:     make([]*Alert, 0),
		maxHistory:  config.MaxHistory,
		logger:      logger,
		occurrences: make(map[string]*AlertOccurrence),
	}
}

// AddRule adds an alert rule
func (am *AlertManager) AddRule(rule AlertRule) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	am.rules[rule.CheckName] = &rule
	am.logger.Infof("Added alert rule for check: %s", rule.CheckName)
}

// RemoveRule removes an alert rule
func (am *AlertManager) RemoveRule(checkName string) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	delete(am.rules, checkName)
	delete(am.occurrences, checkName)
	am.logger.Infof("Removed alert rule for check: %s", checkName)
}

// AddNotificationChannel adds a notification channel
func (am *AlertManager) AddNotificationChannel(channel NotificationChannel) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	am.channels[channel.Name()] = channel
	am.logger.Infof("Added notification channel: %s", channel.Name())
}

// ProcessCheckResult processes a health check result and triggers alerts if needed
func (am *AlertManager) ProcessCheckResult(ctx context.Context, result CheckResult) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	rule, exists := am.rules[result.Name]
	if !exists || !rule.Enabled {
		return
	}

	// Check if status triggers an alert
	shouldAlert := false
	for _, trigger := range rule.StatusTriggers {
		if result.Status == trigger {
			shouldAlert = true
			break
		}
	}

	if !shouldAlert {
		// Check if we should resolve an existing alert
		am.resolveAlert(result.Name, result.Timestamp)
		return
	}

	// Track occurrences
	occurrence := am.occurrences[result.Name]
	if occurrence == nil {
		occurrence = &AlertOccurrence{
			FirstSeen: result.Timestamp,
		}
		am.occurrences[result.Name] = occurrence
	}

	occurrence.Count++
	occurrence.LastSeen = result.Timestamp

	// Check if we should trigger an alert based on occurrences and time window
	if occurrence.Count >= rule.MinOccurrences {
		timeInWindow := occurrence.LastSeen.Sub(occurrence.FirstSeen) <= rule.TimeWindow
		cooldownPassed := occurrence.LastAlert == nil || 
			result.Timestamp.Sub(*occurrence.LastAlert) >= rule.CooldownPeriod

		if (rule.TimeWindow == 0 || timeInWindow) && cooldownPassed {
			am.triggerAlert(ctx, result, rule, occurrence)
			now := result.Timestamp
			occurrence.LastAlert = &now
		}
	}
}

// triggerAlert creates and sends an alert
func (am *AlertManager) triggerAlert(ctx context.Context, result CheckResult, rule *AlertRule, occurrence *AlertOccurrence) {
	alertLevel := am.getAlertLevel(result.Status, result.Critical)
	
	alert := &Alert{
		ID:          fmt.Sprintf("%s-%d", result.Name, time.Now().UnixNano()),
		CheckName:   result.Name,
		Level:       alertLevel,
		Status:      result.Status,
		Message:     result.Message,
		Error:       result.Error,
		Timestamp:   result.Timestamp,
		Resolved:    false,
		Metadata:    result.Metadata,
		Occurrences: occurrence.Count,
		FirstSeen:   occurrence.FirstSeen,
		LastSeen:    occurrence.LastSeen,
	}

	// Store alert
	am.alerts[result.Name] = alert
	am.addToHistory(alert)

	// Send notifications
	for _, channelName := range rule.NotificationChannels {
		if channel, exists := am.channels[channelName]; exists && channel.IsEnabled() {
			go func(ch NotificationChannel, a Alert) {
				if err := ch.Send(ctx, a); err != nil {
					am.logger.Errorf("Failed to send alert via %s: %v", ch.Name(), err)
				}
			}(channel, *alert)
		}
	}

	// Log alert
	fields := logger.Fields{
		"alert_id":    alert.ID,
		"check_name":  alert.CheckName,
		"level":       alert.Level,
		"status":      alert.Status,
		"occurrences": alert.Occurrences,
	}

	switch alertLevel {
	case AlertLevelCritical:
		am.logger.WithFields(fields).Error("Critical health alert triggered")
	case AlertLevelWarning:
		am.logger.WithFields(fields).Warn("Warning health alert triggered")
	default:
		am.logger.WithFields(fields).Info("Info health alert triggered")
	}
}

// resolveAlert resolves an existing alert
func (am *AlertManager) resolveAlert(checkName string, timestamp time.Time) {
	if alert, exists := am.alerts[checkName]; exists && !alert.Resolved {
		alert.Resolved = true
		alert.ResolvedAt = &timestamp

		// Reset occurrences
		delete(am.occurrences, checkName)

		// Log resolution
		am.logger.WithFields(logger.Fields{
			"alert_id":   alert.ID,
			"check_name": alert.CheckName,
			"level":      alert.Level,
		}).Info("Health alert resolved")
	}
}

// getAlertLevel determines alert level based on status and criticality
func (am *AlertManager) getAlertLevel(status Status, critical bool) AlertLevel {
	switch status {
	case StatusUnhealthy:
		if critical {
			return AlertLevelCritical
		}
		return AlertLevelWarning
	case StatusDegraded:
		return AlertLevelWarning
	default:
		return AlertLevelInfo
	}
}

// addToHistory adds an alert to history
func (am *AlertManager) addToHistory(alert *Alert) {
	am.history = append(am.history, alert)
	
	// Trim history if it exceeds max size
	if len(am.history) > am.maxHistory {
		am.history = am.history[len(am.history)-am.maxHistory:]
	}
}

// GetActiveAlerts returns all active (unresolved) alerts
func (am *AlertManager) GetActiveAlerts() map[string]*Alert {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	active := make(map[string]*Alert)
	for name, alert := range am.alerts {
		if !alert.Resolved {
			active[name] = alert
		}
	}

	return active
}

// GetAlertHistory returns alert history
func (am *AlertManager) GetAlertHistory(limit int) []*Alert {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	if limit == 0 || limit > len(am.history) {
		limit = len(am.history)
	}

	// Return most recent alerts
	start := len(am.history) - limit
	if start < 0 {
		start = 0
	}

	result := make([]*Alert, limit)
	copy(result, am.history[start:])
	return result
}

// GetAlertStats returns alert statistics
func (am *AlertManager) GetAlertStats() map[string]interface{} {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	activeCount := 0
	levelCounts := map[AlertLevel]int{
		AlertLevelInfo:     0,
		AlertLevelWarning:  0,
		AlertLevelCritical: 0,
	}

	for _, alert := range am.alerts {
		if !alert.Resolved {
			activeCount++
			levelCounts[alert.Level]++
		}
	}

	return map[string]interface{}{
		"total_rules":      len(am.rules),
		"active_alerts":    activeCount,
		"total_history":    len(am.history),
		"level_counts":     levelCounts,
		"notification_channels": len(am.channels),
	}
}

// Built-in notification channels

// LogNotificationChannel sends alerts to logs
type LogNotificationChannel struct {
	name    string
	logger  *logger.Logger
	enabled bool
}

// NewLogNotificationChannel creates a log notification channel
func NewLogNotificationChannel(name string, logger *logger.Logger) *LogNotificationChannel {
	return &LogNotificationChannel{
		name:    name,
		logger:  logger,
		enabled: true,
	}
}

// Name returns the channel name
func (lnc *LogNotificationChannel) Name() string {
	return lnc.name
}

// Send sends an alert to logs
func (lnc *LogNotificationChannel) Send(ctx context.Context, alert Alert) error {
	fields := logger.Fields{
		"alert_id":    alert.ID,
		"check_name":  alert.CheckName,
		"level":       alert.Level,
		"status":      alert.Status,
		"occurrences": alert.Occurrences,
		"message":     alert.Message,
	}

	if alert.Error != "" {
		fields["error"] = alert.Error
	}

	switch alert.Level {
	case AlertLevelCritical:
		lnc.logger.WithFields(fields).Error("ALERT: Critical health issue detected")
	case AlertLevelWarning:
		lnc.logger.WithFields(fields).Warn("ALERT: Health warning detected")
	default:
		lnc.logger.WithFields(fields).Info("ALERT: Health notification")
	}

	return nil
}

// IsEnabled returns whether the channel is enabled
func (lnc *LogNotificationChannel) IsEnabled() bool {
	return lnc.enabled
}

// SetEnabled enables or disables the channel
func (lnc *LogNotificationChannel) SetEnabled(enabled bool) {
	lnc.enabled = enabled
}

// WebhookNotificationChannel sends alerts to webhooks
type WebhookNotificationChannel struct {
	name     string
	url      string
	enabled  bool
	timeout  time.Duration
}

// NewWebhookNotificationChannel creates a webhook notification channel
func NewWebhookNotificationChannel(name, url string) *WebhookNotificationChannel {
	return &WebhookNotificationChannel{
		name:    name,
		url:     url,
		enabled: true,
		timeout: 10 * time.Second,
	}
}

// Name returns the channel name
func (wnc *WebhookNotificationChannel) Name() string {
	return wnc.name
}

// Send sends an alert to webhook
func (wnc *WebhookNotificationChannel) Send(ctx context.Context, alert Alert) error {
	// This is a placeholder implementation
	// In production, you'd make an HTTP POST request to the webhook URL
	// with the alert data as JSON
	
	// For now, just return success
	return nil
}

// IsEnabled returns whether the channel is enabled
func (wnc *WebhookNotificationChannel) IsEnabled() bool {
	return wnc.enabled
}

// SetEnabled enables or disables the channel
func (wnc *WebhookNotificationChannel) SetEnabled(enabled bool) {
	wnc.enabled = enabled
}
