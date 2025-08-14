package security

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SecurityAlertManager manages security alerts and notifications
type SecurityAlertManager struct {
	config *AlertingConfig
	logger Logger

	// Alert channels
	channels map[string]SecurityAlertChannel

	// Alert rules and conditions
	rules      []*SecurityAlertRule
	conditions map[string]*AlertCondition

	// Alert state management
	activeAlerts map[string]*Alert
	alertHistory []*Alert
	suppressions map[string]*AlertSuppression

	// Escalation management
	escalations map[string]*AlertEscalation

	// Background processing
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Channels for alert processing
	alertChan      chan *Alert
	evaluationChan chan *AlertEvaluation

	// Synchronization
	mu sync.RWMutex
}

// AlertingConfig configuration for alerting system
type AlertingConfig struct {
	Enabled              bool                 `json:"enabled"`
	MaxActiveAlerts      int                  `json:"max_active_alerts"`
	AlertRetentionPeriod time.Duration        `json:"alert_retention_period"`
	EvaluationInterval   time.Duration        `json:"evaluation_interval"`
	BufferSize           int                  `json:"buffer_size"`
	Channels             []*ChannelConfig     `json:"channels"`
	Rules                []*AlertRuleConfig   `json:"rules"`
	Escalations          []*EscalationConfig  `json:"escalations"`
	Suppressions         []*SuppressionConfig `json:"suppressions"`
}

// Alert represents a security alert
type Alert struct {
	ID              string                 `json:"id"`
	RuleID          string                 `json:"rule_id"`
	Type            string                 `json:"type"`
	Severity        string                 `json:"severity"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Status          string                 `json:"status"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	ResolvedAt      *time.Time             `json:"resolved_at,omitempty"`
	Source          string                 `json:"source"`
	Component       string                 `json:"component"`
	ThreatScore     float64                `json:"threat_score"`
	Metadata        map[string]interface{} `json:"metadata"`
	Notifications   []*AlertNotification   `json:"notifications"`
	Escalated       bool                   `json:"escalated"`
	EscalationLevel int                    `json:"escalation_level"`
	SuppressedUntil *time.Time             `json:"suppressed_until,omitempty"`
}

// SecurityAlertRule defines conditions for triggering alerts (renamed to avoid conflicts)
type SecurityAlertRule struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Enabled        bool                   `json:"enabled"`
	Condition      string                 `json:"condition"`
	Threshold      float64                `json:"threshold"`
	Severity       string                 `json:"severity"`
	Description    string                 `json:"description"`
	Component      string                 `json:"component"`
	MetricName     string                 `json:"metric_name"`
	Operator       string                 `json:"operator"`
	TimeWindow     time.Duration          `json:"time_window"`
	MinOccurrences int                    `json:"min_occurrences"`
	Channels       []string               `json:"channels"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// AlertCondition represents an alert condition evaluation
type AlertCondition struct {
	RuleID          string                 `json:"rule_id"`
	MetricValue     float64                `json:"metric_value"`
	Threshold       float64                `json:"threshold"`
	Operator        string                 `json:"operator"`
	Satisfied       bool                   `json:"satisfied"`
	LastEvaluation  time.Time              `json:"last_evaluation"`
	ConsecutiveHits int                    `json:"consecutive_hits"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// AlertEvaluation represents an alert evaluation request
type AlertEvaluation struct {
	RuleID      string                 `json:"rule_id"`
	MetricName  string                 `json:"metric_name"`
	MetricValue float64                `json:"metric_value"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertNotification represents a notification sent for an alert
type AlertNotification struct {
	ID         string                 `json:"id"`
	AlertID    string                 `json:"alert_id"`
	Channel    string                 `json:"channel"`
	Status     string                 `json:"status"`
	SentAt     time.Time              `json:"sent_at"`
	Error      string                 `json:"error,omitempty"`
	RetryCount int                    `json:"retry_count"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// AlertEscalation represents an alert escalation
type AlertEscalation struct {
	AlertID     string                 `json:"alert_id"`
	Level       int                    `json:"level"`
	TriggeredAt time.Time              `json:"triggered_at"`
	Channels    []string               `json:"channels"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertSuppression represents an alert suppression rule
type AlertSuppression struct {
	ID              string                 `json:"id"`
	RuleID          string                 `json:"rule_id"`
	Reason          string                 `json:"reason"`
	SuppressedUntil time.Time              `json:"suppressed_until"`
	CreatedBy       string                 `json:"created_by"`
	CreatedAt       time.Time              `json:"created_at"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// SecurityAlertChannel interface for different notification channels (renamed to avoid conflicts)
type SecurityAlertChannel interface {
	SendAlert(alert *Alert) error
	GetType() string
	IsHealthy() bool
}

// Configuration types
type ChannelConfig struct {
	Type          string                 `json:"type"`
	Name          string                 `json:"name"`
	Enabled       bool                   `json:"enabled"`
	Config        map[string]interface{} `json:"config"`
	Severities    []string               `json:"severities"`
	RetryAttempts int                    `json:"retry_attempts"`
	RetryDelay    time.Duration          `json:"retry_delay"`
}

type AlertRuleConfig struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	Enabled        bool          `json:"enabled"`
	Condition      string        `json:"condition"`
	Threshold      float64       `json:"threshold"`
	Severity       string        `json:"severity"`
	Description    string        `json:"description"`
	Component      string        `json:"component"`
	MetricName     string        `json:"metric_name"`
	Operator       string        `json:"operator"`
	TimeWindow     time.Duration `json:"time_window"`
	MinOccurrences int           `json:"min_occurrences"`
	Channels       []string      `json:"channels"`
}

type EscalationConfig struct {
	RuleID  string             `json:"rule_id"`
	Levels  []*EscalationLevel `json:"levels"`
	Enabled bool               `json:"enabled"`
}

type EscalationLevel struct {
	Level     int           `json:"level"`
	Delay     time.Duration `json:"delay"`
	Channels  []string      `json:"channels"`
	Condition string        `json:"condition"`
}

type SuppressionConfig struct {
	RuleID   string        `json:"rule_id"`
	Duration time.Duration `json:"duration"`
	Reason   string        `json:"reason"`
	Enabled  bool          `json:"enabled"`
}

// NewSecurityAlertManager creates a new security alert manager
func NewSecurityAlertManager(config *AlertingConfig, logger Logger) *SecurityAlertManager {
	ctx, cancel := context.WithCancel(context.Background())

	manager := &SecurityAlertManager{
		config:         config,
		logger:         logger,
		ctx:            ctx,
		cancel:         cancel,
		channels:       make(map[string]SecurityAlertChannel),
		conditions:     make(map[string]*AlertCondition),
		activeAlerts:   make(map[string]*Alert),
		alertHistory:   make([]*Alert, 0),
		suppressions:   make(map[string]*AlertSuppression),
		escalations:    make(map[string]*AlertEscalation),
		alertChan:      make(chan *Alert, config.BufferSize),
		evaluationChan: make(chan *AlertEvaluation, config.BufferSize),
	}

	// Initialize alert rules
	manager.initializeRules()

	// Initialize alert channels
	manager.initializeChannels()

	return manager
}

// Start starts the alert manager
func (sam *SecurityAlertManager) Start() error {
	if !sam.config.Enabled {
		return nil
	}

	sam.logger.Info("Starting security alert manager")

	// Start background workers
	sam.wg.Add(3)
	go sam.alertProcessor()
	go sam.evaluationProcessor()
	go sam.escalationProcessor()

	return nil
}

// Stop stops the alert manager
func (sam *SecurityAlertManager) Stop() error {
	sam.logger.Info("Stopping security alert manager")

	sam.cancel()
	sam.wg.Wait()

	close(sam.alertChan)
	close(sam.evaluationChan)

	return nil
}

// initializeRules initializes alert rules from configuration
func (sam *SecurityAlertManager) initializeRules() {
	sam.rules = make([]*SecurityAlertRule, 0, len(sam.config.Rules))

	for _, ruleConfig := range sam.config.Rules {
		rule := &SecurityAlertRule{
			ID:             ruleConfig.ID,
			Name:           ruleConfig.Name,
			Enabled:        ruleConfig.Enabled,
			Condition:      ruleConfig.Condition,
			Threshold:      ruleConfig.Threshold,
			Severity:       ruleConfig.Severity,
			Description:    ruleConfig.Description,
			Component:      ruleConfig.Component,
			MetricName:     ruleConfig.MetricName,
			Operator:       ruleConfig.Operator,
			TimeWindow:     ruleConfig.TimeWindow,
			MinOccurrences: ruleConfig.MinOccurrences,
			Channels:       ruleConfig.Channels,
			Metadata:       make(map[string]interface{}),
		}

		sam.rules = append(sam.rules, rule)

		// Initialize condition tracking
		sam.conditions[rule.ID] = &AlertCondition{
			RuleID:         rule.ID,
			Threshold:      rule.Threshold,
			Operator:       rule.Operator,
			Satisfied:      false,
			LastEvaluation: time.Now(),
			Metadata:       make(map[string]interface{}),
		}
	}

	sam.logger.Info("Initialized alert rules", "count", len(sam.rules))
}

// initializeChannels initializes alert channels from configuration
func (sam *SecurityAlertManager) initializeChannels() {
	for _, channelConfig := range sam.config.Channels {
		if !channelConfig.Enabled {
			continue
		}

		var channel SecurityAlertChannel

		switch channelConfig.Type {
		case "slack":
			channel = &SlackAlertChannel{
				config: channelConfig,
				logger: sam.logger,
			}
		case "email":
			channel = &EmailAlertChannel{
				config: channelConfig,
				logger: sam.logger,
			}
		case "webhook":
			channel = &WebhookAlertChannel{
				config: channelConfig,
				logger: sam.logger,
			}
		case "log":
			channel = &LogAlertChannel{
				config: channelConfig,
				logger: sam.logger,
			}
		default:
			sam.logger.Warn("Unknown alert channel type", "type", channelConfig.Type)
			continue
		}

		sam.channels[channelConfig.Name] = channel
		sam.logger.Info("Initialized alert channel", "name", channelConfig.Name, "type", channelConfig.Type)
	}
}

// EvaluateMetric evaluates a metric against alert rules
func (sam *SecurityAlertManager) EvaluateMetric(metricName string, value float64, metadata map[string]interface{}) {
	if !sam.config.Enabled {
		return
	}

	evaluation := &AlertEvaluation{
		MetricName:  metricName,
		MetricValue: value,
		Timestamp:   time.Now(),
		Metadata:    metadata,
	}

	select {
	case sam.evaluationChan <- evaluation:
	default:
		sam.logger.Warn("Evaluation channel full, dropping evaluation", "metric", metricName)
	}
}

// TriggerAlert triggers a new alert
func (sam *SecurityAlertManager) TriggerAlert(ruleID, alertType, severity, title, description string, metadata map[string]interface{}) {
	if !sam.config.Enabled {
		return
	}

	alert := &Alert{
		ID:              fmt.Sprintf("alert_%d", time.Now().UnixNano()),
		RuleID:          ruleID,
		Type:            alertType,
		Severity:        severity,
		Title:           title,
		Description:     description,
		Status:          "active",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		Metadata:        metadata,
		Notifications:   make([]*AlertNotification, 0),
		EscalationLevel: 0,
	}

	if source, ok := metadata["source"].(string); ok {
		alert.Source = source
	}

	if component, ok := metadata["component"].(string); ok {
		alert.Component = component
	}

	if threatScore, ok := metadata["threat_score"].(float64); ok {
		alert.ThreatScore = threatScore
	}

	select {
	case sam.alertChan <- alert:
	default:
		sam.logger.Warn("Alert channel full, dropping alert", "alert_id", alert.ID)
	}
}

// alertProcessor processes alerts in the background
func (sam *SecurityAlertManager) alertProcessor() {
	defer sam.wg.Done()

	for {
		select {
		case <-sam.ctx.Done():
			return
		case alert := <-sam.alertChan:
			sam.processAlert(alert)
		}
	}
}

// evaluationProcessor processes metric evaluations in the background
func (sam *SecurityAlertManager) evaluationProcessor() {
	defer sam.wg.Done()

	ticker := time.NewTicker(sam.config.EvaluationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sam.ctx.Done():
			return
		case <-ticker.C:
			sam.evaluateAllRules()
		case evaluation := <-sam.evaluationChan:
			sam.processEvaluation(evaluation)
		}
	}
}

// escalationProcessor handles alert escalations
func (sam *SecurityAlertManager) escalationProcessor() {
	defer sam.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-sam.ctx.Done():
			return
		case <-ticker.C:
			sam.processEscalations()
		}
	}
}

// processAlert processes a single alert
func (sam *SecurityAlertManager) processAlert(alert *Alert) {
	sam.mu.Lock()
	defer sam.mu.Unlock()

	// Check if alert is suppressed
	if sam.isAlertSuppressed(alert.RuleID) {
		sam.logger.Info("Alert suppressed", "alert_id", alert.ID, "rule_id", alert.RuleID)
		return
	}

	// Check for duplicate alerts
	if sam.isDuplicateAlert(alert) {
		sam.logger.Info("Duplicate alert detected", "alert_id", alert.ID, "rule_id", alert.RuleID)
		return
	}

	// Add to active alerts
	sam.activeAlerts[alert.ID] = alert
	sam.alertHistory = append(sam.alertHistory, alert)

	// Trim history if needed
	if len(sam.alertHistory) > 1000 {
		sam.alertHistory = sam.alertHistory[len(sam.alertHistory)-1000:]
	}

	sam.logger.Info("Processing new alert", "alert_id", alert.ID, "severity", alert.Severity, "type", alert.Type)

	// Send notifications
	sam.sendAlertNotifications(alert)

	// Schedule escalation if configured
	sam.scheduleEscalation(alert)
}

// processEvaluation processes a metric evaluation
func (sam *SecurityAlertManager) processEvaluation(evaluation *AlertEvaluation) {
	sam.mu.RLock()
	rules := sam.rules
	sam.mu.RUnlock()

	for _, rule := range rules {
		if !rule.Enabled || rule.MetricName != evaluation.MetricName {
			continue
		}

		sam.evaluateRule(rule, evaluation)
	}
}

// evaluateAllRules evaluates all rules periodically
func (sam *SecurityAlertManager) evaluateAllRules() {
	sam.mu.RLock()
	rules := sam.rules
	sam.mu.RUnlock()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// This would typically fetch current metric values
		// For now, we'll skip periodic evaluation
	}
}

// evaluateRule evaluates a single rule against a metric value
func (sam *SecurityAlertManager) evaluateRule(rule *SecurityAlertRule, evaluation *AlertEvaluation) {
	sam.mu.Lock()
	condition := sam.conditions[rule.ID]
	sam.mu.Unlock()

	// Evaluate condition
	satisfied := sam.evaluateCondition(rule.Operator, evaluation.MetricValue, rule.Threshold)

	sam.mu.Lock()
	condition.MetricValue = evaluation.MetricValue
	condition.LastEvaluation = evaluation.Timestamp

	if satisfied {
		condition.ConsecutiveHits++
		if condition.ConsecutiveHits >= rule.MinOccurrences && !condition.Satisfied {
			condition.Satisfied = true
			sam.mu.Unlock()

			// Trigger alert
			metadata := make(map[string]interface{})
			for k, v := range evaluation.Metadata {
				metadata[k] = v
			}
			metadata["metric_value"] = evaluation.MetricValue
			metadata["threshold"] = rule.Threshold
			metadata["operator"] = rule.Operator

			sam.TriggerAlert(rule.ID, "metric_threshold", rule.Severity, rule.Name, rule.Description, metadata)
		} else {
			sam.mu.Unlock()
		}
	} else {
		condition.ConsecutiveHits = 0
		condition.Satisfied = false
		sam.mu.Unlock()
	}
}

// evaluateCondition evaluates a condition based on operator
func (sam *SecurityAlertManager) evaluateCondition(operator string, value, threshold float64) bool {
	switch operator {
	case ">", "gt":
		return value > threshold
	case ">=", "gte":
		return value >= threshold
	case "<", "lt":
		return value < threshold
	case "<=", "lte":
		return value <= threshold
	case "==", "eq":
		return value == threshold
	case "!=", "ne":
		return value != threshold
	default:
		return false
	}
}

// sendAlertNotifications sends notifications for an alert
func (sam *SecurityAlertManager) sendAlertNotifications(alert *Alert) {
	rule := sam.findRule(alert.RuleID)
	if rule == nil {
		sam.logger.Error("Rule not found for alert", "alert_id", alert.ID, "rule_id", alert.RuleID)
		return
	}

	for _, channelName := range rule.Channels {
		channel, exists := sam.channels[channelName]
		if !exists {
			sam.logger.Warn("Alert channel not found", "channel", channelName)
			continue
		}

		// Check if channel supports this severity
		if !sam.channelSupportsSeverity(channelName, alert.Severity) {
			continue
		}

		notification := &AlertNotification{
			ID:       fmt.Sprintf("notif_%d", time.Now().UnixNano()),
			AlertID:  alert.ID,
			Channel:  channelName,
			Status:   "pending",
			SentAt:   time.Now(),
			Metadata: make(map[string]interface{}),
		}

		go sam.sendNotification(channel, alert, notification)

		alert.Notifications = append(alert.Notifications, notification)
	}
}

// sendNotification sends a notification through a channel
func (sam *SecurityAlertManager) sendNotification(channel SecurityAlertChannel, alert *Alert, notification *AlertNotification) {
	maxRetries := 3
	retryDelay := 5 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := channel.SendAlert(alert)
		if err == nil {
			sam.mu.Lock()
			notification.Status = "sent"
			sam.mu.Unlock()
			sam.logger.Info("Alert notification sent", "alert_id", alert.ID, "channel", notification.Channel)
			return
		}

		sam.logger.Warn("Failed to send alert notification", "alert_id", alert.ID, "channel", notification.Channel, "attempt", attempt+1, "error", err)

		if attempt < maxRetries {
			time.Sleep(retryDelay)
			retryDelay *= 2 // Exponential backoff
		}
	}

	sam.mu.Lock()
	notification.Status = "failed"
	notification.Error = "Max retries exceeded"
	notification.RetryCount = maxRetries
	sam.mu.Unlock()
}

// processEscalations processes alert escalations
func (sam *SecurityAlertManager) processEscalations() {
	sam.mu.RLock()
	activeAlerts := make([]*Alert, 0, len(sam.activeAlerts))
	for _, alert := range sam.activeAlerts {
		activeAlerts = append(activeAlerts, alert)
	}
	sam.mu.RUnlock()

	for _, alert := range activeAlerts {
		sam.checkEscalation(alert)
	}
}

// checkEscalation checks if an alert should be escalated
func (sam *SecurityAlertManager) checkEscalation(alert *Alert) {
	if alert.Escalated {
		return
	}

	// Find escalation configuration
	var escalationConfig *EscalationConfig
	for _, config := range sam.config.Escalations {
		if config.RuleID == alert.RuleID && config.Enabled {
			escalationConfig = config
			break
		}
	}

	if escalationConfig == nil {
		return
	}

	// Check if enough time has passed for escalation
	for _, level := range escalationConfig.Levels {
		if level.Level > alert.EscalationLevel {
			if time.Since(alert.CreatedAt) >= level.Delay {
				sam.escalateAlert(alert, level)
				break
			}
		}
	}
}

// escalateAlert escalates an alert to the next level
func (sam *SecurityAlertManager) escalateAlert(alert *Alert, level *EscalationLevel) {
	sam.mu.Lock()
	alert.Escalated = true
	alert.EscalationLevel = level.Level
	alert.UpdatedAt = time.Now()
	sam.mu.Unlock()

	escalation := &AlertEscalation{
		AlertID:     alert.ID,
		Level:       level.Level,
		TriggeredAt: time.Now(),
		Channels:    level.Channels,
		Status:      "active",
		Metadata:    make(map[string]interface{}),
	}

	sam.mu.Lock()
	sam.escalations[alert.ID] = escalation
	sam.mu.Unlock()

	sam.logger.Info("Alert escalated", "alert_id", alert.ID, "level", level.Level)

	// Send escalation notifications
	for _, channelName := range level.Channels {
		if channel, exists := sam.channels[channelName]; exists {
			go func(ch SecurityAlertChannel) {
				if err := ch.SendAlert(alert); err != nil {
					sam.logger.Error("Failed to send escalation notification", "alert_id", alert.ID, "channel", channelName, "error", err)
				}
			}(channel)
		}
	}
}

// Helper methods

func (sam *SecurityAlertManager) isAlertSuppressed(ruleID string) bool {
	suppression, exists := sam.suppressions[ruleID]
	if !exists {
		return false
	}

	return time.Now().Before(suppression.SuppressedUntil)
}

func (sam *SecurityAlertManager) isDuplicateAlert(alert *Alert) bool {
	for _, existingAlert := range sam.activeAlerts {
		if existingAlert.RuleID == alert.RuleID && existingAlert.Status == "active" {
			// Check if it's within a reasonable time window (e.g., 5 minutes)
			if time.Since(existingAlert.CreatedAt) < 5*time.Minute {
				return true
			}
		}
	}
	return false
}

func (sam *SecurityAlertManager) findRule(ruleID string) *SecurityAlertRule {
	for _, rule := range sam.rules {
		if rule.ID == ruleID {
			return rule
		}
	}
	return nil
}

func (sam *SecurityAlertManager) channelSupportsSeverity(channelName, severity string) bool {
	// This would check channel configuration for supported severities
	// For now, assume all channels support all severities
	return true
}

// Public API methods

// GetActiveAlerts returns all active alerts
func (sam *SecurityAlertManager) GetActiveAlerts() []*Alert {
	sam.mu.RLock()
	defer sam.mu.RUnlock()

	alerts := make([]*Alert, 0, len(sam.activeAlerts))
	for _, alert := range sam.activeAlerts {
		alertCopy := *alert
		alerts = append(alerts, &alertCopy)
	}

	return alerts
}

// GetAlertHistory returns alert history
func (sam *SecurityAlertManager) GetAlertHistory(limit int) []*Alert {
	sam.mu.RLock()
	defer sam.mu.RUnlock()

	history := sam.alertHistory
	if limit > 0 && len(history) > limit {
		history = history[len(history)-limit:]
	}

	result := make([]*Alert, len(history))
	for i, alert := range history {
		alertCopy := *alert
		result[i] = &alertCopy
	}

	return result
}

// ResolveAlert resolves an active alert
func (sam *SecurityAlertManager) ResolveAlert(alertID, reason string) error {
	sam.mu.Lock()
	defer sam.mu.Unlock()

	alert, exists := sam.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	now := time.Now()
	alert.Status = "resolved"
	alert.ResolvedAt = &now
	alert.UpdatedAt = now

	if alert.Metadata == nil {
		alert.Metadata = make(map[string]interface{})
	}
	alert.Metadata["resolution_reason"] = reason

	delete(sam.activeAlerts, alertID)

	sam.logger.Info("Alert resolved", "alert_id", alertID, "reason", reason)

	return nil
}

// SuppressAlert suppresses alerts for a rule
func (sam *SecurityAlertManager) SuppressAlert(ruleID, reason string, duration time.Duration) error {
	sam.mu.Lock()
	defer sam.mu.Unlock()

	suppression := &AlertSuppression{
		ID:              fmt.Sprintf("supp_%d", time.Now().UnixNano()),
		RuleID:          ruleID,
		Reason:          reason,
		SuppressedUntil: time.Now().Add(duration),
		CreatedAt:       time.Now(),
		Metadata:        make(map[string]interface{}),
	}

	sam.suppressions[ruleID] = suppression

	sam.logger.Info("Alert suppressed", "rule_id", ruleID, "duration", duration, "reason", reason)

	return nil
}

// GetAlertStatistics returns alert statistics
func (sam *SecurityAlertManager) GetAlertStatistics() map[string]interface{} {
	sam.mu.RLock()
	defer sam.mu.RUnlock()

	stats := map[string]interface{}{
		"active_alerts":       len(sam.activeAlerts),
		"total_alerts":        len(sam.alertHistory),
		"active_suppressions": len(sam.suppressions),
		"active_escalations":  len(sam.escalations),
	}

	// Count by severity
	severityCounts := make(map[string]int)
	for _, alert := range sam.activeAlerts {
		severityCounts[alert.Severity]++
	}
	stats["alerts_by_severity"] = severityCounts

	// Count by type
	typeCounts := make(map[string]int)
	for _, alert := range sam.activeAlerts {
		typeCounts[alert.Type]++
	}
	stats["alerts_by_type"] = typeCounts

	return stats
}

// scheduleEscalation schedules escalation for an alert (placeholder)
func (sam *SecurityAlertManager) scheduleEscalation(alert *Alert) {
	// This would schedule escalation based on configuration
	// For now, it's a placeholder
}

// Alert Channel Implementations

// LogAlertChannel sends alerts to logs
type LogAlertChannel struct {
	config *ChannelConfig
	logger Logger
}

func (l *LogAlertChannel) SendAlert(alert *Alert) error {
	l.logger.Info("Security Alert",
		"alert_id", alert.ID,
		"type", alert.Type,
		"severity", alert.Severity,
		"title", alert.Title,
		"description", alert.Description,
		"source", alert.Source,
		"component", alert.Component,
		"threat_score", alert.ThreatScore,
	)
	return nil
}

func (l *LogAlertChannel) GetType() string {
	return "log"
}

func (l *LogAlertChannel) IsHealthy() bool {
	return true
}

// SlackAlertChannel sends alerts to Slack
type SlackAlertChannel struct {
	config *ChannelConfig
	logger Logger
}

func (s *SlackAlertChannel) SendAlert(alert *Alert) error {
	// In a real implementation, this would send to Slack webhook
	s.logger.Info("Slack alert sent",
		"alert_id", alert.ID,
		"type", alert.Type,
		"severity", alert.Severity,
		"title", alert.Title,
	)
	return nil
}

func (s *SlackAlertChannel) GetType() string {
	return "slack"
}

func (s *SlackAlertChannel) IsHealthy() bool {
	return true
}

// EmailAlertChannel sends alerts via email
type EmailAlertChannel struct {
	config *ChannelConfig
	logger Logger
}

func (e *EmailAlertChannel) SendAlert(alert *Alert) error {
	// In a real implementation, this would send email
	e.logger.Info("Email alert sent",
		"alert_id", alert.ID,
		"type", alert.Type,
		"severity", alert.Severity,
		"title", alert.Title,
	)
	return nil
}

func (e *EmailAlertChannel) GetType() string {
	return "email"
}

func (e *EmailAlertChannel) IsHealthy() bool {
	return true
}

// WebhookAlertChannel sends alerts to webhook
type WebhookAlertChannel struct {
	config *ChannelConfig
	logger Logger
}

func (w *WebhookAlertChannel) SendAlert(alert *Alert) error {
	// In a real implementation, this would send to webhook
	w.logger.Info("Webhook alert sent",
		"alert_id", alert.ID,
		"type", alert.Type,
		"severity", alert.Severity,
		"title", alert.Title,
	)
	return nil
}

func (w *WebhookAlertChannel) GetType() string {
	return "webhook"
}

func (w *WebhookAlertChannel) IsHealthy() bool {
	return true
}
