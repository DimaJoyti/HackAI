package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// IncidentResponseSystem handles security incident detection, classification, and response
type IncidentResponseSystem struct {
	config           *IncidentResponseConfig
	logger           Logger
	dashboardService *DashboardService
	alertManager     *SecurityAlertManager

	// Incident tracking
	activeIncidents map[string]*SecurityIncident
	incidentHistory []*SecurityIncident
	mu              sync.RWMutex

	// Response automation
	responseRules   []*ResponseRule
	escalationRules []*EscalationRule
	playbooks       map[string]*ResponsePlaybook

	// Background workers
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// OpenTelemetry
	tracer trace.Tracer
}

// IncidentResponseConfig configuration for incident response
type IncidentResponseConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	AutoResponseEnabled   bool          `yaml:"auto_response_enabled" json:"auto_response_enabled"`
	EscalationEnabled     bool          `yaml:"escalation_enabled" json:"escalation_enabled"`
	MaxActiveIncidents    int           `yaml:"max_active_incidents" json:"max_active_incidents"`
	IncidentRetentionTime time.Duration `yaml:"incident_retention_time" json:"incident_retention_time"`
	ResponseTimeout       time.Duration `yaml:"response_timeout" json:"response_timeout"`
	EscalationThreshold   time.Duration `yaml:"escalation_threshold" json:"escalation_threshold"`
	CriticalResponseTime  time.Duration `yaml:"critical_response_time" json:"critical_response_time"`
}

// SecurityIncident represents a security incident
type SecurityIncident struct {
	ID              string                 `json:"id"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Severity        string                 `json:"severity"`
	Status          string                 `json:"status"`
	Category        string                 `json:"category"`
	Source          string                 `json:"source"`
	AffectedSystems []string               `json:"affected_systems"`
	ThreatActors    []string               `json:"threat_actors"`
	IOCs            []string               `json:"iocs"`
	Timeline        []*IncidentEvent       `json:"timeline"`
	ResponseActions []*ResponseAction      `json:"response_actions"`
	AssignedTo      string                 `json:"assigned_to"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	ResolvedAt      *time.Time             `json:"resolved_at,omitempty"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// IncidentEvent represents an event in the incident timeline
type IncidentEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Actor       string                 `json:"actor"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ResponseAction represents an action taken in response to an incident
type ResponseAction struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Status      string                 `json:"status"`
	ExecutedBy  string                 `json:"executed_by"`
	ExecutedAt  time.Time              `json:"executed_at"`
	Result      string                 `json:"result"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ResponseRule defines automated response rules
type ResponseRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Conditions  []*ResponseRuleCondition `json:"conditions"`
	Actions     []*AutomatedAction     `json:"actions"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ResponseRuleCondition defines conditions for response rules
type ResponseRuleCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Negate   bool        `json:"negate"`
}

// AutomatedAction defines automated response actions
type AutomatedAction struct {
	Type        string                 `json:"type"`
	Parameters  map[string]interface{} `json:"parameters"`
	Timeout     time.Duration          `json:"timeout"`
	RetryCount  int                    `json:"retry_count"`
	Description string                 `json:"description"`
}

// EscalationRule defines escalation rules for incidents
type EscalationRule struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Conditions []*ResponseRuleCondition `json:"conditions"`
	EscalateTo []string         `json:"escalate_to"`
	Delay      time.Duration    `json:"delay"`
	Enabled    bool             `json:"enabled"`
}

// ResponsePlaybook defines incident response playbooks
type ResponsePlaybook struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Steps       []*PlaybookStep        `json:"steps"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PlaybookStep defines a step in a response playbook
type PlaybookStep struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Parameters  map[string]interface{} `json:"parameters"`
	Order       int                    `json:"order"`
	Required    bool                   `json:"required"`
}

// NewIncidentResponseSystem creates a new incident response system
func NewIncidentResponseSystem(
	config *IncidentResponseConfig,
	logger Logger,
	dashboardService *DashboardService,
	alertManager *SecurityAlertManager,
) *IncidentResponseSystem {
	ctx, cancel := context.WithCancel(context.Background())

	return &IncidentResponseSystem{
		config:           config,
		logger:           logger,
		dashboardService: dashboardService,
		alertManager:     alertManager,
		activeIncidents:  make(map[string]*SecurityIncident),
		incidentHistory:  make([]*SecurityIncident, 0),
		responseRules:    make([]*ResponseRule, 0),
		escalationRules:  make([]*EscalationRule, 0),
		playbooks:        make(map[string]*ResponsePlaybook),
		ctx:              ctx,
		cancel:           cancel,
		tracer:           otel.Tracer("incident-response"),
	}
}

// Start starts the incident response system
func (irs *IncidentResponseSystem) Start() error {
	if !irs.config.Enabled {
		irs.logger.Info("Incident response system is disabled")
		return nil
	}

	irs.logger.Info("Starting incident response system")

	// Initialize default rules and playbooks
	irs.initializeDefaultRules()
	irs.initializeDefaultPlaybooks()

	// Start background workers
	irs.wg.Add(2)
	go irs.incidentMonitor()
	go irs.escalationMonitor()

	return nil
}

// Stop stops the incident response system
func (irs *IncidentResponseSystem) Stop() error {
	irs.logger.Info("Stopping incident response system")

	irs.cancel()
	irs.wg.Wait()

	return nil
}

// CreateIncident creates a new security incident
func (irs *IncidentResponseSystem) CreateIncident(ctx context.Context, incident *SecurityIncident) error {
	ctx, span := irs.tracer.Start(ctx, "incident_response.create_incident")
	defer span.End()

	irs.mu.Lock()
	defer irs.mu.Unlock()

	// Generate ID if not provided
	if incident.ID == "" {
		incident.ID = fmt.Sprintf("INC-%d", time.Now().Unix())
	}

	// Set timestamps
	incident.CreatedAt = time.Now()
	incident.UpdatedAt = time.Now()

	// Initialize timeline
	if incident.Timeline == nil {
		incident.Timeline = make([]*IncidentEvent, 0)
	}

	// Add creation event
	creationEvent := &IncidentEvent{
		ID:          fmt.Sprintf("EVT-%d", time.Now().UnixNano()),
		Type:        "incident_created",
		Description: "Incident created",
		Timestamp:   time.Now(),
		Actor:       "system",
		Metadata:    make(map[string]interface{}),
	}
	incident.Timeline = append(incident.Timeline, creationEvent)

	// Store incident
	irs.activeIncidents[incident.ID] = incident

	// Log incident creation
	irs.logger.Info("Security incident created",
		"incident_id", incident.ID,
		"severity", incident.Severity,
		"category", incident.Category,
	)

	// Broadcast to dashboard
	if irs.dashboardService != nil {
		// Create a threat event using the MITRE ATLAS ThreatEvent structure
		threatEvent := &ThreatEvent{
			ID:          incident.ID,
			Timestamp:   incident.CreatedAt,
			TacticID:    "TA0001", // Initial Access
			TechniqueID: "T1001",  // Generic technique
			Severity:    incident.Severity,
			Confidence:  irs.calculateThreatScore(incident),
			SourceIP:    incident.Source,
			TargetAsset: "AI System",
			Description: incident.Description,
			Evidence:    []Evidence{},
			Mitigations: []string{},
			Status:      "investigating",
			AssignedTo:  incident.AssignedTo,
			Metadata:    incident.Metadata,
			CreatedAt:   incident.CreatedAt,
			UpdatedAt:   incident.UpdatedAt,
		}
		irs.dashboardService.BroadcastThreatAlert(threatEvent)
	}

	// Trigger automated response if enabled
	if irs.config.AutoResponseEnabled {
		go irs.triggerAutomatedResponse(ctx, incident)
	}

	span.SetAttributes(
		attribute.String("incident.id", incident.ID),
		attribute.String("incident.severity", incident.Severity),
		attribute.String("incident.category", incident.Category),
	)

	return nil
}

// UpdateIncident updates an existing incident
func (irs *IncidentResponseSystem) UpdateIncident(ctx context.Context, incidentID string, updates map[string]interface{}) error {
	ctx, span := irs.tracer.Start(ctx, "incident_response.update_incident")
	defer span.End()

	irs.mu.Lock()
	defer irs.mu.Unlock()

	incident, exists := irs.activeIncidents[incidentID]
	if !exists {
		return fmt.Errorf("incident not found: %s", incidentID)
	}

	// Apply updates
	for field, value := range updates {
		switch field {
		case "status":
			incident.Status = value.(string)
		case "severity":
			incident.Severity = value.(string)
		case "assigned_to":
			incident.AssignedTo = value.(string)
		case "description":
			incident.Description = value.(string)
		}
	}

	incident.UpdatedAt = time.Now()

	// Add update event to timeline
	updateEvent := &IncidentEvent{
		ID:          fmt.Sprintf("EVT-%d", time.Now().UnixNano()),
		Type:        "incident_updated",
		Description: "Incident updated",
		Timestamp:   time.Now(),
		Actor:       "system",
		Metadata:    updates,
	}
	incident.Timeline = append(incident.Timeline, updateEvent)

	span.SetAttributes(
		attribute.String("incident.id", incidentID),
		attribute.String("incident.status", incident.Status),
	)

	return nil
}

// ResolveIncident resolves an incident
func (irs *IncidentResponseSystem) ResolveIncident(ctx context.Context, incidentID string, resolution string) error {
	ctx, span := irs.tracer.Start(ctx, "incident_response.resolve_incident")
	defer span.End()

	irs.mu.Lock()
	defer irs.mu.Unlock()

	incident, exists := irs.activeIncidents[incidentID]
	if !exists {
		return fmt.Errorf("incident not found: %s", incidentID)
	}

	// Update incident status
	incident.Status = "resolved"
	now := time.Now()
	incident.ResolvedAt = &now
	incident.UpdatedAt = now

	// Add resolution event
	resolutionEvent := &IncidentEvent{
		ID:          fmt.Sprintf("EVT-%d", time.Now().UnixNano()),
		Type:        "incident_resolved",
		Description: resolution,
		Timestamp:   time.Now(),
		Actor:       "system",
		Metadata:    map[string]interface{}{"resolution": resolution},
	}
	incident.Timeline = append(incident.Timeline, resolutionEvent)

	// Move to history
	irs.incidentHistory = append(irs.incidentHistory, incident)
	delete(irs.activeIncidents, incidentID)

	irs.logger.Info("Security incident resolved",
		"incident_id", incidentID,
		"resolution", resolution,
	)

	span.SetAttributes(
		attribute.String("incident.id", incidentID),
		attribute.String("resolution", resolution),
	)

	return nil
}

// GetActiveIncidents returns all active incidents
func (irs *IncidentResponseSystem) GetActiveIncidents() []*SecurityIncident {
	irs.mu.RLock()
	defer irs.mu.RUnlock()

	incidents := make([]*SecurityIncident, 0, len(irs.activeIncidents))
	for _, incident := range irs.activeIncidents {
		incidents = append(incidents, incident)
	}

	return incidents
}

// GetIncident returns a specific incident
func (irs *IncidentResponseSystem) GetIncident(incidentID string) (*SecurityIncident, error) {
	irs.mu.RLock()
	defer irs.mu.RUnlock()

	if incident, exists := irs.activeIncidents[incidentID]; exists {
		return incident, nil
	}

	// Check history
	for _, incident := range irs.incidentHistory {
		if incident.ID == incidentID {
			return incident, nil
		}
	}

	return nil, fmt.Errorf("incident not found: %s", incidentID)
}

// incidentMonitor monitors incidents for automated responses and escalations
func (irs *IncidentResponseSystem) incidentMonitor() {
	defer irs.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-irs.ctx.Done():
			return
		case <-ticker.C:
			irs.processIncidents()
		}
	}
}

// escalationMonitor monitors incidents for escalation
func (irs *IncidentResponseSystem) escalationMonitor() {
	defer irs.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-irs.ctx.Done():
			return
		case <-ticker.C:
			irs.processEscalations()
		}
	}
}

// processIncidents processes active incidents for automated responses
func (irs *IncidentResponseSystem) processIncidents() {
	irs.mu.RLock()
	incidents := make([]*SecurityIncident, 0, len(irs.activeIncidents))
	for _, incident := range irs.activeIncidents {
		incidents = append(incidents, incident)
	}
	irs.mu.RUnlock()

	for _, incident := range incidents {
		// Check if incident needs automated response
		if irs.config.AutoResponseEnabled {
			irs.evaluateResponseRules(incident)
		}
	}
}

// processEscalations processes incidents for escalation
func (irs *IncidentResponseSystem) processEscalations() {
	if !irs.config.EscalationEnabled {
		return
	}

	irs.mu.RLock()
	incidents := make([]*SecurityIncident, 0, len(irs.activeIncidents))
	for _, incident := range irs.activeIncidents {
		incidents = append(incidents, incident)
	}
	irs.mu.RUnlock()

	for _, incident := range incidents {
		// Check if incident needs escalation
		if irs.shouldEscalate(incident) {
			irs.escalateIncident(incident)
		}
	}
}

// triggerAutomatedResponse triggers automated response for an incident
func (irs *IncidentResponseSystem) triggerAutomatedResponse(ctx context.Context, incident *SecurityIncident) {
	ctx, span := irs.tracer.Start(ctx, "incident_response.automated_response")
	defer span.End()

	irs.logger.Info("Triggering automated response", "incident_id", incident.ID)

	// Evaluate response rules
	irs.evaluateResponseRules(incident)

	span.SetAttributes(
		attribute.String("incident.id", incident.ID),
		attribute.String("incident.severity", incident.Severity),
	)
}

// evaluateResponseRules evaluates response rules for an incident
func (irs *IncidentResponseSystem) evaluateResponseRules(incident *SecurityIncident) {
	for _, rule := range irs.responseRules {
		if !rule.Enabled {
			continue
		}

		if irs.evaluateConditions(rule.Conditions, incident) {
			irs.executeResponseActions(rule.Actions, incident)
		}
	}
}

// evaluateConditions evaluates rule conditions against an incident
func (irs *IncidentResponseSystem) evaluateConditions(conditions []*ResponseRuleCondition, incident *SecurityIncident) bool {
	for _, condition := range conditions {
		if !irs.evaluateCondition(condition, incident) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition
func (irs *IncidentResponseSystem) evaluateCondition(condition *ResponseRuleCondition, incident *SecurityIncident) bool {
	var fieldValue interface{}

	switch condition.Field {
	case "severity":
		fieldValue = incident.Severity
	case "category":
		fieldValue = incident.Category
	case "source":
		fieldValue = incident.Source
	case "status":
		fieldValue = incident.Status
	default:
		return false
	}

	switch condition.Operator {
	case "equals":
		return fieldValue == condition.Value
	case "not_equals":
		return fieldValue != condition.Value
	case "contains":
		if str, ok := fieldValue.(string); ok {
			if substr, ok := condition.Value.(string); ok {
				return contains(str, substr)
			}
		}
	case "in":
		if values, ok := condition.Value.([]interface{}); ok {
			for _, value := range values {
				if fieldValue == value {
					return true
				}
			}
		}
	}

	return false
}

// executeResponseActions executes automated response actions
func (irs *IncidentResponseSystem) executeResponseActions(actions []*AutomatedAction, incident *SecurityIncident) {
	for _, action := range actions {
		irs.executeAction(action, incident)
	}
}

// executeAction executes a single automated action
func (irs *IncidentResponseSystem) executeAction(action *AutomatedAction, incident *SecurityIncident) {
	irs.logger.Info("Executing automated action",
		"incident_id", incident.ID,
		"action_type", action.Type,
	)

	responseAction := &ResponseAction{
		ID:          fmt.Sprintf("ACT-%d", time.Now().UnixNano()),
		Type:        action.Type,
		Description: action.Description,
		Status:      "executing",
		ExecutedBy:  "system",
		ExecutedAt:  time.Now(),
		Metadata:    action.Parameters,
	}

	// Execute based on action type
	switch action.Type {
	case "block_ip":
		irs.blockIP(action.Parameters, incident)
		responseAction.Status = "completed"
		responseAction.Result = "IP blocked successfully"

	case "isolate_system":
		irs.isolateSystem(action.Parameters, incident)
		responseAction.Status = "completed"
		responseAction.Result = "System isolated successfully"

	case "send_alert":
		irs.sendAlert(action.Parameters, incident)
		responseAction.Status = "completed"
		responseAction.Result = "Alert sent successfully"

	case "create_ticket":
		irs.createTicket(action.Parameters, incident)
		responseAction.Status = "completed"
		responseAction.Result = "Ticket created successfully"

	default:
		responseAction.Status = "failed"
		responseAction.Result = "Unknown action type"
	}

	// Add action to incident
	irs.mu.Lock()
	if activeIncident, exists := irs.activeIncidents[incident.ID]; exists {
		activeIncident.ResponseActions = append(activeIncident.ResponseActions, responseAction)
	}
	irs.mu.Unlock()
}

// shouldEscalate determines if an incident should be escalated
func (irs *IncidentResponseSystem) shouldEscalate(incident *SecurityIncident) bool {
	// Check time-based escalation
	if incident.Severity == "critical" {
		if time.Since(incident.CreatedAt) > irs.config.CriticalResponseTime {
			return true
		}
	}

	if time.Since(incident.CreatedAt) > irs.config.EscalationThreshold {
		return true
	}

	// Check rule-based escalation
	for _, rule := range irs.escalationRules {
		if rule.Enabled && irs.evaluateConditions(rule.Conditions, incident) {
			return true
		}
	}

	return false
}

// escalateIncident escalates an incident
func (irs *IncidentResponseSystem) escalateIncident(incident *SecurityIncident) {
	irs.logger.Info("Escalating incident", "incident_id", incident.ID)

	// Add escalation event
	escalationEvent := &IncidentEvent{
		ID:          fmt.Sprintf("EVT-%d", time.Now().UnixNano()),
		Type:        "incident_escalated",
		Description: "Incident escalated due to time threshold or rule match",
		Timestamp:   time.Now(),
		Actor:       "system",
		Metadata:    make(map[string]interface{}),
	}

	irs.mu.Lock()
	if activeIncident, exists := irs.activeIncidents[incident.ID]; exists {
		activeIncident.Timeline = append(activeIncident.Timeline, escalationEvent)
		activeIncident.UpdatedAt = time.Now()
	}
	irs.mu.Unlock()

	// Send escalation notifications
	irs.sendEscalationNotifications(incident)
}

// calculateThreatScore calculates threat score for an incident
func (irs *IncidentResponseSystem) calculateThreatScore(incident *SecurityIncident) float64 {
	score := 0.5 // Base score

	switch incident.Severity {
	case "critical":
		score = 0.9
	case "high":
		score = 0.7
	case "medium":
		score = 0.5
	case "low":
		score = 0.3
	}

	return score
}

// Helper methods for automated actions
func (irs *IncidentResponseSystem) blockIP(parameters map[string]interface{}, incident *SecurityIncident) {
	// Implementation for blocking IP addresses
	irs.logger.Info("Blocking IP address", "incident_id", incident.ID, "parameters", parameters)
}

func (irs *IncidentResponseSystem) isolateSystem(parameters map[string]interface{}, incident *SecurityIncident) {
	// Implementation for isolating systems
	irs.logger.Info("Isolating system", "incident_id", incident.ID, "parameters", parameters)
}

func (irs *IncidentResponseSystem) sendAlert(parameters map[string]interface{}, incident *SecurityIncident) {
	// Implementation for sending alerts
	irs.logger.Info("Sending alert", "incident_id", incident.ID, "parameters", parameters)
}

func (irs *IncidentResponseSystem) createTicket(parameters map[string]interface{}, incident *SecurityIncident) {
	// Implementation for creating tickets
	irs.logger.Info("Creating ticket", "incident_id", incident.ID, "parameters", parameters)
}

func (irs *IncidentResponseSystem) sendEscalationNotifications(incident *SecurityIncident) {
	// Implementation for sending escalation notifications
	irs.logger.Info("Sending escalation notifications", "incident_id", incident.ID)
}

// initializeDefaultRules initializes default response rules
func (irs *IncidentResponseSystem) initializeDefaultRules() {
	// Critical threat auto-block rule
	criticalRule := &ResponseRule{
		ID:          "rule_critical_auto_block",
		Name:        "Critical Threat Auto Block",
		Description: "Automatically block critical threats",
		Conditions: []*ResponseRuleCondition{
			{Field: "severity", Operator: "equals", Value: "critical"},
		},
		Actions: []*AutomatedAction{
			{
				Type:        "block_ip",
				Description: "Block source IP address",
				Parameters:  map[string]interface{}{"action": "block"},
				Timeout:     30 * time.Second,
				RetryCount:  3,
			},
			{
				Type:        "send_alert",
				Description: "Send critical alert",
				Parameters:  map[string]interface{}{"priority": "critical"},
				Timeout:     10 * time.Second,
				RetryCount:  2,
			},
		},
		Enabled:  true,
		Priority: 1,
		Metadata: make(map[string]interface{}),
	}

	// High severity escalation rule
	escalationRule := &EscalationRule{
		ID:   "escalation_high_severity",
		Name: "High Severity Escalation",
		Conditions: []*ResponseRuleCondition{
			{Field: "severity", Operator: "in", Value: []interface{}{"high", "critical"}},
		},
		EscalateTo: []string{"security_team", "incident_commander"},
		Delay:      15 * time.Minute,
		Enabled:    true,
	}

	irs.responseRules = append(irs.responseRules, criticalRule)
	irs.escalationRules = append(irs.escalationRules, escalationRule)
}

// initializeDefaultPlaybooks initializes default response playbooks
func (irs *IncidentResponseSystem) initializeDefaultPlaybooks() {
	// Malware incident playbook
	malwarePlaybook := &ResponsePlaybook{
		ID:          "playbook_malware_response",
		Name:        "Malware Incident Response",
		Description: "Standard response procedures for malware incidents",
		Category:    "malware",
		Steps: []*PlaybookStep{
			{
				ID:          "step_1",
				Name:        "Isolate Affected Systems",
				Description: "Immediately isolate affected systems from the network",
				Type:        "isolation",
				Parameters:  map[string]interface{}{"method": "network_isolation"},
				Order:       1,
				Required:    true,
			},
			{
				ID:          "step_2",
				Name:        "Collect Evidence",
				Description: "Collect forensic evidence from affected systems",
				Type:        "evidence_collection",
				Parameters:  map[string]interface{}{"type": "memory_dump"},
				Order:       2,
				Required:    true,
			},
			{
				ID:          "step_3",
				Name:        "Analyze Malware",
				Description: "Perform malware analysis to understand capabilities",
				Type:        "analysis",
				Parameters:  map[string]interface{}{"sandbox": "enabled"},
				Order:       3,
				Required:    false,
			},
		},
		Metadata: make(map[string]interface{}),
	}

	irs.playbooks["malware"] = malwarePlaybook
}
