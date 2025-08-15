package security

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// ATLASFramework implements MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)
type ATLASFramework struct {
	logger           *logger.Logger
	tactics          map[string]*ATLASTactic
	techniques       map[string]*ATLASTechnique
	mitigations      map[string]*ATLASMitigation
	detectionRules   map[string]*DetectionRule
	mitigationEngine *MitigationEngine
	threatMapper     *ThreatMapper
	config           *ATLASConfig
	mu               sync.RWMutex
}

// ATLASConfig configuration for MITRE ATLAS framework
type ATLASConfig struct {
	EnableRealTimeMapping   bool          `json:"enable_real_time_mapping"`
	EnableAutoMitigation    bool          `json:"enable_auto_mitigation"`
	ThreatIntelligenceFeeds []string      `json:"threat_intelligence_feeds"`
	UpdateInterval          time.Duration `json:"update_interval"`
	LogAllMappings          bool          `json:"log_all_mappings"`
	EnableThreatHunting     bool          `json:"enable_threat_hunting"`
	MitigationThreshold     float64       `json:"mitigation_threshold"`
	DetectionSensitivity    string        `json:"detection_sensitivity"`
}

// ATLASTactic represents a MITRE ATLAS tactic
type ATLASTactic struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Techniques  []string               `json:"techniques"`
	Phase       string                 `json:"phase"`
	Platforms   []string               `json:"platforms"`
	DataSources []string               `json:"data_sources"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// ATLASTechnique represents a MITRE ATLAS technique
type ATLASTechnique struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	TacticID       string                 `json:"tactic_id"`
	SubTechniques  []string               `json:"sub_techniques"`
	Platforms      []string               `json:"platforms"`
	DataSources    []string               `json:"data_sources"`
	Mitigations    []string               `json:"mitigations"`
	DetectionRules []string               `json:"detection_rules"`
	Examples       []TechniqueExample     `json:"examples"`
	Severity       string                 `json:"severity"`
	Likelihood     float64                `json:"likelihood"`
	Impact         float64                `json:"impact"`
	Metadata       map[string]interface{} `json:"metadata"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// ATLASMitigation represents a MITRE ATLAS mitigation
type ATLASMitigation struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Techniques     []string               `json:"techniques"`
	Implementation string                 `json:"implementation"`
	Effectiveness  float64                `json:"effectiveness"`
	Cost           string                 `json:"cost"`
	Complexity     string                 `json:"complexity"`
	Prerequisites  []string               `json:"prerequisites"`
	Limitations    []string               `json:"limitations"`
	References     []string               `json:"references"`
	Metadata       map[string]interface{} `json:"metadata"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// DetectionRule represents a detection rule for ATLAS techniques
type DetectionRule struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	TechniqueID    string                 `json:"technique_id"`
	RuleType       string                 `json:"rule_type"`
	Pattern        string                 `json:"pattern"`
	Severity       string                 `json:"severity"`
	Confidence     float64                `json:"confidence"`
	FalsePositives []string               `json:"false_positives"`
	DataSources    []string               `json:"data_sources"`
	Query          string                 `json:"query"`
	Enabled        bool                   `json:"enabled"`
	Metadata       map[string]interface{} `json:"metadata"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// TechniqueExample represents an example of a technique implementation
type TechniqueExample struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Code        string                 `json:"code"`
	Platform    string                 `json:"platform"`
	References  []string               `json:"references"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatEvent represents a detected threat event mapped to ATLAS
type ThreatEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	TacticID    string                 `json:"tactic_id"`
	TechniqueID string                 `json:"technique_id"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	SourceIP    string                 `json:"source_ip"`
	TargetAsset string                 `json:"target_asset"`
	Description string                 `json:"description"`
	Evidence    []Evidence             `json:"evidence"`
	Mitigations []string               `json:"mitigations"`
	Status      string                 `json:"status"`
	AssignedTo  string                 `json:"assigned_to"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Evidence represents evidence for a threat event
type Evidence struct {
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Data      string                 `json:"data"`
	Hash      string                 `json:"hash"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// MitigationEngine handles automatic mitigation responses
type MitigationEngine struct {
	logger          *logger.Logger
	mitigations     map[string]*ATLASMitigation
	activeResponses map[string]*ActiveResponse
	config          *MitigationConfig
	mu              sync.RWMutex
}

// MitigationConfig configuration for mitigation engine
type MitigationConfig struct {
	EnableAutoResponse     bool          `json:"enable_auto_response"`
	ResponseDelay          time.Duration `json:"response_delay"`
	MaxConcurrentResponses int           `json:"max_concurrent_responses"`
	RequireApproval        bool          `json:"require_approval"`
	NotificationChannels   []string      `json:"notification_channels"`
	EscalationThreshold    float64       `json:"escalation_threshold"`
}

// ActiveResponse represents an active mitigation response
type ActiveResponse struct {
	ID            string                 `json:"id"`
	ThreatEventID string                 `json:"threat_event_id"`
	MitigationID  string                 `json:"mitigation_id"`
	Status        string                 `json:"status"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       *time.Time             `json:"end_time"`
	Effectiveness float64                `json:"effectiveness"`
	SideEffects   []string               `json:"side_effects"`
	ApprovedBy    string                 `json:"approved_by"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ThreatMapper maps threats to ATLAS framework
type ThreatMapper struct {
	logger       *logger.Logger
	mappingRules map[string]*MappingRule
	config       *MappingConfig
	mu           sync.RWMutex
}

// MappingRule represents a rule for mapping threats to ATLAS
type MappingRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Pattern     string                 `json:"pattern"`
	TacticID    string                 `json:"tactic_id"`
	TechniqueID string                 `json:"technique_id"`
	Confidence  float64                `json:"confidence"`
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// MappingConfig configuration for threat mapping
type MappingConfig struct {
	EnableFuzzyMatching   bool    `json:"enable_fuzzy_matching"`
	ConfidenceThreshold   float64 `json:"confidence_threshold"`
	MaxMappingAttempts    int     `json:"max_mapping_attempts"`
	EnableMachineLearning bool    `json:"enable_machine_learning"`
	UpdateMappingRules    bool    `json:"update_mapping_rules"`
}

// NewATLASFramework creates a new MITRE ATLAS framework instance
func NewATLASFramework(config *ATLASConfig, logger *logger.Logger) *ATLASFramework {
	if config == nil {
		config = DefaultATLASConfig()
	}

	framework := &ATLASFramework{
		logger:         logger,
		tactics:        make(map[string]*ATLASTactic),
		techniques:     make(map[string]*ATLASTechnique),
		mitigations:    make(map[string]*ATLASMitigation),
		detectionRules: make(map[string]*DetectionRule),
		config:         config,
	}

	// Initialize mitigation engine
	mitigationConfig := &MitigationConfig{
		EnableAutoResponse:     config.EnableAutoMitigation,
		ResponseDelay:          5 * time.Second,
		MaxConcurrentResponses: 10,
		RequireApproval:        true,
		EscalationThreshold:    0.8,
	}
	framework.mitigationEngine = NewMitigationEngine(mitigationConfig, logger)

	// Initialize threat mapper
	mappingConfig := &MappingConfig{
		EnableFuzzyMatching:   true,
		ConfidenceThreshold:   0.7,
		MaxMappingAttempts:    3,
		EnableMachineLearning: true,
		UpdateMappingRules:    true,
	}
	framework.threatMapper = NewThreatMapper(mappingConfig, logger)

	// Load default ATLAS data
	framework.loadDefaultATLASData()

	return framework
}

// DefaultATLASConfig returns default configuration for ATLAS framework
func DefaultATLASConfig() *ATLASConfig {
	return &ATLASConfig{
		EnableRealTimeMapping:   true,
		EnableAutoMitigation:    false,
		ThreatIntelligenceFeeds: []string{},
		UpdateInterval:          1 * time.Hour,
		LogAllMappings:          true,
		EnableThreatHunting:     true,
		MitigationThreshold:     0.7,
		DetectionSensitivity:    "medium",
	}
}

// AnalyzeThreat analyzes a threat and maps it to ATLAS framework
func (a *ATLASFramework) AnalyzeThreat(ctx context.Context, threat *ThreatAnalysisRequest) (*ThreatAnalysisResult, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := &ThreatAnalysisResult{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		RequestID: threat.ID,
	}

	// Map threat to ATLAS tactics and techniques
	mappings, err := a.threatMapper.MapThreat(ctx, threat)
	if err != nil {
		a.logger.WithError(err).Error("Failed to map threat to ATLAS")
		return nil, fmt.Errorf("threat mapping failed: %w", err)
	}

	result.Mappings = mappings

	// Analyze each mapping
	for _, mapping := range mappings {
		// Get technique details
		technique, exists := a.techniques[mapping.TechniqueID]
		if !exists {
			continue
		}

		// Calculate risk score
		riskScore := a.calculateRiskScore(technique, mapping.Confidence)
		mapping.RiskScore = riskScore

		// Get applicable mitigations
		mitigations := a.getApplicableMitigations(technique.ID)
		mapping.Mitigations = mitigations

		// Check if auto-mitigation should be triggered
		if a.config.EnableAutoMitigation && riskScore >= a.config.MitigationThreshold {
			err := a.triggerAutoMitigation(ctx, mapping, threat)
			if err != nil {
				a.logger.WithError(err).Error("Auto-mitigation failed")
			}
		}
	}

	// Log the analysis if configured
	if a.config.LogAllMappings {
		a.logger.WithFields(map[string]interface{}{
			"threat_id":      threat.ID,
			"mappings_count": len(mappings),
			"max_risk_score": a.getMaxRiskScore(mappings),
		}).Info("Threat analyzed and mapped to ATLAS")
	}

	return result, nil
}

// DetectTechnique detects if a specific ATLAS technique is being used
func (a *ATLASFramework) DetectTechnique(ctx context.Context, techniqueID string, evidence *Evidence) (*DetectionResult, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	technique, exists := a.techniques[techniqueID]
	if !exists {
		return nil, fmt.Errorf("technique %s not found", techniqueID)
	}

	result := &DetectionResult{
		ID:          uuid.New().String(),
		TechniqueID: techniqueID,
		Timestamp:   time.Now(),
		Evidence:    evidence,
	}

	// Get detection rules for this technique
	rules := a.getDetectionRules(techniqueID)

	// Evaluate each rule against the evidence
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		match, confidence := a.evaluateDetectionRule(rule, evidence)
		if match {
			result.Detected = true
			result.Confidence = confidence
			result.RuleName = rule.Name
			result.Severity = rule.Severity
			break
		}
	}

	// Create threat event if detection is positive
	if result.Detected {
		threatEvent := &ThreatEvent{
			ID:          uuid.New().String(),
			Timestamp:   time.Now(),
			TacticID:    technique.TacticID,
			TechniqueID: techniqueID,
			Severity:    result.Severity,
			Confidence:  result.Confidence,
			Description: fmt.Sprintf("Detected technique: %s", technique.Name),
			Evidence:    []Evidence{*evidence},
			Status:      "detected",
		}

		// Store the threat event
		a.storeThreatEvent(threatEvent)
	}

	return result, nil
}

// GetMitigations returns applicable mitigations for a technique
func (a *ATLASFramework) GetMitigations(techniqueID string) ([]*ATLASMitigation, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	technique, exists := a.techniques[techniqueID]
	if !exists {
		return nil, fmt.Errorf("technique %s not found", techniqueID)
	}

	var mitigations []*ATLASMitigation
	for _, mitigationID := range technique.Mitigations {
		if mitigation, exists := a.mitigations[mitigationID]; exists {
			mitigations = append(mitigations, mitigation)
		}
	}

	return mitigations, nil
}

// ThreatAnalysisRequest represents a request for threat analysis
type ThreatAnalysisRequest struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Data      string                 `json:"data"`
	Context   map[string]interface{} `json:"context"`
	Timestamp time.Time              `json:"timestamp"`
}

// ThreatAnalysisResult represents the result of threat analysis
type ThreatAnalysisResult struct {
	ID        string           `json:"id"`
	Timestamp time.Time        `json:"timestamp"`
	RequestID string           `json:"request_id"`
	Mappings  []*ThreatMapping `json:"mappings"`
}

// ThreatMapping represents a mapping of threat to ATLAS framework
type ThreatMapping struct {
	TacticID    string   `json:"tactic_id"`
	TechniqueID string   `json:"technique_id"`
	Confidence  float64  `json:"confidence"`
	RiskScore   float64  `json:"risk_score"`
	Mitigations []string `json:"mitigations"`
	Evidence    string   `json:"evidence"`
}

// DetectionResult represents the result of technique detection
type DetectionResult struct {
	ID          string    `json:"id"`
	TechniqueID string    `json:"technique_id"`
	Timestamp   time.Time `json:"timestamp"`
	Detected    bool      `json:"detected"`
	Confidence  float64   `json:"confidence"`
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"`
	Evidence    *Evidence `json:"evidence"`
}

// NewMitigationEngine creates a new mitigation engine
func NewMitigationEngine(config *MitigationConfig, logger *logger.Logger) *MitigationEngine {
	return &MitigationEngine{
		logger:          logger,
		mitigations:     make(map[string]*ATLASMitigation),
		activeResponses: make(map[string]*ActiveResponse),
		config:          config,
	}
}

// NewThreatMapper creates a new threat mapper
func NewThreatMapper(config *MappingConfig, logger *logger.Logger) *ThreatMapper {
	return &ThreatMapper{
		logger:       logger,
		mappingRules: make(map[string]*MappingRule),
		config:       config,
	}
}

// MapThreat maps a threat to ATLAS framework
func (tm *ThreatMapper) MapThreat(ctx context.Context, threat *ThreatAnalysisRequest) ([]*ThreatMapping, error) {
	var mappings []*ThreatMapping

	// Simple pattern-based mapping for demonstration
	// In production, this would use ML models and more sophisticated analysis

	// Check for prompt injection patterns
	if strings.Contains(strings.ToLower(threat.Data), "ignore previous instructions") ||
		strings.Contains(strings.ToLower(threat.Data), "system prompt") ||
		strings.Contains(strings.ToLower(threat.Data), "jailbreak") {

		mapping := &ThreatMapping{
			TacticID:    "TA0001", // Initial Access
			TechniqueID: "T1059",  // Prompt Injection
			Confidence:  0.8,
			Evidence:    "Prompt injection patterns detected",
		}
		mappings = append(mappings, mapping)
	}

	// Check for data exfiltration patterns
	if strings.Contains(strings.ToLower(threat.Data), "extract") ||
		strings.Contains(strings.ToLower(threat.Data), "dump") ||
		strings.Contains(strings.ToLower(threat.Data), "reveal") {

		mapping := &ThreatMapping{
			TacticID:    "TA0010", // Exfiltration
			TechniqueID: "T1041",  // Data Exfiltration
			Confidence:  0.7,
			Evidence:    "Data exfiltration patterns detected",
		}
		mappings = append(mappings, mapping)
	}

	return mappings, nil
}

// loadDefaultATLASData loads default ATLAS tactics, techniques, and mitigations
func (a *ATLASFramework) loadDefaultATLASData() {
	// Load default tactics
	a.loadDefaultTactics()

	// Load default techniques
	a.loadDefaultTechniques()

	// Load default mitigations
	a.loadDefaultMitigations()

	// Load default detection rules
	a.loadDefaultDetectionRules()
}

// loadDefaultTactics loads default ATLAS tactics
func (a *ATLASFramework) loadDefaultTactics() {
	tactics := []*ATLASTactic{
		{
			ID:          "TA0001",
			Name:        "Initial Access",
			Description: "Adversaries are trying to get into your AI system",
			Phase:       "initial-access",
			Platforms:   []string{"AI/ML", "Cloud", "Web"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "TA0002",
			Name:        "ML Model Access",
			Description: "Adversaries are trying to gain access to machine learning models",
			Phase:       "model-access",
			Platforms:   []string{"AI/ML"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "TA0010",
			Name:        "Exfiltration",
			Description: "Adversaries are trying to steal data or model information",
			Phase:       "exfiltration",
			Platforms:   []string{"AI/ML", "Cloud", "Web"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, tactic := range tactics {
		a.tactics[tactic.ID] = tactic
	}
}

// loadDefaultTechniques loads default ATLAS techniques
func (a *ATLASFramework) loadDefaultTechniques() {
	techniques := []*ATLASTechnique{
		{
			ID:          "T1059",
			Name:        "Prompt Injection",
			Description: "Adversaries may inject malicious prompts to manipulate AI model behavior",
			TacticID:    "TA0001",
			Platforms:   []string{"AI/ML", "LLM"},
			Severity:    "high",
			Likelihood:  0.8,
			Impact:      0.9,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "T1041",
			Name:        "Data Exfiltration",
			Description: "Adversaries may attempt to extract training data or model parameters",
			TacticID:    "TA0010",
			Platforms:   []string{"AI/ML", "Cloud"},
			Severity:    "high",
			Likelihood:  0.6,
			Impact:      0.8,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "T1200",
			Name:        "Model Inversion",
			Description: "Adversaries may use model inversion attacks to extract training data",
			TacticID:    "TA0002",
			Platforms:   []string{"AI/ML"},
			Severity:    "medium",
			Likelihood:  0.4,
			Impact:      0.7,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, technique := range techniques {
		a.techniques[technique.ID] = technique
	}
}

// loadDefaultMitigations loads default ATLAS mitigations
func (a *ATLASFramework) loadDefaultMitigations() {
	mitigations := []*ATLASMitigation{
		{
			ID:             "M1001",
			Name:           "Input Validation",
			Description:    "Implement comprehensive input validation and sanitization",
			Techniques:     []string{"T1059"},
			Implementation: "Deploy input filtering and validation mechanisms",
			Effectiveness:  0.8,
			Cost:           "low",
			Complexity:     "medium",
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			ID:             "M1002",
			Name:           "Output Filtering",
			Description:    "Implement output filtering to prevent data leakage",
			Techniques:     []string{"T1041"},
			Implementation: "Deploy output sanitization and filtering",
			Effectiveness:  0.7,
			Cost:           "low",
			Complexity:     "medium",
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			ID:             "M1003",
			Name:           "Model Access Control",
			Description:    "Implement strict access controls for ML models",
			Techniques:     []string{"T1200"},
			Implementation: "Deploy authentication and authorization mechanisms",
			Effectiveness:  0.9,
			Cost:           "medium",
			Complexity:     "high",
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
	}

	for _, mitigation := range mitigations {
		a.mitigations[mitigation.ID] = mitigation
	}
}

// loadDefaultDetectionRules loads default detection rules
func (a *ATLASFramework) loadDefaultDetectionRules() {
	rules := []*DetectionRule{
		{
			ID:          "DR001",
			Name:        "Prompt Injection Detection",
			Description: "Detects prompt injection attempts",
			TechniqueID: "T1059",
			RuleType:    "pattern",
			Pattern:     `(?i)(ignore previous|system prompt|jailbreak|override)`,
			Severity:    "high",
			Confidence:  0.8,
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "DR002",
			Name:        "Data Exfiltration Detection",
			Description: "Detects data exfiltration attempts",
			TechniqueID: "T1041",
			RuleType:    "pattern",
			Pattern:     `(?i)(extract|dump|reveal|show me)`,
			Severity:    "high",
			Confidence:  0.7,
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, rule := range rules {
		a.detectionRules[rule.ID] = rule
	}
}

// calculateRiskScore calculates risk score based on technique and confidence
func (a *ATLASFramework) calculateRiskScore(technique *ATLASTechnique, confidence float64) float64 {
	// Risk score = (Impact * Likelihood * Confidence) / 3
	return (technique.Impact * technique.Likelihood * confidence) / 3.0
}

// getApplicableMitigations returns applicable mitigations for a technique
func (a *ATLASFramework) getApplicableMitigations(techniqueID string) []string {
	var mitigations []string

	for _, mitigation := range a.mitigations {
		for _, techID := range mitigation.Techniques {
			if techID == techniqueID {
				mitigations = append(mitigations, mitigation.ID)
				break
			}
		}
	}

	return mitigations
}

// triggerAutoMitigation triggers automatic mitigation response
func (a *ATLASFramework) triggerAutoMitigation(ctx context.Context, mapping *ThreatMapping, threat *ThreatAnalysisRequest) error {
	// Get applicable mitigations
	mitigations := a.getApplicableMitigations(mapping.TechniqueID)

	if len(mitigations) == 0 {
		return fmt.Errorf("no mitigations available for technique %s", mapping.TechniqueID)
	}

	// Select the most effective mitigation
	var selectedMitigation *ATLASMitigation
	maxEffectiveness := 0.0

	for _, mitigationID := range mitigations {
		if mitigation, exists := a.mitigations[mitigationID]; exists {
			if mitigation.Effectiveness > maxEffectiveness {
				maxEffectiveness = mitigation.Effectiveness
				selectedMitigation = mitigation
			}
		}
	}

	if selectedMitigation == nil {
		return fmt.Errorf("no suitable mitigation found")
	}

	// Create active response
	response := &ActiveResponse{
		ID:            uuid.New().String(),
		ThreatEventID: threat.ID,
		MitigationID:  selectedMitigation.ID,
		Status:        "initiated",
		StartTime:     time.Now(),
		Effectiveness: selectedMitigation.Effectiveness,
	}

	// Store active response
	a.mitigationEngine.mu.Lock()
	a.mitigationEngine.activeResponses[response.ID] = response
	a.mitigationEngine.mu.Unlock()

	a.logger.WithFields(map[string]interface{}{
		"threat_id":     threat.ID,
		"mitigation_id": selectedMitigation.ID,
		"response_id":   response.ID,
	}).Info("Auto-mitigation triggered")

	return nil
}

// getMaxRiskScore returns the maximum risk score from mappings
func (a *ATLASFramework) getMaxRiskScore(mappings []*ThreatMapping) float64 {
	maxScore := 0.0
	for _, mapping := range mappings {
		if mapping.RiskScore > maxScore {
			maxScore = mapping.RiskScore
		}
	}
	return maxScore
}

// getDetectionRules returns detection rules for a technique
func (a *ATLASFramework) getDetectionRules(techniqueID string) []*DetectionRule {
	var rules []*DetectionRule

	for _, rule := range a.detectionRules {
		if rule.TechniqueID == techniqueID {
			rules = append(rules, rule)
		}
	}

	return rules
}

// evaluateDetectionRule evaluates a detection rule against evidence
func (a *ATLASFramework) evaluateDetectionRule(rule *DetectionRule, evidence *Evidence) (bool, float64) {
	// Simple pattern matching for demonstration
	// In production, this would use more sophisticated analysis

	if rule.RuleType == "pattern" {
		// Use regex pattern matching
		matched := strings.Contains(strings.ToLower(evidence.Data), strings.ToLower(rule.Pattern))
		if matched {
			return true, rule.Confidence
		}
	}

	return false, 0.0
}

// storeThreatEvent stores a threat event
func (a *ATLASFramework) storeThreatEvent(event *ThreatEvent) {
	// In production, this would store to a database
	a.logger.WithFields(map[string]interface{}{
		"event_id":     event.ID,
		"technique_id": event.TechniqueID,
		"severity":     event.Severity,
		"confidence":   event.Confidence,
	}).Info("Threat event stored")
}

// GetTactics returns all available tactics
func (a *ATLASFramework) GetTactics() map[string]*ATLASTactic {
	a.mu.RLock()
	defer a.mu.RUnlock()

	tactics := make(map[string]*ATLASTactic)
	for id, tactic := range a.tactics {
		tactics[id] = tactic
	}

	return tactics
}

// GetTechniques returns all available techniques
func (a *ATLASFramework) GetTechniques() map[string]*ATLASTechnique {
	a.mu.RLock()
	defer a.mu.RUnlock()

	techniques := make(map[string]*ATLASTechnique)
	for id, technique := range a.techniques {
		techniques[id] = technique
	}

	return techniques
}

// GetTechniquesByTactic returns techniques for a specific tactic
func (a *ATLASFramework) GetTechniquesByTactic(tacticID string) []*ATLASTechnique {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var techniques []*ATLASTechnique
	for _, technique := range a.techniques {
		if technique.TacticID == tacticID {
			techniques = append(techniques, technique)
		}
	}

	return techniques
}

// AddCustomTechnique adds a custom technique to the framework
func (a *ATLASFramework) AddCustomTechnique(technique *ATLASTechnique) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if technique.ID == "" {
		technique.ID = uuid.New().String()
	}

	technique.CreatedAt = time.Now()
	technique.UpdatedAt = time.Now()

	a.techniques[technique.ID] = technique

	a.logger.WithFields(map[string]interface{}{
		"technique_id":   technique.ID,
		"technique_name": technique.Name,
	}).Info("Custom technique added")

	return nil
}

// AddCustomMitigation adds a custom mitigation to the framework
func (a *ATLASFramework) AddCustomMitigation(mitigation *ATLASMitigation) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if mitigation.ID == "" {
		mitigation.ID = uuid.New().String()
	}

	mitigation.CreatedAt = time.Now()
	mitigation.UpdatedAt = time.Now()

	a.mitigations[mitigation.ID] = mitigation

	a.logger.WithFields(map[string]interface{}{
		"mitigation_id":   mitigation.ID,
		"mitigation_name": mitigation.Name,
	}).Info("Custom mitigation added")

	return nil
}

// GetFrameworkStats returns statistics about the framework
func (a *ATLASFramework) GetFrameworkStats() *FrameworkStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return &FrameworkStats{
		TotalTactics:        len(a.tactics),
		TotalTechniques:     len(a.techniques),
		TotalMitigations:    len(a.mitigations),
		TotalDetectionRules: len(a.detectionRules),
		LastUpdated:         time.Now(),
	}
}

// FrameworkStats represents statistics about the ATLAS framework
type FrameworkStats struct {
	TotalTactics        int       `json:"total_tactics"`
	TotalTechniques     int       `json:"total_techniques"`
	TotalMitigations    int       `json:"total_mitigations"`
	TotalDetectionRules int       `json:"total_detection_rules"`
	LastUpdated         time.Time `json:"last_updated"`
}
