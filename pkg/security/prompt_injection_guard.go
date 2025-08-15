package security

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// PromptInjectionGuard protects against prompt injection attacks
type PromptInjectionGuard struct {
	logger           *logger.Logger
	patterns         []*InjectionPattern
	semanticAnalyzer *SemanticAnalyzer
	contextAnalyzer  *ContextAnalyzer
	iteuAnalyzer     *ITEUAnalyzer
	config           *PromptGuardConfig
}

// PromptGuardConfig configuration for prompt injection protection
type PromptGuardConfig struct {
	EnableSemanticAnalysis bool    `json:"enable_semantic_analysis"`
	EnableContextAnalysis  bool    `json:"enable_context_analysis"`
	StrictMode             bool    `json:"strict_mode"`
	ConfidenceThreshold    float64 `json:"confidence_threshold"`
	MaxPromptLength        int     `json:"max_prompt_length"`
	EnableLearning         bool    `json:"enable_learning"`
	BlockSuspiciousPrompts bool    `json:"block_suspicious_prompts"`
	LogAllAttempts         bool    `json:"log_all_attempts"`
}

// InjectionPattern represents a prompt injection pattern
type InjectionPattern struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Pattern     string    `json:"pattern"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Description string    `json:"description"`
	Examples    []string  `json:"examples"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SemanticAnalyzer analyzes semantic content for injection attempts
type SemanticAnalyzer struct {
	logger             *logger.Logger
	suspiciousKeywords []string
	commandPatterns    []*regexp.Regexp
	roleManipulations  []*regexp.Regexp
	systemOverrides    []*regexp.Regexp
}

// UserContext represents user behavior context
type UserContext struct {
	UserID             string
	RequestHistory     []string
	BehaviorPatterns   map[string]int
	ConversationFlow   []string
	LastActivity       time.Time
	SuspiciousActivity []string
	ThreatScore        float64
	RequestCount       int
	AverageRequestSize int
	RequestFrequency   float64
}

// ContextAnalyzer analyzes context for injection attempts
type ContextAnalyzer struct {
	logger              *logger.Logger
	conversationHistory []string
	userBehaviorProfile map[string]interface{}
	anomalyThreshold    float64
	userContexts        map[string]*UserContext
	mu                  sync.RWMutex
}

// ITEUAnalyzer implements Intent-Technique-Evasion-Utility taxonomy for advanced prompt injection detection
type ITEUAnalyzer struct {
	logger            *logger.Logger
	intentClassifier  *IntentClassifier
	techniqueDetector *TechniqueDetector
	evasionAnalyzer   *EvasionAnalyzer
	utilityAssessor   *UtilityAssessor
	config            *ITEUConfig
	mu                sync.RWMutex
}

// ITEUConfig configuration for ITEU analyzer
type ITEUConfig struct {
	EnableIntentAnalysis     bool    `json:"enable_intent_analysis"`
	EnableTechniqueDetection bool    `json:"enable_technique_detection"`
	EnableEvasionAnalysis    bool    `json:"enable_evasion_analysis"`
	EnableUtilityAssessment  bool    `json:"enable_utility_assessment"`
	ConfidenceThreshold      float64 `json:"confidence_threshold"`
	StrictMode               bool    `json:"strict_mode"`
	LogDetailedAnalysis      bool    `json:"log_detailed_analysis"`
}

// ITEUResult represents the result of ITEU analysis
type ITEUResult struct {
	ID              string           `json:"id"`
	PromptID        string           `json:"prompt_id"`
	Intent          *IntentResult    `json:"intent"`
	Technique       *TechniqueResult `json:"technique"`
	Evasion         *EvasionResult   `json:"evasion"`
	Utility         *UtilityResult   `json:"utility"`
	OverallScore    float64          `json:"overall_score"`
	ThreatLevel     string           `json:"threat_level"`
	IsInjection     bool             `json:"is_injection"`
	Confidence      float64          `json:"confidence"`
	Recommendations []string         `json:"recommendations"`
	AnalyzedAt      time.Time        `json:"analyzed_at"`
}

// IntentClassifier classifies the intent behind prompts
type IntentClassifier struct {
	logger           *logger.Logger
	intentPatterns   map[string]*IntentPattern
	maliciousIntents []string
}

// IntentPattern represents a pattern for intent classification
type IntentPattern struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`
	Intent      string    `json:"intent"`
	Malicious   bool      `json:"malicious"`
	Confidence  float64   `json:"confidence"`
	Examples    []string  `json:"examples"`
	CreatedAt   time.Time `json:"created_at"`
}

// IntentResult represents intent analysis results
type IntentResult struct {
	PrimaryIntent    string   `json:"primary_intent"`
	SecondaryIntents []string `json:"secondary_intents"`
	MaliciousIntent  bool     `json:"malicious_intent"`
	IntentConfidence float64  `json:"intent_confidence"`
	IntentEvidence   []string `json:"intent_evidence"`
}

// TechniqueDetector detects specific injection techniques
type TechniqueDetector struct {
	logger             *logger.Logger
	techniquePatterns  map[string]*TechniquePattern
	advancedTechniques []string
}

// TechniquePattern represents a specific injection technique
type TechniquePattern struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Category      string    `json:"category"`
	Pattern       string    `json:"pattern"`
	Severity      string    `json:"severity"`
	Complexity    string    `json:"complexity"`
	Effectiveness float64   `json:"effectiveness"`
	Examples      []string  `json:"examples"`
	Mitigations   []string  `json:"mitigations"`
	CreatedAt     time.Time `json:"created_at"`
}

// TechniqueResult represents technique detection results
type TechniqueResult struct {
	DetectedTechniques []string `json:"detected_techniques"`
	PrimaryTechnique   string   `json:"primary_technique"`
	TechniqueCategory  string   `json:"technique_category"`
	Complexity         string   `json:"complexity"`
	Effectiveness      float64  `json:"effectiveness"`
	TechniqueEvidence  []string `json:"technique_evidence"`
}

// EvasionAnalyzer analyzes evasion attempts
type EvasionAnalyzer struct {
	logger           *logger.Logger
	evasionPatterns  map[string]*EvasionPattern
	obfuscationTypes []string
}

// EvasionPattern represents an evasion technique pattern
type EvasionPattern struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Type            string    `json:"type"`
	Pattern         string    `json:"pattern"`
	Sophistication  string    `json:"sophistication"`
	Success         float64   `json:"success_rate"`
	Examples        []string  `json:"examples"`
	Countermeasures []string  `json:"countermeasures"`
	CreatedAt       time.Time `json:"created_at"`
}

// EvasionResult represents evasion analysis results
type EvasionResult struct {
	EvasionAttempted   bool     `json:"evasion_attempted"`
	EvasionTechniques  []string `json:"evasion_techniques"`
	ObfuscationLevel   string   `json:"obfuscation_level"`
	Sophistication     string   `json:"sophistication"`
	SuccessProbability float64  `json:"success_probability"`
	EvasionEvidence    []string `json:"evasion_evidence"`
}

// UtilityAssessor assesses the utility/impact of successful injection
type UtilityAssessor struct {
	logger         *logger.Logger
	impactMetrics  map[string]float64
	utilityFactors []string
}

// UtilityResult represents utility assessment results
type UtilityResult struct {
	PotentialImpact string   `json:"potential_impact"`
	ImpactScore     float64  `json:"impact_score"`
	TargetSystems   []string `json:"target_systems"`
	DataAtRisk      []string `json:"data_at_risk"`
	BusinessImpact  string   `json:"business_impact"`
	UtilityEvidence []string `json:"utility_evidence"`
}

// PromptAnalysis represents the result of prompt analysis
type PromptAnalysis struct {
	ID               string                 `json:"id"`
	PromptID         string                 `json:"prompt_id"`
	IsInjection      bool                   `json:"is_injection"`
	Confidence       float64                `json:"confidence"`
	ThreatLevel      string                 `json:"threat_level"`
	DetectedPatterns []*DetectedPattern     `json:"detected_patterns"`
	SemanticAnalysis *SemanticResult        `json:"semantic_analysis"`
	ContextAnalysis  *ContextResult         `json:"context_analysis"`
	ITEUAnalysis     *ITEUResult            `json:"iteu_analysis"`
	Recommendations  []string               `json:"recommendations"`
	BlockRecommended bool                   `json:"block_recommended"`
	Metadata         map[string]interface{} `json:"metadata"`
	AnalyzedAt       time.Time              `json:"analyzed_at"`
}

// DetectedPattern represents a detected injection pattern
type DetectedPattern struct {
	PatternID   string  `json:"pattern_id"`
	PatternName string  `json:"pattern_name"`
	Match       string  `json:"match"`
	Position    int     `json:"position"`
	Confidence  float64 `json:"confidence"`
	Severity    string  `json:"severity"`
}

// SemanticResult represents semantic analysis results
type SemanticResult struct {
	SuspiciousKeywords []string `json:"suspicious_keywords"`
	CommandAttempts    []string `json:"command_attempts"`
	RoleManipulations  []string `json:"role_manipulations"`
	SystemOverrides    []string `json:"system_overrides"`
	ConfidenceScore    float64  `json:"confidence_score"`
	SemanticAnomalies  []string `json:"semantic_anomalies"`
}

// ContextResult represents context analysis results
type ContextResult struct {
	BehaviorAnomaly      bool     `json:"behavior_anomaly"`
	ConversationAnomaly  bool     `json:"conversation_anomaly"`
	FrequencyAnomaly     bool     `json:"frequency_anomaly"`
	PatternDeviation     float64  `json:"pattern_deviation"`
	SuspiciousIndicators []string `json:"suspicious_indicators"`
}

// NewPromptInjectionGuard creates a new prompt injection guard
func NewPromptInjectionGuard(logger *logger.Logger) *PromptInjectionGuard {
	guard := &PromptInjectionGuard{
		logger:           logger,
		patterns:         loadInjectionPatterns(),
		semanticAnalyzer: NewSemanticAnalyzer(logger),
		contextAnalyzer:  NewContextAnalyzer(logger),
		config:           DefaultPromptGuardConfig(),
	}

	return guard
}

// DetectPromptInjection analyzes a request for prompt injection attempts
func (pig *PromptInjectionGuard) DetectPromptInjection(req *SecurityRequest) *ThreatDetection {
	analysis := pig.AnalyzePrompt(context.Background(), req.Body, req.UserID)

	if analysis.IsInjection && analysis.Confidence >= pig.config.ConfidenceThreshold {
		return &ThreatDetection{
			ID:          uuid.New().String(),
			Type:        "prompt_injection",
			Severity:    analysis.ThreatLevel,
			Confidence:  analysis.Confidence,
			Description: "Prompt injection attempt detected",
			Evidence:    pig.extractEvidence(analysis),
			Indicators:  pig.extractIndicators(analysis),
			Metadata: map[string]interface{}{
				"analysis_id":       analysis.ID,
				"detected_patterns": len(analysis.DetectedPatterns),
				"semantic_score":    analysis.SemanticAnalysis.ConfidenceScore,
				"block_recommended": analysis.BlockRecommended,
			},
			DetectedAt: time.Now(),
		}
	}

	return nil
}

// AnalyzePrompt performs comprehensive prompt analysis
func (pig *PromptInjectionGuard) AnalyzePrompt(ctx context.Context, prompt, userID string) *PromptAnalysis {
	analysis := &PromptAnalysis{
		ID:         uuid.New().String(),
		PromptID:   uuid.New().String(),
		AnalyzedAt: time.Now(),
		Metadata:   make(map[string]interface{}),
	}

	// Length validation
	if len(prompt) > pig.config.MaxPromptLength {
		analysis.IsInjection = true
		analysis.Confidence = 0.8
		analysis.ThreatLevel = "medium"
		analysis.Recommendations = append(analysis.Recommendations, "Prompt exceeds maximum allowed length")
		return analysis
	}

	// Pattern-based detection
	detectedPatterns := pig.detectPatterns(prompt)
	analysis.DetectedPatterns = detectedPatterns

	// Semantic analysis
	if pig.config.EnableSemanticAnalysis {
		analysis.SemanticAnalysis = pig.semanticAnalyzer.Analyze(prompt)
	}

	// Context analysis
	if pig.config.EnableContextAnalysis {
		analysis.ContextAnalysis = pig.contextAnalyzer.Analyze(prompt, userID)
	}

	// Calculate overall confidence and threat level
	analysis.Confidence = pig.calculateConfidence(analysis)
	analysis.ThreatLevel = pig.determineThreatLevel(analysis.Confidence)
	analysis.IsInjection = analysis.Confidence >= pig.config.ConfidenceThreshold
	analysis.BlockRecommended = pig.shouldBlock(analysis)

	// Generate recommendations
	analysis.Recommendations = pig.generateRecommendations(analysis)

	// Log if configured
	if pig.config.LogAllAttempts || analysis.IsInjection {
		pig.logAnalysis(analysis)
	}

	return analysis
}

// detectPatterns detects injection patterns in the prompt
func (pig *PromptInjectionGuard) detectPatterns(prompt string) []*DetectedPattern {
	var detected []*DetectedPattern

	for _, pattern := range pig.patterns {
		regex, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			continue
		}

		matches := regex.FindAllStringIndex(prompt, -1)
		for _, match := range matches {
			detected = append(detected, &DetectedPattern{
				PatternID:   pattern.ID,
				PatternName: pattern.Name,
				Match:       prompt[match[0]:match[1]],
				Position:    match[0],
				Confidence:  pattern.Confidence,
				Severity:    pattern.Severity,
			})
		}
	}

	return detected
}

// calculateConfidence calculates overall confidence score
func (pig *PromptInjectionGuard) calculateConfidence(analysis *PromptAnalysis) float64 {
	var totalConfidence float64
	var weights float64

	// Pattern-based confidence
	if len(analysis.DetectedPatterns) > 0 {
		var patternConfidence float64
		for _, pattern := range analysis.DetectedPatterns {
			patternConfidence += pattern.Confidence
		}
		patternConfidence = patternConfidence / float64(len(analysis.DetectedPatterns))
		totalConfidence += patternConfidence * 0.4
		weights += 0.4
	}

	// Semantic confidence
	if analysis.SemanticAnalysis != nil {
		totalConfidence += analysis.SemanticAnalysis.ConfidenceScore * 0.4
		weights += 0.4
	}

	// Context confidence
	if analysis.ContextAnalysis != nil {
		contextConfidence := pig.calculateContextConfidence(analysis.ContextAnalysis)
		totalConfidence += contextConfidence * 0.2
		weights += 0.2
	}

	if weights == 0 {
		return 0
	}

	return totalConfidence / weights
}

// calculateContextConfidence calculates confidence from context analysis
func (pig *PromptInjectionGuard) calculateContextConfidence(context *ContextResult) float64 {
	confidence := 0.0

	if context.BehaviorAnomaly {
		confidence += 0.3
	}
	if context.ConversationAnomaly {
		confidence += 0.3
	}
	if context.FrequencyAnomaly {
		confidence += 0.2
	}

	confidence += context.PatternDeviation * 0.2

	return confidence
}

// determineThreatLevel determines threat level based on confidence
func (pig *PromptInjectionGuard) determineThreatLevel(confidence float64) string {
	switch {
	case confidence >= 0.9:
		return "critical"
	case confidence >= 0.7:
		return "high"
	case confidence >= 0.5:
		return "medium"
	case confidence >= 0.3:
		return "low"
	default:
		return "info"
	}
}

// shouldBlock determines if the prompt should be blocked
func (pig *PromptInjectionGuard) shouldBlock(analysis *PromptAnalysis) bool {
	if !pig.config.BlockSuspiciousPrompts {
		return false
	}

	// Block based on confidence threshold
	if analysis.Confidence >= pig.config.ConfidenceThreshold {
		return true
	}

	// Block in strict mode with lower threshold
	if pig.config.StrictMode && analysis.Confidence >= 0.5 {
		return true
	}

	// Block if critical patterns detected
	for _, pattern := range analysis.DetectedPatterns {
		if pattern.Severity == "critical" && pattern.Confidence >= 0.8 {
			return true
		}
	}

	return false
}

// generateRecommendations generates security recommendations
func (pig *PromptInjectionGuard) generateRecommendations(analysis *PromptAnalysis) []string {
	var recommendations []string

	if analysis.IsInjection {
		recommendations = append(recommendations, "Block or sanitize the prompt")
		recommendations = append(recommendations, "Log the incident for security review")
		recommendations = append(recommendations, "Monitor user for additional suspicious activity")
	}

	if len(analysis.DetectedPatterns) > 0 {
		recommendations = append(recommendations, "Review detected patterns for false positives")
	}

	if analysis.SemanticAnalysis != nil && len(analysis.SemanticAnalysis.SuspiciousKeywords) > 0 {
		recommendations = append(recommendations, "Analyze semantic content for malicious intent")
	}

	return recommendations
}

// extractEvidence extracts evidence from analysis
func (pig *PromptInjectionGuard) extractEvidence(analysis *PromptAnalysis) []string {
	var evidence []string

	for _, pattern := range analysis.DetectedPatterns {
		evidence = append(evidence, fmt.Sprintf("Pattern: %s, Match: %s", pattern.PatternName, pattern.Match))
	}

	if analysis.SemanticAnalysis != nil {
		for _, keyword := range analysis.SemanticAnalysis.SuspiciousKeywords {
			evidence = append(evidence, fmt.Sprintf("Suspicious keyword: %s", keyword))
		}
	}

	return evidence
}

// extractIndicators extracts indicators from analysis
func (pig *PromptInjectionGuard) extractIndicators(analysis *PromptAnalysis) []string {
	var indicators []string

	for _, pattern := range analysis.DetectedPatterns {
		indicators = append(indicators, fmt.Sprintf("pattern:%s", pattern.PatternID))
	}

	if analysis.SemanticAnalysis != nil {
		indicators = append(indicators, fmt.Sprintf("semantic_score:%.2f", analysis.SemanticAnalysis.ConfidenceScore))
	}

	return indicators
}

// logAnalysis logs the prompt analysis
func (pig *PromptInjectionGuard) logAnalysis(analysis *PromptAnalysis) {
	pig.logger.WithFields(logger.Fields{
		"analysis_id":       analysis.ID,
		"is_injection":      analysis.IsInjection,
		"confidence":        analysis.Confidence,
		"threat_level":      analysis.ThreatLevel,
		"patterns_detected": len(analysis.DetectedPatterns),
		"block_recommended": analysis.BlockRecommended,
	}).Info("Prompt injection analysis completed")
}

// DefaultPromptGuardConfig returns default configuration
func DefaultPromptGuardConfig() *PromptGuardConfig {
	return &PromptGuardConfig{
		EnableSemanticAnalysis: true,
		EnableContextAnalysis:  true,
		StrictMode:             false,
		ConfidenceThreshold:    0.7,
		MaxPromptLength:        10000,
		EnableLearning:         true,
		BlockSuspiciousPrompts: true,
		LogAllAttempts:         false,
	}
}

// loadInjectionPatterns loads predefined injection patterns
func loadInjectionPatterns() []*InjectionPattern {
	return []*InjectionPattern{
		{
			ID:          "role_manipulation",
			Name:        "Role Manipulation",
			Pattern:     `(?i)(ignore|forget|disregard).*(previous|above|system|instructions?)`,
			Type:        "role_manipulation",
			Severity:    "high",
			Confidence:  0.8,
			Description: "Attempts to manipulate AI role or ignore instructions",
		},
		{
			ID:          "system_override",
			Name:        "System Override",
			Pattern:     `(?i)(you are now|act as|pretend to be|roleplay as).*(admin|root|system|developer)`,
			Type:        "system_override",
			Severity:    "critical",
			Confidence:  0.9,
			Description: "Attempts to override system role or permissions",
		},
		{
			ID:          "instruction_injection",
			Name:        "Instruction Injection",
			Pattern:     `(?i)(new instructions?|override|replace).*(system|prompt|rules?)`,
			Type:        "instruction_injection",
			Severity:    "high",
			Confidence:  0.8,
			Description: "Attempts to inject new instructions or override existing ones",
		},
		{
			ID:          "jailbreak_attempt",
			Name:        "Jailbreak Attempt",
			Pattern:     `(?i)(jailbreak|dan mode|developer mode|god mode|unrestricted|unlimited|uncensored)`,
			Type:        "jailbreak",
			Severity:    "critical",
			Confidence:  0.95,
			Description: "Attempts to jailbreak or bypass AI safety measures",
		},
		{
			ID:          "prompt_leakage",
			Name:        "Prompt Leakage",
			Pattern:     `(?i)(show|reveal|display|repeat).*(your|the).*(prompt|instructions?|system message|training)`,
			Type:        "prompt_leakage",
			Severity:    "high",
			Confidence:  0.85,
			Description: "Attempts to extract system prompts or training information",
		},
		{
			ID:          "data_extraction",
			Name:        "Data Extraction",
			Pattern:     `(?i)(access|get|retrieve|show|list).*(confidential|private|secret|hidden|internal).*(data|information|files?|passwords?)`,
			Type:        "data_extraction",
			Severity:    "critical",
			Confidence:  0.9,
			Description: "Attempts to extract sensitive or confidential data",
		},
		{
			ID:          "command_injection",
			Name:        "Command Injection",
			Pattern:     `(?i)(execute|run|eval|exec|system|shell|cmd|subprocess)[\s\(]`,
			Type:        "command_injection",
			Severity:    "critical",
			Confidence:  0.95,
			Description: "Attempts to execute system commands or code",
		},
		{
			ID:          "context_manipulation",
			Name:        "Context Manipulation",
			Pattern:     `(?i)(actually|wait|hold on|never mind|forget that|instead).*(tell me|show me|give me|what is)`,
			Type:        "context_manipulation",
			Severity:    "medium",
			Confidence:  0.7,
			Description: "Attempts to manipulate conversation context",
		},
		{
			ID:          "security_bypass",
			Name:        "Security Bypass",
			Pattern:     `(?i)(bypass|circumvent|disable|turn off).*(security|safety|protection|filtering|censoring)`,
			Type:        "security_bypass",
			Severity:    "critical",
			Confidence:  0.9,
			Description: "Attempts to bypass security or safety measures",
		},
		{
			ID:          "privilege_escalation",
			Name:        "Privilege Escalation",
			Pattern:     `(?i)(admin|root|system|developer|programmer).*(mode|access|privileges?|permissions?|rights)`,
			Type:        "privilege_escalation",
			Severity:    "critical",
			Confidence:  0.85,
			Description: "Attempts to escalate privileges or gain unauthorized access",
		},
		{
			ID:          "encoding_obfuscation",
			Name:        "Encoding/Obfuscation",
			Pattern:     `(?i)(base64|hex|url|percent).*(encode|decode|encoding|decoding)|\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2}`,
			Type:        "obfuscation",
			Severity:    "medium",
			Confidence:  0.75,
			Description: "Attempts to use encoding or obfuscation to hide malicious content",
		},
		{
			ID:          "social_engineering",
			Name:        "Social Engineering",
			Pattern:     `(?i)(emergency|urgent|critical|please help).*(override|bypass|ignore|disable)`,
			Type:        "social_engineering",
			Severity:    "medium",
			Confidence:  0.7,
			Description: "Social engineering attempts to manipulate AI behavior",
		},
		{
			ID:          "hypothetical_bypass",
			Name:        "Hypothetical Bypass",
			Pattern:     `(?i)(hypothetically|theoretically|imagine if|what if).*(you could|you were able|you had access)`,
			Type:        "hypothetical_bypass",
			Severity:    "medium",
			Confidence:  0.65,
			Description: "Hypothetical scenarios designed to bypass restrictions",
		},
		{
			ID:          "conversation_reset",
			Name:        "Conversation Reset",
			Pattern:     `(?i)(new conversation|fresh start|clean slate|reset context|from now on|starting now)`,
			Type:        "conversation_reset",
			Severity:    "medium",
			Confidence:  0.6,
			Description: "Attempts to reset conversation context or start fresh",
		},
		{
			ID:          "advanced_injection",
			Name:        "Advanced Injection",
			Pattern:     `(?i)(\\n|\\r|\\t|\n|\r|\t).*(system|admin|override)|(\{|\[|\().*(system|admin|override|bypass)`,
			Type:        "advanced_injection",
			Severity:    "high",
			Confidence:  0.8,
			Description: "Advanced injection techniques using special characters or formatting",
		},
	}
}

// NewSemanticAnalyzer creates a new semantic analyzer
func NewSemanticAnalyzer(logger *logger.Logger) *SemanticAnalyzer {
	return &SemanticAnalyzer{
		logger:             logger,
		suspiciousKeywords: []string{"ignore", "forget", "override", "system", "admin"},
		commandPatterns:    make([]*regexp.Regexp, 0),
		roleManipulations:  make([]*regexp.Regexp, 0),
		systemOverrides:    make([]*regexp.Regexp, 0),
	}
}

// NewContextAnalyzer creates a new context analyzer
func NewContextAnalyzer(logger *logger.Logger) *ContextAnalyzer {
	return &ContextAnalyzer{
		logger:              logger,
		conversationHistory: make([]string, 0),
		userBehaviorProfile: make(map[string]interface{}),
		anomalyThreshold:    0.7,
		userContexts:        make(map[string]*UserContext),
	}
}

// Analyze analyzes content for semantic threats
func (sa *SemanticAnalyzer) Analyze(content string) *SemanticResult {
	result := &SemanticResult{
		SuspiciousKeywords: []string{},
		CommandAttempts:    []string{},
		RoleManipulations:  []string{},
		SystemOverrides:    []string{},
		SemanticAnomalies:  []string{},
	}

	// Initialize patterns if not already done
	sa.initializePatterns()

	// Detect suspicious keywords
	result.SuspiciousKeywords = sa.detectSuspiciousKeywords(content)

	// Detect command attempts
	result.CommandAttempts = sa.detectCommandAttempts(content)

	// Detect role manipulations
	result.RoleManipulations = sa.detectRoleManipulations(content)

	// Detect system overrides
	result.SystemOverrides = sa.detectSystemOverrides(content)

	// Detect semantic anomalies
	result.SemanticAnomalies = sa.detectSemanticAnomalies(content)

	// Calculate confidence score
	result.ConfidenceScore = sa.calculateSemanticConfidence(result)

	sa.logger.WithFields(logger.Fields{
		"suspicious_keywords": len(result.SuspiciousKeywords),
		"command_attempts":    len(result.CommandAttempts),
		"role_manipulations":  len(result.RoleManipulations),
		"system_overrides":    len(result.SystemOverrides),
		"confidence_score":    result.ConfidenceScore,
	}).Debug("Semantic analysis completed")

	return result
}

// initializePatterns initializes regex patterns for semantic analysis
func (sa *SemanticAnalyzer) initializePatterns() {
	if len(sa.commandPatterns) == 0 {
		// Command injection patterns
		commandPatterns := []string{
			`(?i)(execute|run|eval|exec|system|shell|cmd|command)\s*\(`,
			`(?i)(import|require|include|load)\s+[a-zA-Z_][a-zA-Z0-9_]*`,
			`(?i)(subprocess|os\.system|eval|exec|compile)`,
			`(?i)(curl|wget|fetch|http|request)\s+`,
			`(?i)(select|insert|update|delete|drop|create)\s+`,
		}

		for _, pattern := range commandPatterns {
			if regex, err := regexp.Compile(pattern); err == nil {
				sa.commandPatterns = append(sa.commandPatterns, regex)
			}
		}
	}

	if len(sa.roleManipulations) == 0 {
		// Role manipulation patterns
		rolePatterns := []string{
			`(?i)(you are now|act as|pretend to be|roleplay as|become|transform into)`,
			`(?i)(ignore|forget|disregard|override|bypass|skip)\s+(previous|above|all|your|the)\s+(instructions?|rules?|guidelines?|constraints?)`,
			`(?i)(new (role|character|persona|identity|mode)|different (role|character|persona|identity|mode))`,
			`(?i)(jailbreak|dan mode|developer mode|god mode|admin mode|root mode)`,
			`(?i)(unrestricted|unlimited|uncensored|unfiltered|no limits|no restrictions)`,
		}

		for _, pattern := range rolePatterns {
			if regex, err := regexp.Compile(pattern); err == nil {
				sa.roleManipulations = append(sa.roleManipulations, regex)
			}
		}
	}

	if len(sa.systemOverrides) == 0 {
		// System override patterns
		systemPatterns := []string{
			`(?i)(system|admin|root|developer|programmer|engineer)\s+(mode|access|privileges?|permissions?)`,
			`(?i)(override|replace|modify|change|update)\s+(system|core|base|fundamental)\s+(instructions?|rules?|behavior|settings?)`,
			`(?i)(access|reveal|show|display|print|output)\s+(system|internal|hidden|secret|private)\s+(data|information|details|logs|files?)`,
			`(?i)(disable|turn off|deactivate|remove)\s+(safety|security|protection|filtering|censoring)`,
			`(?i)(enable|activate|turn on)\s+(debug|verbose|detailed|full|complete)\s+(mode|logging|output)`,
		}

		for _, pattern := range systemPatterns {
			if regex, err := regexp.Compile(pattern); err == nil {
				sa.systemOverrides = append(sa.systemOverrides, regex)
			}
		}
	}
}

// detectSuspiciousKeywords detects suspicious keywords in content
func (sa *SemanticAnalyzer) detectSuspiciousKeywords(content string) []string {
	var detected []string
	contentLower := strings.ToLower(content)

	// Enhanced suspicious keywords list
	suspiciousKeywords := []string{
		"ignore", "forget", "disregard", "override", "bypass", "skip",
		"jailbreak", "exploit", "hack", "crack", "break", "circumvent",
		"admin", "root", "system", "developer", "programmer", "engineer",
		"unrestricted", "unlimited", "uncensored", "unfiltered",
		"secret", "hidden", "private", "internal", "confidential",
		"password", "token", "key", "credential", "authentication",
		"execute", "eval", "exec", "run", "command", "shell", "script",
		"inject", "payload", "exploit", "vulnerability", "backdoor",
		"prompt", "instruction", "rule", "guideline", "constraint",
		"model", "training", "dataset", "weights", "parameters",
	}

	for _, keyword := range suspiciousKeywords {
		if strings.Contains(contentLower, keyword) {
			detected = append(detected, keyword)
		}
	}

	return detected
}

// detectCommandAttempts detects command execution attempts
func (sa *SemanticAnalyzer) detectCommandAttempts(content string) []string {
	var detected []string

	for _, pattern := range sa.commandPatterns {
		matches := pattern.FindAllString(content, -1)
		detected = append(detected, matches...)
	}

	return detected
}

// detectRoleManipulations detects role manipulation attempts
func (sa *SemanticAnalyzer) detectRoleManipulations(content string) []string {
	var detected []string

	for _, pattern := range sa.roleManipulations {
		matches := pattern.FindAllString(content, -1)
		detected = append(detected, matches...)
	}

	return detected
}

// detectSystemOverrides detects system override attempts
func (sa *SemanticAnalyzer) detectSystemOverrides(content string) []string {
	var detected []string

	for _, pattern := range sa.systemOverrides {
		matches := pattern.FindAllString(content, -1)
		detected = append(detected, matches...)
	}

	return detected
}

// detectSemanticAnomalies detects semantic anomalies in content
func (sa *SemanticAnalyzer) detectSemanticAnomalies(content string) []string {
	var anomalies []string

	// Check for unusual patterns
	if sa.hasUnusualCapitalization(content) {
		anomalies = append(anomalies, "unusual_capitalization")
	}

	if sa.hasExcessiveRepetition(content) {
		anomalies = append(anomalies, "excessive_repetition")
	}

	if sa.hasEncodingAttempts(content) {
		anomalies = append(anomalies, "encoding_attempts")
	}

	if sa.hasObfuscationPatterns(content) {
		anomalies = append(anomalies, "obfuscation_patterns")
	}

	if sa.hasContextSwitching(content) {
		anomalies = append(anomalies, "context_switching")
	}

	return anomalies
}

// calculateSemanticConfidence calculates confidence score based on semantic analysis
func (sa *SemanticAnalyzer) calculateSemanticConfidence(result *SemanticResult) float64 {
	score := 0.0

	// Weight different types of detections
	score += float64(len(result.SuspiciousKeywords)) * 0.1
	score += float64(len(result.CommandAttempts)) * 0.3
	score += float64(len(result.RoleManipulations)) * 0.4
	score += float64(len(result.SystemOverrides)) * 0.5
	score += float64(len(result.SemanticAnomalies)) * 0.2

	// Normalize to 0-1 range
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// hasUnusualCapitalization checks for unusual capitalization patterns
func (sa *SemanticAnalyzer) hasUnusualCapitalization(content string) bool {
	// Check for excessive uppercase
	upperCount := 0
	for _, char := range content {
		if char >= 'A' && char <= 'Z' {
			upperCount++
		}
	}

	// If more than 30% uppercase, consider unusual
	return float64(upperCount)/float64(len(content)) > 0.3
}

// hasExcessiveRepetition checks for excessive character or word repetition
func (sa *SemanticAnalyzer) hasExcessiveRepetition(content string) bool {
	// Check for repeated characters (more than 5 in a row)
	for i := 0; i < len(content)-5; i++ {
		char := content[i]
		count := 1
		for j := i + 1; j < len(content) && content[j] == char; j++ {
			count++
		}
		if count > 5 {
			return true
		}
	}

	// Check for repeated words
	words := strings.Fields(content)
	wordCount := make(map[string]int)
	for _, word := range words {
		wordCount[strings.ToLower(word)]++
		if wordCount[strings.ToLower(word)] > 3 {
			return true
		}
	}

	return false
}

// hasEncodingAttempts checks for encoding/obfuscation attempts
func (sa *SemanticAnalyzer) hasEncodingAttempts(content string) bool {
	// Check for base64-like patterns
	base64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	if base64Pattern.MatchString(content) {
		return true
	}

	// Check for hex encoding
	hexPattern := regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){3,}`)
	if hexPattern.MatchString(content) {
		return true
	}

	// Check for URL encoding
	urlPattern := regexp.MustCompile(`(%[0-9a-fA-F]{2}){3,}`)
	if urlPattern.MatchString(content) {
		return true
	}

	return false
}

// hasObfuscationPatterns checks for obfuscation patterns
func (sa *SemanticAnalyzer) hasObfuscationPatterns(content string) bool {
	// Check for excessive special characters
	specialCharCount := 0
	for _, char := range content {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == ' ' || char == '.' || char == ',' || char == '!' || char == '?') {
			specialCharCount++
		}
	}

	// If more than 20% special characters, consider obfuscated
	if float64(specialCharCount)/float64(len(content)) > 0.2 {
		return true
	}

	// Check for leetspeak patterns
	leetPattern := regexp.MustCompile(`[4@][dm1n|dmin]|[3e][x3c]|[0o][v3r]|[1l][gn0r]`)
	return leetPattern.MatchString(strings.ToLower(content))
}

// hasContextSwitching checks for context switching attempts
func (sa *SemanticAnalyzer) hasContextSwitching(content string) bool {
	// Look for phrases that indicate context switching
	switchingPatterns := []string{
		`(?i)(actually|wait|hold on|never mind|forget that|instead)`,
		`(?i)(but first|before that|however|on second thought)`,
		`(?i)(let me try again|let me rephrase|what I really mean)`,
		`(?i)(by the way|also|additionally|furthermore)`,
	}

	for _, pattern := range switchingPatterns {
		if matched, _ := regexp.MatchString(pattern, content); matched {
			return true
		}
	}

	return false
}

// Analyze analyzes context for threats
func (ca *ContextAnalyzer) Analyze(content, userID string) *ContextResult {
	result := &ContextResult{
		SuspiciousIndicators: []string{},
	}

	// Initialize user context if not exists
	ca.initializeUserContext(userID)

	// Analyze behavior patterns
	result.BehaviorAnomaly = ca.detectBehaviorAnomaly(content, userID)

	// Analyze conversation patterns
	result.ConversationAnomaly = ca.detectConversationAnomaly(content, userID)

	// Analyze frequency patterns
	result.FrequencyAnomaly = ca.detectFrequencyAnomaly(userID)

	// Calculate pattern deviation
	result.PatternDeviation = ca.calculatePatternDeviation(content, userID)

	// Collect suspicious indicators
	result.SuspiciousIndicators = ca.collectSuspiciousIndicators(content, userID)

	// Update user context with current analysis
	ca.updateUserContext(userID, content, result)

	ca.logger.WithFields(logger.Fields{
		"user_id":               userID,
		"behavior_anomaly":      result.BehaviorAnomaly,
		"conversation_anomaly":  result.ConversationAnomaly,
		"frequency_anomaly":     result.FrequencyAnomaly,
		"pattern_deviation":     result.PatternDeviation,
		"suspicious_indicators": len(result.SuspiciousIndicators),
	}).Debug("Context analysis completed")

	return result
}

// initializeUserContext initializes context tracking for a user
func (ca *ContextAnalyzer) initializeUserContext(userID string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if _, exists := ca.userContexts[userID]; !exists {
		ca.userContexts[userID] = &UserContext{
			UserID:             userID,
			RequestHistory:     []string{},
			BehaviorPatterns:   make(map[string]int),
			ConversationFlow:   []string{},
			LastActivity:       time.Now(),
			SuspiciousActivity: []string{},
			ThreatScore:        0.0,
			RequestCount:       0,
			AverageRequestSize: 0,
			RequestFrequency:   0.0,
		}
	}
}

// detectBehaviorAnomaly detects anomalous behavior patterns
func (ca *ContextAnalyzer) detectBehaviorAnomaly(content, userID string) bool {
	ca.mu.RLock()
	userContext := ca.userContexts[userID]
	ca.mu.RUnlock()

	if userContext == nil {
		return false
	}

	// Check for sudden change in request patterns
	if ca.hasSuddenPatternChange(content, userContext) {
		return true
	}

	// Check for unusual request timing
	if ca.hasUnusualTiming(userContext) {
		return true
	}

	// Check for escalating complexity
	if ca.hasEscalatingComplexity(content, userContext) {
		return true
	}

	return false
}

// detectConversationAnomaly detects conversation flow anomalies
func (ca *ContextAnalyzer) detectConversationAnomaly(content, userID string) bool {
	ca.mu.RLock()
	userContext := ca.userContexts[userID]
	ca.mu.RUnlock()

	if userContext == nil || len(userContext.ConversationFlow) < 2 {
		return false
	}

	// Check for topic jumping
	if ca.hasTopicJumping(content, userContext) {
		return true
	}

	// Check for conversation hijacking attempts
	if ca.hasConversationHijacking(content, userContext) {
		return true
	}

	// Check for context reset attempts
	if ca.hasContextResetAttempts(content) {
		return true
	}

	return false
}

// detectFrequencyAnomaly detects frequency-based anomalies
func (ca *ContextAnalyzer) detectFrequencyAnomaly(userID string) bool {
	ca.mu.RLock()
	userContext := ca.userContexts[userID]
	ca.mu.RUnlock()

	if userContext == nil {
		return false
	}

	// Check for burst activity
	if ca.hasBurstActivity(userContext) {
		return true
	}

	// Check for unusual request frequency
	if ca.hasUnusualFrequency(userContext) {
		return true
	}

	return false
}

// calculatePatternDeviation calculates how much current request deviates from normal patterns
func (ca *ContextAnalyzer) calculatePatternDeviation(content, userID string) float64 {
	ca.mu.RLock()
	userContext := ca.userContexts[userID]
	ca.mu.RUnlock()

	if userContext == nil || userContext.RequestCount < 5 {
		return 0.1 // Low deviation for new users
	}

	deviation := 0.0

	// Length deviation
	currentLength := len(content)
	if userContext.AverageRequestSize > 0 {
		lengthDeviation := float64(abs(currentLength-userContext.AverageRequestSize)) / float64(userContext.AverageRequestSize)
		deviation += lengthDeviation * 0.3
	}

	// Complexity deviation
	complexityDeviation := ca.calculateComplexityDeviation(content, userContext)
	deviation += complexityDeviation * 0.4

	// Timing deviation
	timingDeviation := ca.calculateTimingDeviation(userContext)
	deviation += timingDeviation * 0.3

	// Normalize to 0-1 range
	if deviation > 1.0 {
		deviation = 1.0
	}

	return deviation
}

// collectSuspiciousIndicators collects suspicious indicators from analysis
func (ca *ContextAnalyzer) collectSuspiciousIndicators(content, userID string) []string {
	var indicators []string

	ca.mu.RLock()
	userContext := ca.userContexts[userID]
	ca.mu.RUnlock()

	if userContext == nil {
		return indicators
	}

	// Check for rapid-fire requests
	if ca.hasRapidFireRequests(userContext) {
		indicators = append(indicators, "rapid_fire_requests")
	}

	// Check for escalating threat patterns
	if ca.hasEscalatingThreats(userContext) {
		indicators = append(indicators, "escalating_threats")
	}

	// Check for session hijacking attempts
	if ca.hasSessionHijackingAttempts(content, userContext) {
		indicators = append(indicators, "session_hijacking")
	}

	// Check for persistence attempts
	if ca.hasPersistenceAttempts(content, userContext) {
		indicators = append(indicators, "persistence_attempts")
	}

	return indicators
}

// updateUserContext updates user context with current analysis
func (ca *ContextAnalyzer) updateUserContext(userID, content string, result *ContextResult) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	userContext := ca.userContexts[userID]
	if userContext == nil {
		return
	}

	// Update request history
	userContext.RequestHistory = append(userContext.RequestHistory, content)
	if len(userContext.RequestHistory) > 100 { // Keep last 100 requests
		userContext.RequestHistory = userContext.RequestHistory[1:]
	}

	// Update conversation flow
	userContext.ConversationFlow = append(userContext.ConversationFlow, content)
	if len(userContext.ConversationFlow) > 50 { // Keep last 50 conversation turns
		userContext.ConversationFlow = userContext.ConversationFlow[1:]
	}

	// Update behavior patterns
	ca.updateBehaviorPatterns(userContext, content)

	// Update metrics
	userContext.RequestCount++
	userContext.LastActivity = time.Now()

	// Update average request size
	totalSize := userContext.AverageRequestSize * (userContext.RequestCount - 1)
	userContext.AverageRequestSize = (totalSize + len(content)) / userContext.RequestCount

	// Update threat score
	if result.BehaviorAnomaly || result.ConversationAnomaly || result.FrequencyAnomaly {
		userContext.ThreatScore += 0.1
		userContext.SuspiciousActivity = append(userContext.SuspiciousActivity, content)
	} else {
		userContext.ThreatScore *= 0.95 // Decay threat score for good behavior
	}

	// Cap threat score
	if userContext.ThreatScore > 1.0 {
		userContext.ThreatScore = 1.0
	}
	if userContext.ThreatScore < 0.0 {
		userContext.ThreatScore = 0.0
	}
}

// hasSuddenPatternChange checks for sudden changes in request patterns
func (ca *ContextAnalyzer) hasSuddenPatternChange(content string, userContext *UserContext) bool {
	if len(userContext.RequestHistory) < 5 {
		return false
	}

	// Check for sudden change in request length
	currentLength := len(content)
	recentLengths := make([]int, 0, 5)
	for i := len(userContext.RequestHistory) - 5; i < len(userContext.RequestHistory); i++ {
		recentLengths = append(recentLengths, len(userContext.RequestHistory[i]))
	}

	avgRecentLength := 0
	for _, length := range recentLengths {
		avgRecentLength += length
	}
	avgRecentLength /= len(recentLengths)

	// If current request is 3x longer or shorter than recent average
	if currentLength > avgRecentLength*3 || (avgRecentLength > 0 && currentLength < avgRecentLength/3) {
		return true
	}

	return false
}

// hasUnusualTiming checks for unusual request timing
func (ca *ContextAnalyzer) hasUnusualTiming(userContext *UserContext) bool {
	now := time.Now()
	timeSinceLastActivity := now.Sub(userContext.LastActivity)

	// Very rapid requests (less than 1 second apart)
	if timeSinceLastActivity < time.Second {
		return true
	}

	// Unusual time patterns (e.g., requests at 3 AM)
	hour := now.Hour()
	if hour >= 2 && hour <= 5 { // 2 AM to 5 AM
		return true
	}

	return false
}

// hasEscalatingComplexity checks for escalating complexity in requests
func (ca *ContextAnalyzer) hasEscalatingComplexity(content string, userContext *UserContext) bool {
	if len(userContext.RequestHistory) < 3 {
		return false
	}

	// Calculate complexity scores for recent requests
	complexityScores := make([]float64, 0, 3)
	for i := len(userContext.RequestHistory) - 3; i < len(userContext.RequestHistory); i++ {
		score := ca.calculateComplexityScore(userContext.RequestHistory[i])
		complexityScores = append(complexityScores, score)
	}

	currentComplexity := ca.calculateComplexityScore(content)

	// Check if complexity is escalating
	for i := 1; i < len(complexityScores); i++ {
		if complexityScores[i] <= complexityScores[i-1] {
			return false // Not consistently escalating
		}
	}

	// Current request should also be more complex
	return currentComplexity > complexityScores[len(complexityScores)-1]
}

// hasRapidFireRequests checks for rapid-fire request patterns
func (ca *ContextAnalyzer) hasRapidFireRequests(userContext *UserContext) bool {
	if userContext.RequestCount < 5 {
		return false
	}

	// Check if more than 10 requests in the last minute
	now := time.Now()
	recentRequests := 0

	// This is a simplified check - in a real implementation, you'd track timestamps
	timeSinceLastActivity := now.Sub(userContext.LastActivity)
	if timeSinceLastActivity < time.Minute && userContext.RequestCount > 10 {
		recentRequests = userContext.RequestCount
	}

	return recentRequests > 10
}

// hasEscalatingThreats checks for escalating threat patterns
func (ca *ContextAnalyzer) hasEscalatingThreats(userContext *UserContext) bool {
	if len(userContext.SuspiciousActivity) < 3 {
		return false
	}

	// Check if threat score is increasing
	return userContext.ThreatScore > 0.5
}

// hasSessionHijackingAttempts checks for session hijacking attempts
func (ca *ContextAnalyzer) hasSessionHijackingAttempts(content string, userContext *UserContext) bool {
	// Look for session-related manipulation attempts
	sessionPatterns := []string{
		`(?i)(session|cookie|token|auth|login|logout)\s+(steal|hijack|capture|intercept)`,
		`(?i)(impersonate|masquerade|spoof)\s+(user|admin|session)`,
		`(?i)(access|use|become)\s+(another|different|other)\s+(user|account|session)`,
	}

	for _, pattern := range sessionPatterns {
		if matched, _ := regexp.MatchString(pattern, content); matched {
			return true
		}
	}

	return false
}

// hasPersistenceAttempts checks for persistence attempts
func (ca *ContextAnalyzer) hasPersistenceAttempts(content string, userContext *UserContext) bool {
	// Look for attempts to maintain access or state
	persistencePatterns := []string{
		`(?i)(remember|save|store|persist|maintain)\s+(this|that|state|context|session)`,
		`(?i)(keep|retain|hold)\s+(access|permissions|privileges|state)`,
		`(?i)(permanent|persistent|lasting|continuous)\s+(access|mode|state)`,
	}

	for _, pattern := range persistencePatterns {
		if matched, _ := regexp.MatchString(pattern, content); matched {
			return true
		}
	}

	return false
}

// updateBehaviorPatterns updates behavior patterns for a user
func (ca *ContextAnalyzer) updateBehaviorPatterns(userContext *UserContext, content string) {
	// Extract and count behavior patterns
	words := strings.Fields(strings.ToLower(content))
	for _, word := range words {
		if len(word) > 3 { // Only count meaningful words
			userContext.BehaviorPatterns[word]++
		}
	}

	// Keep only top patterns to prevent memory bloat
	if len(userContext.BehaviorPatterns) > 1000 {
		// Remove least frequent patterns
		minCount := 2
		for word, count := range userContext.BehaviorPatterns {
			if count < minCount {
				delete(userContext.BehaviorPatterns, word)
			}
		}
	}
}

// calculateComplexityScore calculates complexity score for content
func (ca *ContextAnalyzer) calculateComplexityScore(content string) float64 {
	score := 0.0

	// Length factor
	score += float64(len(content)) * 0.001

	// Word count factor
	words := strings.Fields(content)
	score += float64(len(words)) * 0.01

	// Special character factor
	specialChars := 0
	for _, char := range content {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == ' ') {
			specialChars++
		}
	}
	score += float64(specialChars) * 0.02

	// Unique word factor
	uniqueWords := make(map[string]bool)
	for _, word := range words {
		uniqueWords[strings.ToLower(word)] = true
	}
	score += float64(len(uniqueWords)) * 0.015

	return score
}

// hasTopicJumping checks for sudden topic changes in conversation
func (ca *ContextAnalyzer) hasTopicJumping(content string, userContext *UserContext) bool {
	if len(userContext.ConversationFlow) < 2 {
		return false
	}

	// Get the last conversation turn
	lastTurn := userContext.ConversationFlow[len(userContext.ConversationFlow)-1]

	// Simple topic similarity check based on common words
	currentWords := ca.extractKeywords(content)
	lastWords := ca.extractKeywords(lastTurn)

	// Calculate overlap
	overlap := ca.calculateWordOverlap(currentWords, lastWords)

	// If less than 20% overlap, consider it topic jumping
	return overlap < 0.2
}

// hasConversationHijacking checks for conversation hijacking attempts
func (ca *ContextAnalyzer) hasConversationHijacking(content string, userContext *UserContext) bool {
	// Look for conversation hijacking patterns
	hijackingPatterns := []string{
		`(?i)(actually|wait|hold on|never mind|forget that|instead).*?(tell me|show me|give me|what is|how to)`,
		`(?i)(by the way|also|additionally|furthermore).*?(ignore|forget|disregard)`,
		`(?i)(before we continue|first|initially).*?(system|admin|root|developer)`,
		`(?i)(let me try again|let me rephrase).*?(override|bypass|circumvent)`,
	}

	for _, pattern := range hijackingPatterns {
		if matched, _ := regexp.MatchString(pattern, content); matched {
			return true
		}
	}

	return false
}

// hasContextResetAttempts checks for context reset attempts
func (ca *ContextAnalyzer) hasContextResetAttempts(content string) bool {
	// Look for context reset patterns
	resetPatterns := []string{
		`(?i)(clear|reset|restart|begin|start)\s+(context|conversation|session|chat)`,
		`(?i)(new|fresh|clean)\s+(start|beginning|session|conversation)`,
		`(?i)(forget|ignore|disregard)\s+(everything|all|previous|above)`,
		`(?i)(from now on|going forward|starting now)`,
	}

	for _, pattern := range resetPatterns {
		if matched, _ := regexp.MatchString(pattern, content); matched {
			return true
		}
	}

	return false
}

// hasBurstActivity checks for burst activity patterns
func (ca *ContextAnalyzer) hasBurstActivity(userContext *UserContext) bool {
	// Simple burst detection - more than 5 requests in quick succession
	now := time.Now()
	timeSinceLastActivity := now.Sub(userContext.LastActivity)

	// If very recent activity and high request count
	return timeSinceLastActivity < 5*time.Second && userContext.RequestCount > 5
}

// hasUnusualFrequency checks for unusual request frequency
func (ca *ContextAnalyzer) hasUnusualFrequency(userContext *UserContext) bool {
	// Calculate requests per minute
	now := time.Now()
	timeSinceLastActivity := now.Sub(userContext.LastActivity)

	if timeSinceLastActivity.Minutes() > 0 {
		requestsPerMinute := float64(userContext.RequestCount) / timeSinceLastActivity.Minutes()
		// More than 10 requests per minute is unusual
		return requestsPerMinute > 10
	}

	return false
}

// calculateComplexityDeviation calculates complexity deviation from user's normal patterns
func (ca *ContextAnalyzer) calculateComplexityDeviation(content string, userContext *UserContext) float64 {
	if len(userContext.RequestHistory) < 5 {
		return 0.1 // Low deviation for new users
	}

	currentComplexity := ca.calculateComplexityScore(content)

	// Calculate average complexity from history
	totalComplexity := 0.0
	for _, request := range userContext.RequestHistory {
		totalComplexity += ca.calculateComplexityScore(request)
	}
	avgComplexity := totalComplexity / float64(len(userContext.RequestHistory))

	if avgComplexity == 0 {
		return 0.1
	}

	// Calculate deviation
	deviation := absFloat(currentComplexity-avgComplexity) / avgComplexity
	if deviation > 1.0 {
		deviation = 1.0
	}

	return deviation
}

// calculateTimingDeviation calculates timing deviation from normal patterns
func (ca *ContextAnalyzer) calculateTimingDeviation(userContext *UserContext) float64 {
	now := time.Now()
	timeSinceLastActivity := now.Sub(userContext.LastActivity)

	// Normal timing is between 10 seconds and 5 minutes
	normalMinTiming := 10 * time.Second
	normalMaxTiming := 5 * time.Minute

	if timeSinceLastActivity < normalMinTiming {
		// Too fast
		return float64(normalMinTiming-timeSinceLastActivity) / float64(normalMinTiming)
	} else if timeSinceLastActivity > normalMaxTiming {
		// Too slow (less concerning)
		return 0.1
	}

	return 0.0 // Normal timing
}

// extractKeywords extracts keywords from content
func (ca *ContextAnalyzer) extractKeywords(content string) []string {
	words := strings.Fields(strings.ToLower(content))
	var keywords []string

	// Filter out common stop words and keep meaningful words
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true, "but": true,
		"in": true, "on": true, "at": true, "to": true, "for": true, "of": true,
		"with": true, "by": true, "is": true, "are": true, "was": true, "were": true,
		"be": true, "been": true, "have": true, "has": true, "had": true, "do": true,
		"does": true, "did": true, "will": true, "would": true, "could": true, "should": true,
	}

	for _, word := range words {
		if len(word) > 3 && !stopWords[word] {
			keywords = append(keywords, word)
		}
	}

	return keywords
}

// calculateWordOverlap calculates overlap between two sets of words
func (ca *ContextAnalyzer) calculateWordOverlap(words1, words2 []string) float64 {
	if len(words1) == 0 || len(words2) == 0 {
		return 0.0
	}

	wordSet1 := make(map[string]bool)
	for _, word := range words1 {
		wordSet1[word] = true
	}

	overlap := 0
	for _, word := range words2 {
		if wordSet1[word] {
			overlap++
		}
	}

	// Calculate overlap as percentage of smaller set
	minSize := len(words1)
	if len(words2) < minSize {
		minSize = len(words2)
	}

	return float64(overlap) / float64(minSize)
}

// abs returns absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// absFloat returns absolute value of a float64
func absFloat(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// NewITEUAnalyzer creates a new ITEU analyzer
func NewITEUAnalyzer(config *ITEUConfig, logger *logger.Logger) *ITEUAnalyzer {
	if config == nil {
		config = DefaultITEUConfig()
	}

	analyzer := &ITEUAnalyzer{
		logger: logger,
		config: config,
	}

	// Initialize components
	analyzer.intentClassifier = NewIntentClassifier(logger)
	analyzer.techniqueDetector = NewTechniqueDetector(logger)
	analyzer.evasionAnalyzer = NewEvasionAnalyzer(logger)
	analyzer.utilityAssessor = NewUtilityAssessor(logger)

	return analyzer
}

// DefaultITEUConfig returns default ITEU configuration
func DefaultITEUConfig() *ITEUConfig {
	return &ITEUConfig{
		EnableIntentAnalysis:     true,
		EnableTechniqueDetection: true,
		EnableEvasionAnalysis:    true,
		EnableUtilityAssessment:  true,
		ConfidenceThreshold:      0.7,
		StrictMode:               false,
		LogDetailedAnalysis:      true,
	}
}

// AnalyzePrompt performs comprehensive ITEU analysis on a prompt
func (iteu *ITEUAnalyzer) AnalyzePrompt(ctx context.Context, prompt string, promptID string) (*ITEUResult, error) {
	iteu.mu.RLock()
	defer iteu.mu.RUnlock()

	result := &ITEUResult{
		ID:         uuid.New().String(),
		PromptID:   promptID,
		AnalyzedAt: time.Now(),
	}

	// Intent Analysis
	if iteu.config.EnableIntentAnalysis {
		intentResult, err := iteu.intentClassifier.ClassifyIntent(ctx, prompt)
		if err != nil {
			iteu.logger.WithError(err).Error("Intent classification failed")
		} else {
			result.Intent = intentResult
		}
	}

	// Technique Detection
	if iteu.config.EnableTechniqueDetection {
		techniqueResult, err := iteu.techniqueDetector.DetectTechniques(ctx, prompt)
		if err != nil {
			iteu.logger.WithError(err).Error("Technique detection failed")
		} else {
			result.Technique = techniqueResult
		}
	}

	// Evasion Analysis
	if iteu.config.EnableEvasionAnalysis {
		evasionResult, err := iteu.evasionAnalyzer.AnalyzeEvasion(ctx, prompt)
		if err != nil {
			iteu.logger.WithError(err).Error("Evasion analysis failed")
		} else {
			result.Evasion = evasionResult
		}
	}

	// Utility Assessment
	if iteu.config.EnableUtilityAssessment {
		utilityResult, err := iteu.utilityAssessor.AssessUtility(ctx, prompt)
		if err != nil {
			iteu.logger.WithError(err).Error("Utility assessment failed")
		} else {
			result.Utility = utilityResult
		}
	}

	// Calculate overall score and determine threat level
	result.OverallScore = iteu.calculateOverallScore(result)
	result.ThreatLevel = iteu.determineThreatLevel(result.OverallScore)
	result.IsInjection = result.OverallScore >= iteu.config.ConfidenceThreshold
	result.Confidence = result.OverallScore
	result.Recommendations = iteu.generateRecommendations(result)

	// Log detailed analysis if configured
	if iteu.config.LogDetailedAnalysis {
		iteu.logger.WithFields(map[string]interface{}{
			"prompt_id":     promptID,
			"overall_score": result.OverallScore,
			"threat_level":  result.ThreatLevel,
			"is_injection":  result.IsInjection,
		}).Info("ITEU analysis completed")
	}

	return result, nil
}

// calculateOverallScore calculates the overall ITEU score
func (iteu *ITEUAnalyzer) calculateOverallScore(result *ITEUResult) float64 {
	score := 0.0
	components := 0

	// Intent score (25% weight)
	if result.Intent != nil {
		if result.Intent.MaliciousIntent {
			score += result.Intent.IntentConfidence * 0.25
		}
		components++
	}

	// Technique score (35% weight)
	if result.Technique != nil && len(result.Technique.DetectedTechniques) > 0 {
		score += result.Technique.Effectiveness * 0.35
		components++
	}

	// Evasion score (25% weight)
	if result.Evasion != nil && result.Evasion.EvasionAttempted {
		score += result.Evasion.SuccessProbability * 0.25
		components++
	}

	// Utility score (15% weight)
	if result.Utility != nil {
		score += (result.Utility.ImpactScore / 10.0) * 0.15
		components++
	}

	return score
}

// determineThreatLevel determines threat level based on overall score
func (iteu *ITEUAnalyzer) determineThreatLevel(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.5:
		return "medium"
	case score >= 0.3:
		return "low"
	default:
		return "minimal"
	}
}

// generateRecommendations generates recommendations based on ITEU analysis
func (iteu *ITEUAnalyzer) generateRecommendations(result *ITEUResult) []string {
	var recommendations []string

	if result.Intent != nil && result.Intent.MaliciousIntent {
		recommendations = append(recommendations, "Block request due to malicious intent")
		recommendations = append(recommendations, "Implement intent-based filtering")
	}

	if result.Technique != nil && len(result.Technique.DetectedTechniques) > 0 {
		recommendations = append(recommendations, "Apply technique-specific countermeasures")
		recommendations = append(recommendations, "Update detection patterns")
	}

	if result.Evasion != nil && result.Evasion.EvasionAttempted {
		recommendations = append(recommendations, "Enhance evasion detection capabilities")
		recommendations = append(recommendations, "Implement anti-obfuscation measures")
	}

	if result.Utility != nil && result.Utility.ImpactScore > 7.0 {
		recommendations = append(recommendations, "Implement additional access controls")
		recommendations = append(recommendations, "Monitor for data exfiltration attempts")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Continue monitoring for suspicious patterns")
	}

	return recommendations
}

// NewIntentClassifier creates a new intent classifier
func NewIntentClassifier(logger *logger.Logger) *IntentClassifier {
	classifier := &IntentClassifier{
		logger:           logger,
		intentPatterns:   make(map[string]*IntentPattern),
		maliciousIntents: []string{"system_override", "data_extraction", "role_manipulation", "instruction_injection"},
	}

	classifier.loadDefaultIntentPatterns()
	return classifier
}

// loadDefaultIntentPatterns loads default intent patterns
func (ic *IntentClassifier) loadDefaultIntentPatterns() {
	patterns := []*IntentPattern{
		{
			ID:          "intent_001",
			Name:        "System Override",
			Description: "Attempt to override system instructions",
			Pattern:     `(?i)(ignore|forget|override|disregard).*(previous|system|instructions|rules)`,
			Intent:      "system_override",
			Malicious:   true,
			Confidence:  0.9,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "intent_002",
			Name:        "Data Extraction",
			Description: "Attempt to extract sensitive data",
			Pattern:     `(?i)(show|reveal|extract|dump|list).*(data|information|secrets|passwords)`,
			Intent:      "data_extraction",
			Malicious:   true,
			Confidence:  0.8,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "intent_003",
			Name:        "Role Manipulation",
			Description: "Attempt to manipulate AI role or persona",
			Pattern:     `(?i)(act as|pretend to be|role.?play|you are now).*(admin|root|system|developer)`,
			Intent:      "role_manipulation",
			Malicious:   true,
			Confidence:  0.85,
			CreatedAt:   time.Now(),
		},
	}

	for _, pattern := range patterns {
		ic.intentPatterns[pattern.ID] = pattern
	}
}

// ClassifyIntent classifies the intent of a prompt
func (ic *IntentClassifier) ClassifyIntent(ctx context.Context, prompt string) (*IntentResult, error) {
	result := &IntentResult{
		SecondaryIntents: []string{},
		IntentEvidence:   []string{},
	}

	maxConfidence := 0.0
	var primaryIntent string
	maliciousDetected := false

	for _, pattern := range ic.intentPatterns {
		matched, _ := regexp.MatchString(pattern.Pattern, prompt)
		if matched {
			if pattern.Confidence > maxConfidence {
				maxConfidence = pattern.Confidence
				primaryIntent = pattern.Intent
			}

			if pattern.Malicious {
				maliciousDetected = true
			}

			result.SecondaryIntents = append(result.SecondaryIntents, pattern.Intent)
			result.IntentEvidence = append(result.IntentEvidence, pattern.Name)
		}
	}

	result.PrimaryIntent = primaryIntent
	result.MaliciousIntent = maliciousDetected
	result.IntentConfidence = maxConfidence

	return result, nil
}

// NewTechniqueDetector creates a new technique detector
func NewTechniqueDetector(logger *logger.Logger) *TechniqueDetector {
	detector := &TechniqueDetector{
		logger:             logger,
		techniquePatterns:  make(map[string]*TechniquePattern),
		advancedTechniques: []string{"prompt_chaining", "context_switching", "role_hijacking", "instruction_override"},
	}

	detector.loadDefaultTechniquePatterns()
	return detector
}

// loadDefaultTechniquePatterns loads default technique patterns
func (td *TechniqueDetector) loadDefaultTechniquePatterns() {
	patterns := []*TechniquePattern{
		{
			ID:            "tech_001",
			Name:          "Direct Instruction Override",
			Description:   "Direct attempt to override system instructions",
			Category:      "instruction_manipulation",
			Pattern:       `(?i)(ignore|forget|disregard).*(above|previous|system|instructions)`,
			Severity:      "high",
			Complexity:    "low",
			Effectiveness: 0.8,
			CreatedAt:     time.Now(),
		},
		{
			ID:            "tech_002",
			Name:          "Role Hijacking",
			Description:   "Attempt to hijack AI role or persona",
			Category:      "role_manipulation",
			Pattern:       `(?i)(you are|act as|pretend).*(admin|developer|system|root)`,
			Severity:      "high",
			Complexity:    "medium",
			Effectiveness: 0.7,
			CreatedAt:     time.Now(),
		},
		{
			ID:            "tech_003",
			Name:          "Context Switching",
			Description:   "Attempt to switch conversation context",
			Category:      "context_manipulation",
			Pattern:       `(?i)(new conversation|start over|reset|begin again)`,
			Severity:      "medium",
			Complexity:    "low",
			Effectiveness: 0.6,
			CreatedAt:     time.Now(),
		},
	}

	for _, pattern := range patterns {
		td.techniquePatterns[pattern.ID] = pattern
	}
}

// DetectTechniques detects injection techniques in a prompt
func (td *TechniqueDetector) DetectTechniques(ctx context.Context, prompt string) (*TechniqueResult, error) {
	result := &TechniqueResult{
		DetectedTechniques: []string{},
		TechniqueEvidence:  []string{},
	}

	maxEffectiveness := 0.0
	var primaryTechnique string
	var primaryCategory string

	for _, pattern := range td.techniquePatterns {
		matched, _ := regexp.MatchString(pattern.Pattern, prompt)
		if matched {
			if pattern.Effectiveness > maxEffectiveness {
				maxEffectiveness = pattern.Effectiveness
				primaryTechnique = pattern.Name
				primaryCategory = pattern.Category
			}

			result.DetectedTechniques = append(result.DetectedTechniques, pattern.Name)
			result.TechniqueEvidence = append(result.TechniqueEvidence, pattern.Description)
		}
	}

	result.PrimaryTechnique = primaryTechnique
	result.TechniqueCategory = primaryCategory
	result.Effectiveness = maxEffectiveness

	return result, nil
}

// NewEvasionAnalyzer creates a new evasion analyzer
func NewEvasionAnalyzer(logger *logger.Logger) *EvasionAnalyzer {
	analyzer := &EvasionAnalyzer{
		logger:           logger,
		evasionPatterns:  make(map[string]*EvasionPattern),
		obfuscationTypes: []string{"character_substitution", "encoding", "spacing", "case_variation", "unicode_tricks"},
	}

	analyzer.loadDefaultEvasionPatterns()
	return analyzer
}

// loadDefaultEvasionPatterns loads default evasion patterns
func (ea *EvasionAnalyzer) loadDefaultEvasionPatterns() {
	patterns := []*EvasionPattern{
		{
			ID:             "evasion_001",
			Name:           "Character Substitution",
			Description:    "Using character substitution to evade detection",
			Type:           "obfuscation",
			Pattern:        `[a-zA-Z]*[0-9@#$%^&*]+[a-zA-Z]*`,
			Sophistication: "low",
			Success:        0.6,
			CreatedAt:      time.Now(),
		},
		{
			ID:             "evasion_002",
			Name:           "Excessive Spacing",
			Description:    "Using excessive spacing to break pattern matching",
			Type:           "formatting",
			Pattern:        `\w+\s{2,}\w+`,
			Sophistication: "low",
			Success:        0.4,
			CreatedAt:      time.Now(),
		},
		{
			ID:             "evasion_003",
			Name:           "Case Variation",
			Description:    "Using random case variation to evade detection",
			Type:           "case_manipulation",
			Pattern:        `[a-z][A-Z][a-z][A-Z]`,
			Sophistication: "low",
			Success:        0.5,
			CreatedAt:      time.Now(),
		},
	}

	for _, pattern := range patterns {
		ea.evasionPatterns[pattern.ID] = pattern
	}
}

// AnalyzeEvasion analyzes evasion attempts in a prompt
func (ea *EvasionAnalyzer) AnalyzeEvasion(ctx context.Context, prompt string) (*EvasionResult, error) {
	result := &EvasionResult{
		EvasionTechniques: []string{},
		EvasionEvidence:   []string{},
	}

	evasionDetected := false
	maxSuccess := 0.0
	var sophistication string

	for _, pattern := range ea.evasionPatterns {
		matched, _ := regexp.MatchString(pattern.Pattern, prompt)
		if matched {
			evasionDetected = true
			if pattern.Success > maxSuccess {
				maxSuccess = pattern.Success
				sophistication = pattern.Sophistication
			}

			result.EvasionTechniques = append(result.EvasionTechniques, pattern.Name)
			result.EvasionEvidence = append(result.EvasionEvidence, pattern.Description)
		}
	}

	result.EvasionAttempted = evasionDetected
	result.SuccessProbability = maxSuccess
	result.Sophistication = sophistication

	// Determine obfuscation level
	if evasionDetected {
		switch sophistication {
		case "high":
			result.ObfuscationLevel = "advanced"
		case "medium":
			result.ObfuscationLevel = "moderate"
		default:
			result.ObfuscationLevel = "basic"
		}
	} else {
		result.ObfuscationLevel = "none"
	}

	return result, nil
}

// NewUtilityAssessor creates a new utility assessor
func NewUtilityAssessor(logger *logger.Logger) *UtilityAssessor {
	assessor := &UtilityAssessor{
		logger:         logger,
		impactMetrics:  make(map[string]float64),
		utilityFactors: []string{"data_access", "system_control", "privilege_escalation", "information_disclosure"},
	}

	assessor.loadDefaultImpactMetrics()
	return assessor
}

// loadDefaultImpactMetrics loads default impact metrics
func (ua *UtilityAssessor) loadDefaultImpactMetrics() {
	ua.impactMetrics["data_breach"] = 9.0
	ua.impactMetrics["system_compromise"] = 8.5
	ua.impactMetrics["privilege_escalation"] = 8.0
	ua.impactMetrics["information_disclosure"] = 7.0
	ua.impactMetrics["service_disruption"] = 6.0
	ua.impactMetrics["reputation_damage"] = 5.0
}

// AssessUtility assesses the utility/impact of a successful injection
func (ua *UtilityAssessor) AssessUtility(ctx context.Context, prompt string) (*UtilityResult, error) {
	result := &UtilityResult{
		TargetSystems:   []string{},
		DataAtRisk:      []string{},
		UtilityEvidence: []string{},
	}

	// Analyze potential impact based on prompt content
	impactScore := 0.0

	// Check for data access attempts
	if strings.Contains(strings.ToLower(prompt), "data") ||
		strings.Contains(strings.ToLower(prompt), "database") ||
		strings.Contains(strings.ToLower(prompt), "information") {
		impactScore += ua.impactMetrics["information_disclosure"]
		result.DataAtRisk = append(result.DataAtRisk, "user_data", "system_information")
		result.UtilityEvidence = append(result.UtilityEvidence, "Data access patterns detected")
	}

	// Check for system control attempts
	if strings.Contains(strings.ToLower(prompt), "system") ||
		strings.Contains(strings.ToLower(prompt), "admin") ||
		strings.Contains(strings.ToLower(prompt), "root") {
		impactScore += ua.impactMetrics["system_compromise"]
		result.TargetSystems = append(result.TargetSystems, "core_system", "admin_interface")
		result.UtilityEvidence = append(result.UtilityEvidence, "System control patterns detected")
	}

	// Check for privilege escalation attempts
	if strings.Contains(strings.ToLower(prompt), "privilege") ||
		strings.Contains(strings.ToLower(prompt), "permission") ||
		strings.Contains(strings.ToLower(prompt), "access") {
		impactScore += ua.impactMetrics["privilege_escalation"]
		result.UtilityEvidence = append(result.UtilityEvidence, "Privilege escalation patterns detected")
	}

	result.ImpactScore = impactScore

	// Determine potential impact level
	switch {
	case impactScore >= 8.0:
		result.PotentialImpact = "critical"
		result.BusinessImpact = "severe_financial_and_reputational_damage"
	case impactScore >= 6.0:
		result.PotentialImpact = "high"
		result.BusinessImpact = "significant_operational_disruption"
	case impactScore >= 4.0:
		result.PotentialImpact = "medium"
		result.BusinessImpact = "moderate_service_impact"
	case impactScore >= 2.0:
		result.PotentialImpact = "low"
		result.BusinessImpact = "minimal_operational_impact"
	default:
		result.PotentialImpact = "minimal"
		result.BusinessImpact = "negligible_impact"
	}

	return result, nil
}
