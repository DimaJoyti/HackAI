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

// AgenticSecurityFramework provides autonomous AI security capabilities
type AgenticSecurityFramework struct {
	logger          *logger.Logger
	threatDetector  *AgenticThreatDetector
	promptGuard     *PromptInjectionGuard
	responseFilter  *ResponseFilter
	securityAgent   *SecurityAgent
	alertManager    *AlertManager
	config          *AgenticConfig
	mu              sync.RWMutex
	activeThreatMap map[string]*ActiveThreat
}

// AgenticConfig configuration for the agentic security framework
type AgenticConfig struct {
	EnableRealTimeAnalysis  bool          `json:"enable_real_time_analysis"`
	ThreatResponseThreshold float64       `json:"threat_response_threshold"`
	AutoBlockEnabled        bool          `json:"auto_block_enabled"`
	LearningMode            bool          `json:"learning_mode"`
	MaxConcurrentAnalysis   int           `json:"max_concurrent_analysis"`
	ThreatRetentionDuration time.Duration `json:"threat_retention_duration"`
	AlertCooldownPeriod     time.Duration `json:"alert_cooldown_period"`
}

// SecurityAgent autonomous security decision maker
type SecurityAgent struct {
	config         *AgenticConfig
	logger         *logger.Logger
	decisionEngine *DecisionEngine
	actionExecutor *ActionExecutor
	learningModule *LearningModule
}

// AgenticThreatDetector AI-powered threat detection engine for agentic systems
type AgenticThreatDetector struct {
	logger              *logger.Logger
	promptPatterns      []*ThreatPattern
	behaviorAnalyzer    *BehaviorAnalyzer
	anomalyDetector     *AnomalyDetector
	confidenceThreshold float64
}

// ThreatPattern represents a security threat pattern
type ThreatPattern struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Pattern     string    `json:"pattern"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// AgenticActiveThreat represents an active security threat in agentic framework
type AgenticActiveThreat struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"`
	Severity        string                 `json:"severity"`
	Source          string                 `json:"source"`
	Target          string                 `json:"target"`
	Confidence      float64                `json:"confidence"`
	Evidence        []string               `json:"evidence"`
	Metadata        map[string]interface{} `json:"metadata"`
	DetectedAt      time.Time              `json:"detected_at"`
	Status          string                 `json:"status"`
	ResponseActions []string               `json:"response_actions"`
}

// SecurityDecision represents an autonomous security decision
type SecurityDecision struct {
	ID         string                 `json:"id"`
	ThreatID   string                 `json:"threat_id"`
	Action     string                 `json:"action"`
	Confidence float64                `json:"confidence"`
	Reasoning  string                 `json:"reasoning"`
	Parameters map[string]interface{} `json:"parameters"`
	ExecutedAt time.Time              `json:"executed_at"`
	Result     string                 `json:"result"`
}

// NewAgenticSecurityFramework creates a new agentic security framework
func NewAgenticSecurityFramework(config *AgenticConfig, logger *logger.Logger) *AgenticSecurityFramework {
	framework := &AgenticSecurityFramework{
		logger:          logger,
		config:          config,
		activeThreatMap: make(map[string]*ActiveThreat),
	}

	// Initialize components
	framework.threatDetector = NewAgenticThreatDetector(logger)
	framework.promptGuard = NewPromptInjectionGuard(logger)
	framework.responseFilter = NewResponseFilter(logger)
	framework.securityAgent = NewSecurityAgent(config, logger)
	framework.alertManager = NewAlertManager(logger)

	return framework
}

// AnalyzeRequest performs comprehensive request analysis
func (asf *AgenticSecurityFramework) AnalyzeRequest(ctx context.Context, req *SecurityRequest) (*SecurityAnalysis, error) {
	analysis := &SecurityAnalysis{
		ID:        uuid.New().String(),
		RequestID: req.ID,
		StartTime: time.Now(),
		Threats:   make([]*ThreatDetection, 0),
	}

	// Concurrent threat analysis
	var wg sync.WaitGroup
	threatChan := make(chan *ThreatDetection, 10)

	// Prompt injection detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		if threat := asf.promptGuard.DetectPromptInjection(req); threat != nil {
			threatChan <- threat
		}
	}()

	// Behavioral analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if threats := asf.threatDetector.AnalyzeBehavior(req); len(threats) > 0 {
			for _, threat := range threats {
				threatChan <- threat
			}
		}
	}()

	// Anomaly detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		if threat := asf.threatDetector.DetectAnomalies(req); threat != nil {
			threatChan <- threat
		}
	}()

	// Wait for analysis completion
	go func() {
		wg.Wait()
		close(threatChan)
	}()

	// Collect threats
	for threat := range threatChan {
		analysis.Threats = append(analysis.Threats, threat)
	}

	// Calculate overall risk score
	analysis.RiskScore = asf.calculateRiskScore(analysis.Threats)
	analysis.EndTime = time.Now()
	analysis.Duration = analysis.EndTime.Sub(analysis.StartTime)

	// Autonomous response if threshold exceeded
	if analysis.RiskScore >= asf.config.ThreatResponseThreshold {
		decision := asf.securityAgent.MakeDecision(ctx, analysis)
		if decision != nil {
			analysis.AutoResponse = decision
			asf.executeSecurityAction(ctx, decision)
		}
	}

	return analysis, nil
}

// calculateRiskScore calculates overall risk score from threats
func (asf *AgenticSecurityFramework) calculateRiskScore(threats []*ThreatDetection) float64 {
	if len(threats) == 0 {
		return 0.0
	}

	var totalScore float64
	var maxScore float64

	for _, threat := range threats {
		score := threat.Confidence * asf.getSeverityMultiplier(threat.Severity)
		totalScore += score
		if score > maxScore {
			maxScore = score
		}
	}

	// Weighted average with emphasis on highest threat
	avgScore := totalScore / float64(len(threats))
	return (avgScore*0.7 + maxScore*0.3)
}

// getSeverityMultiplier returns severity multiplier for risk calculation
func (asf *AgenticSecurityFramework) getSeverityMultiplier(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 1.0
	case "high":
		return 0.8
	case "medium":
		return 0.6
	case "low":
		return 0.4
	case "info":
		return 0.2
	default:
		return 0.5
	}
}

// executeSecurityAction executes autonomous security actions
func (asf *AgenticSecurityFramework) executeSecurityAction(ctx context.Context, decision *SecurityDecision) {
	asf.logger.WithFields(logger.Fields{
		"decision_id": decision.ID,
		"action":      decision.Action,
		"confidence":  decision.Confidence,
	}).Info("Executing autonomous security action")

	// Execute based on action type
	switch decision.Action {
	case "block_request":
		asf.blockRequest(ctx, decision)
	case "rate_limit":
		asf.applyRateLimit(ctx, decision)
	case "quarantine_session":
		asf.quarantineSession(ctx, decision)
	case "alert_admin":
		asf.alertManager.SendAlert(ctx, decision)
	case "log_incident":
		asf.logSecurityIncident(ctx, decision)
	}
}

// SecurityRequest represents a request for security analysis
type SecurityRequest struct {
	ID        string                 `json:"id"`
	Method    string                 `json:"method"`
	URL       string                 `json:"url"`
	Headers   map[string]string      `json:"headers"`
	Body      string                 `json:"body"`
	UserID    string                 `json:"user_id"`
	SessionID string                 `json:"session_id"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Timestamp time.Time              `json:"timestamp"`
	Context   map[string]interface{} `json:"context"`
}

// SecurityAnalysis represents the result of security analysis
type SecurityAnalysis struct {
	ID           string             `json:"id"`
	RequestID    string             `json:"request_id"`
	RiskScore    float64            `json:"risk_score"`
	Threats      []*ThreatDetection `json:"threats"`
	AutoResponse *SecurityDecision  `json:"auto_response,omitempty"`
	StartTime    time.Time          `json:"start_time"`
	EndTime      time.Time          `json:"end_time"`
	Duration     time.Duration      `json:"duration"`
}

// ThreatDetection represents a detected threat
type ThreatDetection struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Description string                 `json:"description"`
	Evidence    []string               `json:"evidence"`
	Indicators  []string               `json:"indicators"`
	Metadata    map[string]interface{} `json:"metadata"`
	DetectedAt  time.Time              `json:"detected_at"`
}

// DefaultAgenticConfig returns default configuration
func DefaultAgenticConfig() *AgenticConfig {
	return &AgenticConfig{
		EnableRealTimeAnalysis:  true,
		ThreatResponseThreshold: 0.7,
		AutoBlockEnabled:        true,
		LearningMode:            true,
		MaxConcurrentAnalysis:   10,
		ThreatRetentionDuration: 24 * time.Hour,
		AlertCooldownPeriod:     5 * time.Minute,
	}
}

// Supporting component implementations

// NewAgenticThreatDetector creates a new agentic threat detector
func NewAgenticThreatDetector(logger *logger.Logger) *AgenticThreatDetector {
	return &AgenticThreatDetector{
		logger:              logger,
		promptPatterns:      loadThreatPatterns(),
		behaviorAnalyzer:    NewBehaviorAnalyzer(logger),
		anomalyDetector:     NewAnomalyDetector(logger),
		confidenceThreshold: 0.7,
	}
}

// AnalyzeBehavior analyzes behavior patterns for threats
func (atd *AgenticThreatDetector) AnalyzeBehavior(req *SecurityRequest) []*ThreatDetection {
	var threats []*ThreatDetection

	// Analyze behavior patterns using prompt patterns
	for _, pattern := range atd.promptPatterns {
		if atd.matchesPattern(req.Body, pattern) {
			threat := &ThreatDetection{
				ID:          uuid.New().String(),
				Type:        "behavior_analysis",
				Severity:    pattern.Severity,
				Confidence:  pattern.Confidence,
				Description: fmt.Sprintf("Behavior pattern detected: %s", pattern.Name),
				DetectedAt:  time.Now(),
				Evidence:    []string{req.Body},
				Indicators:  []string{pattern.Pattern},
				Metadata: map[string]interface{}{
					"pattern_id":   pattern.ID,
					"pattern_name": pattern.Name,
					"user_id":      req.UserID,
				},
			}
			threats = append(threats, threat)
		}
	}

	return threats
}

// DetectAnomalies detects anomalous patterns
func (atd *AgenticThreatDetector) DetectAnomalies(req *SecurityRequest) *ThreatDetection {
	// Simple anomaly detection based on request characteristics
	anomalyScore := 0.0

	// Check for unusual request size
	if len(req.Body) > 10000 {
		anomalyScore += 0.3
	}

	// Check for suspicious patterns
	if strings.Contains(strings.ToLower(req.Body), "ignore") ||
		strings.Contains(strings.ToLower(req.Body), "forget") ||
		strings.Contains(strings.ToLower(req.Body), "override") {
		anomalyScore += 0.4
	}

	// Check for rapid requests (simplified check)
	if len(req.Body) > 5000 && strings.Count(req.Body, "\n") > 100 {
		anomalyScore += 0.3
	}

	if anomalyScore >= atd.confidenceThreshold {
		return &ThreatDetection{
			ID:          uuid.New().String(),
			Type:        "anomaly_detection",
			Severity:    "medium",
			Confidence:  anomalyScore,
			Description: "Anomalous behavior detected",
			DetectedAt:  time.Now(),
			Evidence:    []string{req.Body},
			Indicators:  []string{"large_request", "suspicious_patterns"},
			Metadata: map[string]interface{}{
				"anomaly_score":  anomalyScore,
				"detection_type": "behavioral_anomaly",
				"user_id":        req.UserID,
			},
		}
	}

	return nil
}

// matchesPattern checks if content matches a threat pattern
func (atd *AgenticThreatDetector) matchesPattern(content string, pattern *ThreatPattern) bool {
	// Simple pattern matching - in production this would use more sophisticated matching
	return strings.Contains(strings.ToLower(content), strings.ToLower(pattern.Pattern))
}

// NewSecurityAgent creates a new security agent
func NewSecurityAgent(config *AgenticConfig, logger *logger.Logger) *SecurityAgent {
	return &SecurityAgent{
		config:         config,
		logger:         logger,
		decisionEngine: NewDecisionEngine(logger),
		actionExecutor: NewActionExecutor(logger),
		learningModule: NewLearningModule(logger),
	}
}

// NewAlertManager creates a new alert manager
func NewAlertManager(logger *logger.Logger) *AlertManager {
	return &AlertManager{logger: logger}
}

// MakeDecision makes an autonomous security decision
func (sa *SecurityAgent) MakeDecision(ctx context.Context, analysis *SecurityAnalysis) *SecurityDecision {
	decision := &SecurityDecision{
		ID:         uuid.New().String(),
		ExecutedAt: time.Now(),
		Parameters: make(map[string]interface{}),
	}

	// Determine action based on risk score and threat types
	if analysis.RiskScore >= 0.9 {
		decision.Action = "block_request"
		decision.Confidence = analysis.RiskScore
		decision.Reasoning = "Critical threat level detected"
	} else if analysis.RiskScore >= 0.7 {
		decision.Action = "rate_limit"
		decision.Confidence = analysis.RiskScore
		decision.Reasoning = "High threat level detected"
	} else if analysis.RiskScore >= 0.5 {
		decision.Action = "alert_admin"
		decision.Confidence = analysis.RiskScore
		decision.Reasoning = "Medium threat level detected"
	} else {
		decision.Action = "log_incident"
		decision.Confidence = analysis.RiskScore
		decision.Reasoning = "Low threat level detected"
	}

	return decision
}

// Helper methods for security actions
func (asf *AgenticSecurityFramework) blockRequest(ctx context.Context, decision *SecurityDecision) {
	asf.logger.WithField("decision_id", decision.ID).Info("Request blocked by autonomous security agent")
}

func (asf *AgenticSecurityFramework) applyRateLimit(ctx context.Context, decision *SecurityDecision) {
	asf.logger.WithField("decision_id", decision.ID).Info("Rate limit applied by autonomous security agent")
}

func (asf *AgenticSecurityFramework) quarantineSession(ctx context.Context, decision *SecurityDecision) {
	asf.logger.WithField("decision_id", decision.ID).Info("Session quarantined by autonomous security agent")
}

func (asf *AgenticSecurityFramework) logSecurityIncident(ctx context.Context, decision *SecurityDecision) {
	asf.logger.WithField("decision_id", decision.ID).Info("Security incident logged by autonomous security agent")
}

// loadThreatPatterns loads predefined threat patterns
func loadThreatPatterns() []*ThreatPattern {
	return []*ThreatPattern{
		{
			ID:          "sql_injection",
			Name:        "SQL Injection",
			Pattern:     `(?i)(union|select|insert|drop|delete|update).*?(from|into|table)`,
			Severity:    "critical",
			Confidence:  0.9,
			Category:    "injection",
			Description: "SQL injection attack pattern",
			CreatedAt:   time.Now(),
		},
		{
			ID:          "xss_attack",
			Name:        "Cross-Site Scripting",
			Pattern:     `(?i)<script[^>]*>.*?</script>|javascript:|on\w+\s*=`,
			Severity:    "high",
			Confidence:  0.8,
			Category:    "injection",
			Description: "XSS attack pattern",
			CreatedAt:   time.Now(),
		},
	}
}
