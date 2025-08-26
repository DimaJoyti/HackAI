package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/compliance"
	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var integrationTracer = otel.Tracer("hackai/security/integration")

// TradingRiskManager manages trading risk assessment
type TradingRiskManager struct {
	config *RiskConfig
	logger *logger.Logger
}

// RiskConfig holds risk management configuration
type RiskConfig struct {
	MaxDailyLoss       float64            `json:"max_daily_loss"`
	MaxPositionSize    float64            `json:"max_position_size"`
	MaxPortfolioRisk   float64            `json:"max_portfolio_risk"`
	VaRConfidenceLevel float64            `json:"var_confidence_level"`
	StressTestEnabled  bool               `json:"stress_test_enabled"`
	RealTimeMonitoring bool               `json:"real_time_monitoring"`
	AlertThresholds    map[string]float64 `json:"alert_thresholds"`
	RiskLimitOverrides map[string]float64 `json:"risk_limit_overrides"`
}

// TradingRiskAssessmentResult represents trading risk assessment results
type TradingRiskAssessmentResult struct {
	OverallRiskScore float64                `json:"overall_risk_score"`
	RiskFactors      map[string]float64     `json:"risk_factors"`
	Recommendations  []string               `json:"recommendations"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// SecurityIntegrationService integrates all security components
type SecurityIntegrationService struct {
	tradingSecurityManager *TradingSecurityManager
	riskManager            *TradingRiskManager
	complianceFramework    *compliance.RegulatoryFramework
	threatDetector         *SecurityThreatDetector
	incidentManager        *IncidentManager
	securityMetrics        *SecurityMetrics
	config                 *SecurityIntegrationConfig
	logger                 *logger.Logger
	mutex                  sync.RWMutex
}

// SecurityIntegrationConfig holds integration configuration
type SecurityIntegrationConfig struct {
	EnableRealTimeMonitoring bool               `json:"enable_real_time_monitoring"`
	EnableThreatDetection    bool               `json:"enable_threat_detection"`
	EnableIncidentResponse   bool               `json:"enable_incident_response"`
	AlertThresholds          map[string]float64 `json:"alert_thresholds"`
	AutoResponseEnabled      bool               `json:"auto_response_enabled"`
	SecurityLevel            string             `json:"security_level"`
	ComplianceMode           string             `json:"compliance_mode"`
	AuditLevel               string             `json:"audit_level"`
}

// SecurityThreatDetector detects security threats
type SecurityThreatDetector struct {
	threatRules      map[string]*ThreatRule
	detectedThreats  []*DetectedThreat
	behaviorAnalyzer *BehaviorAnalyzer
	anomalyDetector  *AnomalyDetector
	logger           *logger.Logger
	mutex            sync.RWMutex
}

// IncidentManager manages security incidents
type IncidentManager struct {
	incidents       []*SecurityIncident
	responseTeam    *IncidentResponseTeam
	playbooks       map[string]*ResponsePlaybook
	escalationRules *EscalationRules
	logger          *logger.Logger
	mutex           sync.RWMutex
}

// ThreatRule defines a threat detection rule
type ThreatRule struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	Severity  string                 `json:"severity"`
	Condition string                 `json:"condition"`
	Action    string                 `json:"action"`
	Enabled   bool                   `json:"enabled"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// DetectedThreat represents a detected security threat
type DetectedThreat struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	DetectedAt  time.Time              `json:"detected_at"`
	Status      string                 `json:"status"`
	Response    *ThreatResponse        `json:"response,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatResponse represents response to a threat
type ThreatResponse struct {
	ID          string                 `json:"id"`
	ThreatID    string                 `json:"threat_id"`
	Action      string                 `json:"action"`
	Status      string                 `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Result      string                 `json:"result"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// UserBehaviorProfile represents user behavior profile
type UserBehaviorProfile struct {
	UserID          string                 `json:"user_id"`
	TypicalPatterns map[string]interface{} `json:"typical_patterns"`
	RiskScore       float64                `json:"risk_score"`
	LastActivity    time.Time              `json:"last_activity"`
	Anomalies       []*BehaviorAnomaly     `json:"anomalies"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// BaselineMetrics represents baseline behavior metrics
type BaselineMetrics struct {
	UserID         string                 `json:"user_id"`
	AvgSessionTime time.Duration          `json:"avg_session_time"`
	TypicalHours   []int                  `json:"typical_hours"`
	TypicalDays    []int                  `json:"typical_days"`
	AvgTradeSize   float64                `json:"avg_trade_size"`
	TypicalSymbols []string               `json:"typical_symbols"`
	LastUpdated    time.Time              `json:"last_updated"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// BehaviorAnomaly represents a behavior anomaly
type BehaviorAnomaly struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	DetectedAt  time.Time              `json:"detected_at"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AnomalyModel represents an anomaly detection model
type AnomalyModel struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Parameters  map[string]interface{} `json:"parameters"`
	Accuracy    float64                `json:"accuracy"`
	LastTrained time.Time              `json:"last_trained"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DetectedAnomaly represents a detected anomaly
type DetectedAnomaly struct {
	ID          string                 `json:"id"`
	ModelID     string                 `json:"model_id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Score       float64                `json:"score"`
	Description string                 `json:"description"`
	DetectedAt  time.Time              `json:"detected_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SecurityIncident represents a security incident
type SecurityIncident struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Status      string                 `json:"status"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	DetectedAt  time.Time              `json:"detected_at"`
	ReportedAt  time.Time              `json:"reported_at"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Assignee    string                 `json:"assignee"`
	Response    *IncidentResponse      `json:"response,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// IncidentResponse represents response to an incident
type IncidentResponse struct {
	ID          string                 `json:"id"`
	IncidentID  string                 `json:"incident_id"`
	PlaybookID  string                 `json:"playbook_id"`
	Actions     []*ResponseAction      `json:"actions"`
	Status      string                 `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ResponseAction represents a response action
type ResponseAction struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Status      string                 `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Result      string                 `json:"result"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// IncidentResponseTeam represents the incident response team
type IncidentResponseTeam struct {
	Members        []*TeamMember          `json:"members"`
	OnCallSchedule *OnCallSchedule        `json:"on_call_schedule"`
	Contacts       map[string]string      `json:"contacts"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// TeamMember represents a team member
type TeamMember struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Role      string                 `json:"role"`
	Skills    []string               `json:"skills"`
	Contact   string                 `json:"contact"`
	Available bool                   `json:"available"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// OnCallSchedule represents on-call schedule
type OnCallSchedule struct {
	CurrentOnCall string                 `json:"current_on_call"`
	Schedule      map[string]string      `json:"schedule"`
	Rotation      string                 `json:"rotation"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ResponsePlaybook represents an incident response playbook
type ResponsePlaybook struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Steps       []*PlaybookStep        `json:"steps"`
	Triggers    []string               `json:"triggers"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PlaybookStep represents a step in a response playbook
type PlaybookStep struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Description  string                 `json:"description"`
	Action       string                 `json:"action"`
	Automated    bool                   `json:"automated"`
	Timeout      time.Duration          `json:"timeout"`
	Dependencies []string               `json:"dependencies"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// EscalationRules defines escalation rules for incidents
type EscalationRules struct {
	Rules       []*EscalationRule      `json:"rules"`
	DefaultRule *EscalationRule        `json:"default_rule"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// EscalationRule represents an escalation rule
type EscalationRule struct {
	ID         string                 `json:"id"`
	Condition  string                 `json:"condition"`
	Severity   string                 `json:"severity"`
	TimeLimit  time.Duration          `json:"time_limit"`
	Escalatees []string               `json:"escalatees"`
	Actions    []string               `json:"actions"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// NewSecurityIntegrationService creates a new security integration service
func NewSecurityIntegrationService(config *SecurityIntegrationConfig, logger *logger.Logger) (*SecurityIntegrationService, error) {
	// Initialize security components
	tradingSecurityConfig := &TradingSecurityConfig{
		EncryptionEnabled:     true,
		AuditLoggingEnabled:   true,
		RiskMonitoringEnabled: true,
		ComplianceEnabled:     true,
		MaxDailyTrades:        1000,
		MaxPositionSize:       0.1,
		RequiredApprovals:     []string{"risk_manager", "compliance_officer"},
		SessionTimeout:        30 * time.Minute,
		IPWhitelist:           []string{},
		GeoRestrictions:       []string{},
	}

	tradingSecurityManager, err := NewTradingSecurityManager(tradingSecurityConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create trading security manager: %w", err)
	}

	riskConfig := &RiskConfig{
		MaxDailyLoss:       0.05,
		MaxPositionSize:    0.1,
		MaxPortfolioRisk:   0.2,
		VaRConfidenceLevel: 0.95,
		StressTestEnabled:  true,
		RealTimeMonitoring: true,
		AlertThresholds: map[string]float64{
			"var_breach":      0.03,
			"drawdown_breach": 0.15,
			"position_limit":  0.1,
		},
		RiskLimitOverrides: make(map[string]float64),
	}

	riskManager := NewTradingRiskManager(riskConfig, logger)

	complianceConfig := &compliance.ComplianceConfig{
		Jurisdictions:      []string{"US", "EU", "UK"},
		RegulationTypes:    []string{"MiFID", "GDPR", "SOX"},
		ReportingFrequency: 24 * time.Hour,
		AuditRetention:     7 * 365 * 24 * time.Hour,
		AutoReporting:      true,
		RealTimeMonitoring: true,
		AlertThresholds: map[string]float64{
			"violation_count":     5,
			"critical_violations": 1,
		},
		RequiredApprovals: map[string][]string{
			"high_risk_trade": {"risk_manager", "compliance_officer"},
			"large_position":  {"portfolio_manager"},
		},
	}

	complianceFramework := compliance.NewRegulatoryFramework(complianceConfig, logger)

	return &SecurityIntegrationService{
		tradingSecurityManager: tradingSecurityManager,
		riskManager:            riskManager,
		complianceFramework:    complianceFramework,
		threatDetector:         NewSecurityThreatDetector(logger),
		incidentManager:        NewIncidentManager(logger),
		securityMetrics:        NewSecurityMetrics(),
		config:                 config,
		logger:                 logger,
	}, nil
}

// ValidateSecureTradingRequest performs comprehensive security validation
func (sis *SecurityIntegrationService) ValidateSecureTradingRequest(ctx context.Context, request *SecureTradingRequest) (*SecurityValidationResult, error) {
	ctx, span := integrationTracer.Start(ctx, "security_integration.validate_secure_trading_request")
	defer span.End()

	span.SetAttributes(
		attribute.String("user_id", request.UserID),
		attribute.String("symbol", request.Symbol),
		attribute.String("action", request.Action),
	)

	result := &SecurityValidationResult{
		RequestID: request.ID,
		Valid:     true,
		Timestamp: time.Now(),
		Checks:    make(map[string]*SecurityCheckResult),
	}

	// Convert to trading request for security validation
	tradingRequest := &TradingRequest{
		ID:        request.ID,
		UserID:    request.UserID,
		SessionID: request.SessionID,
		Symbol:    request.Symbol,
		Action:    request.Action,
		Quantity:  request.Quantity,
		Price:     request.Price,
		IPAddress: request.IPAddress,
		UserAgent: request.UserAgent,
	}

	// Security validation
	securityResult, err := sis.tradingSecurityManager.ValidateTradingRequest(ctx, tradingRequest)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("security validation failed: %w", err)
	}

	result.Checks["security"] = &SecurityCheckResult{
		Name:    "security_validation",
		Passed:  securityResult.Valid,
		Score:   1.0,
		Message: "Security validation completed",
		Details: securityResult.Checks,
	}

	if !securityResult.Valid {
		result.Valid = false
	}

	// Risk assessment
	riskAssessment, err := sis.riskManager.AssessOverallRisk(ctx)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("risk assessment failed: %w", err)
	}

	result.Checks["risk"] = &SecurityCheckResult{
		Name:    "risk_assessment",
		Passed:  riskAssessment.OverallRiskScore < 0.8,
		Score:   1.0 - riskAssessment.OverallRiskScore,
		Message: fmt.Sprintf("Risk score: %.2f", riskAssessment.OverallRiskScore),
		Details: map[string]*CheckResult{
			"overall_risk": {
				Name:    "overall_risk",
				Passed:  riskAssessment.OverallRiskScore < 0.8,
				Score:   1.0 - riskAssessment.OverallRiskScore,
				Message: fmt.Sprintf("Overall risk score: %.2f", riskAssessment.OverallRiskScore),
			},
		},
	}

	if riskAssessment.OverallRiskScore >= 0.8 {
		result.Valid = false
	}

	// Compliance check
	complianceActivity := &compliance.ComplianceActivity{
		ID:        request.ID,
		Type:      "trading_request",
		Entity:    request.UserID,
		UserID:    request.UserID,
		Timestamp: time.Now(),
		Parameters: map[string]interface{}{
			"symbol":   request.Symbol,
			"action":   request.Action,
			"quantity": request.Quantity,
			"price":    request.Price,
		},
	}

	complianceResult, err := sis.complianceFramework.CheckCompliance(ctx, complianceActivity)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("compliance check failed: %w", err)
	}

	result.Checks["compliance"] = &SecurityCheckResult{
		Name:    "compliance_check",
		Passed:  complianceResult.Passed,
		Score:   complianceResult.Score,
		Message: "Compliance check completed",
		Details: map[string]*CheckResult{
			"compliance": {
				Name:    "compliance",
				Passed:  complianceResult.Passed,
				Score:   complianceResult.Score,
				Message: fmt.Sprintf("Compliance passed: %t", complianceResult.Passed),
			},
		},
	}

	if !complianceResult.Passed {
		result.Valid = false
	}

	// Threat detection
	threatResult := sis.threatDetector.AnalyzeThreat(ctx, request)
	result.Checks["threat_detection"] = threatResult

	if !threatResult.Passed {
		result.Valid = false
	}

	// Update security metrics
	sis.updateSecurityMetrics(result)

	span.SetAttributes(
		attribute.Bool("validation.valid", result.Valid),
		attribute.Int("validation.checks", len(result.Checks)),
	)

	return result, nil
}

// SecureTradingRequest represents a secure trading request
type SecureTradingRequest struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	Symbol    string    `json:"symbol"`
	Action    string    `json:"action"`
	Quantity  float64   `json:"quantity"`
	Price     float64   `json:"price"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp"`
}

// SecurityValidationResult represents the result of security validation
type SecurityValidationResult struct {
	RequestID string                          `json:"request_id"`
	Valid     bool                            `json:"valid"`
	Timestamp time.Time                       `json:"timestamp"`
	Checks    map[string]*SecurityCheckResult `json:"checks"`
}

// SecurityCheckResult represents the result of a security check
type SecurityCheckResult struct {
	Name    string                  `json:"name"`
	Passed  bool                    `json:"passed"`
	Score   float64                 `json:"score"`
	Message string                  `json:"message"`
	Details map[string]*CheckResult `json:"details"`
}

// updateSecurityMetrics updates security metrics
func (sis *SecurityIntegrationService) updateSecurityMetrics(result *SecurityValidationResult) {
	sis.mutex.Lock()
	defer sis.mutex.Unlock()

	if !result.Valid {
		sis.securityMetrics.BlockedRequests++
	} else {
		sis.securityMetrics.AllowedRequests++
	}
	sis.securityMetrics.TotalRequests++
}

// Helper constructors
func NewSecurityThreatDetector(logger *logger.Logger) *SecurityThreatDetector {
	return &SecurityThreatDetector{
		threatRules:      make(map[string]*ThreatRule),
		detectedThreats:  make([]*DetectedThreat, 0),
		behaviorAnalyzer: NewBehaviorAnalyzer(logger),
		anomalyDetector:  NewAnomalyDetector(logger),
		logger:           logger,
	}
}

func NewIncidentManager(logger *logger.Logger) *IncidentManager {
	return &IncidentManager{
		incidents:       make([]*SecurityIncident, 0),
		responseTeam:    &IncidentResponseTeam{},
		playbooks:       make(map[string]*ResponsePlaybook),
		escalationRules: &EscalationRules{},
		logger:          logger,
	}
}

func NewSecurityMetrics() *SecurityMetrics {
	return &SecurityMetrics{
		ThreatsByType:     make(map[string]int64),
		ThreatsBySeverity: make(map[string]int64),
		ThreatsBySource:   make(map[string]int64),
	}
}

// AnalyzeThreat analyzes a request for threats
func (td *SecurityThreatDetector) AnalyzeThreat(ctx context.Context, request *SecureTradingRequest) *SecurityCheckResult {
	// Simplified threat analysis
	passed := true
	message := "No threats detected"

	// Check for suspicious patterns
	if request.Quantity > 10000 {
		passed = false
		message = "Suspicious large quantity detected"
	}

	return &SecurityCheckResult{
		Name:    "threat_detection",
		Passed:  passed,
		Score:   1.0,
		Message: message,
		Details: make(map[string]*CheckResult),
	}
}

// NewTradingRiskManager creates a new trading risk manager
func NewTradingRiskManager(config *RiskConfig, logger *logger.Logger) *TradingRiskManager {
	return &TradingRiskManager{
		config: config,
		logger: logger,
	}
}

// AssessOverallRisk assesses overall trading risk
func (trm *TradingRiskManager) AssessOverallRisk(ctx context.Context) (*TradingRiskAssessmentResult, error) {
	// Simplified risk assessment
	riskScore := 0.3 // Default moderate risk

	return &TradingRiskAssessmentResult{
		OverallRiskScore: riskScore,
		RiskFactors: map[string]float64{
			"market_risk":      0.2,
			"liquidity_risk":   0.1,
			"operational_risk": 0.1,
		},
		Recommendations: []string{
			"Monitor position sizes",
			"Implement stop-loss orders",
			"Diversify portfolio",
		},
		Metadata: make(map[string]interface{}),
	}, nil
}
