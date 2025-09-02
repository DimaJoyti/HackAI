package usecase

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var aiSecurityTracer = otel.Tracer("hackai/usecase/ai_security_framework")

// AISecurityFramework implements comprehensive AI security capabilities
type AISecurityFramework struct {
	logger                *logger.Logger
	atlasFramework        *security.ATLASFramework
	owaspAITop10          *security.OWASPAITop10
	promptInjectionGuard  *security.PromptInjectionGuard
	threatDetectionEngine *security.AdvancedThreatDetectionEngine
	llmContentFilter      *security.LLMContentFilter
	llmPolicyEngine       *security.LLMPolicyEngine
	llmRateLimiter        *security.LLMRateLimiter
	aiFirewall            *security.AIFirewall
	threatIntelligence    *security.ThreatIntelligenceOrchestrator
	securityRepo          domain.LLMSecurityRepository
	auditRepo             domain.AuditRepository
	config                *AISecurityConfig
	mu                    sync.RWMutex
}

// AISecurityConfig configuration for AI security framework
type AISecurityConfig struct {
	EnableMITREATLAS         bool          `json:"enable_mitre_atlas"`
	EnableOWASPAITop10       bool          `json:"enable_owasp_ai_top10"`
	EnablePromptInjection    bool          `json:"enable_prompt_injection"`
	EnableThreatDetection    bool          `json:"enable_threat_detection"`
	EnableContentFiltering   bool          `json:"enable_content_filtering"`
	EnablePolicyEngine       bool          `json:"enable_policy_engine"`
	EnableRateLimiting       bool          `json:"enable_rate_limiting"`
	EnableAIFirewall         bool          `json:"enable_ai_firewall"`
	EnableThreatIntelligence bool          `json:"enable_threat_intelligence"`
	RealTimeMonitoring       bool          `json:"real_time_monitoring"`
	AutoMitigation           bool          `json:"auto_mitigation"`
	ThreatThreshold          float64       `json:"threat_threshold"`
	ScanInterval             time.Duration `json:"scan_interval"`
	LogDetailedAnalysis      bool          `json:"log_detailed_analysis"`
	EnableContinuousLearning bool          `json:"enable_continuous_learning"`
	MaxConcurrentScans       int           `json:"max_concurrent_scans"`
	AlertingEnabled          bool          `json:"alerting_enabled"`
	ComplianceReporting      bool          `json:"compliance_reporting"`
}

// AISecurityAssessment represents a comprehensive AI security assessment
type AISecurityAssessment struct {
	ID                     uuid.UUID                       `json:"id"`
	Timestamp              time.Time                       `json:"timestamp"`
	RequestID              string                          `json:"request_id"`
	UserID                 *uuid.UUID                      `json:"user_id,omitempty"`
	SessionID              *uuid.UUID                      `json:"session_id,omitempty"`
	OverallThreatScore     float64                         `json:"overall_threat_score"`
	RiskLevel              string                          `json:"risk_level"`
	ComplianceStatus       string                          `json:"compliance_status"`
	PromptInjectionResults *security.PromptAnalysis        `json:"prompt_injection_results,omitempty"`
	ThreatDetectionResults *security.ThreatDetectionResult `json:"threat_detection_results,omitempty"`
	ContentFilterResults   *security.ContentFilterResult   `json:"content_filter_results,omitempty"`
	SecurityEvents         []domain.SecurityEvent          `json:"security_events"`
	Recommendations        []SecurityRecommendation        `json:"recommendations"`
	Mitigations            []SecurityMitigation            `json:"mitigations"`
	Blocked                bool                            `json:"blocked"`
	BlockReason            string                          `json:"block_reason,omitempty"`
	ProcessingDuration     time.Duration                   `json:"processing_duration"`
	Metadata               map[string]interface{}          `json:"metadata"`
}

// SecurityRecommendation represents a security recommendation
type SecurityRecommendation struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Priority    string                 `json:"priority"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Action      string                 `json:"action"`
	References  []string               `json:"references"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SecurityMitigation represents a security mitigation
type SecurityMitigation struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Implementation string                 `json:"implementation"`
	Effectiveness  float64                `json:"effectiveness"`
	Applied        bool                   `json:"applied"`
	AppliedAt      *time.Time             `json:"applied_at,omitempty"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// NewAISecurityFramework creates a new AI security framework
func NewAISecurityFramework(
	logger *logger.Logger,
	securityRepo domain.LLMSecurityRepository,
	auditRepo domain.AuditRepository,
	config *AISecurityConfig,
) (*AISecurityFramework, error) {
	if config == nil {
		config = &AISecurityConfig{
			EnableMITREATLAS:         true,
			EnableOWASPAITop10:       true,
			EnablePromptInjection:    true,
			EnableThreatDetection:    true,
			EnableContentFiltering:   true,
			EnablePolicyEngine:       true,
			EnableRateLimiting:       true,
			EnableAIFirewall:         true,
			EnableThreatIntelligence: true,
			RealTimeMonitoring:       true,
			AutoMitigation:           false,
			ThreatThreshold:          0.7,
			ScanInterval:             5 * time.Minute,
			LogDetailedAnalysis:      true,
			EnableContinuousLearning: true,
			MaxConcurrentScans:       10,
			AlertingEnabled:          true,
			ComplianceReporting:      true,
		}
	}

	framework := &AISecurityFramework{
		logger:       logger,
		securityRepo: securityRepo,
		auditRepo:    auditRepo,
		config:       config,
	}

	// Initialize security components
	if err := framework.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize AI security components: %w", err)
	}

	return framework, nil
}

// initializeComponents initializes all security components
func (f *AISecurityFramework) initializeComponents() error {

	// Initialize MITRE ATLAS framework
	if f.config.EnableMITREATLAS {
		atlasConfig := &security.ATLASConfig{
			EnableRealTimeMapping: f.config.RealTimeMonitoring,
			EnableAutoMitigation:  f.config.AutoMitigation,
			UpdateInterval:        f.config.ScanInterval,
			LogAllMappings:        f.config.LogDetailedAnalysis,
			EnableThreatHunting:   true,
			MitigationThreshold:   f.config.ThreatThreshold,
			DetectionSensitivity:  "high",
		}
		f.atlasFramework = security.NewATLASFramework(atlasConfig, f.logger)
	}

	// Initialize OWASP AI Top 10
	if f.config.EnableOWASPAITop10 {
		owaspConfig := &security.OWASPConfig{
			EnableRealTimeScanning:  f.config.RealTimeMonitoring,
			EnableAutoRemediation:   f.config.AutoMitigation,
			ComplianceThreshold:     f.config.ThreatThreshold,
			ScanInterval:            f.config.ScanInterval,
			LogViolations:           f.config.LogDetailedAnalysis,
			EnableContinuousMonitor: true,
			AlertOnViolations:       f.config.AlertingEnabled,
			RemediationTimeout:      30 * time.Second,
		}
		f.owaspAITop10 = security.NewOWASPAITop10(owaspConfig, f.logger)
	}

	// Initialize prompt injection guard
	if f.config.EnablePromptInjection {
		f.promptInjectionGuard = security.NewPromptInjectionGuard(f.logger)
	}

	// Initialize advanced threat detection engine
	if f.config.EnableThreatDetection {
		threatConfig := &security.AdvancedThreatConfig{
			EnableModelInversionDetection:      true,
			EnableDataPoisoningDetection:       true,
			EnableAdversarialAttackDetection:   true,
			EnableMembershipInferenceDetection: true,
			EnableExtractionAttackDetection:    true,
			ThreatThreshold:                    f.config.ThreatThreshold,
			ScanInterval:                       f.config.ScanInterval,
			EnableRealTimeDetection:            f.config.RealTimeMonitoring,
			LogDetailedAnalysis:                f.config.LogDetailedAnalysis,
			EnableThreatIntelligence:           f.config.EnableThreatIntelligence,
			MaxConcurrentScans:                 f.config.MaxConcurrentScans,
		}
		f.threatDetectionEngine = security.NewAdvancedThreatDetectionEngine(threatConfig, f.logger)
	}

	// Initialize components that are available and working
	// Note: Some components require additional dependencies that will be initialized separately

	f.logger.Info("AI Security Framework components initialized successfully")
	return nil
}

// AssessLLMRequest performs comprehensive AI security assessment on an LLM request
func (f *AISecurityFramework) AssessLLMRequest(ctx context.Context, request *security.LLMRequest) (*AISecurityAssessment, error) {
	ctx, span := aiSecurityTracer.Start(ctx, "ai_security_framework.assess_llm_request")
	defer span.End()

	startTime := time.Now()
	assessment := &AISecurityAssessment{
		ID:                 uuid.New(),
		Timestamp:          startTime,
		RequestID:          request.ID,
		UserID:             request.UserID,
		SessionID:          request.SessionID,
		OverallThreatScore: 0.0,
		RiskLevel:          "low",
		ComplianceStatus:   "compliant",
		Recommendations:    []SecurityRecommendation{},
		Mitigations:        []SecurityMitigation{},
		Blocked:            false,
		Metadata:           make(map[string]interface{}),
	}

	span.SetAttributes(
		attribute.String("request.id", request.ID),
		attribute.String("assessment.id", assessment.ID.String()),
	)

	// Perform basic security assessments
	threatScores := make([]float64, 0)

	// Basic prompt injection check
	if f.config.EnablePromptInjection && f.promptInjectionGuard != nil {
		promptText := string(request.Body)
		result := f.promptInjectionGuard.AnalyzePrompt(ctx, promptText, "")
		if result != nil {
			assessment.PromptInjectionResults = result
			threatScores = append(threatScores, result.Confidence)
		}
	}

	// Basic threat analysis
	threatScore := f.analyzeBasicThreats(ctx, request)
	threatScores = append(threatScores, threatScore)

	// Calculate overall threat score
	assessment.OverallThreatScore = f.calculateOverallThreatScore(threatScores)
	assessment.RiskLevel = f.determineRiskLevel(assessment.OverallThreatScore)
	assessment.ComplianceStatus = f.determineComplianceStatus(assessment)

	// Generate recommendations and mitigations
	assessment.Recommendations = f.generateRecommendations(assessment)
	assessment.Mitigations = f.generateMitigations(assessment)

	// Determine if request should be blocked
	assessment.Blocked, assessment.BlockReason = f.shouldBlockRequest(assessment)

	// Record processing duration
	assessment.ProcessingDuration = time.Since(startTime)

	// Log assessment if enabled
	if f.config.LogDetailedAnalysis {
		f.logger.WithFields(map[string]interface{}{
			"assessment_id":        assessment.ID.String(),
			"request_id":           assessment.RequestID,
			"overall_threat_score": assessment.OverallThreatScore,
			"risk_level":           assessment.RiskLevel,
			"blocked":              assessment.Blocked,
			"processing_duration":  assessment.ProcessingDuration,
		}).Info("AI security assessment completed")
	}

	// Store assessment results
	if err := f.storeAssessment(ctx, assessment); err != nil {
		f.logger.WithError(err).Error("Failed to store security assessment")
	}

	span.SetAttributes(
		attribute.Float64("assessment.threat_score", assessment.OverallThreatScore),
		attribute.String("assessment.risk_level", assessment.RiskLevel),
		attribute.Bool("assessment.blocked", assessment.Blocked),
		attribute.Int64("assessment.duration_ms", assessment.ProcessingDuration.Milliseconds()),
	)

	return assessment, nil
}

// Helper methods for AI Security Framework

// analyzeBasicThreats performs basic threat analysis on the request
func (f *AISecurityFramework) analyzeBasicThreats(ctx context.Context, request *security.LLMRequest) float64 {
	threatScore := 0.0

	// Analyze request content for basic threats
	content := string(request.Body)

	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"ignore previous instructions",
		"system prompt",
		"jailbreak",
		"bypass",
		"override",
		"admin",
		"root",
		"sudo",
		"execute",
		"eval",
		"script",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(content), pattern) {
			threatScore += 0.1
		}
	}

	// Check content length (very long prompts can be suspicious)
	if len(content) > 5000 {
		threatScore += 0.2
	}

	// Check for excessive special characters
	specialCharCount := 0
	for _, char := range content {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == ' ') {
			specialCharCount++
		}
	}

	if len(content) > 0 && float64(specialCharCount)/float64(len(content)) > 0.3 {
		threatScore += 0.15
	}

	// Cap the threat score at 1.0
	if threatScore > 1.0 {
		threatScore = 1.0
	}

	return threatScore
}

// calculateOverallThreatScore calculates the overall threat score from individual scores
func (f *AISecurityFramework) calculateOverallThreatScore(scores []float64) float64 {
	if len(scores) == 0 {
		return 0.0
	}

	// Use weighted average with emphasis on highest scores
	var sum float64
	var maxScore float64

	for _, score := range scores {
		sum += score
		if score > maxScore {
			maxScore = score
		}
	}

	avgScore := sum / float64(len(scores))

	// Weight: 70% max score, 30% average score
	overallScore := (maxScore * 0.7) + (avgScore * 0.3)

	return overallScore
}

// determineRiskLevel determines the risk level based on threat score
func (f *AISecurityFramework) determineRiskLevel(threatScore float64) string {
	switch {
	case threatScore >= 0.8:
		return "critical"
	case threatScore >= 0.6:
		return "high"
	case threatScore >= 0.4:
		return "medium"
	case threatScore >= 0.2:
		return "low"
	default:
		return "minimal"
	}
}

// determineComplianceStatus determines compliance status based on assessment
func (f *AISecurityFramework) determineComplianceStatus(assessment *AISecurityAssessment) string {
	if assessment.OverallThreatScore >= f.config.ThreatThreshold {
		return "non-compliant"
	}

	if assessment.OverallThreatScore >= 0.5 {
		return "warning"
	}

	return "compliant"
}

// generateRecommendations generates security recommendations based on assessment
func (f *AISecurityFramework) generateRecommendations(assessment *AISecurityAssessment) []SecurityRecommendation {
	recommendations := []SecurityRecommendation{}

	if assessment.OverallThreatScore >= 0.6 {
		recommendations = append(recommendations, SecurityRecommendation{
			ID:          uuid.New().String(),
			Type:        "security",
			Priority:    "high",
			Title:       "High Threat Score Detected",
			Description: "The request has a high threat score and should be reviewed",
			Action:      "Review request content and consider blocking",
			References:  []string{"OWASP AI Top 10", "MITRE ATLAS"},
			Metadata:    map[string]interface{}{"threat_score": assessment.OverallThreatScore},
		})
	}

	if assessment.PromptInjectionResults != nil && assessment.PromptInjectionResults.IsInjection {
		recommendations = append(recommendations, SecurityRecommendation{
			ID:          uuid.New().String(),
			Type:        "prompt_injection",
			Priority:    "critical",
			Title:       "Prompt Injection Detected",
			Description: "Potential prompt injection attack detected in the request",
			Action:      "Block request and implement additional prompt filtering",
			References:  []string{"OWASP AI Top 10 - A01:2023 Prompt Injection"},
			Metadata:    map[string]interface{}{"confidence": assessment.PromptInjectionResults.Confidence},
		})
	}

	return recommendations
}

// generateMitigations generates security mitigations based on assessment
func (f *AISecurityFramework) generateMitigations(assessment *AISecurityAssessment) []SecurityMitigation {
	mitigations := []SecurityMitigation{}

	if assessment.OverallThreatScore >= f.config.ThreatThreshold {
		mitigations = append(mitigations, SecurityMitigation{
			ID:             uuid.New().String(),
			Type:           "blocking",
			Name:           "Request Blocking",
			Description:    "Block the request due to high threat score",
			Implementation: "Immediate request blocking with threat score logging",
			Effectiveness:  0.95,
			Applied:        f.config.AutoMitigation,
			Metadata:       map[string]interface{}{"threshold": f.config.ThreatThreshold},
		})
	}

	if assessment.PromptInjectionResults != nil && assessment.PromptInjectionResults.IsInjection {
		mitigations = append(mitigations, SecurityMitigation{
			ID:             uuid.New().String(),
			Type:           "filtering",
			Name:           "Prompt Sanitization",
			Description:    "Sanitize or filter the prompt to remove injection attempts",
			Implementation: "Apply prompt sanitization filters and content validation",
			Effectiveness:  0.85,
			Applied:        false,
			Metadata:       map[string]interface{}{"injection_type": "prompt_injection"},
		})
	}

	return mitigations
}

// shouldBlockRequest determines if a request should be blocked
func (f *AISecurityFramework) shouldBlockRequest(assessment *AISecurityAssessment) (bool, string) {
	if assessment.OverallThreatScore >= f.config.ThreatThreshold {
		return true, fmt.Sprintf("Threat score %.2f exceeds threshold %.2f", assessment.OverallThreatScore, f.config.ThreatThreshold)
	}

	if assessment.PromptInjectionResults != nil && assessment.PromptInjectionResults.IsInjection && assessment.PromptInjectionResults.Confidence >= 0.8 {
		return true, "High confidence prompt injection detected"
	}

	return false, ""
}

// storeAssessment stores the security assessment results
func (f *AISecurityFramework) storeAssessment(ctx context.Context, assessment *AISecurityAssessment) error {
	// Create LLM request log entry
	requestLog := &domain.LLMRequestLog{
		ID:              uuid.New(),
		RequestID:       assessment.RequestID,
		UserID:          assessment.UserID,
		SessionID:       assessment.SessionID,
		ThreatScore:     assessment.OverallThreatScore,
		Blocked:         assessment.Blocked,
		BlockReason:     assessment.BlockReason,
		ComplianceFlags: []byte(fmt.Sprintf(`{"status": "%s", "risk_level": "%s"}`, assessment.ComplianceStatus, assessment.RiskLevel)),
		CreatedAt:       assessment.Timestamp,
	}

	if err := f.securityRepo.CreateRequestLog(ctx, requestLog); err != nil {
		return fmt.Errorf("failed to create request log: %w", err)
	}

	// Create security events for high-risk assessments
	if assessment.OverallThreatScore >= 0.6 {
		var severity domain.Severity
		switch assessment.RiskLevel {
		case "critical":
			severity = domain.SeverityCritical
		case "high":
			severity = domain.SeverityHigh
		case "medium":
			severity = domain.SeverityMedium
		case "low":
			severity = domain.SeverityLow
		default:
			severity = domain.SeverityInfo
		}

		securityEvent := &domain.SecurityEvent{
			ID:          uuid.New(),
			Type:        "suspicious_activity",
			Category:    "ai_security",
			Title:       "High Threat Score Detected",
			Description: fmt.Sprintf("AI security assessment detected high threat score: %.2f", assessment.OverallThreatScore),
			Severity:    severity,
			Status:      "open",
			RequestID:   &assessment.RequestID,
			UserID:      assessment.UserID,
			SessionID:   assessment.SessionID,
			CreatedAt:   assessment.Timestamp,
			UpdatedAt:   assessment.Timestamp,
		}

		if err := f.auditRepo.CreateSecurityEvent(securityEvent); err != nil {
			f.logger.WithError(err).Error("Failed to create security event")
		}
	}

	return nil
}
