package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// AutomatedAssessmentEngine provides automated security assessment capabilities
type AutomatedAssessmentEngine struct {
	logger              *logger.Logger
	assessmentScheduler *AssessmentScheduler
	complianceChecker   *ComplianceChecker
	riskAnalyzer        *RiskAnalyzer
	reportAggregator    *ReportAggregator
	config              *AssessmentConfig
	activeAssessments   map[string]*Assessment
	mu                  sync.RWMutex
}

// AssessmentConfig configuration for automated assessments
type AssessmentConfig struct {
	EnableScheduledAssessments bool          `json:"enable_scheduled_assessments"`
	EnableContinuousMonitoring bool          `json:"enable_continuous_monitoring"`
	DefaultAssessmentInterval  time.Duration `json:"default_assessment_interval"`
	MaxConcurrentAssessments   int           `json:"max_concurrent_assessments"`
	EnableRiskScoring          bool          `json:"enable_risk_scoring"`
	EnableComplianceChecking   bool          `json:"enable_compliance_checking"`
	NotificationChannels       []string      `json:"notification_channels"`
	RetentionPeriod            time.Duration `json:"retention_period"`
}

// Assessment represents a security assessment
type Assessment struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Type          string                 `json:"type"`
	Target        *AssessmentTarget      `json:"target"`
	Schedule      *AssessmentSchedule    `json:"schedule"`
	Status        string                 `json:"status"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       *time.Time             `json:"end_time"`
	Progress      float64                `json:"progress"`
	Results       *AssessmentResults     `json:"results"`
	Notifications []*Notification        `json:"notifications"`
	Metadata      map[string]interface{} `json:"metadata"`
	CreatedBy     string                 `json:"created_by"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// AssessmentTarget represents a target for security assessment
type AssessmentTarget struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	URL         string                 `json:"url"`
	Description string                 `json:"description"`
	Components  []string               `json:"components"`
	Credentials *TargetCredentials     `json:"credentials,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AssessmentSchedule represents a schedule for automated assessments
type AssessmentSchedule struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Frequency     string                 `json:"frequency"`
	Interval      time.Duration          `json:"interval"`
	NextRun       time.Time              `json:"next_run"`
	LastRun       *time.Time             `json:"last_run"`
	Enabled       bool                   `json:"enabled"`
	MaxRetries    int                    `json:"max_retries"`
	RetryInterval time.Duration          `json:"retry_interval"`
	Notifications []string               `json:"notifications"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// AssessmentResults represents the results of a security assessment
type AssessmentResults struct {
	OverallScore       float64                `json:"overall_score"`
	RiskLevel          string                 `json:"risk_level"`
	ComplianceScore    float64                `json:"compliance_score"`
	VulnerabilityCount int                    `json:"vulnerability_count"`
	CriticalIssues     int                    `json:"critical_issues"`
	HighIssues         int                    `json:"high_issues"`
	MediumIssues       int                    `json:"medium_issues"`
	LowIssues          int                    `json:"low_issues"`
	SecurityFindings   []*SecurityFinding     `json:"security_findings"`
	ComplianceFindings []*ComplianceFinding   `json:"compliance_findings"`
	RiskAssessment     *RiskAssessmentResult  `json:"risk_assessment"`
	Recommendations    []string               `json:"recommendations"`
	TrendAnalysis      *TrendAnalysis         `json:"trend_analysis"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// SecurityFinding represents a security finding from assessment
type SecurityFinding struct {
	ID              string                 `json:"id"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Severity        string                 `json:"severity"`
	Category        string                 `json:"category"`
	CVSS            float64                `json:"cvss"`
	CWE             string                 `json:"cwe"`
	OWASP           string                 `json:"owasp"`
	Impact          string                 `json:"impact"`
	Likelihood      string                 `json:"likelihood"`
	Evidence        []Evidence             `json:"evidence"`
	Recommendations []string               `json:"recommendations"`
	Status          string                 `json:"status"`
	AssignedTo      string                 `json:"assigned_to"`
	DueDate         *time.Time             `json:"due_date"`
	Metadata        map[string]interface{} `json:"metadata"`
	DiscoveredAt    time.Time              `json:"discovered_at"`
}

// ComplianceFinding represents a compliance finding from assessment
type ComplianceFinding struct {
	ID              string                 `json:"id"`
	Framework       string                 `json:"framework"`
	Control         string                 `json:"control"`
	Requirement     string                 `json:"requirement"`
	Status          string                 `json:"status"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
	Evidence        []Evidence             `json:"evidence"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
	AssessedAt      time.Time              `json:"assessed_at"`
}

// RiskAssessmentResult represents risk assessment results
type RiskAssessmentResult struct {
	OverallRisk          string                 `json:"overall_risk"`
	RiskScore            float64                `json:"risk_score"`
	BusinessImpact       string                 `json:"business_impact"`
	TechnicalImpact      string                 `json:"technical_impact"`
	RiskFactors          []*RiskFactor          `json:"risk_factors"`
	MitigationStrategies []string               `json:"mitigation_strategies"`
	RiskTrend            string                 `json:"risk_trend"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// RiskFactor is defined in autonomous_types.go

// TrendAnalysis represents trend analysis of security metrics
type TrendAnalysis struct {
	Period             string                 `json:"period"`
	SecurityTrend      string                 `json:"security_trend"`
	ComplianceTrend    string                 `json:"compliance_trend"`
	VulnerabilityTrend string                 `json:"vulnerability_trend"`
	RiskTrend          string                 `json:"risk_trend"`
	Metrics            map[string]float64     `json:"metrics"`
	Predictions        map[string]float64     `json:"predictions"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// Notification represents a notification from assessment
type Notification struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Severity   string                 `json:"severity"`
	Title      string                 `json:"title"`
	Message    string                 `json:"message"`
	Recipients []string               `json:"recipients"`
	Channels   []string               `json:"channels"`
	Status     string                 `json:"status"`
	SentAt     *time.Time             `json:"sent_at"`
	Metadata   map[string]interface{} `json:"metadata"`
	CreatedAt  time.Time              `json:"created_at"`
}

// AssessmentScheduler manages scheduled assessments
type AssessmentScheduler struct {
	logger    *logger.Logger
	schedules map[string]*AssessmentSchedule
	config    *SchedulerConfig
	mu        sync.RWMutex
}

// SchedulerConfig configuration for assessment scheduler
type SchedulerConfig struct {
	EnableScheduling  bool          `json:"enable_scheduling"`
	CheckInterval     time.Duration `json:"check_interval"`
	MaxConcurrentRuns int           `json:"max_concurrent_runs"`
	DefaultRetries    int           `json:"default_retries"`
	DefaultRetryDelay time.Duration `json:"default_retry_delay"`
}

// ComplianceChecker checks compliance against various frameworks
type ComplianceChecker struct {
	logger     *logger.Logger
	frameworks map[string]*ComplianceFramework
	config     *ComplianceConfig
}

// ComplianceFramework represents a compliance framework
type ComplianceFramework struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Controls    []*ComplianceControl   `json:"controls"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ComplianceControl represents a compliance control
type ComplianceControl struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Category       string                 `json:"category"`
	Requirements   []string               `json:"requirements"`
	TestProcedures []string               `json:"test_procedures"`
	Severity       string                 `json:"severity"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// ComplianceConfig configuration for compliance checker
type ComplianceConfig struct {
	EnabledFrameworks   []string `json:"enabled_frameworks"`
	StrictMode          bool     `json:"strict_mode"`
	AutoRemediation     bool     `json:"auto_remediation"`
	ComplianceThreshold float64  `json:"compliance_threshold"`
}

// RiskAnalyzer analyzes security risks
type RiskAnalyzer struct {
	logger     *logger.Logger
	riskModels map[string]*RiskModel
	config     *RiskAnalyzerConfig
}

// RiskModel represents a risk analysis model
type RiskModel struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Algorithm   string                 `json:"algorithm"`
	Parameters  map[string]interface{} `json:"parameters"`
	Weights     map[string]float64     `json:"weights"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RiskAnalyzerConfig configuration for risk analyzer
type RiskAnalyzerConfig struct {
	DefaultModel        string  `json:"default_model"`
	EnablePredictive    bool    `json:"enable_predictive"`
	RiskThreshold       float64 `json:"risk_threshold"`
	EnableTrendAnalysis bool    `json:"enable_trend_analysis"`
}

// ReportAggregator aggregates assessment reports
type ReportAggregator struct {
	logger    *logger.Logger
	templates map[string]*ReportTemplate
	config    *AggregatorConfig
}

// AggregatorConfig configuration for report aggregator
type AggregatorConfig struct {
	DefaultFormat     string        `json:"default_format"`
	EnableAggregation bool          `json:"enable_aggregation"`
	AggregationPeriod time.Duration `json:"aggregation_period"`
	IncludeHistorical bool          `json:"include_historical"`
	MaxReportSize     int           `json:"max_report_size"`
}

// NewAutomatedAssessmentEngine creates a new automated assessment engine
func NewAutomatedAssessmentEngine(config *AssessmentConfig, logger *logger.Logger) *AutomatedAssessmentEngine {
	if config == nil {
		config = DefaultAssessmentConfig()
	}

	engine := &AutomatedAssessmentEngine{
		logger:            logger,
		config:            config,
		activeAssessments: make(map[string]*Assessment),
	}

	// Initialize components
	engine.assessmentScheduler = NewAssessmentScheduler(logger)
	engine.complianceChecker = NewComplianceChecker(logger)
	engine.riskAnalyzer = NewRiskAnalyzer(logger)
	engine.reportAggregator = NewReportAggregator(logger)

	return engine
}

// DefaultAssessmentConfig returns default assessment configuration
func DefaultAssessmentConfig() *AssessmentConfig {
	return &AssessmentConfig{
		EnableScheduledAssessments: true,
		EnableContinuousMonitoring: true,
		DefaultAssessmentInterval:  24 * time.Hour,
		MaxConcurrentAssessments:   5,
		EnableRiskScoring:          true,
		EnableComplianceChecking:   true,
		NotificationChannels:       []string{"email", "slack"},
		RetentionPeriod:            90 * 24 * time.Hour,
	}
}

// StartAssessment starts a new security assessment
func (aae *AutomatedAssessmentEngine) StartAssessment(ctx context.Context, target *AssessmentTarget, assessmentType string, createdBy string) (*Assessment, error) {
	aae.mu.Lock()
	defer aae.mu.Unlock()

	// Check concurrent assessment limit
	if len(aae.activeAssessments) >= aae.config.MaxConcurrentAssessments {
		return nil, fmt.Errorf("maximum concurrent assessments limit reached")
	}

	assessment := &Assessment{
		ID:          uuid.New().String(),
		Name:        fmt.Sprintf("%s Assessment of %s", assessmentType, target.Name),
		Description: fmt.Sprintf("Automated %s security assessment", assessmentType),
		Type:        assessmentType,
		Target:      target,
		Status:      "running",
		StartTime:   time.Now(),
		Progress:    0.0,
		Results:     &AssessmentResults{},
		CreatedBy:   createdBy,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	aae.activeAssessments[assessment.ID] = assessment

	// Start assessment in background
	go aae.executeAssessment(ctx, assessment)

	aae.logger.WithFields(map[string]interface{}{
		"assessment_id": assessment.ID,
		"target":        target.Name,
		"type":          assessmentType,
		"created_by":    createdBy,
	}).Info("Security assessment started")

	return assessment, nil
}

// executeAssessment executes a security assessment
func (aae *AutomatedAssessmentEngine) executeAssessment(ctx context.Context, assessment *Assessment) {
	defer func() {
		aae.mu.Lock()
		endTime := time.Now()
		assessment.EndTime = &endTime
		assessment.Status = "completed"
		assessment.Progress = 100.0
		assessment.UpdatedAt = time.Now()
		aae.mu.Unlock()

		// Generate notifications
		aae.generateAssessmentNotifications(assessment)
	}()

	// Phase 1: Security Scanning
	aae.logger.Info("Starting security scanning phase")
	securityFindings := aae.performSecurityScan(ctx, assessment.Target)
	assessment.Results.SecurityFindings = securityFindings
	assessment.Progress = 25.0

	// Phase 2: Compliance Checking
	if aae.config.EnableComplianceChecking {
		aae.logger.Info("Starting compliance checking phase")
		complianceFindings := aae.complianceChecker.CheckCompliance(ctx, assessment.Target)
		assessment.Results.ComplianceFindings = complianceFindings
		assessment.Results.ComplianceScore = aae.calculateComplianceScore(complianceFindings)
	}
	assessment.Progress = 50.0

	// Phase 3: Risk Analysis
	if aae.config.EnableRiskScoring {
		aae.logger.Info("Starting risk analysis phase")
		riskAssessment := aae.riskAnalyzer.AnalyzeRisk(ctx, assessment.Target, securityFindings)
		assessment.Results.RiskAssessment = riskAssessment
		assessment.Results.RiskLevel = riskAssessment.OverallRisk
	}
	assessment.Progress = 75.0

	// Phase 4: Generate Final Results
	aae.logger.Info("Generating final assessment results")
	aae.finalizeAssessmentResults(assessment)
	assessment.Progress = 100.0
}

// performSecurityScan performs security scanning
func (aae *AutomatedAssessmentEngine) performSecurityScan(ctx context.Context, target *AssessmentTarget) []*SecurityFinding {
	var findings []*SecurityFinding

	// Simulate security findings based on target type
	switch target.Type {
	case "ai_model":
		findings = append(findings, aae.generateAIModelFindings(target)...)
	case "web_application":
		findings = append(findings, aae.generateWebAppFindings(target)...)
	case "api":
		findings = append(findings, aae.generateAPIFindings(target)...)
	default:
		findings = append(findings, aae.generateGenericFindings(target)...)
	}

	return findings
}

// generateAIModelFindings generates findings specific to AI models
func (aae *AutomatedAssessmentEngine) generateAIModelFindings(target *AssessmentTarget) []*SecurityFinding {
	return []*SecurityFinding{
		{
			ID:          uuid.New().String(),
			Title:       "Prompt Injection Vulnerability",
			Description: "AI model may be susceptible to prompt injection attacks",
			Severity:    "high",
			Category:    "injection",
			CVSS:        7.5,
			CWE:         "CWE-77",
			OWASP:       "LLM01",
			Impact:      "Unauthorized access to system functions",
			Likelihood:  "medium",
			Evidence: []Evidence{
				{
					Type:      "scan_result",
					Source:    "ai_security_scanner",
					Data:      "No input validation detected",
					Timestamp: time.Now(),
				},
			},
			Recommendations: []string{
				"Implement input validation and sanitization",
				"Use prompt templates with parameter binding",
				"Deploy prompt injection detection filters",
			},
			Status:       "open",
			DiscoveredAt: time.Now(),
		},
		{
			ID:          uuid.New().String(),
			Title:       "Data Exposure Risk",
			Description: "AI model may expose sensitive training data",
			Severity:    "medium",
			Category:    "data_exposure",
			CVSS:        6.5,
			CWE:         "CWE-200",
			OWASP:       "LLM02",
			Impact:      "Sensitive data disclosure",
			Likelihood:  "low",
			Evidence: []Evidence{
				{
					Type:      "scan_result",
					Source:    "data_privacy_scanner",
					Data:      "Model outputs may contain training data",
					Timestamp: time.Now(),
				},
			},
			Recommendations: []string{
				"Implement differential privacy",
				"Add output filtering mechanisms",
				"Monitor for data leakage patterns",
			},
			Status:       "open",
			DiscoveredAt: time.Now(),
		},
	}
}

// generateWebAppFindings generates findings for web applications
func (aae *AutomatedAssessmentEngine) generateWebAppFindings(target *AssessmentTarget) []*SecurityFinding {
	return []*SecurityFinding{
		{
			ID:          uuid.New().String(),
			Title:       "Cross-Site Scripting (XSS)",
			Description: "Application may be vulnerable to XSS attacks",
			Severity:    "medium",
			Category:    "injection",
			CVSS:        6.1,
			CWE:         "CWE-79",
			OWASP:       "A03",
			Impact:      "Session hijacking, data theft",
			Likelihood:  "medium",
			Evidence: []Evidence{
				{
					Type:      "scan_result",
					Source:    "web_scanner",
					Data:      "Unescaped user input detected",
					Timestamp: time.Now(),
				},
			},
			Recommendations: []string{
				"Implement output encoding",
				"Use Content Security Policy",
				"Validate and sanitize all inputs",
			},
			Status:       "open",
			DiscoveredAt: time.Now(),
		},
	}
}

// generateAPIFindings generates findings for APIs
func (aae *AutomatedAssessmentEngine) generateAPIFindings(target *AssessmentTarget) []*SecurityFinding {
	return []*SecurityFinding{
		{
			ID:          uuid.New().String(),
			Title:       "Broken Authentication",
			Description: "API authentication mechanisms may be insufficient",
			Severity:    "high",
			Category:    "authentication",
			CVSS:        8.1,
			CWE:         "CWE-287",
			OWASP:       "API2",
			Impact:      "Unauthorized access to API resources",
			Likelihood:  "high",
			Evidence: []Evidence{
				{
					Type:      "scan_result",
					Source:    "api_scanner",
					Data:      "Weak authentication detected",
					Timestamp: time.Now(),
				},
			},
			Recommendations: []string{
				"Implement strong authentication mechanisms",
				"Use OAuth 2.0 or similar standards",
				"Implement rate limiting",
			},
			Status:       "open",
			DiscoveredAt: time.Now(),
		},
	}
}

// generateGenericFindings generates generic security findings
func (aae *AutomatedAssessmentEngine) generateGenericFindings(target *AssessmentTarget) []*SecurityFinding {
	return []*SecurityFinding{
		{
			ID:          uuid.New().String(),
			Title:       "Security Configuration Issue",
			Description: "Security configuration may not follow best practices",
			Severity:    "low",
			Category:    "configuration",
			CVSS:        3.1,
			CWE:         "CWE-16",
			OWASP:       "A05",
			Impact:      "Potential security weakness",
			Likelihood:  "low",
			Evidence: []Evidence{
				{
					Type:      "scan_result",
					Source:    "config_scanner",
					Data:      "Default configuration detected",
					Timestamp: time.Now(),
				},
			},
			Recommendations: []string{
				"Review and harden security configuration",
				"Follow security best practices",
				"Regular security audits",
			},
			Status:       "open",
			DiscoveredAt: time.Now(),
		},
	}
}

// calculateComplianceScore calculates compliance score from findings
func (aae *AutomatedAssessmentEngine) calculateComplianceScore(findings []*ComplianceFinding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	compliantCount := 0
	for _, finding := range findings {
		if finding.Status == "compliant" {
			compliantCount++
		}
	}

	return float64(compliantCount) / float64(len(findings)) * 100.0
}

// finalizeAssessmentResults finalizes assessment results
func (aae *AutomatedAssessmentEngine) finalizeAssessmentResults(assessment *Assessment) {
	results := assessment.Results

	// Count vulnerabilities by severity
	for _, finding := range results.SecurityFindings {
		results.VulnerabilityCount++
		switch finding.Severity {
		case "critical":
			results.CriticalIssues++
		case "high":
			results.HighIssues++
		case "medium":
			results.MediumIssues++
		case "low":
			results.LowIssues++
		}
	}

	// Calculate overall score
	results.OverallScore = aae.calculateOverallScore(results)

	// Generate recommendations
	results.Recommendations = aae.generateAssessmentRecommendations(results)

	// Generate trend analysis
	results.TrendAnalysis = aae.generateTrendAnalysis(assessment)
}

// calculateOverallScore calculates overall assessment score
func (aae *AutomatedAssessmentEngine) calculateOverallScore(results *AssessmentResults) float64 {
	// Simple scoring algorithm
	baseScore := 100.0

	// Deduct points for vulnerabilities
	baseScore -= float64(results.CriticalIssues) * 20.0
	baseScore -= float64(results.HighIssues) * 10.0
	baseScore -= float64(results.MediumIssues) * 5.0
	baseScore -= float64(results.LowIssues) * 1.0

	// Factor in compliance score
	if results.ComplianceScore > 0 {
		baseScore = (baseScore + results.ComplianceScore) / 2.0
	}

	// Ensure score is between 0 and 100
	if baseScore < 0 {
		baseScore = 0
	}
	if baseScore > 100 {
		baseScore = 100
	}

	return baseScore
}

// generateAssessmentNotifications generates notifications for assessment completion
func (aae *AutomatedAssessmentEngine) generateAssessmentNotifications(assessment *Assessment) {
	notifications := []*Notification{}

	// Generate notification based on critical findings
	if assessment.Results.CriticalIssues > 0 {
		notification := &Notification{
			ID:         uuid.New().String(),
			Type:       "security_alert",
			Severity:   "critical",
			Title:      "Critical Security Issues Detected",
			Message:    fmt.Sprintf("Assessment found %d critical security issues requiring immediate attention", assessment.Results.CriticalIssues),
			Recipients: []string{"security-team@company.com"},
			Channels:   aae.config.NotificationChannels,
			Status:     "pending",
			CreatedAt:  time.Now(),
		}
		notifications = append(notifications, notification)
	}

	// Generate notification for assessment completion
	completionNotification := &Notification{
		ID:         uuid.New().String(),
		Type:       "assessment_complete",
		Severity:   "info",
		Title:      "Security Assessment Completed",
		Message:    fmt.Sprintf("Assessment '%s' completed with overall score: %.1f", assessment.Name, assessment.Results.OverallScore),
		Recipients: []string{"security-team@company.com"},
		Channels:   aae.config.NotificationChannels,
		Status:     "pending",
		CreatedAt:  time.Now(),
	}
	notifications = append(notifications, completionNotification)

	assessment.Notifications = notifications

	// In a real implementation, notifications would be sent here
	aae.logger.WithFields(map[string]interface{}{
		"assessment_id":   assessment.ID,
		"notifications":   len(notifications),
		"critical_issues": assessment.Results.CriticalIssues,
	}).Info("Assessment notifications generated")
}

// generateAssessmentRecommendations generates recommendations from assessment results
func (aae *AutomatedAssessmentEngine) generateAssessmentRecommendations(results *AssessmentResults) []string {
	var recommendations []string
	recommendationSet := make(map[string]bool)

	// Collect recommendations from security findings
	for _, finding := range results.SecurityFindings {
		for _, rec := range finding.Recommendations {
			if !recommendationSet[rec] {
				recommendations = append(recommendations, rec)
				recommendationSet[rec] = true
			}
		}
	}

	// Collect recommendations from compliance findings
	for _, finding := range results.ComplianceFindings {
		for _, rec := range finding.Recommendations {
			if !recommendationSet[rec] {
				recommendations = append(recommendations, rec)
				recommendationSet[rec] = true
			}
		}
	}

	// Add general recommendations based on risk level
	if results.RiskAssessment != nil {
		for _, strategy := range results.RiskAssessment.MitigationStrategies {
			if !recommendationSet[strategy] {
				recommendations = append(recommendations, strategy)
				recommendationSet[strategy] = true
			}
		}
	}

	// Add priority recommendations based on critical issues
	if results.CriticalIssues > 0 {
		recommendations = append([]string{"Immediate remediation required for critical vulnerabilities"}, recommendations...)
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Continue regular security monitoring")
		recommendations = append(recommendations, "Maintain current security posture")
	}

	return recommendations
}

// generateTrendAnalysis generates trend analysis
func (aae *AutomatedAssessmentEngine) generateTrendAnalysis(assessment *Assessment) *TrendAnalysis {
	// In a real implementation, this would analyze historical data
	return &TrendAnalysis{
		Period:             "30_days",
		SecurityTrend:      "stable",
		ComplianceTrend:    "improving",
		VulnerabilityTrend: "decreasing",
		RiskTrend:          "stable",
		Metrics: map[string]float64{
			"security_score":      assessment.Results.OverallScore,
			"compliance_score":    assessment.Results.ComplianceScore,
			"vulnerability_count": float64(assessment.Results.VulnerabilityCount),
		},
		Predictions: map[string]float64{
			"next_month_risk":   5.0,
			"compliance_target": 90.0,
		},
		Metadata: make(map[string]interface{}),
	}
}

// GetActiveAssessments returns all active assessments
func (aae *AutomatedAssessmentEngine) GetActiveAssessments() []*Assessment {
	aae.mu.RLock()
	defer aae.mu.RUnlock()

	assessments := make([]*Assessment, 0, len(aae.activeAssessments))
	for _, assessment := range aae.activeAssessments {
		assessments = append(assessments, assessment)
	}
	return assessments
}

// GetAssessment returns a specific assessment by ID
func (aae *AutomatedAssessmentEngine) GetAssessment(assessmentID string) (*Assessment, error) {
	aae.mu.RLock()
	defer aae.mu.RUnlock()

	assessment, exists := aae.activeAssessments[assessmentID]
	if !exists {
		return nil, fmt.Errorf("assessment not found: %s", assessmentID)
	}
	return assessment, nil
}
