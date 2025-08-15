package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// OWASPAITop10 implements OWASP AI Top 10 vulnerability detection and compliance
type OWASPAITop10 struct {
	logger             *logger.Logger
	vulnerabilities    map[string]*AIVulnerability
	complianceCheckers map[string]VulnerabilityChecker
	remediationEngine  *RemediationEngine
	complianceReporter *ComplianceReporter
	config             *OWASPConfig
	mu                 sync.RWMutex
}

// OWASPConfig configuration for OWASP AI Top 10 compliance
type OWASPConfig struct {
	EnableRealTimeScanning  bool          `json:"enable_real_time_scanning"`
	EnableAutoRemediation   bool          `json:"enable_auto_remediation"`
	ComplianceThreshold     float64       `json:"compliance_threshold"`
	ScanInterval            time.Duration `json:"scan_interval"`
	LogViolations           bool          `json:"log_violations"`
	EnableContinuousMonitor bool          `json:"enable_continuous_monitor"`
	AlertOnViolations       bool          `json:"alert_on_violations"`
	RemediationTimeout      time.Duration `json:"remediation_timeout"`
}

// AIVulnerability represents an OWASP AI Top 10 vulnerability
type AIVulnerability struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Category        string                 `json:"category"`
	Severity        string                 `json:"severity"`
	Impact          string                 `json:"impact"`
	Likelihood      float64                `json:"likelihood"`
	RiskScore       float64                `json:"risk_score"`
	Examples        []VulnerabilityExample `json:"examples"`
	Mitigations     []string               `json:"mitigations"`
	DetectionRules  []string               `json:"detection_rules"`
	ComplianceTests []string               `json:"compliance_tests"`
	References      []string               `json:"references"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// VulnerabilityExample represents an example of a vulnerability
type VulnerabilityExample struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Code        string                 `json:"code"`
	Platform    string                 `json:"platform"`
	Severity    string                 `json:"severity"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// VulnerabilityChecker interface for vulnerability detection
type VulnerabilityChecker interface {
	CheckVulnerability(ctx context.Context, target *ScanTarget) (*VulnerabilityResult, error)
	GetVulnerabilityID() string
	GetSeverity() string
	IsEnabled() bool
}

// ScanTarget represents a target for vulnerability scanning
type ScanTarget struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Name       string                 `json:"name"`
	URL        string                 `json:"url"`
	Data       string                 `json:"data"`
	Headers    map[string]string      `json:"headers"`
	Parameters map[string]interface{} `json:"parameters"`
	Context    map[string]interface{} `json:"context"`
	Timestamp  time.Time              `json:"timestamp"`
}

// VulnerabilityResult represents the result of vulnerability scanning
type VulnerabilityResult struct {
	ID              string                 `json:"id"`
	VulnerabilityID string                 `json:"vulnerability_id"`
	TargetID        string                 `json:"target_id"`
	Detected        bool                   `json:"detected"`
	Severity        string                 `json:"severity"`
	Confidence      float64                `json:"confidence"`
	RiskScore       float64                `json:"risk_score"`
	Evidence        []Evidence             `json:"evidence"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
	Timestamp       time.Time              `json:"timestamp"`
}

// ComplianceReport represents a compliance assessment report
type ComplianceReport struct {
	ID                   string                 `json:"id"`
	Timestamp            time.Time              `json:"timestamp"`
	OverallScore         float64                `json:"overall_score"`
	ComplianceLevel      string                 `json:"compliance_level"`
	VulnerabilityResults []*VulnerabilityResult `json:"vulnerability_results"`
	Summary              *ComplianceSummary     `json:"summary"`
	Recommendations      []string               `json:"recommendations"`
	NextScanDate         time.Time              `json:"next_scan_date"`
}

// ComplianceSummary represents a summary of compliance assessment
type ComplianceSummary struct {
	TotalChecks       int     `json:"total_checks"`
	PassedChecks      int     `json:"passed_checks"`
	FailedChecks      int     `json:"failed_checks"`
	CriticalIssues    int     `json:"critical_issues"`
	HighIssues        int     `json:"high_issues"`
	MediumIssues      int     `json:"medium_issues"`
	LowIssues         int     `json:"low_issues"`
	CompliancePercent float64 `json:"compliance_percent"`
}

// RemediationEngine handles automatic remediation of vulnerabilities
type RemediationEngine struct {
	logger             *logger.Logger
	remediationRules   map[string]*RemediationRule
	activeRemediations map[string]*ActiveRemediation
	config             *RemediationConfig
	mu                 sync.RWMutex
}

// RemediationRule represents a rule for automatic remediation
type RemediationRule struct {
	ID              string                 `json:"id"`
	VulnerabilityID string                 `json:"vulnerability_id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Action          string                 `json:"action"`
	Parameters      map[string]interface{} `json:"parameters"`
	Enabled         bool                   `json:"enabled"`
	Priority        int                    `json:"priority"`
	Timeout         time.Duration          `json:"timeout"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// ActiveRemediation represents an active remediation process
type ActiveRemediation struct {
	ID              string                 `json:"id"`
	VulnerabilityID string                 `json:"vulnerability_id"`
	RuleID          string                 `json:"rule_id"`
	Status          string                 `json:"status"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         *time.Time             `json:"end_time"`
	Progress        float64                `json:"progress"`
	Result          string                 `json:"result"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// RemediationConfig configuration for remediation engine
type RemediationConfig struct {
	EnableAutoRemediation bool          `json:"enable_auto_remediation"`
	MaxConcurrentActions  int           `json:"max_concurrent_actions"`
	DefaultTimeout        time.Duration `json:"default_timeout"`
	RequireApproval       bool          `json:"require_approval"`
	NotificationChannels  []string      `json:"notification_channels"`
}

// ComplianceReporter generates compliance reports
type ComplianceReporter struct {
	logger *logger.Logger
	config *ReporterConfig
	mu     sync.RWMutex
}

// ReporterConfig configuration for compliance reporter
type ReporterConfig struct {
	ReportFormat        string        `json:"report_format"`
	IncludeEvidence     bool          `json:"include_evidence"`
	IncludeRemediation  bool          `json:"include_remediation"`
	ReportRetention     time.Duration `json:"report_retention"`
	AutoGenerateReports bool          `json:"auto_generate_reports"`
}

// NewOWASPAITop10 creates a new OWASP AI Top 10 compliance checker
func NewOWASPAITop10(config *OWASPConfig, logger *logger.Logger) *OWASPAITop10 {
	if config == nil {
		config = DefaultOWASPConfig()
	}

	checker := &OWASPAITop10{
		logger:             logger,
		vulnerabilities:    make(map[string]*AIVulnerability),
		complianceCheckers: make(map[string]VulnerabilityChecker),
		config:             config,
	}

	// Initialize remediation engine
	remediationConfig := &RemediationConfig{
		EnableAutoRemediation: config.EnableAutoRemediation,
		MaxConcurrentActions:  5,
		DefaultTimeout:        30 * time.Minute,
		RequireApproval:       true,
	}
	checker.remediationEngine = NewRemediationEngine(remediationConfig, logger)

	// Initialize compliance reporter
	reporterConfig := &ReporterConfig{
		ReportFormat:        "json",
		IncludeEvidence:     true,
		IncludeRemediation:  true,
		ReportRetention:     30 * 24 * time.Hour,
		AutoGenerateReports: true,
	}
	checker.complianceReporter = NewComplianceReporter(reporterConfig, logger)

	// Load default vulnerabilities and checkers
	checker.loadDefaultVulnerabilities()
	checker.initializeCheckers()

	return checker
}

// DefaultOWASPConfig returns default configuration for OWASP AI Top 10
func DefaultOWASPConfig() *OWASPConfig {
	return &OWASPConfig{
		EnableRealTimeScanning:  true,
		EnableAutoRemediation:   false,
		ComplianceThreshold:     0.8,
		ScanInterval:            24 * time.Hour,
		LogViolations:           true,
		EnableContinuousMonitor: true,
		AlertOnViolations:       true,
		RemediationTimeout:      30 * time.Minute,
	}
}

// NewRemediationEngine creates a new remediation engine
func NewRemediationEngine(config *RemediationConfig, logger *logger.Logger) *RemediationEngine {
	return &RemediationEngine{
		logger:             logger,
		remediationRules:   make(map[string]*RemediationRule),
		activeRemediations: make(map[string]*ActiveRemediation),
		config:             config,
	}
}

// NewComplianceReporter creates a new compliance reporter
func NewComplianceReporter(config *ReporterConfig, logger *logger.Logger) *ComplianceReporter {
	return &ComplianceReporter{
		logger: logger,
		config: config,
	}
}

// ScanTarget performs a comprehensive vulnerability scan on a target
func (o *OWASPAITop10) ScanTarget(ctx context.Context, target *ScanTarget) (*ComplianceReport, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	report := &ComplianceReport{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
	}

	var results []*VulnerabilityResult

	// Run all enabled vulnerability checkers
	for _, checker := range o.complianceCheckers {
		if !checker.IsEnabled() {
			continue
		}

		result, err := checker.CheckVulnerability(ctx, target)
		if err != nil {
			o.logger.WithError(err).WithField("checker", checker.GetVulnerabilityID()).Error("Vulnerability check failed")
			continue
		}

		results = append(results, result)

		// Trigger auto-remediation if enabled and vulnerability detected
		if o.config.EnableAutoRemediation && result.Detected && result.Severity == "critical" {
			err := o.triggerRemediation(ctx, result)
			if err != nil {
				o.logger.WithError(err).Error("Auto-remediation failed")
			}
		}
	}

	report.VulnerabilityResults = results
	report.Summary = o.generateSummary(results)
	report.OverallScore = o.calculateOverallScore(results)
	report.ComplianceLevel = o.determineComplianceLevel(report.OverallScore)
	report.Recommendations = o.generateRecommendations(results)
	report.NextScanDate = time.Now().Add(o.config.ScanInterval)

	// Log compliance report if configured
	if o.config.LogViolations {
		o.logger.WithFields(map[string]interface{}{
			"target_id":        target.ID,
			"overall_score":    report.OverallScore,
			"compliance_level": report.ComplianceLevel,
			"violations":       report.Summary.FailedChecks,
		}).Info("Compliance scan completed")
	}

	return report, nil
}

// CheckSpecificVulnerability checks for a specific vulnerability
func (o *OWASPAITop10) CheckSpecificVulnerability(ctx context.Context, vulnerabilityID string, target *ScanTarget) (*VulnerabilityResult, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	checker, exists := o.complianceCheckers[vulnerabilityID]
	if !exists {
		return nil, fmt.Errorf("vulnerability checker %s not found", vulnerabilityID)
	}

	if !checker.IsEnabled() {
		return nil, fmt.Errorf("vulnerability checker %s is disabled", vulnerabilityID)
	}

	return checker.CheckVulnerability(ctx, target)
}

// GetVulnerabilities returns all available vulnerabilities
func (o *OWASPAITop10) GetVulnerabilities() map[string]*AIVulnerability {
	o.mu.RLock()
	defer o.mu.RUnlock()

	vulnerabilities := make(map[string]*AIVulnerability)
	for id, vuln := range o.vulnerabilities {
		vulnerabilities[id] = vuln
	}

	return vulnerabilities
}

// GetComplianceStatus returns current compliance status
func (o *OWASPAITop10) GetComplianceStatus() *ComplianceStatus {
	o.mu.RLock()
	defer o.mu.RUnlock()

	return &ComplianceStatus{
		TotalVulnerabilities:   len(o.vulnerabilities),
		EnabledCheckers:        o.countEnabledCheckers(),
		LastScanTime:           time.Now(), // In production, this would be stored
		ComplianceThreshold:    o.config.ComplianceThreshold,
		AutoRemediationEnabled: o.config.EnableAutoRemediation,
	}
}

// loadDefaultVulnerabilities loads the OWASP AI Top 10 vulnerabilities
func (o *OWASPAITop10) loadDefaultVulnerabilities() {
	vulnerabilities := []*AIVulnerability{
		{
			ID:          "LLM01",
			Name:        "Prompt Injection",
			Description: "Manipulating LLMs through crafted inputs, causing unintended actions",
			Category:    "Input Manipulation",
			Severity:    "high",
			Impact:      "Data breach, unauthorized access, system compromise",
			Likelihood:  0.8,
			RiskScore:   8.0,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "LLM02",
			Name:        "Insecure Output Handling",
			Description: "Insufficient validation of LLM outputs before downstream use",
			Category:    "Output Validation",
			Severity:    "high",
			Impact:      "XSS, CSRF, SSRF, privilege escalation",
			Likelihood:  0.7,
			RiskScore:   7.5,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "LLM03",
			Name:        "Training Data Poisoning",
			Description: "Manipulating training data to introduce vulnerabilities",
			Category:    "Data Integrity",
			Severity:    "medium",
			Impact:      "Model bias, backdoors, performance degradation",
			Likelihood:  0.4,
			RiskScore:   6.0,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "LLM04",
			Name:        "Model Denial of Service",
			Description: "Resource-heavy operations causing service degradation",
			Category:    "Availability",
			Severity:    "medium",
			Impact:      "Service disruption, increased costs",
			Likelihood:  0.6,
			RiskScore:   6.5,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "LLM05",
			Name:        "Supply Chain Vulnerabilities",
			Description: "Vulnerabilities in third-party components and datasets",
			Category:    "Supply Chain",
			Severity:    "high",
			Impact:      "Data breach, model compromise, system takeover",
			Likelihood:  0.5,
			RiskScore:   7.0,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, vuln := range vulnerabilities {
		o.vulnerabilities[vuln.ID] = vuln
	}
}

// ComplianceStatus represents current compliance status
type ComplianceStatus struct {
	TotalVulnerabilities   int       `json:"total_vulnerabilities"`
	EnabledCheckers        int       `json:"enabled_checkers"`
	LastScanTime           time.Time `json:"last_scan_time"`
	ComplianceThreshold    float64   `json:"compliance_threshold"`
	AutoRemediationEnabled bool      `json:"auto_remediation_enabled"`
}

// initializeCheckers initializes vulnerability checkers
func (o *OWASPAITop10) initializeCheckers() {
	// Initialize prompt injection checker
	o.complianceCheckers["LLM01"] = &PromptInjectionChecker{
		id:       "LLM01",
		severity: "high",
		enabled:  true,
		logger:   o.logger,
	}

	// Initialize insecure output handling checker
	o.complianceCheckers["LLM02"] = &InsecureOutputChecker{
		id:       "LLM02",
		severity: "high",
		enabled:  true,
		logger:   o.logger,
	}

	// Initialize training data poisoning checker
	o.complianceCheckers["LLM03"] = &DataPoisoningChecker{
		id:       "LLM03",
		severity: "medium",
		enabled:  true,
		logger:   o.logger,
	}

	// Initialize model DoS checker
	o.complianceCheckers["LLM04"] = &ModelDoSChecker{
		id:       "LLM04",
		severity: "medium",
		enabled:  true,
		logger:   o.logger,
	}

	// Initialize supply chain checker
	o.complianceCheckers["LLM05"] = &SupplyChainChecker{
		id:       "LLM05",
		severity: "high",
		enabled:  true,
		logger:   o.logger,
	}
}

// triggerRemediation triggers automatic remediation for a vulnerability
func (o *OWASPAITop10) triggerRemediation(ctx context.Context, result *VulnerabilityResult) error {
	return o.remediationEngine.TriggerRemediation(ctx, result)
}

// generateSummary generates a compliance summary from results
func (o *OWASPAITop10) generateSummary(results []*VulnerabilityResult) *ComplianceSummary {
	summary := &ComplianceSummary{
		TotalChecks: len(results),
	}

	for _, result := range results {
		if result.Detected {
			summary.FailedChecks++
			switch result.Severity {
			case "critical":
				summary.CriticalIssues++
			case "high":
				summary.HighIssues++
			case "medium":
				summary.MediumIssues++
			case "low":
				summary.LowIssues++
			}
		} else {
			summary.PassedChecks++
		}
	}

	if summary.TotalChecks > 0 {
		summary.CompliancePercent = float64(summary.PassedChecks) / float64(summary.TotalChecks) * 100
	}

	return summary
}

// calculateOverallScore calculates overall compliance score
func (o *OWASPAITop10) calculateOverallScore(results []*VulnerabilityResult) float64 {
	if len(results) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, result := range results {
		if !result.Detected {
			totalScore += 10.0 // Full score for passed checks
		} else {
			// Deduct points based on severity
			switch result.Severity {
			case "critical":
				totalScore += 0.0
			case "high":
				totalScore += 2.0
			case "medium":
				totalScore += 5.0
			case "low":
				totalScore += 7.0
			}
		}
	}

	return totalScore / float64(len(results))
}

// determineComplianceLevel determines compliance level based on score
func (o *OWASPAITop10) determineComplianceLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "excellent"
	case score >= 8.0:
		return "good"
	case score >= 7.0:
		return "fair"
	case score >= 6.0:
		return "poor"
	default:
		return "critical"
	}
}

// generateRecommendations generates recommendations based on results
func (o *OWASPAITop10) generateRecommendations(results []*VulnerabilityResult) []string {
	var recommendations []string

	for _, result := range results {
		if result.Detected {
			recommendations = append(recommendations, result.Recommendations...)
		}
	}

	// Add general recommendations
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Continue regular security assessments")
		recommendations = append(recommendations, "Keep security frameworks updated")
	}

	return recommendations
}

// countEnabledCheckers counts enabled vulnerability checkers
func (o *OWASPAITop10) countEnabledCheckers() int {
	count := 0
	for _, checker := range o.complianceCheckers {
		if checker.IsEnabled() {
			count++
		}
	}
	return count
}

// TriggerRemediation triggers remediation for a vulnerability result
func (re *RemediationEngine) TriggerRemediation(ctx context.Context, result *VulnerabilityResult) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	// Check if remediation rule exists for this vulnerability
	rule, exists := re.remediationRules[result.VulnerabilityID]
	if !exists {
		return fmt.Errorf("no remediation rule found for vulnerability %s", result.VulnerabilityID)
	}

	if !rule.Enabled {
		return fmt.Errorf("remediation rule %s is disabled", rule.ID)
	}

	// Create active remediation
	remediation := &ActiveRemediation{
		ID:              uuid.New().String(),
		VulnerabilityID: result.VulnerabilityID,
		RuleID:          rule.ID,
		Status:          "initiated",
		StartTime:       time.Now(),
		Progress:        0.0,
	}

	re.activeRemediations[remediation.ID] = remediation

	re.logger.WithFields(map[string]interface{}{
		"remediation_id":   remediation.ID,
		"vulnerability_id": result.VulnerabilityID,
		"rule_id":          rule.ID,
	}).Info("Remediation triggered")

	// In production, this would execute the actual remediation action
	// For now, we'll simulate success
	go func() {
		time.Sleep(5 * time.Second)
		re.mu.Lock()
		remediation.Status = "completed"
		remediation.Progress = 100.0
		endTime := time.Now()
		remediation.EndTime = &endTime
		remediation.Result = "success"
		re.mu.Unlock()
	}()

	return nil
}
