package security

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// NewAssessmentScheduler creates a new assessment scheduler
func NewAssessmentScheduler(logger *logger.Logger) *AssessmentScheduler {
	return &AssessmentScheduler{
		logger:    logger,
		schedules: make(map[string]*AssessmentSchedule),
		config: &SchedulerConfig{
			EnableScheduling:  true,
			CheckInterval:     1 * time.Minute,
			MaxConcurrentRuns: 3,
			DefaultRetries:    3,
			DefaultRetryDelay: 5 * time.Minute,
		},
	}
}

// NewComplianceChecker creates a new compliance checker
func NewComplianceChecker(logger *logger.Logger) *ComplianceChecker {
	checker := &ComplianceChecker{
		logger:     logger,
		frameworks: make(map[string]*ComplianceFramework),
		config: &ComplianceConfig{
			EnabledFrameworks:   []string{"OWASP", "NIST", "ISO27001"},
			StrictMode:          false,
			AutoRemediation:     false,
			ComplianceThreshold: 0.8,
		},
	}

	checker.loadDefaultFrameworks()
	return checker
}

// CheckCompliance checks compliance against configured frameworks
func (cc *ComplianceChecker) CheckCompliance(ctx context.Context, target *AssessmentTarget) []*ComplianceFinding {
	var findings []*ComplianceFinding

	for _, frameworkID := range cc.config.EnabledFrameworks {
		framework, exists := cc.frameworks[frameworkID]
		if !exists {
			continue
		}

		frameworkFindings := cc.checkFrameworkCompliance(framework, target)
		findings = append(findings, frameworkFindings...)
	}

	return findings
}

// checkFrameworkCompliance checks compliance against a specific framework
func (cc *ComplianceChecker) checkFrameworkCompliance(framework *ComplianceFramework, target *AssessmentTarget) []*ComplianceFinding {
	var findings []*ComplianceFinding

	for _, control := range framework.Controls {
		finding := &ComplianceFinding{
			ID:          uuid.New().String(),
			Framework:   framework.Name,
			Control:     control.ID,
			Requirement: control.Name,
			Status:      cc.evaluateControl(control, target),
			Severity:    control.Severity,
			Description: control.Description,
			Evidence: []Evidence{
				{
					Type:      "compliance_check",
					Source:    "compliance_checker",
					Data:      fmt.Sprintf("Evaluated control %s", control.ID),
					Timestamp: time.Now(),
				},
			},
			Recommendations: []string{
				fmt.Sprintf("Ensure compliance with %s", control.Name),
				"Review implementation against requirements",
			},
			AssessedAt: time.Now(),
		}
		findings = append(findings, finding)
	}

	return findings
}

// evaluateControl evaluates a compliance control
func (cc *ComplianceChecker) evaluateControl(control *ComplianceControl, target *AssessmentTarget) string {
	// Simulate compliance evaluation
	// In a real implementation, this would perform actual compliance checks

	switch control.Category {
	case "access_control":
		if target.Credentials != nil {
			return "compliant"
		}
		return "non_compliant"
	case "data_protection":
		return "partially_compliant"
	case "security_monitoring":
		return "compliant"
	default:
		return "not_assessed"
	}
}

// loadDefaultFrameworks loads default compliance frameworks
func (cc *ComplianceChecker) loadDefaultFrameworks() {
	frameworks := []*ComplianceFramework{
		{
			ID:          "owasp_top10",
			Name:        "OWASP Top 10",
			Version:     "2021",
			Description: "OWASP Top 10 Web Application Security Risks",
			Controls: []*ComplianceControl{
				{
					ID:          "A01",
					Name:        "Broken Access Control",
					Description: "Access control enforces policy",
					Category:    "access_control",
					Requirements: []string{
						"Implement proper access controls",
						"Validate user permissions",
					},
					Severity: "high",
				},
				{
					ID:          "A02",
					Name:        "Cryptographic Failures",
					Description: "Protect data in transit and at rest",
					Category:    "data_protection",
					Requirements: []string{
						"Use strong encryption",
						"Protect sensitive data",
					},
					Severity: "high",
				},
			},
		},
		{
			ID:          "nist_csf",
			Name:        "NIST Cybersecurity Framework",
			Version:     "1.1",
			Description: "NIST Cybersecurity Framework",
			Controls: []*ComplianceControl{
				{
					ID:          "ID.AM",
					Name:        "Asset Management",
					Description: "Identify and manage assets",
					Category:    "asset_management",
					Requirements: []string{
						"Maintain asset inventory",
						"Classify assets by criticality",
					},
					Severity: "medium",
				},
				{
					ID:          "DE.CM",
					Name:        "Security Continuous Monitoring",
					Description: "Monitor security events",
					Category:    "security_monitoring",
					Requirements: []string{
						"Implement continuous monitoring",
						"Detect security events",
					},
					Severity: "medium",
				},
			},
		},
	}

	for _, framework := range frameworks {
		cc.frameworks[framework.ID] = framework
	}
}

// NewRiskAnalyzer creates a new risk analyzer
func NewRiskAnalyzer(logger *logger.Logger) *RiskAnalyzer {
	analyzer := &RiskAnalyzer{
		logger:     logger,
		riskModels: make(map[string]*RiskModel),
		config: &RiskAnalyzerConfig{
			DefaultModel:        "cvss_v3",
			EnablePredictive:    true,
			RiskThreshold:       7.0,
			EnableTrendAnalysis: true,
		},
	}

	analyzer.loadDefaultRiskModels()
	return analyzer
}

// AnalyzeRisk analyzes risk based on security findings
func (ra *RiskAnalyzer) AnalyzeRisk(ctx context.Context, target *AssessmentTarget, findings []*SecurityFinding) *RiskAssessmentResult {
	result := &RiskAssessmentResult{
		RiskFactors:          []*RiskFactor{},
		MitigationStrategies: []string{},
		Metadata:             make(map[string]interface{}),
	}

	// Calculate risk score based on findings
	totalRisk := 0.0
	criticalCount := 0
	highCount := 0

	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			criticalCount++
			totalRisk += 9.0
		case "high":
			highCount++
			totalRisk += 7.0
		case "medium":
			totalRisk += 5.0
		case "low":
			totalRisk += 2.0
		}

		// Create risk factor
		riskFactor := &RiskFactor{
			ID:          uuid.New().String(),
			Name:        finding.Title,
			Description: finding.Description,
			Category:    ra.mapCategoryToRiskCategory(finding.Category),
			Probability: ra.calculateLikelihood(finding) / 10.0, // Convert to 0-1 scale
			Impact:      finding.CVSS,
			Severity:    ra.mapSeverityToRiskSeverity(finding.Severity),
			Metadata:    make(map[string]interface{}),
		}
		result.RiskFactors = append(result.RiskFactors, riskFactor)
	}

	// Calculate overall risk
	if len(findings) > 0 {
		result.RiskScore = totalRisk / float64(len(findings))
	}

	// Determine risk level
	result.OverallRisk = ra.determineRiskLevel(result.RiskScore)
	result.BusinessImpact = ra.assessBusinessImpact(criticalCount, highCount)
	result.TechnicalImpact = ra.assessTechnicalImpact(findings)
	result.RiskTrend = "stable" // Would be calculated from historical data
	result.MitigationStrategies = ra.generateMitigationStrategies(findings)

	return result
}

// calculateLikelihood calculates likelihood based on finding characteristics
func (ra *RiskAnalyzer) calculateLikelihood(finding *SecurityFinding) float64 {
	// Simple likelihood calculation based on category and evidence
	switch finding.Category {
	case "injection":
		return 8.0
	case "authentication":
		return 7.0
	case "data_exposure":
		return 6.0
	case "configuration":
		return 4.0
	default:
		return 5.0
	}
}

// mapCategoryToRiskCategory maps finding category to RiskCategory
func (ra *RiskAnalyzer) mapCategoryToRiskCategory(category string) RiskCategory {
	switch category {
	case "injection", "authentication", "authorization", "cryptography":
		return RiskCategoryTechnical
	case "configuration", "deployment":
		return RiskCategoryOperational
	case "monitoring", "logging":
		return RiskCategoryDetection
	case "compliance", "privacy":
		return RiskCategoryLegal
	case "reputation", "brand":
		return RiskCategoryReputational
	case "financial", "business":
		return RiskCategoryFinancial
	default:
		return RiskCategoryTechnical
	}
}

// mapSeverityToRiskSeverity maps finding severity to RiskSeverity
func (ra *RiskAnalyzer) mapSeverityToRiskSeverity(severity string) RiskSeverity {
	switch severity {
	case "critical":
		return RiskSeverityCritical
	case "high":
		return RiskSeverityHigh
	case "medium":
		return RiskSeverityMedium
	case "low":
		return RiskSeverityLow
	default:
		return RiskSeverityMedium
	}
}

// determineRiskLevel determines risk level based on score
func (ra *RiskAnalyzer) determineRiskLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 5.0:
		return "medium"
	case score >= 3.0:
		return "low"
	default:
		return "minimal"
	}
}

// assessBusinessImpact assesses business impact
func (ra *RiskAnalyzer) assessBusinessImpact(critical, high int) string {
	if critical > 0 {
		return "severe"
	}
	if high > 2 {
		return "high"
	}
	if high > 0 {
		return "medium"
	}
	return "low"
}

// assessTechnicalImpact assesses technical impact
func (ra *RiskAnalyzer) assessTechnicalImpact(findings []*SecurityFinding) string {
	hasInjection := false
	hasDataExposure := false

	for _, finding := range findings {
		switch finding.Category {
		case "injection":
			hasInjection = true
		case "data_exposure":
			hasDataExposure = true
		}
	}

	if hasInjection && hasDataExposure {
		return "high"
	}
	if hasInjection || hasDataExposure {
		return "medium"
	}
	return "low"
}

// generateMitigationStrategies generates mitigation strategies
func (ra *RiskAnalyzer) generateMitigationStrategies(findings []*SecurityFinding) []string {
	strategies := make(map[string]bool)

	for _, finding := range findings {
		for _, rec := range finding.Recommendations {
			strategies[rec] = true
		}
	}

	var result []string
	for strategy := range strategies {
		result = append(result, strategy)
	}

	// Add general strategies
	if len(result) == 0 {
		result = append(result, "Implement security monitoring")
		result = append(result, "Regular security assessments")
	}

	return result
}

// loadDefaultRiskModels loads default risk models
func (ra *RiskAnalyzer) loadDefaultRiskModels() {
	models := []*RiskModel{
		{
			ID:          "cvss_v3",
			Name:        "CVSS v3.1",
			Description: "Common Vulnerability Scoring System v3.1",
			Algorithm:   "cvss",
			Parameters: map[string]interface{}{
				"base_score_weight":          0.6,
				"temporal_score_weight":      0.2,
				"environmental_score_weight": 0.2,
			},
			Weights: map[string]float64{
				"impact":     0.6,
				"likelihood": 0.4,
			},
		},
	}

	for _, model := range models {
		ra.riskModels[model.ID] = model
	}
}

// NewReportAggregator creates a new report aggregator
func NewReportAggregator(logger *logger.Logger) *ReportAggregator {
	return &ReportAggregator{
		logger:    logger,
		templates: make(map[string]*ReportTemplate),
		config: &AggregatorConfig{
			DefaultFormat:     "json",
			EnableAggregation: true,
			AggregationPeriod: 24 * time.Hour,
			IncludeHistorical: true,
			MaxReportSize:     10000000, // 10MB
		},
	}
}
