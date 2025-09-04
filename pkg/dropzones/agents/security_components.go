package agents

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/dropzones"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// ThreatDetector detects security threats in data
type ThreatDetector struct {
	logger         *logger.Logger
	threatPatterns map[string]*regexp.Regexp
	signatures     []ThreatSignature
}

// ThreatSignature represents a threat signature
type ThreatSignature struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Pattern     string  `json:"pattern"`
	Severity    string  `json:"severity"`
	Category    string  `json:"category"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// NewThreatDetector creates a new threat detector
func NewThreatDetector(logger *logger.Logger) *ThreatDetector {
	td := &ThreatDetector{
		logger:         logger,
		threatPatterns: make(map[string]*regexp.Regexp),
		signatures:     make([]ThreatSignature, 0),
	}

	// Initialize with common threat signatures
	td.initializeThreatSignatures()
	return td
}

// initializeThreatSignatures initializes common threat signatures
func (td *ThreatDetector) initializeThreatSignatures() {
	signatures := []ThreatSignature{
		{
			ID:          "sql_injection_1",
			Name:        "SQL Injection Pattern",
			Pattern:     `(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from|update\s+set)`,
			Severity:    "high",
			Category:    "injection",
			Confidence:  0.8,
			Description: "Potential SQL injection attack pattern",
		},
		{
			ID:          "xss_1",
			Name:        "Cross-Site Scripting",
			Pattern:     `(?i)(<script|javascript:|onload=|onerror=|onclick=)`,
			Severity:    "medium",
			Category:    "xss",
			Confidence:  0.7,
			Description: "Potential XSS attack pattern",
		},
		{
			ID:          "command_injection_1",
			Name:        "Command Injection",
			Pattern:     `(?i)(;|\||\&\&|\|\|)\s*(rm|del|format|shutdown|reboot|cat|type|dir)`,
			Severity:    "critical",
			Category:    "injection",
			Confidence:  0.9,
			Description: "Potential command injection pattern",
		},
		{
			ID:          "malware_signature_1",
			Name:        "Malware Signature",
			Pattern:     `(?i)(trojan|backdoor|keylogger|rootkit|botnet)`,
			Severity:    "critical",
			Category:    "malware",
			Confidence:  0.6,
			Description: "Potential malware signature",
		},
		{
			ID:          "phishing_1",
			Name:        "Phishing Pattern",
			Pattern:     `(?i)(verify\s+account|suspended\s+account|click\s+here\s+immediately|urgent\s+action\s+required)`,
			Severity:    "medium",
			Category:    "phishing",
			Confidence:  0.5,
			Description: "Potential phishing content",
		},
	}

	for _, sig := range signatures {
		if pattern, err := regexp.Compile(sig.Pattern); err == nil {
			td.threatPatterns[sig.ID] = pattern
			td.signatures = append(td.signatures, sig)
		} else {
			td.logger.Warn("Failed to compile threat pattern", "signature_id", sig.ID, "error", err)
		}
	}

	td.logger.Info("Initialized threat signatures", "count", len(td.signatures))
}

// DetectThreats detects threats in the provided data
func (td *ThreatDetector) DetectThreats(ctx context.Context, data *dropzones.DropZoneData) ([]interface{}, error) {
	threats := make([]interface{}, 0)
	content := string(data.Content)

	for _, signature := range td.signatures {
		if pattern, exists := td.threatPatterns[signature.ID]; exists {
			if matches := pattern.FindAllString(content, -1); len(matches) > 0 {
				threat := map[string]interface{}{
					"signature_id":  signature.ID,
					"name":          signature.Name,
					"severity":      signature.Severity,
					"category":      signature.Category,
					"confidence":    signature.Confidence,
					"description":   signature.Description,
					"matches":       matches,
					"match_count":   len(matches),
					"detected_at":   time.Now(),
				}
				threats = append(threats, threat)
			}
		}
	}

	return threats, nil
}

// VulnerabilityScanner scans for vulnerabilities
type VulnerabilityScanner struct {
	logger           *logger.Logger
	vulnerabilityDB  []VulnerabilityDefinition
	scanners         map[string]VulnerabilityScanner
}

// VulnerabilityDefinition represents a vulnerability definition
type VulnerabilityDefinition struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	CVSS        float64  `json:"cvss"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	References  []string `json:"references"`
	Patterns    []string `json:"patterns"`
}

// NewVulnerabilityScanner creates a new vulnerability scanner
func NewVulnerabilityScanner(logger *logger.Logger) *VulnerabilityScanner {
	vs := &VulnerabilityScanner{
		logger:          logger,
		vulnerabilityDB: make([]VulnerabilityDefinition, 0),
		scanners:        make(map[string]VulnerabilityScanner),
	}

	vs.initializeVulnerabilityDB()
	return vs
}

// initializeVulnerabilityDB initializes the vulnerability database
func (vs *VulnerabilityScanner) initializeVulnerabilityDB() {
	vulnerabilities := []VulnerabilityDefinition{
		{
			ID:          "CVE-2023-DEMO-001",
			Name:        "Insecure Direct Object Reference",
			CVSS:        7.5,
			Severity:    "high",
			Description: "Direct access to objects without proper authorization",
			References:  []string{"https://cwe.mitre.org/data/definitions/639.html"},
			Patterns:    []string{"user_id=", "account_id=", "file_id="},
		},
		{
			ID:          "CVE-2023-DEMO-002",
			Name:        "Hardcoded Credentials",
			CVSS:        9.8,
			Severity:    "critical",
			Description: "Hardcoded passwords or API keys in code",
			References:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
			Patterns:    []string{"password=", "api_key=", "secret=", "token="},
		},
		{
			ID:          "CVE-2023-DEMO-003",
			Name:        "Information Disclosure",
			CVSS:        5.3,
			Severity:    "medium",
			Description: "Sensitive information exposed in error messages or logs",
			References:  []string{"https://cwe.mitre.org/data/definitions/200.html"},
			Patterns:    []string{"stack trace", "error:", "exception:", "debug:"},
		},
	}

	vs.vulnerabilityDB = vulnerabilities
	vs.logger.Info("Initialized vulnerability database", "count", len(vulnerabilities))
}

// ScanVulnerabilities scans for vulnerabilities in the data
func (vs *VulnerabilityScanner) ScanVulnerabilities(ctx context.Context, data *dropzones.DropZoneData) ([]Vulnerability, error) {
	vulnerabilities := make([]Vulnerability, 0)
	content := strings.ToLower(string(data.Content))

	for _, vulnDef := range vs.vulnerabilityDB {
		for _, pattern := range vulnDef.Patterns {
			if strings.Contains(content, strings.ToLower(pattern)) {
				vuln := Vulnerability{
					ID:          vulnDef.ID,
					Type:        vulnDef.Name,
					Severity:    vulnDef.Severity,
					Description: vulnDef.Description,
					Location:    fmt.Sprintf("Pattern: %s", pattern),
					CVSS:        vulnDef.CVSS,
					References:  vulnDef.References,
					Metadata: map[string]interface{}{
						"pattern":     pattern,
						"detected_at": time.Now(),
						"data_type":   data.Type,
					},
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities, nil
}

// MalwareAnalyzer analyzes data for malware indicators
type MalwareAnalyzer struct {
	logger            *logger.Logger
	malwareSignatures []MalwareSignature
	iocPatterns       map[string]*regexp.Regexp
}

// MalwareSignature represents a malware signature
type MalwareSignature struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Family      string  `json:"family"`
	Type        string  `json:"type"`
	Pattern     string  `json:"pattern"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// NewMalwareAnalyzer creates a new malware analyzer
func NewMalwareAnalyzer(logger *logger.Logger) *MalwareAnalyzer {
	ma := &MalwareAnalyzer{
		logger:            logger,
		malwareSignatures: make([]MalwareSignature, 0),
		iocPatterns:       make(map[string]*regexp.Regexp),
	}

	ma.initializeMalwareSignatures()
	return ma
}

// initializeMalwareSignatures initializes malware signatures
func (ma *MalwareAnalyzer) initializeMalwareSignatures() {
	signatures := []MalwareSignature{
		{
			ID:          "MAL-001",
			Name:        "Suspicious File Extension",
			Family:      "generic",
			Type:        "file_extension",
			Pattern:     `\.(exe|scr|bat|cmd|com|pif|vbs|js)$`,
			Confidence:  0.6,
			Description: "Potentially malicious file extension",
		},
		{
			ID:          "MAL-002",
			Name:        "Suspicious URL Pattern",
			Family:      "generic",
			Type:        "url",
			Pattern:     `https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`,
			Confidence:  0.4,
			Description: "Direct IP address in URL (potential C&C)",
		},
		{
			ID:          "MAL-003",
			Name:        "Base64 Encoded Content",
			Family:      "generic",
			Type:        "encoding",
			Pattern:     `[A-Za-z0-9+/]{50,}={0,2}`,
			Confidence:  0.3,
			Description: "Large base64 encoded content (potential payload)",
		},
	}

	for _, sig := range signatures {
		if pattern, err := regexp.Compile(sig.Pattern); err == nil {
			ma.iocPatterns[sig.ID] = pattern
			ma.malwareSignatures = append(ma.malwareSignatures, sig)
		} else {
			ma.logger.Warn("Failed to compile malware pattern", "signature_id", sig.ID, "error", err)
		}
	}

	ma.logger.Info("Initialized malware signatures", "count", len(ma.malwareSignatures))
}

// AnalyzeMalware analyzes data for malware indicators
func (ma *MalwareAnalyzer) AnalyzeMalware(ctx context.Context, data *dropzones.DropZoneData) ([]MalwareIndicator, error) {
	indicators := make([]MalwareIndicator, 0)
	content := string(data.Content)

	for _, signature := range ma.malwareSignatures {
		if pattern, exists := ma.iocPatterns[signature.ID]; exists {
			if matches := pattern.FindAllString(content, -1); len(matches) > 0 {
				indicator := MalwareIndicator{
					Type:        signature.Type,
					Value:       strings.Join(matches, ", "),
					Confidence:  signature.Confidence,
					Description: signature.Description,
					Source:      signature.Name,
					Metadata: map[string]interface{}{
						"signature_id": signature.ID,
						"family":       signature.Family,
						"matches":      matches,
						"match_count":  len(matches),
						"detected_at":  time.Now(),
					},
				}
				indicators = append(indicators, indicator)
			}
		}
	}

	return indicators, nil
}

// SecurityAnalysisResult represents the analysis result
type SecurityAnalysisResult struct {
	RequestID         string                 `json:"request_id"`
	ThreatLevel       string                 `json:"threat_level"`
	ThreatScore       float64                `json:"threat_score"`
	Vulnerabilities   []Vulnerability        `json:"vulnerabilities"`
	Recommendations   []Recommendation       `json:"recommendations"`
	Compliance        ComplianceStatus       `json:"compliance"`
	Incidents         []SecurityIncident     `json:"incidents"`
	MalwareIndicators []MalwareIndicator     `json:"malware_indicators"`
	Analysis          string                 `json:"analysis"`
	Confidence        float64                `json:"confidence"`
	ProcessingTime    time.Duration          `json:"processing_time"`
	Timestamp         time.Time              `json:"timestamp"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	CVSS        float64                `json:"cvss"`
	Description string                 `json:"description"`
	Impact      string                 `json:"impact"`
	Remediation string                 `json:"remediation"`
	Location    string                 `json:"location"`
	References  []string               `json:"references"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Recommendation represents a security recommendation
type Recommendation struct {
	ID          string                 `json:"id"`
	Category    string                 `json:"category"`
	Priority    string                 `json:"priority"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Actions     []string               `json:"actions"`
	Timeline    string                 `json:"timeline"`
	Resources   []string               `json:"resources"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ComplianceStatus represents compliance assessment
type ComplianceStatus struct {
	Framework string                 `json:"framework"`
	Status    string                 `json:"status"`
	Score     float64                `json:"score"`
	Gaps      []ComplianceGap        `json:"gaps"`
	Controls  []ComplianceControl    `json:"controls"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ComplianceGap represents a compliance gap
type ComplianceGap struct {
	ID          string                 `json:"id"`
	Control     string                 `json:"control"`
	Description string                 `json:"description"`
	Impact      string                 `json:"impact"`
	Remediation string                 `json:"remediation"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ComplianceControl represents a compliance control
type ComplianceControl struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Status       string                 `json:"status"`
	Implementation string               `json:"implementation"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// SecurityIncident represents a security incident
type SecurityIncident struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Impact      string                 `json:"impact"`
	Timeline    string                 `json:"timeline"`
	Response    string                 `json:"response"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MalwareIndicator represents a malware indicator of compromise
type MalwareIndicator struct {
	Type        string                 `json:"type"`
	Value       string                 `json:"value"`
	Confidence  float64                `json:"confidence"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RiskAssessment represents a comprehensive risk assessment
type RiskAssessment struct {
	OverallRisk    string                 `json:"overall_risk"`
	RiskScore      float64                `json:"risk_score"`
	RiskFactors    []string               `json:"risk_factors"`
	Mitigations    []string               `json:"mitigations"`
	BusinessImpact string                 `json:"business_impact"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// RiskAssessor assesses overall risk
type RiskAssessor struct {
	logger *logger.Logger
}

// NewRiskAssessor creates a new risk assessor
func NewRiskAssessor(logger *logger.Logger) *RiskAssessor {
	return &RiskAssessor{
		logger: logger,
	}
}

// AssessRisk assesses the overall risk based on analysis results
func (ra *RiskAssessor) AssessRisk(ctx context.Context, data *dropzones.DropZoneData, analysis *SecurityAnalysisResult) (*RiskAssessment, error) {
	assessment := &RiskAssessment{
		OverallRisk:    "low",
		RiskScore:      0.0,
		RiskFactors:    make([]string, 0),
		Mitigations:    make([]string, 0),
		BusinessImpact: "minimal",
		Metadata:       make(map[string]interface{}),
	}

	// Calculate risk score based on various factors
	riskScore := 0.0

	// Threat level contribution
	switch analysis.ThreatLevel {
	case "critical":
		riskScore += 0.4
		assessment.RiskFactors = append(assessment.RiskFactors, "Critical threat level detected")
	case "high":
		riskScore += 0.3
		assessment.RiskFactors = append(assessment.RiskFactors, "High threat level detected")
	case "medium":
		riskScore += 0.2
		assessment.RiskFactors = append(assessment.RiskFactors, "Medium threat level detected")
	}

	// Vulnerability contribution
	criticalVulns := 0
	highVulns := 0
	for _, vuln := range analysis.Vulnerabilities {
		switch vuln.Severity {
		case "critical":
			criticalVulns++
			riskScore += 0.15
		case "high":
			highVulns++
			riskScore += 0.1
		}
	}

	if criticalVulns > 0 {
		assessment.RiskFactors = append(assessment.RiskFactors, 
			fmt.Sprintf("%d critical vulnerabilities", criticalVulns))
	}
	if highVulns > 0 {
		assessment.RiskFactors = append(assessment.RiskFactors, 
			fmt.Sprintf("%d high-severity vulnerabilities", highVulns))
	}

	// Malware indicators contribution
	if len(analysis.MalwareIndicators) > 0 {
		riskScore += 0.2
		assessment.RiskFactors = append(assessment.RiskFactors, 
			fmt.Sprintf("%d malware indicators", len(analysis.MalwareIndicators)))
	}

	// Data sensitivity (based on type and content)
	if ra.isSensitiveData(data) {
		riskScore += 0.1
		assessment.RiskFactors = append(assessment.RiskFactors, "Sensitive data detected")
	}

	// Cap risk score
	if riskScore > 1.0 {
		riskScore = 1.0
	}

	assessment.RiskScore = riskScore

	// Determine overall risk level
	switch {
	case riskScore >= 0.8:
		assessment.OverallRisk = "critical"
		assessment.BusinessImpact = "severe"
	case riskScore >= 0.6:
		assessment.OverallRisk = "high"
		assessment.BusinessImpact = "significant"
	case riskScore >= 0.4:
		assessment.OverallRisk = "medium"
		assessment.BusinessImpact = "moderate"
	default:
		assessment.OverallRisk = "low"
		assessment.BusinessImpact = "minimal"
	}

	// Generate mitigations
	assessment.Mitigations = ra.generateMitigations(assessment, analysis)

	return assessment, nil
}

// isSensitiveData checks if the data contains sensitive information
func (ra *RiskAssessor) isSensitiveData(data *dropzones.DropZoneData) bool {
	content := strings.ToLower(string(data.Content))
	
	sensitivePatterns := []string{
		"password", "secret", "key", "token", "credential",
		"ssn", "social security", "credit card", "bank account",
		"personal", "confidential", "private",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}

	return false
}

// generateMitigations generates risk mitigation recommendations
func (ra *RiskAssessor) generateMitigations(assessment *RiskAssessment, analysis *SecurityAnalysisResult) []string {
	mitigations := make([]string, 0)

	if assessment.OverallRisk == "critical" || assessment.OverallRisk == "high" {
		mitigations = append(mitigations, "Immediate isolation and containment")
		mitigations = append(mitigations, "Escalate to security team")
		mitigations = append(mitigations, "Conduct thorough investigation")
	}

	if len(analysis.Vulnerabilities) > 0 {
		mitigations = append(mitigations, "Apply security patches")
		mitigations = append(mitigations, "Implement additional access controls")
	}

	if len(analysis.MalwareIndicators) > 0 {
		mitigations = append(mitigations, "Run comprehensive malware scan")
		mitigations = append(mitigations, "Update antivirus signatures")
	}

	if analysis.ThreatScore >= 0.7 {
		mitigations = append(mitigations, "Implement enhanced monitoring")
		mitigations = append(mitigations, "Review and update security policies")
	}

	if len(mitigations) == 0 {
		mitigations = append(mitigations, "Continue regular monitoring")
	}

	return mitigations
}
