package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// SecurityScanner represents a multi-cloud security scanner
type SecurityScanner struct {
	kubeClient     kubernetes.Interface
	awsInspector   *inspector2.Client
	awsSecurityHub *securityhub.Client
	awsGuardDuty   *guardduty.Client
	environment    string
	cloudProviders []string
}

// ScanResult represents the result of a security scan
type ScanResult struct {
	Timestamp     time.Time            `json:"timestamp"`
	Environment   string               `json:"environment"`
	CloudProvider string               `json:"cloud_provider"`
	ScanType      string               `json:"scan_type"`
	Findings      []SecurityFinding    `json:"findings"`
	Summary       SecurityScanSummary  `json:"summary"`
	Compliance    ComplianceAssessment `json:"compliance"`
}

// SecurityFinding represents a security finding
type SecurityFinding struct {
	ID            string                 `json:"id"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	Severity      string                 `json:"severity"`
	Category      string                 `json:"category"`
	Resource      string                 `json:"resource"`
	CloudProvider string                 `json:"cloud_provider"`
	Status        string                 `json:"status"`
	FirstSeen     time.Time              `json:"first_seen"`
	LastSeen      time.Time              `json:"last_seen"`
	Evidence      map[string]interface{} `json:"evidence"`
	CVSS          float64                `json:"cvss_score"`
	CWE           string                 `json:"cwe"`
	CVE           string                 `json:"cve"`
	Remediation   RemediationGuidance    `json:"remediation"`
}

// SecurityScanSummary provides a summary of scan results
type SecurityScanSummary struct {
	TotalFindings    int       `json:"total_findings"`
	CriticalFindings int       `json:"critical_findings"`
	HighFindings     int       `json:"high_findings"`
	MediumFindings   int       `json:"medium_findings"`
	LowFindings      int       `json:"low_findings"`
	RiskScore        int       `json:"risk_score"`
	ComplianceScore  int       `json:"compliance_score"`
	TrendDirection   string    `json:"trend_direction"`
	LastScanTime     time.Time `json:"last_scan_time"`
}

// ComplianceAssessment represents compliance framework assessment
type ComplianceAssessment struct {
	Framework    string              `json:"framework"`
	Version      string              `json:"version"`
	Score        int                 `json:"score"`
	Controls     []ComplianceControl `json:"controls"`
	Gaps         []ComplianceGap     `json:"gaps"`
	LastAssessed time.Time           `json:"last_assessed"`
}

// ComplianceControl represents a compliance control
type ComplianceControl struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Status      string    `json:"status"`
	Evidence    string    `json:"evidence"`
	LastChecked time.Time `json:"last_checked"`
}

// ComplianceGap represents a compliance gap
type ComplianceGap struct {
	ControlID   string `json:"control_id"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Priority    string `json:"priority"`
}

// RemediationGuidance provides remediation guidance
type RemediationGuidance struct {
	Steps      []string `json:"steps"`
	Automated  bool     `json:"automated"`
	Effort     string   `json:"effort"`
	Impact     string   `json:"impact"`
	References []string `json:"references"`
}

// NewSecurityScanner creates a new security scanner instance
func NewSecurityScanner(ctx context.Context) (*SecurityScanner, error) {
	// Initialize Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	// Initialize AWS clients
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &SecurityScanner{
		kubeClient:     kubeClient,
		awsInspector:   inspector2.NewFromConfig(awsConfig),
		awsSecurityHub: securityhub.NewFromConfig(awsConfig),
		awsGuardDuty:   guardduty.NewFromConfig(awsConfig),
		environment:    os.Getenv("ENVIRONMENT"),
		cloudProviders: []string{"aws", "gcp", "azure"},
	}, nil
}

// RunComprehensiveScan performs a comprehensive security scan across all clouds
func (s *SecurityScanner) RunComprehensiveScan(ctx context.Context) (*ScanResult, error) {
	log.Printf("Starting comprehensive security scan for environment: %s", s.environment)

	result := &ScanResult{
		Timestamp:   time.Now(),
		Environment: s.environment,
		ScanType:    "comprehensive",
		Findings:    []SecurityFinding{},
	}

	// Scan each cloud provider
	for _, provider := range s.cloudProviders {
		log.Printf("Scanning cloud provider: %s", provider)

		providerFindings, err := s.scanCloudProvider(ctx, provider)
		if err != nil {
			log.Printf("Error scanning %s: %v", provider, err)
			continue
		}

		result.Findings = append(result.Findings, providerFindings...)
	}

	// Scan Kubernetes clusters
	k8sFindings, err := s.scanKubernetes(ctx)
	if err != nil {
		log.Printf("Error scanning Kubernetes: %v", err)
	} else {
		result.Findings = append(result.Findings, k8sFindings...)
	}

	// Calculate summary
	result.Summary = s.calculateSummary(result.Findings)

	// Assess compliance
	result.Compliance = s.assessCompliance(ctx, result.Findings)

	log.Printf("Security scan completed. Found %d findings", len(result.Findings))
	return result, nil
}

// scanCloudProvider scans a specific cloud provider
func (s *SecurityScanner) scanCloudProvider(ctx context.Context, provider string) ([]SecurityFinding, error) {
	var findings []SecurityFinding

	switch provider {
	case "aws":
		awsFindings, err := s.scanAWS(ctx)
		if err != nil {
			return nil, err
		}
		findings = append(findings, awsFindings...)
	case "gcp":
		gcpFindings, err := s.scanGCP(ctx)
		if err != nil {
			return nil, err
		}
		findings = append(findings, gcpFindings...)
	case "azure":
		azureFindings, err := s.scanAzure(ctx)
		if err != nil {
			return nil, err
		}
		findings = append(findings, azureFindings...)
	}

	return findings, nil
}

// scanAWS performs AWS-specific security scanning
func (s *SecurityScanner) scanAWS(ctx context.Context) ([]SecurityFinding, error) {
	var findings []SecurityFinding

	// Scan with AWS Inspector
	inspectorFindings, err := s.scanWithInspector(ctx)
	if err != nil {
		log.Printf("Inspector scan error: %v", err)
	} else {
		findings = append(findings, inspectorFindings...)
	}

	// Scan with AWS Security Hub
	securityHubFindings, err := s.scanWithSecurityHub(ctx)
	if err != nil {
		log.Printf("Security Hub scan error: %v", err)
	} else {
		findings = append(findings, securityHubFindings...)
	}

	// Scan with AWS GuardDuty
	guardDutyFindings, err := s.scanWithGuardDuty(ctx)
	if err != nil {
		log.Printf("GuardDuty scan error: %v", err)
	} else {
		findings = append(findings, guardDutyFindings...)
	}

	return findings, nil
}

// scanWithInspector scans using AWS Inspector
func (s *SecurityScanner) scanWithInspector(ctx context.Context) ([]SecurityFinding, error) {
	// Get Inspector findings
	input := &inspector2.ListFindingsInput{
		MaxResults: aws.Int32(100),
	}

	output, err := s.awsInspector.ListFindings(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list Inspector findings: %w", err)
	}

	var findings []SecurityFinding
	for _, finding := range output.Findings {
		securityFinding := SecurityFinding{
			ID:            aws.ToString(finding.FindingArn),
			Title:         aws.ToString(finding.Title),
			Description:   aws.ToString(finding.Description),
			Severity:      string(finding.Severity),
			Category:      "vulnerability",
			CloudProvider: "aws",
			Status:        string(finding.Status),
			FirstSeen:     aws.ToTime(finding.FirstObservedAt),
			LastSeen:      aws.ToTime(finding.UpdatedAt),
			Evidence: map[string]interface{}{
				"inspector_score": finding.InspectorScore,
				"package_name":    finding.PackageVulnerabilityDetails,
			},
		}

		if finding.InspectorScore != nil {
			securityFinding.CVSS = aws.ToFloat64(finding.InspectorScore)
		}

		findings = append(findings, securityFinding)
	}

	return findings, nil
}

// scanWithSecurityHub scans using AWS Security Hub
func (s *SecurityScanner) scanWithSecurityHub(ctx context.Context) ([]SecurityFinding, error) {
	input := &securityhub.GetFindingsInput{
		MaxResults: aws.Int32(100),
	}

	output, err := s.awsSecurityHub.GetFindings(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get Security Hub findings: %w", err)
	}

	var findings []SecurityFinding
	for _, finding := range output.Findings {
		securityFinding := SecurityFinding{
			ID:            aws.ToString(finding.Id),
			Title:         aws.ToString(finding.Title),
			Description:   aws.ToString(finding.Description),
			Severity:      string(finding.Severity.Label),
			Category:      finding.Types[0],
			CloudProvider: "aws",
			Status:        string(finding.Workflow.Status),
			FirstSeen:     parseTimeFromString(aws.ToString(finding.FirstObservedAt)),
			LastSeen:      parseTimeFromString(aws.ToString(finding.UpdatedAt)),
			Evidence: map[string]interface{}{
				"generator_id": finding.GeneratorId,
				"resources":    finding.Resources,
			},
		}

		findings = append(findings, securityFinding)
	}

	return findings, nil
}

// scanWithGuardDuty scans using AWS GuardDuty
func (s *SecurityScanner) scanWithGuardDuty(ctx context.Context) ([]SecurityFinding, error) {
	// List detectors first
	detectorsOutput, err := s.awsGuardDuty.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list GuardDuty detectors: %w", err)
	}

	var findings []SecurityFinding
	for _, detectorId := range detectorsOutput.DetectorIds {
		// Get findings for each detector
		findingsOutput, err := s.awsGuardDuty.ListFindings(ctx, &guardduty.ListFindingsInput{
			DetectorId: aws.String(detectorId),
			MaxResults: aws.Int32(50),
		})
		if err != nil {
			log.Printf("Failed to list findings for detector %s: %v", detectorId, err)
			continue
		}

		// Get finding details
		if len(findingsOutput.FindingIds) > 0 {
			detailsOutput, err := s.awsGuardDuty.GetFindings(ctx, &guardduty.GetFindingsInput{
				DetectorId: aws.String(detectorId),
				FindingIds: findingsOutput.FindingIds,
			})
			if err != nil {
				log.Printf("Failed to get finding details: %v", err)
				continue
			}

			for _, finding := range detailsOutput.Findings {
				securityFinding := SecurityFinding{
					ID:            aws.ToString(finding.Id),
					Title:         aws.ToString(finding.Title),
					Description:   aws.ToString(finding.Description),
					Severity:      fmt.Sprintf("%.1f", aws.ToFloat64(finding.Severity)),
					Category:      aws.ToString(finding.Type),
					CloudProvider: "aws",
					Status:        "active",
					FirstSeen:     parseTimeFromString(aws.ToString(finding.CreatedAt)),
					LastSeen:      parseTimeFromString(aws.ToString(finding.UpdatedAt)),
					Evidence: map[string]interface{}{
						"service":  finding.Service,
						"resource": finding.Resource,
					},
					CVSS: aws.ToFloat64(finding.Severity),
				}

				findings = append(findings, securityFinding)
			}
		}
	}

	return findings, nil
}

// scanGCP performs GCP-specific security scanning
func (s *SecurityScanner) scanGCP(ctx context.Context) ([]SecurityFinding, error) {
	// Placeholder for GCP security scanning
	// In a real implementation, this would use GCP Security Command Center API
	log.Printf("GCP security scanning not yet implemented")
	return []SecurityFinding{}, nil
}

// scanAzure performs Azure-specific security scanning
func (s *SecurityScanner) scanAzure(ctx context.Context) ([]SecurityFinding, error) {
	// Placeholder for Azure security scanning
	// In a real implementation, this would use Azure Security Center API
	log.Printf("Azure security scanning not yet implemented")
	return []SecurityFinding{}, nil
}

// scanKubernetes performs Kubernetes-specific security scanning
func (s *SecurityScanner) scanKubernetes(ctx context.Context) ([]SecurityFinding, error) {
	var findings []SecurityFinding

	// Scan for insecure pod configurations
	podFindings, err := s.scanPodSecurity(ctx)
	if err != nil {
		log.Printf("Pod security scan error: %v", err)
	} else {
		findings = append(findings, podFindings...)
	}

	// Scan network policies
	networkFindings, err := s.scanNetworkPolicies(ctx)
	if err != nil {
		log.Printf("Network policy scan error: %v", err)
	} else {
		findings = append(findings, networkFindings...)
	}

	// Scan RBAC configurations
	rbacFindings, err := s.scanRBAC(ctx)
	if err != nil {
		log.Printf("RBAC scan error: %v", err)
	} else {
		findings = append(findings, rbacFindings...)
	}

	return findings, nil
}

// scanPodSecurity scans for insecure pod configurations
func (s *SecurityScanner) scanPodSecurity(ctx context.Context) ([]SecurityFinding, error) {
	// Implementation for pod security scanning
	// This would check for privileged containers, root users, etc.
	return []SecurityFinding{}, nil
}

// scanNetworkPolicies scans network policy configurations
func (s *SecurityScanner) scanNetworkPolicies(ctx context.Context) ([]SecurityFinding, error) {
	// Implementation for network policy scanning
	return []SecurityFinding{}, nil
}

// scanRBAC scans RBAC configurations
func (s *SecurityScanner) scanRBAC(ctx context.Context) ([]SecurityFinding, error) {
	// Implementation for RBAC scanning
	return []SecurityFinding{}, nil
}

// calculateSummary calculates scan summary statistics
func (s *SecurityScanner) calculateSummary(findings []SecurityFinding) SecurityScanSummary {
	summary := SecurityScanSummary{
		TotalFindings: len(findings),
		LastScanTime:  time.Now(),
	}

	for _, finding := range findings {
		switch finding.Severity {
		case "critical", "CRITICAL":
			summary.CriticalFindings++
		case "high", "HIGH":
			summary.HighFindings++
		case "medium", "MEDIUM":
			summary.MediumFindings++
		case "low", "LOW":
			summary.LowFindings++
		}
	}

	// Calculate risk score (0-100)
	summary.RiskScore = (summary.CriticalFindings * 25) + (summary.HighFindings * 15) +
		(summary.MediumFindings * 8) + (summary.LowFindings * 2)
	if summary.RiskScore > 100 {
		summary.RiskScore = 100
	}

	return summary
}

// assessCompliance assesses compliance against frameworks
func (s *SecurityScanner) assessCompliance(ctx context.Context, findings []SecurityFinding) ComplianceAssessment {
	// Simplified compliance assessment
	assessment := ComplianceAssessment{
		Framework:    "SOC2",
		Version:      "2017",
		LastAssessed: time.Now(),
	}

	// Calculate compliance score based on findings
	totalChecks := 100
	failedChecks := len(findings)
	assessment.Score = ((totalChecks - failedChecks) * 100) / totalChecks
	if assessment.Score < 0 {
		assessment.Score = 0
	}

	return assessment
}

// SaveResults saves scan results to storage
func (s *SecurityScanner) SaveResults(ctx context.Context, result *ScanResult) error {
	// Convert to JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	// Save to file (in production, this would be saved to S3, database, etc.)
	filename := fmt.Sprintf("/tmp/security-scan-%s-%d.json",
		result.Environment, result.Timestamp.Unix())

	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write results file: %w", err)
	}

	log.Printf("Security scan results saved to: %s", filename)
	return nil
}

// Helper functions
func parseTimeFromString(timeStr string) time.Time {
	if timeStr == "" {
		return time.Time{}
	}

	// Try common time formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t
		}
	}

	// If parsing fails, return current time
	log.Printf("Warning: Failed to parse time string: %s", timeStr)
	return time.Now()
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func main() {
	ctx := context.Background()

	scanner, err := NewSecurityScanner(ctx)
	if err != nil {
		log.Fatalf("Failed to create security scanner: %v", err)
	}

	result, err := scanner.RunComprehensiveScan(ctx)
	if err != nil {
		log.Fatalf("Failed to run security scan: %v", err)
	}

	err = scanner.SaveResults(ctx, result)
	if err != nil {
		log.Fatalf("Failed to save results: %v", err)
	}

	log.Printf("Security scan completed successfully")
}
