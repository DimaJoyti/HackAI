package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/quantum"
	"github.com/dimajoyti/hackai/pkg/quantum/assessment"
	"github.com/dimajoyti/hackai/pkg/quantum/cryptography"
	"github.com/dimajoyti/hackai/pkg/quantum/engine"
)

// QuantumLangGraphNodes provides LangGraph integration for quantum security
type QuantumLangGraphNodes struct {
	logger               *logger.Logger
	quantumSimulator     *engine.QuantumSimulatorImpl
	threatIntel          *assessment.QuantumThreatIntelligence
	vulnerabilityScanner *assessment.QuantumVulnerabilityScanner
	migrationPlanner     *cryptography.QuantumSafeMigrationPlanner
	postQuantumAnalyzer  *cryptography.PostQuantumAnalyzer
}

// NodeInput represents input to a LangGraph node
type NodeInput struct {
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	Context   map[string]interface{} `json:"context"`
	Timestamp time.Time              `json:"timestamp"`
	RequestID string                 `json:"request_id"`
	UserID    string                 `json:"user_id"`
	SessionID string                 `json:"session_id"`
}

// NodeOutput represents output from a LangGraph node
type NodeOutput struct {
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
	Success   bool                   `json:"success"`
	Error     string                 `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	RequestID string                 `json:"request_id"`
	NextNodes []string               `json:"next_nodes,omitempty"`
}

// QuantumAnalysisRequest represents a quantum analysis request
type QuantumAnalysisRequest struct {
	Algorithm    string                       `json:"algorithm"`
	Target       *quantum.CryptographicTarget `json:"target"`
	AnalysisType string                       `json:"analysis_type"`
	Parameters   map[string]interface{}       `json:"parameters"`
	Options      *AnalysisOptions             `json:"options"`
}

// AnalysisOptions represents analysis options
type AnalysisOptions struct {
	DeepAnalysis     bool   `json:"deep_analysis"`
	IncludeTimeline  bool   `json:"include_timeline"`
	GenerateReport   bool   `json:"generate_report"`
	ReportFormat     string `json:"report_format"`
	MaxExecutionTime int    `json:"max_execution_time"`
}

// ThreatAssessmentRequest represents a threat assessment request
type ThreatAssessmentRequest struct {
	Systems   []string                  `json:"systems"`
	Scope     string                    `json:"scope"`
	Timeframe string                    `json:"timeframe"`
	Filters   *assessment.ThreatFilters `json:"filters"`
	Options   *AssessmentOptions        `json:"options"`
}

// AssessmentOptions represents assessment options
type AssessmentOptions struct {
	IncludeRecommendations bool   `json:"include_recommendations"`
	RiskCalculation        string `json:"risk_calculation"`
	ComplianceFramework    string `json:"compliance_framework"`
	OutputFormat           string `json:"output_format"`
}

// MigrationPlanRequest represents a migration planning request
type MigrationPlanRequest struct {
	OrganizationID string                               `json:"organization_id"`
	Inventory      *cryptography.CryptographicInventory `json:"inventory"`
	Requirements   *cryptography.AlgorithmRequirements  `json:"requirements"`
	Constraints    *cryptography.MigrationConfig        `json:"constraints"`
	Options        *MigrationOptions                    `json:"options"`
}

// MigrationOptions represents migration planning options
type MigrationOptions struct {
	PlanningHorizon     string  `json:"planning_horizon"`
	RiskTolerance       string  `json:"risk_tolerance"`
	BudgetConstraints   float64 `json:"budget_constraints"`
	TimelineConstraints string  `json:"timeline_constraints"`
	PriorityFramework   string  `json:"priority_framework"`
	IncludeCostAnalysis bool    `json:"include_cost_analysis"`
	GenerateRoadmap     bool    `json:"generate_roadmap"`
}

// NewQuantumLangGraphNodes creates a new quantum LangGraph nodes instance
func NewQuantumLangGraphNodes(
	logger *logger.Logger,
	quantumSimulator *engine.QuantumSimulatorImpl,
	threatIntel *assessment.QuantumThreatIntelligence,
	vulnerabilityScanner *assessment.QuantumVulnerabilityScanner,
	migrationPlanner *cryptography.QuantumSafeMigrationPlanner,
	postQuantumAnalyzer *cryptography.PostQuantumAnalyzer,
) *QuantumLangGraphNodes {
	return &QuantumLangGraphNodes{
		logger:               logger,
		quantumSimulator:     quantumSimulator,
		threatIntel:          threatIntel,
		vulnerabilityScanner: vulnerabilityScanner,
		migrationPlanner:     migrationPlanner,
		postQuantumAnalyzer:  postQuantumAnalyzer,
	}
}

// QuantumAttackSimulationNode simulates quantum attacks on cryptographic systems
func (qlgn *QuantumLangGraphNodes) QuantumAttackSimulationNode(ctx context.Context, input *NodeInput) (*NodeOutput, error) {
	qlgn.logger.Info("Executing quantum attack simulation node", map[string]interface{}{
		"request_id": input.RequestID,
		"type":       input.Type,
	})

	// Parse the analysis request
	var request QuantumAnalysisRequest
	if err := qlgn.parseInput(input.Data, &request); err != nil {
		return qlgn.createErrorOutput(input, fmt.Sprintf("Failed to parse request: %v", err))
	}

	// Validate the request
	if err := qlgn.validateAnalysisRequest(&request); err != nil {
		return qlgn.createErrorOutput(input, fmt.Sprintf("Invalid request: %v", err))
	}

	// Perform quantum attack simulation
	result, err := qlgn.performQuantumAttack(ctx, &request)
	if err != nil {
		return qlgn.createErrorOutput(input, fmt.Sprintf("Attack simulation failed: %v", err))
	}

	// Create successful output
	output := &NodeOutput{
		Type: "quantum_attack_result",
		Data: map[string]interface{}{
			"attack_result": result,
			"analysis_type": request.AnalysisType,
			"algorithm":     request.Algorithm,
		},
		Metadata: map[string]interface{}{
			"execution_time": time.Since(input.Timestamp),
			"qubits_used":    result.QubitsRequired,
			"gates_used":     result.GatesRequired,
			"success_prob":   result.SuccessProb,
		},
		Success:   true,
		Timestamp: time.Now(),
		RequestID: input.RequestID,
		NextNodes: []string{"threat_assessment", "vulnerability_analysis"},
	}

	qlgn.logger.Info("Quantum attack simulation completed", map[string]interface{}{
		"request_id": input.RequestID,
		"success":    result.Success,
		"algorithm":  request.Algorithm,
	})

	return output, nil
}

// ThreatIntelligenceNode provides quantum threat intelligence analysis
func (qlgn *QuantumLangGraphNodes) ThreatIntelligenceNode(ctx context.Context, input *NodeInput) (*NodeOutput, error) {
	qlgn.logger.Info("Executing threat intelligence node", map[string]interface{}{
		"request_id": input.RequestID,
		"type":       input.Type,
	})

	// Parse the threat assessment request
	var request ThreatAssessmentRequest
	if err := qlgn.parseInput(input.Data, &request); err != nil {
		return qlgn.createErrorOutput(input, fmt.Sprintf("Failed to parse request: %v", err))
	}

	// Get current threats
	threats, err := qlgn.threatIntel.GetThreats(ctx, request.Filters)
	if err != nil {
		return qlgn.createErrorOutput(input, fmt.Sprintf("Failed to get threats: %v", err))
	}

	// Analyze threat landscape
	analysis := qlgn.analyzeThreatLandscape(threats, &request)

	// Create output
	output := &NodeOutput{
		Type: "threat_intelligence_result",
		Data: map[string]interface{}{
			"threats":          threats,
			"threat_analysis":  analysis,
			"assessment_scope": request.Scope,
			"timeframe":        request.Timeframe,
		},
		Metadata: map[string]interface{}{
			"threats_count":    len(threats),
			"critical_threats": qlgn.countCriticalThreats(threats),
			"analysis_time":    time.Since(input.Timestamp),
		},
		Success:   true,
		Timestamp: time.Now(),
		RequestID: input.RequestID,
		NextNodes: []string{"vulnerability_assessment", "risk_analysis"},
	}

	qlgn.logger.Info("Threat intelligence analysis completed", map[string]interface{}{
		"request_id":    input.RequestID,
		"threats_found": len(threats),
		"scope":         request.Scope,
	})

	return output, nil
}

// VulnerabilityAssessmentNode performs quantum vulnerability assessment
func (qlgn *QuantumLangGraphNodes) VulnerabilityAssessmentNode(ctx context.Context, input *NodeInput) (*NodeOutput, error) {
	qlgn.logger.Info("Executing vulnerability assessment node", map[string]interface{}{
		"request_id": input.RequestID,
		"type":       input.Type,
	})

	// Parse systems to scan
	systems, ok := input.Data["systems"].([]interface{})
	if !ok {
		return qlgn.createErrorOutput(input, "Invalid systems data")
	}

	var scanResults []*assessment.ScanResult
	var totalVulnerabilities int

	// Scan each system
	for _, systemData := range systems {
		systemMap, ok := systemData.(map[string]interface{})
		if !ok {
			continue
		}

		target := &assessment.ScanTarget{
			ID:   fmt.Sprintf("%v", systemMap["id"]),
			Name: fmt.Sprintf("%v", systemMap["name"]),
			Type: fmt.Sprintf("%v", systemMap["type"]),
		}

		result, err := qlgn.vulnerabilityScanner.ScanTarget(ctx, target)
		if err != nil {
			qlgn.logger.Error("Scan failed", map[string]interface{}{
				"target": target.Name,
				"error":  err.Error(),
			})
			continue
		}

		scanResults = append(scanResults, result)
		totalVulnerabilities += len(result.Vulnerabilities)
	}

	// Generate assessment summary
	summary := qlgn.generateVulnerabilityAssessmentSummary(scanResults)

	output := &NodeOutput{
		Type: "vulnerability_assessment_result",
		Data: map[string]interface{}{
			"scan_results":          scanResults,
			"assessment_summary":    summary,
			"total_vulnerabilities": totalVulnerabilities,
		},
		Metadata: map[string]interface{}{
			"systems_scanned":       len(systems),
			"vulnerabilities_found": totalVulnerabilities,
			"scan_duration":         time.Since(input.Timestamp),
		},
		Success:   true,
		Timestamp: time.Now(),
		RequestID: input.RequestID,
		NextNodes: []string{"migration_planning", "remediation_planning"},
	}

	qlgn.logger.Info("Vulnerability assessment completed", map[string]interface{}{
		"request_id":      input.RequestID,
		"systems_scanned": len(systems),
		"vulnerabilities": totalVulnerabilities,
	})

	return output, nil
}

// Helper methods

// parseInput parses input data into a specific struct
func (qlgn *QuantumLangGraphNodes) parseInput(data map[string]interface{}, target interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	if err := json.Unmarshal(jsonData, target); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
}

// createErrorOutput creates an error output
func (qlgn *QuantumLangGraphNodes) createErrorOutput(input *NodeInput, errorMsg string) (*NodeOutput, error) {
	return &NodeOutput{
		Type:      "error",
		Data:      map[string]interface{}{},
		Metadata:  map[string]interface{}{"error_time": time.Since(input.Timestamp)},
		Success:   false,
		Error:     errorMsg,
		Timestamp: time.Now(),
		RequestID: input.RequestID,
	}, nil
}

// validateAnalysisRequest validates a quantum analysis request
func (qlgn *QuantumLangGraphNodes) validateAnalysisRequest(request *QuantumAnalysisRequest) error {
	if request.Algorithm == "" {
		return fmt.Errorf("algorithm is required")
	}

	if request.Target == nil {
		return fmt.Errorf("target is required")
	}

	if request.AnalysisType == "" {
		request.AnalysisType = "standard"
	}

	return nil
}

// performQuantumAttack performs a quantum attack simulation
func (qlgn *QuantumLangGraphNodes) performQuantumAttack(ctx context.Context, request *QuantumAnalysisRequest) (*quantum.QuantumAttackResult, error) {
	switch request.AnalysisType {
	case "shor":
		return qlgn.quantumSimulator.RunShor(ctx, request.Target.Parameters["n"].(*big.Int))
	case "grover":
		oracle := func(input []int) bool {
			// Simple oracle for demonstration
			return input[0] == 1 && input[1] == 0
		}
		return qlgn.quantumSimulator.RunGrover(ctx, oracle, 4)
	default:
		// Default to Shor's algorithm for RSA targets
		if n, ok := request.Target.Parameters["n"].(*big.Int); ok {
			return qlgn.quantumSimulator.RunShor(ctx, n)
		}
		return nil, fmt.Errorf("unsupported analysis type: %s", request.AnalysisType)
	}
}

// analyzeThreatLandscape analyzes the threat landscape
func (qlgn *QuantumLangGraphNodes) analyzeThreatLandscape(threats []*assessment.ThreatIndicator, request *ThreatAssessmentRequest) map[string]interface{} {
	analysis := map[string]interface{}{
		"total_threats":           len(threats),
		"critical_count":          0,
		"high_count":              0,
		"medium_count":            0,
		"low_count":               0,
		"threat_categories":       make(map[string]int),
		"geographic_distribution": make(map[string]int),
		"confidence_average":      0.0,
	}

	var confidenceSum float64
	for _, threat := range threats {
		// Count by severity
		switch threat.Severity {
		case assessment.SeverityCritical:
			analysis["critical_count"] = analysis["critical_count"].(int) + 1
		case assessment.SeverityHigh:
			analysis["high_count"] = analysis["high_count"].(int) + 1
		case assessment.SeverityMedium:
			analysis["medium_count"] = analysis["medium_count"].(int) + 1
		case assessment.SeverityLow:
			analysis["low_count"] = analysis["low_count"].(int) + 1
		}

		// Count by type
		categories := analysis["threat_categories"].(map[string]int)
		categories[string(threat.Type)]++

		confidenceSum += threat.Confidence
	}

	if len(threats) > 0 {
		analysis["confidence_average"] = confidenceSum / float64(len(threats))
	}

	return analysis
}

// countCriticalThreats counts critical threats
func (qlgn *QuantumLangGraphNodes) countCriticalThreats(threats []*assessment.ThreatIndicator) int {
	count := 0
	for _, threat := range threats {
		if threat.Severity == assessment.SeverityCritical {
			count++
		}
	}
	return count
}

// generateVulnerabilityAssessmentSummary generates a vulnerability assessment summary
func (qlgn *QuantumLangGraphNodes) generateVulnerabilityAssessmentSummary(results []*assessment.ScanResult) map[string]interface{} {
	summary := map[string]interface{}{
		"total_scans":                len(results),
		"successful_scans":           0,
		"failed_scans":               0,
		"total_vulnerabilities":      0,
		"critical_vulnerabilities":   0,
		"high_vulnerabilities":       0,
		"medium_vulnerabilities":     0,
		"low_vulnerabilities":        0,
		"quantum_vulnerable_systems": 0,
		"average_risk_score":         0.0,
	}

	var riskScoreSum float64
	for _, result := range results {
		if result.Status == "completed" {
			summary["successful_scans"] = summary["successful_scans"].(int) + 1
		} else {
			summary["failed_scans"] = summary["failed_scans"].(int) + 1
		}

		summary["total_vulnerabilities"] = summary["total_vulnerabilities"].(int) + len(result.Vulnerabilities)

		if result.Summary != nil {
			summary["critical_vulnerabilities"] = summary["critical_vulnerabilities"].(int) + result.Summary.CriticalCount
			summary["high_vulnerabilities"] = summary["high_vulnerabilities"].(int) + result.Summary.HighCount
			summary["medium_vulnerabilities"] = summary["medium_vulnerabilities"].(int) + result.Summary.MediumCount
			summary["low_vulnerabilities"] = summary["low_vulnerabilities"].(int) + result.Summary.LowCount

			if result.Summary.QuantumVulnerable {
				summary["quantum_vulnerable_systems"] = summary["quantum_vulnerable_systems"].(int) + 1
			}

			riskScoreSum += result.Summary.RiskScore
		}
	}

	if len(results) > 0 {
		summary["average_risk_score"] = riskScoreSum / float64(len(results))
	}

	return summary
}

// Algorithm type detection methods

func (qlgn *QuantumLangGraphNodes) isLatticeBasedAlgorithm(algorithm string) bool {
	latticeAlgorithms := []string{
		"CRYSTALS-Kyber", "CRYSTALS-Dilithium", "FALCON", "NTRU",
		"FrodoKEM", "SABER", "NewHope", "LAC",
	}

	for _, alg := range latticeAlgorithms {
		if algorithm == alg {
			return true
		}
	}
	return false
}

func (qlgn *QuantumLangGraphNodes) isHashBasedAlgorithm(algorithm string) bool {
	hashAlgorithms := []string{
		"SPHINCS+", "XMSS", "LMS", "WOTS+",
	}

	for _, alg := range hashAlgorithms {
		if algorithm == alg {
			return true
		}
	}
	return false
}

func (qlgn *QuantumLangGraphNodes) isCodeBasedAlgorithm(algorithm string) bool {
	codeAlgorithms := []string{
		"Classic McEliece", "BIKE", "HQC", "ROLLO",
	}

	for _, alg := range codeAlgorithms {
		if algorithm == alg {
			return true
		}
	}
	return false
}

func (qlgn *QuantumLangGraphNodes) isMultivariateAlgorithm(algorithm string) bool {
	multivariateAlgorithms := []string{
		"Rainbow", "GeMSS", "LUOV", "UOV",
	}

	for _, alg := range multivariateAlgorithms {
		if algorithm == alg {
			return true
		}
	}
	return false
}

// PostQuantumAnalysisNode analyzes post-quantum cryptographic algorithms
func (qlgn *QuantumLangGraphNodes) PostQuantumAnalysisNode(ctx context.Context, input *NodeInput) (*NodeOutput, error) {
	qlgn.logger.Info("Executing post-quantum analysis node", map[string]interface{}{
		"request_id": input.RequestID,
		"type":       input.Type,
	})

	// Parse algorithm and parameters
	algorithm, ok := input.Data["algorithm"].(string)
	if !ok {
		return qlgn.createErrorOutput(input, "Algorithm not specified")
	}

	parameters, ok := input.Data["parameters"].(map[string]interface{})
	if !ok {
		parameters = make(map[string]interface{})
	}

	// Determine algorithm type and perform analysis
	var assessment *quantum.SecurityAssessment
	var err error

	switch {
	case qlgn.isLatticeBasedAlgorithm(algorithm):
		assessment, err = qlgn.postQuantumAnalyzer.AnalyzeLatticeBasedCrypto(ctx, algorithm, parameters)
	case qlgn.isHashBasedAlgorithm(algorithm):
		assessment, err = qlgn.postQuantumAnalyzer.AnalyzeHashBasedCrypto(ctx, algorithm, parameters)
	case qlgn.isCodeBasedAlgorithm(algorithm):
		assessment, err = qlgn.postQuantumAnalyzer.AnalyzeCodeBasedCrypto(ctx, algorithm, parameters)
	case qlgn.isMultivariateAlgorithm(algorithm):
		assessment, err = qlgn.postQuantumAnalyzer.AnalyzeMultivariateCrypto(ctx, algorithm, parameters)
	default:
		return qlgn.createErrorOutput(input, fmt.Sprintf("Unsupported algorithm: %s", algorithm))
	}

	if err != nil {
		return qlgn.createErrorOutput(input, fmt.Sprintf("Analysis failed: %v", err))
	}

	output := &NodeOutput{
		Type: "post_quantum_analysis_result",
		Data: map[string]interface{}{
			"algorithm":           algorithm,
			"security_assessment": assessment,
			"parameters":          parameters,
		},
		Metadata: map[string]interface{}{
			"security_level": assessment.SecurityLevel,
			"quantum_safe":   assessment.QuantumSafe,
			"confidence":     assessment.Confidence,
			"analysis_time":  time.Since(input.Timestamp),
		},
		Success:   true,
		Timestamp: time.Now(),
		RequestID: input.RequestID,
		NextNodes: []string{"algorithm_recommendation", "migration_planning"},
	}

	qlgn.logger.Info("Post-quantum analysis completed", map[string]interface{}{
		"request_id":     input.RequestID,
		"algorithm":      algorithm,
		"quantum_safe":   assessment.QuantumSafe,
		"security_level": assessment.SecurityLevel,
	})

	return output, nil
}

// MigrationPlanningNode creates quantum-safe migration plans
func (qlgn *QuantumLangGraphNodes) MigrationPlanningNode(ctx context.Context, input *NodeInput) (*NodeOutput, error) {
	qlgn.logger.Info("Executing migration planning node", map[string]interface{}{
		"request_id": input.RequestID,
		"type":       input.Type,
	})

	// Parse migration planning request
	var request MigrationPlanRequest
	if err := qlgn.parseInput(input.Data, &request); err != nil {
		return qlgn.createErrorOutput(input, fmt.Sprintf("Failed to parse request: %v", err))
	}

	// Create migration plan
	plan, err := qlgn.migrationPlanner.CreateMigrationPlan(ctx, request.OrganizationID, request.Inventory)
	if err != nil {
		return qlgn.createErrorOutput(input, fmt.Sprintf("Migration planning failed: %v", err))
	}

	// Generate readiness assessment if requested
	var readinessReport *cryptography.QuantumReadinessReport
	if request.Options != nil && request.Options.IncludeCostAnalysis {
		readinessReport, err = qlgn.migrationPlanner.AssessQuantumReadiness(ctx, request.Inventory)
		if err != nil {
			qlgn.logger.Warn("Failed to generate readiness report", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	output := &NodeOutput{
		Type: "migration_planning_result",
		Data: map[string]interface{}{
			"migration_plan":   plan,
			"readiness_report": readinessReport,
			"organization_id":  request.OrganizationID,
		},
		Metadata: map[string]interface{}{
			"phases_count":       len(plan.MigrationPhases),
			"total_cost":         plan.CostAnalysis.TotalCost,
			"estimated_duration": plan.Timeline.TotalDuration,
			"planning_time":      time.Since(input.Timestamp),
		},
		Success:   true,
		Timestamp: time.Now(),
		RequestID: input.RequestID,
		NextNodes: []string{"cost_analysis", "timeline_optimization", "risk_assessment"},
	}

	qlgn.logger.Info("Migration planning completed", map[string]interface{}{
		"request_id":      input.RequestID,
		"organization_id": request.OrganizationID,
		"phases":          len(plan.MigrationPhases),
		"total_cost":      plan.CostAnalysis.TotalCost,
	})

	return output, nil
}
