package cryptography

import (
	"context"
	"fmt"
	"time"
)

// QuantumReadinessReport represents a quantum readiness assessment report
type QuantumReadinessReport struct {
	OrganizationID  string                     `json:"organization_id"`
	AssessmentDate  time.Time                  `json:"assessment_date"`
	ReadinessScore  float64                    `json:"readiness_score"`
	ReadinessLevel  string                     `json:"readiness_level"`
	Vulnerabilities []*QuantumVulnerability    `json:"vulnerabilities"`
	CriticalGaps    []*ReadinessGap            `json:"critical_gaps"`
	QuickWins       []*QuickWin                `json:"quick_wins"`
	MigrationEffort *MigrationEffortEstimate   `json:"migration_effort"`
	Recommendations []*ReadinessRecommendation `json:"recommendations"`
	NextSteps       []*NextStep                `json:"next_steps"`
}

// QuantumVulnerability represents a quantum vulnerability
type QuantumVulnerability struct {
	ID                string                 `json:"id"`
	SystemID          string                 `json:"system_id"`
	SystemName        string                 `json:"system_name"`
	VulnerabilityType string                 `json:"vulnerability_type"`
	Algorithm         string                 `json:"algorithm"`
	KeySize           int                    `json:"key_size"`
	Severity          string                 `json:"severity"`
	Impact            string                 `json:"impact"`
	Likelihood        string                 `json:"likelihood"`
	TimeToBreak       string                 `json:"time_to_break"`
	Mitigation        []string               `json:"mitigation"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ReadinessGap represents a gap in quantum readiness
type ReadinessGap struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Impact      string   `json:"impact"`
	Priority    string   `json:"priority"`
	Remediation []string `json:"remediation"`
	Timeline    string   `json:"timeline"`
	Cost        float64  `json:"cost"`
}

// QuickWin represents a quick win opportunity
type QuickWin struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Benefit     string  `json:"benefit"`
	Effort      string  `json:"effort"`
	Timeline    string  `json:"timeline"`
	Cost        float64 `json:"cost"`
	ROI         float64 `json:"roi"`
}

// MigrationEffortEstimate represents migration effort estimation
type MigrationEffortEstimate struct {
	TotalEffort    float64        `json:"total_effort"` // person-hours
	Duration       time.Duration  `json:"duration"`
	Complexity     string         `json:"complexity"`
	RiskLevel      string         `json:"risk_level"`
	ResourceNeeds  *ResourceNeeds `json:"resource_needs"`
	PhaseBreakdown []*EffortPhase `json:"phase_breakdown"`
	Assumptions    []string       `json:"assumptions"`
	Uncertainties  []string       `json:"uncertainties"`
}

// ResourceNeeds represents resource requirements
type ResourceNeeds struct {
	TechnicalExperts    int     `json:"technical_experts"`
	ProjectManagers     int     `json:"project_managers"`
	SecuritySpecialists int     `json:"security_specialists"`
	Developers          int     `json:"developers"`
	Testers             int     `json:"testers"`
	TrainingHours       float64 `json:"training_hours"`
	ExternalConsultants int     `json:"external_consultants"`
}

// EffortPhase represents effort breakdown by phase
type EffortPhase struct {
	Name         string        `json:"name"`
	Effort       float64       `json:"effort"`
	Duration     time.Duration `json:"duration"`
	Resources    []string      `json:"resources"`
	Deliverables []string      `json:"deliverables"`
}

// ReadinessRecommendation represents a readiness recommendation
type ReadinessRecommendation struct {
	ID          string   `json:"id"`
	Priority    string   `json:"priority"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Benefits    []string `json:"benefits"`
	Risks       []string `json:"risks"`
	Timeline    string   `json:"timeline"`
	Cost        float64  `json:"cost"`
}

// NextStep represents a next step in the readiness journey
type NextStep struct {
	ID           string    `json:"id"`
	Order        int       `json:"order"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Owner        string    `json:"owner"`
	DueDate      time.Time `json:"due_date"`
	Dependencies []string  `json:"dependencies"`
	Success      []string  `json:"success_criteria"`
}

// AlgorithmRequirements represents requirements for algorithm selection
type AlgorithmRequirements struct {
	UseCase                 string                   `json:"use_case"`
	SecurityLevel           int                      `json:"security_level"`
	PerformanceRequirements *PerformanceRequirements `json:"performance_requirements"`
	ComplianceRequirements  []string                 `json:"compliance_requirements"`
	EnvironmentConstraints  *EnvironmentConstraints  `json:"environment_constraints"`
	IntegrationRequirements *IntegrationRequirements `json:"integration_requirements"`
}

// EnvironmentConstraints represents environment-specific constraints
type EnvironmentConstraints struct {
	Platform           string   `json:"platform"`          // "server", "mobile", "embedded", "cloud"
	Architecture       string   `json:"architecture"`      // "x86", "ARM", "RISC-V"
	MemoryLimit        int64    `json:"memory_limit"`      // bytes
	StorageLimit       int64    `json:"storage_limit"`     // bytes
	NetworkBandwidth   int64    `json:"network_bandwidth"` // bits per second
	PowerConstraints   bool     `json:"power_constraints"`
	SupportedLibraries []string `json:"supported_libraries"`
}

// IntegrationRequirements represents integration requirements
type IntegrationRequirements struct {
	ExistingProtocols     []string `json:"existing_protocols"`
	APICompatibility      []string `json:"api_compatibility"`
	DataFormats           []string `json:"data_formats"`
	Interoperability      []string `json:"interoperability"`
	BackwardCompatibility bool     `json:"backward_compatibility"`
	GradualMigration      bool     `json:"gradual_migration"`
}

// AlgorithmRecommendation represents an algorithm recommendation
type AlgorithmRecommendation struct {
	Algorithm             string                  `json:"algorithm"`
	Type                  string                  `json:"type"`
	SuitabilityScore      float64                 `json:"suitability_score"`
	SecurityLevel         int                     `json:"security_level"`
	PerformanceScore      float64                 `json:"performance_score"`
	MaturityLevel         string                  `json:"maturity_level"`
	StandardizationStatus string                  `json:"standardization_status"`
	Pros                  []string                `json:"pros"`
	Cons                  []string                `json:"cons"`
	UseCase               string                  `json:"use_case"`
	Implementation        *ImplementationGuidance `json:"implementation"`
	Alternatives          []string                `json:"alternatives"`
	Metadata              map[string]interface{}  `json:"metadata"`
}

// ImplementationGuidance provides implementation guidance
type ImplementationGuidance struct {
	Libraries               []string               `json:"libraries"`
	Frameworks              []string               `json:"frameworks"`
	BestPractices           []string               `json:"best_practices"`
	CommonPitfalls          []string               `json:"common_pitfalls"`
	TestingGuidance         []string               `json:"testing_guidance"`
	SecurityConsiderations  []string               `json:"security_considerations"`
	PerformanceOptimization []string               `json:"performance_optimization"`
	Examples                map[string]interface{} `json:"examples"`
}

// Helper methods for the migration planner

// designTargetState designs the target cryptographic state
func (qsmp *QuantumSafeMigrationPlanner) designTargetState(ctx context.Context, currentState *CryptographicInventory) (*CryptographicInventory, error) {
	targetState := &CryptographicInventory{
		Systems:      make([]*CryptographicSystem, 0),
		Protocols:    make([]*CryptographicProtocol, 0),
		Certificates: make([]*Certificate, 0),
		Keys:         make([]*CryptographicKey, 0),
	}

	// Design quantum-safe replacements for each system
	for _, system := range currentState.Systems {
		targetSystem := qsmp.designQuantumSafeSystem(system)
		targetState.Systems = append(targetState.Systems, targetSystem)
	}

	// Design quantum-safe protocols
	for _, protocol := range currentState.Protocols {
		targetProtocol := qsmp.designQuantumSafeProtocol(protocol)
		targetState.Protocols = append(targetState.Protocols, targetProtocol)
	}

	targetState.Summary = qsmp.generateInventorySummary(targetState)
	return targetState, nil
}

// createMigrationPhases creates migration phases
func (qsmp *QuantumSafeMigrationPlanner) createMigrationPhases(ctx context.Context, currentState, targetState *CryptographicInventory) ([]*MigrationPhase, error) {
	var phases []*MigrationPhase

	// Phase 1: Assessment and Planning
	phase1 := &MigrationPhase{
		ID:            "phase-1",
		Name:          "Assessment and Planning",
		Description:   "Comprehensive assessment and detailed migration planning",
		Order:         1,
		StartDate:     time.Now(),
		EndDate:       time.Now().Add(30 * 24 * time.Hour),
		Status:        "planned",
		RiskLevel:     "low",
		EstimatedCost: 50000,
	}
	phases = append(phases, phase1)

	// Phase 2: Infrastructure Preparation
	phase2 := &MigrationPhase{
		ID:            "phase-2",
		Name:          "Infrastructure Preparation",
		Description:   "Prepare infrastructure for quantum-safe algorithms",
		Order:         2,
		StartDate:     phase1.EndDate,
		EndDate:       phase1.EndDate.Add(60 * 24 * time.Hour),
		Status:        "planned",
		RiskLevel:     "medium",
		EstimatedCost: 100000,
	}
	phases = append(phases, phase2)

	// Phase 3: Pilot Implementation
	phase3 := &MigrationPhase{
		ID:            "phase-3",
		Name:          "Pilot Implementation",
		Description:   "Implement quantum-safe crypto in non-critical systems",
		Order:         3,
		StartDate:     phase2.EndDate,
		EndDate:       phase2.EndDate.Add(90 * 24 * time.Hour),
		Status:        "planned",
		RiskLevel:     "medium",
		EstimatedCost: 200000,
	}
	phases = append(phases, phase3)

	// Phase 4: Production Rollout
	phase4 := &MigrationPhase{
		ID:            "phase-4",
		Name:          "Production Rollout",
		Description:   "Roll out quantum-safe crypto to all systems",
		Order:         4,
		StartDate:     phase3.EndDate,
		EndDate:       phase3.EndDate.Add(180 * 24 * time.Hour),
		Status:        "planned",
		RiskLevel:     "high",
		EstimatedCost: 500000,
	}
	phases = append(phases, phase4)

	return phases, nil
}

// performRiskAnalysis performs comprehensive risk analysis
func (qsmp *QuantumSafeMigrationPlanner) performRiskAnalysis(ctx context.Context, currentState, targetState *CryptographicInventory, phases []*MigrationPhase) (*RiskAnalysis, error) {
	riskAnalysis := &RiskAnalysis{
		OverallRiskLevel: "medium",
		QuantumThreatRisk: &RiskAssessment{
			ID:          "quantum-threat",
			Name:        "Quantum Computing Threat",
			Description: "Risk of quantum computers breaking current cryptography",
			Category:    "external",
			Probability: 0.3,
			Impact:      0.9,
			RiskScore:   0.27,
			RiskLevel:   "medium",
			Timeframe:   "10-15 years",
		},
		MigrationRisks:      make([]*RiskAssessment, 0),
		BusinessImpactRisks: make([]*RiskAssessment, 0),
		TechnicalRisks:      make([]*RiskAssessment, 0),
		ComplianceRisks:     make([]*RiskAssessment, 0),
		Mitigations:         make([]*RiskMitigation, 0),
	}

	// Add migration-specific risks
	migrationRisk := &RiskAssessment{
		ID:          "migration-complexity",
		Name:        "Migration Complexity Risk",
		Description: "Risk of migration complexity causing delays or failures",
		Category:    "technical",
		Probability: 0.4,
		Impact:      0.6,
		RiskScore:   0.24,
		RiskLevel:   "medium",
		Timeframe:   "during migration",
	}
	riskAnalysis.MigrationRisks = append(riskAnalysis.MigrationRisks, migrationRisk)

	return riskAnalysis, nil
}

// calculateCosts calculates migration costs
func (qsmp *QuantumSafeMigrationPlanner) calculateCosts(ctx context.Context, phases []*MigrationPhase, targetState *CryptographicInventory) (*CostAnalysis, error) {
	totalCost := 0.0
	for _, phase := range phases {
		totalCost += phase.EstimatedCost
	}

	costAnalysis := &CostAnalysis{
		TotalCost:          totalCost,
		ImplementationCost: totalCost * 0.6,
		OperationalCost:    totalCost * 0.2,
		TrainingCost:       totalCost * 0.1,
		HardwareCost:       totalCost * 0.1,
		CostBreakdown:      make([]*CostItem, 0),
		ROIAnalysis: &ROIAnalysis{
			InitialInvestment: totalCost,
			AnnualSavings:     totalCost * 0.1,
			PaybackPeriod:     10.0,
		},
	}

	return costAnalysis, nil
}

// createTimeline creates migration timeline
func (qsmp *QuantumSafeMigrationPlanner) createTimeline(ctx context.Context, phases []*MigrationPhase) (*MigrationTimeline, error) {
	if len(phases) == 0 {
		return nil, fmt.Errorf("no phases provided")
	}

	startDate := phases[0].StartDate
	endDate := phases[len(phases)-1].EndDate

	timeline := &MigrationTimeline{
		StartDate:     startDate,
		EndDate:       endDate,
		TotalDuration: endDate.Sub(startDate),
		Phases:        make([]*TimelinePhase, 0),
		Milestones:    make([]*Milestone, 0),
		CriticalPath:  []string{"phase-1", "phase-2", "phase-3", "phase-4"},
		Dependencies:  make([]*Dependency, 0),
	}

	// Convert migration phases to timeline phases
	for _, phase := range phases {
		timelinePhase := &TimelinePhase{
			ID:        phase.ID,
			Name:      phase.Name,
			StartDate: phase.StartDate,
			EndDate:   phase.EndDate,
			Duration:  phase.EndDate.Sub(phase.StartDate),
			Status:    phase.Status,
			Progress:  0.0,
		}
		timeline.Phases = append(timeline.Phases, timelinePhase)
	}

	return timeline, nil
}

// Additional helper methods

func (qsmp *QuantumSafeMigrationPlanner) designQuantumSafeSystem(system *CryptographicSystem) *CryptographicSystem {
	targetSystem := &CryptographicSystem{
		ID:                system.ID + "_target",
		Name:              system.Name + " (Quantum-Safe)",
		Type:              system.Type,
		Criticality:       system.Criticality,
		Algorithms:        qsmp.replaceWithQuantumSafeAlgorithms(system.Algorithms),
		KeySizes:          qsmp.adjustKeySizes(system.KeySizes),
		Protocols:         qsmp.upgradeProtocols(system.Protocols),
		Certificates:      system.Certificates,
		QuantumVulnerable: false,
		MigrationPriority: system.MigrationPriority,
		Dependencies:      system.Dependencies,
		Metadata:          system.Metadata,
	}
	return targetSystem
}

func (qsmp *QuantumSafeMigrationPlanner) designQuantumSafeProtocol(protocol *CryptographicProtocol) *CryptographicProtocol {
	targetProtocol := &CryptographicProtocol{
		Name:                protocol.Name + "_v2",
		Version:             "quantum-safe",
		Algorithms:          qsmp.replaceWithQuantumSafeAlgorithms(protocol.Algorithms),
		QuantumVulnerable:   false,
		ReplacementOptions:  []string{},
		MigrationComplexity: "medium",
	}
	return targetProtocol
}

func (qsmp *QuantumSafeMigrationPlanner) replaceWithQuantumSafeAlgorithms(algorithms []string) []string {
	replacements := map[string]string{
		"RSA":   "CRYSTALS-Kyber",
		"ECDSA": "CRYSTALS-Dilithium",
		"ECDH":  "CRYSTALS-Kyber",
		"DH":    "CRYSTALS-Kyber",
		"DSA":   "CRYSTALS-Dilithium",
		"AES":   "AES", // AES remains quantum-safe with larger keys
	}

	var result []string
	for _, alg := range algorithms {
		if replacement, exists := replacements[alg]; exists {
			result = append(result, replacement)
		} else {
			result = append(result, alg) // Keep if already quantum-safe
		}
	}
	return result
}

func (qsmp *QuantumSafeMigrationPlanner) adjustKeySizes(keySizes []int) []int {
	var result []int
	for _, size := range keySizes {
		// Double AES key sizes for quantum safety
		if size == 128 {
			result = append(result, 256)
		} else if size == 256 {
			result = append(result, 512)
		} else {
			result = append(result, size)
		}
	}
	return result
}

func (qsmp *QuantumSafeMigrationPlanner) upgradeProtocols(protocols []string) []string {
	upgrades := map[string]string{
		"TLS 1.2": "TLS 1.3 + PQC",
		"TLS 1.3": "TLS 1.3 + PQC",
		"SSH":     "SSH + PQC",
		"IPSec":   "IPSec + PQC",
	}

	var result []string
	for _, protocol := range protocols {
		if upgrade, exists := upgrades[protocol]; exists {
			result = append(result, upgrade)
		} else {
			result = append(result, protocol)
		}
	}
	return result
}

// Placeholder implementations for missing methods
func (qsmp *QuantumSafeMigrationPlanner) generateRecommendations(currentState, targetState *CryptographicInventory, riskAnalysis *RiskAnalysis, costAnalysis *CostAnalysis) []*Recommendation {
	return []*Recommendation{
		{
			ID:          "rec-1",
			Type:        "strategic",
			Priority:    "high",
			Title:       "Implement Crypto-Agility",
			Description: "Implement crypto-agility to enable rapid algorithm changes",
			Rationale:   "Enables quick response to quantum threats",
			Impact:      "high",
			Effort:      "medium",
			Timeline:    "6 months",
		},
	}
}

func (qsmp *QuantumSafeMigrationPlanner) assessCompliance(targetState *CryptographicInventory) *ComplianceStatus {
	return &ComplianceStatus{
		OverallStatus:  "compliant",
		Requirements:   make([]*ComplianceRequirement, 0),
		Gaps:           make([]*ComplianceGap, 0),
		Certifications: make([]*Certification, 0),
		AuditReadiness: &AuditReadiness{
			Score:          85.0,
			ReadinessLevel: "high",
			Strengths:      []string{"NIST compliance", "Strong documentation"},
			Weaknesses:     []string{"Limited testing coverage"},
		},
	}
}

func (qsmp *QuantumSafeMigrationPlanner) identifyQuantumVulnerabilities(inventory *CryptographicInventory) []*QuantumVulnerability {
	var vulnerabilities []*QuantumVulnerability

	for _, system := range inventory.Systems {
		if system.QuantumVulnerable {
			vuln := &QuantumVulnerability{
				ID:                system.ID + "_vuln",
				SystemID:          system.ID,
				SystemName:        system.Name,
				VulnerabilityType: "quantum_vulnerable_crypto",
				Severity:          system.Criticality,
				Impact:            "high",
				Likelihood:        "medium",
				TimeToBreak:       "10-15 years",
				Mitigation:        []string{"migrate_to_pqc"},
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities
}

func (qsmp *QuantumSafeMigrationPlanner) calculateReadinessScore(inventory *CryptographicInventory, vulnerabilities []*QuantumVulnerability) float64 {
	if len(inventory.Systems) == 0 {
		return 0.0
	}

	vulnerableCount := len(vulnerabilities)
	totalCount := len(inventory.Systems)

	// Simple scoring: 100 - (vulnerable_percentage * 100)
	score := 100.0 - (float64(vulnerableCount)/float64(totalCount))*100.0

	if score < 0 {
		score = 0
	}

	return score
}

func (qsmp *QuantumSafeMigrationPlanner) getReadinessLevel(score float64) string {
	if score >= 80 {
		return "high"
	} else if score >= 60 {
		return "medium"
	} else if score >= 40 {
		return "low"
	} else {
		return "critical"
	}
}

func (qsmp *QuantumSafeMigrationPlanner) identifyReadinessGaps(inventory *CryptographicInventory, vulnerabilities []*QuantumVulnerability) []*ReadinessGap {
	return []*ReadinessGap{
		{
			ID:          "gap-1",
			Category:    "cryptographic",
			Description: "Quantum-vulnerable algorithms in use",
			Impact:      "high",
			Priority:    "high",
			Remediation: []string{"Migrate to post-quantum cryptography"},
			Timeline:    "12-24 months",
			Cost:        500000,
		},
	}
}

func (qsmp *QuantumSafeMigrationPlanner) identifyQuickWins(inventory *CryptographicInventory, vulnerabilities []*QuantumVulnerability) []*QuickWin {
	return []*QuickWin{
		{
			ID:          "qw-1",
			Title:       "Upgrade AES Key Sizes",
			Description: "Increase AES key sizes from 128 to 256 bits",
			Benefit:     "Immediate quantum resistance improvement",
			Effort:      "low",
			Timeline:    "1-2 months",
			Cost:        10000,
			ROI:         5.0,
		},
	}
}

func (qsmp *QuantumSafeMigrationPlanner) estimateMigrationEffort(inventory *CryptographicInventory, vulnerabilities []*QuantumVulnerability) *MigrationEffortEstimate {
	return &MigrationEffortEstimate{
		TotalEffort: 5000.0,               // person-hours
		Duration:    365 * 24 * time.Hour, // 1 year
		Complexity:  "high",
		RiskLevel:   "medium",
		ResourceNeeds: &ResourceNeeds{
			TechnicalExperts:    5,
			ProjectManagers:     2,
			SecuritySpecialists: 3,
			Developers:          10,
			Testers:             5,
			TrainingHours:       200,
			ExternalConsultants: 2,
		},
	}
}

func (qsmp *QuantumSafeMigrationPlanner) generateReadinessRecommendations(score float64, gaps []*ReadinessGap) []*ReadinessRecommendation {
	return []*ReadinessRecommendation{
		{
			ID:          "rec-1",
			Priority:    "high",
			Category:    "strategic",
			Title:       "Develop Quantum-Safe Strategy",
			Description: "Create comprehensive quantum-safe migration strategy",
			Benefits:    []string{"Proactive security", "Compliance readiness"},
			Timeline:    "3 months",
			Cost:        50000,
		},
	}
}

func (qsmp *QuantumSafeMigrationPlanner) generateNextSteps(score float64, gaps []*ReadinessGap, quickWins []*QuickWin) []*NextStep {
	return []*NextStep{
		{
			ID:          "step-1",
			Order:       1,
			Title:       "Complete Cryptographic Inventory",
			Description: "Conduct comprehensive inventory of all cryptographic assets",
			Owner:       "Security Team",
			DueDate:     time.Now().Add(30 * 24 * time.Hour),
			Success:     []string{"100% system coverage", "Documented algorithms"},
		},
	}
}

func (qsmp *QuantumSafeMigrationPlanner) recommendSignatureAlgorithms(requirements *AlgorithmRequirements) []*AlgorithmRecommendation {
	return []*AlgorithmRecommendation{
		{
			Algorithm:             "CRYSTALS-Dilithium",
			Type:                  "digital_signature",
			SuitabilityScore:      0.9,
			SecurityLevel:         requirements.SecurityLevel,
			PerformanceScore:      0.8,
			MaturityLevel:         "high",
			StandardizationStatus: "NIST_standardized",
			Pros:                  []string{"NIST standardized", "Good performance", "Strong security"},
			Cons:                  []string{"Large signatures", "New technology"},
			UseCase:               "digital_signatures",
		},
	}
}

func (qsmp *QuantumSafeMigrationPlanner) recommendKEMAlgorithms(requirements *AlgorithmRequirements) []*AlgorithmRecommendation {
	return []*AlgorithmRecommendation{
		{
			Algorithm:             "CRYSTALS-Kyber",
			Type:                  "key_encapsulation",
			SuitabilityScore:      0.95,
			SecurityLevel:         requirements.SecurityLevel,
			PerformanceScore:      0.9,
			MaturityLevel:         "high",
			StandardizationStatus: "NIST_standardized",
			Pros:                  []string{"NIST standardized", "Excellent performance", "Compact keys"},
			Cons:                  []string{"Lattice-based assumptions"},
			UseCase:               "key_exchange",
		},
	}
}

func (qsmp *QuantumSafeMigrationPlanner) recommendEncryptionAlgorithms(requirements *AlgorithmRequirements) []*AlgorithmRecommendation {
	return []*AlgorithmRecommendation{
		{
			Algorithm:             "AES-256",
			Type:                  "symmetric_encryption",
			SuitabilityScore:      0.85,
			SecurityLevel:         256,
			PerformanceScore:      0.95,
			MaturityLevel:         "very_high",
			StandardizationStatus: "widely_standardized",
			Pros:                  []string{"Proven security", "Hardware support", "Fast"},
			Cons:                  []string{"Requires larger keys for quantum safety"},
			UseCase:               "encryption",
		},
	}
}
