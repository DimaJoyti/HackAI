package cryptography

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// QuantumSafeMigrationPlanner helps organizations migrate to quantum-safe cryptography
type QuantumSafeMigrationPlanner struct {
	logger   *logger.Logger
	config   *MigrationConfig
	analyzer *PostQuantumAnalyzer
}

// MigrationConfig holds configuration for migration planning
type MigrationConfig struct {
	ThreatHorizon           time.Duration            `json:"threat_horizon"`
	RiskTolerance           string                   `json:"risk_tolerance"` // "low", "medium", "high"
	ComplianceRequirements  []string                 `json:"compliance_requirements"`
	PerformanceRequirements *PerformanceRequirements `json:"performance_requirements"`
	BudgetConstraints       *BudgetConstraints       `json:"budget_constraints"`
	TimelineConstraints     *TimelineConstraints     `json:"timeline_constraints"`
}

// PerformanceRequirements defines performance constraints
type PerformanceRequirements struct {
	MaxKeyGenTime    time.Duration `json:"max_key_gen_time"`
	MaxSignTime      time.Duration `json:"max_sign_time"`
	MaxVerifyTime    time.Duration `json:"max_verify_time"`
	MaxEncryptTime   time.Duration `json:"max_encrypt_time"`
	MaxDecryptTime   time.Duration `json:"max_decrypt_time"`
	MinThroughput    float64       `json:"min_throughput"`
	MaxMemoryUsage   int64         `json:"max_memory_usage"`
	MaxKeySize       int           `json:"max_key_size"`
	MaxSignatureSize int           `json:"max_signature_size"`
}

// BudgetConstraints defines budget limitations
type BudgetConstraints struct {
	MaxImplementationCost float64 `json:"max_implementation_cost"`
	MaxOperationalCost    float64 `json:"max_operational_cost"`
	MaxTrainingCost       float64 `json:"max_training_cost"`
	MaxHardwareCost       float64 `json:"max_hardware_cost"`
}

// TimelineConstraints defines timeline requirements
type TimelineConstraints struct {
	MigrationDeadline time.Time       `json:"migration_deadline"`
	PhaseDeadlines    []PhaseDeadline `json:"phase_deadlines"`
	CriticalSystems   []string        `json:"critical_systems"`
}

// PhaseDeadline represents a migration phase deadline
type PhaseDeadline struct {
	Phase    string    `json:"phase"`
	Deadline time.Time `json:"deadline"`
	Systems  []string  `json:"systems"`
}

// MigrationPlan represents a complete migration plan
type MigrationPlan struct {
	ID               string                  `json:"id"`
	OrganizationID   string                  `json:"organization_id"`
	CreatedAt        time.Time               `json:"created_at"`
	UpdatedAt        time.Time               `json:"updated_at"`
	Status           string                  `json:"status"`
	ThreatAssessment *ThreatAssessment       `json:"threat_assessment"`
	CurrentState     *CryptographicInventory `json:"current_state"`
	TargetState      *CryptographicInventory `json:"target_state"`
	MigrationPhases  []*MigrationPhase       `json:"migration_phases"`
	RiskAnalysis     *RiskAnalysis           `json:"risk_analysis"`
	CostAnalysis     *CostAnalysis           `json:"cost_analysis"`
	Timeline         *MigrationTimeline      `json:"timeline"`
	Recommendations  []*Recommendation       `json:"recommendations"`
	ComplianceStatus *ComplianceStatus       `json:"compliance_status"`
}

// CryptographicInventory represents current cryptographic usage
type CryptographicInventory struct {
	Systems      []*CryptographicSystem   `json:"systems"`
	Protocols    []*CryptographicProtocol `json:"protocols"`
	Certificates []*Certificate           `json:"certificates"`
	Keys         []*CryptographicKey      `json:"keys"`
	Summary      *InventorySummary        `json:"summary"`
}

// CryptographicSystem represents a system using cryptography
type CryptographicSystem struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Type              string                 `json:"type"`
	Criticality       string                 `json:"criticality"` // "critical", "high", "medium", "low"
	Algorithms        []string               `json:"algorithms"`
	KeySizes          []int                  `json:"key_sizes"`
	Protocols         []string               `json:"protocols"`
	Certificates      []string               `json:"certificates"`
	QuantumVulnerable bool                   `json:"quantum_vulnerable"`
	MigrationPriority int                    `json:"migration_priority"`
	Dependencies      []string               `json:"dependencies"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// CryptographicProtocol represents a cryptographic protocol
type CryptographicProtocol struct {
	Name                string   `json:"name"`
	Version             string   `json:"version"`
	Algorithms          []string `json:"algorithms"`
	QuantumVulnerable   bool     `json:"quantum_vulnerable"`
	ReplacementOptions  []string `json:"replacement_options"`
	MigrationComplexity string   `json:"migration_complexity"`
}

// Certificate represents a digital certificate
type Certificate struct {
	ID                string    `json:"id"`
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	Algorithm         string    `json:"algorithm"`
	KeySize           int       `json:"key_size"`
	ExpiryDate        time.Time `json:"expiry_date"`
	QuantumVulnerable bool      `json:"quantum_vulnerable"`
	ReplacementNeeded bool      `json:"replacement_needed"`
}

// CryptographicKey represents a cryptographic key
type CryptographicKey struct {
	ID                string    `json:"id"`
	Type              string    `json:"type"`
	Algorithm         string    `json:"algorithm"`
	KeySize           int       `json:"key_size"`
	Usage             []string  `json:"usage"`
	ExpiryDate        time.Time `json:"expiry_date"`
	QuantumVulnerable bool      `json:"quantum_vulnerable"`
	ReplacementNeeded bool      `json:"replacement_needed"`
}

// InventorySummary provides a summary of the cryptographic inventory
type InventorySummary struct {
	TotalSystems             int            `json:"total_systems"`
	QuantumVulnerableSystems int            `json:"quantum_vulnerable_systems"`
	CriticalSystems          int            `json:"critical_systems"`
	AlgorithmDistribution    map[string]int `json:"algorithm_distribution"`
	KeySizeDistribution      map[int]int    `json:"key_size_distribution"`
	ProtocolDistribution     map[string]int `json:"protocol_distribution"`
	VulnerabilityBreakdown   map[string]int `json:"vulnerability_breakdown"`
}

// MigrationPhase represents a phase in the migration plan
type MigrationPhase struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Order         int                    `json:"order"`
	StartDate     time.Time              `json:"start_date"`
	EndDate       time.Time              `json:"end_date"`
	Status        string                 `json:"status"`
	Systems       []string               `json:"systems"`
	Tasks         []*MigrationTask       `json:"tasks"`
	Dependencies  []string               `json:"dependencies"`
	RiskLevel     string                 `json:"risk_level"`
	EstimatedCost float64                `json:"estimated_cost"`
	ActualCost    float64                `json:"actual_cost"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// MigrationTask represents a specific migration task
type MigrationTask struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Type           string                 `json:"type"`
	Status         string                 `json:"status"`
	AssignedTo     string                 `json:"assigned_to"`
	StartDate      time.Time              `json:"start_date"`
	EndDate        time.Time              `json:"end_date"`
	EstimatedHours float64                `json:"estimated_hours"`
	ActualHours    float64                `json:"actual_hours"`
	Dependencies   []string               `json:"dependencies"`
	Deliverables   []string               `json:"deliverables"`
	RiskLevel      string                 `json:"risk_level"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// RiskAnalysis represents risk analysis for the migration
type RiskAnalysis struct {
	OverallRiskLevel    string            `json:"overall_risk_level"`
	QuantumThreatRisk   *RiskAssessment   `json:"quantum_threat_risk"`
	MigrationRisks      []*RiskAssessment `json:"migration_risks"`
	BusinessImpactRisks []*RiskAssessment `json:"business_impact_risks"`
	TechnicalRisks      []*RiskAssessment `json:"technical_risks"`
	ComplianceRisks     []*RiskAssessment `json:"compliance_risks"`
	Mitigations         []*RiskMitigation `json:"mitigations"`
}

// RiskAssessment represents a specific risk assessment
type RiskAssessment struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Category        string                 `json:"category"`
	Probability     float64                `json:"probability"`
	Impact          float64                `json:"impact"`
	RiskScore       float64                `json:"risk_score"`
	RiskLevel       string                 `json:"risk_level"`
	AffectedSystems []string               `json:"affected_systems"`
	Timeframe       string                 `json:"timeframe"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// RiskMitigation represents a risk mitigation strategy
type RiskMitigation struct {
	ID               string                 `json:"id"`
	RiskID           string                 `json:"risk_id"`
	Strategy         string                 `json:"strategy"`
	Description      string                 `json:"description"`
	Implementation   string                 `json:"implementation"`
	Cost             float64                `json:"cost"`
	Effectiveness    float64                `json:"effectiveness"`
	Timeline         string                 `json:"timeline"`
	ResponsibleParty string                 `json:"responsible_party"`
	Status           string                 `json:"status"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// CostAnalysis represents cost analysis for the migration
type CostAnalysis struct {
	TotalCost          float64         `json:"total_cost"`
	ImplementationCost float64         `json:"implementation_cost"`
	OperationalCost    float64         `json:"operational_cost"`
	TrainingCost       float64         `json:"training_cost"`
	HardwareCost       float64         `json:"hardware_cost"`
	SoftwareCost       float64         `json:"software_cost"`
	ConsultingCost     float64         `json:"consulting_cost"`
	CostBreakdown      []*CostItem     `json:"cost_breakdown"`
	ROIAnalysis        *ROIAnalysis    `json:"roi_analysis"`
	CostComparison     *CostComparison `json:"cost_comparison"`
}

// CostItem represents a specific cost item
type CostItem struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Category    string                 `json:"category"`
	Amount      float64                `json:"amount"`
	Currency    string                 `json:"currency"`
	Frequency   string                 `json:"frequency"`
	Phase       string                 `json:"phase"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ROIAnalysis represents return on investment analysis
type ROIAnalysis struct {
	InitialInvestment float64   `json:"initial_investment"`
	AnnualSavings     float64   `json:"annual_savings"`
	PaybackPeriod     float64   `json:"payback_period"`
	NPV               float64   `json:"npv"`
	IRR               float64   `json:"irr"`
	RiskAdjustedROI   float64   `json:"risk_adjusted_roi"`
	BreakEvenPoint    time.Time `json:"break_even_point"`
}

// CostComparison compares costs of different migration approaches
type CostComparison struct {
	Approaches     []*MigrationApproach `json:"approaches"`
	Recommendation string               `json:"recommendation"`
	Justification  string               `json:"justification"`
}

// MigrationApproach represents a migration approach
type MigrationApproach struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	TotalCost      float64  `json:"total_cost"`
	Timeline       string   `json:"timeline"`
	RiskLevel      string   `json:"risk_level"`
	Complexity     string   `json:"complexity"`
	BusinessImpact string   `json:"business_impact"`
	Pros           []string `json:"pros"`
	Cons           []string `json:"cons"`
}

// MigrationTimeline represents the migration timeline
type MigrationTimeline struct {
	StartDate     time.Time        `json:"start_date"`
	EndDate       time.Time        `json:"end_date"`
	TotalDuration time.Duration    `json:"total_duration"`
	Phases        []*TimelinePhase `json:"phases"`
	Milestones    []*Milestone     `json:"milestones"`
	CriticalPath  []string         `json:"critical_path"`
	Dependencies  []*Dependency    `json:"dependencies"`
	ResourcePlan  *ResourcePlan    `json:"resource_plan"`
}

// TimelinePhase represents a phase in the timeline
type TimelinePhase struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	StartDate time.Time     `json:"start_date"`
	EndDate   time.Time     `json:"end_date"`
	Duration  time.Duration `json:"duration"`
	Status    string        `json:"status"`
	Progress  float64       `json:"progress"`
	Tasks     []string      `json:"tasks"`
	Resources []string      `json:"resources"`
}

// Milestone represents a project milestone
type Milestone struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Date         time.Time              `json:"date"`
	Status       string                 `json:"status"`
	Criteria     []string               `json:"criteria"`
	Deliverables []string               `json:"deliverables"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Dependency represents a project dependency
type Dependency struct {
	ID          string `json:"id"`
	From        string `json:"from"`
	To          string `json:"to"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Constraint  string `json:"constraint"`
}

// ResourcePlan represents resource planning
type ResourcePlan struct {
	Teams      []*Team       `json:"teams"`
	Skills     []*Skill      `json:"skills"`
	Tools      []*Tool       `json:"tools"`
	Budget     *Budget       `json:"budget"`
	Allocation []*Allocation `json:"allocation"`
}

// Team represents a project team
type Team struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Role         string   `json:"role"`
	Members      []string `json:"members"`
	Skills       []string `json:"skills"`
	Availability float64  `json:"availability"`
	Cost         float64  `json:"cost"`
}

// Skill represents a required skill
type Skill struct {
	Name         string  `json:"name"`
	Level        string  `json:"level"`
	Required     bool    `json:"required"`
	Availability int     `json:"availability"`
	Cost         float64 `json:"cost"`
}

// Tool represents a required tool
type Tool struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	License  string  `json:"license"`
	Cost     float64 `json:"cost"`
	Required bool    `json:"required"`
}

// Budget represents budget allocation
type Budget struct {
	Total       float64            `json:"total"`
	Allocated   float64            `json:"allocated"`
	Remaining   float64            `json:"remaining"`
	Categories  map[string]float64 `json:"categories"`
	Contingency float64            `json:"contingency"`
}

// Allocation represents resource allocation
type Allocation struct {
	ResourceID string    `json:"resource_id"`
	TaskID     string    `json:"task_id"`
	StartDate  time.Time `json:"start_date"`
	EndDate    time.Time `json:"end_date"`
	Percentage float64   `json:"percentage"`
}

// Recommendation represents a migration recommendation
type Recommendation struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Priority     string                 `json:"priority"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Rationale    string                 `json:"rationale"`
	Impact       string                 `json:"impact"`
	Effort       string                 `json:"effort"`
	Timeline     string                 `json:"timeline"`
	Dependencies []string               `json:"dependencies"`
	Alternatives []string               `json:"alternatives"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ComplianceStatus represents compliance status
type ComplianceStatus struct {
	OverallStatus  string                   `json:"overall_status"`
	Requirements   []*ComplianceRequirement `json:"requirements"`
	Gaps           []*ComplianceGap         `json:"gaps"`
	Certifications []*Certification         `json:"certifications"`
	AuditReadiness *AuditReadiness          `json:"audit_readiness"`
}

// ComplianceRequirement represents a compliance requirement
type ComplianceRequirement struct {
	ID          string    `json:"id"`
	Framework   string    `json:"framework"`
	Requirement string    `json:"requirement"`
	Status      string    `json:"status"`
	Evidence    []string  `json:"evidence"`
	DueDate     time.Time `json:"due_date"`
}

// ComplianceGap represents a compliance gap
type ComplianceGap struct {
	ID          string `json:"id"`
	Requirement string `json:"requirement"`
	Gap         string `json:"gap"`
	Impact      string `json:"impact"`
	Remediation string `json:"remediation"`
	Timeline    string `json:"timeline"`
}

// Certification represents a certification
type Certification struct {
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	ExpiryDate time.Time `json:"expiry_date"`
	Issuer     string    `json:"issuer"`
	Scope      string    `json:"scope"`
}

// AuditReadiness represents audit readiness
type AuditReadiness struct {
	Score           float64  `json:"score"`
	ReadinessLevel  string   `json:"readiness_level"`
	Strengths       []string `json:"strengths"`
	Weaknesses      []string `json:"weaknesses"`
	Recommendations []string `json:"recommendations"`
}

// ThreatAssessment represents quantum threat assessment
type ThreatAssessment struct {
	ThreatLevel     string    `json:"threat_level"`
	ImmediateThreat bool      `json:"immediate_threat"`
	TimeHorizon     string    `json:"time_horizon"`
	Mitigation      []string  `json:"mitigation"`
	AssessedAt      time.Time `json:"assessed_at"`
}

// NewQuantumSafeMigrationPlanner creates a new migration planner
func NewQuantumSafeMigrationPlanner(logger *logger.Logger, config *MigrationConfig, analyzer *PostQuantumAnalyzer) *QuantumSafeMigrationPlanner {
	if config == nil {
		config = &MigrationConfig{
			ThreatHorizon:          10 * 365 * 24 * time.Hour, // 10 years
			RiskTolerance:          "medium",
			ComplianceRequirements: []string{"NIST", "FIPS"},
			PerformanceRequirements: &PerformanceRequirements{
				MaxKeyGenTime:    1 * time.Second,
				MaxSignTime:      100 * time.Millisecond,
				MaxVerifyTime:    50 * time.Millisecond,
				MaxEncryptTime:   100 * time.Millisecond,
				MaxDecryptTime:   100 * time.Millisecond,
				MinThroughput:    1000,
				MaxMemoryUsage:   10 * 1024 * 1024, // 10MB
				MaxKeySize:       8192,
				MaxSignatureSize: 10240,
			},
			BudgetConstraints: &BudgetConstraints{
				MaxImplementationCost: 1000000,
				MaxOperationalCost:    100000,
				MaxTrainingCost:       50000,
				MaxHardwareCost:       200000,
			},
			TimelineConstraints: &TimelineConstraints{
				MigrationDeadline: time.Now().Add(2 * 365 * 24 * time.Hour), // 2 years
			},
		}
	}

	return &QuantumSafeMigrationPlanner{
		logger:   logger,
		config:   config,
		analyzer: analyzer,
	}
}

// CreateMigrationPlan creates a comprehensive migration plan
func (qsmp *QuantumSafeMigrationPlanner) CreateMigrationPlan(ctx context.Context, organizationID string, inventory *CryptographicInventory) (*MigrationPlan, error) {
	planID := uuid.New().String()
	startTime := time.Now()

	qsmp.logger.Info("Creating quantum-safe migration plan", map[string]interface{}{
		"plan_id":         planID,
		"organization_id": organizationID,
		"systems_count":   len(inventory.Systems),
	})

	// Assess current threat landscape
	threatAssessment, err := qsmp.assessQuantumThreat(ctx)
	if err != nil {
		return nil, fmt.Errorf("threat assessment failed: %w", err)
	}

	// Analyze current cryptographic state
	currentState := qsmp.analyzeCryptographicState(inventory)

	// Design target state
	targetState, err := qsmp.designTargetState(ctx, currentState)
	if err != nil {
		return nil, fmt.Errorf("target state design failed: %w", err)
	}

	// Create migration phases
	phases, err := qsmp.createMigrationPhases(ctx, currentState, targetState)
	if err != nil {
		return nil, fmt.Errorf("migration phases creation failed: %w", err)
	}

	// Perform risk analysis
	riskAnalysis, err := qsmp.performRiskAnalysis(ctx, currentState, targetState, phases)
	if err != nil {
		return nil, fmt.Errorf("risk analysis failed: %w", err)
	}

	// Calculate costs
	costAnalysis, err := qsmp.calculateCosts(ctx, phases, targetState)
	if err != nil {
		return nil, fmt.Errorf("cost analysis failed: %w", err)
	}

	// Create timeline
	timeline, err := qsmp.createTimeline(ctx, phases)
	if err != nil {
		return nil, fmt.Errorf("timeline creation failed: %w", err)
	}

	// Generate recommendations
	recommendations := qsmp.generateRecommendations(currentState, targetState, riskAnalysis, costAnalysis)

	// Assess compliance
	complianceStatus := qsmp.assessCompliance(targetState)

	plan := &MigrationPlan{
		ID:               planID,
		OrganizationID:   organizationID,
		CreatedAt:        startTime,
		UpdatedAt:        time.Now(),
		Status:           "draft",
		ThreatAssessment: threatAssessment,
		CurrentState:     currentState,
		TargetState:      targetState,
		MigrationPhases:  phases,
		RiskAnalysis:     riskAnalysis,
		CostAnalysis:     costAnalysis,
		Timeline:         timeline,
		Recommendations:  recommendations,
		ComplianceStatus: complianceStatus,
	}

	qsmp.logger.Info("Migration plan created successfully", map[string]interface{}{
		"plan_id":      planID,
		"phases_count": len(phases),
		"total_cost":   costAnalysis.TotalCost,
		"duration":     time.Since(startTime),
	})

	return plan, nil
}

// AssessQuantumReadiness assesses an organization's quantum readiness
func (qsmp *QuantumSafeMigrationPlanner) AssessQuantumReadiness(ctx context.Context, inventory *CryptographicInventory) (*QuantumReadinessReport, error) {
	startTime := time.Now()

	qsmp.logger.Info("Assessing quantum readiness", map[string]interface{}{
		"systems_count": len(inventory.Systems),
	})

	// Analyze current cryptographic posture
	vulnerabilities := qsmp.identifyQuantumVulnerabilities(inventory)

	// Calculate readiness score
	readinessScore := qsmp.calculateReadinessScore(inventory, vulnerabilities)

	// Identify critical gaps
	gaps := qsmp.identifyReadinessGaps(inventory, vulnerabilities)

	// Generate quick wins
	quickWins := qsmp.identifyQuickWins(inventory, vulnerabilities)

	// Estimate migration effort
	effort := qsmp.estimateMigrationEffort(inventory, vulnerabilities)

	report := &QuantumReadinessReport{
		OrganizationID:  "default",
		AssessmentDate:  startTime,
		ReadinessScore:  readinessScore,
		ReadinessLevel:  qsmp.getReadinessLevel(readinessScore),
		Vulnerabilities: vulnerabilities,
		CriticalGaps:    gaps,
		QuickWins:       quickWins,
		MigrationEffort: effort,
		Recommendations: qsmp.generateReadinessRecommendations(readinessScore, gaps),
		NextSteps:       qsmp.generateNextSteps(readinessScore, gaps, quickWins),
	}

	qsmp.logger.Info("Quantum readiness assessment completed", map[string]interface{}{
		"readiness_score": readinessScore,
		"readiness_level": report.ReadinessLevel,
		"vulnerabilities": len(vulnerabilities),
		"duration":        time.Since(startTime),
	})

	return report, nil
}

// RecommendPostQuantumAlgorithms recommends suitable post-quantum algorithms
func (qsmp *QuantumSafeMigrationPlanner) RecommendPostQuantumAlgorithms(ctx context.Context, requirements *AlgorithmRequirements) ([]*AlgorithmRecommendation, error) {
	qsmp.logger.Info("Recommending post-quantum algorithms", map[string]interface{}{
		"use_case":        requirements.UseCase,
		"security_level":  requirements.SecurityLevel,
		"performance_req": requirements.PerformanceRequirements != nil,
	})

	var recommendations []*AlgorithmRecommendation

	// Analyze requirements
	switch requirements.UseCase {
	case "digital_signatures":
		recommendations = append(recommendations, qsmp.recommendSignatureAlgorithms(requirements)...)
	case "key_exchange":
		recommendations = append(recommendations, qsmp.recommendKEMAlgorithms(requirements)...)
	case "encryption":
		recommendations = append(recommendations, qsmp.recommendEncryptionAlgorithms(requirements)...)
	case "all":
		recommendations = append(recommendations, qsmp.recommendSignatureAlgorithms(requirements)...)
		recommendations = append(recommendations, qsmp.recommendKEMAlgorithms(requirements)...)
		recommendations = append(recommendations, qsmp.recommendEncryptionAlgorithms(requirements)...)
	}

	// Sort by suitability score
	sort.Slice(recommendations, func(i, j int) bool {
		return recommendations[i].SuitabilityScore > recommendations[j].SuitabilityScore
	})

	qsmp.logger.Info("Algorithm recommendations generated", map[string]interface{}{
		"recommendations_count": len(recommendations),
	})

	return recommendations, nil
}

// Helper methods for migration planning

func (qsmp *QuantumSafeMigrationPlanner) assessQuantumThreat(ctx context.Context) (*ThreatAssessment, error) {
	// Assess current quantum computing capabilities and timeline
	return &ThreatAssessment{
		ThreatLevel:     "medium",
		ImmediateThreat: false,
		TimeHorizon:     "10-15 years",
		Mitigation:      []string{"implement_post_quantum_crypto", "crypto_agility", "hybrid_solutions"},
		AssessedAt:      time.Now(),
	}, nil
}

func (qsmp *QuantumSafeMigrationPlanner) analyzeCryptographicState(inventory *CryptographicInventory) *CryptographicInventory {
	// Analyze and enrich the current cryptographic inventory
	for _, system := range inventory.Systems {
		system.QuantumVulnerable = qsmp.isQuantumVulnerable(system.Algorithms)
		system.MigrationPriority = qsmp.calculateMigrationPriority(system)
	}

	// Update summary
	inventory.Summary = qsmp.generateInventorySummary(inventory)

	return inventory
}

func (qsmp *QuantumSafeMigrationPlanner) isQuantumVulnerable(algorithms []string) bool {
	vulnerableAlgorithms := map[string]bool{
		"RSA":   true,
		"ECDSA": true,
		"ECDH":  true,
		"DH":    true,
		"DSA":   true,
	}

	for _, alg := range algorithms {
		if vulnerableAlgorithms[alg] {
			return true
		}
	}
	return false
}

func (qsmp *QuantumSafeMigrationPlanner) calculateMigrationPriority(system *CryptographicSystem) int {
	priority := 0

	// Base priority on criticality
	switch system.Criticality {
	case "critical":
		priority += 100
	case "high":
		priority += 75
	case "medium":
		priority += 50
	case "low":
		priority += 25
	}

	// Increase priority if quantum vulnerable
	if system.QuantumVulnerable {
		priority += 50
	}

	// Adjust based on dependencies
	priority += len(system.Dependencies) * 10

	return priority
}

func (qsmp *QuantumSafeMigrationPlanner) generateInventorySummary(inventory *CryptographicInventory) *InventorySummary {
	summary := &InventorySummary{
		TotalSystems:           len(inventory.Systems),
		AlgorithmDistribution:  make(map[string]int),
		KeySizeDistribution:    make(map[int]int),
		ProtocolDistribution:   make(map[string]int),
		VulnerabilityBreakdown: make(map[string]int),
	}

	for _, system := range inventory.Systems {
		if system.Criticality == "critical" {
			summary.CriticalSystems++
		}
		if system.QuantumVulnerable {
			summary.QuantumVulnerableSystems++
		}

		for _, alg := range system.Algorithms {
			summary.AlgorithmDistribution[alg]++
		}

		for _, keySize := range system.KeySizes {
			summary.KeySizeDistribution[keySize]++
		}

		for _, protocol := range system.Protocols {
			summary.ProtocolDistribution[protocol]++
		}
	}

	return summary
}
