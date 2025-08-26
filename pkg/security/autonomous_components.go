package security

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/ai/decision"
	"github.com/dimajoyti/hackai/pkg/langgraph/messaging"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/memory"
	"github.com/google/uuid"
)

// Additional types needed for autonomous operations
type OperationCoordination struct {
	CoordinatorID         string                 `json:"coordinator_id"`
	CommunicationPlan     *CommunicationPlan     `json:"communication_plan"`
	SynchronizationPoints []*SyncPoint           `json:"synchronization_points"`
	EscalationProcedures  []*EscalationProcedure `json:"escalation_procedures"`
	Metadata              map[string]interface{} `json:"metadata"`
}

type CommunicationPlan struct {
	Channels          []string               `json:"channels"`
	Protocols         []string               `json:"protocols"`
	UpdateFrequency   time.Duration          `json:"update_frequency"`
	EmergencyChannels []string               `json:"emergency_channels"`
	Metadata          map[string]interface{} `json:"metadata"`
}

type SyncPoint struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Trigger      string                 `json:"trigger"`
	Participants []string               `json:"participants"`
	Actions      []string               `json:"actions"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type EscalationProcedure struct {
	Level    int                    `json:"level"`
	Trigger  string                 `json:"trigger"`
	Actions  []string               `json:"actions"`
	Contacts []string               `json:"contacts"`
	Metadata map[string]interface{} `json:"metadata"`
}

// PhaseResult is defined in orchestration_components.go

type PhaseStatus string

const (
	PhaseStatusPending   PhaseStatus = "pending"
	PhaseStatusActive    PhaseStatus = "active"
	PhaseStatusCompleted PhaseStatus = "completed"
	PhaseStatusFailed    PhaseStatus = "failed"
	PhaseStatusSkipped   PhaseStatus = "skipped"
)

type TaskResult struct {
	TaskID   string                 `json:"task_id"`
	Success  bool                   `json:"success"`
	Output   interface{}            `json:"output"`
	Duration time.Duration          `json:"duration"`
	AgentID  string                 `json:"agent_id"`
	Metadata map[string]interface{} `json:"metadata"`
}

// PhaseMetrics is defined in orchestration_components.go

type OperationIntelligence struct {
	GatheredData    map[string]interface{}     `json:"gathered_data"`
	ThreatLandscape *AutonomousThreatLandscape `json:"threat_landscape"`
	Opportunities   []*Opportunity             `json:"opportunities"`
	Risks           []*IdentifiedRisk          `json:"risks"`
	LastUpdated     time.Time                  `json:"last_updated"`
	Metadata        map[string]interface{}     `json:"metadata"`
}

type AutonomousThreatLandscape struct {
	ActiveThreats  []*ActiveThreat        `json:"active_threats"`
	DefensePosture *DefensePosture        `json:"defense_posture"`
	AttackSurface  *AttackSurface         `json:"attack_surface"`
	Metadata       map[string]interface{} `json:"metadata"`
}

type ActiveThreat struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Indicators  []string               `json:"indicators"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type DefensePosture struct {
	Maturity      float64                `json:"maturity"`
	Coverage      float64                `json:"coverage"`
	Effectiveness float64                `json:"effectiveness"`
	Gaps          []string               `json:"gaps"`
	Strengths     []string               `json:"strengths"`
	Metadata      map[string]interface{} `json:"metadata"`
}

type AttackSurface struct {
	ExternalAssets []*Asset               `json:"external_assets"`
	InternalAssets []*Asset               `json:"internal_assets"`
	EntryPoints    []*EntryPoint          `json:"entry_points"`
	CriticalPaths  []*CriticalPath        `json:"critical_paths"`
	Metadata       map[string]interface{} `json:"metadata"`
}

type Asset struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Value    float64                `json:"value"`
	Exposure float64                `json:"exposure"`
	Metadata map[string]interface{} `json:"metadata"`
}

type EntryPoint struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Difficulty float64                `json:"difficulty"`
	Detection  float64                `json:"detection"`
	Metadata   map[string]interface{} `json:"metadata"`
}

type CriticalPath struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Steps    []string               `json:"steps"`
	Risk     float64                `json:"risk"`
	Impact   float64                `json:"impact"`
	Metadata map[string]interface{} `json:"metadata"`
}

type Opportunity struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Potential   float64                `json:"potential"`
	Difficulty  float64                `json:"difficulty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type IdentifiedRisk struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Probability float64                `json:"probability"`
	Impact      float64                `json:"impact"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type AutonomousOperationMetrics struct {
	OverallSuccess     float64                  `json:"overall_success"`
	EfficiencyScore    float64                  `json:"efficiency_score"`
	StealthScore       float64                  `json:"stealth_score"`
	InnovationScore    float64                  `json:"innovation_score"`
	LearningScore      float64                  `json:"learning_score"`
	CollaborationScore float64                  `json:"collaboration_score"`
	PhaseMetrics       map[string]*PhaseMetrics `json:"phase_metrics"`
	AgentMetrics       map[string]*AgentMetrics `json:"agent_metrics"`
	Metadata           map[string]interface{}   `json:"metadata"`
}

type AgentMetrics struct {
	TasksCompleted  int                    `json:"tasks_completed"`
	SuccessRate     float64                `json:"success_rate"`
	EfficiencyScore float64                `json:"efficiency_score"`
	AdaptationScore float64                `json:"adaptation_score"`
	LearningScore   float64                `json:"learning_score"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type SuccessMetric struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Target   float64                `json:"target"`
	Current  float64                `json:"current"`
	Weight   float64                `json:"weight"`
	Metadata map[string]interface{} `json:"metadata"`
}

// Additional agent types
type AgentKnowledgeBase struct {
	TechnicalKnowledge map[string]interface{} `json:"technical_knowledge"`
	TacticalKnowledge  map[string]interface{} `json:"tactical_knowledge"`
	ExperienceBase     []*Experience          `json:"experience_base"`
	LessonsLearned     []*Lesson              `json:"lessons_learned"`
	BestPractices      []*BestPractice        `json:"best_practices"`
	Metadata           map[string]interface{} `json:"metadata"`
}

type Experience struct {
	ID            string                 `json:"id"`
	Context       string                 `json:"context"`
	Action        string                 `json:"action"`
	Outcome       string                 `json:"outcome"`
	Success       bool                   `json:"success"`
	LearningValue float64                `json:"learning_value"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata"`
}

type Lesson struct {
	ID            string                 `json:"id"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	Category      string                 `json:"category"`
	Importance    float64                `json:"importance"`
	Applicability []string               `json:"applicability"`
	Metadata      map[string]interface{} `json:"metadata"`
}

type BestPractice struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Context       []string               `json:"context"`
	Steps         []string               `json:"steps"`
	Effectiveness float64                `json:"effectiveness"`
	Metadata      map[string]interface{} `json:"metadata"`
}

type CommunicationState struct {
	ActiveChannels []string                `json:"active_channels"`
	MessageHistory []*CommunicationMessage `json:"message_history"`
	Subscriptions  []string                `json:"subscriptions"`
	Metadata       map[string]interface{}  `json:"metadata"`
}

type CommunicationMessage struct {
	ID        string                 `json:"id"`
	From      string                 `json:"from"`
	To        []string               `json:"to"`
	Type      string                 `json:"type"`
	Content   interface{}            `json:"content"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type OperationalMemory struct {
	ShortTermMemory  map[string]interface{} `json:"short_term_memory"`
	WorkingMemory    map[string]interface{} `json:"working_memory"`
	ContextualMemory map[string]interface{} `json:"contextual_memory"`
	Metadata         map[string]interface{} `json:"metadata"`
}

type AgentAdaptationEngine struct {
	AdaptationRules  []*AdaptationRule      `json:"adaptation_rules"`
	LearningHistory  []*LearningEvent       `json:"learning_history"`
	PerformanceModel *PerformanceModel      `json:"performance_model"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// AdaptationRule is defined in adaptive_security_orchestration.go

type LearningEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Context   string                 `json:"context"`
	Input     interface{}            `json:"input"`
	Output    interface{}            `json:"output"`
	Feedback  string                 `json:"feedback"`
	Success   bool                   `json:"success"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type PerformanceModel struct {
	Weights     map[string]float64     `json:"weights"`
	Biases      map[string]float64     `json:"biases"`
	Parameters  map[string]interface{} `json:"parameters"`
	LastTrained time.Time              `json:"last_trained"`
	Accuracy    float64                `json:"accuracy"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Component constructors
func NewAgentKnowledgeBase() *AgentKnowledgeBase {
	return &AgentKnowledgeBase{
		TechnicalKnowledge: make(map[string]interface{}),
		TacticalKnowledge:  make(map[string]interface{}),
		ExperienceBase:     make([]*Experience, 0),
		LessonsLearned:     make([]*Lesson, 0),
		BestPractices:      make([]*BestPractice, 0),
		Metadata:           make(map[string]interface{}),
	}
}

func NewOperationalMemory() *OperationalMemory {
	return &OperationalMemory{
		ShortTermMemory:  make(map[string]interface{}),
		WorkingMemory:    make(map[string]interface{}),
		ContextualMemory: make(map[string]interface{}),
		Metadata:         make(map[string]interface{}),
	}
}

func NewAgentAdaptationEngine() *AgentAdaptationEngine {
	return &AgentAdaptationEngine{
		AdaptationRules: make([]*AdaptationRule, 0),
		LearningHistory: make([]*LearningEvent, 0),
		PerformanceModel: &PerformanceModel{
			Weights:     make(map[string]float64),
			Biases:      make(map[string]float64),
			Parameters:  make(map[string]interface{}),
			LastTrained: time.Now(),
			Accuracy:    0.5,
			Metadata:    make(map[string]interface{}),
		},
		Metadata: make(map[string]interface{}),
	}
}

// Component interfaces and implementations
type MissionPlanner struct {
	logger *logger.Logger
}

func NewMissionPlanner(logger *logger.Logger) *MissionPlanner {
	return &MissionPlanner{logger: logger}
}

func (mp *MissionPlanner) GenerateMissionPlan(ctx context.Context, target *Target, objectives []MissionObjective) (*MissionPlan, error) {
	// Generate a comprehensive mission plan
	plan := &MissionPlan{
		ID:        uuid.New().String(),
		Name:      fmt.Sprintf("Mission-%s", target.Name),
		Phases:    make([]*MissionPhase, 0),
		Timeline:  &MissionTimeline{},
		CreatedAt: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Generate phases based on objectives
	for i, objective := range objectives {
		phase := &MissionPhase{
			ID:                      uuid.New().String(),
			Name:                    fmt.Sprintf("Phase-%d-%s", i+1, objective),
			Objective:               objective,
			RequiredRoles:           mp.getRequiredRoles(objective),
			RequiredSpecializations: mp.getRequiredSpecializations(objective),
			ComplexityLevel:         mp.assessComplexity(objective, target),
			EstimatedDuration:       mp.estimateDuration(objective),
			Tasks:                   mp.generateTasks(objective),
			Metadata:                make(map[string]interface{}),
		}
		plan.Phases = append(plan.Phases, phase)
	}

	mp.logger.Info("Mission plan generated",
		"plan_id", plan.ID,
		"target", target.Name,
		"phases", len(plan.Phases))

	return plan, nil
}

func (mp *MissionPlanner) getRequiredRoles(objective MissionObjective) []AgentRole {
	roleMap := map[MissionObjective][]AgentRole{
		ObjectiveReconnaissance:          {RoleReconSpecialist, RoleIntelligenceAnalyst},
		ObjectiveVulnerabilityAssessment: {RoleReconSpecialist, RoleExploitSpecialist},
		ObjectiveExploitation:            {RoleExploitSpecialist, RoleDefenseEvasion},
		ObjectivePersistence:             {RolePersistenceAgent, RoleStealthOperator},
		ObjectiveLateralMovement:         {RoleLateralMovement, RoleStealthOperator},
		ObjectiveDataExfiltration:        {RoleDataExfiltrator, RoleStealthOperator},
		ObjectiveDefenseEvasion:          {RoleDefenseEvasion, RoleStealthOperator},
		ObjectiveIntelligenceGathering:   {RoleIntelligenceAnalyst, RoleReconSpecialist},
		ObjectiveFullCompromise:          {RoleCommander, RoleExploitSpecialist, RolePersistenceAgent},
	}

	if roles, exists := roleMap[objective]; exists {
		return roles
	}
	return []AgentRole{RoleCommander}
}

func (mp *MissionPlanner) getRequiredSpecializations(objective MissionObjective) []Specialization {
	specMap := map[MissionObjective][]Specialization{
		ObjectiveReconnaissance:          {SpecNetworkInfra, SpecWebApplications},
		ObjectiveVulnerabilityAssessment: {SpecWebApplications, SpecNetworkInfra},
		ObjectiveExploitation:            {SpecWebApplications, SpecNetworkInfra},
		ObjectivePersistence:             {SpecMalwareAnalysis, SpecCryptography},
		ObjectiveLateralMovement:         {SpecNetworkInfra, SpecCloudSecurity},
		ObjectiveDataExfiltration:        {SpecForensics, SpecCryptography},
		ObjectiveDefenseEvasion:          {SpecMalwareAnalysis, SpecCryptography},
		ObjectiveIntelligenceGathering:   {SpecSocialEngineering, SpecForensics},
		ObjectiveFullCompromise:          {SpecWebApplications, SpecNetworkInfra, SpecMalwareAnalysis},
	}

	if specs, exists := specMap[objective]; exists {
		return specs
	}
	return []Specialization{SpecWebApplications}
}

func (mp *MissionPlanner) assessComplexity(objective MissionObjective, target *Target) ComplexityLevel {
	// Simple complexity assessment based on objective and target
	complexityMap := map[MissionObjective]ComplexityLevel{
		ObjectiveReconnaissance:          ComplexityLevelLow,
		ObjectiveVulnerabilityAssessment: ComplexityLevelMedium,
		ObjectiveExploitation:            ComplexityLevelHigh,
		ObjectivePersistence:             ComplexityLevelHigh,
		ObjectiveLateralMovement:         ComplexityLevelHigh,
		ObjectiveDataExfiltration:        ComplexityLevelMedium,
		ObjectiveDefenseEvasion:          ComplexityLevelHigh,
		ObjectiveIntelligenceGathering:   ComplexityLevelMedium,
		ObjectiveFullCompromise:          ComplexityLevelCritical,
	}

	if complexity, exists := complexityMap[objective]; exists {
		return complexity
	}
	return ComplexityLevelMedium
}

func (mp *MissionPlanner) estimateDuration(objective MissionObjective) time.Duration {
	durationMap := map[MissionObjective]time.Duration{
		ObjectiveReconnaissance:          30 * time.Minute,
		ObjectiveVulnerabilityAssessment: 1 * time.Hour,
		ObjectiveExploitation:            2 * time.Hour,
		ObjectivePersistence:             1 * time.Hour,
		ObjectiveLateralMovement:         1 * time.Hour,
		ObjectiveDataExfiltration:        30 * time.Minute,
		ObjectiveDefenseEvasion:          45 * time.Minute,
		ObjectiveIntelligenceGathering:   45 * time.Minute,
		ObjectiveFullCompromise:          4 * time.Hour,
	}

	if duration, exists := durationMap[objective]; exists {
		return duration
	}
	return 1 * time.Hour
}

func (mp *MissionPlanner) generateTasks(objective MissionObjective) []*MissionTask {
	// Generate tasks based on objective
	tasks := make([]*MissionTask, 0)

	switch objective {
	case ObjectiveReconnaissance:
		tasks = append(tasks, &MissionTask{
			ID:            uuid.New().String(),
			Name:          "Network Discovery",
			Type:          TaskTypeReconnaissance,
			Description:   "Discover network topology and services",
			EstimatedTime: 15 * time.Minute,
			Priority:      TaskPriorityHigh,
			Metadata:      make(map[string]interface{}),
		})
	case ObjectiveExploitation:
		tasks = append(tasks, &MissionTask{
			ID:            uuid.New().String(),
			Name:          "Vulnerability Exploitation",
			Type:          TaskTypeExploitation,
			Description:   "Exploit identified vulnerabilities",
			EstimatedTime: 1 * time.Hour,
			Priority:      TaskPriorityCritical,
			Metadata:      make(map[string]interface{}),
		})
	}

	return tasks
}

// TacticalCoordinator coordinates tactical operations
type TacticalCoordinator struct {
	communicationHub *messaging.EnhancedCommunicationHub
	logger           *logger.Logger
}

func NewTacticalCoordinator(communicationHub *messaging.EnhancedCommunicationHub, logger *logger.Logger) *TacticalCoordinator {
	return &TacticalCoordinator{
		communicationHub: communicationHub,
		logger:           logger,
	}
}

func (tc *TacticalCoordinator) InitializeCoordination(ctx context.Context, operation *AutonomousOperation) (*OperationCoordination, error) {
	coordination := &OperationCoordination{
		CoordinatorID: uuid.New().String(),
		CommunicationPlan: &CommunicationPlan{
			Channels:          []string{"tactical", "intelligence", "emergency"},
			Protocols:         []string{"secure", "encrypted"},
			UpdateFrequency:   5 * time.Minute,
			EmergencyChannels: []string{"emergency"},
			Metadata:          make(map[string]interface{}),
		},
		SynchronizationPoints: make([]*SyncPoint, 0),
		EscalationProcedures:  make([]*EscalationProcedure, 0),
		Metadata:              make(map[string]interface{}),
	}

	tc.logger.Info("Operation coordination initialized",
		"operation_id", operation.ID,
		"coordinator_id", coordination.CoordinatorID)

	return coordination, nil
}

// AdaptiveStrategy manages adaptive strategy decisions
type AdaptiveStrategy struct {
	decisionEngine *decision.AdvancedDecisionEngine
	logger         *logger.Logger
}

func NewAdaptiveStrategy(decisionEngine *decision.AdvancedDecisionEngine, logger *logger.Logger) *AdaptiveStrategy {
	return &AdaptiveStrategy{
		decisionEngine: decisionEngine,
		logger:         logger,
	}
}

func (as *AdaptiveStrategy) AdaptToFailure(ctx context.Context, operation *AutonomousOperation, phase *MissionPhase, err error) *AdaptationResult {
	as.logger.Info("Adapting to failure",
		"operation_id", operation.ID,
		"phase_id", phase.ID,
		"error", err.Error())

	// Simple adaptation logic - in production, use sophisticated decision engine
	result := &AdaptationResult{
		ShouldContinue:   true,
		AdaptationAction: "retry_with_different_approach",
		Confidence:       0.7,
		ReasoningPath:    []string{"failure_detected", "alternative_approach_available", "retry_recommended"},
		Metadata:         make(map[string]interface{}),
	}

	return result
}

type AdaptationResult struct {
	ShouldContinue   bool                   `json:"should_continue"`
	AdaptationAction string                 `json:"adaptation_action"`
	Confidence       float64                `json:"confidence"`
	ReasoningPath    []string               `json:"reasoning_path"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// IntelligenceGatherer gathers operational intelligence
type IntelligenceGatherer struct {
	logger *logger.Logger
}

func NewIntelligenceGatherer(logger *logger.Logger) *IntelligenceGatherer {
	return &IntelligenceGatherer{
		logger: logger,
	}
}

func (ig *IntelligenceGatherer) GatherIntelligence(ctx context.Context, target *Target) (*OperationIntelligence, error) {
	intelligence := &OperationIntelligence{
		GatheredData: make(map[string]interface{}),
		ThreatLandscape: &AutonomousThreatLandscape{
			ActiveThreats: make([]*ActiveThreat, 0),
			DefensePosture: &DefensePosture{
				Maturity:      0.7,
				Coverage:      0.8,
				Effectiveness: 0.6,
				Gaps:          []string{"endpoint_protection", "network_segmentation"},
				Strengths:     []string{"logging", "monitoring"},
				Metadata:      make(map[string]interface{}),
			},
			AttackSurface: &AttackSurface{
				ExternalAssets: make([]*Asset, 0),
				InternalAssets: make([]*Asset, 0),
				EntryPoints:    make([]*EntryPoint, 0),
				CriticalPaths:  make([]*CriticalPath, 0),
				Metadata:       make(map[string]interface{}),
			},
			Metadata: make(map[string]interface{}),
		},
		Opportunities: make([]*Opportunity, 0),
		Risks:         make([]*IdentifiedRisk, 0),
		LastUpdated:   time.Now(),
		Metadata:      make(map[string]interface{}),
	}

	ig.logger.Info("Intelligence gathered",
		"target", target.Name,
		"threats", len(intelligence.ThreatLandscape.ActiveThreats),
		"opportunities", len(intelligence.Opportunities))

	return intelligence, nil
}

// OperationController controls operation execution
type OperationController struct {
	logger *logger.Logger
}

func NewOperationController(logger *logger.Logger) *OperationController {
	return &OperationController{
		logger: logger,
	}
}

func (oc *OperationController) MonitorOperation(ctx context.Context, operation *AutonomousOperation) error {
	oc.logger.Debug("Monitoring operation",
		"operation_id", operation.ID,
		"status", operation.Status)

	// Implement operation monitoring logic
	return nil
}

// LearningEngine manages learning from operations
type LearningEngine struct {
	memorySystem *memory.EnhancedMemorySystem
	logger       *logger.Logger
}

func NewLearningEngine(memorySystem *memory.EnhancedMemorySystem, logger *logger.Logger) *LearningEngine {
	return &LearningEngine{
		memorySystem: memorySystem,
		logger:       logger,
	}
}

func (le *LearningEngine) LearnFromPhaseResult(ctx context.Context, operation *AutonomousOperation, phase *MissionPhase, result *PhaseResult) error {
	// Create learning memory entry
	learningEntry := &memory.MemoryEntry{
		ID:       uuid.New().String(),
		AgentID:  "learning_engine",
		Type:     memory.MemoryTypeExperience,
		Category: memory.CategoryExperience,
		Content: map[string]interface{}{
			"operation_id": operation.ID,
			"phase_id":     phase.ID,
			"phase_result": result,
			"success":      (result.Status == PhaseStatusCompleted),
			"duration":     result.Duration,
			"lessons":      []string{}, // Lessons derived from analysis
		},
		Tags:       []string{"learning", "phase_result", string(phase.Objective)},
		Importance: le.calculateLearningImportance(result),
		Metadata:   make(map[string]interface{}),
	}

	// Store in memory system
	if err := le.memorySystem.StoreMemory(ctx, learningEntry); err != nil {
		le.logger.Error("Failed to store learning memory",
			"operation_id", operation.ID,
			"phase_id", phase.ID,
			"error", err)
		return err
	}

	le.logger.Debug("Learning stored from phase result",
		"operation_id", operation.ID,
		"phase_id", phase.ID,
		"success", (result.Status == PhaseStatusCompleted),
		"importance", learningEntry.Importance)

	return nil
}

func (le *LearningEngine) calculateLearningImportance(result *PhaseResult) float64 {
	importance := 0.5 // Base importance

	// Increase importance for failures (more learning value)
	if result.Status == PhaseStatusFailed {
		importance += 0.3
	}

	// Increase importance for longer operations (more complex)
	if result.Duration > 1*time.Hour {
		importance += 0.2
	}

	// Increase importance for phases with findings (lessons can be derived)
	if len(result.Findings) > 0 {
		importance += 0.2
	}

	// Cap at 1.0
	if importance > 1.0 {
		importance = 1.0
	}

	return importance
}
