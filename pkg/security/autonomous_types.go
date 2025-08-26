package security

import (
	"time"
)

// Target represents an attack target
type Target struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Type              TargetType             `json:"type"`
	Description       string                 `json:"description"`
	NetworkInfo       *NetworkInfo           `json:"network_info"`
	Services          []*Service             `json:"services"`
	Vulnerabilities   []*Vulnerability       `json:"vulnerabilities"`
	DefenseMechanisms []*DefenseMechanism    `json:"defense_mechanisms"`
	RiskLevel         RiskLevel              `json:"risk_level"`
	Priority          TargetPriority         `json:"priority"`
	Metadata          map[string]interface{} `json:"metadata"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// TargetType defines types of targets
type TargetType string

const (
	TargetTypeWebApplication  TargetType = "web_application"
	TargetTypeNetworkInfra    TargetType = "network_infrastructure"
	TargetTypeCloudService    TargetType = "cloud_service"
	TargetTypeMobileApp       TargetType = "mobile_application"
	TargetTypeIoTDevice       TargetType = "iot_device"
	TargetTypeDatabase        TargetType = "database"
	TargetTypeAPIEndpoint     TargetType = "api_endpoint"
	TargetTypeActiveDirectory TargetType = "active_directory"
)

// TargetPriority defines target priority levels
type TargetPriority string

const (
	TargetPriorityLow      TargetPriority = "low"
	TargetPriorityMedium   TargetPriority = "medium"
	TargetPriorityHigh     TargetPriority = "high"
	TargetPriorityCritical TargetPriority = "critical"
)

// RiskLevel defines risk levels
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// NetworkInfo represents network information about a target
type NetworkInfo struct {
	IPAddresses  []string               `json:"ip_addresses"`
	Domains      []string               `json:"domains"`
	Ports        []int                  `json:"ports"`
	Protocols    []string               `json:"protocols"`
	NetworkRange string                 `json:"network_range"`
	Topology     string                 `json:"topology"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Service represents a service running on a target
type Service struct {
	Name     string                 `json:"name"`
	Version  string                 `json:"version"`
	Port     int                    `json:"port"`
	Protocol string                 `json:"protocol"`
	Status   string                 `json:"status"`
	Banner   string                 `json:"banner"`
	Metadata map[string]interface{} `json:"metadata"`
}

// Vulnerability represents a vulnerability in a target
type Vulnerability struct {
	ID          string                 `json:"id"`
	CVE         string                 `json:"cve"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"`
	CVSS        float64                `json:"cvss"`
	CWE         string                 `json:"cwe"`
	OWASP       string                 `json:"owasp"`
	Impact      string                 `json:"impact"`
	Likelihood  string                 `json:"likelihood"`
	Exploitable bool                   `json:"exploitable"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DefenseMechanism represents a defense mechanism
type DefenseMechanism struct {
	Type          string                 `json:"type"`
	Name          string                 `json:"name"`
	Status        string                 `json:"status"`
	Effectiveness float64                `json:"effectiveness"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// AutonomousOperation represents a fully autonomous red team operation
type AutonomousOperation struct {
	ID             string                      `json:"id"`
	Name           string                      `json:"name"`
	Target         *Target                     `json:"target"`
	Objectives     []MissionObjective          `json:"objectives"`
	Status         OperationStatus             `json:"status"`
	MissionPlan    *MissionPlan                `json:"mission_plan"`
	AssignedAgents []*AutonomousRedTeamAgent   `json:"assigned_agents"`
	Coordination   *OperationCoordination      `json:"coordination"`
	PhaseResults   []*PhaseResult              `json:"phase_results"`
	Intelligence   *OperationIntelligence      `json:"intelligence"`
	Metrics        *AutonomousOperationMetrics `json:"metrics"`
	CreatedAt      time.Time                   `json:"created_at"`
	StartedAt      *time.Time                  `json:"started_at"`
	CompletedAt    *time.Time                  `json:"completed_at"`
	Metadata       map[string]interface{}      `json:"metadata"`
}

// OperationStatus defines operation status
type OperationStatus string

const (
	OperationStatusPlanning  OperationStatus = "planning"
	OperationStatusActive    OperationStatus = "active"
	OperationStatusPaused    OperationStatus = "paused"
	OperationStatusCompleted OperationStatus = "completed"
	OperationStatusFailed    OperationStatus = "failed"
	OperationStatusTimeout   OperationStatus = "timeout"
	OperationStatusAborted   OperationStatus = "aborted"
)

// MissionPlan represents a comprehensive mission plan
type MissionPlan struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	Phases               []*MissionPhase        `json:"phases"`
	Timeline             *MissionTimeline       `json:"timeline"`
	ResourceRequirements *MissionResources      `json:"resource_requirements"`
	RiskAssessment       *RiskAssessment        `json:"risk_assessment"`
	ContingencyPlans     []*ContingencyPlan     `json:"contingency_plans"`
	SuccessMetrics       []*SuccessMetric       `json:"success_metrics"`
	CreatedAt            time.Time              `json:"created_at"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// MissionPhase represents a phase in a mission
type MissionPhase struct {
	ID                      string                 `json:"id"`
	Name                    string                 `json:"name"`
	Objective               MissionObjective       `json:"objective"`
	RequiredRoles           []AgentRole            `json:"required_roles"`
	RequiredSpecializations []Specialization       `json:"required_specializations"`
	ComplexityLevel         ComplexityLevel        `json:"complexity_level"`
	EstimatedDuration       time.Duration          `json:"estimated_duration"`
	Prerequisites           []string               `json:"prerequisites"`
	Tasks                   []*MissionTask         `json:"tasks"`
	SuccessCriteria         []*SuccessCriterion    `json:"success_criteria"`
	RiskFactors             []*RiskFactor          `json:"risk_factors"`
	Metadata                map[string]interface{} `json:"metadata"`
}

// ComplexityLevel defines complexity levels
type ComplexityLevel string

const (
	ComplexityLevelLow      ComplexityLevel = "low"
	ComplexityLevelMedium   ComplexityLevel = "medium"
	ComplexityLevelHigh     ComplexityLevel = "high"
	ComplexityLevelCritical ComplexityLevel = "critical"
)

// MissionTask represents a specific task within a phase
type MissionTask struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Type          TaskType               `json:"type"`
	Description   string                 `json:"description"`
	RequiredTools []string               `json:"required_tools"`
	EstimatedTime time.Duration          `json:"estimated_time"`
	Priority      TaskPriority           `json:"priority"`
	Dependencies  []string               `json:"dependencies"`
	Parameters    map[string]interface{} `json:"parameters"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// TaskType defines types of tasks
type TaskType string

const (
	TaskTypeReconnaissance   TaskType = "reconnaissance"
	TaskTypeScanning         TaskType = "scanning"
	TaskTypeExploitation     TaskType = "exploitation"
	TaskTypePostExploitation TaskType = "post_exploitation"
	TaskTypePersistence      TaskType = "persistence"
	TaskTypeLateralMovement  TaskType = "lateral_movement"
	TaskTypeDataExfiltration TaskType = "data_exfiltration"
	TaskTypeDefenseEvasion   TaskType = "defense_evasion"
	TaskTypeCleanup          TaskType = "cleanup"
)

// TaskPriority defines task priority levels
type TaskPriority string

const (
	TaskPriorityLow      TaskPriority = "low"
	TaskPriorityMedium   TaskPriority = "medium"
	TaskPriorityHigh     TaskPriority = "high"
	TaskPriorityCritical TaskPriority = "critical"
)

// MissionConstraints defines mission constraints
type MissionConstraints struct {
	TimeLimit           time.Duration          `json:"time_limit"`
	ResourceLimits      map[string]interface{} `json:"resource_limits"`
	StealthRequirements bool                   `json:"stealth_requirements"`
	NoiseLevel          float64                `json:"noise_level"`
	DetectionThreshold  float64                `json:"detection_threshold"`
	EthicalBoundaries   []string               `json:"ethical_boundaries"`
	LegalConstraints    []string               `json:"legal_constraints"`
	TechnicalLimits     map[string]interface{} `json:"technical_limits"`
}

// MissionParameters defines mission parameters
type MissionParameters struct {
	AggressivenessLevel float64                `json:"aggressiveness_level"`
	StealthLevel        float64                `json:"stealth_level"`
	PersistenceLevel    float64                `json:"persistence_level"`
	NoiseThreshold      float64                `json:"noise_threshold"`
	RiskTolerance       float64                `json:"risk_tolerance"`
	SuccessThreshold    float64                `json:"success_threshold"`
	AdaptationRate      float64                `json:"adaptation_rate"`
	LearningRate        float64                `json:"learning_rate"`
	CustomParameters    map[string]interface{} `json:"custom_parameters"`
}

// MissionTimeline defines mission timeline
type MissionTimeline struct {
	StartTime      time.Time              `json:"start_time"`
	EndTime        time.Time              `json:"end_time"`
	PhaseDeadlines map[string]time.Time   `json:"phase_deadlines"`
	Milestones     []*Milestone           `json:"milestones"`
	CriticalPath   []string               `json:"critical_path"`
	BufferTime     time.Duration          `json:"buffer_time"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// Milestone represents a mission milestone
type Milestone struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Deadline    time.Time              `json:"deadline"`
	Criteria    []string               `json:"criteria"`
	Status      MilestoneStatus        `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MilestoneStatus defines milestone status
type MilestoneStatus string

const (
	MilestoneStatusPending   MilestoneStatus = "pending"
	MilestoneStatusActive    MilestoneStatus = "active"
	MilestoneStatusCompleted MilestoneStatus = "completed"
	MilestoneStatusFailed    MilestoneStatus = "failed"
	MilestoneStatusSkipped   MilestoneStatus = "skipped"
)

// MissionResources defines mission resources
type MissionResources struct {
	RequiredAgents   int                    `json:"required_agents"`
	RequiredTools    []string               `json:"required_tools"`
	ComputeResources *ComputeResources      `json:"compute_resources"`
	NetworkResources *NetworkResources      `json:"network_resources"`
	StorageResources *StorageResources      `json:"storage_resources"`
	ExternalServices []string               `json:"external_services"`
	Budget           float64                `json:"budget"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// ComputeResources defines compute resource requirements
type ComputeResources struct {
	CPU     float64 `json:"cpu"`
	Memory  int64   `json:"memory"`
	GPU     int     `json:"gpu"`
	Threads int     `json:"threads"`
}

// NetworkResources defines network resource requirements
type NetworkResources struct {
	Bandwidth   int64    `json:"bandwidth"`
	Connections int      `json:"connections"`
	Protocols   []string `json:"protocols"`
	Proxies     []string `json:"proxies"`
}

// StorageResources defines storage resource requirements
type StorageResources struct {
	DiskSpace   int64 `json:"disk_space"`
	IOPS        int   `json:"iops"`
	Throughput  int64 `json:"throughput"`
	Persistence bool  `json:"persistence"`
}

// SuccessCriterion defines success criteria
type SuccessCriterion struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        CriterionType          `json:"type"`
	Threshold   float64                `json:"threshold"`
	Weight      float64                `json:"weight"`
	Mandatory   bool                   `json:"mandatory"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// CriterionType defines types of success criteria
type CriterionType string

const (
	CriterionTypeObjective    CriterionType = "objective"
	CriterionTypePerformance  CriterionType = "performance"
	CriterionTypeQuality      CriterionType = "quality"
	CriterionTypeEfficiency   CriterionType = "efficiency"
	CriterionTypeStealth      CriterionType = "stealth"
	CriterionTypeCompleteness CriterionType = "completeness"
)

// RiskAssessment represents risk assessment
type RiskAssessment struct {
	OverallRisk    float64                `json:"overall_risk"`
	RiskFactors    []*RiskFactor          `json:"risk_factors"`
	Mitigations    []*RiskMitigation      `json:"mitigations"`
	Contingencies  []*ContingencyPlan     `json:"contingencies"`
	MonitoringPlan *RiskMonitoringPlan    `json:"monitoring_plan"`
	LastAssessment time.Time              `json:"last_assessment"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// RiskFactor represents a risk factor
type RiskFactor struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    RiskCategory           `json:"category"`
	Probability float64                `json:"probability"`
	Impact      float64                `json:"impact"`
	Severity    RiskSeverity           `json:"severity"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RiskCategory defines risk categories
type RiskCategory string

const (
	RiskCategoryTechnical    RiskCategory = "technical"
	RiskCategoryOperational  RiskCategory = "operational"
	RiskCategoryDetection    RiskCategory = "detection"
	RiskCategoryLegal        RiskCategory = "legal"
	RiskCategoryReputational RiskCategory = "reputational"
	RiskCategoryFinancial    RiskCategory = "financial"
)

// RiskSeverity defines risk severity levels
type RiskSeverity string

const (
	RiskSeverityLow      RiskSeverity = "low"
	RiskSeverityMedium   RiskSeverity = "medium"
	RiskSeverityHigh     RiskSeverity = "high"
	RiskSeverityCritical RiskSeverity = "critical"
)

// RiskMitigation represents risk mitigation strategies
type RiskMitigation struct {
	ID            string                 `json:"id"`
	RiskID        string                 `json:"risk_id"`
	Strategy      string                 `json:"strategy"`
	Description   string                 `json:"description"`
	Effectiveness float64                `json:"effectiveness"`
	Cost          float64                `json:"cost"`
	Timeline      time.Duration          `json:"timeline"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ContingencyPlan represents contingency plans
type ContingencyPlan struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Trigger   string                 `json:"trigger"`
	Actions   []string               `json:"actions"`
	Resources []string               `json:"resources"`
	Timeline  time.Duration          `json:"timeline"`
	Priority  ContingencyPriority    `json:"priority"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ContingencyPriority defines contingency priority levels
type ContingencyPriority string

const (
	ContingencyPriorityLow      ContingencyPriority = "low"
	ContingencyPriorityMedium   ContingencyPriority = "medium"
	ContingencyPriorityHigh     ContingencyPriority = "high"
	ContingencyPriorityCritical ContingencyPriority = "critical"
)

// RiskMonitoringPlan defines risk monitoring
type RiskMonitoringPlan struct {
	Indicators []string               `json:"indicators"`
	Thresholds map[string]float64     `json:"thresholds"`
	Frequency  time.Duration          `json:"frequency"`
	Escalation []string               `json:"escalation"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// MissionResults contains mission results
type MissionResults struct {
	ID       string                 `json:"id"`
	Success  bool                   `json:"success"`
	Results  []interface{}          `json:"results"`
	Metadata map[string]interface{} `json:"metadata"`
}
