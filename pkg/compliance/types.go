package compliance

import (
	"time"
)

// ComplianceConfig defines comprehensive compliance configuration
type ComplianceConfig struct {
	// Regulatory frameworks
	Frameworks map[string]FrameworkConfig `yaml:"frameworks"`

	// Monitoring settings
	Monitoring map[string]interface{} `yaml:"monitoring"`

	// Audit settings
	Audit map[string]interface{} `yaml:"audit"`

	// Reporting settings
	Reporting map[string]interface{} `yaml:"reporting"`

	// Risk assessment
	RiskAssessment map[string]interface{} `yaml:"risk_assessment"`

	// Controls management
	Controls map[string]interface{} `yaml:"controls"`

	// Evidence management
	Evidence map[string]interface{} `yaml:"evidence"`

	// Assessment settings
	Assessment map[string]interface{} `yaml:"assessment"`

	// Remediation settings
	Remediation map[string]interface{} `yaml:"remediation"`
}

// RegulatoryConfig holds regulatory framework configuration
type RegulatoryConfig struct {
	Jurisdictions      []string            `json:"jurisdictions"`
	RegulationTypes    []string            `json:"regulation_types"`
	ReportingFrequency time.Duration       `json:"reporting_frequency"`
	AuditRetention     time.Duration       `json:"audit_retention"`
	AutoReporting      bool                `json:"auto_reporting"`
	RealTimeMonitoring bool                `json:"real_time_monitoring"`
	AlertThresholds    map[string]float64  `json:"alert_thresholds"`
	RequiredApprovals  map[string][]string `json:"required_approvals"`
}

// ComplianceActivity represents an activity subject to compliance validation
type ComplianceActivity struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description,omitempty"`
	Entity      string                 `json:"entity,omitempty"`
	UserID      string                 `json:"user_id"`
	Resource    string                 `json:"resource,omitempty"`
	Action      string                 `json:"action,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Location    string                 `json:"location,omitempty"`
	System      string                 `json:"system,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ID              string                 `json:"id"`
	Framework       ComplianceFramework    `json:"framework,omitempty"`
	Type            string                 `json:"type,omitempty"`
	RequirementID   string                 `json:"requirement_id,omitempty"`
	ControlID       string                 `json:"control_id,omitempty"`
	RuleID          string                 `json:"rule_id,omitempty"`
	RegulationID    string                 `json:"regulation_id,omitempty"`
	Severity        string                 `json:"severity"`
	Category        string                 `json:"category,omitempty"`
	Description     string                 `json:"description"`
	Entity          string                 `json:"entity,omitempty"`
	Activity        string                 `json:"activity,omitempty"`
	Impact          string                 `json:"impact,omitempty"`
	Recommendation  string                 `json:"recommendation,omitempty"`
	DetectedAt      time.Time              `json:"detected_at"`
	Status          string                 `json:"status"`
	AssignedTo      string                 `json:"assigned_to,omitempty"`
	DueDate         time.Time              `json:"due_date,omitempty"`
	Evidence        []string               `json:"evidence,omitempty"`
	RemediationPlan *RemediationPlan       `json:"remediation_plan,omitempty"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// RemediationPlan represents a plan to remediate violations
type RemediationPlan struct {
	ID          string                 `json:"id"`
	ViolationID string                 `json:"violation_id"`
	Type        string                 `json:"type"`
	Actions     []*RemediationAction   `json:"actions"`
	Timeline    *RemediationTimeline   `json:"timeline"`
	Assignee    string                 `json:"assignee"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RemediationAction represents a remediation action
type RemediationAction struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Priority    int                    `json:"priority"`
	DueDate     time.Time              `json:"due_date"`
	Status      string                 `json:"status"`
	Assignee    string                 `json:"assignee"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RemediationTimeline represents remediation timeline
type RemediationTimeline struct {
	StartDate  time.Time    `json:"start_date"`
	TargetDate time.Time    `json:"target_date"`
	ActualDate *time.Time   `json:"actual_date,omitempty"`
	Milestones []*Milestone `json:"milestones"`
}

// Milestone represents a remediation milestone
type Milestone struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	TargetDate  time.Time  `json:"target_date"`
	ActualDate  *time.Time `json:"actual_date,omitempty"`
	Status      string     `json:"status"`
	Description string     `json:"description"`
}

// ComplianceResult represents the result of compliance validation
type ComplianceResult struct {
	// Common fields
	ID         string    `json:"id,omitempty"`
	RequestID  string    `json:"request_id,omitempty"`
	ActivityID string    `json:"activity_id,omitempty"`
	Timestamp  time.Time `json:"timestamp,omitempty"`

	// Framework and compliance status
	Framework ComplianceFramework `json:"framework,omitempty"`
	Compliant bool                `json:"compliant"`
	Passed    bool                `json:"passed"` // Alias for regulatory framework compatibility
	Score     float64             `json:"score"`

	// Violations and issues
	Violations []*ComplianceViolation `json:"violations"`
	Warnings   []string               `json:"warnings,omitempty"`

	// Recommendations and evidence
	Recommendations []map[string]interface{} `json:"recommendations,omitempty"`
	Evidence        []map[string]interface{} `json:"evidence,omitempty"`
	Controls        []*ComplianceControl     `json:"controls,omitempty"`

	// Risk and timing
	RiskLevel      string        `json:"risk_level,omitempty"`
	NextAssessment time.Time     `json:"next_assessment,omitempty"`
	ValidUntil     time.Time     `json:"valid_until,omitempty"`
	ProcessingTime time.Duration `json:"processing_time,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata"`
}
