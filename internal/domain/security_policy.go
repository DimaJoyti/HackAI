package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SecurityPolicy represents a configurable security policy
type SecurityPolicy struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string    `json:"name" gorm:"not null;uniqueIndex"`
	DisplayName string    `json:"display_name" gorm:"not null"`
	Description string    `json:"description"`

	// Policy Configuration
	PolicyType string          `json:"policy_type" gorm:"not null;index"`
	Category   string          `json:"category" gorm:"not null;index"`
	Rules      json.RawMessage `json:"rules" gorm:"type:jsonb;not null"`

	// Priority and Execution
	Priority       int  `json:"priority" gorm:"default:100;index"`
	Enabled        bool `json:"enabled" gorm:"default:true;index"`
	ExecutionOrder int  `json:"execution_order" gorm:"default:0"`

	// Scope and Targeting
	Scope           string      `json:"scope" gorm:"not null;index"` // global, user, organization, provider
	TargetUsers     []uuid.UUID `json:"target_users" gorm:"type:uuid[]"`
	TargetProviders []uuid.UUID `json:"target_providers" gorm:"type:uuid[]"`
	TargetModels    []uuid.UUID `json:"target_models" gorm:"type:uuid[]"`

	// Actions and Responses
	Actions          json.RawMessage `json:"actions" gorm:"type:jsonb"`
	BlockOnViolation bool            `json:"block_on_violation" gorm:"default:false"`
	AlertOnViolation bool            `json:"alert_on_violation" gorm:"default:true"`
	LogViolations    bool            `json:"log_violations" gorm:"default:true"`

	// Thresholds and Limits
	ThreatThreshold float64 `json:"threat_threshold" gorm:"type:decimal(5,4);default:0.7"`
	MaxViolations   int     `json:"max_violations" gorm:"default:0"`
	TimeWindow      int     `json:"time_window" gorm:"default:3600"` // seconds

	// Versioning and History
	Version        string     `json:"version" gorm:"not null;index"`
	ParentPolicyID *uuid.UUID `json:"parent_policy_id" gorm:"type:uuid"`
	IsTemplate     bool       `json:"is_template" gorm:"default:false;index"`

	// Compliance and Audit
	ComplianceFrameworks []string `json:"compliance_frameworks" gorm:"type:text[]"`
	AuditRequired        bool     `json:"audit_required" gorm:"default:false"`
	RetentionPeriod      int      `json:"retention_period" gorm:"default:2592000"` // 30 days in seconds

	// Status and Lifecycle
	Status        string     `json:"status" gorm:"default:'draft';index"`
	ActivatedAt   *time.Time `json:"activated_at"`
	DeactivatedAt *time.Time `json:"deactivated_at"`
	ExpiresAt     *time.Time `json:"expires_at"`

	// Metadata
	Tags     []string        `json:"tags" gorm:"type:text[]"`
	Metadata json.RawMessage `json:"metadata" gorm:"type:jsonb"`

	// Timestamps and Ownership
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	CreatedBy uuid.UUID  `json:"created_by" gorm:"type:uuid;not null"`
	UpdatedBy *uuid.UUID `json:"updated_by" gorm:"type:uuid"`

	// Relationships
	Creator       User              `json:"creator" gorm:"foreignKey:CreatedBy"`
	Updater       *User             `json:"updater,omitempty" gorm:"foreignKey:UpdatedBy"`
	ParentPolicy  *SecurityPolicy   `json:"parent_policy,omitempty" gorm:"foreignKey:ParentPolicyID"`
	ChildPolicies []SecurityPolicy  `json:"child_policies,omitempty" gorm:"foreignKey:ParentPolicyID"`
	Violations    []PolicyViolation `json:"violations,omitempty" gorm:"foreignKey:PolicyID"`
}

// PolicyViolation represents a violation of a security policy
type PolicyViolation struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	PolicyID  uuid.UUID  `json:"policy_id" gorm:"type:uuid;not null;index"`
	RequestID string     `json:"request_id" gorm:"index"`
	UserID    *uuid.UUID `json:"user_id" gorm:"type:uuid;index"`
	SessionID *uuid.UUID `json:"session_id" gorm:"type:uuid;index"`

	// Violation Details
	ViolationType string          `json:"violation_type" gorm:"not null;index"`
	Severity      string          `json:"severity" gorm:"not null;index"`
	Description   string          `json:"description" gorm:"not null"`
	Evidence      json.RawMessage `json:"evidence" gorm:"type:jsonb"`

	// Risk Assessment
	RiskScore       float64 `json:"risk_score" gorm:"type:decimal(5,4);default:0"`
	ConfidenceScore float64 `json:"confidence_score" gorm:"type:decimal(5,4);default:0"`
	ImpactLevel     string  `json:"impact_level" gorm:"index"`

	// Response and Mitigation
	ActionTaken     string          `json:"action_taken" gorm:"index"`
	Blocked         bool            `json:"blocked" gorm:"default:false;index"`
	AlertSent       bool            `json:"alert_sent" gorm:"default:false"`
	MitigationSteps json.RawMessage `json:"mitigation_steps" gorm:"type:jsonb"`

	// Resolution
	Status     string     `json:"status" gorm:"default:'open';index"`
	ResolvedAt *time.Time `json:"resolved_at"`
	ResolvedBy *uuid.UUID `json:"resolved_by" gorm:"type:uuid"`
	Resolution string     `json:"resolution"`

	// Context
	Context   json.RawMessage `json:"context" gorm:"type:jsonb"`
	IPAddress string          `json:"ip_address" gorm:"index"`
	UserAgent string          `json:"user_agent"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" gorm:"index"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Policy         SecurityPolicy `json:"policy" gorm:"foreignKey:PolicyID"`
	User           *User          `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Session        *UserSession   `json:"session,omitempty" gorm:"foreignKey:SessionID"`
	ResolvedByUser *User          `json:"resolved_by_user,omitempty" gorm:"foreignKey:ResolvedBy"`
}

// PolicyRule represents an individual rule within a security policy
type PolicyRule struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	PolicyID    uuid.UUID `json:"policy_id" gorm:"type:uuid;not null;index"`
	Name        string    `json:"name" gorm:"not null"`
	Description string    `json:"description"`

	// Rule Configuration
	RuleType  string          `json:"rule_type" gorm:"not null;index"`
	Condition json.RawMessage `json:"condition" gorm:"type:jsonb;not null"`
	Action    json.RawMessage `json:"action" gorm:"type:jsonb;not null"`

	// Execution
	Priority int  `json:"priority" gorm:"default:100"`
	Enabled  bool `json:"enabled" gorm:"default:true;index"`

	// Thresholds
	Threshold  float64 `json:"threshold" gorm:"type:decimal(5,4);default:0.5"`
	MaxMatches int     `json:"max_matches" gorm:"default:0"`

	// Metadata
	Tags     []string        `json:"tags" gorm:"type:text[]"`
	Metadata json.RawMessage `json:"metadata" gorm:"type:jsonb"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Policy SecurityPolicy `json:"policy" gorm:"foreignKey:PolicyID"`
}

// PolicyTemplate represents a reusable policy template
type PolicyTemplate struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string    `json:"name" gorm:"not null;uniqueIndex"`
	DisplayName string    `json:"display_name" gorm:"not null"`
	Description string    `json:"description"`

	// Template Configuration
	Category   string          `json:"category" gorm:"not null;index"`
	PolicyType string          `json:"policy_type" gorm:"not null;index"`
	Template   json.RawMessage `json:"template" gorm:"type:jsonb;not null"`

	// Usage and Popularity
	UsageCount int     `json:"usage_count" gorm:"default:0"`
	Rating     float64 `json:"rating" gorm:"type:decimal(3,2);default:0"`

	// Versioning
	Version    string `json:"version" gorm:"not null"`
	IsOfficial bool   `json:"is_official" gorm:"default:false;index"`
	IsPublic   bool   `json:"is_public" gorm:"default:false;index"`

	// Compliance
	ComplianceFrameworks []string `json:"compliance_frameworks" gorm:"type:text[]"`

	// Metadata
	Tags     []string        `json:"tags" gorm:"type:text[]"`
	Metadata json.RawMessage `json:"metadata" gorm:"type:jsonb"`

	// Timestamps and Ownership
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy uuid.UUID `json:"created_by" gorm:"type:uuid;not null"`

	// Relationships
	Creator User `json:"creator" gorm:"foreignKey:CreatedBy"`
}

// PolicyExecution represents the execution history of a policy
type PolicyExecution struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	PolicyID  uuid.UUID `json:"policy_id" gorm:"type:uuid;not null;index"`
	RequestID string    `json:"request_id" gorm:"index"`

	// Execution Details
	ExecutionTime time.Time `json:"execution_time" gorm:"index"`
	Duration      int64     `json:"duration"`            // microseconds
	Result        string    `json:"result" gorm:"index"` // pass, fail, error

	// Rule Results
	RulesEvaluated int `json:"rules_evaluated" gorm:"default:0"`
	RulesPassed    int `json:"rules_passed" gorm:"default:0"`
	RulesFailed    int `json:"rules_failed" gorm:"default:0"`
	RulesErrored   int `json:"rules_errored" gorm:"default:0"`

	// Scores and Metrics
	ThreatScore     float64 `json:"threat_score" gorm:"type:decimal(5,4);default:0"`
	ConfidenceScore float64 `json:"confidence_score" gorm:"type:decimal(5,4);default:0"`

	// Actions Taken
	ActionsTaken   json.RawMessage `json:"actions_taken" gorm:"type:jsonb"`
	Blocked        bool            `json:"blocked" gorm:"default:false"`
	AlertGenerated bool            `json:"alert_generated" gorm:"default:false"`

	// Error Information
	ErrorMessage string          `json:"error_message"`
	ErrorDetails json.RawMessage `json:"error_details" gorm:"type:jsonb"`

	// Context
	Context json.RawMessage `json:"context" gorm:"type:jsonb"`

	// Relationships
	Policy SecurityPolicy `json:"policy" gorm:"foreignKey:PolicyID"`
}

// TableName methods for custom table names
func (SecurityPolicy) TableName() string {
	return "security_policies"
}

func (PolicyViolation) TableName() string {
	return "policy_violations"
}

func (PolicyRule) TableName() string {
	return "policy_rules"
}

func (PolicyTemplate) TableName() string {
	return "policy_templates"
}

func (PolicyExecution) TableName() string {
	return "policy_executions"
}

// Policy-related constants
const (
	// Policy Types
	PolicyTypeContentFilter   = "content_filter"
	PolicyTypePromptInjection = "prompt_injection"
	PolicyTypeRateLimit       = "rate_limit"
	PolicyTypeAccessControl   = "access_control"
	PolicyTypeCompliance      = "compliance"
	PolicyTypeDataLoss        = "data_loss_prevention"
	PolicyTypeAnomaly         = "anomaly_detection"

	// Policy Categories
	CategorySecurity    = "security"
	CategoryCompliance  = "compliance"
	CategoryPerformance = "performance"
	CategoryCost        = "cost"
	CategoryQuality     = "quality"

	// Policy Scopes
	ScopeGlobal       = "global"
	ScopeUser         = "user"
	ScopeOrganization = "organization"
	ScopeProvider     = "provider"
	ScopeModel        = "model"

	// Policy Status
	StatusDraft    = "draft"
	StatusActive   = "active"
	StatusInactive = "inactive"
	StatusArchived = "archived"
	StatusExpired  = "expired"

	// Violation Types
	ViolationTypePromptInjection = "prompt_injection"
	ViolationTypeContentFilter   = "content_filter"
	ViolationTypeRateLimit       = "rate_limit"
	ViolationTypeAccessDenied    = "access_denied"
	ViolationTypeCompliance      = "compliance"
	ViolationTypeDataLeak        = "data_leak"
	ViolationTypeAnomaly         = "anomaly"

	// Violation Status
	ViolationStatusOpen          = "open"
	ViolationStatusInvestigating = "investigating"
	ViolationStatusResolved      = "resolved"
	ViolationStatusFalsePositive = "false_positive"
	ViolationStatusIgnored       = "ignored"

	// Rule Types
	RuleTypeRegex     = "regex"
	RuleTypeKeyword   = "keyword"
	RuleTypeSemantic  = "semantic"
	RuleTypeML        = "machine_learning"
	RuleTypeCustom    = "custom"
	RuleTypeThreshold = "threshold"

	// Impact Levels
	ImpactLevelCritical = "critical"
	ImpactLevelHigh     = "high"
	ImpactLevelMedium   = "medium"
	ImpactLevelLow      = "low"
	ImpactLevelNone     = "none"

	// Execution Results
	ExecutionResultPass    = "pass"
	ExecutionResultFail    = "fail"
	ExecutionResultError   = "error"
	ExecutionResultSkipped = "skipped"
)
