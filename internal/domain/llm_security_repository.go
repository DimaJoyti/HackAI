package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// LLMSecurityRepository defines the interface for LLM security data operations
type LLMSecurityRepository interface {
	// LLM Request Logs
	CreateRequestLog(ctx context.Context, log *LLMRequestLog) error
	GetRequestLog(ctx context.Context, id uuid.UUID) (*LLMRequestLog, error)
	GetRequestLogByRequestID(ctx context.Context, requestID string) (*LLMRequestLog, error)
	UpdateRequestLog(ctx context.Context, log *LLMRequestLog) error
	ListRequestLogs(ctx context.Context, filter RequestLogFilter) ([]*LLMRequestLog, error)
	DeleteRequestLog(ctx context.Context, id uuid.UUID) error
	
	// Request Log Analytics
	GetRequestLogStats(ctx context.Context, filter RequestLogFilter) (*RequestLogStats, error)
	GetThreatScoreDistribution(ctx context.Context, filter RequestLogFilter) (map[string]int, error)
	GetTopBlockedRequests(ctx context.Context, limit int, timeRange time.Duration) ([]*LLMRequestLog, error)
	GetUserActivitySummary(ctx context.Context, userID uuid.UUID, timeRange time.Duration) (*UserActivitySummary, error)
	
	// Security Events
	CreateSecurityEvent(ctx context.Context, event *SecurityEvent) error
	GetSecurityEvent(ctx context.Context, id uuid.UUID) (*SecurityEvent, error)
	UpdateSecurityEvent(ctx context.Context, event *SecurityEvent) error
	ListSecurityEvents(ctx context.Context, filter SecurityEventFilter) ([]*SecurityEvent, error)
	ResolveSecurityEvent(ctx context.Context, id uuid.UUID, resolvedBy uuid.UUID, resolution string) error
	
	// Security Event Analytics
	GetSecurityEventStats(ctx context.Context, filter SecurityEventFilter) (*SecurityEventStats, error)
	GetThreatTrends(ctx context.Context, timeRange time.Duration) (*ThreatTrends, error)
	GetTopThreats(ctx context.Context, limit int, timeRange time.Duration) ([]*ThreatSummary, error)
	
	// LLM Providers
	CreateProvider(ctx context.Context, provider *LLMProvider) error
	GetProvider(ctx context.Context, id uuid.UUID) (*LLMProvider, error)
	GetProviderByName(ctx context.Context, name string) (*LLMProvider, error)
	UpdateProvider(ctx context.Context, provider *LLMProvider) error
	ListProviders(ctx context.Context, filter ProviderFilter) ([]*LLMProvider, error)
	DeleteProvider(ctx context.Context, id uuid.UUID) error
	
	// LLM Models
	CreateModel(ctx context.Context, model *LLMModel) error
	GetModel(ctx context.Context, id uuid.UUID) (*LLMModel, error)
	UpdateModel(ctx context.Context, model *LLMModel) error
	ListModels(ctx context.Context, filter ModelFilter) ([]*LLMModel, error)
	ListModelsByProvider(ctx context.Context, providerID uuid.UUID) ([]*LLMModel, error)
	DeleteModel(ctx context.Context, id uuid.UUID) error
	
	// Usage Quotas
	CreateUsageQuota(ctx context.Context, quota *LLMUsageQuota) error
	GetUsageQuota(ctx context.Context, id uuid.UUID) (*LLMUsageQuota, error)
	UpdateUsageQuota(ctx context.Context, quota *LLMUsageQuota) error
	ListUsageQuotas(ctx context.Context, filter UsageQuotaFilter) ([]*LLMUsageQuota, error)
	GetUserQuotas(ctx context.Context, userID uuid.UUID) ([]*LLMUsageQuota, error)
	IncrementUsage(ctx context.Context, quotaID uuid.UUID, requests int, tokens int, cost float64) error
	ResetQuotaUsage(ctx context.Context, quotaID uuid.UUID) error
	
	// Bulk Operations
	BulkCreateRequestLogs(ctx context.Context, logs []*LLMRequestLog) error
	BulkUpdateRequestLogs(ctx context.Context, logs []*LLMRequestLog) error
	CleanupExpiredLogs(ctx context.Context, retentionPeriod time.Duration) (int64, error)
}

// SecurityPolicyRepository defines the interface for security policy operations
type SecurityPolicyRepository interface {
	// Security Policies
	CreatePolicy(ctx context.Context, policy *SecurityPolicy) error
	GetPolicy(ctx context.Context, id uuid.UUID) (*SecurityPolicy, error)
	GetPolicyByName(ctx context.Context, name string) (*SecurityPolicy, error)
	UpdatePolicy(ctx context.Context, policy *SecurityPolicy) error
	ListPolicies(ctx context.Context, filter PolicyFilter) ([]*SecurityPolicy, error)
	DeletePolicy(ctx context.Context, id uuid.UUID) error
	
	// Policy Activation/Deactivation
	ActivatePolicy(ctx context.Context, id uuid.UUID) error
	DeactivatePolicy(ctx context.Context, id uuid.UUID) error
	GetActivePolicies(ctx context.Context, scope string, targetID *uuid.UUID) ([]*SecurityPolicy, error)
	
	// Policy Violations
	CreateViolation(ctx context.Context, violation *PolicyViolation) error
	GetViolation(ctx context.Context, id uuid.UUID) (*PolicyViolation, error)
	UpdateViolation(ctx context.Context, violation *PolicyViolation) error
	ListViolations(ctx context.Context, filter ViolationFilter) ([]*PolicyViolation, error)
	ResolveViolation(ctx context.Context, id uuid.UUID, resolvedBy uuid.UUID, resolution string) error
	
	// Policy Rules
	CreateRule(ctx context.Context, rule *PolicyRule) error
	GetRule(ctx context.Context, id uuid.UUID) (*PolicyRule, error)
	UpdateRule(ctx context.Context, rule *PolicyRule) error
	ListRules(ctx context.Context, policyID uuid.UUID) ([]*PolicyRule, error)
	DeleteRule(ctx context.Context, id uuid.UUID) error
	
	// Policy Templates
	CreateTemplate(ctx context.Context, template *PolicyTemplate) error
	GetTemplate(ctx context.Context, id uuid.UUID) (*PolicyTemplate, error)
	UpdateTemplate(ctx context.Context, template *PolicyTemplate) error
	ListTemplates(ctx context.Context, filter TemplateFilter) ([]*PolicyTemplate, error)
	DeleteTemplate(ctx context.Context, id uuid.UUID) error
	
	// Policy Execution
	CreateExecution(ctx context.Context, execution *PolicyExecution) error
	GetExecution(ctx context.Context, id uuid.UUID) (*PolicyExecution, error)
	ListExecutions(ctx context.Context, filter ExecutionFilter) ([]*PolicyExecution, error)
	
	// Policy Analytics
	GetPolicyStats(ctx context.Context, policyID uuid.UUID, timeRange time.Duration) (*PolicyStats, error)
	GetViolationTrends(ctx context.Context, timeRange time.Duration) (*ViolationTrends, error)
	GetTopViolatedPolicies(ctx context.Context, limit int, timeRange time.Duration) ([]*PolicyViolationSummary, error)
}

// Filter structs for repository queries
type RequestLogFilter struct {
	UserID       *uuid.UUID
	Provider     *string
	Model        *string
	Blocked      *bool
	ThreatScore  *float64
	StartTime    *time.Time
	EndTime      *time.Time
	Limit        int
	Offset       int
	OrderBy      string
	OrderDesc    bool
}

type SecurityEventFilter struct {
	EventType    *string
	Severity     *string
	Source       *string
	UserID       *uuid.UUID
	Resolved     *bool
	StartTime    *time.Time
	EndTime      *time.Time
	Limit        int
	Offset       int
	OrderBy      string
	OrderDesc    bool
}

type ProviderFilter struct {
	ProviderType *string
	Enabled      *bool
	Limit        int
	Offset       int
	OrderBy      string
	OrderDesc    bool
}

type ModelFilter struct {
	ProviderID   *uuid.UUID
	ModelType    *string
	Enabled      *bool
	Limit        int
	Offset       int
	OrderBy      string
	OrderDesc    bool
}

type UsageQuotaFilter struct {
	UserID         *uuid.UUID
	ProviderID     *uuid.UUID
	ModelID        *uuid.UUID
	WindowType     *string
	Enabled        *bool
	Exceeded       *bool
	Limit          int
	Offset         int
	OrderBy        string
	OrderDesc      bool
}

type PolicyFilter struct {
	PolicyType   *string
	Category     *string
	Enabled      *bool
	Status       *string
	Scope        *string
	CreatedBy    *uuid.UUID
	Limit        int
	Offset       int
	OrderBy      string
	OrderDesc    bool
}

type ViolationFilter struct {
	PolicyID     *uuid.UUID
	UserID       *uuid.UUID
	ViolationType *string
	Severity     *string
	Status       *string
	StartTime    *time.Time
	EndTime      *time.Time
	Limit        int
	Offset       int
	OrderBy      string
	OrderDesc    bool
}

type TemplateFilter struct {
	Category     *string
	PolicyType   *string
	IsOfficial   *bool
	IsPublic     *bool
	CreatedBy    *uuid.UUID
	Limit        int
	Offset       int
	OrderBy      string
	OrderDesc    bool
}

type ExecutionFilter struct {
	PolicyID     *uuid.UUID
	RequestID    *string
	Result       *string
	StartTime    *time.Time
	EndTime      *time.Time
	Limit        int
	Offset       int
	OrderBy      string
	OrderDesc    bool
}

// Analytics and statistics structs
type RequestLogStats struct {
	TotalRequests    int64   `json:"total_requests"`
	BlockedRequests  int64   `json:"blocked_requests"`
	AverageThreatScore float64 `json:"average_threat_score"`
	TotalTokens      int64   `json:"total_tokens"`
	AverageDuration  float64 `json:"average_duration"`
	TopProviders     []ProviderUsage `json:"top_providers"`
	TopModels        []ModelUsage `json:"top_models"`
}

type ProviderUsage struct {
	Provider string `json:"provider"`
	Count    int64  `json:"count"`
	Tokens   int64  `json:"tokens"`
}

type ModelUsage struct {
	Model  string `json:"model"`
	Count  int64  `json:"count"`
	Tokens int64  `json:"tokens"`
}

type UserActivitySummary struct {
	UserID          uuid.UUID `json:"user_id"`
	TotalRequests   int64     `json:"total_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	TotalTokens     int64     `json:"total_tokens"`
	AverageThreatScore float64 `json:"average_threat_score"`
	LastActivity    time.Time `json:"last_activity"`
}

type SecurityEventStats struct {
	TotalEvents      int64 `json:"total_events"`
	ResolvedEvents   int64 `json:"resolved_events"`
	CriticalEvents   int64 `json:"critical_events"`
	HighEvents       int64 `json:"high_events"`
	MediumEvents     int64 `json:"medium_events"`
	LowEvents        int64 `json:"low_events"`
}

type ThreatTrends struct {
	TimeRange    string                    `json:"time_range"`
	DataPoints   []ThreatTrendDataPoint    `json:"data_points"`
	TopThreats   []ThreatSummary          `json:"top_threats"`
}

type ThreatTrendDataPoint struct {
	Timestamp    time.Time `json:"timestamp"`
	ThreatCount  int64     `json:"threat_count"`
	ThreatScore  float64   `json:"threat_score"`
}

type ThreatSummary struct {
	ThreatType   string  `json:"threat_type"`
	Count        int64   `json:"count"`
	AverageScore float64 `json:"average_score"`
	LastSeen     time.Time `json:"last_seen"`
}


type PolicyStats struct {
	PolicyID         uuid.UUID `json:"policy_id"`
	ExecutionCount   int64     `json:"execution_count"`
	ViolationCount   int64     `json:"violation_count"`
	BlockCount       int64     `json:"block_count"`
	AverageScore     float64   `json:"average_score"`
	LastExecution    time.Time `json:"last_execution"`
}

type ViolationTrends struct {
	TimeRange    string                      `json:"time_range"`
	DataPoints   []ViolationTrendDataPoint   `json:"data_points"`
	TopViolations []PolicyViolationSummary   `json:"top_violations"`
}

type ViolationTrendDataPoint struct {
	Timestamp       time.Time `json:"timestamp"`
	ViolationCount  int64     `json:"violation_count"`
	BlockCount      int64     `json:"block_count"`
}

type PolicyViolationSummary struct {
	PolicyID     uuid.UUID `json:"policy_id"`
	PolicyName   string    `json:"policy_name"`
	Count        int64     `json:"count"`
	BlockCount   int64     `json:"block_count"`
	LastViolation time.Time `json:"last_violation"`
}
