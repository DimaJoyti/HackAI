package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// LLMRequestLog represents a logged LLM request/response interaction
type LLMRequestLog struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    *uuid.UUID `json:"user_id" gorm:"type:uuid;index"`
	SessionID *uuid.UUID `json:"session_id" gorm:"type:uuid;index"`
	RequestID string     `json:"request_id" gorm:"uniqueIndex;not null"`

	// LLM Provider Information
	Provider string `json:"provider" gorm:"not null;index"`
	Model    string `json:"model" gorm:"not null;index"`
	Endpoint string `json:"endpoint" gorm:"not null"`

	// Request Details
	PromptHash       string `json:"prompt_hash" gorm:"index"`
	PromptTokens     int    `json:"prompt_tokens" gorm:"default:0"`
	CompletionTokens int    `json:"completion_tokens" gorm:"default:0"`
	TotalTokens      int    `json:"total_tokens" gorm:"default:0"`
	RequestSize      int64  `json:"request_size" gorm:"default:0"`
	ResponseSize     int64  `json:"response_size" gorm:"default:0"`

	// Performance Metrics
	DurationMs int64 `json:"duration_ms" gorm:"default:0"`
	StatusCode int   `json:"status_code" gorm:"index"`

	// Security Analysis
	ThreatScore      float64         `json:"threat_score" gorm:"type:decimal(5,4);default:0"`
	PolicyViolations json.RawMessage `json:"policy_violations" gorm:"type:jsonb"`
	SecurityFlags    []string        `json:"security_flags" gorm:"type:text[]"`
	Blocked          bool            `json:"blocked" gorm:"default:false;index"`
	BlockReason      string          `json:"block_reason"`

	// Content Analysis
	ContentCategory   string   `json:"content_category" gorm:"index"`
	SensitivityLevel  string   `json:"sensitivity_level" gorm:"index"`
	DetectedLanguages []string `json:"detected_languages" gorm:"type:text[]"`

	// Compliance and Audit
	ComplianceFlags json.RawMessage `json:"compliance_flags" gorm:"type:jsonb"`
	RetentionPolicy string          `json:"retention_policy" gorm:"index"`
	ExpiresAt       *time.Time      `json:"expires_at" gorm:"index"`

	// Network Information
	IPAddress   string          `json:"ip_address" gorm:"index"`
	UserAgent   string          `json:"user_agent"`
	Geolocation json.RawMessage `json:"geolocation" gorm:"type:jsonb"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" gorm:"index"`

	// Relationships
	User           *User           `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Session        *UserSession    `json:"session,omitempty" gorm:"foreignKey:SessionID"`
	SecurityEvents []SecurityEvent `json:"security_events,omitempty" gorm:"foreignKey:RequestID;references:RequestID"`
}

// LLMProvider represents an LLM service provider configuration
type LLMProvider struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name         string    `json:"name" gorm:"not null;uniqueIndex"`
	DisplayName  string    `json:"display_name" gorm:"not null"`
	ProviderType string    `json:"provider_type" gorm:"not null;index"`

	// Configuration
	BaseURL    string          `json:"base_url" gorm:"not null"`
	APIVersion string          `json:"api_version"`
	AuthType   string          `json:"auth_type" gorm:"not null"`
	Config     json.RawMessage `json:"config" gorm:"type:jsonb"`

	// Capabilities
	SupportedModels []string `json:"supported_models" gorm:"type:text[]"`
	Features        []string `json:"features" gorm:"type:text[]"`
	MaxTokens       int      `json:"max_tokens" gorm:"default:0"`

	// Status and Health
	Enabled         bool       `json:"enabled" gorm:"default:true;index"`
	HealthStatus    string     `json:"health_status" gorm:"default:'unknown';index"`
	LastHealthCheck *time.Time `json:"last_health_check"`

	// Rate Limiting
	RateLimit       int `json:"rate_limit" gorm:"default:0"`
	RateLimitWindow int `json:"rate_limit_window" gorm:"default:60"`

	// Security Settings
	SecurityLevel string      `json:"security_level" gorm:"default:'standard';index"`
	AllowedUsers  []uuid.UUID `json:"allowed_users" gorm:"type:uuid[]"`
	BlockedUsers  []uuid.UUID `json:"blocked_users" gorm:"type:uuid[]"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy uuid.UUID `json:"created_by" gorm:"type:uuid"`

	// Relationships
	Creator User `json:"creator" gorm:"foreignKey:CreatedBy"`
}

// LLMModel represents a specific model available from a provider
type LLMModel struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ProviderID  uuid.UUID `json:"provider_id" gorm:"type:uuid;not null;index"`
	Name        string    `json:"name" gorm:"not null"`
	DisplayName string    `json:"display_name" gorm:"not null"`
	ModelType   string    `json:"model_type" gorm:"not null;index"`

	// Model Specifications
	MaxTokens      int        `json:"max_tokens" gorm:"default:0"`
	ContextWindow  int        `json:"context_window" gorm:"default:0"`
	TrainingCutoff *time.Time `json:"training_cutoff"`

	// Capabilities
	Capabilities     []string `json:"capabilities" gorm:"type:text[]"`
	SupportedFormats []string `json:"supported_formats" gorm:"type:text[]"`

	// Pricing and Limits
	InputTokenPrice  float64 `json:"input_token_price" gorm:"type:decimal(10,8);default:0"`
	OutputTokenPrice float64 `json:"output_token_price" gorm:"type:decimal(10,8);default:0"`

	// Status
	Enabled    bool `json:"enabled" gorm:"default:true;index"`
	Deprecated bool `json:"deprecated" gorm:"default:false;index"`

	// Security Classification
	SecurityLevel   string `json:"security_level" gorm:"default:'standard';index"`
	ComplianceLevel string `json:"compliance_level" gorm:"index"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Provider LLMProvider `json:"provider" gorm:"foreignKey:ProviderID"`
}

// LLMUsageQuota represents usage quotas for users or organizations
type LLMUsageQuota struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID         *uuid.UUID `json:"user_id" gorm:"type:uuid;index"`
	OrganizationID *uuid.UUID `json:"organization_id" gorm:"type:uuid;index"`
	ProviderID     *uuid.UUID `json:"provider_id" gorm:"type:uuid;index"`
	ModelID        *uuid.UUID `json:"model_id" gorm:"type:uuid;index"`

	// Quota Limits
	MaxRequests int     `json:"max_requests" gorm:"default:0"`
	MaxTokens   int     `json:"max_tokens" gorm:"default:0"`
	MaxCost     float64 `json:"max_cost" gorm:"type:decimal(10,4);default:0"`

	// Time Window
	WindowType  string    `json:"window_type" gorm:"not null;index"` // hourly, daily, weekly, monthly
	WindowStart time.Time `json:"window_start" gorm:"index"`
	WindowEnd   time.Time `json:"window_end" gorm:"index"`

	// Current Usage
	UsedRequests int     `json:"used_requests" gorm:"default:0"`
	UsedTokens   int     `json:"used_tokens" gorm:"default:0"`
	UsedCost     float64 `json:"used_cost" gorm:"type:decimal(10,4);default:0"`

	// Status
	Enabled    bool       `json:"enabled" gorm:"default:true;index"`
	ExceededAt *time.Time `json:"exceeded_at"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	User     *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Provider *LLMProvider `json:"provider,omitempty" gorm:"foreignKey:ProviderID"`
	Model    *LLMModel    `json:"model,omitempty" gorm:"foreignKey:ModelID"`
}

// TableName methods for custom table names
func (LLMRequestLog) TableName() string {
	return "llm_request_logs"
}

func (LLMProvider) TableName() string {
	return "llm_providers"
}

func (LLMModel) TableName() string {
	return "llm_models"
}

func (LLMUsageQuota) TableName() string {
	return "llm_usage_quotas"
}

// Enums and constants
const (
	// Event Types
	EventTypePromptInjection     = "prompt_injection"
	EventTypeContentViolation    = "content_violation"
	EventTypeRateLimitExceeded   = "rate_limit_exceeded"
	EventTypeUnauthorizedAccess  = "unauthorized_access"
	EventTypeSuspiciousActivity  = "suspicious_activity"
	EventTypeComplianceViolation = "compliance_violation"
	EventTypeSystemAnomaly       = "system_anomaly"

	// Response Status
	ResponseStatusPending    = "pending"
	ResponseStatusInProgress = "in_progress"
	ResponseStatusResolved   = "resolved"
	ResponseStatusIgnored    = "ignored"

	// Security Levels
	SecurityLevelBasic    = "basic"
	SecurityLevelStandard = "standard"
	SecurityLevelEnhanced = "enhanced"
	SecurityLevelMaximum  = "maximum"

	// Provider Types
	ProviderTypeOpenAI    = "openai"
	ProviderTypeAnthropic = "anthropic"
	ProviderTypeGoogle    = "google"
	ProviderTypeMicrosoft = "microsoft"
	ProviderTypeCustom    = "custom"

	// Model Types
	ModelTypeChat       = "chat"
	ModelTypeCompletion = "completion"
	ModelTypeEmbedding  = "embedding"
	ModelTypeImage      = "image"
	ModelTypeAudio      = "audio"

	// Window Types
	WindowTypeHourly  = "hourly"
	WindowTypeDaily   = "daily"
	WindowTypeWeekly  = "weekly"
	WindowTypeMonthly = "monthly"
)
