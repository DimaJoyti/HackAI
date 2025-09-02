package domain

import (
	"time"

	"github.com/google/uuid"
)

// Model represents an AI model in the system
type Model struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name         string    `json:"name" gorm:"unique;not null;index"`
	Provider     string    `json:"provider" gorm:"not null;index"`
	Version      string    `json:"version" gorm:"not null"`
	Type         string    `json:"type" gorm:"not null;index"` // e.g., "text", "embedding", "chat"
	Size         int64     `json:"size"`                       // Model size in bytes
	Status       string    `json:"status" gorm:"not null;index"`
	Description  string    `json:"description"`
	Capabilities []string  `json:"capabilities" gorm:"type:text[]"`
	Parameters   int64     `json:"parameters"` // Number of parameters
	ContextSize  int       `json:"context_size"`

	// Configuration
	Config   map[string]interface{} `json:"config" gorm:"type:jsonb"`
	Metadata map[string]interface{} `json:"metadata" gorm:"type:jsonb"`

	// Usage statistics
	UsageCount  int64      `json:"usage_count" gorm:"default:0"`
	LastUsed    *time.Time `json:"last_used"`
	TotalTokens int64      `json:"total_tokens" gorm:"default:0"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" gorm:"index"`
	UpdatedAt time.Time `json:"updated_at" gorm:"index"`

	// Relationships
	Deployments []ModelDeployment `json:"deployments,omitempty" gorm:"foreignKey:ModelID"`
}

// ModelDeployment represents a deployment of a model
type ModelDeployment struct {
	ID       uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ModelID  uuid.UUID `json:"model_id" gorm:"type:uuid;not null;index"`
	Name     string    `json:"name" gorm:"not null;index"`
	Status   string    `json:"status" gorm:"not null;index"`
	Endpoint string    `json:"endpoint"`
	Port     int       `json:"port"`
	Replicas int       `json:"replicas" gorm:"default:1"`

	// Resource allocation
	CPULimit    string `json:"cpu_limit"`
	MemoryLimit string `json:"memory_limit"`
	GPULimit    string `json:"gpu_limit"`

	// Configuration
	Config      map[string]interface{} `json:"config" gorm:"type:jsonb"`
	Environment map[string]string      `json:"environment" gorm:"type:jsonb"`

	// Health and metrics
	HealthStatus    string     `json:"health_status" gorm:"index"`
	LastHealthCheck *time.Time `json:"last_health_check"`
	RequestCount    int64      `json:"request_count" gorm:"default:0"`
	ErrorCount      int64      `json:"error_count" gorm:"default:0"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" gorm:"index"`
	UpdatedAt time.Time `json:"updated_at" gorm:"index"`

	// Relationships
	Model *Model `json:"model,omitempty" gorm:"foreignKey:ModelID"`
}

// ModelRepository defines the interface for model data access
type ModelRepository interface {
	// Model CRUD operations
	Create(model *Model) error
	GetByID(id uuid.UUID) (*Model, error)
	GetByName(name string) (*Model, error)
	Update(model *Model) error
	Delete(id uuid.UUID) error
	List(filters map[string]interface{}, limit, offset int) ([]*Model, error)

	// Model queries
	ListByProvider(provider string) ([]*Model, error)
	ListByType(modelType string) ([]*Model, error)
	ListByStatus(status string) ([]*Model, error)
	Search(query string, filters map[string]interface{}) ([]*Model, error)

	// Usage tracking
	UpdateUsage(id uuid.UUID, tokens int64) error
	GetUsageStats(id uuid.UUID) (*ModelUsageStats, error)

	// Deployment operations
	CreateDeployment(deployment *ModelDeployment) error
	GetDeployment(id uuid.UUID) (*ModelDeployment, error)
	UpdateDeployment(deployment *ModelDeployment) error
	DeleteDeployment(id uuid.UUID) error
	ListDeployments(modelID uuid.UUID) ([]*ModelDeployment, error)
	ListAllDeployments() ([]*ModelDeployment, error)
}

// ModelUsageStats represents usage statistics for a model
type ModelUsageStats struct {
	ModelID        uuid.UUID    `json:"model_id"`
	TotalRequests  int64        `json:"total_requests"`
	TotalTokens    int64        `json:"total_tokens"`
	AverageLatency float64      `json:"average_latency"`
	ErrorRate      float64      `json:"error_rate"`
	LastUsed       *time.Time   `json:"last_used"`
	UsageByDay     []DailyUsage `json:"usage_by_day"`
}

// DailyUsage represents daily usage statistics
type DailyUsage struct {
	Date     time.Time `json:"date"`
	Requests int64     `json:"requests"`
	Tokens   int64     `json:"tokens"`
	Errors   int64     `json:"errors"`
}

// Model status constants
const (
	ModelStatusAvailable   = "available"
	ModelStatusDownloading = "downloading"
	ModelStatusError       = "error"
	ModelStatusUnavailable = "unavailable"
	ModelStatusDeprecated  = "deprecated"
)

// Model type constants
const (
	ModelTypeText   = "text"
	ModelTypeCode   = "code"
	ModelTypeVision = "vision"
)

// Deployment status constants
const (
	DeploymentStatusPending = "pending"
	DeploymentStatusRunning = "running"
	DeploymentStatusStopped = "stopped"
	DeploymentStatusError   = "error"
	DeploymentStatusScaling = "scaling"
)

// Health status constants
const (
	HealthStatusHealthy   = "healthy"
	HealthStatusUnhealthy = "unhealthy"
	HealthStatusUnknown   = "unknown"
)
