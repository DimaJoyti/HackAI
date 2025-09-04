package dropzones

import (
	"context"
	"time"
)

// DropZoneData represents data submitted to a dropzone
type DropZoneData struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Content   string                 `json:"content"`
	Size      int64                  `json:"size"`
	Checksum  string                 `json:"checksum"`
	Priority  int                    `json:"priority"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// DropZone represents a data processing dropzone
type DropZone struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Type             string                 `json:"type"`
	Description      string                 `json:"description"`
	Configuration    map[string]interface{} `json:"configuration"`
	Config           *DropZoneConfig        `json:"config"`
	Status           string                 `json:"status"`
	ActiveAgents     []string               `json:"active_agents"`
	QueuedRequests   int                    `json:"queued_requests"`
	ProcessingCount  int                    `json:"processing_count"`
	TotalProcessed   int64                  `json:"total_processed"`
	LastActivity     time.Time              `json:"last_activity"`
	Metrics          *DropZoneMetrics       `json:"metrics"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	
	// Internal fields
	ctx    context.Context    `json:"-"`
	cancel context.CancelFunc `json:"-"`
}

// ProcessingRequest represents a processing request
type ProcessingRequest struct {
	ID          string                 `json:"id"`
	DropZoneID  string                 `json:"dropzone_id"`
	Data        *DropZoneData          `json:"data"`
	AgentIDs    []string               `json:"agent_ids"`
	Options     map[string]interface{} `json:"options"`
	Timeout     time.Duration          `json:"timeout"`
	Priority    int                    `json:"priority"`
	Status      string                 `json:"status"`
	Progress    float64                `json:"progress"`
	StartedAt   time.Time              `json:"started_at"`
	SubmittedAt time.Time              `json:"submitted_at"`
	SubmittedBy string                 `json:"submitted_by"`
	CompletedAt *time.Time             `json:"completed_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ProcessingResult represents a processing result
type ProcessingResult struct {
	ID              string                 `json:"id"`
	RequestID       string                 `json:"request_id"`
	Status          string                 `json:"status"`
	Data            interface{}            `json:"data"`
	Results         map[string]interface{} `json:"results"`
	RequiredAgents  []string               `json:"required_agents"`
	ProcessedBy     []string               `json:"processed_by"`
	ThreatLevel     string                 `json:"threat_level"`
	Confidence      float64                `json:"confidence"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         *time.Time             `json:"end_time"`
	Duration        time.Duration          `json:"duration"`
	Errors          []string               `json:"errors"`
	Metadata        map[string]interface{} `json:"metadata"`
	Timestamp       time.Time              `json:"timestamp"`
}

// DropZoneEvent represents an event in the dropzone system
type DropZoneEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	DropZoneID  string                 `json:"dropzone_id"`
	RequestID   string                 `json:"request_id"`
	Severity    string                 `json:"severity"`
	Data        interface{}            `json:"data"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
}

// DropZoneRouter handles routing logic
type DropZoneRouter interface {
	Route(ctx interface{}, request *ProcessingRequest) (*ProcessingResult, error)
	RegisterDropZone(ctx context.Context, dropZone *DropZone) error
	UnregisterDropZone(ctx context.Context, dropZoneID string) error
}

// AgentCoordinator coordinates agent activities
type AgentCoordinator interface {
	Coordinate(ctx interface{}, request *ProcessingRequest) (*ProcessingResult, error)
	AssignAgents(ctx context.Context, request *ProcessingRequest) ([]string, error)
	ReleaseAgents(ctx context.Context, agentIDs []string) error
}

// ContentAnalyzer analyzes content
type ContentAnalyzer interface {
	Analyze(ctx interface{}, data *DropZoneData) (*ProcessingResult, error)
	AnalyzeContent(ctx context.Context, data *DropZoneData) (*ProcessingResult, error)
	ValidateContent(ctx context.Context, data *DropZoneData, rules map[string]interface{}) error
}

// DropZoneConfig represents dropzone configuration
type DropZoneConfig struct {
	ID                string                 `json:"id"`
	Type              string                 `json:"type"`
	MaxConcurrent     int                    `json:"max_concurrent"`
	MaxDataSize       int64                  `json:"max_data_size"`
	MaxQueueSize      int                    `json:"max_queue_size"`
	Timeout           time.Duration          `json:"timeout"`
	ProcessingTimeout time.Duration          `json:"processing_timeout"`
	RetryLimit        int                    `json:"retry_limit"`
	AgentTypes        []string               `json:"agent_types"`
	AllowedDataTypes  []string               `json:"allowed_data_types"`
	SecurityLevel     string                 `json:"security_level"`
	UpdatedAt         time.Time              `json:"updated_at"`
	Configuration     map[string]interface{} `json:"configuration"`
}

// DropZoneMetrics represents dropzone metrics
type DropZoneMetrics struct {
	ProcessingTime       time.Duration          `json:"processing_time"`
	ThroughputPerSec     float64                `json:"throughput_per_sec"`
	ThroughputPerSecond  float64                `json:"throughput_per_second"`
	TotalRequests        int64                  `json:"total_requests"`
	SuccessfulRequests   int64                  `json:"successful_requests"`
	FailedRequests       int64                  `json:"failed_requests"`
	QueueDepth           int                    `json:"queue_depth"`
	ErrorRate            float64                `json:"error_rate"`
	SuccessRate          float64                `json:"success_rate"`
	AverageLatency       time.Duration          `json:"average_latency"`
	PeakLatency          time.Duration          `json:"peak_latency"`
	LastUpdated          time.Time              `json:"last_updated"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// DropZone status constants
const (
	DropZoneStatusActive      = "active"
	DropZoneStatusInactive    = "inactive"
	DropZoneStatusMaintenance = "maintenance"
	DropZoneStatusOverloaded  = "overloaded"
	DropZoneStatusError       = "error"
)

// Event type constants
const (
	EventTypeDropZoneStatus     = "dropzone_status"
	EventTypeDataSubmitted      = "data_submitted"
	EventTypeProcessing         = "processing"
	EventTypeProcessingStarted  = "processing_started"
	EventTypeProcessingCompleted = "processing_completed"
	EventTypeProcessingFailed   = "processing_failed"
	EventTypeError              = "error"
)

// Processing status constants
const (
	ProcessingStatusPending    = "pending"
	ProcessingStatusProcessing = "processing"
	ProcessingStatusCompleted  = "completed"
	ProcessingStatusFailed     = "failed"
	ProcessingStatusCancelled  = "cancelled"
)