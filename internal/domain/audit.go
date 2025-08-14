package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AuditLog represents a comprehensive audit log entry
type AuditLog struct {
	ID           uuid.UUID   `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID       *uuid.UUID  `json:"user_id,omitempty" gorm:"type:uuid;index"`
	SessionID    *uuid.UUID  `json:"session_id,omitempty" gorm:"type:uuid;index"`
	Action       string      `json:"action" gorm:"not null;index"`
	Resource     string      `json:"resource" gorm:"not null;index"`
	ResourceID   *uuid.UUID  `json:"resource_id,omitempty" gorm:"type:uuid;index"`
	Method       string      `json:"method" gorm:"index"` // HTTP method or operation type
	Path         string      `json:"path"`                // API path or operation path
	IPAddress    string      `json:"ip_address" gorm:"index"`
	UserAgent    string      `json:"user_agent"`
	Status       AuditStatus `json:"status" gorm:"index"`
	StatusCode   int         `json:"status_code"`   // HTTP status code or operation result
	Duration     int64       `json:"duration"`      // Duration in milliseconds
	RequestSize  int64       `json:"request_size"`  // Request size in bytes
	ResponseSize int64       `json:"response_size"` // Response size in bytes

	// Detailed information
	Details  json.RawMessage `json:"details" gorm:"type:jsonb"`  // Additional details as JSON
	Changes  json.RawMessage `json:"changes" gorm:"type:jsonb"`  // Before/after changes
	Metadata json.RawMessage `json:"metadata" gorm:"type:jsonb"` // Additional metadata

	// Security context
	RiskLevel RiskLevel `json:"risk_level" gorm:"index"`
	Severity  Severity  `json:"severity" gorm:"index"`
	Tags      []string  `json:"tags" gorm:"type:text[]"` // Searchable tags

	// Compliance and retention
	RetentionPolicy string     `json:"retention_policy" gorm:"index"`
	ExpiresAt       *time.Time `json:"expires_at" gorm:"index"`

	// Audit fields
	CreatedAt time.Time `json:"created_at" gorm:"index"`

	// Relationships
	User    *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Session *UserSession `json:"session,omitempty" gorm:"foreignKey:SessionID"`
}

// AuditStatus represents the status of an audited action
type AuditStatus string

const (
	AuditStatusSuccess AuditStatus = "success"
	AuditStatusFailure AuditStatus = "failure"
	AuditStatusError   AuditStatus = "error"
	AuditStatusWarning AuditStatus = "warning"
)

// RiskLevel represents the risk level of an action
type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "critical"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelLow      RiskLevel = "low"
	RiskLevelInfo     RiskLevel = "info"
)

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID          uuid.UUID   `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Type        string      `json:"type" gorm:"not null;index"`
	Category    string      `json:"category" gorm:"not null;index"`
	Title       string      `json:"title" gorm:"not null"`
	Description string      `json:"description"`
	Severity    Severity    `json:"severity" gorm:"index"`
	Status      EventStatus `json:"status" gorm:"index"`

	// Source information
	SourceIP   string `json:"source_ip" gorm:"index"`
	SourcePort int    `json:"source_port"`
	TargetIP   string `json:"target_ip" gorm:"index"`
	TargetPort int    `json:"target_port"`
	Protocol   string `json:"protocol"`

	// Detection information
	DetectedBy    string  `json:"detected_by"` // System/tool that detected the event
	Confidence    float64 `json:"confidence"`  // Detection confidence (0-1)
	FalsePositive bool    `json:"false_positive"`

	// Event data
	RawData    json.RawMessage `json:"raw_data" gorm:"type:jsonb"`
	Indicators json.RawMessage `json:"indicators" gorm:"type:jsonb"`
	Evidence   json.RawMessage `json:"evidence" gorm:"type:jsonb"`

	// Response information
	AssignedTo *uuid.UUID `json:"assigned_to,omitempty" gorm:"type:uuid"`
	ResolvedBy *uuid.UUID `json:"resolved_by,omitempty" gorm:"type:uuid"`
	ResolvedAt *time.Time `json:"resolved_at"`
	Resolution string     `json:"resolution"`

	// Audit fields
	CreatedAt time.Time `json:"created_at" gorm:"index"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	AssignedUser *User `json:"assigned_user,omitempty" gorm:"foreignKey:AssignedTo"`
	ResolvedUser *User `json:"resolved_user,omitempty" gorm:"foreignKey:ResolvedBy"`
}

// EventStatus represents the status of a security event
type EventStatus string

const (
	EventStatusOpen       EventStatus = "open"
	EventStatusInProgress EventStatus = "in_progress"
	EventStatusResolved   EventStatus = "resolved"
	EventStatusClosed     EventStatus = "closed"
	EventStatusIgnored    EventStatus = "ignored"
)

// ThreatIntelligence represents threat intelligence data
type ThreatIntelligence struct {
	ID         uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Type       string    `json:"type" gorm:"not null;index"`   // ip, domain, url, hash, etc.
	Value      string    `json:"value" gorm:"not null;index"`  // The actual indicator value
	Source     string    `json:"source" gorm:"not null;index"` // Source of intelligence
	Confidence float64   `json:"confidence"`                   // Confidence level (0-1)
	Severity   Severity  `json:"severity" gorm:"index"`

	// Threat information
	ThreatType string `json:"threat_type" gorm:"index"` // malware, phishing, etc.
	Campaign   string `json:"campaign"`                 // Associated campaign
	Actor      string `json:"actor"`                    // Threat actor

	// Context information
	Description string   `json:"description"`
	Tags        []string `json:"tags" gorm:"type:text[]"`
	References  []string `json:"references" gorm:"type:text[]"`

	// Metadata
	FirstSeen time.Time  `json:"first_seen" gorm:"index"`
	LastSeen  time.Time  `json:"last_seen" gorm:"index"`
	ExpiresAt *time.Time `json:"expires_at" gorm:"index"`

	// Additional data
	Metadata json.RawMessage `json:"metadata" gorm:"type:jsonb"`

	// Audit fields
	CreatedAt time.Time `json:"created_at" gorm:"index"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DataRetentionPolicy represents data retention policies
type DataRetentionPolicy struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string    `json:"name" gorm:"not null;uniqueIndex"`
	Description string    `json:"description"`

	// Policy configuration
	DataType      string `json:"data_type" gorm:"not null;index"` // audit_logs, security_events, etc.
	RetentionDays int    `json:"retention_days" gorm:"not null"`  // Days to retain data
	ArchiveDays   int    `json:"archive_days"`                    // Days before archiving

	// Conditions
	Conditions json.RawMessage `json:"conditions" gorm:"type:jsonb"` // JSON conditions for policy application

	// Status
	Enabled bool `json:"enabled" gorm:"default:true"`

	// Audit fields
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy uuid.UUID `json:"created_by" gorm:"type:uuid"`

	// Relationships
	Creator User `json:"creator" gorm:"foreignKey:CreatedBy"`
}

// SystemMetrics represents system performance and usage metrics
type SystemMetrics struct {
	ID         uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	MetricType string    `json:"metric_type" gorm:"not null;index"`
	MetricName string    `json:"metric_name" gorm:"not null;index"`
	Value      float64   `json:"value"`
	Unit       string    `json:"unit"`

	// Context
	Service     string `json:"service" gorm:"index"`
	Instance    string `json:"instance" gorm:"index"`
	Environment string `json:"environment" gorm:"index"`

	// Labels and metadata
	Labels   json.RawMessage `json:"labels" gorm:"type:jsonb"`
	Metadata json.RawMessage `json:"metadata" gorm:"type:jsonb"`

	// Timestamp
	Timestamp time.Time `json:"timestamp" gorm:"index"`
	CreatedAt time.Time `json:"created_at"`
}

// BackupRecord represents database backup records
type BackupRecord struct {
	ID     uuid.UUID    `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Type   string       `json:"type" gorm:"not null;index"` // full, incremental, differential
	Status BackupStatus `json:"status" gorm:"index"`

	// Backup information
	FileName string `json:"file_name" gorm:"not null"`
	FilePath string `json:"file_path" gorm:"not null"`
	FileSize int64  `json:"file_size"` // Size in bytes
	Checksum string `json:"checksum"`  // File checksum for integrity

	// Timing
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Duration    int64      `json:"duration"` // Duration in seconds

	// Configuration
	Compression bool `json:"compression"`
	Encryption  bool `json:"encryption"`

	// Metadata
	DatabaseSize int64 `json:"database_size"` // Database size at backup time
	TableCount   int   `json:"table_count"`
	RecordCount  int64 `json:"record_count"`

	// Error information
	ErrorMessage string `json:"error_message"`

	// Audit fields
	CreatedAt time.Time `json:"created_at"`
	CreatedBy uuid.UUID `json:"created_by" gorm:"type:uuid"`

	// Relationships
	Creator User `json:"creator" gorm:"foreignKey:CreatedBy"`
}

// BackupStatus represents backup status
type BackupStatus string

const (
	BackupStatusPending   BackupStatus = "pending"
	BackupStatusRunning   BackupStatus = "running"
	BackupStatusCompleted BackupStatus = "completed"
	BackupStatusFailed    BackupStatus = "failed"
	BackupStatusCancelled BackupStatus = "cancelled"
)

// AuditRepository defines the interface for audit data access
type AuditRepository interface {
	// Audit logs
	CreateAuditLog(log *AuditLog) error
	GetAuditLog(id uuid.UUID) (*AuditLog, error)
	ListAuditLogs(filters map[string]interface{}, limit, offset int) ([]*AuditLog, error)
	SearchAuditLogs(query string, filters map[string]interface{}, limit, offset int) ([]*AuditLog, error)
	DeleteExpiredAuditLogs(before time.Time) (int64, error)

	// Security events
	CreateSecurityEvent(event *SecurityEvent) error
	GetSecurityEvent(id uuid.UUID) (*SecurityEvent, error)
	UpdateSecurityEvent(event *SecurityEvent) error
	ListSecurityEvents(filters map[string]interface{}, limit, offset int) ([]*SecurityEvent, error)

	// Threat intelligence
	CreateThreatIntelligence(intel *ThreatIntelligence) error
	GetThreatIntelligence(id uuid.UUID) (*ThreatIntelligence, error)
	UpdateThreatIntelligence(intel *ThreatIntelligence) error
	FindThreatIntelligence(value string) (*ThreatIntelligence, error)
	ListThreatIntelligence(filters map[string]interface{}, limit, offset int) ([]*ThreatIntelligence, error)

	// System metrics
	CreateSystemMetrics(metrics []*SystemMetrics) error
	GetSystemMetrics(filters map[string]interface{}, from, to time.Time) ([]*SystemMetrics, error)
	DeleteOldMetrics(before time.Time) (int64, error)

	// Backup records
	CreateBackupRecord(record *BackupRecord) error
	GetBackupRecord(id uuid.UUID) (*BackupRecord, error)
	UpdateBackupRecord(record *BackupRecord) error
	ListBackupRecords(limit, offset int) ([]*BackupRecord, error)

	// Helper methods for audit logging
	LogUserAction(userID uuid.UUID, sessionID *uuid.UUID, action, resource string, details map[string]interface{}) error
	LogSecurityAction(userID *uuid.UUID, action, resource string, riskLevel RiskLevel, details map[string]interface{}) error
	LogAPICall(userID *uuid.UUID, method, path, ipAddress, userAgent string, statusCode int, duration int64) error
}

// TableName returns the table name for AuditLog model
func (AuditLog) TableName() string {
	return "audit_logs"
}

// TableName returns the table name for SecurityEvent model
func (SecurityEvent) TableName() string {
	return "security_events"
}

// TableName returns the table name for ThreatIntelligence model
func (ThreatIntelligence) TableName() string {
	return "threat_intelligence"
}

// TableName returns the table name for DataRetentionPolicy model
func (DataRetentionPolicy) TableName() string {
	return "data_retention_policies"
}

// TableName returns the table name for SystemMetrics model
func (SystemMetrics) TableName() string {
	return "system_metrics"
}

// TableName returns the table name for BackupRecord model
func (BackupRecord) TableName() string {
	return "backup_records"
}

// IsExpired checks if threat intelligence is expired
func (t *ThreatIntelligence) IsExpired() bool {
	return t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt)
}

// IsActive checks if threat intelligence is still active
func (t *ThreatIntelligence) IsActive() bool {
	return !t.IsExpired()
}

// IsCompleted checks if backup is completed
func (b *BackupRecord) IsCompleted() bool {
	return b.Status == BackupStatusCompleted
}

// IsRunning checks if backup is currently running
func (b *BackupRecord) IsRunning() bool {
	return b.Status == BackupStatusRunning || b.Status == BackupStatusPending
}
