package repository

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// AuditRepository implements the domain.AuditRepository interface
type AuditRepository struct {
	db     *gorm.DB
	logger *logger.Logger
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(db *gorm.DB, log *logger.Logger) domain.AuditRepository {
	return &AuditRepository{
		db:     db,
		logger: log,
	}
}

// CreateAuditLog creates a new audit log entry
func (r *AuditRepository) CreateAuditLog(log *domain.AuditLog) error {
	return r.db.Create(log).Error
}

// GetAuditLog retrieves an audit log by ID
func (r *AuditRepository) GetAuditLog(id uuid.UUID) (*domain.AuditLog, error) {
	var log domain.AuditLog
	err := r.db.Preload("User").Preload("Session").First(&log, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &log, nil
}

// ListAuditLogs retrieves audit logs with filters
func (r *AuditRepository) ListAuditLogs(filters map[string]interface{}, limit, offset int) ([]*domain.AuditLog, error) {
	var logs []*domain.AuditLog

	query := r.db.Preload("User").Preload("Session")

	// Apply filters
	for key, value := range filters {
		switch key {
		case "user_id":
			if userID, ok := value.(uuid.UUID); ok {
				query = query.Where("user_id = ?", userID)
			}
		case "action":
			query = query.Where("action = ?", value)
		case "resource":
			query = query.Where("resource = ?", value)
		case "status":
			query = query.Where("status = ?", value)
		case "risk_level":
			query = query.Where("risk_level = ?", value)
		case "severity":
			query = query.Where("severity = ?", value)
		case "ip_address":
			query = query.Where("ip_address = ?", value)
		case "from_date":
			if date, ok := value.(time.Time); ok {
				query = query.Where("created_at >= ?", date)
			}
		case "to_date":
			if date, ok := value.(time.Time); ok {
				query = query.Where("created_at <= ?", date)
			}
		case "tags":
			if tags, ok := value.([]string); ok && len(tags) > 0 {
				query = query.Where("tags && ?", tags)
			}
		}
	}

	err := query.Order("created_at DESC").Limit(limit).Offset(offset).Find(&logs).Error
	return logs, err
}

// SearchAuditLogs searches audit logs with text query
func (r *AuditRepository) SearchAuditLogs(query string, filters map[string]interface{}, limit, offset int) ([]*domain.AuditLog, error) {
	var logs []*domain.AuditLog

	dbQuery := r.db.Preload("User").Preload("Session")

	// Apply text search
	if query != "" {
		searchPattern := fmt.Sprintf("%%%s%%", query)
		dbQuery = dbQuery.Where(
			"action ILIKE ? OR resource ILIKE ? OR path ILIKE ? OR details::text ILIKE ?",
			searchPattern, searchPattern, searchPattern, searchPattern,
		)
	}

	// Apply additional filters
	for key, value := range filters {
		switch key {
		case "user_id":
			if userID, ok := value.(uuid.UUID); ok {
				dbQuery = dbQuery.Where("user_id = ?", userID)
			}
		case "status":
			dbQuery = dbQuery.Where("status = ?", value)
		case "risk_level":
			dbQuery = dbQuery.Where("risk_level = ?", value)
		case "from_date":
			if date, ok := value.(time.Time); ok {
				dbQuery = dbQuery.Where("created_at >= ?", date)
			}
		case "to_date":
			if date, ok := value.(time.Time); ok {
				dbQuery = dbQuery.Where("created_at <= ?", date)
			}
		}
	}

	err := dbQuery.Order("created_at DESC").Limit(limit).Offset(offset).Find(&logs).Error
	return logs, err
}

// DeleteExpiredAuditLogs deletes audit logs older than the specified date
func (r *AuditRepository) DeleteExpiredAuditLogs(before time.Time) (int64, error) {
	result := r.db.Where("created_at < ?", before).Delete(&domain.AuditLog{})
	return result.RowsAffected, result.Error
}

// CreateSecurityEvent creates a new security event
func (r *AuditRepository) CreateSecurityEvent(event *domain.SecurityEvent) error {
	return r.db.Create(event).Error
}

// GetSecurityEvent retrieves a security event by ID
func (r *AuditRepository) GetSecurityEvent(id uuid.UUID) (*domain.SecurityEvent, error) {
	var event domain.SecurityEvent
	err := r.db.Preload("AssignedUser").Preload("ResolvedUser").First(&event, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &event, nil
}

// UpdateSecurityEvent updates a security event
func (r *AuditRepository) UpdateSecurityEvent(event *domain.SecurityEvent) error {
	return r.db.Save(event).Error
}

// ListSecurityEvents retrieves security events with filters
func (r *AuditRepository) ListSecurityEvents(filters map[string]interface{}, limit, offset int) ([]*domain.SecurityEvent, error) {
	var events []*domain.SecurityEvent

	query := r.db.Preload("AssignedUser").Preload("ResolvedUser")

	// Apply filters
	for key, value := range filters {
		switch key {
		case "type":
			query = query.Where("type = ?", value)
		case "category":
			query = query.Where("category = ?", value)
		case "severity":
			query = query.Where("severity = ?", value)
		case "status":
			query = query.Where("status = ?", value)
		case "source_ip":
			query = query.Where("source_ip = ?", value)
		case "target_ip":
			query = query.Where("target_ip = ?", value)
		case "assigned_to":
			if userID, ok := value.(uuid.UUID); ok {
				query = query.Where("assigned_to = ?", userID)
			}
		case "from_date":
			if date, ok := value.(time.Time); ok {
				query = query.Where("created_at >= ?", date)
			}
		case "to_date":
			if date, ok := value.(time.Time); ok {
				query = query.Where("created_at <= ?", date)
			}
		case "false_positive":
			query = query.Where("false_positive = ?", value)
		}
	}

	err := query.Order("created_at DESC").Limit(limit).Offset(offset).Find(&events).Error
	return events, err
}

// CreateThreatIntelligence creates a new threat intelligence record
func (r *AuditRepository) CreateThreatIntelligence(intel *domain.ThreatIntelligence) error {
	return r.db.Create(intel).Error
}

// GetThreatIntelligence retrieves threat intelligence by ID
func (r *AuditRepository) GetThreatIntelligence(id uuid.UUID) (*domain.ThreatIntelligence, error) {
	var intel domain.ThreatIntelligence
	err := r.db.First(&intel, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &intel, nil
}

// UpdateThreatIntelligence updates threat intelligence
func (r *AuditRepository) UpdateThreatIntelligence(intel *domain.ThreatIntelligence) error {
	return r.db.Save(intel).Error
}

// FindThreatIntelligence finds threat intelligence by value
func (r *AuditRepository) FindThreatIntelligence(value string) (*domain.ThreatIntelligence, error) {
	var intel domain.ThreatIntelligence
	err := r.db.Where("value = ?", value).First(&intel).Error
	if err != nil {
		return nil, err
	}
	return &intel, nil
}

// ListThreatIntelligence retrieves threat intelligence with filters
func (r *AuditRepository) ListThreatIntelligence(filters map[string]interface{}, limit, offset int) ([]*domain.ThreatIntelligence, error) {
	var intel []*domain.ThreatIntelligence

	query := r.db.Model(&domain.ThreatIntelligence{})

	// Apply filters
	for key, value := range filters {
		switch key {
		case "type":
			query = query.Where("type = ?", value)
		case "source":
			query = query.Where("source = ?", value)
		case "severity":
			query = query.Where("severity = ?", value)
		case "threat_type":
			query = query.Where("threat_type = ?", value)
		case "campaign":
			query = query.Where("campaign = ?", value)
		case "actor":
			query = query.Where("actor = ?", value)
		case "active_only":
			if active, ok := value.(bool); ok && active {
				query = query.Where("expires_at IS NULL OR expires_at > ?", time.Now())
			}
		case "tags":
			if tags, ok := value.([]string); ok && len(tags) > 0 {
				query = query.Where("tags && ?", tags)
			}
		}
	}

	err := query.Order("last_seen DESC").Limit(limit).Offset(offset).Find(&intel).Error
	return intel, err
}

// CreateSystemMetrics creates system metrics records
func (r *AuditRepository) CreateSystemMetrics(metrics []*domain.SystemMetrics) error {
	if len(metrics) == 0 {
		return nil
	}

	// Use batch insert for better performance
	return r.db.CreateInBatches(metrics, 1000).Error
}

// GetSystemMetrics retrieves system metrics with filters and time range
func (r *AuditRepository) GetSystemMetrics(filters map[string]interface{}, from, to time.Time) ([]*domain.SystemMetrics, error) {
	var metrics []*domain.SystemMetrics

	query := r.db.Where("timestamp BETWEEN ? AND ?", from, to)

	// Apply filters
	for key, value := range filters {
		switch key {
		case "metric_type":
			query = query.Where("metric_type = ?", value)
		case "metric_name":
			query = query.Where("metric_name = ?", value)
		case "service":
			query = query.Where("service = ?", value)
		case "instance":
			query = query.Where("instance = ?", value)
		case "environment":
			query = query.Where("environment = ?", value)
		}
	}

	err := query.Order("timestamp ASC").Find(&metrics).Error
	return metrics, err
}

// DeleteOldMetrics deletes system metrics older than the specified date
func (r *AuditRepository) DeleteOldMetrics(before time.Time) (int64, error) {
	result := r.db.Where("timestamp < ?", before).Delete(&domain.SystemMetrics{})
	return result.RowsAffected, result.Error
}

// CreateBackupRecord creates a new backup record
func (r *AuditRepository) CreateBackupRecord(record *domain.BackupRecord) error {
	return r.db.Create(record).Error
}

// GetBackupRecord retrieves a backup record by ID
func (r *AuditRepository) GetBackupRecord(id uuid.UUID) (*domain.BackupRecord, error) {
	var record domain.BackupRecord
	err := r.db.Preload("Creator").First(&record, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// UpdateBackupRecord updates a backup record
func (r *AuditRepository) UpdateBackupRecord(record *domain.BackupRecord) error {
	return r.db.Save(record).Error
}

// ListBackupRecords retrieves backup records
func (r *AuditRepository) ListBackupRecords(limit, offset int) ([]*domain.BackupRecord, error) {
	var records []*domain.BackupRecord
	err := r.db.Preload("Creator").Order("created_at DESC").Limit(limit).Offset(offset).Find(&records).Error
	return records, err
}

// Helper methods for audit logging

// LogUserAction logs a user action
func (r *AuditRepository) LogUserAction(userID uuid.UUID, sessionID *uuid.UUID, action, resource string, details map[string]interface{}) error {
	detailsJSON, _ := json.Marshal(details)

	log := &domain.AuditLog{
		UserID:    &userID,
		SessionID: sessionID,
		Action:    action,
		Resource:  resource,
		Status:    domain.AuditStatusSuccess,
		RiskLevel: domain.RiskLevelLow,
		Severity:  domain.SeverityInfo,
		Details:   detailsJSON,
	}

	return r.CreateAuditLog(log)
}

// LogSecurityAction logs a security-related action
func (r *AuditRepository) LogSecurityAction(userID *uuid.UUID, action, resource string, riskLevel domain.RiskLevel, details map[string]interface{}) error {
	detailsJSON, _ := json.Marshal(details)

	severity := domain.SeverityInfo
	switch riskLevel {
	case domain.RiskLevelCritical:
		severity = domain.SeverityCritical
	case domain.RiskLevelHigh:
		severity = domain.SeverityHigh
	case domain.RiskLevelMedium:
		severity = domain.SeverityMedium
	case domain.RiskLevelLow:
		severity = domain.SeverityLow
	}

	log := &domain.AuditLog{
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Status:    domain.AuditStatusSuccess,
		RiskLevel: riskLevel,
		Severity:  severity,
		Details:   detailsJSON,
		Tags:      []string{"security"},
	}

	return r.CreateAuditLog(log)
}

// LogAPICall logs an API call
func (r *AuditRepository) LogAPICall(userID *uuid.UUID, method, path, ipAddress, userAgent string, statusCode int, duration int64) error {
	status := domain.AuditStatusSuccess
	if statusCode >= 400 {
		status = domain.AuditStatusFailure
	}

	riskLevel := domain.RiskLevelLow
	if statusCode >= 500 {
		riskLevel = domain.RiskLevelMedium
	}

	log := &domain.AuditLog{
		UserID:     userID,
		Action:     "api_call",
		Resource:   "api",
		Method:     method,
		Path:       path,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		Status:     status,
		StatusCode: statusCode,
		Duration:   duration,
		RiskLevel:  riskLevel,
		Severity:   domain.SeverityInfo,
		Tags:       []string{"api"},
	}

	return r.CreateAuditLog(log)
}
