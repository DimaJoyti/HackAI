package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// DatabaseManagerUseCase provides database management operations
type DatabaseManagerUseCase struct {
	db             *database.DB
	storageManager *database.StorageManager
	auditRepo      domain.AuditRepository
	logger         *logger.Logger
}

// NewDatabaseManagerUseCase creates a new database manager use case
func NewDatabaseManagerUseCase(
	db *database.DB,
	storageManager *database.StorageManager,
	auditRepo domain.AuditRepository,
	log *logger.Logger,
) *DatabaseManagerUseCase {
	return &DatabaseManagerUseCase{
		db:             db,
		storageManager: storageManager,
		auditRepo:      auditRepo,
		logger:         log,
	}
}

// GetDatabaseHealth returns comprehensive database health information
func (d *DatabaseManagerUseCase) GetDatabaseHealth(ctx context.Context) (map[string]interface{}, error) {
	health := make(map[string]interface{})

	// Basic connectivity check
	if err := d.db.Health(ctx); err != nil {
		health["status"] = "unhealthy"
		health["error"] = err.Error()
		return health, err
	}

	health["status"] = "healthy"
	health["timestamp"] = time.Now()

	// Connection statistics
	stats, err := d.db.Stats()
	if err != nil {
		d.logger.WithContext(ctx).WithError(err).Warn("Failed to get database statistics")
	} else {
		health["connection_stats"] = stats
	}

	// Storage statistics
	storageStats, err := d.storageManager.GetStorageStatistics(ctx)
	if err != nil {
		d.logger.WithContext(ctx).WithError(err).Warn("Failed to get storage statistics")
	} else {
		health["storage_stats"] = storageStats
	}

	// Performance metrics
	performanceMetrics, err := d.getPerformanceMetrics(ctx)
	if err != nil {
		d.logger.WithContext(ctx).WithError(err).Warn("Failed to get performance metrics")
	} else {
		health["performance"] = performanceMetrics
	}

	return health, nil
}

// getPerformanceMetrics retrieves database performance metrics
func (d *DatabaseManagerUseCase) getPerformanceMetrics(ctx context.Context) (map[string]interface{}, error) {
	metrics := make(map[string]interface{})

	// Query performance statistics
	var queryStats []map[string]interface{}
	if err := d.db.WithContext(ctx).Raw(`
		SELECT 
			query,
			calls,
			total_time,
			mean_time,
			rows
		FROM pg_stat_statements 
		ORDER BY total_time DESC 
		LIMIT 10
	`).Scan(&queryStats).Error; err != nil {
		d.logger.WithContext(ctx).WithError(err).Debug("pg_stat_statements not available")
	} else {
		metrics["slow_queries"] = queryStats
	}

	// Lock statistics
	var lockStats []map[string]interface{}
	if err := d.db.WithContext(ctx).Raw(`
		SELECT 
			schemaname,
			tablename,
			n_tup_ins as inserts,
			n_tup_upd as updates,
			n_tup_del as deletes,
			n_tup_hot_upd as hot_updates
		FROM pg_stat_user_tables 
		ORDER BY (n_tup_ins + n_tup_upd + n_tup_del) DESC 
		LIMIT 10
	`).Scan(&lockStats).Error; err != nil {
		d.logger.WithContext(ctx).WithError(err).Warn("Failed to get table statistics")
	} else {
		metrics["table_activity"] = lockStats
	}

	// Cache hit ratio
	var cacheHitRatio float64
	if err := d.db.WithContext(ctx).Raw(`
		SELECT 
			ROUND(
				(sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read))) * 100, 2
			) as cache_hit_ratio
		FROM pg_statio_user_tables
	`).Scan(&cacheHitRatio).Error; err != nil {
		d.logger.WithContext(ctx).WithError(err).Warn("Failed to get cache hit ratio")
	} else {
		metrics["cache_hit_ratio"] = cacheHitRatio
	}

	return metrics, nil
}

// CreateBackup creates a database backup
func (d *DatabaseManagerUseCase) CreateBackup(ctx context.Context, backupType string, userID uuid.UUID) (*domain.BackupRecord, error) {
	d.logger.WithContext(ctx).Info("Creating database backup", "type", backupType, "user_id", userID)

	// Log the backup creation
	if err := d.auditRepo.LogUserAction(userID, nil, "create_backup", "database", map[string]interface{}{
		"backup_type": backupType,
	}); err != nil {
		d.logger.WithContext(ctx).WithError(err).Warn("Failed to log backup creation")
	}

	// Create the backup
	backup, err := d.storageManager.CreateBackup(ctx, backupType, userID)
	if err != nil {
		// Log the failure
		d.auditRepo.LogSecurityAction(&userID, "backup_failed", "database", domain.RiskLevelMedium, map[string]interface{}{
			"backup_type": backupType,
			"error":       err.Error(),
		})
		return nil, fmt.Errorf("failed to create backup: %w", err)
	}

	// Log successful backup creation
	d.auditRepo.LogSecurityAction(&userID, "backup_created", "database", domain.RiskLevelLow, map[string]interface{}{
		"backup_id":   backup.ID,
		"backup_type": backupType,
	})

	return backup, nil
}

// ListBackups returns a list of database backups
func (d *DatabaseManagerUseCase) ListBackups(ctx context.Context, limit, offset int) ([]*domain.BackupRecord, error) {
	return d.auditRepo.ListBackupRecords(limit, offset)
}

// GetBackup returns a specific backup record
func (d *DatabaseManagerUseCase) GetBackup(ctx context.Context, backupID uuid.UUID) (*domain.BackupRecord, error) {
	return d.auditRepo.GetBackupRecord(backupID)
}

// PerformMaintenance runs database maintenance tasks
func (d *DatabaseManagerUseCase) PerformMaintenance(ctx context.Context, userID uuid.UUID) error {
	d.logger.WithContext(ctx).Info("Starting database maintenance", "user_id", userID)

	// Log maintenance start
	if err := d.auditRepo.LogUserAction(userID, nil, "start_maintenance", "database", map[string]interface{}{
		"maintenance_type": "full",
	}); err != nil {
		d.logger.WithContext(ctx).WithError(err).Warn("Failed to log maintenance start")
	}

	// Perform maintenance
	if err := d.storageManager.PerformMaintenance(ctx); err != nil {
		// Log maintenance failure
		d.auditRepo.LogSecurityAction(&userID, "maintenance_failed", "database", domain.RiskLevelMedium, map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("database maintenance failed: %w", err)
	}

	// Log successful maintenance
	d.auditRepo.LogSecurityAction(&userID, "maintenance_completed", "database", domain.RiskLevelLow, map[string]interface{}{
		"maintenance_type": "full",
	})

	d.logger.WithContext(ctx).Info("Database maintenance completed successfully")
	return nil
}

// CreateRetentionPolicy creates a new data retention policy
func (d *DatabaseManagerUseCase) CreateRetentionPolicy(ctx context.Context, userID uuid.UUID, policy *domain.DataRetentionPolicy) error {
	policy.CreatedBy = userID

	if err := d.db.DB.WithContext(ctx).Create(policy).Error; err != nil {
		return fmt.Errorf("failed to create retention policy: %w", err)
	}

	// Log policy creation
	d.auditRepo.LogUserAction(userID, nil, "create_retention_policy", "database", map[string]interface{}{
		"policy_id":      policy.ID,
		"policy_name":    policy.Name,
		"data_type":      policy.DataType,
		"retention_days": policy.RetentionDays,
	})

	return nil
}

// UpdateRetentionPolicy updates an existing data retention policy
func (d *DatabaseManagerUseCase) UpdateRetentionPolicy(ctx context.Context, userID uuid.UUID, policy *domain.DataRetentionPolicy) error {
	if err := d.db.DB.WithContext(ctx).Save(policy).Error; err != nil {
		return fmt.Errorf("failed to update retention policy: %w", err)
	}

	// Log policy update
	d.auditRepo.LogUserAction(userID, nil, "update_retention_policy", "database", map[string]interface{}{
		"policy_id":      policy.ID,
		"policy_name":    policy.Name,
		"data_type":      policy.DataType,
		"retention_days": policy.RetentionDays,
	})

	return nil
}

// ListRetentionPolicies returns a list of data retention policies
func (d *DatabaseManagerUseCase) ListRetentionPolicies(ctx context.Context, limit, offset int) ([]*domain.DataRetentionPolicy, error) {
	var policies []*domain.DataRetentionPolicy
	err := d.db.DB.WithContext(ctx).Preload("Creator").Order("created_at DESC").Limit(limit).Offset(offset).Find(&policies).Error
	return policies, err
}

// ArchiveOldData manually triggers data archival
func (d *DatabaseManagerUseCase) ArchiveOldData(ctx context.Context, userID uuid.UUID) error {
	d.logger.WithContext(ctx).Info("Starting manual data archival", "user_id", userID)

	// Log archival start
	if err := d.auditRepo.LogUserAction(userID, nil, "start_archival", "database", map[string]interface{}{
		"archival_type": "manual",
	}); err != nil {
		d.logger.WithContext(ctx).WithError(err).Warn("Failed to log archival start")
	}

	// Perform archival
	if err := d.storageManager.ArchiveOldData(ctx); err != nil {
		// Log archival failure
		d.auditRepo.LogSecurityAction(&userID, "archival_failed", "database", domain.RiskLevelMedium, map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("data archival failed: %w", err)
	}

	// Log successful archival
	d.auditRepo.LogSecurityAction(&userID, "archival_completed", "database", domain.RiskLevelLow, map[string]interface{}{
		"archival_type": "manual",
	})

	d.logger.WithContext(ctx).Info("Data archival completed successfully")
	return nil
}

// GetAuditLogs returns audit logs with filtering
func (d *DatabaseManagerUseCase) GetAuditLogs(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*domain.AuditLog, error) {
	return d.auditRepo.ListAuditLogs(filters, limit, offset)
}

// SearchAuditLogs searches audit logs with text query
func (d *DatabaseManagerUseCase) SearchAuditLogs(ctx context.Context, query string, filters map[string]interface{}, limit, offset int) ([]*domain.AuditLog, error) {
	return d.auditRepo.SearchAuditLogs(query, filters, limit, offset)
}

// GetSecurityEvents returns security events with filtering
func (d *DatabaseManagerUseCase) GetSecurityEvents(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*domain.SecurityEvent, error) {
	return d.auditRepo.ListSecurityEvents(filters, limit, offset)
}

// CreateSecurityEvent creates a new security event
func (d *DatabaseManagerUseCase) CreateSecurityEvent(ctx context.Context, event *domain.SecurityEvent) error {
	if err := d.auditRepo.CreateSecurityEvent(event); err != nil {
		return fmt.Errorf("failed to create security event: %w", err)
	}

	// Log security event creation
	d.auditRepo.LogSecurityAction(nil, "security_event_created", "security", domain.RiskLevelHigh, map[string]interface{}{
		"event_id":   event.ID,
		"event_type": event.Type,
		"severity":   event.Severity,
		"source_ip":  event.SourceIP,
		"target_ip":  event.TargetIP,
	})

	return nil
}

// UpdateSecurityEvent updates a security event
func (d *DatabaseManagerUseCase) UpdateSecurityEvent(ctx context.Context, userID uuid.UUID, event *domain.SecurityEvent) error {
	if err := d.auditRepo.UpdateSecurityEvent(event); err != nil {
		return fmt.Errorf("failed to update security event: %w", err)
	}

	// Log security event update
	d.auditRepo.LogUserAction(userID, nil, "update_security_event", "security", map[string]interface{}{
		"event_id": event.ID,
		"status":   event.Status,
	})

	return nil
}

// GetSystemMetrics returns system metrics for a time range
func (d *DatabaseManagerUseCase) GetSystemMetrics(ctx context.Context, filters map[string]interface{}, from, to time.Time) ([]*domain.SystemMetrics, error) {
	return d.auditRepo.GetSystemMetrics(filters, from, to)
}

// RecordSystemMetrics records new system metrics
func (d *DatabaseManagerUseCase) RecordSystemMetrics(ctx context.Context, metrics []*domain.SystemMetrics) error {
	return d.auditRepo.CreateSystemMetrics(metrics)
}
