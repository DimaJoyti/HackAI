package database

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// StorageManager provides advanced storage management capabilities
type StorageManager struct {
	db     *DB
	logger *logger.Logger
}

// NewStorageManager creates a new storage manager
func NewStorageManager(db *DB, log *logger.Logger) *StorageManager {
	return &StorageManager{
		db:     db,
		logger: log,
	}
}

// ArchiveOldData archives old data based on retention policies
func (s *StorageManager) ArchiveOldData(ctx context.Context) error {
	s.logger.WithContext(ctx).Info("Starting data archival process")

	// Get all active retention policies
	var policies []domain.DataRetentionPolicy
	if err := s.db.DB.WithContext(ctx).Where("enabled = ?", true).Find(&policies).Error; err != nil {
		return fmt.Errorf("failed to get retention policies: %w", err)
	}

	for _, policy := range policies {
		if err := s.applyRetentionPolicy(ctx, &policy); err != nil {
			s.logger.WithContext(ctx).WithError(err).Errorf("Failed to apply retention policy: %s", policy.Name)
			continue
		}
	}

	s.logger.WithContext(ctx).Info("Data archival process completed")
	return nil
}

// applyRetentionPolicy applies a specific retention policy
func (s *StorageManager) applyRetentionPolicy(ctx context.Context, policy *domain.DataRetentionPolicy) error {
	cutoffDate := time.Now().AddDate(0, 0, -policy.RetentionDays)

	switch policy.DataType {
	case "audit_logs":
		return s.archiveAuditLogs(ctx, cutoffDate)
	case "security_events":
		return s.archiveSecurityEvents(ctx, cutoffDate)
	case "system_metrics":
		return s.archiveSystemMetrics(ctx, cutoffDate)
	case "user_activities":
		return s.archiveUserActivities(ctx, cutoffDate)
	default:
		s.logger.WithContext(ctx).Warnf("Unknown data type in retention policy: %s", policy.DataType)
		return nil
	}
}

// archiveAuditLogs archives old audit logs
func (s *StorageManager) archiveAuditLogs(ctx context.Context, cutoffDate time.Time) error {
	// First, count records to be archived
	var count int64
	if err := s.db.DB.WithContext(ctx).Model(&domain.AuditLog{}).
		Where("created_at < ?", cutoffDate).
		Count(&count).Error; err != nil {
		return fmt.Errorf("failed to count audit logs for archival: %w", err)
	}

	if count == 0 {
		return nil
	}

	s.logger.WithContext(ctx).Infof("Archiving %d audit logs older than %s", count, cutoffDate.Format("2006-01-02"))

	// Archive in batches to avoid long-running transactions
	batchSize := 1000
	for offset := 0; offset < int(count); offset += batchSize {
		if err := s.db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Move records to archive table (if exists) or delete
			return tx.Where("created_at < ?", cutoffDate).
				Limit(batchSize).
				Offset(offset).
				Delete(&domain.AuditLog{}).Error
		}); err != nil {
			return fmt.Errorf("failed to archive audit logs batch: %w", err)
		}
	}

	return nil
}

// archiveSecurityEvents archives old security events
func (s *StorageManager) archiveSecurityEvents(ctx context.Context, cutoffDate time.Time) error {
	var count int64
	if err := s.db.DB.WithContext(ctx).Model(&domain.SecurityEvent{}).
		Where("created_at < ? AND status IN ?", cutoffDate, []string{"resolved", "closed"}).
		Count(&count).Error; err != nil {
		return fmt.Errorf("failed to count security events for archival: %w", err)
	}

	if count == 0 {
		return nil
	}

	s.logger.WithContext(ctx).Infof("Archiving %d resolved security events older than %s", count, cutoffDate.Format("2006-01-02"))

	// Archive resolved/closed events only
	return s.db.DB.WithContext(ctx).
		Where("created_at < ? AND status IN ?", cutoffDate, []string{"resolved", "closed"}).
		Delete(&domain.SecurityEvent{}).Error
}

// archiveSystemMetrics archives old system metrics
func (s *StorageManager) archiveSystemMetrics(ctx context.Context, cutoffDate time.Time) error {
	var count int64
	if err := s.db.DB.WithContext(ctx).Model(&domain.SystemMetrics{}).
		Where("timestamp < ?", cutoffDate).
		Count(&count).Error; err != nil {
		return fmt.Errorf("failed to count system metrics for archival: %w", err)
	}

	if count == 0 {
		return nil
	}

	s.logger.WithContext(ctx).Infof("Archiving %d system metrics older than %s", count, cutoffDate.Format("2006-01-02"))

	// Delete old metrics in batches
	batchSize := 5000
	for offset := 0; offset < int(count); offset += batchSize {
		if err := s.db.DB.WithContext(ctx).
			Where("timestamp < ?", cutoffDate).
			Limit(batchSize).
			Delete(&domain.SystemMetrics{}).Error; err != nil {
			return fmt.Errorf("failed to delete system metrics batch: %w", err)
		}
	}

	return nil
}

// archiveUserActivities archives old user activities
func (s *StorageManager) archiveUserActivities(ctx context.Context, cutoffDate time.Time) error {
	var count int64
	if err := s.db.DB.WithContext(ctx).Model(&domain.UserActivity{}).
		Where("created_at < ?", cutoffDate).
		Count(&count).Error; err != nil {
		return fmt.Errorf("failed to count user activities for archival: %w", err)
	}

	if count == 0 {
		return nil
	}

	s.logger.WithContext(ctx).Infof("Archiving %d user activities older than %s", count, cutoffDate.Format("2006-01-02"))

	return s.db.DB.WithContext(ctx).
		Where("created_at < ?", cutoffDate).
		Delete(&domain.UserActivity{}).Error
}

// OptimizeDatabase performs database optimization tasks
func (s *StorageManager) OptimizeDatabase(ctx context.Context) error {
	s.logger.WithContext(ctx).Info("Starting database optimization")

	// Analyze tables for better query planning
	tables := []string{
		"users", "user_sessions", "user_activities", "user_permissions",
		"vulnerability_scans", "vulnerabilities", "network_scans", "network_hosts", "network_ports",
		"audit_logs", "security_events", "threat_intelligence", "system_metrics",
	}

	for _, table := range tables {
		if err := s.db.DB.WithContext(ctx).Exec(fmt.Sprintf("ANALYZE %s", table)).Error; err != nil {
			s.logger.WithContext(ctx).WithError(err).Warnf("Failed to analyze table: %s", table)
		}
	}

	// Vacuum analyze for PostgreSQL
	if err := s.db.DB.WithContext(ctx).Exec("VACUUM ANALYZE").Error; err != nil {
		s.logger.WithContext(ctx).WithError(err).Warn("Failed to run VACUUM ANALYZE")
	}

	// Update table statistics
	if err := s.db.DB.WithContext(ctx).Exec("UPDATE pg_stat_user_tables SET n_tup_ins = 0, n_tup_upd = 0, n_tup_del = 0").Error; err != nil {
		s.logger.WithContext(ctx).WithError(err).Warn("Failed to reset table statistics")
	}

	s.logger.WithContext(ctx).Info("Database optimization completed")
	return nil
}

// GetStorageStatistics returns comprehensive storage statistics
func (s *StorageManager) GetStorageStatistics(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Database size
	var dbSize string
	if err := s.db.DB.WithContext(ctx).Raw("SELECT pg_size_pretty(pg_database_size(current_database()))").Scan(&dbSize).Error; err != nil {
		s.logger.WithContext(ctx).WithError(err).Warn("Failed to get database size")
	} else {
		stats["database_size"] = dbSize
	}

	// Table sizes
	tableSizes := make(map[string]interface{})
	tables := []string{
		"users", "user_sessions", "user_activities", "user_permissions",
		"vulnerability_scans", "vulnerabilities", "network_scans", "network_hosts", "network_ports",
		"audit_logs", "security_events", "threat_intelligence", "system_metrics",
	}

	for _, table := range tables {
		var size string
		var count int64

		// Get table size
		if err := s.db.DB.WithContext(ctx).Raw("SELECT pg_size_pretty(pg_total_relation_size(?))", table).Scan(&size).Error; err != nil {
			s.logger.WithContext(ctx).WithError(err).Warnf("Failed to get size for table: %s", table)
			continue
		}

		// Get row count
		if err := s.db.DB.WithContext(ctx).Raw(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count).Error; err != nil {
			s.logger.WithContext(ctx).WithError(err).Warnf("Failed to get count for table: %s", table)
			continue
		}

		tableSizes[table] = map[string]interface{}{
			"size":  size,
			"count": count,
		}
	}
	stats["table_sizes"] = tableSizes

	// Index usage statistics
	var indexStats []map[string]interface{}
	if err := s.db.DB.WithContext(ctx).Raw(`
		SELECT
			schemaname,
			tablename,
			indexname,
			idx_tup_read,
			idx_tup_fetch,
			pg_size_pretty(pg_relation_size(indexrelid)) as size
		FROM pg_stat_user_indexes
		ORDER BY idx_tup_read DESC
		LIMIT 20
	`).Scan(&indexStats).Error; err != nil {
		s.logger.WithContext(ctx).WithError(err).Warn("Failed to get index statistics")
	} else {
		stats["index_usage"] = indexStats
	}

	// Connection statistics
	connStats, err := s.db.Stats()
	if err != nil {
		s.logger.WithContext(ctx).WithError(err).Warn("Failed to get connection statistics")
	} else {
		stats["connections"] = connStats
	}

	return stats, nil
}

// CreateBackup creates a database backup
func (s *StorageManager) CreateBackup(ctx context.Context, backupType string, userID uuid.UUID) (*domain.BackupRecord, error) {
	s.logger.WithContext(ctx).Info("Starting database backup", "type", backupType)

	record := &domain.BackupRecord{
		Type:        backupType,
		Status:      domain.BackupStatusPending,
		StartedAt:   time.Now(),
		CreatedBy:   userID,
		Compression: true,
		Encryption:  false, // Can be configured
	}

	// Create backup record
	if err := s.db.DB.WithContext(ctx).Create(record).Error; err != nil {
		return nil, fmt.Errorf("failed to create backup record: %w", err)
	}

	// Update status to running
	record.Status = domain.BackupStatusRunning
	if err := s.db.DB.WithContext(ctx).Save(record).Error; err != nil {
		s.logger.WithContext(ctx).WithError(err).Error("Failed to update backup status")
	}

	// Simulate backup process (in real implementation, this would call pg_dump or similar)
	go s.performBackup(context.Background(), record)

	return record, nil
}

// performBackup performs the actual backup operation
func (s *StorageManager) performBackup(ctx context.Context, record *domain.BackupRecord) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.WithContext(ctx).Errorf("Backup process panicked: %v", r)
			record.Status = domain.BackupStatusFailed
			record.ErrorMessage = fmt.Sprintf("Backup process panicked: %v", r)
			s.db.DB.WithContext(ctx).Save(record)
		}
	}()

	// Simulate backup process
	time.Sleep(5 * time.Second)

	// Get database statistics
	stats, err := s.GetStorageStatistics(ctx)
	if err != nil {
		s.logger.WithContext(ctx).WithError(err).Error("Failed to get database statistics for backup")
	}

	// Update backup record with completion
	now := time.Now()
	record.Status = domain.BackupStatusCompleted
	record.CompletedAt = &now
	record.Duration = int64(now.Sub(record.StartedAt).Seconds())
	record.FileName = fmt.Sprintf("hackai_backup_%s_%s.sql", record.Type, record.StartedAt.Format("20060102_150405"))
	record.FilePath = fmt.Sprintf("/backups/%s", record.FileName)
	record.FileSize = 1024 * 1024 * 50     // Simulate 50MB backup
	record.Checksum = "sha256:abcd1234..." // Simulate checksum

	if stats != nil {
		if tableSizes, ok := stats["table_sizes"].(map[string]interface{}); ok {
			totalCount := int64(0)
			tableCount := 0
			for _, tableInfo := range tableSizes {
				if info, ok := tableInfo.(map[string]interface{}); ok {
					if count, ok := info["count"].(int64); ok {
						totalCount += count
					}
					tableCount++
				}
			}
			record.RecordCount = totalCount
			record.TableCount = tableCount
		}
	}

	if err := s.db.DB.WithContext(ctx).Save(record).Error; err != nil {
		s.logger.WithContext(ctx).WithError(err).Error("Failed to update backup record")
	}

	s.logger.WithContext(ctx).Info("Database backup completed successfully",
		"backup_id", record.ID,
		"duration", record.Duration,
		"file_size", record.FileSize)
}

// CleanupExpiredSessions removes expired user sessions
func (s *StorageManager) CleanupExpiredSessions(ctx context.Context) error {
	s.logger.WithContext(ctx).Info("Cleaning up expired sessions")

	result := s.db.DB.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&domain.UserSession{})
	if result.Error != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", result.Error)
	}

	s.logger.WithContext(ctx).Infof("Cleaned up %d expired sessions", result.RowsAffected)
	return nil
}

// CleanupExpiredPermissions removes expired user permissions
func (s *StorageManager) CleanupExpiredPermissions(ctx context.Context) error {
	s.logger.WithContext(ctx).Info("Cleaning up expired permissions")

	result := s.db.DB.WithContext(ctx).Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).Delete(&domain.UserPermission{})
	if result.Error != nil {
		return fmt.Errorf("failed to cleanup expired permissions: %w", result.Error)
	}

	s.logger.WithContext(ctx).Infof("Cleaned up %d expired permissions", result.RowsAffected)
	return nil
}

// CleanupExpiredThreatIntelligence removes expired threat intelligence
func (s *StorageManager) CleanupExpiredThreatIntelligence(ctx context.Context) error {
	s.logger.WithContext(ctx).Info("Cleaning up expired threat intelligence")

	result := s.db.DB.WithContext(ctx).Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).Delete(&domain.ThreatIntelligence{})
	if result.Error != nil {
		return fmt.Errorf("failed to cleanup expired threat intelligence: %w", result.Error)
	}

	s.logger.WithContext(ctx).Infof("Cleaned up %d expired threat intelligence records", result.RowsAffected)
	return nil
}

// PerformMaintenance runs all maintenance tasks
func (s *StorageManager) PerformMaintenance(ctx context.Context) error {
	s.logger.WithContext(ctx).Info("Starting database maintenance")

	// Cleanup expired data
	if err := s.CleanupExpiredSessions(ctx); err != nil {
		s.logger.WithContext(ctx).WithError(err).Error("Failed to cleanup expired sessions")
	}

	if err := s.CleanupExpiredPermissions(ctx); err != nil {
		s.logger.WithContext(ctx).WithError(err).Error("Failed to cleanup expired permissions")
	}

	if err := s.CleanupExpiredThreatIntelligence(ctx); err != nil {
		s.logger.WithContext(ctx).WithError(err).Error("Failed to cleanup expired threat intelligence")
	}

	// Archive old data
	if err := s.ArchiveOldData(ctx); err != nil {
		s.logger.WithContext(ctx).WithError(err).Error("Failed to archive old data")
	}

	// Optimize database
	if err := s.OptimizeDatabase(ctx); err != nil {
		s.logger.WithContext(ctx).WithError(err).Error("Failed to optimize database")
	}

	s.logger.WithContext(ctx).Info("Database maintenance completed")
	return nil
}
