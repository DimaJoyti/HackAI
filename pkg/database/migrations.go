package database

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	pkglogger "github.com/dimajoyti/hackai/pkg/logger"
)

// Migration represents a database migration
type Migration struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Version     string     `json:"version" gorm:"uniqueIndex;not null"`
	Name        string     `json:"name" gorm:"not null"`
	Description string     `json:"description"`
	UpSQL       string     `json:"up_sql" gorm:"type:text"`
	DownSQL     string     `json:"down_sql" gorm:"type:text"`
	Applied     bool       `json:"applied" gorm:"default:false"`
	AppliedAt   *time.Time `json:"applied_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// TableName returns the table name for Migration model
func (Migration) TableName() string {
	return "schema_migrations"
}

// MigrationManager handles database migrations
type MigrationManager struct {
	db     *gorm.DB
	logger *pkglogger.Logger
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db *gorm.DB, logger *pkglogger.Logger) *MigrationManager {
	return &MigrationManager{
		db:     db,
		logger: logger,
	}
}

// InitializeMigrationTable creates the migration table if it doesn't exist
func (m *MigrationManager) InitializeMigrationTable() error {
	if err := m.db.AutoMigrate(&Migration{}); err != nil {
		return fmt.Errorf("failed to create migration table: %w", err)
	}
	return nil
}

// GetPendingMigrations returns migrations that haven't been applied
func (m *MigrationManager) GetPendingMigrations() ([]*Migration, error) {
	var migrations []*Migration
	if err := m.db.Where("applied = ?", false).Order("version ASC").Find(&migrations).Error; err != nil {
		return nil, fmt.Errorf("failed to get pending migrations: %w", err)
	}
	return migrations, nil
}

// GetAppliedMigrations returns migrations that have been applied
func (m *MigrationManager) GetAppliedMigrations() ([]*Migration, error) {
	var migrations []*Migration
	if err := m.db.Where("applied = ?", true).Order("version DESC").Find(&migrations).Error; err != nil {
		return nil, fmt.Errorf("failed to get applied migrations: %w", err)
	}
	return migrations, nil
}

// ApplyMigration applies a single migration
func (m *MigrationManager) ApplyMigration(migration *Migration) error {
	m.logger.Infof("Applying migration %s: %s", migration.Version, migration.Name)

	// Start transaction
	tx := m.db.Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to start transaction: %w", tx.Error)
	}

	// Execute the migration SQL
	if migration.UpSQL != "" {
		if err := tx.Exec(migration.UpSQL).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to execute migration %s: %w", migration.Version, err)
		}
	}

	// Mark migration as applied
	now := time.Now()
	migration.Applied = true
	migration.AppliedAt = &now

	if err := tx.Save(migration).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to mark migration as applied: %w", err)
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit migration transaction: %w", err)
	}

	m.logger.Infof("Successfully applied migration %s", migration.Version)
	return nil
}

// RollbackMigration rolls back a single migration
func (m *MigrationManager) RollbackMigration(migration *Migration) error {
	m.logger.Infof("Rolling back migration %s: %s", migration.Version, migration.Name)

	// Start transaction
	tx := m.db.Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to start transaction: %w", tx.Error)
	}

	// Execute the rollback SQL
	if migration.DownSQL != "" {
		if err := tx.Exec(migration.DownSQL).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to execute rollback %s: %w", migration.Version, err)
		}
	}

	// Mark migration as not applied
	migration.Applied = false
	migration.AppliedAt = nil

	if err := tx.Save(migration).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to mark migration as rolled back: %w", err)
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit rollback transaction: %w", err)
	}

	m.logger.Infof("Successfully rolled back migration %s", migration.Version)
	return nil
}

// RunMigrations applies all pending migrations
func (m *MigrationManager) RunMigrations() error {
	// Initialize migration table
	if err := m.InitializeMigrationTable(); err != nil {
		return err
	}

	// Register built-in migrations
	if err := m.RegisterBuiltinMigrations(); err != nil {
		return err
	}

	// Get pending migrations
	pending, err := m.GetPendingMigrations()
	if err != nil {
		return err
	}

	if len(pending) == 0 {
		m.logger.Info("No pending migrations to apply")
		return nil
	}

	m.logger.Infof("Found %d pending migrations", len(pending))

	// Apply each migration
	for _, migration := range pending {
		if err := m.ApplyMigration(migration); err != nil {
			return fmt.Errorf("migration failed at %s: %w", migration.Version, err)
		}
	}

	m.logger.Info("All migrations applied successfully")
	return nil
}

// RollbackToVersion rolls back to a specific migration version
func (m *MigrationManager) RollbackToVersion(targetVersion string) error {
	applied, err := m.GetAppliedMigrations()
	if err != nil {
		return err
	}

	// Find migrations to rollback (all migrations after target version)
	var toRollback []*Migration
	for _, migration := range applied {
		if m.compareVersions(migration.Version, targetVersion) > 0 {
			toRollback = append(toRollback, migration)
		}
	}

	if len(toRollback) == 0 {
		m.logger.Infof("Already at or before version %s", targetVersion)
		return nil
	}

	m.logger.Infof("Rolling back %d migrations to version %s", len(toRollback), targetVersion)

	// Rollback migrations in reverse order
	for _, migration := range toRollback {
		if err := m.RollbackMigration(migration); err != nil {
			return fmt.Errorf("rollback failed at %s: %w", migration.Version, err)
		}
	}

	m.logger.Infof("Successfully rolled back to version %s", targetVersion)
	return nil
}

// compareVersions compares two version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func (m *MigrationManager) compareVersions(v1, v2 string) int {
	// Simple numeric comparison for versions like "001", "002", etc.
	if num1, err1 := strconv.Atoi(v1); err1 == nil {
		if num2, err2 := strconv.Atoi(v2); err2 == nil {
			if num1 < num2 {
				return -1
			} else if num1 > num2 {
				return 1
			}
			return 0
		}
	}

	// Fallback to string comparison
	return strings.Compare(v1, v2)
}

// GetMigrationStatus returns the current migration status
func (m *MigrationManager) GetMigrationStatus() (map[string]interface{}, error) {
	applied, err := m.GetAppliedMigrations()
	if err != nil {
		return nil, err
	}

	pending, err := m.GetPendingMigrations()
	if err != nil {
		return nil, err
	}

	var currentVersion string
	if len(applied) > 0 {
		currentVersion = applied[0].Version // Most recent applied migration
	}

	return map[string]interface{}{
		"current_version":    currentVersion,
		"applied_count":      len(applied),
		"pending_count":      len(pending),
		"last_migration_at":  getLastMigrationTime(applied),
		"pending_migrations": getPendingVersions(pending),
	}, nil
}

// Helper functions
func getLastMigrationTime(applied []*Migration) *time.Time {
	if len(applied) > 0 && applied[0].AppliedAt != nil {
		return applied[0].AppliedAt
	}
	return nil
}

func getPendingVersions(pending []*Migration) []string {
	versions := make([]string, len(pending))
	for i, migration := range pending {
		versions[i] = migration.Version
	}
	return versions
}

// RegisterBuiltinMigrations registers all built-in migrations
func (m *MigrationManager) RegisterBuiltinMigrations() error {
	migrations := []*Migration{
		{
			Version:     "001",
			Name:        "create_initial_schema",
			Description: "Create initial database schema with all core tables",
			UpSQL:       getInitialSchemaSQL(),
			DownSQL:     getInitialSchemaRollbackSQL(),
		},
		{
			Version:     "002",
			Name:        "add_security_indexes",
			Description: "Add performance indexes for security-related queries",
			UpSQL:       getSecurityIndexesSQL(),
			DownSQL:     getSecurityIndexesRollbackSQL(),
		},
		{
			Version:     "003",
			Name:        "add_llm_security_tables",
			Description: "Add LLM security and policy tables",
			UpSQL:       getLLMSecurityTablesSQL(),
			DownSQL:     getLLMSecurityTablesRollbackSQL(),
		},
		{
			Version:     "004",
			Name:        "add_audit_enhancements",
			Description: "Enhance audit logging with additional fields and indexes",
			UpSQL:       getAuditEnhancementsSQL(),
			DownSQL:     getAuditEnhancementsRollbackSQL(),
		},
	}

	for _, migration := range migrations {
		// Check if migration already exists
		var existing Migration
		err := m.db.Where("version = ?", migration.Version).First(&existing).Error
		if err == gorm.ErrRecordNotFound {
			// Create new migration
			if err := m.db.Create(migration).Error; err != nil {
				return fmt.Errorf("failed to register migration %s: %w", migration.Version, err)
			}
			m.logger.Infof("Registered migration %s: %s", migration.Version, migration.Name)
		} else if err != nil {
			return fmt.Errorf("failed to check existing migration %s: %w", migration.Version, err)
		}
	}

	return nil
}
