package state

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// StateMigrationEngine handles state schema migrations
type StateMigrationEngine struct {
	store      StateStore
	migrations map[string]*StateMigration
	history    []*MigrationExecution
	logger     *logger.Logger
	mutex      sync.RWMutex
}

// MigrationExecution represents an executed migration
type MigrationExecution struct {
	ID          string                 `json:"id"`
	MigrationID string                 `json:"migration_id"`
	Status      MigrationStatus        `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Error       string                 `json:"error,omitempty"`
	AffectedKeys int                   `json:"affected_keys"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MigrationStatus represents the status of a migration
type MigrationStatus string

const (
	MigrationStatusPending   MigrationStatus = "pending"
	MigrationStatusRunning   MigrationStatus = "running"
	MigrationStatusCompleted MigrationStatus = "completed"
	MigrationStatusFailed    MigrationStatus = "failed"
	MigrationStatusRolledBack MigrationStatus = "rolled_back"
)

// MigrationScript represents a migration script
type MigrationScript struct {
	Language string                 `json:"language"`
	Code     string                 `json:"code"`
	Params   map[string]interface{} `json:"params"`
}

// MigrationValidator validates migrations before execution
type MigrationValidator interface {
	ValidateMigration(migration *StateMigration) error
	ValidateScript(script *MigrationScript) error
}

// NewStateMigrationEngine creates a new state migration engine
func NewStateMigrationEngine(store StateStore, logger *logger.Logger) *StateMigrationEngine {
	return &StateMigrationEngine{
		store:      store,
		migrations: make(map[string]*StateMigration),
		history:    make([]*MigrationExecution, 0),
		logger:     logger,
	}
}

// RegisterMigration registers a new migration
func (sme *StateMigrationEngine) RegisterMigration(migration *StateMigration) error {
	sme.mutex.Lock()
	defer sme.mutex.Unlock()

	if migration.ID == "" {
		migration.ID = uuid.New().String()
	}

	if _, exists := sme.migrations[migration.ID]; exists {
		return fmt.Errorf("migration %s already exists", migration.ID)
	}

	sme.migrations[migration.ID] = migration

	sme.logger.Info("Migration registered",
		"migration_id", migration.ID,
		"name", migration.Name,
		"from_version", migration.FromVersion,
		"to_version", migration.ToVersion)

	return nil
}

// ApplyMigration applies a migration
func (sme *StateMigrationEngine) ApplyMigration(ctx context.Context, migration StateMigration) error {
	sme.mutex.Lock()
	defer sme.mutex.Unlock()

	execution := &MigrationExecution{
		ID:          uuid.New().String(),
		MigrationID: migration.ID,
		Status:      MigrationStatusRunning,
		StartedAt:   time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	sme.history = append(sme.history, execution)

	sme.logger.Info("Starting migration",
		"migration_id", migration.ID,
		"execution_id", execution.ID)

	// Apply the migration
	affectedKeys, err := sme.executeMigration(ctx, &migration)
	
	execution.AffectedKeys = affectedKeys
	execution.Duration = time.Since(execution.StartedAt)
	now := time.Now()
	execution.CompletedAt = &now

	if err != nil {
		execution.Status = MigrationStatusFailed
		execution.Error = err.Error()
		
		sme.logger.Error("Migration failed",
			"migration_id", migration.ID,
			"execution_id", execution.ID,
			"error", err)
		
		return fmt.Errorf("migration failed: %w", err)
	}

	execution.Status = MigrationStatusCompleted

	sme.logger.Info("Migration completed",
		"migration_id", migration.ID,
		"execution_id", execution.ID,
		"affected_keys", affectedKeys,
		"duration", execution.Duration)

	return nil
}

// GetMigration retrieves a migration by ID
func (sme *StateMigrationEngine) GetMigration(migrationID string) (*StateMigration, error) {
	sme.mutex.RLock()
	defer sme.mutex.RUnlock()

	migration, exists := sme.migrations[migrationID]
	if !exists {
		return nil, fmt.Errorf("migration %s not found", migrationID)
	}

	return migration, nil
}

// ListMigrations lists all registered migrations
func (sme *StateMigrationEngine) ListMigrations() []*StateMigration {
	sme.mutex.RLock()
	defer sme.mutex.RUnlock()

	migrations := make([]*StateMigration, 0, len(sme.migrations))
	for _, migration := range sme.migrations {
		migrations = append(migrations, migration)
	}

	return migrations
}

// GetMigrationHistory returns migration execution history
func (sme *StateMigrationEngine) GetMigrationHistory() []*MigrationExecution {
	sme.mutex.RLock()
	defer sme.mutex.RUnlock()

	// Return a copy to avoid external modifications
	history := make([]*MigrationExecution, len(sme.history))
	copy(history, sme.history)

	return history
}

// RollbackMigration rolls back a migration
func (sme *StateMigrationEngine) RollbackMigration(ctx context.Context, executionID string) error {
	sme.mutex.Lock()
	defer sme.mutex.Unlock()

	// Find the execution
	var execution *MigrationExecution
	for _, exec := range sme.history {
		if exec.ID == executionID {
			execution = exec
			break
		}
	}

	if execution == nil {
		return fmt.Errorf("migration execution %s not found", executionID)
	}

	if execution.Status != MigrationStatusCompleted {
		return fmt.Errorf("can only rollback completed migrations")
	}

	// Find the migration
	migration, exists := sme.migrations[execution.MigrationID]
	if !exists {
		return fmt.Errorf("migration %s not found", execution.MigrationID)
	}

	sme.logger.Info("Starting migration rollback",
		"migration_id", migration.ID,
		"execution_id", executionID)

	// Create rollback migration
	rollbackMigration := sme.createRollbackMigration(migration)

	// Execute rollback
	_, err := sme.executeMigration(ctx, rollbackMigration)
	if err != nil {
		sme.logger.Error("Migration rollback failed",
			"migration_id", migration.ID,
			"execution_id", executionID,
			"error", err)
		return fmt.Errorf("rollback failed: %w", err)
	}

	execution.Status = MigrationStatusRolledBack

	sme.logger.Info("Migration rollback completed",
		"migration_id", migration.ID,
		"execution_id", executionID)

	return nil
}

// ValidateMigration validates a migration before execution
func (sme *StateMigrationEngine) ValidateMigration(migration *StateMigration) error {
	// Basic validation
	if migration.Name == "" {
		return fmt.Errorf("migration name is required")
	}

	if migration.FromVersion == "" || migration.ToVersion == "" {
		return fmt.Errorf("migration versions are required")
	}

	if migration.Script == "" {
		return fmt.Errorf("migration script is required")
	}

	// Check for version conflicts
	for _, existingMigration := range sme.migrations {
		if existingMigration.FromVersion == migration.FromVersion &&
		   existingMigration.ToVersion == migration.ToVersion {
			return fmt.Errorf("migration from %s to %s already exists",
				migration.FromVersion, migration.ToVersion)
		}
	}

	return nil
}

// executeMigration executes a migration script
func (sme *StateMigrationEngine) executeMigration(ctx context.Context, migration *StateMigration) (int, error) {
	// This is a simplified implementation
	// In production, implement proper script execution based on language
	
	affectedKeys := 0

	// For demonstration, we'll simulate migration execution
	switch migration.Script {
	case "add_field":
		affectedKeys = sme.executeAddFieldMigration(ctx, migration)
	case "remove_field":
		affectedKeys = sme.executeRemoveFieldMigration(ctx, migration)
	case "rename_field":
		affectedKeys = sme.executeRenameFieldMigration(ctx, migration)
	case "change_type":
		affectedKeys = sme.executeChangeTypeMigration(ctx, migration)
	default:
		return 0, fmt.Errorf("unsupported migration script: %s", migration.Script)
	}

	return affectedKeys, nil
}

// executeAddFieldMigration simulates adding a field to state entries
func (sme *StateMigrationEngine) executeAddFieldMigration(ctx context.Context, migration *StateMigration) int {
	// Simulate adding a field to all matching entries
	sme.logger.Debug("Executing add field migration", "migration_id", migration.ID)
	
	// In a real implementation, this would:
	// 1. Query all matching state entries
	// 2. Add the new field with default value
	// 3. Update the entries in the store
	
	return 100 // Simulated affected keys
}

// executeRemoveFieldMigration simulates removing a field from state entries
func (sme *StateMigrationEngine) executeRemoveFieldMigration(ctx context.Context, migration *StateMigration) int {
	sme.logger.Debug("Executing remove field migration", "migration_id", migration.ID)
	return 75 // Simulated affected keys
}

// executeRenameFieldMigration simulates renaming a field in state entries
func (sme *StateMigrationEngine) executeRenameFieldMigration(ctx context.Context, migration *StateMigration) int {
	sme.logger.Debug("Executing rename field migration", "migration_id", migration.ID)
	return 50 // Simulated affected keys
}

// executeChangeTypeMigration simulates changing field type in state entries
func (sme *StateMigrationEngine) executeChangeTypeMigration(ctx context.Context, migration *StateMigration) int {
	sme.logger.Debug("Executing change type migration", "migration_id", migration.ID)
	return 25 // Simulated affected keys
}

// createRollbackMigration creates a rollback migration
func (sme *StateMigrationEngine) createRollbackMigration(original *StateMigration) *StateMigration {
	rollback := &StateMigration{
		ID:          uuid.New().String(),
		Name:        fmt.Sprintf("Rollback: %s", original.Name),
		Description: fmt.Sprintf("Rollback migration for %s", original.ID),
		FromVersion: original.ToVersion,
		ToVersion:   original.FromVersion,
		Metadata:    make(map[string]interface{}),
	}

	// Create inverse script
	switch original.Script {
	case "add_field":
		rollback.Script = "remove_field"
	case "remove_field":
		rollback.Script = "add_field"
	case "rename_field":
		rollback.Script = "rename_field" // Would need to swap field names
	case "change_type":
		rollback.Script = "change_type" // Would need to revert type
	default:
		rollback.Script = "custom_rollback"
	}

	rollback.Metadata["original_migration_id"] = original.ID
	rollback.Metadata["rollback"] = true

	return rollback
}

// GetMigrationPlan creates a migration plan to go from one version to another
func (sme *StateMigrationEngine) GetMigrationPlan(fromVersion, toVersion string) ([]*StateMigration, error) {
	sme.mutex.RLock()
	defer sme.mutex.RUnlock()

	// Simple implementation - find direct migration
	for _, migration := range sme.migrations {
		if migration.FromVersion == fromVersion && migration.ToVersion == toVersion {
			return []*StateMigration{migration}, nil
		}
	}

	// In a more sophisticated implementation, this would:
	// 1. Build a graph of migrations
	// 2. Find the shortest path from fromVersion to toVersion
	// 3. Return the sequence of migrations needed

	return nil, fmt.Errorf("no migration path found from %s to %s", fromVersion, toVersion)
}

// ApplyMigrationPlan applies a sequence of migrations
func (sme *StateMigrationEngine) ApplyMigrationPlan(ctx context.Context, plan []*StateMigration) error {
	for i, migration := range plan {
		sme.logger.Info("Applying migration step",
			"step", i+1,
			"total_steps", len(plan),
			"migration_id", migration.ID)

		if err := sme.ApplyMigration(ctx, *migration); err != nil {
			return fmt.Errorf("migration step %d failed: %w", i+1, err)
		}
	}

	sme.logger.Info("Migration plan completed successfully",
		"total_steps", len(plan))

	return nil
}

// GetMigrationStats returns migration statistics
func (sme *StateMigrationEngine) GetMigrationStats() *MigrationStats {
	sme.mutex.RLock()
	defer sme.mutex.RUnlock()

	stats := &MigrationStats{
		TotalMigrations: int64(len(sme.migrations)),
		TotalExecutions: int64(len(sme.history)),
		Metadata:        make(map[string]interface{}),
	}

	var completedCount, failedCount, rolledBackCount int64
	var totalDuration time.Duration

	for _, execution := range sme.history {
		switch execution.Status {
		case MigrationStatusCompleted:
			completedCount++
		case MigrationStatusFailed:
			failedCount++
		case MigrationStatusRolledBack:
			rolledBackCount++
		}

		totalDuration += execution.Duration
	}

	stats.CompletedMigrations = completedCount
	stats.FailedMigrations = failedCount
	stats.RolledBackMigrations = rolledBackCount

	if stats.TotalExecutions > 0 {
		stats.AverageDuration = totalDuration / time.Duration(stats.TotalExecutions)
		stats.SuccessRate = float64(completedCount) / float64(stats.TotalExecutions)
	}

	return stats
}

// MigrationStats holds migration statistics
type MigrationStats struct {
	TotalMigrations      int64                  `json:"total_migrations"`
	TotalExecutions      int64                  `json:"total_executions"`
	CompletedMigrations  int64                  `json:"completed_migrations"`
	FailedMigrations     int64                  `json:"failed_migrations"`
	RolledBackMigrations int64                  `json:"rolled_back_migrations"`
	AverageDuration      time.Duration          `json:"average_duration"`
	SuccessRate          float64                `json:"success_rate"`
	Metadata             map[string]interface{} `json:"metadata"`
}
