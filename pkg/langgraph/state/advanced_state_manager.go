package state

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var stateTracer = otel.Tracer("hackai/langgraph/state")

// AdvancedStateManager provides sophisticated state management capabilities
type AdvancedStateManager struct {
	stateStore      StateStore
	versionManager  *StateVersionManager
	transactionMgr  *TransactionManager
	snapshotManager *SnapshotManager
	migrationEngine *StateMigrationEngine
	cacheManager    *StateCacheManager
	eventBus        *StateEventBus
	validator       StateValidator
	config          *StateManagerConfig
	logger          *logger.Logger
	mutex           sync.RWMutex
}

// StateManagerConfig holds configuration for the state manager
type StateManagerConfig struct {
	EnableVersioning   bool           `json:"enable_versioning"`
	EnableTransactions bool           `json:"enable_transactions"`
	EnableSnapshots    bool           `json:"enable_snapshots"`
	EnableCaching      bool           `json:"enable_caching"`
	EnableMigrations   bool           `json:"enable_migrations"`
	EnableValidation   bool           `json:"enable_validation"`
	MaxVersions        int            `json:"max_versions"`
	SnapshotInterval   time.Duration  `json:"snapshot_interval"`
	CacheSize          int            `json:"cache_size"`
	CacheTTL           time.Duration  `json:"cache_ttl"`
	TransactionTimeout time.Duration  `json:"transaction_timeout"`
	ValidationMode     ValidationMode `json:"validation_mode"`
}

// ValidationMode defines how strict state validation should be
type ValidationMode string

const (
	ValidationModeStrict   ValidationMode = "strict"
	ValidationModeWarning  ValidationMode = "warning"
	ValidationModeDisabled ValidationMode = "disabled"
)

// StateStore interface for advanced state storage
type StateStore interface {
	Get(ctx context.Context, key StateKey) (*StateEntry, error)
	Set(ctx context.Context, key StateKey, entry *StateEntry) error
	Delete(ctx context.Context, key StateKey) error
	List(ctx context.Context, pattern StateKeyPattern) ([]*StateEntry, error)
	Exists(ctx context.Context, key StateKey) (bool, error)
	GetMetadata(ctx context.Context, key StateKey) (*StateMetadata, error)
	SetMetadata(ctx context.Context, key StateKey, metadata *StateMetadata) error
	Batch(ctx context.Context, operations []BatchOperation) error
	Watch(ctx context.Context, pattern StateKeyPattern) (<-chan StateChangeEvent, error)
}

// StateKey represents a hierarchical state key
type StateKey struct {
	Namespace string `json:"namespace"`
	GraphID   string `json:"graph_id"`
	NodeID    string `json:"node_id"`
	Key       string `json:"key"`
	Version   *int   `json:"version,omitempty"`
}

// StateKeyPattern for matching multiple keys
type StateKeyPattern struct {
	Namespace string `json:"namespace"`
	GraphID   string `json:"graph_id"`
	NodeID    string `json:"node_id"`
	KeyPrefix string `json:"key_prefix"`
}

// StateEntry represents a complete state entry with metadata
type StateEntry struct {
	Key         StateKey               `json:"key"`
	Value       interface{}            `json:"value"`
	Metadata    *StateMetadata         `json:"metadata"`
	Version     int                    `json:"version"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	Tags        map[string]string      `json:"tags"`
	Annotations map[string]interface{} `json:"annotations"`
}

// StateMetadata holds metadata about state entries
type StateMetadata struct {
	Type        string                 `json:"type"`
	Schema      string                 `json:"schema"`
	Encoding    string                 `json:"encoding"`
	Compression string                 `json:"compression"`
	Checksum    string                 `json:"checksum"`
	Size        int64                  `json:"size"`
	AccessCount int64                  `json:"access_count"`
	LastAccess  time.Time              `json:"last_access"`
	Attributes  map[string]interface{} `json:"attributes"`
}

// BatchOperation represents a batch operation on state
type BatchOperation struct {
	Type  BatchOperationType `json:"type"`
	Key   StateKey           `json:"key"`
	Entry *StateEntry        `json:"entry,omitempty"`
}

// BatchOperationType defines types of batch operations
type BatchOperationType string

const (
	BatchOpSet    BatchOperationType = "set"
	BatchOpDelete BatchOperationType = "delete"
	BatchOpUpdate BatchOperationType = "update"
)

// StateChangeEvent represents a change in state
type StateChangeEvent struct {
	Type      StateChangeType        `json:"type"`
	Key       StateKey               `json:"key"`
	OldValue  interface{}            `json:"old_value,omitempty"`
	NewValue  interface{}            `json:"new_value,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// StateChangeType defines types of state changes
type StateChangeType string

const (
	StateChangeCreated StateChangeType = "created"
	StateChangeUpdated StateChangeType = "updated"
	StateChangeDeleted StateChangeType = "deleted"
	StateChangeExpired StateChangeType = "expired"
)

// StateValidator interface for validating state
type StateValidator interface {
	Validate(ctx context.Context, entry *StateEntry) error
	ValidateSchema(ctx context.Context, entry *StateEntry, schema string) error
	ValidateConstraints(ctx context.Context, entry *StateEntry, constraints []StateConstraint) error
}

// StateConstraint represents a constraint on state values
type StateConstraint struct {
	Type       ConstraintType         `json:"type"`
	Field      string                 `json:"field"`
	Value      interface{}            `json:"value"`
	Parameters map[string]interface{} `json:"parameters"`
	Message    string                 `json:"message"`
}

// ConstraintType defines types of state constraints
type ConstraintType string

const (
	ConstraintRequired  ConstraintType = "required"
	ConstraintTypeCheck ConstraintType = "type"
	ConstraintRange     ConstraintType = "range"
	ConstraintPattern   ConstraintType = "pattern"
	ConstraintUnique    ConstraintType = "unique"
	ConstraintCustom    ConstraintType = "custom"
)

// NewAdvancedStateManager creates a new advanced state manager
func NewAdvancedStateManager(store StateStore, config *StateManagerConfig, logger *logger.Logger) *AdvancedStateManager {
	if config == nil {
		config = &StateManagerConfig{
			EnableVersioning:   true,
			EnableTransactions: true,
			EnableSnapshots:    true,
			EnableCaching:      true,
			EnableMigrations:   true,
			EnableValidation:   true,
			MaxVersions:        10,
			SnapshotInterval:   time.Hour,
			CacheSize:          1000,
			CacheTTL:           time.Hour,
			TransactionTimeout: time.Minute * 5,
			ValidationMode:     ValidationModeStrict,
		}
	}

	manager := &AdvancedStateManager{
		stateStore: store,
		config:     config,
		logger:     logger,
	}

	// Initialize components based on configuration
	if config.EnableVersioning {
		manager.versionManager = NewStateVersionManager(store, logger)
	}

	if config.EnableTransactions {
		manager.transactionMgr = NewTransactionManager(store, config.TransactionTimeout, logger)
	}

	if config.EnableSnapshots {
		manager.snapshotManager = NewSnapshotManager(store, config.SnapshotInterval, logger)
	}

	if config.EnableMigrations {
		manager.migrationEngine = NewStateMigrationEngine(store, logger)
	}

	if config.EnableCaching {
		manager.cacheManager = NewStateCacheManager(config.CacheSize, config.CacheTTL, logger)
	}

	manager.eventBus = NewStateEventBus(logger)

	if config.EnableValidation {
		manager.validator = NewDefaultStateValidator(logger)
	}

	return manager
}

// GetState retrieves state with advanced features
func (asm *AdvancedStateManager) GetState(ctx context.Context, key StateKey) (*StateEntry, error) {
	ctx, span := stateTracer.Start(ctx, "advanced_state_manager.get_state",
		trace.WithAttributes(
			attribute.String("namespace", key.Namespace),
			attribute.String("graph_id", key.GraphID),
			attribute.String("node_id", key.NodeID),
			attribute.String("key", key.Key),
		),
	)
	defer span.End()

	// Check cache first if enabled
	if asm.config.EnableCaching && asm.cacheManager != nil {
		if cached, found := asm.cacheManager.Get(key); found {
			span.SetAttributes(attribute.Bool("cache_hit", true))
			return cached, nil
		}
		span.SetAttributes(attribute.Bool("cache_hit", false))
	}

	// Get from store
	entry, err := asm.stateStore.Get(ctx, key)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get state: %w", err)
	}

	// Update access metadata
	if entry.Metadata != nil {
		entry.Metadata.AccessCount++
		entry.Metadata.LastAccess = time.Now()
		asm.stateStore.SetMetadata(ctx, key, entry.Metadata)
	}

	// Cache the result if caching is enabled
	if asm.config.EnableCaching && asm.cacheManager != nil {
		asm.cacheManager.Set(key, entry)
	}

	asm.logger.Debug("State retrieved",
		"key", key,
		"version", entry.Version,
		"size", entry.Metadata.Size)

	return entry, nil
}

// SetState stores state with advanced features
func (asm *AdvancedStateManager) SetState(ctx context.Context, key StateKey, value interface{}, options ...StateOption) error {
	ctx, span := stateTracer.Start(ctx, "advanced_state_manager.set_state",
		trace.WithAttributes(
			attribute.String("namespace", key.Namespace),
			attribute.String("graph_id", key.GraphID),
			attribute.String("node_id", key.NodeID),
			attribute.String("key", key.Key),
		),
	)
	defer span.End()

	// Create state entry
	entry := &StateEntry{
		Key:         key,
		Value:       value,
		Version:     1,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Tags:        make(map[string]string),
		Annotations: make(map[string]interface{}),
		Metadata: &StateMetadata{
			Type:        "unknown",
			Encoding:    "json",
			AccessCount: 0,
			Attributes:  make(map[string]interface{}),
		},
	}

	// Apply options
	for _, option := range options {
		option(entry)
	}

	// Validate if validation is enabled
	if asm.config.EnableValidation && asm.validator != nil {
		if err := asm.validator.Validate(ctx, entry); err != nil {
			if asm.config.ValidationMode == ValidationModeStrict {
				span.RecordError(err)
				return fmt.Errorf("state validation failed: %w", err)
			} else if asm.config.ValidationMode == ValidationModeWarning {
				asm.logger.Warn("State validation warning", "error", err, "key", key)
			}
		}
	}

	// Handle versioning if enabled
	if asm.config.EnableVersioning && asm.versionManager != nil {
		version, err := asm.versionManager.CreateVersion(ctx, key, entry)
		if err != nil {
			span.RecordError(err)
			return fmt.Errorf("failed to create version: %w", err)
		}
		entry.Version = version
	}

	// Store the entry
	if err := asm.stateStore.Set(ctx, key, entry); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to set state: %w", err)
	}

	// Update cache if enabled
	if asm.config.EnableCaching && asm.cacheManager != nil {
		asm.cacheManager.Set(key, entry)
	}

	// Emit state change event
	asm.eventBus.Emit(StateChangeEvent{
		Type:      StateChangeCreated,
		Key:       key,
		NewValue:  value,
		Timestamp: time.Now(),
		Source:    "advanced_state_manager",
	})

	span.SetAttributes(
		attribute.Int("version", entry.Version),
		attribute.Int64("size", entry.Metadata.Size),
	)

	asm.logger.Info("State set",
		"key", key,
		"version", entry.Version,
		"type", entry.Metadata.Type)

	return nil
}

// DeleteState removes state with advanced features
func (asm *AdvancedStateManager) DeleteState(ctx context.Context, key StateKey) error {
	ctx, span := stateTracer.Start(ctx, "advanced_state_manager.delete_state",
		trace.WithAttributes(
			attribute.String("namespace", key.Namespace),
			attribute.String("graph_id", key.GraphID),
			attribute.String("key", key.Key),
		),
	)
	defer span.End()

	// Get current value for event
	oldEntry, _ := asm.stateStore.Get(ctx, key)

	// Delete from store
	if err := asm.stateStore.Delete(ctx, key); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to delete state: %w", err)
	}

	// Remove from cache if enabled
	if asm.config.EnableCaching && asm.cacheManager != nil {
		asm.cacheManager.Delete(key)
	}

	// Emit state change event
	var oldValue interface{}
	if oldEntry != nil {
		oldValue = oldEntry.Value
	}

	asm.eventBus.Emit(StateChangeEvent{
		Type:      StateChangeDeleted,
		Key:       key,
		OldValue:  oldValue,
		Timestamp: time.Now(),
		Source:    "advanced_state_manager",
	})

	asm.logger.Info("State deleted", "key", key)
	return nil
}

// BeginTransaction starts a new transaction
func (asm *AdvancedStateManager) BeginTransaction(ctx context.Context) (*StateTransaction, error) {
	if !asm.config.EnableTransactions || asm.transactionMgr == nil {
		return nil, fmt.Errorf("transactions not enabled")
	}

	return asm.transactionMgr.Begin(ctx)
}

// CreateSnapshot creates a snapshot of current state
func (asm *AdvancedStateManager) CreateSnapshot(ctx context.Context, pattern StateKeyPattern) (*StateSnapshot, error) {
	if !asm.config.EnableSnapshots || asm.snapshotManager == nil {
		return nil, fmt.Errorf("snapshots not enabled")
	}

	return asm.snapshotManager.CreateSnapshot(ctx, pattern)
}

// RestoreSnapshot restores state from a snapshot
func (asm *AdvancedStateManager) RestoreSnapshot(ctx context.Context, snapshotID string) error {
	if !asm.config.EnableSnapshots || asm.snapshotManager == nil {
		return fmt.Errorf("snapshots not enabled")
	}

	return asm.snapshotManager.RestoreSnapshot(ctx, snapshotID)
}

// MigrateState migrates state to a new schema version
func (asm *AdvancedStateManager) MigrateState(ctx context.Context, migration StateMigration) error {
	if !asm.config.EnableMigrations || asm.migrationEngine == nil {
		return fmt.Errorf("migrations not enabled")
	}

	return asm.migrationEngine.ApplyMigration(ctx, migration)
}

// Watch watches for state changes
func (asm *AdvancedStateManager) Watch(ctx context.Context, pattern StateKeyPattern) (<-chan StateChangeEvent, error) {
	return asm.stateStore.Watch(ctx, pattern)
}

// GetVersionHistory gets version history for a key
func (asm *AdvancedStateManager) GetVersionHistory(ctx context.Context, key StateKey) ([]*StateVersion, error) {
	if !asm.config.EnableVersioning || asm.versionManager == nil {
		return nil, fmt.Errorf("versioning not enabled")
	}

	return asm.versionManager.GetVersionHistory(ctx, key)
}

// StateOption allows customizing state entries
type StateOption func(*StateEntry)

// WithTags sets tags on a state entry
func WithTags(tags map[string]string) StateOption {
	return func(entry *StateEntry) {
		for k, v := range tags {
			entry.Tags[k] = v
		}
	}
}

// WithExpiration sets expiration time
func WithExpiration(duration time.Duration) StateOption {
	return func(entry *StateEntry) {
		expiry := time.Now().Add(duration)
		entry.ExpiresAt = &expiry
	}
}

// WithType sets the state type
func WithType(stateType string) StateOption {
	return func(entry *StateEntry) {
		entry.Metadata.Type = stateType
	}
}

// WithSchema sets the schema for validation
func WithSchema(schema string) StateOption {
	return func(entry *StateEntry) {
		entry.Metadata.Schema = schema
	}
}

// GetStats returns statistics about the state manager
func (asm *AdvancedStateManager) GetStats(ctx context.Context) (*StateManagerStats, error) {
	stats := &StateManagerStats{
		Timestamp: time.Now(),
	}

	if asm.cacheManager != nil {
		stats.CacheStats = asm.cacheManager.GetStats()
	}

	if asm.versionManager != nil {
		stats.VersionStats = asm.versionManager.GetStats()
	}

	if asm.transactionMgr != nil {
		stats.TransactionStats = asm.transactionMgr.GetStats()
	}

	return stats, nil
}

// StateManagerStats holds statistics about the state manager
type StateManagerStats struct {
	Timestamp        time.Time              `json:"timestamp"`
	CacheStats       *CacheStats            `json:"cache_stats,omitempty"`
	VersionStats     *VersionStats          `json:"version_stats,omitempty"`
	TransactionStats *TransactionStats      `json:"transaction_stats,omitempty"`
	TotalEntries     int64                  `json:"total_entries"`
	TotalSize        int64                  `json:"total_size"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// Close closes the state manager and cleans up resources
func (asm *AdvancedStateManager) Close() error {
	asm.mutex.Lock()
	defer asm.mutex.Unlock()

	var errors []error

	if asm.cacheManager != nil {
		if err := asm.cacheManager.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if asm.transactionMgr != nil {
		if err := asm.transactionMgr.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if asm.snapshotManager != nil {
		if err := asm.snapshotManager.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors closing state manager: %v", errors)
	}

	asm.logger.Info("Advanced state manager closed")
	return nil
}

// Additional types and interfaces needed by the state manager

// StateMigration represents a state migration
type StateMigration struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	FromVersion string                 `json:"from_version"`
	ToVersion   string                 `json:"to_version"`
	Script      string                 `json:"script"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// StateEventBus handles state change events
type StateEventBus struct {
	logger      *logger.Logger
	subscribers map[string][]func(StateChangeEvent)
	mutex       sync.RWMutex
}

// NewStateEventBus creates a new state event bus
func NewStateEventBus(logger *logger.Logger) *StateEventBus {
	return &StateEventBus{
		logger:      logger,
		subscribers: make(map[string][]func(StateChangeEvent)),
	}
}

// Emit emits a state change event
func (seb *StateEventBus) Emit(event StateChangeEvent) {
	seb.mutex.RLock()
	defer seb.mutex.RUnlock()

	eventType := string(event.Type)
	if subscribers, exists := seb.subscribers[eventType]; exists {
		for _, subscriber := range subscribers {
			go subscriber(event)
		}
	}

	// Also notify wildcard subscribers
	if subscribers, exists := seb.subscribers["*"]; exists {
		for _, subscriber := range subscribers {
			go subscriber(event)
		}
	}
}

// Subscribe subscribes to state change events
func (seb *StateEventBus) Subscribe(eventType string, handler func(StateChangeEvent)) {
	seb.mutex.Lock()
	defer seb.mutex.Unlock()

	seb.subscribers[eventType] = append(seb.subscribers[eventType], handler)
}
