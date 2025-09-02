package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/llm"
)

// FilePersistence implements StatePersistence using file system
type FilePersistence struct {
	basePath string
	mutex    sync.RWMutex
}

// NewFilePersistence creates a new file-based persistence
func NewFilePersistence(basePath string) (*FilePersistence, error) {
	// Create base directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create persistence directory: %w", err)
	}

	return &FilePersistence{
		basePath: basePath,
	}, nil
}

// SaveState saves the graph state to a file
func (p *FilePersistence) SaveState(ctx context.Context, graphID string, state llm.GraphState) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Create state wrapper with metadata
	stateWrapper := StateWrapper{
		GraphID: graphID,
		State:   state,
		SavedAt: time.Now(),
		Version: "1.0",
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(stateWrapper, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// Write to file
	filename := fmt.Sprintf("%s.json", graphID)
	filepath := filepath.Join(p.basePath, filename)

	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}

// LoadState loads the graph state from a file
func (p *FilePersistence) LoadState(ctx context.Context, graphID string) (llm.GraphState, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	filename := fmt.Sprintf("%s.json", graphID)
	filepath := filepath.Join(p.basePath, filename)

	// Read file
	data, err := os.ReadFile(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return llm.GraphState{}, fmt.Errorf("state not found for graph %s", graphID)
		}
		return llm.GraphState{}, fmt.Errorf("failed to read state file: %w", err)
	}

	// Unmarshal JSON
	var stateWrapper StateWrapper
	if err := json.Unmarshal(data, &stateWrapper); err != nil {
		return llm.GraphState{}, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	return stateWrapper.State, nil
}

// DeleteState deletes the graph state file
func (p *FilePersistence) DeleteState(ctx context.Context, graphID string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	filename := fmt.Sprintf("%s.json", graphID)
	filepath := filepath.Join(p.basePath, filename)

	if err := os.Remove(filepath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return fmt.Errorf("failed to delete state file: %w", err)
	}

	return nil
}

// ListStates lists all saved graph states
func (p *FilePersistence) ListStates(ctx context.Context) ([]string, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	entries, err := os.ReadDir(p.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read persistence directory: %w", err)
	}

	var graphIDs []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			// Remove .json extension to get graph ID
			graphID := entry.Name()[:len(entry.Name())-5]
			graphIDs = append(graphIDs, graphID)
		}
	}

	return graphIDs, nil
}

// StateWrapper wraps the graph state with metadata
type StateWrapper struct {
	GraphID string         `json:"graph_id"`
	State   llm.GraphState `json:"state"`
	SavedAt time.Time      `json:"saved_at"`
	Version string         `json:"version"`
}

// InMemoryPersistence implements StatePersistence using in-memory storage
type InMemoryPersistence struct {
	states map[string]llm.GraphState
	mutex  sync.RWMutex
}

// NewInMemoryPersistence creates a new in-memory persistence
func NewInMemoryPersistence() *InMemoryPersistence {
	return &InMemoryPersistence{
		states: make(map[string]llm.GraphState),
	}
}

// SaveState saves the graph state in memory
func (p *InMemoryPersistence) SaveState(ctx context.Context, graphID string, state llm.GraphState) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Create a deep copy of the state to avoid reference issues
	stateCopy := p.deepCopyState(state)
	p.states[graphID] = stateCopy

	return nil
}

// LoadState loads the graph state from memory
func (p *InMemoryPersistence) LoadState(ctx context.Context, graphID string) (llm.GraphState, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	state, exists := p.states[graphID]
	if !exists {
		return llm.GraphState{}, fmt.Errorf("state not found for graph %s", graphID)
	}

	// Return a deep copy to avoid reference issues
	return p.deepCopyState(state), nil
}

// DeleteState deletes the graph state from memory
func (p *InMemoryPersistence) DeleteState(ctx context.Context, graphID string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	delete(p.states, graphID)
	return nil
}

// ListStates lists all saved graph states in memory
func (p *InMemoryPersistence) ListStates(ctx context.Context) ([]string, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	graphIDs := make([]string, 0, len(p.states))
	for graphID := range p.states {
		graphIDs = append(graphIDs, graphID)
	}

	return graphIDs, nil
}

// deepCopyState creates a deep copy of the graph state
func (p *InMemoryPersistence) deepCopyState(state llm.GraphState) llm.GraphState {
	// Use JSON marshal/unmarshal for deep copy
	data, _ := json.Marshal(state)
	var copy llm.GraphState
	json.Unmarshal(data, &copy)
	return copy
}

// DatabasePersistence implements StatePersistence using a database
type DatabasePersistence struct {
	// This would contain database connection and configuration
	// For now, we'll implement a placeholder
	connectionString string
	tableName        string
}

// NewDatabasePersistence creates a new database-based persistence
func NewDatabasePersistence(connectionString, tableName string) *DatabasePersistence {
	return &DatabasePersistence{
		connectionString: connectionString,
		tableName:        tableName,
	}
}

// SaveState saves the graph state to database
func (p *DatabasePersistence) SaveState(ctx context.Context, graphID string, state llm.GraphState) error {
	// Placeholder implementation
	// In a real implementation, this would:
	// 1. Connect to the database
	// 2. Serialize the state to JSON
	// 3. INSERT or UPDATE the state record
	// 4. Handle database errors appropriately

	return fmt.Errorf("database persistence not implemented yet")
}

// LoadState loads the graph state from database
func (p *DatabasePersistence) LoadState(ctx context.Context, graphID string) (llm.GraphState, error) {
	// Placeholder implementation
	// In a real implementation, this would:
	// 1. Connect to the database
	// 2. SELECT the state record by graph ID
	// 3. Deserialize the JSON to GraphState
	// 4. Handle not found and other database errors

	return llm.GraphState{}, fmt.Errorf("database persistence not implemented yet")
}

// DeleteState deletes the graph state from database
func (p *DatabasePersistence) DeleteState(ctx context.Context, graphID string) error {
	// Placeholder implementation
	// In a real implementation, this would:
	// 1. Connect to the database
	// 2. DELETE the state record by graph ID
	// 3. Handle database errors appropriately

	return fmt.Errorf("database persistence not implemented yet")
}

// ListStates lists all saved graph states in database
func (p *DatabasePersistence) ListStates(ctx context.Context) ([]string, error) {
	// Placeholder implementation
	// In a real implementation, this would:
	// 1. Connect to the database
	// 2. SELECT all graph IDs from the table
	// 3. Return the list of graph IDs
	// 4. Handle database errors appropriately

	return nil, fmt.Errorf("database persistence not implemented yet")
}

// PersistenceManager manages multiple persistence backends
type PersistenceManager struct {
	primary   StatePersistence
	secondary StatePersistence
	config    PersistenceConfig
}

// StatePersistence interface (re-exported for convenience)
type StatePersistence interface {
	SaveState(ctx context.Context, graphID string, state llm.GraphState) error
	LoadState(ctx context.Context, graphID string) (llm.GraphState, error)
	DeleteState(ctx context.Context, graphID string) error
	ListStates(ctx context.Context) ([]string, error)
}

// PersistenceConfig represents persistence configuration
type PersistenceConfig struct {
	EnableBackup     bool          `json:"enable_backup"`
	BackupInterval   time.Duration `json:"backup_interval"`
	RetentionPeriod  time.Duration `json:"retention_period"`
	CompressionLevel int           `json:"compression_level"`
}

// NewPersistenceManager creates a new persistence manager
func NewPersistenceManager(primary, secondary StatePersistence, config PersistenceConfig) *PersistenceManager {
	return &PersistenceManager{
		primary:   primary,
		secondary: secondary,
		config:    config,
	}
}

// SaveState saves state to primary and optionally secondary persistence
func (m *PersistenceManager) SaveState(ctx context.Context, graphID string, state llm.GraphState) error {
	// Save to primary
	if err := m.primary.SaveState(ctx, graphID, state); err != nil {
		return fmt.Errorf("primary persistence failed: %w", err)
	}

	// Save to secondary if configured and backup is enabled
	if m.secondary != nil && m.config.EnableBackup {
		if err := m.secondary.SaveState(ctx, graphID, state); err != nil {
			// Log error but don't fail the operation
			// In a real implementation, you'd use a proper logger
			fmt.Printf("Secondary persistence failed: %v\n", err)
		}
	}

	return nil
}

// LoadState loads state from primary, falls back to secondary if needed
func (m *PersistenceManager) LoadState(ctx context.Context, graphID string) (llm.GraphState, error) {
	// Try primary first
	state, err := m.primary.LoadState(ctx, graphID)
	if err == nil {
		return state, nil
	}

	// Fall back to secondary if available
	if m.secondary != nil {
		state, err := m.secondary.LoadState(ctx, graphID)
		if err == nil {
			// Restore to primary
			if restoreErr := m.primary.SaveState(ctx, graphID, state); restoreErr != nil {
				fmt.Printf("Failed to restore state to primary: %v\n", restoreErr)
			}
			return state, nil
		}
	}

	return llm.GraphState{}, fmt.Errorf("state not found in any persistence backend")
}

// DeleteState deletes state from both primary and secondary
func (m *PersistenceManager) DeleteState(ctx context.Context, graphID string) error {
	var errors []error

	// Delete from primary
	if err := m.primary.DeleteState(ctx, graphID); err != nil {
		errors = append(errors, fmt.Errorf("primary deletion failed: %w", err))
	}

	// Delete from secondary if available
	if m.secondary != nil {
		if err := m.secondary.DeleteState(ctx, graphID); err != nil {
			errors = append(errors, fmt.Errorf("secondary deletion failed: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("deletion errors: %v", errors)
	}

	return nil
}

// ListStates lists states from primary persistence
func (m *PersistenceManager) ListStates(ctx context.Context) ([]string, error) {
	return m.primary.ListStates(ctx)
}
