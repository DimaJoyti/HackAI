package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// Checkpoint represents a saved state at a specific point in execution
type Checkpoint struct {
	ID         string                 `json:"id"`
	GraphID    string                 `json:"graph_id"`
	Timestamp  time.Time              `json:"timestamp"`
	NodeID     string                 `json:"node_id"`
	State      llm.GraphState         `json:"state"`
	Metadata   map[string]interface{} `json:"metadata"`
	ParentID   *string                `json:"parent_id,omitempty"`
	BranchID   *string                `json:"branch_id,omitempty"`
	Compressed bool                   `json:"compressed"`
	Data       []byte                 `json:"data,omitempty"`
}

// CheckpointStorage interface for storing checkpoints
type CheckpointStorage interface {
	Store(ctx context.Context, checkpoint *Checkpoint) error
	Load(ctx context.Context, checkpointID string) (*Checkpoint, error)
	List(ctx context.Context, graphID string) ([]*Checkpoint, error)
	Delete(ctx context.Context, checkpointID string) error
	Cleanup(ctx context.Context, policy RetentionPolicy) error
}

// RetentionPolicy defines how long to keep checkpoints and state
type RetentionPolicy struct {
	MaxCheckpoints int           `json:"max_checkpoints"`
	MaxAge         time.Duration `json:"max_age"`
	CompressAfter  time.Duration `json:"compress_after"`
	ArchiveAfter   time.Duration `json:"archive_after"`
}

// MemoryCheckpointStorage implements in-memory checkpoint storage
type MemoryCheckpointStorage struct {
	checkpoints map[string]*Checkpoint
	byGraphID   map[string][]*Checkpoint
	mutex       sync.RWMutex
	logger      *logger.Logger
}

// NewMemoryCheckpointStorage creates a new memory-based checkpoint storage
func NewMemoryCheckpointStorage() *MemoryCheckpointStorage {
	return &MemoryCheckpointStorage{
		checkpoints: make(map[string]*Checkpoint),
		byGraphID:   make(map[string][]*Checkpoint),
	}
}

// Store stores a checkpoint in memory
func (s *MemoryCheckpointStorage) Store(ctx context.Context, checkpoint *Checkpoint) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Store checkpoint
	s.checkpoints[checkpoint.ID] = checkpoint

	// Index by graph ID
	if s.byGraphID[checkpoint.GraphID] == nil {
		s.byGraphID[checkpoint.GraphID] = make([]*Checkpoint, 0)
	}
	s.byGraphID[checkpoint.GraphID] = append(s.byGraphID[checkpoint.GraphID], checkpoint)

	return nil
}

// Load loads a checkpoint from memory
func (s *MemoryCheckpointStorage) Load(ctx context.Context, checkpointID string) (*Checkpoint, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	checkpoint, exists := s.checkpoints[checkpointID]
	if !exists {
		return nil, fmt.Errorf("checkpoint %s not found", checkpointID)
	}

	return checkpoint, nil
}

// List lists all checkpoints for a graph
func (s *MemoryCheckpointStorage) List(ctx context.Context, graphID string) ([]*Checkpoint, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	checkpoints, exists := s.byGraphID[graphID]
	if !exists {
		return []*Checkpoint{}, nil
	}

	// Return a copy to prevent external modification
	result := make([]*Checkpoint, len(checkpoints))
	copy(result, checkpoints)
	return result, nil
}

// Delete deletes a checkpoint from memory
func (s *MemoryCheckpointStorage) Delete(ctx context.Context, checkpointID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	checkpoint, exists := s.checkpoints[checkpointID]
	if !exists {
		return fmt.Errorf("checkpoint %s not found", checkpointID)
	}

	// Remove from main storage
	delete(s.checkpoints, checkpointID)

	// Remove from graph index
	graphCheckpoints := s.byGraphID[checkpoint.GraphID]
	for i, cp := range graphCheckpoints {
		if cp.ID == checkpointID {
			s.byGraphID[checkpoint.GraphID] = append(graphCheckpoints[:i], graphCheckpoints[i+1:]...)
			break
		}
	}

	return nil
}

// Cleanup removes old checkpoints based on retention policy
func (s *MemoryCheckpointStorage) Cleanup(ctx context.Context, policy RetentionPolicy) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	toDelete := make([]string, 0)

	// Find checkpoints to delete based on age
	for id, checkpoint := range s.checkpoints {
		if policy.MaxAge > 0 && now.Sub(checkpoint.Timestamp) > policy.MaxAge {
			toDelete = append(toDelete, id)
		}
	}

	// Delete old checkpoints
	for _, id := range toDelete {
		checkpoint := s.checkpoints[id]
		delete(s.checkpoints, id)

		// Remove from graph index
		graphCheckpoints := s.byGraphID[checkpoint.GraphID]
		for i, cp := range graphCheckpoints {
			if cp.ID == id {
				s.byGraphID[checkpoint.GraphID] = append(graphCheckpoints[:i], graphCheckpoints[i+1:]...)
				break
			}
		}
	}

	// Enforce max checkpoints per graph
	if policy.MaxCheckpoints > 0 {
		for graphID, checkpoints := range s.byGraphID {
			if len(checkpoints) > policy.MaxCheckpoints {
				// Sort by timestamp and keep only the most recent
				// For simplicity, just remove the oldest ones
				excess := len(checkpoints) - policy.MaxCheckpoints
				for i := 0; i < excess; i++ {
					oldest := checkpoints[0]
					delete(s.checkpoints, oldest.ID)
					checkpoints = checkpoints[1:]
				}
				s.byGraphID[graphID] = checkpoints
			}
		}
	}

	return nil
}

// StateSerializer interface for serializing graph state
type StateSerializer interface {
	Serialize(state llm.GraphState) ([]byte, error)
	Deserialize(data []byte) (llm.GraphState, error)
}

// JSONStateSerializer implements JSON-based state serialization
type JSONStateSerializer struct{}

// NewJSONStateSerializer creates a new JSON state serializer
func NewJSONStateSerializer() *JSONStateSerializer {
	return &JSONStateSerializer{}
}

// Serialize serializes a graph state to JSON
func (s *JSONStateSerializer) Serialize(state llm.GraphState) ([]byte, error) {
	return json.Marshal(state)
}

// Deserialize deserializes a graph state from JSON
func (s *JSONStateSerializer) Deserialize(data []byte) (llm.GraphState, error) {
	var state llm.GraphState
	err := json.Unmarshal(data, &state)
	return state, err
}

// StateCompressor interface for compressing serialized state
type StateCompressor interface {
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
}

// GzipStateCompressor implements gzip-based state compression
type GzipStateCompressor struct {
	level int
}

// NewGzipStateCompressor creates a new gzip state compressor
func NewGzipStateCompressor() *GzipStateCompressor {
	return &GzipStateCompressor{
		level: 6, // Default compression level
	}
}

// Compress compresses data using gzip
func (c *GzipStateCompressor) Compress(data []byte) ([]byte, error) {
	// For now, return the data as-is
	// In a real implementation, you would use gzip compression
	return data, nil
}

// Decompress decompresses data using gzip
func (c *GzipStateCompressor) Decompress(data []byte) ([]byte, error) {
	// For now, return the data as-is
	// In a real implementation, you would use gzip decompression
	return data, nil
}

// FileCheckpointStorage implements file-based checkpoint storage
type FileCheckpointStorage struct {
	basePath   string
	serializer StateSerializer
	logger     *logger.Logger
	mutex      sync.RWMutex
}

// NewFileCheckpointStorage creates a new file-based checkpoint storage
func NewFileCheckpointStorage(basePath string, logger *logger.Logger) *FileCheckpointStorage {
	return &FileCheckpointStorage{
		basePath:   basePath,
		serializer: NewJSONStateSerializer(),
		logger:     logger,
	}
}

// Store stores a checkpoint to file
func (s *FileCheckpointStorage) Store(ctx context.Context, checkpoint *Checkpoint) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Serialize checkpoint
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return fmt.Errorf("failed to serialize checkpoint: %w", err)
	}

	// Write to file (implementation would use actual file operations)
	// For now, just log the data size and return success
	_ = data // TODO: Implement actual file writing
	return nil
}

// Load loads a checkpoint from file
func (s *FileCheckpointStorage) Load(ctx context.Context, checkpointID string) (*Checkpoint, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Read from file and deserialize (implementation would use actual file operations)
	// For now, return an error
	return nil, fmt.Errorf("checkpoint %s not found", checkpointID)
}

// List lists all checkpoints for a graph from files
func (s *FileCheckpointStorage) List(ctx context.Context, graphID string) ([]*Checkpoint, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Scan directory and list files (implementation would use actual file operations)
	// For now, return empty list
	return []*Checkpoint{}, nil
}

// Delete deletes a checkpoint file
func (s *FileCheckpointStorage) Delete(ctx context.Context, checkpointID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Delete file (implementation would use actual file operations)
	// For now, just return success
	return nil
}

// Cleanup removes old checkpoint files based on retention policy
func (s *FileCheckpointStorage) Cleanup(ctx context.Context, policy RetentionPolicy) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Scan directory and clean up old files (implementation would use actual file operations)
	// For now, just return success
	return nil
}

// Checkpointer handles state checkpointing and recovery
type Checkpointer struct {
	storage    CheckpointStorage
	serializer StateSerializer
	compressor StateCompressor
	config     CheckpointerConfig
	logger     *logger.Logger
	mutex      sync.RWMutex
}

// CheckpointerConfig holds checkpointer configuration
type CheckpointerConfig struct {
	AutoCheckpoint    bool          `json:"auto_checkpoint"`
	Interval          time.Duration `json:"interval"`
	CompressionLevel  int           `json:"compression_level"`
	EncryptionEnabled bool          `json:"encryption_enabled"`
}

// NewCheckpointer creates a new checkpointer
func NewCheckpointer(storage CheckpointStorage, logger *logger.Logger) *Checkpointer {
	return &Checkpointer{
		storage:    storage,
		serializer: NewJSONStateSerializer(),
		compressor: NewGzipStateCompressor(),
		config: CheckpointerConfig{
			AutoCheckpoint:    true,
			Interval:          5 * time.Minute,
			CompressionLevel:  6,
			EncryptionEnabled: false,
		},
		logger: logger,
	}
}

// CreateCheckpoint creates a new checkpoint
func (c *Checkpointer) CreateCheckpoint(ctx context.Context, graphID, nodeID string, state llm.GraphState) (*Checkpoint, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	checkpoint := &Checkpoint{
		ID:        uuid.New().String(),
		GraphID:   graphID,
		Timestamp: time.Now(),
		NodeID:    nodeID,
		State:     state,
		Metadata:  make(map[string]interface{}),
	}

	// Serialize state
	serialized, err := c.serializer.Serialize(state)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize state: %w", err)
	}

	// Compress if enabled
	if c.config.CompressionLevel > 0 {
		compressed, err := c.compressor.Compress(serialized)
		if err != nil {
			return nil, fmt.Errorf("failed to compress state: %w", err)
		}
		checkpoint.Compressed = true
		checkpoint.Data = compressed
	} else {
		checkpoint.Data = serialized
	}

	// Store checkpoint
	err = c.storage.Store(ctx, checkpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to store checkpoint: %w", err)
	}

	if c.logger != nil {
		c.logger.Info("Checkpoint created",
			"checkpoint_id", checkpoint.ID,
			"graph_id", graphID,
			"node_id", nodeID)
	}

	return checkpoint, nil
}

// RestoreFromCheckpoint restores state from a checkpoint
func (c *Checkpointer) RestoreFromCheckpoint(ctx context.Context, checkpointID string) (llm.GraphState, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	checkpoint, err := c.storage.Load(ctx, checkpointID)
	if err != nil {
		return llm.GraphState{}, fmt.Errorf("failed to load checkpoint: %w", err)
	}

	// Decompress if needed
	data := checkpoint.Data
	if checkpoint.Compressed {
		decompressed, err := c.compressor.Decompress(data)
		if err != nil {
			return llm.GraphState{}, fmt.Errorf("failed to decompress checkpoint: %w", err)
		}
		data = decompressed
	}

	// Deserialize state
	state, err := c.serializer.Deserialize(data)
	if err != nil {
		return llm.GraphState{}, fmt.Errorf("failed to deserialize state: %w", err)
	}

	if c.logger != nil {
		c.logger.Info("Checkpoint restored",
			"checkpoint_id", checkpointID,
			"graph_id", checkpoint.GraphID,
			"node_id", checkpoint.NodeID)
	}

	return state, nil
}
