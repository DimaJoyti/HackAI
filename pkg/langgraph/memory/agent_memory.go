package memory

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

var memoryTracer = otel.Tracer("hackai/langgraph/memory")

// AgentMemory provides comprehensive memory capabilities for agents
type AgentMemory struct {
	agentID          string
	workingMemory    *WorkingMemory
	episodicMemory   *EpisodicMemory
	semanticMemory   *SemanticMemory
	proceduralMemory *ProceduralMemory
	vectorMemory     *VectorMemory
	memoryManager    *MemoryManager
	config           *MemoryConfig
	logger           *logger.Logger
	mutex            sync.RWMutex
}

// MemoryConfig holds configuration for agent memory
type MemoryConfig struct {
	AgentID               string        `json:"agent_id"`
	WorkingMemorySize     int           `json:"working_memory_size"`
	EpisodicMemorySize    int           `json:"episodic_memory_size"`
	SemanticMemorySize    int           `json:"semantic_memory_size"`
	ProceduralMemorySize  int           `json:"procedural_memory_size"`
	VectorMemorySize      int           `json:"vector_memory_size"`
	ConsolidationInterval time.Duration `json:"consolidation_interval"`
	RetentionPeriod       time.Duration `json:"retention_period"`
	CompressionThreshold  int           `json:"compression_threshold"`
	EnablePersistence     bool          `json:"enable_persistence"`
	EnableCompression     bool          `json:"enable_compression"`
	EnableEncryption      bool          `json:"enable_encryption"`
	EnableIndexing        bool          `json:"enable_indexing"`
	EnableAnalytics       bool          `json:"enable_analytics"`
	PersistenceBackend    string        `json:"persistence_backend"`
	VectorDimensions      int           `json:"vector_dimensions"`
	SimilarityThreshold   float64       `json:"similarity_threshold"`
}

// MemoryEntry represents a basic memory entry
type MemoryEntry struct {
	ID          string                 `json:"id"`
	Type        MemoryType             `json:"type"`
	Content     interface{}            `json:"content"`
	Context     map[string]interface{} `json:"context"`
	Importance  float64                `json:"importance"`
	Confidence  float64                `json:"confidence"`
	Timestamp   time.Time              `json:"timestamp"`
	LastAccess  time.Time              `json:"last_access"`
	AccessCount int64                  `json:"access_count"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	Compressed  bool                   `json:"compressed"`
	Encrypted   bool                   `json:"encrypted"`
}

// MemoryQuery represents a memory query
type MemoryQuery struct {
	Type            MemoryType             `json:"type"`
	Content         string                 `json:"content"`
	Context         map[string]interface{} `json:"context"`
	Tags            []string               `json:"tags"`
	TimeRange       *TimeRange             `json:"time_range,omitempty"`
	ImportanceRange *Range                 `json:"importance_range,omitempty"`
	ConfidenceRange *Range                 `json:"confidence_range,omitempty"`
	Limit           int                    `json:"limit"`
	SortBy          string                 `json:"sort_by"`
	SortOrder       string                 `json:"sort_order"`
	IncludeExpired  bool                   `json:"include_expired"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// MemoryResult represents memory query results
type MemoryResult struct {
	Entries    []*MemoryEntry         `json:"entries"`
	TotalCount int                    `json:"total_count"`
	QueryTime  time.Duration          `json:"query_time"`
	Relevance  []float64              `json:"relevance"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// TimeRange represents a time range for queries
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Range represents a numeric range
type Range struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// MemoryType defines different types of memory
type MemoryType string

const (
	MemoryTypeWorking    MemoryType = "working"
	MemoryTypeEpisodic   MemoryType = "episodic"
	MemoryTypeSemantic   MemoryType = "semantic"
	MemoryTypeProcedural MemoryType = "procedural"
	MemoryTypeVector     MemoryType = "vector"
)

// NewAgentMemory creates a new agent memory system
func NewAgentMemory(agentID string, config *MemoryConfig, logger *logger.Logger) (*AgentMemory, error) {
	if config == nil {
		config = &MemoryConfig{
			AgentID:               agentID,
			WorkingMemorySize:     100,
			EpisodicMemorySize:    1000,
			SemanticMemorySize:    5000,
			ProceduralMemorySize:  500,
			VectorMemorySize:      10000,
			ConsolidationInterval: time.Hour,
			RetentionPeriod:       30 * 24 * time.Hour, // 30 days
			CompressionThreshold:  1000,
			EnablePersistence:     true,
			EnableCompression:     true,
			EnableEncryption:      false,
			EnableIndexing:        true,
			EnableAnalytics:       true,
			PersistenceBackend:    "redis",
			VectorDimensions:      1536,
			SimilarityThreshold:   0.8,
		}
	}

	memory := &AgentMemory{
		agentID: agentID,
		config:  config,
		logger:  logger,
	}

	// Initialize memory components
	var err error

	memory.workingMemory, err = NewWorkingMemory(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create working memory: %w", err)
	}

	memory.episodicMemory, err = NewEpisodicMemory(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create episodic memory: %w", err)
	}

	memory.semanticMemory, err = NewSemanticMemory(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create semantic memory: %w", err)
	}

	memory.proceduralMemory, err = NewProceduralMemory(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create procedural memory: %w", err)
	}

	memory.vectorMemory, err = NewVectorMemory(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create vector memory: %w", err)
	}

	memory.memoryManager, err = NewMemoryManager(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create memory manager: %w", err)
	}

	// Start background processes
	go memory.startConsolidationProcess()
	go memory.startMaintenanceProcess()

	logger.Info("Agent memory system initialized",
		"agent_id", agentID,
		"working_memory_size", config.WorkingMemorySize,
		"episodic_memory_size", config.EpisodicMemorySize,
		"semantic_memory_size", config.SemanticMemorySize,
		"procedural_memory_size", config.ProceduralMemorySize,
		"vector_memory_size", config.VectorMemorySize)

	return memory, nil
}

// Store stores a memory entry
func (am *AgentMemory) Store(ctx context.Context, entry *MemoryEntry) error {
	ctx, span := memoryTracer.Start(ctx, "agent_memory.store",
		trace.WithAttributes(
			attribute.String("agent.id", am.agentID),
			attribute.String("memory.type", string(entry.Type)),
			attribute.String("memory.id", entry.ID),
		),
	)
	defer span.End()

	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Set metadata
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	entry.LastAccess = time.Now()
	entry.AccessCount = 1

	// Route to appropriate memory type
	switch entry.Type {
	case MemoryTypeWorking:
		return am.workingMemory.Store(ctx, entry)
	case MemoryTypeEpisodic:
		return am.episodicMemory.Store(ctx, entry)
	case MemoryTypeSemantic:
		return am.semanticMemory.Store(ctx, entry)
	case MemoryTypeProcedural:
		return am.proceduralMemory.Store(ctx, entry)
	case MemoryTypeVector:
		return am.vectorMemory.Store(ctx, entry)
	default:
		return fmt.Errorf("unknown memory type: %s", entry.Type)
	}
}

// Retrieve retrieves a memory entry by ID
func (am *AgentMemory) Retrieve(ctx context.Context, memoryType MemoryType, id string) (*MemoryEntry, error) {
	ctx, span := memoryTracer.Start(ctx, "agent_memory.retrieve",
		trace.WithAttributes(
			attribute.String("agent.id", am.agentID),
			attribute.String("memory.type", string(memoryType)),
			attribute.String("memory.id", id),
		),
	)
	defer span.End()

	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Route to appropriate memory type
	switch memoryType {
	case MemoryTypeWorking:
		return am.workingMemory.Retrieve(ctx, id)
	case MemoryTypeEpisodic:
		return am.episodicMemory.Retrieve(ctx, id)
	case MemoryTypeSemantic:
		return am.semanticMemory.Retrieve(ctx, id)
	case MemoryTypeProcedural:
		return am.proceduralMemory.Retrieve(ctx, id)
	case MemoryTypeVector:
		return am.vectorMemory.Retrieve(ctx, id)
	default:
		return nil, fmt.Errorf("unknown memory type: %s", memoryType)
	}
}

// Query queries memory with complex criteria
func (am *AgentMemory) Query(ctx context.Context, query *MemoryQuery) (*MemoryResult, error) {
	ctx, span := memoryTracer.Start(ctx, "agent_memory.query",
		trace.WithAttributes(
			attribute.String("agent.id", am.agentID),
			attribute.String("query.type", string(query.Type)),
			attribute.Int("query.limit", query.Limit),
		),
	)
	defer span.End()

	startTime := time.Now()

	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Route to appropriate memory type
	var result *MemoryResult
	var err error

	switch query.Type {
	case MemoryTypeWorking:
		result, err = am.workingMemory.Query(ctx, query)
	case MemoryTypeEpisodic:
		result, err = am.episodicMemory.Query(ctx, query)
	case MemoryTypeSemantic:
		result, err = am.semanticMemory.Query(ctx, query)
	case MemoryTypeProcedural:
		result, err = am.proceduralMemory.Query(ctx, query)
	case MemoryTypeVector:
		result, err = am.vectorMemory.Query(ctx, query)
	default:
		// Query all memory types
		result, err = am.queryAllMemoryTypes(ctx, query)
	}

	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	result.QueryTime = time.Since(startTime)

	span.SetAttributes(
		attribute.Int("result.count", len(result.Entries)),
		attribute.Float64("query.duration", result.QueryTime.Seconds()),
	)

	return result, nil
}

// Update updates a memory entry
func (am *AgentMemory) Update(ctx context.Context, entry *MemoryEntry) error {
	ctx, span := memoryTracer.Start(ctx, "agent_memory.update",
		trace.WithAttributes(
			attribute.String("agent.id", am.agentID),
			attribute.String("memory.type", string(entry.Type)),
			attribute.String("memory.id", entry.ID),
		),
	)
	defer span.End()

	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Update access metadata
	entry.LastAccess = time.Now()
	entry.AccessCount++

	// Route to appropriate memory type
	switch entry.Type {
	case MemoryTypeWorking:
		return am.workingMemory.Update(ctx, entry)
	case MemoryTypeEpisodic:
		return am.episodicMemory.Update(ctx, entry)
	case MemoryTypeSemantic:
		return am.semanticMemory.Update(ctx, entry)
	case MemoryTypeProcedural:
		return am.proceduralMemory.Update(ctx, entry)
	case MemoryTypeVector:
		return am.vectorMemory.Update(ctx, entry)
	default:
		return fmt.Errorf("unknown memory type: %s", entry.Type)
	}
}

// Delete deletes a memory entry
func (am *AgentMemory) Delete(ctx context.Context, memoryType MemoryType, id string) error {
	ctx, span := memoryTracer.Start(ctx, "agent_memory.delete",
		trace.WithAttributes(
			attribute.String("agent.id", am.agentID),
			attribute.String("memory.type", string(memoryType)),
			attribute.String("memory.id", id),
		),
	)
	defer span.End()

	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Route to appropriate memory type
	switch memoryType {
	case MemoryTypeWorking:
		return am.workingMemory.Delete(ctx, id)
	case MemoryTypeEpisodic:
		return am.episodicMemory.Delete(ctx, id)
	case MemoryTypeSemantic:
		return am.semanticMemory.Delete(ctx, id)
	case MemoryTypeProcedural:
		return am.proceduralMemory.Delete(ctx, id)
	case MemoryTypeVector:
		return am.vectorMemory.Delete(ctx, id)
	default:
		return fmt.Errorf("unknown memory type: %s", memoryType)
	}
}

// Helper methods

func (am *AgentMemory) queryAllMemoryTypes(ctx context.Context, query *MemoryQuery) (*MemoryResult, error) {
	allEntries := make([]*MemoryEntry, 0)
	totalCount := 0

	// Query each memory type
	memoryTypes := []MemoryType{
		MemoryTypeWorking,
		MemoryTypeEpisodic,
		MemoryTypeSemantic,
		MemoryTypeProcedural,
		MemoryTypeVector,
	}

	for _, memType := range memoryTypes {
		typeQuery := *query
		typeQuery.Type = memType

		var result *MemoryResult
		var err error

		switch memType {
		case MemoryTypeWorking:
			result, err = am.workingMemory.Query(ctx, &typeQuery)
		case MemoryTypeEpisodic:
			result, err = am.episodicMemory.Query(ctx, &typeQuery)
		case MemoryTypeSemantic:
			result, err = am.semanticMemory.Query(ctx, &typeQuery)
		case MemoryTypeProcedural:
			result, err = am.proceduralMemory.Query(ctx, &typeQuery)
		case MemoryTypeVector:
			result, err = am.vectorMemory.Query(ctx, &typeQuery)
		}

		if err != nil {
			am.logger.Warn("Failed to query memory type", "type", memType, "error", err)
			continue
		}

		allEntries = append(allEntries, result.Entries...)
		totalCount += result.TotalCount
	}

	// Sort and limit results
	sortedEntries := am.sortMemoryEntries(allEntries, query.SortBy, query.SortOrder)
	if query.Limit > 0 && len(sortedEntries) > query.Limit {
		sortedEntries = sortedEntries[:query.Limit]
	}

	return &MemoryResult{
		Entries:    sortedEntries,
		TotalCount: totalCount,
		Metadata:   map[string]interface{}{"query_type": "all_types"},
	}, nil
}

func (am *AgentMemory) sortMemoryEntries(entries []*MemoryEntry, sortBy, sortOrder string) []*MemoryEntry {
	// Simple sorting implementation - in production, use more sophisticated sorting
	return entries
}

func (am *AgentMemory) startConsolidationProcess() {
	ticker := time.NewTicker(am.config.ConsolidationInterval)
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()
		if err := am.consolidateMemories(ctx); err != nil {
			am.logger.Error("Memory consolidation failed", "error", err)
		}
	}
}

func (am *AgentMemory) startMaintenanceProcess() {
	ticker := time.NewTicker(time.Hour) // Run maintenance every hour
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()
		if err := am.performMaintenance(ctx); err != nil {
			am.logger.Error("Memory maintenance failed", "error", err)
		}
	}
}

func (am *AgentMemory) consolidateMemories(ctx context.Context) error {
	am.logger.Debug("Starting memory consolidation", "agent_id", am.agentID)

	// Consolidate working memory to long-term memory
	if err := am.memoryManager.ConsolidateWorkingMemory(ctx, am.workingMemory, am.episodicMemory); err != nil {
		return fmt.Errorf("working memory consolidation failed: %w", err)
	}

	// Consolidate episodic to semantic memory
	if err := am.memoryManager.ConsolidateEpisodicMemory(ctx, am.episodicMemory, am.semanticMemory); err != nil {
		return fmt.Errorf("episodic memory consolidation failed: %w", err)
	}

	am.logger.Debug("Memory consolidation completed", "agent_id", am.agentID)
	return nil
}

func (am *AgentMemory) performMaintenance(ctx context.Context) error {
	am.logger.Debug("Starting memory maintenance", "agent_id", am.agentID)

	// Clean up expired memories
	if err := am.memoryManager.CleanupExpiredMemories(ctx, am); err != nil {
		return fmt.Errorf("expired memory cleanup failed: %w", err)
	}

	// Compress old memories
	if am.config.EnableCompression {
		if err := am.memoryManager.CompressOldMemories(ctx, am); err != nil {
			return fmt.Errorf("memory compression failed: %w", err)
		}
	}

	// Update memory statistics
	if err := am.memoryManager.UpdateStatistics(ctx, am); err != nil {
		return fmt.Errorf("statistics update failed: %w", err)
	}

	am.logger.Debug("Memory maintenance completed", "agent_id", am.agentID)
	return nil
}

// GetStatistics returns memory statistics
func (am *AgentMemory) GetStatistics() *MemoryStatistics {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	return &MemoryStatistics{
		AgentID:           am.agentID,
		WorkingMemory:     am.workingMemory.GetStatistics(),
		EpisodicMemory:    am.episodicMemory.GetStatistics(),
		SemanticMemory:    am.semanticMemory.GetStatistics(),
		ProceduralMemory:  am.proceduralMemory.GetStatistics(),
		VectorMemory:      am.vectorMemory.GetStatistics(),
		TotalEntries:      am.getTotalEntries(),
		LastConsolidation: time.Now(), // Simplified
		LastMaintenance:   time.Now(), // Simplified
	}
}

func (am *AgentMemory) getTotalEntries() int {
	return am.workingMemory.GetSize() +
		am.episodicMemory.GetSize() +
		am.semanticMemory.GetSize() +
		am.proceduralMemory.GetSize() +
		am.vectorMemory.GetSize()
}

// MemoryStatistics holds statistics for agent memory
type MemoryStatistics struct {
	AgentID           string                `json:"agent_id"`
	WorkingMemory     *MemoryTypeStatistics `json:"working_memory"`
	EpisodicMemory    *MemoryTypeStatistics `json:"episodic_memory"`
	SemanticMemory    *MemoryTypeStatistics `json:"semantic_memory"`
	ProceduralMemory  *MemoryTypeStatistics `json:"procedural_memory"`
	VectorMemory      *MemoryTypeStatistics `json:"vector_memory"`
	TotalEntries      int                   `json:"total_entries"`
	LastConsolidation time.Time             `json:"last_consolidation"`
	LastMaintenance   time.Time             `json:"last_maintenance"`
}

// MemoryTypeStatistics holds statistics for a specific memory type
type MemoryTypeStatistics struct {
	EntryCount      int       `json:"entry_count"`
	TotalSize       int64     `json:"total_size"`
	AverageSize     float64   `json:"average_size"`
	OldestEntry     time.Time `json:"oldest_entry"`
	NewestEntry     time.Time `json:"newest_entry"`
	AccessCount     int64     `json:"access_count"`
	LastAccess      time.Time `json:"last_access"`
	CompressionRate float64   `json:"compression_rate"`
}
