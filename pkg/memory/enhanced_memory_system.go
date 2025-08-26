package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var memoryTracer = otel.Tracer("hackai/memory/enhanced")

// EnhancedMemorySystem provides advanced memory management capabilities
type EnhancedMemorySystem struct {
	id                   string
	hierarchicalStorage  *HierarchicalStorage
	semanticIndexer      *SemanticIndexer
	crossAgentSharing    *CrossAgentSharing
	memoryConsolidator   *MemoryConsolidator
	accessController     *AccessController
	performanceOptimizer *PerformanceOptimizer
	config               *MemorySystemConfig
	logger               *logger.Logger
	mutex                sync.RWMutex
}

// MemorySystemConfig configures the memory system
type MemorySystemConfig struct {
	EnableHierarchicalStorage bool          `json:"enable_hierarchical_storage"`
	EnableSemanticIndexing    bool          `json:"enable_semantic_indexing"`
	EnableCrossAgentSharing   bool          `json:"enable_cross_agent_sharing"`
	EnableMemoryConsolidation bool          `json:"enable_memory_consolidation"`
	MaxMemorySize             int64         `json:"max_memory_size"`
	ConsolidationInterval     time.Duration `json:"consolidation_interval"`
	IndexingBatchSize         int           `json:"indexing_batch_size"`
	SharingPermissions        []string      `json:"sharing_permissions"`
	CompressionEnabled        bool          `json:"compression_enabled"`
	EncryptionEnabled         bool          `json:"encryption_enabled"`
	BackupEnabled             bool          `json:"backup_enabled"`
	BackupInterval            time.Duration `json:"backup_interval"`
}

// MemoryEntry represents a memory entry
type MemoryEntry struct {
	ID             string                 `json:"id"`
	AgentID        string                 `json:"agent_id"`
	Type           MemoryType             `json:"type"`
	Category       MemoryCategory         `json:"category"`
	Content        interface{}            `json:"content"`
	Metadata       map[string]interface{} `json:"metadata"`
	Tags           []string               `json:"tags"`
	Importance     float64                `json:"importance"`
	AccessCount    int64                  `json:"access_count"`
	LastAccessed   time.Time              `json:"last_accessed"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	ExpiresAt      *time.Time             `json:"expires_at"`
	StorageLevel   StorageLevel           `json:"storage_level"`
	SemanticVector []float64              `json:"semantic_vector"`
	RelatedEntries []string               `json:"related_entries"`
	AccessHistory  []*AccessRecord        `json:"access_history"`
	SharingPolicy  *SharingPolicy         `json:"sharing_policy"`
}

// MemoryType defines the type of memory
type MemoryType string

const (
	MemoryTypeWorking    MemoryType = "working"
	MemoryTypeEpisodic   MemoryType = "episodic"
	MemoryTypeSemantic   MemoryType = "semantic"
	MemoryTypeProcedural MemoryType = "procedural"
	MemoryTypeEmotional  MemoryType = "emotional"
	MemoryTypeFactual    MemoryType = "factual"
	MemoryTypeExperience MemoryType = "experience"
)

// MemoryCategory defines the category of memory
type MemoryCategory string

const (
	CategoryKnowledge    MemoryCategory = "knowledge"
	CategoryExperience   MemoryCategory = "experience"
	CategorySkill        MemoryCategory = "skill"
	CategoryContext      MemoryCategory = "context"
	CategoryRelationship MemoryCategory = "relationship"
	CategoryPreference   MemoryCategory = "preference"
	CategoryGoal         MemoryCategory = "goal"
	CategoryStrategy     MemoryCategory = "strategy"
	CategoryFeedback     MemoryCategory = "feedback"
)

// StorageLevel defines the storage hierarchy level
type StorageLevel string

const (
	StorageLevelHot    StorageLevel = "hot"    // Frequently accessed, in-memory
	StorageLevelWarm   StorageLevel = "warm"   // Occasionally accessed, cached
	StorageLevelCold   StorageLevel = "cold"   // Rarely accessed, disk storage
	StorageLevelFrozen StorageLevel = "frozen" // Archived, compressed storage
)

// AccessRecord represents a memory access record
type AccessRecord struct {
	AccessedBy string    `json:"accessed_by"`
	AccessType string    `json:"access_type"`
	Timestamp  time.Time `json:"timestamp"`
	Context    string    `json:"context"`
}

// SharingPolicy defines memory sharing policies
type SharingPolicy struct {
	AllowedAgents   []string               `json:"allowed_agents"`
	AllowedGroups   []string               `json:"allowed_groups"`
	AccessLevel     AccessLevel            `json:"access_level"`
	ExpirationTime  *time.Time             `json:"expiration_time"`
	Conditions      map[string]interface{} `json:"conditions"`
	RequireApproval bool                   `json:"require_approval"`
}

// AccessLevel defines access levels
type AccessLevel string

const (
	AccessLevelRead    AccessLevel = "read"
	AccessLevelWrite   AccessLevel = "write"
	AccessLevelExecute AccessLevel = "execute"
	AccessLevelAdmin   AccessLevel = "admin"
)

// HierarchicalStorage manages hierarchical memory storage
type HierarchicalStorage struct {
	hotStorage    map[string]*MemoryEntry
	warmStorage   map[string]*MemoryEntry
	coldStorage   map[string]*MemoryEntry
	frozenStorage map[string]*MemoryEntry
	storageStats  *StorageStats
	logger        *logger.Logger
	mutex         sync.RWMutex
}

// StorageStats represents storage statistics
type StorageStats struct {
	HotEntries    int64   `json:"hot_entries"`
	WarmEntries   int64   `json:"warm_entries"`
	ColdEntries   int64   `json:"cold_entries"`
	FrozenEntries int64   `json:"frozen_entries"`
	TotalSize     int64   `json:"total_size"`
	HitRate       float64 `json:"hit_rate"`
	MissRate      float64 `json:"miss_rate"`
}

// SemanticIndexer provides semantic indexing capabilities
type SemanticIndexer struct {
	vectorIndex    map[string][]float64
	semanticGraph  *SemanticGraph
	indexingQueue  chan *MemoryEntry
	batchProcessor *BatchProcessor
	logger         *logger.Logger
	mutex          sync.RWMutex
}

// SemanticGraph represents semantic relationships
type SemanticGraph struct {
	Nodes map[string]*SemanticNode `json:"nodes"`
	Edges map[string]*SemanticEdge `json:"edges"`
}

// SemanticNode represents a semantic node
type SemanticNode struct {
	ID          string                 `json:"id"`
	MemoryID    string                 `json:"memory_id"`
	Concepts    []string               `json:"concepts"`
	Embeddings  []float64              `json:"embeddings"`
	Connections []string               `json:"connections"`
	Weight      float64                `json:"weight"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SemanticEdge represents a semantic relationship
type SemanticEdge struct {
	ID        string                 `json:"id"`
	FromNode  string                 `json:"from_node"`
	ToNode    string                 `json:"to_node"`
	Type      RelationType           `json:"type"`
	Strength  float64                `json:"strength"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"created_at"`
}

// RelationType defines types of semantic relationships
type RelationType string

const (
	RelationTypeSimilar      RelationType = "similar"
	RelationTypeRelated      RelationType = "related"
	RelationTypeCausal       RelationType = "causal"
	RelationTypeTemporal     RelationType = "temporal"
	RelationTypeHierarchical RelationType = "hierarchical"
	RelationTypeConflicting  RelationType = "conflicting"
)

// CrossAgentSharing manages memory sharing between agents
type CrossAgentSharing struct {
	sharedMemories   map[string]*SharedMemory
	sharingRequests  map[string]*SharingRequest
	accessController *AccessController
	logger           *logger.Logger
	mutex            sync.RWMutex
}

// SharedMemory represents shared memory
type SharedMemory struct {
	ID            string                 `json:"id"`
	OriginalID    string                 `json:"original_id"`
	OwnerAgent    string                 `json:"owner_agent"`
	SharedWith    []string               `json:"shared_with"`
	SharingPolicy *SharingPolicy         `json:"sharing_policy"`
	Content       interface{}            `json:"content"`
	Metadata      map[string]interface{} `json:"metadata"`
	CreatedAt     time.Time              `json:"created_at"`
	LastAccessed  time.Time              `json:"last_accessed"`
	AccessCount   int64                  `json:"access_count"`
}

// SharingRequest represents a memory sharing request
type SharingRequest struct {
	ID            string                 `json:"id"`
	RequesterID   string                 `json:"requester_id"`
	MemoryID      string                 `json:"memory_id"`
	OwnerID       string                 `json:"owner_id"`
	AccessLevel   AccessLevel            `json:"access_level"`
	Justification string                 `json:"justification"`
	Status        RequestStatus          `json:"status"`
	Metadata      map[string]interface{} `json:"metadata"`
	CreatedAt     time.Time              `json:"created_at"`
	ProcessedAt   *time.Time             `json:"processed_at"`
}

// RequestStatus defines sharing request status
type RequestStatus string

const (
	RequestStatusPending  RequestStatus = "pending"
	RequestStatusApproved RequestStatus = "approved"
	RequestStatusDenied   RequestStatus = "denied"
	RequestStatusExpired  RequestStatus = "expired"
)

// MemoryConsolidator consolidates and optimizes memory
type MemoryConsolidator struct {
	consolidationRules []*ConsolidationRule
	scheduler          *ConsolidationScheduler
	logger             *logger.Logger
}

// ConsolidationRule defines memory consolidation rules
type ConsolidationRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Condition  string                 `json:"condition"`
	Action     ConsolidationAction    `json:"action"`
	Parameters map[string]interface{} `json:"parameters"`
	Priority   int                    `json:"priority"`
	Enabled    bool                   `json:"enabled"`
}

// ConsolidationAction defines consolidation actions
type ConsolidationAction string

const (
	ActionMerge    ConsolidationAction = "merge"
	ActionCompress ConsolidationAction = "compress"
	ActionArchive  ConsolidationAction = "archive"
	ActionDelete   ConsolidationAction = "delete"
	ActionPromote  ConsolidationAction = "promote"
	ActionDemote   ConsolidationAction = "demote"
)

// NewEnhancedMemorySystem creates a new enhanced memory system
func NewEnhancedMemorySystem(config *MemorySystemConfig, logger *logger.Logger) *EnhancedMemorySystem {
	if config == nil {
		config = DefaultMemorySystemConfig()
	}

	ems := &EnhancedMemorySystem{
		id:     uuid.New().String(),
		config: config,
		logger: logger,
	}

	// Initialize components
	ems.hierarchicalStorage = NewHierarchicalStorage(logger)

	if config.EnableSemanticIndexing {
		ems.semanticIndexer = NewSemanticIndexer(config.IndexingBatchSize, logger)
	}

	if config.EnableCrossAgentSharing {
		ems.crossAgentSharing = NewCrossAgentSharing(logger)
	}

	if config.EnableMemoryConsolidation {
		ems.memoryConsolidator = NewMemoryConsolidator(config.ConsolidationInterval, logger)
	}

	ems.accessController = NewAccessController(logger)
	ems.performanceOptimizer = NewPerformanceOptimizer(logger)

	return ems
}

// DefaultMemorySystemConfig returns default configuration
func DefaultMemorySystemConfig() *MemorySystemConfig {
	return &MemorySystemConfig{
		EnableHierarchicalStorage: true,
		EnableSemanticIndexing:    true,
		EnableCrossAgentSharing:   true,
		EnableMemoryConsolidation: true,
		MaxMemorySize:             1024 * 1024 * 1024, // 1GB
		ConsolidationInterval:     time.Hour,
		IndexingBatchSize:         100,
		SharingPermissions:        []string{"read", "write"},
		CompressionEnabled:        true,
		EncryptionEnabled:         false,
		BackupEnabled:             true,
		BackupInterval:            24 * time.Hour,
	}
}

// StoreMemory stores a memory entry
func (ems *EnhancedMemorySystem) StoreMemory(ctx context.Context, entry *MemoryEntry) error {
	ctx, span := memoryTracer.Start(ctx, "enhanced_memory_system.store_memory",
		trace.WithAttributes(
			attribute.String("memory.id", entry.ID),
			attribute.String("memory.type", string(entry.Type)),
			attribute.String("agent.id", entry.AgentID),
		),
	)
	defer span.End()

	// Validate entry
	if err := ems.validateMemoryEntry(entry); err != nil {
		span.RecordError(err)
		return fmt.Errorf("memory entry validation failed: %w", err)
	}

	// Set metadata
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	entry.CreatedAt = time.Now()
	entry.UpdatedAt = time.Now()
	entry.StorageLevel = StorageLevelHot // Start in hot storage

	// Generate semantic vector if indexing is enabled
	if ems.config.EnableSemanticIndexing && ems.semanticIndexer != nil {
		vector, err := ems.semanticIndexer.GenerateVector(ctx, entry)
		if err != nil {
			ems.logger.Warn("Failed to generate semantic vector", "error", err)
		} else {
			entry.SemanticVector = vector
		}
	}

	// Store in hierarchical storage
	if err := ems.hierarchicalStorage.Store(ctx, entry); err != nil {
		span.RecordError(err)
		return fmt.Errorf("hierarchical storage failed: %w", err)
	}

	// Index semantically if enabled
	if ems.config.EnableSemanticIndexing && ems.semanticIndexer != nil {
		if err := ems.semanticIndexer.IndexMemory(ctx, entry); err != nil {
			ems.logger.Warn("Semantic indexing failed", "error", err)
		}
	}

	ems.logger.Info("Memory stored successfully",
		"memory_id", entry.ID,
		"agent_id", entry.AgentID,
		"type", entry.Type)

	return nil
}

// RetrieveMemory retrieves a memory entry
func (ems *EnhancedMemorySystem) RetrieveMemory(ctx context.Context, memoryID, agentID string) (*MemoryEntry, error) {
	ctx, span := memoryTracer.Start(ctx, "enhanced_memory_system.retrieve_memory",
		trace.WithAttributes(
			attribute.String("memory.id", memoryID),
			attribute.String("agent.id", agentID),
		),
	)
	defer span.End()

	// Check access permissions
	if err := ems.accessController.CheckAccess(ctx, agentID, memoryID, AccessLevelRead); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("access denied: %w", err)
	}

	// Retrieve from hierarchical storage
	entry, err := ems.hierarchicalStorage.Retrieve(ctx, memoryID)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("memory retrieval failed: %w", err)
	}

	// Update access statistics
	entry.AccessCount++
	entry.LastAccessed = time.Now()
	entry.AccessHistory = append(entry.AccessHistory, &AccessRecord{
		AccessedBy: agentID,
		AccessType: "read",
		Timestamp:  time.Now(),
		Context:    "retrieve",
	})

	// Promote to higher storage level if frequently accessed
	ems.performanceOptimizer.OptimizeStorageLevel(entry)

	ems.logger.Debug("Memory retrieved successfully",
		"memory_id", memoryID,
		"agent_id", agentID)

	return entry, nil
}

// validateMemoryEntry validates a memory entry
func (ems *EnhancedMemorySystem) validateMemoryEntry(entry *MemoryEntry) error {
	if entry.AgentID == "" {
		return fmt.Errorf("agent ID cannot be empty")
	}

	if entry.Content == nil {
		return fmt.Errorf("content cannot be nil")
	}

	if entry.Type == "" {
		entry.Type = MemoryTypeWorking // Default type
	}

	if entry.Category == "" {
		entry.Category = CategoryKnowledge // Default category
	}

	if entry.Importance < 0 || entry.Importance > 1 {
		entry.Importance = 0.5 // Default importance
	}

	return nil
}

// SearchMemories searches for memories using semantic similarity
func (ems *EnhancedMemorySystem) SearchMemories(ctx context.Context, query string, agentID string, limit int) ([]*MemoryEntry, error) {
	ctx, span := memoryTracer.Start(ctx, "enhanced_memory_system.search_memories",
		trace.WithAttributes(
			attribute.String("query", query),
			attribute.String("agent.id", agentID),
			attribute.Int("limit", limit),
		),
	)
	defer span.End()

	if !ems.config.EnableSemanticIndexing || ems.semanticIndexer == nil {
		return nil, fmt.Errorf("semantic indexing not enabled")
	}

	// Perform semantic search
	results, err := ems.semanticIndexer.Search(ctx, query, agentID, limit)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("semantic search failed: %w", err)
	}

	ems.logger.Debug("Memory search completed",
		"query", query,
		"agent_id", agentID,
		"results", len(results))

	return results, nil
}

// ShareMemory shares a memory with other agents
func (ems *EnhancedMemorySystem) ShareMemory(ctx context.Context, memoryID, ownerID string, sharingPolicy *SharingPolicy) error {
	ctx, span := memoryTracer.Start(ctx, "enhanced_memory_system.share_memory",
		trace.WithAttributes(
			attribute.String("memory.id", memoryID),
			attribute.String("owner.id", ownerID),
		),
	)
	defer span.End()

	if !ems.config.EnableCrossAgentSharing || ems.crossAgentSharing == nil {
		return fmt.Errorf("cross-agent sharing not enabled")
	}

	// Check ownership
	entry, err := ems.hierarchicalStorage.Retrieve(ctx, memoryID)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("memory not found: %w", err)
	}

	if entry.AgentID != ownerID {
		return fmt.Errorf("access denied: not owner of memory")
	}

	// Create shared memory
	if err := ems.crossAgentSharing.ShareMemory(ctx, entry, sharingPolicy); err != nil {
		span.RecordError(err)
		return fmt.Errorf("memory sharing failed: %w", err)
	}

	ems.logger.Info("Memory shared successfully",
		"memory_id", memoryID,
		"owner_id", ownerID,
		"shared_with", len(sharingPolicy.AllowedAgents))

	return nil
}

// ConsolidateMemories triggers memory consolidation
func (ems *EnhancedMemorySystem) ConsolidateMemories(ctx context.Context) error {
	ctx, span := memoryTracer.Start(ctx, "enhanced_memory_system.consolidate_memories")
	defer span.End()

	if !ems.config.EnableMemoryConsolidation || ems.memoryConsolidator == nil {
		return fmt.Errorf("memory consolidation not enabled")
	}

	if err := ems.memoryConsolidator.Consolidate(ctx, ems.hierarchicalStorage); err != nil {
		span.RecordError(err)
		return fmt.Errorf("memory consolidation failed: %w", err)
	}

	ems.logger.Info("Memory consolidation completed")
	return nil
}

// GetMemoryStats returns memory system statistics
func (ems *EnhancedMemorySystem) GetMemoryStats() *MemorySystemStats {
	ems.mutex.RLock()
	defer ems.mutex.RUnlock()

	stats := &MemorySystemStats{
		TotalEntries:      0,
		StorageStats:      ems.hierarchicalStorage.GetStats(),
		IndexingStats:     nil,
		SharingStats:      nil,
		LastConsolidation: time.Time{},
	}

	if ems.semanticIndexer != nil {
		stats.IndexingStats = ems.semanticIndexer.GetStats()
	}

	if ems.crossAgentSharing != nil {
		stats.SharingStats = ems.crossAgentSharing.GetStats()
	}

	return stats
}

// MemorySystemStats represents memory system statistics
type MemorySystemStats struct {
	TotalEntries      int64          `json:"total_entries"`
	StorageStats      *StorageStats  `json:"storage_stats"`
	IndexingStats     *IndexingStats `json:"indexing_stats"`
	SharingStats      *SharingStats  `json:"sharing_stats"`
	LastConsolidation time.Time      `json:"last_consolidation"`
}

// IndexingStats represents indexing statistics
type IndexingStats struct {
	IndexedEntries  int64     `json:"indexed_entries"`
	PendingIndexing int64     `json:"pending_indexing"`
	IndexingRate    float64   `json:"indexing_rate"`
	LastIndexed     time.Time `json:"last_indexed"`
}

// SharingStats represents sharing statistics
type SharingStats struct {
	SharedMemories   int64     `json:"shared_memories"`
	PendingRequests  int64     `json:"pending_requests"`
	ApprovedRequests int64     `json:"approved_requests"`
	DeniedRequests   int64     `json:"denied_requests"`
	LastShared       time.Time `json:"last_shared"`
}
