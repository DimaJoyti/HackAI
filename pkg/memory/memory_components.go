package memory

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// NewHierarchicalStorage creates a new hierarchical storage
func NewHierarchicalStorage(logger *logger.Logger) *HierarchicalStorage {
	return &HierarchicalStorage{
		hotStorage:    make(map[string]*MemoryEntry),
		warmStorage:   make(map[string]*MemoryEntry),
		coldStorage:   make(map[string]*MemoryEntry),
		frozenStorage: make(map[string]*MemoryEntry),
		storageStats: &StorageStats{
			HotEntries:    0,
			WarmEntries:   0,
			ColdEntries:   0,
			FrozenEntries: 0,
			TotalSize:     0,
			HitRate:       0.0,
			MissRate:      0.0,
		},
		logger: logger,
	}
}

// Store stores a memory entry in hierarchical storage
func (hs *HierarchicalStorage) Store(ctx context.Context, entry *MemoryEntry) error {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	// Store in appropriate level based on storage level
	switch entry.StorageLevel {
	case StorageLevelHot:
		hs.hotStorage[entry.ID] = entry
		hs.storageStats.HotEntries++
	case StorageLevelWarm:
		hs.warmStorage[entry.ID] = entry
		hs.storageStats.WarmEntries++
	case StorageLevelCold:
		hs.coldStorage[entry.ID] = entry
		hs.storageStats.ColdEntries++
	case StorageLevelFrozen:
		hs.frozenStorage[entry.ID] = entry
		hs.storageStats.FrozenEntries++
	default:
		hs.hotStorage[entry.ID] = entry
		hs.storageStats.HotEntries++
	}

	hs.logger.Debug("Memory stored in hierarchical storage",
		"memory_id", entry.ID,
		"storage_level", entry.StorageLevel)

	return nil
}

// Retrieve retrieves a memory entry from hierarchical storage
func (hs *HierarchicalStorage) Retrieve(ctx context.Context, memoryID string) (*MemoryEntry, error) {
	hs.mutex.RLock()
	defer hs.mutex.RUnlock()

	// Search in order of access speed: hot -> warm -> cold -> frozen
	if entry, exists := hs.hotStorage[memoryID]; exists {
		hs.storageStats.HitRate = (hs.storageStats.HitRate + 1.0) / 2.0
		return entry, nil
	}

	if entry, exists := hs.warmStorage[memoryID]; exists {
		hs.storageStats.HitRate = (hs.storageStats.HitRate + 0.8) / 2.0
		return entry, nil
	}

	if entry, exists := hs.coldStorage[memoryID]; exists {
		hs.storageStats.HitRate = (hs.storageStats.HitRate + 0.6) / 2.0
		return entry, nil
	}

	if entry, exists := hs.frozenStorage[memoryID]; exists {
		hs.storageStats.HitRate = (hs.storageStats.HitRate + 0.4) / 2.0
		return entry, nil
	}

	hs.storageStats.MissRate = (hs.storageStats.MissRate + 1.0) / 2.0
	return nil, fmt.Errorf("memory not found: %s", memoryID)
}

// GetStats returns storage statistics
func (hs *HierarchicalStorage) GetStats() *StorageStats {
	hs.mutex.RLock()
	defer hs.mutex.RUnlock()

	return &StorageStats{
		HotEntries:    hs.storageStats.HotEntries,
		WarmEntries:   hs.storageStats.WarmEntries,
		ColdEntries:   hs.storageStats.ColdEntries,
		FrozenEntries: hs.storageStats.FrozenEntries,
		TotalSize:     hs.storageStats.TotalSize,
		HitRate:       hs.storageStats.HitRate,
		MissRate:      hs.storageStats.MissRate,
	}
}

// NewSemanticIndexer creates a new semantic indexer
func NewSemanticIndexer(batchSize int, logger *logger.Logger) *SemanticIndexer {
	return &SemanticIndexer{
		vectorIndex: make(map[string][]float64),
		semanticGraph: &SemanticGraph{
			Nodes: make(map[string]*SemanticNode),
			Edges: make(map[string]*SemanticEdge),
		},
		indexingQueue:  make(chan *MemoryEntry, batchSize*2),
		batchProcessor: NewBatchProcessor(batchSize, logger),
		logger:         logger,
	}
}

// GenerateVector generates a semantic vector for a memory entry
func (si *SemanticIndexer) GenerateVector(ctx context.Context, entry *MemoryEntry) ([]float64, error) {
	// Simple vector generation - in production, use actual embedding models
	vector := make([]float64, 384) // Standard embedding dimension

	// Generate pseudo-random but deterministic vector based on content
	contentStr := fmt.Sprintf("%v", entry.Content)
	hash := 0
	for _, char := range contentStr {
		hash = hash*31 + int(char)
	}

	for i := range vector {
		hash = hash*1103515245 + 12345
		vector[i] = float64(hash%1000)/1000.0 - 0.5 // Normalize to [-0.5, 0.5]
	}

	return vector, nil
}

// IndexMemory indexes a memory entry semantically
func (si *SemanticIndexer) IndexMemory(ctx context.Context, entry *MemoryEntry) error {
	si.mutex.Lock()
	defer si.mutex.Unlock()

	// Store vector
	if len(entry.SemanticVector) > 0 {
		si.vectorIndex[entry.ID] = entry.SemanticVector
	}

	// Create semantic node
	node := &SemanticNode{
		ID:          uuid.New().String(),
		MemoryID:    entry.ID,
		Concepts:    entry.Tags,
		Embeddings:  entry.SemanticVector,
		Connections: make([]string, 0),
		Weight:      entry.Importance,
		Metadata:    make(map[string]interface{}),
	}

	si.semanticGraph.Nodes[node.ID] = node

	si.logger.Debug("Memory indexed semantically",
		"memory_id", entry.ID,
		"node_id", node.ID)

	return nil
}

// Search performs semantic search
func (si *SemanticIndexer) Search(ctx context.Context, query string, agentID string, limit int) ([]*MemoryEntry, error) {
	si.mutex.RLock()
	defer si.mutex.RUnlock()

	// Generate query vector
	queryVector, err := si.generateQueryVector(query)
	if err != nil {
		return nil, fmt.Errorf("failed to generate query vector: %w", err)
	}

	// Calculate similarities
	similarities := make(map[string]float64)
	for memoryID, vector := range si.vectorIndex {
		similarity := si.calculateCosineSimilarity(queryVector, vector)
		similarities[memoryID] = similarity
	}

	// Sort by similarity and return top results
	// Simple implementation - in production, use more sophisticated ranking
	var results []*MemoryEntry
	count := 0
	for memoryID, similarity := range similarities {
		if count >= limit {
			break
		}
		if similarity > 0.5 { // Threshold
			// Create mock result - in production, retrieve actual memory entries
			result := &MemoryEntry{
				ID:      memoryID,
				AgentID: agentID,
				Type:    MemoryTypeSemantic,
				Content: fmt.Sprintf("Search result for: %s (similarity: %.2f)", query, similarity),
				Metadata: map[string]interface{}{
					"similarity": similarity,
					"query":      query,
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
			count++
		}
	}

	return results, nil
}

// generateQueryVector generates a vector for a search query
func (si *SemanticIndexer) generateQueryVector(query string) ([]float64, error) {
	// Simple query vector generation - in production, use actual embedding models
	vector := make([]float64, 384)

	hash := 0
	for _, char := range query {
		hash = hash*31 + int(char)
	}

	for i := range vector {
		hash = hash*1103515245 + 12345
		vector[i] = float64(hash%1000)/1000.0 - 0.5
	}

	return vector, nil
}

// calculateCosineSimilarity calculates cosine similarity between two vectors
func (si *SemanticIndexer) calculateCosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0.0
	}

	var dotProduct, normA, normB float64
	for i := range a {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0.0
	}

	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

// GetStats returns indexing statistics
func (si *SemanticIndexer) GetStats() *IndexingStats {
	si.mutex.RLock()
	defer si.mutex.RUnlock()

	return &IndexingStats{
		IndexedEntries:  int64(len(si.vectorIndex)),
		PendingIndexing: int64(len(si.indexingQueue)),
		IndexingRate:    100.0, // Simulated
		LastIndexed:     time.Now(),
	}
}

// NewCrossAgentSharing creates a new cross-agent sharing manager
func NewCrossAgentSharing(logger *logger.Logger) *CrossAgentSharing {
	return &CrossAgentSharing{
		sharedMemories:   make(map[string]*SharedMemory),
		sharingRequests:  make(map[string]*SharingRequest),
		accessController: NewAccessController(logger),
		logger:           logger,
	}
}

// ShareMemory shares a memory with other agents
func (cas *CrossAgentSharing) ShareMemory(ctx context.Context, entry *MemoryEntry, policy *SharingPolicy) error {
	cas.mutex.Lock()
	defer cas.mutex.Unlock()

	sharedMemory := &SharedMemory{
		ID:            uuid.New().String(),
		OriginalID:    entry.ID,
		OwnerAgent:    entry.AgentID,
		SharedWith:    policy.AllowedAgents,
		SharingPolicy: policy,
		Content:       entry.Content,
		Metadata:      entry.Metadata,
		CreatedAt:     time.Now(),
		LastAccessed:  time.Now(),
		AccessCount:   0,
	}

	cas.sharedMemories[sharedMemory.ID] = sharedMemory

	cas.logger.Info("Memory shared",
		"shared_memory_id", sharedMemory.ID,
		"original_id", entry.ID,
		"owner", entry.AgentID,
		"shared_with", len(policy.AllowedAgents))

	return nil
}

// GetStats returns sharing statistics
func (cas *CrossAgentSharing) GetStats() *SharingStats {
	cas.mutex.RLock()
	defer cas.mutex.RUnlock()

	pendingRequests := int64(0)
	approvedRequests := int64(0)
	deniedRequests := int64(0)

	for _, request := range cas.sharingRequests {
		switch request.Status {
		case RequestStatusPending:
			pendingRequests++
		case RequestStatusApproved:
			approvedRequests++
		case RequestStatusDenied:
			deniedRequests++
		}
	}

	return &SharingStats{
		SharedMemories:   int64(len(cas.sharedMemories)),
		PendingRequests:  pendingRequests,
		ApprovedRequests: approvedRequests,
		DeniedRequests:   deniedRequests,
		LastShared:       time.Now(),
	}
}

// NewMemoryConsolidator creates a new memory consolidator
func NewMemoryConsolidator(interval time.Duration, logger *logger.Logger) *MemoryConsolidator {
	return &MemoryConsolidator{
		consolidationRules: make([]*ConsolidationRule, 0),
		scheduler:          NewConsolidationScheduler(interval, logger),
		logger:             logger,
	}
}

// Consolidate performs memory consolidation
func (mc *MemoryConsolidator) Consolidate(ctx context.Context, storage *HierarchicalStorage) error {
	mc.logger.Info("Starting memory consolidation")

	// Apply consolidation rules
	for _, rule := range mc.consolidationRules {
		if !rule.Enabled {
			continue
		}

		if err := mc.applyRule(ctx, rule, storage); err != nil {
			mc.logger.Error("Failed to apply consolidation rule",
				"rule_id", rule.ID,
				"error", err)
		}
	}

	mc.logger.Info("Memory consolidation completed")
	return nil
}

// applyRule applies a consolidation rule
func (mc *MemoryConsolidator) applyRule(ctx context.Context, rule *ConsolidationRule, storage *HierarchicalStorage) error {
	// Simple rule application - in production, implement sophisticated rule engine
	mc.logger.Debug("Applying consolidation rule",
		"rule_id", rule.ID,
		"action", rule.Action)

	switch rule.Action {
	case ActionCompress:
		// Simulate compression
		mc.logger.Debug("Compressing memories")
	case ActionArchive:
		// Simulate archiving
		mc.logger.Debug("Archiving old memories")
	case ActionDelete:
		// Simulate deletion of expired memories
		mc.logger.Debug("Deleting expired memories")
	}

	return nil
}

// NewAccessController creates a new access controller
func NewAccessController(logger *logger.Logger) *AccessController {
	return &AccessController{
		logger: logger,
	}
}

// AccessController manages memory access control
type AccessController struct {
	logger *logger.Logger
}

// CheckAccess checks if an agent has access to a memory
func (ac *AccessController) CheckAccess(ctx context.Context, agentID, memoryID string, accessLevel AccessLevel) error {
	// Simple access control - in production, implement comprehensive RBAC
	ac.logger.Debug("Checking access",
		"agent_id", agentID,
		"memory_id", memoryID,
		"access_level", accessLevel)

	// For now, allow all access
	return nil
}

// NewPerformanceOptimizer creates a new performance optimizer
func NewPerformanceOptimizer(logger *logger.Logger) *PerformanceOptimizer {
	return &PerformanceOptimizer{
		logger: logger,
	}
}

// PerformanceOptimizer optimizes memory system performance
type PerformanceOptimizer struct {
	logger *logger.Logger
}

// OptimizeStorageLevel optimizes the storage level of a memory entry
func (po *PerformanceOptimizer) OptimizeStorageLevel(entry *MemoryEntry) {
	// Simple optimization based on access patterns
	if entry.AccessCount > 100 {
		entry.StorageLevel = StorageLevelHot
	} else if entry.AccessCount > 10 {
		entry.StorageLevel = StorageLevelWarm
	} else if time.Since(entry.LastAccessed) > 30*24*time.Hour {
		entry.StorageLevel = StorageLevelFrozen
	} else if time.Since(entry.LastAccessed) > 7*24*time.Hour {
		entry.StorageLevel = StorageLevelCold
	}

	po.logger.Debug("Storage level optimized",
		"memory_id", entry.ID,
		"new_level", entry.StorageLevel,
		"access_count", entry.AccessCount)
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(batchSize int, logger *logger.Logger) *BatchProcessor {
	return &BatchProcessor{
		batchSize: batchSize,
		logger:    logger,
	}
}

// BatchProcessor processes items in batches
type BatchProcessor struct {
	batchSize int
	logger    *logger.Logger
}

// NewConsolidationScheduler creates a new consolidation scheduler
func NewConsolidationScheduler(interval time.Duration, logger *logger.Logger) *ConsolidationScheduler {
	return &ConsolidationScheduler{
		interval: interval,
		logger:   logger,
	}
}

// ConsolidationScheduler schedules memory consolidation
type ConsolidationScheduler struct {
	interval time.Duration
	logger   *logger.Logger
}
