package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// MemoryManager manages memory consolidation, compression, and maintenance
type MemoryManager struct {
	config *MemoryConfig
	logger *logger.Logger
}

// ConsolidationRule defines rules for memory consolidation
type ConsolidationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Conditions  []*Condition           `json:"conditions"`
	Actions     []*ConsolidationAction `json:"actions"`
	Priority    float64                `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ConsolidationAction defines an action to take during consolidation
type ConsolidationAction struct {
	Type       ConsolidationActionType `json:"type"`
	Parameters map[string]interface{}  `json:"parameters"`
	Metadata   map[string]interface{}  `json:"metadata"`
}

// ConsolidationActionType defines types of consolidation actions
type ConsolidationActionType string

const (
	ActionTypeMove       ConsolidationActionType = "move"
	ActionTypeMerge      ConsolidationActionType = "merge"
	ActionTypeCompress   ConsolidationActionType = "compress"
	ActionTypeDelete     ConsolidationActionType = "delete"
	ActionTypeArchive    ConsolidationActionType = "archive"
	ActionTypeGeneralize ConsolidationActionType = "generalize"
)

// NewMemoryManager creates a new memory manager
func NewMemoryManager(config *MemoryConfig, logger *logger.Logger) (*MemoryManager, error) {
	return &MemoryManager{
		config: config,
		logger: logger,
	}, nil
}

// ConsolidateWorkingMemory consolidates working memory to episodic memory
func (mm *MemoryManager) ConsolidateWorkingMemory(ctx context.Context, workingMemory *WorkingMemory, episodicMemory *EpisodicMemory) error {
	mm.logger.Debug("Starting working memory consolidation")

	// Get entries from working memory that should be consolidated
	consolidationCandidates := mm.getWorkingMemoryConsolidationCandidates(workingMemory)

	for _, entry := range consolidationCandidates {
		// Check if entry meets consolidation criteria
		if mm.shouldConsolidateToEpisodic(entry) {
			// Convert to episodic memory entry
			episodicEntry := mm.convertToEpisodicEntry(entry)

			// Store in episodic memory
			if err := episodicMemory.Store(ctx, episodicEntry); err != nil {
				mm.logger.Warn("Failed to consolidate entry to episodic memory",
					"entry_id", entry.ID,
					"error", err)
				continue
			}

			// Remove from working memory if successfully consolidated
			if err := workingMemory.Delete(ctx, entry.ID); err != nil {
				mm.logger.Warn("Failed to remove consolidated entry from working memory",
					"entry_id", entry.ID,
					"error", err)
			}

			mm.logger.Debug("Entry consolidated from working to episodic memory",
				"entry_id", entry.ID,
				"importance", entry.Importance)
		}
	}

	mm.logger.Debug("Working memory consolidation completed",
		"candidates", len(consolidationCandidates))

	return nil
}

// ConsolidateEpisodicMemory consolidates episodic memory to semantic memory
func (mm *MemoryManager) ConsolidateEpisodicMemory(ctx context.Context, episodicMemory *EpisodicMemory, semanticMemory *SemanticMemory) error {
	mm.logger.Debug("Starting episodic memory consolidation")

	// Get entries from episodic memory that should be consolidated
	consolidationCandidates := mm.getEpisodicMemoryConsolidationCandidates(episodicMemory)

	for _, entry := range consolidationCandidates {
		// Check if entry meets consolidation criteria
		if mm.shouldConsolidateToSemantic(entry) {
			// Convert to semantic memory entry
			semanticEntry := mm.convertToSemanticEntry(entry)

			// Store in semantic memory
			if err := semanticMemory.Store(ctx, semanticEntry); err != nil {
				mm.logger.Warn("Failed to consolidate entry to semantic memory",
					"entry_id", entry.ID,
					"error", err)
				continue
			}

			// Keep in episodic memory but mark as consolidated
			entry.Metadata["consolidated"] = true
			if err := episodicMemory.Update(ctx, entry); err != nil {
				mm.logger.Warn("Failed to update consolidated entry in episodic memory",
					"entry_id", entry.ID,
					"error", err)
			}

			mm.logger.Debug("Entry consolidated from episodic to semantic memory",
				"entry_id", entry.ID,
				"importance", entry.Importance)
		}
	}

	mm.logger.Debug("Episodic memory consolidation completed",
		"candidates", len(consolidationCandidates))

	return nil
}

// CleanupExpiredMemories removes expired memories from all memory types
func (mm *MemoryManager) CleanupExpiredMemories(ctx context.Context, agentMemory *AgentMemory) error {
	mm.logger.Debug("Starting expired memory cleanup")

	now := time.Now()
	cleanupCount := 0

	// Query for expired entries across all memory types
	memoryTypes := []MemoryType{
		MemoryTypeWorking,
		MemoryTypeEpisodic,
		MemoryTypeSemantic,
		MemoryTypeProcedural,
		MemoryTypeVector,
	}

	for _, memoryType := range memoryTypes {
		query := &MemoryQuery{
			Type:           memoryType,
			IncludeExpired: true,
			Limit:          1000, // Process in batches
		}

		result, err := agentMemory.Query(ctx, query)
		if err != nil {
			mm.logger.Warn("Failed to query expired memories",
				"memory_type", memoryType,
				"error", err)
			continue
		}

		for _, entry := range result.Entries {
			if entry.ExpiresAt != nil && now.After(*entry.ExpiresAt) {
				if err := agentMemory.Delete(ctx, entry.Type, entry.ID); err != nil {
					mm.logger.Warn("Failed to delete expired memory",
						"entry_id", entry.ID,
						"memory_type", entry.Type,
						"error", err)
				} else {
					cleanupCount++
				}
			}
		}
	}

	mm.logger.Debug("Expired memory cleanup completed",
		"cleaned_entries", cleanupCount)

	return nil
}

// CompressOldMemories compresses old memories to save space
func (mm *MemoryManager) CompressOldMemories(ctx context.Context, agentMemory *AgentMemory) error {
	mm.logger.Debug("Starting memory compression")

	compressionThreshold := time.Now().Add(-mm.config.RetentionPeriod / 2)
	compressionCount := 0

	// Query for old entries that can be compressed
	memoryTypes := []MemoryType{
		MemoryTypeEpisodic,
		MemoryTypeSemantic,
		MemoryTypeProcedural,
	}

	for _, memoryType := range memoryTypes {
		query := &MemoryQuery{
			Type: memoryType,
			TimeRange: &TimeRange{
				Start: time.Time{}, // Beginning of time
				End:   compressionThreshold,
			},
			Limit: 1000, // Process in batches
		}

		result, err := agentMemory.Query(ctx, query)
		if err != nil {
			mm.logger.Warn("Failed to query old memories for compression",
				"memory_type", memoryType,
				"error", err)
			continue
		}

		for _, entry := range result.Entries {
			if !entry.Compressed {
				// Compress the entry
				compressedEntry := mm.compressMemoryEntry(entry)
				
				if err := agentMemory.Update(ctx, compressedEntry); err != nil {
					mm.logger.Warn("Failed to compress memory entry",
						"entry_id", entry.ID,
						"error", err)
				} else {
					compressionCount++
				}
			}
		}
	}

	mm.logger.Debug("Memory compression completed",
		"compressed_entries", compressionCount)

	return nil
}

// UpdateStatistics updates memory statistics
func (mm *MemoryManager) UpdateStatistics(ctx context.Context, agentMemory *AgentMemory) error {
	mm.logger.Debug("Updating memory statistics")

	// Get current statistics
	stats := agentMemory.GetStatistics()

	// Log statistics
	mm.logger.Info("Memory statistics updated",
		"agent_id", stats.AgentID,
		"total_entries", stats.TotalEntries,
		"working_memory", stats.WorkingMemory.EntryCount,
		"episodic_memory", stats.EpisodicMemory.EntryCount,
		"semantic_memory", stats.SemanticMemory.EntryCount,
		"procedural_memory", stats.ProceduralMemory.EntryCount,
		"vector_memory", stats.VectorMemory.EntryCount)

	return nil
}

// Helper methods

func (mm *MemoryManager) getWorkingMemoryConsolidationCandidates(workingMemory *WorkingMemory) []*MemoryEntry {
	var candidates []*MemoryEntry

	// Get all entries from working memory
	query := &MemoryQuery{
		Type:  MemoryTypeWorking,
		Limit: 1000,
	}

	result, err := workingMemory.Query(context.Background(), query)
	if err != nil {
		mm.logger.Warn("Failed to get working memory consolidation candidates", "error", err)
		return candidates
	}

	// Filter candidates based on age and importance
	consolidationAge := time.Now().Add(-time.Hour) // Consolidate entries older than 1 hour

	for _, entry := range result.Entries {
		if entry.Timestamp.Before(consolidationAge) && entry.Importance > 0.3 {
			candidates = append(candidates, entry)
		}
	}

	return candidates
}

func (mm *MemoryManager) getEpisodicMemoryConsolidationCandidates(episodicMemory *EpisodicMemory) []*MemoryEntry {
	var candidates []*MemoryEntry

	// Get entries that haven't been consolidated yet
	query := &MemoryQuery{
		Type:  MemoryTypeEpisodic,
		Limit: 1000,
	}

	result, err := episodicMemory.Query(context.Background(), query)
	if err != nil {
		mm.logger.Warn("Failed to get episodic memory consolidation candidates", "error", err)
		return candidates
	}

	// Filter candidates based on age, importance, and consolidation status
	consolidationAge := time.Now().Add(-24 * time.Hour) // Consolidate entries older than 24 hours

	for _, entry := range result.Entries {
		if entry.Timestamp.Before(consolidationAge) && 
		   entry.Importance > 0.5 && 
		   !mm.isAlreadyConsolidated(entry) {
			candidates = append(candidates, entry)
		}
	}

	return candidates
}

func (mm *MemoryManager) shouldConsolidateToEpisodic(entry *MemoryEntry) bool {
	// Consolidate if entry is important enough and old enough
	return entry.Importance > 0.3 && 
		   time.Since(entry.Timestamp) > time.Hour &&
		   entry.AccessCount > 1
}

func (mm *MemoryManager) shouldConsolidateToSemantic(entry *MemoryEntry) bool {
	// Consolidate if entry represents generalizable knowledge
	return entry.Importance > 0.5 && 
		   time.Since(entry.Timestamp) > 24*time.Hour &&
		   entry.AccessCount > 3
}

func (mm *MemoryManager) isAlreadyConsolidated(entry *MemoryEntry) bool {
	if entry.Metadata == nil {
		return false
	}
	
	consolidated, exists := entry.Metadata["consolidated"]
	if !exists {
		return false
	}
	
	consolidatedBool, ok := consolidated.(bool)
	return ok && consolidatedBool
}

func (mm *MemoryManager) convertToEpisodicEntry(entry *MemoryEntry) *MemoryEntry {
	episodicEntry := &MemoryEntry{
		ID:          entry.ID,
		Type:        MemoryTypeEpisodic,
		Content:     entry.Content,
		Context:     entry.Context,
		Importance:  entry.Importance,
		Confidence:  entry.Confidence,
		Timestamp:   entry.Timestamp,
		LastAccess:  entry.LastAccess,
		AccessCount: entry.AccessCount,
		Tags:        entry.Tags,
		Metadata:    make(map[string]interface{}),
	}

	// Copy metadata
	if entry.Metadata != nil {
		for k, v := range entry.Metadata {
			episodicEntry.Metadata[k] = v
		}
	}

	// Add consolidation metadata
	episodicEntry.Metadata["consolidated_from"] = "working_memory"
	episodicEntry.Metadata["consolidation_time"] = time.Now()

	return episodicEntry
}

func (mm *MemoryManager) convertToSemanticEntry(entry *MemoryEntry) *MemoryEntry {
	semanticEntry := &MemoryEntry{
		ID:          entry.ID,
		Type:        MemoryTypeSemantic,
		Content:     entry.Content,
		Context:     entry.Context,
		Importance:  entry.Importance,
		Confidence:  entry.Confidence,
		Timestamp:   entry.Timestamp,
		LastAccess:  entry.LastAccess,
		AccessCount: entry.AccessCount,
		Tags:        entry.Tags,
		Metadata:    make(map[string]interface{}),
	}

	// Copy metadata
	if entry.Metadata != nil {
		for k, v := range entry.Metadata {
			semanticEntry.Metadata[k] = v
		}
	}

	// Add consolidation metadata
	semanticEntry.Metadata["consolidated_from"] = "episodic_memory"
	semanticEntry.Metadata["consolidation_time"] = time.Now()

	return semanticEntry
}

func (mm *MemoryManager) compressMemoryEntry(entry *MemoryEntry) *MemoryEntry {
	compressedEntry := &MemoryEntry{
		ID:          entry.ID,
		Type:        entry.Type,
		Content:     mm.compressContent(entry.Content),
		Context:     entry.Context,
		Importance:  entry.Importance,
		Confidence:  entry.Confidence,
		Timestamp:   entry.Timestamp,
		LastAccess:  entry.LastAccess,
		AccessCount: entry.AccessCount,
		Tags:        entry.Tags,
		Metadata:    entry.Metadata,
		Compressed:  true,
	}

	// Add compression metadata
	if compressedEntry.Metadata == nil {
		compressedEntry.Metadata = make(map[string]interface{})
	}
	compressedEntry.Metadata["compression_time"] = time.Now()
	compressedEntry.Metadata["original_size"] = len(fmt.Sprintf("%v", entry.Content))
	compressedEntry.Metadata["compressed_size"] = len(fmt.Sprintf("%v", compressedEntry.Content))

	return compressedEntry
}

func (mm *MemoryManager) compressContent(content interface{}) interface{} {
	// Simple compression: summarize content if it's a string
	if contentStr, ok := content.(string); ok {
		if len(contentStr) > 200 {
			// Simple summarization: take first 100 and last 100 characters
			return contentStr[:100] + "..." + contentStr[len(contentStr)-100:]
		}
	}
	
	return content
}

// GetConsolidationRules returns default consolidation rules
func (mm *MemoryManager) GetConsolidationRules() []*ConsolidationRule {
	return []*ConsolidationRule{
		{
			ID:          "working_to_episodic",
			Name:        "Working to Episodic Consolidation",
			Description: "Move important working memories to episodic memory",
			Conditions: []*Condition{
				{
					Type:     ConditionTypeTime,
					Field:    "age",
					Operator: ConditionOperatorGreaterThan,
					Value:    time.Hour,
				},
				{
					Type:     ConditionTypePerformance,
					Field:    "importance",
					Operator: ConditionOperatorGreaterThan,
					Value:    0.3,
				},
			},
			Actions: []*ConsolidationAction{
				{
					Type: ActionTypeMove,
					Parameters: map[string]interface{}{
						"target": "episodic_memory",
					},
				},
			},
			Priority: 1.0,
			Enabled:  true,
		},
		{
			ID:          "episodic_to_semantic",
			Name:        "Episodic to Semantic Consolidation",
			Description: "Extract semantic knowledge from episodic memories",
			Conditions: []*Condition{
				{
					Type:     ConditionTypeTime,
					Field:    "age",
					Operator: ConditionOperatorGreaterThan,
					Value:    24 * time.Hour,
				},
				{
					Type:     ConditionTypePerformance,
					Field:    "importance",
					Operator: ConditionOperatorGreaterThan,
					Value:    0.5,
				},
			},
			Actions: []*ConsolidationAction{
				{
					Type: ActionTypeGeneralize,
					Parameters: map[string]interface{}{
						"target": "semantic_memory",
					},
				},
			},
			Priority: 0.8,
			Enabled:  true,
		},
	}
}
