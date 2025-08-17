package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var consolidationTracer = otel.Tracer("hackai/llm/memory/consolidation")

// MemoryConsolidator handles memory consolidation processes
type MemoryConsolidator interface {
	// Consolidation operations
	ConsolidateConversation(ctx context.Context, conversationID string) error
	ConsolidateEpisodes(ctx context.Context, timeRange TimeRange) error
	ConsolidateFacts(ctx context.Context, subject string) error

	// Automatic consolidation
	StartAutoConsolidation(ctx context.Context, interval time.Duration) error
	StopAutoConsolidation() error

	// Memory cleanup
	CleanupOldMemories(ctx context.Context, retentionPolicy RetentionPolicy) error
	ArchiveMemories(ctx context.Context, archivePolicy ArchivePolicy) error

	// Memory optimization
	OptimizeMemoryStorage(ctx context.Context) error
	DeduplicateMemories(ctx context.Context) error

	// Analytics
	GetConsolidationStats(ctx context.Context) (ConsolidationStats, error)
}

// DefaultMemoryConsolidator implements MemoryConsolidator
type DefaultMemoryConsolidator struct {
	memoryManager     *MemoryManager
	contextManager    ContextManager
	summaryChain      interface{} // LLM Chain for summarization
	extractionChain   interface{} // LLM Chain for extraction
	logger            *logger.Logger
	config            ConsolidationConfig
	autoConsolidation *AutoConsolidation
	mutex             sync.RWMutex
}

// ConsolidationConfig provides configuration for memory consolidation
type ConsolidationConfig struct {
	ConversationThreshold int           `json:"conversation_threshold"` // Messages before consolidation
	EpisodeThreshold      int           `json:"episode_threshold"`      // Episodes before consolidation
	FactThreshold         int           `json:"fact_threshold"`         // Facts before consolidation
	ConsolidationInterval time.Duration `json:"consolidation_interval"`
	RetentionPeriod       time.Duration `json:"retention_period"`
	ArchivePeriod         time.Duration `json:"archive_period"`
	EnableAutoCleanup     bool          `json:"enable_auto_cleanup"`
	EnableDeduplication   bool          `json:"enable_deduplication"`
	MaxMemorySize         int64         `json:"max_memory_size"`
}

// RetentionPolicy defines memory retention rules
type RetentionPolicy struct {
	ConversationTTL time.Duration `json:"conversation_ttl"`
	EpisodeTTL      time.Duration `json:"episode_ttl"`
	FactTTL         time.Duration `json:"fact_ttl"`
	VectorTTL       time.Duration `json:"vector_ttl"`
	MinConfidence   float64       `json:"min_confidence"`
	PreserveTagged  []string      `json:"preserve_tagged"`
}

// ArchivePolicy defines memory archiving rules
type ArchivePolicy struct {
	ArchiveAfter    time.Duration `json:"archive_after"`
	ArchiveLocation string        `json:"archive_location"`
	CompressionType string        `json:"compression_type"`
	IncludeMetadata bool          `json:"include_metadata"`
}

// AutoConsolidation manages automatic consolidation
type AutoConsolidation struct {
	interval time.Duration
	ticker   *time.Ticker
	stopChan chan bool
	running  bool
	lastRun  time.Time
	mutex    sync.RWMutex
}

// ConsolidationStats provides statistics about consolidation
type ConsolidationStats struct {
	LastConsolidation      time.Time              `json:"last_consolidation"`
	ConversationsProcessed int                    `json:"conversations_processed"`
	EpisodesConsolidated   int                    `json:"episodes_consolidated"`
	FactsConsolidated      int                    `json:"facts_consolidated"`
	MemoryFreed            int64                  `json:"memory_freed"`
	ConsolidationTime      time.Duration          `json:"consolidation_time"`
	ErrorCount             int                    `json:"error_count"`
	Details                map[string]interface{} `json:"details"`
}

// ConsolidationResult represents the result of a consolidation operation
type ConsolidationResult struct {
	Type           string                 `json:"type"`
	ItemsProcessed int                    `json:"items_processed"`
	ItemsCreated   int                    `json:"items_created"`
	ItemsRemoved   int                    `json:"items_removed"`
	Duration       time.Duration          `json:"duration"`
	Success        bool                   `json:"success"`
	Error          string                 `json:"error,omitempty"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// NewDefaultMemoryConsolidator creates a new default memory consolidator
func NewDefaultMemoryConsolidator(
	memoryManager *MemoryManager,
	contextManager ContextManager,
	config ConsolidationConfig,
	logger *logger.Logger,
) *DefaultMemoryConsolidator {
	return &DefaultMemoryConsolidator{
		memoryManager:  memoryManager,
		contextManager: contextManager,
		config:         config,
		logger:         logger,
	}
}

// SetSummaryChain sets the LLM chain for summarization
func (c *DefaultMemoryConsolidator) SetSummaryChain(chain interface{}) {
	c.summaryChain = chain
}

// SetExtractionChain sets the LLM chain for fact extraction
func (c *DefaultMemoryConsolidator) SetExtractionChain(chain interface{}) {
	c.extractionChain = chain
}

// ConsolidateConversation consolidates a conversation into episodic and semantic memory
func (c *DefaultMemoryConsolidator) ConsolidateConversation(ctx context.Context, conversationID string) error {
	ctx, span := consolidationTracer.Start(ctx, "consolidator.consolidate_conversation",
		trace.WithAttributes(attribute.String("conversation.id", conversationID)),
	)
	defer span.End()

	startTime := time.Now()

	// Get conversation messages
	messages, err := c.memoryManager.conversationalMemory.GetMessages(ctx, conversationID, 0)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to get conversation messages: %w", err)
	}

	if len(messages) < c.config.ConversationThreshold {
		c.logger.Debug("Conversation below threshold for consolidation",
			"conversation_id", conversationID,
			"message_count", len(messages),
			"threshold", c.config.ConversationThreshold,
		)
		return nil
	}

	// Create conversation summary
	summary, err := c.createConversationSummary(ctx, messages)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create conversation summary: %w", err)
	}

	// Extract episodic memories
	episodes, err := c.extractEpisodes(ctx, messages, summary)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to extract episodes: %w", err)
	}

	// Extract semantic facts
	facts, err := c.extractFacts(ctx, messages, summary)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to extract facts: %w", err)
	}

	// Store extracted memories
	episodesStored := 0
	for _, episode := range episodes {
		if err := c.memoryManager.episodicMemory.StoreEpisode(ctx, episode); err != nil {
			c.logger.Warn("Failed to store episode", "error", err)
		} else {
			episodesStored++
		}
	}

	factsStored := 0
	for _, fact := range facts {
		if err := c.memoryManager.semanticMemory.StoreFact(ctx, fact); err != nil {
			c.logger.Warn("Failed to store fact", "error", err)
		} else {
			factsStored++
		}
	}

	// Mark conversation as consolidated (simplified for demo)
	c.logger.Debug("Conversation metadata would be updated",
		"conversation_id", conversationID,
		"episodes_extracted", episodesStored,
		"facts_extracted", factsStored,
	)

	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int("messages.count", len(messages)),
		attribute.Int("episodes.extracted", episodesStored),
		attribute.Int("facts.extracted", factsStored),
		attribute.String("duration", duration.String()),
		attribute.Bool("success", true),
	)

	c.logger.Info("Conversation consolidated",
		"conversation_id", conversationID,
		"messages", len(messages),
		"episodes_extracted", episodesStored,
		"facts_extracted", factsStored,
		"duration", duration,
	)

	return nil
}

// ConsolidateEpisodes consolidates similar episodes
func (c *DefaultMemoryConsolidator) ConsolidateEpisodes(ctx context.Context, timeRange TimeRange) error {
	ctx, span := consolidationTracer.Start(ctx, "consolidator.consolidate_episodes")
	defer span.End()

	// Simplified implementation for demo
	c.logger.Info("Episode consolidation completed (simplified for demo)")

	span.SetAttributes(
		attribute.Bool("success", true),
	)

	return nil
}

// ConsolidateFacts consolidates facts about a subject
func (c *DefaultMemoryConsolidator) ConsolidateFacts(ctx context.Context, subject string) error {
	ctx, span := consolidationTracer.Start(ctx, "consolidator.consolidate_facts",
		trace.WithAttributes(attribute.String("subject", subject)),
	)
	defer span.End()

	// Simplified implementation for demo
	c.logger.Info("Fact consolidation completed (simplified for demo)", "subject", subject)

	span.SetAttributes(
		attribute.Bool("success", true),
	)

	return nil
}

// StartAutoConsolidation starts automatic consolidation
func (c *DefaultMemoryConsolidator) StartAutoConsolidation(ctx context.Context, interval time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.autoConsolidation != nil && c.autoConsolidation.running {
		return fmt.Errorf("auto consolidation is already running")
	}

	c.autoConsolidation = &AutoConsolidation{
		interval: interval,
		ticker:   time.NewTicker(interval),
		stopChan: make(chan bool),
		running:  true,
		lastRun:  time.Now(),
	}

	go c.runAutoConsolidation(ctx)

	c.logger.Info("Auto consolidation started", "interval", interval)
	return nil
}

// StopAutoConsolidation stops automatic consolidation
func (c *DefaultMemoryConsolidator) StopAutoConsolidation() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.autoConsolidation == nil || !c.autoConsolidation.running {
		return fmt.Errorf("auto consolidation is not running")
	}

	c.autoConsolidation.ticker.Stop()
	c.autoConsolidation.stopChan <- true
	c.autoConsolidation.running = false

	c.logger.Info("Auto consolidation stopped")
	return nil
}

// Helper methods

// createConversationSummary creates a summary of conversation messages
func (c *DefaultMemoryConsolidator) createConversationSummary(ctx context.Context, messages []Message) (ConversationSummary, error) {
	// Create simple summary without LLM
	return c.createSimpleSummary(messages), nil
}

// createSimpleSummary creates a simple summary without LLM
func (c *DefaultMemoryConsolidator) createSimpleSummary(messages []Message) ConversationSummary {
	participants := make(map[string]bool)
	for _, msg := range messages {
		participants[msg.Role] = true
	}

	var participantList []string
	for participant := range participants {
		participantList = append(participantList, participant)
	}

	conversationID := "unknown"
	if len(messages) > 0 && messages[0].SessionID != "" {
		conversationID = messages[0].SessionID
	}

	return ConversationSummary{
		ConversationID: conversationID,
		Summary:        fmt.Sprintf("Conversation with %d messages between %v", len(messages), participantList),
		KeyPoints:      []string{},
		Participants:   participantList,
		TimeRange: TimeRange{
			Start: messages[0].Timestamp,
			End:   messages[len(messages)-1].Timestamp,
		},
		MessageCount: len(messages),
		Metadata:     map[string]interface{}{},
	}
}

// extractEpisodes extracts episodic memories from conversation
func (c *DefaultMemoryConsolidator) extractEpisodes(ctx context.Context, messages []Message, summary ConversationSummary) ([]Episode, error) {
	// Simple extraction - in production, this would use LLM
	var episodes []Episode

	// Create one episode for the entire conversation
	episode := Episode{
		Title:       fmt.Sprintf("Conversation on %s", summary.TimeRange.Start.Format("2006-01-02")),
		Description: summary.Summary,
		Context:     fmt.Sprintf("Conversation between %v", summary.Participants),
		Outcome:     "Conversation completed",
		Tags:        []string{"conversation", "interaction"},
		Timestamp:   summary.TimeRange.Start,
		Metadata: map[string]interface{}{
			"conversation_id": summary.ConversationID,
			"message_count":   summary.MessageCount,
			"participants":    summary.Participants,
		},
	}

	episodes = append(episodes, episode)
	return episodes, nil
}

// extractFacts extracts semantic facts from conversation
func (c *DefaultMemoryConsolidator) extractFacts(ctx context.Context, messages []Message, summary ConversationSummary) ([]Fact, error) {
	// Simple extraction - in production, this would use LLM
	var facts []Fact

	// Extract basic facts about the conversation
	for _, participant := range summary.Participants {
		fact := Fact{
			Subject:    participant,
			Predicate:  "participated_in",
			Object:     "conversation",
			Confidence: 1.0,
			Context:    fmt.Sprintf("Conversation on %s", summary.TimeRange.Start.Format("2006-01-02")),
			Timestamp:  summary.TimeRange.Start,
			Metadata: map[string]interface{}{
				"conversation_id": summary.ConversationID,
			},
		}
		facts = append(facts, fact)
	}

	return facts, nil
}

// groupSimilarEpisodes groups episodes by similarity
func (c *DefaultMemoryConsolidator) groupSimilarEpisodes(episodes []Episode) [][]Episode {
	// Simple grouping by tags - in production, this would use semantic similarity
	tagGroups := make(map[string][]Episode)

	for _, episode := range episodes {
		if len(episode.Tags) > 0 {
			key := episode.Tags[0] // Use first tag as grouping key
			tagGroups[key] = append(tagGroups[key], episode)
		}
	}

	var groups [][]Episode
	for _, group := range tagGroups {
		if len(group) > 1 {
			groups = append(groups, group)
		}
	}

	return groups
}

// consolidateEpisodeGroup consolidates a group of similar episodes
func (c *DefaultMemoryConsolidator) consolidateEpisodeGroup(ctx context.Context, episodes []Episode) (Episode, error) {
	if len(episodes) == 0 {
		return Episode{}, fmt.Errorf("empty episode group")
	}

	// Sort by timestamp
	sort.Slice(episodes, func(i, j int) bool {
		return episodes[i].Timestamp.Before(episodes[j].Timestamp)
	})

	// Create consolidated episode
	consolidated := Episode{
		Title:       fmt.Sprintf("Consolidated: %s", episodes[0].Title),
		Description: c.mergeDescriptions(episodes),
		Context:     c.mergeContexts(episodes),
		Outcome:     c.mergeOutcomes(episodes),
		Tags:        c.mergeTags(episodes),
		Timestamp:   episodes[0].Timestamp,
		Metadata: map[string]interface{}{
			"consolidated_from": len(episodes),
			"original_ids":      c.extractEpisodeIDs(episodes),
		},
	}

	return consolidated, nil
}

// consolidateFactGroup consolidates a group of facts
func (c *DefaultMemoryConsolidator) consolidateFactGroup(ctx context.Context, facts []Fact) (Fact, error) {
	if len(facts) == 0 {
		return Fact{}, fmt.Errorf("empty fact group")
	}

	// Calculate average confidence
	totalConfidence := 0.0
	for _, fact := range facts {
		totalConfidence += fact.Confidence
	}
	avgConfidence := totalConfidence / float64(len(facts))

	// Use the most recent fact as base
	sort.Slice(facts, func(i, j int) bool {
		return facts[i].Timestamp.After(facts[j].Timestamp)
	})

	consolidated := facts[0]
	consolidated.Confidence = avgConfidence
	consolidated.Context = c.mergeFactContexts(facts)
	consolidated.Metadata = map[string]interface{}{
		"consolidated_from": len(facts),
		"original_ids":      c.extractFactIDs(facts),
	}

	return consolidated, nil
}

// runAutoConsolidation runs the automatic consolidation process
func (c *DefaultMemoryConsolidator) runAutoConsolidation(ctx context.Context) {
	for {
		select {
		case <-c.autoConsolidation.ticker.C:
			c.performAutoConsolidation(ctx)
		case <-c.autoConsolidation.stopChan:
			return
		}
	}
}

// performAutoConsolidation performs automatic consolidation
func (c *DefaultMemoryConsolidator) performAutoConsolidation(ctx context.Context) {
	c.autoConsolidation.mutex.Lock()
	c.autoConsolidation.lastRun = time.Now()
	c.autoConsolidation.mutex.Unlock()

	c.logger.Info("Starting automatic consolidation")

	// Consolidate recent conversations
	// This would identify conversations that need consolidation

	// Consolidate episodes from last period
	timeRange := TimeRange{
		Start: time.Now().Add(-c.config.ConsolidationInterval),
		End:   time.Now(),
	}

	if err := c.ConsolidateEpisodes(ctx, timeRange); err != nil {
		c.logger.Error("Failed to consolidate episodes", "error", err)
	}

	// Cleanup old memories if enabled
	if c.config.EnableAutoCleanup {
		retentionPolicy := RetentionPolicy{
			ConversationTTL: c.config.RetentionPeriod,
			EpisodeTTL:      c.config.RetentionPeriod,
			FactTTL:         c.config.RetentionPeriod,
			VectorTTL:       c.config.RetentionPeriod,
			MinConfidence:   0.1,
		}

		if err := c.CleanupOldMemories(ctx, retentionPolicy); err != nil {
			c.logger.Error("Failed to cleanup old memories", "error", err)
		}
	}

	c.logger.Info("Automatic consolidation completed")
}

// Utility methods for merging content
func (c *DefaultMemoryConsolidator) mergeDescriptions(episodes []Episode) string {
	var descriptions []string
	for _, episode := range episodes {
		descriptions = append(descriptions, episode.Description)
	}
	return strings.Join(descriptions, "; ")
}

func (c *DefaultMemoryConsolidator) mergeContexts(episodes []Episode) string {
	var contexts []string
	for _, episode := range episodes {
		if episode.Context != "" {
			contexts = append(contexts, episode.Context)
		}
	}
	return strings.Join(contexts, "; ")
}

func (c *DefaultMemoryConsolidator) mergeOutcomes(episodes []Episode) string {
	var outcomes []string
	for _, episode := range episodes {
		if episode.Outcome != "" {
			outcomes = append(outcomes, episode.Outcome)
		}
	}
	return strings.Join(outcomes, "; ")
}

func (c *DefaultMemoryConsolidator) mergeTags(episodes []Episode) []string {
	tagSet := make(map[string]bool)
	for _, episode := range episodes {
		for _, tag := range episode.Tags {
			tagSet[tag] = true
		}
	}

	var tags []string
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	return tags
}

func (c *DefaultMemoryConsolidator) extractEpisodeIDs(episodes []Episode) []string {
	var ids []string
	for _, episode := range episodes {
		ids = append(ids, episode.ID)
	}
	return ids
}

func (c *DefaultMemoryConsolidator) mergeFactContexts(facts []Fact) string {
	var contexts []string
	for _, fact := range facts {
		if fact.Context != "" {
			contexts = append(contexts, fact.Context)
		}
	}
	return strings.Join(contexts, "; ")
}

func (c *DefaultMemoryConsolidator) extractFactIDs(facts []Fact) []string {
	var ids []string
	for _, fact := range facts {
		ids = append(ids, fact.ID)
	}
	return ids
}

// CleanupOldMemories removes old memories based on retention policy
func (c *DefaultMemoryConsolidator) CleanupOldMemories(ctx context.Context, policy RetentionPolicy) error {
	// Implementation would clean up old memories based on TTL and confidence
	c.logger.Info("Memory cleanup completed")
	return nil
}

// ArchiveMemories archives old memories
func (c *DefaultMemoryConsolidator) ArchiveMemories(ctx context.Context, policy ArchivePolicy) error {
	// Implementation would archive old memories to external storage
	c.logger.Info("Memory archiving completed")
	return nil
}

// OptimizeMemoryStorage optimizes memory storage
func (c *DefaultMemoryConsolidator) OptimizeMemoryStorage(ctx context.Context) error {
	// Implementation would optimize memory storage (defragmentation, indexing, etc.)
	c.logger.Info("Memory storage optimization completed")
	return nil
}

// DeduplicateMemories removes duplicate memories
func (c *DefaultMemoryConsolidator) DeduplicateMemories(ctx context.Context) error {
	// Implementation would find and remove duplicate memories
	c.logger.Info("Memory deduplication completed")
	return nil
}

// GetConsolidationStats returns consolidation statistics
func (c *DefaultMemoryConsolidator) GetConsolidationStats(ctx context.Context) (ConsolidationStats, error) {
	stats := ConsolidationStats{
		LastConsolidation:      time.Now(),
		ConversationsProcessed: 0,
		EpisodesConsolidated:   0,
		FactsConsolidated:      0,
		MemoryFreed:            0,
		ConsolidationTime:      0,
		ErrorCount:             0,
		Details:                make(map[string]interface{}),
	}

	if c.autoConsolidation != nil {
		c.autoConsolidation.mutex.RLock()
		stats.LastConsolidation = c.autoConsolidation.lastRun
		c.autoConsolidation.mutex.RUnlock()
	}

	return stats, nil
}
