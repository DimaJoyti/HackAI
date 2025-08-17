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

var contextTracer = otel.Tracer("hackai/llm/memory/context")

// ContextManager manages context across conversations and workflows
type ContextManager interface {
	// Context retrieval
	GetRelevantContext(ctx context.Context, query string, options ContextOptions) (ContextResult, error)
	GetConversationContext(ctx context.Context, conversationID string, options ContextOptions) (ContextResult, error)

	// Context compression
	CompressContext(ctx context.Context, content string, targetLength int) (string, error)
	SummarizeConversation(ctx context.Context, conversationID string) (ConversationSummary, error)

	// Context ranking
	RankContextItems(ctx context.Context, items []ContextItem, query string) ([]ContextItem, error)

	// Context integration
	IntegrateContext(ctx context.Context, sources []ContextSource) (IntegratedContext, error)

	// Context management
	UpdateContext(ctx context.Context, conversationID string, message Message) error
	ClearContext(ctx context.Context, conversationID string) error

	// Context analytics
	GetContextStats(ctx context.Context, conversationID string) (ContextStats, error)
	GetContextUsage(ctx context.Context, timeRange TimeRange) (ContextUsage, error)
}

// DefaultContextManager implements ContextManager
type DefaultContextManager struct {
	memoryManager    *MemoryManager
	compressionChain interface{} // LLM chain for text compression
	summaryChain     interface{} // LLM chain for summarization
	logger           *logger.Logger
	config           ContextConfig
	mutex            sync.RWMutex
}

// ContextConfig provides configuration for context management
type ContextConfig struct {
	MaxContextLength    int           `json:"max_context_length"`
	CompressionRatio    float64       `json:"compression_ratio"`
	RelevanceThreshold  float64       `json:"relevance_threshold"`
	MaxRetrievalItems   int           `json:"max_retrieval_items"`
	ContextTTL          time.Duration `json:"context_ttl"`
	EnableCompression   bool          `json:"enable_compression"`
	EnableSummarization bool          `json:"enable_summarization"`
	SummaryInterval     int           `json:"summary_interval"` // Messages before summarization
}

// ContextOptions provides options for context retrieval
type ContextOptions struct {
	MaxLength       int                    `json:"max_length"`
	IncludeHistory  bool                   `json:"include_history"`
	IncludeEpisodic bool                   `json:"include_episodic"`
	IncludeSemantic bool                   `json:"include_semantic"`
	IncludeVector   bool                   `json:"include_vector"`
	TimeRange       *TimeRange             `json:"time_range,omitempty"`
	RelevanceFilter float64                `json:"relevance_filter"`
	ContextTypes    []string               `json:"context_types"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ContextResult represents the result of context retrieval
type ContextResult struct {
	Items           []ContextItem          `json:"items"`
	TotalLength     int                    `json:"total_length"`
	RelevanceScore  float64                `json:"relevance_score"`
	Sources         []string               `json:"sources"`
	CompressionUsed bool                   `json:"compression_used"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ContextItem represents a single piece of context
type ContextItem struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"` // conversation, episodic, semantic, vector
	Content        string                 `json:"content"`
	RelevanceScore float64                `json:"relevance_score"`
	Timestamp      time.Time              `json:"timestamp"`
	Source         string                 `json:"source"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// ContextSource represents a source of context
type ContextSource struct {
	Type     string                 `json:"type"`
	Query    string                 `json:"query"`
	Options  map[string]interface{} `json:"options"`
	Weight   float64                `json:"weight"`
	Required bool                   `json:"required"`
}

// IntegratedContext represents integrated context from multiple sources
type IntegratedContext struct {
	Content        string                 `json:"content"`
	Sources        []ContextSource        `json:"sources"`
	TotalLength    int                    `json:"total_length"`
	RelevanceScore float64                `json:"relevance_score"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// ConversationSummary represents a conversation summary
type ConversationSummary struct {
	ConversationID string                 `json:"conversation_id"`
	Summary        string                 `json:"summary"`
	KeyPoints      []string               `json:"key_points"`
	Participants   []string               `json:"participants"`
	TimeRange      TimeRange              `json:"time_range"`
	MessageCount   int                    `json:"message_count"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// ContextStats provides statistics about context usage
type ContextStats struct {
	ConversationID     string         `json:"conversation_id"`
	TotalMessages      int            `json:"total_messages"`
	TotalContextLength int            `json:"total_context_length"`
	CompressionRatio   float64        `json:"compression_ratio"`
	LastSummary        *time.Time     `json:"last_summary,omitempty"`
	ContextSources     map[string]int `json:"context_sources"`
}

// ContextUsage provides usage statistics over time
type ContextUsage struct {
	TimeRange        TimeRange      `json:"time_range"`
	TotalRequests    int            `json:"total_requests"`
	AverageLength    float64        `json:"average_length"`
	CompressionUsage float64        `json:"compression_usage"`
	SourceBreakdown  map[string]int `json:"source_breakdown"`
	PopularQueries   []string       `json:"popular_queries"`
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// NewDefaultContextManager creates a new default context manager
func NewDefaultContextManager(memoryManager *MemoryManager, config ContextConfig, logger *logger.Logger) *DefaultContextManager {
	return &DefaultContextManager{
		memoryManager: memoryManager,
		logger:        logger,
		config:        config,
	}
}

// SetCompressionChain sets the LLM chain for text compression
func (cm *DefaultContextManager) SetCompressionChain(chain interface{}) {
	cm.compressionChain = chain
}

// SetSummaryChain sets the LLM chain for summarization
func (cm *DefaultContextManager) SetSummaryChain(chain interface{}) {
	cm.summaryChain = chain
}

// GetRelevantContext retrieves relevant context for a query
func (cm *DefaultContextManager) GetRelevantContext(ctx context.Context, query string, options ContextOptions) (ContextResult, error) {
	ctx, span := contextTracer.Start(ctx, "context_manager.get_relevant_context",
		trace.WithAttributes(
			attribute.String("query", query),
			attribute.Int("max_length", options.MaxLength),
		),
	)
	defer span.End()

	var allItems []ContextItem

	// Retrieve from different memory sources
	if options.IncludeHistory {
		historyItems, err := cm.getHistoryContext(ctx, query, options)
		if err != nil {
			cm.logger.Warn("Failed to get history context", "error", err)
		} else {
			allItems = append(allItems, historyItems...)
		}
	}

	if options.IncludeEpisodic {
		episodicItems, err := cm.getEpisodicContext(ctx, query, options)
		if err != nil {
			cm.logger.Warn("Failed to get episodic context", "error", err)
		} else {
			allItems = append(allItems, episodicItems...)
		}
	}

	if options.IncludeSemantic {
		semanticItems, err := cm.getSemanticContext(ctx, query, options)
		if err != nil {
			cm.logger.Warn("Failed to get semantic context", "error", err)
		} else {
			allItems = append(allItems, semanticItems...)
		}
	}

	if options.IncludeVector {
		vectorItems, err := cm.getVectorContext(ctx, query, options)
		if err != nil {
			cm.logger.Warn("Failed to get vector context", "error", err)
		} else {
			allItems = append(allItems, vectorItems...)
		}
	}

	// Rank and filter items
	rankedItems, err := cm.RankContextItems(ctx, allItems, query)
	if err != nil {
		span.RecordError(err)
		return ContextResult{}, fmt.Errorf("failed to rank context items: %w", err)
	}

	// Apply relevance filter
	var filteredItems []ContextItem
	for _, item := range rankedItems {
		if item.RelevanceScore >= options.RelevanceFilter {
			filteredItems = append(filteredItems, item)
		}
	}

	// Apply length limit
	finalItems, totalLength, compressionUsed := cm.applyLengthLimit(ctx, filteredItems, options.MaxLength)

	// Calculate overall relevance score
	relevanceScore := cm.calculateOverallRelevance(finalItems)

	// Extract sources
	sources := cm.extractSources(finalItems)

	result := ContextResult{
		Items:           finalItems,
		TotalLength:     totalLength,
		RelevanceScore:  relevanceScore,
		Sources:         sources,
		CompressionUsed: compressionUsed,
		Metadata: map[string]interface{}{
			"query":          query,
			"original_count": len(allItems),
			"filtered_count": len(filteredItems),
			"final_count":    len(finalItems),
		},
	}

	span.SetAttributes(
		attribute.Int("result.items", len(finalItems)),
		attribute.Int("result.length", totalLength),
		attribute.Float64("result.relevance", relevanceScore),
		attribute.Bool("compression_used", compressionUsed),
		attribute.Bool("success", true),
	)

	cm.logger.Debug("Relevant context retrieved",
		"query", query,
		"items_count", len(finalItems),
		"total_length", totalLength,
		"relevance_score", relevanceScore,
	)

	return result, nil
}

// GetConversationContext retrieves context for a specific conversation
func (cm *DefaultContextManager) GetConversationContext(ctx context.Context, conversationID string, options ContextOptions) (ContextResult, error) {
	ctx, span := contextTracer.Start(ctx, "context_manager.get_conversation_context",
		trace.WithAttributes(attribute.String("conversation.id", conversationID)),
	)
	defer span.End()

	// Get conversation history
	messages, err := cm.memoryManager.conversationalMemory.GetMessages(ctx, conversationID, 0)
	if err != nil {
		span.RecordError(err)
		return ContextResult{}, fmt.Errorf("failed to get conversation messages: %w", err)
	}

	var items []ContextItem
	for _, message := range messages {
		item := ContextItem{
			ID:             fmt.Sprintf("msg_%s", message.ID),
			Type:           "conversation",
			Content:        message.Content,
			RelevanceScore: 1.0, // All conversation messages are highly relevant
			Timestamp:      message.Timestamp,
			Source:         "conversation",
			Metadata: map[string]interface{}{
				"role":            message.Role,
				"conversation_id": conversationID,
			},
		}
		items = append(items, item)
	}

	// Apply length limit
	finalItems, totalLength, compressionUsed := cm.applyLengthLimit(ctx, items, options.MaxLength)

	result := ContextResult{
		Items:           finalItems,
		TotalLength:     totalLength,
		RelevanceScore:  1.0,
		Sources:         []string{"conversation"},
		CompressionUsed: compressionUsed,
		Metadata: map[string]interface{}{
			"conversation_id": conversationID,
			"message_count":   len(messages),
		},
	}

	span.SetAttributes(
		attribute.Int("messages.count", len(messages)),
		attribute.Int("result.length", totalLength),
		attribute.Bool("compression_used", compressionUsed),
		attribute.Bool("success", true),
	)

	return result, nil
}

// CompressContext compresses context content to fit within target length
func (cm *DefaultContextManager) CompressContext(ctx context.Context, content string, targetLength int) (string, error) {
	ctx, span := contextTracer.Start(ctx, "context_manager.compress_context",
		trace.WithAttributes(
			attribute.Int("content.length", len(content)),
			attribute.Int("target.length", targetLength),
		),
	)
	defer span.End()

	if len(content) <= targetLength {
		return content, nil
	}

	if cm.compressionChain == nil {
		// Simple truncation fallback
		if targetLength > 100 {
			return content[:targetLength-3] + "...", nil
		}
		return content[:targetLength], nil
	}

	// Simple compression for demo (no LLM chain to avoid import cycle)
	if targetLength > 100 {
		compressed := content[:targetLength-3] + "..."
		span.SetAttributes(
			attribute.Int("compressed.length", len(compressed)),
			attribute.Float64("compression.ratio", float64(len(compressed))/float64(len(content))),
			attribute.Bool("success", true),
		)
		return compressed, nil
	}
	compressed := content[:targetLength]

	span.SetAttributes(
		attribute.Int("compressed.length", len(compressed)),
		attribute.Float64("compression.ratio", float64(len(compressed))/float64(len(content))),
		attribute.Bool("success", true),
	)

	return compressed, nil
}

// RankContextItems ranks context items by relevance to a query
func (cm *DefaultContextManager) RankContextItems(ctx context.Context, items []ContextItem, query string) ([]ContextItem, error) {
	if len(items) == 0 {
		return items, nil
	}

	// Calculate relevance scores
	for i := range items {
		items[i].RelevanceScore = cm.calculateRelevanceScore(items[i], query)
	}

	// Sort by relevance score (highest first)
	sort.Slice(items, func(i, j int) bool {
		return items[i].RelevanceScore > items[j].RelevanceScore
	})

	return items, nil
}

// Helper methods

// getHistoryContext retrieves context from conversation history
func (cm *DefaultContextManager) getHistoryContext(ctx context.Context, query string, options ContextOptions) ([]ContextItem, error) {
	// This would search conversation history for relevant messages
	// For now, return empty slice
	return []ContextItem{}, nil
}

// getEpisodicContext retrieves context from episodic memory
func (cm *DefaultContextManager) getEpisodicContext(ctx context.Context, query string, options ContextOptions) ([]ContextItem, error) {
	episodeQuery := EpisodeQuery{
		Query: query,
		Limit: 20, // Default limit
	}

	if options.TimeRange != nil {
		episodeQuery.StartTime = options.TimeRange.Start
		episodeQuery.EndTime = options.TimeRange.End
	}

	episodes, err := cm.memoryManager.episodicMemory.RetrieveEpisodes(ctx, episodeQuery)
	if err != nil {
		return nil, err
	}

	var items []ContextItem
	for _, episode := range episodes {
		item := ContextItem{
			ID:             episode.ID,
			Type:           "episodic",
			Content:        fmt.Sprintf("%s: %s", episode.Title, episode.Description),
			RelevanceScore: 0.8, // Will be recalculated
			Timestamp:      episode.Timestamp,
			Source:         "episodic_memory",
			Metadata: map[string]interface{}{
				"tags":    episode.Tags,
				"context": episode.Context,
				"outcome": episode.Outcome,
			},
		}
		items = append(items, item)
	}

	return items, nil
}

// getSemanticContext retrieves context from semantic memory
func (cm *DefaultContextManager) getSemanticContext(ctx context.Context, query string, options ContextOptions) ([]ContextItem, error) {
	facts, err := cm.memoryManager.semanticMemory.RetrieveFacts(ctx, query, 20) // Default limit
	if err != nil {
		return nil, err
	}

	var items []ContextItem
	for _, fact := range facts {
		item := ContextItem{
			ID:             fact.ID,
			Type:           "semantic",
			Content:        fmt.Sprintf("%s %s %s", fact.Subject, fact.Predicate, fact.Object),
			RelevanceScore: fact.Confidence,
			Timestamp:      fact.Timestamp,
			Source:         "semantic_memory",
			Metadata: map[string]interface{}{
				"confidence": fact.Confidence,
				"context":    fact.Context,
			},
		}
		items = append(items, item)
	}

	return items, nil
}

// getVectorContext retrieves context from vector memory
func (cm *DefaultContextManager) getVectorContext(ctx context.Context, query string, options ContextOptions) ([]ContextItem, error) {
	// This would use vector similarity search
	// For now, return empty slice
	return []ContextItem{}, nil
}

// applyLengthLimit applies length limits to context items
func (cm *DefaultContextManager) applyLengthLimit(ctx context.Context, items []ContextItem, maxLength int) ([]ContextItem, int, bool) {
	if maxLength <= 0 {
		return items, cm.calculateTotalLength(items), false
	}

	var result []ContextItem
	totalLength := 0
	compressionUsed := false

	for _, item := range items {
		itemLength := len(item.Content)

		if totalLength+itemLength <= maxLength {
			result = append(result, item)
			totalLength += itemLength
		} else if cm.config.EnableCompression && totalLength < maxLength {
			// Try to compress the item to fit
			remainingSpace := maxLength - totalLength
			if remainingSpace > 50 { // Minimum space for meaningful compression
				compressed, err := cm.CompressContext(ctx, item.Content, remainingSpace)
				if err == nil {
					item.Content = compressed
					result = append(result, item)
					totalLength += len(compressed)
					compressionUsed = true
				}
			}
			break
		} else {
			break
		}
	}

	return result, totalLength, compressionUsed
}

// calculateRelevanceScore calculates relevance score for a context item
func (cm *DefaultContextManager) calculateRelevanceScore(item ContextItem, query string) float64 {
	// Simple text similarity for now
	query = strings.ToLower(query)
	content := strings.ToLower(item.Content)

	// Count matching words
	queryWords := strings.Fields(query)
	contentWords := strings.Fields(content)

	matches := 0
	for _, qWord := range queryWords {
		for _, cWord := range contentWords {
			if qWord == cWord {
				matches++
				break
			}
		}
	}

	if len(queryWords) == 0 {
		return item.RelevanceScore
	}

	textSimilarity := float64(matches) / float64(len(queryWords))

	// Combine with existing relevance score
	return (item.RelevanceScore + textSimilarity) / 2.0
}

// calculateOverallRelevance calculates overall relevance score
func (cm *DefaultContextManager) calculateOverallRelevance(items []ContextItem) float64 {
	if len(items) == 0 {
		return 0.0
	}

	total := 0.0
	for _, item := range items {
		total += item.RelevanceScore
	}

	return total / float64(len(items))
}

// extractSources extracts unique sources from context items
func (cm *DefaultContextManager) extractSources(items []ContextItem) []string {
	sourceSet := make(map[string]bool)
	for _, item := range items {
		sourceSet[item.Source] = true
	}

	var sources []string
	for source := range sourceSet {
		sources = append(sources, source)
	}

	return sources
}

// calculateTotalLength calculates total length of context items
func (cm *DefaultContextManager) calculateTotalLength(items []ContextItem) int {
	total := 0
	for _, item := range items {
		total += len(item.Content)
	}
	return total
}

// SummarizeConversation creates a summary of a conversation
func (cm *DefaultContextManager) SummarizeConversation(ctx context.Context, conversationID string) (ConversationSummary, error) {
	// Get conversation messages
	messages, err := cm.memoryManager.conversationalMemory.GetMessages(ctx, conversationID, 0)
	if err != nil {
		return ConversationSummary{}, fmt.Errorf("failed to get conversation messages: %w", err)
	}

	// Create summary
	summary := ConversationSummary{
		ConversationID: conversationID,
		Summary:        fmt.Sprintf("Conversation with %d messages", len(messages)),
		KeyPoints:      []string{},
		Participants:   []string{},
		MessageCount:   len(messages),
		Metadata:       make(map[string]interface{}),
	}

	if len(messages) > 0 {
		summary.TimeRange = TimeRange{
			Start: messages[0].Timestamp,
			End:   messages[len(messages)-1].Timestamp,
		}

		// Extract participants
		participants := make(map[string]bool)
		for _, msg := range messages {
			participants[msg.Role] = true
		}
		for participant := range participants {
			summary.Participants = append(summary.Participants, participant)
		}
	}

	return summary, nil
}

// IntegrateContext integrates context from multiple sources
func (cm *DefaultContextManager) IntegrateContext(ctx context.Context, sources []ContextSource) (IntegratedContext, error) {
	var allItems []ContextItem
	var totalWeight float64

	// Retrieve context from each source
	for _, source := range sources {
		options := ContextOptions{
			MaxLength:       1000, // Default per source
			IncludeHistory:  source.Type == "conversation",
			IncludeEpisodic: source.Type == "episodic",
			IncludeSemantic: source.Type == "semantic",
			IncludeVector:   source.Type == "vector",
		}

		result, err := cm.GetRelevantContext(ctx, source.Query, options)
		if err != nil {
			if source.Required {
				return IntegratedContext{}, fmt.Errorf("failed to get required context from source %s: %w", source.Type, err)
			}
			cm.logger.Warn("Failed to get context from source", "type", source.Type, "error", err)
			continue
		}

		// Weight the items
		for _, item := range result.Items {
			item.RelevanceScore *= source.Weight
			allItems = append(allItems, item)
		}
		totalWeight += source.Weight
	}

	// Rank and combine items
	rankedItems, err := cm.RankContextItems(ctx, allItems, "")
	if err != nil {
		return IntegratedContext{}, fmt.Errorf("failed to rank integrated context: %w", err)
	}

	// Build integrated content
	var contentBuilder strings.Builder
	for i, item := range rankedItems {
		if i > 0 {
			contentBuilder.WriteString("\n\n")
		}
		contentBuilder.WriteString(item.Content)
	}

	integrated := IntegratedContext{
		Content:        contentBuilder.String(),
		Sources:        sources,
		TotalLength:    len(contentBuilder.String()),
		RelevanceScore: cm.calculateOverallRelevance(rankedItems),
		Metadata: map[string]interface{}{
			"sources_count": len(sources),
			"items_count":   len(rankedItems),
			"total_weight":  totalWeight,
		},
	}

	return integrated, nil
}

// UpdateContext updates context for a conversation
func (cm *DefaultContextManager) UpdateContext(ctx context.Context, conversationID string, message Message) error {
	// Store the message in conversational memory
	return cm.memoryManager.conversationalMemory.AddMessage(ctx, conversationID, message)
}

// ClearContext clears context for a conversation
func (cm *DefaultContextManager) ClearContext(ctx context.Context, conversationID string) error {
	// Clear conversation history
	return cm.memoryManager.conversationalMemory.ClearSession(ctx, conversationID)
}

// GetContextStats returns context statistics
func (cm *DefaultContextManager) GetContextStats(ctx context.Context, conversationID string) (ContextStats, error) {
	messages, err := cm.memoryManager.conversationalMemory.GetMessages(ctx, conversationID, 0)
	if err != nil {
		return ContextStats{}, err
	}

	totalLength := 0
	for _, msg := range messages {
		totalLength += len(msg.Content)
	}

	stats := ContextStats{
		ConversationID:     conversationID,
		TotalMessages:      len(messages),
		TotalContextLength: totalLength,
		CompressionRatio:   1.0, // No compression by default
		ContextSources: map[string]int{
			"conversation": len(messages),
		},
	}

	return stats, nil
}

// GetContextUsage returns context usage statistics
func (cm *DefaultContextManager) GetContextUsage(ctx context.Context, timeRange TimeRange) (ContextUsage, error) {
	usage := ContextUsage{
		TimeRange:        timeRange,
		TotalRequests:    0,
		AverageLength:    0,
		CompressionUsage: 0,
		SourceBreakdown:  make(map[string]int),
		PopularQueries:   []string{},
	}

	// This would be populated from actual usage metrics
	return usage, nil
}
