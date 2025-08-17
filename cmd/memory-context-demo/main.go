package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dimajoyti/hackai/pkg/llm/memory"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	// Initialize logger
	appLogger, err := logger.New(logger.Config{
		Level:      logger.LevelInfo,
		Format:     "json",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	appLogger.Info("🧠 Starting Memory & Context Management Demo")

	// Run comprehensive demo
	if err := runMemoryContextDemo(appLogger); err != nil {
		appLogger.Fatal("Demo failed", "error", err)
	}

	appLogger.Info("✅ Memory & Context Management Demo completed successfully!")
}

func runMemoryContextDemo(logger *logger.Logger) error {
	ctx := context.Background()

	logger.Info("=== 🚀 Memory & Context Management Demo ===")

	// Demo 1: Basic Memory Operations
	if err := demoBasicMemoryOperations(ctx, logger); err != nil {
		return fmt.Errorf("basic memory operations demo failed: %w", err)
	}

	// Demo 2: Episodic Memory
	if err := demoEpisodicMemory(ctx, logger); err != nil {
		return fmt.Errorf("episodic memory demo failed: %w", err)
	}

	// Demo 3: Semantic Memory
	if err := demoSemanticMemory(ctx, logger); err != nil {
		return fmt.Errorf("semantic memory demo failed: %w", err)
	}

	// Demo 4: Context Management
	if err := demoContextManagement(ctx, logger); err != nil {
		return fmt.Errorf("context management demo failed: %w", err)
	}

	// Demo 5: Memory Consolidation
	if err := demoMemoryConsolidation(ctx, logger); err != nil {
		return fmt.Errorf("memory consolidation demo failed: %w", err)
	}

	return nil
}

func demoBasicMemoryOperations(ctx context.Context, logger *logger.Logger) error {
	logger.Info("💾 Demo 1: Basic Memory Operations")

	// Create memory manager
	config := memory.MemoryConfig{
		VectorMemorySize: 1000,
		ConversationTTL:  24 * time.Hour,
	}
	memoryManager := memory.NewMemoryManager(config, logger)

	// Test conversational memory
	conversationID := "demo-conversation-1"

	// Add messages to conversation
	messages := []memory.Message{
		{
			ID:        "msg1",
			SessionID: conversationID,
			Role:      "user",
			Content:   "Hello, I'm interested in learning about AI and machine learning.",
			Timestamp: time.Now().Add(-10 * time.Minute),
		},
		{
			ID:        "msg2",
			SessionID: conversationID,
			Role:      "assistant",
			Content:   "Great! AI and machine learning are fascinating fields. What specific area interests you most?",
			Timestamp: time.Now().Add(-9 * time.Minute),
		},
		{
			ID:        "msg3",
			SessionID: conversationID,
			Role:      "user",
			Content:   "I'm particularly interested in natural language processing and how LLMs work.",
			Timestamp: time.Now().Add(-8 * time.Minute),
		},
		{
			ID:        "msg4",
			SessionID: conversationID,
			Role:      "assistant",
			Content:   "NLP is an exciting area! Large Language Models use transformer architectures to understand and generate human-like text.",
			Timestamp: time.Now().Add(-7 * time.Minute),
		},
	}

	for _, msg := range messages {
		err := memoryManager.GetConversationalMemory().AddMessage(ctx, conversationID, msg)
		if err != nil {
			return fmt.Errorf("failed to store message: %w", err)
		}
	}

	// Retrieve conversation history
	retrievedMessages, err := memoryManager.GetConversationalMemory().GetMessages(ctx, conversationID, 10)
	if err != nil {
		return fmt.Errorf("failed to retrieve messages: %w", err)
	}

	logger.Info("✅ Conversational memory test completed",
		"stored_messages", len(messages),
		"retrieved_messages", len(retrievedMessages),
	)

	// Test vector memory
	vectorContent := memory.Content{
		ID:        "vec1",
		Text:      "Machine learning is a subset of artificial intelligence that focuses on algorithms that can learn from data.",
		Embedding: []float64{0.1, 0.2, 0.3, 0.4, 0.5}, // Mock embedding
		Metadata: map[string]interface{}{
			"topic":    "machine_learning",
			"category": "definition",
		},
		Timestamp: time.Now(),
	}

	err = memoryManager.GetVectorMemory().Store(ctx, "vec1", vectorContent)
	if err != nil {
		return fmt.Errorf("failed to store vector: %w", err)
	}

	// Search vector memory
	searchResults, err := memoryManager.GetVectorMemory().Retrieve(ctx, "artificial intelligence", 5)
	if err != nil {
		return fmt.Errorf("failed to search vectors: %w", err)
	}

	logger.Info("✅ Vector memory test completed",
		"search_results", len(searchResults),
	)

	return nil
}

func demoEpisodicMemory(ctx context.Context, logger *logger.Logger) error {
	logger.Info("📚 Demo 2: Episodic Memory")

	// Create memory manager
	config := memory.MemoryConfig{
		VectorMemorySize: 1000,
		ConversationTTL:  24 * time.Hour,
	}
	memoryManager := memory.NewMemoryManager(config, logger)

	// Create episodic memories
	episodes := []memory.Episode{
		{
			Title:       "First AI Course Completion",
			Description: "Successfully completed Introduction to Artificial Intelligence course",
			Context:     "Online learning platform, 8-week course",
			Outcome:     "Gained foundational understanding of AI concepts",
			Tags:        []string{"education", "ai", "achievement"},
			Timestamp:   time.Now().Add(-30 * 24 * time.Hour),
			Metadata: map[string]interface{}{
				"course_name": "Introduction to AI",
				"platform":    "online",
				"duration":    "8 weeks",
			},
		},
		{
			Title:       "Machine Learning Project",
			Description: "Built a sentiment analysis model for customer reviews",
			Context:     "Work project, used Python and scikit-learn",
			Outcome:     "Achieved 85% accuracy, deployed to production",
			Tags:        []string{"work", "ml", "project", "nlp"},
			Timestamp:   time.Now().Add(-15 * 24 * time.Hour),
			Metadata: map[string]interface{}{
				"technology": "Python",
				"accuracy":   0.85,
				"status":     "deployed",
			},
		},
		{
			Title:       "AI Conference Attendance",
			Description: "Attended NeurIPS conference and learned about latest research",
			Context:     "Virtual conference, 3 days of sessions",
			Outcome:     "Discovered new techniques for transformer optimization",
			Tags:        []string{"conference", "research", "networking"},
			Timestamp:   time.Now().Add(-7 * 24 * time.Hour),
			Metadata: map[string]interface{}{
				"conference": "NeurIPS",
				"format":     "virtual",
				"duration":   "3 days",
			},
		},
	}

	// Store episodes
	for _, episode := range episodes {
		err := memoryManager.GetEpisodicMemory().StoreEpisode(ctx, episode)
		if err != nil {
			return fmt.Errorf("failed to store episode: %w", err)
		}
	}

	// Query episodes
	query := memory.EpisodeQuery{
		Query: "machine learning",
		Tags:  []string{"ml", "ai"},
		Limit: 10,
	}

	retrievedEpisodes, err := memoryManager.GetEpisodicMemory().RetrieveEpisodes(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to retrieve episodes: %w", err)
	}

	logger.Info("✅ Episodic memory test completed",
		"stored_episodes", len(episodes),
		"retrieved_episodes", len(retrievedEpisodes),
	)

	// Display retrieved episodes
	for _, episode := range retrievedEpisodes {
		logger.Info("📖 Retrieved Episode",
			"title", episode.Title,
			"tags", episode.Tags,
			"timestamp", episode.Timestamp.Format("2006-01-02"),
		)
	}

	return nil
}

func demoSemanticMemory(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🧮 Demo 3: Semantic Memory")

	// Create memory manager
	config := memory.MemoryConfig{
		VectorMemorySize: 1000,
		ConversationTTL:  24 * time.Hour,
	}
	memoryManager := memory.NewMemoryManager(config, logger)

	// Create semantic facts
	facts := []memory.Fact{
		{
			Subject:    "Machine Learning",
			Predicate:  "is_subset_of",
			Object:     "Artificial Intelligence",
			Confidence: 0.95,
			Context:    "Fundamental AI concept",
			Timestamp:  time.Now().Add(-1 * time.Hour),
			Metadata: map[string]interface{}{
				"source": "textbook",
				"domain": "computer_science",
			},
		},
		{
			Subject:    "Neural Networks",
			Predicate:  "inspired_by",
			Object:     "Human Brain",
			Confidence: 0.85,
			Context:    "Biological inspiration for AI",
			Timestamp:  time.Now().Add(-2 * time.Hour),
			Metadata: map[string]interface{}{
				"source": "research_paper",
				"domain": "neuroscience",
			},
		},
		{
			Subject:    "Transformers",
			Predicate:  "revolutionized",
			Object:     "Natural Language Processing",
			Confidence: 0.90,
			Context:    "Modern NLP breakthrough",
			Timestamp:  time.Now().Add(-30 * time.Minute),
			Metadata: map[string]interface{}{
				"source": "conference_paper",
				"year":   2017,
			},
		},
		{
			Subject:    "GPT",
			Predicate:  "uses",
			Object:     "Transformer Architecture",
			Confidence: 0.98,
			Context:    "Large language model implementation",
			Timestamp:  time.Now().Add(-15 * time.Minute),
			Metadata: map[string]interface{}{
				"source": "technical_documentation",
				"model":  "GPT-3",
			},
		},
	}

	// Store facts
	for _, fact := range facts {
		err := memoryManager.GetSemanticMemory().StoreFact(ctx, fact)
		if err != nil {
			return fmt.Errorf("failed to store fact: %w", err)
		}
	}

	// Query facts
	retrievedFacts, err := memoryManager.GetSemanticMemory().RetrieveFacts(ctx, "Machine Learning", 10)
	if err != nil {
		return fmt.Errorf("failed to retrieve facts: %w", err)
	}

	logger.Info("✅ Semantic memory test completed",
		"stored_facts", len(facts),
		"retrieved_facts", len(retrievedFacts),
	)

	// Display retrieved facts
	for _, fact := range retrievedFacts {
		logger.Info("🔗 Retrieved Fact",
			"subject", fact.Subject,
			"predicate", fact.Predicate,
			"object", fact.Object,
			"confidence", fmt.Sprintf("%.2f", fact.Confidence),
		)
	}

	// Test fact relationships (simplified for demo)
	logger.Info("🔗 Fact relationships available for exploration")

	return nil
}

func demoContextManagement(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🎯 Demo 4: Context Management")

	// Create memory manager
	config := memory.MemoryConfig{
		VectorMemorySize: 1000,
		ConversationTTL:  24 * time.Hour,
	}
	memoryManager := memory.NewMemoryManager(config, logger)

	// Test context retrieval
	contextOptions := memory.ContextOptions{
		MaxLength:       2000,
		IncludeHistory:  true,
		IncludeEpisodic: true,
		IncludeSemantic: true,
		IncludeVector:   true,
		RelevanceFilter: 0.3,
	}

	contextResult, err := memoryManager.GetContextManager().GetRelevantContext(ctx, "machine learning projects", contextOptions)
	if err != nil {
		return fmt.Errorf("failed to get relevant context: %w", err)
	}

	logger.Info("✅ Context retrieval completed",
		"items_count", len(contextResult.Items),
		"total_length", contextResult.TotalLength,
		"relevance_score", fmt.Sprintf("%.2f", contextResult.RelevanceScore),
		"compression_used", contextResult.CompressionUsed,
	)

	// Test context compression
	longText := "This is a very long text that needs to be compressed to fit within the context window. " +
		"It contains important information about machine learning, artificial intelligence, and natural language processing. " +
		"The text discusses various algorithms, techniques, and applications in the field of AI. " +
		"It also covers recent developments in transformer architectures and large language models."

	compressedText, err := memoryManager.GetContextManager().CompressContext(ctx, longText, 100)
	if err != nil {
		return fmt.Errorf("failed to compress context: %w", err)
	}

	logger.Info("✅ Context compression completed",
		"original_length", len(longText),
		"compressed_length", len(compressedText),
		"compression_ratio", fmt.Sprintf("%.2f", float64(len(compressedText))/float64(len(longText))),
	)

	// Test conversation summarization
	conversationID := "demo-conversation-1"
	summary, err := memoryManager.GetContextManager().SummarizeConversation(ctx, conversationID)
	if err != nil {
		return fmt.Errorf("failed to summarize conversation: %w", err)
	}

	logger.Info("✅ Conversation summarization completed",
		"conversation_id", summary.ConversationID,
		"message_count", summary.MessageCount,
		"participants", summary.Participants,
	)

	return nil
}

func demoMemoryConsolidation(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🔄 Demo 5: Memory Consolidation")

	// Create memory manager
	config := memory.MemoryConfig{
		VectorMemorySize: 1000,
		ConversationTTL:  24 * time.Hour,
	}
	memoryManager := memory.NewMemoryManager(config, logger)

	// Test conversation consolidation
	conversationID := "demo-conversation-1"
	err := memoryManager.GetConsolidator().ConsolidateConversation(ctx, conversationID)
	if err != nil {
		logger.Warn("Conversation consolidation completed with warnings", "error", err)
	} else {
		logger.Info("✅ Conversation consolidation completed")
	}

	// Test episode consolidation
	timeRange := memory.TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}
	err = memoryManager.GetConsolidator().ConsolidateEpisodes(ctx, timeRange)
	if err != nil {
		logger.Warn("Episode consolidation completed with warnings", "error", err)
	} else {
		logger.Info("✅ Episode consolidation completed")
	}

	// Test fact consolidation
	err = memoryManager.GetConsolidator().ConsolidateFacts(ctx, "Machine Learning")
	if err != nil {
		logger.Warn("Fact consolidation completed with warnings", "error", err)
	} else {
		logger.Info("✅ Fact consolidation completed")
	}

	// Get consolidation statistics
	stats, err := memoryManager.GetConsolidator().GetConsolidationStats(ctx)
	if err != nil {
		return fmt.Errorf("failed to get consolidation stats: %w", err)
	}

	logger.Info("📊 Consolidation Statistics",
		"last_consolidation", stats.LastConsolidation.Format("2006-01-02 15:04:05"),
		"conversations_processed", stats.ConversationsProcessed,
		"episodes_consolidated", stats.EpisodesConsolidated,
		"facts_consolidated", stats.FactsConsolidated,
		"error_count", stats.ErrorCount,
	)

	return nil
}
