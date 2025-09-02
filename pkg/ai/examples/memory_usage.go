package examples

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// MemoryUsageExample demonstrates comprehensive memory management features
func MemoryUsageExample() error {
	// Create logger
	logger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	// Configure memory manager with all features enabled
	config := ai.MemoryConfig{
		RedisURL:         "redis://localhost:6379",
		KeyPrefix:        "hackai:demo",
		DefaultTTL:       24 * time.Hour,
		CompressionType:  ai.CompressionGzip,
		EncryptionType:   ai.EncryptionAES256GCM,
		EncryptionKey:    "demo-encryption-key-32-bytes!!",
		IndexPath:        "./memory_index",
		EnableIndexing:   true,
		EnableAnalytics:  true,
		EnableValidation: true,
	}

	// Create memory manager
	memoryManager, err := ai.NewRedisMemoryManager(config, logger)
	if err != nil {
		return fmt.Errorf("failed to create memory manager: %w", err)
	}

	ctx := context.Background()

	// Example 1: Basic memory operations
	fmt.Println("=== Basic Memory Operations ===")
	if err := basicMemoryOperations(ctx, memoryManager); err != nil {
		return err
	}

	// Example 2: Advanced search
	fmt.Println("\n=== Advanced Search ===")
	if err := advancedSearchExample(ctx, memoryManager); err != nil {
		return err
	}

	// Example 3: Batch operations
	fmt.Println("\n=== Batch Operations ===")
	if err := batchOperationsExample(ctx, memoryManager); err != nil {
		return err
	}

	// Example 4: Analytics and insights
	fmt.Println("\n=== Analytics and Insights ===")
	if err := analyticsExample(ctx, memoryManager); err != nil {
		return err
	}

	// Example 5: Memory validation
	fmt.Println("\n=== Memory Validation ===")
	if err := validationExample(ctx, memoryManager); err != nil {
		return err
	}

	// Example 6: Memory lifecycle management
	fmt.Println("\n=== Lifecycle Management ===")
	if err := lifecycleExample(ctx, memoryManager); err != nil {
		return err
	}

	fmt.Println("\n=== Memory Usage Example Completed ===")
	return nil
}

// basicMemoryOperations demonstrates basic CRUD operations
func basicMemoryOperations(ctx context.Context, manager ai.MemoryManager) error {
	// Create a memory
	memory := ai.Memory{
		SessionID: "demo-session-1",
		UserID:    "user-123",
		Messages: []ai.Message{
			{
				Role:      "user",
				Content:   "Hello, I need help with Go programming",
				Timestamp: time.Now(),
			},
			{
				Role:      "assistant",
				Content:   "I'd be happy to help you with Go programming! What specific topic would you like to learn about?",
				Timestamp: time.Now().Add(time.Second),
			},
		},
		Context: map[string]interface{}{
			"topic":      "programming",
			"language":   "go",
			"difficulty": "beginner",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Version:   1,
	}

	// Store the memory
	fmt.Printf("Storing memory for session: %s\n", memory.SessionID)
	if err := manager.Store(ctx, memory.SessionID, memory); err != nil {
		return fmt.Errorf("failed to store memory: %w", err)
	}

	// Retrieve the memory
	fmt.Printf("Retrieving memory for session: %s\n", memory.SessionID)
	retrieved, err := manager.Retrieve(ctx, memory.SessionID)
	if err != nil {
		return fmt.Errorf("failed to retrieve memory: %w", err)
	}

	fmt.Printf("Retrieved memory with %d messages\n", len(retrieved.Messages))

	// Search for memories
	fmt.Println("Searching for memories containing 'Go programming'")
	results, err := manager.Search(ctx, "Go programming", 10)
	if err != nil {
		return fmt.Errorf("failed to search memories: %w", err)
	}

	fmt.Printf("Found %d matching memories\n", len(results))

	return nil
}

// advancedSearchExample demonstrates advanced search capabilities
func advancedSearchExample(ctx context.Context, manager ai.MemoryManager) error {
	// Create search query
	query := ai.SearchQuery{
		Text: "programming",
		Filters: map[string]interface{}{
			"topic": "programming",
		},
		SortBy:    "created_at",
		SortOrder: "desc",
		Limit:     5,
		Offset:    0,
		TimeRange: &ai.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		UserID: "user-123",
	}

	fmt.Printf("Performing advanced search with filters\n")
	result, err := manager.AdvancedSearch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to perform advanced search: %w", err)
	}

	fmt.Printf("Advanced search found %d results in %v\n", result.Total, result.Duration)
	for i, memory := range result.Memories {
		fmt.Printf("  %d. Session: %s, Messages: %d\n", i+1, memory.SessionID, len(memory.Messages))
	}

	return nil
}

// batchOperationsExample demonstrates batch operations
func batchOperationsExample(ctx context.Context, manager ai.MemoryManager) error {
	// Create multiple memories
	memories := map[string]ai.Memory{
		"batch-session-1": {
			SessionID: "batch-session-1",
			UserID:    "user-456",
			Messages: []ai.Message{
				{Role: "user", Content: "What is machine learning?", Timestamp: time.Now()},
				{Role: "assistant", Content: "Machine learning is a subset of AI...", Timestamp: time.Now()},
			},
			Context:   map[string]interface{}{"topic": "ml"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Version:   1,
		},
		"batch-session-2": {
			SessionID: "batch-session-2",
			UserID:    "user-789",
			Messages: []ai.Message{
				{Role: "user", Content: "Explain neural networks", Timestamp: time.Now()},
				{Role: "assistant", Content: "Neural networks are computing systems...", Timestamp: time.Now()},
			},
			Context:   map[string]interface{}{"topic": "neural-networks"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Version:   1,
		},
	}

	// Batch store
	fmt.Printf("Batch storing %d memories\n", len(memories))
	if err := manager.BatchStore(ctx, memories); err != nil {
		return fmt.Errorf("failed to batch store memories: %w", err)
	}

	// Batch retrieve
	sessionIDs := []string{"batch-session-1", "batch-session-2"}
	fmt.Printf("Batch retrieving %d memories\n", len(sessionIDs))
	retrieved, err := manager.BatchRetrieve(ctx, sessionIDs)
	if err != nil {
		return fmt.Errorf("failed to batch retrieve memories: %w", err)
	}

	fmt.Printf("Successfully retrieved %d memories\n", len(retrieved))

	return nil
}

// analyticsExample demonstrates analytics and insights
func analyticsExample(ctx context.Context, manager ai.MemoryManager) error {
	// Get analytics for the last 24 hours
	timeRange := ai.TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	fmt.Printf("Getting analytics for time range: %v to %v\n", timeRange.Start.Format("15:04"), timeRange.End.Format("15:04"))
	analytics, err := manager.GetAnalytics(ctx, timeRange)
	if err != nil {
		return fmt.Errorf("failed to get analytics: %w", err)
	}

	fmt.Printf("Analytics Summary:\n")
	fmt.Printf("  Total Sessions: %d\n", analytics.TotalSessions)
	fmt.Printf("  Active Sessions: %d\n", analytics.ActiveSessions)
	fmt.Printf("  Total Messages: %d\n", analytics.TotalMessages)
	fmt.Printf("  Average Session Size: %.2f\n", analytics.AverageSessionSize)
	fmt.Printf("  Storage Usage: %d bytes\n", analytics.StorageUsage.TotalSize)
	fmt.Printf("  Compression Ratio: %.2f\n", analytics.StorageUsage.CompressionRatio)

	// Get insights for a specific session
	fmt.Printf("\nGetting insights for session: demo-session-1\n")
	insights, err := manager.GetInsights(ctx, "demo-session-1")
	if err != nil {
		return fmt.Errorf("failed to get insights: %w", err)
	}

	fmt.Printf("Session Insights:\n")
	fmt.Printf("  Message Count: %d\n", insights.MessageCount)
	fmt.Printf("  Conversation Turns: %d\n", len(insights.ConversationFlow))
	fmt.Printf("  Topics Found: %d\n", len(insights.TopicAnalysis))
	fmt.Printf("  Overall Sentiment: %.2f\n", insights.SentimentAnalysis.OverallSentiment)
	fmt.Printf("  Patterns Detected: %d\n", len(insights.Patterns))
	fmt.Printf("  Recommendations: %d\n", len(insights.Recommendations))

	return nil
}

// validationExample demonstrates memory validation
func validationExample(ctx context.Context, manager ai.MemoryManager) error {
	fmt.Printf("Validating memory for session: demo-session-1\n")
	validation, err := manager.Validate(ctx, "demo-session-1")
	if err != nil {
		return fmt.Errorf("failed to validate memory: %w", err)
	}

	fmt.Printf("Validation Results:\n")
	fmt.Printf("  Valid: %t\n", validation.Valid)
	fmt.Printf("  Checksum: %s\n", validation.Checksum[:16]+"...")
	fmt.Printf("  Size: %d bytes\n", validation.Size)
	fmt.Printf("  Errors: %d\n", len(validation.Errors))
	fmt.Printf("  Warnings: %d\n", len(validation.Warnings))

	if len(validation.Errors) > 0 {
		fmt.Printf("  Error Details:\n")
		for _, err := range validation.Errors {
			fmt.Printf("    - %s: %s\n", err.Code, err.Message)
		}
	}

	if len(validation.Warnings) > 0 {
		fmt.Printf("  Warning Details:\n")
		for _, warning := range validation.Warnings {
			fmt.Printf("    - %s: %s\n", warning.Code, warning.Message)
		}
	}

	return nil
}

// lifecycleExample demonstrates memory lifecycle management
func lifecycleExample(ctx context.Context, manager ai.MemoryManager) error {
	sessionID := "lifecycle-demo"

	// Archive a session
	fmt.Printf("Archiving session: %s\n", sessionID)
	if err := manager.Archive(ctx, sessionID); err != nil {
		fmt.Printf("Archive failed (session may not exist): %v\n", err)
	}

	// Restore a session
	fmt.Printf("Restoring session: %s\n", sessionID)
	if err := manager.Restore(ctx, sessionID); err != nil {
		fmt.Printf("Restore failed (session may not exist): %v\n", err)
	}

	// Cleanup old sessions
	criteria := ai.CleanupCriteria{
		OlderThan: &[]time.Time{time.Now().Add(-30 * 24 * time.Hour)}[0],
		Inactive:  true,
		DryRun:    true, // Don't actually delete anything
	}

	fmt.Printf("Running cleanup with criteria (dry run)\n")
	result, err := manager.Cleanup(ctx, criteria)
	if err != nil {
		return fmt.Errorf("failed to run cleanup: %w", err)
	}

	fmt.Printf("Cleanup Results:\n")
	fmt.Printf("  Sessions Processed: %d\n", result.SessionsProcessed)
	fmt.Printf("  Sessions Deleted: %d\n", result.SessionsDeleted)
	fmt.Printf("  Bytes Freed: %d\n", result.BytesFreed)
	fmt.Printf("  Duration: %v\n", result.Duration)

	return nil
}

// AlternativeBackendsExample demonstrates using different storage backends
func AlternativeBackendsExample() error {
	fmt.Println("=== Alternative Storage Backends ===")

	ctx := context.Background()

	// Example 1: In-Memory Backend
	fmt.Println("\n--- In-Memory Backend ---")
	inMemoryBackend := ai.NewInMemoryBackend()
	if err := demonstrateBackend(ctx, inMemoryBackend, "in-memory"); err != nil {
		return err
	}

	// Example 2: File Backend
	fmt.Println("\n--- File Backend ---")
	fileBackend, err := ai.NewFileBackend("./memory_files")
	if err != nil {
		return fmt.Errorf("failed to create file backend: %w", err)
	}
	if err := demonstrateBackend(ctx, fileBackend, "file"); err != nil {
		return err
	}

	return nil
}

// demonstrateBackend shows basic operations with any backend
func demonstrateBackend(ctx context.Context, backend interface{}, name string) error {
	// This is a simplified demonstration
	// In practice, you would use the backend through the MemoryManager interface

	memory := ai.Memory{
		SessionID: fmt.Sprintf("%s-demo", name),
		UserID:    "demo-user",
		Messages: []ai.Message{
			{
				Role:      "user",
				Content:   fmt.Sprintf("Testing %s backend", name),
				Timestamp: time.Now(),
			},
		},
		Context:   map[string]interface{}{"backend": name},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Version:   1,
	}

	fmt.Printf("Testing %s backend with session: %s\n", name, memory.SessionID)

	// Note: This is a simplified example
	// In practice, you would implement the full MemoryManager interface

	return nil
}
