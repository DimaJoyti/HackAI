package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/memory"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

func main() {
	// Initialize logger
	logger := logger.NewDefault()
	logger.Info("Starting Agent Memory Systems Demo")

	fmt.Println("🧠 Agent Memory Systems Demo")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("Demonstrating comprehensive agent memory capabilities")
	fmt.Println()

	ctx := context.Background()

	// Create memory configuration
	config := &memory.MemoryConfig{
		AgentID:               "demo-agent-001",
		WorkingMemorySize:     50,
		EpisodicMemorySize:    200,
		SemanticMemorySize:    500,
		ProceduralMemorySize:  100,
		VectorMemorySize:      300,
		ConsolidationInterval: 30 * time.Second,
		RetentionPeriod:       7 * 24 * time.Hour, // 7 days
		CompressionThreshold:  100,
		EnablePersistence:     true,
		EnableCompression:     true,
		EnableEncryption:      false,
		EnableIndexing:        true,
		EnableAnalytics:       true,
		PersistenceBackend:    "memory", // In-memory for demo
		VectorDimensions:      128,
		SimilarityThreshold:   0.7,
	}

	// Create agent memory system
	agentMemory, err := memory.NewAgentMemory("demo-agent-001", config, logger)
	if err != nil {
		log.Fatalf("Failed to create agent memory: %v", err)
	}

	// Demo 1: Working Memory Operations
	fmt.Println("💭 Demo 1: Working Memory Operations")
	fmt.Println(strings.Repeat("-", 60))

	// Store current context and goals
	workingMemoryEntries := []*memory.MemoryEntry{
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeWorking,
			Content:    "Current task: Analyze customer feedback data",
			Context:    map[string]interface{}{"task_type": "analysis", "priority": "high"},
			Importance: 0.8,
			Confidence: 0.9,
			Timestamp:  time.Now(),
			Tags:       []string{"task", "analysis", "customer"},
			Metadata:   map[string]interface{}{"source": "task_manager"},
		},
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeWorking,
			Content:    "User preference: Prefers visual charts over tables",
			Context:    map[string]interface{}{"user_id": "user123", "preference_type": "visualization"},
			Importance: 0.6,
			Confidence: 0.8,
			Timestamp:  time.Now(),
			Tags:       []string{"preference", "user", "visualization"},
			Metadata:   map[string]interface{}{"source": "user_interaction"},
		},
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeWorking,
			Content:    "Temporary calculation: Average satisfaction score = 4.2",
			Context:    map[string]interface{}{"calculation_type": "average", "metric": "satisfaction"},
			Importance: 0.4,
			Confidence: 0.95,
			Timestamp:  time.Now(),
			Tags:       []string{"calculation", "metric", "temporary"},
			Metadata:   map[string]interface{}{"source": "computation"},
		},
	}

	for _, entry := range workingMemoryEntries {
		if err := agentMemory.Store(ctx, entry); err != nil {
			log.Printf("Failed to store working memory entry: %v", err)
		} else {
			fmt.Printf("✅ Stored working memory: %s\n", truncateString(entry.Content.(string), 50))
		}
	}

	// Query working memory
	workingQuery := &memory.MemoryQuery{
		Type:  memory.MemoryTypeWorking,
		Tags:  []string{"task"},
		Limit: 10,
	}

	workingResult, err := agentMemory.Query(ctx, workingQuery)
	if err != nil {
		log.Printf("Failed to query working memory: %v", err)
	} else {
		fmt.Printf("🔍 Found %d working memory entries with 'task' tag\n", len(workingResult.Entries))
	}

	fmt.Println()

	// Demo 2: Episodic Memory Operations
	fmt.Println("📚 Demo 2: Episodic Memory Operations")
	fmt.Println(strings.Repeat("-", 60))

	// Store episodic memories (experiences and events)
	episodicMemoryEntries := []*memory.MemoryEntry{
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeEpisodic,
			Content:    "Successfully completed data analysis project for client ABC Corp",
			Context:    map[string]interface{}{"project_id": "proj123", "client": "ABC Corp", "outcome": "success"},
			Importance: 0.9,
			Confidence: 1.0,
			Timestamp:  time.Now().Add(-2 * time.Hour),
			Tags:       []string{"project", "success", "client", "analysis"},
			Metadata:   map[string]interface{}{"duration": "3 hours", "satisfaction": 5},
		},
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeEpisodic,
			Content:    "Learned new visualization technique using D3.js during project",
			Context:    map[string]interface{}{"skill": "visualization", "technology": "D3.js", "learning_context": "project"},
			Importance: 0.7,
			Confidence: 0.8,
			Timestamp:  time.Now().Add(-90 * time.Minute),
			Tags:       []string{"learning", "skill", "visualization", "technology"},
			Metadata:   map[string]interface{}{"difficulty": "medium", "usefulness": "high"},
		},
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeEpisodic,
			Content:    "Encountered error with large dataset processing, resolved by chunking data",
			Context:    map[string]interface{}{"problem": "memory_error", "solution": "data_chunking", "dataset_size": "10GB"},
			Importance: 0.8,
			Confidence: 0.9,
			Timestamp:  time.Now().Add(-45 * time.Minute),
			Tags:       []string{"problem", "solution", "data", "performance"},
			Metadata:   map[string]interface{}{"error_type": "OutOfMemoryError", "resolution_time": "30 minutes"},
		},
	}

	for _, entry := range episodicMemoryEntries {
		if err := agentMemory.Store(ctx, entry); err != nil {
			log.Printf("Failed to store episodic memory entry: %v", err)
		} else {
			fmt.Printf("✅ Stored episodic memory: %s\n", truncateString(entry.Content.(string), 50))
		}
	}

	// Query episodic memories by time range
	episodicQuery := &memory.MemoryQuery{
		Type: memory.MemoryTypeEpisodic,
		TimeRange: &memory.TimeRange{
			Start: time.Now().Add(-3 * time.Hour),
			End:   time.Now(),
		},
		SortBy:    "timestamp",
		SortOrder: "desc",
		Limit:     10,
	}

	episodicResult, err := agentMemory.Query(ctx, episodicQuery)
	if err != nil {
		log.Printf("Failed to query episodic memory: %v", err)
	} else {
		fmt.Printf("🔍 Found %d episodic memories from last 3 hours\n", len(episodicResult.Entries))
		for i, entry := range episodicResult.Entries {
			fmt.Printf("   %d. %s (Importance: %.1f)\n", i+1, truncateString(entry.Content.(string), 40), entry.Importance)
		}
	}

	fmt.Println()

	// Demo 3: Semantic Memory Operations
	fmt.Println("🧩 Demo 3: Semantic Memory Operations")
	fmt.Println(strings.Repeat("-", 60))

	// Store semantic knowledge (concepts and facts)
	semanticMemoryEntries := []*memory.MemoryEntry{
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeSemantic,
			Content:    "Data visualization is the graphical representation of information and data",
			Context:    map[string]interface{}{"concept_type": "definition", "domain": "data_science"},
			Importance: 0.9,
			Confidence: 1.0,
			Timestamp:  time.Now().Add(-1 * time.Hour),
			Tags:       []string{"concept", "visualization", "definition", "data_science"},
			Metadata:   map[string]interface{}{"category": "knowledge", "verified": true},
		},
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeSemantic,
			Content:    "Customer satisfaction scores typically range from 1-5, with 4+ being considered good",
			Context:    map[string]interface{}{"concept_type": "rule", "domain": "customer_service"},
			Importance: 0.8,
			Confidence: 0.9,
			Timestamp:  time.Now().Add(-30 * time.Minute),
			Tags:       []string{"rule", "metric", "customer", "satisfaction"},
			Metadata:   map[string]interface{}{"category": "business_rule", "source": "industry_standard"},
		},
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeSemantic,
			Content:    "D3.js is a JavaScript library for producing dynamic, interactive data visualizations",
			Context:    map[string]interface{}{"concept_type": "tool", "domain": "web_development"},
			Importance: 0.7,
			Confidence: 0.95,
			Timestamp:  time.Now().Add(-15 * time.Minute),
			Tags:       []string{"tool", "javascript", "library", "visualization"},
			Metadata:   map[string]interface{}{"category": "technology", "language": "javascript"},
		},
	}

	for _, entry := range semanticMemoryEntries {
		if err := agentMemory.Store(ctx, entry); err != nil {
			log.Printf("Failed to store semantic memory entry: %v", err)
		} else {
			fmt.Printf("✅ Stored semantic knowledge: %s\n", truncateString(entry.Content.(string), 50))
		}
	}

	// Query semantic memory by concept
	semanticQuery := &memory.MemoryQuery{
		Type:    memory.MemoryTypeSemantic,
		Content: "visualization",
		Limit:   10,
	}

	semanticResult, err := agentMemory.Query(ctx, semanticQuery)
	if err != nil {
		log.Printf("Failed to query semantic memory: %v", err)
	} else {
		fmt.Printf("🔍 Found %d semantic concepts related to 'visualization'\n", len(semanticResult.Entries))
		for i, entry := range semanticResult.Entries {
			fmt.Printf("   %d. %s\n", i+1, truncateString(entry.Content.(string), 60))
		}
	}

	fmt.Println()

	// Demo 4: Procedural Memory Operations
	fmt.Println("⚙️ Demo 4: Procedural Memory Operations")
	fmt.Println(strings.Repeat("-", 60))

	// Store procedural knowledge (skills and procedures)
	proceduralMemoryEntries := []*memory.MemoryEntry{
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeProcedural,
			Content:    "Data analysis procedure: 1) Load data, 2) Clean data, 3) Analyze patterns, 4) Generate insights",
			Context:    map[string]interface{}{"procedure_type": "analysis", "steps": 4},
			Importance: 0.9,
			Confidence: 0.95,
			Timestamp:  time.Now().Add(-2 * time.Hour),
			Tags:       []string{"procedure", "analysis", "data", "workflow"},
			Metadata:   map[string]interface{}{"complexity": "medium", "success_rate": 0.9},
		},
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeProcedural,
			Content:    "Error handling strategy: Log error details, attempt recovery, notify user if critical",
			Context:    map[string]interface{}{"procedure_type": "error_handling", "criticality": "high"},
			Importance: 0.8,
			Confidence: 0.9,
			Timestamp:  time.Now().Add(-1 * time.Hour),
			Tags:       []string{"procedure", "error", "handling", "recovery"},
			Metadata:   map[string]interface{}{"reliability": 0.95, "usage_count": 15},
		},
	}

	for _, entry := range proceduralMemoryEntries {
		if err := agentMemory.Store(ctx, entry); err != nil {
			log.Printf("Failed to store procedural memory entry: %v", err)
		} else {
			fmt.Printf("✅ Stored procedural knowledge: %s\n", truncateString(entry.Content.(string), 50))
		}
	}

	// Query procedural memory
	proceduralQuery := &memory.MemoryQuery{
		Type:  memory.MemoryTypeProcedural,
		Tags:  []string{"procedure"},
		Limit: 10,
	}

	proceduralResult, err := agentMemory.Query(ctx, proceduralQuery)
	if err != nil {
		log.Printf("Failed to query procedural memory: %v", err)
	} else {
		fmt.Printf("🔍 Found %d procedural memories\n", len(proceduralResult.Entries))
		for i, entry := range proceduralResult.Entries {
			fmt.Printf("   %d. %s\n", i+1, truncateString(entry.Content.(string), 60))
		}
	}

	fmt.Println()

	// Demo 5: Vector Memory and Similarity Search
	fmt.Println("🔍 Demo 5: Vector Memory and Similarity Search")
	fmt.Println(strings.Repeat("-", 60))

	// Store vector memories for similarity search
	vectorMemoryEntries := []*memory.MemoryEntry{
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeVector,
			Content:    "Customer feedback analysis shows positive sentiment about new features",
			Context:    map[string]interface{}{"analysis_type": "sentiment", "result": "positive"},
			Importance: 0.8,
			Confidence: 0.9,
			Timestamp:  time.Now(),
			Tags:       []string{"analysis", "sentiment", "feedback", "positive"},
			Metadata:   map[string]interface{}{"sentiment_score": 0.8},
		},
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeVector,
			Content:    "Data visualization improves user understanding of complex information",
			Context:    map[string]interface{}{"insight_type": "user_experience", "domain": "visualization"},
			Importance: 0.7,
			Confidence: 0.85,
			Timestamp:  time.Now(),
			Tags:       []string{"insight", "visualization", "user", "understanding"},
			Metadata:   map[string]interface{}{"evidence_strength": "strong"},
		},
		{
			ID:         uuid.New().String(),
			Type:       memory.MemoryTypeVector,
			Content:    "Machine learning models require careful feature selection for optimal performance",
			Context:    map[string]interface{}{"insight_type": "best_practice", "domain": "machine_learning"},
			Importance: 0.9,
			Confidence: 0.95,
			Timestamp:  time.Now(),
			Tags:       []string{"insight", "machine_learning", "features", "performance"},
			Metadata:   map[string]interface{}{"importance_level": "critical"},
		},
	}

	for _, entry := range vectorMemoryEntries {
		if err := agentMemory.Store(ctx, entry); err != nil {
			log.Printf("Failed to store vector memory entry: %v", err)
		} else {
			fmt.Printf("✅ Stored vector memory: %s\n", truncateString(entry.Content.(string), 50))
		}
	}

	// Perform similarity search
	vectorQuery := &memory.MemoryQuery{
		Type:    memory.MemoryTypeVector,
		Content: "analyzing customer data for insights",
		Limit:   5,
	}

	vectorResult, err := agentMemory.Query(ctx, vectorQuery)
	if err != nil {
		log.Printf("Failed to query vector memory: %v", err)
	} else {
		fmt.Printf("🔍 Found %d similar memories for 'analyzing customer data for insights'\n", len(vectorResult.Entries))
		for i, entry := range vectorResult.Entries {
			relevance := 0.0
			if i < len(vectorResult.Relevance) {
				relevance = vectorResult.Relevance[i]
			}
			fmt.Printf("   %d. %s (Similarity: %.2f)\n", i+1, truncateString(entry.Content.(string), 50), relevance)
		}
	}

	fmt.Println()

	// Demo 6: Memory Statistics and Analytics
	fmt.Println("📊 Demo 6: Memory Statistics and Analytics")
	fmt.Println(strings.Repeat("-", 60))

	// Get comprehensive memory statistics
	stats := agentMemory.GetStatistics()

	fmt.Printf("✅ Memory Statistics for Agent: %s\n", stats.AgentID)
	fmt.Printf("   Total Entries: %d\n", stats.TotalEntries)
	fmt.Printf("   Working Memory: %d entries\n", stats.WorkingMemory.EntryCount)
	fmt.Printf("   Episodic Memory: %d entries\n", stats.EpisodicMemory.EntryCount)
	fmt.Printf("   Semantic Memory: %d entries\n", stats.SemanticMemory.EntryCount)
	fmt.Printf("   Procedural Memory: %d entries\n", stats.ProceduralMemory.EntryCount)
	fmt.Printf("   Vector Memory: %d entries\n", stats.VectorMemory.EntryCount)

	// Show memory type details
	fmt.Printf("\n📈 Detailed Memory Statistics:\n")
	memoryTypes := map[string]*memory.MemoryTypeStatistics{
		"Working":    stats.WorkingMemory,
		"Episodic":   stats.EpisodicMemory,
		"Semantic":   stats.SemanticMemory,
		"Procedural": stats.ProceduralMemory,
		"Vector":     stats.VectorMemory,
	}

	for memType, memStats := range memoryTypes {
		fmt.Printf("   %s Memory:\n", memType)
		fmt.Printf("     Entries: %d\n", memStats.EntryCount)
		fmt.Printf("     Total Size: %d bytes\n", memStats.TotalSize)
		fmt.Printf("     Average Size: %.1f bytes\n", memStats.AverageSize)
		fmt.Printf("     Total Access Count: %d\n", memStats.AccessCount)
		if !memStats.LastAccess.IsZero() {
			fmt.Printf("     Last Access: %s\n", memStats.LastAccess.Format("15:04:05"))
		}
	}

	fmt.Println()

	// Demo Summary
	fmt.Println("🎉 Agent Memory Systems Demo Summary")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("✅ Working Memory: Short-term active memory with context and goals\n")
	fmt.Printf("✅ Episodic Memory: Experience-based memories with temporal context\n")
	fmt.Printf("✅ Semantic Memory: Conceptual knowledge and facts\n")
	fmt.Printf("✅ Procedural Memory: Skills, procedures, and behavioral patterns\n")
	fmt.Printf("✅ Vector Memory: Similarity-based retrieval using embeddings\n")
	fmt.Printf("✅ Memory Management: Consolidation, compression, and maintenance\n")
	fmt.Printf("✅ Advanced Analytics: Comprehensive statistics and monitoring\n")
	fmt.Printf("\n🚀 Agent Memory Systems demonstrated successfully!\n")
	fmt.Printf("   Total Memory Entries: %d\n", stats.TotalEntries)
	fmt.Printf("   Memory Types: 5 different memory systems\n")
	fmt.Printf("   Features: Consolidation, Compression, Similarity Search, Analytics\n")

	logger.Info("Agent Memory Systems Demo completed successfully")
}

// Helper function to truncate strings for display
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
