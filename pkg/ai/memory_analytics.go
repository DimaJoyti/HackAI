package ai

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemoryAnalyticsEngine provides advanced analytics for memory usage
type MemoryAnalyticsEngine struct {
	memoryManager MemoryManager
	cache         map[string]*MemoryAnalytics
	cacheTTL      time.Duration
	mutex         sync.RWMutex
}

// NewMemoryAnalyticsEngine creates a new memory analytics engine
func NewMemoryAnalyticsEngine(memoryManager MemoryManager) *MemoryAnalyticsEngine {
	return &MemoryAnalyticsEngine{
		memoryManager: memoryManager,
		cache:         make(map[string]*MemoryAnalytics),
		cacheTTL:      5 * time.Minute,
	}
}

// GetAnalytics generates comprehensive analytics for a time range
func (mae *MemoryAnalyticsEngine) GetAnalytics(ctx context.Context, timeRange TimeRange) (*MemoryAnalytics, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%d-%d", timeRange.Start.Unix(), timeRange.End.Unix())
	if cached := mae.getCachedAnalytics(cacheKey); cached != nil {
		return cached, nil
	}

	// Generate analytics
	analytics, err := mae.generateAnalytics(ctx, timeRange)
	if err != nil {
		return nil, err
	}

	// Cache results
	mae.setCachedAnalytics(cacheKey, analytics)

	return analytics, nil
}

// generateAnalytics generates analytics for the specified time range
func (mae *MemoryAnalyticsEngine) generateAnalytics(ctx context.Context, timeRange TimeRange) (*MemoryAnalytics, error) {
	// This is a simplified implementation
	// In a real system, you would query the memory manager for data within the time range
	
	analytics := &MemoryAnalytics{
		TimeRange:           timeRange,
		TotalSessions:       0,
		ActiveSessions:      0,
		TotalMessages:       0,
		AverageSessionSize:  0,
		TopUsers:            make([]UserStats, 0),
		MessageDistribution: make(map[string]int64),
		HourlyActivity:      make(map[string]int64),
		StorageUsage:        StorageUsageStats{},
		PerformanceMetrics:  PerformanceMetrics{},
	}

	// Get basic stats from memory manager
	stats := mae.memoryManager.GetStats()
	analytics.TotalSessions = stats.TotalMemories
	analytics.ActiveSessions = stats.ActiveSessions

	// Calculate storage usage
	analytics.StorageUsage = StorageUsageStats{
		TotalSize:        stats.AverageSize * stats.TotalMemories,
		CompressedSize:   int64(float64(stats.AverageSize*stats.TotalMemories) * 0.7), // Estimated
		CompressionRatio: 0.7,
		IndexSize:        int64(float64(stats.AverageSize*stats.TotalMemories) * 0.1), // Estimated
		MetadataSize:     int64(float64(stats.AverageSize*stats.TotalMemories) * 0.05), // Estimated
	}

	// Calculate performance metrics
	analytics.PerformanceMetrics = PerformanceMetrics{
		AverageReadLatency:  10 * time.Millisecond, // Estimated
		AverageWriteLatency: 15 * time.Millisecond, // Estimated
		ThroughputRPS:       float64(stats.TotalRequests) / timeRange.End.Sub(timeRange.Start).Seconds(),
		ErrorRate:           0.01, // Estimated 1% error rate
		CacheHitRate:        stats.HitRate,
	}

	return analytics, nil
}

// GetInsights generates insights for a specific memory session
func (mae *MemoryAnalyticsEngine) GetInsights(ctx context.Context, sessionID string) (*MemoryInsights, error) {
	// Retrieve memory for the session
	memory, err := mae.memoryManager.Retrieve(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve memory for insights: %w", err)
	}

	insights := &MemoryInsights{
		SessionID:         sessionID,
		MessageCount:      len(memory.Messages),
		ConversationFlow:  mae.analyzeConversationFlow(memory.Messages),
		TopicAnalysis:     mae.analyzeTopics(memory.Messages),
		SentimentAnalysis: mae.analyzeSentiment(memory.Messages),
		Patterns:          mae.detectPatterns(memory.Messages),
		Recommendations:   mae.generateRecommendations(memory),
		Metadata:          make(map[string]interface{}),
	}

	return insights, nil
}

// analyzeConversationFlow analyzes the flow of conversation
func (mae *MemoryAnalyticsEngine) analyzeConversationFlow(messages []Message) []ConversationTurn {
	turns := make([]ConversationTurn, 0, len(messages))

	for i, msg := range messages {
		turn := ConversationTurn{
			TurnID:    i + 1,
			Role:      msg.Role,
			Timestamp: msg.Timestamp,
			WordCount: len(strings.Fields(msg.Content)),
			Topics:    mae.extractTopics(msg.Content),
			Sentiment: mae.calculateSentiment(msg.Content),
		}
		turns = append(turns, turn)
	}

	return turns
}

// analyzeTopics analyzes topics in the conversation
func (mae *MemoryAnalyticsEngine) analyzeTopics(messages []Message) []Topic {
	topicFreq := make(map[string]int)
	
	// Simple keyword-based topic extraction
	for _, msg := range messages {
		topics := mae.extractTopics(msg.Content)
		for _, topic := range topics {
			topicFreq[topic]++
		}
	}

	// Convert to Topic structs
	topics := make([]Topic, 0, len(topicFreq))
	for name, freq := range topicFreq {
		topic := Topic{
			Name:       name,
			Confidence: float64(freq) / float64(len(messages)),
			Frequency:  freq,
			Keywords:   mae.extractKeywords(name),
		}
		topics = append(topics, topic)
	}

	// Sort by frequency
	sort.Slice(topics, func(i, j int) bool {
		return topics[i].Frequency > topics[j].Frequency
	})

	return topics
}

// analyzeSentiment analyzes sentiment in the conversation
func (mae *MemoryAnalyticsEngine) analyzeSentiment(messages []Message) SentimentAnalysis {
	sentimentTrend := make([]SentimentPoint, 0, len(messages))
	var totalSentiment float64

	for _, msg := range messages {
		sentiment := mae.calculateSentiment(msg.Content)
		totalSentiment += sentiment

		point := SentimentPoint{
			Timestamp:  msg.Timestamp,
			Sentiment:  sentiment,
			Confidence: 0.8, // Simplified confidence
		}
		sentimentTrend = append(sentimentTrend, point)
	}

	overallSentiment := float64(0)
	if len(messages) > 0 {
		overallSentiment = totalSentiment / float64(len(messages))
	}

	return SentimentAnalysis{
		OverallSentiment: overallSentiment,
		SentimentTrend:   sentimentTrend,
		EmotionBreakdown: map[string]float64{
			"positive": 0.4,
			"neutral":  0.4,
			"negative": 0.2,
		},
	}
}

// detectPatterns detects patterns in the conversation
func (mae *MemoryAnalyticsEngine) detectPatterns(messages []Message) []Pattern {
	patterns := make([]Pattern, 0)

	// Detect question patterns
	questionCount := 0
	for _, msg := range messages {
		if strings.Contains(msg.Content, "?") {
			questionCount++
		}
	}

	if questionCount > 0 {
		pattern := Pattern{
			Type:        "question_pattern",
			Description: "Frequent question asking",
			Frequency:   questionCount,
			Confidence:  float64(questionCount) / float64(len(messages)),
			Examples:    []string{"Questions detected in conversation"},
			Metadata:    map[string]interface{}{"question_ratio": float64(questionCount) / float64(len(messages))},
		}
		patterns = append(patterns, pattern)
	}

	// Detect repetitive patterns
	wordFreq := make(map[string]int)
	for _, msg := range messages {
		words := strings.Fields(strings.ToLower(msg.Content))
		for _, word := range words {
			if len(word) > 3 { // Only count significant words
				wordFreq[word]++
			}
		}
	}

	for word, freq := range wordFreq {
		if freq > 3 { // Threshold for repetitive words
			pattern := Pattern{
				Type:        "repetitive_word",
				Description: fmt.Sprintf("Frequent use of word: %s", word),
				Frequency:   freq,
				Confidence:  float64(freq) / float64(len(messages)),
				Examples:    []string{word},
				Metadata:    map[string]interface{}{"word": word, "frequency": freq},
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// generateRecommendations generates recommendations based on the memory
func (mae *MemoryAnalyticsEngine) generateRecommendations(memory Memory) []string {
	recommendations := make([]string, 0)

	// Check message count
	if len(memory.Messages) > 100 {
		recommendations = append(recommendations, "Consider archiving old messages to improve performance")
	}

	// Check session age
	if time.Since(memory.CreatedAt) > 30*24*time.Hour {
		recommendations = append(recommendations, "Session is over 30 days old, consider cleanup")
	}

	// Check for empty context
	if len(memory.Context) == 0 {
		recommendations = append(recommendations, "Consider adding context information for better personalization")
	}

	return recommendations
}

// Helper methods for simplified analysis

func (mae *MemoryAnalyticsEngine) extractTopics(content string) []string {
	// Simplified topic extraction based on keywords
	topics := make([]string, 0)
	content = strings.ToLower(content)

	topicKeywords := map[string][]string{
		"technology": {"computer", "software", "programming", "code", "tech"},
		"business":   {"money", "profit", "company", "business", "market"},
		"health":     {"health", "medical", "doctor", "medicine", "wellness"},
		"education":  {"learn", "study", "school", "education", "knowledge"},
		"travel":     {"travel", "trip", "vacation", "journey", "destination"},
	}

	for topic, keywords := range topicKeywords {
		for _, keyword := range keywords {
			if strings.Contains(content, keyword) {
				topics = append(topics, topic)
				break
			}
		}
	}

	return topics
}

func (mae *MemoryAnalyticsEngine) extractKeywords(topic string) []string {
	// Return relevant keywords for the topic
	keywordMap := map[string][]string{
		"technology": {"computer", "software", "programming", "code"},
		"business":   {"money", "profit", "company", "market"},
		"health":     {"health", "medical", "doctor", "medicine"},
		"education":  {"learn", "study", "school", "knowledge"},
		"travel":     {"travel", "trip", "vacation", "journey"},
	}

	if keywords, exists := keywordMap[topic]; exists {
		return keywords
	}
	return []string{}
}

func (mae *MemoryAnalyticsEngine) calculateSentiment(content string) float64 {
	// Simplified sentiment analysis
	content = strings.ToLower(content)
	
	positiveWords := []string{"good", "great", "excellent", "amazing", "wonderful", "happy", "love", "like"}
	negativeWords := []string{"bad", "terrible", "awful", "hate", "dislike", "sad", "angry", "frustrated"}

	positiveCount := 0
	negativeCount := 0

	for _, word := range positiveWords {
		positiveCount += strings.Count(content, word)
	}

	for _, word := range negativeWords {
		negativeCount += strings.Count(content, word)
	}

	if positiveCount == 0 && negativeCount == 0 {
		return 0.0 // Neutral
	}

	total := positiveCount + negativeCount
	return (float64(positiveCount) - float64(negativeCount)) / float64(total)
}

// Cache management methods

func (mae *MemoryAnalyticsEngine) getCachedAnalytics(key string) *MemoryAnalytics {
	mae.mutex.RLock()
	defer mae.mutex.RUnlock()

	if analytics, exists := mae.cache[key]; exists {
		return analytics
	}
	return nil
}

func (mae *MemoryAnalyticsEngine) setCachedAnalytics(key string, analytics *MemoryAnalytics) {
	mae.mutex.Lock()
	defer mae.mutex.Unlock()

	mae.cache[key] = analytics

	// Simple cache cleanup - remove old entries
	if len(mae.cache) > 100 {
		// Remove oldest entries (simplified)
		for k := range mae.cache {
			delete(mae.cache, k)
			break
		}
	}
}
