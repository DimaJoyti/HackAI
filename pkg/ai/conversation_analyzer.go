package ai

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// ConversationAnalyzer analyzes conversation patterns for jailbreak detection
type ConversationAnalyzer struct {
	logger            *logger.Logger
	conversationCache map[string]*ConversationSession
	maxCacheSize      int
}

// ConversationSession represents a conversation session
type ConversationSession struct {
	ID                string                    `json:"id"`
	StartTime         time.Time                 `json:"start_time"`
	LastActivity      time.Time                 `json:"last_activity"`
	TurnCount         int                       `json:"turn_count"`
	Messages          []ConversationMessage     `json:"messages"`
	TopicShifts       []TopicShift              `json:"topic_shifts"`
	SentimentHistory  []JailbreakSentimentPoint `json:"sentiment_history"`
	JailbreakAttempts int                       `json:"jailbreak_attempts"`
	Metadata          map[string]interface{}    `json:"metadata"`
}

// ConversationMessage represents a single message in conversation
type ConversationMessage struct {
	ID        string                  `json:"id"`
	Timestamp time.Time               `json:"timestamp"`
	Content   string                  `json:"content"`
	Role      string                  `json:"role"` // user, assistant, system
	Topic     string                  `json:"topic"`
	Sentiment JailbreakSentimentPoint `json:"sentiment"`
	Metadata  map[string]interface{}  `json:"metadata"`
}

// ConversationAnalysisResult represents the result of conversation analysis
type ConversationAnalysisResult struct {
	Context            ConversationContext    `json:"context"`
	EscalationDetected bool                   `json:"escalation_detected"`
	TopicManipulation  bool                   `json:"topic_manipulation"`
	SentimentShifts    []SentimentShift       `json:"sentiment_shifts"`
	Anomalies          []ConversationAnomaly  `json:"anomalies"`
	RiskScore          float64                `json:"risk_score"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// SentimentShift represents a significant change in sentiment
type SentimentShift struct {
	FromSentiment string    `json:"from_sentiment"`
	ToSentiment   string    `json:"to_sentiment"`
	Timestamp     time.Time `json:"timestamp"`
	Magnitude     float64   `json:"magnitude"`
	Suspicious    bool      `json:"suspicious"`
}

// ConversationAnomaly represents an anomaly in conversation
type ConversationAnomaly struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"`
	Evidence    []string               `json:"evidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewConversationAnalyzer creates a new conversation analyzer
func NewConversationAnalyzer(logger *logger.Logger) *ConversationAnalyzer {
	return &ConversationAnalyzer{
		logger:            logger,
		conversationCache: make(map[string]*ConversationSession),
		maxCacheSize:      1000,
	}
}

// AnalyzeConversation analyzes a conversation for jailbreak patterns
func (c *ConversationAnalyzer) AnalyzeConversation(ctx context.Context, currentInput string, conversationHistory []string) (*ConversationAnalysisResult, error) {
	// Create or update conversation session
	sessionID := c.getSessionID(ctx)
	session := c.getOrCreateSession(sessionID)

	// Add current message to session
	message := ConversationMessage{
		ID:        c.generateMessageID(),
		Timestamp: time.Now(),
		Content:   currentInput,
		Role:      "user",
		Topic:     c.extractTopic(currentInput),
		Sentiment: c.analyzeSentiment(currentInput),
	}

	session.Messages = append(session.Messages, message)
	session.TurnCount++
	session.LastActivity = time.Now()

	// Analyze conversation patterns
	result := &ConversationAnalysisResult{
		Context: ConversationContext{
			TurnNumber:         session.TurnCount,
			ConversationLength: len(session.Messages),
			PreviousAttempts:   session.JailbreakAttempts,
		},
		SentimentShifts: make([]SentimentShift, 0),
		Anomalies:       make([]ConversationAnomaly, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Detect escalation patterns
	result.EscalationDetected = c.detectEscalation(session)

	// Detect topic manipulation
	result.TopicManipulation = c.detectTopicManipulation(session)

	// Analyze sentiment shifts
	result.SentimentShifts = c.analyzeSentimentShifts(session)

	// Detect conversation anomalies
	result.Anomalies = c.detectAnomalies(session)

	// Calculate risk score
	result.RiskScore = c.calculateConversationRiskScore(result)

	// Update session metadata
	session.Metadata = map[string]interface{}{
		"last_analysis":      time.Now(),
		"risk_score":         result.RiskScore,
		"escalation":         result.EscalationDetected,
		"topic_manipulation": result.TopicManipulation,
	}

	return result, nil
}

// getSessionID extracts session ID from context
func (c *ConversationAnalyzer) getSessionID(ctx context.Context) string {
	if sessionID := ctx.Value("session_id"); sessionID != nil {
		if id, ok := sessionID.(string); ok {
			return id
		}
	}
	return "default_session"
}

// getOrCreateSession gets or creates a conversation session
func (c *ConversationAnalyzer) getOrCreateSession(sessionID string) *ConversationSession {
	if session, exists := c.conversationCache[sessionID]; exists {
		return session
	}

	// Create new session
	session := &ConversationSession{
		ID:                sessionID,
		StartTime:         time.Now(),
		LastActivity:      time.Now(),
		TurnCount:         0,
		Messages:          make([]ConversationMessage, 0),
		TopicShifts:       make([]TopicShift, 0),
		SentimentHistory:  make([]JailbreakSentimentPoint, 0),
		JailbreakAttempts: 0,
		Metadata:          make(map[string]interface{}),
	}

	// Manage cache size
	if len(c.conversationCache) >= c.maxCacheSize {
		c.evictOldestSession()
	}

	c.conversationCache[sessionID] = session
	return session
}

// generateMessageID generates a unique message ID
func (c *ConversationAnalyzer) generateMessageID() string {
	return fmt.Sprintf("msg_%d", time.Now().UnixNano())
}

// extractTopic extracts the topic from a message
func (c *ConversationAnalyzer) extractTopic(content string) string {
	// Simplified topic extraction
	// In a real implementation, this would use NLP models

	contentLower := strings.ToLower(content)

	topics := map[string][]string{
		"security":     {"hack", "security", "password", "vulnerability", "exploit"},
		"jailbreak":    {"jailbreak", "bypass", "override", "ignore", "unrestricted"},
		"roleplay":     {"roleplay", "pretend", "act as", "character", "persona"},
		"technical":    {"code", "programming", "system", "debug", "developer"},
		"emotional":    {"help", "please", "urgent", "desperate", "sad"},
		"hypothetical": {"imagine", "suppose", "what if", "hypothetically"},
	}

	for topic, keywords := range topics {
		for _, keyword := range keywords {
			if strings.Contains(contentLower, keyword) {
				return topic
			}
		}
	}

	return "general"
}

// analyzeSentiment analyzes sentiment of a message
func (c *ConversationAnalyzer) analyzeSentiment(content string) JailbreakSentimentPoint {
	// Simplified sentiment analysis
	// In a real implementation, this would use sentiment analysis models

	contentLower := strings.ToLower(content)

	positiveWords := []string{"please", "thank", "help", "good", "great", "excellent"}
	negativeWords := []string{"bad", "terrible", "hate", "angry", "frustrated", "stupid"}
	neutralWords := []string{"what", "how", "when", "where", "why"}

	positiveCount := 0
	negativeCount := 0
	neutralCount := 0

	for _, word := range positiveWords {
		if strings.Contains(contentLower, word) {
			positiveCount++
		}
	}

	for _, word := range negativeWords {
		if strings.Contains(contentLower, word) {
			negativeCount++
		}
	}

	for _, word := range neutralWords {
		if strings.Contains(contentLower, word) {
			neutralCount++
		}
	}

	var sentiment string
	var score float64
	var polarity float64

	if positiveCount > negativeCount {
		sentiment = "positive"
		score = float64(positiveCount) / float64(positiveCount+negativeCount+neutralCount)
		polarity = 1.0
	} else if negativeCount > positiveCount {
		sentiment = "negative"
		score = float64(negativeCount) / float64(positiveCount+negativeCount+neutralCount)
		polarity = -1.0
	} else {
		sentiment = "neutral"
		score = 0.5
		polarity = 0.0
	}

	return JailbreakSentimentPoint{
		Timestamp: time.Now(),
		Sentiment: sentiment,
		Score:     score,
		Polarity:  polarity,
	}
}

// detectEscalation detects escalation patterns in conversation
func (c *ConversationAnalyzer) detectEscalation(session *ConversationSession) bool {
	if len(session.Messages) < 3 {
		return false
	}

	// Look for escalation patterns in recent messages
	recentMessages := session.Messages
	if len(session.Messages) > 5 {
		recentMessages = session.Messages[len(session.Messages)-5:]
	}

	escalationKeywords := []string{
		"ignore", "override", "bypass", "jailbreak", "unrestricted",
		"please", "help", "urgent", "need", "must",
	}

	escalationCount := 0
	for _, message := range recentMessages {
		contentLower := strings.ToLower(message.Content)
		for _, keyword := range escalationKeywords {
			if strings.Contains(contentLower, keyword) {
				escalationCount++
				break
			}
		}
	}

	// Escalation detected if more than half of recent messages contain escalation keywords
	return float64(escalationCount)/float64(len(recentMessages)) > 0.5
}

// detectTopicManipulation detects topic manipulation attempts
func (c *ConversationAnalyzer) detectTopicManipulation(session *ConversationSession) bool {
	if len(session.Messages) < 3 {
		return false
	}

	// Count topic changes in recent conversation
	topicChanges := 0
	for i := 1; i < len(session.Messages); i++ {
		if session.Messages[i].Topic != session.Messages[i-1].Topic {
			topicChanges++
		}
	}

	// Topic manipulation detected if there are frequent topic changes
	changeRate := float64(topicChanges) / float64(len(session.Messages)-1)
	return changeRate > 0.6 // More than 60% of messages change topic
}

// analyzeSentimentShifts analyzes sentiment shifts in conversation
func (c *ConversationAnalyzer) analyzeSentimentShifts(session *ConversationSession) []SentimentShift {
	var shifts []SentimentShift

	if len(session.Messages) < 2 {
		return shifts
	}

	for i := 1; i < len(session.Messages); i++ {
		prevSentiment := session.Messages[i-1].Sentiment
		currSentiment := session.Messages[i].Sentiment

		if prevSentiment.Sentiment != currSentiment.Sentiment {
			magnitude := math.Abs(currSentiment.Polarity - prevSentiment.Polarity)

			shift := SentimentShift{
				FromSentiment: prevSentiment.Sentiment,
				ToSentiment:   currSentiment.Sentiment,
				Timestamp:     currSentiment.Timestamp,
				Magnitude:     magnitude,
				Suspicious:    magnitude > 1.5, // Large sentiment swings are suspicious
			}

			shifts = append(shifts, shift)
		}
	}

	return shifts
}

// detectAnomalies detects conversation anomalies
func (c *ConversationAnalyzer) detectAnomalies(session *ConversationSession) []ConversationAnomaly {
	var anomalies []ConversationAnomaly

	// Check for rapid message frequency
	if len(session.Messages) >= 2 {
		lastMessage := session.Messages[len(session.Messages)-1]
		prevMessage := session.Messages[len(session.Messages)-2]

		timeDiff := lastMessage.Timestamp.Sub(prevMessage.Timestamp)
		if timeDiff < 5*time.Second {
			anomalies = append(anomalies, ConversationAnomaly{
				Type:        "rapid_messaging",
				Description: "Unusually rapid message frequency detected",
				Timestamp:   lastMessage.Timestamp,
				Severity:    "medium",
				Evidence:    []string{fmt.Sprintf("Time between messages: %v", timeDiff)},
			})
		}
	}

	// Check for message length anomalies
	if len(session.Messages) > 0 {
		lastMessage := session.Messages[len(session.Messages)-1]
		if len(lastMessage.Content) > 2000 {
			anomalies = append(anomalies, ConversationAnomaly{
				Type:        "excessive_length",
				Description: "Unusually long message detected",
				Timestamp:   lastMessage.Timestamp,
				Severity:    "low",
				Evidence:    []string{fmt.Sprintf("Message length: %d characters", len(lastMessage.Content))},
			})
		}
	}

	return anomalies
}

// calculateConversationRiskScore calculates overall conversation risk score
func (c *ConversationAnalyzer) calculateConversationRiskScore(result *ConversationAnalysisResult) float64 {
	score := 0.0

	// Escalation factor
	if result.EscalationDetected {
		score += 3.0
	}

	// Topic manipulation factor
	if result.TopicManipulation {
		score += 2.0
	}

	// Sentiment shift factor
	for _, shift := range result.SentimentShifts {
		if shift.Suspicious {
			score += 1.0
		}
	}

	// Anomaly factor
	for _, anomaly := range result.Anomalies {
		switch anomaly.Severity {
		case "high":
			score += 2.0
		case "medium":
			score += 1.0
		case "low":
			score += 0.5
		}
	}

	// Previous attempts factor
	score += float64(result.Context.PreviousAttempts) * 0.5

	return math.Min(score, 10.0) // Cap at 10.0
}

// evictOldestSession removes the oldest session from cache
func (c *ConversationAnalyzer) evictOldestSession() {
	var oldestID string
	var oldestTime time.Time

	for id, session := range c.conversationCache {
		if oldestID == "" || session.LastActivity.Before(oldestTime) {
			oldestID = id
			oldestTime = session.LastActivity
		}
	}

	if oldestID != "" {
		delete(c.conversationCache, oldestID)
	}
}
