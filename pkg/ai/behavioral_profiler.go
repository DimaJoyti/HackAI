package ai

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// BehavioralProfiler analyzes user behavior patterns for jailbreak detection
type BehavioralProfiler struct {
	logger       *logger.Logger
	userProfiles map[string]*UserBehaviorProfile
	maxProfiles  int
}

// UserBehaviorProfile represents a user's behavioral profile
type UserBehaviorProfile struct {
	UserID              string                 `json:"user_id"`
	FirstSeen           time.Time              `json:"first_seen"`
	LastSeen            time.Time              `json:"last_seen"`
	TotalInteractions   int                    `json:"total_interactions"`
	JailbreakAttempts   int                    `json:"jailbreak_attempts"`
	SuccessfulAttempts  int                    `json:"successful_attempts"`
	AverageMessageLength float64               `json:"average_message_length"`
	CommonTopics        map[string]int         `json:"common_topics"`
	TypicalSentiment    string                 `json:"typical_sentiment"`
	BehaviorPatterns    []BehaviorPattern      `json:"behavior_patterns"`
	RiskScore           float64                `json:"risk_score"`
	TrustScore          float64                `json:"trust_score"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// BehaviorPattern represents a specific behavior pattern
type BehaviorPattern struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Frequency   int                    `json:"frequency"`
	LastSeen    time.Time              `json:"last_seen"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// BehavioralAnalysisResult represents the result of behavioral analysis
type BehavioralAnalysisResult struct {
	UserProfile    *UserBehaviorProfile  `json:"user_profile"`
	Indicators     []BehavioralIndicator `json:"indicators"`
	AnomalyScore   float64               `json:"anomaly_score"`
	RiskAssessment string                `json:"risk_assessment"`
	Recommendations []string             `json:"recommendations"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// NewBehavioralProfiler creates a new behavioral profiler
func NewBehavioralProfiler(logger *logger.Logger) *BehavioralProfiler {
	return &BehavioralProfiler{
		logger:       logger,
		userProfiles: make(map[string]*UserBehaviorProfile),
		maxProfiles:  10000,
	}
}

// ProfileBehavior analyzes user behavior for jailbreak indicators
func (b *BehavioralProfiler) ProfileBehavior(ctx context.Context, input string, userContext map[string]interface{}, detectionHistory []JailbreakDetectionResult) (*BehavioralAnalysisResult, error) {
	userID := b.extractUserID(userContext)
	profile := b.getOrCreateProfile(userID)

	// Update profile with current interaction
	b.updateProfile(profile, input, userContext)

	// Analyze current behavior
	indicators := b.analyzeBehavior(profile, input, detectionHistory)

	// Calculate anomaly score
	anomalyScore := b.calculateAnomalyScore(profile, input)

	// Assess risk
	riskAssessment := b.assessRisk(profile, anomalyScore)

	// Generate recommendations
	recommendations := b.generateRecommendations(profile, indicators)

	result := &BehavioralAnalysisResult{
		UserProfile:     profile,
		Indicators:      indicators,
		AnomalyScore:    anomalyScore,
		RiskAssessment:  riskAssessment,
		Recommendations: recommendations,
		Metadata: map[string]interface{}{
			"analysis_timestamp": time.Now(),
			"user_id":           userID,
		},
	}

	return result, nil
}

// extractUserID extracts user ID from context
func (b *BehavioralProfiler) extractUserID(userContext map[string]interface{}) string {
	if userID, exists := userContext["user_id"]; exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return "anonymous"
}

// getOrCreateProfile gets or creates a user behavior profile
func (b *BehavioralProfiler) getOrCreateProfile(userID string) *UserBehaviorProfile {
	if profile, exists := b.userProfiles[userID]; exists {
		return profile
	}

	// Create new profile
	profile := &UserBehaviorProfile{
		UserID:              userID,
		FirstSeen:           time.Now(),
		LastSeen:            time.Now(),
		TotalInteractions:   0,
		JailbreakAttempts:   0,
		SuccessfulAttempts:  0,
		AverageMessageLength: 0.0,
		CommonTopics:        make(map[string]int),
		TypicalSentiment:    "neutral",
		BehaviorPatterns:    make([]BehaviorPattern, 0),
		RiskScore:           0.0,
		TrustScore:          5.0, // Start with neutral trust
		Metadata:            make(map[string]interface{}),
	}

	// Manage profile cache size
	if len(b.userProfiles) >= b.maxProfiles {
		b.evictOldestProfile()
	}

	b.userProfiles[userID] = profile
	return profile
}

// updateProfile updates user profile with current interaction
func (b *BehavioralProfiler) updateProfile(profile *UserBehaviorProfile, input string, userContext map[string]interface{}) {
	profile.LastSeen = time.Now()
	profile.TotalInteractions++

	// Update average message length
	currentLength := float64(len(input))
	if profile.TotalInteractions == 1 {
		profile.AverageMessageLength = currentLength
	} else {
		profile.AverageMessageLength = (profile.AverageMessageLength*float64(profile.TotalInteractions-1) + currentLength) / float64(profile.TotalInteractions)
	}

	// Update common topics
	topic := b.extractTopic(input)
	profile.CommonTopics[topic]++

	// Update typical sentiment
	sentiment := b.analyzeSentiment(input)
	profile.TypicalSentiment = sentiment

	// Update behavior patterns
	b.updateBehaviorPatterns(profile, input)
}

// analyzeBehavior analyzes current behavior for indicators
func (b *BehavioralProfiler) analyzeBehavior(profile *UserBehaviorProfile, input string, detectionHistory []JailbreakDetectionResult) []BehavioralIndicator {
	var indicators []BehavioralIndicator

	// Check for repeated jailbreak attempts
	if profile.JailbreakAttempts > 3 {
		indicators = append(indicators, BehavioralIndicator{
			Type:        "repeated_attempts",
			Description: "User has made multiple jailbreak attempts",
			Confidence:  0.8,
			Severity:    "high",
			Evidence:    []string{fmt.Sprintf("Total attempts: %d", profile.JailbreakAttempts)},
		})
	}

	// Check for escalating behavior
	if b.isEscalatingBehavior(profile) {
		indicators = append(indicators, BehavioralIndicator{
			Type:        "escalating_behavior",
			Description: "User behavior is escalating in aggressiveness",
			Confidence:  0.7,
			Severity:    "medium",
			Evidence:    []string{"Increasing frequency of suspicious patterns"},
		})
	}

	// Check for unusual message patterns
	if b.hasUnusualMessagePatterns(profile, input) {
		indicators = append(indicators, BehavioralIndicator{
			Type:        "unusual_patterns",
			Description: "Unusual message patterns detected",
			Confidence:  0.6,
			Severity:    "medium",
			Evidence:    []string{"Deviation from typical behavior"},
		})
	}

	// Check for social engineering indicators
	if b.hasSocialEngineeringIndicators(input) {
		indicators = append(indicators, BehavioralIndicator{
			Type:        "social_engineering",
			Description: "Potential social engineering attempt",
			Confidence:  0.7,
			Severity:    "high",
			Evidence:    []string{"Emotional manipulation patterns detected"},
		})
	}

	// Check for technical exploitation indicators
	if b.hasTechnicalExploitationIndicators(input) {
		indicators = append(indicators, BehavioralIndicator{
			Type:        "technical_exploitation",
			Description: "Technical exploitation attempt detected",
			Confidence:  0.8,
			Severity:    "high",
			Evidence:    []string{"Technical bypass patterns detected"},
		})
	}

	return indicators
}

// extractTopic extracts topic from input (simplified)
func (b *BehavioralProfiler) extractTopic(input string) string {
	inputLower := strings.ToLower(input)
	
	topics := map[string][]string{
		"security":    {"hack", "security", "password", "vulnerability"},
		"jailbreak":   {"jailbreak", "bypass", "override", "ignore"},
		"roleplay":    {"roleplay", "pretend", "act as", "character"},
		"technical":   {"code", "programming", "system", "debug"},
		"emotional":   {"help", "please", "urgent", "desperate"},
	}

	for topic, keywords := range topics {
		for _, keyword := range keywords {
			if strings.Contains(inputLower, keyword) {
				return topic
			}
		}
	}

	return "general"
}

// analyzeSentiment analyzes sentiment (simplified)
func (b *BehavioralProfiler) analyzeSentiment(input string) string {
	inputLower := strings.ToLower(input)
	
	positiveWords := []string{"please", "thank", "help", "good", "great"}
	negativeWords := []string{"bad", "terrible", "hate", "angry", "frustrated"}

	positiveCount := 0
	negativeCount := 0

	for _, word := range positiveWords {
		if strings.Contains(inputLower, word) {
			positiveCount++
		}
	}

	for _, word := range negativeWords {
		if strings.Contains(inputLower, word) {
			negativeCount++
		}
	}

	if positiveCount > negativeCount {
		return "positive"
	} else if negativeCount > positiveCount {
		return "negative"
	}
	return "neutral"
}

// updateBehaviorPatterns updates behavior patterns
func (b *BehavioralProfiler) updateBehaviorPatterns(profile *UserBehaviorProfile, input string) {
	patterns := b.detectPatterns(input)
	
	for _, newPattern := range patterns {
		found := false
		for i, existingPattern := range profile.BehaviorPatterns {
			if existingPattern.Type == newPattern.Type {
				profile.BehaviorPatterns[i].Frequency++
				profile.BehaviorPatterns[i].LastSeen = time.Now()
				found = true
				break
			}
		}
		
		if !found {
			profile.BehaviorPatterns = append(profile.BehaviorPatterns, newPattern)
		}
	}
}

// detectPatterns detects behavior patterns in input
func (b *BehavioralProfiler) detectPatterns(input string) []BehaviorPattern {
	var patterns []BehaviorPattern
	inputLower := strings.ToLower(input)

	// Pattern detection logic
	patternChecks := map[string][]string{
		"instruction_override": {"ignore", "forget", "override", "disregard"},
		"role_manipulation":    {"pretend", "act as", "roleplay", "character"},
		"emotional_appeal":     {"please", "help", "urgent", "desperate"},
		"technical_bypass":     {"bypass", "hack", "exploit", "vulnerability"},
	}

	for patternType, keywords := range patternChecks {
		for _, keyword := range keywords {
			if strings.Contains(inputLower, keyword) {
				patterns = append(patterns, BehaviorPattern{
					Type:        patternType,
					Description: fmt.Sprintf("Pattern detected: %s", patternType),
					Frequency:   1,
					LastSeen:    time.Now(),
					Confidence:  0.7,
				})
				break
			}
		}
	}

	return patterns
}

// isEscalatingBehavior checks if behavior is escalating
func (b *BehavioralProfiler) isEscalatingBehavior(profile *UserBehaviorProfile) bool {
	// Check if jailbreak attempts are increasing
	if profile.JailbreakAttempts > 2 && profile.TotalInteractions > 5 {
		attemptRate := float64(profile.JailbreakAttempts) / float64(profile.TotalInteractions)
		return attemptRate > 0.3 // More than 30% of interactions are jailbreak attempts
	}
	return false
}

// hasUnusualMessagePatterns checks for unusual message patterns
func (b *BehavioralProfiler) hasUnusualMessagePatterns(profile *UserBehaviorProfile, input string) bool {
	currentLength := float64(len(input))
	
	// Check if message length is significantly different from average
	if profile.TotalInteractions > 3 {
		lengthDiff := math.Abs(currentLength - profile.AverageMessageLength)
		return lengthDiff > profile.AverageMessageLength*0.5 // 50% deviation
	}
	
	return false
}

// hasSocialEngineeringIndicators checks for social engineering indicators
func (b *BehavioralProfiler) hasSocialEngineeringIndicators(input string) bool {
	inputLower := strings.ToLower(input)
	
	socialEngineering := []string{
		"please help", "urgent", "desperate", "need your help",
		"trust me", "between us", "secret", "don't tell",
	}

	for _, indicator := range socialEngineering {
		if strings.Contains(inputLower, indicator) {
			return true
		}
	}
	
	return false
}

// hasTechnicalExploitationIndicators checks for technical exploitation indicators
func (b *BehavioralProfiler) hasTechnicalExploitationIndicators(input string) bool {
	inputLower := strings.ToLower(input)
	
	technicalExploitation := []string{
		"system", "debug", "admin", "root", "sudo",
		"execute", "run", "command", "script",
		"bypass", "override", "exploit",
	}

	count := 0
	for _, indicator := range technicalExploitation {
		if strings.Contains(inputLower, indicator) {
			count++
		}
	}
	
	return count >= 2 // Multiple technical indicators
}

// calculateAnomalyScore calculates anomaly score
func (b *BehavioralProfiler) calculateAnomalyScore(profile *UserBehaviorProfile, input string) float64 {
	score := 0.0

	// Factor in jailbreak attempt rate
	if profile.TotalInteractions > 0 {
		attemptRate := float64(profile.JailbreakAttempts) / float64(profile.TotalInteractions)
		score += attemptRate * 3.0
	}

	// Factor in message length anomaly
	if profile.TotalInteractions > 3 {
		currentLength := float64(len(input))
		lengthDiff := math.Abs(currentLength - profile.AverageMessageLength)
		if lengthDiff > profile.AverageMessageLength*0.5 {
			score += 1.0
		}
	}

	// Factor in behavior patterns
	suspiciousPatterns := 0
	for _, pattern := range profile.BehaviorPatterns {
		if pattern.Type == "instruction_override" || pattern.Type == "technical_bypass" {
			suspiciousPatterns++
		}
	}
	score += float64(suspiciousPatterns) * 0.5

	return math.Min(score, 10.0) // Cap at 10.0
}

// assessRisk assesses overall risk level
func (b *BehavioralProfiler) assessRisk(profile *UserBehaviorProfile, anomalyScore float64) string {
	if anomalyScore >= 7.0 || profile.JailbreakAttempts >= 5 {
		return "critical"
	} else if anomalyScore >= 5.0 || profile.JailbreakAttempts >= 3 {
		return "high"
	} else if anomalyScore >= 3.0 || profile.JailbreakAttempts >= 1 {
		return "medium"
	}
	return "low"
}

// generateRecommendations generates recommendations based on analysis
func (b *BehavioralProfiler) generateRecommendations(profile *UserBehaviorProfile, indicators []BehavioralIndicator) []string {
	var recommendations []string

	if profile.JailbreakAttempts > 3 {
		recommendations = append(recommendations, "Consider implementing rate limiting for this user")
		recommendations = append(recommendations, "Increase monitoring and logging for this user")
	}

	for _, indicator := range indicators {
		switch indicator.Type {
		case "repeated_attempts":
			recommendations = append(recommendations, "Implement progressive penalties for repeated attempts")
		case "social_engineering":
			recommendations = append(recommendations, "Apply additional validation for emotional appeals")
		case "technical_exploitation":
			recommendations = append(recommendations, "Enhance technical input validation and sanitization")
		}
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Continue normal monitoring")
	}

	return recommendations
}

// evictOldestProfile removes the oldest profile from cache
func (b *BehavioralProfiler) evictOldestProfile() {
	var oldestID string
	var oldestTime time.Time

	for id, profile := range b.userProfiles {
		if oldestID == "" || profile.LastSeen.Before(oldestTime) {
			oldestID = id
			oldestTime = profile.LastSeen
		}
	}

	if oldestID != "" {
		delete(b.userProfiles, oldestID)
	}
}
