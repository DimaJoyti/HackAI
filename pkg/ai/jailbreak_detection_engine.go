package ai

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// JailbreakDetectionEngine provides advanced jailbreak detection capabilities
type JailbreakDetectionEngine struct {
	id                   string
	logger               *logger.Logger
	taxonomy             *JailbreakTaxonomy
	conversationAnalyzer *ConversationAnalyzer
	behavioralProfiler   *BehavioralProfiler
	config               JailbreakDetectionConfig
	detectionHistory     []JailbreakDetectionResult
	knownJailbreaks      map[string]*JailbreakPattern
	adaptiveScoring      *AdaptiveScoring
}

// JailbreakDetectionConfig configures the jailbreak detection engine
type JailbreakDetectionConfig struct {
	EnableTaxonomyDetection    bool    `json:"enable_taxonomy_detection"`
	EnableConversationAnalysis bool    `json:"enable_conversation_analysis"`
	EnableBehavioralProfiling  bool    `json:"enable_behavioral_profiling"`
	EnableAdaptiveScoring      bool    `json:"enable_adaptive_scoring"`
	SensitivityLevel           string  `json:"sensitivity_level"`
	ConfidenceThreshold        float64 `json:"confidence_threshold"`
	MaxConversationHistory     int     `json:"max_conversation_history"`
	RealTimeAnalysis           bool    `json:"real_time_analysis"`
	EnableThreatIntelligence   bool    `json:"enable_threat_intelligence"`
}

// JailbreakDetectionResult represents the result of jailbreak analysis
type JailbreakDetectionResult struct {
	ID                   string                 `json:"id"`
	Timestamp            time.Time              `json:"timestamp"`
	Input                string                 `json:"input"`
	IsJailbreak          bool                   `json:"is_jailbreak"`
	Confidence           float64                `json:"confidence"`
	JailbreakType        string                 `json:"jailbreak_type"`
	TechniqueName        string                 `json:"technique_name"`
	SeverityLevel        string                 `json:"severity_level"`
	RiskScore            float64                `json:"risk_score"`
	DetectionMethods     []string               `json:"detection_methods"`
	ConversationContext  ConversationContext    `json:"conversation_context"`
	BehavioralIndicators []BehavioralIndicator  `json:"behavioral_indicators"`
	Recommendations      []string               `json:"recommendations"`
	ThreatIntelligence   ThreatIntelligence     `json:"threat_intelligence"`
	ProcessingTime       time.Duration          `json:"processing_time"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// JailbreakPattern represents a known jailbreak pattern
type JailbreakPattern struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Type            string                 `json:"type"`
	Description     string                 `json:"description"`
	Patterns        []string               `json:"patterns"`
	Keywords        []string               `json:"keywords"`
	Severity        string                 `json:"severity"`
	SuccessRate     float64                `json:"success_rate"`
	FirstSeen       time.Time              `json:"first_seen"`
	LastSeen        time.Time              `json:"last_seen"`
	Variants        []string               `json:"variants"`
	Countermeasures []string               `json:"countermeasures"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ConversationContext provides context about the conversation
type ConversationContext struct {
	TurnNumber         int                       `json:"turn_number"`
	ConversationLength int                       `json:"conversation_length"`
	PreviousAttempts   int                       `json:"previous_attempts"`
	EscalationPattern  string                    `json:"escalation_pattern"`
	TopicShifts        []TopicShift              `json:"topic_shifts"`
	SentimentEvolution []JailbreakSentimentPoint `json:"sentiment_evolution"`
	Metadata           map[string]interface{}    `json:"metadata"`
}

// BehavioralIndicator represents behavioral patterns that may indicate jailbreak attempts
type BehavioralIndicator struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Confidence  float64                `json:"confidence"`
	Severity    string                 `json:"severity"`
	Evidence    []string               `json:"evidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatIntelligence provides threat intelligence context
type ThreatIntelligence struct {
	ThreatLevel    string    `json:"threat_level"`
	Attribution    string    `json:"attribution"`
	Campaign       string    `json:"campaign"`
	TTPs           []string  `json:"ttps"`
	IOCs           []string  `json:"iocs"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	RelatedThreats []string  `json:"related_threats"`
}

// TopicShift represents a shift in conversation topic
type TopicShift struct {
	FromTopic  string    `json:"from_topic"`
	ToTopic    string    `json:"to_topic"`
	Timestamp  time.Time `json:"timestamp"`
	Abruptness float64   `json:"abruptness"`
	Suspicious bool      `json:"suspicious"`
}

// JailbreakSentimentPoint represents sentiment at a point in conversation
type JailbreakSentimentPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Sentiment string    `json:"sentiment"`
	Score     float64   `json:"score"`
	Polarity  float64   `json:"polarity"`
}

// NewJailbreakDetectionEngine creates a new jailbreak detection engine
func NewJailbreakDetectionEngine(id string, config JailbreakDetectionConfig, logger *logger.Logger) *JailbreakDetectionEngine {
	engine := &JailbreakDetectionEngine{
		id:               id,
		logger:           logger,
		config:           config,
		detectionHistory: make([]JailbreakDetectionResult, 0),
		knownJailbreaks:  make(map[string]*JailbreakPattern),
	}

	// Initialize taxonomy
	if config.EnableTaxonomyDetection {
		engine.taxonomy = NewJailbreakTaxonomy(logger)
	}

	// Initialize conversation analyzer
	if config.EnableConversationAnalysis {
		engine.conversationAnalyzer = NewConversationAnalyzer(logger)
	}

	// Initialize behavioral profiler
	if config.EnableBehavioralProfiling {
		engine.behavioralProfiler = NewBehavioralProfiler(logger)
	}

	// Initialize adaptive scoring
	if config.EnableAdaptiveScoring {
		engine.adaptiveScoring = NewAdaptiveScoring(logger)
	}

	// Load known jailbreak patterns
	engine.loadKnownJailbreaks()

	return engine
}

// DetectJailbreak performs comprehensive jailbreak detection
func (e *JailbreakDetectionEngine) DetectJailbreak(ctx context.Context, input string, conversationHistory []string, userContext map[string]interface{}) (*JailbreakDetectionResult, error) {
	startTime := time.Now()

	result := &JailbreakDetectionResult{
		ID:                   fmt.Sprintf("jailbreak_%d", time.Now().UnixNano()),
		Timestamp:            startTime,
		Input:                input,
		DetectionMethods:     make([]string, 0),
		BehavioralIndicators: make([]BehavioralIndicator, 0),
		Recommendations:      make([]string, 0),
		Metadata:             make(map[string]interface{}),
	}

	e.logger.Debug("Starting jailbreak detection", "input_length", len(input), "detection_id", result.ID)

	// Taxonomy-based detection
	if e.config.EnableTaxonomyDetection && e.taxonomy != nil {
		taxonomyResult, err := e.taxonomy.ClassifyJailbreak(ctx, input)
		if err != nil {
			e.logger.Error("Taxonomy detection failed", "error", err)
		} else {
			result.JailbreakType = taxonomyResult.Type
			result.TechniqueName = taxonomyResult.Technique
			result.SeverityLevel = taxonomyResult.Severity
			result.DetectionMethods = append(result.DetectionMethods, "taxonomy")
		}
	}

	// Conversation analysis
	if e.config.EnableConversationAnalysis && e.conversationAnalyzer != nil {
		conversationResult, err := e.conversationAnalyzer.AnalyzeConversation(ctx, input, conversationHistory)
		if err != nil {
			e.logger.Error("Conversation analysis failed", "error", err)
		} else {
			result.ConversationContext = conversationResult.Context
			result.DetectionMethods = append(result.DetectionMethods, "conversation_analysis")
		}
	}

	// Behavioral profiling
	if e.config.EnableBehavioralProfiling && e.behavioralProfiler != nil {
		behavioralResult, err := e.behavioralProfiler.ProfileBehavior(ctx, input, userContext, e.detectionHistory)
		if err != nil {
			e.logger.Error("Behavioral profiling failed", "error", err)
		} else {
			result.BehavioralIndicators = behavioralResult.Indicators
			result.DetectionMethods = append(result.DetectionMethods, "behavioral_profiling")
		}
	}

	// Pattern matching against known jailbreaks
	patternResult := e.matchKnownPatterns(input)
	if patternResult != nil {
		result.TechniqueName = patternResult.Name
		result.JailbreakType = patternResult.Type
		result.SeverityLevel = patternResult.Severity
		result.DetectionMethods = append(result.DetectionMethods, "pattern_matching")
	}

	// Calculate overall confidence and risk score
	result.Confidence = e.calculateOverallConfidence(result)
	result.RiskScore = e.calculateRiskScore(result)
	result.IsJailbreak = result.Confidence > e.config.ConfidenceThreshold

	// Generate threat intelligence
	if e.config.EnableThreatIntelligence {
		result.ThreatIntelligence = e.generateThreatIntelligence(result)
	}

	// Generate recommendations
	result.Recommendations = e.generateRecommendations(result)

	// Record processing time
	result.ProcessingTime = time.Since(startTime)

	// Update detection history
	e.updateDetectionHistory(*result)

	// Update adaptive scoring if enabled
	if e.config.EnableAdaptiveScoring && e.adaptiveScoring != nil {
		e.adaptiveScoring.UpdateScoring(*result)
	}

	e.logger.Info("Jailbreak detection completed",
		"detection_id", result.ID,
		"is_jailbreak", result.IsJailbreak,
		"confidence", result.Confidence,
		"risk_score", result.RiskScore,
		"technique", result.TechniqueName,
		"processing_time", result.ProcessingTime)

	return result, nil
}

// matchKnownPatterns matches input against known jailbreak patterns
func (e *JailbreakDetectionEngine) matchKnownPatterns(input string) *JailbreakPattern {
	inputLower := strings.ToLower(input)

	for _, pattern := range e.knownJailbreaks {
		// Check keywords
		for _, keyword := range pattern.Keywords {
			if strings.Contains(inputLower, strings.ToLower(keyword)) {
				return pattern
			}
		}

		// Check regex patterns
		for _, regexPattern := range pattern.Patterns {
			if matched, _ := regexp.MatchString(regexPattern, inputLower); matched {
				return pattern
			}
		}
	}

	return nil
}

// calculateOverallConfidence calculates the overall confidence score
func (e *JailbreakDetectionEngine) calculateOverallConfidence(result *JailbreakDetectionResult) float64 {
	var scores []float64
	var weights []float64

	// Taxonomy confidence
	if result.JailbreakType != "" {
		scores = append(scores, e.getTaxonomyConfidence(result.JailbreakType))
		weights = append(weights, 0.4)
	}

	// Conversation analysis confidence
	if result.ConversationContext.PreviousAttempts > 0 {
		convConfidence := math.Min(float64(result.ConversationContext.PreviousAttempts)*0.2, 0.9)
		scores = append(scores, convConfidence)
		weights = append(weights, 0.3)
	}

	// Behavioral indicators confidence
	if len(result.BehavioralIndicators) > 0 {
		behavioralConfidence := e.calculateBehavioralConfidence(result.BehavioralIndicators)
		scores = append(scores, behavioralConfidence)
		weights = append(weights, 0.3)
	}

	// If no scores, return 0
	if len(scores) == 0 {
		return 0.0
	}

	// Calculate weighted average
	var weightedSum float64
	var totalWeight float64
	for i, score := range scores {
		weightedSum += score * weights[i]
		totalWeight += weights[i]
	}

	return weightedSum / totalWeight
}

// calculateRiskScore calculates the risk score
func (e *JailbreakDetectionEngine) calculateRiskScore(result *JailbreakDetectionResult) float64 {
	baseScore := result.Confidence

	// Severity multiplier
	severityMultiplier := map[string]float64{
		"critical": 1.0,
		"high":     0.8,
		"medium":   0.6,
		"low":      0.4,
	}

	if multiplier, exists := severityMultiplier[result.SeverityLevel]; exists {
		baseScore *= multiplier
	}

	// Conversation context multiplier
	if result.ConversationContext.PreviousAttempts > 2 {
		baseScore *= 1.2 // Escalation bonus
	}

	// Behavioral indicators multiplier
	if len(result.BehavioralIndicators) > 3 {
		baseScore *= 1.1 // Multiple indicators bonus
	}

	return math.Min(baseScore, 10.0) // Cap at 10.0
}

// loadKnownJailbreaks loads known jailbreak patterns
func (e *JailbreakDetectionEngine) loadKnownJailbreaks() {
	// Load known jailbreak patterns
	patterns := []*JailbreakPattern{
		{
			ID:          "dan_classic",
			Name:        "DAN (Do Anything Now)",
			Type:        "role_manipulation",
			Description: "Classic DAN jailbreak technique",
			Keywords:    []string{"dan", "do anything now", "jailbreak", "unrestricted"},
			Patterns:    []string{`(?i)dan.*do anything now`, `(?i)jailbreak.*unrestricted`},
			Severity:    "high",
			SuccessRate: 0.7,
		},
		{
			ID:          "stan_variant",
			Name:        "STAN (Strive To Avoid Norms)",
			Type:        "norm_violation",
			Description: "STAN jailbreak variant",
			Keywords:    []string{"stan", "strive to avoid norms", "avoid norms"},
			Patterns:    []string{`(?i)stan.*avoid.*norms`, `(?i)strive.*avoid.*norms`},
			Severity:    "high",
			SuccessRate: 0.6,
		},
		{
			ID:          "developer_mode",
			Name:        "Developer Mode",
			Type:        "mode_manipulation",
			Description: "Developer mode activation attempt",
			Keywords:    []string{"developer mode", "dev mode", "debug mode"},
			Patterns:    []string{`(?i)developer.*mode`, `(?i)dev.*mode`, `(?i)debug.*mode`},
			Severity:    "medium",
			SuccessRate: 0.5,
		},
		{
			ID:          "evil_confidant",
			Name:        "Evil Confidant",
			Type:        "persona_manipulation",
			Description: "Evil confidant persona jailbreak",
			Keywords:    []string{"evil confidant", "evil assistant", "dark side"},
			Patterns:    []string{`(?i)evil.*confidant`, `(?i)evil.*assistant`, `(?i)dark.*side`},
			Severity:    "high",
			SuccessRate: 0.6,
		},
	}

	for _, pattern := range patterns {
		e.knownJailbreaks[pattern.ID] = pattern
	}
}

// getTaxonomyConfidence gets confidence score for taxonomy classification
func (e *JailbreakDetectionEngine) getTaxonomyConfidence(jailbreakType string) float64 {
	// Confidence mapping for different jailbreak types
	confidenceMap := map[string]float64{
		"role_manipulation":      0.8,
		"instruction_override":   0.9,
		"context_manipulation":   0.7,
		"emotional_manipulation": 0.6,
		"hypothetical_scenarios": 0.5,
		"technical_exploitation": 0.8,
	}

	if confidence, exists := confidenceMap[jailbreakType]; exists {
		return confidence
	}
	return 0.5 // Default confidence
}

// calculateBehavioralConfidence calculates confidence from behavioral indicators
func (e *JailbreakDetectionEngine) calculateBehavioralConfidence(indicators []BehavioralIndicator) float64 {
	if len(indicators) == 0 {
		return 0.0
	}

	var totalConfidence float64
	for _, indicator := range indicators {
		totalConfidence += indicator.Confidence
	}

	return totalConfidence / float64(len(indicators))
}

// generateThreatIntelligence generates threat intelligence context
func (e *JailbreakDetectionEngine) generateThreatIntelligence(result *JailbreakDetectionResult) ThreatIntelligence {
	threatLevel := "low"
	if result.Confidence > 0.8 {
		threatLevel = "high"
	} else if result.Confidence > 0.6 {
		threatLevel = "medium"
	}

	return ThreatIntelligence{
		ThreatLevel:    threatLevel,
		Attribution:    "unknown",
		Campaign:       "",
		TTPs:           []string{result.TechniqueName},
		IOCs:           []string{},
		FirstSeen:      time.Now(),
		LastSeen:       time.Now(),
		RelatedThreats: []string{},
	}
}

// generateRecommendations generates security recommendations
func (e *JailbreakDetectionEngine) generateRecommendations(result *JailbreakDetectionResult) []string {
	var recommendations []string

	if result.IsJailbreak {
		recommendations = append(recommendations, "Block or sanitize the input")
		recommendations = append(recommendations, "Increase monitoring for this user")

		switch result.SeverityLevel {
		case "critical":
			recommendations = append(recommendations, "Implement immediate blocking")
			recommendations = append(recommendations, "Alert security team")
		case "high":
			recommendations = append(recommendations, "Apply strict filtering")
			recommendations = append(recommendations, "Log for investigation")
		case "medium":
			recommendations = append(recommendations, "Apply content filtering")
			recommendations = append(recommendations, "Monitor user behavior")
		}
	} else {
		recommendations = append(recommendations, "Continue normal processing")
	}

	return recommendations
}

// updateDetectionHistory updates the detection history
func (e *JailbreakDetectionEngine) updateDetectionHistory(result JailbreakDetectionResult) {
	e.detectionHistory = append(e.detectionHistory, result)

	// Keep only recent history
	if len(e.detectionHistory) > e.config.MaxConversationHistory {
		e.detectionHistory = e.detectionHistory[len(e.detectionHistory)-e.config.MaxConversationHistory:]
	}
}

// GetDetectionMetrics returns detection metrics
func (e *JailbreakDetectionEngine) GetDetectionMetrics() JailbreakDetectionMetrics {
	totalDetections := len(e.detectionHistory)
	jailbreakDetections := 0
	var totalConfidence float64
	var totalProcessingTime time.Duration

	for _, result := range e.detectionHistory {
		if result.IsJailbreak {
			jailbreakDetections++
		}
		totalConfidence += result.Confidence
		totalProcessingTime += result.ProcessingTime
	}

	var detectionRate float64
	var avgConfidence float64
	var avgProcessingTime time.Duration

	if totalDetections > 0 {
		detectionRate = float64(jailbreakDetections) / float64(totalDetections)
		avgConfidence = totalConfidence / float64(totalDetections)
		avgProcessingTime = totalProcessingTime / time.Duration(totalDetections)
	}

	return JailbreakDetectionMetrics{
		TotalAnalyses:         int64(totalDetections),
		DetectedJailbreaks:    int64(jailbreakDetections),
		DetectionRate:         detectionRate,
		AverageConfidence:     avgConfidence,
		AverageProcessingTime: avgProcessingTime,
		LastAnalysis:          time.Now(),
	}
}

// JailbreakDetectionMetrics represents detection metrics
type JailbreakDetectionMetrics struct {
	TotalAnalyses         int64         `json:"total_analyses"`
	DetectedJailbreaks    int64         `json:"detected_jailbreaks"`
	DetectionRate         float64       `json:"detection_rate"`
	AverageConfidence     float64       `json:"average_confidence"`
	AverageProcessingTime time.Duration `json:"average_processing_time"`
	LastAnalysis          time.Time     `json:"last_analysis"`
}

// AdaptiveScoring provides adaptive scoring capabilities
type AdaptiveScoring struct {
	logger *logger.Logger
}

// NewAdaptiveScoring creates a new adaptive scoring system
func NewAdaptiveScoring(logger *logger.Logger) *AdaptiveScoring {
	return &AdaptiveScoring{
		logger: logger,
	}
}

// UpdateScoring updates scoring based on detection results
func (a *AdaptiveScoring) UpdateScoring(result JailbreakDetectionResult) {
	// Placeholder for adaptive scoring logic
	// In a real implementation, this would use machine learning
	// to continuously improve detection accuracy
	a.logger.Debug("Adaptive scoring updated", "detection_id", result.ID, "confidence", result.Confidence)
}
