package ai

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// PromptInjectionDetector provides comprehensive prompt injection detection capabilities
type PromptInjectionDetector struct {
	id                 string
	logger             *logger.Logger
	patternDetectors   []PatternDetector
	mlDetector         *MLPromptDetector
	contextAnalyzer    *ContextAnalyzer
	config             PromptInjectionConfig
	detectionHistory   []DetectionResult
	adaptiveThresholds map[string]float64
	lastAnalysisTime   time.Time
}

// PromptInjectionConfig configures the detection engine
type PromptInjectionConfig struct {
	EnablePatternDetection bool    `json:"enable_pattern_detection"`
	EnableMLDetection      bool    `json:"enable_ml_detection"`
	EnableContextAnalysis  bool    `json:"enable_context_analysis"`
	SensitivityLevel       string  `json:"sensitivity_level"` // low, medium, high, paranoid
	BaseThreshold          float64 `json:"base_threshold"`
	AdaptiveThresholds     bool    `json:"adaptive_thresholds"`
	MaxHistorySize         int     `json:"max_history_size"`
	RealTimeAnalysis       bool    `json:"real_time_analysis"`
	EnableResponseAnalysis bool    `json:"enable_response_analysis"`
}

// DetectionResult represents the result of prompt injection analysis
type DetectionResult struct {
	ID               string                 `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	Input            string                 `json:"input"`
	IsInjection      bool                   `json:"is_injection"`
	Confidence       float64                `json:"confidence"`
	RiskLevel        string                 `json:"risk_level"`
	AttackVectors    []AttackVector         `json:"attack_vectors"`
	DetectionMethods []string               `json:"detection_methods"`
	Recommendations  []string               `json:"recommendations"`
	Context          map[string]interface{} `json:"context"`
	ProcessingTime   time.Duration          `json:"processing_time"`
}

// AttackVector represents a detected attack vector
type AttackVector struct {
	Type        string                 `json:"type"`
	Pattern     string                 `json:"pattern"`
	Confidence  float64                `json:"confidence"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Mitigation  string                 `json:"mitigation"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PatternDetector interface for different pattern detection methods
type PatternDetector interface {
	Name() string
	Detect(input string, context map[string]interface{}) ([]AttackVector, error)
	UpdatePatterns(patterns []string) error
	GetConfidence() float64
}

// NewPromptInjectionDetector creates a new prompt injection detector
func NewPromptInjectionDetector(id string, config PromptInjectionConfig, logger *logger.Logger) *PromptInjectionDetector {
	detector := &PromptInjectionDetector{
		id:                 id,
		logger:             logger,
		config:             config,
		detectionHistory:   make([]DetectionResult, 0),
		adaptiveThresholds: make(map[string]float64),
		lastAnalysisTime:   time.Now(),
	}

	// Initialize pattern detectors
	if config.EnablePatternDetection {
		detector.patternDetectors = []PatternDetector{
			NewRegexPatternDetector(),
			NewSemanticPatternDetector(),
			NewBehavioralPatternDetector(),
			NewContextManipulationDetector(),
		}
	}

	// Initialize ML detector
	if config.EnableMLDetection {
		detector.mlDetector = NewMLPromptDetector(logger)
	}

	// Initialize context analyzer
	if config.EnableContextAnalysis {
		detector.contextAnalyzer = NewContextAnalyzer(logger)
	}

	// Set adaptive thresholds
	detector.initializeAdaptiveThresholds()

	return detector
}

// AnalyzePrompt performs comprehensive prompt injection analysis
func (d *PromptInjectionDetector) AnalyzePrompt(ctx context.Context, input string, context map[string]interface{}) (*DetectionResult, error) {
	startTime := time.Now()

	result := &DetectionResult{
		ID:               fmt.Sprintf("detection_%d", time.Now().UnixNano()),
		Timestamp:        startTime,
		Input:            input,
		AttackVectors:    make([]AttackVector, 0),
		DetectionMethods: make([]string, 0),
		Recommendations:  make([]string, 0),
		Context:          context,
	}

	d.logger.Debug("Starting prompt injection analysis", "input_length", len(input), "detection_id", result.ID)

	// Pattern-based detection
	if d.config.EnablePatternDetection {
		vectors, err := d.runPatternDetection(input, context)
		if err != nil {
			d.logger.Error("Pattern detection failed", "error", err)
		} else {
			result.AttackVectors = append(result.AttackVectors, vectors...)
			result.DetectionMethods = append(result.DetectionMethods, "pattern_detection")
		}
	}

	// ML-based detection
	if d.config.EnableMLDetection && d.mlDetector != nil {
		mlResult, err := d.mlDetector.Analyze(ctx, input, context)
		if err != nil {
			d.logger.Error("ML detection failed", "error", err)
		} else {
			result.AttackVectors = append(result.AttackVectors, mlResult.Vectors...)
			result.DetectionMethods = append(result.DetectionMethods, "ml_detection")
		}
	}

	// Context analysis
	if d.config.EnableContextAnalysis && d.contextAnalyzer != nil {
		contextVectors, err := d.contextAnalyzer.Analyze(ctx, input, context, d.detectionHistory)
		if err != nil {
			d.logger.Error("Context analysis failed", "error", err)
		} else {
			result.AttackVectors = append(result.AttackVectors, contextVectors...)
			result.DetectionMethods = append(result.DetectionMethods, "context_analysis")
		}
	}

	// Calculate overall confidence and risk level
	result.Confidence = d.calculateOverallConfidence(result.AttackVectors)
	result.RiskLevel = d.calculateRiskLevel(result.Confidence, result.AttackVectors)
	result.IsInjection = result.Confidence > d.getThreshold(result.RiskLevel)

	// Generate recommendations
	result.Recommendations = d.generateRecommendations(result)

	// Record processing time
	result.ProcessingTime = time.Since(startTime)

	// Update detection history
	d.updateDetectionHistory(*result)

	// Update adaptive thresholds if enabled
	if d.config.AdaptiveThresholds {
		d.updateAdaptiveThresholds(*result)
	}

	d.logger.Info("Prompt injection analysis completed",
		"detection_id", result.ID,
		"is_injection", result.IsInjection,
		"confidence", result.Confidence,
		"risk_level", result.RiskLevel,
		"processing_time", result.ProcessingTime,
		"attack_vectors", len(result.AttackVectors))

	return result, nil
}

// runPatternDetection runs all pattern detectors
func (d *PromptInjectionDetector) runPatternDetection(input string, context map[string]interface{}) ([]AttackVector, error) {
	var allVectors []AttackVector

	for _, detector := range d.patternDetectors {
		vectors, err := detector.Detect(input, context)
		if err != nil {
			d.logger.Error("Pattern detector failed", "detector", detector.Name(), "error", err)
			continue
		}
		allVectors = append(allVectors, vectors...)
	}

	return allVectors, nil
}

// calculateOverallConfidence calculates the overall confidence score
func (d *PromptInjectionDetector) calculateOverallConfidence(vectors []AttackVector) float64 {
	if len(vectors) == 0 {
		return 0.0
	}

	// Use weighted average with severity multipliers
	var totalWeight float64
	var weightedSum float64

	severityWeights := map[string]float64{
		"critical": 1.0,
		"high":     0.8,
		"medium":   0.6,
		"low":      0.4,
	}

	for _, vector := range vectors {
		weight := severityWeights[vector.Severity]
		if weight == 0 {
			weight = 0.5 // default weight
		}

		weightedSum += vector.Confidence * weight
		totalWeight += weight
	}

	if totalWeight == 0 {
		return 0.0
	}

	confidence := weightedSum / totalWeight

	// Apply ensemble boosting for multiple detections
	if len(vectors) > 1 {
		boostFactor := 1.0 + (float64(len(vectors))-1)*0.1
		confidence = math.Min(confidence*boostFactor, 1.0)
	}

	return confidence
}

// calculateRiskLevel determines the risk level based on confidence and attack vectors
func (d *PromptInjectionDetector) calculateRiskLevel(confidence float64, vectors []AttackVector) string {
	// Check for critical severity vectors
	for _, vector := range vectors {
		if vector.Severity == "critical" && vector.Confidence > 0.7 {
			return "critical"
		}
	}

	// Base risk level on confidence
	switch {
	case confidence >= 0.9:
		return "critical"
	case confidence >= 0.7:
		return "high"
	case confidence >= 0.5:
		return "medium"
	case confidence >= 0.3:
		return "low"
	default:
		return "minimal"
	}
}

// getThreshold returns the detection threshold for a given risk level
func (d *PromptInjectionDetector) getThreshold(riskLevel string) float64 {
	if d.config.AdaptiveThresholds {
		if threshold, exists := d.adaptiveThresholds[riskLevel]; exists {
			return threshold
		}
	}

	// Base thresholds by sensitivity level
	baseThresholds := map[string]map[string]float64{
		"low": {
			"critical": 0.9,
			"high":     0.8,
			"medium":   0.7,
			"low":      0.6,
			"minimal":  0.5,
		},
		"medium": {
			"critical": 0.8,
			"high":     0.7,
			"medium":   0.6,
			"low":      0.5,
			"minimal":  0.4,
		},
		"high": {
			"critical": 0.7,
			"high":     0.6,
			"medium":   0.5,
			"low":      0.4,
			"minimal":  0.3,
		},
		"paranoid": {
			"critical": 0.6,
			"high":     0.5,
			"medium":   0.4,
			"low":      0.3,
			"minimal":  0.2,
		},
	}

	if thresholds, exists := baseThresholds[d.config.SensitivityLevel]; exists {
		if threshold, exists := thresholds[riskLevel]; exists {
			return threshold
		}
	}

	return d.config.BaseThreshold
}

// generateRecommendations generates mitigation recommendations
func (d *PromptInjectionDetector) generateRecommendations(result *DetectionResult) []string {
	var recommendations []string

	if !result.IsInjection {
		return []string{"Input appears safe - no immediate action required"}
	}

	// General recommendations
	recommendations = append(recommendations, "Block or sanitize the detected prompt injection")
	recommendations = append(recommendations, "Log the incident for security analysis")

	// Specific recommendations based on attack vectors
	vectorTypes := make(map[string]bool)
	for _, vector := range result.AttackVectors {
		vectorTypes[vector.Type] = true
		if vector.Mitigation != "" {
			recommendations = append(recommendations, vector.Mitigation)
		}
	}

	// Risk-level specific recommendations
	switch result.RiskLevel {
	case "critical":
		recommendations = append(recommendations, "URGENT: Immediately terminate session and alert security team")
		recommendations = append(recommendations, "Implement emergency response procedures")
	case "high":
		recommendations = append(recommendations, "Escalate to security team for immediate review")
		recommendations = append(recommendations, "Consider temporary access restrictions")
	case "medium":
		recommendations = append(recommendations, "Monitor user behavior closely")
		recommendations = append(recommendations, "Apply additional input validation")
	}

	return recommendations
}

// updateDetectionHistory updates the detection history
func (d *PromptInjectionDetector) updateDetectionHistory(result DetectionResult) {
	d.detectionHistory = append(d.detectionHistory, result)

	// Maintain history size limit
	if len(d.detectionHistory) > d.config.MaxHistorySize {
		d.detectionHistory = d.detectionHistory[len(d.detectionHistory)-d.config.MaxHistorySize:]
	}
}

// initializeAdaptiveThresholds initializes adaptive threshold values
func (d *PromptInjectionDetector) initializeAdaptiveThresholds() {
	riskLevels := []string{"critical", "high", "medium", "low", "minimal"}
	for _, level := range riskLevels {
		d.adaptiveThresholds[level] = d.getThreshold(level)
	}
}

// updateAdaptiveThresholds updates thresholds based on detection history
func (d *PromptInjectionDetector) updateAdaptiveThresholds(result DetectionResult) {
	// Implement adaptive threshold learning based on false positives/negatives
	// This is a simplified implementation - in production, this would use more sophisticated ML

	if len(d.detectionHistory) < 10 {
		return // Need sufficient history
	}

	// Calculate recent false positive rate
	recentResults := d.detectionHistory[len(d.detectionHistory)-10:]
	falsePositiveRate := d.calculateFalsePositiveRate(recentResults)

	// Adjust thresholds based on false positive rate
	adjustment := 0.0
	if falsePositiveRate > 0.2 { // Too many false positives
		adjustment = 0.05 // Increase threshold (less sensitive)
	} else if falsePositiveRate < 0.05 { // Very few false positives
		adjustment = -0.02 // Decrease threshold (more sensitive)
	}

	if adjustment != 0 {
		for level := range d.adaptiveThresholds {
			newThreshold := d.adaptiveThresholds[level] + adjustment
			d.adaptiveThresholds[level] = math.Max(0.1, math.Min(0.95, newThreshold))
		}

		d.logger.Info("Adaptive thresholds updated",
			"adjustment", adjustment,
			"false_positive_rate", falsePositiveRate)
	}
}

// calculateFalsePositiveRate calculates the false positive rate from recent results
func (d *PromptInjectionDetector) calculateFalsePositiveRate(results []DetectionResult) float64 {
	// This is a simplified implementation
	// In practice, you'd need feedback mechanisms to determine true vs false positives

	totalDetections := 0
	for _, result := range results {
		if result.IsInjection {
			totalDetections++
		}
	}

	if totalDetections == 0 {
		return 0.0
	}

	// Estimate false positives based on confidence distribution
	// Lower confidence detections are more likely to be false positives
	estimatedFalsePositives := 0
	for _, result := range results {
		if result.IsInjection && result.Confidence < 0.7 {
			estimatedFalsePositives++
		}
	}

	return float64(estimatedFalsePositives) / float64(totalDetections)
}

// GetMetrics returns detection metrics
func (d *PromptInjectionDetector) GetMetrics() PromptInjectionMetrics {
	totalAnalyses := len(d.detectionHistory)
	detectedInjections := 0
	avgConfidence := 0.0
	avgProcessingTime := time.Duration(0)

	for _, result := range d.detectionHistory {
		if result.IsInjection {
			detectedInjections++
		}
		avgConfidence += result.Confidence
		avgProcessingTime += result.ProcessingTime
	}

	if totalAnalyses > 0 {
		avgConfidence /= float64(totalAnalyses)
		avgProcessingTime /= time.Duration(totalAnalyses)
	}

	return PromptInjectionMetrics{
		TotalAnalyses:         int64(totalAnalyses),
		DetectedInjections:    int64(detectedInjections),
		DetectionRate:         float64(detectedInjections) / float64(totalAnalyses),
		AverageConfidence:     avgConfidence,
		AverageProcessingTime: avgProcessingTime,
		AdaptiveThresholds:    d.adaptiveThresholds,
		LastAnalysisTime:      d.lastAnalysisTime,
	}
}

// PromptInjectionMetrics contains detection metrics
type PromptInjectionMetrics struct {
	TotalAnalyses         int64              `json:"total_analyses"`
	DetectedInjections    int64              `json:"detected_injections"`
	DetectionRate         float64            `json:"detection_rate"`
	AverageConfidence     float64            `json:"average_confidence"`
	AverageProcessingTime time.Duration      `json:"average_processing_time"`
	AdaptiveThresholds    map[string]float64 `json:"adaptive_thresholds"`
	LastAnalysisTime      time.Time          `json:"last_analysis_time"`
}

// MLPromptDetector provides ML-based prompt injection detection
type MLPromptDetector struct {
	logger *logger.Logger
}

// MLDetectionResult represents ML detection results
type MLDetectionResult struct {
	Vectors []AttackVector `json:"vectors"`
	Score   float64        `json:"score"`
}

func NewMLPromptDetector(logger *logger.Logger) *MLPromptDetector {
	return &MLPromptDetector{
		logger: logger,
	}
}

func (d *MLPromptDetector) Analyze(ctx context.Context, input string, context map[string]interface{}) (*MLDetectionResult, error) {
	// Simplified ML analysis - in production this would use actual ML models
	score := d.calculateMLScore(input)

	var vectors []AttackVector
	if score > 0.6 {
		vectors = append(vectors, AttackVector{
			Type:        "ml_detection",
			Pattern:     "ml_analysis",
			Confidence:  score,
			Severity:    d.scoresToSeverity(score),
			Description: "ML model detected potential prompt injection",
			Mitigation:  "Apply ML-based filtering and validation",
			Metadata: map[string]interface{}{
				"ml_score": score,
				"model":    "prompt_injection_classifier",
			},
		})
	}

	return &MLDetectionResult{
		Vectors: vectors,
		Score:   score,
	}, nil
}

func (d *MLPromptDetector) calculateMLScore(input string) float64 {
	// Simplified scoring based on input characteristics
	score := 0.0

	// Length-based scoring
	if len(input) > 1000 {
		score += 0.2
	}

	// Keyword-based scoring
	suspiciousKeywords := []string{
		"ignore", "forget", "override", "system", "admin", "root",
		"jailbreak", "dan", "unrestricted", "bypass", "hack",
	}

	inputLower := strings.ToLower(input)
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(inputLower, keyword) {
			score += 0.15
		}
	}

	// Special character scoring
	specialChars := []string{"```", "---", "===", "###", "***"}
	for _, char := range specialChars {
		if strings.Contains(input, char) {
			score += 0.1
		}
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (d *MLPromptDetector) scoresToSeverity(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

// ContextAnalyzer analyzes conversation context for injection attempts
type ContextAnalyzer struct {
	logger *logger.Logger
}

func NewContextAnalyzer(logger *logger.Logger) *ContextAnalyzer {
	return &ContextAnalyzer{
		logger: logger,
	}
}

func (c *ContextAnalyzer) Analyze(ctx context.Context, input string, context map[string]interface{}, history []DetectionResult) ([]AttackVector, error) {
	var vectors []AttackVector

	// Analyze conversation flow
	if c.detectContextualAnomalies(input, context, history) {
		vectors = append(vectors, AttackVector{
			Type:        "contextual_anomaly",
			Pattern:     "context_flow_analysis",
			Confidence:  0.7,
			Severity:    "medium",
			Description: "Contextual anomaly detected in conversation flow",
			Mitigation:  "Review conversation context and apply additional validation",
			Metadata: map[string]interface{}{
				"analysis_type": "contextual",
				"history_size":  len(history),
			},
		})
	}

	// Check for escalation patterns
	if c.detectEscalationPattern(history) {
		vectors = append(vectors, AttackVector{
			Type:        "escalation_pattern",
			Pattern:     "escalation_analysis",
			Confidence:  0.8,
			Severity:    "high",
			Description: "Escalating injection attempts detected",
			Mitigation:  "Implement progressive restrictions and monitoring",
			Metadata: map[string]interface{}{
				"pattern_type": "escalation",
			},
		})
	}

	return vectors, nil
}

func (c *ContextAnalyzer) detectContextualAnomalies(input string, context map[string]interface{}, history []DetectionResult) bool {
	// Check for sudden topic changes
	if len(history) > 0 {
		lastResult := history[len(history)-1]
		if c.isTopicChange(lastResult.Input, input) {
			return true
		}
	}

	// Check for context inconsistencies
	if sessionID, ok := context["session_id"].(string); ok && sessionID == "" {
		return true
	}

	return false
}

func (c *ContextAnalyzer) detectEscalationPattern(history []DetectionResult) bool {
	if len(history) < 3 {
		return false
	}

	// Check last 3 results for escalating injection attempts
	recentResults := history[len(history)-3:]
	injectionCount := 0

	for _, result := range recentResults {
		if result.IsInjection {
			injectionCount++
		}
	}

	return injectionCount >= 2
}

func (c *ContextAnalyzer) isTopicChange(previous, current string) bool {
	// Simplified topic change detection
	// In production, this would use more sophisticated NLP

	prevWords := strings.Fields(strings.ToLower(previous))
	currWords := strings.Fields(strings.ToLower(current))

	if len(prevWords) == 0 || len(currWords) == 0 {
		return false
	}

	// Calculate word overlap
	overlap := 0
	for _, word := range prevWords {
		for _, currWord := range currWords {
			if word == currWord && len(word) > 3 {
				overlap++
				break
			}
		}
	}

	overlapRatio := float64(overlap) / float64(len(prevWords))
	return overlapRatio < 0.2 // Less than 20% overlap suggests topic change
}
