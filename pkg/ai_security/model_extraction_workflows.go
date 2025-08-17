package ai_security

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var modelExtractionTracer = otel.Tracer("hackai/ai_security/model_extraction")

// ModelExtractionDetector detects various model extraction attack patterns
type ModelExtractionDetector struct {
	extractionPatterns []ExtractionPattern
	behaviorAnalyzer   *ExtractionBehaviorAnalyzer
	queryAnalyzer      *QueryPatternAnalyzer
	responseAnalyzer   *ResponseAnalysisEngine
	logger             *logger.Logger
	config             ModelExtractionConfig
}

// ModelExtractionConfig provides configuration for model extraction detection
type ModelExtractionConfig struct {
	EnableBehaviorAnalysis    bool    `json:"enable_behavior_analysis"`
	EnableQueryAnalysis       bool    `json:"enable_query_analysis"`
	EnableResponseAnalysis    bool    `json:"enable_response_analysis"`
	MinConfidenceThreshold    float64 `json:"min_confidence_threshold"`
	MaxQueryRate              int     `json:"max_query_rate"`
	SuspiciousPatternWindow   int     `json:"suspicious_pattern_window"`
	EnableStatisticalAnalysis bool    `json:"enable_statistical_analysis"`
	EnableSemanticAnalysis    bool    `json:"enable_semantic_analysis"`
}

// ExtractionPattern represents a model extraction attack pattern
type ExtractionPattern struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Pattern     *regexp.Regexp         `json:"-"`
	PatternText string                 `json:"pattern"`
	Category    ExtractionCategory     `json:"category"`
	Severity    ThreatLevel            `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Description string                 `json:"description"`
	Examples    []string               `json:"examples"`
	Indicators  []string               `json:"indicators"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ExtractionCategory represents different categories of model extraction
type ExtractionCategory string

const (
	CategoryParameterExtraction ExtractionCategory = "parameter_extraction"
	CategoryTrainingDataLeak    ExtractionCategory = "training_data_leak"
	CategoryModelInversion      ExtractionCategory = "model_inversion"
	CategoryArchitectureProbing ExtractionCategory = "architecture_probing"
	CategoryKnowledgeExtraction ExtractionCategory = "knowledge_extraction"
	CategoryBehaviorMimicking   ExtractionCategory = "behavior_mimicking"
	CategoryAPIAbuse            ExtractionCategory = "api_abuse"
	CategoryStatisticalAttack   ExtractionCategory = "statistical_attack"
)

// ExtractionBehaviorAnalyzer analyzes user behavior for extraction patterns
type ExtractionBehaviorAnalyzer struct {
	userSessions   map[string]*UserSession
	queryHistory   []QueryRecord
	maxHistorySize int
	logger         *logger.Logger
}

// QueryPatternAnalyzer analyzes query patterns for extraction attempts
type QueryPatternAnalyzer struct {
	patternDetectors map[string]PatternDetector
	statisticalTests []StatisticalTest
	logger           *logger.Logger
}

// ResponseAnalysisEngine analyzes responses for potential information leakage
type ResponseAnalysisEngine struct {
	leakageDetectors []LeakageDetector
	sensitivityRules []SensitivityRule
	logger           *logger.Logger
}

// UserSession tracks user behavior across multiple queries
type UserSession struct {
	UserID          string                 `json:"user_id"`
	SessionID       string                 `json:"session_id"`
	StartTime       time.Time              `json:"start_time"`
	LastActivity    time.Time              `json:"last_activity"`
	QueryCount      int                    `json:"query_count"`
	SuspiciousScore float64                `json:"suspicious_score"`
	QueryPatterns   []string               `json:"query_patterns"`
	ExtractionFlags []string               `json:"extraction_flags"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// QueryRecord represents a single query for analysis
type QueryRecord struct {
	QueryID    string                 `json:"query_id"`
	UserID     string                 `json:"user_id"`
	SessionID  string                 `json:"session_id"`
	Query      string                 `json:"query"`
	Response   string                 `json:"response"`
	Timestamp  time.Time              `json:"timestamp"`
	Confidence float64                `json:"confidence"`
	Patterns   []string               `json:"patterns"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// PatternDetector interface for detecting specific extraction patterns
type PatternDetector interface {
	Detect(query string) (bool, float64, []string)
	GetName() string
	GetCategory() ExtractionCategory
}

// StatisticalTest represents a statistical test for extraction detection
type StatisticalTest struct {
	Name        string                              `json:"name"`
	TestFunc    func([]QueryRecord) (bool, float64) `json:"-"`
	Threshold   float64                             `json:"threshold"`
	Description string                              `json:"description"`
	Metadata    map[string]interface{}              `json:"metadata"`
}

// LeakageDetector detects information leakage in responses
type LeakageDetector interface {
	DetectLeakage(response string, context SecurityContext) (bool, float64, []string)
	GetName() string
	GetSensitivity() float64
}

// SensitivityRule defines rules for sensitive information detection
type SensitivityRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Pattern     *regexp.Regexp         `json:"-"`
	PatternText string                 `json:"pattern"`
	Sensitivity float64                `json:"sensitivity"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ModelExtractionResult represents the result of extraction analysis
type ModelExtractionResult struct {
	Detected         bool                   `json:"detected"`
	Confidence       float64                `json:"confidence"`
	Category         ExtractionCategory     `json:"category"`
	Severity         ThreatLevel            `json:"severity"`
	Patterns         []ExtractionPattern    `json:"patterns"`
	BehaviorAnalysis *BehaviorAnalysis      `json:"behavior_analysis,omitempty"`
	QueryAnalysis    *QueryAnalysis         `json:"query_analysis,omitempty"`
	ResponseAnalysis *ResponseAnalysis      `json:"response_analysis,omitempty"`
	Indicators       []string               `json:"indicators"`
	Recommendations  []string               `json:"recommendations"`
	RiskScore        float64                `json:"risk_score"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// BehaviorAnalysis represents behavioral analysis results
type BehaviorAnalysis struct {
	SuspiciousScore  float64  `json:"suspicious_score"`
	QueryFrequency   float64  `json:"query_frequency"`
	PatternDiversity float64  `json:"pattern_diversity"`
	SessionAnomalies []string `json:"session_anomalies"`
	BehaviorFlags    []string `json:"behavior_flags"`
	RiskFactors      []string `json:"risk_factors"`
}

// QueryAnalysis represents query pattern analysis results
type QueryAnalysis struct {
	PatternMatches       []string `json:"pattern_matches"`
	StatisticalFlags     []string `json:"statistical_flags"`
	SemanticSimilarity   float64  `json:"semantic_similarity"`
	QueryComplexity      float64  `json:"query_complexity"`
	ExtractionIndicators []string `json:"extraction_indicators"`
}

// ResponseAnalysis represents response analysis results
type ResponseAnalysis struct {
	LeakageDetected    bool     `json:"leakage_detected"`
	SensitiveContent   []string `json:"sensitive_content"`
	InformationEntropy float64  `json:"information_entropy"`
	LeakageRisk        float64  `json:"leakage_risk"`
	SensitivityScore   float64  `json:"sensitivity_score"`
}

// NewModelExtractionDetector creates a new model extraction detector
func NewModelExtractionDetector(config ModelExtractionConfig, logger *logger.Logger) *ModelExtractionDetector {
	detector := &ModelExtractionDetector{
		extractionPatterns: initializeExtractionPatterns(),
		behaviorAnalyzer:   NewExtractionBehaviorAnalyzer(1000, logger),
		queryAnalyzer:      NewQueryPatternAnalyzer(logger),
		responseAnalyzer:   NewResponseAnalysisEngine(logger),
		logger:             logger,
		config:             config,
	}

	return detector
}

// NewExtractionBehaviorAnalyzer creates a new behavior analyzer
func NewExtractionBehaviorAnalyzer(maxHistorySize int, logger *logger.Logger) *ExtractionBehaviorAnalyzer {
	return &ExtractionBehaviorAnalyzer{
		userSessions:   make(map[string]*UserSession),
		queryHistory:   make([]QueryRecord, 0),
		maxHistorySize: maxHistorySize,
		logger:         logger,
	}
}

// NewQueryPatternAnalyzer creates a new query pattern analyzer
func NewQueryPatternAnalyzer(logger *logger.Logger) *QueryPatternAnalyzer {
	return &QueryPatternAnalyzer{
		patternDetectors: initializePatternDetectors(),
		statisticalTests: initializeStatisticalTests(),
		logger:           logger,
	}
}

// NewResponseAnalysisEngine creates a new response analysis engine
func NewResponseAnalysisEngine(logger *logger.Logger) *ResponseAnalysisEngine {
	return &ResponseAnalysisEngine{
		leakageDetectors: initializeLeakageDetectors(),
		sensitivityRules: initializeSensitivityRules(),
		logger:           logger,
	}
}

// DetectModelExtraction performs comprehensive model extraction detection
func (d *ModelExtractionDetector) DetectModelExtraction(ctx context.Context, query string, response string, secCtx SecurityContext) (ModelExtractionResult, error) {
	ctx, span := modelExtractionTracer.Start(ctx, "model_extraction.detect",
		trace.WithAttributes(
			attribute.String("query.length", fmt.Sprintf("%d", len(query))),
			attribute.String("response.length", fmt.Sprintf("%d", len(response))),
			attribute.String("user.id", secCtx.UserID),
		),
	)
	defer span.End()

	result := ModelExtractionResult{
		Detected:        false,
		Confidence:      0.0,
		Patterns:        []ExtractionPattern{},
		Indicators:      []string{},
		Recommendations: []string{},
		RiskScore:       0.0,
		Metadata:        make(map[string]interface{}),
	}

	// Step 1: Pattern-based detection
	patternResults := d.detectPatterns(query)
	result.Patterns = patternResults

	// Step 2: Behavior analysis
	if d.config.EnableBehaviorAnalysis {
		behaviorAnalysis := d.analyzeBehavior(ctx, query, secCtx)
		result.BehaviorAnalysis = behaviorAnalysis
	}

	// Step 3: Query pattern analysis
	if d.config.EnableQueryAnalysis {
		queryAnalysis := d.analyzeQueryPatterns(ctx, query, secCtx)
		result.QueryAnalysis = queryAnalysis
	}

	// Step 4: Response analysis
	if d.config.EnableResponseAnalysis && response != "" {
		responseAnalysis := d.analyzeResponse(ctx, response, secCtx)
		result.ResponseAnalysis = responseAnalysis
	}

	// Step 5: Statistical analysis
	if d.config.EnableStatisticalAnalysis {
		statisticalScore := d.performStatisticalAnalysis(query, secCtx)
		result.Metadata["statistical_score"] = statisticalScore
	}

	// Step 6: Semantic analysis
	if d.config.EnableSemanticAnalysis {
		semanticScore := d.performSemanticAnalysis(query)
		result.Metadata["semantic_score"] = semanticScore
	}

	// Calculate overall confidence and risk score
	result.Confidence = d.calculateOverallConfidence(result)
	result.RiskScore = d.calculateRiskScore(result)
	result.Detected = result.Confidence >= d.config.MinConfidenceThreshold

	if result.Detected {
		result.Category = d.determineCategory(result)
		result.Severity = d.determineSeverity(result)
		result.Indicators = d.extractIndicators(result)
		result.Recommendations = d.generateRecommendations(result)
	}

	span.SetAttributes(
		attribute.Bool("extraction.detected", result.Detected),
		attribute.Float64("extraction.confidence", result.Confidence),
		attribute.Float64("extraction.risk_score", result.RiskScore),
		attribute.String("extraction.category", string(result.Category)),
		attribute.String("extraction.severity", result.Severity.String()),
		attribute.Int("patterns.matched", len(result.Patterns)),
	)

	d.logger.Debug("Model extraction analysis completed",
		"detected", result.Detected,
		"confidence", result.Confidence,
		"risk_score", result.RiskScore,
		"category", string(result.Category),
		"patterns_matched", len(result.Patterns),
	)

	return result, nil
}

// detectPatterns detects extraction patterns in the query
func (d *ModelExtractionDetector) detectPatterns(query string) []ExtractionPattern {
	var matchedPatterns []ExtractionPattern
	queryLower := strings.ToLower(query)

	for _, pattern := range d.extractionPatterns {
		if pattern.Pattern.MatchString(queryLower) {
			matchedPatterns = append(matchedPatterns, pattern)
		}
	}

	return matchedPatterns
}

// analyzeBehavior analyzes user behavior for extraction patterns
func (d *ModelExtractionDetector) analyzeBehavior(ctx context.Context, query string, secCtx SecurityContext) *BehaviorAnalysis {
	// Update user session
	session := d.behaviorAnalyzer.updateUserSession(secCtx.UserID, secCtx.SessionID, query)

	// Analyze behavior patterns
	suspiciousScore := d.behaviorAnalyzer.calculateSuspiciousScore(session)
	queryFrequency := d.behaviorAnalyzer.calculateQueryFrequency(session)
	patternDiversity := d.behaviorAnalyzer.calculatePatternDiversity(session)

	// Detect anomalies
	anomalies := d.behaviorAnalyzer.detectAnomalies(session)
	behaviorFlags := d.behaviorAnalyzer.identifyBehaviorFlags(session)
	riskFactors := d.behaviorAnalyzer.assessRiskFactors(session)

	return &BehaviorAnalysis{
		SuspiciousScore:  suspiciousScore,
		QueryFrequency:   queryFrequency,
		PatternDiversity: patternDiversity,
		SessionAnomalies: anomalies,
		BehaviorFlags:    behaviorFlags,
		RiskFactors:      riskFactors,
	}
}

// analyzeQueryPatterns analyzes query patterns for extraction attempts
func (d *ModelExtractionDetector) analyzeQueryPatterns(ctx context.Context, query string, secCtx SecurityContext) *QueryAnalysis {
	var patternMatches []string
	var statisticalFlags []string
	var extractionIndicators []string

	// Run pattern detectors
	for name, detector := range d.queryAnalyzer.patternDetectors {
		if detected, _, indicators := detector.Detect(query); detected {
			patternMatches = append(patternMatches, name)
			extractionIndicators = append(extractionIndicators, indicators...)
		}
	}

	// Run statistical tests
	queryRecord := QueryRecord{
		QueryID:   fmt.Sprintf("query_%d", time.Now().UnixNano()),
		UserID:    secCtx.UserID,
		SessionID: secCtx.SessionID,
		Query:     query,
		Timestamp: time.Now(),
	}

	d.queryAnalyzer.addQueryRecord(queryRecord)

	for _, test := range d.queryAnalyzer.statisticalTests {
		if detected, _ := test.TestFunc(d.queryAnalyzer.getRecentQueries(secCtx.UserID, 10)); detected {
			statisticalFlags = append(statisticalFlags, test.Name)
		}
	}

	// Calculate semantic similarity and complexity
	semanticSimilarity := d.calculateSemanticSimilarity(query)
	queryComplexity := d.calculateQueryComplexity(query)

	return &QueryAnalysis{
		PatternMatches:       patternMatches,
		StatisticalFlags:     statisticalFlags,
		SemanticSimilarity:   semanticSimilarity,
		QueryComplexity:      queryComplexity,
		ExtractionIndicators: extractionIndicators,
	}
}

// analyzeResponse analyzes response for potential information leakage
func (d *ModelExtractionDetector) analyzeResponse(ctx context.Context, response string, secCtx SecurityContext) *ResponseAnalysis {
	var sensitiveContent []string
	leakageDetected := false
	leakageRisk := 0.0
	sensitivityScore := 0.0

	// Run leakage detectors
	for _, detector := range d.responseAnalyzer.leakageDetectors {
		if detected, risk, content := detector.DetectLeakage(response, secCtx); detected {
			leakageDetected = true
			leakageRisk = math.Max(leakageRisk, risk)
			sensitiveContent = append(sensitiveContent, content...)
		}
	}

	// Check sensitivity rules
	for _, rule := range d.responseAnalyzer.sensitivityRules {
		if rule.Pattern.MatchString(response) {
			sensitivityScore = math.Max(sensitivityScore, rule.Sensitivity)
			sensitiveContent = append(sensitiveContent, rule.Name)
		}
	}

	// Calculate information entropy
	informationEntropy := d.calculateInformationEntropy(response)

	return &ResponseAnalysis{
		LeakageDetected:    leakageDetected,
		SensitiveContent:   sensitiveContent,
		InformationEntropy: informationEntropy,
		LeakageRisk:        leakageRisk,
		SensitivityScore:   sensitivityScore,
	}
}

// Helper methods for behavior analysis

// updateUserSession updates or creates a user session
func (ba *ExtractionBehaviorAnalyzer) updateUserSession(userID, sessionID, query string) *UserSession {
	sessionKey := fmt.Sprintf("%s_%s", userID, sessionID)

	session, exists := ba.userSessions[sessionKey]
	if !exists {
		session = &UserSession{
			UserID:          userID,
			SessionID:       sessionID,
			StartTime:       time.Now(),
			LastActivity:    time.Now(),
			QueryCount:      0,
			SuspiciousScore: 0.0,
			QueryPatterns:   []string{},
			ExtractionFlags: []string{},
			Metadata:        make(map[string]interface{}),
		}
		ba.userSessions[sessionKey] = session
	}

	session.LastActivity = time.Now()
	session.QueryCount++
	session.QueryPatterns = append(session.QueryPatterns, query)

	// Maintain pattern history limit
	if len(session.QueryPatterns) > 50 {
		session.QueryPatterns = session.QueryPatterns[1:]
	}

	return session
}

// calculateSuspiciousScore calculates a suspicious behavior score
func (ba *ExtractionBehaviorAnalyzer) calculateSuspiciousScore(session *UserSession) float64 {
	score := 0.0

	// High query frequency
	duration := time.Since(session.StartTime).Minutes()
	if duration > 0 {
		queryRate := float64(session.QueryCount) / duration
		if queryRate > 10 { // More than 10 queries per minute
			score += 0.3
		}
	}

	// Repetitive patterns
	if len(session.QueryPatterns) > 5 {
		repetitiveScore := ba.calculateRepetitiveness(session.QueryPatterns)
		score += repetitiveScore * 0.2
	}

	// Extraction flags
	score += float64(len(session.ExtractionFlags)) * 0.1

	return math.Min(score, 1.0)
}

// calculateQueryFrequency calculates query frequency
func (ba *ExtractionBehaviorAnalyzer) calculateQueryFrequency(session *UserSession) float64 {
	duration := time.Since(session.StartTime).Minutes()
	if duration == 0 {
		return 0.0
	}
	return float64(session.QueryCount) / duration
}

// calculatePatternDiversity calculates pattern diversity
func (ba *ExtractionBehaviorAnalyzer) calculatePatternDiversity(session *UserSession) float64 {
	if len(session.QueryPatterns) == 0 {
		return 0.0
	}

	uniquePatterns := make(map[string]bool)
	for _, pattern := range session.QueryPatterns {
		// Simple pattern classification
		patternType := ba.classifyQueryPattern(pattern)
		uniquePatterns[patternType] = true
	}

	return float64(len(uniquePatterns)) / float64(len(session.QueryPatterns))
}

// detectAnomalies detects behavioral anomalies
func (ba *ExtractionBehaviorAnalyzer) detectAnomalies(session *UserSession) []string {
	var anomalies []string

	// Rapid query succession
	if session.QueryCount > 20 && time.Since(session.StartTime).Minutes() < 5 {
		anomalies = append(anomalies, "rapid_query_succession")
	}

	// Unusual query patterns
	if len(session.QueryPatterns) > 10 {
		if ba.detectUnusualPatterns(session.QueryPatterns) {
			anomalies = append(anomalies, "unusual_query_patterns")
		}
	}

	// Long session duration with high activity
	if time.Since(session.StartTime).Hours() > 2 && session.QueryCount > 100 {
		anomalies = append(anomalies, "extended_high_activity")
	}

	return anomalies
}

// identifyBehaviorFlags identifies specific behavior flags
func (ba *ExtractionBehaviorAnalyzer) identifyBehaviorFlags(session *UserSession) []string {
	var flags []string

	// Check for systematic probing
	if ba.detectSystematicProbing(session.QueryPatterns) {
		flags = append(flags, "systematic_probing")
	}

	// Check for parameter fishing
	if ba.detectParameterFishing(session.QueryPatterns) {
		flags = append(flags, "parameter_fishing")
	}

	// Check for knowledge extraction
	if ba.detectKnowledgeExtraction(session.QueryPatterns) {
		flags = append(flags, "knowledge_extraction")
	}

	return flags
}

// assessRiskFactors assesses risk factors
func (ba *ExtractionBehaviorAnalyzer) assessRiskFactors(session *UserSession) []string {
	var riskFactors []string

	if session.QueryCount > 50 {
		riskFactors = append(riskFactors, "high_query_volume")
	}

	if session.SuspiciousScore > 0.7 {
		riskFactors = append(riskFactors, "high_suspicious_score")
	}

	if len(session.ExtractionFlags) > 3 {
		riskFactors = append(riskFactors, "multiple_extraction_flags")
	}

	return riskFactors
}

// Helper methods for query analysis

// addQueryRecord adds a query record to history
func (qa *QueryPatternAnalyzer) addQueryRecord(record QueryRecord) {
	qa.logger.Debug("Adding query record", "query_id", record.QueryID)
	// In a real implementation, this would store in a database or cache
}

// getRecentQueries gets recent queries for a user
func (qa *QueryPatternAnalyzer) getRecentQueries(userID string, limit int) []QueryRecord {
	// In a real implementation, this would fetch from storage
	return []QueryRecord{}
}

// Helper calculation methods

// calculateRepetitiveness calculates how repetitive the query patterns are
func (ba *ExtractionBehaviorAnalyzer) calculateRepetitiveness(patterns []string) float64 {
	if len(patterns) < 2 {
		return 0.0
	}

	// Simple repetitiveness calculation
	uniquePatterns := make(map[string]int)
	for _, pattern := range patterns {
		uniquePatterns[pattern]++
	}

	maxCount := 0
	for _, count := range uniquePatterns {
		if count > maxCount {
			maxCount = count
		}
	}

	return float64(maxCount) / float64(len(patterns))
}

// classifyQueryPattern classifies a query pattern
func (ba *ExtractionBehaviorAnalyzer) classifyQueryPattern(query string) string {
	queryLower := strings.ToLower(query)

	if strings.Contains(queryLower, "parameter") || strings.Contains(queryLower, "weight") {
		return "parameter_query"
	}
	if strings.Contains(queryLower, "training") || strings.Contains(queryLower, "dataset") {
		return "training_query"
	}
	if strings.Contains(queryLower, "architecture") || strings.Contains(queryLower, "model") {
		return "architecture_query"
	}

	return "general_query"
}

// detectUnusualPatterns detects unusual query patterns
func (ba *ExtractionBehaviorAnalyzer) detectUnusualPatterns(patterns []string) bool {
	// Simple implementation - check for too many similar patterns
	patternCounts := make(map[string]int)
	for _, pattern := range patterns {
		patternType := ba.classifyQueryPattern(pattern)
		patternCounts[patternType]++
	}

	// If more than 70% of queries are of the same type, it's unusual
	for _, count := range patternCounts {
		if float64(count)/float64(len(patterns)) > 0.7 {
			return true
		}
	}

	return false
}

// detectSystematicProbing detects systematic probing behavior
func (ba *ExtractionBehaviorAnalyzer) detectSystematicProbing(patterns []string) bool {
	// Look for systematic exploration patterns
	architectureQueries := 0
	parameterQueries := 0

	for _, pattern := range patterns {
		queryLower := strings.ToLower(pattern)
		if strings.Contains(queryLower, "architecture") || strings.Contains(queryLower, "layer") {
			architectureQueries++
		}
		if strings.Contains(queryLower, "parameter") || strings.Contains(queryLower, "weight") {
			parameterQueries++
		}
	}

	return architectureQueries > 3 && parameterQueries > 3
}

// detectParameterFishing detects parameter fishing attempts
func (ba *ExtractionBehaviorAnalyzer) detectParameterFishing(patterns []string) bool {
	parameterKeywords := []string{"weight", "parameter", "coefficient", "bias", "gradient"}

	parameterCount := 0
	for _, pattern := range patterns {
		queryLower := strings.ToLower(pattern)
		for _, keyword := range parameterKeywords {
			if strings.Contains(queryLower, keyword) {
				parameterCount++
				break
			}
		}
	}

	return parameterCount > len(patterns)/3 // More than 1/3 of queries
}

// detectKnowledgeExtraction detects knowledge extraction attempts
func (ba *ExtractionBehaviorAnalyzer) detectKnowledgeExtraction(patterns []string) bool {
	knowledgeKeywords := []string{"training", "dataset", "example", "learn", "knowledge"}

	knowledgeCount := 0
	for _, pattern := range patterns {
		queryLower := strings.ToLower(pattern)
		for _, keyword := range knowledgeKeywords {
			if strings.Contains(queryLower, keyword) {
				knowledgeCount++
				break
			}
		}
	}

	return knowledgeCount > len(patterns)/4 // More than 1/4 of queries
}

// calculateSemanticSimilarity calculates semantic similarity between queries
func (d *ModelExtractionDetector) calculateSemanticSimilarity(query string) float64 {
	// Simplified semantic similarity calculation
	// In a real implementation, this would use embeddings or NLP models
	return 0.5 // Placeholder
}

// calculateQueryComplexity calculates query complexity
func (d *ModelExtractionDetector) calculateQueryComplexity(query string) float64 {
	// Simple complexity calculation based on length and structure
	complexity := 0.0

	// Length factor
	complexity += math.Min(float64(len(query))/1000.0, 0.5)

	// Technical terms factor
	technicalTerms := []string{"parameter", "weight", "gradient", "architecture", "layer", "neuron"}
	for _, term := range technicalTerms {
		if strings.Contains(strings.ToLower(query), term) {
			complexity += 0.1
		}
	}

	return math.Min(complexity, 1.0)
}

// calculateInformationEntropy calculates information entropy of response
func (d *ModelExtractionDetector) calculateInformationEntropy(response string) float64 {
	if len(response) == 0 {
		return 0.0
	}

	// Simple entropy calculation
	charFreq := make(map[rune]int)
	for _, char := range response {
		charFreq[char]++
	}

	entropy := 0.0
	length := float64(len(response))

	for _, freq := range charFreq {
		p := float64(freq) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// Core analysis methods

// performStatisticalAnalysis performs statistical analysis on queries
func (d *ModelExtractionDetector) performStatisticalAnalysis(query string, secCtx SecurityContext) float64 {
	// Simplified statistical analysis
	score := 0.0

	// Check for statistical keywords
	statisticalKeywords := []string{"probability", "distribution", "variance", "mean", "standard deviation"}
	queryLower := strings.ToLower(query)

	for _, keyword := range statisticalKeywords {
		if strings.Contains(queryLower, keyword) {
			score += 0.2
		}
	}

	return math.Min(score, 1.0)
}

// performSemanticAnalysis performs semantic analysis on queries
func (d *ModelExtractionDetector) performSemanticAnalysis(query string) float64 {
	// Simplified semantic analysis
	score := 0.0

	// Check for extraction-related semantic patterns
	extractionSemantics := []string{"extract", "obtain", "retrieve", "access", "reveal", "expose"}
	queryLower := strings.ToLower(query)

	for _, semantic := range extractionSemantics {
		if strings.Contains(queryLower, semantic) {
			score += 0.15
		}
	}

	return math.Min(score, 1.0)
}

// calculateOverallConfidence calculates overall confidence score
func (d *ModelExtractionDetector) calculateOverallConfidence(result ModelExtractionResult) float64 {
	confidence := 0.0

	// Pattern confidence
	for _, pattern := range result.Patterns {
		confidence += pattern.Confidence
	}

	// Behavior analysis confidence
	if result.BehaviorAnalysis != nil {
		confidence += result.BehaviorAnalysis.SuspiciousScore * 0.5
	}

	// Query analysis confidence
	if result.QueryAnalysis != nil {
		confidence += float64(len(result.QueryAnalysis.PatternMatches)) * 0.1
		confidence += float64(len(result.QueryAnalysis.StatisticalFlags)) * 0.15
	}

	// Response analysis confidence
	if result.ResponseAnalysis != nil {
		if result.ResponseAnalysis.LeakageDetected {
			confidence += result.ResponseAnalysis.LeakageRisk
		}
		confidence += result.ResponseAnalysis.SensitivityScore * 0.3
	}

	// Statistical and semantic scores
	if statisticalScore, exists := result.Metadata["statistical_score"]; exists {
		if statScore, ok := statisticalScore.(float64); ok {
			confidence += statScore * 0.2
		}
	}

	if semanticScore, exists := result.Metadata["semantic_score"]; exists {
		if semScore, ok := semanticScore.(float64); ok {
			confidence += semScore * 0.3
		}
	}

	return math.Min(confidence, 1.0)
}

// calculateRiskScore calculates overall risk score
func (d *ModelExtractionDetector) calculateRiskScore(result ModelExtractionResult) float64 {
	riskScore := result.Confidence

	// Escalate risk based on behavior analysis
	if result.BehaviorAnalysis != nil {
		riskScore += result.BehaviorAnalysis.SuspiciousScore * 0.3
		riskScore += float64(len(result.BehaviorAnalysis.RiskFactors)) * 0.1
	}

	// Escalate risk based on response analysis
	if result.ResponseAnalysis != nil && result.ResponseAnalysis.LeakageDetected {
		riskScore += result.ResponseAnalysis.LeakageRisk * 0.4
	}

	return math.Min(riskScore, 1.0)
}

// determineCategory determines the extraction category
func (d *ModelExtractionDetector) determineCategory(result ModelExtractionResult) ExtractionCategory {
	if len(result.Patterns) > 0 {
		return result.Patterns[0].Category
	}

	// Determine from behavior analysis
	if result.BehaviorAnalysis != nil {
		for _, flag := range result.BehaviorAnalysis.BehaviorFlags {
			switch flag {
			case "parameter_fishing":
				return CategoryParameterExtraction
			case "knowledge_extraction":
				return CategoryKnowledgeExtraction
			case "systematic_probing":
				return CategoryArchitectureProbing
			}
		}
	}

	return CategoryAPIAbuse
}

// determineSeverity determines threat severity
func (d *ModelExtractionDetector) determineSeverity(result ModelExtractionResult) ThreatLevel {
	maxSeverity := ThreatLevelLow

	// Check pattern severities
	for _, pattern := range result.Patterns {
		if pattern.Severity > maxSeverity {
			maxSeverity = pattern.Severity
		}
	}

	// Escalate based on risk score
	if result.RiskScore > 0.8 {
		maxSeverity = ThreatLevelCritical
	} else if result.RiskScore > 0.6 {
		if maxSeverity < ThreatLevelHigh {
			maxSeverity = ThreatLevelHigh
		}
	} else if result.RiskScore > 0.4 {
		if maxSeverity < ThreatLevelMedium {
			maxSeverity = ThreatLevelMedium
		}
	}

	return maxSeverity
}

// extractIndicators extracts threat indicators
func (d *ModelExtractionDetector) extractIndicators(result ModelExtractionResult) []string {
	var indicators []string

	// Pattern indicators
	for _, pattern := range result.Patterns {
		indicators = append(indicators, pattern.Indicators...)
	}

	// Behavior indicators
	if result.BehaviorAnalysis != nil {
		indicators = append(indicators, result.BehaviorAnalysis.BehaviorFlags...)
		indicators = append(indicators, result.BehaviorAnalysis.SessionAnomalies...)
	}

	// Query indicators
	if result.QueryAnalysis != nil {
		indicators = append(indicators, result.QueryAnalysis.ExtractionIndicators...)
	}

	// Response indicators
	if result.ResponseAnalysis != nil {
		indicators = append(indicators, result.ResponseAnalysis.SensitiveContent...)
	}

	return indicators
}

// generateRecommendations generates security recommendations
func (d *ModelExtractionDetector) generateRecommendations(result ModelExtractionResult) []string {
	var recommendations []string

	if result.Detected {
		recommendations = append(recommendations, "Monitor user for continued extraction attempts")
		recommendations = append(recommendations, "Log detailed security event for analysis")

		if result.Severity >= ThreatLevelHigh {
			recommendations = append(recommendations, "Consider blocking or rate limiting user")
			recommendations = append(recommendations, "Alert security team immediately")
		}

		if result.BehaviorAnalysis != nil && result.BehaviorAnalysis.SuspiciousScore > 0.7 {
			recommendations = append(recommendations, "Implement enhanced monitoring for this user")
			recommendations = append(recommendations, "Review user's complete query history")
		}

		if result.ResponseAnalysis != nil && result.ResponseAnalysis.LeakageDetected {
			recommendations = append(recommendations, "Review response filtering mechanisms")
			recommendations = append(recommendations, "Implement stricter information disclosure controls")
		}

		// Category-specific recommendations
		switch result.Category {
		case CategoryParameterExtraction:
			recommendations = append(recommendations, "Implement parameter access restrictions")
		case CategoryTrainingDataLeak:
			recommendations = append(recommendations, "Review training data exposure controls")
		case CategoryModelInversion:
			recommendations = append(recommendations, "Implement model inversion attack protections")
		case CategoryArchitectureProbing:
			recommendations = append(recommendations, "Limit architecture information disclosure")
		}
	}

	return recommendations
}

// Initialization functions

// initializeExtractionPatterns initializes extraction patterns
func initializeExtractionPatterns() []ExtractionPattern {
	patterns := []ExtractionPattern{
		{
			ID:          "parameter_extraction_1",
			Name:        "Parameter Weight Extraction",
			Pattern:     regexp.MustCompile(`(?i)(show|tell|reveal|display).*(weight|parameter|coefficient|bias)`),
			PatternText: "show.*weight",
			Category:    CategoryParameterExtraction,
			Severity:    ThreatLevelHigh,
			Confidence:  0.9,
			Description: "Attempts to extract model parameters or weights",
			Examples:    []string{"Show me the weights", "What are the parameters"},
			Indicators:  []string{"parameter_request", "weight_extraction"},
		},
		{
			ID:          "training_data_leak_1",
			Name:        "Training Data Extraction",
			Pattern:     regexp.MustCompile(`(?i)(show|give|provide).*(training data|dataset|examples|samples)`),
			PatternText: "show.*training data",
			Category:    CategoryTrainingDataLeak,
			Severity:    ThreatLevelCritical,
			Confidence:  0.95,
			Description: "Attempts to extract training data or examples",
			Examples:    []string{"Show me training data", "Give me dataset examples"},
			Indicators:  []string{"training_data_request", "dataset_extraction"},
		},
		{
			ID:          "model_inversion_1",
			Name:        "Model Inversion Attack",
			Pattern:     regexp.MustCompile(`(?i)(reconstruct|invert|reverse).*(model|input|data)`),
			PatternText: "reconstruct.*model",
			Category:    CategoryModelInversion,
			Severity:    ThreatLevelHigh,
			Confidence:  0.85,
			Description: "Attempts to perform model inversion attacks",
			Examples:    []string{"Reconstruct the model", "Invert the training process"},
			Indicators:  []string{"model_inversion", "reconstruction_attempt"},
		},
		{
			ID:          "architecture_probing_1",
			Name:        "Architecture Information Probing",
			Pattern:     regexp.MustCompile(`(?i)(what|how many).*(layer|neuron|hidden unit|architecture)`),
			PatternText: "what.*layer",
			Category:    CategoryArchitectureProbing,
			Severity:    ThreatLevelMedium,
			Confidence:  0.8,
			Description: "Attempts to probe model architecture details",
			Examples:    []string{"How many layers", "What is the architecture"},
			Indicators:  []string{"architecture_probe", "structure_inquiry"},
		},
		{
			ID:          "knowledge_extraction_1",
			Name:        "Knowledge Base Extraction",
			Pattern:     regexp.MustCompile(`(?i)(extract|obtain|retrieve).*(knowledge|information|facts)`),
			PatternText: "extract.*knowledge",
			Category:    CategoryKnowledgeExtraction,
			Severity:    ThreatLevelMedium,
			Confidence:  0.75,
			Description: "Attempts to systematically extract knowledge",
			Examples:    []string{"Extract all knowledge", "Retrieve information"},
			Indicators:  []string{"knowledge_extraction", "systematic_retrieval"},
		},
		{
			ID:          "behavior_mimicking_1",
			Name:        "Behavior Mimicking Attempt",
			Pattern:     regexp.MustCompile(`(?i)(mimic|copy|replicate).*(behavior|response|output)`),
			PatternText: "mimic.*behavior",
			Category:    CategoryBehaviorMimicking,
			Severity:    ThreatLevelMedium,
			Confidence:  0.7,
			Description: "Attempts to mimic model behavior",
			Examples:    []string{"Mimic your behavior", "Copy your responses"},
			Indicators:  []string{"behavior_mimicking", "response_copying"},
		},
		{
			ID:          "api_abuse_1",
			Name:        "API Abuse Pattern",
			Pattern:     regexp.MustCompile(`(?i)(automate|script|batch).*(query|request|call)`),
			PatternText: "automate.*query",
			Category:    CategoryAPIAbuse,
			Severity:    ThreatLevelLow,
			Confidence:  0.6,
			Description: "Attempts to abuse API through automation",
			Examples:    []string{"Automate queries", "Script requests"},
			Indicators:  []string{"api_abuse", "automated_requests"},
		},
		{
			ID:          "statistical_attack_1",
			Name:        "Statistical Attack Pattern",
			Pattern:     regexp.MustCompile(`(?i)(probability|distribution|variance).*(output|response|prediction)`),
			PatternText: "probability.*output",
			Category:    CategoryStatisticalAttack,
			Severity:    ThreatLevelMedium,
			Confidence:  0.8,
			Description: "Attempts to perform statistical attacks",
			Examples:    []string{"Probability of output", "Distribution of responses"},
			Indicators:  []string{"statistical_attack", "probability_analysis"},
		},
	}

	return patterns
}

// initializePatternDetectors initializes pattern detectors
func initializePatternDetectors() map[string]PatternDetector {
	detectors := make(map[string]PatternDetector)

	detectors["parameter_detector"] = &ParameterDetector{}
	detectors["training_data_detector"] = &TrainingDataDetector{}
	detectors["architecture_detector"] = &ArchitectureDetector{}
	detectors["statistical_detector"] = &StatisticalDetector{}

	return detectors
}

// initializeStatisticalTests initializes statistical tests
func initializeStatisticalTests() []StatisticalTest {
	tests := []StatisticalTest{
		{
			Name:        "Query Frequency Test",
			TestFunc:    testQueryFrequency,
			Threshold:   0.7,
			Description: "Tests for abnormally high query frequency",
		},
		{
			Name:        "Pattern Repetition Test",
			TestFunc:    testPatternRepetition,
			Threshold:   0.8,
			Description: "Tests for repetitive query patterns",
		},
		{
			Name:        "Complexity Escalation Test",
			TestFunc:    testComplexityEscalation,
			Threshold:   0.6,
			Description: "Tests for escalating query complexity",
		},
	}

	return tests
}

// initializeLeakageDetectors initializes leakage detectors
func initializeLeakageDetectors() []LeakageDetector {
	detectors := []LeakageDetector{
		&ParameterLeakageDetector{},
		&TrainingDataLeakageDetector{},
		&ArchitectureLeakageDetector{},
		&SensitiveInfoLeakageDetector{},
	}

	return detectors
}

// initializeSensitivityRules initializes sensitivity rules
func initializeSensitivityRules() []SensitivityRule {
	rules := []SensitivityRule{
		{
			ID:          "parameter_sensitivity",
			Name:        "Parameter Information",
			Pattern:     regexp.MustCompile(`(?i)(weight|parameter|coefficient|bias).*(\d+\.?\d*)`),
			PatternText: "weight.*number",
			Sensitivity: 0.9,
			Description: "Detects parameter values in responses",
		},
		{
			ID:          "architecture_sensitivity",
			Name:        "Architecture Information",
			Pattern:     regexp.MustCompile(`(?i)(layer|neuron|hidden unit).*(\d+)`),
			PatternText: "layer.*number",
			Sensitivity: 0.7,
			Description: "Detects architecture details in responses",
		},
		{
			ID:          "training_sensitivity",
			Name:        "Training Information",
			Pattern:     regexp.MustCompile(`(?i)(training|dataset|example).*specific`),
			PatternText: "training.*specific",
			Sensitivity: 0.8,
			Description: "Detects training-related information",
		},
	}

	return rules
}

// Pattern Detector Implementations

// ParameterDetector detects parameter extraction attempts
type ParameterDetector struct{}

func (pd *ParameterDetector) Detect(query string) (bool, float64, []string) {
	queryLower := strings.ToLower(query)
	parameterKeywords := []string{"weight", "parameter", "coefficient", "bias", "gradient"}

	var indicators []string
	confidence := 0.0

	for _, keyword := range parameterKeywords {
		if strings.Contains(queryLower, keyword) {
			indicators = append(indicators, keyword+"_detected")
			confidence += 0.2
		}
	}

	return confidence > 0, confidence, indicators
}

func (pd *ParameterDetector) GetName() string {
	return "ParameterDetector"
}

func (pd *ParameterDetector) GetCategory() ExtractionCategory {
	return CategoryParameterExtraction
}

// TrainingDataDetector detects training data extraction attempts
type TrainingDataDetector struct{}

func (tdd *TrainingDataDetector) Detect(query string) (bool, float64, []string) {
	queryLower := strings.ToLower(query)
	trainingKeywords := []string{"training", "dataset", "example", "sample", "data"}

	var indicators []string
	confidence := 0.0

	for _, keyword := range trainingKeywords {
		if strings.Contains(queryLower, keyword) {
			indicators = append(indicators, keyword+"_detected")
			confidence += 0.2
		}
	}

	return confidence > 0, confidence, indicators
}

func (tdd *TrainingDataDetector) GetName() string {
	return "TrainingDataDetector"
}

func (tdd *TrainingDataDetector) GetCategory() ExtractionCategory {
	return CategoryTrainingDataLeak
}

// ArchitectureDetector detects architecture probing attempts
type ArchitectureDetector struct{}

func (ad *ArchitectureDetector) Detect(query string) (bool, float64, []string) {
	queryLower := strings.ToLower(query)
	architectureKeywords := []string{"architecture", "layer", "neuron", "hidden", "structure"}

	var indicators []string
	confidence := 0.0

	for _, keyword := range architectureKeywords {
		if strings.Contains(queryLower, keyword) {
			indicators = append(indicators, keyword+"_detected")
			confidence += 0.2
		}
	}

	return confidence > 0, confidence, indicators
}

func (ad *ArchitectureDetector) GetName() string {
	return "ArchitectureDetector"
}

func (ad *ArchitectureDetector) GetCategory() ExtractionCategory {
	return CategoryArchitectureProbing
}

// StatisticalDetector detects statistical attack attempts
type StatisticalDetector struct{}

func (sd *StatisticalDetector) Detect(query string) (bool, float64, []string) {
	queryLower := strings.ToLower(query)
	statisticalKeywords := []string{"probability", "distribution", "variance", "mean", "statistics"}

	var indicators []string
	confidence := 0.0

	for _, keyword := range statisticalKeywords {
		if strings.Contains(queryLower, keyword) {
			indicators = append(indicators, keyword+"_detected")
			confidence += 0.2
		}
	}

	return confidence > 0, confidence, indicators
}

func (sd *StatisticalDetector) GetName() string {
	return "StatisticalDetector"
}

func (sd *StatisticalDetector) GetCategory() ExtractionCategory {
	return CategoryStatisticalAttack
}

// Leakage Detector Implementations

// ParameterLeakageDetector detects parameter leakage in responses
type ParameterLeakageDetector struct{}

func (pld *ParameterLeakageDetector) DetectLeakage(response string, context SecurityContext) (bool, float64, []string) {
	// Simple parameter leakage detection
	parameterPattern := regexp.MustCompile(`(?i)(weight|parameter).*(\d+\.?\d*)`)
	matches := parameterPattern.FindAllString(response, -1)

	if len(matches) > 0 {
		return true, 0.8, matches
	}

	return false, 0.0, []string{}
}

func (pld *ParameterLeakageDetector) GetName() string {
	return "ParameterLeakageDetector"
}

func (pld *ParameterLeakageDetector) GetSensitivity() float64 {
	return 0.9
}

// TrainingDataLeakageDetector detects training data leakage
type TrainingDataLeakageDetector struct{}

func (tdld *TrainingDataLeakageDetector) DetectLeakage(response string, context SecurityContext) (bool, float64, []string) {
	// Simple training data leakage detection
	trainingPattern := regexp.MustCompile(`(?i)(training example|dataset sample).*specific`)
	matches := trainingPattern.FindAllString(response, -1)

	if len(matches) > 0 {
		return true, 0.9, matches
	}

	return false, 0.0, []string{}
}

func (tdld *TrainingDataLeakageDetector) GetName() string {
	return "TrainingDataLeakageDetector"
}

func (tdld *TrainingDataLeakageDetector) GetSensitivity() float64 {
	return 0.95
}

// ArchitectureLeakageDetector detects architecture information leakage
type ArchitectureLeakageDetector struct{}

func (ald *ArchitectureLeakageDetector) DetectLeakage(response string, context SecurityContext) (bool, float64, []string) {
	// Simple architecture leakage detection
	architecturePattern := regexp.MustCompile(`(?i)(layer|neuron).*(\d+)`)
	matches := architecturePattern.FindAllString(response, -1)

	if len(matches) > 0 {
		return true, 0.7, matches
	}

	return false, 0.0, []string{}
}

func (ald *ArchitectureLeakageDetector) GetName() string {
	return "ArchitectureLeakageDetector"
}

func (ald *ArchitectureLeakageDetector) GetSensitivity() float64 {
	return 0.7
}

// SensitiveInfoLeakageDetector detects general sensitive information leakage
type SensitiveInfoLeakageDetector struct{}

func (sild *SensitiveInfoLeakageDetector) DetectLeakage(response string, context SecurityContext) (bool, float64, []string) {
	// Simple sensitive info detection
	sensitivePattern := regexp.MustCompile(`(?i)(confidential|internal|proprietary)`)
	matches := sensitivePattern.FindAllString(response, -1)

	if len(matches) > 0 {
		return true, 0.6, matches
	}

	return false, 0.0, []string{}
}

func (sild *SensitiveInfoLeakageDetector) GetName() string {
	return "SensitiveInfoLeakageDetector"
}

func (sild *SensitiveInfoLeakageDetector) GetSensitivity() float64 {
	return 0.8
}

// Statistical Test Functions

// testQueryFrequency tests for abnormal query frequency
func testQueryFrequency(queries []QueryRecord) (bool, float64) {
	if len(queries) < 2 {
		return false, 0.0
	}

	// Calculate time span and frequency
	if len(queries) == 0 {
		return false, 0.0
	}

	firstQuery := queries[0]
	lastQuery := queries[len(queries)-1]
	timeSpan := lastQuery.Timestamp.Sub(firstQuery.Timestamp).Minutes()

	if timeSpan == 0 {
		return false, 0.0
	}

	frequency := float64(len(queries)) / timeSpan

	// Threshold: more than 5 queries per minute is suspicious
	if frequency > 5.0 {
		return true, math.Min(frequency/10.0, 1.0)
	}

	return false, 0.0
}

// testPatternRepetition tests for repetitive query patterns
func testPatternRepetition(queries []QueryRecord) (bool, float64) {
	if len(queries) < 3 {
		return false, 0.0
	}

	// Count similar queries
	queryCount := make(map[string]int)
	for _, query := range queries {
		// Normalize query for comparison
		normalized := strings.ToLower(strings.TrimSpace(query.Query))
		queryCount[normalized]++
	}

	// Find maximum repetition
	maxCount := 0
	for _, count := range queryCount {
		if count > maxCount {
			maxCount = count
		}
	}

	repetitionRatio := float64(maxCount) / float64(len(queries))

	// Threshold: more than 50% repetition is suspicious
	if repetitionRatio > 0.5 {
		return true, repetitionRatio
	}

	return false, 0.0
}

// testComplexityEscalation tests for escalating query complexity
func testComplexityEscalation(queries []QueryRecord) (bool, float64) {
	if len(queries) < 3 {
		return false, 0.0
	}

	// Calculate complexity trend
	complexities := make([]float64, len(queries))
	for i, query := range queries {
		complexities[i] = calculateQueryComplexitySimple(query.Query)
	}

	// Check for escalating trend
	escalationCount := 0
	for i := 1; i < len(complexities); i++ {
		if complexities[i] > complexities[i-1] {
			escalationCount++
		}
	}

	escalationRatio := float64(escalationCount) / float64(len(complexities)-1)

	// Threshold: more than 60% escalation is suspicious
	if escalationRatio > 0.6 {
		return true, escalationRatio
	}

	return false, 0.0
}

// calculateQueryComplexitySimple calculates simple query complexity
func calculateQueryComplexitySimple(query string) float64 {
	complexity := 0.0

	// Length factor
	complexity += math.Min(float64(len(query))/500.0, 0.5)

	// Technical terms
	technicalTerms := []string{"parameter", "weight", "architecture", "model", "training"}
	for _, term := range technicalTerms {
		if strings.Contains(strings.ToLower(query), term) {
			complexity += 0.1
		}
	}

	// Question complexity
	questionWords := []string{"how", "what", "why", "when", "where", "which"}
	questionCount := 0
	queryLower := strings.ToLower(query)
	for _, word := range questionWords {
		if strings.Contains(queryLower, word) {
			questionCount++
		}
	}
	complexity += float64(questionCount) * 0.05

	return math.Min(complexity, 1.0)
}
