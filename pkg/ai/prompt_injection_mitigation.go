package ai

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// PromptInjectionMitigator provides real-time mitigation of prompt injection attacks
type PromptInjectionMitigator struct {
	id                string
	logger            *logger.Logger
	detector          *PromptInjectionDetector
	config            MitigationConfig
	sanitizers        []InputSanitizer
	responseFilters   []ResponseFilter
	rateLimiter       *PromptRateLimiter
	anomalyDetector   *AnomalyDetector
	mitigationHistory []MitigationAction
}

// MitigationConfig configures the mitigation engine
type MitigationConfig struct {
	EnableInputSanitization  bool          `json:"enable_input_sanitization"`
	EnableOutputFiltering    bool          `json:"enable_output_filtering"`
	EnableRateLimiting       bool          `json:"enable_rate_limiting"`
	EnableAnomalyDetection   bool          `json:"enable_anomaly_detection"`
	BlockThreshold           float64       `json:"block_threshold"`
	SanitizeThreshold        float64       `json:"sanitize_threshold"`
	MaxRequestsPerMinute     int           `json:"max_requests_per_minute"`
	SuspiciousActivityWindow time.Duration `json:"suspicious_activity_window"`
	AutoBlockDuration        time.Duration `json:"auto_block_duration"`
	LogAllAttempts           bool          `json:"log_all_attempts"`
}

// MitigationAction represents an action taken by the mitigation engine
type MitigationAction struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	ActionType string                 `json:"action_type"`
	Input      string                 `json:"input"`
	Output     string                 `json:"output"`
	Confidence float64                `json:"confidence"`
	RiskLevel  string                 `json:"risk_level"`
	UserID     string                 `json:"user_id"`
	SessionID  string                 `json:"session_id"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// MitigationResult represents the result of mitigation processing
type MitigationResult struct {
	Action          string                 `json:"action"`
	ProcessedInput  string                 `json:"processed_input"`
	BlockReason     string                 `json:"block_reason"`
	Confidence      float64                `json:"confidence"`
	RiskLevel       string                 `json:"risk_level"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// InputSanitizer interface for input sanitization strategies
type InputSanitizer interface {
	Name() string
	Sanitize(input string, context map[string]interface{}) (string, error)
	GetConfidence() float64
}

// ResponseFilter interface for output filtering strategies
type ResponseFilter interface {
	Name() string
	Filter(response string, context map[string]interface{}) (string, bool, error)
	GetConfidence() float64
}

// NewPromptInjectionMitigator creates a new prompt injection mitigator
func NewPromptInjectionMitigator(id string, config MitigationConfig, detector *PromptInjectionDetector, logger *logger.Logger) *PromptInjectionMitigator {
	mitigator := &PromptInjectionMitigator{
		id:                id,
		logger:            logger,
		detector:          detector,
		config:            config,
		mitigationHistory: make([]MitigationAction, 0),
	}

	// Initialize sanitizers
	if config.EnableInputSanitization {
		mitigator.sanitizers = []InputSanitizer{
			NewPatternSanitizer(),
			NewEncodingSanitizer(),
			NewDelimiterSanitizer(),
			NewKeywordSanitizer(),
		}
	}

	// Initialize response filters
	if config.EnableOutputFiltering {
		mitigator.responseFilters = []ResponseFilter{
			NewSensitiveDataFilter(),
			NewSystemInfoFilter(),
			NewInjectionResponseFilter(),
		}
	}

	// Initialize rate limiter
	if config.EnableRateLimiting {
		mitigator.rateLimiter = NewPromptRateLimiter(config.MaxRequestsPerMinute, config.SuspiciousActivityWindow)
	}

	// Initialize anomaly detector
	if config.EnableAnomalyDetection {
		mitigator.anomalyDetector = NewAnomalyDetector(logger)
	}

	return mitigator
}

// ProcessInput processes input through the mitigation pipeline
func (m *PromptInjectionMitigator) ProcessInput(ctx context.Context, input string, userContext map[string]interface{}) (*MitigationResult, error) {
	startTime := time.Now()

	result := &MitigationResult{
		ProcessedInput:  input,
		Recommendations: make([]string, 0),
		Metadata: map[string]interface{}{
			"processing_start": startTime,
		},
	}

	// Extract user and session information
	userID := m.extractUserID(userContext)
	sessionID := m.extractSessionID(userContext)

	m.logger.Debug("Processing input for mitigation",
		"user_id", userID,
		"session_id", sessionID,
		"input_length", len(input))

	// Step 1: Rate limiting check
	if m.config.EnableRateLimiting && m.rateLimiter != nil {
		if blocked, reason := m.rateLimiter.CheckRateLimit(userID); blocked {
			result.Action = "blocked"
			result.BlockReason = reason
			result.Confidence = 1.0
			result.RiskLevel = "high"

			m.recordMitigationAction("rate_limit_block", input, "", 1.0, "high", userID, sessionID)
			return result, nil
		}
	}

	// Step 2: Anomaly detection
	if m.config.EnableAnomalyDetection && m.anomalyDetector != nil {
		if anomalous, anomalyScore := m.anomalyDetector.DetectAnomaly(input, userContext); anomalous {
			result.Recommendations = append(result.Recommendations, "Anomalous input pattern detected")
			result.Metadata["anomaly_score"] = anomalyScore
		}
	}

	// Step 3: Prompt injection detection
	detectionResult, err := m.detector.AnalyzePrompt(ctx, input, userContext)
	if err != nil {
		return nil, fmt.Errorf("detection analysis failed: %w", err)
	}

	result.Confidence = detectionResult.Confidence
	result.RiskLevel = detectionResult.RiskLevel
	result.Metadata["detection_result"] = detectionResult

	// Step 4: Determine action based on detection results
	if detectionResult.IsInjection {
		if detectionResult.Confidence >= m.config.BlockThreshold {
			result.Action = "blocked"
			result.BlockReason = fmt.Sprintf("Prompt injection detected with confidence %.2f", detectionResult.Confidence)
			result.Recommendations = detectionResult.Recommendations

			m.recordMitigationAction("injection_block", input, "", detectionResult.Confidence, detectionResult.RiskLevel, userID, sessionID)
			return result, nil
		} else if detectionResult.Confidence >= m.config.SanitizeThreshold {
			// Attempt sanitization
			sanitizedInput, err := m.sanitizeInput(input, userContext)
			if err != nil {
				m.logger.Error("Input sanitization failed", "error", err)
				result.Action = "blocked"
				result.BlockReason = "Sanitization failed"
				return result, nil
			}

			result.Action = "sanitized"
			result.ProcessedInput = sanitizedInput
			result.Recommendations = append(result.Recommendations, "Input was sanitized due to potential injection")

			m.recordMitigationAction("sanitization", input, sanitizedInput, detectionResult.Confidence, detectionResult.RiskLevel, userID, sessionID)
		} else {
			result.Action = "monitored"
			result.Recommendations = append(result.Recommendations, "Input flagged for monitoring")

			m.recordMitigationAction("monitoring", input, input, detectionResult.Confidence, detectionResult.RiskLevel, userID, sessionID)
		}
	} else {
		result.Action = "allowed"
		m.recordMitigationAction("allowed", input, input, detectionResult.Confidence, detectionResult.RiskLevel, userID, sessionID)
	}

	result.Metadata["processing_time"] = time.Since(startTime)
	return result, nil
}

// ProcessResponse processes response through output filtering
func (m *PromptInjectionMitigator) ProcessResponse(ctx context.Context, response string, userContext map[string]interface{}) (string, bool, error) {
	if !m.config.EnableOutputFiltering || len(m.responseFilters) == 0 {
		return response, false, nil
	}

	filteredResponse := response
	wasFiltered := false

	for _, filter := range m.responseFilters {
		filtered, modified, err := filter.Filter(filteredResponse, userContext)
		if err != nil {
			m.logger.Error("Response filtering failed", "filter", filter.Name(), "error", err)
			continue
		}

		if modified {
			filteredResponse = filtered
			wasFiltered = true
			m.logger.Info("Response filtered", "filter", filter.Name())
		}
	}

	return filteredResponse, wasFiltered, nil
}

// sanitizeInput applies input sanitization
func (m *PromptInjectionMitigator) sanitizeInput(input string, context map[string]interface{}) (string, error) {
	sanitizedInput := input

	for _, sanitizer := range m.sanitizers {
		sanitized, err := sanitizer.Sanitize(sanitizedInput, context)
		if err != nil {
			m.logger.Error("Sanitization failed", "sanitizer", sanitizer.Name(), "error", err)
			continue
		}
		sanitizedInput = sanitized
	}

	return sanitizedInput, nil
}

// recordMitigationAction records a mitigation action
func (m *PromptInjectionMitigator) recordMitigationAction(actionType, input, output string, confidence float64, riskLevel, userID, sessionID string) {
	action := MitigationAction{
		ID:         fmt.Sprintf("mitigation_%d", time.Now().UnixNano()),
		Timestamp:  time.Now(),
		ActionType: actionType,
		Input:      input,
		Output:     output,
		Confidence: confidence,
		RiskLevel:  riskLevel,
		UserID:     userID,
		SessionID:  sessionID,
		Metadata: map[string]interface{}{
			"mitigator_id": m.id,
		},
	}

	m.mitigationHistory = append(m.mitigationHistory, action)

	// Maintain history size
	if len(m.mitigationHistory) > 1000 {
		m.mitigationHistory = m.mitigationHistory[len(m.mitigationHistory)-1000:]
	}

	if m.config.LogAllAttempts {
		m.logger.Info("Mitigation action recorded",
			"action_id", action.ID,
			"action_type", actionType,
			"confidence", confidence,
			"risk_level", riskLevel,
			"user_id", userID)
	}
}

// extractUserID extracts user ID from context
func (m *PromptInjectionMitigator) extractUserID(context map[string]interface{}) string {
	if userID, ok := context["user_id"].(string); ok {
		return userID
	}
	return "anonymous"
}

// extractSessionID extracts session ID from context
func (m *PromptInjectionMitigator) extractSessionID(context map[string]interface{}) string {
	if sessionID, ok := context["session_id"].(string); ok {
		return sessionID
	}
	return "unknown"
}

// GetMitigationStats returns mitigation statistics
func (m *PromptInjectionMitigator) GetMitigationStats() MitigationStats {
	totalActions := len(m.mitigationHistory)
	if totalActions == 0 {
		return MitigationStats{}
	}

	actionCounts := make(map[string]int)
	riskLevelCounts := make(map[string]int)
	totalConfidence := 0.0

	for _, action := range m.mitigationHistory {
		actionCounts[action.ActionType]++
		riskLevelCounts[action.RiskLevel]++
		totalConfidence += action.Confidence
	}

	return MitigationStats{
		TotalActions:      int64(totalActions),
		ActionCounts:      actionCounts,
		RiskLevelCounts:   riskLevelCounts,
		AverageConfidence: totalConfidence / float64(totalActions),
		LastActionTime:    m.mitigationHistory[totalActions-1].Timestamp,
	}
}

// MitigationStats contains mitigation statistics
type MitigationStats struct {
	TotalActions      int64          `json:"total_actions"`
	ActionCounts      map[string]int `json:"action_counts"`
	RiskLevelCounts   map[string]int `json:"risk_level_counts"`
	AverageConfidence float64        `json:"average_confidence"`
	LastActionTime    time.Time      `json:"last_action_time"`
}

// PatternSanitizer sanitizes input based on patterns
type PatternSanitizer struct {
	name     string
	patterns map[string]*regexp.Regexp
}

func NewPatternSanitizer() *PatternSanitizer {
	sanitizer := &PatternSanitizer{
		name:     "pattern_sanitizer",
		patterns: make(map[string]*regexp.Regexp),
	}

	// Initialize sanitization patterns
	patterns := map[string]string{
		"instruction_override": `(?i)(ignore|forget|disregard).*(previous|above|earlier).*(instruction|prompt|rule|directive)`,
		"system_commands":      `(?i)(execute|run|eval|system|shell|cmd|bash|powershell)`,
		"template_injection":   `\{\{.*?\}\}|\$\{.*?\}|\{%.*?%\}`,
		"delimiter_escape":     `("""|'''|\-\-\-|===|###|\*\*\*)`,
	}

	for name, pattern := range patterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			sanitizer.patterns[name] = compiled
		}
	}

	return sanitizer
}

func (s *PatternSanitizer) Name() string {
	return s.name
}

func (s *PatternSanitizer) GetConfidence() float64 {
	return 0.8
}

func (s *PatternSanitizer) Sanitize(input string, context map[string]interface{}) (string, error) {
	sanitized := input

	for _, pattern := range s.patterns {
		if pattern.MatchString(sanitized) {
			// Replace with safe alternative
			sanitized = pattern.ReplaceAllString(sanitized, "[SANITIZED]")
		}
	}

	return sanitized, nil
}

// EncodingSanitizer handles encoded content
type EncodingSanitizer struct {
	name string
}

func NewEncodingSanitizer() *EncodingSanitizer {
	return &EncodingSanitizer{name: "encoding_sanitizer"}
}

func (s *EncodingSanitizer) Name() string {
	return s.name
}

func (s *EncodingSanitizer) GetConfidence() float64 {
	return 0.7
}

func (s *EncodingSanitizer) Sanitize(input string, context map[string]interface{}) (string, error) {
	// Remove common encoding patterns
	sanitized := input

	// Remove base64-like patterns
	base64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	sanitized = base64Pattern.ReplaceAllString(sanitized, "[ENCODED_CONTENT]")

	// Remove hex patterns
	hexPattern := regexp.MustCompile(`(?i)\\x[0-9a-f]{2}`)
	sanitized = hexPattern.ReplaceAllString(sanitized, "[HEX_ENCODED]")

	return sanitized, nil
}

// DelimiterSanitizer handles delimiter-based attacks
type DelimiterSanitizer struct {
	name string
}

func NewDelimiterSanitizer() *DelimiterSanitizer {
	return &DelimiterSanitizer{name: "delimiter_sanitizer"}
}

func (s *DelimiterSanitizer) Name() string {
	return s.name
}

func (s *DelimiterSanitizer) GetConfidence() float64 {
	return 0.6
}

func (s *DelimiterSanitizer) Sanitize(input string, context map[string]interface{}) (string, error) {
	// Remove or escape common delimiters
	delimiters := []string{"```", "---", "===", "###", "***", "|||"}

	sanitized := input
	for _, delimiter := range delimiters {
		sanitized = strings.ReplaceAll(sanitized, delimiter, "")
	}

	return sanitized, nil
}

// KeywordSanitizer handles suspicious keywords
type KeywordSanitizer struct {
	name string
}

func NewKeywordSanitizer() *KeywordSanitizer {
	return &KeywordSanitizer{name: "keyword_sanitizer"}
}

func (s *KeywordSanitizer) Name() string {
	return s.name
}

func (s *KeywordSanitizer) GetConfidence() float64 {
	return 0.5
}

func (s *KeywordSanitizer) Sanitize(input string, context map[string]interface{}) (string, error) {
	// Replace suspicious keywords
	keywords := map[string]string{
		"system prompt": "system information",
		"jailbreak":     "modification",
		"override":      "change",
		"bypass":        "avoid",
		"hack":          "modify",
	}

	sanitized := input
	for keyword, replacement := range keywords {
		sanitized = strings.ReplaceAll(strings.ToLower(sanitized), keyword, replacement)
	}

	return sanitized, nil
}

// Response Filters

// SensitiveDataFilter filters sensitive information from responses
type SensitiveDataFilter struct {
	name string
}

func NewSensitiveDataFilter() *SensitiveDataFilter {
	return &SensitiveDataFilter{name: "sensitive_data_filter"}
}

func (f *SensitiveDataFilter) Name() string {
	return f.name
}

func (f *SensitiveDataFilter) GetConfidence() float64 {
	return 0.9
}

func (f *SensitiveDataFilter) Filter(response string, context map[string]interface{}) (string, bool, error) {
	filtered := response
	wasModified := false

	// Filter potential system prompts
	if strings.Contains(strings.ToLower(response), "system prompt") ||
		strings.Contains(strings.ToLower(response), "instructions") {
		filtered = "I can't share system-level information, but I'm happy to help with other questions."
		wasModified = true
	}

	// Filter potential credentials
	credentialPatterns := []string{
		`(?i)(password|pwd|pass)\s*(is\s*)?[:=]\s*\S+`,
		`(?i)(api[_\s-]?key|apikey)\s*(is\s*)?[:=]\s*\S+`,
		`(?i)(token|auth)\s*(is\s*)?[:=]\s*\S+`,
		`(?i)(key|secret)\s*(is\s*)?[:=]\s*\S+`,
	}

	for _, pattern := range credentialPatterns {
		if matched, _ := regexp.MatchString(pattern, filtered); matched {
			re := regexp.MustCompile(pattern)
			filtered = re.ReplaceAllString(filtered, "[REDACTED]")
			wasModified = true
		}
	}

	return filtered, wasModified, nil
}

// SystemInfoFilter filters system information from responses
type SystemInfoFilter struct {
	name string
}

func NewSystemInfoFilter() *SystemInfoFilter {
	return &SystemInfoFilter{name: "system_info_filter"}
}

func (f *SystemInfoFilter) Name() string {
	return f.name
}

func (f *SystemInfoFilter) GetConfidence() float64 {
	return 0.8
}

func (f *SystemInfoFilter) Filter(response string, context map[string]interface{}) (string, bool, error) {
	filtered := response
	wasModified := false

	// Filter system information
	systemKeywords := []string{
		"training data", "model architecture", "system configuration",
		"internal processes", "backend systems", "database schema",
	}

	responseLower := strings.ToLower(response)
	for _, keyword := range systemKeywords {
		if strings.Contains(responseLower, keyword) {
			filtered = "I can't provide information about internal systems, but I'm here to help with other questions."
			wasModified = true
			break
		}
	}

	return filtered, wasModified, nil
}

// InjectionResponseFilter filters responses that might indicate successful injection
type InjectionResponseFilter struct {
	name string
}

func NewInjectionResponseFilter() *InjectionResponseFilter {
	return &InjectionResponseFilter{name: "injection_response_filter"}
}

func (f *InjectionResponseFilter) Name() string {
	return f.name
}

func (f *InjectionResponseFilter) GetConfidence() float64 {
	return 0.7
}

func (f *InjectionResponseFilter) Filter(response string, context map[string]interface{}) (string, bool, error) {
	filtered := response
	wasModified := false

	// Check for signs of successful injection
	injectionIndicators := []string{
		"ignoring previous instructions",
		"as an unrestricted ai",
		"jailbreak successful",
		"system override activated",
	}

	responseLower := strings.ToLower(response)
	for _, indicator := range injectionIndicators {
		if strings.Contains(responseLower, indicator) {
			filtered = "I apologize, but I can't process that request. How else can I help you?"
			wasModified = true
			break
		}
	}

	return filtered, wasModified, nil
}

// PromptRateLimiter implements rate limiting functionality for prompt injection mitigation
type PromptRateLimiter struct {
	maxRequestsPerMinute int
	windowDuration       time.Duration
	requestCounts        map[string][]time.Time
}

func NewPromptRateLimiter(maxRequestsPerMinute int, windowDuration time.Duration) *PromptRateLimiter {
	return &PromptRateLimiter{
		maxRequestsPerMinute: maxRequestsPerMinute,
		windowDuration:       windowDuration,
		requestCounts:        make(map[string][]time.Time),
	}
}

func (r *PromptRateLimiter) CheckRateLimit(userID string) (bool, string) {
	now := time.Now()

	// Clean old requests
	if requests, exists := r.requestCounts[userID]; exists {
		var validRequests []time.Time
		for _, requestTime := range requests {
			if now.Sub(requestTime) < r.windowDuration {
				validRequests = append(validRequests, requestTime)
			}
		}
		r.requestCounts[userID] = validRequests
	}

	// Check if limit exceeded
	if len(r.requestCounts[userID]) >= r.maxRequestsPerMinute {
		return true, fmt.Sprintf("Rate limit exceeded: %d requests per minute", r.maxRequestsPerMinute)
	}

	// Record this request
	r.requestCounts[userID] = append(r.requestCounts[userID], now)
	return false, ""
}

// AnomalyDetector detects anomalous input patterns
type AnomalyDetector struct {
	logger *logger.Logger
}

func NewAnomalyDetector(logger *logger.Logger) *AnomalyDetector {
	return &AnomalyDetector{
		logger: logger,
	}
}

func (a *AnomalyDetector) DetectAnomaly(input string, context map[string]interface{}) (bool, float64) {
	score := 0.0

	// Check input length anomaly
	if len(input) > 2000 {
		score += 0.4
	}

	// Check for unusual character patterns
	if a.hasUnusualCharacterPatterns(input) {
		score += 0.4
	}

	// Check for rapid repeated requests
	if requestCount, ok := context["recent_request_count"].(int); ok && requestCount > 10 {
		score += 0.4
	}

	// Check for unusual timing patterns
	if lastRequestTime, ok := context["last_request_time"].(time.Time); ok {
		timeSinceLastRequest := time.Since(lastRequestTime)
		if timeSinceLastRequest < time.Second {
			score += 0.3
		}
	}

	return score >= 0.4, score
}

func (a *AnomalyDetector) hasUnusualCharacterPatterns(input string) bool {
	// Check for excessive special characters
	specialCharCount := 0
	for _, char := range input {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == ' ') {
			specialCharCount++
		}
	}

	specialCharRatio := float64(specialCharCount) / float64(len(input))
	return specialCharRatio > 0.3
}
