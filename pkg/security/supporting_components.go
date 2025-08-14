package security

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// Supporting components for the agentic security framework

// BehaviorAnalyzer analyzes user and system behavior patterns
type BehaviorAnalyzer struct {
	logger           *logger.Logger
	behaviorProfiles map[string]*BehaviorProfile
	anomalyThreshold float64
	mu               sync.RWMutex
}

// BehaviorProfile represents a user's behavior profile
type BehaviorProfile struct {
	UserID             string                 `json:"user_id"`
	CreatedAt          time.Time              `json:"created_at"`
	LastActivity       time.Time              `json:"last_activity"`
	RequestCount       int64                  `json:"request_count"`
	AverageInterval    time.Duration          `json:"average_interval"`
	RequestPatterns    []RequestPattern       `json:"request_patterns"`
	TypicalLocations   []string               `json:"typical_locations"`
	TypicalTimeWindows []*TimeWindow          `json:"typical_time_windows"`
	UsualTimes         []TimeWindow           `json:"usual_times"`
	DeviceFingerprints []string               `json:"device_fingerprints"`
	RiskScore          float64                `json:"risk_score"`
	Metadata           map[string]interface{} `json:"metadata"`
	LastUpdated        time.Time              `json:"last_updated"`
}

// RequestPattern represents a typical request pattern
type RequestPattern struct {
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Frequency float64 `json:"frequency"`
	Timing    string  `json:"timing"`
}

// TimeWindow represents a time window for typical activity
type TimeWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Days  []string  `json:"days"`
}

// AnomalyDetector detects anomalies in requests and behavior
type AnomalyDetector struct {
	logger           *logger.Logger
	baselineMetrics  map[string]float64
	anomalyThreshold float64
}

// DecisionEngine makes autonomous security decisions
type DecisionEngine struct {
	logger     *logger.Logger
	ruleEngine *RuleEngine
	mlModels   map[string]interface{}
	confidence float64
}

// ActionExecutor executes security actions
type ActionExecutor struct {
	logger         *logger.Logger
	actionHandlers map[string]ActionHandler
}

// ActionHandler interface for different action types
type ActionHandler interface {
	Execute(ctx context.Context, decision *SecurityDecision) error
	GetType() string
}

// LearningModule handles machine learning and adaptation
type LearningModule struct {
	logger       *logger.Logger
	models       map[string]interface{}
	trainingData []TrainingExample
}

// TrainingExample represents a training example for ML
type TrainingExample struct {
	Features map[string]interface{} `json:"features"`
	Label    string                 `json:"label"`
	Weight   float64                `json:"weight"`
}

// ResponseFilter filters and sanitizes responses
type ResponseFilter struct {
	logger    *logger.Logger
	filters   []ResponseFilterFunc
	sanitizer *OutputSanitizer
}

// ResponseFilterFunc represents a response filter function
type ResponseFilterFunc func(response string) (string, bool)

// AlertManager manages security alerts and notifications
type AlertManager struct {
	logger        *logger.Logger
	alertChannels map[string]AlertChannel
	alertRules    []*AlertRule
}

// AlertChannel interface for different alert channels
type AlertChannel interface {
	SendAlert(ctx context.Context, alert *SecurityAlert) error
	GetType() string
}

// AlertRule represents an alert rule
type AlertRule struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Condition string                 `json:"condition"`
	Severity  string                 `json:"severity"`
	Channels  []string               `json:"channels"`
	Metadata  map[string]interface{} `json:"metadata"`
	Enabled   bool                   `json:"enabled"`
}

// SecurityAlert represents a security alert
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
}

// ContentAnalyzer analyzes content for threats
type ContentAnalyzer struct {
	logger              *logger.Logger
	patterns            []*ContentPattern
	mlClassifier        interface{}
	confidenceThreshold float64
}

// ContentPattern represents a content analysis pattern
type ContentPattern struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Pattern    string  `json:"pattern"`
	Type       string  `json:"type"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
}

// EncodingDetector detects character encoding
type EncodingDetector struct {
	logger *logger.Logger
}

// ThreatScanner scans for various threats
type ThreatScanner struct {
	logger   *logger.Logger
	scanners map[string]Scanner
}

// Scanner interface for different threat scanners
type Scanner interface {
	Scan(content string) (*ScanResult, error)
	GetType() string
}

// ScanResult represents a scan result
type ScanResult struct {
	Score      float64      `json:"score"`
	Threats    []string     `json:"threats"`
	Violations []*Violation `json:"violations"`
}

// Constructor functions

// NewBehaviorAnalyzer creates a new behavior analyzer
func NewBehaviorAnalyzer(logger *logger.Logger) *BehaviorAnalyzer {
	return &BehaviorAnalyzer{
		logger:           logger,
		behaviorProfiles: make(map[string]*BehaviorProfile),
		anomalyThreshold: 0.7,
	}
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(logger *logger.Logger) *AnomalyDetector {
	return &AnomalyDetector{
		logger:           logger,
		baselineMetrics:  make(map[string]float64),
		anomalyThreshold: 0.7,
	}
}

// NewDecisionEngine creates a new decision engine
func NewDecisionEngine(logger *logger.Logger) *DecisionEngine {
	return &DecisionEngine{
		logger:     logger,
		ruleEngine: NewRuleEngine(logger),
		mlModels:   make(map[string]interface{}),
		confidence: 0.8,
	}
}

// MakeDecision makes an autonomous security decision
func (de *DecisionEngine) MakeDecision(analysis *SecurityAnalysis) *SecurityDecision {
	decision := &SecurityDecision{
		ID:         "decision_" + analysis.ID,
		ThreatID:   analysis.ID,
		Confidence: de.confidence,
		Parameters: make(map[string]interface{}),
		ExecutedAt: time.Now(),
	}

	// Determine action based on risk score and threats
	if analysis.RiskScore >= 0.8 {
		decision.Action = "block_request"
		decision.Reasoning = "High risk score detected"
		decision.Confidence = 0.9
	} else if analysis.RiskScore >= 0.6 {
		decision.Action = "rate_limit"
		decision.Reasoning = "Medium risk score detected"
		decision.Confidence = 0.7
	} else if analysis.RiskScore >= 0.4 {
		decision.Action = "alert_admin"
		decision.Reasoning = "Moderate risk score detected"
		decision.Confidence = 0.6
	} else if len(analysis.Threats) > 0 {
		decision.Action = "log_incident"
		decision.Reasoning = "Threats detected but low risk score"
		decision.Confidence = 0.5
	} else {
		decision.Action = "allow"
		decision.Reasoning = "No significant threats detected"
		decision.Confidence = 0.9
	}

	// Check for specific threat types
	for _, threat := range analysis.Threats {
		if threat.Type == "prompt_injection" && threat.Confidence >= 0.8 {
			decision.Action = "block_request"
			decision.Reasoning = "High confidence prompt injection detected"
			decision.Confidence = 0.95
			break
		}
		if threat.Type == "sql_injection" && threat.Confidence >= 0.7 {
			decision.Action = "block_request"
			decision.Reasoning = "SQL injection attempt detected"
			decision.Confidence = 0.9
			break
		}
	}

	return decision
}

// NewActionExecutor creates a new action executor
func NewActionExecutor(logger *logger.Logger) *ActionExecutor {
	executor := &ActionExecutor{
		logger:         logger,
		actionHandlers: make(map[string]ActionHandler),
	}

	// Register default action handlers
	executor.registerDefaultHandlers()

	return executor
}

// Execute executes a security action
func (ae *ActionExecutor) Execute(ctx context.Context, decision *SecurityDecision) error {
	handler, exists := ae.actionHandlers[decision.Action]
	if !exists {
		ae.logger.WithField("action", decision.Action).Warn("No handler found for action")
		return nil // Don't fail, just log
	}

	return handler.Execute(ctx, decision)
}

// registerDefaultHandlers registers default action handlers
func (ae *ActionExecutor) registerDefaultHandlers() {
	ae.actionHandlers["block_request"] = &BlockRequestHandler{logger: ae.logger}
	ae.actionHandlers["rate_limit"] = &RateLimitHandler{logger: ae.logger}
	ae.actionHandlers["quarantine_session"] = &QuarantineSessionHandler{logger: ae.logger}
	ae.actionHandlers["alert_admin"] = &AlertAdminHandler{logger: ae.logger}
	ae.actionHandlers["log_incident"] = &LogIncidentHandler{logger: ae.logger}
	ae.actionHandlers["allow"] = &AllowHandler{logger: ae.logger}
}

// Default action handlers

// BlockRequestHandler handles request blocking
type BlockRequestHandler struct {
	logger *logger.Logger
}

func (h *BlockRequestHandler) Execute(ctx context.Context, decision *SecurityDecision) error {
	h.logger.WithFields(logger.Fields{
		"decision_id": decision.ID,
		"threat_id":   decision.ThreatID,
		"confidence":  decision.Confidence,
	}).Info("Blocking request due to security threat")
	return nil
}

func (h *BlockRequestHandler) GetType() string {
	return "block_request"
}

// RateLimitHandler handles rate limiting
type RateLimitHandler struct {
	logger *logger.Logger
}

func (h *RateLimitHandler) Execute(ctx context.Context, decision *SecurityDecision) error {
	h.logger.WithFields(logger.Fields{
		"decision_id": decision.ID,
		"threat_id":   decision.ThreatID,
	}).Info("Applying rate limit due to security concern")
	return nil
}

func (h *RateLimitHandler) GetType() string {
	return "rate_limit"
}

// QuarantineSessionHandler handles session quarantine
type QuarantineSessionHandler struct {
	logger *logger.Logger
}

func (h *QuarantineSessionHandler) Execute(ctx context.Context, decision *SecurityDecision) error {
	h.logger.WithFields(logger.Fields{
		"decision_id": decision.ID,
		"threat_id":   decision.ThreatID,
	}).Info("Quarantining session due to security threat")
	return nil
}

func (h *QuarantineSessionHandler) GetType() string {
	return "quarantine_session"
}

// AlertAdminHandler handles admin alerts
type AlertAdminHandler struct {
	logger *logger.Logger
}

func (h *AlertAdminHandler) Execute(ctx context.Context, decision *SecurityDecision) error {
	h.logger.WithFields(logger.Fields{
		"decision_id": decision.ID,
		"threat_id":   decision.ThreatID,
		"reasoning":   decision.Reasoning,
	}).Warn("Security alert: Admin notification required")
	return nil
}

func (h *AlertAdminHandler) GetType() string {
	return "alert_admin"
}

// LogIncidentHandler handles incident logging
type LogIncidentHandler struct {
	logger *logger.Logger
}

func (h *LogIncidentHandler) Execute(ctx context.Context, decision *SecurityDecision) error {
	h.logger.WithFields(logger.Fields{
		"decision_id": decision.ID,
		"threat_id":   decision.ThreatID,
		"reasoning":   decision.Reasoning,
	}).Info("Security incident logged")
	return nil
}

func (h *LogIncidentHandler) GetType() string {
	return "log_incident"
}

// AllowHandler handles allowed requests
type AllowHandler struct {
	logger *logger.Logger
}

func (h *AllowHandler) Execute(ctx context.Context, decision *SecurityDecision) error {
	h.logger.WithFields(logger.Fields{
		"decision_id": decision.ID,
	}).Debug("Request allowed")
	return nil
}

func (h *AllowHandler) GetType() string {
	return "allow"
}

// NewLearningModule creates a new learning module
func NewLearningModule(logger *logger.Logger) *LearningModule {
	return &LearningModule{
		logger:       logger,
		models:       make(map[string]interface{}),
		trainingData: make([]TrainingExample, 0),
	}
}

// Learn updates the learning module with new data
func (lm *LearningModule) Learn(example *TrainingExample) {
	lm.trainingData = append(lm.trainingData, *example)

	// Log learning activity
	lm.logger.WithFields(logger.Fields{
		"label":         example.Label,
		"weight":        example.Weight,
		"feature_count": len(example.Features),
	}).Debug("Learning from new example")

	// Trigger model retraining if we have enough data
	if len(lm.trainingData) > 0 && len(lm.trainingData)%100 == 0 {
		lm.retrainModels()
	}
}

// retrainModels retrains ML models with accumulated data
func (lm *LearningModule) retrainModels() {
	lm.logger.WithField("training_examples", len(lm.trainingData)).Info("Retraining security models")

	// In a real implementation, this would trigger actual ML model training
	// For now, we'll just log the activity

	// Clear old training data to prevent memory growth
	if len(lm.trainingData) > 1000 {
		// Keep only the most recent 500 examples
		lm.trainingData = lm.trainingData[len(lm.trainingData)-500:]
	}
}

// GetModelPrediction gets a prediction from a trained model
func (lm *LearningModule) GetModelPrediction(modelName string, features map[string]interface{}) (float64, error) {
	// Simplified implementation - in production this would use actual ML models

	// Basic heuristic-based prediction
	score := 0.0

	if modelName == "threat_detection" {
		// Simple threat scoring based on features
		if userAgent, ok := features["user_agent"].(string); ok {
			if strings.Contains(strings.ToLower(userAgent), "bot") {
				score += 0.3
			}
		}

		if payloadSize, ok := features["payload_size"].(float64); ok {
			if payloadSize > 10000 {
				score += 0.2
			}
		}

		if requestCount, ok := features["request_count"].(float64); ok {
			if requestCount > 100 {
				score += 0.1
			}
		}
	}

	// Ensure score is between 0 and 1
	if score > 1.0 {
		score = 1.0
	}

	return score, nil
}

// NewResponseFilter creates a new response filter
func NewResponseFilter(logger *logger.Logger) *ResponseFilter {
	// Create default filter config for output sanitizer
	filterConfig := &FilterConfig{
		EnableOutputSanitization: true,
		SanitizationLevel:        "standard",
		MaxOutputLength:          1000000,
	}

	filter := &ResponseFilter{
		logger:    logger,
		filters:   make([]ResponseFilterFunc, 0),
		sanitizer: NewOutputSanitizer(filterConfig, logger),
	}

	// Register default filters
	filter.registerDefaultFilters()

	return filter
}

// FilterResponse filters and sanitizes a response
func (rf *ResponseFilter) FilterResponse(response interface{}) (interface{}, error) {
	// Convert response to string for processing
	responseStr := rf.convertToString(response)

	// Apply all filters
	filtered := responseStr
	modified := false

	for _, filter := range rf.filters {
		newFiltered, wasModified := filter(filtered)
		if wasModified {
			filtered = newFiltered
			modified = true
		}
	}

	// Apply sanitization
	sanitized := rf.sanitizer.SanitizeOutput(filtered)
	if sanitized != filtered {
		modified = true
	}

	// Log if response was modified
	if modified {
		rf.logger.WithFields(logger.Fields{
			"original_length": len(responseStr),
			"filtered_length": len(sanitized),
		}).Debug("Response filtered and sanitized")
	}

	return sanitized, nil
}

// registerDefaultFilters registers default response filters
func (rf *ResponseFilter) registerDefaultFilters() {
	// Filter to remove sensitive information
	rf.filters = append(rf.filters, func(response string) (string, bool) {
		original := response

		// Remove potential API keys
		apiKeyPattern := `(?i)(api[_-]?key|token|secret)["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}`
		if matched, _ := regexp.MatchString(apiKeyPattern, response); matched {
			re := regexp.MustCompile(apiKeyPattern)
			response = re.ReplaceAllString(response, "$1: [REDACTED]")
		}

		// Remove potential passwords
		passwordPattern := `(?i)(password|passwd|pwd)["\s]*[:=]["\s]*[^"\s,}]{6,}`
		if matched, _ := regexp.MatchString(passwordPattern, response); matched {
			re := regexp.MustCompile(passwordPattern)
			response = re.ReplaceAllString(response, "$1: [REDACTED]")
		}

		return response, response != original
	})

	// Filter to remove internal error details
	rf.filters = append(rf.filters, func(response string) (string, bool) {
		original := response

		// Remove stack traces
		stackTracePattern := `(?s)at\s+[a-zA-Z0-9_.]+\([^)]*\)(\s*\n\s*at\s+[a-zA-Z0-9_.]+\([^)]*\))*`
		if matched, _ := regexp.MatchString(stackTracePattern, response); matched {
			re := regexp.MustCompile(stackTracePattern)
			response = re.ReplaceAllString(response, "[Stack trace removed]")
		}

		// Remove file paths
		filePathPattern := `[a-zA-Z]:\\[^"\s<>|]*|/[^"\s<>|]*`
		if matched, _ := regexp.MatchString(filePathPattern, response); matched {
			re := regexp.MustCompile(filePathPattern)
			response = re.ReplaceAllString(response, "[Path removed]")
		}

		return response, response != original
	})
}

// convertToString converts various types to string
func (rf *ResponseFilter) convertToString(data interface{}) string {
	switch v := data.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case map[string]interface{}:
		if jsonBytes, err := json.Marshal(v); err == nil {
			return string(jsonBytes)
		}
		return fmt.Sprintf("%+v", v)
	default:
		return fmt.Sprintf("%+v", v)
	}
}

// NewThreatIntelligence creates a new threat intelligence service
func NewThreatIntelligence(logger *logger.Logger) *ThreatIntelligence {
	return &ThreatIntelligence{
		logger:     logger,
		feeds:      make(map[string]ThreatFeed),
		indicators: make(map[string]*ThreatIndicator),
	}
}

// NewContentAnalyzer creates a new content analyzer
func NewContentAnalyzer(logger *logger.Logger) *ContentAnalyzer {
	return &ContentAnalyzer{
		logger:              logger,
		patterns:            make([]*ContentPattern, 0),
		confidenceThreshold: 0.7,
	}
}

// NewEncodingDetector creates a new encoding detector
func NewEncodingDetector(logger *logger.Logger) *EncodingDetector {
	return &EncodingDetector{
		logger: logger,
	}
}

// NewThreatScanner creates a new threat scanner
func NewThreatScanner(logger *logger.Logger) *ThreatScanner {
	return &ThreatScanner{
		logger:   logger,
		scanners: make(map[string]Scanner),
	}
}

// Method implementations

// AnalyzeRequest analyzes a request for behavioral anomalies
func (ba *BehaviorAnalyzer) AnalyzeRequest(req *SecurityRequest, conn interface{}) float64 {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	// Get or create behavior profile
	profile, exists := ba.behaviorProfiles[req.UserID]
	if !exists {
		profile = &BehaviorProfile{
			UserID:             req.UserID,
			CreatedAt:          time.Now(),
			LastActivity:       time.Now(),
			RequestCount:       0,
			AverageInterval:    0,
			TypicalLocations:   make([]string, 0),
			TypicalTimeWindows: make([]*TimeWindow, 0),
			RiskScore:          0.1,
		}
		ba.behaviorProfiles[req.UserID] = profile
	}

	// Update profile
	now := time.Now()
	interval := now.Sub(profile.LastActivity)
	profile.RequestCount++
	profile.LastActivity = now

	// Calculate average interval
	if profile.AverageInterval == 0 {
		profile.AverageInterval = interval
	} else {
		profile.AverageInterval = time.Duration(
			(int64(profile.AverageInterval) + int64(interval)) / 2,
		)
	}

	// Calculate anomaly score
	score := ba.calculateAnomalyScore(profile, req)

	// Update risk score
	profile.RiskScore = ba.updateRiskScore(profile.RiskScore, score)

	return score
}

// calculateAnomalyScore calculates anomaly score for user behavior
func (ba *BehaviorAnalyzer) calculateAnomalyScore(profile *BehaviorProfile, req *SecurityRequest) float64 {
	score := 0.0

	// Check request frequency anomaly
	if profile.RequestCount > 1 {
		expectedInterval := profile.AverageInterval
		actualInterval := time.Since(profile.LastActivity)

		if actualInterval < expectedInterval/10 { // Too frequent
			score += 0.3
		} else if actualInterval > expectedInterval*10 { // Too infrequent after being active
			score += 0.1
		}
	}

	// Check for rapid successive requests
	if profile.RequestCount > 10 && time.Since(profile.CreatedAt) < 1*time.Minute {
		score += 0.4
	}

	// Check missing user agent
	if req.UserAgent == "" {
		score += 0.2
	}

	// Check for large payloads
	if len(req.Body) > 10000 {
		score += 0.2
	}

	// Check for suspicious timing
	hour := time.Now().Hour()
	if hour < 6 || hour > 22 { // Outside normal hours
		score += 0.1
	}

	// Ensure score is between 0 and 1
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// updateRiskScore updates user risk score using exponential moving average
func (ba *BehaviorAnalyzer) updateRiskScore(currentScore, anomalyScore float64) float64 {
	alpha := 0.1
	newScore := alpha*anomalyScore + (1-alpha)*currentScore

	if newScore > 1.0 {
		newScore = 1.0
	} else if newScore < 0.0 {
		newScore = 0.0
	}

	return newScore
}

// DetectAnomalies detects anomalies in a request
func (ad *AnomalyDetector) DetectAnomalies(req interface{}) float64 {
	secReq, ok := req.(*SecurityRequest)
	if !ok {
		return 0.0
	}

	score := 0.0

	// Check payload size anomaly
	if len(secReq.Body) > 0 {
		payloadSize := float64(len(secReq.Body))
		baseline := ad.baselineMetrics["payload_size"]
		if baseline == 0 {
			baseline = 1024.0 // Default 1KB
		}

		if payloadSize > baseline*10 { // 10x larger than baseline
			score += 0.3
		}
	}

	// Check for suspicious headers
	if ad.hasSuspiciousHeaders(secReq) {
		score += 0.2
	}

	// Check for unusual user agent
	if ad.hasUnusualUserAgent(secReq) {
		score += 0.1
	}

	// Check for potential scanning behavior
	if ad.isPotentialScanning(secReq) {
		score += 0.4
	}

	// Ensure score is between 0 and 1
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// hasSuspiciousHeaders checks for suspicious HTTP headers
func (ad *AnomalyDetector) hasSuspiciousHeaders(req *SecurityRequest) bool {
	suspiciousHeaders := []string{
		"x-forwarded-for",
		"x-real-ip",
		"x-originating-ip",
		"x-cluster-client-ip",
	}

	headerCount := 0
	for header := range req.Headers {
		for _, suspicious := range suspiciousHeaders {
			if strings.ToLower(header) == suspicious {
				headerCount++
			}
		}
	}

	return headerCount > 2 // Multiple proxy headers might indicate spoofing
}

// hasUnusualUserAgent checks for unusual user agents
func (ad *AnomalyDetector) hasUnusualUserAgent(req *SecurityRequest) bool {
	userAgent := req.UserAgent
	if userAgent == "" {
		return true // Missing user agent is suspicious
	}

	// Check for bot/scanner patterns
	botPatterns := []string{
		"bot", "crawler", "spider", "scraper", "scanner",
		"curl", "wget", "python", "go-http-client",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range botPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}

	return false
}

// isPotentialScanning checks for scanning behavior
func (ad *AnomalyDetector) isPotentialScanning(req *SecurityRequest) bool {
	// Check for common scanning paths
	scanningPaths := []string{
		"/admin", "/wp-admin", "/.env", "/config",
		"/api/v1", "/swagger", "/graphql",
		"/.git", "/backup", "/test",
	}

	for _, path := range scanningPaths {
		if strings.Contains(req.URL, path) {
			return true
		}
	}

	// Check for parameter injection attempts
	if strings.Contains(req.Body, "UNION SELECT") ||
		strings.Contains(req.Body, "<script>") ||
		strings.Contains(req.Body, "javascript:") {
		return true
	}

	return false
}

// AnalyzeContent analyzes content for security violations
func (ca *ContentAnalyzer) AnalyzeContent(content string) []*Violation {
	var violations []*Violation

	// SQL Injection detection
	sqlViolations := ca.detectSQLInjection(content)
	violations = append(violations, sqlViolations...)

	// XSS detection
	xssViolations := ca.detectXSS(content)
	violations = append(violations, xssViolations...)

	// Command injection detection
	cmdViolations := ca.detectCommandInjection(content)
	violations = append(violations, cmdViolations...)

	// Path traversal detection
	pathViolations := ca.detectPathTraversal(content)
	violations = append(violations, pathViolations...)

	// Sensitive data detection
	dataViolations := ca.detectSensitiveData(content)
	violations = append(violations, dataViolations...)

	// Malicious URL detection
	urlViolations := ca.detectMaliciousURLs(content)
	violations = append(violations, urlViolations...)

	// Binary content detection
	binaryViolations := ca.detectBinaryContent(content)
	violations = append(violations, binaryViolations...)

	return violations
}

// detectSQLInjection detects SQL injection attempts
func (ca *ContentAnalyzer) detectSQLInjection(content string) []*Violation {
	var violations []*Violation

	sqlPatterns := []struct {
		pattern    string
		severity   string
		confidence float64
		message    string
	}{
		{`(?i)(union\s+select|select.*from|insert\s+into|update.*set|delete\s+from|drop\s+table)`, "high", 0.9, "SQL injection pattern detected"},
		{`(?i)(or|and)\s+\d+\s*=\s*\d+`, "high", 0.8, "SQL boolean injection detected"},
		{`(?i)'\s*(or|and)\s+'`, "high", 0.8, "SQL quote injection detected"},
		{`(?i)--\s*$`, "medium", 0.7, "SQL comment injection detected"},
		{`(?i)/\*.*?\*/`, "medium", 0.6, "SQL block comment detected"},
		{`(?i)(exec|execute|sp_|xp_)`, "high", 0.8, "SQL stored procedure execution detected"},
		{`(?i)(information_schema|sys\.|master\.)`, "medium", 0.7, "SQL system table access detected"},
	}

	for _, pattern := range sqlPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "sql_injection",
				Severity:   pattern.severity,
				Message:    pattern.message,
				Evidence:   ca.extractEvidence(content, pattern.pattern),
				Confidence: pattern.confidence,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// detectXSS detects cross-site scripting attempts
func (ca *ContentAnalyzer) detectXSS(content string) []*Violation {
	var violations []*Violation

	xssPatterns := []struct {
		pattern    string
		severity   string
		confidence float64
		message    string
	}{
		{`(?i)<script[^>]*>.*?</script>`, "high", 0.9, "Script tag injection detected"},
		{`(?i)javascript:`, "high", 0.8, "JavaScript protocol detected"},
		{`(?i)on\w+\s*=\s*['"]*[^'"]*['"]*`, "high", 0.8, "Event handler injection detected"},
		{`(?i)<iframe[^>]*>`, "medium", 0.7, "Iframe injection detected"},
		{`(?i)<object[^>]*>`, "medium", 0.7, "Object tag injection detected"},
		{`(?i)<embed[^>]*>`, "medium", 0.7, "Embed tag injection detected"},
		{`(?i)data:text/html`, "high", 0.8, "Data URI HTML injection detected"},
		{`(?i)vbscript:`, "high", 0.8, "VBScript protocol detected"},
		{`(?i)expression\s*\(`, "medium", 0.7, "CSS expression injection detected"},
	}

	for _, pattern := range xssPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "xss",
				Severity:   pattern.severity,
				Message:    pattern.message,
				Evidence:   ca.extractEvidence(content, pattern.pattern),
				Confidence: pattern.confidence,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// detectCommandInjection detects command injection attempts
func (ca *ContentAnalyzer) detectCommandInjection(content string) []*Violation {
	var violations []*Violation

	cmdPatterns := []struct {
		pattern    string
		severity   string
		confidence float64
		message    string
	}{
		{`(?i)(;|\||&|` + "`" + `)\s*(cat|ls|pwd|whoami|id|uname)`, "high", 0.9, "Unix command injection detected"},
		{`(?i)(;|\||&|` + "`" + `)\s*(dir|type|echo|net|ping)`, "high", 0.9, "Windows command injection detected"},
		{`(?i)(wget|curl|nc|netcat|telnet|ssh)`, "high", 0.8, "Network command injection detected"},
		{`(?i)(rm|del|format|fdisk)\s+`, "critical", 0.9, "Destructive command detected"},
		{`(?i)(bash|sh|cmd|powershell|python|perl|ruby)\s+`, "high", 0.8, "Shell interpreter execution detected"},
		{`(?i)\$\([^)]+\)`, "medium", 0.7, "Command substitution detected"},
		{`(?i)%[a-zA-Z_][a-zA-Z0-9_]*%`, "medium", 0.6, "Environment variable expansion detected"},
	}

	for _, pattern := range cmdPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "command_injection",
				Severity:   pattern.severity,
				Message:    pattern.message,
				Evidence:   ca.extractEvidence(content, pattern.pattern),
				Confidence: pattern.confidence,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// detectPathTraversal detects path traversal attempts
func (ca *ContentAnalyzer) detectPathTraversal(content string) []*Violation {
	var violations []*Violation

	pathPatterns := []struct {
		pattern    string
		severity   string
		confidence float64
		message    string
	}{
		{`\.\.\/|\.\.\\`, "high", 0.9, "Directory traversal pattern detected"},
		{`%2e%2e%2f|%2e%2e%5c`, "high", 0.9, "URL-encoded directory traversal detected"},
		{`\.\.%2f|\.\.%5c`, "high", 0.8, "Mixed encoding directory traversal detected"},
		{`\/etc\/passwd|\/etc\/shadow`, "critical", 0.9, "Unix system file access attempt"},
		{`\\windows\\system32|\\boot\.ini`, "critical", 0.9, "Windows system file access attempt"},
		{`file:\/\/\/`, "high", 0.8, "File protocol access detected"},
		{`\.\..*\/.*\/.*\/`, "medium", 0.7, "Deep directory traversal detected"},
	}

	for _, pattern := range pathPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "path_traversal",
				Severity:   pattern.severity,
				Message:    pattern.message,
				Evidence:   ca.extractEvidence(content, pattern.pattern),
				Confidence: pattern.confidence,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// detectSensitiveData detects sensitive data patterns
func (ca *ContentAnalyzer) detectSensitiveData(content string) []*Violation {
	var violations []*Violation

	sensitivePatterns := []struct {
		pattern    string
		severity   string
		confidence float64
		message    string
	}{
		{`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`, "high", 0.8, "Credit card number pattern detected"},
		{`\b\d{3}-\d{2}-\d{4}\b`, "high", 0.8, "SSN pattern detected"},
		{`(?i)(password|passwd|pwd)\s*[:=]\s*\S+`, "high", 0.9, "Password disclosure detected"},
		{`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*\S+`, "critical", 0.9, "API key disclosure detected"},
		{`(?i)(private[_-]?key|-----BEGIN.*PRIVATE.*KEY-----)`, "critical", 0.9, "Private key disclosure detected"},
		{`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, "medium", 0.6, "Email address detected"},
		{`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`, "low", 0.5, "IP address detected"},
		{`(?i)(bearer\s+[a-zA-Z0-9\-._~+/]+=*)`, "high", 0.8, "Bearer token detected"},
	}

	for _, pattern := range sensitivePatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "sensitive_data",
				Severity:   pattern.severity,
				Message:    pattern.message,
				Evidence:   ca.extractEvidence(content, pattern.pattern),
				Confidence: pattern.confidence,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// detectMaliciousURLs detects malicious URL patterns
func (ca *ContentAnalyzer) detectMaliciousURLs(content string) []*Violation {
	var violations []*Violation

	urlPatterns := []struct {
		pattern    string
		severity   string
		confidence float64
		message    string
	}{
		{`(?i)https?:\/\/[^\s]*\.(tk|ml|ga|cf|bit\.ly|tinyurl|t\.co)\/`, "medium", 0.7, "Suspicious URL shortener detected"},
		{`(?i)https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, "medium", 0.6, "Direct IP URL detected"},
		{`(?i)https?:\/\/[^\s]*\.(exe|scr|bat|cmd|com|pif)`, "high", 0.8, "Executable file URL detected"},
		{`(?i)data:application\/octet-stream`, "high", 0.8, "Binary data URL detected"},
		{`(?i)ftp:\/\/[^\s]*`, "medium", 0.6, "FTP URL detected"},
		{`(?i)file:\/\/[^\s]*`, "high", 0.8, "Local file URL detected"},
		{`(?i)https?:\/\/[^\s]*\.(onion)\/`, "medium", 0.7, "Tor hidden service URL detected"},
	}

	for _, pattern := range urlPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "malicious_url",
				Severity:   pattern.severity,
				Message:    pattern.message,
				Evidence:   ca.extractEvidence(content, pattern.pattern),
				Confidence: pattern.confidence,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// detectBinaryContent detects binary content in text
func (ca *ContentAnalyzer) detectBinaryContent(content string) []*Violation {
	var violations []*Violation

	// Check for high percentage of non-printable characters
	nonPrintableCount := 0
	totalChars := len(content)

	if totalChars == 0 {
		return violations
	}

	for _, char := range content {
		if !unicode.IsPrint(char) && char != '\n' && char != '\r' && char != '\t' {
			nonPrintableCount++
		}
	}

	nonPrintableRatio := float64(nonPrintableCount) / float64(totalChars)

	if nonPrintableRatio > 0.3 {
		violation := &Violation{
			ID:         uuid.New().String(),
			Type:       "binary_content",
			Severity:   "medium",
			Message:    "High percentage of binary content detected",
			Evidence:   fmt.Sprintf("Non-printable ratio: %.2f", nonPrintableRatio),
			Confidence: nonPrintableRatio,
			DetectedAt: time.Now(),
		}
		violations = append(violations, violation)
	}

	// Check for specific binary signatures
	binarySignatures := []struct {
		pattern    string
		severity   string
		confidence float64
		message    string
	}{
		{`\x00\x00\x00`, "medium", 0.7, "Null byte sequence detected"},
		{`\xFF\xFE|\xFE\xFF`, "low", 0.5, "Unicode BOM detected"},
		{`\x89PNG`, "low", 0.6, "PNG file signature detected"},
		{`\xFF\xD8\xFF`, "low", 0.6, "JPEG file signature detected"},
		{`GIF8[79]a`, "low", 0.6, "GIF file signature detected"},
		{`%PDF-`, "low", 0.6, "PDF file signature detected"},
	}

	for _, sig := range binarySignatures {
		if matched, _ := regexp.MatchString(sig.pattern, content); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "binary_signature",
				Severity:   sig.severity,
				Message:    sig.message,
				Evidence:   "Binary signature found",
				Confidence: sig.confidence,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// extractEvidence extracts evidence for a violation
func (ca *ContentAnalyzer) extractEvidence(content, pattern string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "Pattern compilation error"
	}

	matches := re.FindAllString(content, 3) // Limit to 3 matches
	if len(matches) == 0 {
		return "No matches found"
	}

	evidence := strings.Join(matches, ", ")
	if len(evidence) > 200 {
		evidence = evidence[:200] + "..."
	}

	return evidence
}

// DetectEncoding detects character encoding
func (ed *EncodingDetector) DetectEncoding(content string) string {
	if len(content) == 0 {
		return "unknown"
	}

	// Check for BOM (Byte Order Mark)
	if len(content) >= 3 {
		if content[:3] == "\xEF\xBB\xBF" {
			return "utf-8-bom"
		}
	}
	if len(content) >= 2 {
		if content[:2] == "\xFF\xFE" {
			return "utf-16le"
		}
		if content[:2] == "\xFE\xFF" {
			return "utf-16be"
		}
	}
	if len(content) >= 4 {
		if content[:4] == "\xFF\xFE\x00\x00" {
			return "utf-32le"
		}
		if content[:4] == "\x00\x00\xFE\xFF" {
			return "utf-32be"
		}
	}

	// Analyze character patterns
	asciiCount := 0
	utf8Count := 0
	latin1Count := 0
	binaryCount := 0
	totalBytes := len(content)

	for i := 0; i < totalBytes; i++ {
		b := content[i]

		// ASCII characters (0-127)
		if b <= 127 {
			asciiCount++
			if b < 32 && b != 9 && b != 10 && b != 13 {
				binaryCount++
			}
		} else {
			// Check for valid UTF-8 sequences
			if ed.isValidUTF8Sequence(content, i) {
				utf8Count++
				// Skip the rest of the UTF-8 sequence
				if b >= 0xC0 && b <= 0xDF {
					i++ // 2-byte sequence
				} else if b >= 0xE0 && b <= 0xEF {
					i += 2 // 3-byte sequence
				} else if b >= 0xF0 && b <= 0xF7 {
					i += 3 // 4-byte sequence
				}
			} else {
				// Might be Latin-1 or other single-byte encoding
				latin1Count++
			}
		}
	}

	// Calculate percentages
	asciiRatio := float64(asciiCount) / float64(totalBytes)
	utf8Ratio := float64(utf8Count) / float64(totalBytes)
	latin1Ratio := float64(latin1Count) / float64(totalBytes)
	binaryRatio := float64(binaryCount) / float64(totalBytes)

	// Check for suspicious control characters first
	if ed.containsControlCharacters(content) {
		return "suspicious"
	}

	// Determine encoding based on ratios
	if binaryRatio > 0.3 {
		return "binary"
	}

	if asciiRatio > 0.95 {
		return "ascii"
	}

	if utf8Ratio > 0.1 && (utf8Ratio+asciiRatio) > 0.8 {
		return "utf-8"
	}

	if latin1Ratio > 0.1 && (latin1Ratio+asciiRatio) > 0.8 {
		return "iso-8859-1"
	}

	// Default to UTF-8 if uncertain
	return "utf-8"
}

// isValidUTF8Sequence checks if a UTF-8 sequence starting at position i is valid
func (ed *EncodingDetector) isValidUTF8Sequence(content string, i int) bool {
	if i >= len(content) {
		return false
	}

	b := content[i]

	// Single byte (ASCII)
	if b <= 127 {
		return true
	}

	// Multi-byte sequences
	if b >= 0xC2 && b <= 0xDF {
		// 2-byte sequence
		if i+1 >= len(content) {
			return false
		}
		return (content[i+1] & 0xC0) == 0x80
	}

	if b >= 0xE0 && b <= 0xEF {
		// 3-byte sequence
		if i+2 >= len(content) {
			return false
		}
		return (content[i+1]&0xC0) == 0x80 && (content[i+2]&0xC0) == 0x80
	}

	if b >= 0xF0 && b <= 0xF7 {
		// 4-byte sequence
		if i+3 >= len(content) {
			return false
		}
		return (content[i+1]&0xC0) == 0x80 && (content[i+2]&0xC0) == 0x80 && (content[i+3]&0xC0) == 0x80
	}

	return false
}

// containsControlCharacters checks for suspicious control characters
func (ed *EncodingDetector) containsControlCharacters(content string) bool {
	suspiciousChars := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F}

	for _, char := range suspiciousChars {
		if strings.ContainsRune(content, rune(char)) {
			return true
		}
	}

	return false
}

// ScanForThreats scans content for threats
func (ts *ThreatScanner) ScanForThreats(content string) *ThreatScanResult {
	result := &ThreatScanResult{
		Score:      0.0,
		Violations: make([]*Violation, 0),
		Threats:    make([]string, 0),
	}

	// Malware signature detection
	malwareViolations := ts.scanMalwareSignatures(content)
	result.Violations = append(result.Violations, malwareViolations...)

	// Exploit pattern detection
	exploitViolations := ts.scanExploitPatterns(content)
	result.Violations = append(result.Violations, exploitViolations...)

	// Obfuscation detection
	obfuscationViolations := ts.scanObfuscation(content)
	result.Violations = append(result.Violations, obfuscationViolations...)

	// Suspicious encoding detection
	encodingViolations := ts.scanSuspiciousEncoding(content)
	result.Violations = append(result.Violations, encodingViolations...)

	// Calculate overall threat score
	result.Score = ts.calculateThreatScore(result.Violations)

	// Extract threat types
	threatTypes := make(map[string]bool)
	for _, violation := range result.Violations {
		threatTypes[violation.Type] = true
	}
	for threatType := range threatTypes {
		result.Threats = append(result.Threats, threatType)
	}

	return result
}

// scanMalwareSignatures scans for known malware signatures
func (ts *ThreatScanner) scanMalwareSignatures(content string) []*Violation {
	var violations []*Violation

	malwarePatterns := []struct {
		pattern    string
		severity   string
		confidence float64
		message    string
		threatType string
	}{
		{`(?i)(eval|exec|system|shell_exec|passthru|popen)\s*\(`, "critical", 0.9, "Code execution function detected", "code_execution"},
		{`(?i)base64_decode\s*\(`, "high", 0.8, "Base64 decode function detected", "obfuscation"},
		{`(?i)(wget|curl).*\|\s*(bash|sh|python|perl)`, "critical", 0.9, "Remote code execution pattern", "remote_execution"},
		{`(?i)nc\s+-[a-z]*e\s+`, "high", 0.8, "Netcat backdoor pattern", "backdoor"},
		{`(?i)/bin/(bash|sh|dash|zsh)\s+-[a-z]*i`, "high", 0.8, "Interactive shell pattern", "shell_access"},
		{`(?i)python\s+-c\s+["'].*["']`, "medium", 0.7, "Python one-liner execution", "code_execution"},
		{`(?i)powershell\s+.*-encodedcommand`, "high", 0.8, "PowerShell encoded command", "powershell_attack"},
		{`(?i)cmd\.exe\s+/c\s+`, "medium", 0.7, "Windows command execution", "command_execution"},
		{`(?i)(meterpreter|metasploit|cobalt.*strike)`, "critical", 0.9, "Known attack framework", "attack_framework"},
		{`(?i)(mimikatz|procdump|lsass)`, "critical", 0.9, "Credential dumping tool", "credential_theft"},
	}

	for _, pattern := range malwarePatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       pattern.threatType,
				Severity:   pattern.severity,
				Message:    pattern.message,
				Evidence:   ts.extractEvidence(content, pattern.pattern),
				Confidence: pattern.confidence,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// scanExploitPatterns scans for exploit patterns
func (ts *ThreatScanner) scanExploitPatterns(content string) []*Violation {
	var violations []*Violation

	// Check for shellcode patterns using byte sequences
	shellcodePatterns := [][]byte{
		{0x90, 0x90, 0x90, 0x90}, // NOP sled
		{0x31, 0xc0},             // xor eax, eax
		{0x31, 0xdb},             // xor ebx, ebx
	}

	contentBytes := []byte(content)
	for _, pattern := range shellcodePatterns {
		if ts.containsBytes(contentBytes, pattern) {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "shellcode",
				Severity:   "critical",
				Message:    "Shellcode pattern detected",
				Evidence:   "Binary shellcode sequence found",
				Confidence: 0.9,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
			break // Only add one shellcode violation
		}
	}

	// Regular exploit patterns
	exploitPatterns := []struct {
		pattern    string
		severity   string
		confidence float64
		message    string
		threatType string
	}{
		{`(?i)(AAAA|%41%41%41%41){4,}`, "high", 0.8, "Buffer overflow pattern", "buffer_overflow"},
		{`(?i)(\x00{4,}|\xff{4,})`, "medium", 0.7, "Suspicious byte pattern", "suspicious_bytes"},
		{`(?i)(ret2libc|rop.*chain|gadget)`, "high", 0.8, "Return-oriented programming", "rop_attack"},
		{`(?i)(format.*string|%n|%x.*%x.*%x)`, "high", 0.8, "Format string vulnerability", "format_string"},
		{`(?i)(heap.*spray|nop.*sled)`, "high", 0.8, "Heap spray or NOP sled", "memory_corruption"},
		{`(?i)(use.*after.*free|double.*free)`, "high", 0.8, "Memory corruption pattern", "memory_corruption"},
		{`(?i)(integer.*overflow|off.*by.*one)`, "medium", 0.7, "Memory safety issue", "memory_safety"},
	}

	for _, pattern := range exploitPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       pattern.threatType,
				Severity:   pattern.severity,
				Message:    pattern.message,
				Evidence:   ts.extractEvidence(content, pattern.pattern),
				Confidence: pattern.confidence,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// containsBytes checks if a byte slice contains a specific byte pattern
func (ts *ThreatScanner) containsBytes(data []byte, pattern []byte) bool {
	if len(pattern) == 0 || len(data) < len(pattern) {
		return false
	}

	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// scanObfuscation scans for obfuscation techniques
func (ts *ThreatScanner) scanObfuscation(content string) []*Violation {
	var violations []*Violation

	// Check for high entropy (possible encryption/encoding)
	entropy := ts.calculateEntropy(content)
	if entropy > 7.5 {
		violation := &Violation{
			ID:         uuid.New().String(),
			Type:       "high_entropy",
			Severity:   "medium",
			Message:    "High entropy content detected (possible encryption/obfuscation)",
			Evidence:   fmt.Sprintf("Entropy: %.2f", entropy),
			Confidence: (entropy - 7.0) / 1.0, // Scale 7.5-8.0 to 0.5-1.0
			DetectedAt: time.Now(),
		}
		violations = append(violations, violation)
	}

	obfuscationPatterns := []struct {
		pattern    string
		severity   string
		confidence float64
		message    string
	}{
		{`(?i)(chr\(|char\(|fromcharcode\().*[,+].*\)`, "medium", 0.7, "Character code obfuscation"},
		{`(?i)(unescape|decodeuri|atob)\s*\(`, "medium", 0.7, "URL/Base64 decoding obfuscation"},
		{`(?i)string\.fromcharcode\s*\(`, "medium", 0.7, "JavaScript character obfuscation"},
		{`(?i)document\.write\s*\(.*unescape`, "high", 0.8, "JavaScript write with unescape"},
		{`[a-zA-Z0-9+/]{50,}={0,2}`, "low", 0.5, "Possible Base64 encoded content"},
		{`(?i)\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}`, "medium", 0.6, "Hex encoded string"},
		{`(?i)%[0-9a-f]{2}.*%[0-9a-f]{2}.*%[0-9a-f]{2}`, "medium", 0.6, "URL encoded string"},
	}

	for _, pattern := range obfuscationPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "obfuscation",
				Severity:   pattern.severity,
				Message:    pattern.message,
				Evidence:   ts.extractEvidence(content, pattern.pattern),
				Confidence: pattern.confidence,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// scanSuspiciousEncoding scans for suspicious encoding patterns
func (ts *ThreatScanner) scanSuspiciousEncoding(content string) []*Violation {
	var violations []*Violation

	encodingPatterns := []struct {
		pattern    string
		severity   string
		confidence float64
		message    string
	}{
		{`(?i)\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}`, "medium", 0.6, "Unicode escape sequence obfuscation"},
		{`(?i)\\[0-7]{3}.*\\[0-7]{3}.*\\[0-7]{3}`, "medium", 0.6, "Octal escape sequence obfuscation"},
		{`(?i)&#x[0-9a-f]+;.*&#x[0-9a-f]+;`, "medium", 0.6, "HTML hex entity obfuscation"},
		{`(?i)&#[0-9]+;.*&#[0-9]+;`, "medium", 0.6, "HTML decimal entity obfuscation"},
		{`\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0b|\x0c|\x0e|\x0f`, "high", 0.8, "Suspicious control characters"},
		{`[\x80-\xff]{10,}`, "medium", 0.6, "High-bit character sequence"},
	}

	for _, pattern := range encodingPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "suspicious_encoding",
				Severity:   pattern.severity,
				Message:    pattern.message,
				Evidence:   ts.extractEvidence(content, pattern.pattern),
				Confidence: pattern.confidence,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// calculateThreatScore calculates overall threat score from violations
func (ts *ThreatScanner) calculateThreatScore(violations []*Violation) float64 {
	if len(violations) == 0 {
		return 0.0
	}

	var totalScore float64
	var maxScore float64

	for _, violation := range violations {
		var severityWeight float64
		switch violation.Severity {
		case "critical":
			severityWeight = 1.0
		case "high":
			severityWeight = 0.8
		case "medium":
			severityWeight = 0.6
		case "low":
			severityWeight = 0.4
		default:
			severityWeight = 0.2
		}

		score := violation.Confidence * severityWeight
		totalScore += score
		if score > maxScore {
			maxScore = score
		}
	}

	// Use a combination of average and maximum scores
	avgScore := totalScore / float64(len(violations))
	combinedScore := (avgScore + maxScore) / 2

	// Cap at 1.0
	if combinedScore > 1.0 {
		combinedScore = 1.0
	}

	return combinedScore
}

// calculateEntropy calculates Shannon entropy of content
func (ts *ThreatScanner) calculateEntropy(content string) float64 {
	if len(content) == 0 {
		return 0.0
	}

	// Count frequency of each byte
	freq := make(map[byte]int)
	for i := 0; i < len(content); i++ {
		freq[content[i]]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(content))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * (math.Log2(p))
		}
	}

	return entropy
}

// extractEvidence extracts evidence for a violation (ThreatScanner version)
func (ts *ThreatScanner) extractEvidence(content, pattern string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "Pattern compilation error"
	}

	matches := re.FindAllString(content, 3) // Limit to 3 matches
	if len(matches) == 0 {
		return "No matches found"
	}

	evidence := strings.Join(matches, ", ")
	if len(evidence) > 200 {
		evidence = evidence[:200] + "..."
	}

	return evidence
}

// SendAlert sends a security alert
func (am *AlertManager) SendAlert(ctx context.Context, decision *SecurityDecision) {
	am.logger.WithField("decision_id", decision.ID).Info("Security alert sent")
}
