package security

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// AIFirewall intelligent web application firewall with ML capabilities
type AIFirewall struct {
	logger             *logger.Logger
	config             *FirewallConfig
	ruleEngine         *RuleEngine
	threatIntelligence *ThreatIntelligence
	behaviorAnalyzer   *BehaviorAnalyzer
	anomalyDetector    *AnomalyDetector
	blockList          *BlockList
	allowList          *AllowList
	rateLimiter        *IntelligentRateLimiter
	sessionTracker     *SessionTracker
	mu                 sync.RWMutex
	activeConnections  map[string]*Connection
	blockedAttempts    map[string]int
}

// FirewallConfig configuration for AI firewall
type FirewallConfig struct {
	EnableMLDetection      bool          `json:"enable_ml_detection"`
	EnableBehaviorAnalysis bool          `json:"enable_behavior_analysis"`
	EnableAnomalyDetection bool          `json:"enable_anomaly_detection"`
	EnableGeoBlocking      bool          `json:"enable_geo_blocking"`
	EnableRateLimiting     bool          `json:"enable_rate_limiting"`
	BlockThreshold         float64       `json:"block_threshold"`
	LearningMode           bool          `json:"learning_mode"`
	AutoUpdateRules        bool          `json:"auto_update_rules"`
	MaxConnectionsPerIP    int           `json:"max_connections_per_ip"`
	ConnectionTimeout      time.Duration `json:"connection_timeout"`
	BlockDuration          time.Duration `json:"block_duration"`
	LogAllRequests         bool          `json:"log_all_requests"`
	EnableThreatSharing    bool          `json:"enable_threat_sharing"`
}

// RuleEngine manages firewall rules and policies
type RuleEngine struct {
	logger      *logger.Logger
	rules       []*FirewallRule
	customRules []*CustomRule
	mlRules     []*MLRule
	ruleCache   map[string]*RuleResult
	lastUpdated time.Time
}

// FirewallRule represents a firewall rule
type FirewallRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Pattern    string                 `json:"pattern"`
	Action     string                 `json:"action"`
	Priority   int                    `json:"priority"`
	Enabled    bool                   `json:"enabled"`
	Conditions []*RuleCondition       `json:"conditions"`
	Metadata   map[string]interface{} `json:"metadata"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// RuleCondition represents a condition for rule matching
type RuleCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Negate   bool        `json:"negate"`
}

// Connection represents an active connection
type Connection struct {
	ID           string                 `json:"id"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	SessionID    string                 `json:"session_id"`
	RequestCount int                    `json:"request_count"`
	ThreatScore  float64                `json:"threat_score"`
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
	Blocked      bool                   `json:"blocked"`
	BlockReason  string                 `json:"block_reason"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// FirewallDecision represents a firewall decision
type FirewallDecision struct {
	ID              string                 `json:"id"`
	Action          string                 `json:"action"`
	Reason          string                 `json:"reason"`
	Confidence      float64                `json:"confidence"`
	TriggeredRules  []*TriggeredRule       `json:"triggered_rules"`
	ThreatScore     float64                `json:"threat_score"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
	DecisionTime    time.Time              `json:"decision_time"`
}

// TriggeredRule represents a rule that was triggered
type TriggeredRule struct {
	RuleID     string  `json:"rule_id"`
	RuleName   string  `json:"rule_name"`
	RuleType   string  `json:"rule_type"`
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`
	Action     string  `json:"action"`
}

// CustomRule represents a custom firewall rule
type CustomRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Pattern     string                 `json:"pattern"`
	Action      string                 `json:"action"`
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	CreatedBy   string                 `json:"created_by"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MLRule represents a machine learning-based rule
type MLRule struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	ModelType    string                 `json:"model_type"`
	ModelVersion string                 `json:"model_version"`
	Threshold    float64                `json:"threshold"`
	Action       string                 `json:"action"`
	Enabled      bool                   `json:"enabled"`
	Accuracy     float64                `json:"accuracy"`
	LastTrained  time.Time              `json:"last_trained"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// RuleResult represents the result of rule evaluation
type RuleResult struct {
	RuleID     string                 `json:"rule_id"`
	RuleName   string                 `json:"rule_name"`
	RuleType   string                 `json:"rule_type"`
	Matched    bool                   `json:"matched"`
	Confidence float64                `json:"confidence"`
	Evidence   string                 `json:"evidence"`
	Action     string                 `json:"action"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// ThreatIntelligence provides threat intelligence capabilities
type ThreatIntelligence struct {
	logger      *logger.Logger
	feeds       map[string]ThreatFeed
	indicators  map[string]*ThreatIndicator
	lastUpdated time.Time
	mu          sync.RWMutex
}

// ThreatFeed represents a threat intelligence feed
type ThreatFeed struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	URL         string        `json:"url"`
	Type        string        `json:"type"`
	Enabled     bool          `json:"enabled"`
	LastUpdated time.Time     `json:"last_updated"`
	UpdateFreq  time.Duration `json:"update_frequency"`
}

// ThreatIndicator represents an indicator of compromise
type ThreatIndicator struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`        // ip, domain, hash, url
	Value       string    `json:"value"`       // the actual indicator
	Confidence  float64   `json:"confidence"`  // 0.0 to 1.0
	Severity    string    `json:"severity"`    // low, medium, high, critical
	Source      string    `json:"source"`      // threat feed source
	Description string    `json:"description"` // threat description
	Tags        []string  `json:"tags"`        // malware family, campaign, etc.
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// IntelligentRateLimiter provides intelligent rate limiting
type IntelligentRateLimiter struct {
	logger         *logger.Logger
	rateLimits     map[string]*RateLimit
	adaptiveLimits map[string]*AdaptiveLimit
	mu             sync.RWMutex
}

// RateLimit represents a rate limit configuration
type RateLimit struct {
	Requests int           `json:"requests"`
	Window   time.Duration `json:"window"`
	Current  int           `json:"current"`
	ResetAt  time.Time     `json:"reset_at"`
}

// AdaptiveLimit represents an adaptive rate limit
type AdaptiveLimit struct {
	BaseLimit        int       `json:"base_limit"`
	CurrentLimit     int       `json:"current_limit"`
	ThreatScore      float64   `json:"threat_score"`
	LastAdjusted     time.Time `json:"last_adjusted"`
	AdjustmentFactor float64   `json:"adjustment_factor"`
}

// SessionTracker tracks user sessions
type SessionTracker struct {
	logger   *logger.Logger
	sessions map[string]*SessionInfo
	mu       sync.RWMutex
}

// SessionInfo represents session information
type SessionInfo struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
	RequestCount int                    `json:"request_count"`
	ThreatScore  float64                `json:"threat_score"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// BlockList manages blocked IP addresses and entities
type BlockList struct {
	logger      *logger.Logger
	blockedIPs  map[string]*BlockEntry
	blockedASNs map[string]*BlockEntry
	mu          sync.RWMutex
}

// AllowList manages allowed IP addresses and entities
type AllowList struct {
	logger      *logger.Logger
	allowedIPs  map[string]*AllowEntry
	allowedASNs map[string]*AllowEntry
	mu          sync.RWMutex
}

// BlockEntry represents a blocked entity
type BlockEntry struct {
	ID        string    `json:"id"`
	Value     string    `json:"value"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AllowEntry represents an allowed entity
type AllowEntry struct {
	ID        string    `json:"id"`
	Value     string    `json:"value"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// NewAIFirewall creates a new AI-powered firewall
func NewAIFirewall(config *FirewallConfig, logger *logger.Logger) *AIFirewall {
	firewall := &AIFirewall{
		logger:            logger,
		config:            config,
		activeConnections: make(map[string]*Connection),
		blockedAttempts:   make(map[string]int),
	}

	// Initialize components
	firewall.ruleEngine = NewRuleEngine(logger)
	firewall.threatIntelligence = NewThreatIntelligence(logger)
	firewall.behaviorAnalyzer = NewBehaviorAnalyzer(logger)
	firewall.anomalyDetector = NewAnomalyDetector(logger)
	firewall.blockList = NewBlockList(logger)
	firewall.allowList = NewAllowList(logger)
	firewall.rateLimiter = NewIntelligentRateLimiter(logger)
	firewall.sessionTracker = NewSessionTracker(logger)

	// Load default rules
	firewall.loadDefaultRules()

	return firewall
}

// ProcessRequest processes an incoming request through the firewall
func (af *AIFirewall) ProcessRequest(ctx context.Context, req *http.Request) (*FirewallDecision, error) {
	startTime := time.Now()

	// Extract request information
	requestInfo := af.extractRequestInfo(req)

	// Track connection
	connection := af.trackConnection(requestInfo)

	// Initialize decision
	decision := &FirewallDecision{
		ID:           uuid.New().String(),
		DecisionTime: startTime,
		Metadata:     make(map[string]interface{}),
	}

	// Check allow list first
	if af.allowList.IsAllowed(requestInfo.IPAddress) {
		decision.Action = "allow"
		decision.Reason = "IP in allow list"
		decision.Confidence = 1.0
		return decision, nil
	}

	// Check block list
	if af.blockList.IsBlocked(requestInfo.IPAddress) {
		decision.Action = "block"
		decision.Reason = "IP in block list"
		decision.Confidence = 1.0
		return decision, nil
	}

	// Rate limiting check
	if af.config.EnableRateLimiting {
		if !af.rateLimiter.IsAllowed(requestInfo.IPAddress) {
			decision.Action = "block"
			decision.Reason = "Blocked due to rate limit exceeded"
			decision.Confidence = 0.9
			af.updateBlockedAttempts(requestInfo.IPAddress)
			return decision, nil
		}
	}

	// Connection limit check
	if af.exceedsConnectionLimit(requestInfo.IPAddress) {
		decision.Action = "block"
		decision.Reason = "Connection limit exceeded"
		decision.Confidence = 0.8
		return decision, nil
	}

	// Rule engine evaluation
	ruleResults := af.ruleEngine.EvaluateRequest(requestInfo)
	decision.TriggeredRules = af.processRuleResults(ruleResults)

	// ML-based threat detection
	if af.config.EnableMLDetection {
		mlThreatScore := af.calculateMLThreatScore(requestInfo, connection)
		decision.ThreatScore = mlThreatScore
	}

	// Behavior analysis
	if af.config.EnableBehaviorAnalysis {
		// Convert RequestInfo to SecurityRequest for behavior analysis
		securityReq := &SecurityRequest{
			ID:        requestInfo.ID,
			Method:    requestInfo.Method,
			URL:       requestInfo.URL,
			IPAddress: requestInfo.IPAddress,
			UserAgent: requestInfo.UserAgent,
			Headers:   requestInfo.Headers,
			Body:      requestInfo.Body,
			Timestamp: requestInfo.Timestamp,
		}
		behaviorScore := af.behaviorAnalyzer.AnalyzeRequest(securityReq, connection)
		// Use weighted combination instead of simple average
		decision.ThreatScore = decision.ThreatScore*0.9 + behaviorScore*0.1
	}

	// Anomaly detection
	if af.config.EnableAnomalyDetection {
		anomalyScore := af.anomalyDetector.DetectAnomalies(requestInfo)
		// Use weighted combination instead of simple average
		decision.ThreatScore = decision.ThreatScore*0.9 + anomalyScore*0.1
	}

	// Make final decision
	decision = af.makeFinalDecision(decision, requestInfo)

	// Update connection tracking
	af.updateConnection(connection, decision)

	// Log decision
	af.logDecision(decision, requestInfo)

	return decision, nil
}

// extractRequestInfo extracts relevant information from the request
func (af *AIFirewall) extractRequestInfo(req *http.Request) *RequestInfo {
	return &RequestInfo{
		ID:        uuid.New().String(),
		Method:    req.Method,
		URL:       req.URL.String(),
		IPAddress: af.getClientIP(req),
		UserAgent: req.UserAgent(),
		Headers:   af.extractHeaders(req),
		Body:      af.extractBody(req),
		Timestamp: time.Now(),
	}
}

// RequestInfo represents extracted request information
type RequestInfo struct {
	ID        string            `json:"id"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	IPAddress string            `json:"ip_address"`
	UserAgent string            `json:"user_agent"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Timestamp time.Time         `json:"timestamp"`
}

// trackConnection tracks connection information
func (af *AIFirewall) trackConnection(req *RequestInfo) *Connection {
	af.mu.Lock()
	defer af.mu.Unlock()

	connection, exists := af.activeConnections[req.IPAddress]
	if !exists {
		connection = &Connection{
			ID:           uuid.New().String(),
			IPAddress:    req.IPAddress,
			UserAgent:    req.UserAgent,
			RequestCount: 0,
			ThreatScore:  0.0,
			FirstSeen:    req.Timestamp,
			Metadata:     make(map[string]interface{}),
		}
		af.activeConnections[req.IPAddress] = connection
	}

	connection.RequestCount++
	connection.LastSeen = req.Timestamp

	return connection
}

// calculateMLThreatScore calculates ML-based threat score
func (af *AIFirewall) calculateMLThreatScore(req *RequestInfo, conn *Connection) float64 {
	score := 0.0

	// Threat intelligence check (highest priority)
	if af.threatIntelligence != nil {
		threatScore := af.threatIntelligence.GetThreatScore(req.IPAddress, "ip")

		score += threatScore * 0.8 // 80% weight for threat intelligence
	}

	// URL analysis
	score += af.analyzeURL(req.URL) * 0.2

	// Header analysis
	score += af.analyzeHeaders(req.Headers) * 0.15

	// User agent analysis
	score += af.analyzeUserAgent(req.UserAgent) * 0.15

	// Request frequency analysis
	score += af.analyzeRequestFrequency(conn) * 0.1

	// Ensure score doesn't exceed 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// analyzeURL analyzes URL for suspicious patterns
func (af *AIFirewall) analyzeURL(url string) float64 {
	suspiciousPatterns := []string{
		`(?i)\.\.\/`,                     // Directory traversal
		`(?i)(union|select|insert|drop)`, // SQL injection
		`(?i)<script`,                    // XSS
		`(?i)javascript:`,                // JavaScript injection
		`(?i)data:`,                      // Data URI
		`(?i)file:\/\/`,                  // File protocol
	}

	score := 0.0
	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, url); matched {
			score += 0.2
		}
	}

	return score
}

// analyzeHeaders analyzes headers for suspicious patterns
func (af *AIFirewall) analyzeHeaders(headers map[string]string) float64 {
	score := 0.0

	// Check for suspicious headers
	suspiciousHeaders := []string{
		"x-forwarded-for",
		"x-real-ip",
		"x-originating-ip",
	}

	for _, header := range suspiciousHeaders {
		if _, exists := headers[header]; exists {
			score += 0.1
		}
	}

	// Check for missing security headers
	securityHeaders := []string{
		"user-agent",
		"accept",
		"accept-language",
	}

	missing := 0
	for _, header := range securityHeaders {
		if _, exists := headers[header]; !exists {
			missing++
		}
	}

	if missing > 1 {
		score += 0.3
	}

	return score
}

// analyzeUserAgent analyzes user agent for suspicious patterns
func (af *AIFirewall) analyzeUserAgent(userAgent string) float64 {
	if userAgent == "" {
		return 0.5
	}

	suspiciousPatterns := []string{
		`(?i)bot`,
		`(?i)crawler`,
		`(?i)spider`,
		`(?i)scanner`,
		`(?i)curl`,
		`(?i)wget`,
		`(?i)python`,
		`(?i)perl`,
	}

	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, userAgent); matched {
			return 0.4
		}
	}

	return 0.0
}

// analyzeRequestFrequency analyzes request frequency for anomalies
func (af *AIFirewall) analyzeRequestFrequency(conn *Connection) float64 {
	duration := time.Since(conn.FirstSeen)
	if duration.Minutes() < 1 {
		return 0.0
	}

	requestsPerMinute := float64(conn.RequestCount) / duration.Minutes()

	switch {
	case requestsPerMinute > 100:
		return 0.9
	case requestsPerMinute > 50:
		return 0.7
	case requestsPerMinute > 20:
		return 0.5
	case requestsPerMinute > 10:
		return 0.3
	default:
		return 0.0
	}
}

// analyzeGeolocation analyzes IP geolocation for risk
func (af *AIFirewall) analyzeGeolocation(ipAddress string) float64 {
	// This would integrate with a geolocation service
	// For now, return a basic analysis
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return 0.5
	}

	// Check for private IPs
	if ip.IsPrivate() {
		return 0.0
	}

	// Basic risk scoring based on IP ranges
	// This would be enhanced with real geolocation data
	return 0.1
}

// makeFinalDecision makes the final firewall decision
func (af *AIFirewall) makeFinalDecision(decision *FirewallDecision, req *RequestInfo) *FirewallDecision {
	// Determine action based on threat score and triggered rules
	if decision.ThreatScore >= af.config.BlockThreshold {
		decision.Action = "block"
		decision.Reason = "High threat score detected"
		decision.Confidence = decision.ThreatScore
	} else if len(decision.TriggeredRules) > 0 {
		// Check if any critical rules were triggered
		for _, rule := range decision.TriggeredRules {
			if rule.Action == "block" && rule.Confidence >= 0.3 {
				decision.Action = "block"
				decision.Reason = fmt.Sprintf("Critical rule triggered: %s", rule.RuleName)
				decision.Confidence = rule.Confidence
				break
			}
		}
	}

	// Default to allow if no blocking conditions
	if decision.Action == "" {
		decision.Action = "allow"
		decision.Reason = "No threats detected"
		decision.Confidence = 1.0 - decision.ThreatScore
	}

	// Generate recommendations
	decision.Recommendations = af.generateRecommendations(decision)

	return decision
}

// Helper methods
func (af *AIFirewall) getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	return ip
}

func (af *AIFirewall) extractHeaders(req *http.Request) map[string]string {
	headers := make(map[string]string)
	for name, values := range req.Header {
		if len(values) > 0 {
			headers[strings.ToLower(name)] = values[0]
		}
	}
	return headers
}

func (af *AIFirewall) extractBody(req *http.Request) string {
	if req.Body == nil {
		return ""
	}

	// Read body with size limit to prevent DoS
	const maxBodySize = 1024 * 1024 // 1MB limit

	// Read the body
	bodyBytes := make([]byte, maxBodySize)
	n, err := req.Body.Read(bodyBytes)
	if err != nil && err.Error() != "EOF" {
		af.logger.WithError(err).Debug("Failed to read request body")
		return ""
	}

	// Close the original body
	req.Body.Close()

	// Reset body for downstream handlers
	bodyStr := string(bodyBytes[:n])
	req.Body = &readCloser{strings.NewReader(bodyStr)}

	return bodyStr
}

// Helper type for resetting request body
type readCloser struct {
	*strings.Reader
}

func (r *readCloser) Close() error {
	return nil
}

func (af *AIFirewall) exceedsConnectionLimit(ipAddress string) bool {
	af.mu.RLock()
	defer af.mu.RUnlock()

	count := 0
	for _, conn := range af.activeConnections {
		if conn.IPAddress == ipAddress && !conn.Blocked {
			count++
		}
	}

	return count > af.config.MaxConnectionsPerIP
}

func (af *AIFirewall) updateBlockedAttempts(ipAddress string) {
	af.mu.Lock()
	defer af.mu.Unlock()
	af.blockedAttempts[ipAddress]++
}

func (af *AIFirewall) processRuleResults(results []*RuleResult) []*TriggeredRule {
	var triggered []*TriggeredRule
	for _, result := range results {
		if result.Matched {
			triggered = append(triggered, &TriggeredRule{
				RuleID:     result.RuleID,
				RuleName:   result.RuleName,
				RuleType:   result.RuleType,
				Confidence: result.Confidence,
				Evidence:   result.Evidence,
				Action:     result.Action,
			})
		}
	}
	return triggered
}

func (af *AIFirewall) updateConnection(conn *Connection, decision *FirewallDecision) {
	af.mu.Lock()
	defer af.mu.Unlock()

	conn.ThreatScore = decision.ThreatScore
	if decision.Action == "block" {
		conn.Blocked = true
		conn.BlockReason = decision.Reason
	}
}

func (af *AIFirewall) logDecision(decision *FirewallDecision, req *RequestInfo) {
	af.logger.WithFields(logger.Fields{
		"decision_id":     decision.ID,
		"action":          decision.Action,
		"reason":          decision.Reason,
		"confidence":      decision.Confidence,
		"threat_score":    decision.ThreatScore,
		"ip_address":      req.IPAddress,
		"url":             req.URL,
		"triggered_rules": len(decision.TriggeredRules),
	}).Info("Firewall decision made")
}

func (af *AIFirewall) generateRecommendations(decision *FirewallDecision) []string {
	var recommendations []string

	if decision.Action == "block" {
		recommendations = append(recommendations, "Monitor IP for continued suspicious activity")
		recommendations = append(recommendations, "Consider adding IP to permanent block list")
	}

	if decision.ThreatScore > 0.5 {
		recommendations = append(recommendations, "Increase monitoring for this source")
	}

	return recommendations
}

func (af *AIFirewall) loadDefaultRules() {
	// Load default firewall rules - delegated to RuleEngine
	af.logger.Info("Default firewall rules loaded via RuleEngine")

	// Initialize threat intelligence with sample data
	if af.threatIntelligence != nil {
		err := af.threatIntelligence.UpdateThreatFeeds()
		if err != nil {
			af.logger.WithError(err).Error("Failed to update threat intelligence feeds")
		}
	}
}

// ThreatIntelligence methods

// CheckThreatIntelligence checks if an IP or indicator is in threat intelligence
func (ti *ThreatIntelligence) CheckThreatIntelligence(indicator, indicatorType string) *ThreatIndicator {
	ti.mu.RLock()
	defer ti.mu.RUnlock()

	// Check if indicator exists in our database
	if threatIndicator, exists := ti.indicators[indicator]; exists {
		// Update last seen
		threatIndicator.LastSeen = time.Now()
		return threatIndicator
	}

	return nil
}

// AddThreatIndicator adds a new threat indicator
func (ti *ThreatIntelligence) AddThreatIndicator(indicator *ThreatIndicator) {
	ti.mu.Lock()
	defer ti.mu.Unlock()

	ti.indicators[indicator.Value] = indicator
	ti.lastUpdated = time.Now()

	ti.logger.WithFields(logger.Fields{
		"type":       indicator.Type,
		"value":      indicator.Value,
		"severity":   indicator.Severity,
		"confidence": indicator.Confidence,
	}).Info("Threat indicator added")
}

// UpdateThreatFeeds updates threat intelligence feeds
func (ti *ThreatIntelligence) UpdateThreatFeeds() error {
	ti.mu.Lock()
	defer ti.mu.Unlock()

	// In a real implementation, this would fetch from external threat feeds
	// For now, we'll add some sample indicators

	sampleIndicators := []*ThreatIndicator{
		{
			ID:          uuid.New().String(),
			Type:        "ip",
			Value:       "192.0.2.1",
			Confidence:  0.9,
			Severity:    "high",
			Source:      "internal",
			Description: "Known malicious IP",
			Tags:        []string{"malware", "botnet"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		},
		{
			ID:          uuid.New().String(),
			Type:        "domain",
			Value:       "malicious.example.com",
			Confidence:  0.8,
			Severity:    "medium",
			Source:      "internal",
			Description: "Suspicious domain",
			Tags:        []string{"phishing"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		},
	}

	for _, indicator := range sampleIndicators {
		ti.indicators[indicator.Value] = indicator
	}

	ti.lastUpdated = time.Now()
	ti.logger.WithField("indicator_count", len(sampleIndicators)).Info("Threat intelligence feeds updated")

	return nil
}

// GetThreatScore calculates a threat score for an indicator
func (ti *ThreatIntelligence) GetThreatScore(indicator, indicatorType string) float64 {
	threatIndicator := ti.CheckThreatIntelligence(indicator, indicatorType)
	if threatIndicator == nil {

		return 0.0
	}

	// Calculate threat score based on confidence and severity
	baseScore := threatIndicator.Confidence

	switch threatIndicator.Severity {
	case "critical":
		baseScore *= 1.0
	case "high":
		baseScore *= 0.8
	case "medium":
		baseScore *= 0.6
	case "low":
		baseScore *= 0.4
	default:
		baseScore *= 0.2
	}

	return baseScore
}

// GetThreatIntelligenceStats returns threat intelligence statistics
func (ti *ThreatIntelligence) GetThreatIntelligenceStats() map[string]interface{} {
	ti.mu.RLock()
	defer ti.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_indicators"] = len(ti.indicators)
	stats["last_updated"] = ti.lastUpdated

	// Count by type and severity
	typeCount := make(map[string]int)
	severityCount := make(map[string]int)

	for _, indicator := range ti.indicators {
		typeCount[indicator.Type]++
		severityCount[indicator.Severity]++
	}

	stats["by_type"] = typeCount
	stats["by_severity"] = severityCount

	return stats
}

// Supporting component implementations

// NewRuleEngine creates a new rule engine
func NewRuleEngine(logger *logger.Logger) *RuleEngine {
	engine := &RuleEngine{
		logger:      logger,
		rules:       make([]*FirewallRule, 0),
		customRules: make([]*CustomRule, 0),
		mlRules:     make([]*MLRule, 0),
		ruleCache:   make(map[string]*RuleResult),
		lastUpdated: time.Now(),
	}

	// Load default rules
	engine.loadDefaultRules()

	return engine
}

// loadDefaultRules loads default firewall rules
func (re *RuleEngine) loadDefaultRules() {
	// SQL Injection detection rule
	sqlInjectionRule := &FirewallRule{
		ID:       "sql_injection_basic",
		Name:     "Basic SQL Injection Detection",
		Type:     "pattern",
		Pattern:  `(?i)(union\s+select|select.*from|insert\s+into|update.*set|delete\s+from|drop\s+table)`,
		Action:   "block",
		Priority: 100,
		Enabled:  true,
		Conditions: []*RuleCondition{
			{Field: "body", Operator: "matches", Value: `(?i)(union\s+select|select.*from|insert\s+into|update.*set|delete\s+from|drop\s+table)`},
		},
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// XSS detection rule
	xssRule := &FirewallRule{
		ID:       "xss_basic",
		Name:     "Basic XSS Detection",
		Type:     "pattern",
		Pattern:  `(?i)<script[^>]*>|javascript:|on\w+\s*=`,
		Action:   "block",
		Priority: 90,
		Enabled:  true,
		Conditions: []*RuleCondition{
			{Field: "body", Operator: "matches", Value: `(?i)<script[^>]*>|javascript:|on\w+\s*=`},
		},
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Path traversal detection rule
	pathTraversalRule := &FirewallRule{
		ID:       "path_traversal",
		Name:     "Path Traversal Detection",
		Type:     "pattern",
		Pattern:  `\.\./|\.\.\\\|%2e%2e%2f|%2e%2e%5c`,
		Action:   "block",
		Priority: 85,
		Enabled:  true,
		Conditions: []*RuleCondition{
			{Field: "url", Operator: "matches", Value: `\.\./|\.\.\\\|%2e%2e%2f|%2e%2e%5c`},
		},
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Command injection detection rule
	cmdInjectionRule := &FirewallRule{
		ID:       "command_injection",
		Name:     "Command Injection Detection",
		Type:     "pattern",
		Pattern:  `(?i)(;|\||&|` + "`" + `)\s*(cat|ls|pwd|whoami|id|uname|wget|curl|nc|netcat|bash|sh|cmd|powershell)`,
		Action:   "block",
		Priority: 95,
		Enabled:  true,
		Conditions: []*RuleCondition{
			{Field: "body", Operator: "matches", Value: `(?i)(;|\||&|` + "`" + `)\s*(cat|ls|pwd|whoami|id|uname|wget|curl|nc|netcat|bash|sh|cmd|powershell)`},
		},
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Rate limiting rule for suspicious IPs
	rateLimitRule := &FirewallRule{
		ID:       "rate_limit_suspicious",
		Name:     "Rate Limit Suspicious IPs",
		Type:     "rate_limit",
		Pattern:  "",
		Action:   "rate_limit",
		Priority: 50,
		Enabled:  true,
		Conditions: []*RuleCondition{
			{Field: "request_count", Operator: "gt", Value: 100},
			{Field: "time_window", Operator: "eq", Value: "1m"},
		},
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Add rules to engine
	re.rules = append(re.rules, sqlInjectionRule, xssRule, pathTraversalRule, cmdInjectionRule, rateLimitRule)

	re.logger.WithField("rule_count", len(re.rules)).Info("Default firewall rules loaded")
}

// NewBlockList creates a new block list
func NewBlockList(logger *logger.Logger) *BlockList {
	return &BlockList{
		logger:      logger,
		blockedIPs:  make(map[string]*BlockEntry),
		blockedASNs: make(map[string]*BlockEntry),
	}
}

// NewAllowList creates a new allow list
func NewAllowList(logger *logger.Logger) *AllowList {
	return &AllowList{
		logger:      logger,
		allowedIPs:  make(map[string]*AllowEntry),
		allowedASNs: make(map[string]*AllowEntry),
	}
}

// IsBlocked checks if an IP is blocked
func (bl *BlockList) IsBlocked(ipAddress string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	// Check direct IP block
	if entry, exists := bl.blockedIPs[ipAddress]; exists {
		// Check if block has expired
		if time.Now().Before(entry.ExpiresAt) {
			return true
		} else {
			// Remove expired entry
			delete(bl.blockedIPs, ipAddress)
		}
	}

	// Check CIDR blocks
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}

	for cidr, entry := range bl.blockedIPs {
		if strings.Contains(cidr, "/") {
			_, network, err := net.ParseCIDR(cidr)
			if err == nil && network.Contains(ip) {
				if time.Now().Before(entry.ExpiresAt) {
					return true
				}
			}
		}
	}

	return false
}

// AddToBlockList adds an IP to the block list
func (bl *BlockList) AddToBlockList(ipAddress, reason string, duration time.Duration) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	entry := &BlockEntry{
		ID:        uuid.New().String(),
		Value:     ipAddress,
		Reason:    reason,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(duration),
	}

	bl.blockedIPs[ipAddress] = entry

	bl.logger.WithFields(logger.Fields{
		"ip":       ipAddress,
		"reason":   reason,
		"duration": duration,
	}).Info("IP added to block list")
}

// RemoveFromBlockList removes an IP from the block list
func (bl *BlockList) RemoveFromBlockList(ipAddress string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	delete(bl.blockedIPs, ipAddress)

	bl.logger.WithField("ip", ipAddress).Info("IP removed from block list")
}

// IsAllowed checks if an IP is allowed
func (al *AllowList) IsAllowed(ipAddress string) bool {
	al.mu.RLock()
	defer al.mu.RUnlock()

	// Check direct IP allow
	if _, exists := al.allowedIPs[ipAddress]; exists {
		return true
	}

	// Check CIDR allows
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}

	for cidr := range al.allowedIPs {
		if strings.Contains(cidr, "/") {
			_, network, err := net.ParseCIDR(cidr)
			if err == nil && network.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// AddToAllowList adds an IP to the allow list
func (al *AllowList) AddToAllowList(ipAddress, reason string) {
	al.mu.Lock()
	defer al.mu.Unlock()

	entry := &AllowEntry{
		ID:        uuid.New().String(),
		Value:     ipAddress,
		Reason:    reason,
		CreatedAt: time.Now(),
	}

	al.allowedIPs[ipAddress] = entry

	al.logger.WithFields(logger.Fields{
		"ip":     ipAddress,
		"reason": reason,
	}).Info("IP added to allow list")
}

// RemoveFromAllowList removes an IP from the allow list
func (al *AllowList) RemoveFromAllowList(ipAddress string) {
	al.mu.Lock()
	defer al.mu.Unlock()

	delete(al.allowedIPs, ipAddress)

	al.logger.WithField("ip", ipAddress).Info("IP removed from allow list")
}

// NewIntelligentRateLimiter creates a new intelligent rate limiter
func NewIntelligentRateLimiter(logger *logger.Logger) *IntelligentRateLimiter {
	return &IntelligentRateLimiter{
		logger:         logger,
		rateLimits:     make(map[string]*RateLimit),
		adaptiveLimits: make(map[string]*AdaptiveLimit),
	}
}

// NewSessionTracker creates a new session tracker
func NewSessionTracker(logger *logger.Logger) *SessionTracker {
	return &SessionTracker{
		logger:   logger,
		sessions: make(map[string]*SessionInfo),
	}
}

// TrackSession tracks or updates session information
func (st *SessionTracker) TrackSession(sessionID, userID, ipAddress, userAgent string) *SessionInfo {
	st.mu.Lock()
	defer st.mu.Unlock()

	session, exists := st.sessions[sessionID]
	if !exists {
		session = &SessionInfo{
			ID:           sessionID,
			UserID:       userID,
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			CreatedAt:    time.Now(),
			LastActivity: time.Now(),
			RequestCount: 0,
			ThreatScore:  0.0,
			Metadata:     make(map[string]interface{}),
		}
		st.sessions[sessionID] = session

		st.logger.WithFields(logger.Fields{
			"session_id": sessionID,
			"user_id":    userID,
			"ip":         ipAddress,
		}).Debug("New session tracked")
	}

	// Update session activity
	session.LastActivity = time.Now()
	session.RequestCount++

	return session
}

// UpdateSessionThreatScore updates the threat score for a session
func (st *SessionTracker) UpdateSessionThreatScore(sessionID string, threatScore float64) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if session, exists := st.sessions[sessionID]; exists {
		session.ThreatScore = threatScore
		session.LastActivity = time.Now()

		st.logger.WithFields(logger.Fields{
			"session_id":   sessionID,
			"threat_score": threatScore,
		}).Debug("Session threat score updated")
	}
}

// GetSession retrieves session information
func (st *SessionTracker) GetSession(sessionID string) *SessionInfo {
	st.mu.RLock()
	defer st.mu.RUnlock()

	return st.sessions[sessionID]
}

// GetSessionsByIP retrieves all sessions for an IP address
func (st *SessionTracker) GetSessionsByIP(ipAddress string) []*SessionInfo {
	st.mu.RLock()
	defer st.mu.RUnlock()

	var sessions []*SessionInfo
	for _, session := range st.sessions {
		if session.IPAddress == ipAddress {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// CleanupExpiredSessions removes expired sessions
func (st *SessionTracker) CleanupExpiredSessions(maxAge time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	var expiredSessions []string

	for sessionID, session := range st.sessions {
		if session.LastActivity.Before(cutoff) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	for _, sessionID := range expiredSessions {
		delete(st.sessions, sessionID)
	}

	if len(expiredSessions) > 0 {
		st.logger.WithField("expired_count", len(expiredSessions)).Info("Cleaned up expired sessions")
	}
}

// GetSessionStats returns session statistics
func (st *SessionTracker) GetSessionStats() map[string]interface{} {
	st.mu.RLock()
	defer st.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_sessions"] = len(st.sessions)

	// Count active sessions (activity within last hour)
	activeCount := 0
	highThreatCount := 0
	cutoff := time.Now().Add(-1 * time.Hour)

	for _, session := range st.sessions {
		if session.LastActivity.After(cutoff) {
			activeCount++
		}
		if session.ThreatScore > 0.7 {
			highThreatCount++
		}
	}

	stats["active_sessions"] = activeCount
	stats["high_threat_sessions"] = highThreatCount

	return stats
}

// EvaluateRequest evaluates a request against firewall rules
func (re *RuleEngine) EvaluateRequest(req *RequestInfo) []*RuleResult {
	var results []*RuleResult

	// Evaluate standard rules
	for _, rule := range re.rules {
		if rule.Enabled {
			result := re.evaluateRule(rule, req)
			if result != nil {
				results = append(results, result)
			}
		}
	}

	return results
}

// evaluateRule evaluates a single rule against a request
func (re *RuleEngine) evaluateRule(rule *FirewallRule, req *RequestInfo) *RuleResult {
	result := &RuleResult{
		RuleID:     rule.ID,
		RuleName:   rule.Name,
		RuleType:   rule.Type,
		Matched:    false,
		Confidence: 0.0,
		Evidence:   "",
		Action:     rule.Action,
		Metadata:   make(map[string]interface{}),
	}

	// Check if rule has conditions
	if len(rule.Conditions) == 0 && rule.Pattern != "" {
		// Simple pattern matching
		matched, evidence := re.evaluatePattern(rule.Pattern, req)
		result.Matched = matched
		result.Evidence = evidence
		if matched {
			result.Confidence = 0.8
		}
		return result
	}

	// Evaluate conditions
	matchedConditions := 0
	var evidenceList []string

	for _, condition := range rule.Conditions {
		matched, evidence := re.evaluateCondition(condition, req)
		if matched {
			matchedConditions++
			if evidence != "" {
				evidenceList = append(evidenceList, evidence)
			}
		}
	}

	// Determine if rule matches (any condition can match for security rules)
	if matchedConditions > 0 && len(rule.Conditions) > 0 {
		result.Matched = true
		result.Confidence = float64(matchedConditions) / float64(len(rule.Conditions))
		result.Evidence = strings.Join(evidenceList, "; ")
	}

	return result
}

// evaluateCondition evaluates a single condition
func (re *RuleEngine) evaluateCondition(condition *RuleCondition, req *RequestInfo) (bool, string) {
	var fieldValue string

	// Extract field value from request
	switch condition.Field {
	case "url":
		fieldValue = req.URL
	case "method":
		fieldValue = req.Method
	case "body":
		fieldValue = req.Body
	case "user_agent":
		fieldValue = req.UserAgent
	case "ip_address":
		fieldValue = req.IPAddress
	case "headers":
		// For headers, we'll check all header values
		for _, value := range req.Headers {
			fieldValue += value + " "
		}
	default:
		return false, ""
	}

	// Apply operator
	switch condition.Operator {
	case "matches":
		if pattern, ok := condition.Value.(string); ok {
			matched, _ := regexp.MatchString(pattern, fieldValue)
			result := matched
			if condition.Negate {
				result = !result
			}
			if result {
				return true, fmt.Sprintf("Field '%s' matched pattern '%s'", condition.Field, pattern)
			}
		}
	case "equals":
		if value, ok := condition.Value.(string); ok {
			result := fieldValue == value
			if condition.Negate {
				result = !result
			}
			if result {
				return true, fmt.Sprintf("Field '%s' equals '%s'", condition.Field, value)
			}
		}
	case "contains":
		if value, ok := condition.Value.(string); ok {
			result := strings.Contains(fieldValue, value)
			if condition.Negate {
				result = !result
			}
			if result {
				return true, fmt.Sprintf("Field '%s' contains '%s'", condition.Field, value)
			}
		}
	case "gt":
		// For numeric comparisons (like request count)
		if condition.Field == "request_count" {
			// This would need to be implemented with connection tracking
			return false, ""
		}
	}

	return false, ""
}

// evaluatePattern evaluates a pattern against request fields
func (re *RuleEngine) evaluatePattern(pattern string, req *RequestInfo) (bool, string) {
	// Check URL
	if matched, _ := regexp.MatchString(pattern, req.URL); matched {
		return true, fmt.Sprintf("Pattern matched in URL: %s", req.URL)
	}

	// Check body
	if matched, _ := regexp.MatchString(pattern, req.Body); matched {
		return true, fmt.Sprintf("Pattern matched in body")
	}

	// Check headers
	for name, value := range req.Headers {
		if matched, _ := regexp.MatchString(pattern, value); matched {
			return true, fmt.Sprintf("Pattern matched in header %s: %s", name, value)
		}
	}

	return false, ""
}

// IsAllowed checks if a request is allowed by rate limiter
func (irl *IntelligentRateLimiter) IsAllowed(ipAddress string) bool {
	irl.mu.Lock()
	defer irl.mu.Unlock()

	now := time.Now()

	// Get or create rate limit for IP
	rateLimit, exists := irl.rateLimits[ipAddress]
	if !exists {
		// Create default rate limit
		rateLimit = &RateLimit{
			Requests: 100,             // 100 requests
			Window:   1 * time.Minute, // per minute
			Current:  0,
			ResetAt:  now.Add(1 * time.Minute),
		}
		irl.rateLimits[ipAddress] = rateLimit
	}

	// Check if window has expired
	if now.After(rateLimit.ResetAt) {
		rateLimit.Current = 0
		rateLimit.ResetAt = now.Add(rateLimit.Window)
	}

	// Check adaptive limits
	if adaptiveLimit, exists := irl.adaptiveLimits[ipAddress]; exists {
		// Use adaptive limit if it's more restrictive
		if adaptiveLimit.CurrentLimit < rateLimit.Requests {
			if rateLimit.Current >= adaptiveLimit.CurrentLimit {
				irl.logger.WithFields(logger.Fields{
					"ip":             ipAddress,
					"current":        rateLimit.Current,
					"adaptive_limit": adaptiveLimit.CurrentLimit,
				}).Warn("Adaptive rate limit exceeded")
				return false
			}
		}
	}

	// Check standard rate limit
	if rateLimit.Current >= rateLimit.Requests {
		irl.logger.WithFields(logger.Fields{
			"ip":      ipAddress,
			"current": rateLimit.Current,
			"limit":   rateLimit.Requests,
		}).Warn("Rate limit exceeded")
		return false
	}

	// Increment counter
	rateLimit.Current++

	return true
}

// UpdateAdaptiveLimit updates the adaptive rate limit based on threat score
func (irl *IntelligentRateLimiter) UpdateAdaptiveLimit(ipAddress string, threatScore float64) {
	irl.mu.Lock()
	defer irl.mu.Unlock()

	adaptiveLimit, exists := irl.adaptiveLimits[ipAddress]
	if !exists {
		adaptiveLimit = &AdaptiveLimit{
			BaseLimit:        100,
			CurrentLimit:     100,
			ThreatScore:      threatScore,
			LastAdjusted:     time.Now(),
			AdjustmentFactor: 1.0,
		}
		irl.adaptiveLimits[ipAddress] = adaptiveLimit
	}

	// Adjust limit based on threat score
	if threatScore > 0.7 {
		// High threat - reduce limit significantly
		adaptiveLimit.AdjustmentFactor = 0.1
	} else if threatScore > 0.5 {
		// Medium threat - reduce limit moderately
		adaptiveLimit.AdjustmentFactor = 0.3
	} else if threatScore > 0.3 {
		// Low threat - reduce limit slightly
		adaptiveLimit.AdjustmentFactor = 0.7
	} else {
		// No significant threat - use base limit
		adaptiveLimit.AdjustmentFactor = 1.0
	}

	adaptiveLimit.CurrentLimit = int(float64(adaptiveLimit.BaseLimit) * adaptiveLimit.AdjustmentFactor)
	adaptiveLimit.ThreatScore = threatScore
	adaptiveLimit.LastAdjusted = time.Now()

	irl.logger.WithFields(logger.Fields{
		"ip":                ipAddress,
		"threat_score":      threatScore,
		"adjustment_factor": adaptiveLimit.AdjustmentFactor,
		"new_limit":         adaptiveLimit.CurrentLimit,
	}).Debug("Adaptive rate limit updated")
}

// GetRateLimitStatus returns the current rate limit status for an IP
func (irl *IntelligentRateLimiter) GetRateLimitStatus(ipAddress string) map[string]interface{} {
	irl.mu.RLock()
	defer irl.mu.RUnlock()

	status := make(map[string]interface{})

	if rateLimit, exists := irl.rateLimits[ipAddress]; exists {
		status["requests_made"] = rateLimit.Current
		status["requests_limit"] = rateLimit.Requests
		status["window_reset"] = rateLimit.ResetAt
		status["requests_remaining"] = rateLimit.Requests - rateLimit.Current
	}

	if adaptiveLimit, exists := irl.adaptiveLimits[ipAddress]; exists {
		status["adaptive_limit"] = adaptiveLimit.CurrentLimit
		status["threat_score"] = adaptiveLimit.ThreatScore
		status["adjustment_factor"] = adaptiveLimit.AdjustmentFactor
	}

	return status
}

// DefaultFirewallConfig returns default firewall configuration
func DefaultFirewallConfig() *FirewallConfig {
	return &FirewallConfig{
		EnableMLDetection:      true,
		EnableBehaviorAnalysis: true,
		EnableAnomalyDetection: true,
		EnableGeoBlocking:      false,
		EnableRateLimiting:     true,
		BlockThreshold:         0.7,
		LearningMode:           true,
		AutoUpdateRules:        true,
		MaxConnectionsPerIP:    100,
		ConnectionTimeout:      30 * time.Minute,
		BlockDuration:          1 * time.Hour,
		LogAllRequests:         false,
		EnableThreatSharing:    false,
	}
}
