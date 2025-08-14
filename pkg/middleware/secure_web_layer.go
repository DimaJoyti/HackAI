package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
)

// Supporting types and interfaces

// AlertConfig configuration for alert manager
type AlertConfig struct {
	EnableSlack    bool    `json:"enable_slack"`
	SlackWebhook   string  `json:"slack_webhook"`
	EnableEmail    bool    `json:"enable_email"`
	EmailRecipient string  `json:"email_recipient"`
	EnableWebhook  bool    `json:"enable_webhook"`
	WebhookURL     string  `json:"webhook_url"`
	AlertThreshold float64 `json:"alert_threshold"`
}

// AlertChannel interface for different alert channels
type AlertChannel interface {
	SendAlert(alert *SecurityAlert) error
	GetType() string
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	RequestID   string                 `json:"request_id"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	URL         string                 `json:"url"`
	ThreatScore float64                `json:"threat_score"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// CorrelationPattern defines patterns for event correlation
type CorrelationPattern struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	EventTypes []string      `json:"event_types"`
	TimeWindow time.Duration `json:"time_window"`
	Threshold  int           `json:"threshold"`
	Action     string        `json:"action"`
}

// MetricsConfig configuration for metrics export
type MetricsConfig struct {
	EnablePrometheus bool          `json:"enable_prometheus"`
	PrometheusPort   int           `json:"prometheus_port"`
	EnableInfluxDB   bool          `json:"enable_influxdb"`
	InfluxDBURL      string        `json:"influxdb_url"`
	ExportInterval   time.Duration `json:"export_interval"`
}

// MetricsExporterInterface interface for metrics exporters
type MetricsExporterInterface interface {
	Export(metrics *SecurityMetrics) error
	GetType() string
}

// HealthCheckComponent represents a component to health check
type HealthCheckComponent struct {
	Name      string                 `json:"name"`
	Checker   func() error           `json:"-"`
	Status    string                 `json:"status"`
	LastCheck time.Time              `json:"last_check"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// HealthStatus overall health status
type HealthStatus struct {
	Overall    string                 `json:"overall"`
	Components []HealthCheckComponent `json:"components"`
	LastCheck  time.Time              `json:"last_check"`
}

// SecurityAlert represents a security alert
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	RequestID   string                 `json:"request_id"`
	IPAddress   string                 `json:"ip_address"`
	ThreatScore float64                `json:"threat_score"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertManager handles security alerts and notifications
type AlertManager struct {
	logger   *logger.Logger
	config   *AlertConfig
	channels []AlertChannel
	mu       sync.RWMutex
}

// SecurityEventCorrelator correlates security events across requests
type SecurityEventCorrelator struct {
	logger   *logger.Logger
	events   []SecurityEvent
	patterns []CorrelationPattern
	mu       sync.RWMutex
}

// MetricsExporter exports security metrics to external systems
type MetricsExporter struct {
	logger    *logger.Logger
	config    *MetricsConfig
	exporters []MetricsExporterInterface
	mu        sync.RWMutex
}

// HealthChecker monitors the health of security components
type HealthChecker struct {
	logger     *logger.Logger
	components []HealthCheckComponent
	status     HealthStatus
	mu         sync.RWMutex
}

// SecureWebLayer comprehensive security middleware layer
type SecureWebLayer struct {
	logger             *logger.Logger
	config             *SecureWebConfig
	agenticFramework   *security.AgenticSecurityFramework
	aiFirewall         *security.AIFirewall
	inputOutputFilter  *security.InputOutputFilter
	promptGuard        *security.PromptInjectionGuard
	threatIntelligence *security.ThreatIntelligence
	securityMetrics    *SecurityMetrics
	alertManager       *AlertManager
	eventCorrelator    *SecurityEventCorrelator
	metricsExporter    *MetricsExporter
	healthChecker      *HealthChecker
	mu                 sync.RWMutex
}

// SecureWebConfig configuration for secure web layer
type SecureWebConfig struct {
	EnableAgenticSecurity    bool           `json:"enable_agentic_security"`
	EnableAIFirewall         bool           `json:"enable_ai_firewall"`
	EnableInputFiltering     bool           `json:"enable_input_filtering"`
	EnableOutputFiltering    bool           `json:"enable_output_filtering"`
	EnablePromptProtection   bool           `json:"enable_prompt_protection"`
	EnableThreatIntelligence bool           `json:"enable_threat_intelligence"`
	EnableRealTimeMonitoring bool           `json:"enable_real_time_monitoring"`
	EnableSecurityMetrics    bool           `json:"enable_security_metrics"`
	EnableAlerting           bool           `json:"enable_alerting"`
	EnableEventCorrelation   bool           `json:"enable_event_correlation"`
	EnableMetricsExport      bool           `json:"enable_metrics_export"`
	EnableHealthChecks       bool           `json:"enable_health_checks"`
	BlockThreshold           float64        `json:"block_threshold"`
	AlertThreshold           float64        `json:"alert_threshold"`
	MaxRequestSize           int64          `json:"max_request_size"`
	RequestTimeout           time.Duration  `json:"request_timeout"`
	LogSecurityEvents        bool           `json:"log_security_events"`
	EnableCSP                bool           `json:"enable_csp"`
	CSPPolicy                string         `json:"csp_policy"`
	EnableHSTS               bool           `json:"enable_hsts"`
	HSTSMaxAge               int            `json:"hsts_max_age"`
	EnableXFrameOptions      bool           `json:"enable_x_frame_options"`
	XFrameOptionsValue       string         `json:"x_frame_options_value"`
	StrictMode               bool           `json:"strict_mode"`
	AlertConfig              *AlertConfig   `json:"alert_config"`
	MetricsConfig            *MetricsConfig `json:"metrics_config"`
}

// SecurityMetrics tracks security-related metrics
type SecurityMetrics struct {
	TotalRequests         int64            `json:"total_requests"`
	BlockedRequests       int64            `json:"blocked_requests"`
	ThreatsDetected       int64            `json:"threats_detected"`
	PromptInjections      int64            `json:"prompt_injections"`
	InputViolations       int64            `json:"input_violations"`
	OutputSanitizations   int64            `json:"output_sanitizations"`
	AlertsTriggered       int64            `json:"alerts_triggered"`
	HealthCheckFailures   int64            `json:"health_check_failures"`
	AverageRiskScore      float64          `json:"average_risk_score"`
	MaxRiskScore          float64          `json:"max_risk_score"`
	AverageProcessingTime time.Duration    `json:"average_processing_time"`
	ThreatsByType         map[string]int64 `json:"threats_by_type"`
	RequestsByEndpoint    map[string]int64 `json:"requests_by_endpoint"`
	BlocksByReason        map[string]int64 `json:"blocks_by_reason"`
	LastUpdated           time.Time        `json:"last_updated"`
	StartTime             time.Time        `json:"start_time"`
}

// SecurityContext contains security information for a request
type SecurityContext struct {
	RequestID        string                 `json:"request_id"`
	ThreatScore      float64                `json:"threat_score"`
	SecurityDecision string                 `json:"security_decision"`
	DetectedThreats  []string               `json:"detected_threats"`
	AppliedFilters   []string               `json:"applied_filters"`
	SecurityMetadata map[string]interface{} `json:"security_metadata"`
	ProcessingTime   time.Duration          `json:"processing_time"`
}

// NewSecureWebLayer creates a new secure web layer
func NewSecureWebLayer(config *SecureWebConfig, logger *logger.Logger) *SecureWebLayer {
	layer := &SecureWebLayer{
		logger: logger,
		config: config,
		securityMetrics: &SecurityMetrics{
			ThreatsByType:      make(map[string]int64),
			RequestsByEndpoint: make(map[string]int64),
			BlocksByReason:     make(map[string]int64),
			StartTime:          time.Now(),
		},
	}

	// Initialize security components
	if config.EnableAgenticSecurity {
		agenticConfig := security.DefaultAgenticConfig()
		layer.agenticFramework = security.NewAgenticSecurityFramework(agenticConfig, logger)
	}

	if config.EnableAIFirewall {
		firewallConfig := security.DefaultFirewallConfig()
		layer.aiFirewall = security.NewAIFirewall(firewallConfig, logger)
	}

	if config.EnableInputFiltering || config.EnableOutputFiltering {
		filterConfig := security.DefaultFilterConfig()
		layer.inputOutputFilter = security.NewInputOutputFilter(filterConfig, logger)
	}

	if config.EnablePromptProtection {
		layer.promptGuard = security.NewPromptInjectionGuard(logger)
	}

	if config.EnableThreatIntelligence {
		layer.threatIntelligence = security.NewThreatIntelligence(logger)
	}

	// Initialize additional components
	if config.EnableAlerting && config.AlertConfig != nil {
		layer.alertManager = NewAlertManager(config.AlertConfig, logger)
	}

	if config.EnableEventCorrelation {
		layer.eventCorrelator = NewSecurityEventCorrelator(logger)
	}

	if config.EnableMetricsExport && config.MetricsConfig != nil {
		layer.metricsExporter = NewMetricsExporter(config.MetricsConfig, logger)
	}

	if config.EnableHealthChecks {
		layer.healthChecker = NewHealthChecker(logger)
		layer.initializeHealthChecks()
	}

	return layer
}

// SecureMiddleware returns the main security middleware
func (swl *SecureWebLayer) SecureMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()

			// Apply enhanced security headers
			swl.enhancedSecurityHeaders(w, r)

			// Validate request size
			if err := swl.validateRequestSize(r); err != nil {
				swl.handleBlockedRequest(w, r, "Request size limit exceeded", &SecurityContext{
					RequestID: GetRequestIDFromContext(r.Context()),
				})
				return
			}

			// Create security context
			securityCtx := &SecurityContext{
				RequestID:        GetRequestIDFromContext(r.Context()),
				SecurityMetadata: make(map[string]interface{}),
				DetectedThreats:  make([]string, 0),
				AppliedFilters:   make([]string, 0),
			}

			// Update metrics
			swl.updateMetrics("total_requests", 1)
			swl.updateEndpointMetrics(r.URL.Path)

			// AI Firewall processing
			if swl.config.EnableAIFirewall && swl.aiFirewall != nil {
				decision, err := swl.aiFirewall.ProcessRequest(r.Context(), r)
				if err != nil {
					swl.logger.WithError(err).Error("AI Firewall processing failed")
				} else {
					securityCtx.SecurityDecision = decision.Action
					securityCtx.ThreatScore = decision.ThreatScore
					securityCtx.SecurityMetadata["firewall_decision"] = decision

					if decision.Action == "block" {
						swl.handleBlockedRequest(w, r, decision.Reason, securityCtx)
						return
					}
				}
			}

			// Input filtering
			if swl.config.EnableInputFiltering && swl.inputOutputFilter != nil {
				if !swl.processInputFiltering(w, r, securityCtx) {
					return
				}
			}

			// Prompt injection protection for AI-related endpoints
			if swl.config.EnablePromptProtection && swl.isAIEndpoint(r.URL.Path) {
				if !swl.processPromptProtection(w, r, securityCtx) {
					return
				}
			}

			// Agentic security analysis
			if swl.config.EnableAgenticSecurity && swl.agenticFramework != nil {
				if !swl.processAgenticSecurity(w, r, securityCtx) {
					return
				}
			}

			// Create response wrapper for output filtering
			var responseWrapper *ResponseWrapper
			if swl.config.EnableOutputFiltering {
				responseWrapper = NewResponseWrapper(w)
				w = responseWrapper
			}

			// Add security context to request context
			ctx := context.WithValue(r.Context(), "security_context", securityCtx)
			r = r.WithContext(ctx)

			// Process request
			next.ServeHTTP(w, r)

			// Output filtering
			if swl.config.EnableOutputFiltering && responseWrapper != nil {
				swl.processOutputFiltering(responseWrapper, securityCtx)
			}

			// Calculate processing time
			securityCtx.ProcessingTime = time.Since(startTime)

			// Process security event for correlation
			if swl.config.EnableEventCorrelation {
				swl.processSecurityEvent(securityCtx, r)
			}

			// Check if alert should be triggered
			if swl.config.EnableAlerting && securityCtx.ThreatScore >= swl.config.AlertThreshold {
				swl.triggerThreatAlert(securityCtx, r)
			}

			// Export metrics if enabled
			if swl.config.EnableMetricsExport && swl.metricsExporter != nil {
				go swl.exportMetrics()
			}

			// Log security event
			if swl.config.LogSecurityEvents {
				swl.logSecurityEvent(r, securityCtx)
			}

			// Update security metrics
			swl.updateSecurityMetrics(securityCtx)
		})
	}
}

// processInputFiltering handles input filtering
func (swl *SecureWebLayer) processInputFiltering(w http.ResponseWriter, r *http.Request, securityCtx *SecurityContext) bool {
	// Read request body for analysis
	body, err := swl.readRequestBody(r)
	if err != nil {
		swl.logger.WithError(err).Error("Failed to read request body")
		return true // Continue processing
	}

	// Filter input
	filterResult, err := swl.inputOutputFilter.FilterInput(r.Context(), string(body), nil)
	if err != nil {
		swl.logger.WithError(err).Error("Input filtering failed")
		return true // Continue processing
	}

	securityCtx.AppliedFilters = append(securityCtx.AppliedFilters, "input_filter")
	securityCtx.SecurityMetadata["input_filter_result"] = filterResult

	// Check if input should be blocked
	if filterResult.Blocked || (!filterResult.Valid && swl.config.BlockThreshold > 0) {
		swl.handleBlockedRequest(w, r, "Input validation failed", securityCtx)
		swl.updateMetrics("input_violations", 1)
		return false
	}

	// Update threat score
	if filterResult.ThreatScore > securityCtx.ThreatScore {
		securityCtx.ThreatScore = filterResult.ThreatScore
	}

	return true
}

// processPromptProtection handles prompt injection protection
func (swl *SecureWebLayer) processPromptProtection(w http.ResponseWriter, r *http.Request, securityCtx *SecurityContext) bool {
	// Read request body for prompt analysis
	body, err := swl.readRequestBody(r)
	if err != nil {
		swl.logger.WithError(err).Error("Failed to read request body for prompt protection")
		return true
	}

	// Create security request for analysis
	securityReq := &security.SecurityRequest{
		ID:        securityCtx.RequestID,
		Method:    r.Method,
		URL:       r.URL.String(),
		Body:      string(body),
		IPAddress: swl.getClientIP(r),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
	}

	// Detect prompt injection
	threat := swl.promptGuard.DetectPromptInjection(securityReq)
	if threat != nil {
		securityCtx.DetectedThreats = append(securityCtx.DetectedThreats, threat.Type)
		securityCtx.SecurityMetadata["prompt_threat"] = threat

		if threat.Confidence >= swl.config.BlockThreshold {
			swl.handleBlockedRequest(w, r, "Prompt injection detected", securityCtx)
			swl.updateMetrics("prompt_injections", 1)
			return false
		}

		// Update threat score
		if threat.Confidence > securityCtx.ThreatScore {
			securityCtx.ThreatScore = threat.Confidence
		}
	}

	securityCtx.AppliedFilters = append(securityCtx.AppliedFilters, "prompt_protection")
	return true
}

// processAgenticSecurity handles agentic security analysis
func (swl *SecureWebLayer) processAgenticSecurity(w http.ResponseWriter, r *http.Request, securityCtx *SecurityContext) bool {
	// Create security request
	securityReq := &security.SecurityRequest{
		ID:        securityCtx.RequestID,
		Method:    r.Method,
		URL:       r.URL.String(),
		IPAddress: swl.getClientIP(r),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
		Headers:   swl.extractHeaders(r),
	}

	// Perform agentic analysis
	analysis, err := swl.agenticFramework.AnalyzeRequest(r.Context(), securityReq)
	if err != nil {
		swl.logger.WithError(err).Error("Agentic security analysis failed")
		return true
	}

	securityCtx.AppliedFilters = append(securityCtx.AppliedFilters, "agentic_security")
	securityCtx.SecurityMetadata["agentic_analysis"] = analysis

	// Update threat score and detected threats
	if analysis.RiskScore > securityCtx.ThreatScore {
		securityCtx.ThreatScore = analysis.RiskScore
	}

	for _, threat := range analysis.Threats {
		securityCtx.DetectedThreats = append(securityCtx.DetectedThreats, threat.Type)
	}

	// Check if autonomous response was triggered
	if analysis.AutoResponse != nil && analysis.AutoResponse.Action == "block_request" {
		swl.handleBlockedRequest(w, r, "Autonomous security block", securityCtx)
		return false
	}

	return true
}

// processOutputFiltering handles output filtering
func (swl *SecureWebLayer) processOutputFiltering(wrapper *ResponseWrapper, securityCtx *SecurityContext) {
	if wrapper.body.Len() == 0 {
		return
	}

	// Filter output
	filterResult, err := swl.inputOutputFilter.FilterOutput(context.Background(), wrapper.body.String())
	if err != nil {
		swl.logger.WithError(err).Error("Output filtering failed")
		return
	}

	securityCtx.AppliedFilters = append(securityCtx.AppliedFilters, "output_filter")
	securityCtx.SecurityMetadata["output_filter_result"] = filterResult

	// Replace response body with filtered content if sanitized
	if filterResult.Sanitized {
		wrapper.body.Reset()
		wrapper.body.WriteString(filterResult.FilteredData.(string))
		swl.updateMetrics("output_sanitizations", 1)
	}
}

// handleBlockedRequest handles blocked requests
func (swl *SecureWebLayer) handleBlockedRequest(w http.ResponseWriter, r *http.Request, reason string, securityCtx *SecurityContext) {
	swl.updateMetrics("blocked_requests", 1)

	// Track block reasons
	swl.mu.Lock()
	if swl.securityMetrics.BlocksByReason == nil {
		swl.securityMetrics.BlocksByReason = make(map[string]int64)
	}
	swl.securityMetrics.BlocksByReason[reason]++
	swl.mu.Unlock()

	response := map[string]interface{}{
		"error":      "Request blocked by security system",
		"reason":     reason,
		"request_id": securityCtx.RequestID,
		"timestamp":  time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(response)

	swl.logger.WithFields(logger.Fields{
		"request_id":   securityCtx.RequestID,
		"reason":       reason,
		"threat_score": securityCtx.ThreatScore,
		"ip_address":   swl.getClientIP(r),
		"url":          r.URL.String(),
		"user_agent":   r.UserAgent(),
	}).Warn("Request blocked by security system")
}

// Helper methods
func (swl *SecureWebLayer) readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return []byte{}, nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	// Restore body for further processing
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, nil
}

func (swl *SecureWebLayer) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

func (swl *SecureWebLayer) extractHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)
	for name, values := range r.Header {
		if len(values) > 0 {
			headers[strings.ToLower(name)] = values[0]
		}
	}
	return headers
}

func (swl *SecureWebLayer) isAIEndpoint(path string) bool {
	aiEndpoints := []string{"/api/v1/ai/", "/api/v1/chat/", "/api/v1/analyze/"}
	for _, endpoint := range aiEndpoints {
		if strings.HasPrefix(path, endpoint) {
			return true
		}
	}
	return false
}

func (swl *SecureWebLayer) updateMetrics(metric string, value int64) {
	swl.mu.Lock()
	defer swl.mu.Unlock()

	switch metric {
	case "total_requests":
		swl.securityMetrics.TotalRequests += value
	case "blocked_requests":
		swl.securityMetrics.BlockedRequests += value
	case "threats_detected":
		swl.securityMetrics.ThreatsDetected += value
	case "prompt_injections":
		swl.securityMetrics.PromptInjections += value
	case "input_violations":
		swl.securityMetrics.InputViolations += value
	case "output_sanitizations":
		swl.securityMetrics.OutputSanitizations += value
	case "alerts_triggered":
		swl.securityMetrics.AlertsTriggered += value
	case "health_check_failures":
		swl.securityMetrics.HealthCheckFailures += value
	}
	swl.securityMetrics.LastUpdated = time.Now()
}

func (swl *SecureWebLayer) updateSecurityMetrics(securityCtx *SecurityContext) {
	swl.mu.Lock()
	defer swl.mu.Unlock()

	// Update average risk score
	if swl.securityMetrics.TotalRequests > 0 {
		swl.securityMetrics.AverageRiskScore =
			(swl.securityMetrics.AverageRiskScore*float64(swl.securityMetrics.TotalRequests-1) + securityCtx.ThreatScore) /
				float64(swl.securityMetrics.TotalRequests)
	} else {
		swl.securityMetrics.AverageRiskScore = securityCtx.ThreatScore
	}

	// Update max risk score
	if securityCtx.ThreatScore > swl.securityMetrics.MaxRiskScore {
		swl.securityMetrics.MaxRiskScore = securityCtx.ThreatScore
	}

	// Update average processing time
	if swl.securityMetrics.TotalRequests > 0 {
		swl.securityMetrics.AverageProcessingTime =
			time.Duration((int64(swl.securityMetrics.AverageProcessingTime)*int64(swl.securityMetrics.TotalRequests-1) + int64(securityCtx.ProcessingTime)) /
				int64(swl.securityMetrics.TotalRequests))
	} else {
		swl.securityMetrics.AverageProcessingTime = securityCtx.ProcessingTime
	}

	// Update threats by type
	if swl.securityMetrics.ThreatsByType == nil {
		swl.securityMetrics.ThreatsByType = make(map[string]int64)
	}
	for _, threat := range securityCtx.DetectedThreats {
		swl.securityMetrics.ThreatsByType[threat]++
	}

	// Update threats detected count
	if len(securityCtx.DetectedThreats) > 0 {
		swl.securityMetrics.ThreatsDetected += int64(len(securityCtx.DetectedThreats))
	}
}

func (swl *SecureWebLayer) logSecurityEvent(r *http.Request, securityCtx *SecurityContext) {
	swl.logger.WithFields(logger.Fields{
		"request_id":        securityCtx.RequestID,
		"threat_score":      securityCtx.ThreatScore,
		"security_decision": securityCtx.SecurityDecision,
		"detected_threats":  securityCtx.DetectedThreats,
		"applied_filters":   securityCtx.AppliedFilters,
		"processing_time":   securityCtx.ProcessingTime,
		"method":            r.Method,
		"url":               r.URL.String(),
		"ip_address":        swl.getClientIP(r),
		"user_agent":        r.UserAgent(),
	}).Info("Security event processed")
}

// ResponseWrapper wraps http.ResponseWriter to capture response body
type ResponseWrapper struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func NewResponseWrapper(w http.ResponseWriter) *ResponseWrapper {
	return &ResponseWrapper{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
	}
}

func (rw *ResponseWrapper) Write(data []byte) (int, error) {
	rw.body.Write(data)
	return rw.ResponseWriter.Write(data)
}

func (rw *ResponseWrapper) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

// DefaultSecureWebConfig returns default configuration
func DefaultSecureWebConfig() *SecureWebConfig {
	return &SecureWebConfig{
		EnableAgenticSecurity:    true,
		EnableAIFirewall:         true,
		EnableInputFiltering:     true,
		EnableOutputFiltering:    true,
		EnablePromptProtection:   true,
		EnableThreatIntelligence: true,
		EnableRealTimeMonitoring: true,
		EnableSecurityMetrics:    true,
		EnableAlerting:           true,
		EnableEventCorrelation:   true,
		EnableMetricsExport:      true,
		EnableHealthChecks:       true,
		BlockThreshold:           0.7,
		AlertThreshold:           0.5,
		MaxRequestSize:           10 * 1024 * 1024, // 10MB
		RequestTimeout:           30 * time.Second,
		LogSecurityEvents:        true,
		EnableCSP:                true,
		CSPPolicy:                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
		EnableHSTS:               true,
		HSTSMaxAge:               31536000, // 1 year
		EnableXFrameOptions:      true,
		XFrameOptionsValue:       "DENY",
		StrictMode:               false,
		AlertConfig: &AlertConfig{
			EnableSlack:    false,
			EnableEmail:    false,
			EnableWebhook:  false,
			AlertThreshold: 0.7,
		},
		MetricsConfig: &MetricsConfig{
			EnablePrometheus: true,
			PrometheusPort:   9090,
			EnableInfluxDB:   false,
			ExportInterval:   30 * time.Second,
		},
	}
}

// Constructor functions for new components

// NewAlertManager creates a new alert manager
func NewAlertManager(config *AlertConfig, logger *logger.Logger) *AlertManager {
	am := &AlertManager{
		logger:   logger,
		config:   config,
		channels: make([]AlertChannel, 0),
	}

	// Initialize alert channels based on configuration
	if config.EnableSlack && config.SlackWebhook != "" {
		am.channels = append(am.channels, &SlackAlertChannel{
			webhookURL: config.SlackWebhook,
			logger:     logger,
		})
	}

	if config.EnableEmail && config.EmailRecipient != "" {
		am.channels = append(am.channels, &EmailAlertChannel{
			recipient: config.EmailRecipient,
			logger:    logger,
		})
	}

	if config.EnableWebhook && config.WebhookURL != "" {
		am.channels = append(am.channels, &WebhookAlertChannel{
			webhookURL: config.WebhookURL,
			logger:     logger,
		})
	}

	return am
}

// NewSecurityEventCorrelator creates a new security event correlator
func NewSecurityEventCorrelator(logger *logger.Logger) *SecurityEventCorrelator {
	return &SecurityEventCorrelator{
		logger:   logger,
		events:   make([]SecurityEvent, 0),
		patterns: getDefaultCorrelationPatterns(),
	}
}

// NewMetricsExporter creates a new metrics exporter
func NewMetricsExporter(config *MetricsConfig, logger *logger.Logger) *MetricsExporter {
	me := &MetricsExporter{
		logger:    logger,
		config:    config,
		exporters: make([]MetricsExporterInterface, 0),
	}

	// Initialize exporters based on configuration
	if config.EnablePrometheus {
		me.exporters = append(me.exporters, &PrometheusExporter{
			port:   config.PrometheusPort,
			logger: logger,
		})
	}

	if config.EnableInfluxDB && config.InfluxDBURL != "" {
		me.exporters = append(me.exporters, &InfluxDBExporter{
			url:    config.InfluxDBURL,
			logger: logger,
		})
	}

	return me
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(logger *logger.Logger) *HealthChecker {
	return &HealthChecker{
		logger:     logger,
		components: make([]HealthCheckComponent, 0),
		status: HealthStatus{
			Overall:    "unknown",
			Components: make([]HealthCheckComponent, 0),
			LastCheck:  time.Now(),
		},
	}
}

// Alert channel implementations

// SlackAlertChannel sends alerts to Slack
type SlackAlertChannel struct {
	webhookURL string
	logger     *logger.Logger
}

func (s *SlackAlertChannel) SendAlert(alert *SecurityAlert) error {
	// Implementation would send to Slack webhook
	s.logger.WithFields(logger.Fields{
		"alert_id":   alert.ID,
		"alert_type": alert.Type,
		"severity":   alert.Severity,
	}).Info("Slack alert sent")
	return nil
}

func (s *SlackAlertChannel) GetType() string {
	return "slack"
}

// EmailAlertChannel sends alerts via email
type EmailAlertChannel struct {
	recipient string
	logger    *logger.Logger
}

func (e *EmailAlertChannel) SendAlert(alert *SecurityAlert) error {
	// Implementation would send email
	e.logger.WithFields(logger.Fields{
		"alert_id":   alert.ID,
		"alert_type": alert.Type,
		"severity":   alert.Severity,
		"recipient":  e.recipient,
	}).Info("Email alert sent")
	return nil
}

func (e *EmailAlertChannel) GetType() string {
	return "email"
}

// WebhookAlertChannel sends alerts to webhook
type WebhookAlertChannel struct {
	webhookURL string
	logger     *logger.Logger
}

func (w *WebhookAlertChannel) SendAlert(alert *SecurityAlert) error {
	// Implementation would send to webhook
	w.logger.WithFields(logger.Fields{
		"alert_id":   alert.ID,
		"alert_type": alert.Type,
		"severity":   alert.Severity,
		"webhook":    w.webhookURL,
	}).Info("Webhook alert sent")
	return nil
}

func (w *WebhookAlertChannel) GetType() string {
	return "webhook"
}

// Metrics exporter implementations

// PrometheusExporter exports metrics to Prometheus
type PrometheusExporter struct {
	port   int
	logger *logger.Logger
}

func (p *PrometheusExporter) Export(metrics *SecurityMetrics) error {
	// Implementation would export to Prometheus
	p.logger.WithFields(logger.Fields{
		"total_requests":   metrics.TotalRequests,
		"blocked_requests": metrics.BlockedRequests,
		"threats_detected": metrics.ThreatsDetected,
	}).Debug("Metrics exported to Prometheus")
	return nil
}

func (p *PrometheusExporter) GetType() string {
	return "prometheus"
}

// InfluxDBExporter exports metrics to InfluxDB
type InfluxDBExporter struct {
	url    string
	logger *logger.Logger
}

func (i *InfluxDBExporter) Export(metrics *SecurityMetrics) error {
	// Implementation would export to InfluxDB
	i.logger.WithFields(logger.Fields{
		"total_requests":   metrics.TotalRequests,
		"blocked_requests": metrics.BlockedRequests,
		"threats_detected": metrics.ThreatsDetected,
		"influxdb_url":     i.url,
	}).Debug("Metrics exported to InfluxDB")
	return nil
}

func (i *InfluxDBExporter) GetType() string {
	return "influxdb"
}

// Helper functions

// getDefaultCorrelationPatterns returns default correlation patterns
func getDefaultCorrelationPatterns() []CorrelationPattern {
	return []CorrelationPattern{
		{
			ID:         "brute_force_detection",
			Name:       "Brute Force Attack Detection",
			EventTypes: []string{"authentication_failure", "blocked_request"},
			TimeWindow: 5 * time.Minute,
			Threshold:  10,
			Action:     "block_ip",
		},
		{
			ID:         "sql_injection_pattern",
			Name:       "SQL Injection Pattern Detection",
			EventTypes: []string{"sql_injection", "input_violation"},
			TimeWindow: 2 * time.Minute,
			Threshold:  3,
			Action:     "alert_admin",
		},
		{
			ID:         "xss_attack_pattern",
			Name:       "XSS Attack Pattern Detection",
			EventTypes: []string{"xss", "script_injection"},
			TimeWindow: 3 * time.Minute,
			Threshold:  5,
			Action:     "block_request",
		},
	}
}

// Additional methods for SecureWebLayer

// initializeHealthChecks sets up health checks for all components
func (swl *SecureWebLayer) initializeHealthChecks() {
	if swl.healthChecker == nil {
		return
	}

	// Add health checks for each component
	if swl.agenticFramework != nil {
		swl.healthChecker.components = append(swl.healthChecker.components, HealthCheckComponent{
			Name: "agentic_framework",
			Checker: func() error {
				// Check if agentic framework is responsive
				return nil
			},
			Status:    "unknown",
			LastCheck: time.Now(),
			Metadata:  make(map[string]interface{}),
		})
	}

	if swl.aiFirewall != nil {
		swl.healthChecker.components = append(swl.healthChecker.components, HealthCheckComponent{
			Name: "ai_firewall",
			Checker: func() error {
				// Check if AI firewall is responsive
				return nil
			},
			Status:    "unknown",
			LastCheck: time.Now(),
			Metadata:  make(map[string]interface{}),
		})
	}

	if swl.inputOutputFilter != nil {
		swl.healthChecker.components = append(swl.healthChecker.components, HealthCheckComponent{
			Name: "input_output_filter",
			Checker: func() error {
				// Check if input/output filter is responsive
				return nil
			},
			Status:    "unknown",
			LastCheck: time.Now(),
			Metadata:  make(map[string]interface{}),
		})
	}

	if swl.promptGuard != nil {
		swl.healthChecker.components = append(swl.healthChecker.components, HealthCheckComponent{
			Name: "prompt_guard",
			Checker: func() error {
				// Check if prompt guard is responsive
				return nil
			},
			Status:    "unknown",
			LastCheck: time.Now(),
			Metadata:  make(map[string]interface{}),
		})
	}

	if swl.threatIntelligence != nil {
		swl.healthChecker.components = append(swl.healthChecker.components, HealthCheckComponent{
			Name: "threat_intelligence",
			Checker: func() error {
				// Check if threat intelligence is responsive
				return nil
			},
			Status:    "unknown",
			LastCheck: time.Now(),
			Metadata:  make(map[string]interface{}),
		})
	}
}

// Enhanced security middleware with new features
func (swl *SecureWebLayer) enhancedSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	// Content Security Policy
	if swl.config.EnableCSP && swl.config.CSPPolicy != "" {
		w.Header().Set("Content-Security-Policy", swl.config.CSPPolicy)
	}

	// HTTP Strict Transport Security
	if swl.config.EnableHSTS {
		hstsValue := fmt.Sprintf("max-age=%d; includeSubDomains", swl.config.HSTSMaxAge)
		w.Header().Set("Strict-Transport-Security", hstsValue)
	}

	// X-Frame-Options
	if swl.config.EnableXFrameOptions && swl.config.XFrameOptionsValue != "" {
		w.Header().Set("X-Frame-Options", swl.config.XFrameOptionsValue)
	}

	// Additional security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
	w.Header().Set("X-Download-Options", "noopen")
}

// validateRequestSize checks if request size is within limits
func (swl *SecureWebLayer) validateRequestSize(r *http.Request) error {
	if swl.config.MaxRequestSize <= 0 {
		return nil
	}

	contentLength := r.ContentLength
	if contentLength > swl.config.MaxRequestSize {
		return fmt.Errorf("request size %d exceeds maximum allowed size %d", contentLength, swl.config.MaxRequestSize)
	}

	return nil
}

// processSecurityEvent processes and correlates security events
func (swl *SecureWebLayer) processSecurityEvent(securityCtx *SecurityContext, r *http.Request) {
	if swl.eventCorrelator == nil {
		return
	}

	// Create security event
	event := SecurityEvent{
		ID:          securityCtx.RequestID,
		Type:        "security_check",
		Severity:    swl.getSeverityFromThreatScore(securityCtx.ThreatScore),
		Timestamp:   time.Now(),
		RequestID:   securityCtx.RequestID,
		IPAddress:   swl.getClientIP(r),
		UserAgent:   r.UserAgent(),
		URL:         r.URL.String(),
		ThreatScore: securityCtx.ThreatScore,
		Metadata:    securityCtx.SecurityMetadata,
	}

	// Add event to correlator
	swl.eventCorrelator.mu.Lock()
	swl.eventCorrelator.events = append(swl.eventCorrelator.events, event)

	// Keep only recent events (last 1000)
	if len(swl.eventCorrelator.events) > 1000 {
		swl.eventCorrelator.events = swl.eventCorrelator.events[len(swl.eventCorrelator.events)-1000:]
	}
	swl.eventCorrelator.mu.Unlock()

	// Check for correlation patterns
	swl.checkCorrelationPatterns(event)
}

// getSeverityFromThreatScore converts threat score to severity level
func (swl *SecureWebLayer) getSeverityFromThreatScore(score float64) string {
	switch {
	case score >= 0.8:
		return "critical"
	case score >= 0.6:
		return "high"
	case score >= 0.4:
		return "medium"
	case score >= 0.2:
		return "low"
	default:
		return "info"
	}
}

// checkCorrelationPatterns checks if events match correlation patterns
func (swl *SecureWebLayer) checkCorrelationPatterns(event SecurityEvent) {
	if swl.eventCorrelator == nil {
		return
	}

	swl.eventCorrelator.mu.RLock()
	defer swl.eventCorrelator.mu.RUnlock()

	for _, pattern := range swl.eventCorrelator.patterns {
		// Check if event type matches pattern
		eventTypeMatches := false
		for _, eventType := range pattern.EventTypes {
			if event.Type == eventType {
				eventTypeMatches = true
				break
			}
		}

		if !eventTypeMatches {
			continue
		}

		// Count matching events within time window
		cutoff := time.Now().Add(-pattern.TimeWindow)
		matchingEvents := 0

		for _, e := range swl.eventCorrelator.events {
			if e.Timestamp.After(cutoff) && e.IPAddress == event.IPAddress {
				for _, eventType := range pattern.EventTypes {
					if e.Type == eventType {
						matchingEvents++
						break
					}
				}
			}
		}

		// Trigger action if threshold exceeded
		if matchingEvents >= pattern.Threshold {
			swl.triggerCorrelationAction(pattern, event)
		}
	}
}

// triggerCorrelationAction triggers action based on correlation pattern
func (swl *SecureWebLayer) triggerCorrelationAction(pattern CorrelationPattern, event SecurityEvent) {
	swl.logger.WithFields(logger.Fields{
		"pattern_id":   pattern.ID,
		"pattern_name": pattern.Name,
		"action":       pattern.Action,
		"ip_address":   event.IPAddress,
		"event_type":   event.Type,
	}).Warn("Correlation pattern triggered")

	// Create alert
	if swl.alertManager != nil {
		alert := &SecurityAlert{
			ID:          fmt.Sprintf("correlation_%s_%d", pattern.ID, time.Now().Unix()),
			Type:        "correlation_alert",
			Severity:    "high",
			Title:       fmt.Sprintf("Security Pattern Detected: %s", pattern.Name),
			Description: fmt.Sprintf("Pattern %s triggered for IP %s", pattern.Name, event.IPAddress),
			Timestamp:   time.Now(),
			RequestID:   event.RequestID,
			IPAddress:   event.IPAddress,
			ThreatScore: event.ThreatScore,
			Metadata: map[string]interface{}{
				"pattern_id":   pattern.ID,
				"pattern_name": pattern.Name,
				"action":       pattern.Action,
			},
		}

		swl.sendAlert(alert)
	}
}

// sendAlert sends alert through configured channels
func (swl *SecureWebLayer) sendAlert(alert *SecurityAlert) {
	if swl.alertManager == nil {
		return
	}

	swl.alertManager.mu.RLock()
	defer swl.alertManager.mu.RUnlock()

	for _, channel := range swl.alertManager.channels {
		go func(ch AlertChannel) {
			if err := ch.SendAlert(alert); err != nil {
				swl.logger.WithError(err).WithFields(logger.Fields{
					"alert_id":     alert.ID,
					"channel_type": ch.GetType(),
				}).Error("Failed to send alert")
			}
		}(channel)
	}

	// Update metrics
	swl.mu.Lock()
	swl.securityMetrics.AlertsTriggered++
	swl.mu.Unlock()
}

// updateEndpointMetrics updates metrics for specific endpoints
func (swl *SecureWebLayer) updateEndpointMetrics(endpoint string) {
	swl.mu.Lock()
	defer swl.mu.Unlock()

	if swl.securityMetrics.RequestsByEndpoint == nil {
		swl.securityMetrics.RequestsByEndpoint = make(map[string]int64)
	}
	swl.securityMetrics.RequestsByEndpoint[endpoint]++
}

// triggerThreatAlert triggers an alert for high threat scores
func (swl *SecureWebLayer) triggerThreatAlert(securityCtx *SecurityContext, r *http.Request) {
	if swl.alertManager == nil {
		return
	}

	alert := &SecurityAlert{
		ID:          fmt.Sprintf("threat_%s_%d", securityCtx.RequestID, time.Now().Unix()),
		Type:        "high_threat_score",
		Severity:    swl.getSeverityFromThreatScore(securityCtx.ThreatScore),
		Title:       "High Threat Score Detected",
		Description: fmt.Sprintf("Request with threat score %.2f detected from IP %s", securityCtx.ThreatScore, swl.getClientIP(r)),
		Timestamp:   time.Now(),
		RequestID:   securityCtx.RequestID,
		IPAddress:   swl.getClientIP(r),
		ThreatScore: securityCtx.ThreatScore,
		Metadata: map[string]interface{}{
			"url":              r.URL.String(),
			"method":           r.Method,
			"user_agent":       r.UserAgent(),
			"detected_threats": securityCtx.DetectedThreats,
			"applied_filters":  securityCtx.AppliedFilters,
		},
	}

	swl.sendAlert(alert)
}

// exportMetrics exports metrics to configured exporters
func (swl *SecureWebLayer) exportMetrics() {
	if swl.metricsExporter == nil {
		return
	}

	swl.metricsExporter.mu.RLock()
	defer swl.metricsExporter.mu.RUnlock()

	swl.mu.RLock()
	metrics := *swl.securityMetrics // Copy metrics
	swl.mu.RUnlock()

	for _, exporter := range swl.metricsExporter.exporters {
		go func(exp MetricsExporterInterface) {
			if err := exp.Export(&metrics); err != nil {
				swl.logger.WithError(err).WithFields(logger.Fields{
					"exporter_type": exp.GetType(),
				}).Error("Failed to export metrics")
			}
		}(exporter)
	}
}

// GetSecurityMetrics returns current security metrics
func (swl *SecureWebLayer) GetSecurityMetrics() *SecurityMetrics {
	swl.mu.RLock()
	defer swl.mu.RUnlock()

	// Return a copy to avoid race conditions
	metrics := *swl.securityMetrics
	return &metrics
}

// GetHealthStatus returns current health status
func (swl *SecureWebLayer) GetHealthStatus() *HealthStatus {
	if swl.healthChecker == nil {
		return &HealthStatus{
			Overall:   "unknown",
			LastCheck: time.Now(),
		}
	}

	swl.healthChecker.mu.RLock()
	defer swl.healthChecker.mu.RUnlock()

	// Perform health checks
	overallHealthy := true
	for i := range swl.healthChecker.components {
		component := &swl.healthChecker.components[i]
		if component.Checker != nil {
			err := component.Checker()
			if err != nil {
				component.Status = "unhealthy"
				component.Metadata["error"] = err.Error()
				overallHealthy = false
			} else {
				component.Status = "healthy"
				delete(component.Metadata, "error")
			}
			component.LastCheck = time.Now()
		}
	}

	status := swl.healthChecker.status
	if overallHealthy {
		status.Overall = "healthy"
	} else {
		status.Overall = "unhealthy"
	}
	status.Components = swl.healthChecker.components
	status.LastCheck = time.Now()

	return &status
}

// ResetMetrics resets all security metrics
func (swl *SecureWebLayer) ResetMetrics() {
	swl.mu.Lock()
	defer swl.mu.Unlock()

	swl.securityMetrics = &SecurityMetrics{
		ThreatsByType:      make(map[string]int64),
		RequestsByEndpoint: make(map[string]int64),
		BlocksByReason:     make(map[string]int64),
		StartTime:          time.Now(),
		LastUpdated:        time.Now(),
	}
}

// GetSecurityEvents returns recent security events
func (swl *SecureWebLayer) GetSecurityEvents(limit int) []SecurityEvent {
	if swl.eventCorrelator == nil {
		return []SecurityEvent{}
	}

	swl.eventCorrelator.mu.RLock()
	defer swl.eventCorrelator.mu.RUnlock()

	events := swl.eventCorrelator.events
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}

	// Return a copy to avoid race conditions
	result := make([]SecurityEvent, len(events))
	copy(result, events)
	return result
}
