package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var securityProxyTracer = otel.Tracer("hackai/llm/security_proxy")

// SecurityProxy represents the main LLM security proxy service
type SecurityProxy struct {
	logger           *logger.Logger
	config           *SecurityProxyConfig
	policyEngine     PolicyEngine
	contentFilter    ContentFilter
	rateLimiter      RateLimiter
	auditLogger      AuditLogger
	providerManager  ProviderManager
	metricsCollector MetricsCollector
	securityRepo     domain.LLMSecurityRepository
	policyRepo       domain.SecurityPolicyRepository
}

// SecurityProxyConfig holds configuration for the security proxy
type SecurityProxyConfig struct {
	// Request Processing
	MaxRequestSize  int64         `json:"max_request_size"`
	MaxResponseSize int64         `json:"max_response_size"`
	RequestTimeout  time.Duration `json:"request_timeout"`

	// Security Settings
	EnableContentFilter bool    `json:"enable_content_filter"`
	EnableRateLimit     bool    `json:"enable_rate_limit"`
	EnablePolicyEngine  bool    `json:"enable_policy_engine"`
	ThreatThreshold     float64 `json:"threat_threshold"`
	BlockOnViolation    bool    `json:"block_on_violation"`

	// Audit and Logging
	EnableAuditLogging bool `json:"enable_audit_logging"`
	LogRequestContent  bool `json:"log_request_content"`
	LogResponseContent bool `json:"log_response_content"`

	// Performance
	MaxConcurrentRequests int           `json:"max_concurrent_requests"`
	CacheEnabled          bool          `json:"cache_enabled"`
	CacheTTL              time.Duration `json:"cache_ttl"`
}

// LLMRequest represents an incoming LLM request
type LLMRequest struct {
	ID        string                 `json:"id"`
	UserID    *uuid.UUID             `json:"user_id"`
	SessionID *uuid.UUID             `json:"session_id"`
	Provider  string                 `json:"provider"`
	Model     string                 `json:"model"`
	Endpoint  string                 `json:"endpoint"`
	Method    string                 `json:"method"`
	Headers   map[string]string      `json:"headers"`
	Body      json.RawMessage        `json:"body"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Timestamp time.Time              `json:"timestamp"`
	Context   map[string]interface{} `json:"context"`
}

// LLMResponse represents an LLM response
type LLMResponse struct {
	ID         string                 `json:"id"`
	RequestID  string                 `json:"request_id"`
	StatusCode int                    `json:"status_code"`
	Headers    map[string]string      `json:"headers"`
	Body       json.RawMessage        `json:"body"`
	Duration   time.Duration          `json:"duration"`
	TokensUsed int                    `json:"tokens_used"`
	Cost       float64                `json:"cost"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// SecurityResult represents the result of security analysis
type SecurityResult struct {
	Allowed         bool                   `json:"allowed"`
	ThreatScore     float64                `json:"threat_score"`
	Violations      []PolicyViolation      `json:"violations"`
	BlockReason     string                 `json:"block_reason"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	PolicyID    uuid.UUID              `json:"policy_id"`
	PolicyName  string                 `json:"policy_name"`
	RuleID      uuid.UUID              `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Score       float64                `json:"score"`
}

// NewSecurityProxy creates a new security proxy instance
func NewSecurityProxy(
	logger *logger.Logger,
	config *SecurityProxyConfig,
	policyEngine PolicyEngine,
	contentFilter ContentFilter,
	rateLimiter RateLimiter,
	auditLogger AuditLogger,
	providerManager ProviderManager,
	metricsCollector MetricsCollector,
	securityRepo domain.LLMSecurityRepository,
	policyRepo domain.SecurityPolicyRepository,
) *SecurityProxy {
	return &SecurityProxy{
		logger:           logger,
		config:           config,
		policyEngine:     policyEngine,
		contentFilter:    contentFilter,
		rateLimiter:      rateLimiter,
		auditLogger:      auditLogger,
		providerManager:  providerManager,
		metricsCollector: metricsCollector,
		securityRepo:     securityRepo,
		policyRepo:       policyRepo,
	}
}

// ProcessRequest processes an incoming LLM request through the security pipeline
func (sp *SecurityProxy) ProcessRequest(ctx context.Context, req *LLMRequest) (*LLMResponse, error) {
	ctx, span := securityProxyTracer.Start(ctx, "security_proxy.process_request")
	defer span.End()

	span.SetAttributes(
		attribute.String("request.id", req.ID),
		attribute.String("request.provider", req.Provider),
		attribute.String("request.model", req.Model),
		attribute.String("request.endpoint", req.Endpoint),
	)

	startTime := time.Now()

	// Initialize request log
	requestLog := &domain.LLMRequestLog{
		RequestID:   req.ID,
		UserID:      req.UserID,
		SessionID:   req.SessionID,
		Provider:    req.Provider,
		Model:       req.Model,
		Endpoint:    req.Endpoint,
		PromptHash:  sp.hashContent(req.Body),
		RequestSize: int64(len(req.Body)),
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
		CreatedAt:   startTime,
	}

	// Step 1: Rate Limiting
	if sp.config.EnableRateLimit {
		if allowed, err := sp.rateLimiter.CheckLimit(ctx, req); err != nil {
			sp.logger.WithError(err).Error("Rate limit check failed")
			return nil, fmt.Errorf("rate limit check failed: %w", err)
		} else if !allowed {
			requestLog.Blocked = true
			requestLog.BlockReason = "rate_limit_exceeded"
			requestLog.StatusCode = http.StatusTooManyRequests

			sp.recordRequestLog(ctx, requestLog)
			return sp.createErrorResponse(req.ID, http.StatusTooManyRequests, "Rate limit exceeded"), nil
		}
	}

	// Step 2: Content Filtering
	var securityResult *SecurityResult
	if sp.config.EnableContentFilter {
		result, err := sp.contentFilter.FilterRequest(ctx, req)
		if err != nil {
			sp.logger.WithError(err).Error("Content filtering failed")
			return nil, fmt.Errorf("content filtering failed: %w", err)
		}
		securityResult = result

		if !result.Allowed && sp.config.BlockOnViolation {
			requestLog.Blocked = true
			requestLog.BlockReason = result.BlockReason
			requestLog.ThreatScore = result.ThreatScore
			requestLog.StatusCode = http.StatusForbidden

			sp.recordViolations(ctx, req, result.Violations)
			sp.recordRequestLog(ctx, requestLog)
			return sp.createErrorResponse(req.ID, http.StatusForbidden, result.BlockReason), nil
		}
	}

	// Step 3: Policy Engine Evaluation
	if sp.config.EnablePolicyEngine {
		policyResult, err := sp.policyEngine.EvaluateRequest(ctx, req)
		if err != nil {
			sp.logger.WithError(err).Error("Policy evaluation failed")
			return nil, fmt.Errorf("policy evaluation failed: %w", err)
		}

		// Merge security results
		if securityResult == nil {
			securityResult = policyResult
		} else {
			securityResult = sp.mergeSecurityResults(securityResult, policyResult)
		}

		if !policyResult.Allowed && sp.config.BlockOnViolation {
			requestLog.Blocked = true
			requestLog.BlockReason = policyResult.BlockReason
			requestLog.ThreatScore = policyResult.ThreatScore
			requestLog.StatusCode = http.StatusForbidden

			sp.recordViolations(ctx, req, policyResult.Violations)
			sp.recordRequestLog(ctx, requestLog)
			return sp.createErrorResponse(req.ID, http.StatusForbidden, policyResult.BlockReason), nil
		}
	}

	// Step 4: Forward to LLM Provider
	response, err := sp.forwardToProvider(ctx, req)
	if err != nil {
		sp.logger.WithError(err).Error("Failed to forward request to provider")
		requestLog.StatusCode = http.StatusInternalServerError
		requestLog.BlockReason = "provider_error"
		sp.recordRequestLog(ctx, requestLog)
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}

	// Step 5: Response Processing
	if sp.config.EnableContentFilter {
		filteredResponse, err := sp.contentFilter.FilterResponse(ctx, response)
		if err != nil {
			sp.logger.WithError(err).Error("Response filtering failed")
			return nil, fmt.Errorf("response filtering failed: %w", err)
		}
		response = filteredResponse
	}

	// Step 6: Update Request Log
	duration := time.Since(startTime)
	requestLog.DurationMs = duration.Milliseconds()
	requestLog.StatusCode = response.StatusCode
	requestLog.ResponseSize = int64(len(response.Body))
	requestLog.TotalTokens = response.TokensUsed

	if securityResult != nil {
		requestLog.ThreatScore = securityResult.ThreatScore
		if len(securityResult.Violations) > 0 {
			violationsJSON, _ := json.Marshal(securityResult.Violations)
			requestLog.PolicyViolations = violationsJSON
		}
	}

	// Step 7: Audit Logging
	if sp.config.EnableAuditLogging {
		if err := sp.auditLogger.LogRequest(ctx, req, response, securityResult); err != nil {
			sp.logger.WithError(err).Error("Failed to log audit entry")
		}
	}

	// Step 8: Metrics Collection
	sp.metricsCollector.RecordRequest(ctx, req, response, securityResult)

	// Step 9: Record Request Log
	sp.recordRequestLog(ctx, requestLog)

	span.SetAttributes(
		attribute.Int("response.status_code", response.StatusCode),
		attribute.Int64("response.duration_ms", duration.Milliseconds()),
		attribute.Float64("security.threat_score", requestLog.ThreatScore),
		attribute.Bool("security.blocked", requestLog.Blocked),
	)

	return response, nil
}

// hashContent creates a hash of the content for privacy
func (sp *SecurityProxy) hashContent(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// createErrorResponse creates an error response
func (sp *SecurityProxy) createErrorResponse(requestID string, statusCode int, message string) *LLMResponse {
	errorBody := map[string]interface{}{
		"error": map[string]interface{}{
			"message": message,
			"type":    "security_violation",
			"code":    statusCode,
		},
	}

	bodyBytes, _ := json.Marshal(errorBody)

	return &LLMResponse{
		ID:         uuid.New().String(),
		RequestID:  requestID,
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       bodyBytes,
		Duration:   0,
		TokensUsed: 0,
		Cost:       0,
		Timestamp:  time.Now(),
		Metadata:   map[string]interface{}{"blocked": true},
	}
}

// recordRequestLog records the request log to the database
func (sp *SecurityProxy) recordRequestLog(ctx context.Context, log *domain.LLMRequestLog) {
	if err := sp.securityRepo.CreateRequestLog(ctx, log); err != nil {
		sp.logger.WithError(err).Error("Failed to record request log")
	}
}

// recordViolations records policy violations
func (sp *SecurityProxy) recordViolations(ctx context.Context, req *LLMRequest, violations []PolicyViolation) {
	for _, violation := range violations {
		policyViolation := &domain.PolicyViolation{
			PolicyID:      violation.PolicyID,
			RequestID:     req.ID,
			UserID:        req.UserID,
			SessionID:     req.SessionID,
			ViolationType: violation.RuleName,
			Severity:      violation.Severity,
			Description:   violation.Description,
			RiskScore:     violation.Score,
			ActionTaken:   "blocked",
			Blocked:       true,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
		}

		evidenceJSON, _ := json.Marshal(violation.Evidence)
		policyViolation.Evidence = evidenceJSON

		if err := sp.policyRepo.CreateViolation(ctx, policyViolation); err != nil {
			sp.logger.WithError(err).Error("Failed to record policy violation")
		}
	}
}

// forwardToProvider forwards the request to the appropriate LLM provider
func (sp *SecurityProxy) forwardToProvider(ctx context.Context, req *LLMRequest) (*LLMResponse, error) {
	ctx, span := securityProxyTracer.Start(ctx, "security_proxy.forward_to_provider")
	defer span.End()

	// Get provider
	provider, err := sp.providerManager.GetProvider(ctx, req.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider %s: %w", req.Provider, err)
	}

	// Forward request
	startTime := time.Now()
	response, err := provider.ProcessRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("provider request failed: %w", err)
	}

	response.Duration = time.Since(startTime)
	response.RequestID = req.ID
	response.Timestamp = time.Now()

	return response, nil
}

// mergeSecurityResults merges multiple security results
func (sp *SecurityProxy) mergeSecurityResults(result1, result2 *SecurityResult) *SecurityResult {
	merged := &SecurityResult{
		Allowed:         result1.Allowed && result2.Allowed,
		ThreatScore:     max(result1.ThreatScore, result2.ThreatScore),
		Violations:      append(result1.Violations, result2.Violations...),
		Recommendations: append(result1.Recommendations, result2.Recommendations...),
		Metadata:        make(map[string]interface{}),
	}

	// Merge metadata
	for k, v := range result1.Metadata {
		merged.Metadata[k] = v
	}
	for k, v := range result2.Metadata {
		merged.Metadata[k] = v
	}

	// Set block reason from the most severe violation
	if !merged.Allowed {
		if result1.ThreatScore >= result2.ThreatScore {
			merged.BlockReason = result1.BlockReason
		} else {
			merged.BlockReason = result2.BlockReason
		}
	}

	return merged
}

// GetStats returns proxy statistics
func (sp *SecurityProxy) GetStats(ctx context.Context) (*ProxyStats, error) {
	// Get basic stats from repository
	filter := domain.RequestLogFilter{
		StartTime: timePtr(time.Now().Add(-24 * time.Hour)),
		EndTime:   timePtr(time.Now()),
	}

	stats, err := sp.securityRepo.GetRequestLogStats(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get request log stats: %w", err)
	}

	return &ProxyStats{
		TotalRequests:      stats.TotalRequests,
		BlockedRequests:    stats.BlockedRequests,
		AverageThreatScore: stats.AverageThreatScore,
		TotalTokens:        stats.TotalTokens,
		AverageDuration:    stats.AverageDuration,
		Uptime:             time.Since(time.Now()), // This should be actual uptime
	}, nil
}

// GetThreatTrends returns threat trends
func (sp *SecurityProxy) GetThreatTrends(ctx context.Context, timeRange time.Duration) (*domain.ThreatTrends, error) {
	return sp.securityRepo.GetThreatTrends(ctx, timeRange)
}

// GetTopThreats returns top threats
func (sp *SecurityProxy) GetTopThreats(ctx context.Context, limit int, timeRange time.Duration) ([]*domain.ThreatSummary, error) {
	return sp.securityRepo.GetTopThreats(ctx, limit, timeRange)
}

// Health checks the health of the security proxy
func (sp *SecurityProxy) Health(ctx context.Context) error {
	// Check database connectivity
	if _, err := sp.securityRepo.GetRequestLogStats(ctx, domain.RequestLogFilter{Limit: 1}); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	// Check provider manager
	if err := sp.providerManager.Health(ctx); err != nil {
		return fmt.Errorf("provider manager health check failed: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the security proxy
func (sp *SecurityProxy) Shutdown(ctx context.Context) error {
	sp.logger.Info("Shutting down security proxy")

	// Shutdown components
	if err := sp.providerManager.Shutdown(ctx); err != nil {
		sp.logger.WithError(err).Error("Failed to shutdown provider manager")
	}

	if err := sp.metricsCollector.Shutdown(ctx); err != nil {
		sp.logger.WithError(err).Error("Failed to shutdown metrics collector")
	}

	sp.logger.Info("Security proxy shutdown complete")
	return nil
}

// Helper functions and types

// ProxyStats represents proxy statistics
type ProxyStats struct {
	TotalRequests      int64         `json:"total_requests"`
	BlockedRequests    int64         `json:"blocked_requests"`
	AverageThreatScore float64       `json:"average_threat_score"`
	TotalTokens        int64         `json:"total_tokens"`
	AverageDuration    float64       `json:"average_duration"`
	Uptime             time.Duration `json:"uptime"`
}

// Interface definitions for dependency injection

// PolicyEngine interface for policy evaluation
type PolicyEngine interface {
	EvaluateRequest(ctx context.Context, req *LLMRequest) (*SecurityResult, error)
	GetActivePolicies(ctx context.Context, scope string, targetID *uuid.UUID) ([]*domain.SecurityPolicy, error)
	Health(ctx context.Context) error
}

// ContentFilter interface for content filtering
type ContentFilter interface {
	FilterRequest(ctx context.Context, req *LLMRequest) (*SecurityResult, error)
	FilterResponse(ctx context.Context, resp *LLMResponse) (*LLMResponse, error)
	Health(ctx context.Context) error
}

// RateLimiter interface for rate limiting
type RateLimiter interface {
	CheckLimit(ctx context.Context, req *LLMRequest) (bool, error)
	GetQuota(ctx context.Context, userID uuid.UUID) (*domain.LLMUsageQuota, error)
	IncrementUsage(ctx context.Context, userID uuid.UUID, tokens int, cost float64) error
	Health(ctx context.Context) error
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogRequest(ctx context.Context, req *LLMRequest, resp *LLMResponse, security *SecurityResult) error
	Health(ctx context.Context) error
}

// ProviderManager interface for managing LLM providers
type ProviderManager interface {
	GetProvider(ctx context.Context, name string) (LLMProvider, error)
	ListProviders(ctx context.Context) ([]string, error)
	Health(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// LLMProvider interface for LLM providers
type LLMProvider interface {
	ProcessRequest(ctx context.Context, req *LLMRequest) (*LLMResponse, error)
	GetModels(ctx context.Context) ([]string, error)
	Health(ctx context.Context) error
}

// MetricsCollector interface for metrics collection
type MetricsCollector interface {
	RecordRequest(ctx context.Context, req *LLMRequest, resp *LLMResponse, security *SecurityResult)
	GetMetrics(ctx context.Context) (map[string]interface{}, error)
	Shutdown(ctx context.Context) error
}

// DefaultSecurityProxyConfig returns default configuration
func DefaultSecurityProxyConfig() *SecurityProxyConfig {
	return &SecurityProxyConfig{
		MaxRequestSize:        10 * 1024 * 1024, // 10MB
		MaxResponseSize:       50 * 1024 * 1024, // 50MB
		RequestTimeout:        30 * time.Second,
		EnableContentFilter:   true,
		EnableRateLimit:       true,
		EnablePolicyEngine:    true,
		ThreatThreshold:       0.7,
		BlockOnViolation:      true,
		EnableAuditLogging:    true,
		LogRequestContent:     false, // Privacy consideration
		LogResponseContent:    false, // Privacy consideration
		MaxConcurrentRequests: 100,
		CacheEnabled:          false,
		CacheTTL:              5 * time.Minute,
	}
}

// Helper functions
func timePtr(t time.Time) *time.Time {
	return &t
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
