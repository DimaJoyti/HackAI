package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
)

var middlewareTracer = otel.Tracer("hackai/audit/llm_audit_middleware")

// LLMAuditMiddleware provides audit logging middleware for LLM requests
type LLMAuditMiddleware struct {
	logger      *logger.Logger
	auditLogger *LLMAuditLogger
	config      *MiddlewareConfig
}

// MiddlewareConfig represents middleware configuration
type MiddlewareConfig struct {
	Enabled               bool     `json:"enabled"`
	LogSuccessfulRequests bool     `json:"log_successful_requests"`
	LogFailedRequests     bool     `json:"log_failed_requests"`
	LogBlockedRequests    bool     `json:"log_blocked_requests"`
	LogSecurityViolations bool     `json:"log_security_violations"`
	LogPolicyDecisions    bool     `json:"log_policy_decisions"`
	ExcludedEndpoints     []string `json:"excluded_endpoints"`
	ExcludedProviders     []string `json:"excluded_providers"`
	MinThreatScoreToLog   float64  `json:"min_threat_score_to_log"`
	SampleRate            float64  `json:"sample_rate"` // 0.0 to 1.0
}

// LLMRequestProcessor defines the interface for processing LLM requests
type LLMRequestProcessor interface {
	ProcessRequest(ctx context.Context, req *security.LLMRequest) (*security.LLMResponse, error)
}

// NewLLMAuditMiddleware creates a new LLM audit middleware
func NewLLMAuditMiddleware(
	logger *logger.Logger,
	auditLogger *LLMAuditLogger,
	config *MiddlewareConfig,
) *LLMAuditMiddleware {
	if config == nil {
		config = DefaultMiddlewareConfig()
	}

	return &LLMAuditMiddleware{
		logger:      logger,
		auditLogger: auditLogger,
		config:      config,
	}
}

// ProcessRequest wraps the LLM request processing with audit logging
func (m *LLMAuditMiddleware) ProcessRequest(
	ctx context.Context,
	req *security.LLMRequest,
	processor LLMRequestProcessor,
) (*security.LLMResponse, error) {
	if !m.config.Enabled {
		return processor.ProcessRequest(ctx, req)
	}

	ctx, span := middlewareTracer.Start(ctx, "llm_audit_middleware.process_request")
	defer span.End()

	// Check if request should be excluded from audit logging
	if m.shouldExcludeRequest(req) {
		return processor.ProcessRequest(ctx, req)
	}

	// Check sampling rate
	if !m.shouldSampleRequest() {
		return processor.ProcessRequest(ctx, req)
	}

	startTime := time.Now()

	// Process the request
	resp, err := processor.ProcessRequest(ctx, req)

	// Determine if we should log this request
	shouldLog := m.shouldLogRequest(req, resp, err)
	if !shouldLog {
		return resp, err
	}

	// Log the request asynchronously
	go func() {
		auditCtx := context.Background() // Use background context for async logging
		if logErr := m.auditLogger.LogLLMRequest(auditCtx, req, resp); logErr != nil {
			m.logger.WithError(logErr).Error("Failed to log LLM request audit")
		}
	}()

	span.SetAttributes(
		attribute.String("audit.request_id", req.ID),
		attribute.String("audit.provider", req.Provider),
		attribute.String("audit.model", req.Model),
		attribute.Bool("audit.logged", shouldLog),
		attribute.Int64("audit.processing_time_ms", time.Since(startTime).Milliseconds()),
	)

	return resp, err
}

// LogSecurityViolation logs a security violation
func (m *LLMAuditMiddleware) LogSecurityViolation(ctx context.Context, violation *domain.PolicyViolation) {
	if !m.config.Enabled || !m.config.LogSecurityViolations {
		return
	}

	ctx, span := middlewareTracer.Start(ctx, "llm_audit_middleware.log_security_violation")
	defer span.End()

	// Log asynchronously
	go func() {
		auditCtx := context.Background()
		if err := m.auditLogger.LogSecurityViolation(auditCtx, violation); err != nil {
			m.logger.WithError(err).Error("Failed to log security violation audit")
		}
	}()

	span.SetAttributes(
		attribute.String("audit.violation_type", violation.ViolationType),
		attribute.String("audit.severity", violation.Severity),
		attribute.Float64("audit.risk_score", violation.RiskScore),
	)
}

// LogPolicyDecision logs a policy evaluation decision
func (m *LLMAuditMiddleware) LogPolicyDecision(ctx context.Context, decision *PolicyDecision) {
	if !m.config.Enabled || !m.config.LogPolicyDecisions {
		return
	}

	ctx, span := middlewareTracer.Start(ctx, "llm_audit_middleware.log_policy_decision")
	defer span.End()

	// Log asynchronously
	go func() {
		auditCtx := context.Background()
		if err := m.auditLogger.LogPolicyDecision(auditCtx, decision); err != nil {
			m.logger.WithError(err).Error("Failed to log policy decision audit")
		}
	}()

	span.SetAttributes(
		attribute.String("audit.policy_name", decision.PolicyName),
		attribute.String("audit.decision", decision.Decision),
		attribute.Float64("audit.score", decision.Score),
	)
}

// Helper methods

// shouldExcludeRequest determines if a request should be excluded from audit logging
func (m *LLMAuditMiddleware) shouldExcludeRequest(req *security.LLMRequest) bool {
	// Check excluded endpoints
	for _, endpoint := range m.config.ExcludedEndpoints {
		if req.Endpoint == endpoint {
			return true
		}
	}

	// Check excluded providers
	for _, provider := range m.config.ExcludedProviders {
		if req.Provider == provider {
			return true
		}
	}

	return false
}

// shouldSampleRequest determines if a request should be sampled for audit logging
func (m *LLMAuditMiddleware) shouldSampleRequest() bool {
	if m.config.SampleRate >= 1.0 {
		return true
	}
	if m.config.SampleRate <= 0.0 {
		return false
	}

	// Simple sampling based on UUID
	id := uuid.New()
	// Use the first byte of the UUID for sampling
	return float64(id[0])/255.0 < m.config.SampleRate
}

// shouldLogRequest determines if a request should be logged based on configuration
func (m *LLMAuditMiddleware) shouldLogRequest(req *security.LLMRequest, resp *security.LLMResponse, err error) bool {
	// Always log if there was an error
	if err != nil {
		return m.config.LogFailedRequests
	}

	// Check if response indicates blocking
	if resp != nil && resp.StatusCode >= 400 {
		return m.config.LogBlockedRequests
	}

	// Check threat score threshold
	if threatScore := m.getThreatScore(req, resp); threatScore >= m.config.MinThreatScoreToLog {
		return true
	}

	// Log successful requests if configured
	return m.config.LogSuccessfulRequests
}

// getThreatScore extracts threat score from request or response
func (m *LLMAuditMiddleware) getThreatScore(req *security.LLMRequest, resp *security.LLMResponse) float64 {
	// Try to get threat score from response metadata
	if resp != nil && resp.Metadata != nil {
		if score, ok := resp.Metadata["threat_score"].(float64); ok {
			return score
		}
	}

	// Try to get threat score from request context
	if req.Context != nil {
		if score, ok := req.Context["threat_score"].(float64); ok {
			return score
		}
	}

	return 0.0
}

// CreatePolicyDecision creates a policy decision from evaluation results
func (m *LLMAuditMiddleware) CreatePolicyDecision(
	policyID uuid.UUID,
	policyName string,
	decision string,
	reason string,
	score float64,
	executionTime time.Duration,
	metadata map[string]interface{},
) *PolicyDecision {
	return &PolicyDecision{
		PolicyID:      policyID,
		PolicyName:    policyName,
		Decision:      decision,
		Reason:        reason,
		Score:         score,
		ExecutionTime: executionTime,
		Metadata:      metadata,
		Timestamp:     time.Now(),
	}
}

// GetAuditStats returns audit statistics
func (m *LLMAuditMiddleware) GetAuditStats() *AuditStats {
	return &AuditStats{
		Enabled:               m.config.Enabled,
		LogSuccessfulRequests: m.config.LogSuccessfulRequests,
		LogFailedRequests:     m.config.LogFailedRequests,
		LogBlockedRequests:    m.config.LogBlockedRequests,
		LogSecurityViolations: m.config.LogSecurityViolations,
		LogPolicyDecisions:    m.config.LogPolicyDecisions,
		SampleRate:            m.config.SampleRate,
		MinThreatScoreToLog:   m.config.MinThreatScoreToLog,
	}
}

// AuditStats represents audit middleware statistics
type AuditStats struct {
	Enabled               bool    `json:"enabled"`
	LogSuccessfulRequests bool    `json:"log_successful_requests"`
	LogFailedRequests     bool    `json:"log_failed_requests"`
	LogBlockedRequests    bool    `json:"log_blocked_requests"`
	LogSecurityViolations bool    `json:"log_security_violations"`
	LogPolicyDecisions    bool    `json:"log_policy_decisions"`
	SampleRate            float64 `json:"sample_rate"`
	MinThreatScoreToLog   float64 `json:"min_threat_score_to_log"`
}

// DefaultMiddlewareConfig returns default middleware configuration
func DefaultMiddlewareConfig() *MiddlewareConfig {
	return &MiddlewareConfig{
		Enabled:               true,
		LogSuccessfulRequests: true,
		LogFailedRequests:     true,
		LogBlockedRequests:    true,
		LogSecurityViolations: true,
		LogPolicyDecisions:    true,
		ExcludedEndpoints:     []string{"/health", "/metrics"},
		ExcludedProviders:     []string{},
		MinThreatScoreToLog:   0.0,
		SampleRate:            1.0, // Log all requests by default
	}
}
