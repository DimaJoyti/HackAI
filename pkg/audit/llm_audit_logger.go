package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
)

var auditTracer = otel.Tracer("hackai/audit/llm_audit_logger")

// LLMAuditLogger handles comprehensive audit logging for LLM interactions
type LLMAuditLogger struct {
	logger    *logger.Logger
	auditRepo domain.AuditRepository
	config    *AuditConfig

	// Async processing
	auditChan     chan *AuditEntry
	batchSize     int
	flushInterval time.Duration
	shutdown      chan struct{}
	done          chan struct{}
}

// AuditConfig represents audit logging configuration
type AuditConfig struct {
	Enabled               bool          `json:"enabled"`
	LogLevel              string        `json:"log_level"`
	IncludeRequestBody    bool          `json:"include_request_body"`
	IncludeResponseBody   bool          `json:"include_response_body"`
	MaskSensitiveData     bool          `json:"mask_sensitive_data"`
	RetentionPeriod       time.Duration `json:"retention_period"`
	BatchSize             int           `json:"batch_size"`
	FlushInterval         time.Duration `json:"flush_interval"`
	CompressLargePayloads bool          `json:"compress_large_payloads"`
	MaxPayloadSize        int           `json:"max_payload_size"`
	SensitiveFields       []string      `json:"sensitive_fields"`
}

// AuditEntry represents a comprehensive audit log entry
type AuditEntry struct {
	ID        uuid.UUID  `json:"id"`
	Timestamp time.Time  `json:"timestamp"`
	RequestID string     `json:"request_id"`
	SessionID *uuid.UUID `json:"session_id,omitempty"`
	UserID    *uuid.UUID `json:"user_id,omitempty"`

	// Request Information
	Provider       string            `json:"provider"`
	Model          string            `json:"model"`
	Endpoint       string            `json:"endpoint"`
	Method         string            `json:"method"`
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
	RequestBody    json.RawMessage   `json:"request_body,omitempty"`
	RequestSize    int64             `json:"request_size"`

	// Response Information
	ResponseStatus  int               `json:"response_status"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    json.RawMessage   `json:"response_body,omitempty"`
	ResponseSize    int64             `json:"response_size"`

	// Security Information
	ThreatScore        float64             `json:"threat_score"`
	SecurityViolations []SecurityViolation `json:"security_violations,omitempty"`
	PolicyDecisions    []PolicyDecision    `json:"policy_decisions,omitempty"`
	Blocked            bool                `json:"blocked"`
	BlockReason        string              `json:"block_reason,omitempty"`

	// Performance Metrics
	ProcessingTime time.Duration `json:"processing_time"`
	TokensUsed     int           `json:"tokens_used"`
	Cost           float64       `json:"cost"`
	CacheHit       bool          `json:"cache_hit"`

	// Network Information
	ClientIP    string           `json:"client_ip"`
	UserAgent   string           `json:"user_agent"`
	Geolocation *GeolocationInfo `json:"geolocation,omitempty"`

	// Compliance and Audit
	ComplianceFlags    []string `json:"compliance_flags,omitempty"`
	DataClassification string   `json:"data_classification"`
	RetentionCategory  string   `json:"retention_category"`

	// Additional Context
	Tags     []string               `json:"tags,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Audit Trail
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// SecurityViolation represents a security policy violation
type SecurityViolation struct {
	PolicyID      uuid.UUID              `json:"policy_id"`
	PolicyName    string                 `json:"policy_name"`
	ViolationType string                 `json:"violation_type"`
	Severity      string                 `json:"severity"`
	Description   string                 `json:"description"`
	Evidence      map[string]interface{} `json:"evidence"`
	Score         float64                `json:"score"`
	Timestamp     time.Time              `json:"timestamp"`
}

// PolicyDecision represents a policy evaluation decision
type PolicyDecision struct {
	PolicyID      uuid.UUID              `json:"policy_id"`
	PolicyName    string                 `json:"policy_name"`
	Decision      string                 `json:"decision"` // allow, block, warn
	Reason        string                 `json:"reason"`
	Score         float64                `json:"score"`
	ExecutionTime time.Duration          `json:"execution_time"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
}

// GeolocationInfo represents client geolocation information
type GeolocationInfo struct {
	Country      string  `json:"country"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	ISP          string  `json:"isp"`
	Organization string  `json:"organization"`
}

// NewLLMAuditLogger creates a new LLM audit logger
func NewLLMAuditLogger(
	logger *logger.Logger,
	auditRepo domain.AuditRepository,
	config *AuditConfig,
) *LLMAuditLogger {
	if config == nil {
		config = DefaultAuditConfig()
	}

	return &LLMAuditLogger{
		logger:        logger,
		auditRepo:     auditRepo,
		config:        config,
		auditChan:     make(chan *AuditEntry, config.BatchSize*2),
		batchSize:     config.BatchSize,
		flushInterval: config.FlushInterval,
		shutdown:      make(chan struct{}),
		done:          make(chan struct{}),
	}
}

// Start starts the audit logger
func (al *LLMAuditLogger) Start(ctx context.Context) error {
	if !al.config.Enabled {
		al.logger.Info("LLM audit logging is disabled")
		return nil
	}

	al.logger.Info("Starting LLM audit logger")

	// Start batch processor
	go al.processBatches(ctx)

	al.logger.Info("LLM audit logger started")
	return nil
}

// Stop stops the audit logger
func (al *LLMAuditLogger) Stop() error {
	if !al.config.Enabled {
		return nil
	}

	al.logger.Info("Stopping LLM audit logger")

	close(al.shutdown)
	<-al.done

	al.logger.Info("LLM audit logger stopped")
	return nil
}

// LogLLMRequest logs an LLM request with comprehensive audit information
func (al *LLMAuditLogger) LogLLMRequest(ctx context.Context, req *security.LLMRequest, resp *security.LLMResponse) error {
	if !al.config.Enabled {
		return nil
	}

	ctx, span := auditTracer.Start(ctx, "llm_audit_logger.log_llm_request")
	defer span.End()

	entry := &AuditEntry{
		ID:          uuid.New(),
		Timestamp:   time.Now(),
		RequestID:   req.ID,
		SessionID:   req.SessionID,
		UserID:      req.UserID,
		Provider:    req.Provider,
		Model:       req.Model,
		Endpoint:    req.Endpoint,
		Method:      req.Method,
		RequestSize: int64(len(req.Body)),
		ClientIP:    req.IPAddress,
		UserAgent:   req.UserAgent,
		CreatedAt:   time.Now(),
		CreatedBy:   "llm_audit_logger",
	}

	// Process request headers
	if al.config.IncludeRequestBody {
		entry.RequestHeaders = al.maskSensitiveHeaders(req.Headers)
	}

	// Process request body
	if al.config.IncludeRequestBody {
		entry.RequestBody = al.processRequestBody(req.Body)
	}

	// Process response if available
	if resp != nil {
		entry.ResponseStatus = resp.StatusCode
		entry.ResponseSize = int64(len(resp.Body))
		entry.ProcessingTime = resp.Duration
		entry.TokensUsed = resp.TokensUsed
		entry.Cost = resp.Cost

		if al.config.IncludeResponseBody {
			entry.ResponseHeaders = al.maskSensitiveHeaders(resp.Headers)
			entry.ResponseBody = al.processResponseBody(resp.Body)
		}
	}

	// Add security context if available
	if securityCtx := al.getSecurityContext(ctx); securityCtx != nil {
		entry.ThreatScore = securityCtx.ThreatScore
		entry.Blocked = securityCtx.Blocked
		entry.BlockReason = securityCtx.BlockReason
		entry.SecurityViolations = securityCtx.Violations
		entry.PolicyDecisions = securityCtx.PolicyDecisions
	}

	// Add geolocation if available
	if geo := al.getGeolocation(req.IPAddress); geo != nil {
		entry.Geolocation = geo
	}

	// Add compliance and classification
	entry.DataClassification = al.classifyData(req, resp)
	entry.RetentionCategory = al.determineRetentionCategory(entry)
	entry.ComplianceFlags = al.getComplianceFlags(entry)

	// Add tags and metadata
	entry.Tags = al.generateTags(req, resp)
	entry.Metadata = al.extractMetadata(ctx, req, resp)

	span.SetAttributes(
		attribute.String("audit.request_id", entry.RequestID),
		attribute.String("audit.provider", entry.Provider),
		attribute.String("audit.model", entry.Model),
		attribute.Float64("audit.threat_score", entry.ThreatScore),
		attribute.Bool("audit.blocked", entry.Blocked),
	)

	// Send to batch processor
	select {
	case al.auditChan <- entry:
		return nil
	default:
		al.logger.Warn("Audit channel full, dropping audit entry")
		return fmt.Errorf("audit channel full")
	}
}

// LogSecurityViolation logs a security policy violation
func (al *LLMAuditLogger) LogSecurityViolation(ctx context.Context, violation *domain.PolicyViolation) error {
	if !al.config.Enabled {
		return nil
	}

	ctx, span := auditTracer.Start(ctx, "llm_audit_logger.log_security_violation")
	defer span.End()

	entry := &AuditEntry{
		ID:        uuid.New(),
		Timestamp: time.Now(),
		RequestID: violation.RequestID,
		UserID:    violation.UserID,
		SecurityViolations: []SecurityViolation{
			{
				PolicyID:      violation.PolicyID,
				ViolationType: violation.ViolationType,
				Severity:      violation.Severity,
				Description:   violation.Description,
				Score:         violation.RiskScore,
				Timestamp:     violation.CreatedAt,
			},
		},
		CreatedAt: time.Now(),
		CreatedBy: "security_violation_logger",
	}

	span.SetAttributes(
		attribute.String("audit.violation_type", violation.ViolationType),
		attribute.String("audit.severity", violation.Severity),
		attribute.Float64("audit.risk_score", violation.RiskScore),
	)

	// Send to batch processor
	select {
	case al.auditChan <- entry:
		return nil
	default:
		al.logger.Warn("Audit channel full, dropping security violation entry")
		return fmt.Errorf("audit channel full")
	}
}

// LogPolicyDecision logs a policy evaluation decision
func (al *LLMAuditLogger) LogPolicyDecision(ctx context.Context, decision *PolicyDecision) error {
	if !al.config.Enabled {
		return nil
	}

	ctx, span := auditTracer.Start(ctx, "llm_audit_logger.log_policy_decision")
	defer span.End()

	entry := &AuditEntry{
		ID:              uuid.New(),
		Timestamp:       time.Now(),
		PolicyDecisions: []PolicyDecision{*decision},
		CreatedAt:       time.Now(),
		CreatedBy:       "policy_decision_logger",
	}

	span.SetAttributes(
		attribute.String("audit.policy_name", decision.PolicyName),
		attribute.String("audit.decision", decision.Decision),
		attribute.Float64("audit.score", decision.Score),
	)

	// Send to batch processor
	select {
	case al.auditChan <- entry:
		return nil
	default:
		al.logger.Warn("Audit channel full, dropping policy decision entry")
		return fmt.Errorf("audit channel full")
	}
}

// processBatches processes audit entries in batches
func (al *LLMAuditLogger) processBatches(ctx context.Context) {
	defer close(al.done)

	ticker := time.NewTicker(al.flushInterval)
	defer ticker.Stop()

	batch := make([]*AuditEntry, 0, al.batchSize)

	for {
		select {
		case entry := <-al.auditChan:
			batch = append(batch, entry)

			if len(batch) >= al.batchSize {
				al.flushBatch(ctx, batch)
				batch = batch[:0] // Reset slice
			}

		case <-ticker.C:
			if len(batch) > 0 {
				al.flushBatch(ctx, batch)
				batch = batch[:0] // Reset slice
			}

		case <-al.shutdown:
			// Flush remaining entries
			if len(batch) > 0 {
				al.flushBatch(ctx, batch)
			}

			// Drain remaining entries from channel
			for {
				select {
				case entry := <-al.auditChan:
					batch = append(batch, entry)
					if len(batch) >= al.batchSize {
						al.flushBatch(ctx, batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						al.flushBatch(ctx, batch)
					}
					return
				}
			}

		case <-ctx.Done():
			return
		}
	}
}

// flushBatch flushes a batch of audit entries to storage
func (al *LLMAuditLogger) flushBatch(ctx context.Context, batch []*AuditEntry) {
	if len(batch) == 0 {
		return
	}

	ctx, span := auditTracer.Start(ctx, "llm_audit_logger.flush_batch")
	defer span.End()

	start := time.Now()

	// Convert to domain audit logs
	auditLogs := make([]*domain.AuditLog, len(batch))
	for i, entry := range batch {
		auditLogs[i] = al.convertToDomainAuditLog(entry)
	}

	// Store in repository (one by one since CreateAuditLogs doesn't exist)
	for _, auditLog := range auditLogs {
		if err := al.auditRepo.CreateAuditLog(auditLog); err != nil {
			al.logger.WithError(err).WithField("audit_id", auditLog.ID).Error("Failed to store audit log")
			// Continue with other logs even if one fails
		}
	}

	duration := time.Since(start)

	span.SetAttributes(
		attribute.Int("audit.batch_size", len(batch)),
		attribute.Int64("audit.flush_duration_ms", duration.Milliseconds()),
	)

	al.logger.WithFields(map[string]interface{}{
		"batch_size": len(batch),
		"duration":   duration,
	}).Debug("Audit batch flushed successfully")
}

// Helper methods for data processing

// maskSensitiveHeaders masks sensitive information in headers
func (al *LLMAuditLogger) maskSensitiveHeaders(headers map[string]string) map[string]string {
	if !al.config.MaskSensitiveData {
		return headers
	}

	masked := make(map[string]string)
	sensitiveHeaders := map[string]bool{
		"authorization": true,
		"x-api-key":     true,
		"cookie":        true,
		"set-cookie":    true,
	}

	for key, value := range headers {
		if sensitiveHeaders[key] {
			masked[key] = "***MASKED***"
		} else {
			masked[key] = value
		}
	}

	return masked
}

// processRequestBody processes and potentially masks request body
func (al *LLMAuditLogger) processRequestBody(body []byte) json.RawMessage {
	if len(body) == 0 {
		return nil
	}

	if len(body) > al.config.MaxPayloadSize {
		if al.config.CompressLargePayloads {
			// In a real implementation, you would compress the body
			return json.RawMessage(`{"_compressed": true, "_original_size": ` + fmt.Sprintf("%d", len(body)) + `}`)
		}
		return json.RawMessage(`{"_truncated": true, "_original_size": ` + fmt.Sprintf("%d", len(body)) + `}`)
	}

	if al.config.MaskSensitiveData {
		return al.maskSensitiveContent(body)
	}

	return json.RawMessage(body)
}

// processResponseBody processes and potentially masks response body
func (al *LLMAuditLogger) processResponseBody(body []byte) json.RawMessage {
	return al.processRequestBody(body) // Same logic for now
}

// maskSensitiveContent masks sensitive content in JSON payloads
func (al *LLMAuditLogger) maskSensitiveContent(body []byte) json.RawMessage {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		// If not valid JSON, return as-is
		return json.RawMessage(body)
	}

	// Mask sensitive fields
	for _, field := range al.config.SensitiveFields {
		if _, exists := data[field]; exists {
			data[field] = "***MASKED***"
		}
	}

	masked, err := json.Marshal(data)
	if err != nil {
		return json.RawMessage(body)
	}

	return json.RawMessage(masked)
}

// getSecurityContext extracts security context from request context
func (al *LLMAuditLogger) getSecurityContext(ctx context.Context) *SecurityContext {
	// This would extract security context from the request context
	// For now, return nil (would be implemented based on actual security middleware)
	return nil
}

// SecurityContext represents security evaluation context
type SecurityContext struct {
	ThreatScore     float64
	Blocked         bool
	BlockReason     string
	Violations      []SecurityViolation
	PolicyDecisions []PolicyDecision
}

// getGeolocation gets geolocation information for an IP address
func (al *LLMAuditLogger) getGeolocation(ipAddress string) *GeolocationInfo {
	// This would integrate with a geolocation service
	// For now, return nil (would be implemented with actual geolocation provider)
	return nil
}

// classifyData classifies the data sensitivity level
func (al *LLMAuditLogger) classifyData(req *security.LLMRequest, resp *security.LLMResponse) string {
	// Simple classification logic - would be more sophisticated in practice
	if req.UserID != nil {
		return "personal"
	}
	return "public"
}

// determineRetentionCategory determines the retention category for the audit entry
func (al *LLMAuditLogger) determineRetentionCategory(entry *AuditEntry) string {
	if entry.Blocked || len(entry.SecurityViolations) > 0 {
		return "security_incident"
	}
	if entry.ThreatScore > 0.7 {
		return "high_risk"
	}
	return "standard"
}

// getComplianceFlags gets compliance flags for the audit entry
func (al *LLMAuditLogger) getComplianceFlags(entry *AuditEntry) []string {
	flags := []string{}

	if entry.UserID != nil {
		flags = append(flags, "gdpr_applicable")
	}

	if entry.DataClassification == "personal" {
		flags = append(flags, "pii_present")
	}

	return flags
}

// generateTags generates tags for the audit entry
func (al *LLMAuditLogger) generateTags(req *security.LLMRequest, resp *security.LLMResponse) []string {
	tags := []string{
		"llm_request",
		"provider:" + req.Provider,
		"model:" + req.Model,
	}

	if resp != nil && resp.StatusCode >= 400 {
		tags = append(tags, "error")
	}

	return tags
}

// extractMetadata extracts additional metadata from context and request/response
func (al *LLMAuditLogger) extractMetadata(ctx context.Context, req *security.LLMRequest, resp *security.LLMResponse) map[string]interface{} {
	metadata := make(map[string]interface{})

	// Add request metadata
	if req.Context != nil {
		for key, value := range req.Context {
			metadata["req_"+key] = value
		}
	}

	// Add response metadata
	if resp != nil && resp.Metadata != nil {
		for key, value := range resp.Metadata {
			metadata["resp_"+key] = value
		}
	}

	return metadata
}

// convertToDomainAuditLog converts audit entry to domain audit log
func (al *LLMAuditLogger) convertToDomainAuditLog(entry *AuditEntry) *domain.AuditLog {
	// Convert audit entry to domain audit log format
	auditData, _ := json.Marshal(entry)

	// Determine status based on response
	status := domain.AuditStatusSuccess
	if entry.Blocked {
		status = domain.AuditStatusError
	} else if entry.ResponseStatus >= 400 {
		status = domain.AuditStatusFailure
	}

	// Determine risk level based on threat score
	riskLevel := domain.RiskLevelLow
	if entry.ThreatScore >= 0.8 {
		riskLevel = domain.RiskLevelCritical
	} else if entry.ThreatScore >= 0.6 {
		riskLevel = domain.RiskLevelHigh
	} else if entry.ThreatScore >= 0.4 {
		riskLevel = domain.RiskLevelMedium
	}

	// Determine severity
	severity := domain.SeverityInfo
	if len(entry.SecurityViolations) > 0 {
		// Use the highest severity from violations
		for _, violation := range entry.SecurityViolations {
			switch violation.Severity {
			case "critical":
				severity = domain.SeverityCritical
			case "high":
				if severity != domain.SeverityCritical {
					severity = domain.SeverityHigh
				}
			case "medium":
				if severity != domain.SeverityCritical && severity != domain.SeverityHigh {
					severity = domain.SeverityMedium
				}
			case "low":
				if severity == domain.SeverityInfo {
					severity = domain.SeverityLow
				}
			}
		}
	}

	return &domain.AuditLog{
		ID:           entry.ID,
		UserID:       entry.UserID,
		SessionID:    entry.SessionID,
		Action:       "llm_request",
		Resource:     entry.Provider + "/" + entry.Model,
		Method:       entry.Method,
		Path:         entry.Endpoint,
		IPAddress:    entry.ClientIP,
		UserAgent:    entry.UserAgent,
		Status:       status,
		StatusCode:   entry.ResponseStatus,
		Duration:     entry.ProcessingTime.Milliseconds(),
		RequestSize:  entry.RequestSize,
		ResponseSize: entry.ResponseSize,
		Details:      json.RawMessage(auditData),
		RiskLevel:    riskLevel,
		Severity:     domain.Severity(severity),
		Tags:         entry.Tags,
		CreatedAt:    entry.CreatedAt,
	}
}

// DefaultAuditConfig returns default audit configuration
func DefaultAuditConfig() *AuditConfig {
	return &AuditConfig{
		Enabled:               true,
		LogLevel:              "info",
		IncludeRequestBody:    true,
		IncludeResponseBody:   true,
		MaskSensitiveData:     true,
		RetentionPeriod:       90 * 24 * time.Hour, // 90 days
		BatchSize:             100,
		FlushInterval:         30 * time.Second,
		CompressLargePayloads: true,
		MaxPayloadSize:        1024 * 1024, // 1MB
		SensitiveFields: []string{
			"password", "token", "key", "secret", "credential",
			"authorization", "api_key", "access_token", "refresh_token",
		},
	}
}
