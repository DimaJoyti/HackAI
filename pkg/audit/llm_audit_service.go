package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var serviceTracer = otel.Tracer("hackai/audit/llm_audit_service")

// LLMAuditService provides high-level audit management functionality
type LLMAuditService struct {
	logger      *logger.Logger
	auditLogger *LLMAuditLogger
	middleware  *LLMAuditMiddleware
	auditRepo   domain.AuditRepository
	config      *ServiceConfig
}

// ServiceConfig represents audit service configuration
type ServiceConfig struct {
	Enabled               bool             `json:"enabled"`
	RetentionPeriod       time.Duration    `json:"retention_period"`
	CleanupInterval       time.Duration    `json:"cleanup_interval"`
	ArchiveOldLogs        bool             `json:"archive_old_logs"`
	ArchiveThreshold      time.Duration    `json:"archive_threshold"`
	EnableMetrics         bool             `json:"enable_metrics"`
	MetricsUpdateInterval time.Duration    `json:"metrics_update_interval"`
	EnableAlerts          bool             `json:"enable_alerts"`
	AlertThresholds       *AlertThresholds `json:"alert_thresholds"`
}

// AlertThresholds defines thresholds for audit alerts
type AlertThresholds struct {
	HighThreatScoreCount     int           `json:"high_threat_score_count"`
	HighThreatScoreWindow    time.Duration `json:"high_threat_score_window"`
	FailedRequestsCount      int           `json:"failed_requests_count"`
	FailedRequestsWindow     time.Duration `json:"failed_requests_window"`
	SecurityViolationsCount  int           `json:"security_violations_count"`
	SecurityViolationsWindow time.Duration `json:"security_violations_window"`
	MinThreatScore           float64       `json:"min_threat_score"`
}

// AuditMetrics represents audit metrics
type AuditMetrics struct {
	TotalRequests      int64     `json:"total_requests"`
	SuccessfulRequests int64     `json:"successful_requests"`
	FailedRequests     int64     `json:"failed_requests"`
	BlockedRequests    int64     `json:"blocked_requests"`
	SecurityViolations int64     `json:"security_violations"`
	PolicyDecisions    int64     `json:"policy_decisions"`
	AverageThreatScore float64   `json:"average_threat_score"`
	HighThreatRequests int64     `json:"high_threat_requests"`
	TotalTokensUsed    int64     `json:"total_tokens_used"`
	TotalCost          float64   `json:"total_cost"`
	LastUpdated        time.Time `json:"last_updated"`
}

// AuditSummary represents a summary of audit data
type AuditSummary struct {
	TimeRange                string               `json:"time_range"`
	Metrics                  *AuditMetrics        `json:"metrics"`
	TopProviders             []ProviderUsage      `json:"top_providers"`
	TopModels                []ModelUsage         `json:"top_models"`
	TopUsers                 []UserUsage          `json:"top_users"`
	SecurityViolationsByType []ViolationTypeCount `json:"security_violations_by_type"`
	ThreatScoreDistribution  []ThreatScoreBucket  `json:"threat_score_distribution"`
}

// ProviderUsage represents provider usage statistics
type ProviderUsage struct {
	Provider       string  `json:"provider"`
	RequestCount   int64   `json:"request_count"`
	TokensUsed     int64   `json:"tokens_used"`
	Cost           float64 `json:"cost"`
	AvgThreatScore float64 `json:"avg_threat_score"`
}

// ModelUsage represents model usage statistics
type ModelUsage struct {
	Model          string  `json:"model"`
	Provider       string  `json:"provider"`
	RequestCount   int64   `json:"request_count"`
	TokensUsed     int64   `json:"tokens_used"`
	Cost           float64 `json:"cost"`
	AvgThreatScore float64 `json:"avg_threat_score"`
}

// UserUsage represents user usage statistics
type UserUsage struct {
	UserID         uuid.UUID `json:"user_id"`
	RequestCount   int64     `json:"request_count"`
	TokensUsed     int64     `json:"tokens_used"`
	Cost           float64   `json:"cost"`
	AvgThreatScore float64   `json:"avg_threat_score"`
	ViolationCount int64     `json:"violation_count"`
}

// ViolationTypeCount represents violation count by type
type ViolationTypeCount struct {
	ViolationType string `json:"violation_type"`
	Count         int64  `json:"count"`
	Severity      string `json:"severity"`
}

// ThreatScoreBucket represents threat score distribution bucket
type ThreatScoreBucket struct {
	MinScore float64 `json:"min_score"`
	MaxScore float64 `json:"max_score"`
	Count    int64   `json:"count"`
}

// NewLLMAuditService creates a new LLM audit service
func NewLLMAuditService(
	logger *logger.Logger,
	auditLogger *LLMAuditLogger,
	middleware *LLMAuditMiddleware,
	auditRepo domain.AuditRepository,
	config *ServiceConfig,
) *LLMAuditService {
	if config == nil {
		config = DefaultServiceConfig()
	}

	return &LLMAuditService{
		logger:      logger,
		auditLogger: auditLogger,
		middleware:  middleware,
		auditRepo:   auditRepo,
		config:      config,
	}
}

// Start starts the audit service
func (s *LLMAuditService) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("LLM audit service is disabled")
		return nil
	}

	s.logger.Info("Starting LLM audit service")

	// Start audit logger
	if err := s.auditLogger.Start(ctx); err != nil {
		return fmt.Errorf("failed to start audit logger: %w", err)
	}

	// Start background tasks
	go s.runCleanupTask(ctx)
	if s.config.EnableMetrics {
		go s.runMetricsUpdateTask(ctx)
	}
	if s.config.EnableAlerts {
		go s.runAlertsTask(ctx)
	}

	s.logger.Info("LLM audit service started")
	return nil
}

// Stop stops the audit service
func (s *LLMAuditService) Stop() error {
	if !s.config.Enabled {
		return nil
	}

	s.logger.Info("Stopping LLM audit service")

	// Stop audit logger
	if err := s.auditLogger.Stop(); err != nil {
		s.logger.WithError(err).Error("Failed to stop audit logger")
	}

	s.logger.Info("LLM audit service stopped")
	return nil
}

// GetAuditSummary returns an audit summary for the specified time range
func (s *LLMAuditService) GetAuditSummary(ctx context.Context, startTime, endTime time.Time) (*AuditSummary, error) {
	ctx, span := serviceTracer.Start(ctx, "llm_audit_service.get_audit_summary")
	defer span.End()

	// Get audit logs for the time range
	filters := map[string]interface{}{
		"start_time": startTime,
		"end_time":   endTime,
		"action":     "llm_request",
	}

	logs, err := s.auditRepo.ListAuditLogs(filters, 10000, 0) // Large limit for analysis
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}

	// Analyze logs and build summary
	summary := s.analyzeAuditLogs(logs, startTime, endTime)

	span.SetAttributes(
		attribute.String("summary.time_range", summary.TimeRange),
		attribute.Int64("summary.total_requests", summary.Metrics.TotalRequests),
		attribute.Int64("summary.security_violations", summary.Metrics.SecurityViolations),
	)

	return summary, nil
}

// GetAuditMetrics returns current audit metrics
func (s *LLMAuditService) GetAuditMetrics(ctx context.Context) (*AuditMetrics, error) {
	ctx, span := serviceTracer.Start(ctx, "llm_audit_service.get_audit_metrics")
	defer span.End()

	// Get metrics for the last 24 hours
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)

	summary, err := s.GetAuditSummary(ctx, startTime, endTime)
	if err != nil {
		return nil, err
	}

	return summary.Metrics, nil
}

// CleanupOldAuditLogs removes old audit logs based on retention policy
func (s *LLMAuditService) CleanupOldAuditLogs(ctx context.Context) error {
	ctx, span := serviceTracer.Start(ctx, "llm_audit_service.cleanup_old_audit_logs")
	defer span.End()

	cutoffTime := time.Now().Add(-s.config.RetentionPeriod)

	// Get old audit logs
	filters := map[string]interface{}{
		"end_time": cutoffTime,
		"action":   "llm_request",
	}

	oldLogs, err := s.auditRepo.ListAuditLogs(filters, 1000, 0)
	if err != nil {
		return fmt.Errorf("failed to get old audit logs: %w", err)
	}

	// Archive or delete old logs using bulk delete
	archivedCount := 0

	for _, log := range oldLogs {
		if s.config.ArchiveOldLogs && log.CreatedAt.After(time.Now().Add(-s.config.ArchiveThreshold)) {
			// Archive the log (implementation would depend on archive storage)
			archivedCount++
		}
	}

	// Delete expired logs in bulk
	deletedCount, err := s.auditRepo.DeleteExpiredAuditLogs(cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to delete expired audit logs: %w", err)
	}

	span.SetAttributes(
		attribute.Int64("cleanup.deleted_count", deletedCount),
		attribute.Int("cleanup.archived_count", archivedCount),
	)

	s.logger.WithFields(map[string]interface{}{
		"deleted_count":  deletedCount,
		"archived_count": archivedCount,
		"cutoff_time":    cutoffTime,
	}).Info("Audit log cleanup completed")

	return nil
}

// Background tasks

// runCleanupTask runs the cleanup task periodically
func (s *LLMAuditService) runCleanupTask(ctx context.Context) {
	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.CleanupOldAuditLogs(ctx); err != nil {
				s.logger.WithError(err).Error("Audit log cleanup failed")
			}
		case <-ctx.Done():
			return
		}
	}
}

// runMetricsUpdateTask runs the metrics update task periodically
func (s *LLMAuditService) runMetricsUpdateTask(ctx context.Context) {
	ticker := time.NewTicker(s.config.MetricsUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Update metrics (implementation would depend on metrics storage)
			s.logger.Debug("Updating audit metrics")
		case <-ctx.Done():
			return
		}
	}
}

// runAlertsTask runs the alerts task periodically
func (s *LLMAuditService) runAlertsTask(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute) // Check alerts every minute
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkAlerts(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// checkAlerts checks for alert conditions
func (s *LLMAuditService) checkAlerts(ctx context.Context) {
	// Implementation would check various alert conditions
	// and send alerts through configured channels
	s.logger.Debug("Checking audit alerts")
}

// Helper methods

// analyzeAuditLogs analyzes audit logs and builds a summary
func (s *LLMAuditService) analyzeAuditLogs(logs []*domain.AuditLog, startTime, endTime time.Time) *AuditSummary {
	metrics := &AuditMetrics{
		LastUpdated: time.Now(),
	}

	providerUsage := make(map[string]*ProviderUsage)
	modelUsage := make(map[string]*ModelUsage)
	userUsage := make(map[uuid.UUID]*UserUsage)
	violationTypes := make(map[string]*ViolationTypeCount)
	threatBuckets := make([]int64, 10) // 10 buckets for 0.0-0.1, 0.1-0.2, etc.

	for _, log := range logs {
		metrics.TotalRequests++

		// Analyze status
		switch log.Status {
		case domain.AuditStatusSuccess:
			metrics.SuccessfulRequests++
		case domain.AuditStatusFailure, domain.AuditStatusError:
			metrics.FailedRequests++
		}

		// Parse details for additional metrics
		// This would parse the JSON details to extract threat scores, tokens, etc.
		// For now, using placeholder logic
	}

	return &AuditSummary{
		TimeRange:                fmt.Sprintf("%s to %s", startTime.Format(time.RFC3339), endTime.Format(time.RFC3339)),
		Metrics:                  metrics,
		TopProviders:             s.convertProviderUsage(providerUsage),
		TopModels:                s.convertModelUsage(modelUsage),
		TopUsers:                 s.convertUserUsage(userUsage),
		SecurityViolationsByType: s.convertViolationTypes(violationTypes),
		ThreatScoreDistribution:  s.convertThreatBuckets(threatBuckets),
	}
}

// Helper conversion methods
func (s *LLMAuditService) convertProviderUsage(usage map[string]*ProviderUsage) []ProviderUsage {
	result := make([]ProviderUsage, 0, len(usage))
	for _, u := range usage {
		result = append(result, *u)
	}
	return result
}

func (s *LLMAuditService) convertModelUsage(usage map[string]*ModelUsage) []ModelUsage {
	result := make([]ModelUsage, 0, len(usage))
	for _, u := range usage {
		result = append(result, *u)
	}
	return result
}

func (s *LLMAuditService) convertUserUsage(usage map[uuid.UUID]*UserUsage) []UserUsage {
	result := make([]UserUsage, 0, len(usage))
	for _, u := range usage {
		result = append(result, *u)
	}
	return result
}

func (s *LLMAuditService) convertViolationTypes(types map[string]*ViolationTypeCount) []ViolationTypeCount {
	result := make([]ViolationTypeCount, 0, len(types))
	for _, t := range types {
		result = append(result, *t)
	}
	return result
}

func (s *LLMAuditService) convertThreatBuckets(buckets []int64) []ThreatScoreBucket {
	result := make([]ThreatScoreBucket, len(buckets))
	for i, count := range buckets {
		result[i] = ThreatScoreBucket{
			MinScore: float64(i) * 0.1,
			MaxScore: float64(i+1) * 0.1,
			Count:    count,
		}
	}
	return result
}

// DefaultServiceConfig returns default service configuration
func DefaultServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		Enabled:               true,
		RetentionPeriod:       90 * 24 * time.Hour, // 90 days
		CleanupInterval:       24 * time.Hour,      // Daily cleanup
		ArchiveOldLogs:        true,
		ArchiveThreshold:      30 * 24 * time.Hour, // Archive after 30 days
		EnableMetrics:         true,
		MetricsUpdateInterval: 5 * time.Minute,
		EnableAlerts:          true,
		AlertThresholds: &AlertThresholds{
			HighThreatScoreCount:     10,
			HighThreatScoreWindow:    time.Hour,
			FailedRequestsCount:      50,
			FailedRequestsWindow:     time.Hour,
			SecurityViolationsCount:  5,
			SecurityViolationsWindow: time.Hour,
			MinThreatScore:           0.8,
		},
	}
}
