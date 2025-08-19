package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// LLMSecurityRepository implements domain.LLMSecurityRepository
type LLMSecurityRepository struct {
	db     *gorm.DB
	logger *logger.Logger
}

// NewLLMSecurityRepository creates a new LLM security repository
func NewLLMSecurityRepository(db *gorm.DB, log *logger.Logger) domain.LLMSecurityRepository {
	return &LLMSecurityRepository{
		db:     db,
		logger: log,
	}
}

// LLM Request Logs

// CreateRequestLog creates a new LLM request log
func (r *LLMSecurityRepository) CreateRequestLog(ctx context.Context, log *domain.LLMRequestLog) error {
	if err := r.db.WithContext(ctx).Create(log).Error; err != nil {
		r.logger.WithError(err).Error("Failed to create LLM request log")
		return fmt.Errorf("failed to create LLM request log: %w", err)
	}

	r.logger.WithField("request_id", log.RequestID).Info("LLM request log created successfully")
	return nil
}

// GetRequestLog retrieves an LLM request log by ID
func (r *LLMSecurityRepository) GetRequestLog(ctx context.Context, id uuid.UUID) (*domain.LLMRequestLog, error) {
	var log domain.LLMRequestLog
	if err := r.db.WithContext(ctx).
		Preload("User").
		Preload("Session").
		Preload("SecurityEvents").
		Where("id = ?", id).
		First(&log).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("LLM request log not found")
		}
		r.logger.WithError(err).WithField("id", id).Error("Failed to get LLM request log")
		return nil, fmt.Errorf("failed to get LLM request log: %w", err)
	}

	return &log, nil
}

// GetRequestLogByRequestID retrieves an LLM request log by request ID
func (r *LLMSecurityRepository) GetRequestLogByRequestID(ctx context.Context, requestID string) (*domain.LLMRequestLog, error) {
	var log domain.LLMRequestLog
	if err := r.db.WithContext(ctx).
		Preload("User").
		Preload("Session").
		Preload("SecurityEvents").
		Where("request_id = ?", requestID).
		First(&log).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("LLM request log not found")
		}
		r.logger.WithError(err).WithField("request_id", requestID).Error("Failed to get LLM request log")
		return nil, fmt.Errorf("failed to get LLM request log: %w", err)
	}

	return &log, nil
}

// UpdateRequestLog updates an LLM request log
func (r *LLMSecurityRepository) UpdateRequestLog(ctx context.Context, log *domain.LLMRequestLog) error {
	if err := r.db.WithContext(ctx).Save(log).Error; err != nil {
		r.logger.WithError(err).WithField("id", log.ID).Error("Failed to update LLM request log")
		return fmt.Errorf("failed to update LLM request log: %w", err)
	}

	r.logger.WithField("id", log.ID).Info("LLM request log updated successfully")
	return nil
}

// ListRequestLogs lists LLM request logs with filtering
func (r *LLMSecurityRepository) ListRequestLogs(ctx context.Context, filter domain.RequestLogFilter) ([]*domain.LLMRequestLog, error) {
	var logs []*domain.LLMRequestLog
	query := r.db.WithContext(ctx).
		Preload("User").
		Preload("Session")

	// Apply filters
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.Provider != nil {
		query = query.Where("provider = ?", *filter.Provider)
	}
	if filter.Model != nil {
		query = query.Where("model = ?", *filter.Model)
	}
	if filter.Blocked != nil {
		query = query.Where("blocked = ?", *filter.Blocked)
	}
	if filter.ThreatScore != nil {
		query = query.Where("threat_score >= ?", *filter.ThreatScore)
	}
	if filter.StartTime != nil {
		query = query.Where("created_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("created_at <= ?", *filter.EndTime)
	}

	// Apply ordering
	orderBy := "created_at"
	if filter.OrderBy != "" {
		orderBy = filter.OrderBy
	}
	if filter.OrderDesc {
		orderBy += " DESC"
	}
	query = query.Order(orderBy)

	// Apply pagination
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}

	if err := query.Find(&logs).Error; err != nil {
		r.logger.WithError(err).Error("Failed to list LLM request logs")
		return nil, fmt.Errorf("failed to list LLM request logs: %w", err)
	}

	return logs, nil
}

// DeleteRequestLog deletes an LLM request log
func (r *LLMSecurityRepository) DeleteRequestLog(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&domain.LLMRequestLog{}, id).Error; err != nil {
		r.logger.WithError(err).WithField("id", id).Error("Failed to delete LLM request log")
		return fmt.Errorf("failed to delete LLM request log: %w", err)
	}

	r.logger.WithField("id", id).Info("LLM request log deleted successfully")
	return nil
}

// Security Events

// CreateSecurityEvent creates a new security event
func (r *LLMSecurityRepository) CreateSecurityEvent(ctx context.Context, event *domain.SecurityEvent) error {
	if err := r.db.WithContext(ctx).Create(event).Error; err != nil {
		r.logger.WithError(err).Error("Failed to create security event")
		return fmt.Errorf("failed to create security event: %w", err)
	}

	r.logger.WithField("event_id", event.ID).Info("Security event created successfully")
	return nil
}

// GetSecurityEvent retrieves a security event by ID
func (r *LLMSecurityRepository) GetSecurityEvent(ctx context.Context, id uuid.UUID) (*domain.SecurityEvent, error) {
	var event domain.SecurityEvent
	if err := r.db.WithContext(ctx).
		Preload("User").
		Preload("Session").
		Preload("ResolvedByUser").
		Where("id = ?", id).
		First(&event).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("security event not found")
		}
		r.logger.WithError(err).WithField("id", id).Error("Failed to get security event")
		return nil, fmt.Errorf("failed to get security event: %w", err)
	}

	return &event, nil
}

// UpdateSecurityEvent updates a security event
func (r *LLMSecurityRepository) UpdateSecurityEvent(ctx context.Context, event *domain.SecurityEvent) error {
	if err := r.db.WithContext(ctx).Save(event).Error; err != nil {
		r.logger.WithError(err).WithField("id", event.ID).Error("Failed to update security event")
		return fmt.Errorf("failed to update security event: %w", err)
	}

	r.logger.WithField("id", event.ID).Info("Security event updated successfully")
	return nil
}

// ListSecurityEvents lists security events with filtering
func (r *LLMSecurityRepository) ListSecurityEvents(ctx context.Context, filter domain.SecurityEventFilter) ([]*domain.SecurityEvent, error) {
	var events []*domain.SecurityEvent
	query := r.db.WithContext(ctx).
		Preload("User").
		Preload("Session").
		Preload("ResolvedByUser")

	// Apply filters
	if filter.EventType != nil {
		query = query.Where("event_type = ?", *filter.EventType)
	}
	if filter.Severity != nil {
		query = query.Where("severity = ?", *filter.Severity)
	}
	if filter.Source != nil {
		query = query.Where("source = ?", *filter.Source)
	}
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.Resolved != nil {
		query = query.Where("resolved = ?", *filter.Resolved)
	}
	if filter.StartTime != nil {
		query = query.Where("created_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("created_at <= ?", *filter.EndTime)
	}

	// Apply ordering
	orderBy := "created_at"
	if filter.OrderBy != "" {
		orderBy = filter.OrderBy
	}
	if filter.OrderDesc {
		orderBy += " DESC"
	}
	query = query.Order(orderBy)

	// Apply pagination
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}

	if err := query.Find(&events).Error; err != nil {
		r.logger.WithError(err).Error("Failed to list security events")
		return nil, fmt.Errorf("failed to list security events: %w", err)
	}

	return events, nil
}

// ResolveSecurityEvent resolves a security event
func (r *LLMSecurityRepository) ResolveSecurityEvent(ctx context.Context, id uuid.UUID, resolvedBy uuid.UUID, resolution string) error {
	now := time.Now()
	if err := r.db.WithContext(ctx).Model(&domain.SecurityEvent{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"resolved":    true,
			"resolved_at": &now,
			"resolved_by": resolvedBy,
			"resolution":  resolution,
			"updated_at":  now,
		}).Error; err != nil {
		r.logger.WithError(err).WithField("id", id).Error("Failed to resolve security event")
		return fmt.Errorf("failed to resolve security event: %w", err)
	}

	r.logger.WithFields(map[string]interface{}{
		"id":          id,
		"resolved_by": resolvedBy,
	}).Info("Security event resolved successfully")
	return nil
}

// LLM Providers

// CreateProvider creates a new LLM provider
func (r *LLMSecurityRepository) CreateProvider(ctx context.Context, provider *domain.LLMProvider) error {
	if err := r.db.WithContext(ctx).Create(provider).Error; err != nil {
		r.logger.WithError(err).Error("Failed to create LLM provider")
		return fmt.Errorf("failed to create LLM provider: %w", err)
	}

	r.logger.WithField("provider_name", provider.Name).Info("LLM provider created successfully")
	return nil
}

// GetProvider retrieves an LLM provider by ID
func (r *LLMSecurityRepository) GetProvider(ctx context.Context, id uuid.UUID) (*domain.LLMProvider, error) {
	var provider domain.LLMProvider
	if err := r.db.WithContext(ctx).
		Preload("Creator").
		Where("id = ?", id).
		First(&provider).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("LLM provider not found")
		}
		r.logger.WithError(err).WithField("id", id).Error("Failed to get LLM provider")
		return nil, fmt.Errorf("failed to get LLM provider: %w", err)
	}

	return &provider, nil
}

// GetProviderByName retrieves an LLM provider by name
func (r *LLMSecurityRepository) GetProviderByName(ctx context.Context, name string) (*domain.LLMProvider, error) {
	var provider domain.LLMProvider
	if err := r.db.WithContext(ctx).
		Preload("Creator").
		Where("name = ?", name).
		First(&provider).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("LLM provider not found")
		}
		r.logger.WithError(err).WithField("name", name).Error("Failed to get LLM provider")
		return nil, fmt.Errorf("failed to get LLM provider: %w", err)
	}

	return &provider, nil
}

// UpdateProvider updates an LLM provider
func (r *LLMSecurityRepository) UpdateProvider(ctx context.Context, provider *domain.LLMProvider) error {
	if err := r.db.WithContext(ctx).Save(provider).Error; err != nil {
		r.logger.WithError(err).WithField("id", provider.ID).Error("Failed to update LLM provider")
		return fmt.Errorf("failed to update LLM provider: %w", err)
	}

	r.logger.WithField("id", provider.ID).Info("LLM provider updated successfully")
	return nil
}

// ListProviders lists LLM providers with filtering
func (r *LLMSecurityRepository) ListProviders(ctx context.Context, filter domain.ProviderFilter) ([]*domain.LLMProvider, error) {
	var providers []*domain.LLMProvider
	query := r.db.WithContext(ctx).Preload("Creator")

	// Apply filters
	if filter.ProviderType != nil {
		query = query.Where("provider_type = ?", *filter.ProviderType)
	}
	if filter.Enabled != nil {
		query = query.Where("enabled = ?", *filter.Enabled)
	}

	// Apply ordering
	orderBy := "created_at"
	if filter.OrderBy != "" {
		orderBy = filter.OrderBy
	}
	if filter.OrderDesc {
		orderBy += " DESC"
	}
	query = query.Order(orderBy)

	// Apply pagination
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}

	if err := query.Find(&providers).Error; err != nil {
		r.logger.WithError(err).Error("Failed to list LLM providers")
		return nil, fmt.Errorf("failed to list LLM providers: %w", err)
	}

	return providers, nil
}

// DeleteProvider deletes an LLM provider
func (r *LLMSecurityRepository) DeleteProvider(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&domain.LLMProvider{}, id).Error; err != nil {
		r.logger.WithError(err).WithField("id", id).Error("Failed to delete LLM provider")
		return fmt.Errorf("failed to delete LLM provider: %w", err)
	}

	r.logger.WithField("id", id).Info("LLM provider deleted successfully")
	return nil
}

// Analytics methods (simplified implementations)

// GetRequestLogStats returns statistics for request logs
func (r *LLMSecurityRepository) GetRequestLogStats(ctx context.Context, filter domain.RequestLogFilter) (*domain.RequestLogStats, error) {
	var stats domain.RequestLogStats

	query := r.db.WithContext(ctx).Model(&domain.LLMRequestLog{})

	// Apply filters
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.StartTime != nil {
		query = query.Where("created_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("created_at <= ?", *filter.EndTime)
	}

	// Get basic counts
	if err := query.Count(&stats.TotalRequests).Error; err != nil {
		return nil, fmt.Errorf("failed to get total requests: %w", err)
	}

	// Get blocked requests count
	if err := query.Where("blocked = ?", true).Count(&stats.BlockedRequests).Error; err != nil {
		return nil, fmt.Errorf("failed to get blocked requests: %w", err)
	}

	// Get average threat score
	var avgThreatScore sql.NullFloat64
	if err := query.Select("AVG(threat_score)").Scan(&avgThreatScore).Error; err != nil {
		return nil, fmt.Errorf("failed to get average threat score: %w", err)
	}
	if avgThreatScore.Valid {
		stats.AverageThreatScore = avgThreatScore.Float64
	}

	return &stats, nil
}

// GetThreatScoreDistribution returns threat score distribution
func (r *LLMSecurityRepository) GetThreatScoreDistribution(ctx context.Context, filter domain.RequestLogFilter) (map[string]int, error) {
	distribution := make(map[string]int)

	// Simplified implementation - in production, you'd want more sophisticated bucketing
	var results []struct {
		Range string
		Count int
	}

	query := r.db.WithContext(ctx).Model(&domain.LLMRequestLog{})

	// Apply filters
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.StartTime != nil {
		query = query.Where("created_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("created_at <= ?", *filter.EndTime)
	}

	// Get distribution by threat score ranges
	if err := query.Select(`
		CASE
			WHEN threat_score < 0.3 THEN 'low'
			WHEN threat_score < 0.7 THEN 'medium'
			ELSE 'high'
		END as range,
		COUNT(*) as count
	`).Group("range").Scan(&results).Error; err != nil {
		return nil, fmt.Errorf("failed to get threat score distribution: %w", err)
	}

	for _, result := range results {
		distribution[result.Range] = result.Count
	}

	return distribution, nil
}

// GetTopBlockedRequests returns top blocked requests
func (r *LLMSecurityRepository) GetTopBlockedRequests(ctx context.Context, limit int, timeRange time.Duration) ([]*domain.LLMRequestLog, error) {
	var logs []*domain.LLMRequestLog

	startTime := time.Now().Add(-timeRange)

	if err := r.db.WithContext(ctx).
		Preload("User").
		Where("blocked = ? AND created_at >= ?", true, startTime).
		Order("threat_score DESC, created_at DESC").
		Limit(limit).
		Find(&logs).Error; err != nil {
		return nil, fmt.Errorf("failed to get top blocked requests: %w", err)
	}

	return logs, nil
}

// GetUserActivitySummary returns user activity summary
func (r *LLMSecurityRepository) GetUserActivitySummary(ctx context.Context, userID uuid.UUID, timeRange time.Duration) (*domain.UserActivitySummary, error) {
	var summary domain.UserActivitySummary
	summary.UserID = userID

	startTime := time.Now().Add(-timeRange)

	query := r.db.WithContext(ctx).Model(&domain.LLMRequestLog{}).
		Where("user_id = ? AND created_at >= ?", userID, startTime)

	// Get total requests
	if err := query.Count(&summary.TotalRequests).Error; err != nil {
		return nil, fmt.Errorf("failed to get total requests: %w", err)
	}

	// Get blocked requests
	if err := query.Where("blocked = ?", true).Count(&summary.BlockedRequests).Error; err != nil {
		return nil, fmt.Errorf("failed to get blocked requests: %w", err)
	}

	// Get total tokens
	var totalTokens sql.NullInt64
	if err := query.Select("SUM(total_tokens)").Scan(&totalTokens).Error; err != nil {
		return nil, fmt.Errorf("failed to get total tokens: %w", err)
	}
	if totalTokens.Valid {
		summary.TotalTokens = totalTokens.Int64
	}

	// Get average threat score
	var avgThreatScore sql.NullFloat64
	if err := query.Select("AVG(threat_score)").Scan(&avgThreatScore).Error; err != nil {
		return nil, fmt.Errorf("failed to get average threat score: %w", err)
	}
	if avgThreatScore.Valid {
		summary.AverageThreatScore = avgThreatScore.Float64
	}

	// Get last activity
	var lastActivity time.Time
	if err := query.Select("MAX(created_at)").Scan(&lastActivity).Error; err != nil {
		return nil, fmt.Errorf("failed to get last activity: %w", err)
	}
	summary.LastActivity = lastActivity

	return &summary, nil
}

// Remaining interface methods (simplified implementations)

// GetSecurityEventStats returns security event statistics
func (r *LLMSecurityRepository) GetSecurityEventStats(ctx context.Context, filter domain.SecurityEventFilter) (*domain.SecurityEventStats, error) {
	var stats domain.SecurityEventStats

	query := r.db.WithContext(ctx).Model(&domain.SecurityEvent{})

	// Apply filters
	if filter.StartTime != nil {
		query = query.Where("created_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("created_at <= ?", *filter.EndTime)
	}

	// Get total events
	if err := query.Count(&stats.TotalEvents).Error; err != nil {
		return nil, fmt.Errorf("failed to get total events: %w", err)
	}

	// Get resolved events
	if err := query.Where("resolved = ?", true).Count(&stats.ResolvedEvents).Error; err != nil {
		return nil, fmt.Errorf("failed to get resolved events: %w", err)
	}

	return &stats, nil
}

// GetThreatTrends returns threat trends
func (r *LLMSecurityRepository) GetThreatTrends(ctx context.Context, timeRange time.Duration) (*domain.ThreatTrends, error) {
	trends := &domain.ThreatTrends{
		TimeRange:  timeRange.String(),
		DataPoints: []domain.ThreatTrendDataPoint{},
		TopThreats: []domain.ThreatSummary{},
	}

	// Simplified implementation
	return trends, nil
}

// GetTopThreats returns top threats
func (r *LLMSecurityRepository) GetTopThreats(ctx context.Context, limit int, timeRange time.Duration) ([]*domain.ThreatSummary, error) {
	// Simplified implementation
	return []*domain.ThreatSummary{}, nil
}

// CreateModel creates a new LLM model
func (r *LLMSecurityRepository) CreateModel(ctx context.Context, model *domain.LLMModel) error {
	if err := r.db.WithContext(ctx).Create(model).Error; err != nil {
		r.logger.WithError(err).Error("Failed to create LLM model")
		return fmt.Errorf("failed to create LLM model: %w", err)
	}

	r.logger.WithField("model_name", model.Name).Info("LLM model created successfully")
	return nil
}

// GetModel retrieves an LLM model by ID
func (r *LLMSecurityRepository) GetModel(ctx context.Context, id uuid.UUID) (*domain.LLMModel, error) {
	var model domain.LLMModel
	if err := r.db.WithContext(ctx).
		Preload("Provider").
		Where("id = ?", id).
		First(&model).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("LLM model not found")
		}
		r.logger.WithError(err).WithField("id", id).Error("Failed to get LLM model")
		return nil, fmt.Errorf("failed to get LLM model: %w", err)
	}

	return &model, nil
}

// UpdateModel updates an LLM model
func (r *LLMSecurityRepository) UpdateModel(ctx context.Context, model *domain.LLMModel) error {
	if err := r.db.WithContext(ctx).Save(model).Error; err != nil {
		r.logger.WithError(err).WithField("id", model.ID).Error("Failed to update LLM model")
		return fmt.Errorf("failed to update LLM model: %w", err)
	}

	r.logger.WithField("id", model.ID).Info("LLM model updated successfully")
	return nil
}

// ListModels lists LLM models with filtering
func (r *LLMSecurityRepository) ListModels(ctx context.Context, filter domain.ModelFilter) ([]*domain.LLMModel, error) {
	var models []*domain.LLMModel
	query := r.db.WithContext(ctx).Preload("Provider")

	// Apply filters
	if filter.ProviderID != nil {
		query = query.Where("provider_id = ?", *filter.ProviderID)
	}
	if filter.ModelType != nil {
		query = query.Where("model_type = ?", *filter.ModelType)
	}
	if filter.Enabled != nil {
		query = query.Where("enabled = ?", *filter.Enabled)
	}

	// Apply ordering
	orderBy := "created_at"
	if filter.OrderBy != "" {
		orderBy = filter.OrderBy
	}
	if filter.OrderDesc {
		orderBy += " DESC"
	}
	query = query.Order(orderBy)

	// Apply pagination
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}

	if err := query.Find(&models).Error; err != nil {
		r.logger.WithError(err).Error("Failed to list LLM models")
		return nil, fmt.Errorf("failed to list LLM models: %w", err)
	}

	return models, nil
}

// ListModelsByProvider lists LLM models for a specific provider
func (r *LLMSecurityRepository) ListModelsByProvider(ctx context.Context, providerID uuid.UUID) ([]*domain.LLMModel, error) {
	var models []*domain.LLMModel
	if err := r.db.WithContext(ctx).
		Preload("Provider").
		Where("provider_id = ? AND enabled = ?", providerID, true).
		Order("name").
		Find(&models).Error; err != nil {
		r.logger.WithError(err).WithField("provider_id", providerID).Error("Failed to list models by provider")
		return nil, fmt.Errorf("failed to list models by provider: %w", err)
	}

	return models, nil
}

// DeleteModel deletes an LLM model
func (r *LLMSecurityRepository) DeleteModel(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&domain.LLMModel{}, id).Error; err != nil {
		r.logger.WithError(err).WithField("id", id).Error("Failed to delete LLM model")
		return fmt.Errorf("failed to delete LLM model: %w", err)
	}

	r.logger.WithField("id", id).Info("LLM model deleted successfully")
	return nil
}

// Usage Quota methods (simplified implementations)

// CreateUsageQuota creates a new usage quota
func (r *LLMSecurityRepository) CreateUsageQuota(ctx context.Context, quota *domain.LLMUsageQuota) error {
	if err := r.db.WithContext(ctx).Create(quota).Error; err != nil {
		r.logger.WithError(err).Error("Failed to create usage quota")
		return fmt.Errorf("failed to create usage quota: %w", err)
	}

	r.logger.WithField("quota_id", quota.ID).Info("Usage quota created successfully")
	return nil
}

// GetUsageQuota retrieves a usage quota by ID
func (r *LLMSecurityRepository) GetUsageQuota(ctx context.Context, id uuid.UUID) (*domain.LLMUsageQuota, error) {
	var quota domain.LLMUsageQuota
	if err := r.db.WithContext(ctx).
		Preload("User").
		Preload("Provider").
		Preload("Model").
		Where("id = ?", id).
		First(&quota).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("usage quota not found")
		}
		r.logger.WithError(err).WithField("id", id).Error("Failed to get usage quota")
		return nil, fmt.Errorf("failed to get usage quota: %w", err)
	}

	return &quota, nil
}

// UpdateUsageQuota updates a usage quota
func (r *LLMSecurityRepository) UpdateUsageQuota(ctx context.Context, quota *domain.LLMUsageQuota) error {
	if err := r.db.WithContext(ctx).Save(quota).Error; err != nil {
		r.logger.WithError(err).WithField("id", quota.ID).Error("Failed to update usage quota")
		return fmt.Errorf("failed to update usage quota: %w", err)
	}

	r.logger.WithField("id", quota.ID).Info("Usage quota updated successfully")
	return nil
}

// ListUsageQuotas lists usage quotas with filtering
func (r *LLMSecurityRepository) ListUsageQuotas(ctx context.Context, filter domain.UsageQuotaFilter) ([]*domain.LLMUsageQuota, error) {
	var quotas []*domain.LLMUsageQuota
	query := r.db.WithContext(ctx).
		Preload("User").
		Preload("Provider").
		Preload("Model")

	// Apply filters
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.ProviderID != nil {
		query = query.Where("provider_id = ?", *filter.ProviderID)
	}
	if filter.ModelID != nil {
		query = query.Where("model_id = ?", *filter.ModelID)
	}
	if filter.WindowType != nil {
		query = query.Where("window_type = ?", *filter.WindowType)
	}
	if filter.Enabled != nil {
		query = query.Where("enabled = ?", *filter.Enabled)
	}

	// Apply ordering
	orderBy := "created_at"
	if filter.OrderBy != "" {
		orderBy = filter.OrderBy
	}
	if filter.OrderDesc {
		orderBy += " DESC"
	}
	query = query.Order(orderBy)

	// Apply pagination
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}

	if err := query.Find(&quotas).Error; err != nil {
		r.logger.WithError(err).Error("Failed to list usage quotas")
		return nil, fmt.Errorf("failed to list usage quotas: %w", err)
	}

	return quotas, nil
}

// GetUserQuotas returns quotas for a specific user
func (r *LLMSecurityRepository) GetUserQuotas(ctx context.Context, userID uuid.UUID) ([]*domain.LLMUsageQuota, error) {
	var quotas []*domain.LLMUsageQuota
	if err := r.db.WithContext(ctx).
		Preload("Provider").
		Preload("Model").
		Where("user_id = ? AND enabled = ?", userID, true).
		Order("created_at DESC").
		Find(&quotas).Error; err != nil {
		r.logger.WithError(err).WithField("user_id", userID).Error("Failed to get user quotas")
		return nil, fmt.Errorf("failed to get user quotas: %w", err)
	}

	return quotas, nil
}

// IncrementUsage increments usage for a quota
func (r *LLMSecurityRepository) IncrementUsage(ctx context.Context, quotaID uuid.UUID, requests int, tokens int, cost float64) error {
	if err := r.db.WithContext(ctx).Model(&domain.LLMUsageQuota{}).
		Where("id = ?", quotaID).
		Updates(map[string]interface{}{
			"used_requests": gorm.Expr("used_requests + ?", requests),
			"used_tokens":   gorm.Expr("used_tokens + ?", tokens),
			"used_cost":     gorm.Expr("used_cost + ?", cost),
			"updated_at":    time.Now(),
		}).Error; err != nil {
		r.logger.WithError(err).WithField("quota_id", quotaID).Error("Failed to increment usage")
		return fmt.Errorf("failed to increment usage: %w", err)
	}

	r.logger.WithFields(map[string]interface{}{
		"quota_id": quotaID,
		"requests": requests,
		"tokens":   tokens,
		"cost":     cost,
	}).Info("Usage incremented successfully")
	return nil
}

// ResetQuotaUsage resets usage for a quota
func (r *LLMSecurityRepository) ResetQuotaUsage(ctx context.Context, quotaID uuid.UUID) error {
	if err := r.db.WithContext(ctx).Model(&domain.LLMUsageQuota{}).
		Where("id = ?", quotaID).
		Updates(map[string]interface{}{
			"used_requests": 0,
			"used_tokens":   0,
			"used_cost":     0,
			"updated_at":    time.Now(),
		}).Error; err != nil {
		r.logger.WithError(err).WithField("quota_id", quotaID).Error("Failed to reset quota usage")
		return fmt.Errorf("failed to reset quota usage: %w", err)
	}

	r.logger.WithField("quota_id", quotaID).Info("Quota usage reset successfully")
	return nil
}

// Bulk Operations

// BulkCreateRequestLogs creates multiple request logs
func (r *LLMSecurityRepository) BulkCreateRequestLogs(ctx context.Context, logs []*domain.LLMRequestLog) error {
	if len(logs) == 0 {
		return nil
	}

	if err := r.db.WithContext(ctx).CreateInBatches(logs, 100).Error; err != nil {
		r.logger.WithError(err).WithField("count", len(logs)).Error("Failed to bulk create request logs")
		return fmt.Errorf("failed to bulk create request logs: %w", err)
	}

	r.logger.WithField("count", len(logs)).Info("Request logs bulk created successfully")
	return nil
}

// BulkUpdateRequestLogs updates multiple request logs
func (r *LLMSecurityRepository) BulkUpdateRequestLogs(ctx context.Context, logs []*domain.LLMRequestLog) error {
	if len(logs) == 0 {
		return nil
	}

	tx := r.db.WithContext(ctx).Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	for _, log := range logs {
		if err := tx.Save(log).Error; err != nil {
			tx.Rollback()
			r.logger.WithError(err).WithField("log_id", log.ID).Error("Failed to update request log in bulk")
			return fmt.Errorf("failed to update request log in bulk: %w", err)
		}
	}

	if err := tx.Commit().Error; err != nil {
		r.logger.WithError(err).WithField("count", len(logs)).Error("Failed to commit bulk update")
		return fmt.Errorf("failed to commit bulk update: %w", err)
	}

	r.logger.WithField("count", len(logs)).Info("Request logs bulk updated successfully")
	return nil
}

// CleanupExpiredLogs removes expired logs based on retention period
func (r *LLMSecurityRepository) CleanupExpiredLogs(ctx context.Context, retentionPeriod time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-retentionPeriod)

	result := r.db.WithContext(ctx).
		Where("created_at < ? OR (expires_at IS NOT NULL AND expires_at < ?)", cutoffTime, time.Now()).
		Delete(&domain.LLMRequestLog{})

	if result.Error != nil {
		r.logger.WithError(result.Error).Error("Failed to cleanup expired logs")
		return 0, fmt.Errorf("failed to cleanup expired logs: %w", result.Error)
	}

	r.logger.WithFields(map[string]interface{}{
		"deleted_count":    result.RowsAffected,
		"retention_period": retentionPeriod,
	}).Info("Expired logs cleaned up successfully")

	return result.RowsAffected, nil
}
