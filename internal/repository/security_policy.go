package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// SecurityPolicyRepository implements domain.SecurityPolicyRepository
type SecurityPolicyRepository struct {
	db     *gorm.DB
	logger *logger.Logger
}

// NewSecurityPolicyRepository creates a new security policy repository
func NewSecurityPolicyRepository(db *gorm.DB, log *logger.Logger) domain.SecurityPolicyRepository {
	return &SecurityPolicyRepository{
		db:     db,
		logger: log,
	}
}

// Security Policies

// CreatePolicy creates a new security policy
func (r *SecurityPolicyRepository) CreatePolicy(ctx context.Context, policy *domain.SecurityPolicy) error {
	if err := r.db.WithContext(ctx).Create(policy).Error; err != nil {
		r.logger.WithError(err).Error("Failed to create security policy")
		return fmt.Errorf("failed to create security policy: %w", err)
	}

	r.logger.WithField("policy_name", policy.Name).Info("Security policy created successfully")
	return nil
}

// GetPolicy retrieves a security policy by ID
func (r *SecurityPolicyRepository) GetPolicy(ctx context.Context, id uuid.UUID) (*domain.SecurityPolicy, error) {
	var policy domain.SecurityPolicy
	if err := r.db.WithContext(ctx).
		Preload("Creator").
		Preload("Updater").
		Preload("ParentPolicy").
		Preload("ChildPolicies").
		Where("id = ?", id).
		First(&policy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("security policy not found")
		}
		r.logger.WithError(err).WithField("id", id).Error("Failed to get security policy")
		return nil, fmt.Errorf("failed to get security policy: %w", err)
	}

	return &policy, nil
}

// GetPolicyByName retrieves a security policy by name
func (r *SecurityPolicyRepository) GetPolicyByName(ctx context.Context, name string) (*domain.SecurityPolicy, error) {
	var policy domain.SecurityPolicy
	if err := r.db.WithContext(ctx).
		Preload("Creator").
		Preload("Updater").
		Where("name = ?", name).
		First(&policy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("security policy not found")
		}
		r.logger.WithError(err).WithField("name", name).Error("Failed to get security policy")
		return nil, fmt.Errorf("failed to get security policy: %w", err)
	}

	return &policy, nil
}

// UpdatePolicy updates a security policy
func (r *SecurityPolicyRepository) UpdatePolicy(ctx context.Context, policy *domain.SecurityPolicy) error {
	if err := r.db.WithContext(ctx).Save(policy).Error; err != nil {
		r.logger.WithError(err).WithField("id", policy.ID).Error("Failed to update security policy")
		return fmt.Errorf("failed to update security policy: %w", err)
	}

	r.logger.WithField("id", policy.ID).Info("Security policy updated successfully")
	return nil
}

// ListPolicies lists security policies with filtering
func (r *SecurityPolicyRepository) ListPolicies(ctx context.Context, filter domain.PolicyFilter) ([]*domain.SecurityPolicy, error) {
	var policies []*domain.SecurityPolicy
	query := r.db.WithContext(ctx).
		Preload("Creator").
		Preload("Updater")

	// Apply filters
	if filter.PolicyType != nil {
		query = query.Where("policy_type = ?", *filter.PolicyType)
	}
	if filter.Category != nil {
		query = query.Where("category = ?", *filter.Category)
	}
	if filter.Enabled != nil {
		query = query.Where("enabled = ?", *filter.Enabled)
	}
	if filter.Status != nil {
		query = query.Where("status = ?", *filter.Status)
	}
	if filter.Scope != nil {
		query = query.Where("scope = ?", *filter.Scope)
	}
	if filter.CreatedBy != nil {
		query = query.Where("created_by = ?", *filter.CreatedBy)
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

	if err := query.Find(&policies).Error; err != nil {
		r.logger.WithError(err).Error("Failed to list security policies")
		return nil, fmt.Errorf("failed to list security policies: %w", err)
	}

	return policies, nil
}

// DeletePolicy deletes a security policy
func (r *SecurityPolicyRepository) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&domain.SecurityPolicy{}, id).Error; err != nil {
		r.logger.WithError(err).WithField("id", id).Error("Failed to delete security policy")
		return fmt.Errorf("failed to delete security policy: %w", err)
	}

	r.logger.WithField("id", id).Info("Security policy deleted successfully")
	return nil
}

// Policy Activation/Deactivation

// ActivatePolicy activates a security policy
func (r *SecurityPolicyRepository) ActivatePolicy(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	if err := r.db.WithContext(ctx).Model(&domain.SecurityPolicy{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":       domain.StatusActive,
			"activated_at": &now,
			"updated_at":   now,
		}).Error; err != nil {
		r.logger.WithError(err).WithField("id", id).Error("Failed to activate security policy")
		return fmt.Errorf("failed to activate security policy: %w", err)
	}

	r.logger.WithField("id", id).Info("Security policy activated successfully")
	return nil
}

// DeactivatePolicy deactivates a security policy
func (r *SecurityPolicyRepository) DeactivatePolicy(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	if err := r.db.WithContext(ctx).Model(&domain.SecurityPolicy{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":         domain.StatusInactive,
			"deactivated_at": &now,
			"updated_at":     now,
		}).Error; err != nil {
		r.logger.WithError(err).WithField("id", id).Error("Failed to deactivate security policy")
		return fmt.Errorf("failed to deactivate security policy: %w", err)
	}

	r.logger.WithField("id", id).Info("Security policy deactivated successfully")
	return nil
}

// GetActivePolicies returns active policies for a scope and target
func (r *SecurityPolicyRepository) GetActivePolicies(ctx context.Context, scope string, targetID *uuid.UUID) ([]*domain.SecurityPolicy, error) {
	var policies []*domain.SecurityPolicy
	query := r.db.WithContext(ctx).
		Preload("Creator").
		Where("enabled = ? AND status = ? AND scope = ?", true, domain.StatusActive, scope)

	// Add target filtering based on scope
	if targetID != nil {
		switch scope {
		case domain.ScopeUser:
			query = query.Where("? = ANY(target_users)", *targetID)
		case domain.ScopeProvider:
			query = query.Where("? = ANY(target_providers)", *targetID)
		case domain.ScopeModel:
			query = query.Where("? = ANY(target_models)", *targetID)
		}
	}

	// Order by priority (higher priority first)
	query = query.Order("priority DESC, execution_order ASC")

	if err := query.Find(&policies).Error; err != nil {
		r.logger.WithError(err).WithFields(map[string]interface{}{
			"scope":     scope,
			"target_id": targetID,
		}).Error("Failed to get active policies")
		return nil, fmt.Errorf("failed to get active policies: %w", err)
	}

	return policies, nil
}

// Policy Violations

// CreateViolation creates a new policy violation
func (r *SecurityPolicyRepository) CreateViolation(ctx context.Context, violation *domain.PolicyViolation) error {
	if err := r.db.WithContext(ctx).Create(violation).Error; err != nil {
		r.logger.WithError(err).Error("Failed to create policy violation")
		return fmt.Errorf("failed to create policy violation: %w", err)
	}

	r.logger.WithField("violation_id", violation.ID).Info("Policy violation created successfully")
	return nil
}

// GetViolation retrieves a policy violation by ID
func (r *SecurityPolicyRepository) GetViolation(ctx context.Context, id uuid.UUID) (*domain.PolicyViolation, error) {
	var violation domain.PolicyViolation
	if err := r.db.WithContext(ctx).
		Preload("Policy").
		Preload("User").
		Preload("Session").
		Preload("ResolvedByUser").
		Where("id = ?", id).
		First(&violation).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("policy violation not found")
		}
		r.logger.WithError(err).WithField("id", id).Error("Failed to get policy violation")
		return nil, fmt.Errorf("failed to get policy violation: %w", err)
	}

	return &violation, nil
}

// UpdateViolation updates a policy violation
func (r *SecurityPolicyRepository) UpdateViolation(ctx context.Context, violation *domain.PolicyViolation) error {
	if err := r.db.WithContext(ctx).Save(violation).Error; err != nil {
		r.logger.WithError(err).WithField("id", violation.ID).Error("Failed to update policy violation")
		return fmt.Errorf("failed to update policy violation: %w", err)
	}

	r.logger.WithField("id", violation.ID).Info("Policy violation updated successfully")
	return nil
}

// ListViolations lists policy violations with filtering
func (r *SecurityPolicyRepository) ListViolations(ctx context.Context, filter domain.ViolationFilter) ([]*domain.PolicyViolation, error) {
	var violations []*domain.PolicyViolation
	query := r.db.WithContext(ctx).
		Preload("Policy").
		Preload("User").
		Preload("Session").
		Preload("ResolvedByUser")

	// Apply filters
	if filter.PolicyID != nil {
		query = query.Where("policy_id = ?", *filter.PolicyID)
	}
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.ViolationType != nil {
		query = query.Where("violation_type = ?", *filter.ViolationType)
	}
	if filter.Severity != nil {
		query = query.Where("severity = ?", *filter.Severity)
	}
	if filter.Status != nil {
		query = query.Where("status = ?", *filter.Status)
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

	if err := query.Find(&violations).Error; err != nil {
		r.logger.WithError(err).Error("Failed to list policy violations")
		return nil, fmt.Errorf("failed to list policy violations: %w", err)
	}

	return violations, nil
}

// ResolveViolation resolves a policy violation
func (r *SecurityPolicyRepository) ResolveViolation(ctx context.Context, id uuid.UUID, resolvedBy uuid.UUID, resolution string) error {
	now := time.Now()
	if err := r.db.WithContext(ctx).Model(&domain.PolicyViolation{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":      domain.ViolationStatusResolved,
			"resolved_at": &now,
			"resolved_by": resolvedBy,
			"resolution":  resolution,
			"updated_at":  now,
		}).Error; err != nil {
		r.logger.WithError(err).WithField("id", id).Error("Failed to resolve policy violation")
		return fmt.Errorf("failed to resolve policy violation: %w", err)
	}

	r.logger.WithFields(map[string]interface{}{
		"id":          id,
		"resolved_by": resolvedBy,
	}).Info("Policy violation resolved successfully")
	return nil
}

// Policy Rules (simplified implementations)

// CreateRule creates a new policy rule
func (r *SecurityPolicyRepository) CreateRule(ctx context.Context, rule *domain.PolicyRule) error {
	if err := r.db.WithContext(ctx).Create(rule).Error; err != nil {
		r.logger.WithError(err).Error("Failed to create policy rule")
		return fmt.Errorf("failed to create policy rule: %w", err)
	}

	r.logger.WithField("rule_name", rule.Name).Info("Policy rule created successfully")
	return nil
}

// GetRule retrieves a policy rule by ID
func (r *SecurityPolicyRepository) GetRule(ctx context.Context, id uuid.UUID) (*domain.PolicyRule, error) {
	var rule domain.PolicyRule
	if err := r.db.WithContext(ctx).
		Preload("Policy").
		Where("id = ?", id).
		First(&rule).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("policy rule not found")
		}
		r.logger.WithError(err).WithField("id", id).Error("Failed to get policy rule")
		return nil, fmt.Errorf("failed to get policy rule: %w", err)
	}

	return &rule, nil
}

// UpdateRule updates a policy rule
func (r *SecurityPolicyRepository) UpdateRule(ctx context.Context, rule *domain.PolicyRule) error {
	if err := r.db.WithContext(ctx).Save(rule).Error; err != nil {
		r.logger.WithError(err).WithField("id", rule.ID).Error("Failed to update policy rule")
		return fmt.Errorf("failed to update policy rule: %w", err)
	}

	r.logger.WithField("id", rule.ID).Info("Policy rule updated successfully")
	return nil
}

// ListRules lists policy rules for a policy
func (r *SecurityPolicyRepository) ListRules(ctx context.Context, policyID uuid.UUID) ([]*domain.PolicyRule, error) {
	var rules []*domain.PolicyRule
	if err := r.db.WithContext(ctx).
		Where("policy_id = ?", policyID).
		Order("priority DESC, created_at ASC").
		Find(&rules).Error; err != nil {
		r.logger.WithError(err).WithField("policy_id", policyID).Error("Failed to list policy rules")
		return nil, fmt.Errorf("failed to list policy rules: %w", err)
	}

	return rules, nil
}

// DeleteRule deletes a policy rule
func (r *SecurityPolicyRepository) DeleteRule(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&domain.PolicyRule{}, id).Error; err != nil {
		r.logger.WithError(err).WithField("id", id).Error("Failed to delete policy rule")
		return fmt.Errorf("failed to delete policy rule: %w", err)
	}

	r.logger.WithField("id", id).Info("Policy rule deleted successfully")
	return nil
}

// Policy Templates

// CreateTemplate creates a new policy template
func (r *SecurityPolicyRepository) CreateTemplate(ctx context.Context, template *domain.PolicyTemplate) error {
	if err := r.db.WithContext(ctx).Create(template).Error; err != nil {
		r.logger.WithError(err).Error("Failed to create policy template")
		return fmt.Errorf("failed to create policy template: %w", err)
	}

	r.logger.WithField("template_name", template.Name).Info("Policy template created successfully")
	return nil
}

// GetTemplate retrieves a policy template by ID
func (r *SecurityPolicyRepository) GetTemplate(ctx context.Context, id uuid.UUID) (*domain.PolicyTemplate, error) {
	var template domain.PolicyTemplate
	if err := r.db.WithContext(ctx).
		Preload("Creator").
		Where("id = ?", id).
		First(&template).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("policy template not found")
		}
		r.logger.WithError(err).WithField("id", id).Error("Failed to get policy template")
		return nil, fmt.Errorf("failed to get policy template: %w", err)
	}

	return &template, nil
}

// UpdateTemplate updates a policy template
func (r *SecurityPolicyRepository) UpdateTemplate(ctx context.Context, template *domain.PolicyTemplate) error {
	if err := r.db.WithContext(ctx).Save(template).Error; err != nil {
		r.logger.WithError(err).WithField("id", template.ID).Error("Failed to update policy template")
		return fmt.Errorf("failed to update policy template: %w", err)
	}

	r.logger.WithField("id", template.ID).Info("Policy template updated successfully")
	return nil
}

// ListTemplates lists policy templates with filtering
func (r *SecurityPolicyRepository) ListTemplates(ctx context.Context, filter domain.TemplateFilter) ([]*domain.PolicyTemplate, error) {
	var templates []*domain.PolicyTemplate
	query := r.db.WithContext(ctx).Preload("Creator")

	// Apply filters
	if filter.Category != nil {
		query = query.Where("category = ?", *filter.Category)
	}
	if filter.PolicyType != nil {
		query = query.Where("policy_type = ?", *filter.PolicyType)
	}
	if filter.IsOfficial != nil {
		query = query.Where("is_official = ?", *filter.IsOfficial)
	}
	if filter.IsPublic != nil {
		query = query.Where("is_public = ?", *filter.IsPublic)
	}
	if filter.CreatedBy != nil {
		query = query.Where("created_by = ?", *filter.CreatedBy)
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

	if err := query.Find(&templates).Error; err != nil {
		r.logger.WithError(err).Error("Failed to list policy templates")
		return nil, fmt.Errorf("failed to list policy templates: %w", err)
	}

	return templates, nil
}

// DeleteTemplate deletes a policy template
func (r *SecurityPolicyRepository) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&domain.PolicyTemplate{}, id).Error; err != nil {
		r.logger.WithError(err).WithField("id", id).Error("Failed to delete policy template")
		return fmt.Errorf("failed to delete policy template: %w", err)
	}

	r.logger.WithField("id", id).Info("Policy template deleted successfully")
	return nil
}

// Policy Execution

// CreateExecution creates a new policy execution record
func (r *SecurityPolicyRepository) CreateExecution(ctx context.Context, execution *domain.PolicyExecution) error {
	if err := r.db.WithContext(ctx).Create(execution).Error; err != nil {
		r.logger.WithError(err).Error("Failed to create policy execution")
		return fmt.Errorf("failed to create policy execution: %w", err)
	}

	return nil
}

// GetExecution retrieves a policy execution by ID
func (r *SecurityPolicyRepository) GetExecution(ctx context.Context, id uuid.UUID) (*domain.PolicyExecution, error) {
	var execution domain.PolicyExecution
	if err := r.db.WithContext(ctx).
		Preload("Policy").
		Where("id = ?", id).
		First(&execution).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("policy execution not found")
		}
		r.logger.WithError(err).WithField("id", id).Error("Failed to get policy execution")
		return nil, fmt.Errorf("failed to get policy execution: %w", err)
	}

	return &execution, nil
}

// ListExecutions lists policy executions with filtering
func (r *SecurityPolicyRepository) ListExecutions(ctx context.Context, filter domain.ExecutionFilter) ([]*domain.PolicyExecution, error) {
	var executions []*domain.PolicyExecution
	query := r.db.WithContext(ctx).Preload("Policy")

	// Apply filters
	if filter.PolicyID != nil {
		query = query.Where("policy_id = ?", *filter.PolicyID)
	}
	if filter.RequestID != nil {
		query = query.Where("request_id = ?", *filter.RequestID)
	}
	if filter.Result != nil {
		query = query.Where("result = ?", *filter.Result)
	}
	if filter.StartTime != nil {
		query = query.Where("execution_time >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("execution_time <= ?", *filter.EndTime)
	}

	// Apply ordering
	orderBy := "execution_time"
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

	if err := query.Find(&executions).Error; err != nil {
		r.logger.WithError(err).Error("Failed to list policy executions")
		return nil, fmt.Errorf("failed to list policy executions: %w", err)
	}

	return executions, nil
}

// Analytics methods (simplified implementations)

// GetPolicyStats returns policy statistics
func (r *SecurityPolicyRepository) GetPolicyStats(ctx context.Context, policyID uuid.UUID, timeRange time.Duration) (*domain.PolicyStats, error) {
	stats := &domain.PolicyStats{
		PolicyID: policyID,
	}

	startTime := time.Now().Add(-timeRange)

	// Get execution count
	if err := r.db.WithContext(ctx).Model(&domain.PolicyExecution{}).
		Where("policy_id = ? AND execution_time >= ?", policyID, startTime).
		Count(&stats.ExecutionCount).Error; err != nil {
		return nil, fmt.Errorf("failed to get execution count: %w", err)
	}

	// Get violation count
	if err := r.db.WithContext(ctx).Model(&domain.PolicyViolation{}).
		Where("policy_id = ? AND created_at >= ?", policyID, startTime).
		Count(&stats.ViolationCount).Error; err != nil {
		return nil, fmt.Errorf("failed to get violation count: %w", err)
	}

	return stats, nil
}

// GetViolationTrends returns violation trends (simplified)
func (r *SecurityPolicyRepository) GetViolationTrends(ctx context.Context, timeRange time.Duration) (*domain.ViolationTrends, error) {
	trends := &domain.ViolationTrends{
		TimeRange:     timeRange.String(),
		DataPoints:    []domain.ViolationTrendDataPoint{},
		TopViolations: []domain.PolicyViolationSummary{},
	}

	return trends, nil
}

// GetTopViolatedPolicies returns top violated policies (simplified)
func (r *SecurityPolicyRepository) GetTopViolatedPolicies(ctx context.Context, limit int, timeRange time.Duration) ([]*domain.PolicyViolationSummary, error) {
	return []*domain.PolicyViolationSummary{}, nil
}
