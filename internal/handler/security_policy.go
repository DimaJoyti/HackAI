package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var policyHandlerTracer = otel.Tracer("hackai/handler/security_policy")

// SecurityPolicyHandler handles security policy management HTTP requests
type SecurityPolicyHandler struct {
	logger     *logger.Logger
	policyRepo domain.SecurityPolicyRepository
}

// PolicyRequest represents a policy creation/update request
type PolicyRequest struct {
	Name                 string                 `json:"name" validate:"required,min=1,max=255"`
	DisplayName          string                 `json:"display_name" validate:"required,min=1,max=255"`
	Description          string                 `json:"description"`
	PolicyType           string                 `json:"policy_type" validate:"required"`
	Category             string                 `json:"category" validate:"required"`
	Rules                json.RawMessage        `json:"rules" validate:"required"`
	Priority             int                    `json:"priority"`
	Enabled              bool                   `json:"enabled"`
	Scope                string                 `json:"scope" validate:"required"`
	TargetUsers          []uuid.UUID            `json:"target_users"`
	TargetProviders      []uuid.UUID            `json:"target_providers"`
	TargetModels         []uuid.UUID            `json:"target_models"`
	Actions              json.RawMessage        `json:"actions"`
	BlockOnViolation     bool                   `json:"block_on_violation"`
	AlertOnViolation     bool                   `json:"alert_on_violation"`
	LogViolations        bool                   `json:"log_violations"`
	ThreatThreshold      float64                `json:"threat_threshold"`
	MaxViolations        int                    `json:"max_violations"`
	TimeWindow           int                    `json:"time_window"`
	ComplianceFrameworks []string               `json:"compliance_frameworks"`
	AuditRequired        bool                   `json:"audit_required"`
	RetentionPeriod      int                    `json:"retention_period"`
	ExpiresAt            *time.Time             `json:"expires_at"`
	Tags                 []string               `json:"tags"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// PolicyTestRequest represents a policy test request
type PolicyTestRequest struct {
	PolicyID   uuid.UUID              `json:"policy_id"`
	TestData   json.RawMessage        `json:"test_data" validate:"required"`
	TestType   string                 `json:"test_type" validate:"required"`
	Parameters map[string]interface{} `json:"parameters"`
}

// PolicyTestResult represents a policy test result
type PolicyTestResult struct {
	PolicyID        uuid.UUID              `json:"policy_id"`
	TestType        string                 `json:"test_type"`
	Passed          bool                   `json:"passed"`
	Score           float64                `json:"score"`
	Violations      []PolicyViolationInfo  `json:"violations"`
	ExecutionTime   time.Duration          `json:"execution_time"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// PolicyViolationInfo represents violation information for testing
type PolicyViolationInfo struct {
	RuleID      uuid.UUID              `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Score       float64                `json:"score"`
}

// NewSecurityPolicyHandler creates a new security policy handler
func NewSecurityPolicyHandler(
	logger *logger.Logger,
	policyRepo domain.SecurityPolicyRepository,
) *SecurityPolicyHandler {
	return &SecurityPolicyHandler{
		logger:     logger,
		policyRepo: policyRepo,
	}
}

// RegisterRoutes registers the security policy routes
func (h *SecurityPolicyHandler) RegisterRoutes(router *mux.Router) {
	// Policy CRUD operations
	router.HandleFunc("/api/v1/security/policies", h.ListPolicies).Methods("GET")
	router.HandleFunc("/api/v1/security/policies", h.CreatePolicy).Methods("POST")
	router.HandleFunc("/api/v1/security/policies/{id}", h.GetPolicy).Methods("GET")
	router.HandleFunc("/api/v1/security/policies/{id}", h.UpdatePolicy).Methods("PUT")
	router.HandleFunc("/api/v1/security/policies/{id}", h.DeletePolicy).Methods("DELETE")

	// Policy activation/deactivation
	router.HandleFunc("/api/v1/security/policies/{id}/activate", h.ActivatePolicy).Methods("POST")
	router.HandleFunc("/api/v1/security/policies/{id}/deactivate", h.DeactivatePolicy).Methods("POST")

	// Policy testing
	router.HandleFunc("/api/v1/security/policies/{id}/test", h.TestPolicy).Methods("POST")
	router.HandleFunc("/api/v1/security/policies/test", h.TestPolicyContent).Methods("POST")

	// Policy violations
	router.HandleFunc("/api/v1/security/violations", h.ListViolations).Methods("GET")
	router.HandleFunc("/api/v1/security/violations/{id}", h.GetViolation).Methods("GET")
	router.HandleFunc("/api/v1/security/violations/{id}/resolve", h.ResolveViolation).Methods("POST")

	// Policy templates
	router.HandleFunc("/api/v1/security/policy-templates", h.ListTemplates).Methods("GET")
	router.HandleFunc("/api/v1/security/policy-templates", h.CreateTemplate).Methods("POST")
	router.HandleFunc("/api/v1/security/policy-templates/{id}", h.GetTemplate).Methods("GET")

	// Policy analytics
	router.HandleFunc("/api/v1/security/policies/{id}/stats", h.GetPolicyStats).Methods("GET")
	router.HandleFunc("/api/v1/security/violations/trends", h.GetViolationTrends).Methods("GET")
}

// ListPolicies lists security policies with filtering
func (h *SecurityPolicyHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	ctx, span := policyHandlerTracer.Start(r.Context(), "security_policy.list_policies")
	defer span.End()

	// Parse query parameters
	filter := domain.PolicyFilter{
		Limit:  10,
		Offset: 0,
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 100 {
			filter.Limit = limit
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	if policyType := r.URL.Query().Get("type"); policyType != "" {
		filter.PolicyType = &policyType
	}

	if category := r.URL.Query().Get("category"); category != "" {
		filter.Category = &category
	}

	if enabledStr := r.URL.Query().Get("enabled"); enabledStr != "" {
		if enabled, err := strconv.ParseBool(enabledStr); err == nil {
			filter.Enabled = &enabled
		}
	}

	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}

	if scope := r.URL.Query().Get("scope"); scope != "" {
		filter.Scope = &scope
	}

	// Get policies from repository
	policies, err := h.policyRepo.ListPolicies(ctx, filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list policies")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list policies", err)
		return
	}

	span.SetAttributes(
		attribute.Int("policies.count", len(policies)),
	)

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"policies": policies,
		"count":    len(policies),
		"limit":    filter.Limit,
		"offset":   filter.Offset,
	})
}

// CreatePolicy creates a new security policy
func (h *SecurityPolicyHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx, span := policyHandlerTracer.Start(r.Context(), "security_policy.create_policy")
	defer span.End()

	// Parse request body
	var req PolicyRequest
	if err := h.parseJSONRequest(r, &req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if err := h.validatePolicyRequest(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Validation failed", err)
		return
	}

	// Get user ID from context (for audit trail)
	userID := h.getUserIDFromContext(ctx)
	if userID == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User authentication required", nil)
		return
	}

	// Create policy domain object
	policy := &domain.SecurityPolicy{
		Name:                 req.Name,
		DisplayName:          req.DisplayName,
		Description:          req.Description,
		PolicyType:           req.PolicyType,
		Category:             req.Category,
		Rules:                req.Rules,
		Priority:             req.Priority,
		Enabled:              req.Enabled,
		Scope:                req.Scope,
		TargetUsers:          req.TargetUsers,
		TargetProviders:      req.TargetProviders,
		TargetModels:         req.TargetModels,
		Actions:              req.Actions,
		BlockOnViolation:     req.BlockOnViolation,
		AlertOnViolation:     req.AlertOnViolation,
		LogViolations:        req.LogViolations,
		ThreatThreshold:      req.ThreatThreshold,
		MaxViolations:        req.MaxViolations,
		TimeWindow:           req.TimeWindow,
		Version:              "1.0.0",
		ComplianceFrameworks: req.ComplianceFrameworks,
		AuditRequired:        req.AuditRequired,
		RetentionPeriod:      req.RetentionPeriod,
		Status:               domain.StatusDraft,
		ExpiresAt:            req.ExpiresAt,
		Tags:                 req.Tags,
		CreatedBy:            *userID,
	}

	// Set metadata
	if req.Metadata != nil {
		metadataJSON, _ := json.Marshal(req.Metadata)
		policy.Metadata = metadataJSON
	}

	// Create policy in repository
	if err := h.policyRepo.CreatePolicy(ctx, policy); err != nil {
		h.logger.WithError(err).Error("Failed to create policy")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create policy", err)
		return
	}

	span.SetAttributes(
		attribute.String("policy.id", policy.ID.String()),
		attribute.String("policy.name", policy.Name),
		attribute.String("policy.type", policy.PolicyType),
	)

	h.logger.WithFields(map[string]interface{}{
		"policy_id":   policy.ID,
		"policy_name": policy.Name,
		"created_by":  userID,
	}).Info("Security policy created")

	h.writeJSONResponse(w, http.StatusCreated, policy)
}

// GetPolicy gets a specific security policy
func (h *SecurityPolicyHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	ctx, span := policyHandlerTracer.Start(r.Context(), "security_policy.get_policy")
	defer span.End()

	// Parse ID from URL
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid policy ID", err)
		return
	}

	// Get policy from repository
	policy, err := h.policyRepo.GetPolicy(ctx, id)
	if err != nil {
		h.logger.WithError(err).WithField("id", id).Error("Failed to get policy")
		h.writeErrorResponse(w, http.StatusNotFound, "Policy not found", err)
		return
	}

	span.SetAttributes(
		attribute.String("policy.id", policy.ID.String()),
		attribute.String("policy.name", policy.Name),
	)

	h.writeJSONResponse(w, http.StatusOK, policy)
}

// UpdatePolicy updates an existing security policy
func (h *SecurityPolicyHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx, span := policyHandlerTracer.Start(r.Context(), "security_policy.update_policy")
	defer span.End()

	// Parse ID from URL
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid policy ID", err)
		return
	}

	// Parse request body
	var req PolicyRequest
	if err := h.parseJSONRequest(r, &req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if err := h.validatePolicyRequest(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Validation failed", err)
		return
	}

	// Get existing policy
	policy, err := h.policyRepo.GetPolicy(ctx, id)
	if err != nil {
		h.logger.WithError(err).WithField("id", id).Error("Failed to get policy for update")
		h.writeErrorResponse(w, http.StatusNotFound, "Policy not found", err)
		return
	}

	// Get user ID from context
	userID := h.getUserIDFromContext(ctx)
	if userID == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User authentication required", nil)
		return
	}

	// Update policy fields
	policy.Name = req.Name
	policy.DisplayName = req.DisplayName
	policy.Description = req.Description
	policy.PolicyType = req.PolicyType
	policy.Category = req.Category
	policy.Rules = req.Rules
	policy.Priority = req.Priority
	policy.Enabled = req.Enabled
	policy.Scope = req.Scope
	policy.TargetUsers = req.TargetUsers
	policy.TargetProviders = req.TargetProviders
	policy.TargetModels = req.TargetModels
	policy.Actions = req.Actions
	policy.BlockOnViolation = req.BlockOnViolation
	policy.AlertOnViolation = req.AlertOnViolation
	policy.LogViolations = req.LogViolations
	policy.ThreatThreshold = req.ThreatThreshold
	policy.MaxViolations = req.MaxViolations
	policy.TimeWindow = req.TimeWindow
	policy.ComplianceFrameworks = req.ComplianceFrameworks
	policy.AuditRequired = req.AuditRequired
	policy.RetentionPeriod = req.RetentionPeriod
	policy.ExpiresAt = req.ExpiresAt
	policy.Tags = req.Tags
	policy.UpdatedBy = userID

	// Set metadata
	if req.Metadata != nil {
		metadataJSON, _ := json.Marshal(req.Metadata)
		policy.Metadata = metadataJSON
	}

	// Update policy in repository
	if err := h.policyRepo.UpdatePolicy(ctx, policy); err != nil {
		h.logger.WithError(err).Error("Failed to update policy")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update policy", err)
		return
	}

	span.SetAttributes(
		attribute.String("policy.id", policy.ID.String()),
		attribute.String("policy.name", policy.Name),
	)

	h.logger.WithFields(map[string]interface{}{
		"policy_id":   policy.ID,
		"policy_name": policy.Name,
		"updated_by":  userID,
	}).Info("Security policy updated")

	h.writeJSONResponse(w, http.StatusOK, policy)
}

// DeletePolicy deletes a security policy
func (h *SecurityPolicyHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	ctx, span := policyHandlerTracer.Start(r.Context(), "security_policy.delete_policy")
	defer span.End()

	// Parse ID from URL
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid policy ID", err)
		return
	}

	// Get user ID from context
	userID := h.getUserIDFromContext(ctx)
	if userID == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User authentication required", nil)
		return
	}

	// Delete policy from repository
	if err := h.policyRepo.DeletePolicy(ctx, id); err != nil {
		h.logger.WithError(err).WithField("id", id).Error("Failed to delete policy")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete policy", err)
		return
	}

	span.SetAttributes(
		attribute.String("policy.id", id.String()),
	)

	h.logger.WithFields(map[string]interface{}{
		"policy_id":  id,
		"deleted_by": userID,
	}).Info("Security policy deleted")

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Policy deleted successfully",
		"id":      id,
	})
}

// ActivatePolicy activates a security policy
func (h *SecurityPolicyHandler) ActivatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx, span := policyHandlerTracer.Start(r.Context(), "security_policy.activate_policy")
	defer span.End()

	// Parse ID from URL
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid policy ID", err)
		return
	}

	// Get user ID from context
	userID := h.getUserIDFromContext(ctx)
	if userID == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User authentication required", nil)
		return
	}

	// Activate policy
	if err := h.policyRepo.ActivatePolicy(ctx, id); err != nil {
		h.logger.WithError(err).WithField("id", id).Error("Failed to activate policy")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to activate policy", err)
		return
	}

	span.SetAttributes(
		attribute.String("policy.id", id.String()),
	)

	h.logger.WithFields(map[string]interface{}{
		"policy_id":    id,
		"activated_by": userID,
	}).Info("Security policy activated")

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Policy activated successfully",
		"id":      id,
	})
}

// DeactivatePolicy deactivates a security policy
func (h *SecurityPolicyHandler) DeactivatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx, span := policyHandlerTracer.Start(r.Context(), "security_policy.deactivate_policy")
	defer span.End()

	// Parse ID from URL
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid policy ID", err)
		return
	}

	// Get user ID from context
	userID := h.getUserIDFromContext(ctx)
	if userID == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User authentication required", nil)
		return
	}

	// Deactivate policy
	if err := h.policyRepo.DeactivatePolicy(ctx, id); err != nil {
		h.logger.WithError(err).WithField("id", id).Error("Failed to deactivate policy")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to deactivate policy", err)
		return
	}

	span.SetAttributes(
		attribute.String("policy.id", id.String()),
	)

	h.logger.WithFields(map[string]interface{}{
		"policy_id":      id,
		"deactivated_by": userID,
	}).Info("Security policy deactivated")

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Policy deactivated successfully",
		"id":      id,
	})
}

// Helper methods

// parseJSONRequest parses JSON request body
func (h *SecurityPolicyHandler) parseJSONRequest(r *http.Request, v interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	return json.Unmarshal(body, v)
}

// validatePolicyRequest validates a policy request
func (h *SecurityPolicyHandler) validatePolicyRequest(req *PolicyRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if req.PolicyType == "" {
		return fmt.Errorf("policy_type is required")
	}
	if req.Category == "" {
		return fmt.Errorf("category is required")
	}
	if req.Scope == "" {
		return fmt.Errorf("scope is required")
	}
	if len(req.Rules) == 0 {
		return fmt.Errorf("rules are required")
	}
	return nil
}

// getUserIDFromContext extracts user ID from request context
func (h *SecurityPolicyHandler) getUserIDFromContext(ctx context.Context) *uuid.UUID {
	// This would typically extract from JWT token or session
	// For now, return a dummy user ID
	dummyUserID := uuid.New()
	return &dummyUserID
}

// writeJSONResponse writes a JSON response
func (h *SecurityPolicyHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

// writeErrorResponse writes an error response
func (h *SecurityPolicyHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	h.logger.WithError(err).WithFields(map[string]interface{}{
		"status_code": statusCode,
		"message":     message,
	}).Error("HTTP error response")

	errorResponse := map[string]interface{}{
		"error": map[string]interface{}{
			"message":   message,
			"status":    statusCode,
			"timestamp": time.Now(),
		},
	}

	if err != nil {
		errorResponse["error"].(map[string]interface{})["details"] = err.Error()
	}

	h.writeJSONResponse(w, statusCode, errorResponse)
}

// Placeholder methods for missing handlers (to be implemented)

func (h *SecurityPolicyHandler) TestPolicy(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Policy testing not yet implemented", nil)
}

func (h *SecurityPolicyHandler) TestPolicyContent(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Policy content testing not yet implemented", nil)
}

func (h *SecurityPolicyHandler) ListViolations(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Violation listing not yet implemented", nil)
}

func (h *SecurityPolicyHandler) GetViolation(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Violation retrieval not yet implemented", nil)
}

func (h *SecurityPolicyHandler) ResolveViolation(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Violation resolution not yet implemented", nil)
}

func (h *SecurityPolicyHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Template listing not yet implemented", nil)
}

func (h *SecurityPolicyHandler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Template creation not yet implemented", nil)
}

func (h *SecurityPolicyHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Template retrieval not yet implemented", nil)
}

func (h *SecurityPolicyHandler) GetPolicyStats(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Policy statistics not yet implemented", nil)
}

func (h *SecurityPolicyHandler) GetViolationTrends(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Violation trends not yet implemented", nil)
}
