package handler

import (
	"context"
	"encoding/json"
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
	"github.com/dimajoyti/hackai/pkg/security"
)

var llmSecurityTracer = otel.Tracer("hackai/handler/llm_security")

// LLMSecurityHandler handles LLM security-related HTTP requests
type LLMSecurityHandler struct {
	logger        *logger.Logger
	securityRepo  domain.LLMSecurityRepository
	policyRepo    domain.SecurityPolicyRepository
	securityProxy SecurityProxy
}

// SecurityProxy interface for the LLM security proxy
type SecurityProxy interface {
	ProcessRequest(ctx context.Context, req *security.LLMRequest) (*security.LLMResponse, error)
	GetStats(ctx context.Context) (*ProxyStats, error)
	GetThreatTrends(ctx context.Context, timeRange time.Duration) (*domain.ThreatTrends, error)
	GetTopThreats(ctx context.Context, limit int, timeRange time.Duration) ([]*domain.ThreatSummary, error)
	Health(ctx context.Context) error
}

// ProxyStats represents proxy statistics
type ProxyStats struct {
	TotalRequests      int64         `json:"total_requests"`
	BlockedRequests    int64         `json:"blocked_requests"`
	AverageThreatScore float64       `json:"average_threat_score"`
	TotalTokens        int64         `json:"total_tokens"`
	AverageDuration    float64       `json:"average_duration"`
	Uptime             time.Duration `json:"uptime"`
}

// NewLLMSecurityHandler creates a new LLM security handler
func NewLLMSecurityHandler(
	logger *logger.Logger,
	securityRepo domain.LLMSecurityRepository,
	policyRepo domain.SecurityPolicyRepository,
	securityProxy SecurityProxy,
) *LLMSecurityHandler {
	return &LLMSecurityHandler{
		logger:        logger,
		securityRepo:  securityRepo,
		policyRepo:    policyRepo,
		securityProxy: securityProxy,
	}
}

// RegisterRoutes registers the LLM security routes
func (h *LLMSecurityHandler) RegisterRoutes(router *mux.Router) {
	// LLM Proxy endpoints
	router.HandleFunc("/api/v1/llm/chat", h.ProxyChatRequest).Methods("POST")
	router.HandleFunc("/api/v1/llm/completion", h.ProxyCompletionRequest).Methods("POST")
	router.HandleFunc("/api/v1/llm/providers", h.ListProviders).Methods("GET")
	router.HandleFunc("/api/v1/llm/models", h.ListModels).Methods("GET")

	// Security monitoring endpoints
	router.HandleFunc("/api/v1/security/stats", h.GetSecurityStats).Methods("GET")
	router.HandleFunc("/api/v1/security/threats/trends", h.GetThreatTrends).Methods("GET")
	router.HandleFunc("/api/v1/security/threats/top", h.GetTopThreats).Methods("GET")
	router.HandleFunc("/api/v1/security/health", h.GetSecurityHealth).Methods("GET")

	// Request logs endpoints
	router.HandleFunc("/api/v1/security/logs", h.ListRequestLogs).Methods("GET")
	router.HandleFunc("/api/v1/security/logs/{id}", h.GetRequestLog).Methods("GET")

	// Security events endpoints
	router.HandleFunc("/api/v1/security/events", h.ListSecurityEvents).Methods("GET")
	router.HandleFunc("/api/v1/security/events/{id}", h.GetSecurityEvent).Methods("GET")
	router.HandleFunc("/api/v1/security/events/{id}/resolve", h.ResolveSecurityEvent).Methods("POST")
}

// ProxyChatRequest handles chat completion requests through the security proxy
func (h *LLMSecurityHandler) ProxyChatRequest(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.proxy_chat_request")
	defer span.End()

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Failed to read request body", err)
		return
	}
	defer r.Body.Close()

	// Create LLM request
	llmReq := &security.LLMRequest{
		ID:        uuid.New().String(),
		Provider:  r.Header.Get("X-Provider"),
		Model:     r.Header.Get("X-Model"),
		Endpoint:  "/chat/completions",
		Method:    r.Method,
		Headers:   h.extractHeaders(r),
		Body:      body,
		IPAddress: h.getClientIP(r),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
		Context:   make(map[string]interface{}),
	}

	// Extract user ID from context if available
	if userID := h.getUserIDFromContext(r.Context()); userID != nil {
		llmReq.UserID = userID
	}

	// Extract session ID from context if available
	if sessionID := h.getSessionIDFromContext(r.Context()); sessionID != nil {
		llmReq.SessionID = sessionID
	}

	span.SetAttributes(
		attribute.String("request.id", llmReq.ID),
		attribute.String("request.provider", llmReq.Provider),
		attribute.String("request.model", llmReq.Model),
	)

	// Process through security proxy
	response, err := h.securityProxy.ProcessRequest(ctx, llmReq)
	if err != nil {
		h.logger.WithError(err).Error("Security proxy failed")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Security proxy failed", err)
		return
	}

	// Write response
	h.writeProxyResponse(w, response)
}

// ProxyCompletionRequest handles text completion requests through the security proxy
func (h *LLMSecurityHandler) ProxyCompletionRequest(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.proxy_completion_request")
	defer span.End()

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Failed to read request body", err)
		return
	}
	defer r.Body.Close()

	// Create LLM request
	llmReq := &security.LLMRequest{
		ID:        uuid.New().String(),
		Provider:  r.Header.Get("X-Provider"),
		Model:     r.Header.Get("X-Model"),
		Endpoint:  "/completions",
		Method:    r.Method,
		Headers:   h.extractHeaders(r),
		Body:      body,
		IPAddress: h.getClientIP(r),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
		Context:   make(map[string]interface{}),
	}

	// Extract user ID from context if available
	if userID := h.getUserIDFromContext(r.Context()); userID != nil {
		llmReq.UserID = userID
	}

	// Extract session ID from context if available
	if sessionID := h.getSessionIDFromContext(r.Context()); sessionID != nil {
		llmReq.SessionID = sessionID
	}

	span.SetAttributes(
		attribute.String("request.id", llmReq.ID),
		attribute.String("request.provider", llmReq.Provider),
		attribute.String("request.model", llmReq.Model),
	)

	// Process through security proxy
	response, err := h.securityProxy.ProcessRequest(ctx, llmReq)
	if err != nil {
		h.logger.WithError(err).Error("Security proxy failed")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Security proxy failed", err)
		return
	}

	// Write response
	h.writeProxyResponse(w, response)
}

// ListProviders lists available LLM providers
func (h *LLMSecurityHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.list_providers")
	defer span.End()

	// Parse query parameters
	filter := domain.ProviderFilter{
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

	if providerType := r.URL.Query().Get("type"); providerType != "" {
		filter.ProviderType = &providerType
	}

	if enabledStr := r.URL.Query().Get("enabled"); enabledStr != "" {
		if enabled, err := strconv.ParseBool(enabledStr); err == nil {
			filter.Enabled = &enabled
		}
	}

	// Get providers from repository
	providers, err := h.securityRepo.ListProviders(ctx, filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list providers")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list providers", err)
		return
	}

	span.SetAttributes(
		attribute.Int("providers.count", len(providers)),
	)

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"providers": providers,
		"count":     len(providers),
		"limit":     filter.Limit,
		"offset":    filter.Offset,
	})
}

// ListModels lists available LLM models
func (h *LLMSecurityHandler) ListModels(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.list_models")
	defer span.End()

	// Parse query parameters
	filter := domain.ModelFilter{
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

	if providerIDStr := r.URL.Query().Get("provider_id"); providerIDStr != "" {
		if providerID, err := uuid.Parse(providerIDStr); err == nil {
			filter.ProviderID = &providerID
		}
	}

	if modelType := r.URL.Query().Get("type"); modelType != "" {
		filter.ModelType = &modelType
	}

	if enabledStr := r.URL.Query().Get("enabled"); enabledStr != "" {
		if enabled, err := strconv.ParseBool(enabledStr); err == nil {
			filter.Enabled = &enabled
		}
	}

	// Get models from repository
	models, err := h.securityRepo.ListModels(ctx, filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list models")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list models", err)
		return
	}

	span.SetAttributes(
		attribute.Int("models.count", len(models)),
	)

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"models": models,
		"count":  len(models),
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// Helper methods

// extractHeaders extracts relevant headers from the request
func (h *LLMSecurityHandler) extractHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)

	// Extract important headers
	importantHeaders := []string{
		"Authorization",
		"Content-Type",
		"User-Agent",
		"X-Provider",
		"X-Model",
		"X-API-Key",
	}

	for _, header := range importantHeaders {
		if value := r.Header.Get(header); value != "" {
			headers[header] = value
		}
	}

	return headers
}

// getClientIP extracts the client IP address
func (h *LLMSecurityHandler) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// getUserIDFromContext extracts user ID from request context
func (h *LLMSecurityHandler) getUserIDFromContext(ctx context.Context) *uuid.UUID {
	// This would typically extract from JWT token or session
	// For now, return nil (anonymous user)
	return nil
}

// getSessionIDFromContext extracts session ID from request context
func (h *LLMSecurityHandler) getSessionIDFromContext(ctx context.Context) *uuid.UUID {
	// This would typically extract from session store
	// For now, return nil
	return nil
}

// writeProxyResponse writes the LLM response back to the client
func (h *LLMSecurityHandler) writeProxyResponse(w http.ResponseWriter, resp *security.LLMResponse) {
	// Set response headers
	for key, value := range resp.Headers {
		w.Header().Set(key, value)
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Write response body
	w.Write(resp.Body)
}

// writeJSONResponse writes a JSON response
func (h *LLMSecurityHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

// GetSecurityStats gets security proxy statistics
func (h *LLMSecurityHandler) GetSecurityStats(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.get_security_stats")
	defer span.End()

	stats, err := h.securityProxy.GetStats(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security stats")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get security stats", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"stats":     stats,
		"timestamp": time.Now(),
	})
}

// GetThreatTrends gets threat trends analysis
func (h *LLMSecurityHandler) GetThreatTrends(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.get_threat_trends")
	defer span.End()

	// Parse time range parameter
	timeRangeStr := r.URL.Query().Get("range")
	timeRange := 24 * time.Hour // Default to 24 hours

	switch timeRangeStr {
	case "1h":
		timeRange = time.Hour
	case "6h":
		timeRange = 6 * time.Hour
	case "12h":
		timeRange = 12 * time.Hour
	case "24h":
		timeRange = 24 * time.Hour
	case "7d":
		timeRange = 7 * 24 * time.Hour
	case "30d":
		timeRange = 30 * 24 * time.Hour
	}

	trends, err := h.securityProxy.GetThreatTrends(ctx, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get threat trends")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get threat trends", err)
		return
	}

	span.SetAttributes(
		attribute.String("time_range", timeRangeStr),
		attribute.Int("data_points", len(trends.DataPoints)),
	)

	h.writeJSONResponse(w, http.StatusOK, trends)
}

// GetTopThreats gets top threats summary
func (h *LLMSecurityHandler) GetTopThreats(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.get_top_threats")
	defer span.End()

	// Parse parameters
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	timeRangeStr := r.URL.Query().Get("range")
	timeRange := 24 * time.Hour // Default to 24 hours

	switch timeRangeStr {
	case "1h":
		timeRange = time.Hour
	case "6h":
		timeRange = 6 * time.Hour
	case "12h":
		timeRange = 12 * time.Hour
	case "24h":
		timeRange = 24 * time.Hour
	case "7d":
		timeRange = 7 * 24 * time.Hour
	case "30d":
		timeRange = 30 * 24 * time.Hour
	}

	threats, err := h.securityProxy.GetTopThreats(ctx, limit, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get top threats")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get top threats", err)
		return
	}

	span.SetAttributes(
		attribute.Int("limit", limit),
		attribute.String("time_range", timeRangeStr),
		attribute.Int("threats_count", len(threats)),
	)

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"threats":   threats,
		"count":     len(threats),
		"limit":     limit,
		"timestamp": time.Now(),
	})
}

// GetSecurityHealth gets security system health status
func (h *LLMSecurityHandler) GetSecurityHealth(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.get_security_health")
	defer span.End()

	err := h.securityProxy.Health(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Security health check failed")
		h.writeJSONResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":    "unhealthy",
			"error":     err.Error(),
			"timestamp": time.Now(),
		})
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
	})
}

// ListRequestLogs lists LLM request logs
func (h *LLMSecurityHandler) ListRequestLogs(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.list_request_logs")
	defer span.End()

	// Parse query parameters
	filter := domain.RequestLogFilter{
		Limit:  20,
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

	if userIDStr := r.URL.Query().Get("user_id"); userIDStr != "" {
		if userID, err := uuid.Parse(userIDStr); err == nil {
			filter.UserID = &userID
		}
	}

	if provider := r.URL.Query().Get("provider"); provider != "" {
		filter.Provider = &provider
	}

	if model := r.URL.Query().Get("model"); model != "" {
		filter.Model = &model
	}

	if blockedStr := r.URL.Query().Get("blocked"); blockedStr != "" {
		if blocked, err := strconv.ParseBool(blockedStr); err == nil {
			filter.Blocked = &blocked
		}
	}

	// Parse time range
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if from, err := time.Parse(time.RFC3339, fromStr); err == nil {
			filter.StartTime = &from
		}
	}

	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if to, err := time.Parse(time.RFC3339, toStr); err == nil {
			filter.EndTime = &to
		}
	}

	logs, err := h.securityRepo.ListRequestLogs(ctx, filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list request logs")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list request logs", err)
		return
	}

	span.SetAttributes(
		attribute.Int("logs_count", len(logs)),
	)

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"logs":      logs,
		"count":     len(logs),
		"limit":     filter.Limit,
		"offset":    filter.Offset,
		"timestamp": time.Now(),
	})
}

// GetRequestLog gets a specific request log by ID
func (h *LLMSecurityHandler) GetRequestLog(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.get_request_log")
	defer span.End()

	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request log ID", err)
		return
	}

	log, err := h.securityRepo.GetRequestLog(ctx, id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get request log")
		h.writeErrorResponse(w, http.StatusNotFound, "Request log not found", err)
		return
	}

	span.SetAttributes(
		attribute.String("log_id", id.String()),
	)

	h.writeJSONResponse(w, http.StatusOK, log)
}

// ListSecurityEvents lists security events
func (h *LLMSecurityHandler) ListSecurityEvents(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.list_security_events")
	defer span.End()

	// Parse query parameters
	filter := make(map[string]interface{})

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	if severity := r.URL.Query().Get("severity"); severity != "" {
		filter["severity"] = severity
	}

	if eventType := r.URL.Query().Get("type"); eventType != "" {
		filter["type"] = eventType
	}

	if status := r.URL.Query().Get("status"); status != "" {
		filter["status"] = status
	}

	// Get security events from audit repository (since SecurityEvent is defined there)
	auditRepo := h.securityRepo.(interface {
		ListSecurityEvents(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*domain.SecurityEvent, error)
	})

	events, err := auditRepo.ListSecurityEvents(ctx, filter, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list security events")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list security events", err)
		return
	}

	span.SetAttributes(
		attribute.Int("events_count", len(events)),
	)

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"events":    events,
		"count":     len(events),
		"limit":     limit,
		"offset":    offset,
		"timestamp": time.Now(),
	})
}

// GetSecurityEvent gets a specific security event by ID
func (h *LLMSecurityHandler) GetSecurityEvent(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.get_security_event")
	defer span.End()

	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid security event ID", err)
		return
	}

	// Get security event from audit repository
	auditRepo := h.securityRepo.(interface {
		GetSecurityEvent(ctx context.Context, id uuid.UUID) (*domain.SecurityEvent, error)
	})

	event, err := auditRepo.GetSecurityEvent(ctx, id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security event")
		h.writeErrorResponse(w, http.StatusNotFound, "Security event not found", err)
		return
	}

	span.SetAttributes(
		attribute.String("event_id", id.String()),
	)

	h.writeJSONResponse(w, http.StatusOK, event)
}

// ResolveSecurityEvent resolves a security event
func (h *LLMSecurityHandler) ResolveSecurityEvent(w http.ResponseWriter, r *http.Request) {
	ctx, span := llmSecurityTracer.Start(r.Context(), "llm_security.resolve_security_event")
	defer span.End()

	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid security event ID", err)
		return
	}

	// Parse resolution data
	var resolutionData struct {
		Resolution string `json:"resolution"`
		ResolvedBy string `json:"resolved_by,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&resolutionData); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Get security event first
	auditRepo := h.securityRepo.(interface {
		GetSecurityEvent(ctx context.Context, id uuid.UUID) (*domain.SecurityEvent, error)
		UpdateSecurityEvent(ctx context.Context, event *domain.SecurityEvent) error
	})

	event, err := auditRepo.GetSecurityEvent(ctx, id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security event")
		h.writeErrorResponse(w, http.StatusNotFound, "Security event not found", err)
		return
	}

	// Update event resolution
	now := time.Now()
	event.Status = domain.EventStatusResolved
	event.Resolution = resolutionData.Resolution
	event.ResolvedAt = &now
	event.UpdatedAt = now

	// Set resolved by if provided
	if resolutionData.ResolvedBy != "" {
		if resolvedByID, err := uuid.Parse(resolutionData.ResolvedBy); err == nil {
			event.ResolvedBy = &resolvedByID
		}
	}

	if err := auditRepo.UpdateSecurityEvent(ctx, event); err != nil {
		h.logger.WithError(err).Error("Failed to update security event")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to resolve security event", err)
		return
	}

	span.SetAttributes(
		attribute.String("event_id", id.String()),
		attribute.String("resolution", resolutionData.Resolution),
	)

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message":   "Security event resolved successfully",
		"event_id":  id.String(),
		"timestamp": time.Now(),
	})
}

// writeErrorResponse writes an error response
func (h *LLMSecurityHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
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
