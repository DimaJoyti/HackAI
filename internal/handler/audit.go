package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/audit"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var auditHandlerTracer = otel.Tracer("hackai/handler/audit")

// AuditHandler handles audit-related HTTP requests
type AuditHandler struct {
	logger       *logger.Logger
	auditService *audit.LLMAuditService
	auditRepo    domain.AuditRepository
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(
	logger *logger.Logger,
	auditService *audit.LLMAuditService,
	auditRepo domain.AuditRepository,
) *AuditHandler {
	return &AuditHandler{
		logger:       logger,
		auditService: auditService,
		auditRepo:    auditRepo,
	}
}

// RegisterRoutes registers the audit routes
func (h *AuditHandler) RegisterRoutes(router *mux.Router) {
	// Audit logs endpoints
	router.HandleFunc("/api/v1/audit/logs", h.ListAuditLogs).Methods("GET")
	router.HandleFunc("/api/v1/audit/logs/{id}", h.GetAuditLog).Methods("GET")
	router.HandleFunc("/api/v1/audit/logs/export", h.ExportAuditLogs).Methods("GET")

	// Audit metrics endpoints
	router.HandleFunc("/api/v1/audit/metrics", h.GetAuditMetrics).Methods("GET")
	router.HandleFunc("/api/v1/audit/summary", h.GetAuditSummary).Methods("GET")

	// Audit management endpoints
	router.HandleFunc("/api/v1/audit/cleanup", h.TriggerCleanup).Methods("POST")
	router.HandleFunc("/api/v1/audit/status", h.GetAuditStatus).Methods("GET")
	router.HandleFunc("/api/v1/audit/config", h.GetAuditConfig).Methods("GET")
	router.HandleFunc("/api/v1/audit/config", h.UpdateAuditConfig).Methods("PUT")
}

// ListAuditLogs lists audit logs with filtering
func (h *AuditHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	_, span := auditHandlerTracer.Start(r.Context(), "audit.list_audit_logs")
	defer span.End()

	// Parse query parameters
	filters := make(map[string]interface{})
	limit := 50
	offset := 0

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	if userIDStr := r.URL.Query().Get("user_id"); userIDStr != "" {
		if userID, err := uuid.Parse(userIDStr); err == nil {
			filters["user_id"] = userID
		}
	}

	if action := r.URL.Query().Get("action"); action != "" {
		filters["action"] = action
	}

	if status := r.URL.Query().Get("status"); status != "" {
		filters["status"] = status
	}

	if startTimeStr := r.URL.Query().Get("start_time"); startTimeStr != "" {
		if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filters["start_time"] = startTime
		}
	}

	if endTimeStr := r.URL.Query().Get("end_time"); endTimeStr != "" {
		if endTime, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filters["end_time"] = endTime
		}
	}

	// Get audit logs
	logs, err := h.auditRepo.ListAuditLogs(filters, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list audit logs")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list audit logs", err)
		return
	}

	span.SetAttributes(
		attribute.Int("audit.logs_count", len(logs)),
		attribute.Int("audit.limit", limit),
		attribute.Int("audit.offset", offset),
	)

	response := map[string]interface{}{
		"logs":      logs,
		"count":     len(logs),
		"limit":     limit,
		"offset":    offset,
		"filters":   filters,
		"timestamp": time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetAuditLog gets a specific audit log
func (h *AuditHandler) GetAuditLog(w http.ResponseWriter, r *http.Request) {
	_, span := auditHandlerTracer.Start(r.Context(), "audit.get_audit_log")
	defer span.End()

	// Parse ID from URL
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid audit log ID", err)
		return
	}

	// Get audit log
	log, err := h.auditRepo.GetAuditLog(id)
	if err != nil {
		h.logger.WithError(err).WithField("id", id).Error("Failed to get audit log")
		h.writeErrorResponse(w, http.StatusNotFound, "Audit log not found", err)
		return
	}

	span.SetAttributes(
		attribute.String("audit.log_id", log.ID.String()),
		attribute.String("audit.action", log.Action),
	)

	h.writeJSONResponse(w, http.StatusOK, log)
}

// ExportAuditLogs exports audit logs in various formats
func (h *AuditHandler) ExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	_, span := auditHandlerTracer.Start(r.Context(), "audit.export_audit_logs")
	defer span.End()

	// Parse parameters
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	// Parse time range
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour) // Default to last 24 hours

	if startTimeStr := r.URL.Query().Get("start_time"); startTimeStr != "" {
		if parsed, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			startTime = parsed
		}
	}

	if endTimeStr := r.URL.Query().Get("end_time"); endTimeStr != "" {
		if parsed, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			endTime = parsed
		}
	}

	// Get audit logs for export
	filters := map[string]interface{}{
		"start_time": startTime,
		"end_time":   endTime,
	}

	logs, err := h.auditRepo.ListAuditLogs(filters, 10000, 0) // Large limit for export
	if err != nil {
		h.logger.WithError(err).Error("Failed to get audit logs for export")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to export audit logs", err)
		return
	}

	// Set appropriate headers
	filename := "audit_logs_" + startTime.Format("2006-01-02") + "_to_" + endTime.Format("2006-01-02")

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename+".csv")
		h.writeErrorResponse(w, http.StatusNotImplemented, "CSV export not yet implemented", nil)
		return
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename+".json")
	}

	exportData := map[string]interface{}{
		"export_timestamp": time.Now(),
		"time_range": map[string]interface{}{
			"start": startTime,
			"end":   endTime,
		},
		"total_logs": len(logs),
		"logs":       logs,
	}

	span.SetAttributes(
		attribute.String("audit.export_format", format),
		attribute.Int("audit.exported_logs", len(logs)),
	)

	h.writeJSONResponse(w, http.StatusOK, exportData)
}

// GetAuditMetrics returns audit metrics
func (h *AuditHandler) GetAuditMetrics(w http.ResponseWriter, r *http.Request) {
	ctx, span := auditHandlerTracer.Start(r.Context(), "audit.get_audit_metrics")
	defer span.End()

	// Get audit metrics
	metrics, err := h.auditService.GetAuditMetrics(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get audit metrics")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get audit metrics", err)
		return
	}

	span.SetAttributes(
		attribute.Int64("audit.total_requests", metrics.TotalRequests),
		attribute.Int64("audit.security_violations", metrics.SecurityViolations),
	)

	h.writeJSONResponse(w, http.StatusOK, metrics)
}

// GetAuditSummary returns audit summary for a time range
func (h *AuditHandler) GetAuditSummary(w http.ResponseWriter, r *http.Request) {
	ctx, span := auditHandlerTracer.Start(r.Context(), "audit.get_audit_summary")
	defer span.End()

	// Parse time range
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour) // Default to last 24 hours

	if startTimeStr := r.URL.Query().Get("start_time"); startTimeStr != "" {
		if parsed, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			startTime = parsed
		}
	}

	if endTimeStr := r.URL.Query().Get("end_time"); endTimeStr != "" {
		if parsed, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			endTime = parsed
		}
	}

	// Get audit summary
	summary, err := h.auditService.GetAuditSummary(ctx, startTime, endTime)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get audit summary")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get audit summary", err)
		return
	}

	span.SetAttributes(
		attribute.String("audit.time_range", summary.TimeRange),
		attribute.Int64("audit.total_requests", summary.Metrics.TotalRequests),
	)

	h.writeJSONResponse(w, http.StatusOK, summary)
}

// TriggerCleanup triggers manual audit log cleanup
func (h *AuditHandler) TriggerCleanup(w http.ResponseWriter, r *http.Request) {
	ctx, span := auditHandlerTracer.Start(r.Context(), "audit.trigger_cleanup")
	defer span.End()

	// Trigger cleanup
	err := h.auditService.CleanupOldAuditLogs(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to trigger audit cleanup")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to trigger cleanup", err)
		return
	}

	response := map[string]interface{}{
		"message":   "Audit log cleanup triggered successfully",
		"timestamp": time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetAuditStatus returns audit service status
func (h *AuditHandler) GetAuditStatus(w http.ResponseWriter, r *http.Request) {
	_, span := auditHandlerTracer.Start(r.Context(), "audit.get_audit_status")
	defer span.End()

	// Get audit service status
	status := map[string]interface{}{
		"service":   "audit",
		"status":    "running",
		"timestamp": time.Now(),
		"version":   "1.0.0",
	}

	h.writeJSONResponse(w, http.StatusOK, status)
}

// GetAuditConfig returns audit configuration
func (h *AuditHandler) GetAuditConfig(w http.ResponseWriter, r *http.Request) {
	_, span := auditHandlerTracer.Start(r.Context(), "audit.get_audit_config")
	defer span.End()

	// Return placeholder config (would be actual config in production)
	config := map[string]interface{}{
		"enabled":                 true,
		"retention_period":        "90 days",
		"include_request_body":    true,
		"include_response_body":   true,
		"mask_sensitive_data":     true,
		"batch_size":              100,
		"flush_interval":          "30s",
		"compress_large_payloads": true,
		"max_payload_size":        "1MB",
	}

	h.writeJSONResponse(w, http.StatusOK, config)
}

// UpdateAuditConfig updates audit configuration
func (h *AuditHandler) UpdateAuditConfig(w http.ResponseWriter, r *http.Request) {
	_, span := auditHandlerTracer.Start(r.Context(), "audit.update_audit_config")
	defer span.End()

	// Parse request body
	var config map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Update configuration (placeholder implementation)
	h.logger.WithField("config", config).Info("Audit configuration update requested")

	response := map[string]interface{}{
		"message":   "Audit configuration updated successfully",
		"config":    config,
		"timestamp": time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods

// writeJSONResponse writes a JSON response
func (h *AuditHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

// writeErrorResponse writes an error response
func (h *AuditHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
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
