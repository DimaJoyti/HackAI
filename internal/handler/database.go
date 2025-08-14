package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/internal/usecase"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// DatabaseHandler handles database management HTTP requests
type DatabaseHandler struct {
	dbManager *usecase.DatabaseManagerUseCase
	logger    *logger.Logger
}

// NewDatabaseHandler creates a new database handler
func NewDatabaseHandler(dbManager *usecase.DatabaseManagerUseCase, log *logger.Logger) *DatabaseHandler {
	return &DatabaseHandler{
		dbManager: dbManager,
		logger:    log,
	}
}

// GetHealth handles GET /api/v1/database/health
func (h *DatabaseHandler) GetHealth(w http.ResponseWriter, r *http.Request) {
	health, err := h.dbManager.GetDatabaseHealth(r.Context())
	if err != nil {
		h.writeErrorResponse(w, http.StatusServiceUnavailable, "Database health check failed", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, health)
}

// CreateBackup handles POST /api/v1/database/backups
func (h *DatabaseHandler) CreateBackup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type string `json:"type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Type == "" {
		req.Type = "full"
	}

	// Validate backup type
	validTypes := []string{"full", "incremental", "differential"}
	isValid := false
	for _, validType := range validTypes {
		if req.Type == validType {
			isValid = true
			break
		}
	}

	if !isValid {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid backup type", nil)
		return
	}

	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	backup, err := h.dbManager.CreateBackup(r.Context(), req.Type, userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create backup")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create backup", err)
		return
	}

	h.writeJSONResponse(w, http.StatusCreated, backup)
}

// ListBackups handles GET /api/v1/database/backups
func (h *DatabaseHandler) ListBackups(w http.ResponseWriter, r *http.Request) {
	limit := h.parseIntQuery(r, "limit", 20)
	offset := h.parseIntQuery(r, "offset", 0)

	backups, err := h.dbManager.ListBackups(r.Context(), limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list backups")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list backups", err)
		return
	}

	response := map[string]interface{}{
		"backups": backups,
		"total":   len(backups),
		"limit":   limit,
		"offset":  offset,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetBackup handles GET /api/v1/database/backups/{id}
func (h *DatabaseHandler) GetBackup(w http.ResponseWriter, r *http.Request) {
	backupID, err := h.extractUUIDFromPath(r.URL.Path, "/api/v1/database/backups/")
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid backup ID", err)
		return
	}

	backup, err := h.dbManager.GetBackup(r.Context(), backupID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get backup")
		h.writeErrorResponse(w, http.StatusNotFound, "Backup not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, backup)
}

// PerformMaintenance handles POST /api/v1/database/maintenance
func (h *DatabaseHandler) PerformMaintenance(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	if err := h.dbManager.PerformMaintenance(r.Context(), userID); err != nil {
		h.logger.WithError(err).Error("Failed to perform maintenance")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to perform maintenance", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Database maintenance completed successfully",
	})
}

// ArchiveData handles POST /api/v1/database/archive
func (h *DatabaseHandler) ArchiveData(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	if err := h.dbManager.ArchiveOldData(r.Context(), userID); err != nil {
		h.logger.WithError(err).Error("Failed to archive data")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to archive data", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{
		"message": "Data archival completed successfully",
	})
}

// CreateRetentionPolicy handles POST /api/v1/database/retention-policies
func (h *DatabaseHandler) CreateRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	var policy domain.DataRetentionPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if policy.Name == "" || policy.DataType == "" || policy.RetentionDays <= 0 {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing required fields", nil)
		return
	}

	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		h.writeErrorResponse(w, http.StatusUnauthorized, "User not authenticated", nil)
		return
	}

	if err := h.dbManager.CreateRetentionPolicy(r.Context(), userID, &policy); err != nil {
		h.logger.WithError(err).Error("Failed to create retention policy")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create retention policy", err)
		return
	}

	h.writeJSONResponse(w, http.StatusCreated, policy)
}

// ListRetentionPolicies handles GET /api/v1/database/retention-policies
func (h *DatabaseHandler) ListRetentionPolicies(w http.ResponseWriter, r *http.Request) {
	limit := h.parseIntQuery(r, "limit", 20)
	offset := h.parseIntQuery(r, "offset", 0)

	policies, err := h.dbManager.ListRetentionPolicies(r.Context(), limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list retention policies")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list retention policies", err)
		return
	}

	response := map[string]interface{}{
		"policies": policies,
		"total":    len(policies),
		"limit":    limit,
		"offset":   offset,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetAuditLogs handles GET /api/v1/database/audit-logs
func (h *DatabaseHandler) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit := h.parseIntQuery(r, "limit", 50)
	offset := h.parseIntQuery(r, "offset", 0)

	// Parse filters
	filters := make(map[string]interface{})

	if userID := r.URL.Query().Get("user_id"); userID != "" {
		if id, err := uuid.Parse(userID); err == nil {
			filters["user_id"] = id
		}
	}

	if action := r.URL.Query().Get("action"); action != "" {
		filters["action"] = action
	}

	if resource := r.URL.Query().Get("resource"); resource != "" {
		filters["resource"] = resource
	}

	if status := r.URL.Query().Get("status"); status != "" {
		filters["status"] = status
	}

	if riskLevel := r.URL.Query().Get("risk_level"); riskLevel != "" {
		filters["risk_level"] = riskLevel
	}

	if fromDate := r.URL.Query().Get("from_date"); fromDate != "" {
		if date, err := time.Parse(time.RFC3339, fromDate); err == nil {
			filters["from_date"] = date
		}
	}

	if toDate := r.URL.Query().Get("to_date"); toDate != "" {
		if date, err := time.Parse(time.RFC3339, toDate); err == nil {
			filters["to_date"] = date
		}
	}

	// Check if it's a search request
	query := r.URL.Query().Get("q")
	var logs []*domain.AuditLog
	var err error

	if query != "" {
		logs, err = h.dbManager.SearchAuditLogs(r.Context(), query, filters, limit, offset)
	} else {
		logs, err = h.dbManager.GetAuditLogs(r.Context(), filters, limit, offset)
	}

	if err != nil {
		h.logger.WithError(err).Error("Failed to get audit logs")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get audit logs", err)
		return
	}

	response := map[string]interface{}{
		"logs":    logs,
		"total":   len(logs),
		"limit":   limit,
		"offset":  offset,
		"query":   query,
		"filters": filters,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetSecurityEvents handles GET /api/v1/database/security-events
func (h *DatabaseHandler) GetSecurityEvents(w http.ResponseWriter, r *http.Request) {
	limit := h.parseIntQuery(r, "limit", 50)
	offset := h.parseIntQuery(r, "offset", 0)

	// Parse filters
	filters := make(map[string]interface{})

	if eventType := r.URL.Query().Get("type"); eventType != "" {
		filters["type"] = eventType
	}

	if category := r.URL.Query().Get("category"); category != "" {
		filters["category"] = category
	}

	if severity := r.URL.Query().Get("severity"); severity != "" {
		filters["severity"] = severity
	}

	if status := r.URL.Query().Get("status"); status != "" {
		filters["status"] = status
	}

	if sourceIP := r.URL.Query().Get("source_ip"); sourceIP != "" {
		filters["source_ip"] = sourceIP
	}

	events, err := h.dbManager.GetSecurityEvents(r.Context(), filters, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security events")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get security events", err)
		return
	}

	response := map[string]interface{}{
		"events":  events,
		"total":   len(events),
		"limit":   limit,
		"offset":  offset,
		"filters": filters,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetSystemMetrics handles GET /api/v1/database/metrics
func (h *DatabaseHandler) GetSystemMetrics(w http.ResponseWriter, r *http.Request) {
	// Parse time range
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")

	var from, to time.Time
	var err error

	if fromStr != "" {
		from, err = time.Parse(time.RFC3339, fromStr)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid from date format", err)
			return
		}
	} else {
		from = time.Now().Add(-24 * time.Hour) // Default to last 24 hours
	}

	if toStr != "" {
		to, err = time.Parse(time.RFC3339, toStr)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid to date format", err)
			return
		}
	} else {
		to = time.Now()
	}

	// Parse filters
	filters := make(map[string]interface{})

	if metricType := r.URL.Query().Get("metric_type"); metricType != "" {
		filters["metric_type"] = metricType
	}

	if metricName := r.URL.Query().Get("metric_name"); metricName != "" {
		filters["metric_name"] = metricName
	}

	if service := r.URL.Query().Get("service"); service != "" {
		filters["service"] = service
	}

	metrics, err := h.dbManager.GetSystemMetrics(r.Context(), filters, from, to)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get system metrics")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get system metrics", err)
		return
	}

	response := map[string]interface{}{
		"metrics": metrics,
		"total":   len(metrics),
		"from":    from,
		"to":      to,
		"filters": filters,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods (same as in scanner.go)
func (h *DatabaseHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

func (h *DatabaseHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	response := map[string]interface{}{
		"error":  message,
		"status": statusCode,
	}

	if err != nil {
		h.logger.WithError(err).Error(message)
		response["details"] = err.Error()
	}

	h.writeJSONResponse(w, statusCode, response)
}

func (h *DatabaseHandler) parseIntQuery(r *http.Request, key string, defaultValue int) int {
	value := r.URL.Query().Get(key)
	if value == "" {
		return defaultValue
	}

	if intValue, err := strconv.Atoi(value); err == nil {
		return intValue
	}

	return defaultValue
}

func (h *DatabaseHandler) extractUUIDFromPath(path, prefix string) (uuid.UUID, error) {
	if len(path) <= len(prefix) {
		return uuid.Nil, fmt.Errorf("invalid path format")
	}

	idStr := path[len(prefix):]
	// Handle paths like /api/v1/database/backups/{id}/status
	if slashIndex := strings.Index(idStr, "/"); slashIndex != -1 {
		idStr = idStr[:slashIndex]
	}

	return uuid.Parse(idStr)
}
