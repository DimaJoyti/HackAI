package handler

import (
	"context"
	"encoding/json"
	"fmt"
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

var monitoringTracer = otel.Tracer("hackai/handler/security_monitoring")

// SecurityMonitoringHandler handles security monitoring and metrics HTTP requests
type SecurityMonitoringHandler struct {
	logger       *logger.Logger
	securityRepo domain.LLMSecurityRepository
	policyRepo   domain.SecurityPolicyRepository
}

// MonitoringDashboard represents the main monitoring dashboard data
type MonitoringDashboard struct {
	Overview     *SecurityOverview       `json:"overview"`
	ThreatTrends *ThreatTrends           `json:"threat_trends"`
	TopThreats   []*ThreatSummary        `json:"top_threats"`
	RecentEvents []*SecurityEventSummary `json:"recent_events"`
	PolicyStats  []*PolicyStatsSummary   `json:"policy_stats"`
	SystemHealth *SystemHealthStatus     `json:"system_health"`
	Timestamp    time.Time               `json:"timestamp"`
}

// SecurityOverview represents high-level security metrics
type SecurityOverview struct {
	TotalRequests      int64   `json:"total_requests"`
	BlockedRequests    int64   `json:"blocked_requests"`
	BlockedPercentage  float64 `json:"blocked_percentage"`
	AverageThreatScore float64 `json:"average_threat_score"`
	TotalTokens        int64   `json:"total_tokens"`
	ActivePolicies     int     `json:"active_policies"`
	OpenViolations     int64   `json:"open_violations"`
	CriticalAlerts     int64   `json:"critical_alerts"`
}

// ThreatTrends represents threat trend data
type ThreatTrends struct {
	TimeRange      string                 `json:"time_range"`
	DataPoints     []ThreatTrendDataPoint `json:"data_points"`
	TotalThreats   int64                  `json:"total_threats"`
	TrendDirection string                 `json:"trend_direction"`
}

// ThreatTrendDataPoint represents a single data point in threat trends
type ThreatTrendDataPoint struct {
	Timestamp    time.Time `json:"timestamp"`
	ThreatCount  int64     `json:"threat_count"`
	ThreatScore  float64   `json:"threat_score"`
	BlockedCount int64     `json:"blocked_count"`
}

// ThreatSummary represents a summary of a specific threat type
type ThreatSummary struct {
	ThreatType   string    `json:"threat_type"`
	Count        int64     `json:"count"`
	AverageScore float64   `json:"average_score"`
	LastSeen     time.Time `json:"last_seen"`
	Severity     string    `json:"severity"`
	Description  string    `json:"description"`
}

// SecurityEventSummary represents a summary of a security event
type SecurityEventSummary struct {
	ID          uuid.UUID  `json:"id"`
	EventType   string     `json:"event_type"`
	Severity    string     `json:"severity"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	UserID      *uuid.UUID `json:"user_id"`
	CreatedAt   time.Time  `json:"created_at"`
	Resolved    bool       `json:"resolved"`
}

// PolicyStatsSummary represents policy statistics summary
type PolicyStatsSummary struct {
	PolicyID       uuid.UUID `json:"policy_id"`
	PolicyName     string    `json:"policy_name"`
	ExecutionCount int64     `json:"execution_count"`
	ViolationCount int64     `json:"violation_count"`
	BlockCount     int64     `json:"block_count"`
	AverageScore   float64   `json:"average_score"`
	LastExecution  time.Time `json:"last_execution"`
}

// SystemHealthStatus represents system health status
type SystemHealthStatus struct {
	Overall   string                         `json:"overall"`
	Services  map[string]ServiceHealthStatus `json:"services"`
	Timestamp time.Time                      `json:"timestamp"`
}

// ServiceHealthStatus represents individual service health
type ServiceHealthStatus struct {
	Status       string    `json:"status"`
	LastCheck    time.Time `json:"last_check"`
	ResponseTime int64     `json:"response_time_ms"`
	Error        string    `json:"error,omitempty"`
}

// NewSecurityMonitoringHandler creates a new security monitoring handler
func NewSecurityMonitoringHandler(
	logger *logger.Logger,
	securityRepo domain.LLMSecurityRepository,
	policyRepo domain.SecurityPolicyRepository,
) *SecurityMonitoringHandler {
	return &SecurityMonitoringHandler{
		logger:       logger,
		securityRepo: securityRepo,
		policyRepo:   policyRepo,
	}
}

// RegisterRoutes registers the security monitoring routes
func (h *SecurityMonitoringHandler) RegisterRoutes(router *mux.Router) {
	// Dashboard endpoints
	router.HandleFunc("/api/v1/monitoring/dashboard", h.GetDashboard).Methods("GET")
	router.HandleFunc("/api/v1/monitoring/overview", h.GetSecurityOverview).Methods("GET")

	// Metrics endpoints
	router.HandleFunc("/api/v1/monitoring/metrics/threats", h.GetThreatMetrics).Methods("GET")
	router.HandleFunc("/api/v1/monitoring/metrics/requests", h.GetRequestMetrics).Methods("GET")
	router.HandleFunc("/api/v1/monitoring/metrics/policies", h.GetPolicyMetrics).Methods("GET")

	// Trends and analytics
	router.HandleFunc("/api/v1/monitoring/trends/threats", h.GetThreatTrends).Methods("GET")
	router.HandleFunc("/api/v1/monitoring/trends/violations", h.GetViolationTrends).Methods("GET")
	router.HandleFunc("/api/v1/monitoring/trends/usage", h.GetUsageTrends).Methods("GET")

	// Real-time endpoints
	router.HandleFunc("/api/v1/monitoring/events/recent", h.GetRecentEvents).Methods("GET")
	router.HandleFunc("/api/v1/monitoring/alerts/active", h.GetActiveAlerts).Methods("GET")

	// Health and status
	router.HandleFunc("/api/v1/monitoring/health", h.GetSystemHealth).Methods("GET")
	router.HandleFunc("/api/v1/monitoring/status", h.GetSystemStatus).Methods("GET")

	// Export endpoints
	router.HandleFunc("/api/v1/monitoring/export/metrics", h.ExportMetrics).Methods("GET")
	router.HandleFunc("/api/v1/monitoring/export/reports", h.ExportReports).Methods("GET")
}

// GetDashboard returns the main monitoring dashboard data
func (h *SecurityMonitoringHandler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoringTracer.Start(r.Context(), "security_monitoring.get_dashboard")
	defer span.End()

	// Parse time range parameter
	timeRange := 24 * time.Hour // Default to 24 hours
	if rangeStr := r.URL.Query().Get("range"); rangeStr != "" {
		if parsed, err := time.ParseDuration(rangeStr); err == nil {
			timeRange = parsed
		}
	}

	// Get overview data
	overview, err := h.getSecurityOverview(ctx, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security overview")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get security overview", err)
		return
	}

	// Get threat trends
	threatTrends, err := h.getThreatTrends(ctx, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get threat trends")
		// Don't fail the entire request, just log the error
		threatTrends = &ThreatTrends{
			TimeRange:    timeRange.String(),
			DataPoints:   []ThreatTrendDataPoint{},
			TotalThreats: 0,
		}
	}

	// Get top threats
	topThreats, err := h.getTopThreats(ctx, 10, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get top threats")
		topThreats = []*ThreatSummary{}
	}

	// Get recent events
	recentEvents, err := h.getRecentEvents(ctx, 20)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get recent events")
		recentEvents = []*SecurityEventSummary{}
	}

	// Get policy stats
	policyStats, err := h.getPolicyStats(ctx, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get policy stats")
		policyStats = []*PolicyStatsSummary{}
	}

	// Get system health
	systemHealth, err := h.getSystemHealth(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get system health")
		systemHealth = &SystemHealthStatus{
			Overall:   "unknown",
			Services:  make(map[string]ServiceHealthStatus),
			Timestamp: time.Now(),
		}
	}

	// Build dashboard response
	dashboard := &MonitoringDashboard{
		Overview:     overview,
		ThreatTrends: threatTrends,
		TopThreats:   topThreats,
		RecentEvents: recentEvents,
		PolicyStats:  policyStats,
		SystemHealth: systemHealth,
		Timestamp:    time.Now(),
	}

	span.SetAttributes(
		attribute.String("time_range", timeRange.String()),
		attribute.Int64("total_requests", overview.TotalRequests),
		attribute.Int64("blocked_requests", overview.BlockedRequests),
		attribute.Float64("average_threat_score", overview.AverageThreatScore),
	)

	h.writeJSONResponse(w, http.StatusOK, dashboard)
}

// GetSecurityOverview returns security overview metrics
func (h *SecurityMonitoringHandler) GetSecurityOverview(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoringTracer.Start(r.Context(), "security_monitoring.get_security_overview")
	defer span.End()

	// Parse time range parameter
	timeRange := 24 * time.Hour // Default to 24 hours
	if rangeStr := r.URL.Query().Get("range"); rangeStr != "" {
		if parsed, err := time.ParseDuration(rangeStr); err == nil {
			timeRange = parsed
		}
	}

	// Get overview data
	overview, err := h.getSecurityOverview(ctx, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security overview")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get security overview", err)
		return
	}

	span.SetAttributes(
		attribute.String("time_range", timeRange.String()),
		attribute.Int64("total_requests", overview.TotalRequests),
		attribute.Int64("blocked_requests", overview.BlockedRequests),
	)

	h.writeJSONResponse(w, http.StatusOK, overview)
}

// GetThreatMetrics returns threat-related metrics
func (h *SecurityMonitoringHandler) GetThreatMetrics(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoringTracer.Start(r.Context(), "security_monitoring.get_threat_metrics")
	defer span.End()

	// Parse parameters
	timeRange := 24 * time.Hour
	if rangeStr := r.URL.Query().Get("range"); rangeStr != "" {
		if parsed, err := time.ParseDuration(rangeStr); err == nil {
			timeRange = parsed
		}
	}

	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	// Get threat metrics
	topThreats, err := h.getTopThreats(ctx, limit, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get threat metrics")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get threat metrics", err)
		return
	}

	response := map[string]interface{}{
		"threats":    topThreats,
		"count":      len(topThreats),
		"time_range": timeRange.String(),
		"timestamp":  time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods for data aggregation

// getSecurityOverview aggregates security overview metrics
func (h *SecurityMonitoringHandler) getSecurityOverview(ctx context.Context, timeRange time.Duration) (*SecurityOverview, error) {
	startTime := time.Now().Add(-timeRange)
	endTime := time.Now()

	// Get request log stats
	filter := domain.RequestLogFilter{
		StartTime: &startTime,
		EndTime:   &endTime,
	}

	stats, err := h.securityRepo.GetRequestLogStats(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get request log stats: %w", err)
	}

	// Calculate blocked percentage
	var blockedPercentage float64
	if stats.TotalRequests > 0 {
		blockedPercentage = float64(stats.BlockedRequests) / float64(stats.TotalRequests) * 100
	}

	// Get active policies count (simplified)
	activePolicies, err := h.policyRepo.ListPolicies(ctx, domain.PolicyFilter{
		Enabled: boolPtr(true),
		Status:  stringPtr(domain.StatusActive),
		Limit:   1000,
	})
	if err != nil {
		h.logger.WithError(err).Error("Failed to get active policies count")
	}

	// Get security events stats
	eventFilter := domain.SecurityEventFilter{
		StartTime: &startTime,
		EndTime:   &endTime,
	}
	eventStats, err := h.securityRepo.GetSecurityEventStats(ctx, eventFilter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security event stats")
		eventStats = &domain.SecurityEventStats{}
	}

	return &SecurityOverview{
		TotalRequests:      stats.TotalRequests,
		BlockedRequests:    stats.BlockedRequests,
		BlockedPercentage:  blockedPercentage,
		AverageThreatScore: stats.AverageThreatScore,
		TotalTokens:        stats.TotalTokens,
		ActivePolicies:     len(activePolicies),
		OpenViolations:     eventStats.TotalEvents - eventStats.ResolvedEvents,
		CriticalAlerts:     eventStats.CriticalEvents,
	}, nil
}

// getThreatTrends aggregates threat trend data
func (h *SecurityMonitoringHandler) getThreatTrends(ctx context.Context, timeRange time.Duration) (*ThreatTrends, error) {
	// Get threat trends from repository
	trends, err := h.securityRepo.GetThreatTrends(ctx, timeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get threat trends: %w", err)
	}

	// Convert to response format
	dataPoints := make([]ThreatTrendDataPoint, len(trends.DataPoints))
	for i, dp := range trends.DataPoints {
		dataPoints[i] = ThreatTrendDataPoint{
			Timestamp:    dp.Timestamp,
			ThreatCount:  dp.ThreatCount,
			ThreatScore:  dp.ThreatScore,
			BlockedCount: 0, // Would need additional data
		}
	}

	return &ThreatTrends{
		TimeRange:      timeRange.String(),
		DataPoints:     dataPoints,
		TotalThreats:   int64(len(trends.TopThreats)),
		TrendDirection: "stable", // Would calculate based on data
	}, nil
}

// getTopThreats gets top threats summary
func (h *SecurityMonitoringHandler) getTopThreats(ctx context.Context, limit int, timeRange time.Duration) ([]*ThreatSummary, error) {
	// Get top threats from repository
	threats, err := h.securityRepo.GetTopThreats(ctx, limit, timeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get top threats: %w", err)
	}

	// Convert to response format
	summaries := make([]*ThreatSummary, len(threats))
	for i, threat := range threats {
		summaries[i] = &ThreatSummary{
			ThreatType:   threat.ThreatType,
			Count:        threat.Count,
			AverageScore: threat.AverageScore,
			LastSeen:     threat.LastSeen,
			Severity:     h.determineSeverity(threat.AverageScore),
			Description:  fmt.Sprintf("%s threat detected %d times", threat.ThreatType, threat.Count),
		}
	}

	return summaries, nil
}

// getRecentEvents gets recent security events
func (h *SecurityMonitoringHandler) getRecentEvents(ctx context.Context, limit int) ([]*SecurityEventSummary, error) {
	// Get recent security events
	filter := domain.SecurityEventFilter{
		Limit:     limit,
		OrderBy:   "created_at",
		OrderDesc: true,
	}

	events, err := h.securityRepo.ListSecurityEvents(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent events: %w", err)
	}

	// Convert to response format
	summaries := make([]*SecurityEventSummary, len(events))
	for i, event := range events {
		summaries[i] = &SecurityEventSummary{
			ID:          event.ID,
			EventType:   event.Type,
			Severity:    string(event.Severity),
			Title:       event.Title,
			Description: event.Description,
			UserID:      event.UserID,
			CreatedAt:   event.CreatedAt,
			Resolved:    event.Status == domain.EventStatusResolved || event.ResolvedAt != nil,
		}
	}

	return summaries, nil
}

// getPolicyStats gets policy statistics
func (h *SecurityMonitoringHandler) getPolicyStats(ctx context.Context, timeRange time.Duration) ([]*PolicyStatsSummary, error) {
	// Get active policies
	policies, err := h.policyRepo.ListPolicies(ctx, domain.PolicyFilter{
		Enabled: boolPtr(true),
		Limit:   100,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policies: %w", err)
	}

	// Get stats for each policy
	summaries := make([]*PolicyStatsSummary, 0, len(policies))
	for _, policy := range policies {
		stats, err := h.policyRepo.GetPolicyStats(ctx, policy.ID, timeRange)
		if err != nil {
			h.logger.WithError(err).WithField("policy_id", policy.ID).Error("Failed to get policy stats")
			continue
		}

		summaries = append(summaries, &PolicyStatsSummary{
			PolicyID:       policy.ID,
			PolicyName:     policy.Name,
			ExecutionCount: stats.ExecutionCount,
			ViolationCount: stats.ViolationCount,
			BlockCount:     stats.BlockCount,
			AverageScore:   stats.AverageScore,
			LastExecution:  stats.LastExecution,
		})
	}

	return summaries, nil
}

// getSystemHealth checks system health
func (h *SecurityMonitoringHandler) getSystemHealth(ctx context.Context) (*SystemHealthStatus, error) {
	services := make(map[string]ServiceHealthStatus)
	overall := "healthy"

	// Check database health
	start := time.Now()
	_, err := h.securityRepo.GetRequestLogStats(ctx, domain.RequestLogFilter{Limit: 1})
	duration := time.Since(start)

	dbStatus := "healthy"
	dbError := ""
	if err != nil {
		dbStatus = "unhealthy"
		dbError = err.Error()
		overall = "unhealthy"
	}

	services["database"] = ServiceHealthStatus{
		Status:       dbStatus,
		LastCheck:    time.Now(),
		ResponseTime: duration.Milliseconds(),
		Error:        dbError,
	}

	// Check policy repository health
	start = time.Now()
	_, err = h.policyRepo.ListPolicies(ctx, domain.PolicyFilter{Limit: 1})
	duration = time.Since(start)

	policyStatus := "healthy"
	policyError := ""
	if err != nil {
		policyStatus = "unhealthy"
		policyError = err.Error()
		overall = "unhealthy"
	}

	services["policy_repository"] = ServiceHealthStatus{
		Status:       policyStatus,
		LastCheck:    time.Now(),
		ResponseTime: duration.Milliseconds(),
		Error:        policyError,
	}

	return &SystemHealthStatus{
		Overall:   overall,
		Services:  services,
		Timestamp: time.Now(),
	}, nil
}

// Helper utility functions

func (h *SecurityMonitoringHandler) determineSeverity(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.5:
		return "medium"
	case score >= 0.3:
		return "low"
	default:
		return "info"
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func stringPtr(s string) *string {
	return &s
}

// writeJSONResponse writes a JSON response
func (h *SecurityMonitoringHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

// writeErrorResponse writes an error response
func (h *SecurityMonitoringHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
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

// Placeholder methods for remaining endpoints (to be implemented)

func (h *SecurityMonitoringHandler) GetRequestMetrics(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoringTracer.Start(r.Context(), "security_monitoring.get_request_metrics")
	defer span.End()

	// Parse parameters
	timeRange := 24 * time.Hour
	if rangeStr := r.URL.Query().Get("range"); rangeStr != "" {
		if parsed, err := time.ParseDuration(rangeStr); err == nil {
			timeRange = parsed
		}
	}

	startTime := time.Now().Add(-timeRange)
	endTime := time.Now()

	// Get request metrics
	filter := domain.RequestLogFilter{
		StartTime: &startTime,
		EndTime:   &endTime,
	}

	stats, err := h.securityRepo.GetRequestLogStats(ctx, filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get request metrics")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get request metrics", err)
		return
	}

	// Calculate additional metrics
	var successRate float64
	if stats.TotalRequests > 0 {
		successRate = float64(stats.TotalRequests-stats.BlockedRequests) / float64(stats.TotalRequests) * 100
	}

	response := map[string]interface{}{
		"total_requests":       stats.TotalRequests,
		"blocked_requests":     stats.BlockedRequests,
		"success_rate":         successRate,
		"average_threat_score": stats.AverageThreatScore,
		"total_tokens":         stats.TotalTokens,
		"average_duration":     stats.AverageDuration,
		"time_range":           timeRange.String(),
		"timestamp":            time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

func (h *SecurityMonitoringHandler) GetPolicyMetrics(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoringTracer.Start(r.Context(), "security_monitoring.get_policy_metrics")
	defer span.End()

	// Parse parameters
	timeRange := 24 * time.Hour
	if rangeStr := r.URL.Query().Get("range"); rangeStr != "" {
		if parsed, err := time.ParseDuration(rangeStr); err == nil {
			timeRange = parsed
		}
	}

	// Get policy statistics
	policyStats, err := h.getPolicyStats(ctx, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get policy metrics")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get policy metrics", err)
		return
	}

	// Calculate aggregate metrics
	var totalExecutions, totalViolations, totalBlocks int64
	var avgScore float64
	for _, stat := range policyStats {
		totalExecutions += stat.ExecutionCount
		totalViolations += stat.ViolationCount
		totalBlocks += stat.BlockCount
		avgScore += stat.AverageScore
	}

	if len(policyStats) > 0 {
		avgScore = avgScore / float64(len(policyStats))
	}

	response := map[string]interface{}{
		"total_policies":   len(policyStats),
		"total_executions": totalExecutions,
		"total_violations": totalViolations,
		"total_blocks":     totalBlocks,
		"average_score":    avgScore,
		"policy_details":   policyStats,
		"time_range":       timeRange.String(),
		"timestamp":        time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

func (h *SecurityMonitoringHandler) GetThreatTrends(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Threat trends not yet implemented", nil)
}

func (h *SecurityMonitoringHandler) GetViolationTrends(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Violation trends not yet implemented", nil)
}

func (h *SecurityMonitoringHandler) GetUsageTrends(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Usage trends not yet implemented", nil)
}

func (h *SecurityMonitoringHandler) GetRecentEvents(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoringTracer.Start(r.Context(), "security_monitoring.get_recent_events")
	defer span.End()

	// Parse parameters
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	// Get recent events
	recentEvents, err := h.getRecentEvents(ctx, limit)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get recent events")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get recent events", err)
		return
	}

	response := map[string]interface{}{
		"events":    recentEvents,
		"count":     len(recentEvents),
		"limit":     limit,
		"timestamp": time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

func (h *SecurityMonitoringHandler) GetActiveAlerts(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "Active alerts not yet implemented", nil)
}

func (h *SecurityMonitoringHandler) GetSystemHealth(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoringTracer.Start(r.Context(), "security_monitoring.get_system_health")
	defer span.End()

	// Get system health
	systemHealth, err := h.getSystemHealth(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get system health")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get system health", err)
		return
	}

	status := http.StatusOK
	if systemHealth.Overall != "healthy" {
		status = http.StatusServiceUnavailable
	}

	h.writeJSONResponse(w, status, systemHealth)
}

func (h *SecurityMonitoringHandler) GetSystemStatus(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoringTracer.Start(r.Context(), "security_monitoring.get_system_status")
	defer span.End()

	// Get basic system status information
	startTime := time.Now().Add(-24 * time.Hour)
	endTime := time.Now()

	// Get request stats for the last 24 hours
	filter := domain.RequestLogFilter{
		StartTime: &startTime,
		EndTime:   &endTime,
	}

	stats, err := h.securityRepo.GetRequestLogStats(ctx, filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get request stats for system status")
		stats = &domain.RequestLogStats{} // Use empty stats if error
	}

	// Get active policies count
	activePolicies, err := h.policyRepo.ListPolicies(ctx, domain.PolicyFilter{
		Enabled: boolPtr(true),
		Status:  stringPtr(domain.StatusActive),
		Limit:   1000,
	})
	if err != nil {
		h.logger.WithError(err).Error("Failed to get active policies for system status")
		activePolicies = []*domain.SecurityPolicy{}
	}

	// Calculate uptime (simplified - would be actual uptime in production)
	uptime := 24 * time.Hour

	status := map[string]interface{}{
		"status":           "operational",
		"uptime":           uptime.String(),
		"active_policies":  len(activePolicies),
		"requests_24h":     stats.TotalRequests,
		"blocked_24h":      stats.BlockedRequests,
		"avg_threat_score": stats.AverageThreatScore,
		"timestamp":        time.Now(),
		"version":          "1.0.0",
	}

	h.writeJSONResponse(w, http.StatusOK, status)
}

func (h *SecurityMonitoringHandler) ExportMetrics(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoringTracer.Start(r.Context(), "security_monitoring.export_metrics")
	defer span.End()

	// Parse parameters
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	timeRange := 24 * time.Hour
	if rangeStr := r.URL.Query().Get("range"); rangeStr != "" {
		if parsed, err := time.ParseDuration(rangeStr); err == nil {
			timeRange = parsed
		}
	}

	// Get comprehensive metrics
	overview, err := h.getSecurityOverview(ctx, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security overview for export")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to export metrics", err)
		return
	}

	topThreats, err := h.getTopThreats(ctx, 20, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get top threats for export")
		topThreats = []*ThreatSummary{}
	}

	policyStats, err := h.getPolicyStats(ctx, timeRange)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get policy stats for export")
		policyStats = []*PolicyStatsSummary{}
	}

	exportData := map[string]interface{}{
		"export_timestamp": time.Now(),
		"time_range":       timeRange.String(),
		"overview":         overview,
		"top_threats":      topThreats,
		"policy_stats":     policyStats,
		"metadata": map[string]interface{}{
			"format":  format,
			"version": "1.0.0",
		},
	}

	// Set appropriate headers based on format
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=security_metrics.csv")
		// For CSV, we'd need to implement CSV marshaling
		h.writeErrorResponse(w, http.StatusNotImplemented, "CSV export not yet implemented", nil)
		return
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=security_metrics.json")
	}

	h.writeJSONResponse(w, http.StatusOK, exportData)
}

func (h *SecurityMonitoringHandler) ExportReports(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoringTracer.Start(r.Context(), "security_monitoring.export_reports")
	defer span.End()

	// Parse parameters
	reportType := r.URL.Query().Get("type")
	if reportType == "" {
		reportType = "security_summary"
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	timeRange := 7 * 24 * time.Hour // Default to 7 days for reports
	if rangeStr := r.URL.Query().Get("range"); rangeStr != "" {
		if parsed, err := time.ParseDuration(rangeStr); err == nil {
			timeRange = parsed
		}
	}

	var reportData map[string]interface{}

	switch reportType {
	case "security_summary":
		reportData = h.generateSecuritySummaryReport(ctx, timeRange)
	case "threat_analysis":
		reportData = h.generateThreatAnalysisReport(ctx, timeRange)
	case "policy_compliance":
		reportData = h.generatePolicyComplianceReport(ctx, timeRange)
	default:
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid report type", nil)
		return
	}

	// Set appropriate headers
	filename := fmt.Sprintf("%s_report_%s.%s", reportType, time.Now().Format("2006-01-02"), format)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	switch format {
	case "pdf":
		w.Header().Set("Content-Type", "application/pdf")
		h.writeErrorResponse(w, http.StatusNotImplemented, "PDF export not yet implemented", nil)
		return
	default:
		w.Header().Set("Content-Type", "application/json")
	}

	h.writeJSONResponse(w, http.StatusOK, reportData)
}

// generateSecuritySummaryReport generates a comprehensive security summary report
func (h *SecurityMonitoringHandler) generateSecuritySummaryReport(ctx context.Context, timeRange time.Duration) map[string]interface{} {
	overview, _ := h.getSecurityOverview(ctx, timeRange)
	topThreats, _ := h.getTopThreats(ctx, 10, timeRange)
	recentEvents, _ := h.getRecentEvents(ctx, 50)

	return map[string]interface{}{
		"report_type":  "security_summary",
		"generated_at": time.Now(),
		"time_range":   timeRange.String(),
		"executive_summary": map[string]interface{}{
			"total_requests":   overview.TotalRequests,
			"blocked_requests": overview.BlockedRequests,
			"threat_level":     h.determineThreatLevel(overview.AverageThreatScore),
			"critical_alerts":  overview.CriticalAlerts,
		},
		"overview":      overview,
		"top_threats":   topThreats,
		"recent_events": recentEvents,
	}
}

// generateThreatAnalysisReport generates a detailed threat analysis report
func (h *SecurityMonitoringHandler) generateThreatAnalysisReport(ctx context.Context, timeRange time.Duration) map[string]interface{} {
	topThreats, _ := h.getTopThreats(ctx, 20, timeRange)
	threatTrends, _ := h.getThreatTrends(ctx, timeRange)

	return map[string]interface{}{
		"report_type":  "threat_analysis",
		"generated_at": time.Now(),
		"time_range":   timeRange.String(),
		"threat_summary": map[string]interface{}{
			"total_threats":     len(topThreats),
			"high_risk_threats": h.countHighRiskThreats(topThreats),
		},
		"top_threats":   topThreats,
		"threat_trends": threatTrends,
	}
}

// generatePolicyComplianceReport generates a policy compliance report
func (h *SecurityMonitoringHandler) generatePolicyComplianceReport(ctx context.Context, timeRange time.Duration) map[string]interface{} {
	policyStats, _ := h.getPolicyStats(ctx, timeRange)

	var totalViolations, totalBlocks int64
	for _, stat := range policyStats {
		totalViolations += stat.ViolationCount
		totalBlocks += stat.BlockCount
	}

	return map[string]interface{}{
		"report_type":  "policy_compliance",
		"generated_at": time.Now(),
		"time_range":   timeRange.String(),
		"compliance_summary": map[string]interface{}{
			"total_policies":   len(policyStats),
			"total_violations": totalViolations,
			"total_blocks":     totalBlocks,
		},
		"policy_details": policyStats,
	}
}

// Helper methods for report generation
func (h *SecurityMonitoringHandler) determineThreatLevel(score float64) string {
	switch {
	case score >= 0.8:
		return "critical"
	case score >= 0.6:
		return "high"
	case score >= 0.4:
		return "medium"
	case score >= 0.2:
		return "low"
	default:
		return "minimal"
	}
}

func (h *SecurityMonitoringHandler) countHighRiskThreats(threats []*ThreatSummary) int {
	count := 0
	for _, threat := range threats {
		if threat.Severity == "critical" || threat.Severity == "high" {
			count++
		}
	}
	return count
}
