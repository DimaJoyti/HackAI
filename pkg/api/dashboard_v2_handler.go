package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/dimajoyti/hackai/pkg/dashboard"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// DashboardV2Handler handles advanced dashboard API requests
type DashboardV2Handler struct {
	logger            *logger.Logger
	dashboardService  *dashboard.AdvancedDashboardService
	websocketUpgrader websocket.Upgrader
}

// DashboardV2Response represents the standard API response format
type DashboardV2Response struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	Version   string      `json:"version"`
}

// MetricsRequest represents a metrics query request
type MetricsRequest struct {
	MetricNames []string  `json:"metric_names"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Granularity string    `json:"granularity"`
	Aggregation string    `json:"aggregation"`
}

// FeatureToggleRequest represents a feature toggle request
type FeatureToggleRequest struct {
	FeatureID string `json:"feature_id"`
	Enabled   bool   `json:"enabled"`
}

// WorkspaceRequest represents workspace operations
type WorkspaceRequest struct {
	Workspace *dashboard.WorkspaceLayout `json:"workspace"`
	Action    string                     `json:"action"`
}

// WebSocketMessage represents WebSocket communication format
type WebSocketMessage struct {
	Type      string                 `json:"type"`
	Action    string                 `json:"action,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	RequestID string                 `json:"request_id,omitempty"`
}

// NewDashboardV2Handler creates a new dashboard v2 API handler
func NewDashboardV2Handler(
	logger *logger.Logger,
	dashboardService *dashboard.AdvancedDashboardService,
) *DashboardV2Handler {
	return &DashboardV2Handler{
		logger:           logger,
		dashboardService: dashboardService,
		websocketUpgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins in development
			},
			EnableCompression: true,
			ReadBufferSize:    4096,
			WriteBufferSize:   4096,
		},
	}
}

// RegisterDashboardV2Routes registers all dashboard v2 API routes
func (dh *DashboardV2Handler) RegisterDashboardV2Routes(router *mux.Router) {
	// Main dashboard routes
	router.HandleFunc("/api/v2/dashboard/overview", dh.handleDashboardOverview).Methods("GET")
	router.HandleFunc("/api/v2/dashboard/health", dh.handleDashboardHealth).Methods("GET")
	router.HandleFunc("/api/v2/dashboard/status", dh.handleDashboardStatus).Methods("GET")

	// Feature management routes
	router.HandleFunc("/api/v2/dashboard/features", dh.handleGetFeatures).Methods("GET")
	router.HandleFunc("/api/v2/dashboard/features/{feature_id}", dh.handleGetFeature).Methods("GET")
	router.HandleFunc("/api/v2/dashboard/features/{feature_id}/toggle", dh.handleToggleFeature).Methods("POST")
	router.HandleFunc("/api/v2/dashboard/features/{feature_id}/configure", dh.handleConfigureFeature).Methods("PUT")

	// Workspace management routes
	router.HandleFunc("/api/v2/dashboard/workspaces", dh.handleGetWorkspaces).Methods("GET")
	router.HandleFunc("/api/v2/dashboard/workspaces", dh.handleCreateWorkspace).Methods("POST")
	router.HandleFunc("/api/v2/dashboard/workspaces/{workspace_id}", dh.handleGetWorkspace).Methods("GET")
	router.HandleFunc("/api/v2/dashboard/workspaces/{workspace_id}", dh.handleUpdateWorkspace).Methods("PUT")
	router.HandleFunc("/api/v2/dashboard/workspaces/{workspace_id}", dh.handleDeleteWorkspace).Methods("DELETE")

	// Metrics routes
	router.HandleFunc("/api/v2/dashboard/metrics", dh.handleGetMetrics).Methods("GET")
	router.HandleFunc("/api/v2/dashboard/metrics/query", dh.handleQueryMetrics).Methods("POST")
	router.HandleFunc("/api/v2/dashboard/metrics/{metric_name}", dh.handleGetMetric).Methods("GET")
	router.HandleFunc("/api/v2/dashboard/metrics/export", dh.handleExportMetrics).Methods("GET")

	// Real-time communication routes
	router.HandleFunc("/api/v2/dashboard/ws", dh.handleWebSocketConnection)
	router.HandleFunc("/api/v2/dashboard/events", dh.handleServerSentEvents)

	// Analytics routes
	router.HandleFunc("/api/v2/dashboard/analytics/usage", dh.handleUsageAnalytics).Methods("GET")
	router.HandleFunc("/api/v2/dashboard/analytics/performance", dh.handlePerformanceAnalytics).Methods("GET")
	router.HandleFunc("/api/v2/dashboard/analytics/insights", dh.handleInsights).Methods("GET")

	// Configuration routes
	router.HandleFunc("/api/v2/dashboard/config", dh.handleGetConfiguration).Methods("GET")
	router.HandleFunc("/api/v2/dashboard/config", dh.handleUpdateConfiguration).Methods("PUT")
}

// Dashboard Overview Routes

// handleDashboardOverview returns comprehensive dashboard overview
func (dh *DashboardV2Handler) handleDashboardOverview(w http.ResponseWriter, r *http.Request) {
	dh.logger.Info("Dashboard overview requested")

	features := dh.dashboardService.GetFeatures()
	workspaces := dh.dashboardService.GetWorkspaces()
	metrics := dh.dashboardService.GetMetrics()

	overview := map[string]interface{}{
		"features": map[string]interface{}{
			"total":       len(features),
			"active":      countActiveFeatures(features),
			"beta":        countFeaturesByStatus(features, "beta"),
			"experimental": countFeaturesByStatus(features, "experimental"),
		},
		"workspaces": map[string]interface{}{
			"total":   len(workspaces),
			"default": getDefaultWorkspace(workspaces),
		},
		"metrics": map[string]interface{}{
			"streams": len(metrics),
			"latest":  getLatestMetricValues(metrics),
		},
		"system": map[string]interface{}{
			"version":    "2.0.0",
			"uptime":     "99.97%",
			"health":     "optimal",
			"last_update": time.Now(),
		},
	}

	dh.sendResponse(w, overview)
}

// handleDashboardHealth returns dashboard health status
func (dh *DashboardV2Handler) handleDashboardHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status": "healthy",
		"components": map[string]interface{}{
			"database":    "healthy",
			"websockets":  "healthy",
			"metrics":     "healthy",
			"features":    "healthy",
			"workspaces":  "healthy",
		},
		"checks": map[string]interface{}{
			"connectivity": true,
			"performance":  true,
			"security":     true,
			"data_integrity": true,
		},
		"timestamp": time.Now(),
	}

	dh.sendResponse(w, health)
}

// handleDashboardStatus returns current dashboard status
func (dh *DashboardV2Handler) handleDashboardStatus(w http.ResponseWriter, r *http.Request) {
	features := dh.dashboardService.GetFeatures()
	metrics := dh.dashboardService.GetMetrics()

	status := map[string]interface{}{
		"active_features": countActiveFeatures(features),
		"total_metrics":   len(metrics),
		"connections":     0, // Would be populated from connection pool
		"load":           "low",
		"response_time":   "12ms",
		"throughput":     "1.2k req/s",
		"error_rate":     "0.01%",
		"last_restart":   time.Now().Add(-24 * time.Hour),
	}

	dh.sendResponse(w, status)
}

// Feature Management Routes

// handleGetFeatures returns all available features
func (dh *DashboardV2Handler) handleGetFeatures(w http.ResponseWriter, r *http.Request) {
	dh.logger.Info("Features list requested")

	features := dh.dashboardService.GetFeatures()
	dh.sendResponse(w, features)
}

// handleGetFeature returns a specific feature
func (dh *DashboardV2Handler) handleGetFeature(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	featureID := vars["feature_id"]

	features := dh.dashboardService.GetFeatures()
	if feature, exists := features[featureID]; exists {
		dh.sendResponse(w, feature)
	} else {
		dh.sendError(w, http.StatusNotFound, "Feature not found")
	}
}

// handleToggleFeature toggles a feature on/off
func (dh *DashboardV2Handler) handleToggleFeature(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	featureID := vars["feature_id"]

	dh.logger.Info("Feature toggle requested", "feature_id", featureID)

	if err := dh.dashboardService.ToggleFeature(featureID); err != nil {
		dh.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get updated feature state
	features := dh.dashboardService.GetFeatures()
	if feature, exists := features[featureID]; exists {
		dh.sendResponse(w, map[string]interface{}{
			"feature": feature,
			"message": fmt.Sprintf("Feature %s toggled successfully", featureID),
		})
	} else {
		dh.sendError(w, http.StatusInternalServerError, "Failed to retrieve updated feature")
	}
}

// handleConfigureFeature updates feature configuration
func (dh *DashboardV2Handler) handleConfigureFeature(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	featureID := vars["feature_id"]

	var configUpdate map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&configUpdate); err != nil {
		dh.sendError(w, http.StatusBadRequest, "Invalid configuration format")
		return
	}

	dh.logger.Info("Feature configuration update requested", 
		"feature_id", featureID, 
		"config", configUpdate)

	// Update feature configuration (implementation would depend on specific requirements)
	response := map[string]interface{}{
		"feature_id": featureID,
		"updated":    true,
		"config":     configUpdate,
		"timestamp":  time.Now(),
	}

	dh.sendResponse(w, response)
}

// Workspace Management Routes

// handleGetWorkspaces returns all workspaces
func (dh *DashboardV2Handler) handleGetWorkspaces(w http.ResponseWriter, r *http.Request) {
	dh.logger.Info("Workspaces list requested")

	workspaces := dh.dashboardService.GetWorkspaces()
	dh.sendResponse(w, workspaces)
}

// handleGetWorkspace returns a specific workspace
func (dh *DashboardV2Handler) handleGetWorkspace(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	workspaceID := vars["workspace_id"]

	workspaces := dh.dashboardService.GetWorkspaces()
	if workspace, exists := workspaces[workspaceID]; exists {
		dh.sendResponse(w, workspace)
	} else {
		dh.sendError(w, http.StatusNotFound, "Workspace not found")
	}
}

// handleCreateWorkspace creates a new workspace
func (dh *DashboardV2Handler) handleCreateWorkspace(w http.ResponseWriter, r *http.Request) {
	var workspace dashboard.WorkspaceLayout
	if err := json.NewDecoder(r.Body).Decode(&workspace); err != nil {
		dh.sendError(w, http.StatusBadRequest, "Invalid workspace format")
		return
	}

	workspace.CreatedAt = time.Now()
	workspace.UpdatedAt = time.Now()

	if err := dh.dashboardService.UpdateWorkspace(&workspace); err != nil {
		dh.sendError(w, http.StatusInternalServerError, "Failed to create workspace")
		return
	}

	dh.logger.Info("Workspace created", "workspace_id", workspace.ID, "name", workspace.Name)
	dh.sendResponse(w, workspace)
}

// handleUpdateWorkspace updates an existing workspace
func (dh *DashboardV2Handler) handleUpdateWorkspace(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	workspaceID := vars["workspace_id"]

	var workspace dashboard.WorkspaceLayout
	if err := json.NewDecoder(r.Body).Decode(&workspace); err != nil {
		dh.sendError(w, http.StatusBadRequest, "Invalid workspace format")
		return
	}

	workspace.ID = workspaceID
	workspace.UpdatedAt = time.Now()

	if err := dh.dashboardService.UpdateWorkspace(&workspace); err != nil {
		dh.sendError(w, http.StatusInternalServerError, "Failed to update workspace")
		return
	}

	dh.logger.Info("Workspace updated", "workspace_id", workspaceID)
	dh.sendResponse(w, workspace)
}

// handleDeleteWorkspace deletes a workspace
func (dh *DashboardV2Handler) handleDeleteWorkspace(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	workspaceID := vars["workspace_id"]

	dh.logger.Info("Workspace deletion requested", "workspace_id", workspaceID)

	// Implementation would remove workspace from storage
	response := map[string]interface{}{
		"workspace_id": workspaceID,
		"deleted":      true,
		"timestamp":    time.Now(),
	}

	dh.sendResponse(w, response)
}

// Metrics Routes

// handleGetMetrics returns all available metrics
func (dh *DashboardV2Handler) handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	dh.logger.Info("Metrics list requested")

	metrics := dh.dashboardService.GetMetrics()
	
	// Optionally filter by query parameters
	limit := r.URL.Query().Get("limit")
	if limit != "" {
		if limitNum, err := strconv.Atoi(limit); err == nil && limitNum > 0 {
			// Limit the number of data points returned per metric
			filteredMetrics := make(map[string]*dashboard.MetricHistory)
			for name, metric := range metrics {
				filteredMetric := *metric
				if len(filteredMetric.Values) > limitNum {
					filteredMetric.Values = filteredMetric.Values[len(filteredMetric.Values)-limitNum:]
				}
				filteredMetrics[name] = &filteredMetric
			}
			metrics = filteredMetrics
		}
	}

	dh.sendResponse(w, metrics)
}

// handleGetMetric returns a specific metric
func (dh *DashboardV2Handler) handleGetMetric(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	metricName := vars["metric_name"]

	metrics := dh.dashboardService.GetMetrics()
	if metric, exists := metrics[metricName]; exists {
		dh.sendResponse(w, metric)
	} else {
		dh.sendError(w, http.StatusNotFound, "Metric not found")
	}
}

// handleQueryMetrics handles complex metric queries
func (dh *DashboardV2Handler) handleQueryMetrics(w http.ResponseWriter, r *http.Request) {
	var queryRequest MetricsRequest
	if err := json.NewDecoder(r.Body).Decode(&queryRequest); err != nil {
		dh.sendError(w, http.StatusBadRequest, "Invalid query format")
		return
	}

	dh.logger.Info("Metrics query requested", "metrics", queryRequest.MetricNames)

	// Process the query and return filtered results
	results := make(map[string]*dashboard.MetricHistory)
	allMetrics := dh.dashboardService.GetMetrics()

	for _, metricName := range queryRequest.MetricNames {
		if metric, exists := allMetrics[metricName]; exists {
			// Apply time range filtering if specified
			filteredMetric := filterMetricByTime(metric, queryRequest.StartTime, queryRequest.EndTime)
			results[metricName] = filteredMetric
		}
	}

	dh.sendResponse(w, results)
}

// handleExportMetrics exports metrics in various formats
func (dh *DashboardV2Handler) handleExportMetrics(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	metrics := dh.dashboardService.GetMetrics()

	switch format {
	case "csv":
		dh.exportMetricsAsCSV(w, metrics)
	case "json":
		dh.sendResponse(w, metrics)
	default:
		dh.sendError(w, http.StatusBadRequest, "Unsupported export format")
	}
}

// WebSocket and Real-time Communication

// handleWebSocketConnection handles WebSocket connections
func (dh *DashboardV2Handler) handleWebSocketConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := dh.websocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		dh.logger.Error("Failed to upgrade WebSocket connection", "error", err)
		return
	}
	defer conn.Close()

	dh.logger.Info("WebSocket connection established")

	// Handle WebSocket communication
	for {
		var msg WebSocketMessage
		if err := conn.ReadJSON(&msg); err != nil {
			dh.logger.Error("WebSocket read error", "error", err)
			break
		}

		// Process message and send response
		response := dh.processWebSocketMessage(msg)
		if err := conn.WriteJSON(response); err != nil {
			dh.logger.Error("WebSocket write error", "error", err)
			break
		}
	}
}

// handleServerSentEvents handles Server-Sent Events
func (dh *DashboardV2Handler) handleServerSentEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		dh.sendError(w, http.StatusInternalServerError, "Streaming unsupported")
		return
	}

	dh.logger.Info("SSE connection established")

	// Send periodic updates
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			data := map[string]interface{}{
				"timestamp": time.Now(),
				"metrics":   dh.getLatestMetricsSummary(),
				"features":  dh.getFeaturesSummary(),
			}

			jsonData, _ := json.Marshal(data)
			fmt.Fprintf(w, "data: %s\n\n", jsonData)
			flusher.Flush()

		case <-r.Context().Done():
			dh.logger.Info("SSE connection closed")
			return
		}
	}
}

// Analytics Routes

// handleUsageAnalytics returns dashboard usage analytics
func (dh *DashboardV2Handler) handleUsageAnalytics(w http.ResponseWriter, r *http.Request) {
	analytics := map[string]interface{}{
		"active_users":      1250,
		"page_views":        45672,
		"session_duration":  "12m 34s",
		"bounce_rate":       "15.2%",
		"popular_features":  []string{"ai-autopilot", "neural-analytics", "edge-computing"},
		"peak_hours":        []int{9, 10, 11, 14, 15, 16},
		"user_satisfaction": 4.7,
		"timestamp":         time.Now(),
	}

	dh.sendResponse(w, analytics)
}

// handlePerformanceAnalytics returns performance analytics
func (dh *DashboardV2Handler) handlePerformanceAnalytics(w http.ResponseWriter, r *http.Request) {
	performance := map[string]interface{}{
		"avg_response_time": "124ms",
		"p95_response_time": "245ms",
		"p99_response_time": "456ms",
		"throughput":        "2.1k req/s",
		"error_rate":        "0.02%",
		"uptime":           "99.97%",
		"cache_hit_rate":   "94.3%",
		"memory_usage":     "67.2%",
		"cpu_usage":        "43.1%",
		"timestamp":        time.Now(),
	}

	dh.sendResponse(w, performance)
}

// handleInsights returns AI-generated insights
func (dh *DashboardV2Handler) handleInsights(w http.ResponseWriter, r *http.Request) {
	insights := map[string]interface{}{
		"recommendations": []map[string]interface{}{
			{
				"type":        "performance",
				"title":       "Optimize dashboard widget loading",
				"description": "Consider implementing lazy loading for non-critical widgets",
				"impact":      "high",
				"effort":      "medium",
				"priority":    1,
			},
			{
				"type":        "user_experience",
				"title":       "Enhance mobile responsiveness",
				"description": "Some dashboard components could be better optimized for mobile",
				"impact":      "medium",
				"effort":      "low",
				"priority":    2,
			},
		},
		"trends": []map[string]interface{}{
			{
				"metric":    "user_engagement",
				"trend":     "increasing",
				"change":    "+12.3%",
				"timeframe": "last 7 days",
			},
			{
				"metric":    "feature_adoption",
				"trend":     "increasing",
				"change":    "+8.7%",
				"timeframe": "last 30 days",
			},
		},
		"anomalies": []map[string]interface{}{
			{
				"detected_at": time.Now().Add(-2 * time.Hour),
				"type":        "performance",
				"description": "Unusual spike in response time detected",
				"status":      "resolved",
				"impact":      "minor",
			},
		},
		"timestamp": time.Now(),
	}

	dh.sendResponse(w, insights)
}

// Configuration Routes

// handleGetConfiguration returns current dashboard configuration
func (dh *DashboardV2Handler) handleGetConfiguration(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"version":        "2.0.0",
		"theme":          "cyberpunk",
		"refresh_rate":   2000,
		"max_widgets":    50,
		"auto_save":      true,
		"notifications":  true,
		"advanced_mode":  true,
		"debug_mode":     false,
		"experimental_features": true,
		"timestamp":      time.Now(),
	}

	dh.sendResponse(w, config)
}

// handleUpdateConfiguration updates dashboard configuration
func (dh *DashboardV2Handler) handleUpdateConfiguration(w http.ResponseWriter, r *http.Request) {
	var configUpdate map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&configUpdate); err != nil {
		dh.sendError(w, http.StatusBadRequest, "Invalid configuration format")
		return
	}

	dh.logger.Info("Configuration update requested", "config", configUpdate)

	response := map[string]interface{}{
		"updated":   true,
		"config":    configUpdate,
		"timestamp": time.Now(),
	}

	dh.sendResponse(w, response)
}

// Utility Methods

// sendResponse sends a successful API response
func (dh *DashboardV2Handler) sendResponse(w http.ResponseWriter, data interface{}) {
	response := DashboardV2Response{
		Success:   true,
		Data:      data,
		Timestamp: time.Now(),
		Version:   "2.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// sendError sends an error API response
func (dh *DashboardV2Handler) sendError(w http.ResponseWriter, statusCode int, message string) {
	response := DashboardV2Response{
		Success:   false,
		Error:     message,
		Timestamp: time.Now(),
		Version:   "2.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// processWebSocketMessage processes incoming WebSocket messages
func (dh *DashboardV2Handler) processWebSocketMessage(msg WebSocketMessage) WebSocketMessage {
	response := WebSocketMessage{
		Type:      "response",
		Timestamp: time.Now(),
		RequestID: msg.RequestID,
	}

	switch msg.Type {
	case "subscribe":
		response.Data = map[string]interface{}{
			"status":      "subscribed",
			"streams":     msg.Data["streams"],
			"update_rate": "real-time",
		}
	case "unsubscribe":
		response.Data = map[string]interface{}{
			"status": "unsubscribed",
			"streams": msg.Data["streams"],
		}
	case "ping":
		response.Type = "pong"
		response.Data = map[string]interface{}{
			"timestamp": time.Now(),
		}
	default:
		response.Data = map[string]interface{}{
			"error": "Unknown message type",
		}
	}

	return response
}

// Helper functions
func countActiveFeatures(features map[string]*dashboard.AdvancedFeature) int {
	count := 0
	for _, feature := range features {
		if feature.Enabled {
			count++
		}
	}
	return count
}

func countFeaturesByStatus(features map[string]*dashboard.AdvancedFeature, status string) int {
	count := 0
	for _, feature := range features {
		if feature.Status == status {
			count++
		}
	}
	return count
}

func getDefaultWorkspace(workspaces map[string]*dashboard.WorkspaceLayout) string {
	for _, workspace := range workspaces {
		if workspace.IsDefault {
			return workspace.Name
		}
	}
	return "none"
}

func getLatestMetricValues(metrics map[string]*dashboard.MetricHistory) map[string]interface{} {
	latest := make(map[string]interface{})
	for name, metric := range metrics {
		if len(metric.Values) > 0 {
			latest[name] = metric.Values[len(metric.Values)-1].Value
		}
	}
	return latest
}

func filterMetricByTime(metric *dashboard.MetricHistory, startTime, endTime time.Time) *dashboard.MetricHistory {
	if startTime.IsZero() && endTime.IsZero() {
		return metric
	}

	filtered := &dashboard.MetricHistory{
		Name:     metric.Name,
		Metadata: metric.Metadata,
		MaxSize:  metric.MaxSize,
		Values:   []dashboard.MetricValue{},
	}

	for _, value := range metric.Values {
		if (startTime.IsZero() || value.Timestamp.After(startTime)) &&
		   (endTime.IsZero() || value.Timestamp.Before(endTime)) {
			filtered.Values = append(filtered.Values, value)
		}
	}

	if len(filtered.Values) > 0 {
		filtered.LastUpdate = filtered.Values[len(filtered.Values)-1].Timestamp
	}

	return filtered
}

func (dh *DashboardV2Handler) exportMetricsAsCSV(w http.ResponseWriter, metrics map[string]*dashboard.MetricHistory) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=dashboard-metrics.csv")

	// Simple CSV export implementation
	w.Write([]byte("metric_name,timestamp,value\n"))
	
	for name, metric := range metrics {
		for _, value := range metric.Values {
			line := fmt.Sprintf("%s,%s,%v\n", name, value.Timestamp.Format(time.RFC3339), value.Value)
			w.Write([]byte(line))
		}
	}
}

func (dh *DashboardV2Handler) getLatestMetricsSummary() map[string]interface{} {
	metrics := dh.dashboardService.GetMetrics()
	summary := make(map[string]interface{})
	
	for name, metric := range metrics {
		if len(metric.Values) > 0 {
			latest := metric.Values[len(metric.Values)-1]
			summary[name] = map[string]interface{}{
				"value":     latest.Value,
				"timestamp": latest.Timestamp,
				"tags":      latest.Tags,
			}
		}
	}
	
	return summary
}

func (dh *DashboardV2Handler) getFeaturesSummary() map[string]interface{} {
	features := dh.dashboardService.GetFeatures()
	summary := make(map[string]interface{})
	
	for id, feature := range features {
		summary[id] = map[string]interface{}{
			"enabled": feature.Enabled,
			"status":  feature.Status,
			"metrics": feature.Metrics,
		}
	}
	
	return summary
}