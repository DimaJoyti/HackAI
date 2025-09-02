package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// SecurityMonitor provides real-time security monitoring and dashboards
type SecurityMonitor struct {
	metricsCollector *SecurityMetricsCollector
	alertManager     *SecurityAlertManager
	config           *MonitoringConfig
	logger           Logger

	// WebSocket connections for real-time updates
	wsConnections map[string]*websocket.Conn
	wsUpgrader    websocket.Upgrader
	wsMutex       sync.RWMutex

	// Dashboard data
	dashboardData *DashboardData
	dataMutex     sync.RWMutex

	// Background workers
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// MonitoringConfig configuration for security monitoring
type MonitoringConfig struct {
	Enabled          bool          `json:"enabled"`
	DashboardEnabled bool          `json:"dashboard_enabled"`
	RealTimeUpdates  bool          `json:"real_time_updates"`
	UpdateInterval   time.Duration `json:"update_interval"`
	RetentionPeriod  time.Duration `json:"retention_period"`
	MaxConnections   int           `json:"max_connections"`
	EnableWebSocket  bool          `json:"enable_websocket"`
	DashboardPort    int           `json:"dashboard_port"`
	MetricsEndpoint  string        `json:"metrics_endpoint"`
	HealthEndpoint   string        `json:"health_endpoint"`
	AlertsEndpoint   string        `json:"alerts_endpoint"`
}

// DashboardData contains data for the security dashboard
type DashboardData struct {
	Overview        *SecurityOverview `json:"overview"`
	ThreatAnalysis  *ThreatAnalysis   `json:"threat_analysis"`
	ComponentStatus *MonitoringComponentStatus  `json:"component_status"`
	PerformanceData *PerformanceData  `json:"performance_data"`
	RecentEvents    []*SecurityEvent  `json:"recent_events"`
	AlertSummary    *MonitoringAlertSummary     `json:"alert_summary"`
	TrendData       *TrendData        `json:"trend_data"`
	LastUpdated     time.Time         `json:"last_updated"`
}

// SecurityOverview high-level security overview
type SecurityOverview struct {
	TotalRequests      int64     `json:"total_requests"`
	BlockedRequests    int64     `json:"blocked_requests"`
	ThreatsDetected    int64     `json:"threats_detected"`
	ActiveAlerts       int64     `json:"active_alerts"`
	SystemHealth       string    `json:"system_health"`
	AverageRiskScore   float64   `json:"average_risk_score"`
	UptimeSeconds      int64     `json:"uptime_seconds"`
	LastThreatDetected time.Time `json:"last_threat_detected"`
}

// ThreatAnalysis detailed threat analysis
type ThreatAnalysis struct {
	ThreatsByType     map[string]int64 `json:"threats_by_type"`
	ThreatsBySeverity map[string]int64 `json:"threats_by_severity"`
	ThreatsBySource   map[string]int64 `json:"threats_by_source"`
	RiskDistribution  map[string]int64 `json:"risk_distribution"`
	TopThreats        []*ThreatSummary `json:"top_threats"`
	ThreatTrends      []*MonitoringThreatTrend   `json:"threat_trends"`
}

// MonitoringComponentStatus status of security components for monitoring
type MonitoringComponentStatus struct {
	Components          []*ComponentHealth `json:"components"`
	OverallHealth       string             `json:"overall_health"`
	HealthyComponents   int                `json:"healthy_components"`
	UnhealthyComponents int                `json:"unhealthy_components"`
	LastHealthCheck     time.Time          `json:"last_health_check"`
}

// PerformanceData performance metrics
type PerformanceData struct {
	AverageProcessingTime time.Duration        `json:"average_processing_time"`
	MaxProcessingTime     time.Duration        `json:"max_processing_time"`
	RequestsPerSecond     float64              `json:"requests_per_second"`
	ConcurrentRequests    int64                `json:"concurrent_requests"`
	QueueDepth            int64                `json:"queue_depth"`
	ResourceUtilization   *ResourceUtilization `json:"resource_utilization"`
}

// MonitoringAlertSummary summary of alerts for monitoring
type MonitoringAlertSummary struct {
	ActiveAlerts     int64            `json:"active_alerts"`
	AlertsByChannel  map[string]int64 `json:"alerts_by_channel"`
	AlertsBySeverity map[string]int64 `json:"alerts_by_severity"`
	RecentAlerts     []*AlertInfo     `json:"recent_alerts"`
	AlertTrends      []*AlertTrend    `json:"alert_trends"`
}

// TrendData historical trend data
type TrendData struct {
	ThreatTrends      []*DataPoint `json:"threat_trends"`
	RequestTrends     []*DataPoint `json:"request_trends"`
	PerformanceTrends []*DataPoint `json:"performance_trends"`
	AlertTrends       []*DataPoint `json:"alert_trends"`
	TimeRange         string       `json:"time_range"`
}

// Supporting types
type ThreatSummary struct {
	Type        string    `json:"type"`
	Count       int64     `json:"count"`
	Severity    string    `json:"severity"`
	LastSeen    time.Time `json:"last_seen"`
	TrendChange float64   `json:"trend_change"`
}

type MonitoringThreatTrend struct {
	Type       string       `json:"type"`
	DataPoints []*DataPoint `json:"data_points"`
}

type ComponentHealth struct {
	Name              string    `json:"name"`
	Status            string    `json:"status"`
	Healthy           bool      `json:"healthy"`
	LastCheck         time.Time `json:"last_check"`
	RequestsProcessed int64     `json:"requests_processed"`
	ThreatsDetected   int64     `json:"threats_detected"`
	ErrorRate         float64   `json:"error_rate"`
}

type ResourceUtilization struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage int64   `json:"memory_usage"`
	DiskUsage   int64   `json:"disk_usage"`
	NetworkIO   int64   `json:"network_io"`
}

type AlertInfo struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
	Component string    `json:"component"`
}

type AlertTrend struct {
	Severity   string       `json:"severity"`
	DataPoints []*DataPoint `json:"data_points"`
}

type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Label     string    `json:"label,omitempty"`
}

// NewSecurityMonitor creates a new security monitor
func NewSecurityMonitor(metricsCollector *SecurityMetricsCollector, alertManager *SecurityAlertManager, config *MonitoringConfig, logger Logger) *SecurityMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	return &SecurityMonitor{
		metricsCollector: metricsCollector,
		alertManager:     alertManager,
		config:           config,
		logger:           logger,
		ctx:              ctx,
		cancel:           cancel,
		wsConnections:    make(map[string]*websocket.Conn),
		wsUpgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // In production, implement proper origin checking
			},
		},
		dashboardData: &DashboardData{
			Overview:        &SecurityOverview{},
			ThreatAnalysis:  &ThreatAnalysis{},
			ComponentStatus: &MonitoringComponentStatus{},
			PerformanceData: &PerformanceData{},
			RecentEvents:    make([]*SecurityEvent, 0),
			AlertSummary:    &MonitoringAlertSummary{},
			TrendData:       &TrendData{},
		},
	}
}

// Start starts the security monitor
func (sm *SecurityMonitor) Start() error {
	if !sm.config.Enabled {
		return nil
	}

	sm.logger.Info("Starting security monitor")

	// Start background workers
	sm.wg.Add(2)
	go sm.dataUpdater()
	go sm.websocketManager()

	// Start dashboard server if enabled
	if sm.config.DashboardEnabled {
		go sm.startDashboardServer()
	}

	return nil
}

// Stop stops the security monitor
func (sm *SecurityMonitor) Stop() error {
	sm.logger.Info("Stopping security monitor")

	sm.cancel()
	sm.wg.Wait()

	// Close all WebSocket connections
	sm.wsMutex.Lock()
	for id, conn := range sm.wsConnections {
		conn.Close()
		delete(sm.wsConnections, id)
	}
	sm.wsMutex.Unlock()

	return nil
}

// dataUpdater updates dashboard data periodically
func (sm *SecurityMonitor) dataUpdater() {
	defer sm.wg.Done()

	ticker := time.NewTicker(sm.config.UpdateInterval)
	defer ticker.Stop()

	// Initial update
	sm.updateDashboardData()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.updateDashboardData()
			if sm.config.RealTimeUpdates {
				sm.broadcastUpdate()
			}
		}
	}
}

// websocketManager manages WebSocket connections
func (sm *SecurityMonitor) websocketManager() {
	defer sm.wg.Done()

	// This would typically handle WebSocket connection lifecycle
	// For now, it's a placeholder for connection management
	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-time.After(30 * time.Second):
			// Periodic cleanup of stale connections
			sm.cleanupStaleConnections()
		}
	}
}

// updateDashboardData updates the dashboard data
func (sm *SecurityMonitor) updateDashboardData() {
	sm.dataMutex.Lock()
	defer sm.dataMutex.Unlock()

	// Get current metrics
	metrics := sm.metricsCollector.GetMetrics()
	componentMetrics := sm.metricsCollector.GetAllComponentMetrics()
	performanceMetrics := sm.metricsCollector.GetPerformanceMetrics()

	// Update overview
	sm.dashboardData.Overview = &SecurityOverview{
		TotalRequests:      metrics.TotalRequests,
		BlockedRequests:    metrics.BlockedRequests,
		ThreatsDetected:    metrics.ThreatsDetected,
		ActiveAlerts:       metrics.AlertsTriggered,
		SystemHealth:       sm.calculateSystemHealth(componentMetrics),
		AverageRiskScore:   metrics.AverageRiskScore,
		UptimeSeconds:      metrics.UptimeSeconds,
		LastThreatDetected: metrics.LastUpdated,
	}

	// Update threat analysis
	sm.dashboardData.ThreatAnalysis = &ThreatAnalysis{
		ThreatsByType:     metrics.ThreatsByType,
		ThreatsBySeverity: metrics.ThreatsBySeverity,
		ThreatsBySource:   metrics.ThreatsBySource,
		RiskDistribution:  metrics.RiskDistribution,
		TopThreats:        sm.calculateTopThreats(metrics),
		ThreatTrends:      sm.calculateThreatTrends(metrics),
	}

	// Update component status
	sm.dashboardData.ComponentStatus = sm.buildComponentStatus(componentMetrics)

	// Update performance data
	sm.dashboardData.PerformanceData = &PerformanceData{
		AverageProcessingTime: metrics.AverageProcessingTime,
		MaxProcessingTime:     metrics.MaxProcessingTime,
		RequestsPerSecond:     sm.calculateRequestsPerSecond(metrics),
		ConcurrentRequests:    performanceMetrics.ConcurrentRequests,
		QueueDepth:            performanceMetrics.QueueDepth,
		ResourceUtilization: &ResourceUtilization{
			CPUUsage:    performanceMetrics.CPUUsage,
			MemoryUsage: performanceMetrics.MemoryUsage,
			DiskUsage:   performanceMetrics.DiskUsage,
			NetworkIO:   performanceMetrics.NetworkIO,
		},
	}

	// Update alert summary
	if sm.alertManager != nil {
		sm.dashboardData.AlertSummary = sm.buildAlertSummary()
	}

	// Update trend data
	sm.dashboardData.TrendData = sm.buildTrendData(metrics)

	sm.dashboardData.LastUpdated = time.Now()
}

// calculateSystemHealth calculates overall system health
func (sm *SecurityMonitor) calculateSystemHealth(componentMetrics map[string]*ComponentMetrics) string {
	if len(componentMetrics) == 0 {
		return "unknown"
	}

	healthyCount := 0
	for _, metrics := range componentMetrics {
		if metrics.HealthStatus == "healthy" {
			healthyCount++
		}
	}

	healthPercentage := float64(healthyCount) / float64(len(componentMetrics))

	switch {
	case healthPercentage >= 0.9:
		return "healthy"
	case healthPercentage >= 0.7:
		return "degraded"
	case healthPercentage >= 0.5:
		return "warning"
	default:
		return "critical"
	}
}

// calculateTopThreats calculates top threats by count
func (sm *SecurityMonitor) calculateTopThreats(metrics *SecurityMetrics) []*ThreatSummary {
	threats := make([]*ThreatSummary, 0, len(metrics.ThreatsByType))

	for threatType, count := range metrics.ThreatsByType {
		threats = append(threats, &ThreatSummary{
			Type:        threatType,
			Count:       count,
			Severity:    sm.getThreatSeverity(threatType),
			LastSeen:    metrics.LastUpdated,
			TrendChange: 0.0, // Would calculate actual trend in real implementation
		})
	}

	// Sort by count descending
	sort.Slice(threats, func(i, j int) bool {
		return threats[i].Count > threats[j].Count
	})

	// Return top 10
	if len(threats) > 10 {
		threats = threats[:10]
	}

	return threats
}

// calculateThreatTrends calculates threat trends over time
func (sm *SecurityMonitor) calculateThreatTrends(metrics *SecurityMetrics) []*MonitoringThreatTrend {
	trends := make([]*MonitoringThreatTrend, 0, len(metrics.ThreatsByType))

	for threatType := range metrics.ThreatsByType {
		// In a real implementation, this would use historical data
		trend := &MonitoringThreatTrend{
			Type:       threatType,
			DataPoints: sm.generateSampleTrendData(threatType),
		}
		trends = append(trends, trend)
	}

	return trends
}

// buildComponentStatus builds component status information
func (sm *SecurityMonitor) buildComponentStatus(componentMetrics map[string]*ComponentMetrics) *MonitoringComponentStatus {
	components := make([]*ComponentHealth, 0, len(componentMetrics))
	healthyCount := 0

	for _, metrics := range componentMetrics {
		healthy := metrics.HealthStatus == "healthy"
		if healthy {
			healthyCount++
		}

		errorRate := 0.0
		if metrics.RequestsProcessed > 0 {
			errorRate = float64(metrics.ErrorCount) / float64(metrics.RequestsProcessed) * 100
		}

		components = append(components, &ComponentHealth{
			Name:              metrics.ComponentName,
			Status:            metrics.HealthStatus,
			Healthy:           healthy,
			LastCheck:         metrics.LastHealthCheck,
			RequestsProcessed: metrics.RequestsProcessed,
			ThreatsDetected:   metrics.ThreatsDetected,
			ErrorRate:         errorRate,
		})
	}

	overallHealth := "healthy"
	if len(componentMetrics) > 0 {
		healthPercentage := float64(healthyCount) / float64(len(componentMetrics))
		if healthPercentage < 0.9 {
			overallHealth = "degraded"
		}
		if healthPercentage < 0.7 {
			overallHealth = "warning"
		}
		if healthPercentage < 0.5 {
			overallHealth = "critical"
		}
	}

	return &MonitoringComponentStatus{
		Components:          components,
		OverallHealth:       overallHealth,
		HealthyComponents:   healthyCount,
		UnhealthyComponents: len(componentMetrics) - healthyCount,
		LastHealthCheck:     time.Now(),
	}
}

// Helper methods

func (sm *SecurityMonitor) getThreatSeverity(threatType string) string {
	// Map threat types to severities
	severityMap := map[string]string{
		"sql_injection":     "critical",
		"xss":               "high",
		"command_injection": "critical",
		"path_traversal":    "high",
		"prompt_injection":  "medium",
		"malware":           "critical",
		"anomaly":           "medium",
	}

	if severity, exists := severityMap[threatType]; exists {
		return severity
	}
	return "medium"
}

func (sm *SecurityMonitor) calculateRequestsPerSecond(metrics *SecurityMetrics) float64 {
	if metrics.UptimeSeconds == 0 {
		return 0.0
	}
	return float64(metrics.TotalRequests) / float64(metrics.UptimeSeconds)
}

func (sm *SecurityMonitor) generateSampleTrendData(threatType string) []*DataPoint {
	// Generate sample trend data - in real implementation, use historical data
	points := make([]*DataPoint, 24) // Last 24 hours
	now := time.Now()

	for i := 0; i < 24; i++ {
		points[i] = &DataPoint{
			Timestamp: now.Add(time.Duration(-23+i) * time.Hour),
			Value:     float64(i % 10), // Sample data
		}
	}

	return points
}

func (sm *SecurityMonitor) buildAlertSummary() *MonitoringAlertSummary {
	// This would integrate with the actual alert manager
	return &MonitoringAlertSummary{
		ActiveAlerts:     0,
		AlertsByChannel:  make(map[string]int64),
		AlertsBySeverity: make(map[string]int64),
		RecentAlerts:     make([]*AlertInfo, 0),
		AlertTrends:      make([]*AlertTrend, 0),
	}
}

func (sm *SecurityMonitor) buildTrendData(metrics *SecurityMetrics) *TrendData {
	return &TrendData{
		ThreatTrends:      sm.generateSampleTrendData("threats"),
		RequestTrends:     sm.generateSampleTrendData("requests"),
		PerformanceTrends: sm.generateSampleTrendData("performance"),
		AlertTrends:       sm.generateSampleTrendData("alerts"),
		TimeRange:         "24h",
	}
}

func (sm *SecurityMonitor) broadcastUpdate() {
	sm.wsMutex.RLock()
	defer sm.wsMutex.RUnlock()

	if len(sm.wsConnections) == 0 {
		return
	}

	sm.dataMutex.RLock()
	data, err := json.Marshal(sm.dashboardData)
	sm.dataMutex.RUnlock()

	if err != nil {
		sm.logger.Error("Failed to marshal dashboard data", "error", err)
		return
	}

	for id, conn := range sm.wsConnections {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			sm.logger.Warn("Failed to send WebSocket update", "connection_id", id, "error", err)
			conn.Close()
			delete(sm.wsConnections, id)
		}
	}
}

func (sm *SecurityMonitor) cleanupStaleConnections() {
	sm.wsMutex.Lock()
	defer sm.wsMutex.Unlock()

	for id, conn := range sm.wsConnections {
		// Send ping to check if connection is alive
		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			conn.Close()
			delete(sm.wsConnections, id)
		}
	}
}

// startDashboardServer starts the dashboard HTTP server
func (sm *SecurityMonitor) startDashboardServer() {
	router := mux.NewRouter()

	// API endpoints
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/dashboard", sm.handleDashboard).Methods("GET")
	api.HandleFunc("/metrics", sm.handleMetrics).Methods("GET")
	api.HandleFunc("/health", sm.handleHealth).Methods("GET")
	api.HandleFunc("/alerts", sm.handleAlerts).Methods("GET")
	api.HandleFunc("/components", sm.handleComponents).Methods("GET")
	api.HandleFunc("/threats", sm.handleThreats).Methods("GET")
	api.HandleFunc("/performance", sm.handlePerformance).Methods("GET")
	api.HandleFunc("/trends", sm.handleTrends).Methods("GET")

	// WebSocket endpoint
	if sm.config.EnableWebSocket {
		router.HandleFunc("/ws", sm.handleWebSocket)
	}

	// Static files (dashboard UI)
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./web/dashboard/")))

	// Add CORS middleware
	router.Use(sm.corsMiddleware)

	addr := fmt.Sprintf(":%d", sm.config.DashboardPort)
	sm.logger.Info("Starting dashboard server", "address", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	if err := server.ListenAndServe(); err != nil {
		sm.logger.Error("Dashboard server failed", "error", err)
	}
}

// HTTP handlers

func (sm *SecurityMonitor) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sm.dataMutex.RLock()
	data := sm.dashboardData
	sm.dataMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (sm *SecurityMonitor) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := sm.metricsCollector.GetMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func (sm *SecurityMonitor) handleHealth(w http.ResponseWriter, r *http.Request) {
	sm.dataMutex.RLock()
	componentStatus := sm.dashboardData.ComponentStatus
	sm.dataMutex.RUnlock()

	status := http.StatusOK
	if componentStatus.OverallHealth == "critical" {
		status = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(componentStatus)
}

func (sm *SecurityMonitor) handleAlerts(w http.ResponseWriter, r *http.Request) {
	sm.dataMutex.RLock()
	alertSummary := sm.dashboardData.AlertSummary
	sm.dataMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alertSummary)
}

func (sm *SecurityMonitor) handleComponents(w http.ResponseWriter, r *http.Request) {
	componentMetrics := sm.metricsCollector.GetAllComponentMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(componentMetrics)
}

func (sm *SecurityMonitor) handleThreats(w http.ResponseWriter, r *http.Request) {
	sm.dataMutex.RLock()
	threatAnalysis := sm.dashboardData.ThreatAnalysis
	sm.dataMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threatAnalysis)
}

func (sm *SecurityMonitor) handlePerformance(w http.ResponseWriter, r *http.Request) {
	performanceMetrics := sm.metricsCollector.GetPerformanceMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(performanceMetrics)
}

func (sm *SecurityMonitor) handleTrends(w http.ResponseWriter, r *http.Request) {
	sm.dataMutex.RLock()
	trendData := sm.dashboardData.TrendData
	sm.dataMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(trendData)
}

func (sm *SecurityMonitor) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := sm.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		sm.logger.Error("WebSocket upgrade failed", "error", err)
		return
	}

	connectionID := fmt.Sprintf("conn_%d", time.Now().UnixNano())

	sm.wsMutex.Lock()
	if len(sm.wsConnections) >= sm.config.MaxConnections {
		sm.wsMutex.Unlock()
		conn.Close()
		return
	}
	sm.wsConnections[connectionID] = conn
	sm.wsMutex.Unlock()

	sm.logger.Info("WebSocket connection established", "connection_id", connectionID)

	// Send initial data
	sm.dataMutex.RLock()
	data, _ := json.Marshal(sm.dashboardData)
	sm.dataMutex.RUnlock()

	conn.WriteMessage(websocket.TextMessage, data)

	// Handle connection lifecycle
	go func() {
		defer func() {
			sm.wsMutex.Lock()
			delete(sm.wsConnections, connectionID)
			sm.wsMutex.Unlock()
			conn.Close()
			sm.logger.Info("WebSocket connection closed", "connection_id", connectionID)
		}()

		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()
}

func (sm *SecurityMonitor) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetDashboardData returns current dashboard data
func (sm *SecurityMonitor) GetDashboardData() *DashboardData {
	sm.dataMutex.RLock()
	defer sm.dataMutex.RUnlock()

	// Return a copy to avoid race conditions
	data := *sm.dashboardData
	return &data
}

// GetSecurityOverview returns security overview
func (sm *SecurityMonitor) GetSecurityOverview() *SecurityOverview {
	sm.dataMutex.RLock()
	defer sm.dataMutex.RUnlock()

	overview := *sm.dashboardData.Overview
	return &overview
}

// GetThreatAnalysis returns threat analysis
func (sm *SecurityMonitor) GetThreatAnalysis() *ThreatAnalysis {
	sm.dataMutex.RLock()
	defer sm.dataMutex.RUnlock()

	analysis := *sm.dashboardData.ThreatAnalysis
	return &analysis
}

// GetComponentStatus returns component status
func (sm *SecurityMonitor) GetComponentStatus() *MonitoringComponentStatus {
	sm.dataMutex.RLock()
	defer sm.dataMutex.RUnlock()

	status := *sm.dashboardData.ComponentStatus
	return &status
}

// AddWebSocketConnection adds a WebSocket connection
func (sm *SecurityMonitor) AddWebSocketConnection(id string, conn *websocket.Conn) error {
	sm.wsMutex.Lock()
	defer sm.wsMutex.Unlock()

	if len(sm.wsConnections) >= sm.config.MaxConnections {
		return fmt.Errorf("maximum connections reached")
	}

	sm.wsConnections[id] = conn
	return nil
}

// RemoveWebSocketConnection removes a WebSocket connection
func (sm *SecurityMonitor) RemoveWebSocketConnection(id string) {
	sm.wsMutex.Lock()
	defer sm.wsMutex.Unlock()

	if conn, exists := sm.wsConnections[id]; exists {
		conn.Close()
		delete(sm.wsConnections, id)
	}
}

// GetActiveConnections returns the number of active WebSocket connections
func (sm *SecurityMonitor) GetActiveConnections() int {
	sm.wsMutex.RLock()
	defer sm.wsMutex.RUnlock()

	return len(sm.wsConnections)
}
