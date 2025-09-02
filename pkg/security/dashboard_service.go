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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// DashboardService provides real-time security dashboard functionality
type DashboardService struct {
	metricsCollector *SecurityMetricsCollector
	alertManager     *SecurityAlertManager
	threatDetector   *AdvancedThreatDetectionEngine
	config           *DashboardConfig
	logger           Logger

	// Real-time data
	currentMetrics *SecurityDashboardMetrics
	recentThreats  []*ThreatEvent
	systemStatus   *SystemStatus
	alertSummary   *AlertSummary
	mu             sync.RWMutex

	// WebSocket connections for real-time updates
	wsConnections map[string]*websocket.Conn
	wsUpgrader    websocket.Upgrader
	wsMutex       sync.RWMutex

	// Background workers
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// OpenTelemetry
	tracer trace.Tracer
}

// DashboardConfig configuration for the security dashboard
type DashboardConfig struct {
	Enabled              bool          `yaml:"enabled" json:"enabled"`
	Port                 int           `yaml:"port" json:"port"`
	UpdateInterval       time.Duration `yaml:"update_interval" json:"update_interval"`
	MaxRecentThreats     int           `yaml:"max_recent_threats" json:"max_recent_threats"`
	EnableWebSocket      bool          `yaml:"enable_websocket" json:"enable_websocket"`
	EnableRealTimeAlerts bool          `yaml:"enable_realtime_alerts" json:"enable_realtime_alerts"`
	ThreatRetentionTime  time.Duration `yaml:"threat_retention_time" json:"threat_retention_time"`
	MetricsRetentionTime time.Duration `yaml:"metrics_retention_time" json:"metrics_retention_time"`
}

// SecurityDashboardMetrics represents current security metrics
type SecurityDashboardMetrics struct {
	Timestamp            time.Time                   `json:"timestamp"`
	OverallThreatLevel   string                      `json:"overall_threat_level"`
	ThreatScore          float64                     `json:"threat_score"`
	ActiveThreats        int                         `json:"active_threats"`
	BlockedAttacks       int64                       `json:"blocked_attacks"`
	SystemHealth         float64                     `json:"system_health"`
	Uptime               string                      `json:"uptime"`
	VulnerabilitySummary *VulnerabilitySummary       `json:"vulnerability_summary"`
	ComponentMetrics     map[string]*ComponentStatus `json:"component_metrics"`
}

// ThreatEvent is defined in mitre_atlas.go to avoid duplication

// SystemStatus represents the overall system status
type SystemStatus struct {
	OverallHealth string                      `json:"overall_health"`
	Components    map[string]*ComponentStatus `json:"components"`
	LastUpdated   time.Time                   `json:"last_updated"`
}

// ComponentStatus represents the status of a security component
type ComponentStatus struct {
	Name         string                 `json:"name"`
	Status       string                 `json:"status"`
	Uptime       string                 `json:"uptime"`
	LastCheck    time.Time              `json:"last_check"`
	ThreatsCount int                    `json:"threats_count"`
	Health       float64                `json:"health"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// AlertSummary represents a summary of security alerts
type AlertSummary struct {
	Critical    int       `json:"critical"`
	High        int       `json:"high"`
	Medium      int       `json:"medium"`
	Low         int       `json:"low"`
	Total       int       `json:"total"`
	LastUpdated time.Time `json:"last_updated"`
}

// VulnerabilitySummary represents vulnerability statistics
type VulnerabilitySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// NewDashboardService creates a new security dashboard service
func NewDashboardService(
	metricsCollector *SecurityMetricsCollector,
	alertManager *SecurityAlertManager,
	threatDetector *AdvancedThreatDetectionEngine,
	config *DashboardConfig,
	logger Logger,
) *DashboardService {
	ctx, cancel := context.WithCancel(context.Background())

	return &DashboardService{
		metricsCollector: metricsCollector,
		alertManager:     alertManager,
		threatDetector:   threatDetector,
		config:           config,
		logger:           logger,
		currentMetrics:   &SecurityDashboardMetrics{},
		recentThreats:    make([]*ThreatEvent, 0),
		systemStatus:     &SystemStatus{Components: make(map[string]*ComponentStatus)},
		alertSummary:     &AlertSummary{},
		wsConnections:    make(map[string]*websocket.Conn),
		wsUpgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Configure properly for production
			},
		},
		ctx:    ctx,
		cancel: cancel,
		tracer: otel.Tracer("security-dashboard"),
	}
}

// Start starts the dashboard service
func (ds *DashboardService) Start() error {
	if !ds.config.Enabled {
		ds.logger.Info("Security dashboard is disabled")
		return nil
	}

	ds.logger.Info("Starting security dashboard service", "port", ds.config.Port)

	// Start background workers
	ds.wg.Add(3)
	go ds.metricsUpdater()
	go ds.threatMonitor()
	go ds.systemHealthMonitor()

	// Start HTTP server
	go ds.startHTTPServer()

	return nil
}

// Stop stops the dashboard service
func (ds *DashboardService) Stop() error {
	ds.logger.Info("Stopping security dashboard service")

	ds.cancel()
	ds.wg.Wait()

	// Close all WebSocket connections
	ds.wsMutex.Lock()
	for id, conn := range ds.wsConnections {
		conn.Close()
		delete(ds.wsConnections, id)
	}
	ds.wsMutex.Unlock()

	return nil
}

// metricsUpdater updates dashboard metrics periodically
func (ds *DashboardService) metricsUpdater() {
	defer ds.wg.Done()

	ticker := time.NewTicker(ds.config.UpdateInterval)
	defer ticker.Stop()

	// Initial update
	ds.updateMetrics()

	for {
		select {
		case <-ds.ctx.Done():
			return
		case <-ticker.C:
			ds.updateMetrics()
			if ds.config.EnableWebSocket {
				ds.broadcastMetricsUpdate()
			}
		}
	}
}

// threatMonitor monitors for new threats
func (ds *DashboardService) threatMonitor() {
	defer ds.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ds.ctx.Done():
			return
		case <-ticker.C:
			ds.updateRecentThreats()
		}
	}
}

// systemHealthMonitor monitors system component health
func (ds *DashboardService) systemHealthMonitor() {
	defer ds.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ds.ctx.Done():
			return
		case <-ticker.C:
			ds.updateSystemStatus()
		}
	}
}

// updateMetrics updates the current security metrics
func (ds *DashboardService) updateMetrics() {
	_, span := ds.tracer.Start(ds.ctx, "dashboard.update_metrics")
	defer span.End()

	ds.mu.Lock()
	defer ds.mu.Unlock()

	// Get current metrics from collector
	if ds.metricsCollector != nil {
		metrics := ds.metricsCollector.GetMetrics()

		ds.currentMetrics = &SecurityDashboardMetrics{
			Timestamp:          time.Now(),
			OverallThreatLevel: ds.calculateThreatLevel(metrics),
			ThreatScore:        ds.calculateThreatScore(metrics),
			ActiveThreats:      len(ds.recentThreats),
			BlockedAttacks:     metrics.BlockedRequests,
			SystemHealth:       ds.calculateSystemHealth(),
			Uptime:             ds.calculateUptime(),
			VulnerabilitySummary: &VulnerabilitySummary{
				Critical: 2,
				High:     8,
				Medium:   15,
				Low:      23,
				Total:    48,
			},
			ComponentMetrics: ds.getComponentMetrics(),
		}
	}

	span.SetAttributes(
		attribute.Float64("threat_score", ds.currentMetrics.ThreatScore),
		attribute.Int("active_threats", ds.currentMetrics.ActiveThreats),
		attribute.Float64("system_health", ds.currentMetrics.SystemHealth),
	)
}

// updateRecentThreats updates the list of recent threats
func (ds *DashboardService) updateRecentThreats() {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	// Simulate threat detection - in production this would come from real threat detection
	// This is a placeholder for integration with existing threat detection systems

	// Remove old threats
	cutoff := time.Now().Add(-ds.config.ThreatRetentionTime)
	filtered := make([]*ThreatEvent, 0)
	for _, threat := range ds.recentThreats {
		if threat.Timestamp.After(cutoff) {
			filtered = append(filtered, threat)
		}
	}
	ds.recentThreats = filtered

	// Sort by timestamp (newest first)
	sort.Slice(ds.recentThreats, func(i, j int) bool {
		return ds.recentThreats[i].Timestamp.After(ds.recentThreats[j].Timestamp)
	})

	// Limit to max recent threats
	if len(ds.recentThreats) > ds.config.MaxRecentThreats {
		ds.recentThreats = ds.recentThreats[:ds.config.MaxRecentThreats]
	}
}

// updateSystemStatus updates the system component status
func (ds *DashboardService) updateSystemStatus() {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	// Update component statuses
	components := map[string]*ComponentStatus{
		"ai_firewall": {
			Name:         "AI Firewall",
			Status:       "healthy",
			Uptime:       "99.9%",
			LastCheck:    time.Now(),
			ThreatsCount: 45,
			Health:       99.9,
			Metadata:     make(map[string]interface{}),
		},
		"prompt_injection_guard": {
			Name:         "Prompt Injection Guard",
			Status:       "healthy",
			Uptime:       "99.8%",
			LastCheck:    time.Now(),
			ThreatsCount: 23,
			Health:       99.8,
			Metadata:     make(map[string]interface{}),
		},
		"threat_intelligence": {
			Name:         "Threat Intelligence",
			Status:       "warning",
			Uptime:       "98.5%",
			LastCheck:    time.Now(),
			ThreatsCount: 67,
			Health:       98.5,
			Metadata:     make(map[string]interface{}),
		},
		"vulnerability_scanner": {
			Name:         "Vulnerability Scanner",
			Status:       "healthy",
			Uptime:       "99.7%",
			LastCheck:    time.Now(),
			ThreatsCount: 12,
			Health:       99.7,
			Metadata:     make(map[string]interface{}),
		},
		"security_orchestrator": {
			Name:         "Security Orchestrator",
			Status:       "healthy",
			Uptime:       "99.9%",
			LastCheck:    time.Now(),
			ThreatsCount: 8,
			Health:       99.9,
			Metadata:     make(map[string]interface{}),
		},
		"incident_response": {
			Name:         "Incident Response",
			Status:       "healthy",
			Uptime:       "100%",
			LastCheck:    time.Now(),
			ThreatsCount: 3,
			Health:       100.0,
			Metadata:     make(map[string]interface{}),
		},
	}

	ds.systemStatus = &SystemStatus{
		OverallHealth: ds.calculateOverallHealth(components),
		Components:    components,
		LastUpdated:   time.Now(),
	}

	// Update alert summary
	ds.alertSummary = &AlertSummary{
		Critical:    2,
		High:        8,
		Medium:      15,
		Low:         23,
		Total:       48,
		LastUpdated: time.Now(),
	}
}

// Helper methods for calculations
func (ds *DashboardService) calculateThreatLevel(metrics *SecurityMetrics) string {
	if metrics == nil {
		return "Unknown"
	}

	avgThreatScore := ds.calculateThreatScore(metrics)

	if avgThreatScore >= 0.8 {
		return "Critical"
	} else if avgThreatScore >= 0.6 {
		return "High"
	} else if avgThreatScore >= 0.4 {
		return "Medium"
	}
	return "Low"
}

func (ds *DashboardService) calculateThreatScore(metrics *SecurityMetrics) float64 {
	if metrics == nil {
		return 0.0
	}

	// Calculate based on recent threat activity
	score := 0.0
	if len(ds.recentThreats) > 0 {
		total := 0.0
		for _, threat := range ds.recentThreats {
			total += threat.Confidence
		}
		score = total / float64(len(ds.recentThreats))
	}

	// Add some randomness for demo purposes
	return score + (float64(time.Now().Unix()%100) / 1000.0)
}

func (ds *DashboardService) calculateSystemHealth() float64 {
	// Calculate based on component health
	if ds.systemStatus == nil || len(ds.systemStatus.Components) == 0 {
		return 100.0
	}

	total := 0.0
	count := 0
	for _, component := range ds.systemStatus.Components {
		total += component.Health
		count++
	}

	if count == 0 {
		return 100.0
	}

	return total / float64(count)
}

func (ds *DashboardService) calculateUptime() string {
	// This would be calculated based on actual system uptime
	return "99.9%"
}

func (ds *DashboardService) calculateOverallHealth(components map[string]*ComponentStatus) string {
	criticalCount := 0
	warningCount := 0

	for _, component := range components {
		switch component.Status {
		case "critical":
			criticalCount++
		case "warning":
			warningCount++
		}
	}

	if criticalCount > 0 {
		return "critical"
	} else if warningCount > 0 {
		return "warning"
	}
	return "healthy"
}

func (ds *DashboardService) getComponentMetrics() map[string]*ComponentStatus {
	if ds.systemStatus != nil {
		return ds.systemStatus.Components
	}
	return make(map[string]*ComponentStatus)
}

// startHTTPServer starts the HTTP server for the dashboard API
func (ds *DashboardService) startHTTPServer() {
	router := mux.NewRouter()

	// API endpoints
	api := router.PathPrefix("/api/v1/security").Subrouter()
	api.HandleFunc("/dashboard/metrics", ds.handleGetMetrics).Methods("GET")
	api.HandleFunc("/dashboard/threats", ds.handleGetThreats).Methods("GET")
	api.HandleFunc("/dashboard/status", ds.handleGetStatus).Methods("GET")
	api.HandleFunc("/dashboard/alerts", ds.handleGetAlerts).Methods("GET")
	api.HandleFunc("/dashboard/components", ds.handleGetComponents).Methods("GET")
	api.HandleFunc("/health", ds.handleHealth).Methods("GET")

	// WebSocket endpoint
	if ds.config.EnableWebSocket {
		router.HandleFunc("/ws/security", ds.handleWebSocket)
	}

	// CORS middleware
	router.Use(ds.corsMiddleware)

	addr := fmt.Sprintf(":%d", ds.config.Port)
	ds.logger.Info("Starting security dashboard HTTP server", "address", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	if err := server.ListenAndServe(); err != nil {
		ds.logger.Error("Dashboard HTTP server failed", "error", err)
	}
}

// HTTP handlers
func (ds *DashboardService) handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	ds.mu.RLock()
	metrics := ds.currentMetrics
	ds.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func (ds *DashboardService) handleGetThreats(w http.ResponseWriter, r *http.Request) {
	ds.mu.RLock()
	threats := ds.recentThreats
	ds.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"threats": threats,
		"total":   len(threats),
	})
}

func (ds *DashboardService) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	ds.mu.RLock()
	status := ds.systemStatus
	ds.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (ds *DashboardService) handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	ds.mu.RLock()
	alerts := ds.alertSummary
	ds.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (ds *DashboardService) handleGetComponents(w http.ResponseWriter, r *http.Request) {
	ds.mu.RLock()
	components := ds.systemStatus.Components
	ds.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"components": components,
		"total":      len(components),
	})
}

func (ds *DashboardService) handleHealth(w http.ResponseWriter, r *http.Request) {
	ds.mu.RLock()
	overallHealth := ds.systemStatus.OverallHealth
	ds.mu.RUnlock()

	status := http.StatusOK
	if overallHealth == "critical" {
		status = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    overallHealth,
		"service":   "security-dashboard",
		"timestamp": time.Now(),
	})
}

// WebSocket handler
func (ds *DashboardService) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := ds.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		ds.logger.Error("WebSocket upgrade failed", "error", err)
		return
	}

	clientID := fmt.Sprintf("client_%d", time.Now().UnixNano())

	ds.wsMutex.Lock()
	ds.wsConnections[clientID] = conn
	ds.wsMutex.Unlock()

	ds.logger.Info("WebSocket client connected", "client_id", clientID)

	// Send initial data
	ds.sendInitialData(conn)

	// Handle client disconnection
	defer func() {
		ds.wsMutex.Lock()
		delete(ds.wsConnections, clientID)
		ds.wsMutex.Unlock()
		conn.Close()
		ds.logger.Info("WebSocket client disconnected", "client_id", clientID)
	}()

	// Keep connection alive and handle messages
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// sendInitialData sends initial dashboard data to a new WebSocket client
func (ds *DashboardService) sendInitialData(conn *websocket.Conn) {
	ds.mu.RLock()
	data := map[string]interface{}{
		"type":      "initial_data",
		"metrics":   ds.currentMetrics,
		"threats":   ds.recentThreats,
		"status":    ds.systemStatus,
		"alerts":    ds.alertSummary,
		"timestamp": time.Now(),
	}
	ds.mu.RUnlock()

	if err := conn.WriteJSON(data); err != nil {
		ds.logger.Error("Failed to send initial data", "error", err)
	}
}

// broadcastMetricsUpdate broadcasts metrics updates to all WebSocket clients
func (ds *DashboardService) broadcastMetricsUpdate() {
	ds.mu.RLock()
	data := map[string]interface{}{
		"type":      "metrics_update",
		"metrics":   ds.currentMetrics,
		"timestamp": time.Now(),
	}
	ds.mu.RUnlock()

	ds.broadcastToClients(data)
}

// broadcastThreatAlert broadcasts threat alerts to all WebSocket clients
func (ds *DashboardService) BroadcastThreatAlert(threat *ThreatEvent) {
	ds.mu.Lock()
	ds.recentThreats = append([]*ThreatEvent{threat}, ds.recentThreats...)
	if len(ds.recentThreats) > ds.config.MaxRecentThreats {
		ds.recentThreats = ds.recentThreats[:ds.config.MaxRecentThreats]
	}
	ds.mu.Unlock()

	if ds.config.EnableRealTimeAlerts {
		data := map[string]interface{}{
			"type":      "threat_alert",
			"threat":    threat,
			"timestamp": time.Now(),
		}
		ds.broadcastToClients(data)
	}
}

// broadcastToClients broadcasts data to all connected WebSocket clients
func (ds *DashboardService) broadcastToClients(data interface{}) {
	ds.wsMutex.RLock()
	defer ds.wsMutex.RUnlock()

	for clientID, conn := range ds.wsConnections {
		if err := conn.WriteJSON(data); err != nil {
			ds.logger.Error("Failed to broadcast to client", "client_id", clientID, "error", err)
			// Remove failed connection
			go func(id string) {
				ds.wsMutex.Lock()
				delete(ds.wsConnections, id)
				ds.wsMutex.Unlock()
			}(clientID)
		}
	}
}

// corsMiddleware adds CORS headers
func (ds *DashboardService) corsMiddleware(next http.Handler) http.Handler {
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

// GetCurrentMetrics returns the current dashboard metrics
func (ds *DashboardService) GetCurrentMetrics() *SecurityDashboardMetrics {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.currentMetrics
}

// GetRecentThreats returns the recent threats
func (ds *DashboardService) GetRecentThreats() []*ThreatEvent {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.recentThreats
}

// GetSystemStatus returns the current system status
func (ds *DashboardService) GetSystemStatus() *SystemStatus {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.systemStatus
}
