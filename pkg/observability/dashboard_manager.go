package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// DashboardManagerConfig configuration for dashboard management
type DashboardManagerConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	Port          int           `yaml:"port" json:"port"`
	RefreshRate   time.Duration `yaml:"refresh_rate" json:"refresh_rate"`
	DataRetention time.Duration `yaml:"data_retention" json:"data_retention"`
	EnableWebSocket bool        `yaml:"enable_websocket" json:"enable_websocket"`
	MaxConnections  int         `yaml:"max_connections" json:"max_connections"`
}

// DashboardData represents dashboard data structure
type DashboardData struct {
	Timestamp      time.Time                  `json:"timestamp"`
	SystemHealth   string                     `json:"system_health"`
	Metrics        *DashboardMetrics          `json:"metrics"`
	Alerts         []*Alert                   `json:"alerts"`
	Components     map[string]*ComponentInfo  `json:"components"`
	Performance    *PerformanceData           `json:"performance"`
	Metadata       map[string]interface{}     `json:"metadata"`
}

// DashboardMetrics represents key metrics for dashboard
type DashboardMetrics struct {
	RequestsPerSecond   float64 `json:"requests_per_second"`
	ErrorRate           float64 `json:"error_rate"`
	AverageResponseTime float64 `json:"average_response_time"`
	ActiveConnections   int64   `json:"active_connections"`
	MemoryUsage         float64 `json:"memory_usage"`
	CPUUsage            float64 `json:"cpu_usage"`
	DiskUsage           float64 `json:"disk_usage"`
	Uptime              float64 `json:"uptime"`
}

// ComponentInfo represents component information for dashboard
type ComponentInfo struct {
	Name         string                 `json:"name"`
	Status       string                 `json:"status"`
	Health       float64                `json:"health"`
	LastCheck    time.Time              `json:"last_check"`
	Version      string                 `json:"version"`
	Dependencies []string               `json:"dependencies"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// PerformanceData represents performance data for dashboard
type PerformanceData struct {
	Latency     *LatencyData     `json:"latency"`
	Throughput  *ThroughputData  `json:"throughput"`
	Resources   *ResourceData    `json:"resources"`
	Errors      *ErrorData       `json:"errors"`
}

// LatencyData represents latency metrics
type LatencyData struct {
	P50  float64 `json:"p50"`
	P90  float64 `json:"p90"`
	P95  float64 `json:"p95"`
	P99  float64 `json:"p99"`
	Mean float64 `json:"mean"`
}

// ThroughputData represents throughput metrics
type ThroughputData struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	BytesPerSecond    float64 `json:"bytes_per_second"`
	EventsPerSecond   float64 `json:"events_per_second"`
}

// ResourceData represents resource usage metrics
type ResourceData struct {
	CPU    float64 `json:"cpu"`
	Memory float64 `json:"memory"`
	Disk   float64 `json:"disk"`
	Network float64 `json:"network"`
}

// ErrorData represents error metrics
type ErrorData struct {
	Total      int64              `json:"total"`
	Rate       float64            `json:"rate"`
	ByType     map[string]int64   `json:"by_type"`
	ByService  map[string]int64   `json:"by_service"`
	Recent     []*ErrorInfo       `json:"recent"`
}

// DashboardManager manages observability dashboards
type DashboardManager struct {
	config     *DashboardManagerConfig
	logger     *logger.Logger
	provider   *Provider
	
	// Dashboard data
	currentData *DashboardData
	dataHistory []*DashboardData
	mu          sync.RWMutex
	
	// WebSocket connections
	wsUpgrader  websocket.Upgrader
	connections map[string]*websocket.Conn
	connMu      sync.RWMutex
	
	// HTTP server
	server *http.Server
	
	// Background processing
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDashboardManager creates a new dashboard manager
func NewDashboardManager(
	config *DashboardManagerConfig,
	provider *Provider,
	log *logger.Logger,
) *DashboardManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &DashboardManager{
		config:      config,
		logger:      log,
		provider:    provider,
		currentData: &DashboardData{},
		dataHistory: make([]*DashboardData, 0),
		connections: make(map[string]*websocket.Conn),
		ctx:         ctx,
		cancel:      cancel,
		wsUpgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins in development
			},
		},
	}
}

// Start starts the dashboard manager
func (dm *DashboardManager) Start(ctx context.Context) error {
	if !dm.config.Enabled {
		dm.logger.Info("Dashboard manager is disabled")
		return nil
	}
	
	dm.logger.Info("Starting dashboard manager",
		"port", dm.config.Port,
		"refresh_rate", dm.config.RefreshRate,
		"websocket_enabled", dm.config.EnableWebSocket,
	)
	
	// Start background workers
	dm.wg.Add(2)
	go dm.updateDashboardData()
	go dm.startHTTPServer()
	
	return nil
}

// Stop stops the dashboard manager
func (dm *DashboardManager) Stop() error {
	dm.logger.Info("Stopping dashboard manager")
	
	dm.cancel()
	
	// Close WebSocket connections
	dm.connMu.Lock()
	for id, conn := range dm.connections {
		conn.Close()
		delete(dm.connections, id)
	}
	dm.connMu.Unlock()
	
	// Shutdown HTTP server
	if dm.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		dm.server.Shutdown(ctx)
	}
	
	dm.wg.Wait()
	
	return nil
}

// updateDashboardData periodically updates dashboard data
func (dm *DashboardManager) updateDashboardData() {
	defer dm.wg.Done()
	
	ticker := time.NewTicker(dm.config.RefreshRate)
	defer ticker.Stop()
	
	for {
		select {
		case <-dm.ctx.Done():
			return
		case <-ticker.C:
			dm.refreshData()
		}
	}
}

// refreshData refreshes dashboard data
func (dm *DashboardManager) refreshData() {
	data := &DashboardData{
		Timestamp:    time.Now(),
		SystemHealth: "healthy", // Would be calculated from actual metrics
		Metrics:      dm.collectMetrics(),
		Alerts:       dm.collectAlerts(),
		Components:   dm.collectComponentInfo(),
		Performance:  dm.collectPerformanceData(),
		Metadata:     make(map[string]interface{}),
	}
	
	dm.mu.Lock()
	dm.currentData = data
	dm.dataHistory = append(dm.dataHistory, data)
	
	// Cleanup old data
	if len(dm.dataHistory) > 1000 { // Keep last 1000 data points
		dm.dataHistory = dm.dataHistory[1:]
	}
	dm.mu.Unlock()
	
	// Broadcast to WebSocket clients
	if dm.config.EnableWebSocket {
		dm.broadcastData(data)
	}
}

// collectMetrics collects current metrics
func (dm *DashboardManager) collectMetrics() *DashboardMetrics {
	// This would collect actual metrics from the provider
	return &DashboardMetrics{
		RequestsPerSecond:   100.5,
		ErrorRate:           0.02,
		AverageResponseTime: 150.0,
		ActiveConnections:   250,
		MemoryUsage:         0.65,
		CPUUsage:            0.45,
		DiskUsage:           0.30,
		Uptime:              time.Since(time.Now().Add(-2*time.Hour)).Seconds(),
	}
}

// collectAlerts collects current alerts
func (dm *DashboardManager) collectAlerts() []*Alert {
	// This would collect actual alerts from alert manager
	return []*Alert{}
}

// collectComponentInfo collects component information
func (dm *DashboardManager) collectComponentInfo() map[string]*ComponentInfo {
	components := make(map[string]*ComponentInfo)
	
	components["api_gateway"] = &ComponentInfo{
		Name:         "API Gateway",
		Status:       "healthy",
		Health:       0.98,
		LastCheck:    time.Now(),
		Version:      "1.0.0",
		Dependencies: []string{"database", "redis"},
		Metadata:     make(map[string]interface{}),
	}
	
	components["database"] = &ComponentInfo{
		Name:         "Database",
		Status:       "healthy",
		Health:       0.95,
		LastCheck:    time.Now(),
		Version:      "14.0",
		Dependencies: []string{},
		Metadata:     make(map[string]interface{}),
	}
	
	return components
}

// collectPerformanceData collects performance data
func (dm *DashboardManager) collectPerformanceData() *PerformanceData {
	return &PerformanceData{
		Latency: &LatencyData{
			P50:  50.0,
			P90:  150.0,
			P95:  200.0,
			P99:  500.0,
			Mean: 75.0,
		},
		Throughput: &ThroughputData{
			RequestsPerSecond: 100.5,
			BytesPerSecond:    1024000,
			EventsPerSecond:   50.2,
		},
		Resources: &ResourceData{
			CPU:     0.45,
			Memory:  0.65,
			Disk:    0.30,
			Network: 0.20,
		},
		Errors: &ErrorData{
			Total:     125,
			Rate:      0.02,
			ByType:    map[string]int64{"validation": 50, "timeout": 30, "auth": 45},
			ByService: map[string]int64{"api": 75, "auth": 25, "db": 25},
			Recent:    []*ErrorInfo{},
		},
	}
}

// startHTTPServer starts the HTTP server for dashboard
func (dm *DashboardManager) startHTTPServer() {
	defer dm.wg.Done()
	
	router := mux.NewRouter()
	
	// Dashboard API endpoints
	router.HandleFunc("/api/dashboard", dm.handleDashboardData).Methods("GET")
	router.HandleFunc("/api/dashboard/metrics", dm.handleMetrics).Methods("GET")
	router.HandleFunc("/api/dashboard/alerts", dm.handleAlerts).Methods("GET")
	router.HandleFunc("/api/dashboard/components", dm.handleComponents).Methods("GET")
	router.HandleFunc("/api/dashboard/performance", dm.handlePerformance).Methods("GET")
	
	// WebSocket endpoint
	if dm.config.EnableWebSocket {
		router.HandleFunc("/ws/dashboard", dm.handleWebSocket)
	}
	
	// Static dashboard (would serve actual dashboard files)
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./web/dashboard/")))
	
	dm.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", dm.config.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	dm.logger.Info("Dashboard HTTP server starting", "port", dm.config.Port)
	
	if err := dm.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		dm.logger.Error("Dashboard server error", "error", err)
	}
}

// HTTP Handlers

// handleDashboardData handles dashboard data requests
func (dm *DashboardManager) handleDashboardData(w http.ResponseWriter, r *http.Request) {
	dm.mu.RLock()
	data := dm.currentData
	dm.mu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		dm.logger.Error("Failed to encode dashboard data", "error", err)
	}
}

// handleMetrics handles metrics requests
func (dm *DashboardManager) handleMetrics(w http.ResponseWriter, r *http.Request) {
	dm.mu.RLock()
	metrics := dm.currentData.Metrics
	dm.mu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	json.NewEncoder(w).Encode(metrics)
}

// handleAlerts handles alerts requests
func (dm *DashboardManager) handleAlerts(w http.ResponseWriter, r *http.Request) {
	dm.mu.RLock()
	alerts := dm.currentData.Alerts
	dm.mu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	json.NewEncoder(w).Encode(alerts)
}

// handleComponents handles components requests
func (dm *DashboardManager) handleComponents(w http.ResponseWriter, r *http.Request) {
	dm.mu.RLock()
	components := dm.currentData.Components
	dm.mu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	json.NewEncoder(w).Encode(components)
}

// handlePerformance handles performance requests
func (dm *DashboardManager) handlePerformance(w http.ResponseWriter, r *http.Request) {
	dm.mu.RLock()
	performance := dm.currentData.Performance
	dm.mu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	json.NewEncoder(w).Encode(performance)
}

// handleWebSocket handles WebSocket connections
func (dm *DashboardManager) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := dm.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		dm.logger.Error("WebSocket upgrade failed", "error", err)
		return
	}
	
	connID := fmt.Sprintf("%s_%d", r.RemoteAddr, time.Now().UnixNano())
	
	dm.connMu.Lock()
	dm.connections[connID] = conn
	dm.connMu.Unlock()
	
	dm.logger.Info("WebSocket connection established", "connection_id", connID)
	
	// Send current data immediately
	dm.mu.RLock()
	currentData := dm.currentData
	dm.mu.RUnlock()
	
	if err := conn.WriteJSON(currentData); err != nil {
		dm.logger.Error("Failed to send initial data", "error", err)
	}
	
	// Handle connection cleanup
	defer func() {
		dm.connMu.Lock()
		delete(dm.connections, connID)
		dm.connMu.Unlock()
		conn.Close()
		dm.logger.Info("WebSocket connection closed", "connection_id", connID)
	}()
	
	// Keep connection alive and handle ping/pong
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// broadcastData broadcasts data to all WebSocket connections
func (dm *DashboardManager) broadcastData(data *DashboardData) {
	dm.connMu.RLock()
	connections := make(map[string]*websocket.Conn)
	for id, conn := range dm.connections {
		connections[id] = conn
	}
	dm.connMu.RUnlock()
	
	for connID, conn := range connections {
		if err := conn.WriteJSON(data); err != nil {
			dm.logger.Warn("Failed to send data to WebSocket client", "connection_id", connID, "error", err)
			
			// Remove failed connection
			dm.connMu.Lock()
			delete(dm.connections, connID)
			dm.connMu.Unlock()
			conn.Close()
		}
	}
}

// GetCurrentData returns current dashboard data
func (dm *DashboardManager) GetCurrentData() *DashboardData {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.currentData
}
