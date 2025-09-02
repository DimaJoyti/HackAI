package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// MultiCloudDashboard represents the main dashboard application
type MultiCloudDashboard struct {
	server   *http.Server
	upgrader websocket.Upgrader
	clients  map[*websocket.Conn]bool
	mutex    sync.RWMutex
	logger   *log.Logger
}

// CloudProvider represents a cloud provider status
type CloudProvider struct {
	Name      string              `json:"name"`
	Enabled   bool                `json:"enabled"`
	Status    string              `json:"status"`
	Region    string              `json:"region"`
	Clusters  []KubernetesCluster `json:"clusters"`
	Databases []Database          `json:"databases"`
	Storage   []StorageAccount    `json:"storage"`
	Metrics   CloudMetrics        `json:"metrics"`
	LastCheck time.Time           `json:"last_check"`
}

// KubernetesCluster represents a Kubernetes cluster
type KubernetesCluster struct {
	Name           string    `json:"name"`
	Status         string    `json:"status"`
	Version        string    `json:"version"`
	NodeCount      int       `json:"node_count"`
	PodCount       int       `json:"pod_count"`
	NamespaceCount int       `json:"namespace_count"`
	LastUpdated    time.Time `json:"last_updated"`
}

// Database represents a database instance
type Database struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	Version     string    `json:"version"`
	Size        string    `json:"size"`
	Connections int       `json:"connections"`
	LastBackup  time.Time `json:"last_backup"`
}

// StorageAccount represents a storage account
type StorageAccount struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Status      string  `json:"status"`
	UsedSpace   float64 `json:"used_space_gb"`
	TotalSpace  float64 `json:"total_space_gb"`
	ObjectCount int     `json:"object_count"`
}

// CloudMetrics represents cloud provider metrics
type CloudMetrics struct {
	CPUUsage     float64 `json:"cpu_usage"`
	MemoryUsage  float64 `json:"memory_usage"`
	StorageUsage float64 `json:"storage_usage"`
	NetworkIn    float64 `json:"network_in_mbps"`
	NetworkOut   float64 `json:"network_out_mbps"`
	Cost         float64 `json:"estimated_cost_usd"`
}

// DashboardData represents the complete dashboard data
type DashboardData struct {
	Timestamp     time.Time       `json:"timestamp"`
	Providers     []CloudProvider `json:"providers"`
	TotalClusters int             `json:"total_clusters"`
	TotalNodes    int             `json:"total_nodes"`
	TotalPods     int             `json:"total_pods"`
	TotalCost     float64         `json:"total_cost"`
	OverallStatus string          `json:"overall_status"`
}

// NewMultiCloudDashboard creates a new dashboard instance
func NewMultiCloudDashboard() *MultiCloudDashboard {
	return &MultiCloudDashboard{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins in development
			},
		},
		clients: make(map[*websocket.Conn]bool),
		logger:  log.New(os.Stdout, "[Dashboard] ", log.LstdFlags),
	}
}

// Start starts the dashboard server
func (mcd *MultiCloudDashboard) Start(port string) error {
	router := mux.NewRouter()

	// Static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	// API routes
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/status", mcd.handleStatus).Methods("GET")
	api.HandleFunc("/providers", mcd.handleProviders).Methods("GET")
	api.HandleFunc("/clusters", mcd.handleClusters).Methods("GET")
	api.HandleFunc("/metrics", mcd.handleMetrics).Methods("GET")

	// WebSocket endpoint
	router.HandleFunc("/ws", mcd.handleWebSocket)

	// Dashboard page
	router.HandleFunc("/", mcd.handleDashboard).Methods("GET")

	mcd.server = &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	mcd.logger.Printf("Starting Multi-Cloud Dashboard on port %s", port)

	// Start background data collection
	go mcd.startDataCollection()

	return mcd.server.ListenAndServe()
}

// handleDashboard serves the main dashboard page
func (mcd *MultiCloudDashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HackAI Multi-Cloud Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 1rem; text-align: center; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
        .card { background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .card h3 { color: #2c3e50; margin-bottom: 1rem; }
        .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
        .status-healthy { background: #27ae60; }
        .status-warning { background: #f39c12; }
        .status-error { background: #e74c3c; }
        .metric { display: flex; justify-content: space-between; margin: 0.5rem 0; }
        .metric-value { font-weight: bold; color: #3498db; }
        .provider-card { border-left: 4px solid #3498db; }
        .aws { border-left-color: #ff9900; }
        .gcp { border-left-color: #4285f4; }
        .azure { border-left-color: #0078d4; }
        .refresh-btn { background: #3498db; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; }
        .refresh-btn:hover { background: #2980b9; }
        .timestamp { color: #7f8c8d; font-size: 0.9rem; text-align: center; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 HackAI Multi-Cloud Infrastructure Dashboard</h1>
        <p>Real-time monitoring across AWS, GCP, and Azure</p>
    </div>
    
    <div class="container">
        <div class="card">
            <h3>📊 Overall Status</h3>
            <div id="overall-status">
                <div class="metric">
                    <span>Overall Health:</span>
                    <span class="metric-value" id="overall-health">Loading...</span>
                </div>
                <div class="metric">
                    <span>Total Clusters:</span>
                    <span class="metric-value" id="total-clusters">-</span>
                </div>
                <div class="metric">
                    <span>Total Nodes:</span>
                    <span class="metric-value" id="total-nodes">-</span>
                </div>
                <div class="metric">
                    <span>Total Pods:</span>
                    <span class="metric-value" id="total-pods">-</span>
                </div>
                <div class="metric">
                    <span>Estimated Cost:</span>
                    <span class="metric-value" id="total-cost">$-</span>
                </div>
            </div>
            <button class="refresh-btn" onclick="refreshData()">🔄 Refresh</button>
        </div>

        <div class="grid" id="providers-grid">
            <!-- Provider cards will be populated here -->
        </div>

        <div class="timestamp" id="last-updated">
            Last updated: Loading...
        </div>
    </div>

    <script>
        let ws;
        
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(protocol + '//' + window.location.host + '/ws');
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                updateDashboard(data);
            };
            
            ws.onclose = function() {
                console.log('WebSocket connection closed. Reconnecting...');
                setTimeout(connectWebSocket, 5000);
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
            };
        }
        
        function updateDashboard(data) {
            // Update overall status
            document.getElementById('overall-health').textContent = data.overall_status;
            document.getElementById('total-clusters').textContent = data.total_clusters;
            document.getElementById('total-nodes').textContent = data.total_nodes;
            document.getElementById('total-pods').textContent = data.total_pods;
            document.getElementById('total-cost').textContent = '$' + data.total_cost.toFixed(2);
            
            // Update providers
            const providersGrid = document.getElementById('providers-grid');
            providersGrid.innerHTML = '';
            
            data.providers.forEach(provider => {
                const providerCard = createProviderCard(provider);
                providersGrid.appendChild(providerCard);
            });
            
            // Update timestamp
            document.getElementById('last-updated').textContent = 
                'Last updated: ' + new Date(data.timestamp).toLocaleString();
        }
        
        function createProviderCard(provider) {
            const card = document.createElement('div');
            card.className = 'card provider-card ' + provider.name.toLowerCase();
            
            const statusClass = provider.status === 'healthy' ? 'status-healthy' : 
                               provider.status === 'warning' ? 'status-warning' : 'status-error';
            
            card.innerHTML = ` + "`" + `
                <h3>
                    <span class="status-indicator ${statusClass}"></span>
                    ${provider.name.toUpperCase()}
                </h3>
                <div class="metric">
                    <span>Status:</span>
                    <span class="metric-value">${provider.status}</span>
                </div>
                <div class="metric">
                    <span>Region:</span>
                    <span class="metric-value">${provider.region}</span>
                </div>
                <div class="metric">
                    <span>Clusters:</span>
                    <span class="metric-value">${provider.clusters.length}</span>
                </div>
                <div class="metric">
                    <span>CPU Usage:</span>
                    <span class="metric-value">${provider.metrics.cpu_usage.toFixed(1)}%</span>
                </div>
                <div class="metric">
                    <span>Memory Usage:</span>
                    <span class="metric-value">${provider.metrics.memory_usage.toFixed(1)}%</span>
                </div>
                <div class="metric">
                    <span>Cost:</span>
                    <span class="metric-value">$${provider.metrics.cost.toFixed(2)}</span>
                </div>
            ` + "`" + `;
            
            return card;
        }
        
        function refreshData() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => updateDashboard(data))
                .catch(error => console.error('Error fetching data:', error));
        }
        
        // Initialize
        connectWebSocket();
        refreshData();
    </script>
</body>
</html>
`

	t, err := template.New("dashboard").Parse(tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	t.Execute(w, nil)
}

// handleStatus returns the current status of all cloud providers
func (mcd *MultiCloudDashboard) handleStatus(w http.ResponseWriter, r *http.Request) {
	data := mcd.collectDashboardData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// handleProviders returns detailed provider information
func (mcd *MultiCloudDashboard) handleProviders(w http.ResponseWriter, r *http.Request) {
	data := mcd.collectDashboardData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data.Providers)
}

// handleClusters returns cluster information
func (mcd *MultiCloudDashboard) handleClusters(w http.ResponseWriter, r *http.Request) {
	data := mcd.collectDashboardData()

	clusters := make([]KubernetesCluster, 0)
	for _, provider := range data.Providers {
		clusters = append(clusters, provider.Clusters...)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clusters)
}

// handleMetrics returns aggregated metrics
func (mcd *MultiCloudDashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	data := mcd.collectDashboardData()

	metrics := map[string]interface{}{
		"total_clusters": data.TotalClusters,
		"total_nodes":    data.TotalNodes,
		"total_pods":     data.TotalPods,
		"total_cost":     data.TotalCost,
		"overall_status": data.OverallStatus,
		"timestamp":      data.Timestamp,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// handleWebSocket handles WebSocket connections
func (mcd *MultiCloudDashboard) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := mcd.upgrader.Upgrade(w, r, nil)
	if err != nil {
		mcd.logger.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	mcd.mutex.Lock()
	mcd.clients[conn] = true
	mcd.mutex.Unlock()

	mcd.logger.Printf("New WebSocket client connected")

	// Send initial data
	data := mcd.collectDashboardData()
	conn.WriteJSON(data)

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			mcd.mutex.Lock()
			delete(mcd.clients, conn)
			mcd.mutex.Unlock()
			break
		}
	}
}

// startDataCollection starts the background data collection process
func (mcd *MultiCloudDashboard) startDataCollection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			data := mcd.collectDashboardData()
			mcd.broadcastToClients(data)
		}
	}
}

// collectDashboardData collects data from all cloud providers
func (mcd *MultiCloudDashboard) collectDashboardData() DashboardData {
	// This is a mock implementation
	// In a real implementation, this would query actual cloud APIs

	providers := []CloudProvider{
		{
			Name:    "AWS",
			Enabled: true,
			Status:  "healthy",
			Region:  "us-west-2",
			Clusters: []KubernetesCluster{
				{
					Name:           "hackai-production-eks",
					Status:         "running",
					Version:        "1.28",
					NodeCount:      5,
					PodCount:       42,
					NamespaceCount: 8,
					LastUpdated:    time.Now(),
				},
			},
			Databases: []Database{
				{
					Name:        "hackai-prod-db",
					Type:        "PostgreSQL",
					Status:      "available",
					Version:     "15.4",
					Size:        "db.t3.medium",
					Connections: 15,
					LastBackup:  time.Now().Add(-2 * time.Hour),
				},
			},
			Storage: []StorageAccount{
				{
					Name:        "hackai-artifacts",
					Type:        "S3",
					Status:      "available",
					UsedSpace:   125.5,
					TotalSpace:  1000.0,
					ObjectCount: 1250,
				},
			},
			Metrics: CloudMetrics{
				CPUUsage:     65.2,
				MemoryUsage:  78.1,
				StorageUsage: 12.6,
				NetworkIn:    45.2,
				NetworkOut:   38.7,
				Cost:         245.67,
			},
			LastCheck: time.Now(),
		},
		{
			Name:      "GCP",
			Enabled:   false,
			Status:    "disabled",
			Region:    "us-central1",
			Clusters:  []KubernetesCluster{},
			Databases: []Database{},
			Storage:   []StorageAccount{},
			Metrics:   CloudMetrics{},
			LastCheck: time.Now(),
		},
		{
			Name:      "Azure",
			Enabled:   false,
			Status:    "disabled",
			Region:    "East US",
			Clusters:  []KubernetesCluster{},
			Databases: []Database{},
			Storage:   []StorageAccount{},
			Metrics:   CloudMetrics{},
			LastCheck: time.Now(),
		},
	}

	totalClusters := 0
	totalNodes := 0
	totalPods := 0
	totalCost := 0.0

	for _, provider := range providers {
		if provider.Enabled {
			totalClusters += len(provider.Clusters)
			for _, cluster := range provider.Clusters {
				totalNodes += cluster.NodeCount
				totalPods += cluster.PodCount
			}
			totalCost += provider.Metrics.Cost
		}
	}

	overallStatus := "healthy"
	for _, provider := range providers {
		if provider.Enabled && provider.Status != "healthy" {
			overallStatus = "warning"
			break
		}
	}

	return DashboardData{
		Timestamp:     time.Now(),
		Providers:     providers,
		TotalClusters: totalClusters,
		TotalNodes:    totalNodes,
		TotalPods:     totalPods,
		TotalCost:     totalCost,
		OverallStatus: overallStatus,
	}
}

// broadcastToClients sends data to all connected WebSocket clients
func (mcd *MultiCloudDashboard) broadcastToClients(data DashboardData) {
	mcd.mutex.RLock()
	defer mcd.mutex.RUnlock()

	for client := range mcd.clients {
		err := client.WriteJSON(data)
		if err != nil {
			mcd.logger.Printf("Error sending data to client: %v", err)
			client.Close()
			delete(mcd.clients, client)
		}
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dashboard := NewMultiCloudDashboard()

	log.Printf("Starting HackAI Multi-Cloud Dashboard on port %s", port)
	if err := dashboard.Start(port); err != nil {
		log.Fatal("Failed to start dashboard:", err)
	}
}
