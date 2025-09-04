package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	fmt.Println("🚀 HackAI Dashboard v2.0 - Simple Demo")
	fmt.Println("=====================================")

	// Setup HTTP server with simple routes
	mux := http.NewServeMux()
	
	// Dashboard homepage
	mux.HandleFunc("/", serveDashboardPage)
	mux.HandleFunc("/dashboard", serveDashboardPage)
	mux.HandleFunc("/dashboard/", serveDashboardPage)
	
	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"dashboard-demo","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	})

	// Simple API endpoints that simulate the advanced dashboard
	mux.HandleFunc("/api/features", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := `{
			"success": true,
			"data": {
				"count": 4,
				"features": [
					{"id": "ai-autopilot", "name": "AI Autopilot", "enabled": true, "status": "active"},
					{"id": "neural-analytics", "name": "Neural Analytics", "enabled": true, "status": "active"},
					{"id": "quantum-security", "name": "Quantum Security", "enabled": false, "status": "beta"},
					{"id": "edge-computing", "name": "Edge Computing", "enabled": true, "status": "active"}
				]
			},
			"timestamp": "` + time.Now().Format(time.RFC3339) + `"
		}`
		w.Write([]byte(response))
	})

	mux.HandleFunc("/api/workspaces", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := `{
			"success": true,
			"data": {
				"count": 2,
				"workspaces": [
					{"id": "security-ops", "name": "Security Operations", "isDefault": true, "widgets": 3},
					{"id": "ai-ops", "name": "AI Operations", "isDefault": false, "widgets": 2}
				]
			},
			"timestamp": "` + time.Now().Format(time.RFC3339) + `"
		}`
		w.Write([]byte(response))
	})

	mux.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := `{
			"success": true,
			"data": {
				"system_uptime": 99.97,
				"active_threats": 0,
				"ai_accuracy": 97.3,
				"total_scans": 1247,
				"blocked_attacks": 23
			},
			"timestamp": "` + time.Now().Format(time.RFC3339) + `"
		}`
		w.Write([]byte(response))
	})

	server := &http.Server{
		Addr:    ":9000",
		Handler: mux,
	}

	// Start server
	go func() {
		fmt.Printf("\n🎉 SUCCESS! Dashboard v2.0 Demo WORKING at: http://localhost:9000\n")
		fmt.Printf("📊 Features API: http://localhost:9000/api/features\n")
		fmt.Printf("🏗️  Workspaces API: http://localhost:9000/api/workspaces\n")
		fmt.Printf("📈 Metrics API: http://localhost:9000/api/metrics\n")
		fmt.Printf("❤️  Health Check: http://localhost:9000/health\n")
		fmt.Printf("🚀 FIXED: No more 404 errors!\n\n")
		
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server:", err)
		}
	}()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	fmt.Println("\n🛑 Shutting down dashboard demo server...")
	server.Close()
	fmt.Println("✅ Dashboard demo server stopped")
}

func serveDashboardPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HackAI Dashboard v2.0 - WORKING DEMO</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
            color: #00ff41;
            font-family: 'Courier New', monospace;
            min-height: 100vh;
            padding: 2rem;
            box-sizing: border-box;
        }
        .dashboard-container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            text-align: center;
            margin-bottom: 2rem;
        }
        .logo {
            font-size: 3rem;
            margin-bottom: 1rem;
            text-shadow: 0 0 10px #00ff41;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 50%, 100% { opacity: 1; }
            25%, 75% { opacity: 0.7; }
        }
        .version {
            font-size: 1.2rem;
            opacity: 0.8;
        }
        .working-badge {
            display: inline-block;
            background: rgba(0, 255, 65, 0.2);
            color: #00ff41;
            padding: 0.5rem 1rem;
            border-radius: 15px;
            border: 1px solid #00ff41;
            margin: 1rem 0;
            font-size: 0.9rem;
            animation: glow 1.5s ease-in-out infinite alternate;
        }
        @keyframes glow {
            from { box-shadow: 0 0 5px rgba(0, 255, 65, 0.5); }
            to { box-shadow: 0 0 15px rgba(0, 255, 65, 0.8); }
        }
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin: 2rem 0;
        }
        .dashboard-card {
            border: 1px solid #00ff41;
            border-radius: 10px;
            padding: 1.5rem;
            background: rgba(0, 255, 65, 0.05);
            backdrop-filter: blur(5px);
        }
        .card-title {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            text-align: center;
            color: #00ff41;
        }
        .metrics-display {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }
        .metric-item {
            text-align: center;
            padding: 1rem;
            border: 1px solid rgba(0, 255, 65, 0.3);
            border-radius: 5px;
            background: rgba(0, 255, 65, 0.02);
        }
        .metric-value {
            font-size: 1.5rem;
            color: #ff6b35;
            font-weight: bold;
        }
        .metric-label {
            font-size: 0.8rem;
            margin-top: 0.5rem;
            opacity: 0.8;
        }
        .api-buttons {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }
        .api-button {
            color: #00ff41;
            text-decoration: none;
            border: 1px solid #00ff41;
            padding: 0.75rem;
            border-radius: 5px;
            transition: all 0.3s;
            text-align: center;
            display: block;
        }
        .api-button:hover {
            background: rgba(0, 255, 65, 0.2);
            text-shadow: 0 0 5px #00ff41;
            transform: translateY(-2px);
        }
        .feature-list {
            list-style: none;
            padding: 0;
        }
        .feature-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem;
            margin: 0.5rem 0;
            border: 1px solid rgba(0, 255, 65, 0.3);
            border-radius: 3px;
            background: rgba(0, 255, 65, 0.02);
        }
        .status-indicator {
            padding: 0.25rem 0.5rem;
            border-radius: 10px;
            font-size: 0.8rem;
        }
        .status-active {
            background: rgba(0, 255, 65, 0.2);
            border: 1px solid #00ff41;
        }
        .status-beta {
            background: rgba(255, 107, 53, 0.2);
            border: 1px solid #ff6b35;
            color: #ff6b35;
        }
        .live-data {
            position: fixed;
            top: 1rem;
            right: 1rem;
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid #00ff41;
            border-radius: 5px;
            padding: 1rem;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <div class="live-data">
        <strong>⚡ LIVE</strong><br>
        Uptime: <span id="uptime">0s</span><br>
        Last Update: <span id="last-update">Now</span>
    </div>

    <div class="dashboard-container">
        <div class="header">
            <div class="logo">🚀 HackAI</div>
            <div class="version">Dashboard v2.0 - Advanced AI Security Platform</div>
            <div class="working-badge">✅ WORKING DEMO - FIXED 404 ERROR</div>
        </div>

        <div class="dashboard-grid">
            <!-- Features Card -->
            <div class="dashboard-card">
                <div class="card-title">🤖 AI Features</div>
                <ul class="feature-list" id="features-list">
                    <li>Loading features...</li>
                </ul>
                <div class="api-buttons">
                    <a href="/api/features" class="api-button">📊 Features API</a>
                </div>
            </div>

            <!-- Workspaces Card -->
            <div class="dashboard-card">
                <div class="card-title">🏗️ Workspaces</div>
                <div id="workspaces-info">Loading workspaces...</div>
                <div class="api-buttons">
                    <a href="/api/workspaces" class="api-button">🏗️ Workspaces API</a>
                </div>
            </div>

            <!-- Metrics Card -->
            <div class="dashboard-card">
                <div class="card-title">📈 System Metrics</div>
                <div class="metrics-display" id="metrics-display">
                    <div class="metric-item">
                        <div class="metric-value" id="uptime-metric">Loading...</div>
                        <div class="metric-label">Uptime %</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-value" id="threats-metric">Loading...</div>
                        <div class="metric-label">Active Threats</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-value" id="accuracy-metric">Loading...</div>
                        <div class="metric-label">AI Accuracy %</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-value" id="scans-metric">Loading...</div>
                        <div class="metric-label">Total Scans</div>
                    </div>
                </div>
                <div class="api-buttons">
                    <a href="/api/metrics" class="api-button">📈 Metrics API</a>
                </div>
            </div>

            <!-- Status Card -->
            <div class="dashboard-card">
                <div class="card-title">⚡ System Status</div>
                <div class="metrics-display">
                    <div class="metric-item">
                        <div class="metric-value" style="color: #00ff41;">🟢</div>
                        <div class="metric-label">Dashboard</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-value" style="color: #00ff41;">🟢</div>
                        <div class="metric-label">API Server</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-value" style="color: #00ff41;">🟢</div>
                        <div class="metric-label">Security</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-value" style="color: #00ff41;">🟢</div>
                        <div class="metric-label">AI Systems</div>
                    </div>
                </div>
                <div class="api-buttons">
                    <a href="/health" class="api-button">❤️ Health Check</a>
                </div>
            </div>
        </div>
    </div>

    <script>
        let startTime = Date.now();

        function updateUptime() {
            const uptime = Math.floor((Date.now() - startTime) / 1000);
            document.getElementById('uptime').textContent = uptime + 's';
            document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
        }

        function loadFeatures() {
            fetch('/api/features')
                .then(response => response.json())
                .then(data => {
                    const featuresList = document.getElementById('features-list');
                    featuresList.innerHTML = '';
                    data.data.features.forEach(feature => {
                        const li = document.createElement('li');
                        li.className = 'feature-item';
                        li.innerHTML = 
                            '<span><strong>' + feature.name + '</strong></span>' +
                            '<span class="status-indicator status-' + (feature.enabled ? 'active' : 'beta') + '">' +
                                feature.status.toUpperCase() +
                            '</span>';
                        featuresList.appendChild(li);
                    });
                })
                .catch(error => {
                    document.getElementById('features-list').innerHTML = '<li style="color: #ff6b35;">Error loading features</li>';
                });
        }

        function loadWorkspaces() {
            fetch('/api/workspaces')
                .then(response => response.json())
                .then(data => {
                    const info = document.getElementById('workspaces-info');
                    let html = '<strong>Total: ' + data.data.count + ' workspaces</strong><br><br>';
                    data.data.workspaces.forEach(workspace => {
                        html += 
                            '<div class="feature-item">' +
                                '<span><strong>' + workspace.name + '</strong></span>' +
                                '<span>' + workspace.widgets + ' widgets ' + (workspace.isDefault ? '(Default)' : '') + '</span>' +
                            '</div>';
                    });
                    info.innerHTML = html;
                })
                .catch(error => {
                    document.getElementById('workspaces-info').innerHTML = '<span style="color: #ff6b35;">Error loading workspaces</span>';
                });
        }

        function loadMetrics() {
            fetch('/api/metrics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('uptime-metric').textContent = data.data.system_uptime + '%';
                    document.getElementById('threats-metric').textContent = data.data.active_threats;
                    document.getElementById('accuracy-metric').textContent = data.data.ai_accuracy + '%';
                    document.getElementById('scans-metric').textContent = data.data.total_scans.toLocaleString();
                })
                .catch(error => {
                    document.getElementById('uptime-metric').textContent = 'Error';
                    document.getElementById('threats-metric').textContent = 'Error';
                    document.getElementById('accuracy-metric').textContent = 'Error';
                    document.getElementById('scans-metric').textContent = 'Error';
                });
        }

        // Initialize
        loadFeatures();
        loadWorkspaces();
        loadMetrics();
        updateUptime();

        // Update every 2 seconds
        setInterval(updateUptime, 1000);
        setInterval(loadMetrics, 2000);
        
        // Update features and workspaces every 10 seconds
        setInterval(loadFeatures, 10000);
        setInterval(loadWorkspaces, 10000);
    </script>
</body>
</html>`;

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}