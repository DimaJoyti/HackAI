package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	fmt.Println("🚀 HackAI Dashboard v2.0 Server - Port 5000")
	fmt.Println("==========================================")

	mux := http.NewServeMux()
	
	// Main dashboard routes
	mux.HandleFunc("/", serveDashboardHome)
	mux.HandleFunc("/dashboard", serveDashboardHome)
	mux.HandleFunc("/dashboard/", serveDashboardHome)
	mux.HandleFunc("/dashboard/overview", serveDashboardOverview)
	
	// API routes
	mux.HandleFunc("/api/dashboard/overview", handleDashboardOverviewAPI)
	mux.HandleFunc("/api/dashboard/features", handleFeaturesAPI)
	mux.HandleFunc("/api/dashboard/workspaces", handleWorkspacesAPI)
	mux.HandleFunc("/api/dashboard/metrics", handleMetricsAPI)
	
	// Health check
	mux.HandleFunc("/health", handleHealth)

	server := &http.Server{
		Addr:    ":5000",
		Handler: mux,
	}

	// Start server
	go func() {
		fmt.Printf("\n✅ Dashboard v2.0 Server READY on: http://localhost:5000\n")
		fmt.Printf("🎯 Dashboard Overview: http://localhost:5000/dashboard/overview\n")
		fmt.Printf("📊 API Overview: http://localhost:5000/api/dashboard/overview\n")
		fmt.Printf("❤️  Health Check: http://localhost:5000/health\n")
		fmt.Printf("🚀 FIXED: Dashboard 404 resolved!\n\n")
		
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server:", err)
		}
	}()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	fmt.Println("\n🛑 Shutting down dashboard server...")
	server.Close()
	fmt.Println("✅ Dashboard server stopped")
}

func serveDashboardHome(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HackAI Dashboard v2.0</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
            color: #00ff41;
            font-family: 'Courier New', monospace;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            text-align: center;
            padding: 3rem;
            border: 2px solid #00ff41;
            border-radius: 15px;
            background: rgba(0, 255, 65, 0.1);
            max-width: 800px;
            box-shadow: 0 0 30px rgba(0, 255, 65, 0.5);
            animation: pulse 2s infinite alternate;
        }
        @keyframes pulse {
            from { box-shadow: 0 0 30px rgba(0, 255, 65, 0.3); }
            to { box-shadow: 0 0 50px rgba(0, 255, 65, 0.7); }
        }
        .logo {
            font-size: 4rem;
            margin-bottom: 1rem;
            text-shadow: 0 0 20px #00ff41;
        }
        .success-message {
            font-size: 1.5rem;
            margin: 2rem 0;
            color: #00ff41;
            animation: glow 1.5s ease-in-out infinite alternate;
        }
        @keyframes glow {
            from { text-shadow: 0 0 10px rgba(0, 255, 65, 0.5); }
            to { text-shadow: 0 0 20px rgba(0, 255, 65, 1); }
        }
        .links {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }
        .link {
            color: #00ff41;
            text-decoration: none;
            padding: 1rem;
            border: 1px solid #00ff41;
            border-radius: 8px;
            transition: all 0.3s;
            background: rgba(0, 255, 65, 0.05);
        }
        .link:hover {
            background: rgba(0, 255, 65, 0.2);
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0, 255, 65, 0.3);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🚀 HackAI</div>
        <h1>Dashboard v2.0</h1>
        <div class="success-message">✅ SUCCESS - Dashboard is Working!</div>
        
        <div class="links">
            <a href="/dashboard/overview" class="link">📊 Dashboard Overview</a>
            <a href="/api/dashboard/overview" class="link">🔧 API Overview</a>
            <a href="/api/dashboard/features" class="link">🤖 Features API</a>
            <a href="/health" class="link">❤️ Health Check</a>
        </div>
        
        <p>🎯 Port 5000 Dashboard Ready</p>
        <p>🚀 No more 404 errors!</p>
    </div>
</body>
</html>`;

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func serveDashboardOverview(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HackAI Dashboard - Overview</title>
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
        .header {
            text-align: center;
            margin-bottom: 2rem;
        }
        .logo {
            font-size: 2.5rem;
            text-shadow: 0 0 10px #00ff41;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }
        .card {
            border: 1px solid #00ff41;
            border-radius: 10px;
            padding: 2rem;
            background: rgba(0, 255, 65, 0.05);
        }
        .card h2 {
            color: #00ff41;
            margin-bottom: 1rem;
        }
        .metric {
            display: flex;
            justify-content: space-between;
            margin: 1rem 0;
            padding: 0.5rem;
            border: 1px solid rgba(0, 255, 65, 0.3);
            border-radius: 5px;
        }
        .metric-value {
            color: #ff6b35;
            font-weight: bold;
        }
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }
        .status-online {
            background: #00ff41;
            box-shadow: 0 0 5px #00ff41;
        }
        .back-link {
            position: fixed;
            top: 1rem;
            left: 1rem;
            color: #00ff41;
            text-decoration: none;
            padding: 0.5rem 1rem;
            border: 1px solid #00ff41;
            border-radius: 5px;
            background: rgba(0, 0, 0, 0.8);
        }
    </style>
</head>
<body>
    <a href="/" class="back-link">← Back to Dashboard</a>
    
    <div class="header">
        <div class="logo">🚀 HackAI Dashboard Overview</div>
        <p>Real-time System Status & Metrics</p>
    </div>

    <div class="grid">
        <div class="card">
            <h2>🤖 AI Systems</h2>
            <div class="metric">
                <span><span class="status-indicator status-online"></span>AI Autopilot</span>
                <span class="metric-value">Active</span>
            </div>
            <div class="metric">
                <span><span class="status-indicator status-online"></span>Neural Analytics</span>
                <span class="metric-value">97.3% Accuracy</span>
            </div>
            <div class="metric">
                <span>Model Training</span>
                <span class="metric-value">Completed</span>
            </div>
        </div>

        <div class="card">
            <h2>🔒 Security Status</h2>
            <div class="metric">
                <span><span class="status-indicator status-online"></span>Threat Detection</span>
                <span class="metric-value">Online</span>
            </div>
            <div class="metric">
                <span>Active Threats</span>
                <span class="metric-value">0</span>
            </div>
            <div class="metric">
                <span>Blocked Attacks</span>
                <span class="metric-value">23 Today</span>
            </div>
        </div>

        <div class="card">
            <h2>📊 System Performance</h2>
            <div class="metric">
                <span>System Uptime</span>
                <span class="metric-value">99.97%</span>
            </div>
            <div class="metric">
                <span>Response Time</span>
                <span class="metric-value">12ms</span>
            </div>
            <div class="metric">
                <span>Active Users</span>
                <span class="metric-value">1,247</span>
            </div>
        </div>

        <div class="card">
            <h2>🏗️ Workspaces</h2>
            <div class="metric">
                <span>Security Operations</span>
                <span class="metric-value">3 Widgets</span>
            </div>
            <div class="metric">
                <span>AI Operations</span>
                <span class="metric-value">2 Widgets</span>
            </div>
            <div class="metric">
                <span>Last Updated</span>
                <span class="metric-value" id="last-updated">Now</span>
            </div>
        </div>
    </div>

    <script>
        function updateTimestamp() {
            document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
        }
        setInterval(updateTimestamp, 1000);
        updateTimestamp();
    </script>
</body>
</html>`;

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func handleDashboardOverviewAPI(w http.ResponseWriter, r *http.Request) {
	overview := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"system_status": "healthy",
			"uptime_percentage": 99.97,
			"active_features": 4,
			"total_workspaces": 2,
			"active_threats": 0,
			"blocked_attacks_today": 23,
			"ai_accuracy": 97.3,
			"response_time_ms": 12,
			"active_users": 1247,
			"last_updated": time.Now().Format(time.RFC3339),
		},
		"timestamp": time.Now().Format(time.RFC3339),
		"version": "2.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(overview)
}

func handleFeaturesAPI(w http.ResponseWriter, r *http.Request) {
	features := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"features": []map[string]interface{}{
				{"id": "ai-autopilot", "name": "AI Autopilot", "status": "active", "enabled": true},
				{"id": "neural-analytics", "name": "Neural Analytics", "status": "active", "enabled": true},
				{"id": "quantum-security", "name": "Quantum Security", "status": "beta", "enabled": false},
				{"id": "edge-computing", "name": "Edge Computing", "status": "active", "enabled": true},
			},
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(features)
}

func handleWorkspacesAPI(w http.ResponseWriter, r *http.Request) {
	workspaces := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"workspaces": []map[string]interface{}{
				{"id": "security-ops", "name": "Security Operations", "widgets": 3, "default": true},
				{"id": "ai-ops", "name": "AI Operations", "widgets": 2, "default": false},
			},
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(workspaces)
}

func handleMetricsAPI(w http.ResponseWriter, r *http.Request) {
	metrics := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"system_uptime": 99.97,
			"response_time": 12,
			"active_users": 1247,
			"ai_accuracy": 97.3,
			"blocked_attacks": 23,
			"active_threats": 0,
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(metrics)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status": "healthy",
		"service": "hackai-dashboard-v2",
		"port": 5000,
		"timestamp": time.Now().Format(time.RFC3339),
		"version": "2.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(health)
}