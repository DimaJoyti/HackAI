package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dimajoyti/hackai/pkg/dashboard"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/realtime"
)

func main() {
	fmt.Println("🚀 HackAI Dashboard v2.0 Demo Server")
	fmt.Println("===================================")

	// Initialize logger
	loggerInstance, err := logger.New(logger.Config{
		Level:          "info",
		Format:         "json",
		Output:         "stdout",
		ServiceName:    "dashboard-demo",
		ServiceVersion: "2.0.0",
		Environment:    "demo",
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	ctx := context.Background()

	// Initialize realtime system for the demo
	realtimeConfig := &realtime.RealtimeConfig{
		WebSocketConfig: realtime.WebSocketConfig{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			HandshakeTimeout:  30 * time.Second,
			ReadDeadline:      60 * time.Second,
			WriteDeadline:     60 * time.Second,
			PongWait:          60 * time.Second,
			PingPeriod:        30 * time.Second,
			MaxMessageSize:    1024,
			EnableCompression: true,
		},
		StreamConfig: realtime.StreamConfig{
			BufferSize:        1000,
			FlushInterval:     1 * time.Second,
			MaxStreamAge:      24 * time.Hour,
			EnablePersistence: false,
			CompressionLevel:  1,
		},
		PubSubConfig: realtime.PubSubConfig{
			ChannelBufferSize: 100,
			SubscriberTimeout: 30 * time.Second,
			EnablePersistence: false,
			RetentionPeriod:   1 * time.Hour,
		},
		MaxConnections:      500,
		ConnectionTimeout:   60 * time.Second,
		MetricsEnabled:      false,
		HealthCheckInterval: 30 * time.Second,
	}

	realtimeSystem := realtime.NewRealtimeSystem(realtimeConfig, nil, nil, loggerInstance)
	
	if err := realtimeSystem.Start(ctx); err != nil {
		loggerInstance.Fatal("Failed to start realtime system", "error", err)
	}

	// Initialize advanced dashboard service
	advancedDashboard := dashboard.NewAdvancedDashboardService(loggerInstance, realtimeSystem)
	
	if err := advancedDashboard.Start(ctx); err != nil {
		loggerInstance.Fatal("Failed to start advanced dashboard service", "error", err)
	}

	// Setup HTTP server
	mux := http.NewServeMux()
	
	// Dashboard homepage
	mux.HandleFunc("GET /", serveDashboardPage)
	mux.HandleFunc("GET /dashboard", serveDashboardPage)
	
	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"dashboard-demo","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	})

	// Simple API endpoints
	mux.HandleFunc("GET /api/features", func(w http.ResponseWriter, r *http.Request) {
		features := advancedDashboard.GetFeatures()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"success":true,"data":{"count":%d},"timestamp":"%s"}`, len(features), time.Now().Format(time.RFC3339))
	})

	mux.HandleFunc("GET /api/workspaces", func(w http.ResponseWriter, r *http.Request) {
		workspaces := advancedDashboard.GetWorkspaces()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"success":true,"data":{"count":%d},"timestamp":"%s"}`, len(workspaces), time.Now().Format(time.RFC3339))
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start server
	go func() {
		loggerInstance.Info("Dashboard demo server starting", "address", server.Addr)
		fmt.Printf("\n✅ Dashboard v2.0 Demo available at: http://localhost:8080\n")
		fmt.Printf("📊 Features API: http://localhost:8080/api/features\n")
		fmt.Printf("🏗️  Workspaces API: http://localhost:8080/api/workspaces\n")
		fmt.Printf("❤️  Health Check: http://localhost:8080/health\n\n")
		
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			loggerInstance.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	fmt.Println("\n🛑 Shutting down dashboard demo server...")
	
	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := server.Shutdown(ctx); err != nil {
		loggerInstance.Error("Server forced to shutdown", "error", err)
	}

	loggerInstance.Info("Dashboard demo server stopped")
}

func serveDashboardPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HackAI Dashboard v2.0 - Demo</title>
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
        .dashboard-container {
            text-align: center;
            padding: 2rem;
            border: 1px solid #00ff41;
            border-radius: 10px;
            background: rgba(0, 255, 65, 0.1);
            max-width: 900px;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
            animation: glow 2s ease-in-out infinite alternate;
        }
        @keyframes glow {
            from { box-shadow: 0 0 20px rgba(0, 255, 65, 0.3); }
            to { box-shadow: 0 0 30px rgba(0, 255, 65, 0.5); }
        }
        .logo {
            font-size: 3rem;
            margin-bottom: 1rem;
            text-shadow: 0 0 10px #00ff41;
        }
        .version {
            font-size: 1.2rem;
            margin-bottom: 2rem;
            opacity: 0.8;
        }
        .demo-badge {
            display: inline-block;
            background: rgba(255, 107, 53, 0.2);
            color: #ff6b35;
            padding: 0.5rem 1rem;
            border-radius: 15px;
            border: 1px solid #ff6b35;
            margin-bottom: 2rem;
            font-size: 0.9rem;
        }
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }
        .feature-card {
            padding: 1rem;
            border: 1px solid #00ff41;
            border-radius: 5px;
            background: rgba(0, 255, 65, 0.05);
            text-align: left;
        }
        .api-links {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }
        .api-link {
            color: #00ff41;
            text-decoration: none;
            border: 1px solid #00ff41;
            padding: 0.75rem;
            border-radius: 5px;
            transition: all 0.3s;
            text-align: center;
        }
        .api-link:hover {
            background: rgba(0, 255, 65, 0.2);
            text-shadow: 0 0 5px #00ff41;
            transform: translateY(-2px);
        }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 2rem;
        }
        .status-card {
            padding: 1rem;
            border: 1px solid #00ff41;
            border-radius: 5px;
            background: rgba(0, 255, 65, 0.05);
        }
        .live-counter {
            font-size: 1.2rem;
            color: #ff6b35;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="logo">🚀 HackAI</div>
        <div class="version">Dashboard v2.0 - Advanced AI Security Platform</div>
        <div class="demo-badge">🎯 DEMO MODE ACTIVE</div>
        
        <div class="feature-grid">
            <div class="feature-card">
                <strong>🤖 AI Autopilot</strong><br>
                Autonomous system management with machine learning
            </div>
            <div class="feature-card">
                <strong>🧠 Neural Analytics</strong><br>
                Predictive insights powered by neural networks
            </div>
            <div class="feature-card">
                <strong>⚡ Edge Computing</strong><br>
                Distributed processing across multiple nodes
            </div>
            <div class="feature-card">
                <strong>🔒 Quantum Security</strong><br>
                Next-generation quantum-resistant encryption
            </div>
            <div class="feature-card">
                <strong>🎨 Adaptive UI</strong><br>
                Personalized interfaces that learn from usage
            </div>
            <div class="feature-card">
                <strong>🛡️ Zero Trust</strong><br>
                Comprehensive zero-trust security architecture
            </div>
        </div>

        <div class="api-links">
            <a href="/api/features" class="api-link">📊 Features API</a>
            <a href="/api/workspaces" class="api-link">🏗️ Workspaces API</a>
            <a href="/health" class="api-link">❤️ Health Check</a>
        </div>

        <div class="status-grid">
            <div class="status-card">
                <strong>Status:</strong><br>
                <span id="server-status">🟢 Online</span>
            </div>
            <div class="status-card">
                <strong>Features:</strong><br>
                <span id="feature-count">Loading...</span>
            </div>
            <div class="status-card">
                <strong>Workspaces:</strong><br>
                <span id="workspace-count">Loading...</span>
            </div>
            <div class="status-card">
                <strong>Uptime:</strong><br>
                <span id="uptime-counter">Starting...</span>
            </div>
        </div>

        <div class="live-counter">
            <strong>Demo Active:</strong> <span id="demo-timer">0s</span>
        </div>
    </div>

    <script>
        let startTime = Date.now();
        let demoTime = 0;

        // Update live counters
        function updateCounters() {
            demoTime = Math.floor((Date.now() - startTime) / 1000);
            document.getElementById('demo-timer').textContent = demoTime + 's';
            document.getElementById('uptime-counter').textContent = demoTime + 's';
        }

        // Fetch API data
        function updateAPIData() {
            // Fetch features count
            fetch('/api/features')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('feature-count').textContent = data.data.count + ' active';
                })
                .catch(error => {
                    document.getElementById('feature-count').textContent = 'Error';
                });

            // Fetch workspaces count  
            fetch('/api/workspaces')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('workspace-count').textContent = data.data.count + ' configured';
                })
                .catch(error => {
                    document.getElementById('workspace-count').textContent = 'Error';
                });

            // Check health
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('server-status').textContent = '🟢 Healthy';
                })
                .catch(error => {
                    document.getElementById('server-status').textContent = '🔴 Error';
                });
        }

        // Initialize
        updateAPIData();
        updateCounters();

        // Update every second
        setInterval(updateCounters, 1000);
        
        // Update API data every 5 seconds
        setInterval(updateAPIData, 5000);
    </script>
</body>
</html>`;

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}