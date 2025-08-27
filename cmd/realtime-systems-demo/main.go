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

	"github.com/gorilla/mux"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/infrastructure"
	"github.com/dimajoyti/hackai/pkg/langgraph/messaging"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/realtime"
)

func main() {
	fmt.Println("🚀 HackAI Real-time Systems Integration Demo")
	fmt.Println("=============================================")
	fmt.Println("Demonstrating: WebSockets, Server-Sent Events, PubSub, Streaming, Real-time Analytics")

	// Initialize logger
	logger, err := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize Redis client (optional - will work without Redis)
	var redisClient *infrastructure.RedisClient
	redisConfig := &config.RedisConfig{
		Host:         "localhost",
		Port:         "6379",
		Password:     "",
		DB:           0,
		PoolSize:     10,
		MinIdleConns: 5,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	redisClient, err = infrastructure.NewRedisClient(redisConfig, logger)
	if err != nil {
		logger.Warn("Redis not available, continuing without persistence", "error", err)
		redisClient = nil
	} else {
		logger.Info("✅ Redis client initialized")
	}

	// Initialize event system
	eventSystem := &messaging.EventSystem{} // Simplified for demo

	// Configure real-time system
	realtimeConfig := &realtime.RealtimeConfig{
		WebSocketConfig: realtime.WebSocketConfig{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			HandshakeTimeout:  10 * time.Second,
			ReadDeadline:      60 * time.Second,
			WriteDeadline:     10 * time.Second,
			PongWait:          60 * time.Second,
			PingPeriod:        54 * time.Second,
			MaxMessageSize:    512 * 1024, // 512KB
			EnableCompression: true,
		},
		StreamConfig: realtime.StreamConfig{
			BufferSize:        1000,
			FlushInterval:     5 * time.Second,
			MaxStreamAge:      1 * time.Hour,
			EnablePersistence: redisClient != nil,
			CompressionLevel:  6,
		},
		PubSubConfig: realtime.PubSubConfig{
			ChannelBufferSize: 100,
			SubscriberTimeout: 5 * time.Minute,
			EnablePersistence: redisClient != nil,
			RetentionPeriod:   24 * time.Hour,
		},
		MaxConnections:      1000,
		ConnectionTimeout:   30 * time.Second,
		HeartbeatInterval:   30 * time.Second,
		MessageBufferSize:   1000,
		MessageTimeout:      10 * time.Second,
		EnableCompression:   true,
		EnableAuth:          false,
		AllowedOrigins:      []string{"*"},
		RateLimitEnabled:    true,
		RateLimitRequests:   100,
		RateLimitWindow:     1 * time.Minute,
		MetricsEnabled:      true,
		HealthCheckInterval: 30 * time.Second,
	}

	// Create real-time system
	realtimeSystem := realtime.NewRealtimeSystem(realtimeConfig, redisClient, eventSystem, logger)

	// Start real-time system
	if err := realtimeSystem.Start(ctx); err != nil {
		logger.Fatal("Failed to start real-time system", "error", err)
	}
	logger.Info("✅ Real-time system started")

	// Create HTTP handlers
	httpHandlers := realtime.NewHTTPHandlers(realtimeSystem, logger)

	// Setup HTTP server
	router := mux.NewRouter()

	// Register real-time routes
	httpHandlers.RegisterRoutes(router)

	// Add demo routes
	setupDemoRoutes(router, realtimeSystem, logger)

	// Create HTTP server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start HTTP server
	go func() {
		logger.Info("🌐 HTTP server starting", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP server failed", "error", err)
		}
	}()

	// Start demo scenarios
	go runDemoScenarios(ctx, realtimeSystem, logger)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("🎯 Real-time Systems Demo is running!")
	logger.Info("📊 Available endpoints:")
	logger.Info("   • WebSocket: ws://localhost:8080/ws")
	logger.Info("   • Server-Sent Events: http://localhost:8080/events")
	logger.Info("   • REST API: http://localhost:8080/api/realtime/")
	logger.Info("   • Demo Dashboard: http://localhost:8080/demo")
	logger.Info("   • System Status: http://localhost:8080/api/realtime/status")
	logger.Info("   • Health Check: http://localhost:8080/api/realtime/health")
	logger.Info("Press Ctrl+C to stop...")

	<-sigChan
	logger.Info("🛑 Shutting down...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}

	// Stop real-time system
	if err := realtimeSystem.Stop(); err != nil {
		logger.Error("Real-time system shutdown error", "error", err)
	}

	logger.Info("✅ Shutdown complete")
}

// setupDemoRoutes sets up demo-specific routes
func setupDemoRoutes(router *mux.Router, realtimeSystem *realtime.RealtimeSystem, logger *logger.Logger) {
	// Demo dashboard
	router.HandleFunc("/demo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, getDemoDashboardHTML())
	}).Methods("GET")

	// Demo data endpoints
	router.HandleFunc("/demo/publish", func(w http.ResponseWriter, r *http.Request) {
		channel := r.URL.Query().Get("channel")
		if channel == "" {
			channel = "demo"
		}

		data := map[string]interface{}{
			"message":   "Demo message from REST API",
			"timestamp": time.Now(),
			"source":    "demo-endpoint",
		}

		err := realtimeSystem.PublishMessage(r.Context(), channel, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success": true, "channel": "%s", "message": "Published successfully"}`, channel)
	}).Methods("POST")

	// Demo stream creation
	router.HandleFunc("/demo/stream", func(w http.ResponseWriter, r *http.Request) {
		stream, err := realtimeSystem.GetStreamManager().CreateStream(
			r.Context(),
			"demo-stream",
			"Demo data stream",
			realtime.StreamTypeData,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success": true, "stream_id": "%s", "message": "Stream created"}`, stream.ID)
	}).Methods("POST")
}

// runDemoScenarios runs various demo scenarios
func runDemoScenarios(ctx context.Context, realtimeSystem *realtime.RealtimeSystem, logger *logger.Logger) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	scenarios := []string{
		"real-time-analytics",
		"live-notifications",
		"system-monitoring",
		"user-activity",
		"market-data",
	}

	scenarioIndex := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scenario := scenarios[scenarioIndex%len(scenarios)]
			runScenario(ctx, realtimeSystem, scenario, logger)
			scenarioIndex++
		}
	}
}

// runScenario runs a specific demo scenario
func runScenario(ctx context.Context, realtimeSystem *realtime.RealtimeSystem, scenario string, logger *logger.Logger) {
	switch scenario {
	case "real-time-analytics":
		data := map[string]interface{}{
			"type":         "analytics",
			"page_views":   1000 + (time.Now().Unix() % 500),
			"active_users": 150 + (time.Now().Unix() % 50),
			"timestamp":    time.Now(),
		}
		realtimeSystem.PublishMessage(ctx, "analytics", data)

	case "live-notifications":
		data := map[string]interface{}{
			"type":      "notification",
			"title":     "New Security Alert",
			"message":   "Suspicious activity detected in system",
			"severity":  "high",
			"timestamp": time.Now(),
		}
		realtimeSystem.PublishMessage(ctx, "notifications", data)

	case "system-monitoring":
		data := map[string]interface{}{
			"type":         "metrics",
			"cpu_usage":    float64(20 + (time.Now().Unix() % 60)),
			"memory_usage": float64(40 + (time.Now().Unix() % 40)),
			"disk_usage":   float64(60 + (time.Now().Unix() % 20)),
			"timestamp":    time.Now(),
		}
		realtimeSystem.PublishMessage(ctx, "system-metrics", data)

	case "user-activity":
		data := map[string]interface{}{
			"type":       "activity",
			"user_id":    fmt.Sprintf("user_%d", time.Now().Unix()%1000),
			"action":     "login",
			"ip_address": "192.168.1.100",
			"timestamp":  time.Now(),
		}
		realtimeSystem.PublishMessage(ctx, "user-activity", data)

	case "market-data":
		data := map[string]interface{}{
			"type":      "market",
			"symbol":    "BTC/USD",
			"price":     45000 + (time.Now().Unix() % 5000),
			"volume":    1000000 + (time.Now().Unix() % 500000),
			"timestamp": time.Now(),
		}
		realtimeSystem.PublishMessage(ctx, "market-data", data)
	}

	logger.Debug("Demo scenario executed", "scenario", scenario)
}

// getDemoDashboardHTML returns HTML for the demo dashboard
func getDemoDashboardHTML() string {
	return `
<!DOCTYPE html>
<html>
<head>
    <title>HackAI Real-time Systems Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .metric { background: #ecf0f1; padding: 15px; border-radius: 6px; text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #2c3e50; }
        .metric .value { font-size: 24px; font-weight: bold; color: #27ae60; }
        .log { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 6px; font-family: monospace; height: 200px; overflow-y: auto; }
        button { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 5px; }
        button:hover { background: #2980b9; }
        .status { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .status.healthy { background: #27ae60; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 HackAI Real-time Systems Integration Demo</h1>
            <p>WebSockets • Server-Sent Events • PubSub • Streaming • Real-time Analytics</p>
            <span class="status healthy">SYSTEM HEALTHY</span>
        </div>

        <div class="section">
            <h2>📊 Real-time Metrics</h2>
            <div class="metrics">
                <div class="metric">
                    <h3>Active Connections</h3>
                    <div class="value" id="connections">0</div>
                </div>
                <div class="metric">
                    <h3>Messages/sec</h3>
                    <div class="value" id="messages">0</div>
                </div>
                <div class="metric">
                    <h3>Active Streams</h3>
                    <div class="value" id="streams">0</div>
                </div>
                <div class="metric">
                    <h3>Channels</h3>
                    <div class="value" id="channels">0</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🎮 Demo Controls</h2>
            <button onclick="connectWebSocket()">Connect WebSocket</button>
            <button onclick="connectSSE()">Connect Server-Sent Events</button>
            <button onclick="publishMessage()">Publish Message</button>
            <button onclick="createStream()">Create Stream</button>
            <button onclick="clearLog()">Clear Log</button>
        </div>

        <div class="section">
            <h2>📝 Real-time Event Log</h2>
            <div class="log" id="eventLog">
                <div>🚀 Real-time Systems Demo initialized...</div>
                <div>📡 Waiting for connections...</div>
            </div>
        </div>
    </div>

    <script>
        let ws = null;
        let eventSource = null;

        function log(message) {
            const logDiv = document.getElementById('eventLog');
            const timestamp = new Date().toLocaleTimeString();
            logDiv.innerHTML += '<div>[' + timestamp + '] ' + message + '</div>';
            logDiv.scrollTop = logDiv.scrollHeight;
        }

        function connectWebSocket() {
            if (ws) {
                ws.close();
            }
            
            ws = new WebSocket('ws://localhost:8080/ws');
            
            ws.onopen = function() {
                log('🔌 WebSocket connected');
                updateMetrics();
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                log('📨 WebSocket message: ' + JSON.stringify(data));
            };
            
            ws.onclose = function() {
                log('❌ WebSocket disconnected');
                updateMetrics();
            };
        }

        function connectSSE() {
            if (eventSource) {
                eventSource.close();
            }
            
            eventSource = new EventSource('http://localhost:8080/events');
            
            eventSource.onopen = function() {
                log('📡 Server-Sent Events connected');
            };
            
            eventSource.onmessage = function(event) {
                const data = JSON.parse(event.data);
                log('📨 SSE message: ' + JSON.stringify(data));
            };
            
            eventSource.onerror = function() {
                log('❌ SSE connection error');
            };
        }

        function publishMessage() {
            fetch('/demo/publish?channel=demo', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                log('📤 Message published: ' + JSON.stringify(data));
            })
            .catch(error => {
                log('❌ Publish error: ' + error);
            });
        }

        function createStream() {
            fetch('/demo/stream', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                log('🌊 Stream created: ' + JSON.stringify(data));
                updateMetrics();
            })
            .catch(error => {
                log('❌ Stream creation error: ' + error);
            });
        }

        function clearLog() {
            document.getElementById('eventLog').innerHTML = '';
        }

        function updateMetrics() {
            fetch('/api/realtime/status')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('connections').textContent = data.status.connections.total;
                    document.getElementById('streams').textContent = data.status.streams.total;
                    document.getElementById('channels').textContent = data.status.channels.total;
                    document.getElementById('messages').textContent = data.status.messages.total;
                }
            })
            .catch(error => {
                console.error('Metrics update error:', error);
            });
        }

        // Update metrics every 5 seconds
        setInterval(updateMetrics, 5000);
        
        // Initial metrics load
        updateMetrics();
        
        log('🎯 Demo dashboard loaded - ready for real-time action!');
    </script>
</body>
</html>
`
}
