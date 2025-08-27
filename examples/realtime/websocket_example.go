// Package: realtime
// Description: Comprehensive WebSocket real-time communication example
// Complexity: Intermediate
// Category: Real-time Communication

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/dimajoyti/hackai/pkg/langgraph/messaging"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/realtime"
)

// WebSocketExample demonstrates comprehensive real-time communication
func main() {
	fmt.Println("📡 HackAI WebSocket Real-time Communication Example")
	fmt.Println("==================================================")

	// Initialize logger
	logger, err := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
	})
	if err != nil {
		log.Fatal("Failed to initialize logger:", err)
	}

	// Initialize event system (simplified for demo)
	eventSystem := &messaging.EventSystem{}

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
			MaxMessageSize:    512 * 1024,
			EnableCompression: true,
		},
		StreamConfig: realtime.StreamConfig{
			BufferSize:        1000,
			FlushInterval:     5 * time.Second,
			MaxStreamAge:      1 * time.Hour,
			EnablePersistence: false,
			CompressionLevel:  1,
		},
		PubSubConfig: realtime.PubSubConfig{
			ChannelBufferSize: 100,
			SubscriberTimeout: 30 * time.Second,
			EnablePersistence: false,
			RetentionPeriod:   24 * time.Hour,
		},
		MaxConnections:      100,
		HeartbeatInterval:   30 * time.Second,
		MessageBufferSize:   1000,
		EnableAuth:          false, // Simplified for demo
		AllowedOrigins:      []string{"*"},
		RateLimitEnabled:    true,
		RateLimitRequests:   100,
		RateLimitWindow:     1 * time.Minute,
		MetricsEnabled:      true,
		HealthCheckInterval: 30 * time.Second,
	}

	// Create real-time system
	realtimeSystem := realtime.NewRealtimeSystem(realtimeConfig, nil, eventSystem, logger)

	// Start real-time system
	ctx := context.Background()
	if err := realtimeSystem.Start(ctx); err != nil {
		log.Fatal("Failed to start real-time system:", err)
	}
	defer realtimeSystem.Stop()

	// Setup HTTP server with WebSocket endpoints
	router := mux.NewRouter()

	// WebSocket endpoint
	router.HandleFunc("/ws", handleWebSocketConnection(realtimeSystem, logger)).Methods("GET")

	// Demo endpoints
	router.HandleFunc("/", serveDemoPage).Methods("GET")
	router.HandleFunc("/api/publish", handlePublishMessage(realtimeSystem)).Methods("POST")
	router.HandleFunc("/api/status", handleSystemStatus(realtimeSystem)).Methods("GET")

	// Start HTTP server
	server := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		fmt.Println("🌐 WebSocket server starting on :8080")
		fmt.Println("📊 Demo available at: http://localhost:8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("HTTP server failed:", err)
		}
	}()

	// Start demo message publisher
	go startDemoMessagePublisher(ctx, realtimeSystem, logger)

	// Wait for interrupt
	fmt.Println("Press Ctrl+C to stop...")
	select {}
}

// handleWebSocketConnection handles WebSocket upgrade and connection management
func handleWebSocketConnection(realtimeSystem *realtime.RealtimeSystem, logger *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Upgrade connection to WebSocket
		err := realtimeSystem.GetWebSocketManager().HandleUpgrade(w, r)
		if err != nil {
			logger.Error("WebSocket upgrade failed", "error", err)
			http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
			return
		}

		logger.Info("WebSocket connection established",
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent())
	}
}

// handlePublishMessage handles REST API message publishing
func handlePublishMessage(realtimeSystem *realtime.RealtimeSystem) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Channel string                 `json:"channel"`
			Message string                 `json:"message"`
			Data    map[string]interface{} `json:"data"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Prepare message data
		messageData := map[string]interface{}{
			"message":   request.Message,
			"timestamp": time.Now(),
			"source":    "rest_api",
		}

		// Merge additional data
		for k, v := range request.Data {
			messageData[k] = v
		}

		// Publish message
		err := realtimeSystem.PublishMessage(r.Context(), request.Channel, messageData)
		if err != nil {
			http.Error(w, "Failed to publish message", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Message published successfully",
			"channel": request.Channel,
		})
	}
}

// handleSystemStatus provides real-time system status
func handleSystemStatus(realtimeSystem *realtime.RealtimeSystem) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics := realtimeSystem.GetMetrics()
		connections := realtimeSystem.GetActiveConnections()

		status := map[string]interface{}{
			"status":              "healthy",
			"active_connections":  len(connections),
			"total_messages":      metrics.TotalMessages,
			"system_uptime":       metrics.SystemUptime,
			"last_activity":       metrics.LastActivity,
			"connections_by_type": groupConnectionsByType(connections),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}
}

// groupConnectionsByType groups connections by their type
func groupConnectionsByType(connections []*realtime.ConnectionInfo) map[string]int {
	groups := make(map[string]int)
	for _, conn := range connections {
		groups[string(conn.Type)]++
	}
	return groups
}

// startDemoMessagePublisher publishes demo messages periodically
func startDemoMessagePublisher(ctx context.Context, realtimeSystem *realtime.RealtimeSystem, logger *logger.Logger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	messageTypes := []struct {
		channel string
		data    map[string]interface{}
	}{
		{
			channel: "system-alerts",
			data: map[string]interface{}{
				"type":     "system_alert",
				"severity": "info",
				"message":  "System health check completed",
				"cpu":      45.2,
				"memory":   67.8,
			},
		},
		{
			channel: "security-events",
			data: map[string]interface{}{
				"type":       "security_event",
				"event_type": "login_attempt",
				"user":       "demo_user",
				"ip_address": "192.168.1.100",
				"success":    true,
			},
		},
		{
			channel: "analytics",
			data: map[string]interface{}{
				"type":         "analytics",
				"page_views":   1000 + (time.Now().Unix() % 500),
				"active_users": 150 + (time.Now().Unix() % 50),
				"bounce_rate":  0.25,
			},
		},
		{
			channel: "notifications",
			data: map[string]interface{}{
				"type":     "notification",
				"title":    "Demo Notification",
				"message":  "This is a demo real-time notification",
				"priority": "normal",
			},
		},
	}

	messageIndex := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			message := messageTypes[messageIndex%len(messageTypes)]

			// Add timestamp to message
			message.data["timestamp"] = time.Now()
			message.data["demo"] = true

			err := realtimeSystem.PublishMessage(ctx, message.channel, message.data)
			if err != nil {
				logger.Error("Failed to publish demo message", "error", err)
			} else {
				logger.Debug("Published demo message",
					"channel", message.channel,
					"type", message.data["type"])
			}

			messageIndex++
		}
	}
}

// serveDemoPage serves the interactive demo HTML page
func serveDemoPage(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>HackAI WebSocket Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .metric { background: #ecf0f1; padding: 15px; border-radius: 6px; text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #2c3e50; }
        .metric .value { font-size: 24px; font-weight: bold; color: #27ae60; }
        .log { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 6px; font-family: monospace; height: 300px; overflow-y: auto; }
        .controls { display: flex; gap: 10px; margin: 15px 0; }
        button { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #2980b9; }
        button:disabled { background: #bdc3c7; cursor: not-allowed; }
        .status { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .status.connected { background: #27ae60; color: white; }
        .status.disconnected { background: #e74c3c; color: white; }
        input, select { padding: 8px; border: 1px solid #ddd; border-radius: 4px; margin: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📡 HackAI WebSocket Real-time Communication Demo</h1>
            <p>Interactive demonstration of WebSocket communication, real-time messaging, and system monitoring</p>
            <span id="connectionStatus" class="status disconnected">DISCONNECTED</span>
        </div>

        <div class="section">
            <h2>📊 Real-time System Metrics</h2>
            <div class="metrics">
                <div class="metric">
                    <h3>Active Connections</h3>
                    <div class="value" id="activeConnections">0</div>
                </div>
                <div class="metric">
                    <h3>Total Messages</h3>
                    <div class="value" id="totalMessages">0</div>
                </div>
                <div class="metric">
                    <h3>System Uptime</h3>
                    <div class="value" id="systemUptime">0s</div>
                </div>
                <div class="metric">
                    <h3>Messages/min</h3>
                    <div class="value" id="messageRate">0</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🎮 WebSocket Controls</h2>
            <div class="controls">
                <button id="connectBtn" onclick="connectWebSocket()">Connect WebSocket</button>
                <button id="disconnectBtn" onclick="disconnectWebSocket()" disabled>Disconnect</button>
                <button onclick="subscribeToChannel()">Subscribe to Channel</button>
                <button onclick="publishMessage()">Publish Message</button>
                <button onclick="clearLog()">Clear Log</button>
            </div>
            
            <div class="controls">
                <input type="text" id="channelInput" placeholder="Channel name (e.g., notifications)" value="notifications">
                <input type="text" id="messageInput" placeholder="Message content" value="Hello from WebSocket!">
                <select id="messageType">
                    <option value="notification">Notification</option>
                    <option value="alert">Alert</option>
                    <option value="data">Data</option>
                    <option value="command">Command</option>
                </select>
            </div>
        </div>

        <div class="section">
            <h2>📝 Real-time Message Log</h2>
            <div class="log" id="messageLog">
                <div>🚀 WebSocket Demo initialized...</div>
                <div>📡 Ready to connect to WebSocket server...</div>
            </div>
        </div>
    </div>

    <script>
        let ws = null;
        let messageCount = 0;
        let startTime = Date.now();

        function log(message, type = 'info') {
            const logDiv = document.getElementById('messageLog');
            const timestamp = new Date().toLocaleTimeString();
            const icon = type === 'error' ? '❌' : type === 'success' ? '✅' : '📨';
            logDiv.innerHTML += '<div>[' + timestamp + '] ' + icon + ' ' + message + '</div>';
            logDiv.scrollTop = logDiv.scrollHeight;
        }

        function updateConnectionStatus(connected) {
            const statusEl = document.getElementById('connectionStatus');
            const connectBtn = document.getElementById('connectBtn');
            const disconnectBtn = document.getElementById('disconnectBtn');
            
            if (connected) {
                statusEl.textContent = 'CONNECTED';
                statusEl.className = 'status connected';
                connectBtn.disabled = true;
                disconnectBtn.disabled = false;
            } else {
                statusEl.textContent = 'DISCONNECTED';
                statusEl.className = 'status disconnected';
                connectBtn.disabled = false;
                disconnectBtn.disabled = true;
            }
        }

        function connectWebSocket() {
            if (ws) {
                ws.close();
            }
            
            ws = new WebSocket('ws://localhost:8080/ws');
            
            ws.onopen = function() {
                log('WebSocket connected successfully', 'success');
                updateConnectionStatus(true);
                updateMetrics();
            };
            
            ws.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    messageCount++;
                    log('Received: ' + JSON.stringify(data, null, 2));
                    updateMessageRate();
                } catch (e) {
                    log('Received (raw): ' + event.data);
                }
            };
            
            ws.onclose = function() {
                log('WebSocket connection closed', 'error');
                updateConnectionStatus(false);
            };
            
            ws.onerror = function(error) {
                log('WebSocket error: ' + error, 'error');
                updateConnectionStatus(false);
            };
        }

        function disconnectWebSocket() {
            if (ws) {
                ws.close();
                ws = null;
            }
        }

        function subscribeToChannel() {
            const channel = document.getElementById('channelInput').value;
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                log('WebSocket not connected', 'error');
                return;
            }

            const message = {
                type: 'subscribe',
                channel: channel
            };

            ws.send(JSON.stringify(message));
            log('Subscribed to channel: ' + channel, 'success');
        }

        function publishMessage() {
            const channel = document.getElementById('channelInput').value;
            const message = document.getElementById('messageInput').value;
            const type = document.getElementById('messageType').value;

            fetch('/api/publish', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    channel: channel,
                    message: message,
                    data: {
                        type: type,
                        source: 'web_demo'
                    }
                })
            })
            .then(response => response.json())
            .then(data => {
                log('Message published via REST API: ' + JSON.stringify(data), 'success');
            })
            .catch(error => {
                log('Publish error: ' + error, 'error');
            });
        }

        function clearLog() {
            document.getElementById('messageLog').innerHTML = '';
        }

        function updateMetrics() {
            fetch('/api/status')
            .then(response => response.json())
            .then(data => {
                document.getElementById('activeConnections').textContent = data.active_connections;
                document.getElementById('totalMessages').textContent = data.total_messages;
                
                const uptimeSeconds = Math.floor(data.system_uptime / 1000000000);
                document.getElementById('systemUptime').textContent = uptimeSeconds + 's';
            })
            .catch(error => {
                console.error('Metrics update error:', error);
            });
        }

        function updateMessageRate() {
            const elapsed = (Date.now() - startTime) / 1000 / 60; // minutes
            const rate = elapsed > 0 ? Math.round(messageCount / elapsed) : 0;
            document.getElementById('messageRate').textContent = rate;
        }

        // Update metrics every 5 seconds
        setInterval(updateMetrics, 5000);
        
        // Initial metrics load
        updateMetrics();
        
        log('🎯 WebSocket demo ready - click Connect to start!');
    </script>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}
