package realtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var streamingAPITracer = otel.Tracer("hackai/realtime/streaming-api")

// StreamingAPIHandler provides HTTP handlers for real-time streaming APIs
type StreamingAPIHandler struct {
	realtimeSystem         *RealtimeSystem
	threatStreamer         *ThreatIntelligenceStreamer
	logger                 *logger.Logger
	upgrader               websocket.Upgrader
	activeSSEConnections   map[string]*SSEConnection
	streamingConnections   map[string]*StreamingConnection
	connectionsMutex       map[string]interface{}
}

// SSEConnection represents a Server-Sent Events connection
type SSEConnection struct {
	ID            string
	Writer        http.ResponseWriter
	Flusher       http.Flusher
	Context       context.Context
	Cancel        context.CancelFunc
	Channels      []string
	LastEventID   string
	ConnectedAt   time.Time
	LastActivity  time.Time
}

// StreamingConnection represents a streaming connection
type StreamingConnection struct {
	ID           string
	Type         string
	Context      context.Context
	Cancel       context.CancelFunc
	DataChannel  chan interface{}
	ConnectedAt  time.Time
	LastActivity time.Time
	Metadata     map[string]interface{}
}

// StreamingAPIConfig configuration for streaming API
type StreamingAPIConfig struct {
	EnableCORS            bool          `json:"enable_cors"`
	AllowedOrigins        []string      `json:"allowed_origins"`
	SSEHeartbeatInterval  time.Duration `json:"sse_heartbeat_interval"`
	SSEConnectionTimeout  time.Duration `json:"sse_connection_timeout"`
	MaxSSEConnections     int           `json:"max_sse_connections"`
	StreamBufferSize      int           `json:"stream_buffer_size"`
	EnableAuthentication  bool          `json:"enable_authentication"`
	RateLimitRequests     int           `json:"rate_limit_requests"`
	RateLimitWindow       time.Duration `json:"rate_limit_window"`
}

// StreamRequest represents a request to create/manage streams
type StreamRequest struct {
	StreamType   string                 `json:"stream_type"`
	Channels     []string               `json:"channels"`
	Filters      map[string]interface{} `json:"filters,omitempty"`
	Options      map[string]interface{} `json:"options,omitempty"`
	LastEventID  string                 `json:"last_event_id,omitempty"`
}

// StreamResponse represents a streaming response
type StreamResponse struct {
	Success   bool                   `json:"success"`
	StreamID  string                 `json:"stream_id,omitempty"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// NewStreamingAPIHandler creates a new streaming API handler
func NewStreamingAPIHandler(
	realtimeSystem *RealtimeSystem,
	threatStreamer *ThreatIntelligenceStreamer,
	logger *logger.Logger,
) *StreamingAPIHandler {
	return &StreamingAPIHandler{
		realtimeSystem:       realtimeSystem,
		threatStreamer:       threatStreamer,
		logger:               logger,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				// Allow all origins for now - should be configurable
				return true
			},
		},
		activeSSEConnections: make(map[string]*SSEConnection),
		streamingConnections: make(map[string]*StreamingConnection),
		connectionsMutex:     make(map[string]interface{}),
	}
}

// RegisterStreamingRoutes registers all streaming API routes
func (sah *StreamingAPIHandler) RegisterStreamingRoutes(router *mux.Router) {
	// WebSocket endpoints
	router.HandleFunc("/api/stream/ws", sah.handleWebSocketConnection).Methods("GET")
	router.HandleFunc("/api/stream/ws/{stream_type}", sah.handleTypedWebSocketConnection).Methods("GET")
	
	// Server-Sent Events endpoints
	router.HandleFunc("/api/stream/events", sah.handleSSEConnection).Methods("GET")
	router.HandleFunc("/api/stream/events/{channels}", sah.handleChannelSSE).Methods("GET")
	
	// REST API endpoints
	router.HandleFunc("/api/stream/publish", sah.handlePublishMessage).Methods("POST")
	router.HandleFunc("/api/stream/publish/{channel}", sah.handleChannelPublish).Methods("POST")
	
	// Stream management endpoints
	router.HandleFunc("/api/stream/create", sah.handleCreateStream).Methods("POST")
	router.HandleFunc("/api/stream/subscribe", sah.handleSubscribe).Methods("POST")
	router.HandleFunc("/api/stream/unsubscribe", sah.handleUnsubscribe).Methods("POST")
	
	// Threat intelligence streaming endpoints
	router.HandleFunc("/api/stream/threat/ioc", sah.handleIOCStream).Methods("GET", "POST")
	router.HandleFunc("/api/stream/threat/cve", sah.handleCVEStream).Methods("GET", "POST")
	router.HandleFunc("/api/stream/threat/mitre", sah.handleMITREStream).Methods("GET", "POST")
	router.HandleFunc("/api/stream/threat/alerts", sah.handleAlertsStream).Methods("GET", "POST")
	router.HandleFunc("/api/stream/threat/metrics", sah.handleMetricsStream).Methods("GET")
	
	// Status and monitoring endpoints
	router.HandleFunc("/api/stream/status", sah.handleStreamStatus).Methods("GET")
	router.HandleFunc("/api/stream/connections", sah.handleActiveConnections).Methods("GET")
	router.HandleFunc("/api/stream/health", sah.handleStreamHealth).Methods("GET")
	
	sah.logger.Info("Streaming API routes registered")
}

// WebSocket handlers
func (sah *StreamingAPIHandler) handleWebSocketConnection(w http.ResponseWriter, r *http.Request) {
	ctx, span := streamingAPITracer.Start(r.Context(), "websocket_connection")
	defer span.End()

	conn, err := sah.upgrader.Upgrade(w, r, nil)
	if err != nil {
		sah.logger.Error("WebSocket upgrade failed", "error", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}

	connectionID := fmt.Sprintf("ws_%d", time.Now().UnixNano())
	
	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("connection_type", "websocket"),
	)

	sah.handleWebSocketClient(ctx, conn, connectionID)
}

func (sah *StreamingAPIHandler) handleTypedWebSocketConnection(w http.ResponseWriter, r *http.Request) {
	ctx, span := streamingAPITracer.Start(r.Context(), "typed_websocket_connection")
	defer span.End()

	vars := mux.Vars(r)
	streamType := vars["stream_type"]

	conn, err := sah.upgrader.Upgrade(w, r, nil)
	if err != nil {
		sah.logger.Error("WebSocket upgrade failed", "error", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}

	connectionID := fmt.Sprintf("ws_%s_%d", streamType, time.Now().UnixNano())
	
	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("stream_type", streamType),
	)

	// Auto-subscribe to the specified stream type
	channel := fmt.Sprintf("threat.%s", streamType)
	sah.realtimeSystem.Subscribe(ctx, connectionID, channel)

	sah.handleWebSocketClient(ctx, conn, connectionID)
}

func (sah *StreamingAPIHandler) handleWebSocketClient(ctx context.Context, conn *websocket.Conn, connectionID string) {
	defer conn.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle incoming messages
	go func() {
		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				sah.logger.Debug("WebSocket read error", "error", err, "connection_id", connectionID)
				return
			}

			if messageType == websocket.TextMessage {
				sah.handleWebSocketMessage(ctx, conn, connectionID, message)
			}
		}
	}()

	// Send periodic ping messages
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				sah.logger.Debug("WebSocket ping failed", "error", err, "connection_id", connectionID)
				return
			}
		}
	}
}

func (sah *StreamingAPIHandler) handleWebSocketMessage(ctx context.Context, conn *websocket.Conn, connectionID string, message []byte) {
	var request map[string]interface{}
	if err := json.Unmarshal(message, &request); err != nil {
		sah.logger.Error("Invalid JSON in WebSocket message", "error", err)
		return
	}

	action, ok := request["action"].(string)
	if !ok {
		sah.logger.Error("Missing action in WebSocket message")
		return
	}

	switch action {
	case "subscribe":
		if channel, ok := request["channel"].(string); ok {
			sah.realtimeSystem.Subscribe(ctx, connectionID, channel)
			response := map[string]interface{}{
				"type":    "subscribe_response",
				"channel": channel,
				"status":  "subscribed",
			}
			sah.sendWebSocketMessage(conn, response)
		}
	case "unsubscribe":
		if channel, ok := request["channel"].(string); ok {
			sah.realtimeSystem.Unsubscribe(ctx, connectionID, channel)
			response := map[string]interface{}{
				"type":    "unsubscribe_response",
				"channel": channel,
				"status":  "unsubscribed",
			}
			sah.sendWebSocketMessage(conn, response)
		}
	case "publish":
		if channel, ok := request["channel"].(string); ok {
			if data, ok := request["data"].(map[string]interface{}); ok {
				sah.realtimeSystem.PublishMessage(ctx, channel, data)
			}
		}
	}
}

func (sah *StreamingAPIHandler) sendWebSocketMessage(conn *websocket.Conn, message interface{}) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}

// Server-Sent Events handlers
func (sah *StreamingAPIHandler) handleSSEConnection(w http.ResponseWriter, r *http.Request) {
	ctx, span := streamingAPITracer.Start(r.Context(), "sse_connection")
	defer span.End()

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Cache-Control")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	connectionID := fmt.Sprintf("sse_%d", time.Now().UnixNano())
	ctx, cancel := context.WithCancel(ctx)

	connection := &SSEConnection{
		ID:           connectionID,
		Writer:       w,
		Flusher:      flusher,
		Context:      ctx,
		Cancel:       cancel,
		Channels:     []string{"*"}, // Subscribe to all channels
		ConnectedAt:  time.Now(),
		LastActivity: time.Now(),
	}

	sah.activeSSEConnections[connectionID] = connection

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("connection_type", "sse"),
	)

	// Send initial connection message
	sah.sendSSEMessage(connection, "connected", map[string]interface{}{
		"connection_id": connectionID,
		"timestamp":     time.Now(),
		"message":       "SSE connection established",
	})

	// Handle the connection
	sah.handleSSEClient(ctx, connection)

	// Clean up on disconnect
	delete(sah.activeSSEConnections, connectionID)
}

func (sah *StreamingAPIHandler) handleChannelSSE(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	_ = vars["channels"] // TODO: Use channels for filtering specific channel subscriptions
	
	// Similar to handleSSEConnection but with specific channels
	// Implementation would filter messages based on channels
	sah.handleSSEConnection(w, r)
}

func (sah *StreamingAPIHandler) handleSSEClient(ctx context.Context, connection *SSEConnection) {
	// Send periodic heartbeat
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sah.sendSSEMessage(connection, "heartbeat", map[string]interface{}{
				"timestamp": time.Now(),
				"status":    "alive",
			})
		}
	}
}

func (sah *StreamingAPIHandler) sendSSEMessage(connection *SSEConnection, eventType string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(connection.Writer, "event: %s\ndata: %s\n\n", eventType, string(jsonData))
	if err != nil {
		return err
	}

	connection.Flusher.Flush()
	connection.LastActivity = time.Now()
	return nil
}

// REST API handlers
func (sah *StreamingAPIHandler) handlePublishMessage(w http.ResponseWriter, r *http.Request) {
	ctx, span := streamingAPITracer.Start(r.Context(), "publish_message")
	defer span.End()

	var request struct {
		Channel string                 `json:"channel"`
		Data    map[string]interface{} `json:"data"`
		Type    string                 `json:"type,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if request.Channel == "" {
		http.Error(w, "Channel is required", http.StatusBadRequest)
		return
	}

	err := sah.realtimeSystem.PublishMessage(ctx, request.Channel, request.Data)
	if err != nil {
		sah.logger.Error("Failed to publish message", "error", err)
		http.Error(w, "Failed to publish message", http.StatusInternalServerError)
		return
	}

	response := StreamResponse{
		Success:   true,
		Message:   "Message published successfully",
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sah *StreamingAPIHandler) handleChannelPublish(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channel := vars["channel"]

	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	err := sah.realtimeSystem.PublishMessage(r.Context(), channel, data)
	if err != nil {
		http.Error(w, "Failed to publish message", http.StatusInternalServerError)
		return
	}

	response := StreamResponse{
		Success:   true,
		Message:   fmt.Sprintf("Message published to channel %s", channel),
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Stream management handlers
func (sah *StreamingAPIHandler) handleCreateStream(w http.ResponseWriter, r *http.Request) {
	var request StreamRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Create stream in stream manager
	stream, err := sah.realtimeSystem.GetStreamManager().CreateStream(
		r.Context(),
		fmt.Sprintf("api-stream-%d", time.Now().UnixNano()),
		"API created stream",
		StreamType(request.StreamType),
	)
	if err != nil {
		http.Error(w, "Failed to create stream", http.StatusInternalServerError)
		return
	}

	response := StreamResponse{
		Success:  true,
		StreamID: stream.ID,
		Message:  "Stream created successfully",
		Data: map[string]interface{}{
			"stream_id":   stream.ID,
			"stream_type": request.StreamType,
			"created_at":  stream.CreatedAt,
		},
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sah *StreamingAPIHandler) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ConnectionID string   `json:"connection_id"`
		Channels     []string `json:"channels"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	for _, channel := range request.Channels {
		err := sah.realtimeSystem.Subscribe(r.Context(), request.ConnectionID, channel)
		if err != nil {
			sah.logger.Error("Failed to subscribe to channel", "error", err, "channel", channel)
		}
	}

	response := StreamResponse{
		Success:   true,
		Message:   fmt.Sprintf("Subscribed to %d channels", len(request.Channels)),
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sah *StreamingAPIHandler) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ConnectionID string   `json:"connection_id"`
		Channels     []string `json:"channels"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	for _, channel := range request.Channels {
		err := sah.realtimeSystem.Unsubscribe(r.Context(), request.ConnectionID, channel)
		if err != nil {
			sah.logger.Error("Failed to unsubscribe from channel", "error", err, "channel", channel)
		}
	}

	response := StreamResponse{
		Success:   true,
		Message:   fmt.Sprintf("Unsubscribed from %d channels", len(request.Channels)),
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Threat intelligence streaming handlers
func (sah *StreamingAPIHandler) handleIOCStream(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		sah.handleThreatStreamSubscription(w, r, "ioc")
	} else if r.Method == "POST" {
		sah.handleIOCStreamPublish(w, r)
	}
}

func (sah *StreamingAPIHandler) handleIOCStreamPublish(w http.ResponseWriter, r *http.Request) {
	var indicator ThreatIndicator
	if err := json.NewDecoder(r.Body).Decode(&indicator); err != nil {
		http.Error(w, "Invalid IOC data", http.StatusBadRequest)
		return
	}

	err := sah.threatStreamer.CreateIOCStream(r.Context(), &indicator)
	if err != nil {
		http.Error(w, "Failed to create IOC stream", http.StatusInternalServerError)
		return
	}

	response := StreamResponse{
		Success:   true,
		Message:   "IOC stream event created",
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sah *StreamingAPIHandler) handleCVEStream(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		sah.handleThreatStreamSubscription(w, r, "cve")
	} else if r.Method == "POST" {
		sah.handleCVEStreamPublish(w, r)
	}
}

func (sah *StreamingAPIHandler) handleCVEStreamPublish(w http.ResponseWriter, r *http.Request) {
	var request struct {
		CVEID          string             `json:"cve_id"`
		Vulnerability  VulnerabilityInfo  `json:"vulnerability"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid CVE data", http.StatusBadRequest)
		return
	}

	err := sah.threatStreamer.CreateCVEStream(r.Context(), request.CVEID, &request.Vulnerability)
	if err != nil {
		http.Error(w, "Failed to create CVE stream", http.StatusInternalServerError)
		return
	}

	response := StreamResponse{
		Success:   true,
		Message:   "CVE stream event created",
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sah *StreamingAPIHandler) handleMITREStream(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		sah.handleThreatStreamSubscription(w, r, "mitre")
	} else if r.Method == "POST" {
		sah.handleMITREStreamPublish(w, r)
	}
}

func (sah *StreamingAPIHandler) handleMITREStreamPublish(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Tactic    string                 `json:"tactic"`
		Technique string                 `json:"technique"`
		Details   map[string]interface{} `json:"details"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid MITRE data", http.StatusBadRequest)
		return
	}

	err := sah.threatStreamer.CreateMITREStream(r.Context(), request.Tactic, request.Technique, request.Details)
	if err != nil {
		http.Error(w, "Failed to create MITRE stream", http.StatusInternalServerError)
		return
	}

	response := StreamResponse{
		Success:   true,
		Message:   "MITRE stream event created",
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sah *StreamingAPIHandler) handleAlertsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		sah.handleThreatStreamSubscription(w, r, "alerts")
	} else if r.Method == "POST" {
		sah.handleAlertStreamPublish(w, r)
	}
}

func (sah *StreamingAPIHandler) handleAlertStreamPublish(w http.ResponseWriter, r *http.Request) {
	var request struct {
		AlertType   string  `json:"alert_type"`
		Title       string  `json:"title"`
		Description string  `json:"description"`
		Severity    string  `json:"severity"`
		Confidence  float64 `json:"confidence"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid alert data", http.StatusBadRequest)
		return
	}

	err := sah.threatStreamer.CreateAlertStream(r.Context(), request.AlertType, request.Title, request.Description, request.Severity, request.Confidence)
	if err != nil {
		http.Error(w, "Failed to create alert stream", http.StatusInternalServerError)
		return
	}

	response := StreamResponse{
		Success:   true,
		Message:   "Alert stream event created",
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sah *StreamingAPIHandler) handleMetricsStream(w http.ResponseWriter, r *http.Request) {
	sah.handleThreatStreamSubscription(w, r, "metrics")
}

func (sah *StreamingAPIHandler) handleThreatStreamSubscription(w http.ResponseWriter, r *http.Request, streamType string) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	connectionID := fmt.Sprintf("threat_%s_%d", streamType, time.Now().UnixNano())
	channel := fmt.Sprintf("threat.%s", streamType)

	// Subscribe to the threat stream
	err := sah.realtimeSystem.Subscribe(r.Context(), connectionID, channel)
	if err != nil {
		http.Error(w, "Failed to subscribe to stream", http.StatusInternalServerError)
		return
	}

	// Send initial message
	initialMessage := map[string]interface{}{
		"type":          "subscription_confirmed",
		"stream_type":   streamType,
		"connection_id": connectionID,
		"timestamp":     time.Now(),
	}

	data, _ := json.Marshal(initialMessage)
	fmt.Fprintf(w, "data: %s\n\n", string(data))
	flusher.Flush()

	// Keep connection alive
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			sah.realtimeSystem.Unsubscribe(context.Background(), connectionID, channel)
			return
		case <-ticker.C:
			heartbeat := map[string]interface{}{
				"type":      "heartbeat",
				"timestamp": time.Now(),
			}
			data, _ := json.Marshal(heartbeat)
			fmt.Fprintf(w, "event: heartbeat\ndata: %s\n\n", string(data))
			flusher.Flush()
		}
	}
}

// Status and monitoring handlers
func (sah *StreamingAPIHandler) handleStreamStatus(w http.ResponseWriter, r *http.Request) {
	metrics := sah.realtimeSystem.GetMetrics()

	status := map[string]interface{}{
		"success": true,
		"status": map[string]interface{}{
			"connections": map[string]interface{}{
				"total":     metrics.ActiveConnections,
				"websocket": len(sah.streamingConnections),
				"sse":       len(sah.activeSSEConnections),
			},
			"streams": map[string]interface{}{
				"total": 0, // Would get from stream manager
			},
			"channels": map[string]interface{}{
				"total": metrics.ChannelSubscriptions,
			},
			"messages": map[string]interface{}{
				"total": metrics.TotalMessages,
			},
			"uptime": metrics.SystemUptime.Seconds(),
		},
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (sah *StreamingAPIHandler) handleActiveConnections(w http.ResponseWriter, r *http.Request) {
	connections := sah.realtimeSystem.GetActiveConnections()

	response := map[string]interface{}{
		"success":     true,
		"connections": connections,
		"count":       len(connections),
		"timestamp":   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sah *StreamingAPIHandler) handleStreamHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"success": true,
		"health": map[string]interface{}{
			"realtime_system":   "healthy",
			"threat_streamer":   "healthy",
			"websocket_manager": "healthy",
			"stream_manager":    "healthy",
		},
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// Helper methods
func (sah *StreamingAPIHandler) enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Request-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}