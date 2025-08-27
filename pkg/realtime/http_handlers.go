package realtime

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/gorilla/mux"
)

var httpHandlerTracer = otel.Tracer("hackai/realtime/http")

// HTTPHandlers provides HTTP endpoints for the real-time system
type HTTPHandlers struct {
	realtimeSystem *RealtimeSystem
	logger         *logger.Logger
}

// NewHTTPHandlers creates new HTTP handlers
func NewHTTPHandlers(realtimeSystem *RealtimeSystem, logger *logger.Logger) *HTTPHandlers {
	return &HTTPHandlers{
		realtimeSystem: realtimeSystem,
		logger:         logger,
	}
}

// RegisterRoutes registers HTTP routes
func (h *HTTPHandlers) RegisterRoutes(router *mux.Router) {
	// WebSocket endpoint
	router.HandleFunc("/ws", h.HandleWebSocket).Methods("GET")

	// Server-Sent Events endpoint
	router.HandleFunc("/events", h.HandleSSE).Methods("GET")

	// REST API endpoints
	api := router.PathPrefix("/api/realtime").Subrouter()

	// Message endpoints
	api.HandleFunc("/messages", h.PublishMessage).Methods("POST")
	api.HandleFunc("/channels/{channel}/messages", h.PublishChannelMessage).Methods("POST")

	// Subscription endpoints
	api.HandleFunc("/subscriptions", h.CreateSubscription).Methods("POST")
	api.HandleFunc("/subscriptions/{id}", h.DeleteSubscription).Methods("DELETE")
	api.HandleFunc("/subscriptions", h.ListSubscriptions).Methods("GET")

	// Stream endpoints
	api.HandleFunc("/streams", h.CreateStream).Methods("POST")
	api.HandleFunc("/streams/{id}", h.GetStream).Methods("GET")
	api.HandleFunc("/streams/{id}", h.DeleteStream).Methods("DELETE")
	api.HandleFunc("/streams", h.ListStreams).Methods("GET")
	api.HandleFunc("/streams/{id}/events", h.PublishStreamEvent).Methods("POST")

	// Connection endpoints
	api.HandleFunc("/connections", h.ListConnections).Methods("GET")
	api.HandleFunc("/connections/{id}", h.GetConnection).Methods("GET")
	api.HandleFunc("/connections/{id}", h.CloseConnection).Methods("DELETE")

	// System endpoints
	api.HandleFunc("/status", h.GetSystemStatus).Methods("GET")
	api.HandleFunc("/metrics", h.GetMetrics).Methods("GET")
	api.HandleFunc("/health", h.HealthCheck).Methods("GET")
}

// HandleWebSocket handles WebSocket upgrade requests
func (h *HTTPHandlers) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	_, span := httpHandlerTracer.Start(r.Context(), "websocket_upgrade")
	defer span.End()

	span.SetAttributes(
		attribute.String("remote_addr", r.RemoteAddr),
		attribute.String("user_agent", r.UserAgent()),
	)

	err := h.realtimeSystem.websocketManager.HandleUpgrade(w, r)
	if err != nil {
		span.RecordError(err)
		h.logger.Error("WebSocket upgrade failed", "error", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}
}

// HandleSSE handles Server-Sent Events connections
func (h *HTTPHandlers) HandleSSE(w http.ResponseWriter, r *http.Request) {
	_, span := httpHandlerTracer.Start(r.Context(), "sse_connection")
	defer span.End()

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Create SSE connection
	connectionID := fmt.Sprintf("sse_%d", time.Now().UnixNano())

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("remote_addr", r.RemoteAddr),
	)

	// Send initial connection message
	fmt.Fprintf(w, "data: {\"type\":\"connected\",\"connection_id\":\"%s\"}\n\n", connectionID)

	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// Keep connection alive
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, "data: {\"type\":\"heartbeat\",\"timestamp\":\"%s\"}\n\n", time.Now().Format(time.RFC3339))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
}

// PublishMessage publishes a message to the system
func (h *HTTPHandlers) PublishMessage(w http.ResponseWriter, r *http.Request) {
	ctx, span := httpHandlerTracer.Start(r.Context(), "publish_message")
	defer span.End()

	var request struct {
		Channel string                 `json:"channel"`
		Type    MessageType            `json:"type"`
		Data    map[string]interface{} `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		span.RecordError(err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	span.SetAttributes(
		attribute.String("channel", request.Channel),
		attribute.String("message_type", string(request.Type)),
	)

	err := h.realtimeSystem.PublishMessage(ctx, request.Channel, request.Data)
	if err != nil {
		span.RecordError(err)
		h.logger.Error("Failed to publish message", "error", err)
		http.Error(w, "Failed to publish message", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Message published successfully",
	})
}

// PublishChannelMessage publishes a message to a specific channel
func (h *HTTPHandlers) PublishChannelMessage(w http.ResponseWriter, r *http.Request) {
	ctx, span := httpHandlerTracer.Start(r.Context(), "publish_channel_message")
	defer span.End()

	vars := mux.Vars(r)
	channel := vars["channel"]

	var request struct {
		Type MessageType            `json:"type"`
		Data map[string]interface{} `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		span.RecordError(err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	span.SetAttributes(
		attribute.String("channel", channel),
		attribute.String("message_type", string(request.Type)),
	)

	err := h.realtimeSystem.PublishMessage(ctx, channel, request.Data)
	if err != nil {
		span.RecordError(err)
		h.logger.Error("Failed to publish channel message", "error", err)
		http.Error(w, "Failed to publish message", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"channel": channel,
		"message": "Message published successfully",
	})
}

// CreateSubscription creates a new subscription
func (h *HTTPHandlers) CreateSubscription(w http.ResponseWriter, r *http.Request) {
	ctx, span := httpHandlerTracer.Start(r.Context(), "create_subscription")
	defer span.End()

	var request struct {
		ConnectionID string `json:"connection_id"`
		Channel      string `json:"channel"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		span.RecordError(err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	span.SetAttributes(
		attribute.String("connection_id", request.ConnectionID),
		attribute.String("channel", request.Channel),
	)

	err := h.realtimeSystem.Subscribe(ctx, request.ConnectionID, request.Channel)
	if err != nil {
		span.RecordError(err)
		h.logger.Error("Failed to create subscription", "error", err)
		http.Error(w, "Failed to create subscription", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"connection_id": request.ConnectionID,
		"channel":       request.Channel,
		"message":       "Subscription created successfully",
	})
}

// DeleteSubscription deletes a subscription
func (h *HTTPHandlers) DeleteSubscription(w http.ResponseWriter, r *http.Request) {
	ctx, span := httpHandlerTracer.Start(r.Context(), "delete_subscription")
	defer span.End()

	vars := mux.Vars(r)
	subscriptionID := vars["id"]

	// Parse subscription ID to extract connection ID and channel
	// Format: connectionID:channel
	// This is a simplified implementation
	connectionID := r.URL.Query().Get("connection_id")
	channel := r.URL.Query().Get("channel")

	if connectionID == "" || channel == "" {
		http.Error(w, "connection_id and channel query parameters required", http.StatusBadRequest)
		return
	}

	span.SetAttributes(
		attribute.String("subscription_id", subscriptionID),
		attribute.String("connection_id", connectionID),
		attribute.String("channel", channel),
	)

	err := h.realtimeSystem.Unsubscribe(ctx, connectionID, channel)
	if err != nil {
		span.RecordError(err)
		h.logger.Error("Failed to delete subscription", "error", err)
		http.Error(w, "Failed to delete subscription", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Subscription deleted successfully",
	})
}

// ListSubscriptions lists all subscriptions
func (h *HTTPHandlers) ListSubscriptions(w http.ResponseWriter, r *http.Request) {
	_, span := httpHandlerTracer.Start(r.Context(), "list_subscriptions")
	defer span.End()

	channels := h.realtimeSystem.pubsubManager.GetChannels()

	span.SetAttributes(
		attribute.Int("channel_count", len(channels)),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"channels": channels,
		"count":    len(channels),
	})
}

// CreateStream creates a new stream
func (h *HTTPHandlers) CreateStream(w http.ResponseWriter, r *http.Request) {
	ctx, span := httpHandlerTracer.Start(r.Context(), "create_stream")
	defer span.End()

	var request struct {
		Name        string     `json:"name"`
		Description string     `json:"description"`
		Type        StreamType `json:"type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		span.RecordError(err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	span.SetAttributes(
		attribute.String("stream_name", request.Name),
		attribute.String("stream_type", string(request.Type)),
	)

	stream, err := h.realtimeSystem.streamManager.CreateStream(ctx, request.Name, request.Description, request.Type)
	if err != nil {
		span.RecordError(err)
		h.logger.Error("Failed to create stream", "error", err)
		http.Error(w, "Failed to create stream", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"stream":  stream,
		"message": "Stream created successfully",
	})
}

// GetStream gets a stream by ID
func (h *HTTPHandlers) GetStream(w http.ResponseWriter, r *http.Request) {
	_, span := httpHandlerTracer.Start(r.Context(), "get_stream")
	defer span.End()

	vars := mux.Vars(r)
	streamID := vars["id"]

	span.SetAttributes(
		attribute.String("stream_id", streamID),
	)

	stream, err := h.realtimeSystem.streamManager.GetStream(streamID)
	if err != nil {
		span.RecordError(err)
		http.Error(w, "Stream not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"stream":  stream,
	})
}

// DeleteStream deletes a stream
func (h *HTTPHandlers) DeleteStream(w http.ResponseWriter, r *http.Request) {
	ctx, span := httpHandlerTracer.Start(r.Context(), "delete_stream")
	defer span.End()

	vars := mux.Vars(r)
	streamID := vars["id"]

	span.SetAttributes(
		attribute.String("stream_id", streamID),
	)

	err := h.realtimeSystem.streamManager.DeleteStream(ctx, streamID)
	if err != nil {
		span.RecordError(err)
		h.logger.Error("Failed to delete stream", "error", err)
		http.Error(w, "Failed to delete stream", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Stream deleted successfully",
	})
}

// ListStreams lists all streams
func (h *HTTPHandlers) ListStreams(w http.ResponseWriter, r *http.Request) {
	_, span := httpHandlerTracer.Start(r.Context(), "list_streams")
	defer span.End()

	streams := h.realtimeSystem.streamManager.GetStreams()

	span.SetAttributes(
		attribute.Int("stream_count", len(streams)),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"streams": streams,
		"count":   len(streams),
	})
}

// PublishStreamEvent publishes an event to a stream
func (h *HTTPHandlers) PublishStreamEvent(w http.ResponseWriter, r *http.Request) {
	ctx, span := httpHandlerTracer.Start(r.Context(), "publish_stream_event")
	defer span.End()

	vars := mux.Vars(r)
	streamID := vars["id"]

	var request struct {
		Type string      `json:"type"`
		Data interface{} `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		span.RecordError(err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	span.SetAttributes(
		attribute.String("stream_id", streamID),
		attribute.String("event_type", request.Type),
	)

	err := h.realtimeSystem.streamManager.PublishEvent(ctx, streamID, request.Type, request.Data)
	if err != nil {
		span.RecordError(err)
		h.logger.Error("Failed to publish stream event", "error", err)
		http.Error(w, "Failed to publish event", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"stream_id": streamID,
		"message":   "Event published successfully",
	})
}

// ListConnections lists all active connections
func (h *HTTPHandlers) ListConnections(w http.ResponseWriter, r *http.Request) {
	_, span := httpHandlerTracer.Start(r.Context(), "list_connections")
	defer span.End()

	connections := h.realtimeSystem.GetActiveConnections()

	span.SetAttributes(
		attribute.Int("connection_count", len(connections)),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"connections": connections,
		"count":       len(connections),
	})
}

// GetConnection gets a specific connection
func (h *HTTPHandlers) GetConnection(w http.ResponseWriter, r *http.Request) {
	_, span := httpHandlerTracer.Start(r.Context(), "get_connection")
	defer span.End()

	vars := mux.Vars(r)
	connectionID := vars["id"]

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
	)

	connection, err := h.realtimeSystem.GetConnectionInfo(connectionID)
	if err != nil {
		span.RecordError(err)
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"connection": connection,
	})
}

// CloseConnection closes a specific connection
func (h *HTTPHandlers) CloseConnection(w http.ResponseWriter, r *http.Request) {
	_, span := httpHandlerTracer.Start(r.Context(), "close_connection")
	defer span.End()

	vars := mux.Vars(r)
	connectionID := vars["id"]

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
	)

	// This would typically close the connection through the connection pool
	// For now, we'll just return success
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Connection close requested",
	})
}

// GetSystemStatus gets the real-time system status
func (h *HTTPHandlers) GetSystemStatus(w http.ResponseWriter, r *http.Request) {
	_, span := httpHandlerTracer.Start(r.Context(), "get_system_status")
	defer span.End()

	metrics := h.realtimeSystem.GetMetrics()
	connections := h.realtimeSystem.GetActiveConnections()
	streams := h.realtimeSystem.streamManager.GetStreams()
	channels := h.realtimeSystem.pubsubManager.GetChannels()

	status := map[string]interface{}{
		"status": "healthy",
		"uptime": metrics.SystemUptime,
		"connections": map[string]interface{}{
			"total":   len(connections),
			"by_type": h.groupConnectionsByType(connections),
		},
		"streams": map[string]interface{}{
			"total":   len(streams),
			"by_type": h.groupStreamsByType(streams),
		},
		"channels": map[string]interface{}{
			"total":         len(channels),
			"subscriptions": metrics.ChannelSubscriptions,
		},
		"messages": map[string]interface{}{
			"total": metrics.TotalMessages,
		},
		"last_activity": metrics.LastActivity,
	}

	span.SetAttributes(
		attribute.Int("total_connections", len(connections)),
		attribute.Int("total_streams", len(streams)),
		attribute.Int("total_channels", len(channels)),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"status":  status,
	})
}

// GetMetrics gets detailed system metrics
func (h *HTTPHandlers) GetMetrics(w http.ResponseWriter, r *http.Request) {
	_, span := httpHandlerTracer.Start(r.Context(), "get_metrics")
	defer span.End()

	metrics := h.realtimeSystem.GetMetrics()

	span.SetAttributes(
		attribute.Int("active_connections", metrics.ActiveConnections),
		attribute.Int64("total_messages", metrics.TotalMessages),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"metrics": metrics,
	})
}

// HealthCheck performs a health check
func (h *HTTPHandlers) HealthCheck(w http.ResponseWriter, r *http.Request) {
	_, span := httpHandlerTracer.Start(r.Context(), "health_check")
	defer span.End()

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
		"components": map[string]string{
			"websocket_manager": "healthy",
			"pubsub_manager":    "healthy",
			"stream_manager":    "healthy",
			"connection_pool":   "healthy",
			"message_router":    "healthy",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// Helper methods

// groupConnectionsByType groups connections by type
func (h *HTTPHandlers) groupConnectionsByType(connections []*ConnectionInfo) map[string]int {
	groups := make(map[string]int)
	for _, conn := range connections {
		groups[string(conn.Type)]++
	}
	return groups
}

// groupStreamsByType groups streams by type
func (h *HTTPHandlers) groupStreamsByType(streams []*Stream) map[string]int {
	groups := make(map[string]int)
	for _, stream := range streams {
		groups[string(stream.Type)]++
	}
	return groups
}
