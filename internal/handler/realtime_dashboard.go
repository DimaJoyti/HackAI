package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var realtimeTracer = otel.Tracer("hackai/handler/realtime_dashboard")

// RealtimeDashboardHandler handles real-time dashboard WebSocket connections
type RealtimeDashboardHandler struct {
	logger       *logger.Logger
	securityRepo domain.LLMSecurityRepository
	policyRepo   domain.SecurityPolicyRepository

	// WebSocket management
	upgrader   websocket.Upgrader
	clients    map[string]*Client
	clientsMu  sync.RWMutex
	broadcast  chan *Message
	register   chan *Client
	unregister chan *Client

	// Data aggregation
	aggregator *DataAggregator

	// Shutdown
	shutdown chan struct{}
	done     chan struct{}
}

// Client represents a WebSocket client connection
type Client struct {
	ID        string
	Conn      *websocket.Conn
	Send      chan *Message
	Filters   *ClientFilters
	LastSeen  time.Time
	UserID    *uuid.UUID
	SessionID string
}

// ClientFilters represents client-specific filtering preferences
type ClientFilters struct {
	ThreatTypes    []string `json:"threat_types"`
	Severities     []string `json:"severities"`
	PolicyIDs      []string `json:"policy_ids"`
	MinThreatScore float64  `json:"min_threat_score"`
	TimeWindow     string   `json:"time_window"`
	EventTypes     []string `json:"event_types"`
}

// Message represents a real-time message sent to clients
type Message struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	ClientID  string                 `json:"client_id,omitempty"`
}

// MessageType constants
const (
	MessageTypeSecurityAlert      = "security_alert"
	MessageTypeThreatUpdate       = "threat_update"
	MessageTypeMetricsUpdate      = "metrics_update"
	MessageTypeSystemStatus       = "system_status"
	MessageTypePolicyViolation    = "policy_violation"
	MessageTypeHealthUpdate       = "health_update"
	MessageTypeClientConnected    = "client_connected"
	MessageTypeClientDisconnected = "client_disconnected"
	MessageTypeError              = "error"
)

// DataAggregator handles real-time data aggregation and broadcasting
type DataAggregator struct {
	handler     *RealtimeDashboardHandler
	ticker      *time.Ticker
	interval    time.Duration
	lastMetrics map[string]interface{}
	mu          sync.RWMutex
}

// NewRealtimeDashboardHandler creates a new real-time dashboard handler
func NewRealtimeDashboardHandler(
	logger *logger.Logger,
	securityRepo domain.LLMSecurityRepository,
	policyRepo domain.SecurityPolicyRepository,
) *RealtimeDashboardHandler {
	handler := &RealtimeDashboardHandler{
		logger:       logger,
		securityRepo: securityRepo,
		policyRepo:   policyRepo,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// In production, implement proper origin checking
				return true
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		clients:    make(map[string]*Client),
		broadcast:  make(chan *Message, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		shutdown:   make(chan struct{}),
		done:       make(chan struct{}),
	}

	// Initialize data aggregator
	handler.aggregator = &DataAggregator{
		handler:     handler,
		interval:    5 * time.Second, // Update every 5 seconds
		lastMetrics: make(map[string]interface{}),
	}

	return handler
}

// RegisterRoutes registers the real-time dashboard routes
func (h *RealtimeDashboardHandler) RegisterRoutes(router *mux.Router) {
	// WebSocket endpoint
	router.HandleFunc("/api/v1/realtime/dashboard", h.HandleWebSocket).Methods("GET")

	// REST endpoints for initial data
	router.HandleFunc("/api/v1/realtime/status", h.GetRealtimeStatus).Methods("GET")
	router.HandleFunc("/api/v1/realtime/clients", h.GetConnectedClients).Methods("GET")
	router.HandleFunc("/api/v1/realtime/metrics", h.GetRealtimeMetrics).Methods("GET")
}

// Start starts the real-time dashboard service
func (h *RealtimeDashboardHandler) Start(ctx context.Context) error {
	h.logger.Info("Starting real-time dashboard service")

	// Start the hub
	go h.runHub(ctx)

	// Start data aggregation
	go h.aggregator.start(ctx)

	h.logger.Info("Real-time dashboard service started")
	return nil
}

// Stop stops the real-time dashboard service
func (h *RealtimeDashboardHandler) Stop() error {
	h.logger.Info("Stopping real-time dashboard service")

	close(h.shutdown)
	<-h.done

	h.logger.Info("Real-time dashboard service stopped")
	return nil
}

// HandleWebSocket handles WebSocket connections
func (h *RealtimeDashboardHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	ctx, span := realtimeTracer.Start(r.Context(), "realtime_dashboard.handle_websocket")
	defer span.End()

	// Upgrade HTTP connection to WebSocket
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.WithError(err).Error("Failed to upgrade WebSocket connection")
		return
	}

	// Create client
	clientID := uuid.New().String()
	client := &Client{
		ID:        clientID,
		Conn:      conn,
		Send:      make(chan *Message, 256),
		Filters:   h.parseClientFilters(r),
		LastSeen:  time.Now(),
		SessionID: h.getSessionID(r),
	}

	// Extract user ID if available
	if userID := h.getUserIDFromContext(ctx); userID != nil {
		client.UserID = userID
	}

	span.SetAttributes(
		attribute.String("client.id", clientID),
		attribute.String("client.session_id", client.SessionID),
	)

	h.logger.WithFields(map[string]interface{}{
		"client_id":   clientID,
		"session_id":  client.SessionID,
		"remote_addr": r.RemoteAddr,
	}).Info("New WebSocket client connected")

	// Register client
	h.register <- client

	// Start client goroutines
	go h.handleClientWrite(client)
	go h.handleClientRead(client)
}

// runHub runs the WebSocket hub
func (h *RealtimeDashboardHandler) runHub(ctx context.Context) {
	defer close(h.done)

	for {
		select {
		case client := <-h.register:
			h.clientsMu.Lock()
			h.clients[client.ID] = client
			h.clientsMu.Unlock()

			// Send welcome message
			welcomeMsg := &Message{
				Type:      MessageTypeClientConnected,
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"client_id":    client.ID,
					"session_id":   client.SessionID,
					"connected_at": time.Now(),
				},
			}

			select {
			case client.Send <- welcomeMsg:
			default:
				close(client.Send)
				h.clientsMu.Lock()
				delete(h.clients, client.ID)
				h.clientsMu.Unlock()
			}

		case client := <-h.unregister:
			h.clientsMu.Lock()
			if _, ok := h.clients[client.ID]; ok {
				delete(h.clients, client.ID)
				close(client.Send)

				h.logger.WithField("client_id", client.ID).Info("WebSocket client disconnected")
			}
			h.clientsMu.Unlock()

		case message := <-h.broadcast:
			h.broadcastMessage(message)

		case <-h.shutdown:
			// Close all client connections
			h.clientsMu.Lock()
			for _, client := range h.clients {
				close(client.Send)
			}
			h.clients = make(map[string]*Client)
			h.clientsMu.Unlock()
			return

		case <-ctx.Done():
			return
		}
	}
}

// handleClientWrite handles writing messages to a client
func (h *RealtimeDashboardHandler) handleClientWrite(client *Client) {
	ticker := time.NewTicker(54 * time.Second) // Ping interval
	defer func() {
		ticker.Stop()
		client.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-client.Send:
			client.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				client.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := client.Conn.WriteJSON(message); err != nil {
				h.logger.WithError(err).WithField("client_id", client.ID).Error("Failed to write message to client")
				return
			}

		case <-ticker.C:
			client.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := client.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleClientRead handles reading messages from a client
func (h *RealtimeDashboardHandler) handleClientRead(client *Client) {
	defer func() {
		h.unregister <- client
		client.Conn.Close()
	}()

	client.Conn.SetReadLimit(512)
	client.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	client.Conn.SetPongHandler(func(string) error {
		client.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		var msg map[string]interface{}
		err := client.Conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				h.logger.WithError(err).WithField("client_id", client.ID).Error("WebSocket error")
			}
			break
		}

		client.LastSeen = time.Now()
		h.handleClientMessage(client, msg)
	}
}

// handleClientMessage handles messages received from clients
func (h *RealtimeDashboardHandler) handleClientMessage(client *Client, msg map[string]interface{}) {
	msgType, ok := msg["type"].(string)
	if !ok {
		return
	}

	switch msgType {
	case "update_filters":
		if filtersData, ok := msg["filters"].(map[string]interface{}); ok {
			h.updateClientFilters(client, filtersData)
		}
	case "subscribe":
		if topics, ok := msg["topics"].([]interface{}); ok {
			h.subscribeClientToTopics(client, topics)
		}
	case "ping":
		// Respond with pong
		pongMsg := &Message{
			Type:      "pong",
			Timestamp: time.Now(),
			Data:      map[string]interface{}{"client_id": client.ID},
		}
		select {
		case client.Send <- pongMsg:
		default:
		}
	}
}

// broadcastMessage broadcasts a message to all connected clients
func (h *RealtimeDashboardHandler) broadcastMessage(message *Message) {
	h.clientsMu.RLock()
	defer h.clientsMu.RUnlock()

	for _, client := range h.clients {
		if h.shouldSendToClient(client, message) {
			select {
			case client.Send <- message:
			default:
				// Client's send channel is full, close it
				close(client.Send)
				delete(h.clients, client.ID)
			}
		}
	}
}

// shouldSendToClient determines if a message should be sent to a specific client
func (h *RealtimeDashboardHandler) shouldSendToClient(client *Client, message *Message) bool {
	if client.Filters == nil {
		return true
	}

	// Apply filters based on message type and content
	switch message.Type {
	case MessageTypeSecurityAlert, MessageTypeThreatUpdate:
		if severity, ok := message.Data["severity"].(string); ok {
			if len(client.Filters.Severities) > 0 && !contains(client.Filters.Severities, severity) {
				return false
			}
		}

		if threatScore, ok := message.Data["threat_score"].(float64); ok {
			if threatScore < client.Filters.MinThreatScore {
				return false
			}
		}

		if threatType, ok := message.Data["threat_type"].(string); ok {
			if len(client.Filters.ThreatTypes) > 0 && !contains(client.Filters.ThreatTypes, threatType) {
				return false
			}
		}

	case MessageTypePolicyViolation:
		if policyID, ok := message.Data["policy_id"].(string); ok {
			if len(client.Filters.PolicyIDs) > 0 && !contains(client.Filters.PolicyIDs, policyID) {
				return false
			}
		}
	}

	return true
}

// BroadcastSecurityAlert broadcasts a security alert to all clients
func (h *RealtimeDashboardHandler) BroadcastSecurityAlert(alert *domain.SecurityEvent) {
	message := &Message{
		Type:      MessageTypeSecurityAlert,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"id":          alert.ID,
			"type":        alert.Type,
			"category":    alert.Category,
			"severity":    alert.Severity,
			"title":       alert.Title,
			"description": alert.Description,
			"confidence":  alert.Confidence,
			"source_ip":   alert.SourceIP,
			"created_at":  alert.CreatedAt,
		},
	}

	select {
	case h.broadcast <- message:
	default:
		h.logger.Warn("Broadcast channel full, dropping security alert message")
	}
}

// BroadcastThreatUpdate broadcasts a threat update to all clients
func (h *RealtimeDashboardHandler) BroadcastThreatUpdate(threatType string, count int64, avgScore float64) {
	message := &Message{
		Type:      MessageTypeThreatUpdate,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"threat_type":   threatType,
			"count":         count,
			"average_score": avgScore,
			"severity":      h.determineSeverity(avgScore),
		},
	}

	select {
	case h.broadcast <- message:
	default:
		h.logger.Warn("Broadcast channel full, dropping threat update message")
	}
}

// BroadcastMetricsUpdate broadcasts metrics updates to all clients
func (h *RealtimeDashboardHandler) BroadcastMetricsUpdate(metrics map[string]interface{}) {
	message := &Message{
		Type:      MessageTypeMetricsUpdate,
		Timestamp: time.Now(),
		Data:      metrics,
	}

	select {
	case h.broadcast <- message:
	default:
		h.logger.Warn("Broadcast channel full, dropping metrics update message")
	}
}

// BroadcastSystemStatus broadcasts system status updates to all clients
func (h *RealtimeDashboardHandler) BroadcastSystemStatus(status map[string]interface{}) {
	message := &Message{
		Type:      MessageTypeSystemStatus,
		Timestamp: time.Now(),
		Data:      status,
	}

	select {
	case h.broadcast <- message:
	default:
		h.logger.Warn("Broadcast channel full, dropping system status message")
	}
}

// BroadcastPolicyViolation broadcasts policy violation alerts to all clients
func (h *RealtimeDashboardHandler) BroadcastPolicyViolation(violation *domain.PolicyViolation) {
	message := &Message{
		Type:      MessageTypePolicyViolation,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"id":             violation.ID,
			"policy_id":      violation.PolicyID,
			"violation_type": violation.ViolationType,
			"severity":       violation.Severity,
			"description":    violation.Description,
			"user_id":        violation.UserID,
			"created_at":     violation.CreatedAt,
		},
	}

	select {
	case h.broadcast <- message:
	default:
		h.logger.Warn("Broadcast channel full, dropping policy violation message")
	}
}

// REST endpoint handlers

// GetRealtimeStatus returns the status of the real-time dashboard service
func (h *RealtimeDashboardHandler) GetRealtimeStatus(w http.ResponseWriter, r *http.Request) {
	_, span := realtimeTracer.Start(r.Context(), "realtime_dashboard.get_status")
	defer span.End()

	h.clientsMu.RLock()
	clientCount := len(h.clients)
	h.clientsMu.RUnlock()

	status := map[string]interface{}{
		"service":           "realtime_dashboard",
		"status":            "running",
		"connected_clients": clientCount,
		"uptime":            time.Since(time.Now().Add(-24 * time.Hour)).String(), // Simplified
		"last_update":       time.Now(),
		"version":           "1.0.0",
	}

	h.writeJSONResponse(w, http.StatusOK, status)
}

// GetConnectedClients returns information about connected clients
func (h *RealtimeDashboardHandler) GetConnectedClients(w http.ResponseWriter, r *http.Request) {
	_, span := realtimeTracer.Start(r.Context(), "realtime_dashboard.get_connected_clients")
	defer span.End()

	h.clientsMu.RLock()
	defer h.clientsMu.RUnlock()

	clients := make([]map[string]interface{}, 0, len(h.clients))
	for _, client := range h.clients {
		clientInfo := map[string]interface{}{
			"id":         client.ID,
			"session_id": client.SessionID,
			"last_seen":  client.LastSeen,
			"filters":    client.Filters,
		}

		if client.UserID != nil {
			clientInfo["user_id"] = client.UserID.String()
		}

		clients = append(clients, clientInfo)
	}

	response := map[string]interface{}{
		"clients":   clients,
		"count":     len(clients),
		"timestamp": time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetRealtimeMetrics returns current real-time metrics
func (h *RealtimeDashboardHandler) GetRealtimeMetrics(w http.ResponseWriter, r *http.Request) {
	_, span := realtimeTracer.Start(r.Context(), "realtime_dashboard.get_realtime_metrics")
	defer span.End()

	h.aggregator.mu.RLock()
	metrics := make(map[string]interface{})
	for k, v := range h.aggregator.lastMetrics {
		metrics[k] = v
	}
	h.aggregator.mu.RUnlock()

	response := map[string]interface{}{
		"metrics":   metrics,
		"timestamp": time.Now(),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods

// parseClientFilters parses client filters from request
func (h *RealtimeDashboardHandler) parseClientFilters(r *http.Request) *ClientFilters {
	filters := &ClientFilters{
		MinThreatScore: 0.0,
		TimeWindow:     "1h",
	}

	// Parse query parameters for initial filters
	if threatTypes := r.URL.Query().Get("threat_types"); threatTypes != "" {
		// Parse comma-separated threat types
		// Implementation would parse the string
	}

	if minScore := r.URL.Query().Get("min_threat_score"); minScore != "" {
		if score, err := strconv.ParseFloat(minScore, 64); err == nil {
			filters.MinThreatScore = score
		}
	}

	return filters
}

// updateClientFilters updates a client's filters
func (h *RealtimeDashboardHandler) updateClientFilters(client *Client, filtersData map[string]interface{}) {
	if client.Filters == nil {
		client.Filters = &ClientFilters{}
	}

	if threatTypes, ok := filtersData["threat_types"].([]interface{}); ok {
		client.Filters.ThreatTypes = interfaceSliceToStringSlice(threatTypes)
	}

	if severities, ok := filtersData["severities"].([]interface{}); ok {
		client.Filters.Severities = interfaceSliceToStringSlice(severities)
	}

	if minScore, ok := filtersData["min_threat_score"].(float64); ok {
		client.Filters.MinThreatScore = minScore
	}

	h.logger.WithFields(map[string]interface{}{
		"client_id": client.ID,
		"filters":   client.Filters,
	}).Debug("Updated client filters")
}

// subscribeClientToTopics subscribes a client to specific topics
func (h *RealtimeDashboardHandler) subscribeClientToTopics(client *Client, topics []interface{}) {
	// Implementation for topic-based subscriptions
	h.logger.WithFields(map[string]interface{}{
		"client_id": client.ID,
		"topics":    topics,
	}).Debug("Client subscribed to topics")
}

// getSessionID extracts session ID from request
func (h *RealtimeDashboardHandler) getSessionID(r *http.Request) string {
	if sessionID := r.Header.Get("X-Session-ID"); sessionID != "" {
		return sessionID
	}
	return uuid.New().String()
}

// getUserIDFromContext extracts user ID from context
func (h *RealtimeDashboardHandler) getUserIDFromContext(ctx context.Context) *uuid.UUID {
	// This would typically extract from JWT token or session
	// For now, return nil (anonymous user)
	return nil
}

// determineSeverity determines severity based on threat score
func (h *RealtimeDashboardHandler) determineSeverity(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.5:
		return "medium"
	case score >= 0.3:
		return "low"
	default:
		return "info"
	}
}

// writeJSONResponse writes a JSON response
func (h *RealtimeDashboardHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

// Utility functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func interfaceSliceToStringSlice(slice []interface{}) []string {
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if str, ok := item.(string); ok {
			result = append(result, str)
		}
	}
	return result
}

// DataAggregator implementation

// start starts the data aggregation process
func (da *DataAggregator) start(ctx context.Context) {
	da.ticker = time.NewTicker(da.interval)
	defer da.ticker.Stop()

	for {
		select {
		case <-da.ticker.C:
			da.aggregateAndBroadcast(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// aggregateAndBroadcast aggregates current metrics and broadcasts updates
func (da *DataAggregator) aggregateAndBroadcast(ctx context.Context) {
	// Get current metrics
	startTime := time.Now().Add(-5 * time.Minute) // Last 5 minutes
	endTime := time.Now()

	filter := domain.RequestLogFilter{
		StartTime: &startTime,
		EndTime:   &endTime,
		Limit:     1000,
	}

	stats, err := da.handler.securityRepo.GetRequestLogStats(ctx, filter)
	if err != nil {
		da.handler.logger.WithError(err).Error("Failed to get request stats for aggregation")
		return
	}

	// Calculate metrics
	metrics := map[string]interface{}{
		"requests_per_minute":  stats.TotalRequests,
		"blocked_per_minute":   stats.BlockedRequests,
		"average_threat_score": stats.AverageThreatScore,
		"total_tokens":         stats.TotalTokens,
		"timestamp":            time.Now(),
	}

	// Store metrics
	da.mu.Lock()
	da.lastMetrics = metrics
	da.mu.Unlock()

	// Broadcast metrics update
	da.handler.BroadcastMetricsUpdate(metrics)

	// Get and broadcast recent threats
	threats, err := da.handler.securityRepo.GetTopThreats(ctx, 5, 5*time.Minute)
	if err == nil && len(threats) > 0 {
		for _, threat := range threats {
			da.handler.BroadcastThreatUpdate(threat.ThreatType, threat.Count, threat.AverageScore)
		}
	}
}
