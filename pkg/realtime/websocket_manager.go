package realtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

var websocketTracer = otel.Tracer("hackai/realtime/websocket")

// WebSocketManager manages WebSocket connections
type WebSocketManager struct {
	config      WebSocketConfig
	logger      *logger.Logger
	upgrader    websocket.Upgrader
	connections map[string]*WebSocketConnection
	handlers    map[MessageType]WebSocketHandler
	middleware  []WebSocketMiddleware
	running     bool
	stopChan    chan struct{}
	wg          sync.WaitGroup
	mutex       sync.RWMutex
}

// WebSocketConnection represents a WebSocket connection
type WebSocketConnection struct {
	ID       string
	conn     *websocket.Conn
	send     chan []byte
	receive  chan []byte
	info     *ConnectionInfo
	lastPong time.Time
	manager  *WebSocketManager
	ctx      context.Context
	cancel   context.CancelFunc
	mutex    sync.RWMutex
}

// WebSocketHandler interface for handling WebSocket messages
type WebSocketHandler interface {
	HandleMessage(ctx context.Context, conn *WebSocketConnection, message *RealtimeMessage) error
	GetMessageType() MessageType
}

// WebSocketMiddleware interface for WebSocket middleware
type WebSocketMiddleware interface {
	ProcessMessage(ctx context.Context, conn *WebSocketConnection, message *RealtimeMessage, next func() error) error
}

// NewWebSocketManager creates a new WebSocket manager
func NewWebSocketManager(config WebSocketConfig, logger *logger.Logger) *WebSocketManager {
	upgrader := websocket.Upgrader{
		ReadBufferSize:   config.ReadBufferSize,
		WriteBufferSize:  config.WriteBufferSize,
		HandshakeTimeout: config.HandshakeTimeout,
		CheckOrigin: func(r *http.Request) bool {
			// TODO: Implement proper origin checking
			return true
		},
		EnableCompression: config.EnableCompression,
	}

	return &WebSocketManager{
		config:      config,
		logger:      logger,
		upgrader:    upgrader,
		connections: make(map[string]*WebSocketConnection),
		handlers:    make(map[MessageType]WebSocketHandler),
		middleware:  []WebSocketMiddleware{},
		stopChan:    make(chan struct{}),
	}
}

// Start starts the WebSocket manager
func (wm *WebSocketManager) Start(ctx context.Context) error {
	ctx, span := websocketTracer.Start(ctx, "websocket_manager_start")
	defer span.End()

	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	if wm.running {
		return fmt.Errorf("WebSocket manager is already running")
	}

	wm.logger.Info("Starting WebSocket manager",
		"read_buffer_size", wm.config.ReadBufferSize,
		"write_buffer_size", wm.config.WriteBufferSize,
		"max_message_size", wm.config.MaxMessageSize)

	// Start background workers
	wm.wg.Add(1)
	go wm.connectionCleanupWorker(ctx)

	wm.running = true

	span.SetAttributes(
		attribute.Bool("manager_started", true),
		attribute.Int("read_buffer_size", wm.config.ReadBufferSize),
		attribute.Int("write_buffer_size", wm.config.WriteBufferSize),
	)

	wm.logger.Info("WebSocket manager started successfully")
	return nil
}

// Stop stops the WebSocket manager
func (wm *WebSocketManager) Stop() error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	if !wm.running {
		return nil
	}

	wm.logger.Info("Stopping WebSocket manager")

	// Signal stop to workers
	close(wm.stopChan)

	// Close all connections
	for _, conn := range wm.connections {
		conn.Close()
	}

	// Wait for workers to finish
	wm.wg.Wait()

	wm.running = false
	wm.logger.Info("WebSocket manager stopped")
	return nil
}

// HandleUpgrade handles WebSocket upgrade requests
func (wm *WebSocketManager) HandleUpgrade(w http.ResponseWriter, r *http.Request) error {
	ctx, span := websocketTracer.Start(r.Context(), "websocket_upgrade")
	defer span.End()

	// Upgrade the connection
	conn, err := wm.upgrader.Upgrade(w, r, nil)
	if err != nil {
		span.RecordError(err)
		wm.logger.Error("Failed to upgrade WebSocket connection", "error", err)
		return fmt.Errorf("failed to upgrade connection: %w", err)
	}

	// Create connection info
	connectionID := uuid.New().String()
	info := &ConnectionInfo{
		ID:            connectionID,
		Type:          ConnectionTypeWebSocket,
		RemoteAddr:    r.RemoteAddr,
		UserAgent:     r.UserAgent(),
		ConnectedAt:   time.Now(),
		LastActivity:  time.Now(),
		Subscriptions: []string{},
		Metadata:      make(map[string]interface{}),
	}

	// Create WebSocket connection
	ctx, cancel := context.WithCancel(ctx)
	wsConn := &WebSocketConnection{
		ID:       connectionID,
		conn:     conn,
		send:     make(chan []byte, 256),
		receive:  make(chan []byte, 256),
		info:     info,
		lastPong: time.Now(),
		manager:  wm,
		ctx:      ctx,
		cancel:   cancel,
	}

	// Configure connection
	conn.SetReadLimit(wm.config.MaxMessageSize)
	conn.SetReadDeadline(time.Now().Add(wm.config.PongWait))
	conn.SetPongHandler(func(string) error {
		wsConn.lastPong = time.Now()
		conn.SetReadDeadline(time.Now().Add(wm.config.PongWait))
		return nil
	})

	// Register connection
	wm.mutex.Lock()
	wm.connections[connectionID] = wsConn
	wm.mutex.Unlock()

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("remote_addr", r.RemoteAddr),
		attribute.String("user_agent", r.UserAgent()),
	)

	wm.logger.Info("WebSocket connection established",
		"connection_id", connectionID,
		"remote_addr", r.RemoteAddr)

	// Start connection handlers
	go wsConn.readPump()
	go wsConn.writePump()

	return nil
}

// RegisterHandler registers a message handler
func (wm *WebSocketManager) RegisterHandler(handler WebSocketHandler) {
	wm.handlers[handler.GetMessageType()] = handler
	wm.logger.Info("WebSocket handler registered", "message_type", handler.GetMessageType())
}

// AddMiddleware adds middleware to the WebSocket manager
func (wm *WebSocketManager) AddMiddleware(middleware WebSocketMiddleware) {
	wm.middleware = append(wm.middleware, middleware)
	wm.logger.Info("WebSocket middleware added")
}

// BroadcastMessage broadcasts a message to all connections
func (wm *WebSocketManager) BroadcastMessage(ctx context.Context, message *RealtimeMessage) error {
	ctx, span := websocketTracer.Start(ctx, "broadcast_message")
	defer span.End()

	data, err := json.Marshal(message)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	wm.mutex.RLock()
	connections := make([]*WebSocketConnection, 0, len(wm.connections))
	for _, conn := range wm.connections {
		connections = append(connections, conn)
	}
	wm.mutex.RUnlock()

	span.SetAttributes(
		attribute.String("message_id", message.ID),
		attribute.String("message_type", string(message.Type)),
		attribute.Int("connection_count", len(connections)),
	)

	// Send to all connections
	for _, conn := range connections {
		select {
		case conn.send <- data:
		default:
			// Connection buffer is full, close it
			conn.Close()
		}
	}

	wm.logger.Debug("Message broadcasted",
		"message_id", message.ID,
		"connection_count", len(connections))

	return nil
}

// SendMessage sends a message to a specific connection
func (wm *WebSocketManager) SendMessage(ctx context.Context, connectionID string, message *RealtimeMessage) error {
	ctx, span := websocketTracer.Start(ctx, "send_message")
	defer span.End()

	wm.mutex.RLock()
	conn, exists := wm.connections[connectionID]
	wm.mutex.RUnlock()

	if !exists {
		err := fmt.Errorf("connection not found: %s", connectionID)
		span.RecordError(err)
		return err
	}

	data, err := json.Marshal(message)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("message_id", message.ID),
		attribute.String("message_type", string(message.Type)),
	)

	select {
	case conn.send <- data:
		return nil
	default:
		// Connection buffer is full, close it
		conn.Close()
		return fmt.Errorf("connection buffer full, connection closed")
	}
}

// GetConnections gets all active connections
func (wm *WebSocketManager) GetConnections() []*ConnectionInfo {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	connections := make([]*ConnectionInfo, 0, len(wm.connections))
	for _, conn := range wm.connections {
		connections = append(connections, conn.info)
	}

	return connections
}

// GetConnectionCount gets the number of active connections
func (wm *WebSocketManager) GetConnectionCount() int {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()
	return len(wm.connections)
}

// removeConnection removes a connection from the manager
func (wm *WebSocketManager) removeConnection(connectionID string) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	if conn, exists := wm.connections[connectionID]; exists {
		delete(wm.connections, connectionID)
		wm.logger.Info("WebSocket connection removed", "connection_id", connectionID)

		// Cancel connection context
		conn.cancel()
	}
}

// connectionCleanupWorker cleans up stale connections
func (wm *WebSocketManager) connectionCleanupWorker(ctx context.Context) {
	defer wm.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-wm.stopChan:
			return
		case <-ticker.C:
			wm.cleanupStaleConnections()
		}
	}
}

// cleanupStaleConnections removes stale connections
func (wm *WebSocketManager) cleanupStaleConnections() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	now := time.Now()
	staleConnections := []string{}

	for id, conn := range wm.connections {
		if now.Sub(conn.lastPong) > wm.config.PongWait*2 {
			staleConnections = append(staleConnections, id)
		}
	}

	for _, id := range staleConnections {
		if conn, exists := wm.connections[id]; exists {
			conn.Close()
			delete(wm.connections, id)
			wm.logger.Info("Removed stale WebSocket connection", "connection_id", id)
		}
	}

	if len(staleConnections) > 0 {
		wm.logger.Info("Cleaned up stale connections", "count", len(staleConnections))
	}
}

// WebSocket connection methods

// Close closes the WebSocket connection
func (c *WebSocketConnection) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Cancel context
	if c.cancel != nil {
		c.cancel()
	}

	// Close WebSocket connection
	if c.conn != nil {
		c.conn.Close()
	}

	// Close channels
	close(c.send)

	// Remove from manager
	c.manager.removeConnection(c.ID)

	c.manager.logger.Info("WebSocket connection closed", "connection_id", c.ID)
	return nil
}

// readPump handles reading messages from the WebSocket connection
func (c *WebSocketConnection) readPump() {
	defer c.Close()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			_, messageData, err := c.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					c.manager.logger.Error("WebSocket read error", "connection_id", c.ID, "error", err)
				}
				return
			}

			// Update last activity
			c.info.LastActivity = time.Now()

			// Parse message
			var message RealtimeMessage
			if err := json.Unmarshal(messageData, &message); err != nil {
				c.manager.logger.Error("Failed to parse WebSocket message", "connection_id", c.ID, "error", err)
				continue
			}

			// Process message through middleware and handlers
			c.processMessage(&message)
		}
	}
}

// writePump handles writing messages to the WebSocket connection
func (c *WebSocketConnection) writePump() {
	ticker := time.NewTicker(c.manager.config.PingPeriod)
	defer func() {
		ticker.Stop()
		c.Close()
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(c.manager.config.WriteDeadline))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				c.manager.logger.Error("WebSocket write error", "connection_id", c.ID, "error", err)
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(c.manager.config.WriteDeadline))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// processMessage processes a message through middleware and handlers
func (c *WebSocketConnection) processMessage(message *RealtimeMessage) {
	ctx, span := websocketTracer.Start(c.ctx, "process_websocket_message")
	defer span.End()

	span.SetAttributes(
		attribute.String("connection_id", c.ID),
		attribute.String("message_id", message.ID),
		attribute.String("message_type", string(message.Type)),
	)

	// Process through middleware
	err := c.processMiddleware(ctx, message, func() error {
		// Find and execute handler
		if handler, exists := c.manager.handlers[message.Type]; exists {
			return handler.HandleMessage(ctx, c, message)
		}
		return fmt.Errorf("no handler found for message type: %s", message.Type)
	})

	if err != nil {
		span.RecordError(err)
		c.manager.logger.Error("Failed to process WebSocket message",
			"connection_id", c.ID,
			"message_id", message.ID,
			"error", err)

		// Send error response
		errorMessage := &RealtimeMessage{
			ID:        uuid.New().String(),
			Type:      MessageTypeError,
			Channel:   message.Channel,
			Source:    "system",
			Target:    c.ID,
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"error":            err.Error(),
				"original_message": message.ID,
			},
			Metadata: make(map[string]interface{}),
			Priority: PriorityHigh,
		}

		errorData, _ := json.Marshal(errorMessage)
		select {
		case c.send <- errorData:
		default:
			// Buffer full, close connection
			c.Close()
		}
	}
}

// processMiddleware processes message through middleware chain
func (c *WebSocketConnection) processMiddleware(ctx context.Context, message *RealtimeMessage, next func() error) error {
	if len(c.manager.middleware) == 0 {
		return next()
	}

	// Create middleware chain
	var chain func(int) error
	chain = func(index int) error {
		if index >= len(c.manager.middleware) {
			return next()
		}

		middleware := c.manager.middleware[index]
		return middleware.ProcessMessage(ctx, c, message, func() error {
			return chain(index + 1)
		})
	}

	return chain(0)
}
