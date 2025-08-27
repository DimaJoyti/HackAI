package realtime

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/infrastructure"
	"github.com/dimajoyti/hackai/pkg/langgraph/messaging"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

var realtimeTracer = otel.Tracer("hackai/realtime")

// RealtimeSystem provides comprehensive real-time communication capabilities
type RealtimeSystem struct {
	config           *RealtimeConfig
	logger           *logger.Logger
	redisClient      *infrastructure.RedisClient
	eventSystem      *messaging.EventSystem
	websocketManager *WebSocketManager
	streamManager    *StreamManager
	pubsubManager    *PubSubManager
	connectionPool   *ConnectionPool
	messageRouter    *MessageRouter
	running          bool
	stopChan         chan struct{}
	wg               sync.WaitGroup
	mutex            sync.RWMutex
}

// RealtimeConfig configuration for real-time system
type RealtimeConfig struct {
	// WebSocket configuration
	WebSocketConfig WebSocketConfig `json:"websocket"`

	// Streaming configuration
	StreamConfig StreamConfig `json:"stream"`

	// PubSub configuration
	PubSubConfig PubSubConfig `json:"pubsub"`

	// Connection management
	MaxConnections    int           `json:"max_connections"`
	ConnectionTimeout time.Duration `json:"connection_timeout"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`

	// Message handling
	MessageBufferSize int           `json:"message_buffer_size"`
	MessageTimeout    time.Duration `json:"message_timeout"`
	EnableCompression bool          `json:"enable_compression"`

	// Security
	EnableAuth        bool          `json:"enable_auth"`
	AllowedOrigins    []string      `json:"allowed_origins"`
	RateLimitEnabled  bool          `json:"rate_limit_enabled"`
	RateLimitRequests int           `json:"rate_limit_requests"`
	RateLimitWindow   time.Duration `json:"rate_limit_window"`

	// Monitoring
	MetricsEnabled      bool          `json:"metrics_enabled"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
}

// WebSocketConfig configuration for WebSocket connections
type WebSocketConfig struct {
	ReadBufferSize    int           `json:"read_buffer_size"`
	WriteBufferSize   int           `json:"write_buffer_size"`
	HandshakeTimeout  time.Duration `json:"handshake_timeout"`
	ReadDeadline      time.Duration `json:"read_deadline"`
	WriteDeadline     time.Duration `json:"write_deadline"`
	PongWait          time.Duration `json:"pong_wait"`
	PingPeriod        time.Duration `json:"ping_period"`
	MaxMessageSize    int64         `json:"max_message_size"`
	EnableCompression bool          `json:"enable_compression"`
}

// StreamConfig configuration for streaming
type StreamConfig struct {
	BufferSize        int           `json:"buffer_size"`
	FlushInterval     time.Duration `json:"flush_interval"`
	MaxStreamAge      time.Duration `json:"max_stream_age"`
	EnablePersistence bool          `json:"enable_persistence"`
	CompressionLevel  int           `json:"compression_level"`
}

// PubSubConfig configuration for publish-subscribe
type PubSubConfig struct {
	ChannelBufferSize int           `json:"channel_buffer_size"`
	SubscriberTimeout time.Duration `json:"subscriber_timeout"`
	EnablePersistence bool          `json:"enable_persistence"`
	RetentionPeriod   time.Duration `json:"retention_period"`
}

// RealtimeMessage represents a real-time message
type RealtimeMessage struct {
	ID        string                 `json:"id"`
	Type      MessageType            `json:"type"`
	Channel   string                 `json:"channel"`
	Source    string                 `json:"source"`
	Target    string                 `json:"target,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
	Priority  MessagePriority        `json:"priority"`
}

// MessageType represents the type of real-time message
type MessageType string

const (
	MessageTypeEvent        MessageType = "event"
	MessageTypeCommand      MessageType = "command"
	MessageTypeQuery        MessageType = "query"
	MessageTypeResponse     MessageType = "response"
	MessageTypeNotification MessageType = "notification"
	MessageTypeHeartbeat    MessageType = "heartbeat"
	MessageTypeError        MessageType = "error"
	MessageTypeCustom       MessageType = "custom"
)

// MessagePriority represents message priority levels
type MessagePriority int

const (
	PriorityLow MessagePriority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// ConnectionInfo represents connection information
type ConnectionInfo struct {
	ID            string                 `json:"id"`
	Type          ConnectionType         `json:"type"`
	RemoteAddr    string                 `json:"remote_addr"`
	UserAgent     string                 `json:"user_agent"`
	ConnectedAt   time.Time              `json:"connected_at"`
	LastActivity  time.Time              `json:"last_activity"`
	Subscriptions []string               `json:"subscriptions"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ConnectionType represents the type of connection
type ConnectionType string

const (
	ConnectionTypeWebSocket ConnectionType = "websocket"
	ConnectionTypeSSE       ConnectionType = "sse"
	ConnectionTypeLongPoll  ConnectionType = "longpoll"
	ConnectionTypeStream    ConnectionType = "stream"
)

// NewRealtimeSystem creates a new real-time system
func NewRealtimeSystem(config *RealtimeConfig, redisClient *infrastructure.RedisClient, eventSystem *messaging.EventSystem, logger *logger.Logger) *RealtimeSystem {
	return &RealtimeSystem{
		config:           config,
		logger:           logger,
		redisClient:      redisClient,
		eventSystem:      eventSystem,
		websocketManager: NewWebSocketManager(config.WebSocketConfig, logger),
		streamManager:    NewStreamManager(config.StreamConfig, logger),
		pubsubManager:    NewPubSubManager(config.PubSubConfig, redisClient, logger),
		connectionPool:   NewConnectionPool(config.MaxConnections, logger),
		messageRouter:    NewMessageRouter(logger),
		stopChan:         make(chan struct{}),
	}
}

// Start starts the real-time system
func (rs *RealtimeSystem) Start(ctx context.Context) error {
	ctx, span := realtimeTracer.Start(ctx, "realtime_system_start")
	defer span.End()

	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if rs.running {
		return fmt.Errorf("real-time system is already running")
	}

	rs.logger.Info("Starting real-time system",
		"max_connections", rs.config.MaxConnections,
		"websocket_enabled", true,
		"pubsub_enabled", true,
		"metrics_enabled", rs.config.MetricsEnabled)

	// Start WebSocket manager
	if err := rs.websocketManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start WebSocket manager: %w", err)
	}

	// Start stream manager
	if err := rs.streamManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start stream manager: %w", err)
	}

	// Start PubSub manager
	if err := rs.pubsubManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start PubSub manager: %w", err)
	}

	// Start connection pool
	if err := rs.connectionPool.Start(ctx); err != nil {
		return fmt.Errorf("failed to start connection pool: %w", err)
	}

	// Start message router
	if err := rs.messageRouter.Start(ctx); err != nil {
		return fmt.Errorf("failed to start message router: %w", err)
	}

	// Start background workers
	rs.wg.Add(3)
	go rs.heartbeatWorker(ctx)
	go rs.cleanupWorker(ctx)
	go rs.metricsWorker(ctx)

	rs.running = true

	span.SetAttributes(
		attribute.Bool("system_started", true),
		attribute.Int("max_connections", rs.config.MaxConnections),
	)

	rs.logger.Info("Real-time system started successfully")
	return nil
}

// Stop stops the real-time system
func (rs *RealtimeSystem) Stop() error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if !rs.running {
		return nil
	}

	rs.logger.Info("Stopping real-time system")

	// Signal stop to all workers
	close(rs.stopChan)

	// Stop all managers
	rs.messageRouter.Stop()
	rs.connectionPool.Stop()
	rs.pubsubManager.Stop()
	rs.streamManager.Stop()
	rs.websocketManager.Stop()

	// Wait for workers to finish
	rs.wg.Wait()

	rs.running = false
	rs.logger.Info("Real-time system stopped")
	return nil
}

// PublishMessage publishes a message to a channel
func (rs *RealtimeSystem) PublishMessage(ctx context.Context, channel string, data map[string]interface{}) error {
	ctx, span := realtimeTracer.Start(ctx, "publish_message")
	defer span.End()

	message := &RealtimeMessage{
		ID:        uuid.New().String(),
		Type:      MessageTypeEvent,
		Channel:   channel,
		Source:    "system",
		Timestamp: time.Now(),
		Data:      data,
		Metadata:  make(map[string]interface{}),
		Priority:  PriorityNormal,
	}

	span.SetAttributes(
		attribute.String("message_id", message.ID),
		attribute.String("channel", channel),
		attribute.String("message_type", string(message.Type)),
	)

	return rs.pubsubManager.Publish(ctx, message)
}

// Subscribe subscribes to a channel
func (rs *RealtimeSystem) Subscribe(ctx context.Context, connectionID, channel string) error {
	ctx, span := realtimeTracer.Start(ctx, "subscribe_channel")
	defer span.End()

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("channel", channel),
	)

	return rs.pubsubManager.Subscribe(ctx, connectionID, channel)
}

// Unsubscribe unsubscribes from a channel
func (rs *RealtimeSystem) Unsubscribe(ctx context.Context, connectionID, channel string) error {
	ctx, span := realtimeTracer.Start(ctx, "unsubscribe_channel")
	defer span.End()

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("channel", channel),
	)

	return rs.pubsubManager.Unsubscribe(ctx, connectionID, channel)
}

// GetConnectionInfo gets connection information
func (rs *RealtimeSystem) GetConnectionInfo(connectionID string) (*ConnectionInfo, error) {
	return rs.connectionPool.GetConnectionInfo(connectionID)
}

// GetActiveConnections gets all active connections
func (rs *RealtimeSystem) GetActiveConnections() []*ConnectionInfo {
	return rs.connectionPool.GetActiveConnections()
}

// GetMetrics gets real-time system metrics
func (rs *RealtimeSystem) GetMetrics() *RealtimeMetrics {
	return &RealtimeMetrics{
		ActiveConnections:    rs.connectionPool.GetConnectionCount(),
		TotalMessages:        rs.messageRouter.GetMessageCount(),
		ChannelSubscriptions: rs.pubsubManager.GetSubscriptionCount(),
		SystemUptime:         time.Since(rs.connectionPool.startTime),
		LastActivity:         time.Now(),
	}
}

// GetStreamManager gets the stream manager
func (rs *RealtimeSystem) GetStreamManager() *StreamManager {
	return rs.streamManager
}

// GetWebSocketManager gets the WebSocket manager
func (rs *RealtimeSystem) GetWebSocketManager() *WebSocketManager {
	return rs.websocketManager
}

// RealtimeMetrics represents real-time system metrics
type RealtimeMetrics struct {
	ActiveConnections    int           `json:"active_connections"`
	TotalMessages        int64         `json:"total_messages"`
	ChannelSubscriptions int           `json:"channel_subscriptions"`
	SystemUptime         time.Duration `json:"system_uptime"`
	LastActivity         time.Time     `json:"last_activity"`
}

// Background workers
func (rs *RealtimeSystem) heartbeatWorker(ctx context.Context) {
	defer rs.wg.Done()

	ticker := time.NewTicker(rs.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rs.stopChan:
			return
		case <-ticker.C:
			rs.sendHeartbeat(ctx)
		}
	}
}

func (rs *RealtimeSystem) cleanupWorker(ctx context.Context) {
	defer rs.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rs.stopChan:
			return
		case <-ticker.C:
			rs.performCleanup(ctx)
		}
	}
}

func (rs *RealtimeSystem) metricsWorker(ctx context.Context) {
	defer rs.wg.Done()

	if !rs.config.MetricsEnabled {
		return
	}

	ticker := time.NewTicker(rs.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rs.stopChan:
			return
		case <-ticker.C:
			rs.collectMetrics(ctx)
		}
	}
}

func (rs *RealtimeSystem) sendHeartbeat(ctx context.Context) {
	heartbeatData := map[string]interface{}{
		"timestamp": time.Now(),
		"system":    "realtime",
		"status":    "healthy",
	}

	rs.PublishMessage(ctx, "system.heartbeat", heartbeatData)
}

func (rs *RealtimeSystem) performCleanup(ctx context.Context) {
	rs.connectionPool.CleanupStaleConnections()
	rs.pubsubManager.CleanupStaleSubscriptions()
}

func (rs *RealtimeSystem) collectMetrics(ctx context.Context) {
	metrics := rs.GetMetrics()
	rs.logger.Debug("Real-time system metrics",
		"active_connections", metrics.ActiveConnections,
		"total_messages", metrics.TotalMessages,
		"channel_subscriptions", metrics.ChannelSubscriptions,
		"uptime", metrics.SystemUptime)
}
