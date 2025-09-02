package orchestration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/agents/multiagent"
	"github.com/dimajoyti/hackai/pkg/langgraph/messaging"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// CommunicationHub manages advanced agent communication
type CommunicationHub struct {
	channels         map[string]*CommunicationChannel
	messageRouter    *messaging.MessageRouter
	protocolHandlers map[CommunicationProtocol]ProtocolHandler
	config           *OrchestratorConfig
	logger           *logger.Logger
	mutex            sync.RWMutex
}

// CommunicationChannel represents a communication channel between agents
type CommunicationChannel struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Type          ChannelType            `json:"type"`
	Protocol      CommunicationProtocol  `json:"protocol"`
	Participants  []string               `json:"participants"`
	Status        ChannelStatus          `json:"status"`
	Configuration *ChannelConfig         `json:"configuration"`
	MessageQueue  []*ChannicationMessage `json:"message_queue"`
	Statistics    *ChannelStatistics     `json:"statistics"`
	CreatedAt     time.Time              `json:"created_at"`
	LastActivity  time.Time              `json:"last_activity"`
	Metadata      map[string]interface{} `json:"metadata"`
	mutex         sync.RWMutex
}

// ChannelConfig holds configuration for a communication channel
type ChannelConfig struct {
	MaxMessageSize   int                    `json:"max_message_size"`
	MessageRetention time.Duration          `json:"message_retention"`
	Encryption       bool                   `json:"encryption"`
	Compression      bool                   `json:"compression"`
	Reliability      ReliabilityLevel       `json:"reliability"`
	Timeout          time.Duration          `json:"timeout"`
	RetryPolicy      *RetryPolicy           `json:"retry_policy"`
	RateLimit        *RateLimit             `json:"rate_limit"`
	Filters          []MessageFilter        `json:"filters"`
	Middleware       []string               `json:"middleware"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// ChannelStatistics holds statistics for a communication channel
type ChannelStatistics struct {
	MessagesSent     int64         `json:"messages_sent"`
	MessagesReceived int64         `json:"messages_received"`
	MessagesDropped  int64         `json:"messages_dropped"`
	BytesSent        int64         `json:"bytes_sent"`
	BytesReceived    int64         `json:"bytes_received"`
	AverageLatency   time.Duration `json:"average_latency"`
	ErrorCount       int64         `json:"error_count"`
	LastMessageTime  time.Time     `json:"last_message_time"`
	ThroughputPerSec float64       `json:"throughput_per_sec"`
}

// ChannicationMessage represents a message in the communication system
type ChannicationMessage struct {
	ID            string                 `json:"id"`
	Type          MessageType            `json:"type"`
	From          string                 `json:"from"`
	To            []string               `json:"to"`
	Subject       string                 `json:"subject"`
	Content       interface{}            `json:"content"`
	Priority      MessagePriority        `json:"priority"`
	Timestamp     time.Time              `json:"timestamp"`
	ExpiresAt     *time.Time             `json:"expires_at,omitempty"`
	CorrelationID string                 `json:"correlation_id"`
	ReplyTo       string                 `json:"reply_to,omitempty"`
	Headers       map[string]string      `json:"headers"`
	Metadata      map[string]interface{} `json:"metadata"`
	Encrypted     bool                   `json:"encrypted"`
	Compressed    bool                   `json:"compressed"`
	Size          int64                  `json:"size"`
}

// MessageFilter defines message filtering criteria
type MessageFilter struct {
	Type     FilterType             `json:"type"`
	Field    string                 `json:"field"`
	Operator FilterOperator         `json:"operator"`
	Value    interface{}            `json:"value"`
	Action   FilterAction           `json:"action"`
	Metadata map[string]interface{} `json:"metadata"`
}

// RateLimit defines rate limiting for channels
type RateLimit struct {
	MessagesPerSecond int           `json:"messages_per_second"`
	BurstSize         int           `json:"burst_size"`
	WindowSize        time.Duration `json:"window_size"`
}

// ProtocolHandler interface for different communication protocols
type ProtocolHandler interface {
	Initialize(config *ChannelConfig) error
	SendMessage(ctx context.Context, message *ChannicationMessage) error
	ReceiveMessage(ctx context.Context) (*ChannicationMessage, error)
	Close() error
	GetStatistics() *ProtocolStatistics
}

// ProtocolStatistics holds statistics for a protocol handler
type ProtocolStatistics struct {
	ConnectionsActive int64         `json:"connections_active"`
	MessagesSent      int64         `json:"messages_sent"`
	MessagesReceived  int64         `json:"messages_received"`
	BytesSent         int64         `json:"bytes_sent"`
	BytesReceived     int64         `json:"bytes_received"`
	ErrorCount        int64         `json:"error_count"`
	AverageLatency    time.Duration `json:"average_latency"`
}

// Enums for communication
type ChannelType string
type ChannelStatus string
type MessageType string
type MessagePriority string
type FilterType string
type FilterOperator string
type FilterAction string

const (
	// Channel Types
	ChannelTypePointToPoint ChannelType = "point_to_point"
	ChannelTypeMulticast    ChannelType = "multicast"
	ChannelTypeBroadcast    ChannelType = "broadcast"
	ChannelTypePubSub       ChannelType = "pub_sub"
	ChannelTypeQueue        ChannelType = "queue"

	// Channel Status
	ChannelStatusActive   ChannelStatus = "active"
	ChannelStatusInactive ChannelStatus = "inactive"
	ChannelStatusError    ChannelStatus = "error"
	ChannelStatusClosed   ChannelStatus = "closed"

	// Message Types
	MessageTypeCommand      MessageType = "command"
	MessageTypeQuery        MessageType = "query"
	MessageTypeResponse     MessageType = "response"
	MessageTypeNotification MessageType = "notification"
	MessageTypeEvent        MessageType = "event"
	MessageTypeHeartbeat    MessageType = "heartbeat"

	// Message Priorities
	PriorityLow      MessagePriority = "low"
	PriorityNormal   MessagePriority = "normal"
	PriorityHigh     MessagePriority = "high"
	PriorityCritical MessagePriority = "critical"

	// Filter Types
	FilterTypeContent FilterType = "content"
	FilterTypeHeader  FilterType = "header"
	FilterTypeSender  FilterType = "sender"
	FilterTypeSize    FilterType = "size"

	// Filter Operators
	OperatorEquals      FilterOperator = "equals"
	OperatorNotEquals   FilterOperator = "not_equals"
	OperatorContains    FilterOperator = "contains"
	OperatorMatches     FilterOperator = "matches"
	OperatorGreaterThan FilterOperator = "greater_than"
	OperatorLessThan    FilterOperator = "less_than"

	// Filter Actions
	ActionAllow FilterAction = "allow"
	ActionDeny  FilterAction = "deny"
	ActionLog   FilterAction = "log"
	ActionRoute FilterAction = "route"
)

// NewCommunicationHub creates a new communication hub
func NewCommunicationHub(config *OrchestratorConfig, logger *logger.Logger) *CommunicationHub {
	hub := &CommunicationHub{
		channels:         make(map[string]*CommunicationChannel),
		messageRouter:    messaging.NewMessageRouter(logger),
		protocolHandlers: make(map[CommunicationProtocol]ProtocolHandler),
		config:           config,
		logger:           logger,
	}

	// Initialize protocol handlers
	hub.initializeProtocolHandlers()

	return hub
}

// InitializeChannels initializes communication channels for a task
func (ch *CommunicationHub) InitializeChannels(ctx context.Context, task *OrchestrationTask, agents map[string]multiagent.Agent) error {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()

	ch.logger.Info("Initializing communication channels",
		"task_id", task.ID,
		"agents", len(agents))

	// Create channels based on task phases and coordination specs
	for _, phase := range task.Phases {
		if phase.Coordination != nil && phase.Coordination.Communication != nil {
			channel, err := ch.createChannel(ctx, phase, agents)
			if err != nil {
				return fmt.Errorf("failed to create channel for phase %s: %w", phase.ID, err)
			}

			ch.channels[channel.ID] = channel
			ch.logger.Debug("Communication channel created",
				"channel_id", channel.ID,
				"phase_id", phase.ID,
				"protocol", channel.Protocol)
		}
	}

	// Create default channels for agent-to-agent communication
	if err := ch.createDefaultChannels(ctx, task, agents); err != nil {
		return fmt.Errorf("failed to create default channels: %w", err)
	}

	return nil
}

// SendMessage sends a message through the communication hub
func (ch *CommunicationHub) SendMessage(ctx context.Context, message *ChannicationMessage) error {
	ch.mutex.RLock()
	defer ch.mutex.RUnlock()

	// Find appropriate channel
	channel := ch.findChannelForMessage(message)
	if channel == nil {
		return fmt.Errorf("no suitable channel found for message")
	}

	// Apply filters
	if !ch.applyFilters(message, channel.Configuration.Filters) {
		return fmt.Errorf("message filtered out")
	}

	// Apply rate limiting
	if err := ch.applyRateLimit(channel); err != nil {
		return fmt.Errorf("rate limit exceeded: %w", err)
	}

	// Get protocol handler
	handler, exists := ch.protocolHandlers[channel.Protocol]
	if !exists {
		return fmt.Errorf("protocol handler not found for %s", channel.Protocol)
	}

	// Send message
	if err := handler.SendMessage(ctx, message); err != nil {
		channel.Statistics.ErrorCount++
		return fmt.Errorf("failed to send message: %w", err)
	}

	// Update statistics
	ch.updateChannelStatistics(channel, message, true)

	ch.logger.Debug("Message sent",
		"message_id", message.ID,
		"channel_id", channel.ID,
		"from", message.From,
		"to", message.To)

	return nil
}

// ReceiveMessage receives a message from the communication hub
func (ch *CommunicationHub) ReceiveMessage(ctx context.Context, agentID string) (*ChannicationMessage, error) {
	ch.mutex.RLock()
	defer ch.mutex.RUnlock()

	// Find channels where agent is a participant
	for _, channel := range ch.channels {
		if ch.isParticipant(agentID, channel.Participants) {
			handler, exists := ch.protocolHandlers[channel.Protocol]
			if !exists {
				continue
			}

			message, err := handler.ReceiveMessage(ctx)
			if err != nil {
				continue // Try next channel
			}

			if message != nil {
				// Update statistics
				ch.updateChannelStatistics(channel, message, false)

				ch.logger.Debug("Message received",
					"message_id", message.ID,
					"channel_id", channel.ID,
					"agent_id", agentID)

				return message, nil
			}
		}
	}

	return nil, fmt.Errorf("no messages available for agent %s", agentID)
}

// CloseChannels closes all communication channels for a task
func (ch *CommunicationHub) CloseChannels(ctx context.Context, task *OrchestrationTask) error {
	ch.mutex.Lock()
	defer ch.mutex.Unlock()

	var errors []error

	for channelID, channel := range ch.channels {
		if ch.isTaskChannel(task.ID, channel) {
			if err := ch.closeChannel(channel); err != nil {
				errors = append(errors, err)
			} else {
				delete(ch.channels, channelID)
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors closing channels: %v", errors)
	}

	ch.logger.Info("Communication channels closed", "task_id", task.ID)
	return nil
}

// Helper methods

func (ch *CommunicationHub) initializeProtocolHandlers() {
	// Initialize HTTP handler
	ch.protocolHandlers[ProtocolHTTP] = NewHTTPProtocolHandler(ch.config, ch.logger)

	// Initialize WebSocket handler
	ch.protocolHandlers[ProtocolWebSocket] = NewWebSocketProtocolHandler(ch.config, ch.logger)

	// Initialize gRPC handler
	ch.protocolHandlers[ProtocolGRPC] = NewGRPCProtocolHandler(ch.config, ch.logger)

	// Initialize MQTT handler
	ch.protocolHandlers[ProtocolMQTT] = NewMQTTProtocolHandler(ch.config, ch.logger)

	// Initialize Custom handler
	ch.protocolHandlers[ProtocolCustom] = NewCustomProtocolHandler(ch.config, ch.logger)
}

func (ch *CommunicationHub) createChannel(ctx context.Context, phase *TaskPhase, agents map[string]multiagent.Agent) (*CommunicationChannel, error) {
	commSpec := phase.Coordination.Communication

	channel := &CommunicationChannel{
		ID:           uuid.New().String(),
		Name:         fmt.Sprintf("channel_%s", phase.ID),
		Type:         ChannelTypeMulticast, // Default
		Protocol:     commSpec.Protocol,
		Participants: commSpec.Channels, // Use channels as participants for now
		Status:       ChannelStatusActive,
		Configuration: &ChannelConfig{
			MaxMessageSize:   1024 * 1024, // 1MB
			MessageRetention: time.Hour,
			Encryption:       commSpec.Encryption,
			Compression:      commSpec.Compression,
			Reliability:      commSpec.Reliability,
			Timeout:          commSpec.Timeout,
			RetryPolicy:      commSpec.RetryPolicy,
			Filters:          make([]MessageFilter, 0),
			Middleware:       make([]string, 0),
			Metadata:         make(map[string]interface{}),
		},
		MessageQueue: make([]*ChannicationMessage, 0),
		Statistics: &ChannelStatistics{
			LastMessageTime: time.Now(),
		},
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	// Initialize protocol handler
	handler, exists := ch.protocolHandlers[channel.Protocol]
	if !exists {
		return nil, fmt.Errorf("protocol handler not found for %s", channel.Protocol)
	}

	if err := handler.Initialize(channel.Configuration); err != nil {
		return nil, fmt.Errorf("failed to initialize protocol handler: %w", err)
	}

	return channel, nil
}

func (ch *CommunicationHub) createDefaultChannels(ctx context.Context, task *OrchestrationTask, agents map[string]multiagent.Agent) error {
	// Create a default broadcast channel for all agents
	participants := make([]string, 0, len(agents))
	for agentID := range agents {
		participants = append(participants, agentID)
	}

	defaultChannel := &CommunicationChannel{
		ID:           uuid.New().String(),
		Name:         fmt.Sprintf("default_%s", task.ID),
		Type:         ChannelTypeBroadcast,
		Protocol:     ProtocolHTTP, // Default protocol
		Participants: participants,
		Status:       ChannelStatusActive,
		Configuration: &ChannelConfig{
			MaxMessageSize:   1024 * 1024,
			MessageRetention: time.Hour,
			Encryption:       false,
			Compression:      false,
			Reliability:      ReliabilityBestEffort,
			Timeout:          30 * time.Second,
			Filters:          make([]MessageFilter, 0),
			Middleware:       make([]string, 0),
			Metadata:         make(map[string]interface{}),
		},
		MessageQueue: make([]*ChannicationMessage, 0),
		Statistics: &ChannelStatistics{
			LastMessageTime: time.Now(),
		},
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		Metadata:     map[string]interface{}{"task_id": task.ID},
	}

	ch.channels[defaultChannel.ID] = defaultChannel
	return nil
}

func (ch *CommunicationHub) findChannelForMessage(message *ChannicationMessage) *CommunicationChannel {
	// Simple implementation - find first suitable channel
	for _, channel := range ch.channels {
		if ch.isParticipant(message.From, channel.Participants) {
			return channel
		}
	}
	return nil
}

func (ch *CommunicationHub) applyFilters(message *ChannicationMessage, filters []MessageFilter) bool {
	for _, filter := range filters {
		if !ch.evaluateFilter(message, filter) {
			return false
		}
	}
	return true
}

func (ch *CommunicationHub) evaluateFilter(message *ChannicationMessage, filter MessageFilter) bool {
	// Simplified filter evaluation
	switch filter.Action {
	case ActionAllow:
		return true
	case ActionDeny:
		return false
	default:
		return true
	}
}

func (ch *CommunicationHub) applyRateLimit(channel *CommunicationChannel) error {
	// Simplified rate limiting
	if channel.Configuration.RateLimit != nil {
		// Check if rate limit is exceeded
		// This is a simplified implementation
		return nil
	}
	return nil
}

func (ch *CommunicationHub) updateChannelStatistics(channel *CommunicationChannel, message *ChannicationMessage, sent bool) {
	channel.mutex.Lock()
	defer channel.mutex.Unlock()

	if sent {
		channel.Statistics.MessagesSent++
		channel.Statistics.BytesSent += message.Size
	} else {
		channel.Statistics.MessagesReceived++
		channel.Statistics.BytesReceived += message.Size
	}

	channel.Statistics.LastMessageTime = time.Now()
	channel.LastActivity = time.Now()
}

func (ch *CommunicationHub) isParticipant(agentID string, participants []string) bool {
	for _, participant := range participants {
		if participant == agentID {
			return true
		}
	}
	return false
}

func (ch *CommunicationHub) isTaskChannel(taskID string, channel *CommunicationChannel) bool {
	if taskIDValue, exists := channel.Metadata["task_id"]; exists {
		if taskIDStr, ok := taskIDValue.(string); ok {
			return taskIDStr == taskID
		}
	}
	return false
}

func (ch *CommunicationHub) closeChannel(channel *CommunicationChannel) error {
	handler, exists := ch.protocolHandlers[channel.Protocol]
	if exists {
		if err := handler.Close(); err != nil {
			return err
		}
	}

	channel.Status = ChannelStatusClosed
	return nil
}

// GetChannelStatistics returns statistics for all channels
func (ch *CommunicationHub) GetChannelStatistics() map[string]*ChannelStatistics {
	ch.mutex.RLock()
	defer ch.mutex.RUnlock()

	stats := make(map[string]*ChannelStatistics)
	for channelID, channel := range ch.channels {
		stats[channelID] = channel.Statistics
	}

	return stats
}

// GetActiveChannels returns all active channels
func (ch *CommunicationHub) GetActiveChannels() []*CommunicationChannel {
	ch.mutex.RLock()
	defer ch.mutex.RUnlock()

	channels := make([]*CommunicationChannel, 0)
	for _, channel := range ch.channels {
		if channel.Status == ChannelStatusActive {
			channels = append(channels, channel)
		}
	}

	return channels
}
