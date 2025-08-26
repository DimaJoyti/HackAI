package messaging

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var enhancedCommTracer = otel.Tracer("hackai/langgraph/messaging/enhanced")

// EnhancedCommunicationHub provides advanced multi-agent communication capabilities
type EnhancedCommunicationHub struct {
	messageRouter       *MessageRouter
	consensusEngine     *ConsensusEngine
	broadcastManager    *BroadcastManager
	subscriptionManager *SubscriptionManager
	messageBuffer       *MessageBuffer
	reliabilityManager  *ReliabilityManager
	securityManager     *CommunicationSecurityManager
	metricsCollector    *CommunicationMetrics
	config              *EnhancedCommunicationConfig
	logger              *logger.Logger
	mutex               sync.RWMutex
}

// EnhancedCommunicationConfig configures the enhanced communication system
type EnhancedCommunicationConfig struct {
	EnableConsensus       bool          `json:"enable_consensus"`
	EnableReliability     bool          `json:"enable_reliability"`
	EnableSecurity        bool          `json:"enable_security"`
	MaxMessageBuffer      int           `json:"max_message_buffer"`
	MessageRetryAttempts  int           `json:"message_retry_attempts"`
	MessageTimeout        time.Duration `json:"message_timeout"`
	ConsensusTimeout      time.Duration `json:"consensus_timeout"`
	BroadcastBatchSize    int           `json:"broadcast_batch_size"`
	EnableMessageOrdering bool          `json:"enable_message_ordering"`
	EnableDeduplication   bool          `json:"enable_deduplication"`
	CompressionEnabled    bool          `json:"compression_enabled"`
	EncryptionEnabled     bool          `json:"encryption_enabled"`
}

// ConsensusEngine handles distributed consensus among agents
type ConsensusEngine struct {
	proposals       map[string]*ConsensusProposal
	votes           map[string]map[string]*Vote
	consensusRules  map[string]ConsensusRule
	activeConsensus map[string]*ActiveConsensus
	logger          *logger.Logger
	mutex           sync.RWMutex
}

// ConsensusProposal represents a proposal for consensus
type ConsensusProposal struct {
	ID           string                 `json:"id"`
	ProposerID   string                 `json:"proposer_id"`
	Type         ConsensusType          `json:"type"`
	Content      interface{}            `json:"content"`
	Participants []string               `json:"participants"`
	Deadline     time.Time              `json:"deadline"`
	Metadata     map[string]interface{} `json:"metadata"`
	CreatedAt    time.Time              `json:"created_at"`
}

// Vote represents a vote in consensus
type Vote struct {
	VoterID   string                 `json:"voter_id"`
	Decision  VoteDecision           `json:"decision"`
	Reasoning string                 `json:"reasoning"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// ConsensusType defines the type of consensus
type ConsensusType string

const (
	ConsensusTypeSimpleMajority   ConsensusType = "simple_majority"
	ConsensusTypeUnanimous        ConsensusType = "unanimous"
	ConsensusTypeWeightedMajority ConsensusType = "weighted_majority"
	ConsensusTypeQuorum           ConsensusType = "quorum"
)

// VoteDecision represents a vote decision
type VoteDecision string

const (
	VoteApprove VoteDecision = "approve"
	VoteReject  VoteDecision = "reject"
	VoteAbstain VoteDecision = "abstain"
)

// ConsensusRule defines rules for consensus
type ConsensusRule struct {
	Type                ConsensusType          `json:"type"`
	MinimumParticipants int                    `json:"minimum_participants"`
	RequiredPercentage  float64                `json:"required_percentage"`
	Timeout             time.Duration          `json:"timeout"`
	WeightFunction      WeightFunction         `json:"weight_function"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// WeightFunction calculates voting weight for agents
type WeightFunction func(agentID string, context map[string]interface{}) float64

// ActiveConsensus tracks ongoing consensus processes
type ActiveConsensus struct {
	Proposal     *ConsensusProposal `json:"proposal"`
	Votes        map[string]*Vote   `json:"votes"`
	Status       ConsensusStatus    `json:"status"`
	Result       *ConsensusResult   `json:"result"`
	StartTime    time.Time          `json:"start_time"`
	EndTime      *time.Time         `json:"end_time"`
	Participants map[string]bool    `json:"participants"`
}

// ConsensusStatus represents the status of consensus
type ConsensusStatus string

const (
	ConsensusStatusPending   ConsensusStatus = "pending"
	ConsensusStatusActive    ConsensusStatus = "active"
	ConsensusStatusCompleted ConsensusStatus = "completed"
	ConsensusStatusTimeout   ConsensusStatus = "timeout"
	ConsensusStatusCancelled ConsensusStatus = "cancelled"
)

// ConsensusResult represents the result of consensus
type ConsensusResult struct {
	Decision      VoteDecision           `json:"decision"`
	VoteCount     map[VoteDecision]int   `json:"vote_count"`
	Participation float64                `json:"participation"`
	Confidence    float64                `json:"confidence"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// BroadcastManager handles efficient message broadcasting
type BroadcastManager struct {
	broadcastGroups map[string]*BroadcastGroup
	messageQueue    chan *BroadcastMessage
	workers         []*BroadcastWorker
	config          *BroadcastConfig
	logger          *logger.Logger
	mutex           sync.RWMutex
}

// BroadcastGroup represents a group of agents for broadcasting
type BroadcastGroup struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Members      []string               `json:"members"`
	Filters      []MessageFilter        `json:"filters"`
	Priority     Priority               `json:"priority"`
	Metadata     map[string]interface{} `json:"metadata"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
}

// BroadcastMessage represents a message to be broadcast
type BroadcastMessage struct {
	ID        string                 `json:"id"`
	GroupID   string                 `json:"group_id"`
	Content   interface{}            `json:"content"`
	Type      MessageType            `json:"type"`
	Priority  Priority               `json:"priority"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// MessageFilter defines filters for message routing
type MessageFilter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// BroadcastConfig configures broadcast behavior
type BroadcastConfig struct {
	MaxWorkers     int           `json:"max_workers"`
	BatchSize      int           `json:"batch_size"`
	RetryAttempts  int           `json:"retry_attempts"`
	RetryDelay     time.Duration `json:"retry_delay"`
	QueueSize      int           `json:"queue_size"`
	EnableBatching bool          `json:"enable_batching"`
}

// BroadcastWorker handles broadcast message processing
type BroadcastWorker struct {
	ID           string
	messageQueue chan *BroadcastMessage
	router       *MessageRouter
	logger       *logger.Logger
	stopChan     chan struct{}
}

// SubscriptionManager handles pub/sub messaging patterns
type SubscriptionManager struct {
	subscriptions map[string]*Subscription
	topics        map[string]*Topic
	subscribers   map[string][]string
	publishers    map[string][]string
	messageQueue  chan *TopicMessage
	config        *SubscriptionConfig
	logger        *logger.Logger
	mutex         sync.RWMutex
}

// Subscription represents an agent's subscription to a topic
type Subscription struct {
	ID         string                 `json:"id"`
	AgentID    string                 `json:"agent_id"`
	TopicID    string                 `json:"topic_id"`
	Filters    []MessageFilter        `json:"filters"`
	Priority   Priority               `json:"priority"`
	Metadata   map[string]interface{} `json:"metadata"`
	CreatedAt  time.Time              `json:"created_at"`
	LastAccess time.Time              `json:"last_access"`
}

// Topic represents a communication topic
type Topic struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Subscribers  []string               `json:"subscribers"`
	Publishers   []string               `json:"publishers"`
	MessageCount int64                  `json:"message_count"`
	Metadata     map[string]interface{} `json:"metadata"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
}

// TopicMessage represents a message published to a topic
type TopicMessage struct {
	ID        string                 `json:"id"`
	TopicID   string                 `json:"topic_id"`
	Publisher string                 `json:"publisher"`
	Content   interface{}            `json:"content"`
	Type      MessageType            `json:"type"`
	Priority  Priority               `json:"priority"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// SubscriptionConfig configures subscription behavior
type SubscriptionConfig struct {
	MaxSubscriptions     int           `json:"max_subscriptions"`
	MessageRetention     time.Duration `json:"message_retention"`
	EnableFiltering      bool          `json:"enable_filtering"`
	EnablePrioritization bool          `json:"enable_prioritization"`
	QueueSize            int           `json:"queue_size"`
}

// MessageBuffer provides reliable message buffering
type MessageBuffer struct {
	buffer     map[string]*BufferedMessage
	priorities map[Priority][]*BufferedMessage
	config     *BufferConfig
	logger     *logger.Logger
	mutex      sync.RWMutex
}

// BufferedMessage represents a buffered message
type BufferedMessage struct {
	Message     *AgentMessage `json:"message"`
	Attempts    int           `json:"attempts"`
	NextRetry   time.Time     `json:"next_retry"`
	MaxRetries  int           `json:"max_retries"`
	CreatedAt   time.Time     `json:"created_at"`
	LastAttempt time.Time     `json:"last_attempt"`
}

// BufferConfig configures message buffering
type BufferConfig struct {
	MaxBufferSize    int           `json:"max_buffer_size"`
	RetryDelay       time.Duration `json:"retry_delay"`
	MaxRetries       int           `json:"max_retries"`
	EnablePriority   bool          `json:"enable_priority"`
	PersistentBuffer bool          `json:"persistent_buffer"`
}

// NewEnhancedCommunicationHub creates a new enhanced communication hub
func NewEnhancedCommunicationHub(config *EnhancedCommunicationConfig, logger *logger.Logger) *EnhancedCommunicationHub {
	if config == nil {
		config = DefaultEnhancedCommunicationConfig()
	}

	hub := &EnhancedCommunicationHub{
		messageRouter: NewMessageRouter(logger),
		config:        config,
		logger:        logger,
	}

	// Initialize components based on configuration
	if config.EnableConsensus {
		hub.consensusEngine = NewConsensusEngine(logger)
	}

	hub.broadcastManager = NewBroadcastManager(&BroadcastConfig{
		MaxWorkers:     10,
		BatchSize:      config.BroadcastBatchSize,
		RetryAttempts:  config.MessageRetryAttempts,
		RetryDelay:     time.Second,
		QueueSize:      1000,
		EnableBatching: true,
	}, logger)

	hub.subscriptionManager = NewSubscriptionManager(&SubscriptionConfig{
		MaxSubscriptions:     1000,
		MessageRetention:     24 * time.Hour,
		EnableFiltering:      true,
		EnablePrioritization: true,
		QueueSize:            1000,
	}, logger)

	hub.messageBuffer = NewMessageBuffer(&BufferConfig{
		MaxBufferSize:    config.MaxMessageBuffer,
		RetryDelay:       time.Second,
		MaxRetries:       config.MessageRetryAttempts,
		EnablePriority:   true,
		PersistentBuffer: false,
	}, logger)

	if config.EnableReliability {
		hub.reliabilityManager = NewReliabilityManager(logger)
	}

	if config.EnableSecurity {
		hub.securityManager = NewCommunicationSecurityManager(logger)
	}

	hub.metricsCollector = NewCommunicationMetrics(logger)

	return hub
}

// DefaultEnhancedCommunicationConfig returns default configuration
func DefaultEnhancedCommunicationConfig() *EnhancedCommunicationConfig {
	return &EnhancedCommunicationConfig{
		EnableConsensus:       true,
		EnableReliability:     true,
		EnableSecurity:        true,
		MaxMessageBuffer:      10000,
		MessageRetryAttempts:  3,
		MessageTimeout:        30 * time.Second,
		ConsensusTimeout:      60 * time.Second,
		BroadcastBatchSize:    100,
		EnableMessageOrdering: true,
		EnableDeduplication:   true,
		CompressionEnabled:    true,
		EncryptionEnabled:     false,
	}
}

// SendMessage sends a message through the enhanced communication hub
func (ech *EnhancedCommunicationHub) SendMessage(ctx context.Context, message *AgentMessage) error {
	ctx, span := enhancedCommTracer.Start(ctx, "enhanced_communication.send_message",
		trace.WithAttributes(
			attribute.String("message.id", message.ID),
			attribute.String("message.from", message.From),
			attribute.Int("message.to_count", len(message.To)),
		),
	)
	defer span.End()

	// Apply security checks if enabled
	if ech.config.EnableSecurity && ech.securityManager != nil {
		if err := ech.securityManager.ValidateMessage(ctx, message); err != nil {
			span.RecordError(err)
			return fmt.Errorf("security validation failed: %w", err)
		}
	}

	// Apply deduplication if enabled
	if ech.config.EnableDeduplication {
		if ech.isDuplicateMessage(message) {
			ech.logger.Debug("Duplicate message detected, skipping", "message_id", message.ID)
			return nil
		}
	}

	// Buffer message for reliability if enabled
	if ech.config.EnableReliability && ech.messageBuffer != nil {
		if err := ech.messageBuffer.BufferMessage(ctx, message); err != nil {
			ech.logger.Error("Failed to buffer message", "error", err)
		}
	}

	// Route message through standard router
	if err := ech.messageRouter.RouteMessage(ctx, message); err != nil {
		span.RecordError(err)
		return fmt.Errorf("message routing failed: %w", err)
	}

	// Update metrics
	ech.metricsCollector.RecordMessageSent(message)

	return nil
}

// BroadcastMessage broadcasts a message to multiple agents
func (ech *EnhancedCommunicationHub) BroadcastMessage(ctx context.Context, groupID string, content interface{}, messageType MessageType) error {
	ctx, span := enhancedCommTracer.Start(ctx, "enhanced_communication.broadcast_message",
		trace.WithAttributes(
			attribute.String("group.id", groupID),
			attribute.String("message.type", string(messageType)),
		),
	)
	defer span.End()

	broadcastMsg := &BroadcastMessage{
		ID:        uuid.New().String(),
		GroupID:   groupID,
		Content:   content,
		Type:      messageType,
		Priority:  PriorityNormal,
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	if err := ech.broadcastManager.Broadcast(ctx, broadcastMsg); err != nil {
		span.RecordError(err)
		return fmt.Errorf("broadcast failed: %w", err)
	}

	return nil
}

// InitiateConsensus initiates a consensus process among agents
func (ech *EnhancedCommunicationHub) InitiateConsensus(ctx context.Context, proposal *ConsensusProposal) (*ActiveConsensus, error) {
	if !ech.config.EnableConsensus || ech.consensusEngine == nil {
		return nil, fmt.Errorf("consensus not enabled")
	}

	ctx, span := enhancedCommTracer.Start(ctx, "enhanced_communication.initiate_consensus",
		trace.WithAttributes(
			attribute.String("proposal.id", proposal.ID),
			attribute.String("proposal.type", string(proposal.Type)),
			attribute.Int("participants.count", len(proposal.Participants)),
		),
	)
	defer span.End()

	consensus, err := ech.consensusEngine.InitiateConsensus(ctx, proposal)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("consensus initiation failed: %w", err)
	}

	return consensus, nil
}

// SubscribeToTopic subscribes an agent to a topic
func (ech *EnhancedCommunicationHub) SubscribeToTopic(ctx context.Context, agentID, topicID string, filters []MessageFilter) (*Subscription, error) {
	ctx, span := enhancedCommTracer.Start(ctx, "enhanced_communication.subscribe_to_topic",
		trace.WithAttributes(
			attribute.String("agent.id", agentID),
			attribute.String("topic.id", topicID),
		),
	)
	defer span.End()

	subscription, err := ech.subscriptionManager.Subscribe(ctx, agentID, topicID, filters)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("subscription failed: %w", err)
	}

	return subscription, nil
}

// PublishToTopic publishes a message to a topic
func (ech *EnhancedCommunicationHub) PublishToTopic(ctx context.Context, topicID, publisher string, content interface{}, messageType MessageType) error {
	ctx, span := enhancedCommTracer.Start(ctx, "enhanced_communication.publish_to_topic",
		trace.WithAttributes(
			attribute.String("topic.id", topicID),
			attribute.String("publisher", publisher),
			attribute.String("message.type", string(messageType)),
		),
	)
	defer span.End()

	topicMsg := &TopicMessage{
		ID:        uuid.New().String(),
		TopicID:   topicID,
		Publisher: publisher,
		Content:   content,
		Type:      messageType,
		Priority:  PriorityNormal,
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	if err := ech.subscriptionManager.Publish(ctx, topicMsg); err != nil {
		span.RecordError(err)
		return fmt.Errorf("publish failed: %w", err)
	}

	return nil
}

// isDuplicateMessage checks if a message is a duplicate
func (ech *EnhancedCommunicationHub) isDuplicateMessage(message *AgentMessage) bool {
	// Simple implementation - in production, use a more sophisticated approach
	// with time windows and content hashing
	return false
}
