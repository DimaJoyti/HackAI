package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// EventSystem handles event-driven communication
type EventSystem struct {
	eventBus       *EventBus
	subscribers    map[EventType][]EventHandler
	eventStore     EventStore
	eventProcessor *EventProcessor
	logger         *logger.Logger
	mutex          sync.RWMutex
}

// EventType represents the type of event
type EventType string

const (
	EventTypeNodeStarted   EventType = "node_started"
	EventTypeNodeCompleted EventType = "node_completed"
	EventTypeNodeFailed    EventType = "node_failed"
	EventTypeBranchCreated EventType = "branch_created"
	EventTypeBranchMerged  EventType = "branch_merged"
	EventTypeStateChanged  EventType = "state_changed"
	EventTypeCheckpoint    EventType = "checkpoint_created"
	EventTypeError         EventType = "error_occurred"
	EventTypeCustom        EventType = "custom"
)

// Event represents an event in the system
type Event struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Source    string                 `json:"source"`
	Target    string                 `json:"target,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// EventHandler interface for handling events
type EventHandler interface {
	Handle(ctx context.Context, event *Event) error
	CanHandle(eventType EventType) bool
}

// EventStore interface for storing events
type EventStore interface {
	Store(ctx context.Context, event *Event) error
	Load(ctx context.Context, eventID string) (*Event, error)
	Query(ctx context.Context, filter EventFilter) ([]*Event, error)
}

// EventFilter for querying events
type EventFilter struct {
	Types     []EventType `json:"types"`
	Source    string      `json:"source"`
	Target    string      `json:"target"`
	StartTime *time.Time  `json:"start_time"`
	EndTime   *time.Time  `json:"end_time"`
	Limit     int         `json:"limit"`
}

// EventBus handles event distribution
type EventBus struct {
	subscribers map[EventType][]chan *Event
	mutex       sync.RWMutex
	logger      *logger.Logger
}

// EventProcessor processes events asynchronously
type EventProcessor struct {
	eventQueue chan *Event
	handlers   map[EventType][]EventHandler
	logger     *logger.Logger
	running    bool
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// NewEventSystem creates a new event system
func NewEventSystem(logger *logger.Logger) *EventSystem {
	return &EventSystem{
		eventBus:       NewEventBus(logger),
		subscribers:    make(map[EventType][]EventHandler),
		eventStore:     NewMemoryEventStore(),
		eventProcessor: NewEventProcessor(logger),
		logger:         logger,
	}
}

// PublishEvent publishes an event to the system
func (es *EventSystem) PublishEvent(ctx context.Context, event *Event) error {
	es.mutex.Lock()
	defer es.mutex.Unlock()

	// Store event
	if err := es.eventStore.Store(ctx, event); err != nil {
		es.logger.Error("Failed to store event", "event_id", event.ID, "error", err)
	}

	// Publish to event bus
	if err := es.eventBus.Publish(ctx, event); err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	// Process event
	if err := es.eventProcessor.ProcessEvent(ctx, event); err != nil {
		es.logger.Error("Failed to process event", "event_id", event.ID, "error", err)
	}

	return nil
}

// Subscribe subscribes a handler to an event type
func (es *EventSystem) Subscribe(eventType EventType, handler EventHandler) error {
	es.mutex.Lock()
	defer es.mutex.Unlock()

	if es.subscribers[eventType] == nil {
		es.subscribers[eventType] = make([]EventHandler, 0)
	}
	es.subscribers[eventType] = append(es.subscribers[eventType], handler)

	// Also register with event processor
	return es.eventProcessor.RegisterHandler(eventType, handler)
}

// Unsubscribe removes a handler from an event type
func (es *EventSystem) Unsubscribe(eventType EventType, handler EventHandler) error {
	es.mutex.Lock()
	defer es.mutex.Unlock()

	handlers := es.subscribers[eventType]
	for i, h := range handlers {
		if h == handler {
			es.subscribers[eventType] = append(handlers[:i], handlers[i+1:]...)
			break
		}
	}

	return nil
}

// NewEventBus creates a new event bus
func NewEventBus(logger *logger.Logger) *EventBus {
	return &EventBus{
		subscribers: make(map[EventType][]chan *Event),
		logger:      logger,
	}
}

// Publish publishes an event to all subscribers
func (eb *EventBus) Publish(ctx context.Context, event *Event) error {
	eb.mutex.RLock()
	defer eb.mutex.RUnlock()

	subscribers, exists := eb.subscribers[event.Type]
	if !exists {
		return nil // No subscribers
	}

	// Send event to all subscribers
	for _, subscriber := range subscribers {
		select {
		case subscriber <- event:
			// Event sent successfully
		default:
			eb.logger.Warn("Subscriber channel full, dropping event", "event_id", event.ID)
		}
	}

	return nil
}

// Subscribe subscribes to an event type
func (eb *EventBus) Subscribe(eventType EventType) <-chan *Event {
	eb.mutex.Lock()
	defer eb.mutex.Unlock()

	eventChan := make(chan *Event, 100) // Buffered channel
	if eb.subscribers[eventType] == nil {
		eb.subscribers[eventType] = make([]chan *Event, 0)
	}
	eb.subscribers[eventType] = append(eb.subscribers[eventType], eventChan)

	return eventChan
}

// NewEventProcessor creates a new event processor
func NewEventProcessor(logger *logger.Logger) *EventProcessor {
	return &EventProcessor{
		eventQueue: make(chan *Event, 1000),
		handlers:   make(map[EventType][]EventHandler),
		logger:     logger,
		stopChan:   make(chan struct{}),
	}
}

// Start starts the event processor
func (ep *EventProcessor) Start(ctx context.Context) error {
	if ep.running {
		return fmt.Errorf("event processor already running")
	}

	ep.running = true
	ep.wg.Add(1)
	go ep.processEvents(ctx)

	ep.logger.Info("Event processor started")
	return nil
}

// Stop stops the event processor
func (ep *EventProcessor) Stop() error {
	if !ep.running {
		return fmt.Errorf("event processor not running")
	}

	close(ep.stopChan)
	ep.wg.Wait()
	ep.running = false

	ep.logger.Info("Event processor stopped")
	return nil
}

// ProcessEvent processes a single event
func (ep *EventProcessor) ProcessEvent(ctx context.Context, event *Event) error {
	if !ep.running {
		return fmt.Errorf("event processor not running")
	}

	select {
	case ep.eventQueue <- event:
		return nil
	default:
		return fmt.Errorf("event queue full")
	}
}

// RegisterHandler registers an event handler
func (ep *EventProcessor) RegisterHandler(eventType EventType, handler EventHandler) error {
	if ep.handlers[eventType] == nil {
		ep.handlers[eventType] = make([]EventHandler, 0)
	}
	ep.handlers[eventType] = append(ep.handlers[eventType], handler)
	return nil
}

// processEvents processes events from the queue
func (ep *EventProcessor) processEvents(ctx context.Context) {
	defer ep.wg.Done()

	for {
		select {
		case event := <-ep.eventQueue:
			ep.handleEvent(ctx, event)

		case <-ep.stopChan:
			return

		case <-ctx.Done():
			return
		}
	}
}

// handleEvent handles a single event
func (ep *EventProcessor) handleEvent(ctx context.Context, event *Event) {
	handlers, exists := ep.handlers[event.Type]
	if !exists {
		return // No handlers for this event type
	}

	for _, handler := range handlers {
		if handler.CanHandle(event.Type) {
			if err := handler.Handle(ctx, event); err != nil {
				ep.logger.Error("Event handler failed",
					"event_id", event.ID,
					"event_type", event.Type,
					"error", err)
			}
		}
	}
}

// MemoryEventStore implements in-memory event storage
type MemoryEventStore struct {
	events map[string]*Event
	mutex  sync.RWMutex
}

// NewMemoryEventStore creates a new memory event store
func NewMemoryEventStore() *MemoryEventStore {
	return &MemoryEventStore{
		events: make(map[string]*Event),
	}
}

// Store stores an event
func (mes *MemoryEventStore) Store(ctx context.Context, event *Event) error {
	mes.mutex.Lock()
	defer mes.mutex.Unlock()

	mes.events[event.ID] = event
	return nil
}

// Load loads an event by ID
func (mes *MemoryEventStore) Load(ctx context.Context, eventID string) (*Event, error) {
	mes.mutex.RLock()
	defer mes.mutex.RUnlock()

	event, exists := mes.events[eventID]
	if !exists {
		return nil, fmt.Errorf("event %s not found", eventID)
	}

	return event, nil
}

// Query queries events based on filter
func (mes *MemoryEventStore) Query(ctx context.Context, filter EventFilter) ([]*Event, error) {
	mes.mutex.RLock()
	defer mes.mutex.RUnlock()

	var results []*Event
	for _, event := range mes.events {
		if mes.matchesFilter(event, filter) {
			results = append(results, event)
		}
	}

	// Apply limit
	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[:filter.Limit]
	}

	return results, nil
}

// matchesFilter checks if an event matches the filter
func (mes *MemoryEventStore) matchesFilter(event *Event, filter EventFilter) bool {
	// Check event types
	if len(filter.Types) > 0 {
		found := false
		for _, eventType := range filter.Types {
			if event.Type == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check source
	if filter.Source != "" && event.Source != filter.Source {
		return false
	}

	// Check target
	if filter.Target != "" && event.Target != filter.Target {
		return false
	}

	// Check time range
	if filter.StartTime != nil && event.Timestamp.Before(*filter.StartTime) {
		return false
	}
	if filter.EndTime != nil && event.Timestamp.After(*filter.EndTime) {
		return false
	}

	return true
}

// DefaultEventHandler provides a base implementation for event handlers
type DefaultEventHandler struct {
	supportedTypes []EventType
	handler        func(ctx context.Context, event *Event) error
}

// NewDefaultEventHandler creates a new default event handler
func NewDefaultEventHandler(supportedTypes []EventType, handler func(ctx context.Context, event *Event) error) *DefaultEventHandler {
	return &DefaultEventHandler{
		supportedTypes: supportedTypes,
		handler:        handler,
	}
}

// Handle handles an event
func (deh *DefaultEventHandler) Handle(ctx context.Context, event *Event) error {
	if deh.handler != nil {
		return deh.handler(ctx, event)
	}
	return nil
}

// CanHandle checks if the handler can handle the event type
func (deh *DefaultEventHandler) CanHandle(eventType EventType) bool {
	for _, supportedType := range deh.supportedTypes {
		if supportedType == eventType {
			return true
		}
	}
	return false
}

// CreateEvent creates a new event
func CreateEvent(eventType EventType, source string, data map[string]interface{}) *Event {
	return &Event{
		ID:        uuid.New().String(),
		Type:      eventType,
		Source:    source,
		Timestamp: time.Now(),
		Data:      data,
		Metadata:  make(map[string]interface{}),
	}
}

// MessageRouter handles agent-to-agent communication
type MessageRouter struct {
	routes     map[string]MessageRoute
	channels   map[string]*MessageChannel
	middleware []MessageMiddleware
	serializer MessageSerializer
	logger     *logger.Logger
	mutex      sync.RWMutex
}

// MessageRoute defines how messages are routed
type MessageRoute struct {
	From       string                 `json:"from"`
	To         []string               `json:"to"`
	Conditions []RouteCondition       `json:"conditions"`
	Transform  MessageTransform       `json:"transform"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// RouteCondition defines conditions for message routing
type RouteCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// MessageTransform defines how messages are transformed during routing
type MessageTransform struct {
	AddFields    map[string]interface{} `json:"add_fields"`
	RemoveFields []string               `json:"remove_fields"`
	RenameFields map[string]string      `json:"rename_fields"`
}

// MessageChannel represents a communication channel between agents
type MessageChannel struct {
	ID          string
	From        string
	To          string
	MessageChan chan *AgentMessage
	Config      ChannelConfig
	Stats       *ChannelStats
	mutex       sync.RWMutex
}

// ChannelConfig holds channel configuration
type ChannelConfig struct {
	BufferSize  int           `json:"buffer_size"`
	Timeout     time.Duration `json:"timeout"`
	Persistent  bool          `json:"persistent"`
	Encrypted   bool          `json:"encrypted"`
	Compression bool          `json:"compression"`
}

// ChannelStats holds channel statistics
type ChannelStats struct {
	MessagesSent     int64     `json:"messages_sent"`
	MessagesReceived int64     `json:"messages_received"`
	BytesSent        int64     `json:"bytes_sent"`
	BytesReceived    int64     `json:"bytes_received"`
	LastActivity     time.Time `json:"last_activity"`
	ErrorCount       int64     `json:"error_count"`
}

// AgentMessage represents a message between agents
type AgentMessage struct {
	ID        string                 `json:"id"`
	From      string                 `json:"from"`
	To        []string               `json:"to"`
	Type      MessageType            `json:"type"`
	Content   interface{}            `json:"content"`
	Timestamp time.Time              `json:"timestamp"`
	Priority  Priority               `json:"priority"`
	ReplyTo   *string                `json:"reply_to,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// MessageType represents the type of message
type MessageType string

const (
	MessageTypeRequest      MessageType = "request"
	MessageTypeResponse     MessageType = "response"
	MessageTypeNotification MessageType = "notification"
	MessageTypeCommand      MessageType = "command"
	MessageTypeEvent        MessageType = "event"
	MessageTypeData         MessageType = "data"
)

// Priority represents message priority
type Priority int

const (
	PriorityLow      Priority = 1
	PriorityNormal   Priority = 5
	PriorityHigh     Priority = 8
	PriorityCritical Priority = 10
)

// MessageMiddleware interface for message processing middleware
type MessageMiddleware interface {
	Process(ctx context.Context, message *AgentMessage, next func(*AgentMessage) error) error
}

// MessageSerializer interface for message serialization
type MessageSerializer interface {
	Serialize(message *AgentMessage) ([]byte, error)
	Deserialize(data []byte) (*AgentMessage, error)
}

// NewMessageRouter creates a new message router
func NewMessageRouter(logger *logger.Logger) *MessageRouter {
	return &MessageRouter{
		routes:     make(map[string]MessageRoute),
		channels:   make(map[string]*MessageChannel),
		middleware: make([]MessageMiddleware, 0),
		serializer: NewJSONMessageSerializer(),
		logger:     logger,
	}
}

// RouteMessage routes a message to its destination
func (mr *MessageRouter) RouteMessage(ctx context.Context, message *AgentMessage) error {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	// Apply middleware
	err := mr.applyMiddleware(ctx, message)
	if err != nil {
		return fmt.Errorf("middleware processing failed: %w", err)
	}

	// Route to each destination
	for _, to := range message.To {
		channel, err := mr.getOrCreateChannel(message.From, to)
		if err != nil {
			mr.logger.Error("Failed to get channel", "from", message.From, "to", to, "error", err)
			continue
		}

		// Send message through channel
		select {
		case channel.MessageChan <- message:
			channel.Stats.MessagesSent++
			channel.Stats.LastActivity = time.Now()
		case <-time.After(channel.Config.Timeout):
			mr.logger.Error("Message routing timeout", "from", message.From, "to", to)
			channel.Stats.ErrorCount++
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// getOrCreateChannel gets or creates a message channel
func (mr *MessageRouter) getOrCreateChannel(from, to string) (*MessageChannel, error) {
	channelID := fmt.Sprintf("%s->%s", from, to)

	if channel, exists := mr.channels[channelID]; exists {
		return channel, nil
	}

	// Create new channel
	channel := &MessageChannel{
		ID:          channelID,
		From:        from,
		To:          to,
		MessageChan: make(chan *AgentMessage, 100), // Default buffer size
		Config: ChannelConfig{
			BufferSize:  100,
			Timeout:     30 * time.Second,
			Persistent:  false,
			Encrypted:   false,
			Compression: false,
		},
		Stats: &ChannelStats{
			LastActivity: time.Now(),
		},
	}

	mr.channels[channelID] = channel
	return channel, nil
}

// applyMiddleware applies middleware to a message
func (mr *MessageRouter) applyMiddleware(ctx context.Context, message *AgentMessage) error {
	if len(mr.middleware) == 0 {
		return nil
	}

	// Create middleware chain
	var next func(*AgentMessage) error
	for i := len(mr.middleware) - 1; i >= 0; i-- {
		middleware := mr.middleware[i]
		currentNext := next
		next = func(msg *AgentMessage) error {
			if currentNext != nil {
				return currentNext(msg)
			}
			return nil
		}

		// Apply middleware
		if err := middleware.Process(ctx, message, next); err != nil {
			return err
		}
	}

	return nil
}

// JSONMessageSerializer implements JSON message serialization
type JSONMessageSerializer struct{}

// NewJSONMessageSerializer creates a new JSON message serializer
func NewJSONMessageSerializer() *JSONMessageSerializer {
	return &JSONMessageSerializer{}
}

// Serialize serializes a message to JSON
func (jms *JSONMessageSerializer) Serialize(message *AgentMessage) ([]byte, error) {
	return json.Marshal(message)
}

// Deserialize deserializes a message from JSON
func (jms *JSONMessageSerializer) Deserialize(data []byte) (*AgentMessage, error) {
	var message AgentMessage
	err := json.Unmarshal(data, &message)
	return &message, err
}
