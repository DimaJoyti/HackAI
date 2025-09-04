package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// PubSubManager handles Redis pub/sub operations
type PubSubManager struct {
	client      *Client
	logger      *logger.Logger
	subscribers map[string]*Subscriber
	mu          sync.RWMutex
}

// Subscriber represents a pub/sub subscriber
type Subscriber struct {
	id       string
	channels []string
	pubsub   *redis.PubSub
	msgChan  chan *Message
	errChan  chan error
	stopChan chan struct{}
	stopped  bool
	mu       sync.RWMutex
}

// Message represents a pub/sub message
type Message struct {
	Channel   string                 `json:"channel"`
	Pattern   string                 `json:"pattern,omitempty"`
	Payload   string                 `json:"payload"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	MessageID string                 `json:"message_id,omitempty"`
}

// MessageHandler is a function that handles incoming messages
type MessageHandler func(msg *Message) error

// NewPubSubManager creates a new pub/sub manager
func NewPubSubManager(client *Client, logger *logger.Logger) *PubSubManager {
	return &PubSubManager{
		client:      client,
		logger:      logger,
		subscribers: make(map[string]*Subscriber),
	}
}

// Publish publishes a message to a channel
func (psm *PubSubManager) Publish(ctx context.Context, channel string, message interface{}) error {
	var payload string
	
	switch v := message.(type) {
	case string:
		payload = v
	case []byte:
		payload = string(v)
	default:
		// JSON encode the message
		data, err := json.Marshal(message)
		if err != nil {
			return fmt.Errorf("failed to marshal message: %w", err)
		}
		payload = string(data)
	}
	
	result, err := psm.client.Publish(ctx, channel, payload).Result()
	if err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}
	
	psm.logger.Debugf("Published message to channel %s (subscribers: %d)", channel, result)
	return nil
}

// PublishJSON publishes a JSON message to a channel
func (psm *PubSubManager) PublishJSON(ctx context.Context, channel string, data map[string]interface{}) error {
	msg := &Message{
		Channel:   channel,
		Data:      data,
		Timestamp: time.Now(),
		MessageID: fmt.Sprintf("%d", time.Now().UnixNano()),
	}
	
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON message: %w", err)
	}
	
	result, err := psm.client.Publish(ctx, channel, string(payload)).Result()
	if err != nil {
		return fmt.Errorf("failed to publish JSON message: %w", err)
	}
	
	psm.logger.Debugf("Published JSON message to channel %s (subscribers: %d)", channel, result)
	return nil
}

// Subscribe creates a new subscriber for the specified channels
func (psm *PubSubManager) Subscribe(ctx context.Context, channels ...string) (*Subscriber, error) {
	if len(channels) == 0 {
		return nil, fmt.Errorf("at least one channel must be specified")
	}
	
	pubsub := psm.client.Subscribe(ctx, channels...)
	
	// Wait for subscription confirmation
	_, err := pubsub.Receive(ctx)
	if err != nil {
		pubsub.Close()
		return nil, fmt.Errorf("failed to subscribe to channels: %w", err)
	}
	
	subscriberID := fmt.Sprintf("sub_%d", time.Now().UnixNano())
	subscriber := &Subscriber{
		id:       subscriberID,
		channels: channels,
		pubsub:   pubsub,
		msgChan:  make(chan *Message, 100), // Buffered channel
		errChan:  make(chan error, 10),
		stopChan: make(chan struct{}),
		stopped:  false,
	}
	
	// Store subscriber
	psm.mu.Lock()
	psm.subscribers[subscriberID] = subscriber
	psm.mu.Unlock()
	
	// Start message processing goroutine
	go subscriber.processMessages(ctx, psm.logger)
	
	psm.logger.Infof("Subscribed to channels: %v (subscriber: %s)", channels, subscriberID)
	return subscriber, nil
}

// SubscribePattern creates a new subscriber for channels matching a pattern
func (psm *PubSubManager) SubscribePattern(ctx context.Context, patterns ...string) (*Subscriber, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("at least one pattern must be specified")
	}
	
	pubsub := psm.client.PSubscribe(ctx, patterns...)
	
	// Wait for subscription confirmation
	_, err := pubsub.Receive(ctx)
	if err != nil {
		pubsub.Close()
		return nil, fmt.Errorf("failed to subscribe to patterns: %w", err)
	}
	
	subscriberID := fmt.Sprintf("psub_%d", time.Now().UnixNano())
	subscriber := &Subscriber{
		id:       subscriberID,
		channels: patterns, // Store patterns in channels field
		pubsub:   pubsub,
		msgChan:  make(chan *Message, 100),
		errChan:  make(chan error, 10),
		stopChan: make(chan struct{}),
		stopped:  false,
	}
	
	// Store subscriber
	psm.mu.Lock()
	psm.subscribers[subscriberID] = subscriber
	psm.mu.Unlock()
	
	// Start message processing goroutine
	go subscriber.processMessages(ctx, psm.logger)
	
	psm.logger.Infof("Subscribed to patterns: %v (subscriber: %s)", patterns, subscriberID)
	return subscriber, nil
}

// Unsubscribe removes a subscriber
func (psm *PubSubManager) Unsubscribe(subscriberID string) error {
	psm.mu.Lock()
	subscriber, exists := psm.subscribers[subscriberID]
	if exists {
		delete(psm.subscribers, subscriberID)
	}
	psm.mu.Unlock()
	
	if !exists {
		return fmt.Errorf("subscriber not found: %s", subscriberID)
	}
	
	return subscriber.Close()
}

// GetSubscribers returns information about active subscribers
func (psm *PubSubManager) GetSubscribers() map[string][]string {
	psm.mu.RLock()
	defer psm.mu.RUnlock()
	
	result := make(map[string][]string)
	for id, sub := range psm.subscribers {
		result[id] = sub.channels
	}
	
	return result
}

// Close closes all subscribers and the pub/sub manager
func (psm *PubSubManager) Close() error {
	psm.mu.Lock()
	subscribers := make([]*Subscriber, 0, len(psm.subscribers))
	for _, sub := range psm.subscribers {
		subscribers = append(subscribers, sub)
	}
	psm.subscribers = make(map[string]*Subscriber)
	psm.mu.Unlock()
	
	// Close all subscribers
	for _, sub := range subscribers {
		if err := sub.Close(); err != nil {
			psm.logger.Errorf("Failed to close subscriber %s: %v", sub.id, err)
		}
	}
	
	psm.logger.Info("PubSub manager closed")
	return nil
}

// Subscriber methods

// Messages returns the message channel
func (s *Subscriber) Messages() <-chan *Message {
	return s.msgChan
}

// Errors returns the error channel
func (s *Subscriber) Errors() <-chan error {
	return s.errChan
}

// ID returns the subscriber ID
func (s *Subscriber) ID() string {
	return s.id
}

// Channels returns the subscribed channels/patterns
func (s *Subscriber) Channels() []string {
	return s.channels
}

// IsStopped returns whether the subscriber is stopped
func (s *Subscriber) IsStopped() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stopped
}

// Close closes the subscriber
func (s *Subscriber) Close() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	s.mu.Unlock()
	
	close(s.stopChan)
	
	if err := s.pubsub.Close(); err != nil {
		return fmt.Errorf("failed to close pubsub: %w", err)
	}
	
	return nil
}

// Listen starts listening for messages with a handler function
func (s *Subscriber) Listen(ctx context.Context, handler MessageHandler) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stopChan:
			return nil
		case msg := <-s.msgChan:
			if err := handler(msg); err != nil {
				select {
				case s.errChan <- fmt.Errorf("handler error: %w", err):
				default:
					// Error channel is full, skip
				}
			}
		case err := <-s.errChan:
			return fmt.Errorf("subscriber error: %w", err)
		}
	}
}

// processMessages processes incoming Redis messages
func (s *Subscriber) processMessages(ctx context.Context, logger *logger.Logger) {
	defer func() {
		close(s.msgChan)
		close(s.errChan)
	}()
	
	ch := s.pubsub.Channel()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case redisMsg := <-ch:
			if redisMsg == nil {
				continue
			}
			
			msg := &Message{
				Channel:   redisMsg.Channel,
				Pattern:   redisMsg.Pattern,
				Payload:   redisMsg.Payload,
				Timestamp: time.Now(),
			}
			
			// Try to parse as JSON
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(redisMsg.Payload), &data); err == nil {
				msg.Data = data
				// Extract message ID if present
				if msgID, ok := data["message_id"].(string); ok {
					msg.MessageID = msgID
				}
				// Extract timestamp if present
				if ts, ok := data["timestamp"].(string); ok {
					if parsedTime, err := time.Parse(time.RFC3339, ts); err == nil {
						msg.Timestamp = parsedTime
					}
				}
			}
			
			select {
			case s.msgChan <- msg:
			case <-s.stopChan:
				return
			default:
				// Channel is full, send error
				select {
				case s.errChan <- fmt.Errorf("message channel full, dropping message"):
				default:
					// Error channel is also full
				}
			}
		}
	}
}

// Utility functions

// BroadcastToUsers publishes a message to user-specific channels
func (psm *PubSubManager) BroadcastToUsers(ctx context.Context, userIDs []string, message interface{}) error {
	for _, userID := range userIDs {
		channel := fmt.Sprintf("user:%s", userID)
		if err := psm.Publish(ctx, channel, message); err != nil {
			psm.logger.Errorf("Failed to publish to user %s: %v", userID, err)
		}
	}
	return nil
}

// BroadcastToRoles publishes a message to role-specific channels
func (psm *PubSubManager) BroadcastToRoles(ctx context.Context, roles []string, message interface{}) error {
	for _, role := range roles {
		channel := fmt.Sprintf("role:%s", role)
		if err := psm.Publish(ctx, channel, message); err != nil {
			psm.logger.Errorf("Failed to publish to role %s: %v", role, err)
		}
	}
	return nil
}

// GetChannelSubscribers returns the number of subscribers for a channel
func (psm *PubSubManager) GetChannelSubscribers(ctx context.Context, channel string) (int64, error) {
	result, err := psm.client.PubSubNumSub(ctx, channel).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get channel subscribers: %w", err)
	}
	
	if count, ok := result[channel]; ok {
		return count, nil
	}
	
	return 0, nil
}
