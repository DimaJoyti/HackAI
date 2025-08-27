package realtime

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/infrastructure"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var pubsubTracer = otel.Tracer("hackai/realtime/pubsub")

// PubSubManager manages publish-subscribe messaging
type PubSubManager struct {
	config        PubSubConfig
	logger        *logger.Logger
	redisClient   *infrastructure.RedisClient
	subscriptions map[string]map[string]*Subscription // channel -> connectionID -> subscription
	subscribers   map[string]*Subscriber              // connectionID -> subscriber
	channels      map[string]*Channel                 // channel -> channel info
	running       bool
	stopChan      chan struct{}
	wg            sync.WaitGroup
	mutex         sync.RWMutex
}

// Subscription represents a channel subscription
type Subscription struct {
	ID           string                 `json:"id"`
	ConnectionID string                 `json:"connection_id"`
	Channel      string                 `json:"channel"`
	Filters      map[string]interface{} `json:"filters"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
}

// Subscriber represents a message subscriber
type Subscriber struct {
	ID            string                   `json:"id"`
	ConnectionID  string                   `json:"connection_id"`
	Subscriptions map[string]*Subscription `json:"subscriptions"`
	MessageQueue  chan *RealtimeMessage    `json:"-"`
	Active        bool                     `json:"active"`
	CreatedAt     time.Time                `json:"created_at"`
	LastActivity  time.Time                `json:"last_activity"`
	ctx           context.Context
	cancel        context.CancelFunc
}

// Channel represents a message channel
type Channel struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Subscribers  int                    `json:"subscribers"`
	MessageCount int64                  `json:"message_count"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
	Metadata     map[string]interface{} `json:"metadata"`
	Persistent   bool                   `json:"persistent"`
}

// NewPubSubManager creates a new PubSub manager
func NewPubSubManager(config PubSubConfig, redisClient *infrastructure.RedisClient, logger *logger.Logger) *PubSubManager {
	return &PubSubManager{
		config:        config,
		logger:        logger,
		redisClient:   redisClient,
		subscriptions: make(map[string]map[string]*Subscription),
		subscribers:   make(map[string]*Subscriber),
		channels:      make(map[string]*Channel),
		stopChan:      make(chan struct{}),
	}
}

// Start starts the PubSub manager
func (pm *PubSubManager) Start(ctx context.Context) error {
	ctx, span := pubsubTracer.Start(ctx, "pubsub_manager_start")
	defer span.End()

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if pm.running {
		return fmt.Errorf("PubSub manager is already running")
	}

	pm.logger.Info("Starting PubSub manager",
		"channel_buffer_size", pm.config.ChannelBufferSize,
		"subscriber_timeout", pm.config.SubscriberTimeout,
		"enable_persistence", pm.config.EnablePersistence)

	// Start background workers
	pm.wg.Add(2)
	go pm.subscriptionCleanupWorker(ctx)
	go pm.messageProcessor(ctx)

	pm.running = true

	span.SetAttributes(
		attribute.Bool("manager_started", true),
		attribute.Int("channel_buffer_size", pm.config.ChannelBufferSize),
		attribute.Bool("persistence_enabled", pm.config.EnablePersistence),
	)

	pm.logger.Info("PubSub manager started successfully")
	return nil
}

// Stop stops the PubSub manager
func (pm *PubSubManager) Stop() error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.running {
		return nil
	}

	pm.logger.Info("Stopping PubSub manager")

	// Signal stop to workers
	close(pm.stopChan)

	// Close all subscribers
	for _, subscriber := range pm.subscribers {
		subscriber.cancel()
	}

	// Wait for workers to finish
	pm.wg.Wait()

	pm.running = false
	pm.logger.Info("PubSub manager stopped")
	return nil
}

// Publish publishes a message to a channel
func (pm *PubSubManager) Publish(ctx context.Context, message *RealtimeMessage) error {
	ctx, span := pubsubTracer.Start(ctx, "publish_message")
	defer span.End()

	pm.mutex.RLock()
	channelSubs, exists := pm.subscriptions[message.Channel]
	pm.mutex.RUnlock()

	if !exists || len(channelSubs) == 0 {
		// No subscribers, but still log the message
		pm.logger.Debug("No subscribers for channel", "channel", message.Channel)
		return nil
	}

	span.SetAttributes(
		attribute.String("channel", message.Channel),
		attribute.String("message_id", message.ID),
		attribute.String("message_type", string(message.Type)),
		attribute.Int("subscriber_count", len(channelSubs)),
	)

	// Update channel info
	pm.updateChannelActivity(message.Channel)

	// Publish to Redis if persistence is enabled
	if pm.config.EnablePersistence {
		if err := pm.publishToRedis(ctx, message); err != nil {
			pm.logger.Error("Failed to publish to Redis", "error", err)
		}
	}

	// Send to local subscribers
	// Note: messageData not needed for local subscribers as we send the message object directly

	pm.mutex.RLock()
	subscribers := make([]*Subscriber, 0, len(channelSubs))
	for connectionID := range channelSubs {
		if subscriber, exists := pm.subscribers[connectionID]; exists && subscriber.Active {
			subscribers = append(subscribers, subscriber)
		}
	}
	pm.mutex.RUnlock()

	// Send to subscribers
	for _, subscriber := range subscribers {
		select {
		case subscriber.MessageQueue <- message:
			subscriber.LastActivity = time.Now()
		default:
			// Queue is full, log warning
			pm.logger.Warn("Subscriber message queue full",
				"connection_id", subscriber.ConnectionID,
				"channel", message.Channel)
		}
	}

	pm.logger.Debug("Message published",
		"channel", message.Channel,
		"message_id", message.ID,
		"subscriber_count", len(subscribers))

	return nil
}

// Subscribe subscribes a connection to a channel
func (pm *PubSubManager) Subscribe(ctx context.Context, connectionID, channel string) error {
	ctx, span := pubsubTracer.Start(ctx, "subscribe_channel")
	defer span.End()

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("channel", channel),
	)

	// Create subscription
	subscription := &Subscription{
		ID:           fmt.Sprintf("%s:%s", connectionID, channel),
		ConnectionID: connectionID,
		Channel:      channel,
		Filters:      make(map[string]interface{}),
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	// Add to subscriptions map
	if pm.subscriptions[channel] == nil {
		pm.subscriptions[channel] = make(map[string]*Subscription)
	}
	pm.subscriptions[channel][connectionID] = subscription

	// Create or update subscriber
	subscriber, exists := pm.subscribers[connectionID]
	if !exists {
		ctx, cancel := context.WithCancel(ctx)
		subscriber = &Subscriber{
			ID:            connectionID,
			ConnectionID:  connectionID,
			Subscriptions: make(map[string]*Subscription),
			MessageQueue:  make(chan *RealtimeMessage, pm.config.ChannelBufferSize),
			Active:        true,
			CreatedAt:     time.Now(),
			LastActivity:  time.Now(),
			ctx:           ctx,
			cancel:        cancel,
		}
		pm.subscribers[connectionID] = subscriber

		// Start subscriber worker
		go pm.subscriberWorker(subscriber)
	}

	subscriber.Subscriptions[channel] = subscription
	subscriber.LastActivity = time.Now()

	// Create or update channel
	if pm.channels[channel] == nil {
		pm.channels[channel] = &Channel{
			Name:         channel,
			Description:  fmt.Sprintf("Channel: %s", channel),
			Subscribers:  0,
			MessageCount: 0,
			CreatedAt:    time.Now(),
			LastActivity: time.Now(),
			Metadata:     make(map[string]interface{}),
			Persistent:   pm.config.EnablePersistence,
		}
	}
	pm.channels[channel].Subscribers++
	pm.channels[channel].LastActivity = time.Now()

	pm.logger.Info("Subscription created",
		"connection_id", connectionID,
		"channel", channel,
		"total_subscribers", pm.channels[channel].Subscribers)

	return nil
}

// Unsubscribe unsubscribes a connection from a channel
func (pm *PubSubManager) Unsubscribe(ctx context.Context, connectionID, channel string) error {
	ctx, span := pubsubTracer.Start(ctx, "unsubscribe_channel")
	defer span.End()

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	span.SetAttributes(
		attribute.String("connection_id", connectionID),
		attribute.String("channel", channel),
	)

	// Remove from subscriptions
	if channelSubs, exists := pm.subscriptions[channel]; exists {
		delete(channelSubs, connectionID)
		if len(channelSubs) == 0 {
			delete(pm.subscriptions, channel)
		}
	}

	// Update subscriber
	if subscriber, exists := pm.subscribers[connectionID]; exists {
		delete(subscriber.Subscriptions, channel)
		subscriber.LastActivity = time.Now()

		// Remove subscriber if no subscriptions left
		if len(subscriber.Subscriptions) == 0 {
			subscriber.Active = false
			subscriber.cancel()
			delete(pm.subscribers, connectionID)
		}
	}

	// Update channel
	if channelInfo, exists := pm.channels[channel]; exists {
		channelInfo.Subscribers--
		channelInfo.LastActivity = time.Now()

		// Remove channel if no subscribers
		if channelInfo.Subscribers <= 0 {
			delete(pm.channels, channel)
		}
	}

	pm.logger.Info("Subscription removed",
		"connection_id", connectionID,
		"channel", channel)

	return nil
}

// GetSubscriptionCount gets the total number of subscriptions
func (pm *PubSubManager) GetSubscriptionCount() int {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	count := 0
	for _, channelSubs := range pm.subscriptions {
		count += len(channelSubs)
	}
	return count
}

// GetChannels gets all active channels
func (pm *PubSubManager) GetChannels() []*Channel {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	channels := make([]*Channel, 0, len(pm.channels))
	for _, channel := range pm.channels {
		channels = append(channels, channel)
	}
	return channels
}

// CleanupStaleSubscriptions removes stale subscriptions
func (pm *PubSubManager) CleanupStaleSubscriptions() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	now := time.Now()
	staleSubscribers := []string{}

	for connectionID, subscriber := range pm.subscribers {
		if now.Sub(subscriber.LastActivity) > pm.config.SubscriberTimeout {
			staleSubscribers = append(staleSubscribers, connectionID)
		}
	}

	for _, connectionID := range staleSubscribers {
		if subscriber, exists := pm.subscribers[connectionID]; exists {
			// Remove all subscriptions for this subscriber
			for channel := range subscriber.Subscriptions {
				if channelSubs, exists := pm.subscriptions[channel]; exists {
					delete(channelSubs, connectionID)
					if len(channelSubs) == 0 {
						delete(pm.subscriptions, channel)
					}
				}

				// Update channel subscriber count
				if channelInfo, exists := pm.channels[channel]; exists {
					channelInfo.Subscribers--
					if channelInfo.Subscribers <= 0 {
						delete(pm.channels, channel)
					}
				}
			}

			// Remove subscriber
			subscriber.Active = false
			subscriber.cancel()
			delete(pm.subscribers, connectionID)
		}
	}

	if len(staleSubscribers) > 0 {
		pm.logger.Info("Cleaned up stale subscriptions", "count", len(staleSubscribers))
	}
}

// publishToRedis publishes message to Redis for persistence
func (pm *PubSubManager) publishToRedis(ctx context.Context, message *RealtimeMessage) error {
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Publish to Redis channel
	redisChannel := fmt.Sprintf("realtime:%s", message.Channel)
	return pm.redisClient.Publish(ctx, redisChannel, data)
}

// updateChannelActivity updates channel activity timestamp
func (pm *PubSubManager) updateChannelActivity(channel string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if channelInfo, exists := pm.channels[channel]; exists {
		channelInfo.MessageCount++
		channelInfo.LastActivity = time.Now()
	}
}

// subscriberWorker processes messages for a subscriber
func (pm *PubSubManager) subscriberWorker(subscriber *Subscriber) {
	defer func() {
		close(subscriber.MessageQueue)
		pm.logger.Info("Subscriber worker stopped", "connection_id", subscriber.ConnectionID)
	}()

	for {
		select {
		case <-subscriber.ctx.Done():
			return
		case message, ok := <-subscriber.MessageQueue:
			if !ok {
				return
			}

			// Process message for subscriber
			pm.processSubscriberMessage(subscriber, message)
		}
	}
}

// processSubscriberMessage processes a message for a specific subscriber
func (pm *PubSubManager) processSubscriberMessage(subscriber *Subscriber, message *RealtimeMessage) {
	// Check if subscriber is still subscribed to the channel
	subscription, exists := subscriber.Subscriptions[message.Channel]
	if !exists {
		return
	}

	// Apply filters if any
	if !pm.messageMatchesFilters(message, subscription.Filters) {
		return
	}

	// Update subscription activity
	subscription.LastActivity = time.Now()
	subscriber.LastActivity = time.Now()

	// Here you would typically send the message to the actual connection
	// This would be handled by the WebSocket manager or other transport
	pm.logger.Debug("Message processed for subscriber",
		"connection_id", subscriber.ConnectionID,
		"channel", message.Channel,
		"message_id", message.ID)
}

// messageMatchesFilters checks if a message matches subscription filters
func (pm *PubSubManager) messageMatchesFilters(message *RealtimeMessage, filters map[string]interface{}) bool {
	if len(filters) == 0 {
		return true
	}

	// Simple filter matching - can be extended for complex filtering
	for key, expectedValue := range filters {
		if actualValue, exists := message.Data[key]; !exists || actualValue != expectedValue {
			return false
		}
	}

	return true
}

// subscriptionCleanupWorker cleans up stale subscriptions
func (pm *PubSubManager) subscriptionCleanupWorker(ctx context.Context) {
	defer pm.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pm.stopChan:
			return
		case <-ticker.C:
			pm.CleanupStaleSubscriptions()
		}
	}
}

// messageProcessor processes incoming messages from Redis
func (pm *PubSubManager) messageProcessor(ctx context.Context) {
	defer pm.wg.Done()

	if !pm.config.EnablePersistence {
		return
	}

	// Subscribe to Redis channels for distributed messaging
	// This would be implemented based on your Redis pub/sub setup
	pm.logger.Info("Message processor started for Redis pub/sub")

	// Implementation would go here for Redis subscription handling
	// For now, this is a placeholder for the distributed messaging feature
}
