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

var subscriptionTracer = otel.Tracer("hackai/langgraph/messaging/subscription")

// NewSubscriptionManager creates a new subscription manager
func NewSubscriptionManager(config *SubscriptionConfig, logger *logger.Logger) *SubscriptionManager {
	if config == nil {
		config = &SubscriptionConfig{
			MaxSubscriptions:     1000,
			MessageRetention:     24 * time.Hour,
			EnableFiltering:      true,
			EnablePrioritization: true,
			QueueSize:            1000,
		}
	}

	sm := &SubscriptionManager{
		subscriptions: make(map[string]*Subscription),
		topics:        make(map[string]*Topic),
		subscribers:   make(map[string][]string),
		publishers:    make(map[string][]string),
		messageQueue:  make(chan *TopicMessage, config.QueueSize),
		config:        config,
		logger:        logger,
	}

	return sm
}

// CreateTopic creates a new topic
func (sm *SubscriptionManager) CreateTopic(name, description string) (*Topic, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	topicID := uuid.New().String()
	topic := &Topic{
		ID:           topicID,
		Name:         name,
		Description:  description,
		Subscribers:  make([]string, 0),
		Publishers:   make([]string, 0),
		MessageCount: 0,
		Metadata:     make(map[string]interface{}),
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	sm.topics[topicID] = topic
	sm.subscribers[topicID] = make([]string, 0)
	sm.publishers[topicID] = make([]string, 0)

	sm.logger.Info("Topic created",
		"topic_id", topicID,
		"name", name)

	return topic, nil
}

// Subscribe subscribes an agent to a topic
func (sm *SubscriptionManager) Subscribe(ctx context.Context, agentID, topicID string, filters []MessageFilter) (*Subscription, error) {
	ctx, span := subscriptionTracer.Start(ctx, "subscription_manager.subscribe",
		trace.WithAttributes(
			attribute.String("agent.id", agentID),
			attribute.String("topic.id", topicID),
		),
	)
	defer span.End()

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Check if topic exists
	topic, exists := sm.topics[topicID]
	if !exists {
		err := fmt.Errorf("topic not found: %s", topicID)
		span.RecordError(err)
		return nil, err
	}

	// Check subscription limit
	agentSubscriptions := sm.getAgentSubscriptions(agentID)
	if len(agentSubscriptions) >= sm.config.MaxSubscriptions {
		err := fmt.Errorf("subscription limit reached for agent: %s", agentID)
		span.RecordError(err)
		return nil, err
	}

	// Create subscription
	subscriptionID := uuid.New().String()
	subscription := &Subscription{
		ID:         subscriptionID,
		AgentID:    agentID,
		TopicID:    topicID,
		Filters:    filters,
		Priority:   PriorityNormal,
		Metadata:   make(map[string]interface{}),
		CreatedAt:  time.Now(),
		LastAccess: time.Now(),
	}

	// Store subscription
	sm.subscriptions[subscriptionID] = subscription
	sm.subscribers[topicID] = append(sm.subscribers[topicID], agentID)
	topic.Subscribers = append(topic.Subscribers, agentID)

	sm.logger.Info("Agent subscribed to topic",
		"subscription_id", subscriptionID,
		"agent_id", agentID,
		"topic_id", topicID)

	return subscription, nil
}

// Unsubscribe unsubscribes an agent from a topic
func (sm *SubscriptionManager) Unsubscribe(ctx context.Context, subscriptionID string) error {
	ctx, span := subscriptionTracer.Start(ctx, "subscription_manager.unsubscribe",
		trace.WithAttributes(
			attribute.String("subscription.id", subscriptionID),
		),
	)
	defer span.End()

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Find subscription
	subscription, exists := sm.subscriptions[subscriptionID]
	if !exists {
		err := fmt.Errorf("subscription not found: %s", subscriptionID)
		span.RecordError(err)
		return err
	}

	// Remove from topic subscribers
	if subscribers, exists := sm.subscribers[subscription.TopicID]; exists {
		for i, agentID := range subscribers {
			if agentID == subscription.AgentID {
				sm.subscribers[subscription.TopicID] = append(subscribers[:i], subscribers[i+1:]...)
				break
			}
		}
	}

	// Update topic
	if topic, exists := sm.topics[subscription.TopicID]; exists {
		for i, agentID := range topic.Subscribers {
			if agentID == subscription.AgentID {
				topic.Subscribers = append(topic.Subscribers[:i], topic.Subscribers[i+1:]...)
				break
			}
		}
	}

	// Remove subscription
	delete(sm.subscriptions, subscriptionID)

	sm.logger.Info("Agent unsubscribed from topic",
		"subscription_id", subscriptionID,
		"agent_id", subscription.AgentID,
		"topic_id", subscription.TopicID)

	return nil
}

// Publish publishes a message to a topic
func (sm *SubscriptionManager) Publish(ctx context.Context, message *TopicMessage) error {
	ctx, span := subscriptionTracer.Start(ctx, "subscription_manager.publish",
		trace.WithAttributes(
			attribute.String("message.id", message.ID),
			attribute.String("topic.id", message.TopicID),
			attribute.String("publisher", message.Publisher),
		),
	)
	defer span.End()

	sm.mutex.RLock()
	topic, exists := sm.topics[message.TopicID]
	if !exists {
		sm.mutex.RUnlock()
		err := fmt.Errorf("topic not found: %s", message.TopicID)
		span.RecordError(err)
		return err
	}

	subscribers := make([]string, len(sm.subscribers[message.TopicID]))
	copy(subscribers, sm.subscribers[message.TopicID])
	sm.mutex.RUnlock()

	// Update topic statistics
	sm.mutex.Lock()
	topic.MessageCount++
	topic.LastActivity = time.Now()
	sm.mutex.Unlock()

	// Deliver message to subscribers
	var wg sync.WaitGroup
	errorChan := make(chan error, len(subscribers))

	for _, subscriberID := range subscribers {
		wg.Add(1)
		go func(subscriberID string) {
			defer wg.Done()

			if err := sm.deliverToSubscriber(ctx, message, subscriberID); err != nil {
				errorChan <- fmt.Errorf("failed to deliver to %s: %w", subscriberID, err)
			}
		}(subscriberID)
	}

	// Wait for all deliveries
	wg.Wait()
	close(errorChan)

	// Collect errors
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		sm.logger.Warn("Message delivery partially failed",
			"message_id", message.ID,
			"errors", len(errors),
			"total_subscribers", len(subscribers))
	}

	sm.logger.Debug("Message published",
		"message_id", message.ID,
		"topic_id", message.TopicID,
		"subscribers", len(subscribers))

	return nil
}

// deliverToSubscriber delivers a message to a specific subscriber
func (sm *SubscriptionManager) deliverToSubscriber(ctx context.Context, message *TopicMessage, subscriberID string) error {
	// Find subscriber's subscriptions for this topic
	subscriptions := sm.getSubscriberSubscriptions(subscriberID, message.TopicID)

	for _, subscription := range subscriptions {
		// Apply filters
		if sm.config.EnableFiltering && !sm.applySubscriptionFilters(message, subscription.Filters) {
			continue
		}

		// Create agent message
		agentMessage := &AgentMessage{
			ID:        uuid.New().String(),
			From:      "topic-system",
			To:        []string{subscriberID},
			Type:      message.Type,
			Content:   message.Content,
			Timestamp: message.Timestamp,
			Priority:  message.Priority,
			Metadata:  make(map[string]interface{}),
		}

		// Add topic metadata
		for k, v := range message.Metadata {
			agentMessage.Metadata[k] = v
		}
		agentMessage.Metadata["topic_id"] = message.TopicID
		agentMessage.Metadata["topic_message_id"] = message.ID
		agentMessage.Metadata["publisher"] = message.Publisher

		// Deliver message (would use actual router in production)
		if err := sm.deliverMessage(ctx, agentMessage); err != nil {
			return err
		}

		// Update subscription access time
		sm.mutex.Lock()
		subscription.LastAccess = time.Now()
		sm.mutex.Unlock()
	}

	return nil
}

// deliverMessage delivers a message to an agent
func (sm *SubscriptionManager) deliverMessage(ctx context.Context, message *AgentMessage) error {
	// In a real implementation, this would use the message router
	// For now, just simulate the delivery
	sm.logger.Debug("Delivering message to subscriber",
		"message_id", message.ID,
		"subscriber_id", message.To[0])

	// Simulate network delay
	time.Sleep(5 * time.Millisecond)

	return nil
}

// getAgentSubscriptions returns all subscriptions for an agent
func (sm *SubscriptionManager) getAgentSubscriptions(agentID string) []*Subscription {
	var subscriptions []*Subscription
	for _, subscription := range sm.subscriptions {
		if subscription.AgentID == agentID {
			subscriptions = append(subscriptions, subscription)
		}
	}
	return subscriptions
}

// getSubscriberSubscriptions returns subscriptions for a subscriber on a specific topic
func (sm *SubscriptionManager) getSubscriberSubscriptions(subscriberID, topicID string) []*Subscription {
	var subscriptions []*Subscription
	for _, subscription := range sm.subscriptions {
		if subscription.AgentID == subscriberID && subscription.TopicID == topicID {
			subscriptions = append(subscriptions, subscription)
		}
	}
	return subscriptions
}

// applySubscriptionFilters applies subscription filters to a message
func (sm *SubscriptionManager) applySubscriptionFilters(message *TopicMessage, filters []MessageFilter) bool {
	for _, filter := range filters {
		if !sm.evaluateSubscriptionFilter(message, filter) {
			return false
		}
	}
	return true
}

// evaluateSubscriptionFilter evaluates a single subscription filter
func (sm *SubscriptionManager) evaluateSubscriptionFilter(message *TopicMessage, filter MessageFilter) bool {
	// Simple filter evaluation - in production, use a more sophisticated approach
	switch filter.Field {
	case "type":
		return string(message.Type) == filter.Value
	case "priority":
		if priority, ok := filter.Value.(Priority); ok {
			return message.Priority >= priority
		}
	case "publisher":
		return message.Publisher == filter.Value
	}
	return true
}

// GetTopic returns a topic by ID
func (sm *SubscriptionManager) GetTopic(topicID string) (*Topic, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	topic, exists := sm.topics[topicID]
	if !exists {
		return nil, fmt.Errorf("topic not found: %s", topicID)
	}

	return topic, nil
}

// ListTopics returns all topics
func (sm *SubscriptionManager) ListTopics() []*Topic {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	topics := make([]*Topic, 0, len(sm.topics))
	for _, topic := range sm.topics {
		topics = append(topics, topic)
	}

	return topics
}

// GetSubscription returns a subscription by ID
func (sm *SubscriptionManager) GetSubscription(subscriptionID string) (*Subscription, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	subscription, exists := sm.subscriptions[subscriptionID]
	if !exists {
		return nil, fmt.Errorf("subscription not found: %s", subscriptionID)
	}

	return subscription, nil
}

// ListSubscriptions returns all subscriptions for an agent
func (sm *SubscriptionManager) ListSubscriptions(agentID string) []*Subscription {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	return sm.getAgentSubscriptions(agentID)
}
