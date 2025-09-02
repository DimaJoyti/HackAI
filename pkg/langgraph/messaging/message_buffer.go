package messaging

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// NewMessageBuffer creates a new message buffer
func NewMessageBuffer(config *BufferConfig, logger *logger.Logger) *MessageBuffer {
	if config == nil {
		config = &BufferConfig{
			MaxBufferSize:    10000,
			RetryDelay:       time.Second,
			MaxRetries:       3,
			EnablePriority:   true,
			PersistentBuffer: false,
		}
	}

	mb := &MessageBuffer{
		buffer:     make(map[string]*BufferedMessage),
		priorities: make(map[Priority][]*BufferedMessage),
		config:     config,
		logger:     logger,
	}

	// Initialize priority queues
	mb.priorities[PriorityLow] = make([]*BufferedMessage, 0)
	mb.priorities[PriorityNormal] = make([]*BufferedMessage, 0)
	mb.priorities[PriorityHigh] = make([]*BufferedMessage, 0)
	mb.priorities[PriorityCritical] = make([]*BufferedMessage, 0)

	return mb
}

// BufferMessage buffers a message for reliable delivery
func (mb *MessageBuffer) BufferMessage(ctx context.Context, message *AgentMessage) error {
	mb.mutex.Lock()
	defer mb.mutex.Unlock()

	// Check buffer size limit
	if len(mb.buffer) >= mb.config.MaxBufferSize {
		return fmt.Errorf("message buffer full")
	}

	// Create buffered message
	bufferedMsg := &BufferedMessage{
		Message:     message,
		Attempts:    0,
		NextRetry:   time.Now(),
		MaxRetries:  mb.config.MaxRetries,
		CreatedAt:   time.Now(),
		LastAttempt: time.Time{},
	}

	// Store in buffer
	mb.buffer[message.ID] = bufferedMsg

	// Add to priority queue if enabled
	if mb.config.EnablePriority {
		mb.priorities[message.Priority] = append(mb.priorities[message.Priority], bufferedMsg)
	}

	mb.logger.Debug("Message buffered",
		"message_id", message.ID,
		"priority", message.Priority,
		"buffer_size", len(mb.buffer))

	return nil
}

// GetPendingMessages returns messages ready for retry
func (mb *MessageBuffer) GetPendingMessages() []*BufferedMessage {
	mb.mutex.RLock()
	defer mb.mutex.RUnlock()

	now := time.Now()
	var pending []*BufferedMessage

	if mb.config.EnablePriority {
		// Process by priority order
		priorities := []Priority{PriorityCritical, PriorityHigh, PriorityNormal, PriorityLow}
		for _, priority := range priorities {
			for _, bufferedMsg := range mb.priorities[priority] {
				if bufferedMsg.NextRetry.Before(now) && bufferedMsg.Attempts < bufferedMsg.MaxRetries {
					pending = append(pending, bufferedMsg)
				}
			}
		}
	} else {
		// Process all messages
		for _, bufferedMsg := range mb.buffer {
			if bufferedMsg.NextRetry.Before(now) && bufferedMsg.Attempts < bufferedMsg.MaxRetries {
				pending = append(pending, bufferedMsg)
			}
		}
	}

	return pending
}

// MarkMessageSent marks a message as successfully sent
func (mb *MessageBuffer) MarkMessageSent(messageID string) error {
	mb.mutex.Lock()
	defer mb.mutex.Unlock()

	bufferedMsg, exists := mb.buffer[messageID]
	if !exists {
		return fmt.Errorf("buffered message not found: %s", messageID)
	}

	// Remove from buffer
	delete(mb.buffer, messageID)

	// Remove from priority queue
	if mb.config.EnablePriority {
		mb.removeFromPriorityQueue(bufferedMsg)
	}

	mb.logger.Debug("Message marked as sent",
		"message_id", messageID,
		"attempts", bufferedMsg.Attempts)

	return nil
}

// MarkMessageFailed marks a message delivery attempt as failed
func (mb *MessageBuffer) MarkMessageFailed(messageID string, err error) error {
	mb.mutex.Lock()
	defer mb.mutex.Unlock()

	bufferedMsg, exists := mb.buffer[messageID]
	if !exists {
		return fmt.Errorf("buffered message not found: %s", messageID)
	}

	// Increment attempt count
	bufferedMsg.Attempts++
	bufferedMsg.LastAttempt = time.Now()

	// Calculate next retry time with exponential backoff
	backoffMultiplier := time.Duration(1 << bufferedMsg.Attempts) // 2^attempts
	nextRetryDelay := mb.config.RetryDelay * backoffMultiplier
	bufferedMsg.NextRetry = time.Now().Add(nextRetryDelay)

	// Check if max retries exceeded
	if bufferedMsg.Attempts >= bufferedMsg.MaxRetries {
		mb.logger.Error("Message exceeded max retries",
			"message_id", messageID,
			"attempts", bufferedMsg.Attempts,
			"error", err)

		// Remove from buffer
		delete(mb.buffer, messageID)
		if mb.config.EnablePriority {
			mb.removeFromPriorityQueue(bufferedMsg)
		}

		return fmt.Errorf("message exceeded max retries: %s", messageID)
	}

	mb.logger.Debug("Message retry scheduled",
		"message_id", messageID,
		"attempts", bufferedMsg.Attempts,
		"next_retry", bufferedMsg.NextRetry,
		"error", err)

	return nil
}

// removeFromPriorityQueue removes a message from the priority queue
func (mb *MessageBuffer) removeFromPriorityQueue(bufferedMsg *BufferedMessage) {
	priority := bufferedMsg.Message.Priority
	queue := mb.priorities[priority]

	for i, msg := range queue {
		if msg.Message.ID == bufferedMsg.Message.ID {
			mb.priorities[priority] = append(queue[:i], queue[i+1:]...)
			break
		}
	}
}

// GetBufferStats returns buffer statistics
func (mb *MessageBuffer) GetBufferStats() *BufferStats {
	mb.mutex.RLock()
	defer mb.mutex.RUnlock()

	stats := &BufferStats{
		TotalMessages:     len(mb.buffer),
		PriorityBreakdown: make(map[Priority]int),
		OldestMessage:     time.Now(),
		AverageRetries:    0,
	}

	totalRetries := 0
	for _, bufferedMsg := range mb.buffer {
		priority := bufferedMsg.Message.Priority
		stats.PriorityBreakdown[priority]++

		if bufferedMsg.CreatedAt.Before(stats.OldestMessage) {
			stats.OldestMessage = bufferedMsg.CreatedAt
		}

		totalRetries += bufferedMsg.Attempts
	}

	if len(mb.buffer) > 0 {
		stats.AverageRetries = float64(totalRetries) / float64(len(mb.buffer))
	}

	return stats
}

// BufferStats represents buffer statistics
type BufferStats struct {
	TotalMessages     int              `json:"total_messages"`
	PriorityBreakdown map[Priority]int `json:"priority_breakdown"`
	OldestMessage     time.Time        `json:"oldest_message"`
	AverageRetries    float64          `json:"average_retries"`
}

// CleanupExpiredMessages removes expired messages from the buffer
func (mb *MessageBuffer) CleanupExpiredMessages(maxAge time.Duration) int {
	mb.mutex.Lock()
	defer mb.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)
	var expiredIDs []string

	for messageID, bufferedMsg := range mb.buffer {
		if bufferedMsg.CreatedAt.Before(cutoff) {
			expiredIDs = append(expiredIDs, messageID)
		}
	}

	// Remove expired messages
	for _, messageID := range expiredIDs {
		bufferedMsg := mb.buffer[messageID]
		delete(mb.buffer, messageID)

		if mb.config.EnablePriority {
			mb.removeFromPriorityQueue(bufferedMsg)
		}
	}

	if len(expiredIDs) > 0 {
		mb.logger.Info("Cleaned up expired messages",
			"count", len(expiredIDs),
			"max_age", maxAge)
	}

	return len(expiredIDs)
}

// NewReliabilityManager creates a new reliability manager
func NewReliabilityManager(logger *logger.Logger) *ReliabilityManager {
	return &ReliabilityManager{
		deliveryTracking: make(map[string]*DeliveryTracking),
		logger:           logger,
	}
}

// ReliabilityManager manages message delivery reliability
type ReliabilityManager struct {
	deliveryTracking map[string]*DeliveryTracking
	logger           *logger.Logger
	mutex            sync.RWMutex
}

// DeliveryTracking tracks message delivery status
type DeliveryTracking struct {
	MessageID       string                 `json:"message_id"`
	Status          DeliveryStatus         `json:"status"`
	Attempts        int                    `json:"attempts"`
	LastAttempt     time.Time              `json:"last_attempt"`
	Acknowledgments map[string]time.Time   `json:"acknowledgments"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// DeliveryStatus represents message delivery status
type DeliveryStatus string

const (
	DeliveryStatusPending      DeliveryStatus = "pending"
	DeliveryStatusDelivered    DeliveryStatus = "delivered"
	DeliveryStatusFailed       DeliveryStatus = "failed"
	DeliveryStatusAcknowledged DeliveryStatus = "acknowledged"
)

// TrackDelivery starts tracking a message delivery
func (rm *ReliabilityManager) TrackDelivery(messageID string) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	rm.deliveryTracking[messageID] = &DeliveryTracking{
		MessageID:       messageID,
		Status:          DeliveryStatusPending,
		Attempts:        0,
		Acknowledgments: make(map[string]time.Time),
		Metadata:        make(map[string]interface{}),
	}
}

// RecordDeliveryAttempt records a delivery attempt
func (rm *ReliabilityManager) RecordDeliveryAttempt(messageID string, success bool) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	tracking, exists := rm.deliveryTracking[messageID]
	if !exists {
		return
	}

	tracking.Attempts++
	tracking.LastAttempt = time.Now()

	if success {
		tracking.Status = DeliveryStatusDelivered
	} else {
		tracking.Status = DeliveryStatusFailed
	}
}

// RecordAcknowledgment records message acknowledgment from recipient
func (rm *ReliabilityManager) RecordAcknowledgment(messageID, recipientID string) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	tracking, exists := rm.deliveryTracking[messageID]
	if !exists {
		return
	}

	tracking.Acknowledgments[recipientID] = time.Now()
	tracking.Status = DeliveryStatusAcknowledged
}

// GetDeliveryStatus returns delivery status for a message
func (rm *ReliabilityManager) GetDeliveryStatus(messageID string) (*DeliveryTracking, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	tracking, exists := rm.deliveryTracking[messageID]
	if !exists {
		return nil, fmt.Errorf("delivery tracking not found: %s", messageID)
	}

	return tracking, nil
}

// NewCommunicationSecurityManager creates a new communication security manager
func NewCommunicationSecurityManager(logger *logger.Logger) *CommunicationSecurityManager {
	return &CommunicationSecurityManager{
		logger: logger,
	}
}

// CommunicationSecurityManager manages communication security
type CommunicationSecurityManager struct {
	logger *logger.Logger
}

// ValidateMessage validates a message for security
func (csm *CommunicationSecurityManager) ValidateMessage(ctx context.Context, message *AgentMessage) error {
	// Basic security validation - in production, implement comprehensive checks
	if message.From == "" {
		return fmt.Errorf("message sender cannot be empty")
	}

	if len(message.To) == 0 {
		return fmt.Errorf("message recipients cannot be empty")
	}

	// Check for suspicious content patterns
	if content, ok := message.Content.(string); ok {
		if len(content) > 1000000 { // 1MB limit
			return fmt.Errorf("message content too large")
		}
	}

	return nil
}

// NewCommunicationMetrics creates a new communication metrics collector
func NewCommunicationMetrics(logger *logger.Logger) *CommunicationMetrics {
	return &CommunicationMetrics{
		messagesSent:     0,
		messagesReceived: 0,
		logger:           logger,
	}
}

// CommunicationMetrics collects communication metrics
type CommunicationMetrics struct {
	messagesSent     int64
	messagesReceived int64
	logger           *logger.Logger
	mutex            sync.RWMutex
}

// RecordMessageSent records a sent message
func (cm *CommunicationMetrics) RecordMessageSent(message *AgentMessage) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.messagesSent++
}

// RecordMessageReceived records a received message
func (cm *CommunicationMetrics) RecordMessageReceived(message *AgentMessage) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.messagesReceived++
}

// GetMetrics returns current metrics
func (cm *CommunicationMetrics) GetMetrics() (int64, int64) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	return cm.messagesSent, cm.messagesReceived
}
