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

var broadcastTracer = otel.Tracer("hackai/langgraph/messaging/broadcast")

// NewBroadcastManager creates a new broadcast manager
func NewBroadcastManager(config *BroadcastConfig, logger *logger.Logger) *BroadcastManager {
	if config == nil {
		config = &BroadcastConfig{
			MaxWorkers:     10,
			BatchSize:      100,
			RetryAttempts:  3,
			RetryDelay:     time.Second,
			QueueSize:      1000,
			EnableBatching: true,
		}
	}

	bm := &BroadcastManager{
		broadcastGroups: make(map[string]*BroadcastGroup),
		messageQueue:    make(chan *BroadcastMessage, config.QueueSize),
		workers:         make([]*BroadcastWorker, 0, config.MaxWorkers),
		config:          config,
		logger:          logger,
	}

	// Initialize workers
	for i := 0; i < config.MaxWorkers; i++ {
		worker := &BroadcastWorker{
			ID:           fmt.Sprintf("worker-%d", i),
			messageQueue: make(chan *BroadcastMessage, 100),
			logger:       logger,
			stopChan:     make(chan struct{}),
		}
		bm.workers = append(bm.workers, worker)
	}

	return bm
}

// CreateBroadcastGroup creates a new broadcast group
func (bm *BroadcastManager) CreateBroadcastGroup(name string, members []string, filters []MessageFilter) (*BroadcastGroup, error) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	groupID := uuid.New().String()
	group := &BroadcastGroup{
		ID:           groupID,
		Name:         name,
		Members:      members,
		Filters:      filters,
		Priority:     PriorityNormal,
		Metadata:     make(map[string]interface{}),
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	bm.broadcastGroups[groupID] = group

	bm.logger.Info("Broadcast group created",
		"group_id", groupID,
		"name", name,
		"members", len(members))

	return group, nil
}

// Broadcast broadcasts a message to a group
func (bm *BroadcastManager) Broadcast(ctx context.Context, message *BroadcastMessage) error {
	ctx, span := broadcastTracer.Start(ctx, "broadcast_manager.broadcast",
		trace.WithAttributes(
			attribute.String("message.id", message.ID),
			attribute.String("group.id", message.GroupID),
		),
	)
	defer span.End()

	bm.mutex.RLock()
	group, exists := bm.broadcastGroups[message.GroupID]
	bm.mutex.RUnlock()

	if !exists {
		err := fmt.Errorf("broadcast group not found: %s", message.GroupID)
		span.RecordError(err)
		return err
	}

	// Apply filters
	if !bm.applyFilters(message, group.Filters) {
		bm.logger.Debug("Message filtered out", "message_id", message.ID)
		return nil
	}

	// Queue message for broadcasting
	select {
	case bm.messageQueue <- message:
		bm.logger.Debug("Message queued for broadcast",
			"message_id", message.ID,
			"group_id", message.GroupID)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		err := fmt.Errorf("broadcast queue full")
		span.RecordError(err)
		return err
	}
}

// Start starts the broadcast manager
func (bm *BroadcastManager) Start(ctx context.Context) error {
	bm.logger.Info("Starting broadcast manager", "workers", len(bm.workers))

	// Start workers
	for _, worker := range bm.workers {
		go bm.runWorker(ctx, worker)
	}

	// Start message dispatcher
	go bm.runMessageDispatcher(ctx)

	return nil
}

// Stop stops the broadcast manager
func (bm *BroadcastManager) Stop() error {
	bm.logger.Info("Stopping broadcast manager")

	// Stop all workers
	for _, worker := range bm.workers {
		close(worker.stopChan)
	}

	return nil
}

// runMessageDispatcher dispatches messages to workers
func (bm *BroadcastManager) runMessageDispatcher(ctx context.Context) {
	for {
		select {
		case message := <-bm.messageQueue:
			// Find available worker
			worker := bm.getAvailableWorker()
			if worker != nil {
				select {
				case worker.messageQueue <- message:
					// Message dispatched
				default:
					// Worker queue full, try next worker
					bm.logger.Warn("Worker queue full, retrying",
						"worker_id", worker.ID,
						"message_id", message.ID)
					// Put message back in main queue
					select {
					case bm.messageQueue <- message:
					default:
						bm.logger.Error("Failed to requeue message", "message_id", message.ID)
					}
				}
			} else {
				// No available workers, put message back
				select {
				case bm.messageQueue <- message:
				default:
					bm.logger.Error("No available workers and queue full", "message_id", message.ID)
				}
				time.Sleep(100 * time.Millisecond) // Brief delay before retry
			}

		case <-ctx.Done():
			return
		}
	}
}

// runWorker runs a broadcast worker
func (bm *BroadcastManager) runWorker(ctx context.Context, worker *BroadcastWorker) {
	bm.logger.Debug("Starting broadcast worker", "worker_id", worker.ID)

	for {
		select {
		case message := <-worker.messageQueue:
			if err := bm.processBroadcastMessage(ctx, worker, message); err != nil {
				bm.logger.Error("Failed to process broadcast message",
					"worker_id", worker.ID,
					"message_id", message.ID,
					"error", err)
			}

		case <-worker.stopChan:
			bm.logger.Debug("Stopping broadcast worker", "worker_id", worker.ID)
			return

		case <-ctx.Done():
			return
		}
	}
}

// processBroadcastMessage processes a single broadcast message
func (bm *BroadcastManager) processBroadcastMessage(ctx context.Context, worker *BroadcastWorker, message *BroadcastMessage) error {
	bm.mutex.RLock()
	group, exists := bm.broadcastGroups[message.GroupID]
	bm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("broadcast group not found: %s", message.GroupID)
	}

	// Create individual messages for each member
	var wg sync.WaitGroup
	errorChan := make(chan error, len(group.Members))

	for _, memberID := range group.Members {
		wg.Add(1)
		go func(memberID string) {
			defer wg.Done()

			agentMessage := &AgentMessage{
				ID:        uuid.New().String(),
				From:      "broadcast-system",
				To:        []string{memberID},
				Type:      message.Type,
				Content:   message.Content,
				Timestamp: message.Timestamp,
				Priority:  message.Priority,
				Metadata:  message.Metadata,
			}

			// Add broadcast metadata
			if agentMessage.Metadata == nil {
				agentMessage.Metadata = make(map[string]interface{})
			}
			agentMessage.Metadata["broadcast_id"] = message.ID
			agentMessage.Metadata["broadcast_group"] = message.GroupID

			// Send message (would use actual router in production)
			if err := bm.sendToMember(ctx, agentMessage); err != nil {
				errorChan <- fmt.Errorf("failed to send to %s: %w", memberID, err)
			}
		}(memberID)
	}

	// Wait for all sends to complete
	wg.Wait()
	close(errorChan)

	// Collect errors
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("broadcast partially failed: %d errors", len(errors))
	}

	// Update group activity
	bm.mutex.Lock()
	group.LastActivity = time.Now()
	bm.mutex.Unlock()

	bm.logger.Debug("Broadcast completed",
		"message_id", message.ID,
		"group_id", message.GroupID,
		"members", len(group.Members))

	return nil
}

// sendToMember sends a message to a specific member
func (bm *BroadcastManager) sendToMember(ctx context.Context, message *AgentMessage) error {
	// In a real implementation, this would use the message router
	// For now, just simulate the send
	bm.logger.Debug("Sending message to member",
		"message_id", message.ID,
		"member_id", message.To[0])

	// Simulate network delay
	time.Sleep(10 * time.Millisecond)

	return nil
}

// getAvailableWorker finds an available worker
func (bm *BroadcastManager) getAvailableWorker() *BroadcastWorker {
	for _, worker := range bm.workers {
		select {
		case <-worker.messageQueue:
			// Worker has capacity
			return worker
		default:
			// Worker queue full, try next
			continue
		}
	}
	return nil
}

// applyFilters applies message filters
func (bm *BroadcastManager) applyFilters(message *BroadcastMessage, filters []MessageFilter) bool {
	for _, filter := range filters {
		if !bm.evaluateFilter(message, filter) {
			return false
		}
	}
	return true
}

// evaluateFilter evaluates a single filter
func (bm *BroadcastManager) evaluateFilter(message *BroadcastMessage, filter MessageFilter) bool {
	// Simple filter evaluation - in production, use a more sophisticated approach
	switch filter.Field {
	case "type":
		return string(message.Type) == filter.Value
	case "priority":
		if priority, ok := filter.Value.(Priority); ok {
			return message.Priority >= priority
		}
	}
	return true
}

// GetBroadcastGroup returns a broadcast group by ID
func (bm *BroadcastManager) GetBroadcastGroup(groupID string) (*BroadcastGroup, error) {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	group, exists := bm.broadcastGroups[groupID]
	if !exists {
		return nil, fmt.Errorf("broadcast group not found: %s", groupID)
	}

	return group, nil
}

// ListBroadcastGroups returns all broadcast groups
func (bm *BroadcastManager) ListBroadcastGroups() []*BroadcastGroup {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	groups := make([]*BroadcastGroup, 0, len(bm.broadcastGroups))
	for _, group := range bm.broadcastGroups {
		groups = append(groups, group)
	}

	return groups
}

// DeleteBroadcastGroup deletes a broadcast group
func (bm *BroadcastManager) DeleteBroadcastGroup(groupID string) error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if _, exists := bm.broadcastGroups[groupID]; !exists {
		return fmt.Errorf("broadcast group not found: %s", groupID)
	}

	delete(bm.broadcastGroups, groupID)

	bm.logger.Info("Broadcast group deleted", "group_id", groupID)
	return nil
}
