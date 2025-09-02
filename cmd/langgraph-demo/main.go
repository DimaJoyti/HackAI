package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/messaging"
	"github.com/dimajoyti/hackai/pkg/langgraph/storage"
	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	fmt.Println("🤖 HackAI LangGraph Demo")
	fmt.Println("========================")

	// Initialize logger
	appLogger := logger.NewDefault()

	// Run demos
	if err := runCheckpointDemo(appLogger); err != nil {
		log.Fatalf("Checkpoint demo failed: %v", err)
	}

	if err := runEventSystemDemo(appLogger); err != nil {
		log.Fatalf("Event system demo failed: %v", err)
	}

	if err := runMessageRoutingDemo(appLogger); err != nil {
		log.Fatalf("Message routing demo failed: %v", err)
	}

	fmt.Println("\n✅ All demos completed successfully!")
}

// runCheckpointDemo demonstrates the checkpointing system
func runCheckpointDemo(logger *logger.Logger) error {
	fmt.Println("\n🔄 Checkpoint System Demo")
	fmt.Println("-------------------------")

	ctx := context.Background()

	// Create checkpoint storage
	checkpointStorage := storage.NewMemoryCheckpointStorage()
	checkpointer := storage.NewCheckpointer(checkpointStorage, logger)

	// Create a sample graph state
	state := llm.GraphState{
		CurrentNode: "start",
		StartTime:   time.Now(),
		Data: map[string]interface{}{
			"user_input": "Hello, world!",
			"step_count": 1,
			"status":     "processing",
		},
	}

	// Create checkpoint
	checkpoint, err := checkpointer.CreateCheckpoint(ctx, "demo-graph", "start", state)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint: %w", err)
	}

	fmt.Printf("✅ Created checkpoint: %s\n", checkpoint.ID)

	// Modify state
	state.Data["step_count"] = 2
	state.Data["status"] = "completed"
	state.CurrentNode = "end"

	// Create another checkpoint
	checkpoint2, err := checkpointer.CreateCheckpoint(ctx, "demo-graph", "end", state)
	if err != nil {
		return fmt.Errorf("failed to create second checkpoint: %w", err)
	}

	fmt.Printf("✅ Created second checkpoint: %s\n", checkpoint2.ID)

	// Restore from first checkpoint
	restoredState, err := checkpointer.RestoreFromCheckpoint(ctx, checkpoint.ID)
	if err != nil {
		return fmt.Errorf("failed to restore checkpoint: %w", err)
	}

	fmt.Printf("✅ Restored state from checkpoint: node=%s, step=%v\n",
		restoredState.CurrentNode,
		restoredState.Data["step_count"])

	return nil
}

// runEventSystemDemo demonstrates the event system
func runEventSystemDemo(logger *logger.Logger) error {
	fmt.Println("\n📡 Event System Demo")
	fmt.Println("--------------------")

	ctx := context.Background()

	// Create event system
	eventSystem := messaging.NewEventSystem(logger)

	// Create event handler
	handler := messaging.NewDefaultEventHandler(
		[]messaging.EventType{messaging.EventTypeNodeStarted, messaging.EventTypeNodeCompleted},
		func(ctx context.Context, event *messaging.Event) error {
			fmt.Printf("📨 Received event: %s from %s\n", event.Type, event.Source)
			return nil
		},
	)

	// Subscribe to events
	err := eventSystem.Subscribe(messaging.EventTypeNodeStarted, handler)
	if err != nil {
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}

	err = eventSystem.Subscribe(messaging.EventTypeNodeCompleted, handler)
	if err != nil {
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}

	// Create and publish events
	event1 := messaging.CreateEvent(
		messaging.EventTypeNodeStarted,
		"demo-agent",
		map[string]interface{}{
			"node_id": "start",
			"message": "Starting demo workflow",
		},
	)

	err = eventSystem.PublishEvent(ctx, event1)
	if err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	event2 := messaging.CreateEvent(
		messaging.EventTypeNodeCompleted,
		"demo-agent",
		map[string]interface{}{
			"node_id":  "start",
			"result":   "success",
			"duration": "100ms",
		},
	)

	err = eventSystem.PublishEvent(ctx, event2)
	if err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	// Give events time to process
	time.Sleep(100 * time.Millisecond)

	fmt.Println("✅ Event system demo completed")
	return nil
}

// runMessageRoutingDemo demonstrates the message routing system
func runMessageRoutingDemo(logger *logger.Logger) error {
	fmt.Println("\n💬 Message Routing Demo")
	fmt.Println("-----------------------")

	ctx := context.Background()

	// Create message router
	messageRouter := messaging.NewMessageRouter(logger)

	// Create sample messages
	message1 := &messaging.AgentMessage{
		ID:        "msg-1",
		From:      "agent-a",
		To:        []string{"agent-b"},
		Type:      messaging.MessageTypeRequest,
		Content:   "Hello from Agent A!",
		Timestamp: time.Now(),
		Priority:  messaging.PriorityNormal,
		Metadata:  make(map[string]interface{}),
	}

	message2 := &messaging.AgentMessage{
		ID:        "msg-2",
		From:      "agent-b",
		To:        []string{"agent-a"},
		Type:      messaging.MessageTypeResponse,
		Content:   "Hello back from Agent B!",
		Timestamp: time.Now(),
		Priority:  messaging.PriorityNormal,
		ReplyTo:   &message1.ID,
		Metadata:  make(map[string]interface{}),
	}

	// Route messages
	err := messageRouter.RouteMessage(ctx, message1)
	if err != nil {
		return fmt.Errorf("failed to route message 1: %w", err)
	}

	fmt.Printf("✅ Routed message from %s to %s\n", message1.From, message1.To[0])

	err = messageRouter.RouteMessage(ctx, message2)
	if err != nil {
		return fmt.Errorf("failed to route message 2: %w", err)
	}

	fmt.Printf("✅ Routed reply from %s to %s\n", message2.From, message2.To[0])

	// Demonstrate broadcast message
	broadcastMessage := &messaging.AgentMessage{
		ID:        "msg-broadcast",
		From:      "coordinator",
		To:        []string{"agent-a", "agent-b", "agent-c"},
		Type:      messaging.MessageTypeNotification,
		Content:   "System maintenance in 5 minutes",
		Timestamp: time.Now(),
		Priority:  messaging.PriorityHigh,
		Metadata:  make(map[string]interface{}),
	}

	err = messageRouter.RouteMessage(ctx, broadcastMessage)
	if err != nil {
		return fmt.Errorf("failed to route broadcast message: %w", err)
	}

	fmt.Printf("✅ Broadcast message from %s to %d agents\n",
		broadcastMessage.From, len(broadcastMessage.To))

	fmt.Println("✅ Message routing demo completed")
	return nil
}

// SimpleAgent demonstrates a basic agent implementation
type SimpleAgent struct {
	ID       string
	Name     string
	Logger   *logger.Logger
	Messages chan *messaging.AgentMessage
}

// NewSimpleAgent creates a new simple agent
func NewSimpleAgent(id, name string, logger *logger.Logger) *SimpleAgent {
	return &SimpleAgent{
		ID:       id,
		Name:     name,
		Logger:   logger,
		Messages: make(chan *messaging.AgentMessage, 10),
	}
}

// Start starts the agent
func (a *SimpleAgent) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case message := <-a.Messages:
				a.handleMessage(ctx, message)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// handleMessage handles incoming messages
func (a *SimpleAgent) handleMessage(ctx context.Context, message *messaging.AgentMessage) {
	a.Logger.Info("Agent received message",
		"agent_id", a.ID,
		"message_id", message.ID,
		"from", message.From,
		"type", message.Type,
		"content", message.Content)

	// Simple echo response
	if message.Type == messaging.MessageTypeRequest {
		response := &messaging.AgentMessage{
			ID:        fmt.Sprintf("response-%s", message.ID),
			From:      a.ID,
			To:        []string{message.From},
			Type:      messaging.MessageTypeResponse,
			Content:   fmt.Sprintf("Echo: %v", message.Content),
			Timestamp: time.Now(),
			Priority:  messaging.PriorityNormal,
			ReplyTo:   &message.ID,
			Metadata:  make(map[string]interface{}),
		}

		a.Logger.Info("Agent sending response",
			"agent_id", a.ID,
			"response_id", response.ID,
			"to", response.To[0])
	}
}

// SendMessage sends a message from this agent
func (a *SimpleAgent) SendMessage(to string, content interface{}) *messaging.AgentMessage {
	message := &messaging.AgentMessage{
		ID:        fmt.Sprintf("msg-%s-%d", a.ID, time.Now().UnixNano()),
		From:      a.ID,
		To:        []string{to},
		Type:      messaging.MessageTypeRequest,
		Content:   content,
		Timestamp: time.Now(),
		Priority:  messaging.PriorityNormal,
		Metadata:  make(map[string]interface{}),
	}

	return message
}
