package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/graph"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// SimpleMemory implements a simple in-memory storage for demo purposes
type SimpleMemory struct {
	data map[string]interface{}
}

// NewSimpleMemory creates a new simple memory
func NewSimpleMemory() *SimpleMemory {
	return &SimpleMemory{
		data: make(map[string]interface{}),
	}
}

// Store stores a value in memory
func (m *SimpleMemory) Store(ctx context.Context, key string, value interface{}) error {
	m.data[key] = value
	return nil
}

// Retrieve retrieves a value from memory
func (m *SimpleMemory) Retrieve(ctx context.Context, key string) (interface{}, error) {
	value, exists := m.data[key]
	if !exists {
		return nil, fmt.Errorf("key %s not found", key)
	}
	return value, nil
}

// Delete removes a value from memory
func (m *SimpleMemory) Delete(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

// Clear removes all values from memory
func (m *SimpleMemory) Clear(ctx context.Context) error {
	m.data = make(map[string]interface{})
	return nil
}

// Keys returns all keys in memory
func (m *SimpleMemory) Keys(ctx context.Context) ([]string, error) {
	keys := make([]string, 0, len(m.data))
	for key := range m.data {
		keys = append(keys, key)
	}
	return keys, nil
}

func main() {
	// Initialize logger
	appLogger, err := logger.New(logger.Config{
		Level:      logger.LevelInfo,
		Format:     "json",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	appLogger.Info("🔗 Starting Graph Execution Engine Demo")

	// Run comprehensive demo
	if err := runGraphExecutionDemo(appLogger); err != nil {
		appLogger.Fatal("Demo failed", "error", err)
	}

	appLogger.Info("✅ Graph Execution Engine Demo completed successfully!")
}

func runGraphExecutionDemo(logger *logger.Logger) error {
	ctx := context.Background()

	logger.Info("=== 🚀 Graph Execution Engine Demo ===")

	// Demo 1: Simple Sequential Graph
	if err := demoSimpleSequentialGraph(ctx, logger); err != nil {
		return fmt.Errorf("simple sequential graph demo failed: %w", err)
	}

	// Demo 2: Conditional Branching Graph
	if err := demoConditionalBranchingGraph(ctx, logger); err != nil {
		return fmt.Errorf("conditional branching graph demo failed: %w", err)
	}

	// Demo 3: Parallel Execution Graph
	if err := demoParallelExecutionGraph(ctx, logger); err != nil {
		return fmt.Errorf("parallel execution graph demo failed: %w", err)
	}

	// Demo 4: Complex Workflow Graph
	if err := demoComplexWorkflowGraph(ctx, logger); err != nil {
		return fmt.Errorf("complex workflow graph demo failed: %w", err)
	}

	// Demo 5: Async Execution and Monitoring
	if err := demoAsyncExecutionAndMonitoring(ctx, logger); err != nil {
		return fmt.Errorf("async execution demo failed: %w", err)
	}

	return nil
}

func demoSimpleSequentialGraph(ctx context.Context, logger *logger.Logger) error {
	logger.Info("📋 Demo 1: Simple Sequential Graph Execution")

	// Create a simple sequential graph using template
	template := graph.NewGraphTemplate(logger)
	chainIDs := []string{"input-processor", "text-analyzer", "output-formatter"}

	sequentialGraph, err := template.SimpleSequential(
		"sequential-demo",
		"Sequential Processing Demo",
		chainIDs,
	)
	if err != nil {
		return fmt.Errorf("failed to create sequential graph: %w", err)
	}

	// Create initial state
	initialState := llm.GraphState{
		CurrentNode: "node_input-processor",
		Data: map[string]interface{}{
			"input_text": "Hello, this is a test document for processing.",
			"user_id":    "demo-user",
			"timestamp":  time.Now(),
		},
		History:    []llm.StateTransition{},
		Metadata:   map[string]interface{}{"demo": "sequential"},
		StartTime:  time.Now(),
		UpdateTime: time.Now(),
	}

	// Execute the graph
	finalState, err := sequentialGraph.Execute(ctx, initialState)
	if err != nil {
		return fmt.Errorf("graph execution failed: %w", err)
	}

	logger.Info("✅ Sequential graph executed successfully",
		"final_node", finalState.CurrentNode,
		"transitions", len(finalState.History),
		"result", finalState.Data["result"],
	)

	return nil
}

func demoConditionalBranchingGraph(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🔀 Demo 2: Conditional Branching Graph")

	// Create a graph with conditional branching
	builder := graph.NewFluentGraphBuilder(
		"conditional-demo",
		"Conditional Branching Demo",
		"Demonstrates conditional execution based on input",
		logger,
	)

	// Create conditions
	lengthCondition := graph.NewCustomCondition("text_length_check", func(ctx context.Context, state llm.GraphState) (bool, error) {
		text, ok := state.Data["input_text"].(string)
		if !ok {
			return false, nil
		}
		return len(text) > 50, nil
	})

	// Build the graph using regular builder methods
	builder.AddLLMNode("input_node", "input-validator")
	builder.AddConditionNode("length_check", lengthCondition)
	builder.AddLLMNode("long_text_processor", "detailed-analyzer")
	builder.AddLLMNode("short_text_processor", "simple-analyzer")
	builder.AddLLMNode("output_node", "result-formatter")

	// Add edges
	builder.AddEdge("input_node", "length_check")
	builder.AddConditionalEdge("length_check", "long_text_processor", lengthCondition)
	builder.AddConditionalEdge("length_check", "short_text_processor", graph.NewNotCondition(lengthCondition))
	builder.AddEdge("long_text_processor", "output_node")
	builder.AddEdge("short_text_processor", "output_node")

	conditionalGraph, err := builder.Build()

	if err != nil {
		return fmt.Errorf("failed to build conditional graph: %w", err)
	}

	// Test with long text
	longTextState := llm.GraphState{
		CurrentNode: "input_node",
		Data: map[string]interface{}{
			"input_text": "This is a very long text that should trigger the detailed analysis path because it contains more than fifty characters and provides substantial content for processing.",
		},
		History:    []llm.StateTransition{},
		Metadata:   map[string]interface{}{"demo": "conditional_long"},
		StartTime:  time.Now(),
		UpdateTime: time.Now(),
	}

	finalState, err := conditionalGraph.Execute(ctx, longTextState)
	if err != nil {
		return fmt.Errorf("long text execution failed: %w", err)
	}

	logger.Info("✅ Long text processed",
		"path_taken", "detailed_analysis",
		"result", finalState.Data["result"],
	)

	// Test with short text
	shortTextState := llm.GraphState{
		CurrentNode: "input_node",
		Data: map[string]interface{}{
			"input_text": "Short text.",
		},
		History:    []llm.StateTransition{},
		Metadata:   map[string]interface{}{"demo": "conditional_short"},
		StartTime:  time.Now(),
		UpdateTime: time.Now(),
	}

	finalState, err = conditionalGraph.Execute(ctx, shortTextState)
	if err != nil {
		return fmt.Errorf("short text execution failed: %w", err)
	}

	logger.Info("✅ Short text processed",
		"path_taken", "simple_analysis",
		"result", finalState.Data["result"],
	)

	return nil
}

func demoParallelExecutionGraph(ctx context.Context, logger *logger.Logger) error {
	logger.Info("⚡ Demo 3: Parallel Execution Graph")

	// Create a graph with parallel execution
	template := graph.NewGraphTemplate(logger)
	parallelChains := []string{"sentiment-analyzer", "entity-extractor", "topic-classifier"}

	parallelGraph, err := template.ParallelExecution(
		"parallel-demo",
		"Parallel Processing Demo",
		parallelChains,
		"result-aggregator",
	)
	if err != nil {
		return fmt.Errorf("failed to create parallel graph: %w", err)
	}

	// Create initial state
	initialState := llm.GraphState{
		CurrentNode: "parallel_0", // Start with first parallel node
		Data: map[string]interface{}{
			"input_text":    "I love this new AI technology! It's revolutionizing how we work with artificial intelligence and machine learning.",
			"analysis_type": "comprehensive",
		},
		History:    []llm.StateTransition{},
		Metadata:   map[string]interface{}{"demo": "parallel"},
		StartTime:  time.Now(),
		UpdateTime: time.Now(),
	}

	// Execute the graph
	finalState, err := parallelGraph.Execute(ctx, initialState)
	if err != nil {
		return fmt.Errorf("parallel execution failed: %w", err)
	}

	logger.Info("✅ Parallel graph executed successfully",
		"final_node", finalState.CurrentNode,
		"sentiment", finalState.Data["sentiment"],
		"entities", finalState.Data["entities"],
		"topics", finalState.Data["topics"],
	)

	return nil
}

func demoComplexWorkflowGraph(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🔧 Demo 4: Complex Workflow Graph")

	// Create memory for the workflow
	workflowMemory := NewSimpleMemory()

	// Create a complex workflow with validation, transformation, and memory
	builder := graph.NewGraphBuilder(
		"complex-workflow",
		"Complex Workflow Demo",
		"Demonstrates a complex workflow with validation, transformation, memory, and error handling",
		logger,
	)

	// Add input validation
	inputValidator := func(ctx context.Context, data map[string]interface{}) error {
		text, ok := data["input_text"].(string)
		if !ok || text == "" {
			return fmt.Errorf("input_text is required and must be a non-empty string")
		}
		if len(text) < 10 {
			return fmt.Errorf("input_text must be at least 10 characters long")
		}
		return nil
	}

	// Add data transformer
	textTransformer := func(ctx context.Context, data map[string]interface{}) (map[string]interface{}, error) {
		text := data["input_text"].(string)

		// Transform the text
		transformed := map[string]interface{}{
			"original_text":   text,
			"text_length":     len(text),
			"word_count":      len(strings.Fields(text)),
			"processed_text":  strings.ToUpper(text),
			"processing_time": time.Now(),
		}

		// Merge with existing data
		for k, v := range data {
			transformed[k] = v
		}

		return transformed, nil
	}

	// Build the complex workflow
	builder.
		AddValidatorNode("input_validator", inputValidator).
		AddTransformNode("text_transformer", textTransformer).
		AddMemoryNodeWithKey("save_to_memory", workflowMemory, graph.MemoryOpSet, "processed_data").
		AddLLMNode("main_processor", "advanced-text-processor").
		AddMemoryNodeWithKey("load_from_memory", workflowMemory, graph.MemoryOpGet, "processed_data").
		AddLLMNode("final_processor", "result-generator").
		AddEdge("input_validator", "text_transformer").
		AddEdge("text_transformer", "save_to_memory").
		AddEdge("save_to_memory", "main_processor").
		AddEdge("main_processor", "load_from_memory").
		AddEdge("load_from_memory", "final_processor")

	complexGraph, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build complex graph: %w", err)
	}

	// Create initial state
	initialState := llm.GraphState{
		CurrentNode: "input_validator",
		Data: map[string]interface{}{
			"input_text": "This is a comprehensive test of the complex workflow system with validation, transformation, and memory operations.",
			"user_id":    "workflow-user",
			"session_id": "demo-session-123",
		},
		History:    []llm.StateTransition{},
		Metadata:   map[string]interface{}{"demo": "complex_workflow"},
		StartTime:  time.Now(),
		UpdateTime: time.Now(),
	}

	// Execute the complex workflow
	finalState, err := complexGraph.Execute(ctx, initialState)
	if err != nil {
		return fmt.Errorf("complex workflow execution failed: %w", err)
	}

	logger.Info("✅ Complex workflow executed successfully",
		"final_node", finalState.CurrentNode,
		"transitions", len(finalState.History),
		"word_count", finalState.Data["word_count"],
		"result", finalState.Data["result"],
	)

	return nil
}

func demoAsyncExecutionAndMonitoring(ctx context.Context, logger *logger.Logger) error {
	logger.Info("📊 Demo 5: Async Execution and Monitoring")

	// Create a simple graph for async execution
	builder := graph.NewFluentGraphBuilder(
		"async-demo",
		"Async Execution Demo",
		"Demonstrates asynchronous execution with monitoring",
		logger,
	)

	// Add a slow processing action
	slowAction := func(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
		logger.Info("Starting slow processing...")
		time.Sleep(2 * time.Second) // Simulate slow processing

		newState := state
		newState.Data["slow_result"] = "Slow processing completed"
		newState.Data["processing_duration"] = "2 seconds"

		logger.Info("Slow processing completed")
		return newState, nil
	}

	// Build async graph using regular builder methods
	builder.AddLLMNode("input_node", "input-processor")
	builder.AddActionNode("slow_processor", slowAction)
	builder.AddLLMNode("output_node", "output-formatter")

	// Add edges
	builder.AddEdge("input_node", "slow_processor")
	builder.AddEdge("slow_processor", "output_node")

	asyncGraph, err := builder.Build()

	if err != nil {
		return fmt.Errorf("failed to build async graph: %w", err)
	}

	// Create execution engine
	config := graph.EngineConfig{
		MaxConcurrentExecutions: 5,
		DefaultTimeout:          30 * time.Second,
		MaxRetries:              3,
		RetryDelay:              1 * time.Second,
		EnableParallelExecution: true,
		MaxParallelNodes:        3,
		EnableTracing:           true,
		EnableMetrics:           true,
	}

	engine := graph.NewDefaultExecutionEngine(config, logger)

	// Create initial state
	initialState := llm.GraphState{
		CurrentNode: "input_node",
		Data: map[string]interface{}{
			"input_text": "This is an async execution test",
			"priority":   "high",
		},
		History:    []llm.StateTransition{},
		Metadata:   map[string]interface{}{"demo": "async"},
		StartTime:  time.Now(),
		UpdateTime: time.Now(),
	}

	// Execute asynchronously
	updateChannel, err := engine.ExecuteAsync(ctx, asyncGraph, initialState)
	if err != nil {
		return fmt.Errorf("failed to start async execution: %w", err)
	}

	// Monitor execution
	logger.Info("🔍 Monitoring async execution...")
	for update := range updateChannel {
		switch update.Type {
		case graph.UpdateNodeStarted:
			logger.Info("📍 Node started", "node_id", update.NodeID)
		case graph.UpdateNodeCompleted:
			logger.Info("✅ Node completed", "node_id", update.NodeID)
		case graph.UpdateNodeFailed:
			logger.Error("❌ Node failed", "node_id", update.NodeID, "error", update.Error)
		case graph.UpdateExecutionDone:
			if update.Error != nil {
				logger.Error("❌ Execution failed", "error", update.Error)
			} else {
				logger.Info("✅ Async execution completed successfully",
					"result", update.State.Data["result"],
					"slow_result", update.State.Data["slow_result"],
				)
			}
		}
	}

	return nil
}
