package examples

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// BasicUsageExample demonstrates basic usage of the AI framework
func BasicUsageExample() error {
	// Create logger
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	// Create orchestrator
	config := ai.OrchestratorConfig{
		MaxConcurrentExecutions: 100,
		WorkerPoolSize:          10,
		RequestQueueSize:        1000,
		DefaultTimeout:          5 * time.Minute,
		EnableMetrics:           true,
		EnableTracing:           true,
		HealthCheckInterval:     30 * time.Second,
	}

	orchestrator := ai.NewOrchestrator(config, testLogger)

	// Start orchestrator
	ctx := context.Background()
	if err := orchestrator.Start(ctx); err != nil {
		return fmt.Errorf("failed to start orchestrator: %w", err)
	}
	defer orchestrator.Stop()

	// Create and register a simple tool
	echoTool := NewEchoTool()
	if err := orchestrator.RegisterTool(echoTool); err != nil {
		return fmt.Errorf("failed to register echo tool: %w", err)
	}

	// Create and register a simple chain
	echoChain := NewEchoChain(testLogger)
	if err := orchestrator.RegisterChain(echoChain); err != nil {
		return fmt.Errorf("failed to register echo chain: %w", err)
	}

	// Execute the chain
	input := map[string]interface{}{
		"message": "Hello, AI Framework!",
	}

	output, err := orchestrator.ExecuteChain(ctx, "echo-chain", input)
	if err != nil {
		return fmt.Errorf("failed to execute chain: %w", err)
	}

	fmt.Printf("Chain output: %v\n", output)

	// Create and register a simple graph
	echoGraph := NewEchoGraph(testLogger)
	if err := orchestrator.RegisterGraph(echoGraph); err != nil {
		return fmt.Errorf("failed to register echo graph: %w", err)
	}

	// Execute the graph
	initialState := ai.GraphState{
		"input": "Hello, Graph!",
	}

	finalState, err := orchestrator.ExecuteGraph(ctx, "echo-graph", initialState)
	if err != nil {
		return fmt.Errorf("failed to execute graph: %w", err)
	}

	fmt.Printf("Graph final state: %v\n", finalState)

	// Print statistics
	stats := orchestrator.GetStats()
	fmt.Printf("Orchestrator stats: %+v\n", stats)

	return nil
}

// EchoTool is a simple tool that echoes input
type EchoTool struct {
	*ai.BaseTool
}

func NewEchoTool() *EchoTool {
	schema := ai.ToolSchema{
		Name:        "echo",
		Description: "Echoes the input message",
		InputSchema: map[string]ai.ParameterSchema{
			"message": {
				Type:        "string",
				Description: "Message to echo",
				Required:    true,
			},
		},
		OutputSchema: map[string]ai.ParameterSchema{
			"echoed_message": {
				Type:        "string",
				Description: "The echoed message",
				Required:    true,
			},
		},
	}

	testLogger, _ := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})

	baseTool := ai.NewBaseTool("echo", "Echoes input messages", schema, testLogger)

	return &EchoTool{
		BaseTool: baseTool,
	}
}

func (t *EchoTool) Execute(ctx context.Context, input ai.ToolInput) (ai.ToolOutput, error) {
	message, exists := input["message"]
	if !exists {
		return nil, fmt.Errorf("message parameter is required")
	}

	return ai.ToolOutput{
		"echoed_message": fmt.Sprintf("Echo: %s", message),
		"timestamp":      time.Now().Format(time.RFC3339),
	}, nil
}

// EchoChain is a simple chain that uses the echo tool
type EchoChain struct {
	*ai.BaseChain
}

func NewEchoChain(logger *logger.Logger) *EchoChain {
	config := ai.ChainConfig{
		ID:          "echo-chain",
		Name:        "Echo Chain",
		Description: "A simple chain that echoes messages",
		Type:        ai.ChainTypeSequential,
		Enabled:     true,
		MaxRetries:  3,
		Timeout:     30 * time.Second,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	baseChain := ai.NewBaseChain(config, logger)

	return &EchoChain{
		BaseChain: baseChain,
	}
}

func (c *EchoChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	// Simple echo logic
	message, exists := input["message"]
	if !exists {
		return nil, fmt.Errorf("message parameter is required")
	}

	return llm.ChainOutput{
		"original_message": message,
		"echoed_message":   fmt.Sprintf("Chain Echo: %s", message),
		"processed_at":     time.Now().Format(time.RFC3339),
	}, nil
}

func (c *EchoChain) GetMemory() llm.Memory {
	return nil
}

func (c *EchoChain) SetMemory(memory llm.Memory) {
	// No-op for this simple example
}

// EchoGraph is a simple graph with echo functionality
type EchoGraph struct {
	*ai.StateGraph
}

func NewEchoGraph(logger *logger.Logger) *EchoGraph {
	graph := ai.NewStateGraph("echo-graph", "Echo Graph", "A simple graph that processes messages", logger)

	echoGraph := &EchoGraph{
		StateGraph: graph,
	}

	// Add nodes
	inputNode := &InputNode{}
	processNode := &ProcessNode{}
	outputNode := &OutputNode{}

	graph.AddNode(inputNode)
	graph.AddNode(processNode)
	graph.AddNode(outputNode)

	// Add edges
	graph.AddEdge("input", "process")
	graph.AddEdge("process", "output")

	// Set entry point
	graph.SetEntryPoint("input")

	return echoGraph
}

// Graph nodes

type InputNode struct{}

func (n *InputNode) ID() string        { return "input" }
func (n *InputNode) Type() ai.NodeType { return ai.NodeTypeTransform }

func (n *InputNode) Execute(ctx context.Context, state ai.GraphState) (ai.GraphState, error) {
	input, exists := state["input"]
	if !exists {
		return state, fmt.Errorf("input not found in state")
	}

	state["processed_input"] = fmt.Sprintf("Processed: %s", input)
	state["step"] = "input_processed"

	return state, nil
}

func (n *InputNode) GetConfig() ai.NodeConfig {
	return ai.NodeConfig{
		ID:   "input",
		Type: ai.NodeTypeTransform,
		Name: "Input Node",
	}
}

func (n *InputNode) SetConfig(config ai.NodeConfig) error { return nil }
func (n *InputNode) Validate() error                      { return nil }

type ProcessNode struct{}

func (n *ProcessNode) ID() string        { return "process" }
func (n *ProcessNode) Type() ai.NodeType { return ai.NodeTypeTransform }

func (n *ProcessNode) Execute(ctx context.Context, state ai.GraphState) (ai.GraphState, error) {
	processedInput, exists := state["processed_input"]
	if !exists {
		return state, fmt.Errorf("processed_input not found in state")
	}

	state["final_output"] = fmt.Sprintf("Final: %s", processedInput)
	state["step"] = "processing_complete"

	return state, nil
}

func (n *ProcessNode) GetConfig() ai.NodeConfig {
	return ai.NodeConfig{
		ID:   "process",
		Type: ai.NodeTypeTransform,
		Name: "Process Node",
	}
}

func (n *ProcessNode) SetConfig(config ai.NodeConfig) error { return nil }
func (n *ProcessNode) Validate() error                      { return nil }

type OutputNode struct{}

func (n *OutputNode) ID() string        { return "output" }
func (n *OutputNode) Type() ai.NodeType { return ai.NodeTypeTransform }

func (n *OutputNode) Execute(ctx context.Context, state ai.GraphState) (ai.GraphState, error) {
	finalOutput, exists := state["final_output"]
	if !exists {
		return state, fmt.Errorf("final_output not found in state")
	}

	state["result"] = finalOutput
	state["step"] = "complete"
	state["completed_at"] = time.Now().Format(time.RFC3339)

	return state, nil
}

func (n *OutputNode) GetConfig() ai.NodeConfig {
	return ai.NodeConfig{
		ID:   "output",
		Type: ai.NodeTypeTransform,
		Name: "Output Node",
	}
}

func (n *OutputNode) SetConfig(config ai.NodeConfig) error { return nil }
func (n *OutputNode) Validate() error                      { return nil }
