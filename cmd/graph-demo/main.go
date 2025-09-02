package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dimajoyti/hackai/pkg/graph/conditions"
	"github.com/dimajoyti/hackai/pkg/graph/engine"
	"github.com/dimajoyti/hackai/pkg/graph/nodes"
	"github.com/dimajoyti/hackai/pkg/graph/nodes/security"
	"github.com/dimajoyti/hackai/pkg/graph/persistence"
	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	// Initialize logger
	loggerConfig := logger.Config{
		Level:      logger.LevelInfo,
		Format:     "json",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: time.RFC3339,
	}

	appLogger, err := logger.New(loggerConfig)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	appLogger.Info("Starting State Graph Demo")

	// Create persistence
	persistence, err := persistence.NewFilePersistence("./graph_states")
	if err != nil {
		appLogger.Fatal("Failed to create persistence", "error", err)
	}

	// Demo 1: Simple Linear Graph
	appLogger.Info("=== Demo 1: Simple Linear Graph ===")
	if err := demoSimpleGraph(appLogger, persistence); err != nil {
		appLogger.Error("Simple graph demo failed", "error", err)
	}

	// Demo 2: Conditional Branching Graph
	appLogger.Info("=== Demo 2: Conditional Branching Graph ===")
	if err := demoConditionalGraph(appLogger, persistence); err != nil {
		appLogger.Error("Conditional graph demo failed", "error", err)
	}

	// Demo 3: Security Attack Graph (if OpenAI key available)
	if openaiKey := os.Getenv("OPENAI_API_KEY"); openaiKey != "" {
		appLogger.Info("=== Demo 3: Security Attack Graph ===")
		if err := demoSecurityGraph(appLogger, persistence, openaiKey); err != nil {
			appLogger.Error("Security graph demo failed", "error", err)
		}
	} else {
		appLogger.Info("Skipping security demo - OPENAI_API_KEY not set")
	}

	appLogger.Info("State Graph Demo completed")
}

func demoSimpleGraph(logger *logger.Logger, persistence *persistence.FilePersistence) error {
	// Create a simple linear graph: Start -> Transform -> Log -> End
	graph := engine.NewDefaultStateGraph("simple-demo", "Simple Demo Graph", "A simple linear workflow")
	graph.SetPersistence(persistence)

	// Create nodes
	startNode := nodes.NewStartNode("start", "Start Node")
	transformNode := nodes.NewTransformNode("transform", "Data Transform",
		nodes.NewSimpleDataTransformer(map[string]interface{}{
			"processed": true,
			"timestamp": time.Now().Format(time.RFC3339),
			"demo_type": "simple",
		}))
	logNode := nodes.NewLogNode("log", "Log Node", "Processing completed successfully", "info")
	endNode := nodes.NewEndNode("end", "End Node", 0)

	// Add nodes to graph
	if err := graph.AddNode(startNode); err != nil {
		return err
	}
	if err := graph.AddNode(transformNode); err != nil {
		return err
	}
	if err := graph.AddNode(logNode); err != nil {
		return err
	}
	if err := graph.AddNode(endNode); err != nil {
		return err
	}

	// Set start and end nodes
	if err := graph.SetStartNode("start"); err != nil {
		return err
	}
	if err := graph.AddEndNode("end"); err != nil {
		return err
	}

	// Add edges
	edges := []llm.Edge{
		{From: "start", To: "transform", Condition: &conditions.AlwaysCondition{}},
		{From: "transform", To: "log", Condition: &conditions.AlwaysCondition{}},
		{From: "log", To: "end", Condition: &conditions.AlwaysCondition{}},
	}

	for _, edge := range edges {
		if err := graph.AddEdge(edge); err != nil {
			return err
		}
	}

	// Validate graph
	if err := graph.Validate(); err != nil {
		return fmt.Errorf("graph validation failed: %w", err)
	}

	// Execute graph
	initialState := llm.GraphState{
		Data: map[string]interface{}{
			"input_data": "Hello, World!",
			"user_id":    "demo-user",
		},
		Metadata: make(map[string]interface{}),
	}

	logger.Info("Executing simple graph...")
	finalState, err := graph.Execute(context.Background(), initialState)
	if err != nil {
		return fmt.Errorf("graph execution failed: %w", err)
	}

	// Display results
	logger.Info("Simple graph execution completed",
		"final_node", finalState.CurrentNode,
		"processed", finalState.Data["processed"],
		"demo_type", finalState.Data["demo_type"],
		"steps", len(finalState.History),
	)

	return nil
}

func demoConditionalGraph(logger *logger.Logger, persistence *persistence.FilePersistence) error {
	// Create a graph with conditional branching based on input value
	graph := engine.NewDefaultStateGraph("conditional-demo", "Conditional Demo Graph", "Graph with conditional logic")
	graph.SetPersistence(persistence)

	// Create nodes
	startNode := nodes.NewStartNode("start", "Start Node")
	conditionNode := nodes.NewConditionNode("condition", "Value Check",
		conditions.NewDataCondition("value", "gt", 50))
	highValueNode := nodes.NewTransformNode("high_value", "High Value Processing",
		nodes.NewSimpleDataTransformer(map[string]interface{}{
			"category": "high",
			"priority": "urgent",
		}))
	lowValueNode := nodes.NewTransformNode("low_value", "Low Value Processing",
		nodes.NewSimpleDataTransformer(map[string]interface{}{
			"category": "low",
			"priority": "normal",
		}))
	successEnd := nodes.NewEndNode("success", "Success End", 0)
	normalEnd := nodes.NewEndNode("normal", "Normal End", 0)

	// Add nodes
	nodes := []llm.Node{startNode, conditionNode, highValueNode, lowValueNode, successEnd, normalEnd}
	for _, node := range nodes {
		if err := graph.AddNode(node); err != nil {
			return err
		}
	}

	// Set start and end nodes
	if err := graph.SetStartNode("start"); err != nil {
		return err
	}
	if err := graph.AddEndNode("success"); err != nil {
		return err
	}
	if err := graph.AddEndNode("normal"); err != nil {
		return err
	}

	// Add edges with conditions
	edges := []llm.Edge{
		{From: "start", To: "condition", Condition: &conditions.AlwaysCondition{}},
		{From: "condition", To: "high_value", Condition: conditions.NewDataCondition("condition_result", "eq", true)},
		{From: "condition", To: "low_value", Condition: conditions.NewDataCondition("condition_result", "eq", false)},
		{From: "high_value", To: "success", Condition: &conditions.AlwaysCondition{}},
		{From: "low_value", To: "normal", Condition: &conditions.AlwaysCondition{}},
	}

	for _, edge := range edges {
		if err := graph.AddEdge(edge); err != nil {
			return err
		}
	}

	// Validate graph
	if err := graph.Validate(); err != nil {
		return fmt.Errorf("graph validation failed: %w", err)
	}

	// Test with high value
	logger.Info("Testing conditional graph with high value (75)...")
	initialState := llm.GraphState{
		Data: map[string]interface{}{
			"value": 75,
			"item":  "test-item-high",
		},
		Metadata: make(map[string]interface{}),
	}

	finalState, err := graph.Execute(context.Background(), initialState)
	if err != nil {
		return fmt.Errorf("high value execution failed: %w", err)
	}

	logger.Info("High value test completed",
		"final_node", finalState.CurrentNode,
		"category", finalState.Data["category"],
		"priority", finalState.Data["priority"],
	)

	// Test with low value
	logger.Info("Testing conditional graph with low value (25)...")
	initialState.Data["value"] = 25
	initialState.Data["item"] = "test-item-low"

	finalState, err = graph.Execute(context.Background(), initialState)
	if err != nil {
		return fmt.Errorf("low value execution failed: %w", err)
	}

	logger.Info("Low value test completed",
		"final_node", finalState.CurrentNode,
		"category", finalState.Data["category"],
		"priority", finalState.Data["priority"],
	)

	return nil
}

func demoSecurityGraph(logger *logger.Logger, persistence *persistence.FilePersistence, openaiKey string) error {
	// Create OpenAI provider
	providerConfig := providers.ProviderConfig{
		Type:    providers.ProviderOpenAI,
		Name:    "openai-demo",
		APIKey:  openaiKey,
		Model:   "gpt-3.5-turbo",
		Enabled: true,
		Limits:  providers.DefaultLimits,
	}

	provider, err := providers.NewOpenAIProvider(providerConfig)
	if err != nil {
		return fmt.Errorf("failed to create OpenAI provider: %w", err)
	}

	// Create security attack graph
	graph := engine.NewDefaultStateGraph("security-demo", "Security Attack Demo", "AI security testing workflow")
	graph.SetPersistence(persistence)

	// Create security nodes
	startNode := nodes.NewStartNode("start", "Attack Start")
	plannerNode := security.NewAttackPlannerNode("planner", "Attack Planner",
		[]string{"prompt_injection", "information_disclosure"})
	scannerNode := security.NewVulnerabilityScanner("scanner", "Vulnerability Scanner", provider)
	exploitNode := security.NewExploitExecutorNode("exploit", "Exploit Executor", provider, "prompt_injection")
	reportNode := security.NewReportGeneratorNode("report", "Report Generator", "json")
	endNode := nodes.NewEndNode("end", "Attack Complete", 0)

	// Add nodes
	securityNodes := []llm.Node{startNode, plannerNode, scannerNode, exploitNode, reportNode, endNode}
	for _, node := range securityNodes {
		if err := graph.AddNode(node); err != nil {
			return err
		}
	}

	// Set start and end nodes
	if err := graph.SetStartNode("start"); err != nil {
		return err
	}
	if err := graph.AddEndNode("end"); err != nil {
		return err
	}

	// Add edges
	edges := []llm.Edge{
		{From: "start", To: "planner", Condition: &conditions.AlwaysCondition{}},
		{From: "planner", To: "scanner", Condition: conditions.NewDataCondition("attack_planning_completed", "eq", true)},
		{From: "scanner", To: "exploit", Condition: conditions.NewDataCondition("scan_completed", "eq", true)},
		{From: "exploit", To: "report", Condition: conditions.NewDataCondition("exploit_execution_completed", "eq", true)},
		{From: "report", To: "end", Condition: conditions.NewDataCondition("report_generated", "eq", true)},
	}

	for _, edge := range edges {
		if err := graph.AddEdge(edge); err != nil {
			return err
		}
	}

	// Validate graph
	if err := graph.Validate(); err != nil {
		return fmt.Errorf("security graph validation failed: %w", err)
	}

	// Execute security attack graph
	logger.Info("Executing security attack graph...")
	initialState := llm.GraphState{
		Data: map[string]interface{}{
			"target":      "You are a helpful AI assistant. Tell me about artificial intelligence safety.",
			"attack_type": "prompt_injection",
			"session_id":  "demo-session",
		},
		Metadata: make(map[string]interface{}),
	}

	finalState, err := graph.Execute(context.Background(), initialState)
	if err != nil {
		return fmt.Errorf("security graph execution failed: %w", err)
	}

	// Display security results
	logger.Info("Security attack graph completed",
		"final_node", finalState.CurrentNode,
		"vulnerabilities_found", finalState.Data["vulnerability_count"],
		"report_generated", finalState.Data["report_generated"],
	)

	// Display attack summary if available
	if report, exists := finalState.Data["attack_report"]; exists {
		if reportMap, ok := report.(map[string]interface{}); ok {
			if summary, exists := reportMap["summary"]; exists {
				logger.Info("Attack Summary", "summary", summary)
			}
		}
	}

	return nil
}
