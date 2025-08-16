package unit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/graph/conditions"
	"github.com/dimajoyti/hackai/pkg/graph/engine"
	"github.com/dimajoyti/hackai/pkg/graph/nodes"
	"github.com/dimajoyti/hackai/pkg/graph/persistence"
	"github.com/dimajoyti/hackai/pkg/llm"
)

// TestStateGraphBasicExecution tests basic state graph execution
func TestStateGraphBasicExecution(t *testing.T) {
	// Create a simple graph: Start -> Transform -> End
	graph := engine.NewDefaultStateGraph("test-graph", "Test Graph", "A simple test graph")

	// Create nodes
	startNode := nodes.NewStartNode("start", "Start Node")
	transformNode := nodes.NewTransformNode("transform", "Transform Node",
		nodes.NewSimpleDataTransformer(map[string]interface{}{
			"processed": true,
			"step":      "transform",
		}))
	endNode := nodes.NewEndNode("end", "End Node", 0)

	// Add nodes to graph
	require.NoError(t, graph.AddNode(startNode))
	require.NoError(t, graph.AddNode(transformNode))
	require.NoError(t, graph.AddNode(endNode))

	// Set start and end nodes
	require.NoError(t, graph.SetStartNode("start"))
	require.NoError(t, graph.AddEndNode("end"))

	// Add edges
	require.NoError(t, graph.AddEdge(llm.Edge{
		From:      "start",
		To:        "transform",
		Condition: &conditions.AlwaysCondition{},
	}))
	require.NoError(t, graph.AddEdge(llm.Edge{
		From:      "transform",
		To:        "end",
		Condition: &conditions.AlwaysCondition{},
	}))

	// Validate graph
	require.NoError(t, graph.Validate())

	// Execute graph
	initialState := llm.GraphState{
		Data:     make(map[string]interface{}),
		Metadata: make(map[string]interface{}),
	}

	finalState, err := graph.Execute(context.Background(), initialState)
	require.NoError(t, err)

	// Verify final state
	assert.Equal(t, "end", finalState.CurrentNode)

	// Check data with proper type assertions
	if started, ok := finalState.Data["started"].(bool); ok {
		assert.True(t, started)
	}
	if processed, ok := finalState.Data["processed"].(bool); ok {
		assert.True(t, processed)
	}
	if completed, ok := finalState.Data["completed"].(bool); ok {
		assert.True(t, completed)
	}
	if step, ok := finalState.Data["step"].(string); ok {
		assert.Equal(t, "transform", step)
	}
	if exitCode, ok := finalState.Data["exit_code"].(int); ok {
		assert.Equal(t, 0, exitCode)
	}

	assert.Len(t, finalState.History, 2) // start->transform, transform->end
}

// TestStateGraphConditionalExecution tests conditional execution
func TestStateGraphConditionalExecution(t *testing.T) {
	// Create a graph with conditional branching
	graph := engine.NewDefaultStateGraph("conditional-graph", "Conditional Graph", "Graph with conditional logic")

	// Create nodes
	startNode := nodes.NewStartNode("start", "Start Node")
	conditionNode := nodes.NewConditionNode("condition", "Condition Node",
		conditions.NewDataCondition("value", "gt", 5))
	successNode := nodes.NewEndNode("success", "Success Node", 0)
	failureNode := nodes.NewEndNode("failure", "Failure Node", 1)

	// Add nodes
	require.NoError(t, graph.AddNode(startNode))
	require.NoError(t, graph.AddNode(conditionNode))
	require.NoError(t, graph.AddNode(successNode))
	require.NoError(t, graph.AddNode(failureNode))

	// Set start and end nodes
	require.NoError(t, graph.SetStartNode("start"))
	require.NoError(t, graph.AddEndNode("success"))
	require.NoError(t, graph.AddEndNode("failure"))

	// Add edges
	require.NoError(t, graph.AddEdge(llm.Edge{
		From:      "start",
		To:        "condition",
		Condition: &conditions.AlwaysCondition{},
	}))
	require.NoError(t, graph.AddEdge(llm.Edge{
		From:      "condition",
		To:        "success",
		Condition: conditions.NewDataCondition("condition_result", "eq", true),
	}))
	require.NoError(t, graph.AddEdge(llm.Edge{
		From:      "condition",
		To:        "failure",
		Condition: conditions.NewDataCondition("condition_result", "eq", false),
	}))

	// Test with value > 5 (should go to success)
	initialState := llm.GraphState{
		Data: map[string]interface{}{
			"value": 10,
		},
		Metadata: make(map[string]interface{}),
	}

	finalState, err := graph.Execute(context.Background(), initialState)
	require.NoError(t, err)
	assert.Equal(t, "success", finalState.CurrentNode)
	if exitCode, ok := finalState.Data["exit_code"].(int); ok {
		assert.Equal(t, 0, exitCode)
	}

	// Test with value <= 5 (should go to failure)
	initialState.Data["value"] = 3
	finalState, err = graph.Execute(context.Background(), initialState)
	require.NoError(t, err)
	assert.Equal(t, "failure", finalState.CurrentNode)
	if exitCode, ok := finalState.Data["exit_code"].(int); ok {
		assert.Equal(t, 1, exitCode)
	}
}

// TestStateGraphPersistence tests state persistence functionality
func TestStateGraphPersistence(t *testing.T) {
	// Create in-memory persistence
	persistence := persistence.NewInMemoryPersistence()

	// Create a simple graph
	graph := engine.NewDefaultStateGraph("persist-graph", "Persistence Graph", "Graph with persistence")
	graph.SetPersistence(persistence)

	// Create and add nodes
	startNode := nodes.NewStartNode("start", "Start Node")
	delayNode := nodes.NewDelayNode("delay", "Delay Node", 100*time.Millisecond)
	endNode := nodes.NewEndNode("end", "End Node", 0)

	require.NoError(t, graph.AddNode(startNode))
	require.NoError(t, graph.AddNode(delayNode))
	require.NoError(t, graph.AddNode(endNode))

	require.NoError(t, graph.SetStartNode("start"))
	require.NoError(t, graph.AddEndNode("end"))

	require.NoError(t, graph.AddEdge(llm.Edge{
		From:      "start",
		To:        "delay",
		Condition: &conditions.AlwaysCondition{},
	}))
	require.NoError(t, graph.AddEdge(llm.Edge{
		From:      "delay",
		To:        "end",
		Condition: &conditions.AlwaysCondition{},
	}))

	// Test state persistence
	testState := llm.GraphState{
		CurrentNode: "delay",
		Data: map[string]interface{}{
			"test_key": "test_value",
		},
		Metadata:  make(map[string]interface{}),
		StartTime: time.Now(),
	}

	// Save state
	err := persistence.SaveState(context.Background(), "test-state", testState)
	require.NoError(t, err)

	// Load state
	loadedState, err := persistence.LoadState(context.Background(), "test-state")
	require.NoError(t, err)
	assert.Equal(t, "delay", loadedState.CurrentNode)
	assert.Equal(t, "test_value", loadedState.Data["test_key"])

	// List states
	states, err := persistence.ListStates(context.Background())
	require.NoError(t, err)
	assert.Contains(t, states, "test-state")

	// Delete state
	err = persistence.DeleteState(context.Background(), "test-state")
	require.NoError(t, err)

	// Verify deletion
	_, err = persistence.LoadState(context.Background(), "test-state")
	assert.Error(t, err)
}

// TestConditions tests various condition types
func TestConditions(t *testing.T) {
	state := llm.GraphState{
		Data: map[string]interface{}{
			"count":   10,
			"status":  "active",
			"success": true,
			"error":   nil,
		},
	}

	ctx := context.Background()

	// Test DataCondition
	condition := conditions.NewDataCondition("count", "gt", 5)
	result, err := condition.Evaluate(ctx, state)
	require.NoError(t, err)
	assert.True(t, result)

	condition = conditions.NewDataCondition("status", "eq", "active")
	result, err = condition.Evaluate(ctx, state)
	require.NoError(t, err)
	assert.True(t, result)

	// Test SuccessCondition
	successCondition := conditions.NewSuccessCondition("")
	result, err = successCondition.Evaluate(ctx, state)
	require.NoError(t, err)
	assert.True(t, result)

	// Test ErrorCondition
	errorCondition := conditions.NewErrorCondition("")
	result, err = errorCondition.Evaluate(ctx, state)
	require.NoError(t, err)
	assert.False(t, result) // No error present

	// Test AndCondition
	andCondition := conditions.NewAndCondition(
		conditions.NewDataCondition("count", "gt", 5),
		conditions.NewDataCondition("status", "eq", "active"),
	)
	result, err = andCondition.Evaluate(ctx, state)
	require.NoError(t, err)
	assert.True(t, result)

	// Test OrCondition
	orCondition := conditions.NewOrCondition(
		conditions.NewDataCondition("count", "lt", 5),
		conditions.NewDataCondition("status", "eq", "active"),
	)
	result, err = orCondition.Evaluate(ctx, state)
	require.NoError(t, err)
	assert.True(t, result) // Second condition is true

	// Test NotCondition
	notCondition := conditions.NewNotCondition(
		conditions.NewDataCondition("count", "lt", 5),
	)
	result, err = notCondition.Evaluate(ctx, state)
	require.NoError(t, err)
	assert.True(t, result) // count is not < 5
}

// TestGraphValidation tests graph validation
func TestGraphValidation(t *testing.T) {
	// Test empty graph
	graph := engine.NewDefaultStateGraph("empty-graph", "Empty Graph", "Empty graph")
	err := graph.Validate()
	assert.Error(t, err) // Should fail - no nodes

	// Test graph without start node
	graph = engine.NewDefaultStateGraph("no-start", "No Start Graph", "Graph without start node")
	endNode := nodes.NewEndNode("end", "End Node", 0)
	require.NoError(t, graph.AddNode(endNode))
	require.NoError(t, graph.AddEndNode("end"))
	err = graph.Validate()
	assert.Error(t, err) // Should fail - no start node

	// Test graph without end nodes
	graph = engine.NewDefaultStateGraph("no-end", "No End Graph", "Graph without end nodes")
	startNode := nodes.NewStartNode("start", "Start Node")
	require.NoError(t, graph.AddNode(startNode))
	require.NoError(t, graph.SetStartNode("start"))
	err = graph.Validate()
	assert.Error(t, err) // Should fail - no end nodes

	// Test valid graph
	graph = engine.NewDefaultStateGraph("valid-graph", "Valid Graph", "Valid graph")
	startNode = nodes.NewStartNode("start", "Start Node")
	endNode = nodes.NewEndNode("end", "End Node", 0)
	require.NoError(t, graph.AddNode(startNode))
	require.NoError(t, graph.AddNode(endNode))
	require.NoError(t, graph.SetStartNode("start"))
	require.NoError(t, graph.AddEndNode("end"))
	require.NoError(t, graph.AddEdge(llm.Edge{
		From:      "start",
		To:        "end",
		Condition: &conditions.AlwaysCondition{},
	}))
	err = graph.Validate()
	assert.NoError(t, err) // Should pass
}

// TestGraphTimeout tests execution timeout
func TestGraphTimeout(t *testing.T) {
	graph := engine.NewDefaultStateGraph("timeout-graph", "Timeout Graph", "Graph with timeout")

	// Set a very short timeout
	config := engine.GraphConfig{
		MaxExecutionTime: 10 * time.Millisecond,
		MaxSteps:         1000,
	}
	graph.SetConfig(config)

	// Create nodes with delay
	startNode := nodes.NewStartNode("start", "Start Node")
	delayNode := nodes.NewDelayNode("delay", "Long Delay Node", 100*time.Millisecond) // Longer than timeout
	endNode := nodes.NewEndNode("end", "End Node", 0)

	require.NoError(t, graph.AddNode(startNode))
	require.NoError(t, graph.AddNode(delayNode))
	require.NoError(t, graph.AddNode(endNode))

	require.NoError(t, graph.SetStartNode("start"))
	require.NoError(t, graph.AddEndNode("end"))

	require.NoError(t, graph.AddEdge(llm.Edge{
		From:      "start",
		To:        "delay",
		Condition: &conditions.AlwaysCondition{},
	}))
	require.NoError(t, graph.AddEdge(llm.Edge{
		From:      "delay",
		To:        "end",
		Condition: &conditions.AlwaysCondition{},
	}))

	// Execute graph - should timeout
	initialState := llm.GraphState{
		Data:     make(map[string]interface{}),
		Metadata: make(map[string]interface{}),
	}

	_, err := graph.Execute(context.Background(), initialState)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

// TestMaxSteps tests maximum steps limit
func TestMaxSteps(t *testing.T) {
	graph := engine.NewDefaultStateGraph("max-steps-graph", "Max Steps Graph", "Graph with step limit")

	// Set a very low step limit
	config := engine.GraphConfig{
		MaxExecutionTime: 30 * time.Second,
		MaxSteps:         2, // Very low limit
	}
	graph.SetConfig(config)

	// Create a longer chain of nodes
	startNode := nodes.NewStartNode("start", "Start Node")
	transform1 := nodes.NewTransformNode("transform1", "Transform 1",
		nodes.NewSimpleDataTransformer(map[string]interface{}{"step": 1}))
	transform2 := nodes.NewTransformNode("transform2", "Transform 2",
		nodes.NewSimpleDataTransformer(map[string]interface{}{"step": 2}))
	endNode := nodes.NewEndNode("end", "End Node", 0)

	require.NoError(t, graph.AddNode(startNode))
	require.NoError(t, graph.AddNode(transform1))
	require.NoError(t, graph.AddNode(transform2))
	require.NoError(t, graph.AddNode(endNode))

	require.NoError(t, graph.SetStartNode("start"))
	require.NoError(t, graph.AddEndNode("end"))

	// Add edges
	require.NoError(t, graph.AddEdge(llm.Edge{From: "start", To: "transform1", Condition: &conditions.AlwaysCondition{}}))
	require.NoError(t, graph.AddEdge(llm.Edge{From: "transform1", To: "transform2", Condition: &conditions.AlwaysCondition{}}))
	require.NoError(t, graph.AddEdge(llm.Edge{From: "transform2", To: "end", Condition: &conditions.AlwaysCondition{}}))

	// Execute graph - should hit step limit
	initialState := llm.GraphState{
		Data:     make(map[string]interface{}),
		Metadata: make(map[string]interface{}),
	}

	_, err := graph.Execute(context.Background(), initialState)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum steps")
}
