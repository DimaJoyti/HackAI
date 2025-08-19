package ai

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var graphTracer = otel.Tracer("hackai/ai/graph")

// GraphExecutionContext provides enhanced context for graph execution
type GraphExecutionContext struct {
	RequestID     string                 `json:"request_id"`
	UserID        string                 `json:"user_id"`
	SessionID     string                 `json:"session_id"`
	SecurityLevel SecurityLevel          `json:"security_level"`
	MaxDepth      int                    `json:"max_depth"`
	Timeout       time.Duration          `json:"timeout"`
	Metadata      map[string]interface{} `json:"metadata"`
	StartTime     time.Time              `json:"start_time"`
}

// GraphExecutionResult provides detailed execution results
type GraphExecutionResult struct {
	Success       bool                   `json:"success"`
	FinalState    GraphState             `json:"final_state"`
	Error         error                  `json:"error,omitempty"`
	ExecutionTime time.Duration          `json:"execution_time"`
	NodesExecuted []string               `json:"nodes_executed"`
	ExecutionPath []GraphExecutionStep   `json:"execution_path"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// GraphExecutionStep represents a single step in graph execution
type GraphExecutionStep struct {
	NodeID        string                 `json:"node_id"`
	NodeType      string                 `json:"node_type"`
	InputState    GraphState             `json:"input_state"`
	OutputState   GraphState             `json:"output_state"`
	ExecutionTime time.Duration          `json:"execution_time"`
	Error         error                  `json:"error,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// AdvancedEdgeCondition provides more sophisticated condition evaluation
type AdvancedEdgeCondition struct {
	ID          string                                                       `json:"id"`
	Name        string                                                       `json:"name"`
	Description string                                                       `json:"description"`
	Evaluator   func(state GraphState, context GraphExecutionContext) string `json:"-"`
	Priority    int                                                          `json:"priority"`
}

// ConditionalBranch represents a conditional branch with multiple conditions
type ConditionalBranch struct {
	Conditions  []AdvancedEdgeCondition `json:"conditions"`
	DefaultEdge string                  `json:"default_edge"`
}

// EnhancedGraph extends the basic Graph interface with advanced capabilities
type EnhancedGraph interface {
	Graph
	ExecuteWithContext(ctx context.Context, execCtx GraphExecutionContext, initialState GraphState) (*GraphExecutionResult, error)
	ExecuteAsync(ctx context.Context, execCtx GraphExecutionContext, initialState GraphState) (<-chan *GraphExecutionResult, error)
	AddAdvancedConditionalEdge(from string, branch ConditionalBranch) error
	GetExecutionHistory() []GraphExecutionResult
	ValidateState(state GraphState) error
}

// StateGraph implements the Graph interface using state machine patterns
type StateGraph struct {
	id                       string
	name                     string
	description              string
	nodes                    map[string]GraphNode
	edges                    map[string][]string
	conditionalEdges         map[string]ConditionalEdge
	advancedConditionalEdges map[string]ConditionalBranch
	entryPoint               string
	metrics                  GraphMetrics
	executionHistory         []GraphExecutionResult
	maxHistorySize           int
	stateValidator           GraphStateValidator
	logger                   *logger.Logger
	tracer                   trace.Tracer
	mutex                    sync.RWMutex
}

// GraphStateValidator validates graph state
type GraphStateValidator interface {
	Validate(state GraphState) error
}

// ConditionalEdge represents a conditional edge in the graph
type ConditionalEdge struct {
	Condition EdgeCondition
	Edges     map[string]string
}

// NewStateGraph creates a new state graph
func NewStateGraph(id, name, description string, logger *logger.Logger) *StateGraph {
	return &StateGraph{
		id:                       id,
		name:                     name,
		description:              description,
		nodes:                    make(map[string]GraphNode),
		edges:                    make(map[string][]string),
		conditionalEdges:         make(map[string]ConditionalEdge),
		advancedConditionalEdges: make(map[string]ConditionalBranch),
		executionHistory:         make([]GraphExecutionResult, 0),
		maxHistorySize:           100, // Default history size
		logger:                   logger,
		tracer:                   graphTracer,
		metrics: GraphMetrics{
			NodeMetrics:       make(map[string]NodeMetrics),
			LastExecutionTime: time.Now(),
		},
	}
}

// ID returns the graph ID
func (g *StateGraph) ID() string {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.id
}

// Name returns the graph name
func (g *StateGraph) Name() string {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.name
}

// Description returns the graph description
func (g *StateGraph) Description() string {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.description
}

// AddNode adds a node to the graph
func (g *StateGraph) AddNode(node GraphNode) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	nodeID := node.ID()
	if nodeID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}

	if _, exists := g.nodes[nodeID]; exists {
		return fmt.Errorf("node %s already exists", nodeID)
	}

	if err := node.Validate(); err != nil {
		return fmt.Errorf("node validation failed: %w", err)
	}

	g.nodes[nodeID] = node
	g.metrics.NodeMetrics[nodeID] = NodeMetrics{
		LastExecution: time.Now(),
	}

	g.logger.Debug("Node added to graph",
		"graph_id", g.id,
		"node_id", nodeID,
		"node_type", string(node.Type()))

	return nil
}

// AddEdge adds a simple edge between two nodes
func (g *StateGraph) AddEdge(from, to string) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if _, exists := g.nodes[from]; !exists {
		return fmt.Errorf("source node %s does not exist", from)
	}
	if _, exists := g.nodes[to]; !exists {
		return fmt.Errorf("target node %s does not exist", to)
	}

	g.edges[from] = append(g.edges[from], to)

	g.logger.Debug("Edge added to graph",
		"graph_id", g.id,
		"from", from,
		"to", to)

	return nil
}

// AddConditionalEdge adds a conditional edge with multiple possible targets
func (g *StateGraph) AddConditionalEdge(from string, condition EdgeCondition, edges map[string]string) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if _, exists := g.nodes[from]; !exists {
		return fmt.Errorf("source node %s does not exist", from)
	}

	// Validate all target nodes exist
	for _, to := range edges {
		if _, exists := g.nodes[to]; !exists {
			return fmt.Errorf("target node %s does not exist", to)
		}
	}

	if condition == nil {
		return fmt.Errorf("condition cannot be nil")
	}

	g.conditionalEdges[from] = ConditionalEdge{
		Condition: condition,
		Edges:     edges,
	}

	g.logger.Debug("Conditional edge added to graph",
		"graph_id", g.id,
		"from", from,
		"edge_count", len(edges))

	return nil
}

// SetEntryPoint sets the entry point for graph execution
func (g *StateGraph) SetEntryPoint(nodeID string) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if _, exists := g.nodes[nodeID]; !exists {
		return fmt.Errorf("node %s does not exist", nodeID)
	}

	g.entryPoint = nodeID

	g.logger.Debug("Entry point set for graph",
		"graph_id", g.id,
		"entry_point", nodeID)

	return nil
}

// GetNodes returns all nodes in the graph
func (g *StateGraph) GetNodes() map[string]GraphNode {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	// Return a copy to prevent external modification
	nodes := make(map[string]GraphNode)
	for id, node := range g.nodes {
		nodes[id] = node
	}
	return nodes
}

// GetEdges returns all edges in the graph
func (g *StateGraph) GetEdges() map[string][]string {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	// Return a copy to prevent external modification
	edges := make(map[string][]string)
	for from, toList := range g.edges {
		edges[from] = make([]string, len(toList))
		copy(edges[from], toList)
	}
	return edges
}

// GetMetrics returns the graph metrics
func (g *StateGraph) GetMetrics() GraphMetrics {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.metrics
}

// Execute executes the graph starting from the entry point
func (g *StateGraph) Execute(ctx context.Context, initialState GraphState) (GraphState, error) {
	startTime := time.Now()

	// Create span for tracing
	ctx, span := g.tracer.Start(ctx, "graph.execute",
		trace.WithAttributes(
			attribute.String("graph.id", g.id),
			attribute.String("graph.name", g.name),
		),
	)
	defer span.End()

	// Update metrics
	g.updateExecutionStart()

	if g.entryPoint == "" {
		err := fmt.Errorf("no entry point set for graph %s", g.id)
		span.RecordError(err)
		return nil, err
	}

	currentState := initialState
	if currentState == nil {
		currentState = make(GraphState)
	}

	// Execute the graph
	finalState, err := g.executeFromNode(ctx, g.entryPoint, currentState)

	// Update metrics
	duration := time.Since(startTime)
	g.updateExecutionEnd(duration, err == nil)

	if err != nil {
		span.RecordError(err)
		g.logger.Error("Graph execution failed",
			"graph_id", g.id,
			"error", err,
			"duration", duration)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("execution.duration", duration.String()),
		attribute.Bool("execution.success", true),
	)

	g.logger.Info("Graph executed successfully",
		"graph_id", g.id,
		"duration", duration)

	return finalState, nil
}

// executeFromNode executes the graph starting from a specific node
func (g *StateGraph) executeFromNode(ctx context.Context, nodeID string, state GraphState) (GraphState, error) {
	visited := make(map[string]bool)
	return g.executeNode(ctx, nodeID, state, visited)
}

// executeNode executes a single node and follows edges
func (g *StateGraph) executeNode(ctx context.Context, nodeID string, state GraphState, visited map[string]bool) (GraphState, error) {
	// Check for cycles
	if visited[nodeID] {
		return state, fmt.Errorf("cycle detected at node %s", nodeID)
	}
	visited[nodeID] = true

	// Get the node
	g.mutex.RLock()
	node, exists := g.nodes[nodeID]
	g.mutex.RUnlock()

	if !exists {
		return state, fmt.Errorf("node %s not found", nodeID)
	}

	// Execute the node
	nodeStartTime := time.Now()
	nodeCtx, nodeSpan := g.tracer.Start(ctx, fmt.Sprintf("graph.node.%s", nodeID),
		trace.WithAttributes(
			attribute.String("node.id", nodeID),
			attribute.String("node.type", string(node.Type())),
		),
	)

	newState, err := node.Execute(nodeCtx, state)
	nodeSpan.End()

	// Update node metrics
	nodeDuration := time.Since(nodeStartTime)
	g.updateNodeMetrics(nodeID, nodeDuration, err == nil)

	if err != nil {
		nodeSpan.RecordError(err)
		return state, fmt.Errorf("node %s execution failed: %w", nodeID, err)
	}

	// Determine next node(s)
	nextNodes, err := g.getNextNodes(nodeID, newState)
	if err != nil {
		return newState, err
	}

	// If no next nodes, we're done
	if len(nextNodes) == 0 {
		return newState, nil
	}

	// Execute next nodes (for now, just execute the first one)
	// In a more sophisticated implementation, we might handle parallel execution
	return g.executeNode(ctx, nextNodes[0], newState, visited)
}

// getNextNodes determines the next nodes to execute based on edges and conditions
func (g *StateGraph) getNextNodes(nodeID string, state GraphState) ([]string, error) {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	// Check for conditional edges first
	if conditionalEdge, exists := g.conditionalEdges[nodeID]; exists {
		condition := conditionalEdge.Condition(state)
		if nextNode, exists := conditionalEdge.Edges[condition]; exists {
			return []string{nextNode}, nil
		}
		return nil, fmt.Errorf("no edge found for condition %s from node %s", condition, nodeID)
	}

	// Check for simple edges
	if edges, exists := g.edges[nodeID]; exists {
		return edges, nil
	}

	// No edges found - this is a terminal node
	return []string{}, nil
}

// Validate validates the graph structure
func (g *StateGraph) Validate() error {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	if g.id == "" {
		return fmt.Errorf("graph ID cannot be empty")
	}
	if g.name == "" {
		return fmt.Errorf("graph name cannot be empty")
	}
	if len(g.nodes) == 0 {
		return fmt.Errorf("graph must have at least one node")
	}
	if g.entryPoint == "" {
		return fmt.Errorf("graph must have an entry point")
	}

	// Validate all nodes
	for nodeID, node := range g.nodes {
		if err := node.Validate(); err != nil {
			return fmt.Errorf("node %s validation failed: %w", nodeID, err)
		}
	}

	// Validate edges reference existing nodes
	for from, toList := range g.edges {
		if _, exists := g.nodes[from]; !exists {
			return fmt.Errorf("edge references non-existent source node %s", from)
		}
		for _, to := range toList {
			if _, exists := g.nodes[to]; !exists {
				return fmt.Errorf("edge references non-existent target node %s", to)
			}
		}
	}

	return nil
}

// Clone creates a copy of the graph
func (g *StateGraph) Clone() Graph {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	cloned := NewStateGraph(g.id+"_clone", g.name, g.description, g.logger)

	// Clone nodes (assuming nodes implement a Clone method)
	for nodeID, node := range g.nodes {
		// For now, we'll just add the same node reference
		// In a full implementation, nodes should also be cloneable
		cloned.nodes[nodeID] = node
	}

	// Clone edges
	for from, toList := range g.edges {
		cloned.edges[from] = make([]string, len(toList))
		copy(cloned.edges[from], toList)
	}

	// Clone conditional edges
	for from, condEdge := range g.conditionalEdges {
		edgesCopy := make(map[string]string)
		for k, v := range condEdge.Edges {
			edgesCopy[k] = v
		}
		cloned.conditionalEdges[from] = ConditionalEdge{
			Condition: condEdge.Condition,
			Edges:     edgesCopy,
		}
	}

	cloned.entryPoint = g.entryPoint

	return cloned
}

// updateExecutionStart updates metrics at the start of execution
func (g *StateGraph) updateExecutionStart() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.metrics.TotalExecutions++
}

// updateExecutionEnd updates metrics at the end of execution
func (g *StateGraph) updateExecutionEnd(duration time.Duration, success bool) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if success {
		g.metrics.SuccessfulRuns++
	} else {
		g.metrics.FailedRuns++
	}

	// Update average latency
	if g.metrics.TotalExecutions == 1 {
		g.metrics.AverageLatency = duration
	} else {
		total := time.Duration(g.metrics.TotalExecutions-1) * g.metrics.AverageLatency
		g.metrics.AverageLatency = (total + duration) / time.Duration(g.metrics.TotalExecutions)
	}

	g.metrics.LastExecutionTime = time.Now()
}

// ExecuteWithContext executes the graph with enhanced context and detailed results
func (g *StateGraph) ExecuteWithContext(ctx context.Context, execCtx GraphExecutionContext, initialState GraphState) (*GraphExecutionResult, error) {
	ctx, span := g.tracer.Start(ctx, "state_graph.execute_with_context",
		trace.WithAttributes(
			attribute.String("graph.id", g.id),
			attribute.String("graph.name", g.name),
			attribute.String("request.id", execCtx.RequestID),
			attribute.String("user.id", execCtx.UserID),
			attribute.Int("max.depth", execCtx.MaxDepth),
		),
	)
	defer span.End()

	startTime := time.Now()
	result := &GraphExecutionResult{
		NodesExecuted: make([]string, 0),
		ExecutionPath: make([]GraphExecutionStep, 0),
		Metadata:      make(map[string]interface{}),
	}

	// Validate initial state
	if g.stateValidator != nil {
		if err := g.stateValidator.Validate(initialState); err != nil {
			result.Success = false
			result.Error = fmt.Errorf("initial state validation failed: %w", err)
			result.ExecutionTime = time.Since(startTime)
			span.RecordError(result.Error)
			return result, result.Error
		}
	}

	// Execute the graph with enhanced tracking
	finalState, err := g.executeWithTracking(ctx, execCtx, initialState, result)
	if err != nil {
		result.Success = false
		result.Error = err
		result.FinalState = initialState
	} else {
		result.Success = true
		result.FinalState = finalState
	}

	result.ExecutionTime = time.Since(startTime)

	// Update metrics
	g.updateExecutionEnd(result.ExecutionTime, result.Success)

	// Store execution history
	g.addToHistory(*result)

	span.SetAttributes(
		attribute.Bool("execution.success", result.Success),
		attribute.String("execution.duration", result.ExecutionTime.String()),
		attribute.Int("nodes.executed", len(result.NodesExecuted)),
	)

	return result, nil
}

// ExecuteAsync executes the graph asynchronously
func (g *StateGraph) ExecuteAsync(ctx context.Context, execCtx GraphExecutionContext, initialState GraphState) (<-chan *GraphExecutionResult, error) {
	resultChan := make(chan *GraphExecutionResult, 1)

	go func() {
		defer close(resultChan)
		result, _ := g.ExecuteWithContext(ctx, execCtx, initialState)
		resultChan <- result
	}()

	return resultChan, nil
}

// executeWithTracking executes the graph with detailed tracking
func (g *StateGraph) executeWithTracking(ctx context.Context, execCtx GraphExecutionContext, state GraphState, result *GraphExecutionResult) (GraphState, error) {
	if g.entryPoint == "" {
		return state, fmt.Errorf("no entry point set")
	}

	currentNodeID := g.entryPoint
	currentState := state
	depth := 0
	maxDepth := execCtx.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 100 // Default max depth
	}

	visited := make(map[string]bool)

	for depth < maxDepth {
		// Check for cycles
		if visited[currentNodeID] {
			g.logger.Warn("Cycle detected in graph execution",
				"graph_id", g.id,
				"node_id", currentNodeID,
				"depth", depth)
			break
		}
		visited[currentNodeID] = true

		// Get current node
		node, exists := g.nodes[currentNodeID]
		if !exists {
			return currentState, fmt.Errorf("node %s not found", currentNodeID)
		}

		// Execute node with tracking
		stepStartTime := time.Now()
		stepResult := GraphExecutionStep{
			NodeID:     currentNodeID,
			NodeType:   string(node.Type()),
			InputState: copyGraphState(currentState),
			Timestamp:  stepStartTime,
			Metadata:   make(map[string]interface{}),
		}

		// Execute the node
		newState, err := node.Execute(ctx, currentState)
		stepResult.ExecutionTime = time.Since(stepStartTime)
		stepResult.OutputState = copyGraphState(newState)

		if err != nil {
			stepResult.Error = err
			result.ExecutionPath = append(result.ExecutionPath, stepResult)
			return currentState, fmt.Errorf("node %s execution failed: %w", currentNodeID, err)
		}

		// Update tracking
		result.NodesExecuted = append(result.NodesExecuted, currentNodeID)
		result.ExecutionPath = append(result.ExecutionPath, stepResult)
		currentState = newState

		// Determine next node
		nextNodeID, err := g.getNextNode(currentNodeID, currentState, execCtx)
		if err != nil {
			return currentState, err
		}

		// If no next node, we're done
		if nextNodeID == "" {
			break
		}

		currentNodeID = nextNodeID
		depth++
	}

	if depth >= maxDepth {
		return currentState, fmt.Errorf("maximum execution depth %d reached", maxDepth)
	}

	return currentState, nil
}

// getNextNode determines the next node to execute based on edges and conditions
func (g *StateGraph) getNextNode(currentNodeID string, state GraphState, execCtx GraphExecutionContext) (string, error) {
	// Check for advanced conditional edges first
	if branch, exists := g.advancedConditionalEdges[currentNodeID]; exists {
		return g.evaluateAdvancedConditionalBranch(branch, state, execCtx)
	}

	// Check for basic conditional edges
	if condEdge, exists := g.conditionalEdges[currentNodeID]; exists {
		condition := condEdge.Condition(state)
		if nextNode, exists := condEdge.Edges[condition]; exists {
			return nextNode, nil
		}
	}

	// Check for regular edges
	if edges, exists := g.edges[currentNodeID]; exists && len(edges) > 0 {
		// For now, just take the first edge
		// In a more sophisticated implementation, this could be configurable
		return edges[0], nil
	}

	// No next node found
	return "", nil
}

// evaluateAdvancedConditionalBranch evaluates an advanced conditional branch
func (g *StateGraph) evaluateAdvancedConditionalBranch(branch ConditionalBranch, state GraphState, execCtx GraphExecutionContext) (string, error) {
	// Sort conditions by priority (higher priority first)
	conditions := make([]AdvancedEdgeCondition, len(branch.Conditions))
	copy(conditions, branch.Conditions)

	// Simple bubble sort by priority
	for i := 0; i < len(conditions)-1; i++ {
		for j := 0; j < len(conditions)-i-1; j++ {
			if conditions[j].Priority < conditions[j+1].Priority {
				conditions[j], conditions[j+1] = conditions[j+1], conditions[j]
			}
		}
	}

	// Evaluate conditions in priority order
	for _, condition := range conditions {
		if condition.Evaluator != nil {
			result := condition.Evaluator(state, execCtx)
			if result != "" {
				return result, nil
			}
		}
	}

	// Return default edge if no condition matched
	return branch.DefaultEdge, nil
}

// copyGraphState creates a deep copy of graph state
func copyGraphState(state GraphState) GraphState {
	if state == nil {
		return nil
	}

	copied := make(GraphState)
	for key, value := range state {
		// For simplicity, we'll do a shallow copy here
		// In a production system, you might want deep copying for complex types
		copied[key] = value
	}
	return copied
}

// addToHistory adds an execution result to the history
func (g *StateGraph) addToHistory(result GraphExecutionResult) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	g.executionHistory = append(g.executionHistory, result)

	// Maintain history size limit
	if len(g.executionHistory) > g.maxHistorySize {
		g.executionHistory = g.executionHistory[1:]
	}
}

// AddAdvancedConditionalEdge adds an advanced conditional edge to the graph
func (g *StateGraph) AddAdvancedConditionalEdge(from string, branch ConditionalBranch) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if _, exists := g.nodes[from]; !exists {
		return fmt.Errorf("source node %s does not exist", from)
	}

	// Validate that all target nodes exist
	for range branch.Conditions {
		// Note: We can't validate the condition result nodes here since they're dynamic
		// This would need to be done at runtime
	}

	if branch.DefaultEdge != "" {
		if _, exists := g.nodes[branch.DefaultEdge]; !exists {
			return fmt.Errorf("default edge target node %s does not exist", branch.DefaultEdge)
		}
	}

	g.advancedConditionalEdges[from] = branch
	return nil
}

// GetExecutionHistory returns the execution history
func (g *StateGraph) GetExecutionHistory() []GraphExecutionResult {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	// Return a copy to prevent external modification
	history := make([]GraphExecutionResult, len(g.executionHistory))
	copy(history, g.executionHistory)
	return history
}

// ValidateState validates the graph state
func (g *StateGraph) ValidateState(state GraphState) error {
	if g.stateValidator != nil {
		return g.stateValidator.Validate(state)
	}
	return nil
}

// updateNodeMetrics updates metrics for a specific node
func (g *StateGraph) updateNodeMetrics(nodeID string, duration time.Duration, success bool) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	nodeMetrics := g.metrics.NodeMetrics[nodeID]
	nodeMetrics.ExecutionCount++
	nodeMetrics.LastExecution = time.Now()

	if !success {
		nodeMetrics.ErrorCount++
	}

	// Update average latency
	if nodeMetrics.ExecutionCount == 1 {
		nodeMetrics.AverageLatency = duration
	} else {
		total := time.Duration(nodeMetrics.ExecutionCount-1) * nodeMetrics.AverageLatency
		nodeMetrics.AverageLatency = (total + duration) / time.Duration(nodeMetrics.ExecutionCount)
	}

	g.metrics.NodeMetrics[nodeID] = nodeMetrics
}
