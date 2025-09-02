package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/google/uuid"
)

var tracer = otel.Tracer("hackai/graph/engine")

// DefaultStateGraph implements the StateGraph interface
type DefaultStateGraph struct {
	id          string
	name        string
	description string
	nodes       map[string]llm.Node
	edges       map[string][]llm.Edge
	startNode   string
	endNodes    []string
	config      GraphConfig
	persistence StatePersistence
	mutex       sync.RWMutex
	createdAt   time.Time
	updatedAt   time.Time
}

// GraphConfig represents configuration for a state graph
type GraphConfig struct {
	MaxExecutionTime   time.Duration          `json:"max_execution_time"`
	MaxSteps           int                    `json:"max_steps"`
	EnablePersistence  bool                   `json:"enable_persistence"`
	EnableCheckpoints  bool                   `json:"enable_checkpoints"`
	CheckpointInterval int                    `json:"checkpoint_interval"`
	RetryPolicy        RetryPolicy            `json:"retry_policy"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// RetryPolicy defines retry behavior for failed nodes
type RetryPolicy struct {
	MaxRetries    int           `json:"max_retries"`
	BackoffFactor float64       `json:"backoff_factor"`
	InitialDelay  time.Duration `json:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
}

// StatePersistence handles graph state storage and recovery
type StatePersistence interface {
	SaveState(ctx context.Context, graphID string, state llm.GraphState) error
	LoadState(ctx context.Context, graphID string) (llm.GraphState, error)
	DeleteState(ctx context.Context, graphID string) error
	ListStates(ctx context.Context) ([]string, error)
}

// NewDefaultStateGraph creates a new state graph
func NewDefaultStateGraph(id, name, description string) *DefaultStateGraph {
	if id == "" {
		id = uuid.New().String()
	}

	return &DefaultStateGraph{
		id:          id,
		name:        name,
		description: description,
		nodes:       make(map[string]llm.Node),
		edges:       make(map[string][]llm.Edge),
		endNodes:    make([]string, 0),
		config: GraphConfig{
			MaxExecutionTime:   30 * time.Minute,
			MaxSteps:           1000,
			EnablePersistence:  true,
			EnableCheckpoints:  true,
			CheckpointInterval: 10,
			RetryPolicy: RetryPolicy{
				MaxRetries:    3,
				BackoffFactor: 2.0,
				InitialDelay:  time.Second,
				MaxDelay:      30 * time.Second,
			},
			Metadata: make(map[string]interface{}),
		},
		createdAt: time.Now(),
		updatedAt: time.Now(),
	}
}

// ID returns the graph ID
func (g *DefaultStateGraph) ID() string {
	return g.id
}

// Name returns the graph name
func (g *DefaultStateGraph) Name() string {
	return g.name
}

// Description returns the graph description
func (g *DefaultStateGraph) Description() string {
	return g.description
}

// GetNodes returns all nodes in the graph
func (g *DefaultStateGraph) GetNodes() map[string]llm.Node {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	// Return a copy to prevent external modification
	nodes := make(map[string]llm.Node)
	for id, node := range g.nodes {
		nodes[id] = node
	}
	return nodes
}

// GetEdges returns all edges in the graph
func (g *DefaultStateGraph) GetEdges() map[string][]llm.Edge {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	// Return a copy to prevent external modification
	edges := make(map[string][]llm.Edge)
	for from, edgeList := range g.edges {
		edges[from] = make([]llm.Edge, len(edgeList))
		copy(edges[from], edgeList)
	}
	return edges
}

// AddNode adds a node to the graph
func (g *DefaultStateGraph) AddNode(node llm.Node) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if err := node.Validate(); err != nil {
		return fmt.Errorf("node validation failed: %w", err)
	}

	g.nodes[node.ID()] = node
	g.updatedAt = time.Now()
	return nil
}

// AddEdge adds an edge to the graph
func (g *DefaultStateGraph) AddEdge(edge llm.Edge) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	// Validate that both nodes exist
	if _, exists := g.nodes[edge.From]; !exists {
		return fmt.Errorf("source node %s does not exist", edge.From)
	}
	if _, exists := g.nodes[edge.To]; !exists {
		return fmt.Errorf("target node %s does not exist", edge.To)
	}

	g.edges[edge.From] = append(g.edges[edge.From], edge)
	g.updatedAt = time.Now()
	return nil
}

// SetStartNode sets the starting node for the graph
func (g *DefaultStateGraph) SetStartNode(nodeID string) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if _, exists := g.nodes[nodeID]; !exists {
		return fmt.Errorf("start node %s does not exist", nodeID)
	}

	g.startNode = nodeID
	g.updatedAt = time.Now()
	return nil
}

// AddEndNode adds an end node to the graph
func (g *DefaultStateGraph) AddEndNode(nodeID string) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if _, exists := g.nodes[nodeID]; !exists {
		return fmt.Errorf("end node %s does not exist", nodeID)
	}

	// Check if already exists
	for _, endNode := range g.endNodes {
		if endNode == nodeID {
			return nil // Already exists
		}
	}

	g.endNodes = append(g.endNodes, nodeID)
	g.updatedAt = time.Now()
	return nil
}

// SetPersistence sets the state persistence handler
func (g *DefaultStateGraph) SetPersistence(persistence StatePersistence) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	g.persistence = persistence
	g.updatedAt = time.Now()
}

// SetConfig updates the graph configuration
func (g *DefaultStateGraph) SetConfig(config GraphConfig) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	g.config = config
	g.updatedAt = time.Now()
}

// Execute executes the state graph
func (g *DefaultStateGraph) Execute(ctx context.Context, initialState llm.GraphState) (llm.GraphState, error) {
	ctx, span := tracer.Start(ctx, "state_graph.execute",
		trace.WithAttributes(
			attribute.String("graph.id", g.ID()),
			attribute.String("graph.name", g.Name()),
		),
	)
	defer span.End()

	// Apply execution timeout
	if g.config.MaxExecutionTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.config.MaxExecutionTime)
		defer cancel()
	}

	// Initialize state
	state := initialState
	if state.CurrentNode == "" {
		state.CurrentNode = g.startNode
	}
	if state.StartTime.IsZero() {
		state.StartTime = time.Now()
	}
	if state.Data == nil {
		state.Data = make(map[string]interface{})
	}
	if state.Metadata == nil {
		state.Metadata = make(map[string]interface{})
	}
	if state.History == nil {
		state.History = make([]llm.StateTransition, 0)
	}

	stepCount := 0

	span.SetAttributes(
		attribute.String("start_node", state.CurrentNode),
		attribute.Int("max_steps", g.config.MaxSteps),
	)

	for {
		select {
		case <-ctx.Done():
			return state, ctx.Err()
		default:
			// Check step limit
			if stepCount >= g.config.MaxSteps {
				return state, fmt.Errorf("maximum steps (%d) exceeded", g.config.MaxSteps)
			}

			// Check if we've reached an end node
			if g.isEndNode(state.CurrentNode) {
				span.SetAttributes(
					attribute.Bool("completed", true),
					attribute.Int("total_steps", stepCount),
				)
				return state, nil
			}

			// Get current node
			node, exists := g.nodes[state.CurrentNode]
			if !exists {
				err := fmt.Errorf("node %s not found", state.CurrentNode)
				span.RecordError(err)
				return state, err
			}

			// Execute current node with retry logic
			newState, err := g.executeNodeWithRetry(ctx, node, state)
			if err != nil {
				span.RecordError(err)
				return state, fmt.Errorf("node %s execution failed: %w", state.CurrentNode, err)
			}

			// Determine next node
			nextNode, err := g.getNextNode(state.CurrentNode, newState)
			if err != nil {
				span.RecordError(err)
				return state, fmt.Errorf("failed to determine next node: %w", err)
			}

			// Record state transition
			transition := llm.StateTransition{
				From:      state.CurrentNode,
				To:        nextNode,
				Timestamp: time.Now(),
				Data:      newState.Data,
				Metadata:  make(map[string]interface{}),
			}

			// Update state
			state = newState
			state.CurrentNode = nextNode
			state.UpdateTime = time.Now()
			state.History = append(state.History, transition)

			stepCount++

			// Checkpoint if enabled
			if g.config.EnableCheckpoints && stepCount%g.config.CheckpointInterval == 0 {
				if err := g.saveCheckpoint(ctx, state); err != nil {
					span.AddEvent("checkpoint_failed", trace.WithAttributes(
						attribute.String("error", err.Error()),
					))
				}
			}

			span.AddEvent("step_completed", trace.WithAttributes(
				attribute.Int("step", stepCount),
				attribute.String("from_node", transition.From),
				attribute.String("to_node", transition.To),
			))
		}
	}
}

// executeNodeWithRetry executes a node with retry logic
func (g *DefaultStateGraph) executeNodeWithRetry(ctx context.Context, node llm.Node, state llm.GraphState) (llm.GraphState, error) {
	var lastErr error
	delay := g.config.RetryPolicy.InitialDelay

	for attempt := 0; attempt <= g.config.RetryPolicy.MaxRetries; attempt++ {
		if attempt > 0 {
			// Apply backoff delay
			select {
			case <-ctx.Done():
				return state, ctx.Err()
			case <-time.After(delay):
			}

			// Increase delay for next attempt
			delay = time.Duration(float64(delay) * g.config.RetryPolicy.BackoffFactor)
			if delay > g.config.RetryPolicy.MaxDelay {
				delay = g.config.RetryPolicy.MaxDelay
			}
		}

		newState, err := node.Execute(ctx, state)
		if err == nil {
			return newState, nil
		}

		lastErr = err
	}

	return state, fmt.Errorf("node execution failed after %d attempts: %w", g.config.RetryPolicy.MaxRetries+1, lastErr)
}

// getNextNode determines the next node based on current state and edges
func (g *DefaultStateGraph) getNextNode(currentNode string, state llm.GraphState) (string, error) {
	edges, exists := g.edges[currentNode]
	if !exists || len(edges) == 0 {
		// No outgoing edges, this should be an end node
		if g.isEndNode(currentNode) {
			return currentNode, nil
		}
		return "", fmt.Errorf("no outgoing edges from node %s", currentNode)
	}

	// Evaluate conditions to find the next node
	for _, edge := range edges {
		if edge.Condition == nil {
			// Unconditional edge
			return edge.To, nil
		}

		// Evaluate condition
		shouldTake, err := edge.Condition.Evaluate(context.Background(), state)
		if err != nil {
			continue // Skip this edge on condition evaluation error
		}

		if shouldTake {
			return edge.To, nil
		}
	}

	return "", fmt.Errorf("no valid edge found from node %s", currentNode)
}

// isEndNode checks if a node is an end node
func (g *DefaultStateGraph) isEndNode(nodeID string) bool {
	for _, endNode := range g.endNodes {
		if endNode == nodeID {
			return true
		}
	}
	return false
}

// saveCheckpoint saves the current state as a checkpoint
func (g *DefaultStateGraph) saveCheckpoint(ctx context.Context, state llm.GraphState) error {
	if !g.config.EnablePersistence || g.persistence == nil {
		return nil
	}

	checkpointID := fmt.Sprintf("%s_checkpoint_%d", g.ID(), time.Now().Unix())
	return g.persistence.SaveState(ctx, checkpointID, state)
}

// Validate validates the graph structure
func (g *DefaultStateGraph) Validate() error {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	if g.id == "" {
		return fmt.Errorf("graph ID is required")
	}

	if g.name == "" {
		return fmt.Errorf("graph name is required")
	}

	if len(g.nodes) == 0 {
		return fmt.Errorf("graph must have at least one node")
	}

	if g.startNode == "" {
		return fmt.Errorf("start node is required")
	}

	if _, exists := g.nodes[g.startNode]; !exists {
		return fmt.Errorf("start node %s does not exist", g.startNode)
	}

	if len(g.endNodes) == 0 {
		return fmt.Errorf("graph must have at least one end node")
	}

	// Validate all end nodes exist
	for _, endNode := range g.endNodes {
		if _, exists := g.nodes[endNode]; !exists {
			return fmt.Errorf("end node %s does not exist", endNode)
		}
	}

	// Validate all nodes
	for _, node := range g.nodes {
		if err := node.Validate(); err != nil {
			return fmt.Errorf("node %s validation failed: %w", node.ID(), err)
		}
	}

	// Validate edges reference existing nodes
	for from, edgeList := range g.edges {
		if _, exists := g.nodes[from]; !exists {
			return fmt.Errorf("edge source node %s does not exist", from)
		}

		for _, edge := range edgeList {
			if _, exists := g.nodes[edge.To]; !exists {
				return fmt.Errorf("edge target node %s does not exist", edge.To)
			}
		}
	}

	return nil
}
