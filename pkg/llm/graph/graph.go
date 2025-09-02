package graph

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var graphTracer = otel.Tracer("hackai/llm/graph/graph")

// DefaultStateGraph implements the StateGraph interface
type DefaultStateGraph struct {
	id          string
	name        string
	description string
	nodes       map[string]llm.Node
	edges       map[string][]llm.Edge
	metadata    map[string]interface{}
	logger      *logger.Logger
}

// NewDefaultStateGraph creates a new default state graph
func NewDefaultStateGraph(id, name, description string, logger *logger.Logger) *DefaultStateGraph {
	return &DefaultStateGraph{
		id:          id,
		name:        name,
		description: description,
		nodes:       make(map[string]llm.Node),
		edges:       make(map[string][]llm.Edge),
		metadata:    make(map[string]interface{}),
		logger:      logger,
	}
}

// ID returns the graph ID
func (g *DefaultStateGraph) ID() string { return g.id }

// Name returns the graph name
func (g *DefaultStateGraph) Name() string { return g.name }

// Description returns the graph description
func (g *DefaultStateGraph) Description() string { return g.description }

// GetNodes returns all nodes in the graph
func (g *DefaultStateGraph) GetNodes() map[string]llm.Node { return g.nodes }

// GetEdges returns all edges in the graph
func (g *DefaultStateGraph) GetEdges() map[string][]llm.Edge { return g.edges }

// Execute executes the graph with the given initial state
func (g *DefaultStateGraph) Execute(ctx context.Context, initialState llm.GraphState) (llm.GraphState, error) {
	ctx, span := graphTracer.Start(ctx, "graph.execute",
		trace.WithAttributes(
			attribute.String("graph.id", g.id),
			attribute.String("graph.name", g.name),
		),
	)
	defer span.End()

	// Create execution engine
	config := EngineConfig{
		MaxConcurrentExecutions: 10,
		DefaultTimeout:          5 * time.Minute,
		MaxRetries:              3,
		RetryDelay:              1 * time.Second,
		EnableParallelExecution: true,
		MaxParallelNodes:        5,
		EnableTracing:           true,
		EnableMetrics:           true,
	}

	engine := NewDefaultExecutionEngine(config, g.logger)

	// Execute the graph
	finalState, err := engine.Execute(ctx, g, initialState)
	if err != nil {
		span.RecordError(err)
		return finalState, err
	}

	span.SetAttributes(attribute.Bool("success", true))
	return finalState, nil
}

// AddNode adds a node to the graph
func (g *DefaultStateGraph) AddNode(node llm.Node) error {
	if node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	if err := node.Validate(); err != nil {
		return fmt.Errorf("node validation failed: %w", err)
	}

	g.nodes[node.ID()] = node
	g.logger.Debug("Node added to graph", "graph_id", g.id, "node_id", node.ID())
	return nil
}

// RemoveNode removes a node from the graph
func (g *DefaultStateGraph) RemoveNode(nodeID string) error {
	if _, exists := g.nodes[nodeID]; !exists {
		return fmt.Errorf("node %s not found", nodeID)
	}

	// Remove node
	delete(g.nodes, nodeID)

	// Remove edges involving this node
	g.removeEdgesForNode(nodeID)

	g.logger.Debug("Node removed from graph", "graph_id", g.id, "node_id", nodeID)
	return nil
}

// AddEdge adds an edge to the graph
func (g *DefaultStateGraph) AddEdge(edge llm.Edge) error {
	// Validate that both nodes exist
	if _, exists := g.nodes[edge.From]; !exists {
		return fmt.Errorf("source node %s not found", edge.From)
	}
	if _, exists := g.nodes[edge.To]; !exists {
		return fmt.Errorf("target node %s not found", edge.To)
	}

	// Add edge to the adjacency list
	g.edges[edge.From] = append(g.edges[edge.From], edge)

	g.logger.Debug("Edge added to graph",
		"graph_id", g.id,
		"from", edge.From,
		"to", edge.To,
	)
	return nil
}

// RemoveEdge removes an edge from the graph
func (g *DefaultStateGraph) RemoveEdge(from, to string) error {
	edges, exists := g.edges[from]
	if !exists {
		return fmt.Errorf("no edges from node %s", from)
	}

	// Find and remove the edge
	for i, edge := range edges {
		if edge.To == to {
			g.edges[from] = append(edges[:i], edges[i+1:]...)
			g.logger.Debug("Edge removed from graph",
				"graph_id", g.id,
				"from", from,
				"to", to,
			)
			return nil
		}
	}

	return fmt.Errorf("edge from %s to %s not found", from, to)
}

// Validate validates the graph structure
func (g *DefaultStateGraph) Validate() error {
	if g.id == "" {
		return fmt.Errorf("graph ID cannot be empty")
	}

	if len(g.nodes) == 0 {
		return fmt.Errorf("graph must have at least one node")
	}

	// Validate all nodes
	for nodeID, node := range g.nodes {
		if err := node.Validate(); err != nil {
			return fmt.Errorf("node %s validation failed: %w", nodeID, err)
		}
	}

	// Validate edges
	for from, edgeList := range g.edges {
		if _, exists := g.nodes[from]; !exists {
			return fmt.Errorf("edge source node %s not found", from)
		}

		for _, edge := range edgeList {
			if _, exists := g.nodes[edge.To]; !exists {
				return fmt.Errorf("edge target node %s not found", edge.To)
			}
		}
	}

	// Check for cycles (optional - some graphs may want cycles)
	if g.hasCycles() {
		g.logger.Warn("Graph contains cycles", "graph_id", g.id)
	}

	// Check for unreachable nodes
	unreachable := g.findUnreachableNodes()
	if len(unreachable) > 0 {
		g.logger.Warn("Graph has unreachable nodes",
			"graph_id", g.id,
			"unreachable_nodes", unreachable,
		)
	}

	return nil
}

// Helper methods

// removeEdgesForNode removes all edges involving a specific node
func (g *DefaultStateGraph) removeEdgesForNode(nodeID string) {
	// Remove outgoing edges
	delete(g.edges, nodeID)

	// Remove incoming edges
	for from, edgeList := range g.edges {
		var newEdges []llm.Edge
		for _, edge := range edgeList {
			if edge.To != nodeID {
				newEdges = append(newEdges, edge)
			}
		}
		g.edges[from] = newEdges
	}
}

// hasCycles checks if the graph has cycles using DFS
func (g *DefaultStateGraph) hasCycles() bool {
	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)

	for nodeID := range g.nodes {
		if !visited[nodeID] {
			if g.dfsHasCycle(nodeID, visited, recursionStack) {
				return true
			}
		}
	}

	return false
}

// dfsHasCycle performs DFS to detect cycles
func (g *DefaultStateGraph) dfsHasCycle(nodeID string, visited, recursionStack map[string]bool) bool {
	visited[nodeID] = true
	recursionStack[nodeID] = true

	for _, edge := range g.edges[nodeID] {
		if !visited[edge.To] {
			if g.dfsHasCycle(edge.To, visited, recursionStack) {
				return true
			}
		} else if recursionStack[edge.To] {
			return true
		}
	}

	recursionStack[nodeID] = false
	return false
}

// findUnreachableNodes finds nodes that cannot be reached from any start node
func (g *DefaultStateGraph) findUnreachableNodes() []string {
	// Find start nodes (nodes with no incoming edges)
	hasIncoming := make(map[string]bool)
	for _, edgeList := range g.edges {
		for _, edge := range edgeList {
			hasIncoming[edge.To] = true
		}
	}

	var startNodes []string
	for nodeID := range g.nodes {
		if !hasIncoming[nodeID] {
			startNodes = append(startNodes, nodeID)
		}
	}

	// If no start nodes, all nodes are potentially unreachable
	if len(startNodes) == 0 {
		var allNodes []string
		for nodeID := range g.nodes {
			allNodes = append(allNodes, nodeID)
		}
		return allNodes
	}

	// Find reachable nodes from start nodes
	reachable := make(map[string]bool)
	for _, startNode := range startNodes {
		g.dfsMarkReachable(startNode, reachable)
	}

	// Find unreachable nodes
	var unreachable []string
	for nodeID := range g.nodes {
		if !reachable[nodeID] {
			unreachable = append(unreachable, nodeID)
		}
	}

	return unreachable
}

// dfsMarkReachable marks all nodes reachable from a given node
func (g *DefaultStateGraph) dfsMarkReachable(nodeID string, reachable map[string]bool) {
	if reachable[nodeID] {
		return // Already visited
	}

	reachable[nodeID] = true

	for _, edge := range g.edges[nodeID] {
		g.dfsMarkReachable(edge.To, reachable)
	}
}

// GetMetadata returns graph metadata
func (g *DefaultStateGraph) GetMetadata() map[string]interface{} {
	return g.metadata
}

// SetMetadata sets graph metadata
func (g *DefaultStateGraph) SetMetadata(key string, value interface{}) {
	g.metadata[key] = value
}

// GetNodeCount returns the number of nodes
func (g *DefaultStateGraph) GetNodeCount() int {
	return len(g.nodes)
}

// GetEdgeCount returns the number of edges
func (g *DefaultStateGraph) GetEdgeCount() int {
	count := 0
	for _, edgeList := range g.edges {
		count += len(edgeList)
	}
	return count
}

// Clone creates a deep copy of the graph
func (g *DefaultStateGraph) Clone() *DefaultStateGraph {
	clone := &DefaultStateGraph{
		id:          g.id + "_clone",
		name:        g.name + " (Clone)",
		description: g.description,
		nodes:       make(map[string]llm.Node),
		edges:       make(map[string][]llm.Edge),
		metadata:    make(map[string]interface{}),
		logger:      g.logger,
	}

	// Copy nodes (shallow copy for now - deep copy would require node cloning)
	for id, node := range g.nodes {
		clone.nodes[id] = node
	}

	// Copy edges
	for from, edgeList := range g.edges {
		clone.edges[from] = make([]llm.Edge, len(edgeList))
		copy(clone.edges[from], edgeList)
	}

	// Copy metadata
	for key, value := range g.metadata {
		clone.metadata[key] = value
	}

	return clone
}

// ToJSON returns a JSON representation of the graph structure
func (g *DefaultStateGraph) ToJSON() map[string]interface{} {
	nodeList := make([]map[string]interface{}, 0, len(g.nodes))
	for id, node := range g.nodes {
		nodeList = append(nodeList, map[string]interface{}{
			"id":   id,
			"type": string(node.Type()),
		})
	}

	edgeList := make([]map[string]interface{}, 0)
	for from, edges := range g.edges {
		for _, edge := range edges {
			edgeList = append(edgeList, map[string]interface{}{
				"from":   from,
				"to":     edge.To,
				"weight": edge.Weight,
			})
		}
	}

	return map[string]interface{}{
		"id":          g.id,
		"name":        g.name,
		"description": g.description,
		"nodes":       nodeList,
		"edges":       edgeList,
		"metadata":    g.metadata,
	}
}
