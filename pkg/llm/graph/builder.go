package graph

import (
	"fmt"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// GraphBuilder provides a fluent interface for building graphs
type GraphBuilder struct {
	graph  *DefaultStateGraph
	logger *logger.Logger
}

// NewGraphBuilder creates a new graph builder
func NewGraphBuilder(id, name, description string, logger *logger.Logger) *GraphBuilder {
	return &GraphBuilder{
		graph:  NewDefaultStateGraph(id, name, description, logger),
		logger: logger,
	}
}

// AddLLMNode adds an LLM node to the graph
func (b *GraphBuilder) AddLLMNode(id, chainID string) *GraphBuilder {
	node := NewLLMNode(id, chainID, b.logger)
	b.graph.AddNode(node)
	return b
}

// AddLLMNodeWithMapping adds an LLM node with input/output mapping
func (b *GraphBuilder) AddLLMNodeWithMapping(id, chainID string, inputMapping, outputMapping map[string]string) *GraphBuilder {
	node := NewLLMNode(id, chainID, b.logger)
	node.SetInputMapping(inputMapping)
	node.SetOutputMapping(outputMapping)
	b.graph.AddNode(node)
	return b
}

// AddConditionNode adds a condition node to the graph
func (b *GraphBuilder) AddConditionNode(id string, condition llm.Condition) *GraphBuilder {
	node := NewConditionNode(id, condition, b.logger)
	b.graph.AddNode(node)
	return b
}

// AddTransformNode adds a transform node to the graph
func (b *GraphBuilder) AddTransformNode(id string, transformer DataTransformer) *GraphBuilder {
	node := NewTransformNode(id, transformer, b.logger)
	b.graph.AddNode(node)
	return b
}

// AddMemoryNode adds a memory node to the graph
func (b *GraphBuilder) AddMemoryNode(id string, memory llm.Memory, operation MemoryOperation) *GraphBuilder {
	node := NewMemoryNode(id, memory, operation, b.logger)
	b.graph.AddNode(node)
	return b
}

// AddMemoryNodeWithKey adds a memory node with a specific key
func (b *GraphBuilder) AddMemoryNodeWithKey(id string, memory llm.Memory, operation MemoryOperation, key string) *GraphBuilder {
	node := NewMemoryNode(id, memory, operation, b.logger)
	node.SetKey(key)
	b.graph.AddNode(node)
	return b
}

// AddActionNode adds an action node to the graph
func (b *GraphBuilder) AddActionNode(id string, action ActionFunc) *GraphBuilder {
	node := NewActionNode(id, action, b.logger)
	b.graph.AddNode(node)
	return b
}

// AddValidatorNode adds a validator node to the graph
func (b *GraphBuilder) AddValidatorNode(id string, validator DataValidator) *GraphBuilder {
	node := NewValidatorNode(id, validator, b.logger)
	b.graph.AddNode(node)
	return b
}

// AddValidatorNodeWithFailure adds a validator node with failure handling
func (b *GraphBuilder) AddValidatorNodeWithFailure(id string, validator DataValidator, onFailure ValidationFailureAction, failureNode string) *GraphBuilder {
	node := NewValidatorNode(id, validator, b.logger)
	node.SetOnFailure(onFailure)
	node.SetFailureNode(failureNode)
	b.graph.AddNode(node)
	return b
}

// AddEdge adds an edge between two nodes
func (b *GraphBuilder) AddEdge(from, to string) *GraphBuilder {
	edge := llm.Edge{
		From:   from,
		To:     to,
		Weight: 1.0,
	}
	b.graph.AddEdge(edge)
	return b
}

// AddConditionalEdge adds an edge with a condition
func (b *GraphBuilder) AddConditionalEdge(from, to string, condition llm.Condition) *GraphBuilder {
	edge := llm.Edge{
		From:      from,
		To:        to,
		Condition: condition,
		Weight:    1.0,
	}
	b.graph.AddEdge(edge)
	return b
}

// AddWeightedEdge adds an edge with a weight
func (b *GraphBuilder) AddWeightedEdge(from, to string, weight float64) *GraphBuilder {
	edge := llm.Edge{
		From:   from,
		To:     to,
		Weight: weight,
	}
	b.graph.AddEdge(edge)
	return b
}

// AddEdgeWithMetadata adds an edge with metadata
func (b *GraphBuilder) AddEdgeWithMetadata(from, to string, condition llm.Condition, weight float64, metadata interface{}) *GraphBuilder {
	edge := llm.Edge{
		From:      from,
		To:        to,
		Condition: condition,
		Weight:    weight,
		Metadata:  metadata,
	}
	b.graph.AddEdge(edge)
	return b
}

// SetMetadata sets metadata for the graph
func (b *GraphBuilder) SetMetadata(key string, value interface{}) *GraphBuilder {
	b.graph.SetMetadata(key, value)
	return b
}

// Build builds and validates the graph
func (b *GraphBuilder) Build() (*DefaultStateGraph, error) {
	if err := b.graph.Validate(); err != nil {
		return nil, fmt.Errorf("graph validation failed: %w", err)
	}
	return b.graph, nil
}

// BuildUnsafe builds the graph without validation
func (b *GraphBuilder) BuildUnsafe() *DefaultStateGraph {
	return b.graph
}

// FluentGraphBuilder provides a more fluent interface for common patterns
type FluentGraphBuilder struct {
	*GraphBuilder
	currentNode string
}

// NewFluentGraphBuilder creates a new fluent graph builder
func NewFluentGraphBuilder(id, name, description string, logger *logger.Logger) *FluentGraphBuilder {
	return &FluentGraphBuilder{
		GraphBuilder: NewGraphBuilder(id, name, description, logger),
	}
}

// Start sets the starting node
func (b *FluentGraphBuilder) Start(nodeID string) *FluentGraphBuilder {
	b.currentNode = nodeID
	return b
}

// ThenLLM adds an LLM node and connects it to the current node
func (b *FluentGraphBuilder) ThenLLM(nodeID, chainID string) *FluentGraphBuilder {
	b.AddLLMNode(nodeID, chainID)
	if b.currentNode != "" {
		b.AddEdge(b.currentNode, nodeID)
	}
	b.currentNode = nodeID
	return b
}

// ThenCondition adds a condition node and connects it to the current node
func (b *FluentGraphBuilder) ThenCondition(nodeID string, condition llm.Condition) *FluentGraphBuilder {
	b.AddConditionNode(nodeID, condition)
	if b.currentNode != "" {
		b.AddEdge(b.currentNode, nodeID)
	}
	b.currentNode = nodeID
	return b
}

// ThenTransform adds a transform node and connects it to the current node
func (b *FluentGraphBuilder) ThenTransform(nodeID string, transformer DataTransformer) *FluentGraphBuilder {
	b.AddTransformNode(nodeID, transformer)
	if b.currentNode != "" {
		b.AddEdge(b.currentNode, nodeID)
	}
	b.currentNode = nodeID
	return b
}

// ThenAction adds an action node and connects it to the current node
func (b *FluentGraphBuilder) ThenAction(nodeID string, action ActionFunc) *FluentGraphBuilder {
	b.AddActionNode(nodeID, action)
	if b.currentNode != "" {
		b.AddEdge(b.currentNode, nodeID)
	}
	b.currentNode = nodeID
	return b
}

// ThenValidator adds a validator node and connects it to the current node
func (b *FluentGraphBuilder) ThenValidator(nodeID string, validator DataValidator) *FluentGraphBuilder {
	b.AddValidatorNode(nodeID, validator)
	if b.currentNode != "" {
		b.AddEdge(b.currentNode, nodeID)
	}
	b.currentNode = nodeID
	return b
}

// Branch creates a conditional branch
func (b *FluentGraphBuilder) Branch(condition llm.Condition, trueNodeID, falseNodeID string) *FluentGraphBuilder {
	if b.currentNode != "" {
		b.AddConditionalEdge(b.currentNode, trueNodeID, condition)
		b.AddConditionalEdge(b.currentNode, falseNodeID, NewNotCondition(condition))
	}
	return b
}

// Parallel creates parallel execution paths
func (b *FluentGraphBuilder) Parallel(nodeIDs ...string) *FluentGraphBuilder {
	if b.currentNode != "" {
		for _, nodeID := range nodeIDs {
			b.AddEdge(b.currentNode, nodeID)
		}
	}
	return b
}

// Join joins multiple nodes to a single node
func (b *FluentGraphBuilder) Join(fromNodes []string, toNode string) *FluentGraphBuilder {
	for _, fromNode := range fromNodes {
		b.AddEdge(fromNode, toNode)
	}
	b.currentNode = toNode
	return b
}

// GraphTemplate provides pre-built graph templates
type GraphTemplate struct {
	logger *logger.Logger
}

// NewGraphTemplate creates a new graph template builder
func NewGraphTemplate(logger *logger.Logger) *GraphTemplate {
	return &GraphTemplate{logger: logger}
}

// SimpleSequential creates a simple sequential graph
func (t *GraphTemplate) SimpleSequential(id, name string, chainIDs []string) (*DefaultStateGraph, error) {
	builder := NewFluentGraphBuilder(id, name, "Simple sequential execution", t.logger)

	if len(chainIDs) == 0 {
		return nil, fmt.Errorf("at least one chain ID is required")
	}

	// Start with first chain
	builder.Start(fmt.Sprintf("node_%s", chainIDs[0]))
	builder.AddLLMNode(fmt.Sprintf("node_%s", chainIDs[0]), chainIDs[0])

	// Add remaining chains sequentially
	for i := 1; i < len(chainIDs); i++ {
		nodeID := fmt.Sprintf("node_%s", chainIDs[i])
		builder.ThenLLM(nodeID, chainIDs[i])
	}

	return builder.Build()
}

// ConditionalBranch creates a graph with conditional branching
func (t *GraphTemplate) ConditionalBranch(id, name string, conditionChainID, trueChainID, falseChainID string, condition llm.Condition) (*DefaultStateGraph, error) {
	builder := NewFluentGraphBuilder(id, name, "Conditional branch execution", t.logger)

	// Add condition evaluation node
	builder.Start("condition_node")
	builder.AddLLMNode("condition_node", conditionChainID)

	// Add branch nodes
	builder.AddLLMNode("true_node", trueChainID)
	builder.AddLLMNode("false_node", falseChainID)

	// Add conditional edges
	builder.Branch(condition, "true_node", "false_node")

	return builder.Build()
}

// ParallelExecution creates a graph with parallel execution
func (t *GraphTemplate) ParallelExecution(id, name string, parallelChainIDs []string, joinChainID string) (*DefaultStateGraph, error) {
	builder := NewFluentGraphBuilder(id, name, "Parallel execution", t.logger)

	if len(parallelChainIDs) == 0 {
		return nil, fmt.Errorf("at least one parallel chain ID is required")
	}

	// Add parallel nodes
	var parallelNodes []string
	for i, chainID := range parallelChainIDs {
		nodeID := fmt.Sprintf("parallel_%d", i)
		builder.AddLLMNode(nodeID, chainID)
		parallelNodes = append(parallelNodes, nodeID)
	}

	// Add join node if specified
	if joinChainID != "" {
		builder.AddLLMNode("join_node", joinChainID)
		builder.Join(parallelNodes, "join_node")
	}

	return builder.Build()
}

// ValidationPipeline creates a graph with validation steps
func (t *GraphTemplate) ValidationPipeline(id, name string, chainID string, validators []DataValidator) (*DefaultStateGraph, error) {
	builder := NewFluentGraphBuilder(id, name, "Validation pipeline", t.logger)

	// Add main processing node
	builder.Start("main_node")
	builder.AddLLMNode("main_node", chainID)

	// Add validation nodes
	for i, validator := range validators {
		validatorID := fmt.Sprintf("validator_%d", i)
		builder.ThenValidator(validatorID, validator)
	}

	return builder.Build()
}
