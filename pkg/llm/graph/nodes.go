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

var nodeTracer = otel.Tracer("hackai/llm/graph/nodes")

// BaseNode provides common functionality for all node types
type BaseNode struct {
	id         string
	nodeType   llm.NodeType
	conditions []llm.Condition
	nextNodes  []string
	metadata   map[string]interface{}
	logger     *logger.Logger
}

// NewBaseNode creates a new base node
func NewBaseNode(id string, nodeType llm.NodeType, logger *logger.Logger) *BaseNode {
	return &BaseNode{
		id:         id,
		nodeType:   nodeType,
		conditions: make([]llm.Condition, 0),
		nextNodes:  make([]string, 0),
		metadata:   make(map[string]interface{}),
		logger:     logger,
	}
}

// ID returns the node ID
func (n *BaseNode) ID() string { return n.id }

// Type returns the node type
func (n *BaseNode) Type() llm.NodeType { return n.nodeType }

// GetConditions returns the node conditions
func (n *BaseNode) GetConditions() []llm.Condition { return n.conditions }

// GetNextNodes returns the next node IDs
func (n *BaseNode) GetNextNodes() []string { return n.nextNodes }

// SetConditions sets the node conditions
func (n *BaseNode) SetConditions(conditions []llm.Condition) {
	n.conditions = conditions
}

// SetNextNodes sets the next node IDs
func (n *BaseNode) SetNextNodes(nextNodes []string) {
	n.nextNodes = nextNodes
}

// Validate validates the base node
func (n *BaseNode) Validate() error {
	if n.id == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	return nil
}

// LLMNode represents a node that executes an LLM chain
type LLMNode struct {
	*BaseNode
	chainID       string
	chainManager  interface{} // Will be injected
	inputMapping  map[string]string
	outputMapping map[string]string
}

// NewLLMNode creates a new LLM node
func NewLLMNode(id, chainID string, logger *logger.Logger) *LLMNode {
	return &LLMNode{
		BaseNode:      NewBaseNode(id, llm.NodeTypeLLM, logger),
		chainID:       chainID,
		inputMapping:  make(map[string]string),
		outputMapping: make(map[string]string),
	}
}

// Execute executes the LLM node
func (n *LLMNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := nodeTracer.Start(ctx, "llm_node.execute",
		trace.WithAttributes(
			attribute.String("node.id", n.id),
			attribute.String("chain.id", n.chainID),
		),
	)
	defer span.End()

	// Map input data
	input := make(llm.ChainInput)
	for stateKey, chainKey := range n.inputMapping {
		if value, exists := state.Data[stateKey]; exists {
			input[chainKey] = value
		}
	}

	// If no input mapping, use all state data
	if len(n.inputMapping) == 0 {
		for key, value := range state.Data {
			input[key] = value
		}
	}

	// Execute chain (this would be injected in real implementation)
	// For now, simulate chain execution
	output := llm.ChainOutput{
		"result":    fmt.Sprintf("LLM processed: %v", input),
		"success":   true,
		"timestamp": time.Now(),
	}

	// Map output data
	newState := state
	if len(n.outputMapping) > 0 {
		for chainKey, stateKey := range n.outputMapping {
			if value, exists := output[chainKey]; exists {
				newState.Data[stateKey] = value
			}
		}
	} else {
		// If no output mapping, merge all output into state
		for key, value := range output {
			newState.Data[key] = value
		}
	}

	span.SetAttributes(attribute.Bool("success", true))
	n.logger.Debug("LLM node executed", "node_id", n.id, "chain_id", n.chainID)

	return newState, nil
}

// SetInputMapping sets the input mapping for the node
func (n *LLMNode) SetInputMapping(mapping map[string]string) {
	n.inputMapping = mapping
}

// SetOutputMapping sets the output mapping for the node
func (n *LLMNode) SetOutputMapping(mapping map[string]string) {
	n.outputMapping = mapping
}

// ConditionNode represents a node that evaluates conditions
type ConditionNode struct {
	*BaseNode
	condition llm.Condition
	trueNode  string
	falseNode string
}

// NewConditionNode creates a new condition node
func NewConditionNode(id string, condition llm.Condition, logger *logger.Logger) *ConditionNode {
	return &ConditionNode{
		BaseNode:  NewBaseNode(id, llm.NodeTypeCondition, logger),
		condition: condition,
	}
}

// Execute executes the condition node
func (n *ConditionNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := nodeTracer.Start(ctx, "condition_node.execute",
		trace.WithAttributes(attribute.String("node.id", n.id)),
	)
	defer span.End()

	result, err := n.condition.Evaluate(ctx, state)
	if err != nil {
		span.RecordError(err)
		return state, fmt.Errorf("condition evaluation failed: %w", err)
	}

	// Store condition result in state
	newState := state
	newState.Data["_condition_result"] = result
	newState.Data["_last_condition"] = n.id

	span.SetAttributes(
		attribute.Bool("condition.result", result),
		attribute.Bool("success", true),
	)

	n.logger.Debug("Condition node executed", "node_id", n.id, "result", result)

	return newState, nil
}

// SetTrueNode sets the node to execute when condition is true
func (n *ConditionNode) SetTrueNode(nodeID string) {
	n.trueNode = nodeID
}

// SetFalseNode sets the node to execute when condition is false
func (n *ConditionNode) SetFalseNode(nodeID string) {
	n.falseNode = nodeID
}

// TransformNode represents a node that transforms data
type TransformNode struct {
	*BaseNode
	transformer DataTransformer
}

// DataTransformer defines a function that transforms data
type DataTransformer func(ctx context.Context, data map[string]interface{}) (map[string]interface{}, error)

// NewTransformNode creates a new transform node
func NewTransformNode(id string, transformer DataTransformer, logger *logger.Logger) *TransformNode {
	return &TransformNode{
		BaseNode:    NewBaseNode(id, llm.NodeTypeTransform, logger),
		transformer: transformer,
	}
}

// Execute executes the transform node
func (n *TransformNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := nodeTracer.Start(ctx, "transform_node.execute",
		trace.WithAttributes(attribute.String("node.id", n.id)),
	)
	defer span.End()

	transformedData, err := n.transformer(ctx, state.Data)
	if err != nil {
		span.RecordError(err)
		return state, fmt.Errorf("data transformation failed: %w", err)
	}

	newState := state
	newState.Data = transformedData

	span.SetAttributes(attribute.Bool("success", true))
	n.logger.Debug("Transform node executed", "node_id", n.id)

	return newState, nil
}

// MemoryNode represents a node that interacts with memory
type MemoryNode struct {
	*BaseNode
	memory    llm.Memory
	operation MemoryOperation
	key       string
	value     interface{}
}

// MemoryOperation defines the type of memory operation
type MemoryOperation string

const (
	MemoryOpGet    MemoryOperation = "get"
	MemoryOpSet    MemoryOperation = "set"
	MemoryOpDelete MemoryOperation = "delete"
	MemoryOpClear  MemoryOperation = "clear"
)

// NewMemoryNode creates a new memory node
func NewMemoryNode(id string, memory llm.Memory, operation MemoryOperation, logger *logger.Logger) *MemoryNode {
	return &MemoryNode{
		BaseNode:  NewBaseNode(id, llm.NodeTypeMemory, logger),
		memory:    memory,
		operation: operation,
	}
}

// Execute executes the memory node
func (n *MemoryNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := nodeTracer.Start(ctx, "memory_node.execute",
		trace.WithAttributes(
			attribute.String("node.id", n.id),
			attribute.String("operation", string(n.operation)),
		),
	)
	defer span.End()

	newState := state

	switch n.operation {
	case MemoryOpGet:
		value, err := n.memory.Retrieve(ctx, n.key)
		if err != nil {
			span.RecordError(err)
			return state, fmt.Errorf("memory get failed: %w", err)
		}
		newState.Data[n.key] = value

	case MemoryOpSet:
		valueToSet := n.value
		if valueToSet == nil {
			// Use value from state if not explicitly set
			if val, exists := state.Data[n.key]; exists {
				valueToSet = val
			}
		}
		err := n.memory.Store(ctx, n.key, valueToSet)
		if err != nil {
			span.RecordError(err)
			return state, fmt.Errorf("memory set failed: %w", err)
		}

	case MemoryOpDelete:
		err := n.memory.Delete(ctx, n.key)
		if err != nil {
			span.RecordError(err)
			return state, fmt.Errorf("memory delete failed: %w", err)
		}

	case MemoryOpClear:
		err := n.memory.Clear(ctx)
		if err != nil {
			span.RecordError(err)
			return state, fmt.Errorf("memory clear failed: %w", err)
		}

	default:
		return state, fmt.Errorf("unknown memory operation: %s", n.operation)
	}

	span.SetAttributes(attribute.Bool("success", true))
	n.logger.Debug("Memory node executed", "node_id", n.id, "operation", n.operation)

	return newState, nil
}

// SetKey sets the memory key
func (n *MemoryNode) SetKey(key string) {
	n.key = key
}

// SetValue sets the memory value
func (n *MemoryNode) SetValue(value interface{}) {
	n.value = value
}

// ActionNode represents a node that performs custom actions
type ActionNode struct {
	*BaseNode
	action ActionFunc
}

// ActionFunc defines a custom action function
type ActionFunc func(ctx context.Context, state llm.GraphState) (llm.GraphState, error)

// NewActionNode creates a new action node
func NewActionNode(id string, action ActionFunc, logger *logger.Logger) *ActionNode {
	return &ActionNode{
		BaseNode: NewBaseNode(id, llm.NodeTypeAction, logger),
		action:   action,
	}
}

// Execute executes the action node
func (n *ActionNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := nodeTracer.Start(ctx, "action_node.execute",
		trace.WithAttributes(attribute.String("node.id", n.id)),
	)
	defer span.End()

	newState, err := n.action(ctx, state)
	if err != nil {
		span.RecordError(err)
		return state, fmt.Errorf("action execution failed: %w", err)
	}

	span.SetAttributes(attribute.Bool("success", true))
	n.logger.Debug("Action node executed", "node_id", n.id)

	return newState, nil
}

// ValidatorNode represents a node that validates data
type ValidatorNode struct {
	*BaseNode
	validator   DataValidator
	onFailure   ValidationFailureAction
	failureNode string
}

// DataValidator defines a function that validates data
type DataValidator func(ctx context.Context, data map[string]interface{}) error

// ValidationFailureAction defines what to do when validation fails
type ValidationFailureAction string

const (
	ValidationFailStop     ValidationFailureAction = "stop"
	ValidationFailContinue ValidationFailureAction = "continue"
	ValidationFailRedirect ValidationFailureAction = "redirect"
)

// NewValidatorNode creates a new validator node
func NewValidatorNode(id string, validator DataValidator, logger *logger.Logger) *ValidatorNode {
	return &ValidatorNode{
		BaseNode:  NewBaseNode(id, llm.NodeTypeValidator, logger),
		validator: validator,
		onFailure: ValidationFailStop,
	}
}

// Execute executes the validator node
func (n *ValidatorNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := nodeTracer.Start(ctx, "validator_node.execute",
		trace.WithAttributes(attribute.String("node.id", n.id)),
	)
	defer span.End()

	err := n.validator(ctx, state.Data)

	newState := state
	newState.Data["_validation_result"] = err == nil
	newState.Data["_last_validator"] = n.id

	if err != nil {
		newState.Data["_validation_error"] = err.Error()

		switch n.onFailure {
		case ValidationFailStop:
			span.RecordError(err)
			return newState, fmt.Errorf("validation failed: %w", err)
		case ValidationFailContinue:
			// Continue execution despite validation failure
			span.SetAttributes(attribute.String("validation.action", "continue"))
		case ValidationFailRedirect:
			// Redirect to failure node (handled by execution engine)
			span.SetAttributes(attribute.String("validation.action", "redirect"))
		}
	}

	span.SetAttributes(
		attribute.Bool("validation.success", err == nil),
		attribute.Bool("success", true),
	)

	n.logger.Debug("Validator node executed", "node_id", n.id, "valid", err == nil)

	return newState, nil
}

// SetOnFailure sets the action to take when validation fails
func (n *ValidatorNode) SetOnFailure(action ValidationFailureAction) {
	n.onFailure = action
}

// SetFailureNode sets the node to redirect to on validation failure
func (n *ValidatorNode) SetFailureNode(nodeID string) {
	n.failureNode = nodeID
}
