package nodes

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/google/uuid"
)

var tracer = otel.Tracer("hackai/graph/nodes")

// BaseNode provides common functionality for all nodes
type BaseNode struct {
	id          string
	name        string
	description string
	nodeType    llm.NodeType
	conditions  []llm.Condition
	nextNodes   []string
	config      NodeConfig
	createdAt   time.Time
	updatedAt   time.Time
}

// NodeConfig represents configuration for a node
type NodeConfig struct {
	Timeout       time.Duration          `json:"timeout"`
	MaxRetries    int                    `json:"max_retries"`
	EnableTracing bool                   `json:"enable_tracing"`
	Parameters    map[string]interface{} `json:"parameters"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// NewBaseNode creates a new base node
func NewBaseNode(id, name, description string, nodeType llm.NodeType) *BaseNode {
	if id == "" {
		id = uuid.New().String()
	}

	return &BaseNode{
		id:          id,
		name:        name,
		description: description,
		nodeType:    nodeType,
		conditions:  make([]llm.Condition, 0),
		nextNodes:   make([]string, 0),
		config: NodeConfig{
			Timeout:       30 * time.Second,
			MaxRetries:    3,
			EnableTracing: true,
			Parameters:    make(map[string]interface{}),
			Metadata:      make(map[string]interface{}),
		},
		createdAt: time.Now(),
		updatedAt: time.Now(),
	}
}

// ID returns the node ID
func (n *BaseNode) ID() string {
	return n.id
}

// Name returns the node name
func (n *BaseNode) Name() string {
	return n.name
}

// Description returns the node description
func (n *BaseNode) Description() string {
	return n.description
}

// Type returns the node type
func (n *BaseNode) Type() llm.NodeType {
	return n.nodeType
}

// GetConditions returns the node conditions
func (n *BaseNode) GetConditions() []llm.Condition {
	return n.conditions
}

// GetNextNodes returns the next possible nodes
func (n *BaseNode) GetNextNodes() []string {
	return n.nextNodes
}

// AddCondition adds a condition to the node
func (n *BaseNode) AddCondition(condition llm.Condition) {
	n.conditions = append(n.conditions, condition)
	n.updatedAt = time.Now()
}

// AddNextNode adds a next node
func (n *BaseNode) AddNextNode(nodeID string) {
	n.nextNodes = append(n.nextNodes, nodeID)
	n.updatedAt = time.Now()
}

// SetConfig updates the node configuration
func (n *BaseNode) SetConfig(config NodeConfig) {
	n.config = config
	n.updatedAt = time.Now()
}

// GetConfig returns the node configuration
func (n *BaseNode) GetConfig() NodeConfig {
	return n.config
}

// Validate validates the node
func (n *BaseNode) Validate() error {
	if n.id == "" {
		return fmt.Errorf("node ID is required")
	}
	if n.name == "" {
		return fmt.Errorf("node name is required")
	}
	return nil
}

// Execute is a base implementation that should be overridden
func (n *BaseNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	return state, fmt.Errorf("execute method not implemented for node %s", n.id)
}

// StartNode represents a starting node in the graph
type StartNode struct {
	*BaseNode
}

// NewStartNode creates a new start node
func NewStartNode(id, name string) *StartNode {
	base := NewBaseNode(id, name, "Graph starting point", llm.NodeTypeAction)
	return &StartNode{BaseNode: base}
}

// Execute executes the start node
func (n *StartNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := tracer.Start(ctx, "start_node.execute",
		trace.WithAttributes(
			attribute.String("node.id", n.ID()),
			attribute.String("node.name", n.Name()),
		),
	)
	defer span.End()

	// Initialize state if needed
	if state.Data == nil {
		state.Data = make(map[string]interface{})
	}
	if state.Metadata == nil {
		state.Metadata = make(map[string]interface{})
	}

	// Mark start time
	state.Data["start_time"] = time.Now()
	state.Data["started"] = true

	span.SetAttributes(attribute.Bool("success", true))
	return state, nil
}

// EndNode represents an ending node in the graph
type EndNode struct {
	*BaseNode
	exitCode int
}

// NewEndNode creates a new end node
func NewEndNode(id, name string, exitCode int) *EndNode {
	base := NewBaseNode(id, name, "Graph ending point", llm.NodeTypeAction)
	return &EndNode{
		BaseNode: base,
		exitCode: exitCode,
	}
}

// Execute executes the end node
func (n *EndNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := tracer.Start(ctx, "end_node.execute",
		trace.WithAttributes(
			attribute.String("node.id", n.ID()),
			attribute.String("node.name", n.Name()),
			attribute.Int("exit_code", n.exitCode),
		),
	)
	defer span.End()

	// Mark completion
	state.Data["end_time"] = time.Now()
	state.Data["completed"] = true
	state.Data["exit_code"] = n.exitCode

	// Calculate duration if start time exists
	if startTime, exists := state.Data["start_time"]; exists {
		if startTimeTyped, ok := startTime.(time.Time); ok {
			duration := time.Since(startTimeTyped)
			state.Data["duration"] = duration
		}
	}

	span.SetAttributes(attribute.Bool("success", true))
	return state, nil
}

// TransformNode applies transformations to the state data
type TransformNode struct {
	*BaseNode
	transformer DataTransformer
}

// DataTransformer defines how to transform state data
type DataTransformer interface {
	Transform(ctx context.Context, data map[string]interface{}) (map[string]interface{}, error)
}

// NewTransformNode creates a new transform node
func NewTransformNode(id, name string, transformer DataTransformer) *TransformNode {
	base := NewBaseNode(id, name, "Data transformation node", llm.NodeTypeTransform)
	return &TransformNode{
		BaseNode:    base,
		transformer: transformer,
	}
}

// Execute executes the transform node
func (n *TransformNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := tracer.Start(ctx, "transform_node.execute",
		trace.WithAttributes(
			attribute.String("node.id", n.ID()),
			attribute.String("node.name", n.Name()),
		),
	)
	defer span.End()

	if n.transformer == nil {
		err := fmt.Errorf("no transformer configured for node %s", n.ID())
		span.RecordError(err)
		return state, err
	}

	// Apply transformation
	transformedData, err := n.transformer.Transform(ctx, state.Data)
	if err != nil {
		span.RecordError(err)
		return state, fmt.Errorf("transformation failed: %w", err)
	}

	// Update state with transformed data
	state.Data = transformedData
	state.UpdateTime = time.Now()

	span.SetAttributes(attribute.Bool("success", true))
	return state, nil
}

// ConditionNode evaluates conditions and sets results in state
type ConditionNode struct {
	*BaseNode
	condition llm.Condition
}

// NewConditionNode creates a new condition node
func NewConditionNode(id, name string, condition llm.Condition) *ConditionNode {
	base := NewBaseNode(id, name, "Condition evaluation node", llm.NodeTypeCondition)
	return &ConditionNode{
		BaseNode:  base,
		condition: condition,
	}
}

// Execute executes the condition node
func (n *ConditionNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := tracer.Start(ctx, "condition_node.execute",
		trace.WithAttributes(
			attribute.String("node.id", n.ID()),
			attribute.String("node.name", n.Name()),
		),
	)
	defer span.End()

	if n.condition == nil {
		err := fmt.Errorf("no condition configured for node %s", n.ID())
		span.RecordError(err)
		return state, err
	}

	// Evaluate condition
	result, err := n.condition.Evaluate(ctx, state)
	if err != nil {
		span.RecordError(err)
		return state, fmt.Errorf("condition evaluation failed: %w", err)
	}

	// Store result in state
	state.Data["condition_result"] = result
	state.Data["condition_description"] = n.condition.String()
	state.UpdateTime = time.Now()

	span.SetAttributes(
		attribute.Bool("condition_result", result),
		attribute.String("condition_description", n.condition.String()),
		attribute.Bool("success", true),
	)

	return state, nil
}

// DelayNode introduces a delay in the graph execution
type DelayNode struct {
	*BaseNode
	delay time.Duration
}

// NewDelayNode creates a new delay node
func NewDelayNode(id, name string, delay time.Duration) *DelayNode {
	base := NewBaseNode(id, name, fmt.Sprintf("Delay node (%s)", delay), llm.NodeTypeAction)
	return &DelayNode{
		BaseNode: base,
		delay:    delay,
	}
}

// Execute executes the delay node
func (n *DelayNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := tracer.Start(ctx, "delay_node.execute",
		trace.WithAttributes(
			attribute.String("node.id", n.ID()),
			attribute.String("node.name", n.Name()),
			attribute.String("delay", n.delay.String()),
		),
	)
	defer span.End()

	// Apply delay
	select {
	case <-ctx.Done():
		return state, ctx.Err()
	case <-time.After(n.delay):
		// Delay completed
	}

	// Update state
	state.Data["delay_applied"] = n.delay.String()
	state.UpdateTime = time.Now()

	span.SetAttributes(attribute.Bool("success", true))
	return state, nil
}

// LogNode logs information about the current state
type LogNode struct {
	*BaseNode
	message string
	level   string
}

// NewLogNode creates a new log node
func NewLogNode(id, name, message, level string) *LogNode {
	base := NewBaseNode(id, name, "Logging node", llm.NodeTypeAction)
	return &LogNode{
		BaseNode: base,
		message:  message,
		level:    level,
	}
}

// Execute executes the log node
func (n *LogNode) Execute(ctx context.Context, state llm.GraphState) (llm.GraphState, error) {
	ctx, span := tracer.Start(ctx, "log_node.execute",
		trace.WithAttributes(
			attribute.String("node.id", n.ID()),
			attribute.String("node.name", n.Name()),
			attribute.String("log_level", n.level),
		),
	)
	defer span.End()

	// Create log entry
	logEntry := map[string]interface{}{
		"timestamp":  time.Now(),
		"level":      n.level,
		"message":    n.message,
		"node_id":    n.ID(),
		"node_name":  n.Name(),
		"state_data": state.Data,
	}

	// Add to state logs
	if state.Data["logs"] == nil {
		state.Data["logs"] = make([]map[string]interface{}, 0)
	}

	logs := state.Data["logs"].([]map[string]interface{})
	logs = append(logs, logEntry)
	state.Data["logs"] = logs

	state.UpdateTime = time.Now()

	span.AddEvent("log_entry_created", trace.WithAttributes(
		attribute.String("message", n.message),
		attribute.String("level", n.level),
	))

	span.SetAttributes(attribute.Bool("success", true))
	return state, nil
}

// SimpleDataTransformer implements basic data transformations
type SimpleDataTransformer struct {
	transformations map[string]interface{}
}

// NewSimpleDataTransformer creates a new simple data transformer
func NewSimpleDataTransformer(transformations map[string]interface{}) *SimpleDataTransformer {
	return &SimpleDataTransformer{
		transformations: transformations,
	}
}

// Transform applies simple transformations to the data
func (t *SimpleDataTransformer) Transform(ctx context.Context, data map[string]interface{}) (map[string]interface{}, error) {
	if data == nil {
		data = make(map[string]interface{})
	}

	// Apply transformations
	for key, value := range t.transformations {
		data[key] = value
	}

	return data, nil
}
