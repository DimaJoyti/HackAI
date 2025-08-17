package workflows

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

var workflowTracer = otel.Tracer("hackai/workflows/graph")

// WorkflowGraph represents a graph-based workflow
type WorkflowGraph struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Version     string                  `json:"version"`
	Nodes       map[string]WorkflowNode `json:"nodes"`
	Edges       []WorkflowEdge          `json:"edges"`
	StartNodes  []string                `json:"start_nodes"`
	EndNodes    []string                `json:"end_nodes"`
	Config      WorkflowConfig          `json:"config"`
	Metadata    map[string]interface{}  `json:"metadata"`
	CreatedAt   time.Time               `json:"created_at"`
	UpdatedAt   time.Time               `json:"updated_at"`
}

// WorkflowNode represents a node in the workflow graph
type WorkflowNode interface {
	GetID() string
	GetType() NodeType
	GetName() string
	GetDescription() string
	Execute(ctx context.Context, input WorkflowData) (WorkflowData, error)
	Validate() error
	GetConfig() NodeConfig
	GetMetadata() map[string]interface{}
}

// WorkflowEdge represents an edge between workflow nodes
type WorkflowEdge struct {
	ID        string                 `json:"id"`
	FromNode  string                 `json:"from_node"`
	ToNode    string                 `json:"to_node"`
	Condition EdgeCondition          `json:"condition"`
	Weight    float64                `json:"weight"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// NodeType represents different types of workflow nodes
type NodeType string

const (
	NodeTypeAIProcessing NodeType = "ai_processing"
	NodeTypeSecurity     NodeType = "security"
	NodeTypeDecision     NodeType = "decision"
	NodeTypeParallel     NodeType = "parallel"
	NodeTypeAggregator   NodeType = "aggregator"
	NodeTypeTransform    NodeType = "transform"
	NodeTypeValidation   NodeType = "validation"
	NodeTypeInput        NodeType = "input"
	NodeTypeOutput       NodeType = "output"
	NodeTypeCustom       NodeType = "custom"
)

// EdgeCondition represents conditions for edge traversal
type EdgeCondition struct {
	Type       ConditionType          `json:"type"`
	Expression string                 `json:"expression"`
	Parameters map[string]interface{} `json:"parameters"`
}

// ConditionType represents different types of edge conditions
type ConditionType string

const (
	ConditionTypeAlways     ConditionType = "always"
	ConditionTypeNever      ConditionType = "never"
	ConditionTypeExpression ConditionType = "expression"
	ConditionTypeSuccess    ConditionType = "success"
	ConditionTypeError      ConditionType = "error"
	ConditionTypeCustom     ConditionType = "custom"
)

// WorkflowData represents data flowing through the workflow
type WorkflowData struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Content   interface{}            `json:"content"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// WorkflowConfig represents workflow configuration
type WorkflowConfig struct {
	MaxConcurrency     int           `json:"max_concurrency"`
	Timeout            time.Duration `json:"timeout"`
	RetryPolicy        RetryPolicy   `json:"retry_policy"`
	ErrorHandling      ErrorHandling `json:"error_handling"`
	EnableOptimization bool          `json:"enable_optimization"`
	EnableMonitoring   bool          `json:"enable_monitoring"`
}

// NodeConfig represents node configuration
type NodeConfig struct {
	Timeout     time.Duration          `json:"timeout"`
	RetryPolicy RetryPolicy            `json:"retry_policy"`
	Resources   ResourceRequirements   `json:"resources"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// RetryPolicy represents retry configuration
type RetryPolicy struct {
	MaxRetries    int           `json:"max_retries"`
	InitialDelay  time.Duration `json:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
}

// ErrorHandling represents error handling configuration
type ErrorHandling struct {
	Strategy     ErrorStrategy `json:"strategy"`
	FallbackNode string        `json:"fallback_node"`
	IgnoreErrors bool          `json:"ignore_errors"`
}

// ErrorStrategy represents different error handling strategies
type ErrorStrategy string

const (
	ErrorStrategyFail     ErrorStrategy = "fail"
	ErrorStrategyRetry    ErrorStrategy = "retry"
	ErrorStrategyFallback ErrorStrategy = "fallback"
	ErrorStrategyIgnore   ErrorStrategy = "ignore"
)

// ResourceRequirements represents resource requirements for nodes
type ResourceRequirements struct {
	CPU    float64 `json:"cpu"`
	Memory int64   `json:"memory"`
	GPU    int     `json:"gpu"`
}

// WorkflowExecutor executes workflow graphs
type WorkflowExecutor struct {
	scheduler *WorkflowScheduler
	optimizer *WorkflowOptimizer
	monitor   *WorkflowMonitor
	logger    *logger.Logger
	config    ExecutorConfig
	mu        sync.RWMutex
}

// ExecutorConfig represents executor configuration
type ExecutorConfig struct {
	MaxConcurrentWorkflows int            `json:"max_concurrent_workflows"`
	DefaultTimeout         time.Duration  `json:"default_timeout"`
	EnableOptimization     bool           `json:"enable_optimization"`
	EnableMonitoring       bool           `json:"enable_monitoring"`
	ResourceLimits         ResourceLimits `json:"resource_limits"`
}

// ResourceLimits represents system resource limits
type ResourceLimits struct {
	MaxCPU    float64 `json:"max_cpu"`
	MaxMemory int64   `json:"max_memory"`
	MaxGPU    int     `json:"max_gpu"`
}

// WorkflowScheduler manages workflow execution scheduling
type WorkflowScheduler struct {
	activeWorkflows map[string]*WorkflowExecution
	resourcePool    *ResourcePool
	logger          *logger.Logger
	mu              sync.RWMutex
}

// WorkflowOptimizer optimizes workflow execution
type WorkflowOptimizer struct {
	optimizationRules []OptimizationRule
	performanceCache  map[string]PerformanceMetrics
	logger            *logger.Logger
	mu                sync.RWMutex
}

// WorkflowMonitor monitors workflow execution
type WorkflowMonitor struct {
	metrics       map[string]ExecutionMetrics
	eventHandlers []EventHandler
	logger        *logger.Logger
	mu            sync.RWMutex
}

// WorkflowExecution represents an executing workflow
type WorkflowExecution struct {
	ID             string                  `json:"id"`
	WorkflowID     string                  `json:"workflow_id"`
	Status         ExecutionStatus         `json:"status"`
	StartTime      time.Time               `json:"start_time"`
	EndTime        *time.Time              `json:"end_time,omitempty"`
	CurrentNodes   []string                `json:"current_nodes"`
	CompletedNodes []string                `json:"completed_nodes"`
	FailedNodes    []string                `json:"failed_nodes"`
	Data           map[string]WorkflowData `json:"data"`
	Metrics        ExecutionMetrics        `json:"metrics"`
	Error          *WorkflowError          `json:"error,omitempty"`
	Context        context.Context         `json:"-"`
	CancelFunc     context.CancelFunc      `json:"-"`
}

// ExecutionStatus represents workflow execution status
type ExecutionStatus string

const (
	StatusPending   ExecutionStatus = "pending"
	StatusRunning   ExecutionStatus = "running"
	StatusCompleted ExecutionStatus = "completed"
	StatusFailed    ExecutionStatus = "failed"
	StatusCancelled ExecutionStatus = "cancelled"
	StatusPaused    ExecutionStatus = "paused"
)

// ExecutionMetrics represents execution metrics
type ExecutionMetrics struct {
	Duration        time.Duration          `json:"duration"`
	NodesExecuted   int                    `json:"nodes_executed"`
	NodesSucceeded  int                    `json:"nodes_succeeded"`
	NodesFailed     int                    `json:"nodes_failed"`
	DataProcessed   int64                  `json:"data_processed"`
	ResourceUsage   ResourceUsage          `json:"resource_usage"`
	PerformanceData map[string]interface{} `json:"performance_data"`
}

// ResourceUsage represents resource usage metrics
type ResourceUsage struct {
	CPUTime    time.Duration `json:"cpu_time"`
	MemoryPeak int64         `json:"memory_peak"`
	GPUTime    time.Duration `json:"gpu_time"`
}

// WorkflowError represents workflow execution errors
type WorkflowError struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	NodeID    string                 `json:"node_id"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details"`
	Cause     error                  `json:"-"`
}

// ResourcePool manages execution resources
type ResourcePool struct {
	availableCPU    float64
	availableMemory int64
	availableGPU    int
	allocations     map[string]ResourceAllocation
	mu              sync.RWMutex
}

// ResourceAllocation represents allocated resources
type ResourceAllocation struct {
	ExecutionID string    `json:"execution_id"`
	CPU         float64   `json:"cpu"`
	Memory      int64     `json:"memory"`
	GPU         int       `json:"gpu"`
	AllocatedAt time.Time `json:"allocated_at"`
}

// OptimizationRule represents workflow optimization rules
type OptimizationRule struct {
	ID          string                              `json:"id"`
	Name        string                              `json:"name"`
	Description string                              `json:"description"`
	Condition   func(*WorkflowGraph) bool           `json:"-"`
	Optimizer   func(*WorkflowGraph) *WorkflowGraph `json:"-"`
	Priority    int                                 `json:"priority"`
}

// PerformanceMetrics represents performance metrics
type PerformanceMetrics struct {
	AverageExecutionTime time.Duration          `json:"average_execution_time"`
	SuccessRate          float64                `json:"success_rate"`
	ResourceEfficiency   float64                `json:"resource_efficiency"`
	Bottlenecks          []string               `json:"bottlenecks"`
	Recommendations      []string               `json:"recommendations"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// EventHandler represents workflow event handlers
type EventHandler interface {
	HandleEvent(event WorkflowEvent) error
	GetEventTypes() []EventType
}

// WorkflowEvent represents workflow events
type WorkflowEvent struct {
	Type        EventType              `json:"type"`
	WorkflowID  string                 `json:"workflow_id"`
	ExecutionID string                 `json:"execution_id"`
	NodeID      string                 `json:"node_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Data        map[string]interface{} `json:"data"`
}

// EventType represents different types of workflow events
type EventType string

const (
	EventTypeWorkflowStarted   EventType = "workflow_started"
	EventTypeWorkflowCompleted EventType = "workflow_completed"
	EventTypeWorkflowFailed    EventType = "workflow_failed"
	EventTypeNodeStarted       EventType = "node_started"
	EventTypeNodeCompleted     EventType = "node_completed"
	EventTypeNodeFailed        EventType = "node_failed"
	EventTypeDataProcessed     EventType = "data_processed"
	EventTypeResourceAllocated EventType = "resource_allocated"
)

// NewWorkflowExecutor creates a new workflow executor
func NewWorkflowExecutor(config ExecutorConfig, logger *logger.Logger) *WorkflowExecutor {
	return &WorkflowExecutor{
		scheduler: NewWorkflowScheduler(logger),
		optimizer: NewWorkflowOptimizer(logger),
		monitor:   NewWorkflowMonitor(logger),
		logger:    logger,
		config:    config,
	}
}

// NewWorkflowScheduler creates a new workflow scheduler
func NewWorkflowScheduler(logger *logger.Logger) *WorkflowScheduler {
	return &WorkflowScheduler{
		activeWorkflows: make(map[string]*WorkflowExecution),
		resourcePool:    NewResourcePool(),
		logger:          logger,
	}
}

// NewWorkflowOptimizer creates a new workflow optimizer
func NewWorkflowOptimizer(logger *logger.Logger) *WorkflowOptimizer {
	return &WorkflowOptimizer{
		optimizationRules: initializeOptimizationRules(),
		performanceCache:  make(map[string]PerformanceMetrics),
		logger:            logger,
	}
}

// NewWorkflowMonitor creates a new workflow monitor
func NewWorkflowMonitor(logger *logger.Logger) *WorkflowMonitor {
	return &WorkflowMonitor{
		metrics:       make(map[string]ExecutionMetrics),
		eventHandlers: []EventHandler{},
		logger:        logger,
	}
}

// NewResourcePool creates a new resource pool
func NewResourcePool() *ResourcePool {
	return &ResourcePool{
		availableCPU:    100.0,                    // 100 CPU cores
		availableMemory: 1024 * 1024 * 1024 * 100, // 100 GB
		availableGPU:    8,                        // 8 GPUs
		allocations:     make(map[string]ResourceAllocation),
	}
}

// Core workflow execution methods

// ExecuteWorkflow executes a workflow graph
func (we *WorkflowExecutor) ExecuteWorkflow(ctx context.Context, workflow *WorkflowGraph, input WorkflowData) (*WorkflowExecution, error) {
	ctx, span := workflowTracer.Start(ctx, "workflow.execute",
		trace.WithAttributes(
			attribute.String("workflow.id", workflow.ID),
			attribute.String("workflow.name", workflow.Name),
		),
	)
	defer span.End()

	we.mu.Lock()
	defer we.mu.Unlock()

	// Create execution context
	execution := &WorkflowExecution{
		ID:             fmt.Sprintf("exec_%d", time.Now().UnixNano()),
		WorkflowID:     workflow.ID,
		Status:         StatusPending,
		StartTime:      time.Now(),
		CurrentNodes:   workflow.StartNodes,
		CompletedNodes: []string{},
		FailedNodes:    []string{},
		Data:           map[string]WorkflowData{"input": input},
		Metrics:        ExecutionMetrics{},
	}

	// Set up cancellation context
	execution.Context, execution.CancelFunc = context.WithTimeout(ctx, workflow.Config.Timeout)

	// Optimize workflow if enabled
	if we.config.EnableOptimization {
		optimizedWorkflow := we.optimizer.OptimizeWorkflow(workflow)
		workflow = optimizedWorkflow
	}

	// Schedule execution
	err := we.scheduler.ScheduleExecution(execution, workflow)
	if err != nil {
		return nil, fmt.Errorf("failed to schedule workflow execution: %w", err)
	}

	// Start monitoring if enabled
	if we.config.EnableMonitoring {
		we.monitor.StartMonitoring(execution)
	}

	// Execute workflow
	go we.executeWorkflowAsync(execution, workflow)

	span.SetAttributes(
		attribute.String("execution.id", execution.ID),
		attribute.String("execution.status", string(execution.Status)),
	)

	we.logger.Info("Workflow execution started",
		"workflow_id", workflow.ID,
		"execution_id", execution.ID,
		"start_nodes", workflow.StartNodes,
	)

	return execution, nil
}

// executeWorkflowAsync executes workflow asynchronously
func (we *WorkflowExecutor) executeWorkflowAsync(execution *WorkflowExecution, workflow *WorkflowGraph) {
	defer execution.CancelFunc()

	execution.Status = StatusRunning
	we.monitor.EmitEvent(WorkflowEvent{
		Type:        EventTypeWorkflowStarted,
		WorkflowID:  workflow.ID,
		ExecutionID: execution.ID,
		Timestamp:   time.Now(),
	})

	// Execute nodes
	err := we.executeNodes(execution, workflow)

	// Update execution status
	execution.EndTime = &[]time.Time{time.Now()}[0]
	execution.Metrics.Duration = execution.EndTime.Sub(execution.StartTime)

	if err != nil {
		execution.Status = StatusFailed
		execution.Error = &WorkflowError{
			Code:      "EXECUTION_FAILED",
			Message:   err.Error(),
			Timestamp: time.Now(),
			Cause:     err,
		}
		we.monitor.EmitEvent(WorkflowEvent{
			Type:        EventTypeWorkflowFailed,
			WorkflowID:  workflow.ID,
			ExecutionID: execution.ID,
			Timestamp:   time.Now(),
			Data:        map[string]interface{}{"error": err.Error()},
		})
	} else {
		execution.Status = StatusCompleted
		we.monitor.EmitEvent(WorkflowEvent{
			Type:        EventTypeWorkflowCompleted,
			WorkflowID:  workflow.ID,
			ExecutionID: execution.ID,
			Timestamp:   time.Now(),
		})
	}

	// Clean up resources
	we.scheduler.CleanupExecution(execution.ID)

	we.logger.Info("Workflow execution completed",
		"workflow_id", workflow.ID,
		"execution_id", execution.ID,
		"status", string(execution.Status),
		"duration", execution.Metrics.Duration,
	)
}

// executeNodes executes workflow nodes
func (we *WorkflowExecutor) executeNodes(execution *WorkflowExecution, workflow *WorkflowGraph) error {
	currentNodes := execution.CurrentNodes

	for len(currentNodes) > 0 {
		// Check for cancellation
		select {
		case <-execution.Context.Done():
			return execution.Context.Err()
		default:
		}

		// Execute current nodes
		nextNodes, err := we.executeCurrentNodes(execution, workflow, currentNodes)
		if err != nil {
			return err
		}

		// Update current nodes
		execution.CompletedNodes = append(execution.CompletedNodes, currentNodes...)
		currentNodes = nextNodes
		execution.CurrentNodes = currentNodes

		// Check if we've reached end nodes
		if we.hasReachedEndNodes(currentNodes, workflow.EndNodes) {
			break
		}
	}

	return nil
}

// executeCurrentNodes executes the current set of nodes
func (we *WorkflowExecutor) executeCurrentNodes(execution *WorkflowExecution, workflow *WorkflowGraph, nodeIDs []string) ([]string, error) {
	var nextNodes []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	var executionError error

	// Execute nodes in parallel if possible
	for _, nodeID := range nodeIDs {
		node, exists := workflow.Nodes[nodeID]
		if !exists {
			return nil, fmt.Errorf("node %s not found in workflow", nodeID)
		}

		wg.Add(1)
		go func(nodeID string, node WorkflowNode) {
			defer wg.Done()

			// Execute node
			err := we.executeNode(execution, workflow, nodeID, node)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				execution.FailedNodes = append(execution.FailedNodes, nodeID)
				if executionError == nil {
					executionError = err
				}
				return
			}

			// Find next nodes
			next := we.findNextNodes(workflow, nodeID, execution)
			nextNodes = append(nextNodes, next...)
		}(nodeID, node)
	}

	wg.Wait()

	if executionError != nil {
		return nil, executionError
	}

	// Remove duplicates from next nodes
	nextNodes = we.removeDuplicates(nextNodes)

	return nextNodes, nil
}

// executeNode executes a single workflow node
func (we *WorkflowExecutor) executeNode(execution *WorkflowExecution, workflow *WorkflowGraph, nodeID string, node WorkflowNode) error {
	we.monitor.EmitEvent(WorkflowEvent{
		Type:        EventTypeNodeStarted,
		WorkflowID:  workflow.ID,
		ExecutionID: execution.ID,
		NodeID:      nodeID,
		Timestamp:   time.Now(),
	})

	startTime := time.Now()

	// Get input data for node
	inputData := we.getNodeInputData(execution, nodeID)

	// Execute node with retry policy
	var outputData WorkflowData
	var err error

	retryPolicy := node.GetConfig().RetryPolicy
	for attempt := 0; attempt <= retryPolicy.MaxRetries; attempt++ {
		outputData, err = node.Execute(execution.Context, inputData)
		if err == nil {
			break
		}

		if attempt < retryPolicy.MaxRetries {
			delay := we.calculateRetryDelay(retryPolicy, attempt)
			time.Sleep(delay)
		}
	}

	duration := time.Since(startTime)

	if err != nil {
		we.monitor.EmitEvent(WorkflowEvent{
			Type:        EventTypeNodeFailed,
			WorkflowID:  workflow.ID,
			ExecutionID: execution.ID,
			NodeID:      nodeID,
			Timestamp:   time.Now(),
			Data:        map[string]interface{}{"error": err.Error(), "duration": duration},
		})
		return fmt.Errorf("node %s execution failed: %w", nodeID, err)
	}

	// Store output data
	execution.Data[nodeID] = outputData
	execution.Metrics.NodesExecuted++
	execution.Metrics.NodesSucceeded++

	we.monitor.EmitEvent(WorkflowEvent{
		Type:        EventTypeNodeCompleted,
		WorkflowID:  workflow.ID,
		ExecutionID: execution.ID,
		NodeID:      nodeID,
		Timestamp:   time.Now(),
		Data:        map[string]interface{}{"duration": duration},
	})

	we.logger.Debug("Node executed successfully",
		"workflow_id", workflow.ID,
		"execution_id", execution.ID,
		"node_id", nodeID,
		"duration", duration,
	)

	return nil
}

// Helper methods

// findNextNodes finds the next nodes to execute
func (we *WorkflowExecutor) findNextNodes(workflow *WorkflowGraph, currentNodeID string, execution *WorkflowExecution) []string {
	var nextNodes []string

	for _, edge := range workflow.Edges {
		if edge.FromNode == currentNodeID {
			// Check edge condition
			if we.evaluateEdgeCondition(edge.Condition, execution) {
				nextNodes = append(nextNodes, edge.ToNode)
			}
		}
	}

	return nextNodes
}

// evaluateEdgeCondition evaluates an edge condition
func (we *WorkflowExecutor) evaluateEdgeCondition(condition EdgeCondition, execution *WorkflowExecution) bool {
	switch condition.Type {
	case ConditionTypeAlways:
		return true
	case ConditionTypeNever:
		return false
	case ConditionTypeSuccess:
		return execution.Error == nil
	case ConditionTypeError:
		return execution.Error != nil
	case ConditionTypeExpression:
		// Simple expression evaluation (can be extended)
		return we.evaluateExpression(condition.Expression, execution)
	default:
		return true
	}
}

// evaluateExpression evaluates a simple expression
func (we *WorkflowExecutor) evaluateExpression(expression string, execution *WorkflowExecution) bool {
	// Simple expression evaluation - can be extended with a proper expression parser
	// For now, just return true for any expression
	return true
}

// getNodeInputData gets input data for a node
func (we *WorkflowExecutor) getNodeInputData(execution *WorkflowExecution, nodeID string) WorkflowData {
	// For now, return the input data
	// In a more sophisticated implementation, this would aggregate data from predecessor nodes
	if inputData, exists := execution.Data["input"]; exists {
		return inputData
	}

	return WorkflowData{
		ID:        fmt.Sprintf("data_%d", time.Now().UnixNano()),
		Type:      "empty",
		Content:   nil,
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
	}
}

// calculateRetryDelay calculates retry delay with exponential backoff
func (we *WorkflowExecutor) calculateRetryDelay(policy RetryPolicy, attempt int) time.Duration {
	delay := policy.InitialDelay
	for i := 0; i < attempt; i++ {
		delay = time.Duration(float64(delay) * policy.BackoffFactor)
		if delay > policy.MaxDelay {
			delay = policy.MaxDelay
			break
		}
	}
	return delay
}

// hasReachedEndNodes checks if we've reached end nodes
func (we *WorkflowExecutor) hasReachedEndNodes(currentNodes, endNodes []string) bool {
	if len(endNodes) == 0 {
		return len(currentNodes) == 0
	}

	for _, currentNode := range currentNodes {
		for _, endNode := range endNodes {
			if currentNode == endNode {
				return true
			}
		}
	}

	return false
}

// removeDuplicates removes duplicate strings from slice
func (we *WorkflowExecutor) removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// Scheduler methods

// ScheduleExecution schedules a workflow execution
func (ws *WorkflowScheduler) ScheduleExecution(execution *WorkflowExecution, workflow *WorkflowGraph) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	// Allocate resources
	err := ws.resourcePool.AllocateResources(execution.ID, ResourceRequirements{
		CPU:    1.0,
		Memory: 1024 * 1024 * 1024, // 1 GB
		GPU:    0,
	})
	if err != nil {
		return fmt.Errorf("failed to allocate resources: %w", err)
	}

	// Add to active workflows
	ws.activeWorkflows[execution.ID] = execution

	ws.logger.Debug("Workflow execution scheduled",
		"execution_id", execution.ID,
		"workflow_id", workflow.ID,
	)

	return nil
}

// CleanupExecution cleans up after workflow execution
func (ws *WorkflowScheduler) CleanupExecution(executionID string) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	// Release resources
	ws.resourcePool.ReleaseResources(executionID)

	// Remove from active workflows
	delete(ws.activeWorkflows, executionID)

	ws.logger.Debug("Workflow execution cleaned up", "execution_id", executionID)
}

// Optimizer methods

// OptimizeWorkflow optimizes a workflow
func (wo *WorkflowOptimizer) OptimizeWorkflow(workflow *WorkflowGraph) *WorkflowGraph {
	wo.mu.Lock()
	defer wo.mu.Unlock()

	optimizedWorkflow := *workflow // Copy workflow

	// Apply optimization rules
	for _, rule := range wo.optimizationRules {
		if rule.Condition(&optimizedWorkflow) {
			optimizedWorkflow = *rule.Optimizer(&optimizedWorkflow)
		}
	}

	wo.logger.Debug("Workflow optimized", "workflow_id", workflow.ID)

	return &optimizedWorkflow
}

// Monitor methods

// StartMonitoring starts monitoring a workflow execution
func (wm *WorkflowMonitor) StartMonitoring(execution *WorkflowExecution) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	wm.metrics[execution.ID] = ExecutionMetrics{
		NodesExecuted:  0,
		NodesSucceeded: 0,
		NodesFailed:    0,
	}

	wm.logger.Debug("Started monitoring workflow execution", "execution_id", execution.ID)
}

// EmitEvent emits a workflow event
func (wm *WorkflowMonitor) EmitEvent(event WorkflowEvent) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	// Handle event with registered handlers
	for _, handler := range wm.eventHandlers {
		for _, eventType := range handler.GetEventTypes() {
			if eventType == event.Type {
				go func(h EventHandler, e WorkflowEvent) {
					err := h.HandleEvent(e)
					if err != nil {
						wm.logger.Error("Event handler failed", "error", err, "event_type", e.Type)
					}
				}(handler, event)
			}
		}
	}

	wm.logger.Debug("Event emitted",
		"event_type", string(event.Type),
		"workflow_id", event.WorkflowID,
		"execution_id", event.ExecutionID,
	)
}

// ResourcePool methods

// AllocateResources allocates resources for execution
func (rp *ResourcePool) AllocateResources(executionID string, requirements ResourceRequirements) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	// Check if resources are available
	if rp.availableCPU < requirements.CPU ||
		rp.availableMemory < requirements.Memory ||
		rp.availableGPU < requirements.GPU {
		return fmt.Errorf("insufficient resources available")
	}

	// Allocate resources
	allocation := ResourceAllocation{
		ExecutionID: executionID,
		CPU:         requirements.CPU,
		Memory:      requirements.Memory,
		GPU:         requirements.GPU,
		AllocatedAt: time.Now(),
	}

	rp.allocations[executionID] = allocation
	rp.availableCPU -= requirements.CPU
	rp.availableMemory -= requirements.Memory
	rp.availableGPU -= requirements.GPU

	return nil
}

// ReleaseResources releases allocated resources
func (rp *ResourcePool) ReleaseResources(executionID string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if allocation, exists := rp.allocations[executionID]; exists {
		rp.availableCPU += allocation.CPU
		rp.availableMemory += allocation.Memory
		rp.availableGPU += allocation.GPU
		delete(rp.allocations, executionID)
	}
}

// GetResourceUsage gets current resource usage
func (rp *ResourcePool) GetResourceUsage() ResourceUsage {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	totalCPU := 100.0
	totalMemory := int64(1024 * 1024 * 1024 * 100)
	totalGPU := 8

	return ResourceUsage{
		CPUTime:    time.Duration(float64(time.Hour) * (totalCPU - rp.availableCPU) / totalCPU),
		MemoryPeak: totalMemory - rp.availableMemory,
		GPUTime:    time.Duration(float64(time.Hour) * (float64(totalGPU) - float64(rp.availableGPU)) / float64(totalGPU)),
	}
}

// Initialization functions

// initializeOptimizationRules initializes optimization rules
func initializeOptimizationRules() []OptimizationRule {
	return []OptimizationRule{
		{
			ID:          "parallel_optimization",
			Name:        "Parallel Execution Optimization",
			Description: "Optimize workflows for parallel execution",
			Condition: func(workflow *WorkflowGraph) bool {
				return len(workflow.Nodes) > 3
			},
			Optimizer: func(workflow *WorkflowGraph) *WorkflowGraph {
				// Simple optimization - return workflow as-is for now
				return workflow
			},
			Priority: 1,
		},
		{
			ID:          "resource_optimization",
			Name:        "Resource Usage Optimization",
			Description: "Optimize resource allocation for nodes",
			Condition: func(workflow *WorkflowGraph) bool {
				return true
			},
			Optimizer: func(workflow *WorkflowGraph) *WorkflowGraph {
				// Simple optimization - return workflow as-is for now
				return workflow
			},
			Priority: 2,
		},
	}
}
