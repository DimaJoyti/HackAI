package planexecute

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var planExecuteTracer = otel.Tracer("hackai/langgraph/agents/planexecute")

// PlanAndExecuteAgent implements the Plan-and-Execute pattern
type PlanAndExecuteAgent struct {
	ID          string
	Name        string
	Description string
	Tools       map[string]tools.Tool
	Logger      *logger.Logger
	Planner     *TaskPlanner
	Executor    *TaskExecutor
	Monitor     *ExecutionMonitor
	Replanner   *Replanner
	config      *PlanExecuteConfig
	mutex       sync.RWMutex
}

// PlanExecuteConfig holds configuration for the Plan-and-Execute agent
type PlanExecuteConfig struct {
	MaxPlanningIterations   int           `json:"max_planning_iterations"`
	MaxExecutionTime        time.Duration `json:"max_execution_time"`
	EnableParallelExecution bool          `json:"enable_parallel_execution"`
	MaxParallelTasks        int           `json:"max_parallel_tasks"`
	EnableReplanning        bool          `json:"enable_replanning"`
	ReplanThreshold         float64       `json:"replan_threshold"`
	EnableProgressTracking  bool          `json:"enable_progress_tracking"`
}

// AgentInput represents input to the Plan-and-Execute agent
type AgentInput struct {
	Objective   string                 `json:"objective"`
	Context     map[string]interface{} `json:"context"`
	Constraints []string               `json:"constraints"`
	Preferences map[string]interface{} `json:"preferences"`
	Deadline    *time.Time             `json:"deadline,omitempty"`
}

// AgentOutput represents output from the Plan-and-Execute agent
type AgentOutput struct {
	Success        bool                   `json:"success"`
	Result         interface{}            `json:"result"`
	Plan           *ExecutionPlan         `json:"plan"`
	Duration       time.Duration          `json:"duration"`
	TasksCompleted int                    `json:"tasks_completed"`
	TasksFailed    int                    `json:"tasks_failed"`
	Error          string                 `json:"error,omitempty"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// ExecutionPlan represents a plan for achieving an objective
type ExecutionPlan struct {
	ID           string                 `json:"id"`
	Objective    string                 `json:"objective"`
	Tasks        []*Task                `json:"tasks"`
	Dependencies map[string][]string    `json:"dependencies"`
	Status       PlanStatus             `json:"status"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Task represents a single task in the execution plan
type Task struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Type              TaskType               `json:"type"`
	Tool              string                 `json:"tool"`
	Input             map[string]interface{} `json:"input"`
	Output            interface{}            `json:"output,omitempty"`
	Status            TaskStatus             `json:"status"`
	Priority          int                    `json:"priority"`
	Dependencies      []string               `json:"dependencies"`
	EstimatedDuration time.Duration          `json:"estimated_duration"`
	ActualDuration    time.Duration          `json:"actual_duration"`
	StartTime         *time.Time             `json:"start_time,omitempty"`
	EndTime           *time.Time             `json:"end_time,omitempty"`
	Error             string                 `json:"error,omitempty"`
	Retries           int                    `json:"retries"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// PlanStatus represents the status of an execution plan
type PlanStatus string

const (
	PlanStatusDraft     PlanStatus = "draft"
	PlanStatusApproved  PlanStatus = "approved"
	PlanStatusExecuting PlanStatus = "executing"
	PlanStatusCompleted PlanStatus = "completed"
	PlanStatusFailed    PlanStatus = "failed"
	PlanStatusCancelled PlanStatus = "cancelled"
)

// TaskStatus represents the status of a task
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusReady     TaskStatus = "ready"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusSkipped   TaskStatus = "skipped"
	TaskStatusCancelled TaskStatus = "cancelled"
)

// TaskType represents the type of task
type TaskType string

const (
	TaskTypeAnalysis       TaskType = "analysis"
	TaskTypeDataCollection TaskType = "data_collection"
	TaskTypeProcessing     TaskType = "processing"
	TaskTypeValidation     TaskType = "validation"
	TaskTypeReporting      TaskType = "reporting"
	TaskTypeIntegration    TaskType = "integration"
	TaskTypeCustom         TaskType = "custom"
)

// NewPlanAndExecuteAgent creates a new Plan-and-Execute agent
func NewPlanAndExecuteAgent(id, name string, logger *logger.Logger) *PlanAndExecuteAgent {
	config := &PlanExecuteConfig{
		MaxPlanningIterations:   5,
		MaxExecutionTime:        time.Hour,
		EnableParallelExecution: true,
		MaxParallelTasks:        5,
		EnableReplanning:        true,
		ReplanThreshold:         0.3,
		EnableProgressTracking:  true,
	}

	return &PlanAndExecuteAgent{
		ID:          id,
		Name:        name,
		Description: "Plan-and-Execute agent for complex multi-step tasks",
		Tools:       make(map[string]tools.Tool),
		Logger:      logger,
		Planner:     NewTaskPlanner(logger),
		Executor:    NewTaskExecutor(config, logger),
		Monitor:     NewExecutionMonitor(logger),
		Replanner:   NewReplanner(logger),
		config:      config,
	}
}

// RegisterTool registers a tool with the agent
func (pea *PlanAndExecuteAgent) RegisterTool(tool tools.Tool) error {
	pea.mutex.Lock()
	defer pea.mutex.Unlock()

	if tool == nil {
		return fmt.Errorf("tool cannot be nil")
	}

	pea.Tools[tool.ID()] = tool
	pea.Logger.Info("Tool registered with Plan-and-Execute agent",
		"agent_id", pea.ID,
		"tool_id", tool.ID(),
		"tool_name", tool.Name())

	return nil
}

// Execute executes the Plan-and-Execute workflow
func (pea *PlanAndExecuteAgent) Execute(ctx context.Context, input AgentInput) (*AgentOutput, error) {
	ctx, span := planExecuteTracer.Start(ctx, "plan_execute_agent.execute",
		trace.WithAttributes(
			attribute.String("agent.id", pea.ID),
			attribute.String("agent.name", pea.Name),
			attribute.String("objective", input.Objective),
		),
	)
	defer span.End()

	startTime := time.Now()

	pea.Logger.Info("Starting Plan-and-Execute agent execution",
		"agent_id", pea.ID,
		"objective", input.Objective)

	// Create execution context with timeout
	execCtx := ctx
	if pea.config.MaxExecutionTime > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, pea.config.MaxExecutionTime)
		defer cancel()
	}

	// Phase 1: Planning
	plan, err := pea.createInitialPlan(execCtx, input)
	if err != nil {
		span.RecordError(err)
		return &AgentOutput{
			Success:  false,
			Error:    fmt.Sprintf("planning failed: %v", err),
			Duration: time.Since(startTime),
			Metadata: make(map[string]interface{}),
		}, err
	}

	span.SetAttributes(
		attribute.String("plan.id", plan.ID),
		attribute.Int("plan.tasks", len(plan.Tasks)),
	)

	// Phase 2: Execution with monitoring
	result, err := pea.executePlanWithMonitoring(execCtx, plan, input)
	if err != nil {
		span.RecordError(err)
		return &AgentOutput{
			Success:  false,
			Plan:     plan,
			Error:    fmt.Sprintf("execution failed: %v", err),
			Duration: time.Since(startTime),
			Metadata: make(map[string]interface{}),
		}, err
	}

	// Calculate final statistics
	tasksCompleted := 0
	tasksFailed := 0
	for _, task := range plan.Tasks {
		switch task.Status {
		case TaskStatusCompleted:
			tasksCompleted++
		case TaskStatusFailed:
			tasksFailed++
		}
	}

	output := &AgentOutput{
		Success:        plan.Status == PlanStatusCompleted,
		Result:         result,
		Plan:           plan,
		Duration:       time.Since(startTime),
		TasksCompleted: tasksCompleted,
		TasksFailed:    tasksFailed,
		Metadata: map[string]interface{}{
			"total_tasks":      len(plan.Tasks),
			"execution_phases": "planning_and_execution",
			"replanning_used":  pea.config.EnableReplanning,
		},
	}

	span.SetAttributes(
		attribute.Bool("execution.success", output.Success),
		attribute.Int("execution.tasks_completed", tasksCompleted),
		attribute.Int("execution.tasks_failed", tasksFailed),
		attribute.Float64("execution.duration", output.Duration.Seconds()),
	)

	pea.Logger.Info("Plan-and-Execute agent execution completed",
		"agent_id", pea.ID,
		"success", output.Success,
		"tasks_completed", tasksCompleted,
		"tasks_failed", tasksFailed,
		"duration", output.Duration)

	return output, nil
}

// createInitialPlan creates the initial execution plan
func (pea *PlanAndExecuteAgent) createInitialPlan(ctx context.Context, input AgentInput) (*ExecutionPlan, error) {
	pea.Logger.Debug("Creating initial plan", "agent_id", pea.ID, "objective", input.Objective)

	plan, err := pea.Planner.CreatePlan(ctx, input, pea.Tools)
	if err != nil {
		return nil, fmt.Errorf("failed to create plan: %w", err)
	}

	// Validate plan
	if err := pea.validatePlan(plan); err != nil {
		return nil, fmt.Errorf("plan validation failed: %w", err)
	}

	plan.Status = PlanStatusApproved
	plan.UpdatedAt = time.Now()

	pea.Logger.Info("Initial plan created",
		"agent_id", pea.ID,
		"plan_id", plan.ID,
		"tasks", len(plan.Tasks))

	return plan, nil
}

// executePlanWithMonitoring executes the plan with continuous monitoring
func (pea *PlanAndExecuteAgent) executePlanWithMonitoring(ctx context.Context, plan *ExecutionPlan, input AgentInput) (interface{}, error) {
	plan.Status = PlanStatusExecuting
	plan.UpdatedAt = time.Now()

	// Start monitoring
	if pea.config.EnableProgressTracking {
		go pea.Monitor.StartMonitoring(ctx, plan)
	}

	var finalResult interface{}
	var executionError error

	if pea.config.EnableParallelExecution {
		finalResult, executionError = pea.executeParallel(ctx, plan, input)
	} else {
		finalResult, executionError = pea.executeSequential(ctx, plan, input)
	}

	// Update plan status based on execution result
	if executionError != nil {
		plan.Status = PlanStatusFailed
	} else {
		plan.Status = PlanStatusCompleted
	}
	plan.UpdatedAt = time.Now()

	return finalResult, executionError
}

// executeSequential executes tasks sequentially
func (pea *PlanAndExecuteAgent) executeSequential(ctx context.Context, plan *ExecutionPlan, input AgentInput) (interface{}, error) {
	pea.Logger.Debug("Executing plan sequentially", "plan_id", plan.ID)

	var lastResult interface{}

	for _, task := range plan.Tasks {
		if task.Status == TaskStatusSkipped {
			continue
		}

		// Check if dependencies are satisfied
		if !pea.areDependenciesSatisfied(task, plan) {
			task.Status = TaskStatusFailed
			task.Error = "dependencies not satisfied"
			continue
		}

		// Execute task
		result, err := pea.Executor.ExecuteTask(ctx, task, pea.Tools, input.Context)
		if err != nil {
			task.Status = TaskStatusFailed
			task.Error = err.Error()

			// Check if replanning is needed
			if pea.config.EnableReplanning && pea.shouldReplan(plan) {
				newPlan, replanErr := pea.Replanner.Replan(ctx, plan, task, err, input)
				if replanErr != nil {
					return nil, fmt.Errorf("execution failed and replanning failed: %w", err)
				}
				*plan = *newPlan
				continue
			}

			return nil, fmt.Errorf("task %s failed: %w", task.ID, err)
		}

		task.Status = TaskStatusCompleted
		task.Output = result
		lastResult = result

		// Update context with task result
		input.Context[fmt.Sprintf("task_%s_result", task.ID)] = result
	}

	return lastResult, nil
}

// executeParallel executes tasks in parallel where possible
func (pea *PlanAndExecuteAgent) executeParallel(ctx context.Context, plan *ExecutionPlan, input AgentInput) (interface{}, error) {
	pea.Logger.Debug("Executing plan in parallel", "plan_id", plan.ID)

	// Build dependency graph and execution levels
	levels := pea.buildExecutionLevels(plan)

	var finalResult interface{}

	for levelIndex, level := range levels {
		pea.Logger.Debug("Executing level", "level", levelIndex, "tasks", len(level))

		// Execute all tasks in this level in parallel
		results, err := pea.executeTasksInParallel(ctx, level, pea.Tools, input.Context)
		if err != nil {
			return nil, fmt.Errorf("parallel execution failed at level %d: %w", levelIndex, err)
		}

		// Update context with results
		for taskID, result := range results {
			input.Context[fmt.Sprintf("task_%s_result", taskID)] = result
			finalResult = result // Keep the last result as final result
		}
	}

	return finalResult, nil
}

// buildExecutionLevels builds levels of tasks that can be executed in parallel
func (pea *PlanAndExecuteAgent) buildExecutionLevels(plan *ExecutionPlan) [][]*Task {
	levels := make([][]*Task, 0)
	remaining := make([]*Task, 0)

	// Copy all tasks to remaining
	for _, task := range plan.Tasks {
		if task.Status != TaskStatusSkipped {
			remaining = append(remaining, task)
		}
	}

	for len(remaining) > 0 {
		currentLevel := make([]*Task, 0)
		newRemaining := make([]*Task, 0)

		for _, task := range remaining {
			if pea.areDependenciesSatisfied(task, plan) {
				currentLevel = append(currentLevel, task)
			} else {
				newRemaining = append(newRemaining, task)
			}
		}

		if len(currentLevel) == 0 {
			// No tasks can be executed, break to avoid infinite loop
			pea.Logger.Warn("Circular dependency detected or unsatisfied dependencies",
				"remaining_tasks", len(newRemaining))
			break
		}

		levels = append(levels, currentLevel)
		remaining = newRemaining

		// Mark current level tasks as ready
		for _, task := range currentLevel {
			task.Status = TaskStatusReady
		}
	}

	return levels
}

// executeTasksInParallel executes multiple tasks in parallel
func (pea *PlanAndExecuteAgent) executeTasksInParallel(ctx context.Context, tasks []*Task, tools map[string]tools.Tool, context map[string]interface{}) (map[string]interface{}, error) {
	results := make(map[string]interface{})
	errors := make(map[string]error)
	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Limit parallel execution
	semaphore := make(chan struct{}, pea.config.MaxParallelTasks)

	for _, task := range tasks {
		wg.Add(1)
		go func(t *Task) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result, err := pea.Executor.ExecuteTask(ctx, t, tools, context)

			mutex.Lock()
			defer mutex.Unlock()

			if err != nil {
				t.Status = TaskStatusFailed
				t.Error = err.Error()
				errors[t.ID] = err
			} else {
				t.Status = TaskStatusCompleted
				t.Output = result
				results[t.ID] = result
			}
		}(task)
	}

	wg.Wait()

	// Check if any critical tasks failed
	if len(errors) > 0 {
		return results, fmt.Errorf("some tasks failed: %d errors", len(errors))
	}

	return results, nil
}

// areDependenciesSatisfied checks if all dependencies for a task are satisfied
func (pea *PlanAndExecuteAgent) areDependenciesSatisfied(task *Task, plan *ExecutionPlan) bool {
	for _, depID := range task.Dependencies {
		for _, planTask := range plan.Tasks {
			if planTask.ID == depID && planTask.Status != TaskStatusCompleted {
				return false
			}
		}
	}
	return true
}

// shouldReplan determines if replanning is needed
func (pea *PlanAndExecuteAgent) shouldReplan(plan *ExecutionPlan) bool {
	if !pea.config.EnableReplanning {
		return false
	}

	failedTasks := 0
	totalTasks := len(plan.Tasks)

	for _, task := range plan.Tasks {
		if task.Status == TaskStatusFailed {
			failedTasks++
		}
	}

	failureRate := float64(failedTasks) / float64(totalTasks)
	return failureRate >= pea.config.ReplanThreshold
}

// validatePlan validates the execution plan
func (pea *PlanAndExecuteAgent) validatePlan(plan *ExecutionPlan) error {
	if len(plan.Tasks) == 0 {
		return fmt.Errorf("plan has no tasks")
	}

	// Check for circular dependencies
	if pea.hasCircularDependencies(plan) {
		return fmt.Errorf("plan has circular dependencies")
	}

	// Validate that all required tools are available
	for _, task := range plan.Tasks {
		if task.Tool != "" {
			if _, exists := pea.Tools[task.Tool]; !exists {
				return fmt.Errorf("required tool %s not available for task %s", task.Tool, task.ID)
			}
		}
	}

	return nil
}

// hasCircularDependencies checks for circular dependencies in the plan
func (pea *PlanAndExecuteAgent) hasCircularDependencies(plan *ExecutionPlan) bool {
	// Simple cycle detection using DFS
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var hasCycle func(taskID string) bool
	hasCycle = func(taskID string) bool {
		visited[taskID] = true
		recStack[taskID] = true

		// Find the task
		var currentTask *Task
		for _, task := range plan.Tasks {
			if task.ID == taskID {
				currentTask = task
				break
			}
		}

		if currentTask == nil {
			return false
		}

		// Check all dependencies
		for _, depID := range currentTask.Dependencies {
			if !visited[depID] {
				if hasCycle(depID) {
					return true
				}
			} else if recStack[depID] {
				return true
			}
		}

		recStack[taskID] = false
		return false
	}

	for _, task := range plan.Tasks {
		if !visited[task.ID] {
			if hasCycle(task.ID) {
				return true
			}
		}
	}

	return false
}

// GetCapabilities returns the agent's capabilities
func (pea *PlanAndExecuteAgent) GetCapabilities() map[string]interface{} {
	pea.mutex.RLock()
	defer pea.mutex.RUnlock()

	toolNames := make([]string, 0, len(pea.Tools))
	for _, tool := range pea.Tools {
		toolNames = append(toolNames, tool.Name())
	}

	return map[string]interface{}{
		"agent_type":              "plan_and_execute",
		"max_planning_iterations": pea.config.MaxPlanningIterations,
		"parallel_execution":      pea.config.EnableParallelExecution,
		"max_parallel_tasks":      pea.config.MaxParallelTasks,
		"replanning_enabled":      pea.config.EnableReplanning,
		"available_tools":         toolNames,
		"progress_tracking":       pea.config.EnableProgressTracking,
	}
}

// UpdateConfig updates the agent configuration
func (pea *PlanAndExecuteAgent) UpdateConfig(config *PlanExecuteConfig) {
	pea.mutex.Lock()
	defer pea.mutex.Unlock()

	if config.MaxPlanningIterations > 0 {
		pea.config.MaxPlanningIterations = config.MaxPlanningIterations
	}

	if config.MaxExecutionTime > 0 {
		pea.config.MaxExecutionTime = config.MaxExecutionTime
	}

	if config.MaxParallelTasks > 0 {
		pea.config.MaxParallelTasks = config.MaxParallelTasks
	}

	pea.config.EnableParallelExecution = config.EnableParallelExecution
	pea.config.EnableReplanning = config.EnableReplanning
	pea.config.EnableProgressTracking = config.EnableProgressTracking

	if config.ReplanThreshold > 0 && config.ReplanThreshold <= 1.0 {
		pea.config.ReplanThreshold = config.ReplanThreshold
	}

	pea.Logger.Info("Plan-and-Execute agent configuration updated",
		"agent_id", pea.ID,
		"max_planning_iterations", pea.config.MaxPlanningIterations,
		"parallel_execution", pea.config.EnableParallelExecution)
}
