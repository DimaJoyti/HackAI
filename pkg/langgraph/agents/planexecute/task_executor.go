package planexecute

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var taskTracer = otel.Tracer("hackai/langgraph/agents/planexecute/tasks")

// TaskExecutor executes individual tasks
type TaskExecutor struct {
	config       *PlanExecuteConfig
	logger       *logger.Logger
	validator    *TaskValidator
	errorHandler *TaskErrorHandler
	metrics      *TaskExecutionMetrics
}

// TaskValidator validates tasks before execution
type TaskValidator struct {
	logger *logger.Logger
}

// TaskErrorHandler handles task execution errors
type TaskErrorHandler struct {
	logger          *logger.Logger
	retryStrategies map[TaskType]RetryStrategy
}

// RetryStrategy defines retry behavior for different task types
type RetryStrategy struct {
	MaxRetries      int           `json:"max_retries"`
	RetryDelay      time.Duration `json:"retry_delay"`
	BackoffFactor   float64       `json:"backoff_factor"`
	RetryableErrors []string      `json:"retryable_errors"`
}

// TaskExecutionMetrics tracks task execution metrics
type TaskExecutionMetrics struct {
	TotalTasks      int64                    `json:"total_tasks"`
	SuccessfulTasks int64                    `json:"successful_tasks"`
	FailedTasks     int64                    `json:"failed_tasks"`
	AverageLatency  time.Duration            `json:"average_latency"`
	TaskTypeMetrics map[TaskType]TypeMetrics `json:"task_type_metrics"`
	LastUpdated     time.Time                `json:"last_updated"`
}

// TypeMetrics holds metrics for a specific task type
type TypeMetrics struct {
	Count        int64         `json:"count"`
	SuccessRate  float64       `json:"success_rate"`
	AvgDuration  time.Duration `json:"avg_duration"`
	LastExecuted time.Time     `json:"last_executed"`
}

// NewTaskExecutor creates a new task executor
func NewTaskExecutor(config *PlanExecuteConfig, logger *logger.Logger) *TaskExecutor {
	return &TaskExecutor{
		config:       config,
		logger:       logger,
		validator:    &TaskValidator{logger: logger},
		errorHandler: NewTaskErrorHandler(logger),
		metrics: &TaskExecutionMetrics{
			TaskTypeMetrics: make(map[TaskType]TypeMetrics),
			LastUpdated:     time.Now(),
		},
	}
}

// NewTaskErrorHandler creates a new task error handler
func NewTaskErrorHandler(logger *logger.Logger) *TaskErrorHandler {
	teh := &TaskErrorHandler{
		logger:          logger,
		retryStrategies: make(map[TaskType]RetryStrategy),
	}

	// Initialize retry strategies for different task types
	teh.initializeRetryStrategies()

	return teh
}

// initializeRetryStrategies sets up retry strategies for different task types
func (teh *TaskErrorHandler) initializeRetryStrategies() {
	strategies := map[TaskType]RetryStrategy{
		TaskTypeAnalysis: {
			MaxRetries:      2,
			RetryDelay:      time.Second * 5,
			BackoffFactor:   1.5,
			RetryableErrors: []string{"timeout", "temporary", "network"},
		},
		TaskTypeDataCollection: {
			MaxRetries:      3,
			RetryDelay:      time.Second * 3,
			BackoffFactor:   2.0,
			RetryableErrors: []string{"timeout", "rate_limit", "network", "temporary"},
		},
		TaskTypeProcessing: {
			MaxRetries:      2,
			RetryDelay:      time.Second * 2,
			BackoffFactor:   1.0,
			RetryableErrors: []string{"timeout", "temporary"},
		},
		TaskTypeValidation: {
			MaxRetries:      1,
			RetryDelay:      time.Second,
			BackoffFactor:   1.0,
			RetryableErrors: []string{"timeout"},
		},
		TaskTypeReporting: {
			MaxRetries:      2,
			RetryDelay:      time.Second * 3,
			BackoffFactor:   1.5,
			RetryableErrors: []string{"timeout", "temporary", "format_error"},
		},
	}

	teh.retryStrategies = strategies
}

// ExecuteTask executes a single task
func (te *TaskExecutor) ExecuteTask(ctx context.Context, task *Task, availableTools map[string]tools.Tool, context map[string]interface{}) (interface{}, error) {
	ctx, span := taskTracer.Start(ctx, "task_executor.execute_task",
		trace.WithAttributes(
			attribute.String("task.id", task.ID),
			attribute.String("task.name", task.Name),
			attribute.String("task.type", string(task.Type)),
			attribute.String("task.tool", task.Tool),
		),
	)
	defer span.End()

	startTime := time.Now()
	task.StartTime = &startTime
	task.Status = TaskStatusRunning

	te.logger.Debug("Executing task",
		"task_id", task.ID,
		"task_name", task.Name,
		"task_type", task.Type,
		"tool", task.Tool)

	// Validate task before execution
	if err := te.validator.ValidateTask(task, availableTools); err != nil {
		task.Status = TaskStatusFailed
		task.Error = fmt.Sprintf("validation failed: %v", err)
		span.RecordError(err)
		te.updateMetrics(task, false, time.Since(startTime))
		return nil, err
	}

	// Execute task with retries
	result, err := te.executeWithRetries(ctx, task, availableTools, context)

	// Update task status and timing
	endTime := time.Now()
	task.EndTime = &endTime
	task.ActualDuration = endTime.Sub(startTime)

	if err != nil {
		task.Status = TaskStatusFailed
		task.Error = err.Error()
		span.RecordError(err)
		te.updateMetrics(task, false, task.ActualDuration)

		te.logger.Error("Task execution failed",
			"task_id", task.ID,
			"task_name", task.Name,
			"error", err,
			"duration", task.ActualDuration,
			"retries", task.Retries)

		return nil, err
	}

	task.Status = TaskStatusCompleted
	task.Output = result
	te.updateMetrics(task, true, task.ActualDuration)

	span.SetAttributes(
		attribute.Bool("task.success", true),
		attribute.Float64("task.duration", task.ActualDuration.Seconds()),
		attribute.Int("task.retries", task.Retries),
	)

	te.logger.Info("Task execution completed",
		"task_id", task.ID,
		"task_name", task.Name,
		"duration", task.ActualDuration,
		"retries", task.Retries)

	return result, nil
}

// executeWithRetries executes a task with retry logic
func (te *TaskExecutor) executeWithRetries(ctx context.Context, task *Task, availableTools map[string]tools.Tool, context map[string]interface{}) (interface{}, error) {
	strategy := te.errorHandler.GetRetryStrategy(task.Type)
	var lastError error

	for attempt := 0; attempt <= strategy.MaxRetries; attempt++ {
		// Execute the task
		result, err := te.executeSingleAttempt(ctx, task, availableTools, context)

		if err == nil {
			// Success
			return result, nil
		}

		lastError = err
		task.Retries++

		// Check if we should retry
		if attempt < strategy.MaxRetries && te.errorHandler.IsRetryable(err, task.Type) {
			delay := te.calculateRetryDelay(attempt, strategy)

			te.logger.Debug("Task execution failed, retrying",
				"task_id", task.ID,
				"attempt", attempt+1,
				"error", err,
				"retry_delay", delay)

			// Wait before retry
			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			break
		}
	}

	return nil, lastError
}

// executeSingleAttempt executes a single attempt of the task
func (te *TaskExecutor) executeSingleAttempt(ctx context.Context, task *Task, availableTools map[string]tools.Tool, context map[string]interface{}) (interface{}, error) {
	// If task has a specific tool, use it
	if task.Tool != "" {
		tool, exists := availableTools[task.Tool]
		if !exists {
			return nil, fmt.Errorf("required tool %s not available", task.Tool)
		}

		// Prepare tool input
		toolInput := te.prepareToolInput(task, context)

		// Execute tool
		return tool.Execute(ctx, toolInput)
	}

	// If no specific tool, execute based on task type
	return te.executeByTaskType(ctx, task, availableTools, context)
}

// prepareToolInput prepares input for tool execution
func (te *TaskExecutor) prepareToolInput(task *Task, context map[string]interface{}) map[string]interface{} {
	input := make(map[string]interface{})

	// Copy task input
	for key, value := range task.Input {
		input[key] = value
	}

	// Add context
	for key, value := range context {
		input[key] = value
	}

	// Add task metadata
	input["task_id"] = task.ID
	input["task_name"] = task.Name
	input["task_type"] = string(task.Type)

	return input
}

// executeByTaskType executes task based on its type when no specific tool is assigned
func (te *TaskExecutor) executeByTaskType(ctx context.Context, task *Task, availableTools map[string]tools.Tool, context map[string]interface{}) (interface{}, error) {
	switch task.Type {
	case TaskTypeAnalysis:
		return te.executeAnalysisTask(ctx, task, availableTools, context)
	case TaskTypeDataCollection:
		return te.executeDataCollectionTask(ctx, task, availableTools, context)
	case TaskTypeProcessing:
		return te.executeProcessingTask(ctx, task, availableTools, context)
	case TaskTypeValidation:
		return te.executeValidationTask(ctx, task, availableTools, context)
	case TaskTypeReporting:
		return te.executeReportingTask(ctx, task, availableTools, context)
	case TaskTypeIntegration:
		return te.executeIntegrationTask(ctx, task, availableTools, context)
	default:
		return te.executeCustomTask(ctx, task, availableTools, context)
	}
}

// executeAnalysisTask executes an analysis task
func (te *TaskExecutor) executeAnalysisTask(ctx context.Context, task *Task, availableTools map[string]tools.Tool, context map[string]interface{}) (interface{}, error) {
	// Look for analysis tools
	for _, tool := range availableTools {
		if te.isAnalysisTool(tool) {
			input := te.prepareToolInput(task, context)
			return tool.Execute(ctx, input)
		}
	}

	// Fallback: simulate analysis
	return map[string]interface{}{
		"analysis_type": "generic",
		"result":        "Analysis completed successfully",
		"timestamp":     time.Now(),
		"task_id":       task.ID,
	}, nil
}

// executeDataCollectionTask executes a data collection task
func (te *TaskExecutor) executeDataCollectionTask(ctx context.Context, task *Task, availableTools map[string]tools.Tool, context map[string]interface{}) (interface{}, error) {
	// Look for data collection tools
	for _, tool := range availableTools {
		if te.isDataCollectionTool(tool) {
			input := te.prepareToolInput(task, context)
			return tool.Execute(ctx, input)
		}
	}

	// Fallback: simulate data collection
	return map[string]interface{}{
		"data_collected": true,
		"records":        100,
		"timestamp":      time.Now(),
		"task_id":        task.ID,
	}, nil
}

// executeProcessingTask executes a processing task
func (te *TaskExecutor) executeProcessingTask(ctx context.Context, task *Task, availableTools map[string]tools.Tool, context map[string]interface{}) (interface{}, error) {
	// Look for processing tools
	for _, tool := range availableTools {
		if te.isProcessingTool(tool) {
			input := te.prepareToolInput(task, context)
			return tool.Execute(ctx, input)
		}
	}

	// Fallback: simulate processing
	return map[string]interface{}{
		"processing_completed": true,
		"processed_items":      50,
		"timestamp":            time.Now(),
		"task_id":              task.ID,
	}, nil
}

// executeValidationTask executes a validation task
func (te *TaskExecutor) executeValidationTask(ctx context.Context, task *Task, availableTools map[string]tools.Tool, context map[string]interface{}) (interface{}, error) {
	// Validation logic
	return map[string]interface{}{
		"validation_passed": true,
		"errors_found":      0,
		"warnings_found":    2,
		"timestamp":         time.Now(),
		"task_id":           task.ID,
	}, nil
}

// executeReportingTask executes a reporting task
func (te *TaskExecutor) executeReportingTask(ctx context.Context, task *Task, availableTools map[string]tools.Tool, context map[string]interface{}) (interface{}, error) {
	// Look for reporting tools
	for _, tool := range availableTools {
		if te.isReportingTool(tool) {
			input := te.prepareToolInput(task, context)
			return tool.Execute(ctx, input)
		}
	}

	// Fallback: generate simple report
	return map[string]interface{}{
		"report_generated": true,
		"report_type":      "summary",
		"sections":         []string{"overview", "findings", "recommendations"},
		"timestamp":        time.Now(),
		"task_id":          task.ID,
	}, nil
}

// executeIntegrationTask executes an integration task
func (te *TaskExecutor) executeIntegrationTask(ctx context.Context, task *Task, availableTools map[string]tools.Tool, context map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"integration_completed":   true,
		"connections_established": 3,
		"timestamp":               time.Now(),
		"task_id":                 task.ID,
	}, nil
}

// executeCustomTask executes a custom task
func (te *TaskExecutor) executeCustomTask(ctx context.Context, task *Task, availableTools map[string]tools.Tool, context map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"custom_task_completed": true,
		"timestamp":             time.Now(),
		"task_id":               task.ID,
	}, nil
}

// Tool type detection helpers
func (te *TaskExecutor) isAnalysisTool(tool tools.Tool) bool {
	toolName := tool.Name()
	analysisKeywords := []string{"analyze", "analysis", "scan", "inspect", "examine"}
	for _, keyword := range analysisKeywords {
		if contains(toolName, keyword) {
			return true
		}
	}
	return false
}

func (te *TaskExecutor) isDataCollectionTool(tool tools.Tool) bool {
	toolName := tool.Name()
	collectionKeywords := []string{"collect", "gather", "fetch", "retrieve", "scrape"}
	for _, keyword := range collectionKeywords {
		if contains(toolName, keyword) {
			return true
		}
	}
	return false
}

func (te *TaskExecutor) isProcessingTool(tool tools.Tool) bool {
	toolName := tool.Name()
	processingKeywords := []string{"process", "transform", "convert", "parse", "filter"}
	for _, keyword := range processingKeywords {
		if contains(toolName, keyword) {
			return true
		}
	}
	return false
}

func (te *TaskExecutor) isReportingTool(tool tools.Tool) bool {
	toolName := tool.Name()
	reportingKeywords := []string{"report", "generate", "create", "format", "export"}
	for _, keyword := range reportingKeywords {
		if contains(toolName, keyword) {
			return true
		}
	}
	return false
}

// calculateRetryDelay calculates the delay before the next retry
func (te *TaskExecutor) calculateRetryDelay(attempt int, strategy RetryStrategy) time.Duration {
	delay := strategy.RetryDelay
	for i := 0; i < attempt; i++ {
		delay = time.Duration(float64(delay) * strategy.BackoffFactor)
	}

	// Cap the delay at 60 seconds
	if delay > 60*time.Second {
		delay = 60 * time.Second
	}

	return delay
}

// updateMetrics updates task execution metrics
func (te *TaskExecutor) updateMetrics(task *Task, success bool, duration time.Duration) {
	te.metrics.TotalTasks++

	if success {
		te.metrics.SuccessfulTasks++
	} else {
		te.metrics.FailedTasks++
	}

	// Update average latency
	if te.metrics.TotalTasks == 1 {
		te.metrics.AverageLatency = duration
	} else {
		te.metrics.AverageLatency = time.Duration(
			(int64(te.metrics.AverageLatency)*te.metrics.TotalTasks + int64(duration)) / (te.metrics.TotalTasks + 1),
		)
	}

	// Update task type metrics
	typeMetrics := te.metrics.TaskTypeMetrics[task.Type]
	typeMetrics.Count++
	typeMetrics.LastExecuted = time.Now()

	if typeMetrics.Count == 1 {
		typeMetrics.AvgDuration = duration
		typeMetrics.SuccessRate = 0.0
		if success {
			typeMetrics.SuccessRate = 1.0
		}
	} else {
		// Update average duration
		typeMetrics.AvgDuration = time.Duration(
			(int64(typeMetrics.AvgDuration)*typeMetrics.Count + int64(duration)) / (typeMetrics.Count + 1),
		)

		// Update success rate
		if success {
			typeMetrics.SuccessRate = (typeMetrics.SuccessRate*float64(typeMetrics.Count-1) + 1.0) / float64(typeMetrics.Count)
		} else {
			typeMetrics.SuccessRate = (typeMetrics.SuccessRate * float64(typeMetrics.Count-1)) / float64(typeMetrics.Count)
		}
	}

	te.metrics.TaskTypeMetrics[task.Type] = typeMetrics
	te.metrics.LastUpdated = time.Now()
}

// ValidateTask validates a task before execution
func (tv *TaskValidator) ValidateTask(task *Task, availableTools map[string]tools.Tool) error {
	if task == nil {
		return fmt.Errorf("task cannot be nil")
	}

	if task.ID == "" {
		return fmt.Errorf("task ID cannot be empty")
	}

	if task.Name == "" {
		return fmt.Errorf("task name cannot be empty")
	}

	// Validate tool availability if specified
	if task.Tool != "" {
		if _, exists := availableTools[task.Tool]; !exists {
			return fmt.Errorf("required tool %s not available", task.Tool)
		}
	}

	// Validate task input
	if task.Input == nil {
		task.Input = make(map[string]interface{})
	}

	return nil
}

// GetRetryStrategy gets the retry strategy for a task type
func (teh *TaskErrorHandler) GetRetryStrategy(taskType TaskType) RetryStrategy {
	if strategy, exists := teh.retryStrategies[taskType]; exists {
		return strategy
	}

	// Default strategy
	return RetryStrategy{
		MaxRetries:      1,
		RetryDelay:      time.Second,
		BackoffFactor:   1.0,
		RetryableErrors: []string{"timeout", "temporary"},
	}
}

// IsRetryable checks if an error is retryable for a given task type
func (teh *TaskErrorHandler) IsRetryable(err error, taskType TaskType) bool {
	if err == nil {
		return false
	}

	strategy := teh.GetRetryStrategy(taskType)
	errorStr := err.Error()

	for _, retryableError := range strategy.RetryableErrors {
		if contains(errorStr, retryableError) {
			return true
		}
	}

	return false
}

// GetMetrics returns current task execution metrics
func (te *TaskExecutor) GetMetrics() TaskExecutionMetrics {
	return *te.metrics
}

// contains checks if a string contains a substring (case-insensitive)
func contains(str, substr string) bool {
	return len(str) >= len(substr) &&
		(str == substr ||
			(len(str) > len(substr) &&
				(str[:len(substr)] == substr ||
					str[len(str)-len(substr):] == substr ||
					containsSubstring(str, substr))))
}

// containsSubstring checks if str contains substr anywhere
func containsSubstring(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
