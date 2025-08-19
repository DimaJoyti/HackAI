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

var toolTracer = otel.Tracer("hackai/ai/tool")

// BaseTool provides common functionality for all tools
type BaseTool struct {
	name        string
	description string
	schema      ToolSchema
	metrics     ToolMetrics
	logger      *logger.Logger
	tracer      trace.Tracer
	mutex       sync.RWMutex
}

// NewBaseTool creates a new base tool
func NewBaseTool(name, description string, schema ToolSchema, logger *logger.Logger) *BaseTool {
	return &BaseTool{
		name:        name,
		description: description,
		schema:      schema,
		logger:      logger,
		tracer:      toolTracer,
		metrics: ToolMetrics{
			LastExecutionTime: time.Now(),
		},
	}
}

// Name returns the tool name
func (t *BaseTool) Name() string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.name
}

// Description returns the tool description
func (t *BaseTool) Description() string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.description
}

// GetSchema returns the tool schema
func (t *BaseTool) GetSchema() ToolSchema {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.schema
}

// GetMetrics returns the tool metrics
func (t *BaseTool) GetMetrics() ToolMetrics {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.metrics
}

// Execute provides base execution functionality with metrics and tracing
func (t *BaseTool) Execute(ctx context.Context, input ToolInput) (ToolOutput, error) {
	startTime := time.Now()

	// Create span for tracing
	ctx, span := t.tracer.Start(ctx, "tool.execute",
		trace.WithAttributes(
			attribute.String("tool.name", t.name),
		),
	)
	defer span.End()

	// Update metrics
	t.updateExecutionStart()

	// Validate input
	if err := t.Validate(input); err != nil {
		t.updateExecutionEnd(time.Since(startTime), false)
		span.RecordError(err)
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	// Execute the actual tool logic (to be implemented by concrete tools)
	output, err := t.executeInternal(ctx, input)

	// Update metrics
	duration := time.Since(startTime)
	t.updateExecutionEnd(duration, err == nil)

	if err != nil {
		span.RecordError(err)
		t.logger.Error("Tool execution failed",
			"tool_name", t.name,
			"error", err,
			"duration", duration)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("execution.duration", duration.String()),
		attribute.Bool("execution.success", true),
	)

	t.logger.Debug("Tool executed successfully",
		"tool_name", t.name,
		"duration", duration)

	return output, nil
}

// executeInternal is meant to be overridden by concrete tool implementations
func (t *BaseTool) executeInternal(ctx context.Context, input ToolInput) (ToolOutput, error) {
	return nil, fmt.Errorf("executeInternal not implemented")
}

// Validate validates the tool input against the schema
func (t *BaseTool) Validate(input ToolInput) error {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	// Validate required parameters
	for paramName, paramSchema := range t.schema.InputSchema {
		if paramSchema.Required {
			if _, exists := input[paramName]; !exists {
				return fmt.Errorf("required parameter %s is missing", paramName)
			}
		}
	}

	// Validate parameter types and constraints
	for paramName, value := range input {
		if paramSchema, exists := t.schema.InputSchema[paramName]; exists {
			if err := t.validateParameter(paramName, value, paramSchema); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateParameter validates a single parameter
func (t *BaseTool) validateParameter(name string, value interface{}, schema ParameterSchema) error {
	// Type validation
	switch schema.Type {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("parameter %s must be a string", name)
		}
		strValue := value.(string)
		
		// Length validation
		if schema.MinLength != nil && len(strValue) < *schema.MinLength {
			return fmt.Errorf("parameter %s must be at least %d characters", name, *schema.MinLength)
		}
		if schema.MaxLength != nil && len(strValue) > *schema.MaxLength {
			return fmt.Errorf("parameter %s must be at most %d characters", name, *schema.MaxLength)
		}
		
		// Enum validation
		if len(schema.Enum) > 0 {
			found := false
			for _, enumValue := range schema.Enum {
				if strValue == enumValue {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("parameter %s must be one of %v", name, schema.Enum)
			}
		}
		
	case "number":
		if _, ok := value.(float64); !ok {
			if _, ok := value.(int); !ok {
				return fmt.Errorf("parameter %s must be a number", name)
			}
		}
		
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("parameter %s must be a boolean", name)
		}
		
	case "array":
		if _, ok := value.([]interface{}); !ok {
			return fmt.Errorf("parameter %s must be an array", name)
		}
		
	case "object":
		if _, ok := value.(map[string]interface{}); !ok {
			return fmt.Errorf("parameter %s must be an object", name)
		}
	}

	return nil
}

// IsHealthy checks if the tool is healthy and ready to use
func (t *BaseTool) IsHealthy(ctx context.Context) bool {
	// Base implementation always returns true
	// Concrete tools can override this to perform actual health checks
	return true
}

// updateExecutionStart updates metrics at the start of execution
func (t *BaseTool) updateExecutionStart() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.metrics.TotalExecutions++
}

// updateExecutionEnd updates metrics at the end of execution
func (t *BaseTool) updateExecutionEnd(duration time.Duration, success bool) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if success {
		t.metrics.SuccessfulRuns++
	} else {
		t.metrics.FailedRuns++
	}

	// Update average latency
	if t.metrics.TotalExecutions == 1 {
		t.metrics.AverageLatency = duration
	} else {
		total := time.Duration(t.metrics.TotalExecutions-1) * t.metrics.AverageLatency
		t.metrics.AverageLatency = (total + duration) / time.Duration(t.metrics.TotalExecutions)
	}

	// Update error rate
	t.metrics.ErrorRate = float64(t.metrics.FailedRuns) / float64(t.metrics.TotalExecutions)
	t.metrics.LastExecutionTime = time.Now()
}

// ToolRegistry manages available tools
type ToolRegistry struct {
	tools map[string]Tool
	mutex sync.RWMutex
	logger *logger.Logger
}

// NewToolRegistry creates a new tool registry
func NewToolRegistry(logger *logger.Logger) *ToolRegistry {
	return &ToolRegistry{
		tools:  make(map[string]Tool),
		logger: logger,
	}
}

// RegisterTool registers a new tool
func (r *ToolRegistry) RegisterTool(tool Tool) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if tool == nil {
		return fmt.Errorf("tool cannot be nil")
	}

	name := tool.Name()
	if name == "" {
		return fmt.Errorf("tool name cannot be empty")
	}

	if _, exists := r.tools[name]; exists {
		return fmt.Errorf("tool %s already registered", name)
	}

	// Validate tool health
	if !tool.IsHealthy(context.Background()) {
		return fmt.Errorf("tool %s is not healthy", name)
	}

	r.tools[name] = tool

	r.logger.Info("Tool registered",
		"tool_name", name,
		"description", tool.Description())

	return nil
}

// UnregisterTool unregisters a tool
func (r *ToolRegistry) UnregisterTool(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.tools[name]; !exists {
		return fmt.Errorf("tool %s not found", name)
	}

	delete(r.tools, name)

	r.logger.Info("Tool unregistered",
		"tool_name", name)

	return nil
}

// GetTool retrieves a tool by name
func (r *ToolRegistry) GetTool(name string) (Tool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	tool, exists := r.tools[name]
	if !exists {
		return nil, fmt.Errorf("tool %s not found", name)
	}

	return tool, nil
}

// ListTools returns a list of all registered tool names
func (r *ToolRegistry) ListTools() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}

	return names
}

// GetAllTools returns all registered tools
func (r *ToolRegistry) GetAllTools() map[string]Tool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Return a copy to prevent external modification
	tools := make(map[string]Tool)
	for name, tool := range r.tools {
		tools[name] = tool
	}

	return tools
}

// GetToolsByType returns tools of a specific type (based on name patterns or metadata)
func (r *ToolRegistry) GetToolsByType(toolType string) []Tool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var tools []Tool
	for _, tool := range r.tools {
		// Simple type matching based on name prefix
		// In a more sophisticated implementation, tools could have explicit types
		if len(tool.Name()) > len(toolType) && tool.Name()[:len(toolType)] == toolType {
			tools = append(tools, tool)
		}
	}

	return tools
}

// HealthCheck checks the health of all registered tools
func (r *ToolRegistry) HealthCheck(ctx context.Context) map[string]bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	health := make(map[string]bool)
	for name, tool := range r.tools {
		health[name] = tool.IsHealthy(ctx)
	}

	return health
}

// GetMetrics returns aggregated metrics for all tools
func (r *ToolRegistry) GetMetrics() map[string]ToolMetrics {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	metrics := make(map[string]ToolMetrics)
	for name, tool := range r.tools {
		metrics[name] = tool.GetMetrics()
	}

	return metrics
}
