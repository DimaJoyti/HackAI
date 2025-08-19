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

// ToolRegistry manages available tools with advanced capabilities
type ToolRegistry struct {
	tools            map[string]Tool
	toolCategories   map[string][]string
	toolValidators   map[string][]ToolValidator
	securityPolicies map[string]ToolSecurityPolicy
	mutex            sync.RWMutex
	logger           *logger.Logger
}

// ToolSecurityPolicy defines security constraints for tool usage
type ToolSecurityPolicy struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	AllowedUsers      []string        `json:"allowed_users"`
	AllowedRoles      []string        `json:"allowed_roles"`
	RequiredSecLevel  SecurityLevel   `json:"required_security_level"`
	MaxUsagePerHour   int             `json:"max_usage_per_hour"`
	MaxUsagePerDay    int             `json:"max_usage_per_day"`
	AllowedTimeRanges []ToolTimeRange `json:"allowed_time_ranges"`
	Enabled           bool            `json:"enabled"`
}

// ToolTimeRange defines allowed time ranges for tool usage
type ToolTimeRange struct {
	StartHour int `json:"start_hour"` // 0-23
	EndHour   int `json:"end_hour"`   // 0-23
}

// ToolCategory defines categories for organizing tools
type ToolCategory string

const (
	CategorySecurity     ToolCategory = "security"
	CategoryAnalysis     ToolCategory = "analysis"
	CategoryPenetration  ToolCategory = "penetration"
	CategoryRecon        ToolCategory = "reconnaissance"
	CategoryExploitation ToolCategory = "exploitation"
	CategoryGeneral      ToolCategory = "general"
)

// NewToolRegistry creates a new tool registry
func NewToolRegistry(logger *logger.Logger) *ToolRegistry {
	return &ToolRegistry{
		tools:            make(map[string]Tool),
		toolCategories:   make(map[string][]string),
		toolValidators:   make(map[string][]ToolValidator),
		securityPolicies: make(map[string]ToolSecurityPolicy),
		logger:           logger,
	}
}

// RegisterTool registers a new tool
func (r *ToolRegistry) RegisterTool(tool Tool) error {
	return r.RegisterToolWithCategory(tool, CategoryGeneral, ToolSecurityPolicy{
		ID:      fmt.Sprintf("default_%s", tool.Name()),
		Name:    fmt.Sprintf("Default policy for %s", tool.Name()),
		Enabled: true,
	})
}

// RegisterToolWithCategory registers a new tool with category and security policy
func (r *ToolRegistry) RegisterToolWithCategory(tool Tool, category ToolCategory, policy ToolSecurityPolicy) error {
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

	// Register the tool
	r.tools[name] = tool

	// Add to category
	categoryStr := string(category)
	if r.toolCategories[categoryStr] == nil {
		r.toolCategories[categoryStr] = make([]string, 0)
	}
	r.toolCategories[categoryStr] = append(r.toolCategories[categoryStr], name)

	// Set security policy
	r.securityPolicies[name] = policy

	if r.logger != nil {
		r.logger.Info("Tool registered",
			"tool_name", name,
			"category", category,
			"description", tool.Description())
	}

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

// Enhanced ToolRegistry methods

// GetToolsByCategory retrieves all tools in a specific category
func (r *ToolRegistry) GetToolsByCategory(category ToolCategory) []Tool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	categoryStr := string(category)
	toolNames, exists := r.toolCategories[categoryStr]
	if !exists {
		return []Tool{}
	}

	tools := make([]Tool, 0, len(toolNames))
	for _, name := range toolNames {
		if tool, exists := r.tools[name]; exists {
			tools = append(tools, tool)
		}
	}

	return tools
}

// AddToolValidator adds a validator for a specific tool
func (r *ToolRegistry) AddToolValidator(toolName string, validator ToolValidator) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.tools[toolName]; !exists {
		return fmt.Errorf("tool %s not found", toolName)
	}

	if r.toolValidators[toolName] == nil {
		r.toolValidators[toolName] = make([]ToolValidator, 0)
	}

	// Check for duplicate validator IDs
	for _, existing := range r.toolValidators[toolName] {
		if existing.ID() == validator.ID() {
			return fmt.Errorf("validator with ID %s already exists for tool %s", validator.ID(), toolName)
		}
	}

	r.toolValidators[toolName] = append(r.toolValidators[toolName], validator)

	if r.logger != nil {
		r.logger.Debug("Tool validator added",
			"tool_name", toolName,
			"validator_id", validator.ID())
	}

	return nil
}

// RemoveToolValidator removes a validator for a specific tool
func (r *ToolRegistry) RemoveToolValidator(toolName, validatorID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	validators, exists := r.toolValidators[toolName]
	if !exists {
		return fmt.Errorf("no validators found for tool %s", toolName)
	}

	for i, validator := range validators {
		if validator.ID() == validatorID {
			r.toolValidators[toolName] = append(validators[:i], validators[i+1:]...)

			if r.logger != nil {
				r.logger.Debug("Tool validator removed",
					"tool_name", toolName,
					"validator_id", validatorID)
			}

			return nil
		}
	}

	return fmt.Errorf("validator with ID %s not found for tool %s", validatorID, toolName)
}

// UpdateSecurityPolicy updates the security policy for a tool
func (r *ToolRegistry) UpdateSecurityPolicy(toolName string, policy ToolSecurityPolicy) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.tools[toolName]; !exists {
		return fmt.Errorf("tool %s not found", toolName)
	}

	r.securityPolicies[toolName] = policy

	if r.logger != nil {
		r.logger.Debug("Security policy updated",
			"tool_name", toolName,
			"policy_id", policy.ID)
	}

	return nil
}

// ExecuteToolWithValidation executes a tool with security validation and metrics tracking
func (r *ToolRegistry) ExecuteToolWithValidation(ctx context.Context, toolName string, input map[string]interface{}, userID string, securityLevel SecurityLevel) (map[string]interface{}, error) {
	ctx, span := toolTracer.Start(ctx, "tool_registry.execute_with_validation",
		trace.WithAttributes(
			attribute.String("tool.name", toolName),
			attribute.String("user.id", userID),
			attribute.String("security.level", string(securityLevel)),
		),
	)
	defer span.End()

	// Get tool
	tool, err := r.GetTool(toolName)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	// Validate security policy
	if err := r.validateSecurityPolicy(toolName, userID, securityLevel); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("security validation failed: %w", err)
	}

	// Run tool validators
	if validators, exists := r.toolValidators[toolName]; exists {
		for _, validator := range validators {
			if err := validator.ValidateTool(ctx, tool, input); err != nil {
				span.RecordError(err)
				return nil, fmt.Errorf("tool validation failed: %w", err)
			}
		}
	}

	// Execute tool
	output, err := tool.Execute(ctx, input)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("tool execution failed: %w", err)
	}

	// Validate output
	if validators, exists := r.toolValidators[toolName]; exists {
		for _, validator := range validators {
			if err := validator.ValidateOutput(ctx, tool, output); err != nil {
				span.RecordError(err)
				return nil, fmt.Errorf("output validation failed: %w", err)
			}
		}
	}

	span.SetAttributes(
		attribute.Bool("execution.success", true),
	)

	return output, nil
}

// validateSecurityPolicy validates if a user can execute a tool based on security policy
func (r *ToolRegistry) validateSecurityPolicy(toolName, userID string, securityLevel SecurityLevel) error {
	policy, exists := r.securityPolicies[toolName]
	if !exists {
		// No policy means no restrictions
		return nil
	}

	if !policy.Enabled {
		return fmt.Errorf("tool %s is disabled", toolName)
	}

	// Check security level
	securityLevels := map[SecurityLevel]int{
		SecurityLevelLow:      1,
		SecurityLevelMedium:   2,
		SecurityLevelHigh:     3,
		SecurityLevelCritical: 4,
	}

	if securityLevels[securityLevel] < securityLevels[policy.RequiredSecLevel] {
		return fmt.Errorf("insufficient security level: required %s, provided %s",
			policy.RequiredSecLevel, securityLevel)
	}

	// Check user permissions
	if len(policy.AllowedUsers) > 0 {
		allowed := false
		for _, allowedUser := range policy.AllowedUsers {
			if allowedUser == userID {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("user %s not authorized to use tool %s", userID, toolName)
		}
	}

	// Check time restrictions
	if len(policy.AllowedTimeRanges) > 0 {
		currentHour := time.Now().Hour()
		allowed := false
		for _, timeRange := range policy.AllowedTimeRanges {
			if currentHour >= timeRange.StartHour && currentHour <= timeRange.EndHour {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("tool %s not available at current time", toolName)
		}
	}

	return nil
}

// GetCategories returns all available tool categories
func (r *ToolRegistry) GetCategories() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	categories := make([]string, 0, len(r.toolCategories))
	for category := range r.toolCategories {
		categories = append(categories, category)
	}

	return categories
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
