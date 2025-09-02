package tools

import (
	"context"
	"fmt"
	"time"
)

// Tool interface defines the contract for all tools
type Tool interface {
	// ID returns the unique identifier for the tool
	ID() string

	// Name returns the human-readable name of the tool
	Name() string

	// Description returns a description of what the tool does
	Description() string

	// Execute executes the tool with the given input
	Execute(ctx context.Context, input map[string]interface{}) (interface{}, error)
}

// ValidatableTool interface for tools that support input validation
type ValidatableTool interface {
	Tool
	Validate(input map[string]interface{}) error
}

// ConfigurableTool interface for tools that support configuration
type ConfigurableTool interface {
	Tool
	Configure(config map[string]interface{}) error
	GetConfig() map[string]interface{}
}

// MetricsTool interface for tools that provide metrics
type MetricsTool interface {
	Tool
	GetMetrics() ToolMetrics
	ResetMetrics()
}

// ToolMetrics holds metrics for tool execution
type ToolMetrics struct {
	ExecutionCount int64         `json:"execution_count"`
	SuccessCount   int64         `json:"success_count"`
	ErrorCount     int64         `json:"error_count"`
	AverageLatency time.Duration `json:"average_latency"`
	LastExecuted   time.Time     `json:"last_executed"`
	TotalLatency   time.Duration `json:"total_latency"`
}

// ToolInput represents input to a tool
type ToolInput map[string]interface{}

// GetString safely gets a string value from the input
func (ti ToolInput) GetString(key string) string {
	if value, exists := ti[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// GetInt safely gets an int value from the input
func (ti ToolInput) GetInt(key string) int {
	if value, exists := ti[key]; exists {
		switch v := value.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		}
	}
	return 0
}

// GetFloat safely gets a float64 value from the input
func (ti ToolInput) GetFloat(key string) float64 {
	if value, exists := ti[key]; exists {
		switch v := value.(type) {
		case float64:
			return v
		case float32:
			return float64(v)
		case int:
			return float64(v)
		case int64:
			return float64(v)
		}
	}
	return 0.0
}

// GetBool safely gets a bool value from the input
func (ti ToolInput) GetBool(key string) bool {
	if value, exists := ti[key]; exists {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return false
}

// GetMap safely gets a map value from the input
func (ti ToolInput) GetMap(key string) map[string]interface{} {
	if value, exists := ti[key]; exists {
		if m, ok := value.(map[string]interface{}); ok {
			return m
		}
	}
	return make(map[string]interface{})
}

// GetSlice safely gets a slice value from the input
func (ti ToolInput) GetSlice(key string) []interface{} {
	if value, exists := ti[key]; exists {
		if s, ok := value.([]interface{}); ok {
			return s
		}
	}
	return make([]interface{}, 0)
}

// HasField checks if a field exists in the input
func (ti ToolInput) HasField(key string) bool {
	_, exists := ti[key]
	return exists
}

// Validate validates that required fields are present
func (ti ToolInput) Validate(requiredFields []string) error {
	for _, field := range requiredFields {
		if !ti.HasField(field) {
			return fmt.Errorf("required field '%s' is missing", field)
		}
	}
	return nil
}

// ToolOutput represents output from a tool
type ToolOutput struct {
	Success  bool                   `json:"success"`
	Data     interface{}            `json:"data"`
	Error    string                 `json:"error,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ToolCategory represents different categories of tools
type ToolCategory string

const (
	CategoryAnalysis      ToolCategory = "analysis"
	CategorySecurity      ToolCategory = "security"
	CategoryData          ToolCategory = "data"
	CategoryCommunication ToolCategory = "communication"
	CategoryUtility       ToolCategory = "utility"
	CategoryIntegration   ToolCategory = "integration"
	CategoryReporting     ToolCategory = "reporting"
)

// ToolCapability represents capabilities that tools can have
type ToolCapability string

const (
	CapabilityAsync     ToolCapability = "async"
	CapabilityBatch     ToolCapability = "batch"
	CapabilityStreaming ToolCapability = "streaming"
	CapabilityRetryable ToolCapability = "retryable"
	CapabilityCacheable ToolCapability = "cacheable"
	CapabilityStateful  ToolCapability = "stateful"
)

// ToolInfo provides metadata about a tool
type ToolInfo struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Category     ToolCategory     `json:"category"`
	Capabilities []ToolCapability `json:"capabilities"`
	Version      string           `json:"version"`
	Author       string           `json:"author"`
	InputSchema  interface{}      `json:"input_schema,omitempty"`
	OutputSchema interface{}      `json:"output_schema,omitempty"`
	Examples     []ToolExample    `json:"examples,omitempty"`
}

// ToolExample provides usage examples for a tool
type ToolExample struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Input       map[string]interface{} `json:"input"`
	Output      interface{}            `json:"output"`
}

// ExtendedTool interface for tools with additional metadata
type ExtendedTool interface {
	Tool
	GetInfo() ToolInfo
	GetCategory() ToolCategory
	GetCapabilities() []ToolCapability
	GetExamples() []ToolExample
}

// BaseTool provides a base implementation for tools
type BaseTool struct {
	id           string
	name         string
	description  string
	category     ToolCategory
	capabilities []ToolCapability
	version      string
	author       string
	metrics      ToolMetrics
}

// NewBaseTool creates a new base tool
func NewBaseTool(id, name, description string, category ToolCategory) *BaseTool {
	return &BaseTool{
		id:           id,
		name:         name,
		description:  description,
		category:     category,
		capabilities: make([]ToolCapability, 0),
		version:      "1.0.0",
		author:       "HackAI",
		metrics:      ToolMetrics{},
	}
}

// ID returns the tool ID
func (bt *BaseTool) ID() string {
	return bt.id
}

// Name returns the tool name
func (bt *BaseTool) Name() string {
	return bt.name
}

// Description returns the tool description
func (bt *BaseTool) Description() string {
	return bt.description
}

// GetInfo returns tool information
func (bt *BaseTool) GetInfo() ToolInfo {
	return ToolInfo{
		ID:           bt.id,
		Name:         bt.name,
		Description:  bt.description,
		Category:     bt.category,
		Capabilities: bt.capabilities,
		Version:      bt.version,
		Author:       bt.author,
	}
}

// GetCategory returns the tool category
func (bt *BaseTool) GetCategory() ToolCategory {
	return bt.category
}

// GetCapabilities returns the tool capabilities
func (bt *BaseTool) GetCapabilities() []ToolCapability {
	return bt.capabilities
}

// AddCapability adds a capability to the tool
func (bt *BaseTool) AddCapability(capability ToolCapability) {
	bt.capabilities = append(bt.capabilities, capability)
}

// HasCapability checks if the tool has a specific capability
func (bt *BaseTool) HasCapability(capability ToolCapability) bool {
	for _, cap := range bt.capabilities {
		if cap == capability {
			return true
		}
	}
	return false
}

// GetMetrics returns tool metrics
func (bt *BaseTool) GetMetrics() ToolMetrics {
	return bt.metrics
}

// ResetMetrics resets tool metrics
func (bt *BaseTool) ResetMetrics() {
	bt.metrics = ToolMetrics{}
}

// UpdateMetrics updates tool metrics after execution
func (bt *BaseTool) UpdateMetrics(success bool, latency time.Duration) {
	bt.metrics.ExecutionCount++
	bt.metrics.LastExecuted = time.Now()
	bt.metrics.TotalLatency += latency

	if success {
		bt.metrics.SuccessCount++
	} else {
		bt.metrics.ErrorCount++
	}

	// Calculate average latency
	if bt.metrics.ExecutionCount > 0 {
		bt.metrics.AverageLatency = bt.metrics.TotalLatency / time.Duration(bt.metrics.ExecutionCount)
	}
}

// SetVersion sets the tool version
func (bt *BaseTool) SetVersion(version string) {
	bt.version = version
}

// SetAuthor sets the tool author
func (bt *BaseTool) SetAuthor(author string) {
	bt.author = author
}

// ToolError represents an error from tool execution
type ToolError struct {
	ToolID    string `json:"tool_id"`
	Message   string `json:"message"`
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
	Cause     error  `json:"cause,omitempty"`
}

// Error implements the error interface
func (te *ToolError) Error() string {
	return fmt.Sprintf("tool %s error [%s]: %s", te.ToolID, te.Code, te.Message)
}

// Unwrap returns the underlying error
func (te *ToolError) Unwrap() error {
	return te.Cause
}

// NewToolError creates a new tool error
func NewToolError(toolID, code, message string, retryable bool, cause error) *ToolError {
	return &ToolError{
		ToolID:    toolID,
		Code:      code,
		Message:   message,
		Retryable: retryable,
		Cause:     cause,
	}
}

// Common error codes
const (
	ErrorCodeInvalidInput     = "INVALID_INPUT"
	ErrorCodeTimeout          = "TIMEOUT"
	ErrorCodeNetworkError     = "NETWORK_ERROR"
	ErrorCodeAuthError        = "AUTH_ERROR"
	ErrorCodeRateLimit        = "RATE_LIMIT"
	ErrorCodeInternalError    = "INTERNAL_ERROR"
	ErrorCodeNotFound         = "NOT_FOUND"
	ErrorCodePermissionDenied = "PERMISSION_DENIED"
	ErrorCodeConfigError      = "CONFIG_ERROR"
)

// IsRetryableError checks if an error is retryable
func IsRetryableError(err error) bool {
	if toolErr, ok := err.(*ToolError); ok {
		return toolErr.Retryable
	}
	return false
}

// GetErrorCode extracts the error code from an error
func GetErrorCode(err error) string {
	if toolErr, ok := err.(*ToolError); ok {
		return toolErr.Code
	}
	return ErrorCodeInternalError
}
