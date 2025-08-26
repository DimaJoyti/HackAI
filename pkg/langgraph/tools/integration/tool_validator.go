package integration

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// ToolValidator validates tools and their inputs
type ToolValidator struct {
	mode   ValidationMode
	logger *logger.Logger
	rules  map[string]*ValidationRule
}

// ValidationRule defines a validation rule
type ValidationRule struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        ValidationRuleType     `json:"type"`
	Pattern     string                 `json:"pattern,omitempty"`
	MinValue    *float64               `json:"min_value,omitempty"`
	MaxValue    *float64               `json:"max_value,omitempty"`
	Required    bool                   `json:"required"`
	Custom      func(interface{}) bool `json:"-"`
	Message     string                 `json:"message"`
}

// ValidationRuleType defines types of validation rules
type ValidationRuleType string

const (
	ValidationRuleTypeString  ValidationRuleType = "string"
	ValidationRuleTypeNumber  ValidationRuleType = "number"
	ValidationRuleTypeBoolean ValidationRuleType = "boolean"
	ValidationRuleTypeArray   ValidationRuleType = "array"
	ValidationRuleTypeObject  ValidationRuleType = "object"
	ValidationRuleTypePattern ValidationRuleType = "pattern"
	ValidationRuleTypeRange   ValidationRuleType = "range"
	ValidationRuleTypeCustom  ValidationRuleType = "custom"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string      `json:"field"`
	Rule    string      `json:"rule"`
	Message string      `json:"message"`
	Value   interface{} `json:"value"`
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", ve.Field, ve.Message)
}

// ValidationResult holds the result of validation
type ValidationResult struct {
	Valid  bool               `json:"valid"`
	Errors []*ValidationError `json:"errors"`
}

// Error implements the error interface for ValidationResult
func (vr *ValidationResult) Error() string {
	if len(vr.Errors) == 0 {
		return "validation failed"
	}

	var messages []string
	for _, err := range vr.Errors {
		messages = append(messages, err.Error())
	}
	return fmt.Sprintf("validation failed: %s", strings.Join(messages, "; "))
}

// NewToolValidator creates a new tool validator
func NewToolValidator(mode ValidationMode, logger *logger.Logger) *ToolValidator {
	validator := &ToolValidator{
		mode:   mode,
		logger: logger,
		rules:  make(map[string]*ValidationRule),
	}

	// Initialize default validation rules
	validator.initializeDefaultRules()

	return validator
}

// ValidateTool validates a tool implementation
func (tv *ToolValidator) ValidateTool(ctx context.Context, tool tools.Tool) error {
	if tv.mode == ValidationModeNone {
		return nil
	}

	var errors []*ValidationError

	// Basic tool validation
	if tool.ID() == "" {
		errors = append(errors, &ValidationError{
			Field:   "id",
			Rule:    "required",
			Message: "tool ID cannot be empty",
			Value:   tool.ID(),
		})
	}

	if tool.Name() == "" {
		errors = append(errors, &ValidationError{
			Field:   "name",
			Rule:    "required",
			Message: "tool name cannot be empty",
			Value:   tool.Name(),
		})
	}

	if tool.Description() == "" {
		errors = append(errors, &ValidationError{
			Field:   "description",
			Rule:    "required",
			Message: "tool description cannot be empty",
			Value:   tool.Description(),
		})
	}

	// Validate tool ID format
	if !tv.isValidToolID(tool.ID()) {
		errors = append(errors, &ValidationError{
			Field:   "id",
			Rule:    "format",
			Message: "tool ID must contain only alphanumeric characters, hyphens, and underscores",
			Value:   tool.ID(),
		})
	}

	// Validate tool name format
	if !tv.isValidToolName(tool.Name()) {
		errors = append(errors, &ValidationError{
			Field:   "name",
			Rule:    "format",
			Message: "tool name must be between 3 and 50 characters",
			Value:   tool.Name(),
		})
	}

	// Test tool execution if in strict mode
	if tv.mode == ValidationModeStrict {
		if err := tv.testToolExecution(ctx, tool); err != nil {
			errors = append(errors, &ValidationError{
				Field:   "execution",
				Rule:    "functionality",
				Message: fmt.Sprintf("tool execution test failed: %v", err),
				Value:   nil,
			})
		}
	}

	// Check if tool implements recommended interfaces
	tv.validateToolInterfaces(tool, &errors)

	if len(errors) > 0 {
		return &ValidationResult{
			Valid:  false,
			Errors: errors,
		}
	}

	tv.logger.Debug("Tool validation passed", "tool_id", tool.ID())
	return nil
}

// ValidateInput validates tool input against rules
func (tv *ToolValidator) ValidateInput(input map[string]interface{}, rules map[string]*ValidationRule) error {
	if tv.mode == ValidationModeNone {
		return nil
	}

	var errors []*ValidationError

	// Check required fields
	for fieldName, rule := range rules {
		value, exists := input[fieldName]

		if rule.Required && !exists {
			errors = append(errors, &ValidationError{
				Field:   fieldName,
				Rule:    "required",
				Message: fmt.Sprintf("field '%s' is required", fieldName),
				Value:   nil,
			})
			continue
		}

		if exists {
			if err := tv.validateFieldValue(fieldName, value, rule); err != nil {
				errors = append(errors, err)
			}
		}
	}

	// Check for unexpected fields in strict mode
	if tv.mode == ValidationModeStrict {
		for fieldName := range input {
			if _, exists := rules[fieldName]; !exists {
				errors = append(errors, &ValidationError{
					Field:   fieldName,
					Rule:    "unexpected",
					Message: fmt.Sprintf("unexpected field '%s'", fieldName),
					Value:   input[fieldName],
				})
			}
		}
	}

	if len(errors) > 0 {
		return &ValidationResult{
			Valid:  false,
			Errors: errors,
		}
	}

	return nil
}

// AddValidationRule adds a custom validation rule
func (tv *ToolValidator) AddValidationRule(name string, rule *ValidationRule) {
	tv.rules[name] = rule
}

// GetValidationRule retrieves a validation rule
func (tv *ToolValidator) GetValidationRule(name string) (*ValidationRule, bool) {
	rule, exists := tv.rules[name]
	return rule, exists
}

// Helper methods

func (tv *ToolValidator) initializeDefaultRules() {
	// String validation rules
	tv.rules["non_empty_string"] = &ValidationRule{
		Name:        "non_empty_string",
		Description: "String must not be empty",
		Type:        ValidationRuleTypeString,
		Custom: func(value interface{}) bool {
			if str, ok := value.(string); ok {
				return strings.TrimSpace(str) != ""
			}
			return false
		},
		Message: "string cannot be empty",
	}

	// Email validation rule
	tv.rules["email"] = &ValidationRule{
		Name:        "email",
		Description: "Valid email address",
		Type:        ValidationRuleTypePattern,
		Pattern:     `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
		Message:     "must be a valid email address",
	}

	// URL validation rule
	tv.rules["url"] = &ValidationRule{
		Name:        "url",
		Description: "Valid URL",
		Type:        ValidationRuleTypePattern,
		Pattern:     `^https?://[^\s/$.?#].[^\s]*$`,
		Message:     "must be a valid URL",
	}

	// Positive number rule
	tv.rules["positive_number"] = &ValidationRule{
		Name:        "positive_number",
		Description: "Positive number",
		Type:        ValidationRuleTypeRange,
		MinValue:    &[]float64{0}[0],
		Message:     "must be a positive number",
	}

	// Port number rule
	tv.rules["port_number"] = &ValidationRule{
		Name:        "port_number",
		Description: "Valid port number",
		Type:        ValidationRuleTypeRange,
		MinValue:    &[]float64{1}[0],
		MaxValue:    &[]float64{65535}[0],
		Message:     "must be a valid port number (1-65535)",
	}
}

func (tv *ToolValidator) isValidToolID(id string) bool {
	// Tool ID should contain only alphanumeric characters, hyphens, and underscores
	pattern := `^[a-zA-Z0-9_-]+$`
	matched, _ := regexp.MatchString(pattern, id)
	return matched && len(id) >= 3 && len(id) <= 50
}

func (tv *ToolValidator) isValidToolName(name string) bool {
	// Tool name should be between 3 and 50 characters
	return len(strings.TrimSpace(name)) >= 3 && len(name) <= 50
}

func (tv *ToolValidator) testToolExecution(ctx context.Context, tool tools.Tool) error {
	// Create minimal test input
	testInput := make(map[string]interface{})

	// If tool supports validation, get required fields
	if validatable, ok := tool.(tools.ValidatableTool); ok {
		// Try with empty input first
		if err := validatable.Validate(testInput); err != nil {
			// If validation fails, we can't test execution
			tv.logger.Debug("Tool validation test skipped due to required fields",
				"tool_id", tool.ID(),
				"error", err)
			return nil
		}
	}

	// Try to execute with test input
	// Use a short timeout for testing
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := tool.Execute(testCtx, testInput)

	// We don't care about the actual result, just that it doesn't panic or crash
	// Some errors are expected (like missing required parameters)
	if err != nil {
		// Check if it's a validation error (acceptable)
		if strings.Contains(err.Error(), "required") ||
			strings.Contains(err.Error(), "validation") ||
			strings.Contains(err.Error(), "missing") {
			return nil
		}

		// Other errors might indicate implementation issues
		return err
	}

	return nil
}

func (tv *ToolValidator) validateToolInterfaces(tool tools.Tool, errors *[]*ValidationError) {
	toolType := reflect.TypeOf(tool)

	// Check if tool implements ValidatableTool (recommended)
	if _, ok := tool.(tools.ValidatableTool); !ok {
		*errors = append(*errors, &ValidationError{
			Field:   "interfaces",
			Rule:    "recommended",
			Message: "tool should implement ValidatableTool interface for better input validation",
			Value:   toolType.String(),
		})
	}

	// Check if tool implements ConfigurableTool (recommended for complex tools)
	if _, ok := tool.(tools.ConfigurableTool); !ok && tv.mode == ValidationModeStrict {
		*errors = append(*errors, &ValidationError{
			Field:   "interfaces",
			Rule:    "recommended",
			Message: "complex tools should implement ConfigurableTool interface",
			Value:   toolType.String(),
		})
	}

	// Check if tool implements MetricsTool (recommended for production)
	if _, ok := tool.(tools.MetricsTool); !ok && tv.mode == ValidationModeStrict {
		*errors = append(*errors, &ValidationError{
			Field:   "interfaces",
			Rule:    "recommended",
			Message: "production tools should implement MetricsTool interface",
			Value:   toolType.String(),
		})
	}
}

func (tv *ToolValidator) validateFieldValue(fieldName string, value interface{}, rule *ValidationRule) *ValidationError {
	switch rule.Type {
	case ValidationRuleTypeString:
		return tv.validateStringField(fieldName, value, rule)
	case ValidationRuleTypeNumber:
		return tv.validateNumberField(fieldName, value, rule)
	case ValidationRuleTypeBoolean:
		return tv.validateBooleanField(fieldName, value, rule)
	case ValidationRuleTypeArray:
		return tv.validateArrayField(fieldName, value, rule)
	case ValidationRuleTypeObject:
		return tv.validateObjectField(fieldName, value, rule)
	case ValidationRuleTypePattern:
		return tv.validatePatternField(fieldName, value, rule)
	case ValidationRuleTypeRange:
		return tv.validateRangeField(fieldName, value, rule)
	case ValidationRuleTypeCustom:
		return tv.validateCustomField(fieldName, value, rule)
	default:
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: fmt.Sprintf("unknown validation rule type: %s", rule.Type),
			Value:   value,
		}
	}
}

func (tv *ToolValidator) validateStringField(fieldName string, value interface{}, rule *ValidationRule) *ValidationError {
	str, ok := value.(string)
	if !ok {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: "value must be a string",
			Value:   value,
		}
	}

	if rule.Custom != nil && !rule.Custom(str) {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: rule.Message,
			Value:   value,
		}
	}

	return nil
}

func (tv *ToolValidator) validateNumberField(fieldName string, value interface{}, rule *ValidationRule) *ValidationError {
	var num float64
	var ok bool

	switch v := value.(type) {
	case int:
		num = float64(v)
		ok = true
	case int64:
		num = float64(v)
		ok = true
	case float32:
		num = float64(v)
		ok = true
	case float64:
		num = v
		ok = true
	}

	if !ok {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: "value must be a number",
			Value:   value,
		}
	}

	if rule.MinValue != nil && num < *rule.MinValue {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: fmt.Sprintf("value must be at least %f", *rule.MinValue),
			Value:   value,
		}
	}

	if rule.MaxValue != nil && num > *rule.MaxValue {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: fmt.Sprintf("value must be at most %f", *rule.MaxValue),
			Value:   value,
		}
	}

	return nil
}

func (tv *ToolValidator) validateBooleanField(fieldName string, value interface{}, rule *ValidationRule) *ValidationError {
	if _, ok := value.(bool); !ok {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: "value must be a boolean",
			Value:   value,
		}
	}

	return nil
}

func (tv *ToolValidator) validateArrayField(fieldName string, value interface{}, rule *ValidationRule) *ValidationError {
	if reflect.TypeOf(value).Kind() != reflect.Slice {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: "value must be an array",
			Value:   value,
		}
	}

	return nil
}

func (tv *ToolValidator) validateObjectField(fieldName string, value interface{}, rule *ValidationRule) *ValidationError {
	if reflect.TypeOf(value).Kind() != reflect.Map {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: "value must be an object",
			Value:   value,
		}
	}

	return nil
}

func (tv *ToolValidator) validatePatternField(fieldName string, value interface{}, rule *ValidationRule) *ValidationError {
	str, ok := value.(string)
	if !ok {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: "value must be a string for pattern validation",
			Value:   value,
		}
	}

	matched, err := regexp.MatchString(rule.Pattern, str)
	if err != nil {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: fmt.Sprintf("invalid pattern: %v", err),
			Value:   value,
		}
	}

	if !matched {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: rule.Message,
			Value:   value,
		}
	}

	return nil
}

func (tv *ToolValidator) validateRangeField(fieldName string, value interface{}, rule *ValidationRule) *ValidationError {
	return tv.validateNumberField(fieldName, value, rule)
}

func (tv *ToolValidator) validateCustomField(fieldName string, value interface{}, rule *ValidationRule) *ValidationError {
	if rule.Custom == nil {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: "custom validation function not provided",
			Value:   value,
		}
	}

	if !rule.Custom(value) {
		return &ValidationError{
			Field:   fieldName,
			Rule:    rule.Name,
			Message: rule.Message,
			Value:   value,
		}
	}

	return nil
}
