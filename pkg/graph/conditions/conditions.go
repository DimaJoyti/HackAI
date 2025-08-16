package conditions

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/dimajoyti/hackai/pkg/llm"
)

// AlwaysCondition always evaluates to true
type AlwaysCondition struct{}

// Evaluate always returns true
func (c *AlwaysCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	return true, nil
}

// String returns a string representation
func (c *AlwaysCondition) String() string {
	return "always"
}

// NeverCondition always evaluates to false
type NeverCondition struct{}

// Evaluate always returns false
func (c *NeverCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	return false, nil
}

// String returns a string representation
func (c *NeverCondition) String() string {
	return "never"
}

// DataCondition evaluates based on data in the graph state
type DataCondition struct {
	Key      string      `json:"key"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// Evaluate evaluates the condition based on state data
func (c *DataCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	if state.Data == nil {
		return false, fmt.Errorf("state data is nil")
	}

	actualValue, exists := state.Data[c.Key]
	if !exists {
		return false, fmt.Errorf("key %s not found in state data", c.Key)
	}

	return c.compareValues(actualValue, c.Value, c.Operator)
}

// String returns a string representation
func (c *DataCondition) String() string {
	return fmt.Sprintf("data[%s] %s %v", c.Key, c.Operator, c.Value)
}

// compareValues compares two values using the specified operator
func (c *DataCondition) compareValues(actual, expected interface{}, operator string) (bool, error) {
	switch operator {
	case "==", "eq":
		return reflect.DeepEqual(actual, expected), nil
	case "!=", "ne":
		return !reflect.DeepEqual(actual, expected), nil
	case ">", "gt":
		return c.compareNumeric(actual, expected, func(a, b float64) bool { return a > b })
	case ">=", "gte":
		return c.compareNumeric(actual, expected, func(a, b float64) bool { return a >= b })
	case "<", "lt":
		return c.compareNumeric(actual, expected, func(a, b float64) bool { return a < b })
	case "<=", "lte":
		return c.compareNumeric(actual, expected, func(a, b float64) bool { return a <= b })
	case "contains":
		return c.containsCheck(actual, expected)
	case "starts_with":
		return c.startsWithCheck(actual, expected)
	case "ends_with":
		return c.endsWithCheck(actual, expected)
	case "regex":
		return c.regexCheck(actual, expected)
	default:
		return false, fmt.Errorf("unsupported operator: %s", operator)
	}
}

// compareNumeric compares numeric values
func (c *DataCondition) compareNumeric(actual, expected interface{}, compareFn func(float64, float64) bool) (bool, error) {
	actualFloat, err := c.toFloat64(actual)
	if err != nil {
		return false, fmt.Errorf("cannot convert actual value to number: %w", err)
	}

	expectedFloat, err := c.toFloat64(expected)
	if err != nil {
		return false, fmt.Errorf("cannot convert expected value to number: %w", err)
	}

	return compareFn(actualFloat, expectedFloat), nil
}

// toFloat64 converts various numeric types to float64
func (c *DataCondition) toFloat64(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("unsupported type: %T", value)
	}
}

// containsCheck checks if actual contains expected
func (c *DataCondition) containsCheck(actual, expected interface{}) (bool, error) {
	actualStr, ok := actual.(string)
	if !ok {
		return false, fmt.Errorf("contains operator requires string actual value")
	}

	expectedStr, ok := expected.(string)
	if !ok {
		return false, fmt.Errorf("contains operator requires string expected value")
	}

	return strings.Contains(actualStr, expectedStr), nil
}

// startsWithCheck checks if actual starts with expected
func (c *DataCondition) startsWithCheck(actual, expected interface{}) (bool, error) {
	actualStr, ok := actual.(string)
	if !ok {
		return false, fmt.Errorf("starts_with operator requires string actual value")
	}

	expectedStr, ok := expected.(string)
	if !ok {
		return false, fmt.Errorf("starts_with operator requires string expected value")
	}

	return strings.HasPrefix(actualStr, expectedStr), nil
}

// endsWithCheck checks if actual ends with expected
func (c *DataCondition) endsWithCheck(actual, expected interface{}) (bool, error) {
	actualStr, ok := actual.(string)
	if !ok {
		return false, fmt.Errorf("ends_with operator requires string actual value")
	}

	expectedStr, ok := expected.(string)
	if !ok {
		return false, fmt.Errorf("ends_with operator requires string expected value")
	}

	return strings.HasSuffix(actualStr, expectedStr), nil
}

// regexCheck checks if actual matches expected regex pattern
func (c *DataCondition) regexCheck(actual, expected interface{}) (bool, error) {
	// For now, implement as contains check
	// In a full implementation, you'd use regexp package
	return c.containsCheck(actual, expected)
}

// AndCondition evaluates multiple conditions with AND logic
type AndCondition struct {
	Conditions []llm.Condition `json:"conditions"`
}

// Evaluate evaluates all conditions with AND logic
func (c *AndCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	for _, condition := range c.Conditions {
		result, err := condition.Evaluate(ctx, state)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil
		}
	}
	return true, nil
}

// String returns a string representation
func (c *AndCondition) String() string {
	parts := make([]string, len(c.Conditions))
	for i, condition := range c.Conditions {
		parts[i] = condition.String()
	}
	return fmt.Sprintf("(%s)", strings.Join(parts, " AND "))
}

// OrCondition evaluates multiple conditions with OR logic
type OrCondition struct {
	Conditions []llm.Condition `json:"conditions"`
}

// Evaluate evaluates all conditions with OR logic
func (c *OrCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	for _, condition := range c.Conditions {
		result, err := condition.Evaluate(ctx, state)
		if err != nil {
			return false, err
		}
		if result {
			return true, nil
		}
	}
	return false, nil
}

// String returns a string representation
func (c *OrCondition) String() string {
	parts := make([]string, len(c.Conditions))
	for i, condition := range c.Conditions {
		parts[i] = condition.String()
	}
	return fmt.Sprintf("(%s)", strings.Join(parts, " OR "))
}

// NotCondition negates another condition
type NotCondition struct {
	Condition llm.Condition `json:"condition"`
}

// Evaluate negates the wrapped condition
func (c *NotCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	result, err := c.Condition.Evaluate(ctx, state)
	if err != nil {
		return false, err
	}
	return !result, nil
}

// String returns a string representation
func (c *NotCondition) String() string {
	return fmt.Sprintf("NOT (%s)", c.Condition.String())
}

// SuccessCondition checks if the previous operation was successful
type SuccessCondition struct {
	Key string `json:"key"` // Optional key to check specific success status
}

// Evaluate checks for success status in state data
func (c *SuccessCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	if state.Data == nil {
		return false, nil
	}

	key := "success"
	if c.Key != "" {
		key = c.Key
	}

	success, exists := state.Data[key]
	if !exists {
		return false, nil
	}

	successBool, ok := success.(bool)
	if !ok {
		return false, fmt.Errorf("success value is not boolean")
	}

	return successBool, nil
}

// String returns a string representation
func (c *SuccessCondition) String() string {
	if c.Key != "" {
		return fmt.Sprintf("success[%s]", c.Key)
	}
	return "success"
}

// ErrorCondition checks if there was an error in the previous operation
type ErrorCondition struct {
	Key string `json:"key"` // Optional key to check specific error
}

// Evaluate checks for error status in state data
func (c *ErrorCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	if state.Data == nil {
		return false, nil
	}

	key := "error"
	if c.Key != "" {
		key = c.Key
	}

	errorValue, exists := state.Data[key]
	if !exists {
		return false, nil
	}

	// Check if error is non-nil/non-empty
	if errorValue == nil {
		return false, nil
	}

	if errorStr, ok := errorValue.(string); ok {
		return errorStr != "", nil
	}

	return true, nil
}

// String returns a string representation
func (c *ErrorCondition) String() string {
	if c.Key != "" {
		return fmt.Sprintf("error[%s]", c.Key)
	}
	return "error"
}

// CountCondition checks if a count meets certain criteria
type CountCondition struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`
	Value    int    `json:"value"`
}

// Evaluate checks count conditions
func (c *CountCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	if state.Data == nil {
		return false, fmt.Errorf("state data is nil")
	}

	countValue, exists := state.Data[c.Key]
	if !exists {
		return false, fmt.Errorf("key %s not found in state data", c.Key)
	}

	count, ok := countValue.(int)
	if !ok {
		// Try to convert from float64 (common in JSON)
		if countFloat, ok := countValue.(float64); ok {
			count = int(countFloat)
		} else {
			return false, fmt.Errorf("count value is not numeric")
		}
	}

	switch c.Operator {
	case "==", "eq":
		return count == c.Value, nil
	case "!=", "ne":
		return count != c.Value, nil
	case ">", "gt":
		return count > c.Value, nil
	case ">=", "gte":
		return count >= c.Value, nil
	case "<", "lt":
		return count < c.Value, nil
	case "<=", "lte":
		return count <= c.Value, nil
	default:
		return false, fmt.Errorf("unsupported operator: %s", c.Operator)
	}
}

// String returns a string representation
func (c *CountCondition) String() string {
	return fmt.Sprintf("count[%s] %s %d", c.Key, c.Operator, c.Value)
}

// NewDataCondition creates a new data condition
func NewDataCondition(key, operator string, value interface{}) *DataCondition {
	return &DataCondition{
		Key:      key,
		Operator: operator,
		Value:    value,
	}
}

// NewAndCondition creates a new AND condition
func NewAndCondition(conditions ...llm.Condition) *AndCondition {
	return &AndCondition{
		Conditions: conditions,
	}
}

// NewOrCondition creates a new OR condition
func NewOrCondition(conditions ...llm.Condition) *OrCondition {
	return &OrCondition{
		Conditions: conditions,
	}
}

// NewNotCondition creates a new NOT condition
func NewNotCondition(condition llm.Condition) *NotCondition {
	return &NotCondition{
		Condition: condition,
	}
}

// NewSuccessCondition creates a new success condition
func NewSuccessCondition(key string) *SuccessCondition {
	return &SuccessCondition{
		Key: key,
	}
}

// NewErrorCondition creates a new error condition
func NewErrorCondition(key string) *ErrorCondition {
	return &ErrorCondition{
		Key: key,
	}
}

// NewCountCondition creates a new count condition
func NewCountCondition(key, operator string, value int) *CountCondition {
	return &CountCondition{
		Key:      key,
		Operator: operator,
		Value:    value,
	}
}
