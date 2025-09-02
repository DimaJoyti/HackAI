package graph

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/dimajoyti/hackai/pkg/llm"
)

// AlwaysCondition always returns true
type AlwaysCondition struct{}

// NewAlwaysCondition creates a condition that always returns true
func NewAlwaysCondition() *AlwaysCondition {
	return &AlwaysCondition{}
}

// Evaluate always returns true
func (c *AlwaysCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	return true, nil
}

// String returns a string representation
func (c *AlwaysCondition) String() string {
	return "always"
}

// NeverCondition always returns false
type NeverCondition struct{}

// NewNeverCondition creates a condition that always returns false
func NewNeverCondition() *NeverCondition {
	return &NeverCondition{}
}

// Evaluate always returns false
func (c *NeverCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	return false, nil
}

// String returns a string representation
func (c *NeverCondition) String() string {
	return "never"
}

// FieldExistsCondition checks if a field exists in the state
type FieldExistsCondition struct {
	fieldName string
}

// NewFieldExistsCondition creates a condition that checks if a field exists
func NewFieldExistsCondition(fieldName string) *FieldExistsCondition {
	return &FieldExistsCondition{fieldName: fieldName}
}

// Evaluate checks if the field exists in the state
func (c *FieldExistsCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	_, exists := state.Data[c.fieldName]
	return exists, nil
}

// String returns a string representation
func (c *FieldExistsCondition) String() string {
	return fmt.Sprintf("field_exists(%s)", c.fieldName)
}

// FieldEqualsCondition checks if a field equals a specific value
type FieldEqualsCondition struct {
	fieldName string
	value     interface{}
}

// NewFieldEqualsCondition creates a condition that checks if a field equals a value
func NewFieldEqualsCondition(fieldName string, value interface{}) *FieldEqualsCondition {
	return &FieldEqualsCondition{
		fieldName: fieldName,
		value:     value,
	}
}

// Evaluate checks if the field equals the expected value
func (c *FieldEqualsCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	fieldValue, exists := state.Data[c.fieldName]
	if !exists {
		return false, nil
	}

	return reflect.DeepEqual(fieldValue, c.value), nil
}

// String returns a string representation
func (c *FieldEqualsCondition) String() string {
	return fmt.Sprintf("field_equals(%s, %v)", c.fieldName, c.value)
}

// FieldContainsCondition checks if a string field contains a substring
type FieldContainsCondition struct {
	fieldName       string
	substring       string
	caseInsensitive bool
}

// NewFieldContainsCondition creates a condition that checks if a field contains a substring
func NewFieldContainsCondition(fieldName, substring string, caseInsensitive bool) *FieldContainsCondition {
	return &FieldContainsCondition{
		fieldName:       fieldName,
		substring:       substring,
		caseInsensitive: caseInsensitive,
	}
}

// Evaluate checks if the field contains the substring
func (c *FieldContainsCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	fieldValue, exists := state.Data[c.fieldName]
	if !exists {
		return false, nil
	}

	str, ok := fieldValue.(string)
	if !ok {
		return false, fmt.Errorf("field %s is not a string", c.fieldName)
	}

	if c.caseInsensitive {
		str = strings.ToLower(str)
		substring := strings.ToLower(c.substring)
		return strings.Contains(str, substring), nil
	}

	return strings.Contains(str, c.substring), nil
}

// String returns a string representation
func (c *FieldContainsCondition) String() string {
	return fmt.Sprintf("field_contains(%s, %s, case_insensitive=%t)", c.fieldName, c.substring, c.caseInsensitive)
}

// FieldMatchesRegexCondition checks if a field matches a regular expression
type FieldMatchesRegexCondition struct {
	fieldName string
	pattern   string
	regex     *regexp.Regexp
}

// NewFieldMatchesRegexCondition creates a condition that checks if a field matches a regex
func NewFieldMatchesRegexCondition(fieldName, pattern string) (*FieldMatchesRegexCondition, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	return &FieldMatchesRegexCondition{
		fieldName: fieldName,
		pattern:   pattern,
		regex:     regex,
	}, nil
}

// Evaluate checks if the field matches the regex
func (c *FieldMatchesRegexCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	fieldValue, exists := state.Data[c.fieldName]
	if !exists {
		return false, nil
	}

	str, ok := fieldValue.(string)
	if !ok {
		return false, fmt.Errorf("field %s is not a string", c.fieldName)
	}

	return c.regex.MatchString(str), nil
}

// String returns a string representation
func (c *FieldMatchesRegexCondition) String() string {
	return fmt.Sprintf("field_matches_regex(%s, %s)", c.fieldName, c.pattern)
}

// NumericComparisonCondition compares numeric fields
type NumericComparisonCondition struct {
	fieldName string
	operator  ComparisonOperator
	value     float64
}

// ComparisonOperator defines comparison operators
type ComparisonOperator string

const (
	OpEqual              ComparisonOperator = "eq"
	OpNotEqual           ComparisonOperator = "ne"
	OpGreaterThan        ComparisonOperator = "gt"
	OpGreaterThanOrEqual ComparisonOperator = "gte"
	OpLessThan           ComparisonOperator = "lt"
	OpLessThanOrEqual    ComparisonOperator = "lte"
)

// NewNumericComparisonCondition creates a condition that compares numeric values
func NewNumericComparisonCondition(fieldName string, operator ComparisonOperator, value float64) *NumericComparisonCondition {
	return &NumericComparisonCondition{
		fieldName: fieldName,
		operator:  operator,
		value:     value,
	}
}

// Evaluate compares the numeric field with the expected value
func (c *NumericComparisonCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	fieldValue, exists := state.Data[c.fieldName]
	if !exists {
		return false, nil
	}

	// Convert to float64
	var numValue float64
	switch v := fieldValue.(type) {
	case float64:
		numValue = v
	case float32:
		numValue = float64(v)
	case int:
		numValue = float64(v)
	case int32:
		numValue = float64(v)
	case int64:
		numValue = float64(v)
	case string:
		var err error
		numValue, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return false, fmt.Errorf("field %s cannot be converted to number: %w", c.fieldName, err)
		}
	default:
		return false, fmt.Errorf("field %s is not a numeric type", c.fieldName)
	}

	switch c.operator {
	case OpEqual:
		return numValue == c.value, nil
	case OpNotEqual:
		return numValue != c.value, nil
	case OpGreaterThan:
		return numValue > c.value, nil
	case OpGreaterThanOrEqual:
		return numValue >= c.value, nil
	case OpLessThan:
		return numValue < c.value, nil
	case OpLessThanOrEqual:
		return numValue <= c.value, nil
	default:
		return false, fmt.Errorf("unknown comparison operator: %s", c.operator)
	}
}

// String returns a string representation
func (c *NumericComparisonCondition) String() string {
	return fmt.Sprintf("numeric_comparison(%s %s %f)", c.fieldName, c.operator, c.value)
}

// AndCondition combines multiple conditions with AND logic
type AndCondition struct {
	conditions []llm.Condition
}

// NewAndCondition creates a condition that requires all sub-conditions to be true
func NewAndCondition(conditions ...llm.Condition) *AndCondition {
	return &AndCondition{conditions: conditions}
}

// Evaluate checks if all conditions are true
func (c *AndCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	for _, condition := range c.conditions {
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
	var parts []string
	for _, condition := range c.conditions {
		parts = append(parts, condition.String())
	}
	return fmt.Sprintf("and(%s)", strings.Join(parts, ", "))
}

// OrCondition combines multiple conditions with OR logic
type OrCondition struct {
	conditions []llm.Condition
}

// NewOrCondition creates a condition that requires at least one sub-condition to be true
func NewOrCondition(conditions ...llm.Condition) *OrCondition {
	return &OrCondition{conditions: conditions}
}

// Evaluate checks if any condition is true
func (c *OrCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	for _, condition := range c.conditions {
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
	var parts []string
	for _, condition := range c.conditions {
		parts = append(parts, condition.String())
	}
	return fmt.Sprintf("or(%s)", strings.Join(parts, ", "))
}

// NotCondition negates a condition
type NotCondition struct {
	condition llm.Condition
}

// NewNotCondition creates a condition that negates another condition
func NewNotCondition(condition llm.Condition) *NotCondition {
	return &NotCondition{condition: condition}
}

// Evaluate negates the result of the wrapped condition
func (c *NotCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	result, err := c.condition.Evaluate(ctx, state)
	if err != nil {
		return false, err
	}
	return !result, nil
}

// String returns a string representation
func (c *NotCondition) String() string {
	return fmt.Sprintf("not(%s)", c.condition.String())
}

// CustomCondition allows for custom evaluation logic
type CustomCondition struct {
	name      string
	evaluator func(ctx context.Context, state llm.GraphState) (bool, error)
}

// NewCustomCondition creates a condition with custom evaluation logic
func NewCustomCondition(name string, evaluator func(ctx context.Context, state llm.GraphState) (bool, error)) *CustomCondition {
	return &CustomCondition{
		name:      name,
		evaluator: evaluator,
	}
}

// Evaluate uses the custom evaluator function
func (c *CustomCondition) Evaluate(ctx context.Context, state llm.GraphState) (bool, error) {
	return c.evaluator(ctx, state)
}

// String returns a string representation
func (c *CustomCondition) String() string {
	return fmt.Sprintf("custom(%s)", c.name)
}
