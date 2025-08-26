package state

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strconv"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// DefaultStateValidator implements basic state validation
type DefaultStateValidator struct {
	logger  *logger.Logger
	schemas map[string]*StateSchema
}

// StateSchema defines the schema for state validation
type StateSchema struct {
	Name        string                  `json:"name"`
	Version     string                  `json:"version"`
	Fields      map[string]*FieldSchema `json:"fields"`
	Required    []string                `json:"required"`
	Constraints []StateConstraint       `json:"constraints"`
	Metadata    map[string]interface{}  `json:"metadata"`
}

// FieldSchema defines the schema for a field
type FieldSchema struct {
	Type        string            `json:"type"`
	Format      string            `json:"format,omitempty"`
	Pattern     string            `json:"pattern,omitempty"`
	MinLength   *int              `json:"min_length,omitempty"`
	MaxLength   *int              `json:"max_length,omitempty"`
	Minimum     *float64          `json:"minimum,omitempty"`
	Maximum     *float64          `json:"maximum,omitempty"`
	Enum        []interface{}     `json:"enum,omitempty"`
	Default     interface{}       `json:"default,omitempty"`
	Description string            `json:"description,omitempty"`
	Constraints []StateConstraint `json:"constraints,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string      `json:"field"`
	Value   interface{} `json:"value"`
	Message string      `json:"message"`
	Code    string      `json:"code"`
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", ve.Field, ve.Message)
}

// ValidationResult holds the result of validation
type ValidationResult struct {
	Valid  bool               `json:"valid"`
	Errors []*ValidationError `json:"errors"`
}

// NewDefaultStateValidator creates a new default state validator
func NewDefaultStateValidator(logger *logger.Logger) *DefaultStateValidator {
	return &DefaultStateValidator{
		logger:  logger,
		schemas: make(map[string]*StateSchema),
	}
}

// Validate validates a state entry
func (dsv *DefaultStateValidator) Validate(ctx context.Context, entry *StateEntry) error {
	if entry == nil {
		return fmt.Errorf("entry cannot be nil")
	}

	// Basic validation
	if entry.Key.Key == "" {
		return &ValidationError{
			Field:   "key",
			Value:   entry.Key.Key,
			Message: "key cannot be empty",
			Code:    "REQUIRED",
		}
	}

	if entry.Value == nil {
		return &ValidationError{
			Field:   "value",
			Value:   entry.Value,
			Message: "value cannot be nil",
			Code:    "REQUIRED",
		}
	}

	// Validate metadata if present
	if entry.Metadata != nil {
		if err := dsv.validateMetadata(entry.Metadata); err != nil {
			return err
		}
	}

	dsv.logger.Debug("State entry validation passed", "key", entry.Key)
	return nil
}

// ValidateSchema validates a state entry against a specific schema
func (dsv *DefaultStateValidator) ValidateSchema(ctx context.Context, entry *StateEntry, schemaName string) error {
	schema, exists := dsv.schemas[schemaName]
	if !exists {
		return fmt.Errorf("schema '%s' not found", schemaName)
	}

	result := dsv.validateAgainstSchema(entry, schema)
	if !result.Valid {
		return fmt.Errorf("schema validation failed: %d errors", len(result.Errors))
	}

	return nil
}

// ValidateConstraints validates state entry against constraints
func (dsv *DefaultStateValidator) ValidateConstraints(ctx context.Context, entry *StateEntry, constraints []StateConstraint) error {
	for _, constraint := range constraints {
		if err := dsv.validateConstraint(entry, constraint); err != nil {
			return err
		}
	}

	return nil
}

// RegisterSchema registers a validation schema
func (dsv *DefaultStateValidator) RegisterSchema(schema *StateSchema) error {
	if schema.Name == "" {
		return fmt.Errorf("schema name is required")
	}

	dsv.schemas[schema.Name] = schema

	dsv.logger.Info("Schema registered",
		"schema_name", schema.Name,
		"version", schema.Version,
		"fields", len(schema.Fields))

	return nil
}

// GetSchema retrieves a schema by name
func (dsv *DefaultStateValidator) GetSchema(name string) (*StateSchema, error) {
	schema, exists := dsv.schemas[name]
	if !exists {
		return nil, fmt.Errorf("schema '%s' not found", name)
	}

	return schema, nil
}

// ListSchemas returns all registered schemas
func (dsv *DefaultStateValidator) ListSchemas() []*StateSchema {
	schemas := make([]*StateSchema, 0, len(dsv.schemas))
	for _, schema := range dsv.schemas {
		schemas = append(schemas, schema)
	}
	return schemas
}

// validateMetadata validates state metadata
func (dsv *DefaultStateValidator) validateMetadata(metadata *StateMetadata) error {
	if metadata.Type == "" {
		return &ValidationError{
			Field:   "metadata.type",
			Value:   metadata.Type,
			Message: "metadata type is required",
			Code:    "REQUIRED",
		}
	}

	if metadata.Size < 0 {
		return &ValidationError{
			Field:   "metadata.size",
			Value:   metadata.Size,
			Message: "metadata size cannot be negative",
			Code:    "INVALID_VALUE",
		}
	}

	return nil
}

// validateAgainstSchema validates an entry against a schema
func (dsv *DefaultStateValidator) validateAgainstSchema(entry *StateEntry, schema *StateSchema) *ValidationResult {
	result := &ValidationResult{
		Valid:  true,
		Errors: make([]*ValidationError, 0),
	}

	// Convert entry value to map for field validation
	valueMap, ok := dsv.convertToMap(entry.Value)
	if !ok {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:   "value",
			Value:   entry.Value,
			Message: "value must be a map/object for schema validation",
			Code:    "INVALID_TYPE",
		})
		return result
	}

	// Check required fields
	for _, requiredField := range schema.Required {
		if _, exists := valueMap[requiredField]; !exists {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:   requiredField,
				Value:   nil,
				Message: fmt.Sprintf("required field '%s' is missing", requiredField),
				Code:    "REQUIRED",
			})
		}
	}

	// Validate each field
	for fieldName, fieldValue := range valueMap {
		fieldSchema, exists := schema.Fields[fieldName]
		if !exists {
			// Unknown field - could be allowed or not based on schema settings
			continue
		}

		if err := dsv.validateField(fieldName, fieldValue, fieldSchema); err != nil {
			result.Valid = false
			if validationErr, ok := err.(*ValidationError); ok {
				result.Errors = append(result.Errors, validationErr)
			} else {
				result.Errors = append(result.Errors, &ValidationError{
					Field:   fieldName,
					Value:   fieldValue,
					Message: err.Error(),
					Code:    "VALIDATION_ERROR",
				})
			}
		}
	}

	// Validate schema-level constraints
	for _, constraint := range schema.Constraints {
		if err := dsv.validateConstraint(entry, constraint); err != nil {
			result.Valid = false
			if validationErr, ok := err.(*ValidationError); ok {
				result.Errors = append(result.Errors, validationErr)
			}
		}
	}

	return result
}

// validateField validates a single field
func (dsv *DefaultStateValidator) validateField(fieldName string, value interface{}, schema *FieldSchema) error {
	// Type validation
	if err := dsv.validateFieldType(fieldName, value, schema.Type); err != nil {
		return err
	}

	// Pattern validation
	if schema.Pattern != "" {
		if err := dsv.validatePattern(fieldName, value, schema.Pattern); err != nil {
			return err
		}
	}

	// Length validation
	if err := dsv.validateLength(fieldName, value, schema.MinLength, schema.MaxLength); err != nil {
		return err
	}

	// Range validation
	if err := dsv.validateRange(fieldName, value, schema.Minimum, schema.Maximum); err != nil {
		return err
	}

	// Enum validation
	if len(schema.Enum) > 0 {
		if err := dsv.validateEnum(fieldName, value, schema.Enum); err != nil {
			return err
		}
	}

	// Field-level constraints
	for _, constraint := range schema.Constraints {
		if err := dsv.validateFieldConstraint(fieldName, value, constraint); err != nil {
			return err
		}
	}

	return nil
}

// validateFieldType validates field type
func (dsv *DefaultStateValidator) validateFieldType(fieldName string, value interface{}, expectedType string) error {
	actualType := dsv.getValueType(value)

	if !dsv.isTypeCompatible(actualType, expectedType) {
		return &ValidationError{
			Field:   fieldName,
			Value:   value,
			Message: fmt.Sprintf("expected type '%s', got '%s'", expectedType, actualType),
			Code:    "TYPE_MISMATCH",
		}
	}

	return nil
}

// validatePattern validates against a regex pattern
func (dsv *DefaultStateValidator) validatePattern(fieldName string, value interface{}, pattern string) error {
	strValue, ok := value.(string)
	if !ok {
		return nil // Pattern validation only applies to strings
	}

	matched, err := regexp.MatchString(pattern, strValue)
	if err != nil {
		return &ValidationError{
			Field:   fieldName,
			Value:   value,
			Message: fmt.Sprintf("invalid pattern: %s", err.Error()),
			Code:    "INVALID_PATTERN",
		}
	}

	if !matched {
		return &ValidationError{
			Field:   fieldName,
			Value:   value,
			Message: fmt.Sprintf("value does not match pattern '%s'", pattern),
			Code:    "PATTERN_MISMATCH",
		}
	}

	return nil
}

// validateLength validates string length or array/slice length
func (dsv *DefaultStateValidator) validateLength(fieldName string, value interface{}, minLength, maxLength *int) error {
	var length int

	switch v := value.(type) {
	case string:
		length = len(v)
	case []interface{}:
		length = len(v)
	default:
		return nil // Length validation doesn't apply
	}

	if minLength != nil && length < *minLength {
		return &ValidationError{
			Field:   fieldName,
			Value:   value,
			Message: fmt.Sprintf("length %d is less than minimum %d", length, *minLength),
			Code:    "TOO_SHORT",
		}
	}

	if maxLength != nil && length > *maxLength {
		return &ValidationError{
			Field:   fieldName,
			Value:   value,
			Message: fmt.Sprintf("length %d is greater than maximum %d", length, *maxLength),
			Code:    "TOO_LONG",
		}
	}

	return nil
}

// validateRange validates numeric ranges
func (dsv *DefaultStateValidator) validateRange(fieldName string, value interface{}, minimum, maximum *float64) error {
	var numValue float64
	var ok bool

	switch v := value.(type) {
	case int:
		numValue = float64(v)
		ok = true
	case int64:
		numValue = float64(v)
		ok = true
	case float32:
		numValue = float64(v)
		ok = true
	case float64:
		numValue = v
		ok = true
	case string:
		if parsed, err := strconv.ParseFloat(v, 64); err == nil {
			numValue = parsed
			ok = true
		}
	}

	if !ok {
		return nil // Range validation doesn't apply
	}

	if minimum != nil && numValue < *minimum {
		return &ValidationError{
			Field:   fieldName,
			Value:   value,
			Message: fmt.Sprintf("value %f is less than minimum %f", numValue, *minimum),
			Code:    "TOO_SMALL",
		}
	}

	if maximum != nil && numValue > *maximum {
		return &ValidationError{
			Field:   fieldName,
			Value:   value,
			Message: fmt.Sprintf("value %f is greater than maximum %f", numValue, *maximum),
			Code:    "TOO_LARGE",
		}
	}

	return nil
}

// validateEnum validates against allowed values
func (dsv *DefaultStateValidator) validateEnum(fieldName string, value interface{}, enum []interface{}) error {
	for _, allowedValue := range enum {
		if dsv.valuesEqual(value, allowedValue) {
			return nil
		}
	}

	return &ValidationError{
		Field:   fieldName,
		Value:   value,
		Message: fmt.Sprintf("value is not in allowed enum values: %v", enum),
		Code:    "INVALID_ENUM",
	}
}

// validateConstraint validates a state constraint
func (dsv *DefaultStateValidator) validateConstraint(entry *StateEntry, constraint StateConstraint) error {
	switch constraint.Type {
	case ConstraintRequired:
		return dsv.validateRequiredConstraint(entry, constraint)
	case ConstraintUnique:
		return dsv.validateUniqueConstraint(entry, constraint)
	case ConstraintCustom:
		return dsv.validateCustomConstraint(entry, constraint)
	default:
		return nil
	}
}

// validateFieldConstraint validates a field-level constraint
func (dsv *DefaultStateValidator) validateFieldConstraint(fieldName string, value interface{}, constraint StateConstraint) error {
	// Implementation depends on constraint type
	return nil
}

// Helper methods

func (dsv *DefaultStateValidator) convertToMap(value interface{}) (map[string]interface{}, bool) {
	if valueMap, ok := value.(map[string]interface{}); ok {
		return valueMap, true
	}

	// Try to convert using reflection
	v := reflect.ValueOf(value)
	if v.Kind() == reflect.Map {
		result := make(map[string]interface{})
		for _, key := range v.MapKeys() {
			if keyStr, ok := key.Interface().(string); ok {
				result[keyStr] = v.MapIndex(key).Interface()
			}
		}
		return result, true
	}

	return nil, false
}

func (dsv *DefaultStateValidator) getValueType(value interface{}) string {
	if value == nil {
		return "null"
	}

	switch value.(type) {
	case bool:
		return "boolean"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "integer"
	case float32, float64:
		return "number"
	case string:
		return "string"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return "unknown"
	}
}

func (dsv *DefaultStateValidator) isTypeCompatible(actual, expected string) bool {
	if actual == expected {
		return true
	}

	// Allow some type compatibility
	switch expected {
	case "number":
		return actual == "integer" || actual == "number"
	case "integer":
		return actual == "integer"
	default:
		return false
	}
}

func (dsv *DefaultStateValidator) valuesEqual(a, b interface{}) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func (dsv *DefaultStateValidator) validateRequiredConstraint(entry *StateEntry, constraint StateConstraint) error {
	// Check if required field exists
	if constraint.Field == "" {
		return nil
	}

	valueMap, ok := dsv.convertToMap(entry.Value)
	if !ok {
		return &ValidationError{
			Field:   constraint.Field,
			Message: "cannot validate required constraint on non-object value",
			Code:    "CONSTRAINT_ERROR",
		}
	}

	if _, exists := valueMap[constraint.Field]; !exists {
		return &ValidationError{
			Field:   constraint.Field,
			Message: constraint.Message,
			Code:    "REQUIRED",
		}
	}

	return nil
}

func (dsv *DefaultStateValidator) validateUniqueConstraint(entry *StateEntry, constraint StateConstraint) error {
	// In a real implementation, this would check uniqueness across the store
	// For now, just return nil
	return nil
}

func (dsv *DefaultStateValidator) validateCustomConstraint(entry *StateEntry, constraint StateConstraint) error {
	// Custom constraint validation would be implemented here
	// This could involve calling external validation functions
	return nil
}
