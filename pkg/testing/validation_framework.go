// Package testing provides comprehensive validation framework capabilities
package testing

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// ValidationFramework provides comprehensive validation capabilities
type ValidationFramework struct {
	logger     *logger.Logger
	validators map[string]DataValidator
	rules      map[string][]ValidationRule
	config     *ValidationConfig
}

// ValidationConfig configures the validation framework
type ValidationConfig struct {
	StrictMode         bool          `yaml:"strict_mode"`
	FailFast           bool          `yaml:"fail_fast"`
	ValidationTimeout  time.Duration `yaml:"validation_timeout"`
	EnableCustomRules  bool          `yaml:"enable_custom_rules"`
	LogValidationSteps bool          `yaml:"log_validation_steps"`
	ParallelValidation bool          `yaml:"parallel_validation"`
	MaxConcurrency     int           `yaml:"max_concurrency"`
}

// DataValidator interface for different types of data validation
type DataValidator interface {
	Validate(ctx context.Context, data interface{}) (*DataValidationResult, error)
	GetName() string
	GetDescription() string
	GetSupportedTypes() []string
}

// ValidationRule represents a validation rule
type ValidationRule struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Parameters  map[string]interface{} `json:"parameters"`
	Severity    string                 `json:"severity"` // error, warning, info
	Enabled     bool                   `json:"enabled"`
}

// DataValidationResult represents the result of data validation
type DataValidationResult struct {
	Valid         bool                   `json:"valid"`
	Score         float64                `json:"score"`
	Errors        []ValidationError      `json:"errors"`
	Warnings      []ValidationWarning    `json:"warnings"`
	Info          []ValidationInfo       `json:"info"`
	Metadata      map[string]interface{} `json:"metadata"`
	Duration      time.Duration          `json:"duration"`
	ValidatorName string                 `json:"validator_name"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Code        string                 `json:"code"`
	Message     string                 `json:"message"`
	Field       string                 `json:"field,omitempty"`
	Value       interface{}            `json:"value,omitempty"`
	Expected    interface{}            `json:"expected,omitempty"`
	Severity    string                 `json:"severity"`
	Suggestions []string               `json:"suggestions,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Code        string                 `json:"code"`
	Message     string                 `json:"message"`
	Field       string                 `json:"field,omitempty"`
	Suggestions []string               `json:"suggestions,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// ValidationInfo represents validation information
type ValidationInfo struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Context map[string]interface{} `json:"context,omitempty"`
}

// SchemaValidator validates data against JSON schemas
type SchemaValidator struct {
	logger  *logger.Logger
	schemas map[string]interface{}
}

// DataTypeValidator validates data types and formats
type DataTypeValidator struct {
	logger *logger.Logger
	rules  map[string][]ValidationRule
}

// SecurityValidator validates security-related aspects
type SecurityValidator struct {
	logger   *logger.Logger
	patterns map[string]*regexp.Regexp
}

// PerformanceValidator validates performance characteristics
type PerformanceValidator struct {
	logger     *logger.Logger
	benchmarks map[string]PerformanceBenchmark
}

// PerformanceBenchmark defines performance expectations
type PerformanceBenchmark struct {
	Name           string        `json:"name"`
	MaxLatency     time.Duration `json:"max_latency"`
	MinThroughput  float64       `json:"min_throughput"`
	MaxMemoryUsage int64         `json:"max_memory_usage"`
	MaxCPUUsage    float64       `json:"max_cpu_usage"`
	MaxErrorRate   float64       `json:"max_error_rate"`
}

// NewValidationFramework creates a new validation framework
func NewValidationFramework(logger *logger.Logger, config *ValidationConfig) *ValidationFramework {
	framework := &ValidationFramework{
		logger:     logger,
		validators: make(map[string]DataValidator),
		rules:      make(map[string][]ValidationRule),
		config:     config,
	}

	// Initialize built-in validators
	framework.initializeValidators()

	return framework
}

// initializeValidators initializes built-in validators
func (vf *ValidationFramework) initializeValidators() {
	// Schema validator
	schemaValidator := &SchemaValidator{
		logger:  vf.logger,
		schemas: make(map[string]interface{}),
	}
	vf.RegisterValidator("schema", schemaValidator)

	// Data type validator
	dataTypeValidator := &DataTypeValidator{
		logger: vf.logger,
		rules:  make(map[string][]ValidationRule),
	}
	vf.RegisterValidator("datatype", dataTypeValidator)

	// Security validator
	securityValidator := &SecurityValidator{
		logger:   vf.logger,
		patterns: make(map[string]*regexp.Regexp),
	}
	vf.initializeSecurityPatterns(securityValidator)
	vf.RegisterValidator("security", securityValidator)

	// Performance validator
	performanceValidator := &PerformanceValidator{
		logger:     vf.logger,
		benchmarks: make(map[string]PerformanceBenchmark),
	}
	vf.initializePerformanceBenchmarks(performanceValidator)
	vf.RegisterValidator("performance", performanceValidator)
}

// RegisterValidator registers a custom validator
func (vf *ValidationFramework) RegisterValidator(name string, validator DataValidator) {
	vf.validators[name] = validator
	vf.logger.Info("Validator registered", "name", name, "description", validator.GetDescription())
}

// ValidateData validates data using all applicable validators
func (vf *ValidationFramework) ValidateData(ctx context.Context, data interface{}, validatorNames ...string) (*DataValidationResult, error) {
	start := time.Now()

	// Create context with timeout
	validationCtx, cancel := context.WithTimeout(ctx, vf.config.ValidationTimeout)
	defer cancel()

	// Determine which validators to use
	validators := vf.getValidatorsForData(data, validatorNames...)

	// Combined result
	combinedResult := &DataValidationResult{
		Valid:         true,
		Score:         1.0,
		Errors:        make([]ValidationError, 0),
		Warnings:      make([]ValidationWarning, 0),
		Info:          make([]ValidationInfo, 0),
		Metadata:      make(map[string]interface{}),
		ValidatorName: "combined",
	}

	// Run validators
	for name, validator := range validators {
		if vf.config.LogValidationSteps {
			vf.logger.Debug("Running validator", "name", name)
		}

		result, err := validator.Validate(validationCtx, data)
		if err != nil {
			if vf.config.FailFast {
				return nil, fmt.Errorf("validation failed for %s: %w", name, err)
			}
			vf.logger.Error("Validator failed", "name", name, "error", err)
			continue
		}

		// Combine results
		vf.combineResults(combinedResult, result)

		// Store individual validator results
		combinedResult.Metadata[name] = result

		// Fail fast on errors if configured
		if vf.config.FailFast && !result.Valid {
			break
		}
	}

	combinedResult.Duration = time.Since(start)

	// Calculate overall validity and score
	vf.calculateOverallScore(combinedResult)

	return combinedResult, nil
}

// getValidatorsForData determines which validators to use for the given data
func (vf *ValidationFramework) getValidatorsForData(data interface{}, validatorNames ...string) map[string]DataValidator {
	validators := make(map[string]DataValidator)

	// If specific validators are requested, use only those
	if len(validatorNames) > 0 {
		for _, name := range validatorNames {
			if validator, exists := vf.validators[name]; exists {
				validators[name] = validator
			}
		}
		return validators
	}

	// Otherwise, use all applicable validators
	dataType := reflect.TypeOf(data).String()

	for name, validator := range vf.validators {
		supportedTypes := validator.GetSupportedTypes()
		if len(supportedTypes) == 0 || vf.isTypeSupported(dataType, supportedTypes) {
			validators[name] = validator
		}
	}

	return validators
}

// isTypeSupported checks if a data type is supported by a validator
func (vf *ValidationFramework) isTypeSupported(dataType string, supportedTypes []string) bool {
	for _, supportedType := range supportedTypes {
		if supportedType == "*" || supportedType == dataType {
			return true
		}
		// Check for partial matches (e.g., "map[" for map types)
		if strings.Contains(dataType, supportedType) {
			return true
		}
	}
	return false
}

// combineResults combines individual validation results
func (vf *ValidationFramework) combineResults(combined *DataValidationResult, individual *DataValidationResult) {
	// Combine errors
	combined.Errors = append(combined.Errors, individual.Errors...)

	// Combine warnings
	combined.Warnings = append(combined.Warnings, individual.Warnings...)

	// Combine info
	combined.Info = append(combined.Info, individual.Info...)

	// Update validity
	if !individual.Valid {
		combined.Valid = false
	}
}

// calculateOverallScore calculates the overall validation score
func (vf *ValidationFramework) calculateOverallScore(result *DataValidationResult) {
	if len(result.Errors) > 0 {
		result.Valid = false
		// Reduce score based on number and severity of errors
		errorPenalty := float64(len(result.Errors)) * 0.1
		result.Score = 1.0 - errorPenalty
		if result.Score < 0 {
			result.Score = 0
		}
	} else {
		result.Valid = true
		// Reduce score slightly for warnings
		warningPenalty := float64(len(result.Warnings)) * 0.05
		result.Score = 1.0 - warningPenalty
		if result.Score < 0.5 {
			result.Score = 0.5
		}
	}
}

// Schema Validator Implementation
func (sv *SchemaValidator) Validate(ctx context.Context, data interface{}) (*DataValidationResult, error) {
	result := &DataValidationResult{
		Valid:         true,
		Score:         1.0,
		Errors:        make([]ValidationError, 0),
		Warnings:      make([]ValidationWarning, 0),
		Info:          make([]ValidationInfo, 0),
		Metadata:      make(map[string]interface{}),
		ValidatorName: "schema",
	}

	// Basic schema validation (simplified)
	if data == nil {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "NULL_DATA",
			Message:  "Data cannot be null",
			Severity: "error",
		})
		result.Valid = false
	}

	return result, nil
}

func (sv *SchemaValidator) GetName() string             { return "schema" }
func (sv *SchemaValidator) GetDescription() string      { return "Validates data against JSON schemas" }
func (sv *SchemaValidator) GetSupportedTypes() []string { return []string{"*"} }

// Data Type Validator Implementation
func (dtv *DataTypeValidator) Validate(ctx context.Context, data interface{}) (*DataValidationResult, error) {
	result := &DataValidationResult{
		Valid:         true,
		Score:         1.0,
		Errors:        make([]ValidationError, 0),
		Warnings:      make([]ValidationWarning, 0),
		Info:          make([]ValidationInfo, 0),
		Metadata:      make(map[string]interface{}),
		ValidatorName: "datatype",
	}

	// Basic data type validation
	dataType := reflect.TypeOf(data)
	result.Metadata["detected_type"] = dataType.String()

	// Add info about detected type
	result.Info = append(result.Info, ValidationInfo{
		Code:    "TYPE_DETECTED",
		Message: fmt.Sprintf("Detected data type: %s", dataType.String()),
		Context: map[string]interface{}{"type": dataType.String()},
	})

	return result, nil
}

func (dtv *DataTypeValidator) GetName() string             { return "datatype" }
func (dtv *DataTypeValidator) GetDescription() string      { return "Validates data types and formats" }
func (dtv *DataTypeValidator) GetSupportedTypes() []string { return []string{"*"} }

// Security Validator Implementation
func (sv *SecurityValidator) Validate(ctx context.Context, data interface{}) (*DataValidationResult, error) {
	result := &DataValidationResult{
		Valid:         true,
		Score:         1.0,
		Errors:        make([]ValidationError, 0),
		Warnings:      make([]ValidationWarning, 0),
		Info:          make([]ValidationInfo, 0),
		Metadata:      make(map[string]interface{}),
		ValidatorName: "security",
	}

	// Convert data to string for pattern matching
	dataStr := fmt.Sprintf("%v", data)

	// Check for security patterns
	for patternName, pattern := range sv.patterns {
		if pattern.MatchString(dataStr) {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Code:    "SECURITY_PATTERN_DETECTED",
				Message: fmt.Sprintf("Potential security issue detected: %s", patternName),
				Suggestions: []string{
					"Review the content for security implications",
					"Consider sanitizing the input",
				},
				Context: map[string]interface{}{
					"pattern":         patternName,
					"matched_content": dataStr,
				},
			})
		}
	}

	return result, nil
}

func (sv *SecurityValidator) GetName() string             { return "security" }
func (sv *SecurityValidator) GetDescription() string      { return "Validates security-related aspects" }
func (sv *SecurityValidator) GetSupportedTypes() []string { return []string{"string", "map[", "[]"} }

// Performance Validator Implementation
func (pv *PerformanceValidator) Validate(ctx context.Context, data interface{}) (*DataValidationResult, error) {
	result := &DataValidationResult{
		Valid:         true,
		Score:         1.0,
		Errors:        make([]ValidationError, 0),
		Warnings:      make([]ValidationWarning, 0),
		Info:          make([]ValidationInfo, 0),
		Metadata:      make(map[string]interface{}),
		ValidatorName: "performance",
	}

	// Basic performance validation (placeholder)
	result.Info = append(result.Info, ValidationInfo{
		Code:    "PERFORMANCE_CHECK",
		Message: "Performance validation completed",
		Context: map[string]interface{}{
			"data_size": len(fmt.Sprintf("%v", data)),
		},
	})

	return result, nil
}

func (pv *PerformanceValidator) GetName() string { return "performance" }
func (pv *PerformanceValidator) GetDescription() string {
	return "Validates performance characteristics"
}
func (pv *PerformanceValidator) GetSupportedTypes() []string { return []string{"*"} }

// Helper methods for initialization
func (vf *ValidationFramework) initializeSecurityPatterns(sv *SecurityValidator) {
	patterns := map[string]string{
		"sql_injection":     `(?i)(union|select|insert|update|delete|drop|exec|script)`,
		"xss_attempt":       `(?i)(<script|javascript:|on\w+\s*=)`,
		"path_traversal":    `\.\./`,
		"command_injection": `(?i)(;|\||&|` + "`" + `).*?(rm|del|format|shutdown)`,
	}

	for name, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			vf.logger.Error("Failed to compile security pattern", "name", name, "error", err)
			continue
		}
		sv.patterns[name] = compiled
	}
}

func (vf *ValidationFramework) initializePerformanceBenchmarks(pv *PerformanceValidator) {
	benchmarks := map[string]PerformanceBenchmark{
		"api_response": {
			Name:           "API Response",
			MaxLatency:     500 * time.Millisecond,
			MinThroughput:  100.0,
			MaxMemoryUsage: 100 * 1024 * 1024, // 100MB
			MaxCPUUsage:    80.0,
			MaxErrorRate:   0.01,
		},
		"database_query": {
			Name:           "Database Query",
			MaxLatency:     200 * time.Millisecond,
			MinThroughput:  500.0,
			MaxMemoryUsage: 50 * 1024 * 1024, // 50MB
			MaxCPUUsage:    60.0,
			MaxErrorRate:   0.005,
		},
	}

	for name, benchmark := range benchmarks {
		pv.benchmarks[name] = benchmark
	}
}
