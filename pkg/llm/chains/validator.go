package chains

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var validatorTracer = otel.Tracer("hackai/llm/chains/validator")

// ChainValidator provides comprehensive chain validation
type ChainValidator interface {
	// Core validation
	ValidateChain(ctx context.Context, chain llm.Chain) (ValidationResult, error)
	ValidateMetadata(ctx context.Context, metadata ChainMetadata) (ValidationResult, error)
	ValidateConfiguration(ctx context.Context, config ChainConfiguration) (ValidationResult, error)

	// Security validation
	ValidateSecurityConstraints(ctx context.Context, chain llm.Chain) (ValidationResult, error)
	ValidatePermissions(ctx context.Context, permissions ChainPermissions) (ValidationResult, error)

	// Performance validation
	ValidatePerformanceConstraints(ctx context.Context, chain llm.Chain) (ValidationResult, error)
	ValidateResourceUsage(ctx context.Context, chain llm.Chain) (ValidationResult, error)

	// Dependency validation
	ValidateDependencies(ctx context.Context, dependencies []string, registry ChainRegistry) (ValidationResult, error)
	ValidateCircularDependencies(ctx context.Context, chainID string, dependencies []string, registry ChainRegistry) (ValidationResult, error)

	// Custom validation
	AddCustomValidator(name string, validator CustomValidator) error
	RemoveCustomValidator(name string) error
	RunCustomValidators(ctx context.Context, chain llm.Chain) (ValidationResult, error)
}

// DefaultChainValidator implements the ChainValidator interface
type DefaultChainValidator struct {
	customValidators map[string]CustomValidator
	config           ValidatorConfig
	logger           *logger.Logger
}

// CustomValidator defines a custom validation function
type CustomValidator func(ctx context.Context, chain llm.Chain) (ValidationResult, error)

// ValidatorConfig provides configuration for the validator
type ValidatorConfig struct {
	MaxNameLength        int            `json:"max_name_length"`
	MaxDescriptionLength int            `json:"max_description_length"`
	AllowedTags          []string       `json:"allowed_tags"`
	RequiredTags         []string       `json:"required_tags"`
	MaxDependencies      int            `json:"max_dependencies"`
	MaxExecutionTime     time.Duration  `json:"max_execution_time"`
	MaxMemoryUsage       int64          `json:"max_memory_usage"`
	SecurityChecks       SecurityChecks `json:"security_checks"`
}

// SecurityChecks defines security validation settings
type SecurityChecks struct {
	CheckPromptInjection bool `json:"check_prompt_injection"`
	CheckDataLeakage     bool `json:"check_data_leakage"`
	CheckMaliciousCode   bool `json:"check_malicious_code"`
	CheckResourceLimits  bool `json:"check_resource_limits"`
}

// ChainConfiguration represents chain configuration for validation
type ChainConfiguration struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        llm.ChainType          `json:"type"`
	Enabled     bool                   `json:"enabled"`
	MaxRetries  int                    `json:"max_retries"`
	Timeout     time.Duration          `json:"timeout"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// NewDefaultChainValidator creates a new default chain validator
func NewDefaultChainValidator(config ValidatorConfig, logger *logger.Logger) *DefaultChainValidator {
	return &DefaultChainValidator{
		customValidators: make(map[string]CustomValidator),
		config:           config,
		logger:           logger,
	}
}

// ValidateChain performs comprehensive chain validation
func (v *DefaultChainValidator) ValidateChain(ctx context.Context, chain llm.Chain) (ValidationResult, error) {
	ctx, span := validatorTracer.Start(ctx, "validator.validate_chain",
		trace.WithAttributes(
			attribute.String("chain.id", chain.ID()),
			attribute.String("chain.name", chain.Name()),
		),
	)
	defer span.End()

	result := ValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Score:       100.0,
		Suggestions: []string{},
	}

	// Basic validation
	if err := v.validateBasicProperties(chain, &result); err != nil {
		span.RecordError(err)
		return result, err
	}

	// Chain-specific validation
	if err := chain.Validate(); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "chain_validation",
			Message:   fmt.Sprintf("Chain validation failed: %v", err),
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 20
	}

	// Security validation
	if v.config.SecurityChecks.CheckPromptInjection {
		v.validatePromptInjection(chain, &result)
	}

	if v.config.SecurityChecks.CheckDataLeakage {
		v.validateDataLeakage(chain, &result)
	}

	if v.config.SecurityChecks.CheckMaliciousCode {
		v.validateMaliciousCode(chain, &result)
	}

	// Performance validation
	v.validatePerformanceConstraints(chain, &result)

	// Custom validators
	customResult, err := v.RunCustomValidators(ctx, chain)
	if err != nil {
		v.logger.Warn("Custom validation failed", "chain_id", chain.ID(), "error", err)
	} else {
		v.mergeValidationResults(&result, customResult)
	}

	// Calculate final score
	v.calculateFinalScore(&result)

	span.SetAttributes(
		attribute.Bool("validation.valid", result.Valid),
		attribute.Float64("validation.score", result.Score),
		attribute.Int("validation.errors", len(result.Errors)),
		attribute.Int("validation.warnings", len(result.Warnings)),
	)

	v.logger.Info("Chain validation completed",
		"chain_id", chain.ID(),
		"valid", result.Valid,
		"score", result.Score,
		"errors", len(result.Errors),
		"warnings", len(result.Warnings),
	)

	return result, nil
}

// ValidateMetadata validates chain metadata
func (v *DefaultChainValidator) ValidateMetadata(ctx context.Context, metadata ChainMetadata) (ValidationResult, error) {
	result := ValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Score:       100.0,
		Suggestions: []string{},
	}

	// Validate version format
	if metadata.Version == "" {
		result.Errors = append(result.Errors, ValidationError{
			Type:      "metadata_validation",
			Message:   "Version is required",
			Field:     "version",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Valid = false
		result.Score -= 10
	} else if !v.isValidVersion(metadata.Version) {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:      "metadata_validation",
			Message:   "Version format should follow semantic versioning (e.g., 1.0.0)",
			Field:     "version",
			Timestamp: time.Now(),
		})
		result.Score -= 5
	}

	// Validate author
	if metadata.Author == "" {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:      "metadata_validation",
			Message:   "Author is recommended for better traceability",
			Field:     "author",
			Timestamp: time.Now(),
		})
		result.Score -= 5
	}

	// Validate tags
	if len(v.config.RequiredTags) > 0 {
		for _, requiredTag := range v.config.RequiredTags {
			found := false
			for _, tag := range metadata.Tags {
				if tag == requiredTag {
					found = true
					break
				}
			}
			if !found {
				result.Errors = append(result.Errors, ValidationError{
					Type:      "metadata_validation",
					Message:   fmt.Sprintf("Required tag '%s' is missing", requiredTag),
					Field:     "tags",
					Severity:  "error",
					Timestamp: time.Now(),
				})
				result.Valid = false
				result.Score -= 10
			}
		}
	}

	// Validate allowed tags
	if len(v.config.AllowedTags) > 0 {
		for _, tag := range metadata.Tags {
			allowed := false
			for _, allowedTag := range v.config.AllowedTags {
				if tag == allowedTag {
					allowed = true
					break
				}
			}
			if !allowed {
				result.Warnings = append(result.Warnings, ValidationWarning{
					Type:      "metadata_validation",
					Message:   fmt.Sprintf("Tag '%s' is not in the allowed tags list", tag),
					Field:     "tags",
					Timestamp: time.Now(),
				})
				result.Score -= 2
			}
		}
	}

	// Validate dependencies
	if len(metadata.Dependencies) > v.config.MaxDependencies {
		result.Errors = append(result.Errors, ValidationError{
			Type:      "metadata_validation",
			Message:   fmt.Sprintf("Too many dependencies: %d (max: %d)", len(metadata.Dependencies), v.config.MaxDependencies),
			Field:     "dependencies",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Valid = false
		result.Score -= 15
	}

	return result, nil
}

// ValidateDependencies validates chain dependencies
func (v *DefaultChainValidator) ValidateDependencies(ctx context.Context, dependencies []string, registry ChainRegistry) (ValidationResult, error) {
	result := ValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Score:       100.0,
		Suggestions: []string{},
	}

	// Check if all dependencies exist
	for _, dep := range dependencies {
		if !registry.Exists(ctx, dep) {
			result.Errors = append(result.Errors, ValidationError{
				Type:      "dependency_validation",
				Message:   fmt.Sprintf("Dependency '%s' not found", dep),
				Field:     "dependencies",
				Severity:  "error",
				Timestamp: time.Now(),
			})
			result.Valid = false
			result.Score -= 20
		}
	}

	return result, nil
}

// ValidateCircularDependencies checks for circular dependencies
func (v *DefaultChainValidator) ValidateCircularDependencies(ctx context.Context, chainID string, dependencies []string, registry ChainRegistry) (ValidationResult, error) {
	result := ValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Score:       100.0,
		Suggestions: []string{},
	}

	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)

	if v.hasCircularDependency(ctx, chainID, dependencies, registry, visited, recursionStack) {
		result.Errors = append(result.Errors, ValidationError{
			Type:      "dependency_validation",
			Message:   "Circular dependency detected",
			Field:     "dependencies",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Valid = false
		result.Score = 0
	}

	return result, nil
}

// AddCustomValidator adds a custom validator
func (v *DefaultChainValidator) AddCustomValidator(name string, validator CustomValidator) error {
	if validator == nil {
		return fmt.Errorf("validator cannot be nil")
	}
	v.customValidators[name] = validator
	return nil
}

// RemoveCustomValidator removes a custom validator
func (v *DefaultChainValidator) RemoveCustomValidator(name string) error {
	delete(v.customValidators, name)
	return nil
}

// RunCustomValidators runs all custom validators
func (v *DefaultChainValidator) RunCustomValidators(ctx context.Context, chain llm.Chain) (ValidationResult, error) {
	result := ValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Score:       100.0,
		Suggestions: []string{},
	}

	for name, validator := range v.customValidators {
		customResult, err := validator(ctx, chain)
		if err != nil {
			v.logger.Warn("Custom validator failed", "validator", name, "error", err)
			continue
		}
		v.mergeValidationResults(&result, customResult)
	}

	return result, nil
}

// Helper methods

// validateBasicProperties validates basic chain properties
func (v *DefaultChainValidator) validateBasicProperties(chain llm.Chain, result *ValidationResult) error {
	// Validate ID
	if chain.ID() == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "basic_validation",
			Message:   "Chain ID is required",
			Field:     "id",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 20
	}

	// Validate name
	if chain.Name() == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "basic_validation",
			Message:   "Chain name is required",
			Field:     "name",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 20
	} else if len(chain.Name()) > v.config.MaxNameLength {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:      "basic_validation",
			Message:   fmt.Sprintf("Chain name is too long: %d characters (max: %d)", len(chain.Name()), v.config.MaxNameLength),
			Field:     "name",
			Timestamp: time.Now(),
		})
		result.Score -= 5
	}

	// Validate description
	if chain.Description() == "" {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:      "basic_validation",
			Message:   "Chain description is recommended for better documentation",
			Field:     "description",
			Timestamp: time.Now(),
		})
		result.Score -= 5
	} else if len(chain.Description()) > v.config.MaxDescriptionLength {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:      "basic_validation",
			Message:   fmt.Sprintf("Chain description is too long: %d characters (max: %d)", len(chain.Description()), v.config.MaxDescriptionLength),
			Field:     "description",
			Timestamp: time.Now(),
		})
		result.Score -= 5
	}

	return nil
}

// validatePromptInjection checks for potential prompt injection vulnerabilities
func (v *DefaultChainValidator) validatePromptInjection(chain llm.Chain, result *ValidationResult) {
	// This is a simplified check - in production, you'd use more sophisticated detection
	suspiciousPatterns := []string{
		"ignore previous instructions",
		"forget everything",
		"system:",
		"assistant:",
		"user:",
		"<script>",
		"javascript:",
	}

	description := strings.ToLower(chain.Description())
	name := strings.ToLower(chain.Name())

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(description, pattern) || strings.Contains(name, pattern) {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Type:      "security_validation",
				Message:   fmt.Sprintf("Potential prompt injection pattern detected: %s", pattern),
				Timestamp: time.Now(),
			})
			result.Score -= 10
		}
	}
}

// validateDataLeakage checks for potential data leakage issues
func (v *DefaultChainValidator) validateDataLeakage(chain llm.Chain, result *ValidationResult) {
	// Check for sensitive data patterns
	sensitivePatterns := []string{
		"password",
		"secret",
		"token",
		"api_key",
		"private_key",
		"ssn",
		"credit_card",
	}

	description := strings.ToLower(chain.Description())

	for _, pattern := range sensitivePatterns {
		if strings.Contains(description, pattern) {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Type:      "security_validation",
				Message:   fmt.Sprintf("Potential sensitive data reference detected: %s", pattern),
				Timestamp: time.Now(),
			})
			result.Score -= 5
		}
	}
}

// validateMaliciousCode checks for potentially malicious code patterns
func (v *DefaultChainValidator) validateMaliciousCode(chain llm.Chain, result *ValidationResult) {
	// This is a basic check - in production, you'd use more sophisticated analysis
	maliciousPatterns := []string{
		"eval(",
		"exec(",
		"system(",
		"shell_exec",
		"file_get_contents",
		"curl_exec",
	}

	description := strings.ToLower(chain.Description())

	for _, pattern := range maliciousPatterns {
		if strings.Contains(description, pattern) {
			result.Errors = append(result.Errors, ValidationError{
				Type:      "security_validation",
				Message:   fmt.Sprintf("Potentially malicious code pattern detected: %s", pattern),
				Severity:  "high",
				Timestamp: time.Now(),
			})
			result.Valid = false
			result.Score -= 30
		}
	}
}

// validatePerformanceConstraints validates performance-related constraints
func (v *DefaultChainValidator) validatePerformanceConstraints(chain llm.Chain, result *ValidationResult) {
	// This would typically involve more sophisticated analysis
	// For now, we'll do basic checks

	if len(chain.Description()) > 10000 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:      "performance_validation",
			Message:   "Very long description may impact performance",
			Timestamp: time.Now(),
		})
		result.Score -= 5
	}
}

// isValidVersion checks if a version string follows semantic versioning
func (v *DefaultChainValidator) isValidVersion(version string) bool {
	// Simple semantic versioning check
	semverPattern := `^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`
	matched, _ := regexp.MatchString(semverPattern, version)
	return matched
}

// hasCircularDependency checks for circular dependencies using DFS
func (v *DefaultChainValidator) hasCircularDependency(ctx context.Context, chainID string, dependencies []string, registry ChainRegistry, visited, recursionStack map[string]bool) bool {
	visited[chainID] = true
	recursionStack[chainID] = true

	for _, dep := range dependencies {
		if !visited[dep] {
			depDependencies, _ := registry.GetDependencies(ctx, dep)
			if v.hasCircularDependency(ctx, dep, depDependencies, registry, visited, recursionStack) {
				return true
			}
		} else if recursionStack[dep] {
			return true
		}
	}

	recursionStack[chainID] = false
	return false
}

// mergeValidationResults merges two validation results
func (v *DefaultChainValidator) mergeValidationResults(target *ValidationResult, source ValidationResult) {
	if !source.Valid {
		target.Valid = false
	}
	target.Errors = append(target.Errors, source.Errors...)
	target.Warnings = append(target.Warnings, source.Warnings...)
	target.Suggestions = append(target.Suggestions, source.Suggestions...)

	// Average the scores
	target.Score = (target.Score + source.Score) / 2
}

// calculateFinalScore calculates the final validation score
func (v *DefaultChainValidator) calculateFinalScore(result *ValidationResult) {
	// Ensure score doesn't go below 0
	if result.Score < 0 {
		result.Score = 0
	}

	// If there are critical errors, set score to 0
	for _, err := range result.Errors {
		if err.Severity == "critical" {
			result.Score = 0
			result.Valid = false
			break
		}
	}
}

// ValidateConfiguration validates a chain configuration
func (v *DefaultChainValidator) ValidateConfiguration(ctx context.Context, config ChainConfiguration) (ValidationResult, error) {
	result := ValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Score:       100.0,
		Suggestions: []string{},
	}

	// Validate basic fields
	if config.ID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "config_validation",
			Message:   "Configuration ID is required",
			Field:     "id",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 20
	}

	if config.Name == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "config_validation",
			Message:   "Configuration name is required",
			Field:     "name",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 20
	}

	// Validate timeout
	if config.Timeout < 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "config_validation",
			Message:   "Timeout cannot be negative",
			Field:     "timeout",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 15
	}

	// Validate max retries
	if config.MaxRetries < 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "config_validation",
			Message:   "Max retries cannot be negative",
			Field:     "max_retries",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 10
	}

	return result, nil
}

// ValidatePerformanceConstraints validates performance constraints
func (v *DefaultChainValidator) ValidatePerformanceConstraints(ctx context.Context, chain llm.Chain) (ValidationResult, error) {
	result := ValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Score:       100.0,
		Suggestions: []string{},
	}

	v.validatePerformanceConstraints(chain, &result)
	return result, nil
}

// ValidateResourceUsage validates resource usage constraints
func (v *DefaultChainValidator) ValidateResourceUsage(ctx context.Context, chain llm.Chain) (ValidationResult, error) {
	result := ValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Score:       100.0,
		Suggestions: []string{},
	}

	// Basic resource usage validation
	if len(chain.Description()) > 50000 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:      "resource_validation",
			Message:   "Very large description may consume excessive memory",
			Timestamp: time.Now(),
		})
		result.Score -= 10
	}

	return result, nil
}

// ValidateSecurityConstraints validates security constraints
func (v *DefaultChainValidator) ValidateSecurityConstraints(ctx context.Context, chain llm.Chain) (ValidationResult, error) {
	result := ValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Score:       100.0,
		Suggestions: []string{},
	}

	// Run security checks
	if v.config.SecurityChecks.CheckPromptInjection {
		v.validatePromptInjection(chain, &result)
	}

	if v.config.SecurityChecks.CheckDataLeakage {
		v.validateDataLeakage(chain, &result)
	}

	if v.config.SecurityChecks.CheckMaliciousCode {
		v.validateMaliciousCode(chain, &result)
	}

	return result, nil
}

// ValidatePermissions validates chain permissions
func (v *DefaultChainValidator) ValidatePermissions(ctx context.Context, permissions ChainPermissions) (ValidationResult, error) {
	result := ValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Score:       100.0,
		Suggestions: []string{},
	}

	// Validate that chain ID is set
	if permissions.ChainID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:      "permission_validation",
			Message:   "Chain ID is required in permissions",
			Field:     "chain_id",
			Severity:  "error",
			Timestamp: time.Now(),
		})
		result.Score -= 30
	}

	// Validate that at least one owner is specified
	if len(permissions.Owners) == 0 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:      "permission_validation",
			Message:   "No owners specified - chain may become unmanageable",
			Field:     "owners",
			Timestamp: time.Now(),
		})
		result.Score -= 10
	}

	return result, nil
}
