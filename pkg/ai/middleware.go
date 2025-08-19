package ai

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var middlewareTracer = otel.Tracer("hackai/ai/middleware")

// SecurityMiddleware provides security validation for chain execution
type SecurityMiddleware struct {
	id                string
	logger            *logger.Logger
	tracer            trace.Tracer
	maxInputSize      int
	allowedInputTypes map[string]bool
	securityLevel     SecurityLevel
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(id string, securityLevel SecurityLevel, logger *logger.Logger) *SecurityMiddleware {
	return &SecurityMiddleware{
		id:            id,
		logger:        logger,
		tracer:        middlewareTracer,
		maxInputSize:  1024 * 1024, // 1MB default
		securityLevel: securityLevel,
		allowedInputTypes: map[string]bool{
			"string": true,
			"int":    true,
			"float":  true,
			"bool":   true,
			"map":    true,
			"slice":  true,
		},
	}
}

// ID returns the middleware ID
func (m *SecurityMiddleware) ID() string {
	return m.id
}

// PreExecute validates security constraints before chain execution
func (m *SecurityMiddleware) PreExecute(ctx context.Context, execCtx ChainExecutionContext, input map[string]interface{}) error {
	ctx, span := m.tracer.Start(ctx, "security_middleware.pre_execute",
		trace.WithAttributes(
			attribute.String("middleware.id", m.id),
			attribute.String("security.level", string(m.securityLevel)),
		),
	)
	defer span.End()

	// Validate security level compatibility
	// Higher security levels have higher requirements, so execution level should not exceed middleware level
	securityLevels := map[SecurityLevel]int{
		SecurityLevelLow:      1,
		SecurityLevelMedium:   2,
		SecurityLevelHigh:     3,
		SecurityLevelCritical: 4,
	}

	if securityLevels[execCtx.SecurityLevel] > securityLevels[m.securityLevel] {
		err := fmt.Errorf("execution security level %s exceeds middleware security level %s",
			execCtx.SecurityLevel, m.securityLevel)
		span.RecordError(err)
		return err
	}

	// Validate input size
	inputSize := m.calculateInputSize(input)
	if inputSize > m.maxInputSize {
		err := fmt.Errorf("input size %d exceeds maximum allowed size %d", inputSize, m.maxInputSize)
		span.RecordError(err)
		return err
	}

	// Validate input types
	if err := m.validateInputTypes(input); err != nil {
		span.RecordError(err)
		return err
	}

	// Check for potential injection patterns
	if err := m.checkForInjectionPatterns(input); err != nil {
		span.RecordError(err)
		return err
	}

	if m.logger != nil {
		m.logger.Debug("Security validation passed",
			"middleware_id", m.id,
			"input_size", inputSize,
			"security_level", m.securityLevel)
	}

	return nil
}

// PostExecute performs security validation after chain execution
func (m *SecurityMiddleware) PostExecute(ctx context.Context, execCtx ChainExecutionContext, result *ChainExecutionResult) error {
	ctx, span := m.tracer.Start(ctx, "security_middleware.post_execute",
		trace.WithAttributes(
			attribute.String("middleware.id", m.id),
			attribute.Bool("execution.success", result.Success),
		),
	)
	defer span.End()

	// Validate output if execution was successful
	if result.Success && result.Output != nil {
		if err := m.validateOutput(result.Output); err != nil {
			span.RecordError(err)
			if m.logger != nil {
				m.logger.Warn("Output validation failed",
					"middleware_id", m.id,
					"error", err)
			}
			// Don't fail the execution, just log the warning
		}
	}

	return nil
}

// calculateInputSize estimates the size of input data
func (m *SecurityMiddleware) calculateInputSize(input map[string]interface{}) int {
	size := 0
	for key, value := range input {
		size += len(key)
		switch v := value.(type) {
		case string:
			size += len(v)
		case []byte:
			size += len(v)
		case map[string]interface{}:
			size += m.calculateInputSize(v)
		default:
			size += 64 // Estimate for other types
		}
	}
	return size
}

// validateInputTypes validates that input types are allowed
func (m *SecurityMiddleware) validateInputTypes(input map[string]interface{}) error {
	for key, value := range input {
		valueType := fmt.Sprintf("%T", value)
		if !m.allowedInputTypes[valueType] && !m.isAllowedComplexType(value) {
			return fmt.Errorf("input type %s for key %s is not allowed", valueType, key)
		}
	}
	return nil
}

// isAllowedComplexType checks if complex types are allowed
func (m *SecurityMiddleware) isAllowedComplexType(value interface{}) bool {
	switch value.(type) {
	case map[string]interface{}:
		return true
	case []interface{}:
		return true
	case []string:
		return true
	case []int:
		return true
	case []float64:
		return true
	default:
		return false
	}
}

// checkForInjectionPatterns checks for potential injection patterns
func (m *SecurityMiddleware) checkForInjectionPatterns(input map[string]interface{}) error {
	suspiciousPatterns := []string{
		"<script",
		"javascript:",
		"eval(",
		"exec(",
		"system(",
		"DROP TABLE",
		"DELETE FROM",
		"INSERT INTO",
		"UPDATE SET",
	}

	for key, value := range input {
		if str, ok := value.(string); ok {
			for _, pattern := range suspiciousPatterns {
				if containsPattern(str, pattern) {
					return fmt.Errorf("suspicious pattern '%s' detected in input key '%s'", pattern, key)
				}
			}
		}
	}
	return nil
}

// validateOutput validates the output data
func (m *SecurityMiddleware) validateOutput(output map[string]interface{}) error {
	// Check for sensitive data patterns in output
	sensitivePatterns := []string{
		"password",
		"secret",
		"token",
		"key",
		"credential",
	}

	for key := range output {
		for _, pattern := range sensitivePatterns {
			if containsPattern(key, pattern) {
				return fmt.Errorf("potentially sensitive data '%s' detected in output", key)
			}
		}
	}
	return nil
}

// containsPattern checks if a string contains a substring (case-insensitive)
func containsPattern(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsSubstring(s, substr))))
}

// containsSubstring checks if string contains substring
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// MetricsMiddleware collects detailed metrics for chain execution
type MetricsMiddleware struct {
	id     string
	logger *logger.Logger
	tracer trace.Tracer
}

// NewMetricsMiddleware creates a new metrics middleware
func NewMetricsMiddleware(id string, logger *logger.Logger) *MetricsMiddleware {
	return &MetricsMiddleware{
		id:     id,
		logger: logger,
		tracer: middlewareTracer,
	}
}

// ID returns the middleware ID
func (m *MetricsMiddleware) ID() string {
	return m.id
}

// PreExecute records metrics before chain execution
func (m *MetricsMiddleware) PreExecute(ctx context.Context, execCtx ChainExecutionContext, input map[string]interface{}) error {
	ctx, span := m.tracer.Start(ctx, "metrics_middleware.pre_execute",
		trace.WithAttributes(
			attribute.String("middleware.id", m.id),
			attribute.String("request.id", execCtx.RequestID),
		),
	)
	defer span.End()

	// Record pre-execution metrics
	if m.logger != nil {
		m.logger.Info("Chain execution starting",
			"middleware_id", m.id,
			"request_id", execCtx.RequestID,
			"user_id", execCtx.UserID,
			"session_id", execCtx.SessionID,
			"security_level", execCtx.SecurityLevel,
			"start_time", execCtx.StartTime,
		)
	}

	return nil
}

// PostExecute records metrics after chain execution
func (m *MetricsMiddleware) PostExecute(ctx context.Context, execCtx ChainExecutionContext, result *ChainExecutionResult) error {
	ctx, span := m.tracer.Start(ctx, "metrics_middleware.post_execute",
		trace.WithAttributes(
			attribute.String("middleware.id", m.id),
			attribute.Bool("execution.success", result.Success),
			attribute.String("execution.duration", result.ExecutionTime.String()),
		),
	)
	defer span.End()

	// Record post-execution metrics
	if m.logger != nil {
		m.logger.Info("Chain execution completed",
			"middleware_id", m.id,
			"request_id", execCtx.RequestID,
			"success", result.Success,
			"execution_time", result.ExecutionTime,
			"tokens_used", result.TokensUsed,
			"cost", result.Cost,
			"steps_count", len(result.Steps),
		)
	}

	return nil
}
