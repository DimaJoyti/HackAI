package infrastructure

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var securityTracer = otel.Tracer("hackai/infrastructure/security")

// SecurityValidator provides input validation and filtering for LLM operations
type SecurityValidator struct {
	config *LLMSecurityConfig
	logger *logger.Logger

	// Compiled regex patterns for performance
	blockedPatterns   []*regexp.Regexp
	sensitivePatterns []*regexp.Regexp
}

// NewSecurityValidator creates a new security validator
func NewSecurityValidator(config *LLMSecurityConfig, logger *logger.Logger) (*SecurityValidator, error) {
	validator := &SecurityValidator{
		config: config,
		logger: logger,
	}

	// Compile blocked patterns
	for _, pattern := range config.BlockedPatterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile blocked pattern %s: %w", pattern, err)
		}
		validator.blockedPatterns = append(validator.blockedPatterns, regex)
	}

	// Compile sensitive data patterns
	sensitivePatterns := []string{
		`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`,                       // Credit card numbers
		`\b\d{3}-\d{2}-\d{4}\b`,                                            // SSN
		`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,              // Email addresses
		`\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`, // Phone numbers
		`\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*[^\s]+\b`,        // API keys/tokens
	}

	for _, pattern := range sensitivePatterns {
		regex, err := regexp.Compile(`(?i)` + pattern) // Case insensitive
		if err != nil {
			return nil, fmt.Errorf("failed to compile sensitive pattern %s: %w", pattern, err)
		}
		validator.sensitivePatterns = append(validator.sensitivePatterns, regex)
	}

	return validator, nil
}

// ValidationResult represents the result of input validation
type ValidationResult struct {
	Valid              bool     `json:"valid"`
	Blocked            bool     `json:"blocked"`
	SensitiveDataFound bool     `json:"sensitive_data_found"`
	Issues             []string `json:"issues"`
	SanitizedInput     string   `json:"sanitized_input,omitempty"`
}

// ValidateInput validates and sanitizes input text
func (sv *SecurityValidator) ValidateInput(ctx context.Context, input string) *ValidationResult {
	ctx, span := securityTracer.Start(ctx, "security_validator.validate_input",
		trace.WithAttributes(
			attribute.Int("input.length", len(input)),
		),
	)
	defer span.End()

	result := &ValidationResult{
		Valid:          true,
		Issues:         make([]string, 0),
		SanitizedInput: input,
	}

	// Check input length
	if len(input) > sv.config.MaxPromptLength {
		result.Valid = false
		result.Issues = append(result.Issues, fmt.Sprintf("Input too long: %d characters (max: %d)", len(input), sv.config.MaxPromptLength))
	}

	// Check for blocked patterns
	if sv.config.EnableInputValidation {
		for _, pattern := range sv.blockedPatterns {
			if pattern.MatchString(input) {
				result.Valid = false
				result.Blocked = true
				result.Issues = append(result.Issues, fmt.Sprintf("Input contains blocked pattern: %s", pattern.String()))

				span.AddEvent("blocked_pattern_detected", trace.WithAttributes(
					attribute.String("pattern", pattern.String()),
				))
			}
		}
	}

	// Check for sensitive data
	if sv.config.SensitiveDataDetection {
		for _, pattern := range sv.sensitivePatterns {
			if pattern.MatchString(input) {
				result.SensitiveDataFound = true
				result.Issues = append(result.Issues, "Input contains potentially sensitive data")

				// Sanitize by replacing with placeholder
				result.SanitizedInput = pattern.ReplaceAllString(result.SanitizedInput, "[REDACTED]")

				span.AddEvent("sensitive_data_detected", trace.WithAttributes(
					attribute.String("pattern", pattern.String()),
				))
			}
		}
	}

	// Additional sanitization
	result.SanitizedInput = sv.sanitizeInput(result.SanitizedInput)

	span.SetAttributes(
		attribute.Bool("validation.valid", result.Valid),
		attribute.Bool("validation.blocked", result.Blocked),
		attribute.Bool("validation.sensitive_data", result.SensitiveDataFound),
		attribute.Int("validation.issues", len(result.Issues)),
	)

	if !result.Valid {
		sv.logger.Warn("Input validation failed",
			"issues", result.Issues,
			"input_length", len(input),
		)
	}

	return result
}

// ValidateOutput validates LLM output for safety
func (sv *SecurityValidator) ValidateOutput(ctx context.Context, output string) *ValidationResult {
	ctx, span := securityTracer.Start(ctx, "security_validator.validate_output",
		trace.WithAttributes(
			attribute.Int("output.length", len(output)),
		),
	)
	defer span.End()

	result := &ValidationResult{
		Valid:          true,
		Issues:         make([]string, 0),
		SanitizedInput: output,
	}

	// Check output length
	if len(output) > sv.config.MaxResponseLength {
		result.Valid = false
		result.Issues = append(result.Issues, fmt.Sprintf("Output too long: %d characters (max: %d)", len(output), sv.config.MaxResponseLength))
	}

	// Check for sensitive data in output
	if sv.config.EnableOutputFiltering {
		for _, pattern := range sv.sensitivePatterns {
			if pattern.MatchString(output) {
				result.SensitiveDataFound = true
				result.Issues = append(result.Issues, "Output contains potentially sensitive data")

				// Sanitize output
				result.SanitizedInput = pattern.ReplaceAllString(result.SanitizedInput, "[REDACTED]")

				span.AddEvent("sensitive_data_in_output", trace.WithAttributes(
					attribute.String("pattern", pattern.String()),
				))
			}
		}
	}

	span.SetAttributes(
		attribute.Bool("validation.valid", result.Valid),
		attribute.Bool("validation.sensitive_data", result.SensitiveDataFound),
		attribute.Int("validation.issues", len(result.Issues)),
	)

	return result
}

// sanitizeInput performs basic input sanitization
func (sv *SecurityValidator) sanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Normalize whitespace
	input = strings.TrimSpace(input)

	// Remove excessive whitespace
	spaceRegex := regexp.MustCompile(`\s+`)
	input = spaceRegex.ReplaceAllString(input, " ")

	return input
}

// SecurityMiddleware provides HTTP middleware for security validation
type SecurityMiddleware struct {
	validator *SecurityValidator
	config    *LLMSecurityConfig
	logger    *logger.Logger
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(validator *SecurityValidator, config *LLMSecurityConfig, logger *logger.Logger) *SecurityMiddleware {
	return &SecurityMiddleware{
		validator: validator,
		config:    config,
		logger:    logger,
	}
}

// Handler returns the HTTP middleware handler
func (m *SecurityMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := securityTracer.Start(r.Context(), "security_middleware",
			trace.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.url", r.URL.Path),
			),
		)
		defer span.End()

		// Add security headers
		m.addSecurityHeaders(w)

		// Validate request if it contains input data
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			if err := m.validateRequest(ctx, r); err != nil {
				span.RecordError(err)
				http.Error(w, "Request validation failed", http.StatusBadRequest)
				return
			}
		}

		// Log security event if audit logging is enabled
		if m.config.AuditLogging {
			m.logSecurityEvent(ctx, r)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// addSecurityHeaders adds security headers to the response
func (m *SecurityMiddleware) addSecurityHeaders(w http.ResponseWriter) {
	// Prevent MIME type sniffing
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Prevent clickjacking
	w.Header().Set("X-Frame-Options", "DENY")

	// XSS protection
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Referrer policy
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Content Security Policy (basic)
	w.Header().Set("Content-Security-Policy", "default-src 'self'")

	// HSTS (if HTTPS)
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
}

// validateRequest validates the incoming request
func (m *SecurityMiddleware) validateRequest(ctx context.Context, r *http.Request) error {
	// This is a simplified validation - in practice, you'd parse the request body
	// and validate specific fields based on the endpoint

	// For now, just validate the User-Agent header as an example
	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		result := m.validator.ValidateInput(ctx, userAgent)
		if result.Blocked {
			return fmt.Errorf("blocked user agent: %v", result.Issues)
		}
	}

	return nil
}

// logSecurityEvent logs security-related events
func (m *SecurityMiddleware) logSecurityEvent(ctx context.Context, r *http.Request) {
	event := map[string]interface{}{
		"timestamp":   time.Now(),
		"method":      r.Method,
		"url":         r.URL.String(),
		"user_agent":  r.Header.Get("User-Agent"),
		"remote_addr": r.RemoteAddr,
		"headers":     r.Header,
	}

	// Add user context if available
	if userID := getUserIDFromContext(ctx); userID != "" {
		event["user_id"] = userID
	}

	m.logger.Info("Security audit log", "event", event)
}

// AuditLogger provides audit logging for LLM operations
type AuditLogger struct {
	logger *logger.Logger
	config *LLMSecurityConfig
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logger *logger.Logger, config *LLMSecurityConfig) *AuditLogger {
	return &AuditLogger{
		logger: logger,
		config: config,
	}
}

// LogLLMRequest logs an LLM request for audit purposes
func (al *AuditLogger) LogLLMRequest(ctx context.Context, userID, prompt, model string) {
	if !al.config.AuditLogging {
		return
	}

	event := map[string]interface{}{
		"event_type":    "llm_request",
		"timestamp":     time.Now(),
		"user_id":       userID,
		"model":         model,
		"prompt_length": len(prompt),
	}

	// Include prompt if not sensitive
	if !al.containsSensitiveData(prompt) {
		event["prompt"] = prompt
	} else {
		event["prompt"] = "[REDACTED - SENSITIVE DATA]"
	}

	al.logger.Info("LLM request audit", "event", event)
}

// LogLLMResponse logs an LLM response for audit purposes
func (al *AuditLogger) LogLLMResponse(ctx context.Context, userID, response, model string, tokensUsed int) {
	if !al.config.AuditLogging {
		return
	}

	event := map[string]interface{}{
		"event_type":      "llm_response",
		"timestamp":       time.Now(),
		"user_id":         userID,
		"model":           model,
		"response_length": len(response),
		"tokens_used":     tokensUsed,
	}

	// Include response if not sensitive
	if !al.containsSensitiveData(response) {
		event["response"] = response
	} else {
		event["response"] = "[REDACTED - SENSITIVE DATA]"
	}

	al.logger.Info("LLM response audit", "event", event)
}

// containsSensitiveData checks if text contains sensitive data
func (al *AuditLogger) containsSensitiveData(text string) bool {
	// Simple check for common sensitive patterns
	sensitiveKeywords := []string{
		"password", "token", "key", "secret", "credit card",
		"ssn", "social security", "api_key", "private",
	}

	textLower := strings.ToLower(text)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(textLower, keyword) {
			return true
		}
	}

	return false
}

// SecurityHealthChecker checks security component health
type SecurityHealthChecker struct {
	validator *SecurityValidator
	logger    *logger.Logger
}

// NewSecurityHealthChecker creates a new security health checker
func NewSecurityHealthChecker(validator *SecurityValidator, logger *logger.Logger) *SecurityHealthChecker {
	return &SecurityHealthChecker{
		validator: validator,
		logger:    logger,
	}
}

// Name returns the checker name
func (c *SecurityHealthChecker) Name() string {
	return "security"
}

// Check performs the security component health check
func (c *SecurityHealthChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()

	// Test validation with a safe input
	testInput := "This is a test input for health check"
	result := c.validator.ValidateInput(ctx, testInput)

	if !result.Valid {
		return ComponentHealth{
			Name:        c.Name(),
			Status:      HealthStatusUnhealthy,
			Message:     fmt.Sprintf("Security validator failed test: %v", result.Issues),
			LastChecked: time.Now(),
			Duration:    time.Since(start),
		}
	}

	metadata := map[string]interface{}{
		"blocked_patterns_count":   len(c.validator.blockedPatterns),
		"sensitive_patterns_count": len(c.validator.sensitivePatterns),
		"input_validation_enabled": c.validator.config.EnableInputValidation,
		"output_filtering_enabled": c.validator.config.EnableOutputFiltering,
		"sensitive_data_detection": c.validator.config.SensitiveDataDetection,
	}

	return ComponentHealth{
		Name:        c.Name(),
		Status:      HealthStatusHealthy,
		Message:     "Security validator is healthy",
		LastChecked: time.Now(),
		Duration:    time.Since(start),
		Metadata:    metadata,
	}
}
