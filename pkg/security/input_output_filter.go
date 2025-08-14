package security

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// InputOutputFilter comprehensive input validation and output sanitization
type InputOutputFilter struct {
	logger           *logger.Logger
	config           *FilterConfig
	inputValidator   *InputValidator
	outputSanitizer  *OutputSanitizer
	contentAnalyzer  *ContentAnalyzer
	encodingDetector *EncodingDetector
	threatScanner    *ThreatScanner
}

// FilterConfig configuration for input/output filtering
type FilterConfig struct {
	EnableInputValidation    bool     `json:"enable_input_validation"`
	EnableOutputSanitization bool     `json:"enable_output_sanitization"`
	EnableContentAnalysis    bool     `json:"enable_content_analysis"`
	EnableThreatScanning     bool     `json:"enable_threat_scanning"`
	StrictMode               bool     `json:"strict_mode"`
	MaxInputLength           int      `json:"max_input_length"`
	MaxOutputLength          int      `json:"max_output_length"`
	AllowedFileTypes         []string `json:"allowed_file_types"`
	BlockedPatterns          []string `json:"blocked_patterns"`
	SanitizationLevel        string   `json:"sanitization_level"` // basic, standard, strict
	LogViolations            bool     `json:"log_violations"`
	BlockOnViolation         bool     `json:"block_on_violation"`
}

// InputValidator validates and sanitizes input data
type InputValidator struct {
	logger          *logger.Logger
	config          *FilterConfig
	validationRules []*ValidationRule
	sanitizers      map[string]Sanitizer
}

// OutputSanitizerInterface defines the interface for output sanitizers
type OutputSanitizerInterface interface {
	SanitizeOutput(output string) string
}

// OutputSanitizer sanitizes output data
type OutputSanitizer struct {
	logger     *logger.Logger
	config     *FilterConfig
	sanitizers map[string]OutputSanitizerInterface
}

// ValidationRule represents an input validation rule
type ValidationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Field       string                 `json:"field"`
	Type        string                 `json:"type"`
	Pattern     string                 `json:"pattern"`
	Required    bool                   `json:"required"`
	MinLength   int                    `json:"min_length"`
	MaxLength   int                    `json:"max_length"`
	AllowedVals []string               `json:"allowed_values"`
	Sanitize    bool                   `json:"sanitize"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// FilterResult represents the result of filtering operation
type FilterResult struct {
	ID              string                 `json:"id"`
	Valid           bool                   `json:"valid"`
	Sanitized       bool                   `json:"sanitized"`
	Blocked         bool                   `json:"blocked"`
	OriginalData    interface{}            `json:"original_data"`
	FilteredData    interface{}            `json:"filtered_data"`
	Violations      []*Violation           `json:"violations"`
	ThreatScore     float64                `json:"threat_score"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
	ProcessedAt     time.Time              `json:"processed_at"`
}

// Violation represents a validation or security violation
type Violation struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Severity   string                 `json:"severity"`
	Field      string                 `json:"field"`
	Rule       string                 `json:"rule"`
	Message    string                 `json:"message"`
	Evidence   string                 `json:"evidence"`
	Confidence float64                `json:"confidence"`
	Metadata   map[string]interface{} `json:"metadata"`
	DetectedAt time.Time              `json:"detected_at"`
}

// Sanitizer interface for different sanitization strategies
type Sanitizer interface {
	Sanitize(input string) (string, error)
	GetType() string
}

// NewInputOutputFilter creates a new input/output filter
func NewInputOutputFilter(config *FilterConfig, logger *logger.Logger) *InputOutputFilter {
	filter := &InputOutputFilter{
		logger: logger,
		config: config,
	}

	// Initialize components
	filter.inputValidator = NewInputValidator(config, logger)
	filter.outputSanitizer = NewOutputSanitizer(config, logger)
	filter.contentAnalyzer = NewContentAnalyzer(logger)
	filter.encodingDetector = NewEncodingDetector(logger)
	filter.threatScanner = NewThreatScanner(logger)

	return filter
}

// FilterInput validates and sanitizes input data
func (iof *InputOutputFilter) FilterInput(ctx context.Context, data interface{}, rules []*ValidationRule) (*FilterResult, error) {
	result := &FilterResult{
		ID:           uuid.New().String(),
		OriginalData: data,
		ProcessedAt:  time.Now(),
		Violations:   make([]*Violation, 0),
		Metadata:     make(map[string]interface{}),
	}

	// Convert data to string for processing
	inputStr := iof.convertToString(data)

	// Length validation
	if len(inputStr) > iof.config.MaxInputLength {
		violation := &Violation{
			ID:         uuid.New().String(),
			Type:       "length_violation",
			Severity:   "medium",
			Message:    fmt.Sprintf("Input exceeds maximum length of %d characters", iof.config.MaxInputLength),
			Evidence:   fmt.Sprintf("Length: %d", len(inputStr)),
			Confidence: 1.0,
			DetectedAt: time.Now(),
		}
		result.Violations = append(result.Violations, violation)

		if iof.config.BlockOnViolation {
			result.Blocked = true
			return result, nil
		}
	}

	// Encoding detection and validation
	encoding := iof.encodingDetector.DetectEncoding(inputStr)
	if !iof.isValidEncoding(encoding) {
		violation := &Violation{
			ID:         uuid.New().String(),
			Type:       "encoding_violation",
			Severity:   "high",
			Message:    "Invalid or suspicious character encoding detected",
			Evidence:   fmt.Sprintf("Encoding: %s", encoding),
			Confidence: 0.8,
			DetectedAt: time.Now(),
		}
		result.Violations = append(result.Violations, violation)
	}

	// Content analysis
	if iof.config.EnableContentAnalysis {
		contentViolations := iof.contentAnalyzer.AnalyzeContent(inputStr)
		result.Violations = append(result.Violations, contentViolations...)
	}

	// Threat scanning
	if iof.config.EnableThreatScanning {
		threatResult := iof.threatScanner.ScanForThreats(inputStr)
		result.ThreatScore = threatResult.Score
		result.Violations = append(result.Violations, threatResult.Violations...)
	}

	// Rule-based validation
	if rules != nil {
		ruleViolations := iof.inputValidator.ValidateWithRules(inputStr, rules)
		result.Violations = append(result.Violations, ruleViolations...)
	}

	// Pattern-based validation
	patternViolations := iof.validatePatterns(inputStr)
	result.Violations = append(result.Violations, patternViolations...)

	// Sanitization
	sanitizedData, sanitized := iof.sanitizeInput(inputStr)
	result.FilteredData = sanitizedData
	result.Sanitized = sanitized

	// Calculate comprehensive threat score from all violations
	if result.ThreatScore == 0.0 && len(result.Violations) > 0 {
		result.ThreatScore = iof.calculateComprehensiveThreatScore(result.Violations)
	}

	// Determine if input is valid
	result.Valid = len(result.Violations) == 0 || !iof.hasBlockingViolations(result.Violations)

	// Generate recommendations
	result.Recommendations = iof.generateInputRecommendations(result)

	// Log violations if configured
	if iof.config.LogViolations && len(result.Violations) > 0 {
		iof.logViolations(result)
	}

	return result, nil
}

// FilterOutput sanitizes output data
func (iof *InputOutputFilter) FilterOutput(ctx context.Context, data interface{}) (*FilterResult, error) {
	result := &FilterResult{
		ID:           uuid.New().String(),
		OriginalData: data,
		ProcessedAt:  time.Now(),
		Violations:   make([]*Violation, 0),
		Metadata:     make(map[string]interface{}),
	}

	// Convert data to string for processing
	outputStr := iof.convertToString(data)

	// Length validation
	if len(outputStr) > iof.config.MaxOutputLength {
		outputStr = outputStr[:iof.config.MaxOutputLength]
		result.Sanitized = true
	}

	// Content sanitization
	sanitizedOutput := iof.outputSanitizer.SanitizeOutput(outputStr)
	result.FilteredData = sanitizedOutput
	result.Sanitized = sanitizedOutput != outputStr

	// Threat scanning for output
	if iof.config.EnableThreatScanning {
		threatResult := iof.threatScanner.ScanForThreats(sanitizedOutput)
		result.ThreatScore = threatResult.Score
		if threatResult.Score > 0.7 {
			// High threat score in output, apply additional sanitization
			result.FilteredData = iof.applySafeSanitization(sanitizedOutput)
			result.Sanitized = true
		}
	}

	result.Valid = true
	return result, nil
}

// validatePatterns validates input against blocked patterns
func (iof *InputOutputFilter) validatePatterns(input string) []*Violation {
	var violations []*Violation

	for _, pattern := range iof.config.BlockedPatterns {
		if matched, _ := regexp.MatchString(pattern, input); matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "pattern_violation",
				Severity:   "high",
				Rule:       pattern,
				Message:    "Input matches blocked pattern",
				Evidence:   input,
				Confidence: 0.9,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// sanitizeInput sanitizes input data
func (iof *InputOutputFilter) sanitizeInput(input string) (string, bool) {
	original := input
	sanitized := input

	// Only apply aggressive sanitization in strict mode
	if iof.config.StrictMode {
		// HTML encoding
		sanitized = html.EscapeString(sanitized)

		// URL encoding for special characters
		sanitized = url.QueryEscape(sanitized)
	}

	// Remove null bytes
	sanitized = strings.ReplaceAll(sanitized, "\x00", "")

	// Remove control characters
	sanitized = regexp.MustCompile(`[\x00-\x1F\x7F]`).ReplaceAllString(sanitized, "")

	// SQL injection prevention
	sqlPatterns := []string{
		`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)`,
		`(?i)(or|and)\s+\d+\s*=\s*\d+`,
		`(?i)'\s*(or|and)\s+'`,
		`(?i)--`,
		`(?i)/\*.*?\*/`,
	}

	for _, pattern := range sqlPatterns {
		re := regexp.MustCompile(pattern)
		sanitized = re.ReplaceAllString(sanitized, "")
	}

	// XSS prevention
	xssPatterns := []string{
		`(?i)<script[^>]*>.*?</script>`,
		`(?i)javascript:`,
		`(?i)on\w+\s*=`,
		`(?i)<iframe[^>]*>`,
		`(?i)<object[^>]*>`,
		`(?i)<embed[^>]*>`,
	}

	for _, pattern := range xssPatterns {
		re := regexp.MustCompile(pattern)
		sanitized = re.ReplaceAllString(sanitized, "")
	}

	return sanitized, sanitized != original
}

// applySafeSanitization applies safe sanitization for high-threat content
func (iof *InputOutputFilter) applySafeSanitization(input string) string {
	// Remove all HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	sanitized := re.ReplaceAllString(input, "")

	// Remove JavaScript
	jsRe := regexp.MustCompile(`(?i)javascript:[^"']*`)
	sanitized = jsRe.ReplaceAllString(sanitized, "")

	// Remove data URIs
	dataRe := regexp.MustCompile(`(?i)data:[^"']*`)
	sanitized = dataRe.ReplaceAllString(sanitized, "")

	// Encode remaining special characters
	sanitized = html.EscapeString(sanitized)

	return sanitized
}

// convertToString converts various data types to string
func (iof *InputOutputFilter) convertToString(data interface{}) string {
	switch v := data.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case int, int32, int64, float32, float64:
		return fmt.Sprintf("%v", v)
	default:
		// Try JSON marshaling for complex types
		if jsonData, err := json.Marshal(v); err == nil {
			return string(jsonData)
		}
		return fmt.Sprintf("%v", v)
	}
}

// isValidEncoding checks if the encoding is valid and safe
func (iof *InputOutputFilter) isValidEncoding(encoding string) bool {
	validEncodings := []string{"utf-8", "ascii", "iso-8859-1"}
	for _, valid := range validEncodings {
		if strings.EqualFold(encoding, valid) {
			return true
		}
	}
	return false
}

// hasBlockingViolations checks if any violations should block the request
func (iof *InputOutputFilter) hasBlockingViolations(violations []*Violation) bool {
	for _, violation := range violations {
		if violation.Severity == "critical" || violation.Severity == "high" {
			return true
		}
	}
	return false
}

// generateInputRecommendations generates recommendations for input filtering
func (iof *InputOutputFilter) generateInputRecommendations(result *FilterResult) []string {
	var recommendations []string

	if len(result.Violations) > 0 {
		recommendations = append(recommendations, "Review input for security violations")
	}

	if result.ThreatScore > 0.5 {
		recommendations = append(recommendations, "Apply additional sanitization")
		recommendations = append(recommendations, "Monitor source for suspicious activity")
	}

	if result.Sanitized {
		recommendations = append(recommendations, "Verify sanitized data meets requirements")
	}

	return recommendations
}

// logViolations logs security violations
func (iof *InputOutputFilter) logViolations(result *FilterResult) {
	for _, violation := range result.Violations {
		iof.logger.WithFields(logger.Fields{
			"violation_id":   violation.ID,
			"violation_type": violation.Type,
			"severity":       violation.Severity,
			"field":          violation.Field,
			"rule":           violation.Rule,
			"confidence":     violation.Confidence,
		}).Warn("Input validation violation detected")
	}
}

// DefaultFilterConfig returns default filter configuration
func DefaultFilterConfig() *FilterConfig {
	return &FilterConfig{
		EnableInputValidation:    true,
		EnableOutputSanitization: true,
		EnableContentAnalysis:    true,
		EnableThreatScanning:     true,
		StrictMode:               false,
		MaxInputLength:           100000,
		MaxOutputLength:          1000000,
		AllowedFileTypes:         []string{"txt", "json", "xml", "csv"},
		BlockedPatterns: []string{
			`(?i)(union|select|insert|update|delete|drop)\s+`,
			`(?i)<script[^>]*>`,
			`(?i)javascript:`,
			`(?i)on\w+\s*=`,
			`(?i)data:`,
			`(?i)file://`,
		},
		SanitizationLevel: "standard",
		LogViolations:     true,
		BlockOnViolation:  false,
	}
}

// ThreatScanResult represents the result of threat scanning
type ThreatScanResult struct {
	Score      float64      `json:"score"`
	Violations []*Violation `json:"violations"`
	Threats    []string     `json:"threats"`
}

// NewInputValidator creates a new input validator
func NewInputValidator(config *FilterConfig, logger *logger.Logger) *InputValidator {
	iv := &InputValidator{
		logger:          logger,
		config:          config,
		validationRules: make([]*ValidationRule, 0),
		sanitizers:      make(map[string]Sanitizer),
	}

	// Initialize default sanitizers
	iv.sanitizers["html"] = &HTMLSanitizer{}
	iv.sanitizers["sql"] = &SQLSanitizer{}
	iv.sanitizers["xss"] = &XSSSanitizer{}
	iv.sanitizers["path"] = &PathSanitizer{}
	iv.sanitizers["command"] = &CommandSanitizer{}

	return iv
}

// NewOutputSanitizer creates a new output sanitizer
func NewOutputSanitizer(config *FilterConfig, logger *logger.Logger) *OutputSanitizer {
	return &OutputSanitizer{
		logger: logger,
		config: config,
		sanitizers: map[string]OutputSanitizerInterface{
			"html":     &HTMLOutputSanitizer{},
			"json":     &JSONOutputSanitizer{},
			"xml":      &XMLOutputSanitizer{},
			"markdown": &MarkdownOutputSanitizer{},
		},
	}
}

// ValidateWithRules validates input against specific rules
func (iv *InputValidator) ValidateWithRules(input string, rules []*ValidationRule) []*Violation {
	var violations []*Violation

	for _, rule := range rules {
		ruleViolations := iv.validateRule(input, rule)
		violations = append(violations, ruleViolations...)
	}

	return violations
}

// validateRule validates input against a single rule
func (iv *InputValidator) validateRule(input string, rule *ValidationRule) []*Violation {
	var violations []*Violation

	// Required field validation
	if rule.Required && strings.TrimSpace(input) == "" {
		violation := &Violation{
			ID:         uuid.New().String(),
			Type:       "required_field",
			Severity:   "medium",
			Field:      rule.Field,
			Rule:       rule.ID,
			Message:    fmt.Sprintf("Required field '%s' is empty", rule.Field),
			Evidence:   "Empty input",
			Confidence: 1.0,
			DetectedAt: time.Now(),
		}
		violations = append(violations, violation)
		return violations
	}

	// Length validation
	if rule.MinLength > 0 && len(input) < rule.MinLength {
		violation := &Violation{
			ID:         uuid.New().String(),
			Type:       "length_violation",
			Severity:   "medium",
			Field:      rule.Field,
			Rule:       rule.ID,
			Message:    fmt.Sprintf("Input length %d is below minimum %d", len(input), rule.MinLength),
			Evidence:   fmt.Sprintf("Length: %d", len(input)),
			Confidence: 1.0,
			DetectedAt: time.Now(),
		}
		violations = append(violations, violation)
	}

	if rule.MaxLength > 0 && len(input) > rule.MaxLength {
		violation := &Violation{
			ID:         uuid.New().String(),
			Type:       "length_violation",
			Severity:   "medium",
			Field:      rule.Field,
			Rule:       rule.ID,
			Message:    fmt.Sprintf("Input length %d exceeds maximum %d", len(input), rule.MaxLength),
			Evidence:   fmt.Sprintf("Length: %d", len(input)),
			Confidence: 1.0,
			DetectedAt: time.Now(),
		}
		violations = append(violations, violation)
	}

	// Pattern validation
	if rule.Pattern != "" {
		if matched, _ := regexp.MatchString(rule.Pattern, input); !matched {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "pattern_violation",
				Severity:   "medium",
				Field:      rule.Field,
				Rule:       rule.ID,
				Message:    fmt.Sprintf("Input does not match required pattern for field '%s'", rule.Field),
				Evidence:   input,
				Confidence: 0.8,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	// Allowed values validation
	if len(rule.AllowedVals) > 0 {
		allowed := false
		for _, allowedVal := range rule.AllowedVals {
			if input == allowedVal {
				allowed = true
				break
			}
		}
		if !allowed {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "allowed_values_violation",
				Severity:   "medium",
				Field:      rule.Field,
				Rule:       rule.ID,
				Message:    fmt.Sprintf("Input value not in allowed list for field '%s'", rule.Field),
				Evidence:   input,
				Confidence: 1.0,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	// Type-specific validation
	typeViolations := iv.validateType(input, rule)
	violations = append(violations, typeViolations...)

	return violations
}

// validateType validates input based on its type
func (iv *InputValidator) validateType(input string, rule *ValidationRule) []*Violation {
	var violations []*Violation

	switch rule.Type {
	case "email":
		if !iv.isValidEmail(input) {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "type_violation",
				Severity:   "medium",
				Field:      rule.Field,
				Rule:       rule.ID,
				Message:    "Invalid email format",
				Evidence:   input,
				Confidence: 0.9,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	case "url":
		if !iv.isValidURL(input) {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "type_violation",
				Severity:   "medium",
				Field:      rule.Field,
				Rule:       rule.ID,
				Message:    "Invalid URL format",
				Evidence:   input,
				Confidence: 0.9,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	case "ip":
		if !iv.isValidIP(input) {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "type_violation",
				Severity:   "medium",
				Field:      rule.Field,
				Rule:       rule.ID,
				Message:    "Invalid IP address format",
				Evidence:   input,
				Confidence: 0.9,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	case "numeric":
		if !iv.isNumeric(input) {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "type_violation",
				Severity:   "medium",
				Field:      rule.Field,
				Rule:       rule.ID,
				Message:    "Input must be numeric",
				Evidence:   input,
				Confidence: 1.0,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	case "alphanumeric":
		if !iv.isAlphanumeric(input) {
			violation := &Violation{
				ID:         uuid.New().String(),
				Type:       "type_violation",
				Severity:   "medium",
				Field:      rule.Field,
				Rule:       rule.ID,
				Message:    "Input must be alphanumeric",
				Evidence:   input,
				Confidence: 1.0,
				DetectedAt: time.Now(),
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// Helper validation methods
func (iv *InputValidator) isValidEmail(email string) bool {
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(emailRegex, email)
	return matched
}

func (iv *InputValidator) isValidURL(urlStr string) bool {
	_, err := url.Parse(urlStr)
	return err == nil && (strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://"))
}

func (iv *InputValidator) isValidIP(ip string) bool {
	ipRegex := `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	matched, _ := regexp.MatchString(ipRegex, ip)
	return matched
}

func (iv *InputValidator) isNumeric(input string) bool {
	numericRegex := `^[0-9]+$`
	matched, _ := regexp.MatchString(numericRegex, input)
	return matched
}

func (iv *InputValidator) isAlphanumeric(input string) bool {
	alphanumericRegex := `^[a-zA-Z0-9]+$`
	matched, _ := regexp.MatchString(alphanumericRegex, input)
	return matched
}

// SanitizeOutput sanitizes output based on configuration
func (os *OutputSanitizer) SanitizeOutput(output string) string {
	sanitized := output

	switch os.config.SanitizationLevel {
	case "strict":
		sanitized = os.strictSanitization(sanitized)
	case "standard":
		sanitized = os.standardSanitization(sanitized)
	case "basic":
		sanitized = os.basicSanitization(sanitized)
	default:
		sanitized = os.standardSanitization(sanitized)
	}

	return sanitized
}

// basicSanitization applies basic HTML escaping
func (os *OutputSanitizer) basicSanitization(output string) string {
	return html.EscapeString(output)
}

// standardSanitization applies standard sanitization
func (os *OutputSanitizer) standardSanitization(output string) string {
	sanitized := html.EscapeString(output)

	// Remove potentially dangerous protocols
	dangerousProtocols := []string{"javascript:", "vbscript:", "data:", "file:"}
	for _, protocol := range dangerousProtocols {
		sanitized = strings.ReplaceAll(sanitized, protocol, "")
	}

	// Remove script tags
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	sanitized = scriptRegex.ReplaceAllString(sanitized, "")

	// Remove event handlers
	eventRegex := regexp.MustCompile(`(?i)on\w+\s*=\s*['"]*[^'"]*['"]*`)
	sanitized = eventRegex.ReplaceAllString(sanitized, "")

	return sanitized
}

// strictSanitization applies strict sanitization
func (os *OutputSanitizer) strictSanitization(output string) string {
	// Remove all HTML tags
	htmlRegex := regexp.MustCompile(`<[^>]*>`)
	sanitized := htmlRegex.ReplaceAllString(output, "")

	// Escape remaining content
	sanitized = html.EscapeString(sanitized)

	// Remove control characters
	controlRegex := regexp.MustCompile(`[\x00-\x1F\x7F]`)
	sanitized = controlRegex.ReplaceAllString(sanitized, "")

	return sanitized
}

// Sanitizer implementations
type HTMLSanitizer struct{}

func (h *HTMLSanitizer) Sanitize(input string) (string, error) {
	return html.EscapeString(input), nil
}

func (h *HTMLSanitizer) GetType() string {
	return "html"
}

type SQLSanitizer struct{}

func (s *SQLSanitizer) Sanitize(input string) (string, error) {
	// Escape single quotes
	sanitized := strings.ReplaceAll(input, "'", "''")

	// Remove SQL keywords
	sqlKeywords := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "EXEC", "UNION"}
	for _, keyword := range sqlKeywords {
		sanitized = regexp.MustCompile(`(?i)\b`+keyword+`\b`).ReplaceAllString(sanitized, "")
	}

	return sanitized, nil
}

func (s *SQLSanitizer) GetType() string {
	return "sql"
}

type XSSSanitizer struct{}

func (x *XSSSanitizer) Sanitize(input string) (string, error) {
	// Remove script tags
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	sanitized := scriptRegex.ReplaceAllString(input, "")

	// Remove event handlers
	eventRegex := regexp.MustCompile(`(?i)on\w+\s*=`)
	sanitized = eventRegex.ReplaceAllString(sanitized, "")

	// Remove javascript: protocol
	sanitized = strings.ReplaceAll(sanitized, "javascript:", "")

	return html.EscapeString(sanitized), nil
}

func (x *XSSSanitizer) GetType() string {
	return "xss"
}

type PathSanitizer struct{}

func (p *PathSanitizer) Sanitize(input string) (string, error) {
	// Remove path traversal patterns
	sanitized := strings.ReplaceAll(input, "../", "")
	sanitized = strings.ReplaceAll(sanitized, "..\\", "")
	sanitized = strings.ReplaceAll(sanitized, "%2e%2e%2f", "")
	sanitized = strings.ReplaceAll(sanitized, "%2e%2e%5c", "")

	return sanitized, nil
}

func (p *PathSanitizer) GetType() string {
	return "path"
}

type CommandSanitizer struct{}

func (c *CommandSanitizer) Sanitize(input string) (string, error) {
	// Remove command injection characters
	dangerousChars := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "[", "]"}
	sanitized := input
	for _, char := range dangerousChars {
		sanitized = strings.ReplaceAll(sanitized, char, "")
	}

	return sanitized, nil
}

func (c *CommandSanitizer) GetType() string {
	return "command"
}

// Output sanitizer implementations
type HTMLOutputSanitizer struct{}

func (h *HTMLOutputSanitizer) SanitizeOutput(output string) string {
	return html.EscapeString(output)
}

type JSONOutputSanitizer struct{}

func (j *JSONOutputSanitizer) SanitizeOutput(output string) string {
	// Escape JSON special characters
	sanitized := strings.ReplaceAll(output, "\\", "\\\\")
	sanitized = strings.ReplaceAll(sanitized, "\"", "\\\"")
	sanitized = strings.ReplaceAll(sanitized, "\n", "\\n")
	sanitized = strings.ReplaceAll(sanitized, "\r", "\\r")
	sanitized = strings.ReplaceAll(sanitized, "\t", "\\t")
	return sanitized
}

type XMLOutputSanitizer struct{}

func (x *XMLOutputSanitizer) SanitizeOutput(output string) string {
	// Escape XML special characters
	sanitized := strings.ReplaceAll(output, "&", "&amp;")
	sanitized = strings.ReplaceAll(sanitized, "<", "&lt;")
	sanitized = strings.ReplaceAll(sanitized, ">", "&gt;")
	sanitized = strings.ReplaceAll(sanitized, "\"", "&quot;")
	sanitized = strings.ReplaceAll(sanitized, "'", "&#39;")
	return sanitized
}

type MarkdownOutputSanitizer struct{}

func (m *MarkdownOutputSanitizer) SanitizeOutput(output string) string {
	// Escape Markdown special characters
	specialChars := []string{"*", "_", "`", "#", "+", "-", ".", "!", "[", "]", "(", ")"}
	sanitized := output
	for _, char := range specialChars {
		sanitized = strings.ReplaceAll(sanitized, char, "\\"+char)
	}
	return sanitized
}

// calculateComprehensiveThreatScore calculates threat score from all violations
func (iof *InputOutputFilter) calculateComprehensiveThreatScore(violations []*Violation) float64 {
	if len(violations) == 0 {
		return 0.0
	}

	var totalScore float64
	var maxScore float64

	for _, violation := range violations {
		var severityWeight float64
		switch violation.Severity {
		case "critical":
			severityWeight = 1.0
		case "high":
			severityWeight = 0.8
		case "medium":
			severityWeight = 0.6
		case "low":
			severityWeight = 0.4
		default:
			severityWeight = 0.2
		}

		score := violation.Confidence * severityWeight
		totalScore += score
		if score > maxScore {
			maxScore = score
		}
	}

	// Use a combination of average and maximum scores
	avgScore := totalScore / float64(len(violations))
	combinedScore := (avgScore + maxScore) / 2

	// Cap at 1.0
	if combinedScore > 1.0 {
		combinedScore = 1.0
	}

	return combinedScore
}
