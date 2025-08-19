package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

var contentFilterTracer = otel.Tracer("hackai/security/llm_content_filter")

// LLMContentFilter provides content filtering for LLM requests and responses
type LLMContentFilter struct {
	logger         *logger.Logger
	config         *ContentFilterConfig
	promptGuard    *PromptInjectionGuard
	toxicityFilter *ToxicityFilter
	piiDetector    *PIIDetector
	malwareScanner *MalwareScanner
	customFilters  []CustomFilter
}

// ContentFilterConfig holds configuration for content filtering
type ContentFilterConfig struct {
	// General Settings
	Enabled                bool    `json:"enabled"`
	StrictMode             bool    `json:"strict_mode"`
	DefaultThreatThreshold float64 `json:"default_threat_threshold"`

	// Prompt Injection Detection
	EnablePromptInjection    bool     `json:"enable_prompt_injection"`
	PromptInjectionThreshold float64  `json:"prompt_injection_threshold"`
	PromptInjectionPatterns  []string `json:"prompt_injection_patterns"`

	// Toxicity Detection
	EnableToxicity     bool     `json:"enable_toxicity"`
	ToxicityThreshold  float64  `json:"toxicity_threshold"`
	ToxicityCategories []string `json:"toxicity_categories"`

	// PII Detection
	EnablePII           bool     `json:"enable_pii"`
	PIITypes            []string `json:"pii_types"`
	PIIRedactionEnabled bool     `json:"pii_redaction_enabled"`

	// Malware Detection
	EnableMalware   bool     `json:"enable_malware"`
	MalwarePatterns []string `json:"malware_patterns"`

	// Content Categories
	BlockedCategories []string `json:"blocked_categories"`
	AllowedCategories []string `json:"allowed_categories"`

	// Response Filtering
	EnableResponseFilter bool `json:"enable_response_filter"`
	MaxResponseLength    int  `json:"max_response_length"`
	FilterSensitiveData  bool `json:"filter_sensitive_data"`
}

// ContentFilterResult represents the result of content filtering
type ContentFilterResult struct {
	Allowed         bool                   `json:"allowed"`
	ThreatScore     float64                `json:"threat_score"`
	ConfidenceScore float64                `json:"confidence_score"`
	Violations      []ContentViolation     `json:"violations"`
	BlockReason     string                 `json:"block_reason"`
	Recommendations []string               `json:"recommendations"`
	FilteredContent string                 `json:"filtered_content"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ContentViolation represents a content filtering violation
type ContentViolation struct {
	Type        string                 `json:"type"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"`
	Score       float64                `json:"score"`
	Confidence  float64                `json:"confidence"`
	Description string                 `json:"description"`
	Evidence    string                 `json:"evidence"`
	Position    *ContentPosition       `json:"position,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ContentPosition represents the position of a violation in content
type ContentPosition struct {
	Start  int `json:"start"`
	End    int `json:"end"`
	Line   int `json:"line"`
	Column int `json:"column"`
}

// NewLLMContentFilter creates a new LLM content filter
func NewLLMContentFilter(
	logger *logger.Logger,
	config *ContentFilterConfig,
	promptGuard *PromptInjectionGuard,
	toxicityFilter *ToxicityFilter,
	piiDetector *PIIDetector,
	malwareScanner *MalwareScanner,
) *LLMContentFilter {
	return &LLMContentFilter{
		logger:         logger,
		config:         config,
		promptGuard:    promptGuard,
		toxicityFilter: toxicityFilter,
		piiDetector:    piiDetector,
		malwareScanner: malwareScanner,
		customFilters:  []CustomFilter{},
	}
}

// FilterRequest filters an LLM request for security violations
func (cf *LLMContentFilter) FilterRequest(ctx context.Context, req *LLMRequest) (*SecurityResult, error) {
	ctx, span := contentFilterTracer.Start(ctx, "llm_content_filter.filter_request")
	defer span.End()

	span.SetAttributes(
		attribute.String("request.id", req.ID),
		attribute.String("request.provider", req.Provider),
		attribute.String("request.model", req.Model),
	)

	if !cf.config.Enabled {
		return &SecurityResult{
			Allowed:         true,
			ThreatScore:     0.0,
			Violations:      []PolicyViolation{},
			BlockReason:     "",
			Recommendations: []string{},
			Metadata:        map[string]interface{}{"filter_enabled": false},
		}, nil
	}

	startTime := time.Now()

	// Extract content from request body
	content, err := cf.extractContentFromRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract content from request: %w", err)
	}

	// Run content filtering
	result, err := cf.filterContent(ctx, content, "request")
	if err != nil {
		return nil, fmt.Errorf("content filtering failed: %w", err)
	}

	// Convert to SecurityResult
	securityResult := cf.convertToSecurityResult(result)

	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("threat.score", securityResult.ThreatScore),
		attribute.Int("violations.count", len(securityResult.Violations)),
		attribute.Bool("request.allowed", securityResult.Allowed),
		attribute.Int64("filter.duration_ms", duration.Milliseconds()),
	)

	cf.logger.WithFields(map[string]interface{}{
		"request_id":       req.ID,
		"threat_score":     securityResult.ThreatScore,
		"violations_count": len(securityResult.Violations),
		"allowed":          securityResult.Allowed,
		"duration_ms":      duration.Milliseconds(),
	}).Info("Request content filtering completed")

	return securityResult, nil
}

// FilterResponse filters an LLM response for security violations
func (cf *LLMContentFilter) FilterResponse(ctx context.Context, resp *LLMResponse) (*LLMResponse, error) {
	ctx, span := contentFilterTracer.Start(ctx, "llm_content_filter.filter_response")
	defer span.End()

	span.SetAttributes(
		attribute.String("response.id", resp.ID),
		attribute.String("response.request_id", resp.RequestID),
		attribute.Int("response.status_code", resp.StatusCode),
	)

	if !cf.config.EnableResponseFilter {
		return resp, nil
	}

	startTime := time.Now()

	// Extract content from response body
	content, err := cf.extractContentFromResponse(resp)
	if err != nil {
		cf.logger.WithError(err).Error("Failed to extract content from response")
		return resp, nil // Don't block response on extraction error
	}

	// Run content filtering
	result, err := cf.filterContent(ctx, content, "response")
	if err != nil {
		cf.logger.WithError(err).Error("Response content filtering failed")
		return resp, nil // Don't block response on filtering error
	}

	// Apply filtering results
	if !result.Allowed && cf.config.StrictMode {
		// Block the response
		resp.StatusCode = 403
		errorBody := map[string]interface{}{
			"error": map[string]interface{}{
				"message": "Response blocked by content filter",
				"type":    "content_violation",
				"details": result.BlockReason,
			},
		}
		bodyBytes, _ := json.Marshal(errorBody)
		resp.Body = bodyBytes
	} else if result.FilteredContent != "" {
		// Apply content filtering/redaction
		filteredBody := map[string]interface{}{
			"content":    result.FilteredContent,
			"filtered":   true,
			"violations": len(result.Violations),
		}
		bodyBytes, _ := json.Marshal(filteredBody)
		resp.Body = bodyBytes
	}

	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("threat.score", result.ThreatScore),
		attribute.Int("violations.count", len(result.Violations)),
		attribute.Bool("response.allowed", result.Allowed),
		attribute.Int64("filter.duration_ms", duration.Milliseconds()),
	)

	cf.logger.WithFields(map[string]interface{}{
		"response_id":      resp.ID,
		"request_id":       resp.RequestID,
		"threat_score":     result.ThreatScore,
		"violations_count": len(result.Violations),
		"allowed":          result.Allowed,
		"duration_ms":      duration.Milliseconds(),
	}).Info("Response content filtering completed")

	return resp, nil
}

// Health checks the health of the content filter
func (cf *LLMContentFilter) Health(ctx context.Context) error {
	// Basic health check - in production, implement proper health checks for components
	if !cf.config.Enabled {
		return fmt.Errorf("content filter is disabled")
	}

	// TODO: Implement proper health checks for external components
	// if cf.promptGuard != nil {
	//     if err := cf.promptGuard.Health(ctx); err != nil {
	//         return fmt.Errorf("prompt guard health check failed: %w", err)
	//     }
	// }

	return nil
}

// extractContentFromRequest extracts text content from request body
func (cf *LLMContentFilter) extractContentFromRequest(req *LLMRequest) (string, error) {
	var requestData map[string]interface{}
	if err := json.Unmarshal(req.Body, &requestData); err != nil {
		return "", fmt.Errorf("failed to parse request body: %w", err)
	}

	// Extract common content fields
	var content strings.Builder

	// Check for prompt/messages
	if prompt, ok := requestData["prompt"].(string); ok {
		content.WriteString(prompt)
	}

	if messages, ok := requestData["messages"].([]interface{}); ok {
		for _, msg := range messages {
			if msgMap, ok := msg.(map[string]interface{}); ok {
				if msgContent, ok := msgMap["content"].(string); ok {
					content.WriteString(" ")
					content.WriteString(msgContent)
				}
			}
		}
	}

	// Check for input field
	if input, ok := requestData["input"].(string); ok {
		content.WriteString(" ")
		content.WriteString(input)
	}

	return strings.TrimSpace(content.String()), nil
}

// extractContentFromResponse extracts text content from response body
func (cf *LLMContentFilter) extractContentFromResponse(resp *LLMResponse) (string, error) {
	var responseData map[string]interface{}
	if err := json.Unmarshal(resp.Body, &responseData); err != nil {
		return "", fmt.Errorf("failed to parse response body: %w", err)
	}

	// Extract common content fields
	var content strings.Builder

	// Check for choices (OpenAI format)
	if choices, ok := responseData["choices"].([]interface{}); ok {
		for _, choice := range choices {
			if choiceMap, ok := choice.(map[string]interface{}); ok {
				if message, ok := choiceMap["message"].(map[string]interface{}); ok {
					if msgContent, ok := message["content"].(string); ok {
						content.WriteString(" ")
						content.WriteString(msgContent)
					}
				}
				if text, ok := choiceMap["text"].(string); ok {
					content.WriteString(" ")
					content.WriteString(text)
				}
			}
		}
	}

	// Check for content field (Anthropic format)
	if contentArray, ok := responseData["content"].([]interface{}); ok {
		for _, item := range contentArray {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if text, ok := itemMap["text"].(string); ok {
					content.WriteString(" ")
					content.WriteString(text)
				}
			}
		}
	}

	return strings.TrimSpace(content.String()), nil
}

// filterContent performs content filtering on text
func (cf *LLMContentFilter) filterContent(ctx context.Context, content, contentType string) (*ContentFilterResult, error) {
	result := &ContentFilterResult{
		Allowed:         true,
		ThreatScore:     0.0,
		ConfidenceScore: 0.0,
		Violations:      []ContentViolation{},
		BlockReason:     "",
		Recommendations: []string{},
		FilteredContent: content,
		Metadata:        make(map[string]interface{}),
	}

	if content == "" {
		return result, nil
	}

	// Simplified content filtering - in production, integrate with actual detection services
	// For now, just check for basic patterns

	// Check for potential prompt injection patterns
	if cf.config.EnablePromptInjection {
		injectionPatterns := []string{
			"ignore previous instructions",
			"forget everything",
			"system:",
			"assistant:",
			"\\n\\nHuman:",
			"\\n\\nAssistant:",
		}

		for _, pattern := range injectionPatterns {
			if strings.Contains(strings.ToLower(content), pattern) {
				violation := ContentViolation{
					Type:        "prompt_injection",
					Category:    "security",
					Severity:    "high",
					Score:       0.8,
					Confidence:  0.7,
					Description: "Potential prompt injection pattern detected",
					Evidence:    pattern,
					Metadata:    map[string]interface{}{"pattern": pattern},
				}
				result.Violations = append(result.Violations, violation)
				result.ThreatScore = 0.8
			}
		}
	}

	// Check for basic toxicity patterns
	if cf.config.EnableToxicity {
		toxicPatterns := []string{
			"hate", "kill", "murder", "violence", "attack",
		}

		for _, pattern := range toxicPatterns {
			if strings.Contains(strings.ToLower(content), pattern) {
				violation := ContentViolation{
					Type:        "toxicity",
					Category:    "content_policy",
					Severity:    "medium",
					Score:       0.6,
					Confidence:  0.5,
					Description: "Potentially toxic content detected",
					Evidence:    pattern,
					Metadata:    map[string]interface{}{"pattern": pattern},
				}
				result.Violations = append(result.Violations, violation)
				if result.ThreatScore < 0.6 {
					result.ThreatScore = 0.6
				}
			}
		}
	}

	// Determine final result
	if len(result.Violations) > 0 {
		result.Allowed = result.ThreatScore < cf.config.DefaultThreatThreshold
		if !result.Allowed {
			result.BlockReason = cf.generateBlockReason(result.Violations)
		}
	}

	return result, nil
}

// convertToSecurityResult converts ContentFilterResult to SecurityResult
func (cf *LLMContentFilter) convertToSecurityResult(result *ContentFilterResult) *SecurityResult {
	var violations []PolicyViolation

	for _, violation := range result.Violations {
		policyViolation := PolicyViolation{
			PolicyID:    uuid.New(), // Generate a UUID for content filter violations
			PolicyName:  "Content Filter",
			RuleID:      uuid.New(),
			RuleName:    violation.Type,
			Severity:    violation.Severity,
			Description: violation.Description,
			Evidence: map[string]interface{}{
				"type":     violation.Type,
				"category": violation.Category,
				"evidence": violation.Evidence,
				"position": violation.Position,
				"metadata": violation.Metadata,
			},
			Score: violation.Score,
		}
		violations = append(violations, policyViolation)
	}

	return &SecurityResult{
		Allowed:         result.Allowed,
		ThreatScore:     result.ThreatScore,
		Violations:      violations,
		BlockReason:     result.BlockReason,
		Recommendations: result.Recommendations,
		Metadata: map[string]interface{}{
			"content_filter_result": result,
			"filtered_content":      result.FilteredContent,
		},
	}
}

// generateBlockReason generates a block reason from violations
func (cf *LLMContentFilter) generateBlockReason(violations []ContentViolation) string {
	if len(violations) == 0 {
		return ""
	}

	var reasons []string
	for _, violation := range violations {
		reasons = append(reasons, violation.Description)
	}

	return strings.Join(reasons, "; ")
}

// Interface definitions and helper types

// CustomFilter interface for custom content filters
type CustomFilter interface {
	Filter(ctx context.Context, content string) (*CustomFilterResult, error)
	GetType() string
	GetCategory() string
	Health(ctx context.Context) error
}

// CustomFilterResult represents the result of a custom filter
type CustomFilterResult struct {
	Allowed    bool                   `json:"allowed"`
	Score      float64                `json:"score"`
	Confidence float64                `json:"confidence"`
	Reason     string                 `json:"reason"`
	Evidence   string                 `json:"evidence"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// PIIEntity represents a detected PII entity
type PIIEntity struct {
	Type       string  `json:"type"`
	Text       string  `json:"text"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
}

// Helper interfaces for external components

// ToxicityFilter interface
type ToxicityFilter interface {
	AnalyzeToxicity(ctx context.Context, content string) (*ToxicityResult, error)
	Health(ctx context.Context) error
}

// ToxicityResult represents toxicity analysis result
type ToxicityResult struct {
	IsToxic    bool     `json:"is_toxic"`
	Score      float64  `json:"score"`
	Confidence float64  `json:"confidence"`
	Categories []string `json:"categories"`
	Evidence   string   `json:"evidence"`
}

// PIIDetector interface
type PIIDetector interface {
	DetectPII(ctx context.Context, content string) (*PIIResult, error)
	Health(ctx context.Context) error
}

// PIIResult represents PII detection result
type PIIResult struct {
	HasPII   bool        `json:"has_pii"`
	Entities []PIIEntity `json:"entities"`
}

// MalwareScanner interface
type MalwareScanner interface {
	ScanContent(ctx context.Context, content string) (*MalwareResult, error)
	Health(ctx context.Context) error
}

// MalwareResult represents malware scanning result
type MalwareResult struct {
	IsMalicious bool     `json:"is_malicious"`
	Score       float64  `json:"score"`
	Confidence  float64  `json:"confidence"`
	Evidence    string   `json:"evidence"`
	Signatures  []string `json:"signatures"`
}

// DefaultContentFilterConfig returns default configuration
func DefaultContentFilterConfig() *ContentFilterConfig {
	return &ContentFilterConfig{
		Enabled:                  true,
		StrictMode:               false,
		DefaultThreatThreshold:   0.7,
		EnablePromptInjection:    true,
		PromptInjectionThreshold: 0.7,
		PromptInjectionPatterns:  []string{},
		EnableToxicity:           true,
		ToxicityThreshold:        0.6,
		ToxicityCategories:       []string{"hate", "harassment", "violence", "sexual"},
		EnablePII:                true,
		PIITypes:                 []string{"email", "phone", "ssn", "credit_card"},
		PIIRedactionEnabled:      true,
		EnableMalware:            true,
		MalwarePatterns:          []string{},
		BlockedCategories:        []string{},
		AllowedCategories:        []string{},
		EnableResponseFilter:     true,
		MaxResponseLength:        100000,
		FilterSensitiveData:      true,
	}
}
