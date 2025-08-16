package pipeline

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/infrastructure"
	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var pipelineTracer = otel.Tracer("hackai/llm/pipeline")

// RequestProcessor handles the complete LLM request processing pipeline
type RequestProcessor struct {
	providerManager   providers.ProviderManager
	securityValidator *infrastructure.SecurityValidator
	auditLogger       *infrastructure.AuditLogger
	cache             *infrastructure.LLMCache
	memory            llm.Memory
	logger            *logger.Logger

	// Configuration
	enableCaching  bool
	enableSecurity bool
	enableAudit    bool
	cacheTimeout   time.Duration
}

// ProcessorConfig represents processor configuration
type ProcessorConfig struct {
	EnableCaching  bool          `json:"enable_caching"`
	EnableSecurity bool          `json:"enable_security"`
	EnableAudit    bool          `json:"enable_audit"`
	CacheTimeout   time.Duration `json:"cache_timeout"`
}

// NewRequestProcessor creates a new request processor
func NewRequestProcessor(
	providerManager providers.ProviderManager,
	securityValidator *infrastructure.SecurityValidator,
	auditLogger *infrastructure.AuditLogger,
	cache *infrastructure.LLMCache,
	memory llm.Memory,
	logger *logger.Logger,
	config ProcessorConfig,
) *RequestProcessor {
	return &RequestProcessor{
		providerManager:   providerManager,
		securityValidator: securityValidator,
		auditLogger:       auditLogger,
		cache:             cache,
		memory:            memory,
		logger:            logger,
		enableCaching:     config.EnableCaching,
		enableSecurity:    config.EnableSecurity,
		enableAudit:       config.EnableAudit,
		cacheTimeout:      config.CacheTimeout,
	}
}

// ProcessRequest processes a complete LLM request through the pipeline
func (rp *RequestProcessor) ProcessRequest(ctx context.Context, request LLMRequest) (LLMResponse, error) {
	ctx, span := pipelineTracer.Start(ctx, "request_processor.process_request",
		trace.WithAttributes(
			attribute.String("request.id", request.ID),
			attribute.String("request.type", request.Type),
		),
	)
	defer span.End()

	startTime := time.Now()

	// Step 1: Security validation
	if rp.enableSecurity && rp.securityValidator != nil {
		if err := rp.validateSecurity(ctx, request); err != nil {
			span.RecordError(err)
			return LLMResponse{}, fmt.Errorf("security validation failed: %w", err)
		}
	}

	// Step 2: Check cache
	if rp.enableCaching && rp.cache != nil {
		if cachedResponse, found := rp.checkCache(ctx, request); found {
			span.SetAttributes(attribute.Bool("cache_hit", true))
			return cachedResponse, nil
		}
		span.SetAttributes(attribute.Bool("cache_hit", false))
	}

	// Step 3: Process with provider
	response, err := rp.processWithProvider(ctx, request)
	if err != nil {
		span.RecordError(err)
		return LLMResponse{}, err
	}

	// Step 4: Post-process response
	if err := rp.postProcessResponse(ctx, &response); err != nil {
		span.RecordError(err)
		rp.logger.Warn("Post-processing failed", "error", err)
	}

	// Step 5: Cache response
	if rp.enableCaching && rp.cache != nil {
		if err := rp.cacheResponse(ctx, request, response); err != nil {
			rp.logger.Warn("Failed to cache response", "error", err)
		}
	}

	// Step 6: Audit logging
	if rp.enableAudit && rp.auditLogger != nil {
		rp.auditRequest(ctx, request, response, time.Since(startTime))
	}

	span.SetAttributes(
		attribute.String("response.id", response.ID),
		attribute.Int("tokens_used", response.TokensUsed),
		attribute.String("duration", time.Since(startTime).String()),
		attribute.Bool("success", true),
	)

	return response, nil
}

// validateSecurity validates the request for security issues
func (rp *RequestProcessor) validateSecurity(ctx context.Context, request LLMRequest) error {
	ctx, span := pipelineTracer.Start(ctx, "request_processor.validate_security")
	defer span.End()

	// Validate input
	result := rp.securityValidator.ValidateInput(ctx, request.Input)
	if !result.Valid {
		span.SetAttributes(
			attribute.Bool("validation.valid", false),
			attribute.StringSlice("validation.issues", result.Issues),
		)
		return fmt.Errorf("input validation failed: %v", result.Issues)
	}

	if result.SensitiveDataFound {
		span.SetAttributes(attribute.Bool("sensitive_data_found", true))
		// Use sanitized input
		request.Input = result.SanitizedInput
	}

	return nil
}

// checkCache checks if the request is cached
func (rp *RequestProcessor) checkCache(ctx context.Context, request LLMRequest) (LLMResponse, bool) {
	ctx, span := pipelineTracer.Start(ctx, "request_processor.check_cache")
	defer span.End()

	cacheKey := rp.generateCacheKey(request)

	var cachedResponse LLMResponse
	if err := rp.cache.Get(ctx, cacheKey, &cachedResponse); err != nil {
		if err != infrastructure.ErrCacheMiss {
			rp.logger.Warn("Cache get error", "error", err)
		}
		return LLMResponse{}, false
	}

	span.SetAttributes(attribute.String("cache_key", cacheKey))
	return cachedResponse, true
}

// processWithProvider processes the request with an LLM provider
func (rp *RequestProcessor) processWithProvider(ctx context.Context, request LLMRequest) (LLMResponse, error) {
	ctx, span := pipelineTracer.Start(ctx, "request_processor.process_with_provider")
	defer span.End()

	// Convert to provider request
	providerRequest := rp.convertToProviderRequest(request)

	// Route to best provider
	providerResponse, err := rp.providerManager.RouteRequest(ctx, providerRequest)
	if err != nil {
		span.RecordError(err)
		return LLMResponse{}, fmt.Errorf("provider request failed: %w", err)
	}

	// Convert back to LLM response
	response := rp.convertFromProviderResponse(request, providerResponse)

	span.SetAttributes(
		attribute.String("model", providerResponse.Model),
		attribute.Int("tokens_used", providerResponse.TokensUsed.TotalTokens),
	)

	return response, nil
}

// postProcessResponse performs post-processing on the response
func (rp *RequestProcessor) postProcessResponse(ctx context.Context, response *LLMResponse) error {
	ctx, span := pipelineTracer.Start(ctx, "request_processor.post_process_response")
	defer span.End()

	// Security validation of output
	if rp.enableSecurity && rp.securityValidator != nil {
		result := rp.securityValidator.ValidateOutput(ctx, response.Content)
		if result.SensitiveDataFound {
			response.Content = result.SanitizedInput
			span.SetAttributes(attribute.Bool("output_sanitized", true))
		}
	}

	// Add metadata
	response.ProcessedAt = time.Now()
	response.Metadata["post_processed"] = true

	return nil
}

// cacheResponse caches the response
func (rp *RequestProcessor) cacheResponse(ctx context.Context, request LLMRequest, response LLMResponse) error {
	ctx, span := pipelineTracer.Start(ctx, "request_processor.cache_response")
	defer span.End()

	cacheKey := rp.generateCacheKey(request)

	if err := rp.cache.Set(ctx, cacheKey, response, rp.cacheTimeout); err != nil {
		span.RecordError(err)
		return err
	}

	span.SetAttributes(
		attribute.String("cache_key", cacheKey),
		attribute.String("cache_timeout", rp.cacheTimeout.String()),
	)

	return nil
}

// auditRequest logs the request for audit purposes
func (rp *RequestProcessor) auditRequest(ctx context.Context, request LLMRequest, response LLMResponse, duration time.Duration) {
	userID := rp.extractUserID(ctx)

	// Log request
	rp.auditLogger.LogLLMRequest(ctx, userID, request.Input, response.Model)

	// Log response
	rp.auditLogger.LogLLMResponse(ctx, userID, response.Content, response.Model, response.TokensUsed)
}

// generateCacheKey generates a cache key for the request
func (rp *RequestProcessor) generateCacheKey(request LLMRequest) string {
	// Simple hash-based cache key
	// In production, you'd use a proper hash function
	return fmt.Sprintf("llm_request_%s_%s", request.Type, request.ID)
}

// convertToProviderRequest converts LLMRequest to provider request
func (rp *RequestProcessor) convertToProviderRequest(request LLMRequest) providers.GenerationRequest {
	return providers.GenerationRequest{
		Messages: []providers.Message{
			{Role: "user", Content: request.Input},
		},
		Temperature: request.Parameters.Temperature,
		MaxTokens:   request.Parameters.MaxTokens,
		Metadata:    request.Parameters.Additional,
	}
}

// convertFromProviderResponse converts provider response to LLMResponse
func (rp *RequestProcessor) convertFromProviderResponse(request LLMRequest, response providers.GenerationResponse) LLMResponse {
	return LLMResponse{
		ID:           fmt.Sprintf("resp_%s_%d", request.ID, time.Now().UnixNano()),
		Content:      response.Content,
		Model:        response.Model,
		TokensUsed:   response.TokensUsed.TotalTokens,
		FinishReason: response.FinishReason,
		CreatedAt:    time.Now(),
		Metadata: map[string]interface{}{
			"request_id": request.ID,

			"prompt_tokens":     response.TokensUsed.PromptTokens,
			"completion_tokens": response.TokensUsed.CompletionTokens,
		},
	}
}

// extractUserID extracts user ID from context
func (rp *RequestProcessor) extractUserID(ctx context.Context) string {
	if userID, ok := ctx.Value("user_id").(string); ok {
		return userID
	}
	return "anonymous"
}

// LLMRequest represents a high-level LLM request
type LLMRequest struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Input      string                 `json:"input"`
	Parameters LLMParameters          `json:"parameters"`
	Context    map[string]interface{} `json:"context"`
	CreatedAt  time.Time              `json:"created_at"`
}

// LLMResponse represents a high-level LLM response
type LLMResponse struct {
	ID           string                 `json:"id"`
	Content      string                 `json:"content"`
	Model        string                 `json:"model"`
	TokensUsed   int                    `json:"tokens_used"`
	FinishReason string                 `json:"finish_reason"`
	CreatedAt    time.Time              `json:"created_at"`
	ProcessedAt  time.Time              `json:"processed_at"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// LLMParameters represents LLM generation parameters
type LLMParameters struct {
	Temperature float64                `json:"temperature"`
	MaxTokens   int                    `json:"max_tokens"`
	TopP        float64                `json:"top_p"`
	TopK        int                    `json:"top_k"`
	Additional  map[string]interface{} `json:"additional"`
}
