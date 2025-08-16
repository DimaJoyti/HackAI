package pipeline

import (
	"context"
	"fmt"
	"io"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/infrastructure"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var streamingTracer = otel.Tracer("hackai/llm/pipeline/streaming")

// StreamingProcessor handles streaming LLM requests
type StreamingProcessor struct {
	providerManager   providers.ProviderManager
	securityValidator *infrastructure.SecurityValidator
	auditLogger       *infrastructure.AuditLogger
	logger            *logger.Logger

	// Configuration
	enableSecurity bool
	enableAudit    bool
	bufferSize     int
	flushInterval  time.Duration
}

// StreamingConfig represents streaming processor configuration
type StreamingConfig struct {
	EnableSecurity bool          `json:"enable_security"`
	EnableAudit    bool          `json:"enable_audit"`
	BufferSize     int           `json:"buffer_size"`
	FlushInterval  time.Duration `json:"flush_interval"`
}

// NewStreamingProcessor creates a new streaming processor
func NewStreamingProcessor(
	providerManager providers.ProviderManager,
	securityValidator *infrastructure.SecurityValidator,
	auditLogger *infrastructure.AuditLogger,
	logger *logger.Logger,
	config StreamingConfig,
) *StreamingProcessor {
	return &StreamingProcessor{
		providerManager:   providerManager,
		securityValidator: securityValidator,
		auditLogger:       auditLogger,
		logger:            logger,
		enableSecurity:    config.EnableSecurity,
		enableAudit:       config.EnableAudit,
		bufferSize:        config.BufferSize,
		flushInterval:     config.FlushInterval,
	}
}

// StreamRequest represents a streaming request
type StreamRequest struct {
	ID         string                 `json:"id"`
	Input      string                 `json:"input"`
	Parameters LLMParameters          `json:"parameters"`
	Context    map[string]interface{} `json:"context"`
	UserID     string                 `json:"user_id"`
}

// StreamChunk represents a chunk of streaming response
type StreamChunk struct {
	ID        string                 `json:"id"`
	Content   string                 `json:"content"`
	Delta     string                 `json:"delta"`
	Finished  bool                   `json:"finished"`
	Error     string                 `json:"error,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// StreamResponse represents the complete streaming response
type StreamResponse struct {
	ID           string                 `json:"id"`
	Content      string                 `json:"content"`
	TokensUsed   int                    `json:"tokens_used"`
	Duration     time.Duration          `json:"duration"`
	ChunkCount   int                    `json:"chunk_count"`
	FinishReason string                 `json:"finish_reason"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ProcessStreamingRequest processes a streaming LLM request
func (sp *StreamingProcessor) ProcessStreamingRequest(ctx context.Context, request StreamRequest) (<-chan StreamChunk, error) {
	ctx, span := streamingTracer.Start(ctx, "streaming_processor.process_streaming_request",
		trace.WithAttributes(
			attribute.String("request.id", request.ID),
			attribute.String("user.id", request.UserID),
		),
	)
	defer span.End()

	// Step 1: Security validation
	if sp.enableSecurity && sp.securityValidator != nil {
		if err := sp.validateStreamingSecurity(ctx, request); err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("security validation failed: %w", err)
		}
	}

	// Step 2: Get best provider
	providerRequest := sp.convertToProviderStreamRequest(request)
	provider, err := sp.providerManager.GetBestProvider(ctx, providerRequest)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	// Step 3: Start streaming
	outputChan := make(chan StreamChunk, sp.bufferSize)

	go sp.handleStreaming(ctx, request, provider, providerRequest, outputChan)

	return outputChan, nil
}

// handleStreaming handles the streaming process
func (sp *StreamingProcessor) handleStreaming(
	ctx context.Context,
	request StreamRequest,
	provider providers.LLMProvider,
	providerRequest providers.GenerationRequest,
	outputChan chan<- StreamChunk,
) {
	defer close(outputChan)

	ctx, span := streamingTracer.Start(ctx, "streaming_processor.handle_streaming")
	defer span.End()

	startTime := time.Now()
	var fullContent string
	var chunkCount int
	var totalTokens int

	// Check if provider supports streaming
	streamProvider, ok := provider.(StreamingProvider)
	if !ok {
		// Fallback to non-streaming
		sp.handleNonStreamingFallback(ctx, request, provider, providerRequest, outputChan)
		return
	}

	// Start streaming
	stream, err := streamProvider.GenerateStream(ctx, providerRequest)
	if err != nil {
		span.RecordError(err)
		sp.sendErrorChunk(outputChan, request.ID, fmt.Sprintf("streaming failed: %v", err))
		return
	}
	defer stream.Close()

	// Process stream chunks
	buffer := make([]string, 0, 10)
	lastFlush := time.Now()

	for {
		chunk, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				// Stream finished
				break
			}
			span.RecordError(err)
			sp.sendErrorChunk(outputChan, request.ID, fmt.Sprintf("stream error: %v", err))
			return
		}

		chunkCount++
		fullContent += chunk.Content
		buffer = append(buffer, chunk.Content)

		// Flush buffer based on size or time
		if len(buffer) >= sp.bufferSize || time.Since(lastFlush) >= sp.flushInterval {
			sp.flushBuffer(outputChan, request.ID, buffer, false)
			buffer = buffer[:0]
			lastFlush = time.Now()
		}
	}

	// Flush remaining buffer
	if len(buffer) > 0 {
		sp.flushBuffer(outputChan, request.ID, buffer, false)
	}

	// Send final chunk
	finalChunk := StreamChunk{
		ID:       request.ID,
		Content:  fullContent,
		Finished: true,
		Metadata: map[string]interface{}{
			"duration":    time.Since(startTime),
			"chunk_count": chunkCount,
			"tokens_used": totalTokens,
			"provider":    string(provider.GetType()),
			"model":       provider.GetModel().Name,
		},
		Timestamp: time.Now(),
	}

	select {
	case outputChan <- finalChunk:
	case <-ctx.Done():
		return
	}

	// Audit logging
	if sp.enableAudit && sp.auditLogger != nil {
		sp.auditLogger.LogLLMRequest(ctx, request.UserID, request.Input, provider.GetModel().Name)
		sp.auditLogger.LogLLMResponse(ctx, request.UserID, fullContent, provider.GetModel().Name, totalTokens)
	}

	span.SetAttributes(
		attribute.String("provider", string(provider.GetType())),
		attribute.Int("chunk_count", chunkCount),
		attribute.String("duration", time.Since(startTime).String()),
		attribute.Bool("success", true),
	)
}

// handleNonStreamingFallback handles providers that don't support streaming
func (sp *StreamingProcessor) handleNonStreamingFallback(
	ctx context.Context,
	request StreamRequest,
	provider providers.LLMProvider,
	providerRequest providers.GenerationRequest,
	outputChan chan<- StreamChunk,
) {
	ctx, span := streamingTracer.Start(ctx, "streaming_processor.non_streaming_fallback")
	defer span.End()

	// Generate response normally
	response, err := provider.Generate(ctx, providerRequest)
	if err != nil {
		span.RecordError(err)
		sp.sendErrorChunk(outputChan, request.ID, fmt.Sprintf("generation failed: %v", err))
		return
	}

	// Simulate streaming by sending content in chunks
	content := response.Content
	chunkSize := 50 // Characters per chunk

	for i := 0; i < len(content); i += chunkSize {
		end := i + chunkSize
		if end > len(content) {
			end = len(content)
		}

		chunk := StreamChunk{
			ID:        request.ID,
			Content:   content[:end],
			Delta:     content[i:end],
			Finished:  false,
			Timestamp: time.Now(),
		}

		select {
		case outputChan <- chunk:
		case <-ctx.Done():
			return
		}

		// Small delay to simulate streaming
		time.Sleep(50 * time.Millisecond)
	}

	// Send final chunk
	finalChunk := StreamChunk{
		ID:       request.ID,
		Content:  content,
		Finished: true,
		Metadata: map[string]interface{}{
			"tokens_used":      response.TokensUsed.TotalTokens,
			"finish_reason":    response.FinishReason,
			"provider":         string(provider.GetType()),
			"model":            response.Model,
			"simulated_stream": true,
		},
		Timestamp: time.Now(),
	}

	select {
	case outputChan <- finalChunk:
	case <-ctx.Done():
		return
	}
}

// flushBuffer flushes the buffer to output channel
func (sp *StreamingProcessor) flushBuffer(outputChan chan<- StreamChunk, requestID string, buffer []string, finished bool) {
	if len(buffer) == 0 {
		return
	}

	delta := ""
	for _, chunk := range buffer {
		delta += chunk
	}

	chunk := StreamChunk{
		ID:        requestID,
		Delta:     delta,
		Finished:  finished,
		Timestamp: time.Now(),
	}

	select {
	case outputChan <- chunk:
	default:
		// Channel full, skip this chunk
		sp.logger.Warn("Output channel full, dropping chunk")
	}
}

// sendErrorChunk sends an error chunk
func (sp *StreamingProcessor) sendErrorChunk(outputChan chan<- StreamChunk, requestID, errorMsg string) {
	errorChunk := StreamChunk{
		ID:        requestID,
		Error:     errorMsg,
		Finished:  true,
		Timestamp: time.Now(),
	}

	select {
	case outputChan <- errorChunk:
	default:
		// Channel closed or full
	}
}

// validateStreamingSecurity validates streaming request security
func (sp *StreamingProcessor) validateStreamingSecurity(ctx context.Context, request StreamRequest) error {
	result := sp.securityValidator.ValidateInput(ctx, request.Input)
	if !result.Valid {
		return fmt.Errorf("input validation failed: %v", result.Issues)
	}

	if result.SensitiveDataFound {
		// Use sanitized input
		request.Input = result.SanitizedInput
	}

	return nil
}

// convertToProviderStreamRequest converts to provider request
func (sp *StreamingProcessor) convertToProviderStreamRequest(request StreamRequest) providers.GenerationRequest {
	return providers.GenerationRequest{
		Messages: []providers.Message{
			{Role: "user", Content: request.Input},
		},
		Temperature: request.Parameters.Temperature,
		MaxTokens:   request.Parameters.MaxTokens,
		Metadata:    request.Parameters.Additional,
		Stream:      true,
	}
}

// StreamingProvider interface for providers that support streaming
type StreamingProvider interface {
	providers.LLMProvider
	GenerateStream(ctx context.Context, request providers.GenerationRequest) (StreamReader, error)
}

// StreamReader interface for reading streaming responses
type StreamReader interface {
	Recv() (providers.StreamChunk, error)
	Close() error
}

// BatchProcessor handles batch processing of multiple requests
type BatchProcessor struct {
	requestProcessor *RequestProcessor
	logger           *logger.Logger
	maxBatchSize     int
	batchTimeout     time.Duration
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(requestProcessor *RequestProcessor, logger *logger.Logger, maxBatchSize int, batchTimeout time.Duration) *BatchProcessor {
	return &BatchProcessor{
		requestProcessor: requestProcessor,
		logger:           logger,
		maxBatchSize:     maxBatchSize,
		batchTimeout:     batchTimeout,
	}
}

// ProcessBatch processes a batch of requests
func (bp *BatchProcessor) ProcessBatch(ctx context.Context, requests []LLMRequest) ([]LLMResponse, error) {
	ctx, span := streamingTracer.Start(ctx, "batch_processor.process_batch",
		trace.WithAttributes(
			attribute.Int("batch_size", len(requests)),
		),
	)
	defer span.End()

	if len(requests) == 0 {
		return []LLMResponse{}, nil
	}

	if len(requests) > bp.maxBatchSize {
		return nil, fmt.Errorf("batch size %d exceeds maximum %d", len(requests), bp.maxBatchSize)
	}

	responses := make([]LLMResponse, len(requests))
	errors := make([]error, len(requests))

	// Process requests concurrently
	type result struct {
		index    int
		response LLMResponse
		err      error
	}

	resultChan := make(chan result, len(requests))

	for i, request := range requests {
		go func(idx int, req LLMRequest) {
			resp, err := bp.requestProcessor.ProcessRequest(ctx, req)
			resultChan <- result{index: idx, response: resp, err: err}
		}(i, request)
	}

	// Collect results
	for i := 0; i < len(requests); i++ {
		select {
		case res := <-resultChan:
			responses[res.index] = res.response
			errors[res.index] = res.err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(bp.batchTimeout):
			return nil, fmt.Errorf("batch processing timeout")
		}
	}

	// Check for errors
	var firstError error
	for _, err := range errors {
		if err != nil && firstError == nil {
			firstError = err
		}
	}

	if firstError != nil {
		span.RecordError(firstError)
		return responses, firstError
	}

	span.SetAttributes(
		attribute.Int("successful_requests", len(requests)),
		attribute.Bool("success", true),
	)

	return responses, nil
}
