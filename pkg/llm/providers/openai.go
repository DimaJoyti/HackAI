package providers

import (
	"context"
	"fmt"
	"time"

	"github.com/sashabaranov/go-openai"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var tracer = otel.Tracer("hackai/llm/providers")

// OpenAIProvider implements LLMProvider for OpenAI
type OpenAIProvider struct {
	client *openai.Client
	config ProviderConfig
	model  string
	limits ProviderLimits
	stats  *ProviderStat
}

// NewOpenAIProvider creates a new OpenAI provider
func NewOpenAIProvider(config ProviderConfig) (*OpenAIProvider, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("OpenAI API key is required")
	}

	clientConfig := openai.DefaultConfig(config.APIKey)
	if config.BaseURL != "" {
		clientConfig.BaseURL = config.BaseURL
	}

	client := openai.NewClientWithConfig(clientConfig)

	// Set default model if not specified
	model := config.Model
	if model == "" {
		model = openai.GPT4TurboPreview
	}

	// Set default limits if not specified
	limits := config.Limits
	if limits.RequestsPerMinute == 0 {
		limits = DefaultLimits
	}

	return &OpenAIProvider{
		client: client,
		config: config,
		model:  model,
		limits: limits,
		stats: &ProviderStat{
			Name:   config.Name,
			Status: "active",
		},
	}, nil
}

// Generate generates text using OpenAI
func (p *OpenAIProvider) Generate(ctx context.Context, request GenerationRequest) (GenerationResponse, error) {
	ctx, span := tracer.Start(ctx, "openai.generate",
		trace.WithAttributes(
			attribute.String("provider", "openai"),
			attribute.String("model", request.Model),
			attribute.Int("max_tokens", request.MaxTokens),
		),
	)
	defer span.End()

	startTime := time.Now()

	// Convert request to OpenAI format
	openaiRequest := p.convertRequest(request)

	// Make the API call
	response, err := p.client.CreateChatCompletion(ctx, openaiRequest)
	if err != nil {
		span.RecordError(err)
		p.updateStats(startTime, 0, true)
		return GenerationResponse{}, NewProviderError("openai", "api_error", err.Error(), true)
	}

	// Convert response
	result := p.convertResponse(response)

	// Update statistics
	p.updateStats(startTime, result.TokensUsed.TotalTokens, false)

	span.SetAttributes(
		attribute.Int("tokens_used", result.TokensUsed.TotalTokens),
		attribute.String("finish_reason", result.FinishReason),
	)

	return result, nil
}

// Stream generates streaming text using OpenAI
func (p *OpenAIProvider) Stream(ctx context.Context, request GenerationRequest) (<-chan StreamChunk, error) {
	ctx, span := tracer.Start(ctx, "openai.stream",
		trace.WithAttributes(
			attribute.String("provider", "openai"),
			attribute.String("model", request.Model),
		),
	)
	defer span.End()

	// Convert request to OpenAI format
	openaiRequest := p.convertRequest(request)
	openaiRequest.Stream = true

	// Create stream
	stream, err := p.client.CreateChatCompletionStream(ctx, openaiRequest)
	if err != nil {
		span.RecordError(err)
		return nil, NewProviderError("openai", "stream_error", err.Error(), true)
	}

	// Create output channel
	chunks := make(chan StreamChunk, 10)

	// Start streaming goroutine
	go func() {
		defer close(chunks)
		defer stream.Close()

		for {
			response, err := stream.Recv()
			if err != nil {
				if err.Error() == "EOF" {
					return
				}
				chunks <- StreamChunk{Error: err}
				return
			}

			// Convert and send chunk
			chunk := p.convertStreamResponse(response)
			chunks <- chunk
		}
	}()

	return chunks, nil
}

// Embed creates embeddings using OpenAI
func (p *OpenAIProvider) Embed(ctx context.Context, text string) ([]float64, error) {
	ctx, span := tracer.Start(ctx, "openai.embed",
		trace.WithAttributes(
			attribute.String("provider", "openai"),
			attribute.Int("text_length", len(text)),
		),
	)
	defer span.End()

	request := openai.EmbeddingRequest{
		Input: []string{text},
		Model: openai.AdaEmbeddingV2,
	}

	response, err := p.client.CreateEmbeddings(ctx, request)
	if err != nil {
		span.RecordError(err)
		return nil, NewProviderError("openai", "embedding_error", err.Error(), true)
	}

	if len(response.Data) == 0 {
		return nil, NewProviderError("openai", "no_embedding", "no embedding returned", false)
	}

	// Convert []float32 to []float64
	embedding := make([]float64, len(response.Data[0].Embedding))
	for i, v := range response.Data[0].Embedding {
		embedding[i] = float64(v)
	}
	return embedding, nil
}

// EmbedBatch creates embeddings for multiple texts
func (p *OpenAIProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	ctx, span := tracer.Start(ctx, "openai.embed_batch",
		trace.WithAttributes(
			attribute.String("provider", "openai"),
			attribute.Int("batch_size", len(texts)),
		),
	)
	defer span.End()

	request := openai.EmbeddingRequest{
		Input: texts,
		Model: openai.AdaEmbeddingV2,
	}

	response, err := p.client.CreateEmbeddings(ctx, request)
	if err != nil {
		span.RecordError(err)
		return nil, NewProviderError("openai", "embedding_error", err.Error(), true)
	}

	embeddings := make([][]float64, len(response.Data))
	for i, data := range response.Data {
		// Convert []float32 to []float64
		embedding := make([]float64, len(data.Embedding))
		for j, v := range data.Embedding {
			embedding[j] = float64(v)
		}
		embeddings[i] = embedding
	}

	return embeddings, nil
}

// GetModel returns model information
func (p *OpenAIProvider) GetModel() ModelInfo {
	return ModelInfo{
		Name:         p.model,
		Provider:     "openai",
		Version:      "1.0",
		MaxTokens:    getModelMaxTokens(p.model),
		ContextSize:  getModelContextSize(p.model),
		Capabilities: []string{"text_generation", "embeddings", "function_calling"},
		CreatedAt:    time.Now(),
	}
}

// GetLimits returns provider limits
func (p *OpenAIProvider) GetLimits() ProviderLimits {
	return p.limits
}

// GetType returns provider type
func (p *OpenAIProvider) GetType() ProviderType {
	return ProviderOpenAI
}

// Health checks provider health
func (p *OpenAIProvider) Health(ctx context.Context) error {
	// Simple health check by listing models
	_, err := p.client.ListModels(ctx)
	if err != nil {
		return NewProviderError("openai", "health_check_failed", err.Error(), true)
	}
	return nil
}

// Close closes the provider
func (p *OpenAIProvider) Close() error {
	// OpenAI client doesn't need explicit closing
	return nil
}

// convertRequest converts GenerationRequest to OpenAI format
func (p *OpenAIProvider) convertRequest(request GenerationRequest) openai.ChatCompletionRequest {
	messages := make([]openai.ChatCompletionMessage, len(request.Messages))
	for i, msg := range request.Messages {
		messages[i] = openai.ChatCompletionMessage{
			Role:    msg.Role,
			Content: msg.Content,
			Name:    msg.Name,
		}
	}

	model := request.Model
	if model == "" {
		model = p.model
	}

	return openai.ChatCompletionRequest{
		Model:       model,
		Messages:    messages,
		Temperature: float32(request.Temperature),
		MaxTokens:   request.MaxTokens,
		TopP:        float32(request.TopP),
		Stop:        request.Stop,
		Stream:      request.Stream,
		Seed:        request.Seed,
	}
}

// convertResponse converts OpenAI response to GenerationResponse
func (p *OpenAIProvider) convertResponse(response openai.ChatCompletionResponse) GenerationResponse {
	var content string
	var finishReason string

	if len(response.Choices) > 0 {
		content = response.Choices[0].Message.Content
		finishReason = string(response.Choices[0].FinishReason)
	}

	return GenerationResponse{
		Content: content,
		TokensUsed: TokenUsage{
			PromptTokens:     response.Usage.PromptTokens,
			CompletionTokens: response.Usage.CompletionTokens,
			TotalTokens:      response.Usage.TotalTokens,
		},
		FinishReason: finishReason,
		Model:        response.Model,
		ID:           response.ID,
		Created:      time.Unix(response.Created, 0),
	}
}

// convertStreamResponse converts OpenAI stream response to StreamChunk
func (p *OpenAIProvider) convertStreamResponse(response openai.ChatCompletionStreamResponse) StreamChunk {
	var content, delta, finishReason string

	if len(response.Choices) > 0 {
		choice := response.Choices[0]
		delta = choice.Delta.Content
		content = choice.Delta.Content
		finishReason = string(choice.FinishReason)
	}

	return StreamChunk{
		Content:      content,
		Delta:        delta,
		FinishReason: finishReason,
	}
}

// updateStats updates provider statistics
func (p *OpenAIProvider) updateStats(startTime time.Time, tokens int, hasError bool) {
	duration := time.Since(startTime)

	p.stats.Requests++
	p.stats.Tokens += int64(tokens)
	p.stats.LastUsed = time.Now()

	if hasError {
		p.stats.ErrorCount++
	}

	// Update average latency (simple moving average)
	if p.stats.AverageLatency == 0 {
		p.stats.AverageLatency = duration
	} else {
		p.stats.AverageLatency = (p.stats.AverageLatency + duration) / 2
	}
}

// getModelMaxTokens returns max tokens for a model
func getModelMaxTokens(model string) int {
	switch model {
	case openai.GPT4TurboPreview, openai.GPT4VisionPreview:
		return 4096
	case openai.GPT4, openai.GPT432K:
		return 8192
	case openai.GPT3Dot5Turbo, openai.GPT3Dot5Turbo16K:
		return 4096
	default:
		return 4096
	}
}

// getModelContextSize returns context size for a model
func getModelContextSize(model string) int {
	switch model {
	case openai.GPT4TurboPreview:
		return 128000
	case openai.GPT432K:
		return 32768
	case openai.GPT4:
		return 8192
	case openai.GPT3Dot5Turbo16K:
		return 16384
	case openai.GPT3Dot5Turbo:
		return 4096
	default:
		return 4096
	}
}
