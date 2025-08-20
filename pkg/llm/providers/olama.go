package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var olamaTracer = otel.Tracer("hackai/llm/providers/olama")

// OlamaProvider implements LLMProvider for OLAMA local models
type OlamaProvider struct {
	client    *http.Client
	config    ProviderConfig
	baseURL   string
	model     string
	limits    ProviderLimits
	stats     *ProviderStat
	modelInfo ModelInfo
}

// OlamaRequest represents an OLAMA API request
type OlamaRequest struct {
	Model    string                 `json:"model"`
	Prompt   string                 `json:"prompt,omitempty"`
	Messages []OlamaMessage         `json:"messages,omitempty"`
	Stream   bool                   `json:"stream,omitempty"`
	Options  map[string]interface{} `json:"options,omitempty"`
	Format   string                 `json:"format,omitempty"`
	System   string                 `json:"system,omitempty"`
	Template string                 `json:"template,omitempty"`
	Context  []int                  `json:"context,omitempty"`
	Raw      bool                   `json:"raw,omitempty"`
}

// OlamaMessage represents a message in OLAMA format
type OlamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OlamaResponse represents an OLAMA API response
type OlamaResponse struct {
	Model              string       `json:"model"`
	CreatedAt          time.Time    `json:"created_at"`
	Message            OlamaMessage `json:"message,omitempty"`
	Response           string       `json:"response,omitempty"`
	Done               bool         `json:"done"`
	Context            []int        `json:"context,omitempty"`
	TotalDuration      int64        `json:"total_duration,omitempty"`
	LoadDuration       int64        `json:"load_duration,omitempty"`
	PromptEvalCount    int          `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration int64        `json:"prompt_eval_duration,omitempty"`
	EvalCount          int          `json:"eval_count,omitempty"`
	EvalDuration       int64        `json:"eval_duration,omitempty"`
}

// OlamaModelInfo represents model information from OLAMA
type OlamaModelInfo struct {
	Name       string            `json:"name"`
	Size       int64             `json:"size"`
	Digest     string            `json:"digest"`
	Details    OlamaModelDetails `json:"details"`
	ModifiedAt time.Time         `json:"modified_at"`
}

// OlamaModelDetails represents detailed model information
type OlamaModelDetails struct {
	Format            string   `json:"format"`
	Family            string   `json:"family"`
	Families          []string `json:"families"`
	ParameterSize     string   `json:"parameter_size"`
	QuantizationLevel string   `json:"quantization_level"`
}

// NewOlamaProvider creates a new OLAMA provider
func NewOlamaProvider(config ProviderConfig) (*OlamaProvider, error) {
	if config.BaseURL == "" {
		config.BaseURL = "http://localhost:11434"
	}

	client := &http.Client{
		Timeout: config.Limits.Timeout,
	}

	provider := &OlamaProvider{
		client:  client,
		config:  config,
		baseURL: strings.TrimSuffix(config.BaseURL, "/"),
		model:   config.Model,
		limits:  config.Limits,
		stats: &ProviderStat{
			Name:     config.Name,
			Status:   "initializing",
			LastUsed: time.Now(),
		},
	}

	// Initialize model info
	if err := provider.initializeModelInfo(); err != nil {
		return nil, fmt.Errorf("failed to initialize model info: %w", err)
	}

	provider.stats.Status = "healthy"
	return provider, nil
}

// initializeModelInfo fetches model information from OLAMA
func (p *OlamaProvider) initializeModelInfo() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to get model info
	modelInfo, err := p.getModelInfo(ctx, p.model)
	if err != nil {
		// If model doesn't exist, try to pull it
		if strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("model %s not found, please pull it first: olama pull %s", p.model, p.model)
		}
		return err
	}

	// Safely extract version from digest
	version := modelInfo.Digest
	if len(version) > 12 {
		version = version[:12]
	}

	p.modelInfo = ModelInfo{
		Name:         modelInfo.Name,
		Provider:     "olama",
		Version:      version,
		MaxTokens:    4096, // Default, can be configured
		ContextSize:  4096, // Default, can be configured
		Capabilities: []string{"text-generation", "conversation"},
		CreatedAt:    modelInfo.ModifiedAt,
	}

	return nil
}

// getModelInfo fetches model information from OLAMA API
func (p *OlamaProvider) getModelInfo(ctx context.Context, modelName string) (*OlamaModelInfo, error) {
	url := fmt.Sprintf("%s/api/show", p.baseURL)

	reqBody := map[string]string{"name": modelName}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OLAMA API error: %s", string(body))
	}

	var modelInfo OlamaModelInfo
	if err := json.NewDecoder(resp.Body).Decode(&modelInfo); err != nil {
		return nil, err
	}

	return &modelInfo, nil
}

// Generate generates text using OLAMA
func (p *OlamaProvider) Generate(ctx context.Context, request GenerationRequest) (GenerationResponse, error) {
	ctx, span := olamaTracer.Start(ctx, "olama.generate",
		trace.WithAttributes(
			attribute.String("provider", "olama"),
			attribute.String("model", request.Model),
			attribute.Int("max_tokens", request.MaxTokens),
		),
	)
	defer span.End()

	startTime := time.Now()

	// Convert request to OLAMA format
	olamaRequest := p.convertRequest(request)

	// Make the API call
	response, err := p.makeRequest(ctx, "/api/chat", olamaRequest)
	if err != nil {
		span.RecordError(err)
		p.updateStats(startTime, 0, true)
		return GenerationResponse{}, NewProviderError("olama", "api_error", err.Error(), true)
	}

	// Convert response
	genResponse := p.convertResponse(response, request.Model)

	// Update stats
	p.updateStats(startTime, genResponse.TokensUsed.TotalTokens, false)

	span.SetAttributes(
		attribute.String("finish_reason", genResponse.FinishReason),
		attribute.Int("tokens_used", genResponse.TokensUsed.TotalTokens),
	)

	return genResponse, nil
}

// Stream generates streaming text using OLAMA
func (p *OlamaProvider) Stream(ctx context.Context, request GenerationRequest) (<-chan StreamChunk, error) {
	ctx, span := olamaTracer.Start(ctx, "olama.stream",
		trace.WithAttributes(
			attribute.String("provider", "olama"),
			attribute.String("model", request.Model),
		),
	)
	defer span.End()

	chunks := make(chan StreamChunk, 100)

	go func() {
		defer close(chunks)
		defer span.End()

		// Convert request to OLAMA format with streaming enabled
		olamaRequest := p.convertRequest(request)
		olamaRequest.Stream = true

		// Make streaming request
		if err := p.makeStreamingRequest(ctx, "/api/chat", olamaRequest, chunks); err != nil {
			chunks <- StreamChunk{Error: err}
		}
	}()

	return chunks, nil
}

// convertRequest converts GenerationRequest to OlamaRequest
func (p *OlamaProvider) convertRequest(request GenerationRequest) OlamaRequest {
	olamaReq := OlamaRequest{
		Model:   request.Model,
		Stream:  request.Stream,
		Options: make(map[string]interface{}),
	}

	// Convert messages
	if len(request.Messages) > 0 {
		olamaReq.Messages = make([]OlamaMessage, len(request.Messages))
		for i, msg := range request.Messages {
			olamaReq.Messages[i] = OlamaMessage{
				Role:    msg.Role,
				Content: msg.Content,
			}
		}
	}

	// Set options
	if request.Temperature > 0 {
		olamaReq.Options["temperature"] = request.Temperature
	}
	if request.MaxTokens > 0 {
		olamaReq.Options["num_predict"] = request.MaxTokens
	}
	if request.TopP > 0 {
		olamaReq.Options["top_p"] = request.TopP
	}
	if request.TopK > 0 {
		olamaReq.Options["top_k"] = request.TopK
	}
	if len(request.Stop) > 0 {
		olamaReq.Options["stop"] = request.Stop
	}

	return olamaReq
}

// convertResponse converts OlamaResponse to GenerationResponse
func (p *OlamaProvider) convertResponse(response *OlamaResponse, model string) GenerationResponse {
	content := response.Response
	if response.Message.Content != "" {
		content = response.Message.Content
	}

	// Calculate token usage (approximate)
	promptTokens := response.PromptEvalCount
	completionTokens := response.EvalCount
	totalTokens := promptTokens + completionTokens

	return GenerationResponse{
		Content: content,
		TokensUsed: TokenUsage{
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      totalTokens,
		},
		FinishReason: p.determineFinishReason(response),
		Model:        model,
		ID:           fmt.Sprintf("olama-%d", time.Now().UnixNano()),
		Created:      response.CreatedAt,
		Metadata: map[string]interface{}{
			"total_duration":       response.TotalDuration,
			"load_duration":        response.LoadDuration,
			"prompt_eval_duration": response.PromptEvalDuration,
			"eval_duration":        response.EvalDuration,
		},
	}
}

// determineFinishReason determines the finish reason from OLAMA response
func (p *OlamaProvider) determineFinishReason(response *OlamaResponse) string {
	if response.Done {
		return FinishReasonStop
	}
	return ""
}

// makeRequest makes a non-streaming request to OLAMA API
func (p *OlamaProvider) makeRequest(ctx context.Context, endpoint string, request OlamaRequest) (*OlamaResponse, error) {
	url := p.baseURL + endpoint

	jsonBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OLAMA API error: %s", string(body))
	}

	var olamaResp OlamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&olamaResp); err != nil {
		return nil, err
	}

	return &olamaResp, nil
}

// makeStreamingRequest makes a streaming request to OLAMA API
func (p *OlamaProvider) makeStreamingRequest(ctx context.Context, endpoint string, request OlamaRequest, chunks chan<- StreamChunk) error {
	url := p.baseURL + endpoint

	jsonBody, err := json.Marshal(request)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("OLAMA API error: %s", string(body))
	}

	decoder := json.NewDecoder(resp.Body)
	for {
		var response OlamaResponse
		if err := decoder.Decode(&response); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		content := response.Response
		if response.Message.Content != "" {
			content = response.Message.Content
		}

		chunk := StreamChunk{
			Content: content,
			Delta:   content,
			TokensUsed: TokenUsage{
				PromptTokens:     response.PromptEvalCount,
				CompletionTokens: response.EvalCount,
				TotalTokens:      response.PromptEvalCount + response.EvalCount,
			},
		}

		if response.Done {
			chunk.FinishReason = FinishReasonStop
		}

		select {
		case chunks <- chunk:
		case <-ctx.Done():
			return ctx.Err()
		}

		if response.Done {
			break
		}
	}

	return nil
}

// Embed creates embeddings using OLAMA (if supported by model)
func (p *OlamaProvider) Embed(ctx context.Context, text string) ([]float64, error) {
	ctx, span := olamaTracer.Start(ctx, "olama.embed",
		trace.WithAttributes(
			attribute.String("provider", "olama"),
			attribute.Int("text_length", len(text)),
		),
	)
	defer span.End()

	url := p.baseURL + "/api/embeddings"

	reqBody := map[string]interface{}{
		"model":  p.model,
		"prompt": text,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, NewProviderError("olama", "embedding_error", err.Error(), true)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("OLAMA embedding error: %s", string(body))
		span.RecordError(err)
		return nil, NewProviderError("olama", "embedding_error", err.Error(), false)
	}

	var embeddingResp struct {
		Embedding []float64 `json:"embedding"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&embeddingResp); err != nil {
		span.RecordError(err)
		return nil, NewProviderError("olama", "decode_error", err.Error(), false)
	}

	return embeddingResp.Embedding, nil
}

// EmbedBatch creates embeddings for multiple texts
func (p *OlamaProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	embeddings := make([][]float64, len(texts))

	for i, text := range texts {
		embedding, err := p.Embed(ctx, text)
		if err != nil {
			return nil, fmt.Errorf("failed to embed text %d: %w", i, err)
		}
		embeddings[i] = embedding
	}

	return embeddings, nil
}

// GetModel returns model information
func (p *OlamaProvider) GetModel() ModelInfo {
	return p.modelInfo
}

// GetLimits returns provider limits
func (p *OlamaProvider) GetLimits() ProviderLimits {
	return p.limits
}

// GetType returns provider type
func (p *OlamaProvider) GetType() ProviderType {
	return ProviderOlama
}

// Health checks the health of the OLAMA provider
func (p *OlamaProvider) Health(ctx context.Context) error {
	ctx, span := olamaTracer.Start(ctx, "olama.health")
	defer span.End()

	// Try to get model list to verify OLAMA is running
	url := p.baseURL + "/api/tags"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("OLAMA server not reachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OLAMA server returned status %d", resp.StatusCode)
	}

	// Verify our specific model is available
	_, err = p.getModelInfo(ctx, p.model)
	if err != nil {
		return fmt.Errorf("model %s not available: %w", p.model, err)
	}

	return nil
}

// Close closes the provider
func (p *OlamaProvider) Close() error {
	// OLAMA provider doesn't need explicit cleanup
	return nil
}

// updateStats updates provider statistics
func (p *OlamaProvider) updateStats(startTime time.Time, tokens int, hasError bool) {
	duration := time.Since(startTime)

	p.stats.Requests++
	p.stats.Tokens += int64(tokens)
	p.stats.LastUsed = time.Now()

	if hasError {
		p.stats.ErrorCount++
	}

	// Update average latency
	if p.stats.Requests == 1 {
		p.stats.AverageLatency = duration
	} else {
		total := time.Duration(p.stats.Requests-1) * p.stats.AverageLatency
		p.stats.AverageLatency = (total + duration) / time.Duration(p.stats.Requests)
	}
}

// ListModels lists available models from OLAMA
func (p *OlamaProvider) ListModels(ctx context.Context) ([]string, error) {
	url := p.baseURL + "/api/tags"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OLAMA API error: %s", string(body))
	}

	var tagsResp struct {
		Models []OlamaModelInfo `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err != nil {
		return nil, err
	}

	models := make([]string, len(tagsResp.Models))
	for i, model := range tagsResp.Models {
		models[i] = model.Name
	}

	return models, nil
}

// PullModel pulls a model from OLAMA registry
func (p *OlamaProvider) PullModel(ctx context.Context, modelName string) error {
	url := p.baseURL + "/api/pull"

	reqBody := map[string]string{"name": modelName}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("OLAMA pull error: %s", string(body))
	}

	return nil
}
