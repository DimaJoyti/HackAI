package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var orchestratorTracer = otel.Tracer("hackai/pkg/ollama/orchestrator")

const (
	contentTypeJSON   = "application/json"
	contentTypeHeader = "Content-Type"
)

// Orchestrator handles OLLAMA inference operations and advanced workflows
type Orchestrator struct {
	manager   *Manager
	modelRepo domain.ModelRepository
	logger    *logger.Logger
	presets   map[string]*ModelPreset
}

// ModelPreset represents a predefined model configuration
type ModelPreset struct {
	Name         string                 `json:"name"`
	Model        string                 `json:"model"`
	Temperature  float64                `json:"temperature"`
	MaxTokens    int                    `json:"max_tokens"`
	SystemPrompt string                 `json:"system_prompt"`
	Description  string                 `json:"description"`
	Parameters   map[string]interface{} `json:"parameters"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// GenerateRequest represents a text generation request
type GenerateRequest struct {
	Model     string                 `json:"model"`
	Prompt    string                 `json:"prompt"`
	System    string                 `json:"system,omitempty"`
	Template  string                 `json:"template,omitempty"`
	Context   []int                  `json:"context,omitempty"`
	Stream    bool                   `json:"stream,omitempty"`
	Raw       bool                   `json:"raw,omitempty"`
	Format    string                 `json:"format,omitempty"`
	Options   map[string]interface{} `json:"options,omitempty"`
	KeepAlive string                 `json:"keep_alive,omitempty"`
}

// ChatRequest represents a chat completion request
type ChatRequest struct {
	Model     string                 `json:"model"`
	Messages  []ChatMessage          `json:"messages"`
	Stream    bool                   `json:"stream,omitempty"`
	Format    string                 `json:"format,omitempty"`
	Options   map[string]interface{} `json:"options,omitempty"`
	KeepAlive string                 `json:"keep_alive,omitempty"`
}

// ChatMessage represents a chat message
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// EmbeddingRequest represents an embedding request
type EmbeddingRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// GenerateResponse represents a generation response
type GenerateResponse struct {
	Model              string    `json:"model"`
	CreatedAt          time.Time `json:"created_at"`
	Response           string    `json:"response"`
	Done               bool      `json:"done"`
	Context            []int     `json:"context,omitempty"`
	TotalDuration      int64     `json:"total_duration,omitempty"`
	LoadDuration       int64     `json:"load_duration,omitempty"`
	PromptEvalCount    int       `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration int64     `json:"prompt_eval_duration,omitempty"`
	EvalCount          int       `json:"eval_count,omitempty"`
	EvalDuration       int64     `json:"eval_duration,omitempty"`
}

// ChatResponse represents a chat response
type ChatResponse struct {
	Model              string      `json:"model"`
	CreatedAt          time.Time   `json:"created_at"`
	Message            ChatMessage `json:"message"`
	Done               bool        `json:"done"`
	TotalDuration      int64       `json:"total_duration,omitempty"`
	LoadDuration       int64       `json:"load_duration,omitempty"`
	PromptEvalCount    int         `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration int64       `json:"prompt_eval_duration,omitempty"`
	EvalCount          int         `json:"eval_count,omitempty"`
	EvalDuration       int64       `json:"eval_duration,omitempty"`
}

// EmbeddingResponse represents an embedding response
type EmbeddingResponse struct {
	Embedding []float64 `json:"embedding"`
}

// NewOrchestrator creates a new OLLAMA orchestrator
func NewOrchestrator(manager *Manager, logger *logger.Logger) (*Orchestrator, error) {
	orchestrator := &Orchestrator{
		manager: manager,
		logger:  logger,
		presets: make(map[string]*ModelPreset),
	}

	// Initialize default presets
	orchestrator.initializeDefaultPresets()

	logger.Info("OLLAMA orchestrator initialized")
	return orchestrator, nil
}

// initializeDefaultPresets sets up default model presets
func (o *Orchestrator) initializeDefaultPresets() {
	defaultPresets := map[string]*ModelPreset{
		"general": {
			Name:         "general",
			Model:        "llama2",
			Temperature:  0.7,
			MaxTokens:    2048,
			SystemPrompt: "You are a helpful AI assistant. Provide accurate and helpful responses.",
			Description:  "General purpose conversational AI",
			Parameters: map[string]interface{}{
				"top_p":          0.9,
				"top_k":          40,
				"repeat_penalty": 1.1,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		"coding": {
			Name:         "coding",
			Model:        "codellama",
			Temperature:  0.1,
			MaxTokens:    4096,
			SystemPrompt: "You are an expert programmer. Provide clean, efficient, and well-documented code solutions.",
			Description:  "Specialized for code generation and programming tasks",
			Parameters: map[string]interface{}{
				"top_p":          0.95,
				"top_k":          50,
				"repeat_penalty": 1.05,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		"security": {
			Name:         "security",
			Model:        "llama2",
			Temperature:  0.2,
			MaxTokens:    2048,
			SystemPrompt: "You are a cybersecurity expert. Focus on security analysis, threat detection, and vulnerability assessment.",
			Description:  "Specialized for security analysis and penetration testing",
			Parameters: map[string]interface{}{
				"top_p":          0.8,
				"top_k":          30,
				"repeat_penalty": 1.1,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		"creative": {
			Name:         "creative",
			Model:        "mistral",
			Temperature:  0.9,
			MaxTokens:    3072,
			SystemPrompt: "You are a creative AI assistant. Generate imaginative and original content.",
			Description:  "Optimized for creative writing and content generation",
			Parameters: map[string]interface{}{
				"top_p":          0.95,
				"top_k":          60,
				"repeat_penalty": 1.05,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	for name, preset := range defaultPresets {
		o.presets[name] = preset
	}
}

// Generate performs text generation using OLLAMA
func (o *Orchestrator) Generate(ctx context.Context, request GenerateRequest) (*GenerateResponse, error) {
	ctx, span := orchestratorTracer.Start(ctx, "orchestrator.generate",
		trace.WithAttributes(
			attribute.String("model", request.Model),
			attribute.Int("prompt_length", len(request.Prompt)),
		))
	defer span.End()

	// Validate model availability
	if _, err := o.manager.GetModel(request.Model); err != nil {
		return nil, fmt.Errorf("model not available: %w", err)
	}

	// Make the API call
	url := o.manager.baseURL + "/api/generate"
	jsonBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set(contentTypeHeader, contentTypeJSON)

	resp, err := o.manager.client.Do(req)
	if err != nil {
		span.RecordError(err)
		o.manager.UpdateFailedRequest()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("OLLAMA generate error: %s", string(body))
		span.RecordError(err)
		o.manager.UpdateFailedRequest()
		return nil, err
	}

	var response GenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		span.RecordError(err)
		o.manager.UpdateFailedRequest()
		return nil, err
	}

	// Update usage statistics
	o.manager.UpdateModelUsage(request.Model, int64(response.EvalCount))

	span.SetAttributes(
		attribute.Int("response_length", len(response.Response)),
		attribute.Int("eval_count", response.EvalCount),
		attribute.Int64("total_duration", response.TotalDuration),
	)

	return &response, nil
}

// Chat performs chat completion using OLLAMA
func (o *Orchestrator) Chat(ctx context.Context, request ChatRequest) (*ChatResponse, error) {
	ctx, span := orchestratorTracer.Start(ctx, "orchestrator.chat",
		trace.WithAttributes(
			attribute.String("model", request.Model),
			attribute.Int("messages_count", len(request.Messages)),
		))
	defer span.End()

	// Validate model availability
	if _, err := o.manager.GetModel(request.Model); err != nil {
		return nil, fmt.Errorf("model not available: %w", err)
	}

	// Make the API call
	url := o.manager.baseURL + "/api/chat"
	jsonBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set(contentTypeHeader, contentTypeJSON)

	resp, err := o.manager.client.Do(req)
	if err != nil {
		span.RecordError(err)
		o.manager.UpdateFailedRequest()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("OLLAMA chat error: %s", string(body))
		span.RecordError(err)
		o.manager.UpdateFailedRequest()
		return nil, err
	}

	var response ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		span.RecordError(err)
		o.manager.UpdateFailedRequest()
		return nil, err
	}

	// Update usage statistics
	o.manager.UpdateModelUsage(request.Model, int64(response.EvalCount))

	span.SetAttributes(
		attribute.Int("response_length", len(response.Message.Content)),
		attribute.Int("eval_count", response.EvalCount),
		attribute.Int64("total_duration", response.TotalDuration),
	)

	return &response, nil
}

// GetPresets returns available model presets
func (o *Orchestrator) GetPresets() map[string]*ModelPreset {
	presets := make(map[string]*ModelPreset)
	for name, preset := range o.presets {
		presets[name] = preset
	}
	return presets
}

// GetPreset returns a specific model preset
func (o *Orchestrator) GetPreset(name string) (*ModelPreset, error) {
	preset, exists := o.presets[name]
	if !exists {
		return nil, fmt.Errorf("preset not found: %s", name)
	}
	return preset, nil
}

// CreatePreset creates a new model preset
func (o *Orchestrator) CreatePreset(preset *ModelPreset) error {
	preset.CreatedAt = time.Now()
	preset.UpdatedAt = time.Now()
	o.presets[preset.Name] = preset
	o.logger.Info("Created model preset", "name", preset.Name)
	return nil
}

// UpdatePreset updates an existing model preset
func (o *Orchestrator) UpdatePreset(name string, preset *ModelPreset) error {
	if _, exists := o.presets[name]; !exists {
		return fmt.Errorf("preset not found: %s", name)
	}
	preset.UpdatedAt = time.Now()
	o.presets[name] = preset
	o.logger.Info("Updated model preset", "name", name)
	return nil
}

// DeletePreset deletes a model preset
func (o *Orchestrator) DeletePreset(name string) error {
	if _, exists := o.presets[name]; !exists {
		return fmt.Errorf("preset not found: %s", name)
	}
	delete(o.presets, name)
	o.logger.Info("Deleted model preset", "name", name)
	return nil
}
