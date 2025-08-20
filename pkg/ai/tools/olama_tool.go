package tools

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
)

// OlamaTool provides access to OLAMA local models for AI operations
type OlamaTool struct {
	name        string
	description string
	provider    *providers.OlamaProvider
	config      OlamaToolConfig
	metrics     ai.ToolMetrics
	metricsMux  sync.RWMutex
}

// OlamaToolConfig holds configuration for the OLAMA tool
type OlamaToolConfig struct {
	DefaultModel    string            `json:"default_model"`
	MaxTokens       int               `json:"max_tokens"`
	Temperature     float64           `json:"temperature"`
	EnableStreaming bool              `json:"enable_streaming"`
	ModelPresets    map[string]Preset `json:"model_presets"`
}

// Preset defines model-specific presets for different use cases
type Preset struct {
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens"`
	SystemPrompt string `json:"system_prompt"`
	Description string  `json:"description"`
}

// NewOlamaTool creates a new OLAMA tool
func NewOlamaTool(provider *providers.OlamaProvider, config OlamaToolConfig) *OlamaTool {
	if config.DefaultModel == "" {
		config.DefaultModel = "llama2"
	}
	if config.MaxTokens == 0 {
		config.MaxTokens = 2048
	}
	if config.Temperature == 0 {
		config.Temperature = 0.7
	}

	// Initialize default presets if not provided
	if config.ModelPresets == nil {
		config.ModelPresets = getDefaultPresets()
	}

	return &OlamaTool{
		name:        "olama_llm",
		description: "Access to OLAMA local language models for text generation, analysis, and AI operations",
		provider:    provider,
		config:      config,
	}
}

// getDefaultPresets returns default model presets for common use cases
func getDefaultPresets() map[string]Preset {
	return map[string]Preset{
		"creative": {
			Model:       "llama2",
			Temperature: 0.9,
			MaxTokens:   2048,
			SystemPrompt: "You are a creative and imaginative AI assistant. Think outside the box and provide innovative solutions.",
			Description: "High creativity for brainstorming and creative writing",
		},
		"analytical": {
			Model:       "llama2",
			Temperature: 0.3,
			MaxTokens:   2048,
			SystemPrompt: "You are a precise and analytical AI assistant. Focus on accuracy, logic, and detailed analysis.",
			Description: "Low temperature for analytical and factual tasks",
		},
		"coding": {
			Model:       "codellama",
			Temperature: 0.1,
			MaxTokens:   4096,
			SystemPrompt: "You are an expert programmer. Provide clean, efficient, and well-documented code solutions.",
			Description: "Specialized for code generation and programming tasks",
		},
		"security": {
			Model:       "llama2",
			Temperature: 0.2,
			MaxTokens:   2048,
			SystemPrompt: "You are a cybersecurity expert. Focus on security analysis, threat detection, and vulnerability assessment.",
			Description: "Specialized for security analysis and penetration testing",
		},
		"conversational": {
			Model:       "neural-chat",
			Temperature: 0.7,
			MaxTokens:   1024,
			SystemPrompt: "You are a helpful and friendly AI assistant. Engage in natural conversation and provide helpful responses.",
			Description: "Optimized for natural conversation and chat",
		},
	}
}

// Name returns the tool name
func (t *OlamaTool) Name() string {
	return t.name
}

// Description returns the tool description
func (t *OlamaTool) Description() string {
	return t.description
}

// Execute executes the OLAMA tool with the given input
func (t *OlamaTool) Execute(ctx context.Context, input ai.ToolInput) (ai.ToolOutput, error) {
	// Parse input parameters
	prompt, ok := input["prompt"].(string)
	if !ok || prompt == "" {
		return nil, fmt.Errorf("prompt is required")
	}

	// Get optional parameters
	model := t.getStringParam(input, "model", t.config.DefaultModel)
	preset := t.getStringParam(input, "preset", "")
	temperature := t.getFloatParam(input, "temperature", t.config.Temperature)
	maxTokens := t.getIntParam(input, "max_tokens", t.config.MaxTokens)
	systemPrompt := t.getStringParam(input, "system_prompt", "")
	streaming := t.getBoolParam(input, "streaming", t.config.EnableStreaming)

	// Apply preset if specified
	if preset != "" {
		if presetConfig, exists := t.config.ModelPresets[preset]; exists {
			model = presetConfig.Model
			temperature = presetConfig.Temperature
			maxTokens = presetConfig.MaxTokens
			if systemPrompt == "" {
				systemPrompt = presetConfig.SystemPrompt
			}
		}
	}

	// Build messages
	messages := []providers.Message{}
	if systemPrompt != "" {
		messages = append(messages, providers.Message{
			Role:    providers.RoleSystem,
			Content: systemPrompt,
		})
	}
	messages = append(messages, providers.Message{
		Role:    providers.RoleUser,
		Content: prompt,
	})

	// Create generation request
	request := providers.GenerationRequest{
		Messages:    messages,
		Model:       model,
		Temperature: temperature,
		MaxTokens:   maxTokens,
		Stream:      streaming,
	}

	// Execute based on streaming preference
	if streaming {
		return t.executeStreaming(ctx, request)
	}
	return t.executeNonStreaming(ctx, request)
}

// executeNonStreaming executes a non-streaming request
func (t *OlamaTool) executeNonStreaming(ctx context.Context, request providers.GenerationRequest) (ai.ToolOutput, error) {
	start := time.Now()
	response, err := t.provider.Generate(ctx, request)
	latency := time.Since(start)
	
	success := err == nil
	t.updateMetrics(success, latency)
	
	if err != nil {
		return nil, fmt.Errorf("OLAMA generation failed: %w", err)
	}

	return ai.ToolOutput{
		"response":      response.Content,
		"model":         response.Model,
		"finish_reason": response.FinishReason,
		"tokens_used":   response.TokensUsed.TotalTokens,
		"prompt_tokens": response.TokensUsed.PromptTokens,
		"completion_tokens": response.TokensUsed.CompletionTokens,
		"metadata":      response.Metadata,
		"streaming":     false,
	}, nil
}

// executeStreaming executes a streaming request
func (t *OlamaTool) executeStreaming(ctx context.Context, request providers.GenerationRequest) (ai.ToolOutput, error) {
	start := time.Now()
	chunks, err := t.provider.Stream(ctx, request)
	if err != nil {
		latency := time.Since(start)
		t.updateMetrics(false, latency)
		return nil, fmt.Errorf("OLAMA streaming failed: %w", err)
	}

	var fullResponse strings.Builder
	var totalTokens int
	var finishReason string
	var streamErr error

	for chunk := range chunks {
		if chunk.Error != nil {
			streamErr = chunk.Error
			break
		}

		fullResponse.WriteString(chunk.Delta)
		totalTokens = chunk.TokensUsed.TotalTokens
		if chunk.FinishReason != "" {
			finishReason = chunk.FinishReason
		}
	}

	latency := time.Since(start)
	success := streamErr == nil
	t.updateMetrics(success, latency)

	if streamErr != nil {
		return nil, fmt.Errorf("streaming error: %w", streamErr)
	}

	return ai.ToolOutput{
		"response":      fullResponse.String(),
		"model":         request.Model,
		"finish_reason": finishReason,
		"tokens_used":   totalTokens,
		"streaming":     true,
	}, nil
}

// GetSchema returns the tool schema
func (t *OlamaTool) GetSchema() ai.ToolSchema {
	return ai.ToolSchema{
		InputSchema: map[string]ai.ParameterSchema{
			"prompt": {
				Type:        "string",
				Description: "The prompt to send to the OLAMA model",
				Required:    true,
			},
			"model": {
				Type:        "string",
				Description: "The OLAMA model to use (optional, defaults to configured model)",
				Required:    false,
				Default:     t.config.DefaultModel,
			},
			"preset": {
				Type:        "string",
				Description: "Preset configuration to use (creative, analytical, coding, security, conversational)",
				Required:    false,
			},
			"temperature": {
				Type:        "number",
				Description: "Temperature for generation (0.0 to 1.0)",
				Required:    false,
				Default:     t.config.Temperature,
			},
			"max_tokens": {
				Type:        "integer",
				Description: "Maximum tokens to generate",
				Required:    false,
				Default:     t.config.MaxTokens,
			},
			"system_prompt": {
				Type:        "string",
				Description: "System prompt to set context",
				Required:    false,
			},
			"streaming": {
				Type:        "boolean",
				Description: "Enable streaming response",
				Required:    false,
				Default:     t.config.EnableStreaming,
			},
		},
		OutputSchema: map[string]ai.ParameterSchema{
			"response": {
				Type:        "string",
				Description: "Generated response from the model",
			},
			"model": {
				Type:        "string",
				Description: "Model used for generation",
			},
			"finish_reason": {
				Type:        "string",
				Description: "Reason why generation finished",
			},
			"tokens_used": {
				Type:        "integer",
				Description: "Total tokens used",
			},
			"streaming": {
				Type:        "boolean",
				Description: "Whether streaming was used",
			},
		},
	}
}

// Validate validates the tool input
func (t *OlamaTool) Validate(input ai.ToolInput) error {
	prompt, ok := input["prompt"].(string)
	if !ok || prompt == "" {
		return fmt.Errorf("prompt is required and must be a non-empty string")
	}

	// Validate optional parameters
	if model, exists := input["model"]; exists {
		if _, ok := model.(string); !ok {
			return fmt.Errorf("model must be a string")
		}
	}

	if preset, exists := input["preset"]; exists {
		if presetStr, ok := preset.(string); ok {
			if _, validPreset := t.config.ModelPresets[presetStr]; !validPreset {
				return fmt.Errorf("invalid preset: %s", presetStr)
			}
		} else {
			return fmt.Errorf("preset must be a string")
		}
	}

	if temp, exists := input["temperature"]; exists {
		if tempFloat, ok := temp.(float64); ok {
			if tempFloat < 0 || tempFloat > 1 {
				return fmt.Errorf("temperature must be between 0 and 1")
			}
		} else {
			return fmt.Errorf("temperature must be a number")
		}
	}

	if maxTokens, exists := input["max_tokens"]; exists {
		if tokensInt, ok := maxTokens.(int); ok {
			if tokensInt <= 0 {
				return fmt.Errorf("max_tokens must be positive")
			}
		} else {
			return fmt.Errorf("max_tokens must be an integer")
		}
	}

	return nil
}

// Helper methods for parameter extraction
func (t *OlamaTool) getStringParam(input ai.ToolInput, key, defaultValue string) string {
	if value, exists := input[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return defaultValue
}

func (t *OlamaTool) getFloatParam(input ai.ToolInput, key string, defaultValue float64) float64 {
	if value, exists := input[key]; exists {
		if f, ok := value.(float64); ok {
			return f
		}
	}
	return defaultValue
}

func (t *OlamaTool) getIntParam(input ai.ToolInput, key string, defaultValue int) int {
	if value, exists := input[key]; exists {
		if i, ok := value.(int); ok {
			return i
		}
	}
	return defaultValue
}

func (t *OlamaTool) getBoolParam(input ai.ToolInput, key string, defaultValue bool) bool {
	if value, exists := input[key]; exists {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return defaultValue
}

// GetMetrics returns the current metrics for the tool
func (t *OlamaTool) GetMetrics() ai.ToolMetrics {
	t.metricsMux.RLock()
	defer t.metricsMux.RUnlock()
	return t.metrics
}

// IsHealthy checks if the tool is healthy and operational
func (t *OlamaTool) IsHealthy(ctx context.Context) bool {
	return t.provider.Health(ctx) == nil
}

// updateMetrics updates the tool metrics (called internally)
func (t *OlamaTool) updateMetrics(success bool, latency time.Duration) {
	t.metricsMux.Lock()
	defer t.metricsMux.Unlock()
	
	t.metrics.TotalExecutions++
	t.metrics.LastExecutionTime = time.Now()
	
	if success {
		t.metrics.SuccessfulRuns++
	} else {
		t.metrics.FailedRuns++
	}
	
	// Update average latency (simple moving average)
	if t.metrics.TotalExecutions == 1 {
		t.metrics.AverageLatency = latency
	} else {
		// Simple weighted average: (old_avg * (n-1) + new_latency) / n
		totalLatency := t.metrics.AverageLatency * time.Duration(t.metrics.TotalExecutions-1)
		t.metrics.AverageLatency = (totalLatency + latency) / time.Duration(t.metrics.TotalExecutions)
	}
	
	// Update error rate
	if t.metrics.TotalExecutions > 0 {
		t.metrics.ErrorRate = float64(t.metrics.FailedRuns) / float64(t.metrics.TotalExecutions)
	}
}
