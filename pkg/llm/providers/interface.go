package providers

import (
	"context"
	"time"
)

// LLMProvider abstracts different LLM services
type LLMProvider interface {
	// Core generation methods
	Generate(ctx context.Context, request GenerationRequest) (GenerationResponse, error)
	Stream(ctx context.Context, request GenerationRequest) (<-chan StreamChunk, error)

	// Embedding methods
	Embed(ctx context.Context, text string) ([]float64, error)
	EmbedBatch(ctx context.Context, texts []string) ([][]float64, error)

	// Provider information
	GetModel() ModelInfo
	GetLimits() ProviderLimits
	GetType() ProviderType

	// Health and status
	Health(ctx context.Context) error
	Close() error
}

// GenerationRequest represents an LLM generation request
type GenerationRequest struct {
	Messages    []Message              `json:"messages"`
	Model       string                 `json:"model"`
	Temperature float64                `json:"temperature,omitempty"`
	MaxTokens   int                    `json:"max_tokens,omitempty"`
	TopP        float64                `json:"top_p,omitempty"`
	TopK        int                    `json:"top_k,omitempty"`
	Stop        []string               `json:"stop,omitempty"`
	Stream      bool                   `json:"stream,omitempty"`
	Seed        *int                   `json:"seed,omitempty"`
	Tools       []Tool                 `json:"tools,omitempty"`
	ToolChoice  interface{}            `json:"tool_choice,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// GenerationResponse represents an LLM generation response
type GenerationResponse struct {
	Content      string                 `json:"content"`
	TokensUsed   TokenUsage             `json:"tokens_used"`
	FinishReason string                 `json:"finish_reason"`
	Model        string                 `json:"model"`
	ID           string                 `json:"id"`
	Created      time.Time              `json:"created"`
	ToolCalls    []ToolCall             `json:"tool_calls,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// StreamChunk represents a chunk in a streaming response
type StreamChunk struct {
	Content      string                 `json:"content"`
	Delta        string                 `json:"delta"`
	FinishReason string                 `json:"finish_reason,omitempty"`
	TokensUsed   TokenUsage             `json:"tokens_used,omitempty"`
	Error        error                  `json:"error,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// Message represents a message in the conversation
type Message struct {
	Role       string      `json:"role"`
	Content    string      `json:"content"`
	Name       string      `json:"name,omitempty"`
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`
	ToolCallID string      `json:"tool_call_id,omitempty"`
	Metadata   interface{} `json:"metadata,omitempty"`
}

// Tool represents a tool that can be called by the LLM
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction represents a function tool
type ToolFunction struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Parameters  interface{} `json:"parameters"`
}

// ToolCall represents a tool call made by the LLM
type ToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function ToolCallFunction `json:"function"`
}

// ToolCallFunction represents the function part of a tool call
type ToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// TokenUsage represents token usage information
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ModelInfo provides information about the model
type ModelInfo struct {
	Name         string    `json:"name"`
	Provider     string    `json:"provider"`
	Version      string    `json:"version"`
	MaxTokens    int       `json:"max_tokens"`
	ContextSize  int       `json:"context_size"`
	Capabilities []string  `json:"capabilities"`
	CreatedAt    time.Time `json:"created_at"`
}

// ProviderLimits defines the limits for a provider
type ProviderLimits struct {
	RequestsPerMinute int           `json:"requests_per_minute"`
	TokensPerMinute   int           `json:"tokens_per_minute"`
	MaxConcurrent     int           `json:"max_concurrent"`
	MaxRetries        int           `json:"max_retries"`
	Timeout           time.Duration `json:"timeout"`
}

// ProviderType represents the type of LLM provider
type ProviderType string

const (
	ProviderOpenAI      ProviderType = "openai"
	ProviderAnthropic   ProviderType = "anthropic"
	ProviderLocal       ProviderType = "local"
	ProviderOlama       ProviderType = "olama"
	ProviderAzure       ProviderType = "azure"
	ProviderGoogle      ProviderType = "google"
	ProviderCohere      ProviderType = "cohere"
	ProviderHuggingFace ProviderType = "huggingface"
)

// ProviderConfig represents configuration for a provider
type ProviderConfig struct {
	Type       ProviderType           `json:"type"`
	Name       string                 `json:"name"`
	APIKey     string                 `json:"api_key"`
	BaseURL    string                 `json:"base_url,omitempty"`
	Model      string                 `json:"model"`
	Enabled    bool                   `json:"enabled"`
	Priority   int                    `json:"priority"`
	Limits     ProviderLimits         `json:"limits"`
	Parameters map[string]interface{} `json:"parameters"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// ProviderManager manages multiple LLM providers
type ProviderManager interface {
	// Provider management
	RegisterProvider(name string, provider LLMProvider) error
	UnregisterProvider(name string) error
	GetProvider(name string) (LLMProvider, error)
	ListProviders() []string

	// Load balancing and routing
	GetBestProvider(ctx context.Context, request GenerationRequest) (LLMProvider, error)
	RouteRequest(ctx context.Context, request GenerationRequest) (GenerationResponse, error)

	// Health and monitoring
	HealthCheck(ctx context.Context) map[string]error
	GetStats() ProviderStats

	// Lifecycle
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// ProviderStats provides statistics about provider usage
type ProviderStats struct {
	TotalRequests  int64                   `json:"total_requests"`
	TotalTokens    int64                   `json:"total_tokens"`
	TotalCost      float64                 `json:"total_cost"`
	AverageLatency time.Duration           `json:"average_latency"`
	ErrorRate      float64                 `json:"error_rate"`
	ProviderStats  map[string]ProviderStat `json:"provider_stats"`
	LastUpdated    time.Time               `json:"last_updated"`
}

// ProviderStat provides statistics for a specific provider
type ProviderStat struct {
	Name           string        `json:"name"`
	Requests       int64         `json:"requests"`
	Tokens         int64         `json:"tokens"`
	Cost           float64       `json:"cost"`
	AverageLatency time.Duration `json:"average_latency"`
	ErrorCount     int64         `json:"error_count"`
	LastUsed       time.Time     `json:"last_used"`
	Status         string        `json:"status"`
}

// EmbeddingRequest represents an embedding request
type EmbeddingRequest struct {
	Input    interface{}            `json:"input"`
	Model    string                 `json:"model"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// EmbeddingResponse represents an embedding response
type EmbeddingResponse struct {
	Embeddings [][]float64            `json:"embeddings"`
	Model      string                 `json:"model"`
	TokensUsed int                    `json:"tokens_used"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ProviderError represents an error from a provider
type ProviderError struct {
	Provider  string `json:"provider"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (e *ProviderError) Error() string {
	return e.Message
}

// IsRetryable returns whether the error is retryable
func (e *ProviderError) IsRetryable() bool {
	return e.Retryable
}

// NewProviderError creates a new provider error
func NewProviderError(provider, code, message string, retryable bool) *ProviderError {
	return &ProviderError{
		Provider:  provider,
		Code:      code,
		Message:   message,
		Retryable: retryable,
	}
}

// MessageRole constants
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

// FinishReason constants
const (
	FinishReasonStop          = "stop"
	FinishReasonLength        = "length"
	FinishReasonToolCalls     = "tool_calls"
	FinishReasonContentFilter = "content_filter"
	FinishReasonError         = "error"
)

// Tool types
const (
	ToolTypeFunction = "function"
)

// Default limits
var DefaultLimits = ProviderLimits{
	RequestsPerMinute: 60,
	TokensPerMinute:   100000,
	MaxConcurrent:     10,
	MaxRetries:        3,
	Timeout:           30 * time.Second,
}
