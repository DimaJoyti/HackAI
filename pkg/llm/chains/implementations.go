package chains

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var chainTracer = otel.Tracer("hackai/llm/chains")

// SimpleChain implements a basic LLM chain
type SimpleChain struct {
	id          string
	name        string
	description string
	provider    providers.LLMProvider
	template    string
	memory      llm.Memory
	logger      *logger.Logger
}

// NewSimpleChain creates a new simple chain
func NewSimpleChain(id, name, description string, provider providers.LLMProvider, template string, logger *logger.Logger) *SimpleChain {
	return &SimpleChain{
		id:          id,
		name:        name,
		description: description,
		provider:    provider,
		template:    template,
		logger:      logger,
	}
}

// ID returns the chain ID
func (sc *SimpleChain) ID() string {
	return sc.id
}

// Name returns the chain name
func (sc *SimpleChain) Name() string {
	return sc.name
}

// Description returns the chain description
func (sc *SimpleChain) Description() string {
	return sc.description
}

// Execute executes the simple chain
func (sc *SimpleChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	ctx, span := chainTracer.Start(ctx, "simple_chain.execute",
		trace.WithAttributes(
			attribute.String("chain.id", sc.id),
			attribute.String("chain.name", sc.name),
		),
	)
	defer span.End()

	// Build prompt from template and input
	prompt, err := sc.buildPrompt(input)
	if err != nil {
		span.RecordError(err)
		return llm.ChainOutput{}, fmt.Errorf("failed to build prompt: %w", err)
	}

	// Extract parameters from input
	temperature := 0.7
	maxTokens := 100

	if temp, ok := input["temperature"].(float64); ok {
		temperature = temp
	}
	if tokens, ok := input["max_tokens"].(int); ok {
		maxTokens = tokens
	}

	// Create generation request
	request := providers.GenerationRequest{
		Messages: []providers.Message{
			{Role: "user", Content: prompt},
		},
		Temperature: temperature,
		MaxTokens:   maxTokens,
	}

	// Generate response
	response, err := sc.provider.Generate(ctx, request)
	if err != nil {
		span.RecordError(err)
		return llm.ChainOutput{}, fmt.Errorf("LLM generation failed: %w", err)
	}

	// Create chain output
	output := llm.ChainOutput{
		"result":        response.Content,
		"provider":      string(sc.provider.GetType()),
		"model":         sc.provider.GetModel().Name,
		"tokens_used":   response.TokensUsed.TotalTokens,
		"finish_reason": response.FinishReason,
		"prompt":        prompt,
		"success":       true,
	}

	span.SetAttributes(
		attribute.String("response", response.Content),
		attribute.Int("tokens_used", response.TokensUsed.TotalTokens),
		attribute.Bool("success", true),
	)

	return output, nil
}

// GetMemory returns the chain's memory
func (sc *SimpleChain) GetMemory() llm.Memory {
	return sc.memory
}

// SetMemory sets the chain's memory
func (sc *SimpleChain) SetMemory(memory llm.Memory) {
	sc.memory = memory
}

// Validate validates the chain configuration
func (sc *SimpleChain) Validate() error {
	if sc.id == "" {
		return fmt.Errorf("chain ID is required")
	}
	if sc.name == "" {
		return fmt.Errorf("chain name is required")
	}
	if sc.provider == nil {
		return fmt.Errorf("LLM provider is required")
	}
	if sc.template == "" {
		return fmt.Errorf("template is required")
	}
	return nil
}

// buildPrompt builds the prompt from template and input
func (sc *SimpleChain) buildPrompt(input llm.ChainInput) (string, error) {
	prompt := sc.template

	// Simple template substitution
	for key, value := range input {
		placeholder := fmt.Sprintf("{{%s}}", key)
		if valueStr, ok := value.(string); ok {
			prompt = strings.ReplaceAll(prompt, placeholder, valueStr)
		}
	}

	return prompt, nil
}

// ConversationalChain implements a conversational LLM chain with memory
type ConversationalChain struct {
	id           string
	name         string
	description  string
	provider     providers.LLMProvider
	memory       llm.Memory
	systemPrompt string
	logger       *logger.Logger
}

// NewConversationalChain creates a new conversational chain
func NewConversationalChain(id, name, description string, provider providers.LLMProvider, memory llm.Memory, systemPrompt string, logger *logger.Logger) *ConversationalChain {
	return &ConversationalChain{
		id:           id,
		name:         name,
		description:  description,
		provider:     provider,
		memory:       memory,
		systemPrompt: systemPrompt,
		logger:       logger,
	}
}

// ID returns the chain ID
func (cc *ConversationalChain) ID() string {
	return cc.id
}

// Name returns the chain name
func (cc *ConversationalChain) Name() string {
	return cc.name
}

// Description returns the chain description
func (cc *ConversationalChain) Description() string {
	return cc.description
}

// Execute executes the conversational chain
func (cc *ConversationalChain) Execute(ctx context.Context, input llm.ChainInput) (llm.ChainOutput, error) {
	ctx, span := chainTracer.Start(ctx, "conversational_chain.execute",
		trace.WithAttributes(
			attribute.String("chain.id", cc.id),
			attribute.String("chain.name", cc.name),
		),
	)
	defer span.End()

	// Get conversation ID from input
	conversationID, ok := input["conversation_id"].(string)
	if !ok {
		conversationID = "default"
	}

	// Get user message from input
	userMessage, _ := input["message"].(string)
	if userMessage == "" {
		return llm.ChainOutput{"error": "no message provided"}, fmt.Errorf("no message provided")
	}

	// Extract parameters
	temperature := 0.7
	maxTokens := 100

	if temp, ok := input["temperature"].(float64); ok {
		temperature = temp
	}
	if tokens, ok := input["max_tokens"].(int); ok {
		maxTokens = tokens
	}

	// Build messages
	messages := []providers.Message{}

	// Add system prompt if provided
	if cc.systemPrompt != "" {
		messages = append(messages, providers.Message{
			Role:    "system",
			Content: cc.systemPrompt,
		})
	}

	// Add current user message
	messages = append(messages, providers.Message{
		Role:    "user",
		Content: userMessage,
	})

	// Create generation request
	request := providers.GenerationRequest{
		Messages:    messages,
		Temperature: temperature,
		MaxTokens:   maxTokens,
	}

	// Generate response
	response, err := cc.provider.Generate(ctx, request)
	if err != nil {
		span.RecordError(err)
		return llm.ChainOutput{}, fmt.Errorf("LLM generation failed: %w", err)
	}

	// Store conversation in memory (simplified)
	conversationKey := fmt.Sprintf("conversation:%s", conversationID)
	conversationData := map[string]interface{}{
		"user_message":      userMessage,
		"assistant_message": response.Content,
		"timestamp":         time.Now(),
		"tokens_used":       response.TokensUsed.TotalTokens,
	}

	if err := cc.memory.Store(ctx, conversationKey, conversationData); err != nil {
		cc.logger.Warn("Failed to store conversation", "error", err)
	}

	// Create chain output
	output := llm.ChainOutput{
		"result":          response.Content,
		"provider":        string(cc.provider.GetType()),
		"model":           cc.provider.GetModel().Name,
		"tokens_used":     response.TokensUsed.TotalTokens,
		"finish_reason":   response.FinishReason,
		"conversation_id": conversationID,
		"success":         true,
	}

	span.SetAttributes(
		attribute.String("conversation_id", conversationID),
		attribute.Int("tokens_used", response.TokensUsed.TotalTokens),
		attribute.Bool("success", true),
	)

	return output, nil
}

// GetMemory returns the chain's memory
func (cc *ConversationalChain) GetMemory() llm.Memory {
	return cc.memory
}

// SetMemory sets the chain's memory
func (cc *ConversationalChain) SetMemory(memory llm.Memory) {
	cc.memory = memory
}

// Validate validates the chain configuration
func (cc *ConversationalChain) Validate() error {
	if cc.id == "" {
		return fmt.Errorf("chain ID is required")
	}
	if cc.name == "" {
		return fmt.Errorf("chain name is required")
	}
	if cc.provider == nil {
		return fmt.Errorf("LLM provider is required")
	}
	return nil
}
