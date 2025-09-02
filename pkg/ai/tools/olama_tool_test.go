package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOlamaTool(t *testing.T) {
	// Create mock OLAMA server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			response := providers.OlamaModelInfo{
				Name:   "llama2",
				Size:   3800000000,
				Digest: "abc123def456",
				Details: providers.OlamaModelDetails{
					Format:            "gguf",
					Family:            "llama",
					ParameterSize:     "7B",
					QuantizationLevel: "Q4_0",
				},
				ModifiedAt: time.Now(),
			}
			json.NewEncoder(w).Encode(response)
		case "/api/tags":
			response := struct {
				Models []providers.OlamaModelInfo `json:"models"`
			}{
				Models: []providers.OlamaModelInfo{
					{
						Name:       "llama2",
						Size:       3800000000,
						Digest:     "abc123def456",
						ModifiedAt: time.Now(),
					},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create provider
	config := providers.ProviderConfig{
		Type:    providers.ProviderOlama,
		Name:    "test-olama",
		BaseURL: server.URL,
		Model:   "llama2",
		Enabled: true,
		Limits:  providers.DefaultLimits,
	}

	provider, err := providers.NewOlamaProvider(config)
	require.NoError(t, err)

	// Create tool
	toolConfig := OlamaToolConfig{
		DefaultModel:    "llama2",
		MaxTokens:       1024,
		Temperature:     0.7,
		EnableStreaming: false,
	}

	tool := NewOlamaTool(provider, toolConfig)

	// Test tool properties
	assert.Equal(t, "olama_llm", tool.Name())
	assert.Contains(t, tool.Description(), "OLAMA local language models")

	// Test schema
	schema := tool.GetSchema()
	assert.NotNil(t, schema.InputSchema)
	assert.NotNil(t, schema.OutputSchema)
	assert.Contains(t, schema.InputSchema, "prompt")
	assert.Contains(t, schema.OutputSchema, "response")
}

func TestOlamaTool_Execute(t *testing.T) {
	// Create mock OLAMA server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			response := providers.OlamaModelInfo{
				Name:       "llama2",
				Digest:     "abc123def456",
				ModifiedAt: time.Now(),
			}
			json.NewEncoder(w).Encode(response)
		case "/api/chat":
			response := providers.OlamaResponse{
				Model:     "llama2",
				CreatedAt: time.Now(),
				Message: providers.OlamaMessage{
					Role:    "assistant",
					Content: "This is a test response from OLAMA.",
				},
				Done:               true,
				TotalDuration:      1000000000, // 1 second
				PromptEvalCount:    10,
				PromptEvalDuration: 200000000, // 200ms
				EvalCount:          15,
				EvalDuration:       700000000, // 700ms
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create provider and tool
	config := providers.ProviderConfig{
		Type:    providers.ProviderOlama,
		Name:    "test-olama",
		BaseURL: server.URL,
		Model:   "llama2",
		Enabled: true,
		Limits:  providers.DefaultLimits,
	}

	provider, err := providers.NewOlamaProvider(config)
	require.NoError(t, err)

	toolConfig := OlamaToolConfig{
		DefaultModel:    "llama2",
		MaxTokens:       1024,
		Temperature:     0.7,
		EnableStreaming: false,
	}

	tool := NewOlamaTool(provider, toolConfig)

	// Test execution
	ctx := context.Background()
	input := ai.ToolInput{
		"prompt": "Hello, how are you?",
	}

	result, err := tool.Execute(ctx, input)
	require.NoError(t, err)

	// Verify result
	assert.Contains(t, result, "response")
	assert.Contains(t, result, "model")
	assert.Contains(t, result, "tokens_used")
	assert.Equal(t, "This is a test response from OLAMA.", result["response"])
	assert.Equal(t, "llama2", result["model"])
	assert.Equal(t, 25, result["tokens_used"]) // 10 + 15
}

func TestOlamaTool_ExecuteWithPreset(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			response := providers.OlamaModelInfo{
				Name:       "codellama",
				Digest:     "def456ghi789",
				ModifiedAt: time.Now(),
			}
			json.NewEncoder(w).Encode(response)
		case "/api/chat":
			// Verify request contains system prompt from preset
			var reqBody providers.OlamaRequest
			json.NewDecoder(r.Body).Decode(&reqBody)

			// Check if coding preset was applied
			hasSystemPrompt := false
			for _, msg := range reqBody.Messages {
				if msg.Role == "system" && msg.Content != "" {
					hasSystemPrompt = true
					break
				}
			}

			response := providers.OlamaResponse{
				Model:     "codellama",
				CreatedAt: time.Now(),
				Message: providers.OlamaMessage{
					Role:    "assistant",
					Content: "Here's a code solution for you.",
				},
				Done: true,
			}

			if hasSystemPrompt {
				response.Message.Content = "Expert code solution with system prompt applied."
			}

			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create provider and tool
	config := providers.ProviderConfig{
		Type:    providers.ProviderOlama,
		Name:    "test-olama",
		BaseURL: server.URL,
		Model:   "llama2",
		Enabled: true,
		Limits:  providers.DefaultLimits,
	}

	provider, err := providers.NewOlamaProvider(config)
	require.NoError(t, err)

	tool := NewOlamaTool(provider, OlamaToolConfig{})

	// Test with coding preset
	ctx := context.Background()
	input := ai.ToolInput{
		"prompt": "Write a function to sort an array",
		"preset": "coding",
	}

	result, err := tool.Execute(ctx, input)
	require.NoError(t, err)

	// Verify preset was applied
	assert.Contains(t, result, "response")
	assert.Equal(t, "codellama", result["model"]) // Should use coding preset model
	response := result["response"].(string)
	assert.Contains(t, response, "Expert code solution") // Should have system prompt applied
}

func TestOlamaTool_Validate(t *testing.T) {
	tool := &OlamaTool{
		config: OlamaToolConfig{
			ModelPresets: getDefaultPresets(),
		},
	}

	tests := []struct {
		name    string
		input   ai.ToolInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: ai.ToolInput{
				"prompt": "Hello world",
			},
			wantErr: false,
		},
		{
			name: "missing prompt",
			input: ai.ToolInput{
				"model": "llama2",
			},
			wantErr: true,
		},
		{
			name: "empty prompt",
			input: ai.ToolInput{
				"prompt": "",
			},
			wantErr: true,
		},
		{
			name: "invalid preset",
			input: ai.ToolInput{
				"prompt": "Hello",
				"preset": "invalid_preset",
			},
			wantErr: true,
		},
		{
			name: "valid preset",
			input: ai.ToolInput{
				"prompt": "Hello",
				"preset": "creative",
			},
			wantErr: false,
		},
		{
			name: "invalid temperature",
			input: ai.ToolInput{
				"prompt":      "Hello",
				"temperature": 2.0, // > 1.0
			},
			wantErr: true,
		},
		{
			name: "invalid max_tokens",
			input: ai.ToolInput{
				"prompt":     "Hello",
				"max_tokens": -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tool.Validate(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOlamaTool_ParameterExtraction(t *testing.T) {
	tool := &OlamaTool{}

	// Test string parameter extraction
	input := ai.ToolInput{
		"string_param": "test_value",
		"int_param":    42,
		"float_param":  3.14,
		"bool_param":   true,
	}

	assert.Equal(t, "test_value", tool.getStringParam(input, "string_param", "default"))
	assert.Equal(t, "default", tool.getStringParam(input, "missing_param", "default"))

	assert.Equal(t, 42, tool.getIntParam(input, "int_param", 0))
	assert.Equal(t, 0, tool.getIntParam(input, "missing_param", 0))

	assert.Equal(t, 3.14, tool.getFloatParam(input, "float_param", 0.0))
	assert.Equal(t, 0.0, tool.getFloatParam(input, "missing_param", 0.0))

	assert.Equal(t, true, tool.getBoolParam(input, "bool_param", false))
	assert.Equal(t, false, tool.getBoolParam(input, "missing_param", false))
}

func TestOlamaTool_DefaultPresets(t *testing.T) {
	presets := getDefaultPresets()

	// Verify all expected presets exist
	expectedPresets := []string{"creative", "analytical", "coding", "security", "conversational"}
	for _, preset := range expectedPresets {
		assert.Contains(t, presets, preset, "Missing preset: %s", preset)
	}

	// Verify preset properties
	creative := presets["creative"]
	assert.Equal(t, "llama2", creative.Model)
	assert.Equal(t, 0.9, creative.Temperature)
	assert.Contains(t, creative.Description, "creativity")

	coding := presets["coding"]
	assert.Equal(t, "codellama", coding.Model)
	assert.Equal(t, 0.1, coding.Temperature)
	assert.Contains(t, coding.Description, "code")

	security := presets["security"]
	assert.Equal(t, 0.2, security.Temperature)
	assert.Contains(t, security.Description, "security")
}

func BenchmarkOlamaTool_Execute(b *testing.B) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			response := providers.OlamaModelInfo{
				Name:       "llama2",
				Digest:     "abc123",
				ModifiedAt: time.Now(),
			}
			json.NewEncoder(w).Encode(response)
		case "/api/chat":
			response := providers.OlamaResponse{
				Model:     "llama2",
				CreatedAt: time.Now(),
				Message: providers.OlamaMessage{
					Role:    "assistant",
					Content: "Benchmark response",
				},
				Done: true,
			}
			json.NewEncoder(w).Encode(response)
		}
	}))
	defer server.Close()

	// Create provider and tool
	config := providers.ProviderConfig{
		Type:    providers.ProviderOlama,
		Name:    "benchmark-olama",
		BaseURL: server.URL,
		Model:   "llama2",
		Enabled: true,
		Limits:  providers.DefaultLimits,
	}

	provider, err := providers.NewOlamaProvider(config)
	require.NoError(b, err)

	tool := NewOlamaTool(provider, OlamaToolConfig{})

	input := ai.ToolInput{
		"prompt": "Benchmark test prompt",
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tool.Execute(ctx, input)
		if err != nil {
			b.Fatal(err)
		}
	}
}
