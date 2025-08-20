package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOlamaProvider(t *testing.T) {
	// Create mock OLAMA server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			response := OlamaModelInfo{
				Name:   "llama2",
				Size:   3800000000,
				Digest: "abc123def456",
				Details: OlamaModelDetails{
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
				Models []OlamaModelInfo `json:"models"`
			}{
				Models: []OlamaModelInfo{
					{
						Name:   "llama2",
						Size:   3800000000,
						Digest: "abc123def456",
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

	config := ProviderConfig{
		Type:    ProviderOlama,
		Name:    "test-olama",
		BaseURL: server.URL,
		Model:   "llama2",
		Enabled: true,
		Limits:  DefaultLimits,
	}

	provider, err := NewOlamaProvider(config)
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, ProviderOlama, provider.GetType())
	assert.Equal(t, "llama2", provider.GetModel().Name)
}

func TestOlamaProvider_Generate(t *testing.T) {
	// Create mock OLAMA server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			response := OlamaModelInfo{
				Name:   "llama2",
				Size:   3800000000,
				Digest: "abc123def456",
				Details: OlamaModelDetails{
					Format:            "gguf",
					Family:            "llama",
					ParameterSize:     "7B",
					QuantizationLevel: "Q4_0",
				},
				ModifiedAt: time.Now(),
			}
			json.NewEncoder(w).Encode(response)
		case "/api/chat":
			response := OlamaResponse{
				Model:     "llama2",
				CreatedAt: time.Now(),
				Message: OlamaMessage{
					Role:    "assistant",
					Content: "Hello! How can I help you today?",
				},
				Done:               true,
				TotalDuration:      1000000000, // 1 second in nanoseconds
				LoadDuration:       100000000,  // 100ms
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

	config := ProviderConfig{
		Type:    ProviderOlama,
		Name:    "test-olama",
		BaseURL: server.URL,
		Model:   "llama2",
		Enabled: true,
		Limits:  DefaultLimits,
	}

	provider, err := NewOlamaProvider(config)
	require.NoError(t, err)

	request := GenerationRequest{
		Messages: []Message{
			{
				Role:    RoleUser,
				Content: "Hello, how are you?",
			},
		},
		Model:       "llama2",
		Temperature: 0.7,
		MaxTokens:   100,
	}

	ctx := context.Background()
	response, err := provider.Generate(ctx, request)
	require.NoError(t, err)

	assert.Equal(t, "Hello! How can I help you today?", response.Content)
	assert.Equal(t, "llama2", response.Model)
	assert.Equal(t, FinishReasonStop, response.FinishReason)
	assert.Equal(t, 10, response.TokensUsed.PromptTokens)
	assert.Equal(t, 15, response.TokensUsed.CompletionTokens)
	assert.Equal(t, 25, response.TokensUsed.TotalTokens)
}

func TestOlamaProvider_Stream(t *testing.T) {
	// Create mock OLAMA server for streaming
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			response := OlamaModelInfo{
				Name:   "llama2",
				Digest: "abc123def456",
				ModifiedAt: time.Now(),
			}
			json.NewEncoder(w).Encode(response)
		case "/api/chat":
			// Simulate streaming response
			encoder := json.NewEncoder(w)
			
			// First chunk
			chunk1 := OlamaResponse{
				Model:     "llama2",
				CreatedAt: time.Now(),
				Message: OlamaMessage{
					Role:    "assistant",
					Content: "Hello",
				},
				Done:      false,
				EvalCount: 1,
			}
			encoder.Encode(chunk1)

			// Second chunk
			chunk2 := OlamaResponse{
				Model:     "llama2",
				CreatedAt: time.Now(),
				Message: OlamaMessage{
					Role:    "assistant",
					Content: " there!",
				},
				Done:      true,
				EvalCount: 2,
			}
			encoder.Encode(chunk2)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := ProviderConfig{
		Type:    ProviderOlama,
		Name:    "test-olama",
		BaseURL: server.URL,
		Model:   "llama2",
		Enabled: true,
		Limits:  DefaultLimits,
	}

	provider, err := NewOlamaProvider(config)
	require.NoError(t, err)

	request := GenerationRequest{
		Messages: []Message{
			{
				Role:    RoleUser,
				Content: "Hello",
			},
		},
		Model:  "llama2",
		Stream: true,
	}

	ctx := context.Background()
	chunks, err := provider.Stream(ctx, request)
	require.NoError(t, err)

	var receivedChunks []StreamChunk
	for chunk := range chunks {
		if chunk.Error != nil {
			t.Fatalf("Received error in stream: %v", chunk.Error)
		}
		receivedChunks = append(receivedChunks, chunk)
	}

	assert.Len(t, receivedChunks, 2)
	assert.Equal(t, "Hello", receivedChunks[0].Content)
	assert.Equal(t, " there!", receivedChunks[1].Content)
	assert.Equal(t, FinishReasonStop, receivedChunks[1].FinishReason)
}

func TestOlamaProvider_Embed(t *testing.T) {
	// Create mock OLAMA server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			response := OlamaModelInfo{
				Name:   "llama2",
				Digest: "abc123def456",
				ModifiedAt: time.Now(),
			}
			json.NewEncoder(w).Encode(response)
		case "/api/embeddings":
			response := struct {
				Embedding []float64 `json:"embedding"`
			}{
				Embedding: []float64{0.1, 0.2, 0.3, 0.4, 0.5},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := ProviderConfig{
		Type:    ProviderOlama,
		Name:    "test-olama",
		BaseURL: server.URL,
		Model:   "llama2",
		Enabled: true,
		Limits:  DefaultLimits,
	}

	provider, err := NewOlamaProvider(config)
	require.NoError(t, err)

	ctx := context.Background()
	embedding, err := provider.Embed(ctx, "test text")
	require.NoError(t, err)

	expected := []float64{0.1, 0.2, 0.3, 0.4, 0.5}
	assert.Equal(t, expected, embedding)
}

func TestOlamaProvider_Health(t *testing.T) {
	// Create mock OLAMA server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			response := OlamaModelInfo{
				Name:   "llama2",
				Digest: "abc123def456",
				ModifiedAt: time.Now(),
			}
			json.NewEncoder(w).Encode(response)
		case "/api/tags":
			response := struct {
				Models []OlamaModelInfo `json:"models"`
			}{
				Models: []OlamaModelInfo{
					{Name: "llama2"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := ProviderConfig{
		Type:    ProviderOlama,
		Name:    "test-olama",
		BaseURL: server.URL,
		Model:   "llama2",
		Enabled: true,
		Limits:  DefaultLimits,
	}

	provider, err := NewOlamaProvider(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = provider.Health(ctx)
	assert.NoError(t, err)
}

func TestOlamaProvider_ListModels(t *testing.T) {
	// Create mock OLAMA server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			response := OlamaModelInfo{
				Name:   "llama2",
				Digest: "abc123def456",
				ModifiedAt: time.Now(),
			}
			json.NewEncoder(w).Encode(response)
		case "/api/tags":
			response := struct {
				Models []OlamaModelInfo `json:"models"`
			}{
				Models: []OlamaModelInfo{
					{Name: "llama2"},
					{Name: "codellama"},
					{Name: "mistral"},
				},
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := ProviderConfig{
		Type:    ProviderOlama,
		Name:    "test-olama",
		BaseURL: server.URL,
		Model:   "llama2",
		Enabled: true,
		Limits:  DefaultLimits,
	}

	provider, err := NewOlamaProvider(config)
	require.NoError(t, err)

	ctx := context.Background()
	models, err := provider.ListModels(ctx)
	require.NoError(t, err)

	expected := []string{"llama2", "codellama", "mistral"}
	assert.Equal(t, expected, models)
}
