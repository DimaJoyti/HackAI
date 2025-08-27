package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var supabaseTracer = otel.Tracer("hackai/llm/providers/supabase")

// SupabaseProvider implements LLMProvider for Supabase vector operations
type SupabaseProvider struct {
	config     SupabaseConfig
	httpClient *http.Client
	logger     *logger.Logger
}

// SupabaseConfig configures the Supabase provider
type SupabaseConfig struct {
	URL       string `json:"url"`
	APIKey    string `json:"api_key"`
	Table     string `json:"table"`
	Timeout   time.Duration `json:"timeout"`
	MaxRetries int `json:"max_retries"`
}

// SupabaseDocument represents a document in Supabase
type SupabaseDocument struct {
	ID        string                 `json:"id"`
	Content   string                 `json:"content"`
	Embedding []float64              `json:"embedding"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// SupabaseSearchRequest represents a vector search request
type SupabaseSearchRequest struct {
	QueryEmbedding []float64 `json:"query_embedding"`
	MatchThreshold float64   `json:"match_threshold"`
	MatchCount     int       `json:"match_count"`
	Filter         map[string]interface{} `json:"filter,omitempty"`
}

// SupabaseSearchResponse represents the search response
type SupabaseSearchResponse struct {
	Documents []SupabaseDocument `json:"documents"`
	Count     int                `json:"count"`
}

// NewSupabaseProvider creates a new Supabase provider
func NewSupabaseProvider(config SupabaseConfig, logger *logger.Logger) *SupabaseProvider {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.Table == "" {
		config.Table = "documents"
	}

	return &SupabaseProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		logger: logger,
	}
}

// Generate implements LLMProvider interface for text generation
func (sp *SupabaseProvider) Generate(ctx context.Context, request GenerationRequest) (GenerationResponse, error) {
	ctx, span := supabaseTracer.Start(ctx, "supabase_provider.generate")
	defer span.End()

	// Supabase is primarily for vector operations, not text generation
	// This could be extended to use Supabase Edge Functions for LLM calls
	return GenerationResponse{}, fmt.Errorf("text generation not supported by Supabase provider")
}

// Stream implements LLMProvider interface for streaming
func (sp *SupabaseProvider) Stream(ctx context.Context, request GenerationRequest) (<-chan StreamChunk, error) {
	return nil, fmt.Errorf("streaming not supported by Supabase provider")
}

// Embed generates embeddings using Supabase Edge Functions
func (sp *SupabaseProvider) Embed(ctx context.Context, text string) ([]float64, error) {
	ctx, span := supabaseTracer.Start(ctx, "supabase_provider.embed",
		trace.WithAttributes(
			attribute.Int("text_length", len(text)),
		),
	)
	defer span.End()

	// Call Supabase Edge Function for embedding generation
	embedRequest := map[string]interface{}{
		"input": text,
	}

	embedData, err := json.Marshal(embedRequest)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to marshal embed request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", 
		fmt.Sprintf("%s/functions/v1/embed", sp.config.URL), 
		strings.NewReader(string(embedData)))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create embed request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sp.config.APIKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := sp.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to call embed function: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embed function returned status %d", resp.StatusCode)
	}

	var embedResponse struct {
		Embedding []float64 `json:"embedding"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&embedResponse); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decode embed response: %w", err)
	}

	span.SetAttributes(
		attribute.Int("embedding_dimensions", len(embedResponse.Embedding)),
	)

	return embedResponse.Embedding, nil
}

// EmbedBatch generates embeddings for multiple texts
func (sp *SupabaseProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	ctx, span := supabaseTracer.Start(ctx, "supabase_provider.embed_batch",
		trace.WithAttributes(
			attribute.Int("batch_size", len(texts)),
		),
	)
	defer span.End()

	embeddings := make([][]float64, len(texts))
	for i, text := range texts {
		embedding, err := sp.Embed(ctx, text)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("failed to embed text %d: %w", i, err)
		}
		embeddings[i] = embedding
	}

	return embeddings, nil
}

// StoreDocument stores a document with its embedding in Supabase
func (sp *SupabaseProvider) StoreDocument(ctx context.Context, doc SupabaseDocument) error {
	ctx, span := supabaseTracer.Start(ctx, "supabase_provider.store_document",
		trace.WithAttributes(
			attribute.String("document_id", doc.ID),
			attribute.Int("content_length", len(doc.Content)),
		),
	)
	defer span.End()

	docData, err := json.Marshal(doc)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/rest/v1/%s", sp.config.URL, sp.config.Table),
		strings.NewReader(string(docData)))
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create store request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sp.config.APIKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=minimal")

	resp, err := sp.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to store document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("store document returned status %d", resp.StatusCode)
	}

	sp.logger.Info("Document stored successfully", "document_id", doc.ID)
	return nil
}

// SearchSimilar performs vector similarity search
func (sp *SupabaseProvider) SearchSimilar(ctx context.Context, searchReq SupabaseSearchRequest) (*SupabaseSearchResponse, error) {
	ctx, span := supabaseTracer.Start(ctx, "supabase_provider.search_similar",
		trace.WithAttributes(
			attribute.Float64("match_threshold", searchReq.MatchThreshold),
			attribute.Int("match_count", searchReq.MatchCount),
		),
	)
	defer span.End()

	// Call Supabase RPC function for vector similarity search
	rpcRequest := map[string]interface{}{
		"query_embedding":  searchReq.QueryEmbedding,
		"match_threshold":  searchReq.MatchThreshold,
		"match_count":      searchReq.MatchCount,
	}

	if searchReq.Filter != nil {
		rpcRequest["filter"] = searchReq.Filter
	}

	rpcData, err := json.Marshal(rpcRequest)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to marshal search request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/rest/v1/rpc/match_documents", sp.config.URL),
		strings.NewReader(string(rpcData)))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create search request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sp.config.APIKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := sp.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to search documents: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search returned status %d", resp.StatusCode)
	}

	var documents []SupabaseDocument
	if err := json.NewDecoder(resp.Body).Decode(&documents); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decode search response: %w", err)
	}

	span.SetAttributes(
		attribute.Int("results_count", len(documents)),
	)

	return &SupabaseSearchResponse{
		Documents: documents,
		Count:     len(documents),
	}, nil
}

// GetModel returns model information
func (sp *SupabaseProvider) GetModel() ModelInfo {
	return ModelInfo{
		Name:         "supabase-vector",
		Provider:     "supabase",
		MaxTokens:    0, // Not applicable for vector operations
		ContextSize:  0, // Not applicable for vector operations
		Capabilities: []string{"vector_search", "document_storage", "embedding"},
	}
}

// GetLimits returns provider limits
func (sp *SupabaseProvider) GetLimits() ProviderLimits {
	return ProviderLimits{
		RequestsPerMinute: 1000, // Adjust based on Supabase plan
		TokensPerMinute:   0,    // Not applicable
		MaxConcurrent:     10,
		MaxRetries:        sp.config.MaxRetries,
	}
}

// GetType returns the provider type
func (sp *SupabaseProvider) GetType() ProviderType {
	return ProviderType("supabase")
}

// Health checks the provider health
func (sp *SupabaseProvider) Health(ctx context.Context) error {
	ctx, span := supabaseTracer.Start(ctx, "supabase_provider.health")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/rest/v1/%s?limit=1", sp.config.URL, sp.config.Table),
		nil)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sp.config.APIKey))

	resp, err := sp.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	return nil
}

// Close closes the provider
func (sp *SupabaseProvider) Close() error {
	// Nothing to close for HTTP client
	return nil
}
