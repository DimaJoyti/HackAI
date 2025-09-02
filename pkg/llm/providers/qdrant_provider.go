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

var qdrantTracer = otel.Tracer("hackai/llm/providers/qdrant")

// QdrantProvider implements LLMProvider for Qdrant vector operations
type QdrantProvider struct {
	config     QdrantConfig
	httpClient *http.Client
	logger     *logger.Logger
}

// QdrantConfig configures the Qdrant provider
type QdrantConfig struct {
	URL        string        `json:"url"`
	APIKey     string        `json:"api_key,omitempty"`
	Collection string        `json:"collection"`
	Timeout    time.Duration `json:"timeout"`
	MaxRetries int           `json:"max_retries"`
}

// QdrantPoint represents a point in Qdrant
type QdrantPoint struct {
	ID      interface{}            `json:"id"`
	Vector  []float64              `json:"vector"`
	Payload map[string]interface{} `json:"payload"`
}

// QdrantSearchRequest represents a search request
type QdrantSearchRequest struct {
	Vector         []float64              `json:"vector"`
	Limit          int                    `json:"limit"`
	ScoreThreshold *float64               `json:"score_threshold,omitempty"`
	Filter         map[string]interface{} `json:"filter,omitempty"`
	WithPayload    bool                   `json:"with_payload"`
	WithVector     bool                   `json:"with_vector"`
}

// QdrantSearchResponse represents the search response
type QdrantSearchResponse struct {
	Result []QdrantSearchResult `json:"result"`
	Status string               `json:"status"`
	Time   float64              `json:"time"`
}

// QdrantSearchResult represents a single search result
type QdrantSearchResult struct {
	ID      interface{}            `json:"id"`
	Version int                    `json:"version"`
	Score   float64                `json:"score"`
	Payload map[string]interface{} `json:"payload,omitempty"`
	Vector  []float64              `json:"vector,omitempty"`
}

// QdrantUpsertRequest represents an upsert request
type QdrantUpsertRequest struct {
	Points []QdrantPoint `json:"points"`
}

// QdrantUpsertResponse represents the upsert response
type QdrantUpsertResponse struct {
	Result struct {
		OperationID int    `json:"operation_id"`
		Status      string `json:"status"`
	} `json:"result"`
	Status string  `json:"status"`
	Time   float64 `json:"time"`
}

// NewQdrantProvider creates a new Qdrant provider
func NewQdrantProvider(config QdrantConfig, logger *logger.Logger) *QdrantProvider {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.Collection == "" {
		config.Collection = "documents"
	}

	return &QdrantProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		logger: logger,
	}
}

// Generate implements LLMProvider interface for text generation
func (qp *QdrantProvider) Generate(ctx context.Context, request GenerationRequest) (GenerationResponse, error) {
	// Qdrant is for vector operations, not text generation
	return GenerationResponse{}, fmt.Errorf("text generation not supported by Qdrant provider")
}

// Stream implements LLMProvider interface for streaming
func (qp *QdrantProvider) Stream(ctx context.Context, request GenerationRequest) (<-chan StreamChunk, error) {
	return nil, fmt.Errorf("streaming not supported by Qdrant provider")
}

// Embed generates embeddings (delegated to another provider)
func (qp *QdrantProvider) Embed(ctx context.Context, text string) ([]float64, error) {
	return nil, fmt.Errorf("embedding generation not supported by Qdrant provider - use dedicated embedding provider")
}

// EmbedBatch generates embeddings for multiple texts
func (qp *QdrantProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	return nil, fmt.Errorf("embedding generation not supported by Qdrant provider - use dedicated embedding provider")
}

// UpsertPoints upserts points into Qdrant collection
func (qp *QdrantProvider) UpsertPoints(ctx context.Context, points []QdrantPoint) (*QdrantUpsertResponse, error) {
	ctx, span := qdrantTracer.Start(ctx, "qdrant_provider.upsert_points",
		trace.WithAttributes(
			attribute.Int("points_count", len(points)),
			attribute.String("collection", qp.config.Collection),
		),
	)
	defer span.End()

	upsertReq := QdrantUpsertRequest{
		Points: points,
	}

	reqData, err := json.Marshal(upsertReq)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to marshal upsert request: %w", err)
	}

	url := fmt.Sprintf("%s/collections/%s/points", qp.config.URL, qp.config.Collection)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, strings.NewReader(string(reqData)))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create upsert request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if qp.config.APIKey != "" {
		req.Header.Set("api-key", qp.config.APIKey)
	}

	resp, err := qp.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to upsert points: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upsert returned status %d", resp.StatusCode)
	}

	var upsertResp QdrantUpsertResponse
	if err := json.NewDecoder(resp.Body).Decode(&upsertResp); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decode upsert response: %w", err)
	}

	span.SetAttributes(
		attribute.String("operation_status", upsertResp.Result.Status),
		attribute.Int("operation_id", upsertResp.Result.OperationID),
	)

	qp.logger.Info("Points upserted successfully",
		"collection", qp.config.Collection,
		"points_count", len(points),
		"operation_id", upsertResp.Result.OperationID)

	return &upsertResp, nil
}

// SearchPoints performs vector similarity search
func (qp *QdrantProvider) SearchPoints(ctx context.Context, searchReq QdrantSearchRequest) (*QdrantSearchResponse, error) {
	ctx, span := qdrantTracer.Start(ctx, "qdrant_provider.search_points",
		trace.WithAttributes(
			attribute.String("collection", qp.config.Collection),
			attribute.Int("limit", searchReq.Limit),
			attribute.Int("vector_dimensions", len(searchReq.Vector)),
		),
	)
	defer span.End()

	reqData, err := json.Marshal(searchReq)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to marshal search request: %w", err)
	}

	url := fmt.Sprintf("%s/collections/%s/points/search", qp.config.URL, qp.config.Collection)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(reqData)))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create search request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if qp.config.APIKey != "" {
		req.Header.Set("api-key", qp.config.APIKey)
	}

	resp, err := qp.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to search points: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search returned status %d", resp.StatusCode)
	}

	var searchResp QdrantSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decode search response: %w", err)
	}

	span.SetAttributes(
		attribute.Int("results_count", len(searchResp.Result)),
		attribute.Float64("search_time", searchResp.Time),
	)

	return &searchResp, nil
}

// CreateCollection creates a new collection in Qdrant
func (qp *QdrantProvider) CreateCollection(ctx context.Context, vectorSize int, distance string) error {
	ctx, span := qdrantTracer.Start(ctx, "qdrant_provider.create_collection",
		trace.WithAttributes(
			attribute.String("collection", qp.config.Collection),
			attribute.Int("vector_size", vectorSize),
			attribute.String("distance", distance),
		),
	)
	defer span.End()

	createReq := map[string]interface{}{
		"vectors": map[string]interface{}{
			"size":     vectorSize,
			"distance": distance,
		},
	}

	reqData, err := json.Marshal(createReq)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal create collection request: %w", err)
	}

	url := fmt.Sprintf("%s/collections/%s", qp.config.URL, qp.config.Collection)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, strings.NewReader(string(reqData)))
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create collection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if qp.config.APIKey != "" {
		req.Header.Set("api-key", qp.config.APIKey)
	}

	resp, err := qp.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create collection: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		return fmt.Errorf("create collection returned status %d", resp.StatusCode)
	}

	qp.logger.Info("Collection created successfully", "collection", qp.config.Collection)
	return nil
}

// GetModel returns model information
func (qp *QdrantProvider) GetModel() ModelInfo {
	return ModelInfo{
		Name:         "qdrant-vector",
		Provider:     "qdrant",
		MaxTokens:    0, // Not applicable
		ContextSize:  0, // Not applicable
		Capabilities: []string{"vector_search", "point_storage", "filtering"},
	}
}

// GetLimits returns provider limits
func (qp *QdrantProvider) GetLimits() ProviderLimits {
	return ProviderLimits{
		RequestsPerMinute: 1000, // Adjust based on Qdrant instance
		TokensPerMinute:   0,    // Not applicable
		MaxConcurrent:     10,
		MaxRetries:        qp.config.MaxRetries,
	}
}

// GetType returns the provider type
func (qp *QdrantProvider) GetType() ProviderType {
	return ProviderType("qdrant")
}

// Health checks the provider health
func (qp *QdrantProvider) Health(ctx context.Context) error {
	ctx, span := qdrantTracer.Start(ctx, "qdrant_provider.health")
	defer span.End()

	url := fmt.Sprintf("%s/collections/%s", qp.config.URL, qp.config.Collection)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	if qp.config.APIKey != "" {
		req.Header.Set("api-key", qp.config.APIKey)
	}

	resp, err := qp.httpClient.Do(req)
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
func (qp *QdrantProvider) Close() error {
	// Nothing to close for HTTP client
	return nil
}
