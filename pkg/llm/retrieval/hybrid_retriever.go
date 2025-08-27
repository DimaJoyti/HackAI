package retrieval

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/llm/vectordb"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var retrievalTracer = otel.Tracer("hackai/llm/retrieval")

// HybridRetriever combines vector similarity search with keyword search and re-ranking
type HybridRetriever struct {
	vectorDB      *vectordb.VectorDBManager
	embedder      providers.LLMProvider
	reranker      Reranker
	config        RetrieverConfig
	logger        *logger.Logger
	fallbackChain []RetrievalStrategy
}

// RetrieverConfig configures the hybrid retriever
type RetrieverConfig struct {
	VectorWeight     float64       `json:"vector_weight"`
	KeywordWeight    float64       `json:"keyword_weight"`
	SemanticWeight   float64       `json:"semantic_weight"`
	MaxResults       int           `json:"max_results"`
	MinScore         float64       `json:"min_score"`
	EnableReranking  bool          `json:"enable_reranking"`
	EnableFallback   bool          `json:"enable_fallback"`
	ContextWindow    int           `json:"context_window"`
	DiversityFactor  float64       `json:"diversity_factor"`
	FreshnessWeight  float64       `json:"freshness_weight"`
	AuthorityWeight  float64       `json:"authority_weight"`
	RetrievalTimeout time.Duration `json:"retrieval_timeout"`
}

// RetrievalQuery represents a search query
type RetrievalQuery struct {
	Text            string                 `json:"text"`
	Vector          []float64              `json:"vector,omitempty"`
	Keywords        []string               `json:"keywords,omitempty"`
	Filters         map[string]interface{} `json:"filters,omitempty"`
	MaxResults      int                    `json:"max_results,omitempty"`
	MinScore        float64                `json:"min_score,omitempty"`
	IncludeMetadata bool                   `json:"include_metadata"`
	Strategy        string                 `json:"strategy,omitempty"`
	Context         map[string]interface{} `json:"context,omitempty"`
}

// RetrievalResult represents search results
type RetrievalResult struct {
	Documents  []ScoredDocument       `json:"documents"`
	TotalFound int                    `json:"total_found"`
	SearchTime time.Duration          `json:"search_time"`
	Strategy   string                 `json:"strategy"`
	Scores     map[string]float64     `json:"scores"`
	Metadata   map[string]interface{} `json:"metadata"`
	QueryID    string                 `json:"query_id"`
	Timestamp  time.Time              `json:"timestamp"`
}

// ScoredDocument represents a document with multiple scores
type ScoredDocument struct {
	vectordb.Document
	VectorScore   float64                `json:"vector_score"`
	KeywordScore  float64                `json:"keyword_score"`
	SemanticScore float64                `json:"semantic_score"`
	FinalScore    float64                `json:"final_score"`
	Rank          int                    `json:"rank"`
	Explanation   map[string]interface{} `json:"explanation,omitempty"`
}

// RetrievalStrategy defines different retrieval approaches
type RetrievalStrategy interface {
	Name() string
	Retrieve(ctx context.Context, query RetrievalQuery) (*RetrievalResult, error)
	CanHandle(query RetrievalQuery) bool
}

// Reranker interface for result re-ranking
type Reranker interface {
	Rerank(ctx context.Context, query string, documents []ScoredDocument) ([]ScoredDocument, error)
}

// NewHybridRetriever creates a new hybrid retriever
func NewHybridRetriever(
	vectorDB *vectordb.VectorDBManager,
	embedder providers.LLMProvider,
	config RetrieverConfig,
	logger *logger.Logger,
) *HybridRetriever {
	// Set defaults
	if config.VectorWeight == 0 {
		config.VectorWeight = 0.7
	}
	if config.KeywordWeight == 0 {
		config.KeywordWeight = 0.2
	}
	if config.SemanticWeight == 0 {
		config.SemanticWeight = 0.1
	}
	if config.MaxResults == 0 {
		config.MaxResults = 10
	}
	if config.MinScore == 0 {
		config.MinScore = 0.1
	}
	if config.ContextWindow == 0 {
		config.ContextWindow = 3
	}
	if config.DiversityFactor == 0 {
		config.DiversityFactor = 0.3
	}
	if config.RetrievalTimeout == 0 {
		config.RetrievalTimeout = 30 * time.Second
	}

	retriever := &HybridRetriever{
		vectorDB: vectorDB,
		embedder: embedder,
		reranker: NewSimpleReranker(logger),
		config:   config,
		logger:   logger,
	}

	// Initialize fallback strategies
	if config.EnableFallback {
		retriever.fallbackChain = []RetrievalStrategy{
			NewVectorStrategy(vectorDB, embedder, logger),
			NewKeywordStrategy(vectorDB, logger),
			NewFuzzyStrategy(vectorDB, logger),
		}
	}

	return retriever
}

// Retrieve performs hybrid retrieval combining multiple strategies
func (hr *HybridRetriever) Retrieve(ctx context.Context, query RetrievalQuery) (*RetrievalResult, error) {
	ctx, span := retrievalTracer.Start(ctx, "hybrid_retriever.retrieve",
		trace.WithAttributes(
			attribute.String("query_text", query.Text),
			attribute.Int("max_results", query.MaxResults),
		),
	)
	defer span.End()

	startTime := time.Now()
	queryID := fmt.Sprintf("query_%d", time.Now().UnixNano())

	// Set defaults from config
	if query.MaxResults == 0 {
		query.MaxResults = hr.config.MaxResults
	}
	if query.MinScore == 0 {
		query.MinScore = hr.config.MinScore
	}

	// Generate query vector if not provided
	if len(query.Vector) == 0 && query.Text != "" {
		vector, err := hr.embedder.Embed(ctx, query.Text)
		if err != nil {
			span.RecordError(err)
			return hr.fallbackRetrieve(ctx, query, queryID, startTime)
		}
		query.Vector = vector
	}

	// Perform vector similarity search
	vectorResults, err := hr.vectorSearch(ctx, query)
	if err != nil {
		span.RecordError(err)
		hr.logger.Warn("Vector search failed, trying fallback", "error", err)
		return hr.fallbackRetrieve(ctx, query, queryID, startTime)
	}

	// Perform keyword search if keywords provided
	var keywordResults []ScoredDocument
	if len(query.Keywords) > 0 {
		keywordResults, err = hr.keywordSearch(ctx, query)
		if err != nil {
			hr.logger.Warn("Keyword search failed", "error", err)
		}
	}

	// Combine and score results
	combinedResults := hr.combineResults(vectorResults, keywordResults)

	// Apply diversity filtering
	if hr.config.DiversityFactor > 0 {
		combinedResults = hr.applyDiversityFiltering(combinedResults)
	}

	// Re-rank results if enabled
	if hr.config.EnableReranking && hr.reranker != nil {
		rerankedResults, err := hr.reranker.Rerank(ctx, query.Text, combinedResults)
		if err != nil {
			hr.logger.Warn("Re-ranking failed", "error", err)
		} else {
			combinedResults = rerankedResults
		}
	}

	// Limit results
	if len(combinedResults) > query.MaxResults {
		combinedResults = combinedResults[:query.MaxResults]
	}

	// Update ranks
	for i := range combinedResults {
		combinedResults[i].Rank = i + 1
	}

	result := &RetrievalResult{
		Documents:  combinedResults,
		TotalFound: len(combinedResults),
		SearchTime: time.Since(startTime),
		Strategy:   "hybrid",
		Scores: map[string]float64{
			"vector_weight":   hr.config.VectorWeight,
			"keyword_weight":  hr.config.KeywordWeight,
			"semantic_weight": hr.config.SemanticWeight,
		},
		QueryID:   queryID,
		Timestamp: time.Now(),
	}

	span.SetAttributes(
		attribute.Int("results_count", len(combinedResults)),
		attribute.String("strategy", "hybrid"),
		attribute.Float64("search_time_ms", float64(result.SearchTime.Milliseconds())),
	)

	return result, nil
}

// vectorSearch performs vector similarity search
func (hr *HybridRetriever) vectorSearch(ctx context.Context, query RetrievalQuery) ([]ScoredDocument, error) {
	searchQuery := vectordb.SearchQuery{
		Vector:         query.Vector,
		Content:        query.Text,
		Limit:          query.MaxResults * 2, // Get more for diversity
		Threshold:      query.MinScore,
		Filter:         query.Filters,
		IncludeContent: true,
		IncludeVector:  false,
	}

	result, err := hr.vectorDB.Search(ctx, searchQuery)
	if err != nil {
		return nil, fmt.Errorf("vector search failed: %w", err)
	}

	scoredDocs := make([]ScoredDocument, len(result.Documents))
	for i, doc := range result.Documents {
		scoredDocs[i] = ScoredDocument{
			Document:    doc.Document,
			VectorScore: doc.Score,
			FinalScore:  doc.Score * hr.config.VectorWeight,
		}
	}

	return scoredDocs, nil
}

// keywordSearch performs keyword-based search
func (hr *HybridRetriever) keywordSearch(ctx context.Context, query RetrievalQuery) ([]ScoredDocument, error) {
	// This is a simplified keyword search implementation
	// In a real system, you might use Elasticsearch, Solr, or similar

	var results []ScoredDocument

	// For now, we'll use vector search with keyword-enhanced queries
	keywordQuery := fmt.Sprintf("%s %s", query.Text, joinKeywords(query.Keywords))

	vector, err := hr.embedder.Embed(ctx, keywordQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to embed keyword query: %w", err)
	}

	searchQuery := vectordb.SearchQuery{
		Vector:         vector,
		Content:        keywordQuery,
		Limit:          query.MaxResults,
		Threshold:      query.MinScore * 0.8, // Lower threshold for keyword search
		Filter:         query.Filters,
		IncludeContent: true,
		IncludeVector:  false,
	}

	result, err := hr.vectorDB.Search(ctx, searchQuery)
	if err != nil {
		return nil, fmt.Errorf("keyword search failed: %w", err)
	}

	for _, doc := range result.Documents {
		keywordScore := hr.calculateKeywordScore(doc.Content, query.Keywords)
		results = append(results, ScoredDocument{
			Document:     doc.Document,
			KeywordScore: keywordScore,
			FinalScore:   keywordScore * hr.config.KeywordWeight,
		})
	}

	return results, nil
}

// combineResults merges vector and keyword search results
func (hr *HybridRetriever) combineResults(vectorResults, keywordResults []ScoredDocument) []ScoredDocument {
	docMap := make(map[string]*ScoredDocument)

	// Add vector results
	for _, doc := range vectorResults {
		docMap[doc.ID] = &ScoredDocument{
			Document:      doc.Document,
			VectorScore:   doc.VectorScore,
			KeywordScore:  0,
			SemanticScore: 0,
			FinalScore:    doc.VectorScore * hr.config.VectorWeight,
		}
	}

	// Merge keyword results
	for _, doc := range keywordResults {
		if existing, exists := docMap[doc.ID]; exists {
			existing.KeywordScore = doc.KeywordScore
			existing.FinalScore += doc.KeywordScore * hr.config.KeywordWeight
		} else {
			docMap[doc.ID] = &ScoredDocument{
				Document:      doc.Document,
				VectorScore:   0,
				KeywordScore:  doc.KeywordScore,
				SemanticScore: 0,
				FinalScore:    doc.KeywordScore * hr.config.KeywordWeight,
			}
		}
	}

	// Convert to slice and sort by final score
	var results []ScoredDocument
	for _, doc := range docMap {
		if doc.FinalScore >= hr.config.MinScore {
			results = append(results, *doc)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].FinalScore > results[j].FinalScore
	})

	return results
}

// calculateKeywordScore calculates keyword relevance score
func (hr *HybridRetriever) calculateKeywordScore(content string, keywords []string) float64 {
	if len(keywords) == 0 {
		return 0
	}

	contentLower := strings.ToLower(content)
	score := 0.0

	for _, keyword := range keywords {
		keywordLower := strings.ToLower(keyword)
		count := strings.Count(contentLower, keywordLower)
		if count > 0 {
			// TF-IDF-like scoring
			tf := float64(count) / float64(len(strings.Fields(content)))
			score += tf * math.Log(1.0+1.0/float64(len(keywords)))
		}
	}

	return math.Min(score, 1.0)
}

// applyDiversityFiltering applies diversity filtering to results
func (hr *HybridRetriever) applyDiversityFiltering(results []ScoredDocument) []ScoredDocument {
	if len(results) <= 1 {
		return results
	}

	var filtered []ScoredDocument
	filtered = append(filtered, results[0]) // Always include top result

	for _, candidate := range results[1:] {
		isDiverse := true
		for _, selected := range filtered {
			similarity := hr.calculateContentSimilarity(candidate.Content, selected.Content)
			if similarity > (1.0 - hr.config.DiversityFactor) {
				isDiverse = false
				break
			}
		}
		if isDiverse {
			filtered = append(filtered, candidate)
		}
	}

	return filtered
}

// calculateContentSimilarity calculates content similarity (simplified)
func (hr *HybridRetriever) calculateContentSimilarity(content1, content2 string) float64 {
	// Simplified Jaccard similarity
	words1 := strings.Fields(strings.ToLower(content1))
	words2 := strings.Fields(strings.ToLower(content2))

	set1 := make(map[string]bool)
	set2 := make(map[string]bool)

	for _, word := range words1 {
		set1[word] = true
	}
	for _, word := range words2 {
		set2[word] = true
	}

	intersection := 0
	for word := range set1 {
		if set2[word] {
			intersection++
		}
	}

	union := len(set1) + len(set2) - intersection
	if union == 0 {
		return 0
	}

	return float64(intersection) / float64(union)
}

// fallbackRetrieve attempts retrieval using fallback strategies
func (hr *HybridRetriever) fallbackRetrieve(ctx context.Context, query RetrievalQuery, queryID string, startTime time.Time) (*RetrievalResult, error) {
	if !hr.config.EnableFallback {
		return nil, fmt.Errorf("primary retrieval failed and fallback disabled")
	}

	for _, strategy := range hr.fallbackChain {
		if strategy.CanHandle(query) {
			result, err := strategy.Retrieve(ctx, query)
			if err == nil {
				result.Strategy = fmt.Sprintf("fallback_%s", strategy.Name())
				result.QueryID = queryID
				result.SearchTime = time.Since(startTime)
				hr.logger.Info("Fallback strategy succeeded", "strategy", strategy.Name())
				return result, nil
			}
			hr.logger.Warn("Fallback strategy failed", "strategy", strategy.Name(), "error", err)
		}
	}

	return nil, fmt.Errorf("all retrieval strategies failed")
}

// joinKeywords joins keywords into a single string
func joinKeywords(keywords []string) string {
	return strings.Join(keywords, " ")
}
