package retrieval

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/llm/vectordb"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// VectorStrategy implements vector-only retrieval
type VectorStrategy struct {
	vectorDB *vectordb.VectorDBManager
	embedder providers.LLMProvider
	logger   *logger.Logger
}

// NewVectorStrategy creates a new vector strategy
func NewVectorStrategy(vectorDB *vectordb.VectorDBManager, embedder providers.LLMProvider, logger *logger.Logger) *VectorStrategy {
	return &VectorStrategy{
		vectorDB: vectorDB,
		embedder: embedder,
		logger:   logger,
	}
}

// Name returns the strategy name
func (vs *VectorStrategy) Name() string {
	return "vector"
}

// CanHandle checks if the strategy can handle the query
func (vs *VectorStrategy) CanHandle(query RetrievalQuery) bool {
	return query.Text != "" || len(query.Vector) > 0
}

// Retrieve performs vector-only retrieval
func (vs *VectorStrategy) Retrieve(ctx context.Context, query RetrievalQuery) (*RetrievalResult, error) {
	startTime := time.Now()

	// Generate vector if not provided
	var vector []float64
	var err error
	if len(query.Vector) > 0 {
		vector = query.Vector
	} else if query.Text != "" {
		vector, err = vs.embedder.Embed(ctx, query.Text)
		if err != nil {
			return nil, fmt.Errorf("failed to generate embedding: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no text or vector provided")
	}

	searchQuery := vectordb.SearchQuery{
		Vector:         vector,
		Content:        query.Text,
		Limit:          query.MaxResults,
		Threshold:      query.MinScore,
		Filter:         query.Filters,
		IncludeContent: true,
		IncludeVector:  false,
	}

	result, err := vs.vectorDB.Search(ctx, searchQuery)
	if err != nil {
		return nil, fmt.Errorf("vector search failed: %w", err)
	}

	documents := make([]ScoredDocument, len(result.Documents))
	for i, doc := range result.Documents {
		documents[i] = ScoredDocument{
			Document:    doc.Document,
			VectorScore: doc.Score,
			FinalScore:  doc.Score,
			Rank:        i + 1,
		}
	}

	return &RetrievalResult{
		Documents:  documents,
		TotalFound: len(documents),
		SearchTime: time.Since(startTime),
		Strategy:   "vector",
		Timestamp:  time.Now(),
	}, nil
}

// KeywordStrategy implements keyword-based retrieval
type KeywordStrategy struct {
	vectorDB *vectordb.VectorDBManager
	logger   *logger.Logger
}

// NewKeywordStrategy creates a new keyword strategy
func NewKeywordStrategy(vectorDB *vectordb.VectorDBManager, logger *logger.Logger) *KeywordStrategy {
	return &KeywordStrategy{
		vectorDB: vectorDB,
		logger:   logger,
	}
}

// Name returns the strategy name
func (ks *KeywordStrategy) Name() string {
	return "keyword"
}

// CanHandle checks if the strategy can handle the query
func (ks *KeywordStrategy) CanHandle(query RetrievalQuery) bool {
	return len(query.Keywords) > 0 || query.Text != ""
}

// Retrieve performs keyword-based retrieval
func (ks *KeywordStrategy) Retrieve(ctx context.Context, query RetrievalQuery) (*RetrievalResult, error) {
	startTime := time.Now()

	// For now, this is a simplified implementation
	// In a real system, you would use a proper text search engine
	
	// Extract keywords from text if not provided
	keywords := query.Keywords
	if len(keywords) == 0 && query.Text != "" {
		keywords = extractKeywords(query.Text)
	}

	if len(keywords) == 0 {
		return nil, fmt.Errorf("no keywords available for search")
	}

	// This is a placeholder implementation
	// In practice, you would implement proper keyword search
	documents := []ScoredDocument{}

	return &RetrievalResult{
		Documents:  documents,
		TotalFound: len(documents),
		SearchTime: time.Since(startTime),
		Strategy:   "keyword",
		Timestamp:  time.Now(),
	}, nil
}

// FuzzyStrategy implements fuzzy/approximate retrieval
type FuzzyStrategy struct {
	vectorDB *vectordb.VectorDBManager
	logger   *logger.Logger
}

// NewFuzzyStrategy creates a new fuzzy strategy
func NewFuzzyStrategy(vectorDB *vectordb.VectorDBManager, logger *logger.Logger) *FuzzyStrategy {
	return &FuzzyStrategy{
		vectorDB: vectorDB,
		logger:   logger,
	}
}

// Name returns the strategy name
func (fs *FuzzyStrategy) Name() string {
	return "fuzzy"
}

// CanHandle checks if the strategy can handle the query
func (fs *FuzzyStrategy) CanHandle(query RetrievalQuery) bool {
	return query.Text != ""
}

// Retrieve performs fuzzy retrieval
func (fs *FuzzyStrategy) Retrieve(ctx context.Context, query RetrievalQuery) (*RetrievalResult, error) {
	startTime := time.Now()

	// This is a simplified fuzzy search implementation
	// In practice, you would use proper fuzzy matching algorithms
	
	documents := []ScoredDocument{}

	return &RetrievalResult{
		Documents:  documents,
		TotalFound: len(documents),
		SearchTime: time.Since(startTime),
		Strategy:   "fuzzy",
		Timestamp:  time.Now(),
	}, nil
}

// SimpleReranker implements basic re-ranking
type SimpleReranker struct {
	logger *logger.Logger
}

// NewSimpleReranker creates a new simple reranker
func NewSimpleReranker(logger *logger.Logger) *SimpleReranker {
	return &SimpleReranker{
		logger: logger,
	}
}

// Rerank re-ranks documents based on query relevance
func (sr *SimpleReranker) Rerank(ctx context.Context, query string, documents []ScoredDocument) ([]ScoredDocument, error) {
	if len(documents) <= 1 {
		return documents, nil
	}

	// Simple re-ranking based on content relevance
	queryWords := strings.Fields(strings.ToLower(query))
	
	for i := range documents {
		contentWords := strings.Fields(strings.ToLower(documents[i].Content))
		relevanceScore := calculateRelevanceScore(queryWords, contentWords)
		
		// Combine with existing score
		documents[i].SemanticScore = relevanceScore
		documents[i].FinalScore = (documents[i].FinalScore + relevanceScore) / 2.0
	}

	// Re-sort by final score
	for i := 0; i < len(documents)-1; i++ {
		for j := i + 1; j < len(documents); j++ {
			if documents[j].FinalScore > documents[i].FinalScore {
				documents[i], documents[j] = documents[j], documents[i]
			}
		}
	}

	// Update ranks
	for i := range documents {
		documents[i].Rank = i + 1
	}

	return documents, nil
}

// extractKeywords extracts keywords from text (simplified)
func extractKeywords(text string) []string {
	// Simple keyword extraction - split by spaces and filter
	words := strings.Fields(strings.ToLower(text))
	
	// Filter out common stop words
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"but": true, "in": true, "on": true, "at": true, "to": true,
		"for": true, "of": true, "with": true, "by": true, "is": true,
		"are": true, "was": true, "were": true, "be": true, "been": true,
		"have": true, "has": true, "had": true, "do": true, "does": true,
		"did": true, "will": true, "would": true, "could": true, "should": true,
	}
	
	var keywords []string
	for _, word := range words {
		// Remove punctuation and check length
		word = strings.Trim(word, ".,!?;:")
		if len(word) > 2 && !stopWords[word] {
			keywords = append(keywords, word)
		}
	}
	
	return keywords
}

// calculateRelevanceScore calculates relevance between query and content words
func calculateRelevanceScore(queryWords, contentWords []string) float64 {
	if len(queryWords) == 0 || len(contentWords) == 0 {
		return 0.0
	}

	contentWordSet := make(map[string]bool)
	for _, word := range contentWords {
		contentWordSet[word] = true
	}

	matches := 0
	for _, queryWord := range queryWords {
		if contentWordSet[queryWord] {
			matches++
		}
	}

	return float64(matches) / float64(len(queryWords))
}
