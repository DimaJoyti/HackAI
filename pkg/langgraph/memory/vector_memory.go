package memory

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// VectorMemory manages vector-based memory for similarity search
type VectorMemory struct {
	vectors     map[string]*VectorEntry
	index       *VectorIndex
	embedder    VectorEmbedder
	maxSize     int
	dimensions  int
	threshold   float64
	config      *MemoryConfig
	logger      *logger.Logger
	mutex       sync.RWMutex
}

// VectorEntry represents a vector memory entry
type VectorEntry struct {
	ID          string                 `json:"id"`
	Vector      []float64              `json:"vector"`
	Content     interface{}            `json:"content"`
	Metadata    map[string]interface{} `json:"metadata"`
	Importance  float64                `json:"importance"`
	Confidence  float64                `json:"confidence"`
	Timestamp   time.Time              `json:"timestamp"`
	LastAccess  time.Time              `json:"last_access"`
	AccessCount int64                  `json:"access_count"`
	Tags        []string               `json:"tags"`
	Norm        float64                `json:"norm"`
}

// VectorIndex provides efficient vector similarity search
type VectorIndex struct {
	entries     []*VectorEntry
	clusters    map[string][]*VectorEntry
	centroids   map[string][]float64
	indexType   IndexType
	buildTime   time.Time
	mutex       sync.RWMutex
}

// VectorEmbedder interface for generating embeddings
type VectorEmbedder interface {
	Embed(ctx context.Context, content interface{}) ([]float64, error)
	GetDimensions() int
}

// SimilarityResult represents a similarity search result
type SimilarityResult struct {
	Entry      *VectorEntry `json:"entry"`
	Similarity float64      `json:"similarity"`
	Distance   float64      `json:"distance"`
}

// VectorQuery represents a vector-based query
type VectorQuery struct {
	Vector      []float64              `json:"vector"`
	Content     interface{}            `json:"content"`
	Limit       int                    `json:"limit"`
	Threshold   float64                `json:"threshold"`
	Metric      SimilarityMetric       `json:"metric"`
	Filters     map[string]interface{} `json:"filters"`
	IncludeSelf bool                   `json:"include_self"`
}

// Enums for vector memory
type IndexType string
type SimilarityMetric string

const (
	// Index Types
	IndexTypeFlat     IndexType = "flat"
	IndexTypeHNSW     IndexType = "hnsw"
	IndexTypeIVF      IndexType = "ivf"
	IndexTypeLSH      IndexType = "lsh"
	IndexTypeKMeans   IndexType = "kmeans"

	// Similarity Metrics
	MetricCosine    SimilarityMetric = "cosine"
	MetricEuclidean SimilarityMetric = "euclidean"
	MetricDotProduct SimilarityMetric = "dot_product"
	MetricManhattan SimilarityMetric = "manhattan"
)

// SimpleEmbedder provides a simple embedding implementation
type SimpleEmbedder struct {
	dimensions int
}

func NewSimpleEmbedder(dimensions int) *SimpleEmbedder {
	return &SimpleEmbedder{dimensions: dimensions}
}

func (se *SimpleEmbedder) Embed(ctx context.Context, content interface{}) ([]float64, error) {
	// Simple hash-based embedding for demo purposes
	contentStr := fmt.Sprintf("%v", content)
	vector := make([]float64, se.dimensions)
	
	// Generate pseudo-random vector based on content hash
	hash := simpleHash(contentStr)
	for i := 0; i < se.dimensions; i++ {
		vector[i] = float64((hash+uint64(i))%1000) / 1000.0 - 0.5
	}
	
	// Normalize vector
	norm := vectorNorm(vector)
	if norm > 0 {
		for i := range vector {
			vector[i] /= norm
		}
	}
	
	return vector, nil
}

func (se *SimpleEmbedder) GetDimensions() int {
	return se.dimensions
}

// NewVectorMemory creates a new vector memory instance
func NewVectorMemory(config *MemoryConfig, logger *logger.Logger) (*VectorMemory, error) {
	embedder := NewSimpleEmbedder(config.VectorDimensions)
	
	index := &VectorIndex{
		entries:   make([]*VectorEntry, 0),
		clusters:  make(map[string][]*VectorEntry),
		centroids: make(map[string][]float64),
		indexType: IndexTypeFlat,
		buildTime: time.Now(),
	}

	return &VectorMemory{
		vectors:    make(map[string]*VectorEntry),
		index:      index,
		embedder:   embedder,
		maxSize:    config.VectorMemorySize,
		dimensions: config.VectorDimensions,
		threshold:  config.SimilarityThreshold,
		config:     config,
		logger:     logger,
	}, nil
}

// Store stores a memory entry as a vector
func (vm *VectorMemory) Store(ctx context.Context, entry *MemoryEntry) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// Generate vector embedding
	vector, err := vm.embedder.Embed(ctx, entry.Content)
	if err != nil {
		return fmt.Errorf("failed to generate embedding: %w", err)
	}

	// Create vector entry
	vectorEntry := &VectorEntry{
		ID:          entry.ID,
		Vector:      vector,
		Content:     entry.Content,
		Metadata:    entry.Metadata,
		Importance:  entry.Importance,
		Confidence:  entry.Confidence,
		Timestamp:   entry.Timestamp,
		LastAccess:  entry.LastAccess,
		AccessCount: entry.AccessCount,
		Tags:        entry.Tags,
		Norm:        vectorNorm(vector),
	}

	// Check if we need to evict vectors
	if len(vm.vectors) >= vm.maxSize {
		if err := vm.evictLeastSimilar(vectorEntry); err != nil {
			return fmt.Errorf("failed to evict vectors: %w", err)
		}
	}

	// Store the vector entry
	vm.vectors[vectorEntry.ID] = vectorEntry

	// Update index
	vm.index.AddVector(vectorEntry)

	vm.logger.Debug("Vector stored in vector memory",
		"vector_id", vectorEntry.ID,
		"dimensions", len(vector),
		"norm", vectorEntry.Norm,
		"total_vectors", len(vm.vectors))

	return nil
}

// Retrieve retrieves a memory entry by ID
func (vm *VectorMemory) Retrieve(ctx context.Context, id string) (*MemoryEntry, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	vectorEntry, exists := vm.vectors[id]
	if !exists {
		return nil, fmt.Errorf("vector entry not found: %s", id)
	}

	// Update access information
	vectorEntry.LastAccess = time.Now()
	vectorEntry.AccessCount++

	// Convert vector entry back to memory entry
	return vm.convertToMemoryEntry(vectorEntry), nil
}

// Query queries vector memory with similarity search
func (vm *VectorMemory) Query(ctx context.Context, query *MemoryQuery) (*MemoryResult, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	var queryVector []float64
	var err error

	// Generate query vector if content is provided
	if query.Content != "" {
		queryVector, err = vm.embedder.Embed(ctx, query.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to generate query embedding: %w", err)
		}
	} else {
		return nil, fmt.Errorf("content required for vector query")
	}

	// Perform similarity search
	vectorQuery := &VectorQuery{
		Vector:    queryVector,
		Content:   query.Content,
		Limit:     query.Limit,
		Threshold: vm.threshold,
		Metric:    MetricCosine,
	}

	similarityResults, err := vm.similaritySearch(vectorQuery)
	if err != nil {
		return nil, fmt.Errorf("similarity search failed: %w", err)
	}

	// Convert to memory entries
	var matchingEntries []*MemoryEntry
	var relevanceScores []float64

	for _, result := range similarityResults {
		entry := vm.convertToMemoryEntry(result.Entry)
		matchingEntries = append(matchingEntries, entry)
		relevanceScores = append(relevanceScores, result.Similarity)
	}

	return &MemoryResult{
		Entries:   matchingEntries,
		TotalCount: len(matchingEntries),
		Relevance: relevanceScores,
		Metadata:  map[string]interface{}{"source": "vector_memory", "metric": string(vectorQuery.Metric)},
	}, nil
}

// Update updates a memory entry
func (vm *VectorMemory) Update(ctx context.Context, entry *MemoryEntry) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	vectorEntry, exists := vm.vectors[entry.ID]
	if !exists {
		return fmt.Errorf("vector entry not found: %s", entry.ID)
	}

	// Generate new vector if content changed
	newVector, err := vm.embedder.Embed(ctx, entry.Content)
	if err != nil {
		return fmt.Errorf("failed to generate new embedding: %w", err)
	}

	// Update vector entry
	vectorEntry.Vector = newVector
	vectorEntry.Content = entry.Content
	vectorEntry.Metadata = entry.Metadata
	vectorEntry.Importance = entry.Importance
	vectorEntry.Confidence = entry.Confidence
	vectorEntry.Tags = entry.Tags
	vectorEntry.Norm = vectorNorm(newVector)
	vectorEntry.LastAccess = time.Now()

	// Update index
	vm.index.UpdateVector(vectorEntry)

	vm.logger.Debug("Vector updated in vector memory",
		"vector_id", entry.ID,
		"new_norm", vectorEntry.Norm)

	return nil
}

// Delete deletes a memory entry
func (vm *VectorMemory) Delete(ctx context.Context, id string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	vectorEntry, exists := vm.vectors[id]
	if !exists {
		return fmt.Errorf("vector entry not found: %s", id)
	}

	// Remove from index
	vm.index.RemoveVector(vectorEntry)

	// Delete the vector entry
	delete(vm.vectors, id)

	vm.logger.Debug("Vector deleted from vector memory",
		"vector_id", id,
		"remaining_vectors", len(vm.vectors))

	return nil
}

// SimilaritySearch performs similarity search
func (vm *VectorMemory) similaritySearch(query *VectorQuery) ([]*SimilarityResult, error) {
	var results []*SimilarityResult

	// Search through all vectors
	for _, vectorEntry := range vm.vectors {
		similarity := vm.calculateSimilarity(query.Vector, vectorEntry.Vector, query.Metric)
		
		if similarity >= query.Threshold {
			results = append(results, &SimilarityResult{
				Entry:      vectorEntry,
				Similarity: similarity,
				Distance:   1.0 - similarity,
			})
		}
	}

	// Sort by similarity (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Similarity > results[j].Similarity
	})

	// Apply limit
	if query.Limit > 0 && len(results) > query.Limit {
		results = results[:query.Limit]
	}

	return results, nil
}

// GetSize returns the current size of vector memory
func (vm *VectorMemory) GetSize() int {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	return len(vm.vectors)
}

// GetStatistics returns vector memory statistics
func (vm *VectorMemory) GetStatistics() *MemoryTypeStatistics {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	var totalSize int64
	var totalAccess int64
	var oldestEntry, newestEntry time.Time
	var lastAccess time.Time

	for _, vectorEntry := range vm.vectors {
		// Calculate size (vector dimensions * 8 bytes per float64)
		totalSize += int64(len(vectorEntry.Vector) * 8)
		totalAccess += vectorEntry.AccessCount

		if oldestEntry.IsZero() || vectorEntry.Timestamp.Before(oldestEntry) {
			oldestEntry = vectorEntry.Timestamp
		}

		if newestEntry.IsZero() || vectorEntry.Timestamp.After(newestEntry) {
			newestEntry = vectorEntry.Timestamp
		}

		if lastAccess.IsZero() || vectorEntry.LastAccess.After(lastAccess) {
			lastAccess = vectorEntry.LastAccess
		}
	}

	var averageSize float64
	if len(vm.vectors) > 0 {
		averageSize = float64(totalSize) / float64(len(vm.vectors))
	}

	return &MemoryTypeStatistics{
		EntryCount:      len(vm.vectors),
		TotalSize:       totalSize,
		AverageSize:     averageSize,
		OldestEntry:     oldestEntry,
		NewestEntry:     newestEntry,
		AccessCount:     totalAccess,
		LastAccess:      lastAccess,
		CompressionRate: 0.0, // Vectors are not compressed
	}
}

// Helper methods

func (vm *VectorMemory) convertToMemoryEntry(vectorEntry *VectorEntry) *MemoryEntry {
	return &MemoryEntry{
		ID:          vectorEntry.ID,
		Type:        MemoryTypeVector,
		Content:     vectorEntry.Content,
		Context:     vectorEntry.Metadata,
		Importance:  vectorEntry.Importance,
		Confidence:  vectorEntry.Confidence,
		Timestamp:   vectorEntry.Timestamp,
		LastAccess:  vectorEntry.LastAccess,
		AccessCount: vectorEntry.AccessCount,
		Tags:        vectorEntry.Tags,
		Metadata:    vectorEntry.Metadata,
	}
}

func (vm *VectorMemory) evictLeastSimilar(newEntry *VectorEntry) error {
	if len(vm.vectors) == 0 {
		return nil
	}

	// Find the entry least similar to the new entry
	var leastSimilarID string
	var leastSimilarity float64 = 1.0

	for id, vectorEntry := range vm.vectors {
		similarity := vm.calculateSimilarity(newEntry.Vector, vectorEntry.Vector, MetricCosine)
		
		if leastSimilarID == "" || similarity < leastSimilarity {
			leastSimilarID = id
			leastSimilarity = similarity
		}
	}

	// Remove the least similar entry
	if vectorEntry, exists := vm.vectors[leastSimilarID]; exists {
		vm.index.RemoveVector(vectorEntry)
		delete(vm.vectors, leastSimilarID)

		vm.logger.Debug("Evicted least similar vector from vector memory",
			"vector_id", leastSimilarID,
			"similarity", leastSimilarity,
			"remaining_vectors", len(vm.vectors))
	}

	return nil
}

func (vm *VectorMemory) calculateSimilarity(vec1, vec2 []float64, metric SimilarityMetric) float64 {
	if len(vec1) != len(vec2) {
		return 0.0
	}

	switch metric {
	case MetricCosine:
		return cosineSimilarity(vec1, vec2)
	case MetricEuclidean:
		return 1.0 / (1.0 + euclideanDistance(vec1, vec2))
	case MetricDotProduct:
		return dotProduct(vec1, vec2)
	case MetricManhattan:
		return 1.0 / (1.0 + manhattanDistance(vec1, vec2))
	default:
		return cosineSimilarity(vec1, vec2)
	}
}

// Vector math functions

func vectorNorm(vector []float64) float64 {
	var sum float64
	for _, v := range vector {
		sum += v * v
	}
	return math.Sqrt(sum)
}

func cosineSimilarity(vec1, vec2 []float64) float64 {
	dot := dotProduct(vec1, vec2)
	norm1 := vectorNorm(vec1)
	norm2 := vectorNorm(vec2)
	
	if norm1 == 0 || norm2 == 0 {
		return 0.0
	}
	
	return dot / (norm1 * norm2)
}

func dotProduct(vec1, vec2 []float64) float64 {
	var sum float64
	for i := range vec1 {
		sum += vec1[i] * vec2[i]
	}
	return sum
}

func euclideanDistance(vec1, vec2 []float64) float64 {
	var sum float64
	for i := range vec1 {
		diff := vec1[i] - vec2[i]
		sum += diff * diff
	}
	return math.Sqrt(sum)
}

func manhattanDistance(vec1, vec2 []float64) float64 {
	var sum float64
	for i := range vec1 {
		sum += math.Abs(vec1[i] - vec2[i])
	}
	return sum
}

func simpleHash(s string) uint64 {
	var hash uint64 = 5381
	for _, c := range s {
		hash = ((hash << 5) + hash) + uint64(c)
	}
	return hash
}

// VectorIndex methods

func (vi *VectorIndex) AddVector(entry *VectorEntry) {
	vi.mutex.Lock()
	defer vi.mutex.Unlock()

	vi.entries = append(vi.entries, entry)
}

func (vi *VectorIndex) UpdateVector(entry *VectorEntry) {
	vi.mutex.Lock()
	defer vi.mutex.Unlock()

	// Find and update the entry
	for i, existing := range vi.entries {
		if existing.ID == entry.ID {
			vi.entries[i] = entry
			break
		}
	}
}

func (vi *VectorIndex) RemoveVector(entry *VectorEntry) {
	vi.mutex.Lock()
	defer vi.mutex.Unlock()

	// Find and remove the entry
	for i, existing := range vi.entries {
		if existing.ID == entry.ID {
			vi.entries = append(vi.entries[:i], vi.entries[i+1:]...)
			break
		}
	}
}

func (vi *VectorIndex) Search(queryVector []float64, limit int, threshold float64) ([]*VectorEntry, []float64) {
	vi.mutex.RLock()
	defer vi.mutex.RUnlock()

	var results []*VectorEntry
	var similarities []float64

	for _, entry := range vi.entries {
		similarity := cosineSimilarity(queryVector, entry.Vector)
		if similarity >= threshold {
			results = append(results, entry)
			similarities = append(similarities, similarity)
		}
	}

	// Sort by similarity (descending)
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if similarities[i] < similarities[j] {
				results[i], results[j] = results[j], results[i]
				similarities[i], similarities[j] = similarities[j], similarities[i]
			}
		}
	}

	// Apply limit
	if limit > 0 && len(results) > limit {
		results = results[:limit]
		similarities = similarities[:limit]
	}

	return results, similarities
}
