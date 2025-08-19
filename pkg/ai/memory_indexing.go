package ai

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// IndexType represents different indexing strategies
type IndexType string

const (
	IndexTypeFullText IndexType = "fulltext"
	IndexTypeKeyword  IndexType = "keyword"
	IndexTypeNumeric  IndexType = "numeric"
	IndexTypeDate     IndexType = "date"
	IndexTypeGeo      IndexType = "geo"
)

// MemoryIndex provides advanced indexing capabilities for memory search
type MemoryIndex interface {
	Index(ctx context.Context, sessionID string, memory Memory) error
	Search(ctx context.Context, query SearchQuery) (*SearchResult, error)
	Delete(ctx context.Context, sessionID string) error
	Update(ctx context.Context, sessionID string, memory Memory) error
	GetStats() IndexStats
	Optimize(ctx context.Context) error
	Close() error
}

// IndexStats tracks indexing statistics
type IndexStats struct {
	TotalDocuments    int64         `json:"total_documents"`
	IndexSize         int64         `json:"index_size_bytes"`
	LastIndexTime     time.Time     `json:"last_index_time"`
	SearchCount       int64         `json:"search_count"`
	AverageSearchTime time.Duration `json:"average_search_time"`
	IndexingErrors    int64         `json:"indexing_errors"`
}

// SimpleMemoryIndex implements MemoryIndex using simple in-memory search
type SimpleMemoryIndex struct {
	documents map[string]Memory
	stats     IndexStats
	mutex     sync.RWMutex
}

// NewBleveMemoryIndex creates a new simple memory index (fallback implementation)
func NewBleveMemoryIndex(indexPath string) (*SimpleMemoryIndex, error) {
	return &SimpleMemoryIndex{
		documents: make(map[string]Memory),
		stats:     IndexStats{},
	}, nil
}

// Index indexes a memory document
func (smi *SimpleMemoryIndex) Index(ctx context.Context, sessionID string, memory Memory) error {
	smi.mutex.Lock()
	defer smi.mutex.Unlock()

	smi.documents[sessionID] = memory
	smi.stats.TotalDocuments = int64(len(smi.documents))
	smi.stats.LastIndexTime = time.Now()

	return nil
}

// Search performs an advanced search on the memory index
func (smi *SimpleMemoryIndex) Search(ctx context.Context, query SearchQuery) (*SearchResult, error) {
	smi.mutex.RLock()
	defer smi.mutex.RUnlock()

	startTime := time.Now()

	var matches []Memory
	searchText := strings.ToLower(query.Text)

	for _, memory := range smi.documents {
		if smi.matchesQuery(memory, query, searchText) {
			matches = append(matches, memory)
		}
	}

	// Sort results
	smi.sortResults(matches, query.SortBy, query.SortOrder)

	// Apply pagination
	start := query.Offset
	end := start + query.Limit
	if start > len(matches) {
		start = len(matches)
	}
	if end > len(matches) {
		end = len(matches)
	}

	result := &SearchResult{
		Memories: matches[start:end],
		Total:    int64(len(matches)),
		Limit:    query.Limit,
		Offset:   query.Offset,
		Duration: time.Since(startTime),
		Metadata: map[string]interface{}{
			"total_documents": len(smi.documents),
		},
	}

	smi.updateSearchStats(time.Since(startTime))
	return result, nil
}

// Delete removes a document from the index
func (smi *SimpleMemoryIndex) Delete(ctx context.Context, sessionID string) error {
	smi.mutex.Lock()
	defer smi.mutex.Unlock()

	delete(smi.documents, sessionID)
	smi.stats.TotalDocuments = int64(len(smi.documents))
	return nil
}

// Update updates a document in the index
func (smi *SimpleMemoryIndex) Update(ctx context.Context, sessionID string, memory Memory) error {
	return smi.Index(ctx, sessionID, memory)
}

// GetStats returns indexing statistics
func (smi *SimpleMemoryIndex) GetStats() IndexStats {
	smi.mutex.RLock()
	defer smi.mutex.RUnlock()
	return smi.stats
}

// Optimize is a no-op for simple index
func (smi *SimpleMemoryIndex) Optimize(ctx context.Context) error {
	return nil
}

// Close is a no-op for simple index
func (smi *SimpleMemoryIndex) Close() error {
	return nil
}

// matchesQuery checks if a memory matches the search query
func (smi *SimpleMemoryIndex) matchesQuery(memory Memory, query SearchQuery, searchText string) bool {
	// Text search
	if searchText != "" {
		found := false
		for _, msg := range memory.Messages {
			if strings.Contains(strings.ToLower(msg.Content), searchText) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// User ID filter
	if query.UserID != "" && memory.UserID != query.UserID {
		return false
	}

	// Time range filter
	if query.TimeRange != nil {
		if memory.CreatedAt.Before(query.TimeRange.Start) || memory.CreatedAt.After(query.TimeRange.End) {
			return false
		}
	}

	return true
}

// sortResults sorts the search results
func (smi *SimpleMemoryIndex) sortResults(memories []Memory, sortBy, sortOrder string) {
	if sortBy == "" {
		return
	}

	sort.Slice(memories, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "created_at":
			less = memories[i].CreatedAt.Before(memories[j].CreatedAt)
		case "updated_at":
			less = memories[i].UpdatedAt.Before(memories[j].UpdatedAt)
		case "session_id":
			less = memories[i].SessionID < memories[j].SessionID
		default:
			return false
		}

		if sortOrder == "desc" {
			return !less
		}
		return less
	})
}

// updateSearchStats updates search statistics
func (smi *SimpleMemoryIndex) updateSearchStats(duration time.Duration) {
	smi.stats.SearchCount++

	if smi.stats.SearchCount == 1 {
		smi.stats.AverageSearchTime = duration
	} else {
		total := time.Duration(smi.stats.SearchCount-1) * smi.stats.AverageSearchTime
		smi.stats.AverageSearchTime = (total + duration) / time.Duration(smi.stats.SearchCount)
	}
}

// InMemoryIndex provides a simple in-memory index for testing
type InMemoryIndex struct {
	documents map[string]Memory
	stats     IndexStats
	mutex     sync.RWMutex
}

// NewInMemoryIndex creates a new in-memory index
func NewInMemoryIndex() *InMemoryIndex {
	return &InMemoryIndex{
		documents: make(map[string]Memory),
		stats:     IndexStats{},
	}
}

// Index indexes a memory document in memory
func (imi *InMemoryIndex) Index(ctx context.Context, sessionID string, memory Memory) error {
	imi.mutex.Lock()
	defer imi.mutex.Unlock()

	imi.documents[sessionID] = memory
	imi.stats.TotalDocuments = int64(len(imi.documents))
	imi.stats.LastIndexTime = time.Now()

	return nil
}

// Search performs a simple text search in memory
func (imi *InMemoryIndex) Search(ctx context.Context, query SearchQuery) (*SearchResult, error) {
	imi.mutex.RLock()
	defer imi.mutex.RUnlock()

	startTime := time.Now()

	var matches []Memory
	searchText := strings.ToLower(query.Text)

	for _, memory := range imi.documents {
		if imi.matchesQuery(memory, query, searchText) {
			matches = append(matches, memory)
		}
	}

	// Sort results
	imi.sortResults(matches, query.SortBy, query.SortOrder)

	// Apply pagination
	start := query.Offset
	end := start + query.Limit
	if start > len(matches) {
		start = len(matches)
	}
	if end > len(matches) {
		end = len(matches)
	}

	result := &SearchResult{
		Memories: matches[start:end],
		Total:    int64(len(matches)),
		Limit:    query.Limit,
		Offset:   query.Offset,
		Duration: time.Since(startTime),
		Metadata: map[string]interface{}{
			"total_documents": len(imi.documents),
		},
	}

	imi.updateSearchStats(time.Since(startTime))
	return result, nil
}

// matchesQuery checks if a memory matches the search query
func (imi *InMemoryIndex) matchesQuery(memory Memory, query SearchQuery, searchText string) bool {
	// Text search
	if searchText != "" {
		found := false
		for _, msg := range memory.Messages {
			if strings.Contains(strings.ToLower(msg.Content), searchText) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// User ID filter
	if query.UserID != "" && memory.UserID != query.UserID {
		return false
	}

	// Time range filter
	if query.TimeRange != nil {
		if memory.CreatedAt.Before(query.TimeRange.Start) || memory.CreatedAt.After(query.TimeRange.End) {
			return false
		}
	}

	return true
}

// sortResults sorts the search results
func (imi *InMemoryIndex) sortResults(memories []Memory, sortBy, sortOrder string) {
	if sortBy == "" {
		return
	}

	sort.Slice(memories, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "created_at":
			less = memories[i].CreatedAt.Before(memories[j].CreatedAt)
		case "updated_at":
			less = memories[i].UpdatedAt.Before(memories[j].UpdatedAt)
		case "session_id":
			less = memories[i].SessionID < memories[j].SessionID
		default:
			return false
		}

		if sortOrder == "desc" {
			return !less
		}
		return less
	})
}

// Delete removes a document from the in-memory index
func (imi *InMemoryIndex) Delete(ctx context.Context, sessionID string) error {
	imi.mutex.Lock()
	defer imi.mutex.Unlock()

	delete(imi.documents, sessionID)
	imi.stats.TotalDocuments = int64(len(imi.documents))
	return nil
}

// Update updates a document in the in-memory index
func (imi *InMemoryIndex) Update(ctx context.Context, sessionID string, memory Memory) error {
	return imi.Index(ctx, sessionID, memory)
}

// GetStats returns indexing statistics
func (imi *InMemoryIndex) GetStats() IndexStats {
	imi.mutex.RLock()
	defer imi.mutex.RUnlock()
	return imi.stats
}

// Optimize is a no-op for in-memory index
func (imi *InMemoryIndex) Optimize(ctx context.Context) error {
	return nil
}

// Close is a no-op for in-memory index
func (imi *InMemoryIndex) Close() error {
	return nil
}

// updateSearchStats updates search statistics
func (imi *InMemoryIndex) updateSearchStats(duration time.Duration) {
	imi.stats.SearchCount++

	if imi.stats.SearchCount == 1 {
		imi.stats.AverageSearchTime = duration
	} else {
		total := time.Duration(imi.stats.SearchCount-1) * imi.stats.AverageSearchTime
		imi.stats.AverageSearchTime = (total + duration) / time.Duration(imi.stats.SearchCount)
	}
}
