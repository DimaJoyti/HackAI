package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// Content represents stored memory content
type Content struct {
	ID        string                 `json:"id"`
	Text      string                 `json:"text"`
	Metadata  map[string]interface{} `json:"metadata"`
	Embedding []float64              `json:"embedding"`
	Timestamp time.Time              `json:"timestamp"`
	TTL       time.Duration          `json:"ttl,omitempty"`
}

// VectorMemory provides semantic memory storage
type VectorMemory interface {
	Store(ctx context.Context, key string, content Content) error
	Retrieve(ctx context.Context, query string, limit int) ([]Content, error)
	Update(ctx context.Context, key string, content Content) error
	Delete(ctx context.Context, key string) error
	Search(ctx context.Context, embedding []float64, threshold float64) ([]Content, error)
	Clear(ctx context.Context) error
	Size(ctx context.Context) (int, error)
}

// ConversationalMemory stores conversation history
type ConversationalMemory interface {
	AddMessage(ctx context.Context, sessionID string, message Message) error
	GetMessages(ctx context.Context, sessionID string, limit int) ([]Message, error)
	GetSummary(ctx context.Context, sessionID string) (string, error)
	UpdateSummary(ctx context.Context, sessionID string, summary string) error
	ClearSession(ctx context.Context, sessionID string) error
}

// EpisodicMemory stores episodic memories (events, experiences)
type EpisodicMemory interface {
	StoreEpisode(ctx context.Context, episode Episode) error
	RetrieveEpisodes(ctx context.Context, query EpisodeQuery) ([]Episode, error)
	UpdateEpisode(ctx context.Context, episodeID string, episode Episode) error
	DeleteEpisode(ctx context.Context, episodeID string) error
}

// SemanticMemory stores semantic knowledge
type SemanticMemory interface {
	StoreFact(ctx context.Context, fact Fact) error
	RetrieveFacts(ctx context.Context, query string, limit int) ([]Fact, error)
	UpdateFact(ctx context.Context, factID string, fact Fact) error
	DeleteFact(ctx context.Context, factID string) error
}

// Message represents a conversation message
type Message struct {
	ID        string                 `json:"id"`
	SessionID string                 `json:"session_id"`
	Role      string                 `json:"role"`
	Content   string                 `json:"content"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// Episode represents an episodic memory
type Episode struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Context     string                 `json:"context"`
	Outcome     string                 `json:"outcome"`
	Timestamp   time.Time              `json:"timestamp"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
	Embedding   []float64              `json:"embedding"`
}

// EpisodeQuery represents a query for episodes
type EpisodeQuery struct {
	Query     string    `json:"query"`
	Tags      []string  `json:"tags"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Limit     int       `json:"limit"`
}

// Fact represents a semantic fact
type Fact struct {
	ID         string                 `json:"id"`
	Subject    string                 `json:"subject"`
	Predicate  string                 `json:"predicate"`
	Object     string                 `json:"object"`
	Context    string                 `json:"context"`
	Confidence float64                `json:"confidence"`
	Source     string                 `json:"source"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata"`
	Embedding  []float64              `json:"embedding"`
}

// InMemoryVectorMemory implements VectorMemory using in-memory storage
type InMemoryVectorMemory struct {
	data    map[string]Content
	mutex   sync.RWMutex
	maxSize int
}

// NewInMemoryVectorMemory creates a new in-memory vector memory
func NewInMemoryVectorMemory(maxSize int) *InMemoryVectorMemory {
	return &InMemoryVectorMemory{
		data:    make(map[string]Content),
		maxSize: maxSize,
	}
}

// Store stores content in memory
func (m *InMemoryVectorMemory) Store(ctx context.Context, key string, content Content) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check size limit
	if len(m.data) >= m.maxSize && m.data[key].ID == "" {
		return fmt.Errorf("memory size limit exceeded")
	}

	// Set ID if not provided
	if content.ID == "" {
		content.ID = uuid.New().String()
	}

	// Set timestamp if not provided
	if content.Timestamp.IsZero() {
		content.Timestamp = time.Now()
	}

	m.data[key] = content
	return nil
}

// Retrieve retrieves content by semantic similarity
func (m *InMemoryVectorMemory) Retrieve(ctx context.Context, query string, limit int) ([]Content, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Simple text-based search for now
	// In a real implementation, this would use vector similarity
	var results []Content
	for _, content := range m.data {
		if containsText(content.Text, query) {
			results = append(results, content)
			if len(results) >= limit {
				break
			}
		}
	}

	return results, nil
}

// Update updates existing content
func (m *InMemoryVectorMemory) Update(ctx context.Context, key string, content Content) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.data[key]; !exists {
		return fmt.Errorf("content with key %s not found", key)
	}

	content.Timestamp = time.Now()
	m.data[key] = content
	return nil
}

// Delete deletes content by key
func (m *InMemoryVectorMemory) Delete(ctx context.Context, key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.data, key)
	return nil
}

// Search searches by embedding similarity
func (m *InMemoryVectorMemory) Search(ctx context.Context, embedding []float64, threshold float64) ([]Content, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var results []Content
	for _, content := range m.data {
		if len(content.Embedding) > 0 {
			similarity := cosineSimilarity(embedding, content.Embedding)
			if similarity >= threshold {
				results = append(results, content)
			}
		}
	}

	return results, nil
}

// Clear clears all content
func (m *InMemoryVectorMemory) Clear(ctx context.Context) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.data = make(map[string]Content)
	return nil
}

// Size returns the number of stored items
func (m *InMemoryVectorMemory) Size(ctx context.Context) (int, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return len(m.data), nil
}

// InMemoryConversationalMemory implements ConversationalMemory
type InMemoryConversationalMemory struct {
	sessions  map[string][]Message
	summaries map[string]string
	mutex     sync.RWMutex
}

// NewInMemoryConversationalMemory creates a new in-memory conversational memory
func NewInMemoryConversationalMemory() *InMemoryConversationalMemory {
	return &InMemoryConversationalMemory{
		sessions:  make(map[string][]Message),
		summaries: make(map[string]string),
	}
}

// AddMessage adds a message to a session
func (m *InMemoryConversationalMemory) AddMessage(ctx context.Context, sessionID string, message Message) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if message.ID == "" {
		message.ID = uuid.New().String()
	}
	if message.Timestamp.IsZero() {
		message.Timestamp = time.Now()
	}
	message.SessionID = sessionID

	m.sessions[sessionID] = append(m.sessions[sessionID], message)
	return nil
}

// GetMessages retrieves messages from a session
func (m *InMemoryConversationalMemory) GetMessages(ctx context.Context, sessionID string, limit int) ([]Message, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	messages, exists := m.sessions[sessionID]
	if !exists {
		return []Message{}, nil
	}

	// Return last N messages
	start := 0
	if len(messages) > limit {
		start = len(messages) - limit
	}

	return messages[start:], nil
}

// GetSummary retrieves session summary
func (m *InMemoryConversationalMemory) GetSummary(ctx context.Context, sessionID string) (string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	summary, exists := m.summaries[sessionID]
	if !exists {
		return "", nil
	}

	return summary, nil
}

// UpdateSummary updates session summary
func (m *InMemoryConversationalMemory) UpdateSummary(ctx context.Context, sessionID string, summary string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.summaries[sessionID] = summary
	return nil
}

// ClearSession clears a session
func (m *InMemoryConversationalMemory) ClearSession(ctx context.Context, sessionID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.sessions, sessionID)
	delete(m.summaries, sessionID)
	return nil
}

// MemoryManager coordinates different memory types
type MemoryManager struct {
	vectorMemory         VectorMemory
	conversationalMemory ConversationalMemory
	episodicMemory       EpisodicMemory
	semanticMemory       SemanticMemory
	contextManager       ContextManager
	consolidator         MemoryConsolidator
	config               MemoryConfig
	logger               *logger.Logger
}

// MemoryConfig represents memory configuration
type MemoryConfig struct {
	VectorMemorySize  int           `json:"vector_memory_size"`
	ConversationTTL   time.Duration `json:"conversation_ttl"`
	EpisodeRetention  time.Duration `json:"episode_retention"`
	FactRetention     time.Duration `json:"fact_retention"`
	EnablePersistence bool          `json:"enable_persistence"`
	PersistencePath   string        `json:"persistence_path"`
}

// NewMemoryManager creates a new memory manager
func NewMemoryManager(config MemoryConfig, logger *logger.Logger) *MemoryManager {
	// Create memory components
	vectorMemory := NewInMemoryVectorMemory(config.VectorMemorySize)
	conversationalMemory := NewInMemoryConversationalMemory()
	episodicMemory := NewInMemoryEpisodicMemory(1000, logger) // Default size
	semanticMemory := NewInMemorySemanticMemory(1000, logger) // Default size

	// Create memory manager
	manager := &MemoryManager{
		vectorMemory:         vectorMemory,
		conversationalMemory: conversationalMemory,
		episodicMemory:       episodicMemory,
		semanticMemory:       semanticMemory,
		config:               config,
		logger:               logger,
	}

	// Create context manager
	contextConfig := ContextConfig{
		MaxContextLength:    4000,
		CompressionRatio:    0.7,
		RelevanceThreshold:  0.5,
		MaxRetrievalItems:   20,
		ContextTTL:          24 * time.Hour,
		EnableCompression:   true,
		EnableSummarization: true,
		SummaryInterval:     10,
	}
	manager.contextManager = NewDefaultContextManager(manager, contextConfig, logger)

	// Create consolidator
	consolidationConfig := ConsolidationConfig{
		ConversationThreshold: 10,
		EpisodeThreshold:      5,
		FactThreshold:         3,
		ConsolidationInterval: 1 * time.Hour,
		RetentionPeriod:       30 * 24 * time.Hour,
		ArchivePeriod:         90 * 24 * time.Hour,
		EnableAutoCleanup:     true,
		EnableDeduplication:   true,
		MaxMemorySize:         1024 * 1024 * 1024, // 1GB
	}
	manager.consolidator = NewDefaultMemoryConsolidator(manager, manager.contextManager, consolidationConfig, logger)

	return manager
}

// GetVectorMemory returns the vector memory
func (m *MemoryManager) GetVectorMemory() VectorMemory {
	return m.vectorMemory
}

// GetConversationalMemory returns the conversational memory
func (m *MemoryManager) GetConversationalMemory() ConversationalMemory {
	return m.conversationalMemory
}

// GetEpisodicMemory returns the episodic memory
func (m *MemoryManager) GetEpisodicMemory() EpisodicMemory {
	return m.episodicMemory
}

// GetSemanticMemory returns the semantic memory
func (m *MemoryManager) GetSemanticMemory() SemanticMemory {
	return m.semanticMemory
}

// GetContextManager returns the context manager
func (m *MemoryManager) GetContextManager() ContextManager {
	return m.contextManager
}

// GetConsolidator returns the memory consolidator
func (m *MemoryManager) GetConsolidator() MemoryConsolidator {
	return m.consolidator
}

// Helper functions

// containsText checks if text contains query (simple implementation)
func containsText(text, query string) bool {
	return len(query) > 0 && len(text) > 0 &&
		strings.Contains(strings.ToLower(text), strings.ToLower(query))
}

// cosineSimilarity calculates cosine similarity between two vectors
func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0
	}

	var dotProduct, normA, normB float64
	for i := range a {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProduct / (normA * normB)
}
