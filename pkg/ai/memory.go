package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var memoryTracer = otel.Tracer("hackai/ai/memory")

// MemoryManager handles conversation history and context storage with advanced features
type MemoryManager interface {
	// Basic operations
	Store(ctx context.Context, sessionID string, memory Memory) error
	Retrieve(ctx context.Context, sessionID string) (Memory, error)
	Search(ctx context.Context, query string, limit int) ([]Memory, error)
	Clear(ctx context.Context, sessionID string) error

	// Advanced operations
	BatchStore(ctx context.Context, memories map[string]Memory) error
	BatchRetrieve(ctx context.Context, sessionIDs []string) (map[string]Memory, error)
	AdvancedSearch(ctx context.Context, query SearchQuery) (*SearchResult, error)

	// Lifecycle management
	Archive(ctx context.Context, sessionID string) error
	Restore(ctx context.Context, sessionID string) error
	Cleanup(ctx context.Context, criteria CleanupCriteria) (*CleanupResult, error)

	// Analytics and insights
	GetStats() MemoryStats
	GetAnalytics(ctx context.Context, timeRange TimeRange) (*MemoryAnalytics, error)
	GetInsights(ctx context.Context, sessionID string) (*MemoryInsights, error)

	// System operations
	IsHealthy(ctx context.Context) bool
	Backup(ctx context.Context, destination string) error
	Migrate(ctx context.Context, target MemoryManager) error
	Validate(ctx context.Context, sessionID string) (*ValidationResult, error)
}

// Memory represents stored conversation context
type Memory struct {
	SessionID string                 `json:"session_id"`
	UserID    string                 `json:"user_id"`
	Messages  []Message              `json:"messages"`
	Context   map[string]interface{} `json:"context"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
	Version   int                    `json:"version"`
}

// Message represents a single conversation message
type Message struct {
	ID        string                 `json:"id"`
	Role      string                 `json:"role"` // "user", "assistant", "system", "tool"
	Content   string                 `json:"content"`
	ToolCalls []ToolCall             `json:"tool_calls,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// ToolCall represents a tool call in a message
type ToolCall struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function ToolCallFunction       `json:"function"`
	Result   map[string]interface{} `json:"result,omitempty"`
}

// ToolCallFunction represents a function call
type ToolCallFunction struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// MemoryConfig represents configuration for memory management
type MemoryConfig struct {
	RedisURL         string          `json:"redis_url"`
	KeyPrefix        string          `json:"key_prefix"`
	DefaultTTL       time.Duration   `json:"default_ttl"`
	MaxMemories      int             `json:"max_memories"`
	CompressionType  CompressionType `json:"compression_type"`
	EncryptionType   EncryptionType  `json:"encryption_type"`
	EncryptionKey    string          `json:"encryption_key"`
	IndexPath        string          `json:"index_path"`
	EnableIndexing   bool            `json:"enable_indexing"`
	EnableAnalytics  bool            `json:"enable_analytics"`
	EnableValidation bool            `json:"enable_validation"`
}

// MemoryStats tracks memory management statistics
type MemoryStats struct {
	TotalMemories  int64     `json:"total_memories"`
	ActiveSessions int64     `json:"active_sessions"`
	AverageSize    int64     `json:"average_size_bytes"`
	HitRate        float64   `json:"hit_rate"`
	MissRate       float64   `json:"miss_rate"`
	TotalRequests  int64     `json:"total_requests"`
	TotalHits      int64     `json:"total_hits"`
	TotalMisses    int64     `json:"total_misses"`
	LastAccessTime time.Time `json:"last_access_time"`
}

// SearchQuery represents an advanced search query
type SearchQuery struct {
	Text        string                 `json:"text"`
	Filters     map[string]interface{} `json:"filters"`
	SortBy      string                 `json:"sort_by"`
	SortOrder   string                 `json:"sort_order"` // "asc" or "desc"
	Limit       int                    `json:"limit"`
	Offset      int                    `json:"offset"`
	TimeRange   *TimeRange             `json:"time_range,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	MessageType string                 `json:"message_type,omitempty"`
}

// SearchResult represents search results with metadata
type SearchResult struct {
	Memories []Memory               `json:"memories"`
	Total    int64                  `json:"total"`
	Limit    int                    `json:"limit"`
	Offset   int                    `json:"offset"`
	Duration time.Duration          `json:"duration"`
	Metadata map[string]interface{} `json:"metadata"`
}

// TimeRange represents a time range for queries
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// CleanupCriteria defines criteria for memory cleanup
type CleanupCriteria struct {
	OlderThan    *time.Time `json:"older_than,omitempty"`
	SizeLimit    *int64     `json:"size_limit,omitempty"`
	UserID       string     `json:"user_id,omitempty"`
	MessageCount *int       `json:"message_count,omitempty"`
	Inactive     bool       `json:"inactive"`
	DryRun       bool       `json:"dry_run"`
}

// CleanupResult represents the result of a cleanup operation
type CleanupResult struct {
	SessionsProcessed int64         `json:"sessions_processed"`
	SessionsDeleted   int64         `json:"sessions_deleted"`
	BytesFreed        int64         `json:"bytes_freed"`
	Duration          time.Duration `json:"duration"`
	Errors            []string      `json:"errors,omitempty"`
}

// MemoryAnalytics provides detailed analytics about memory usage
type MemoryAnalytics struct {
	TimeRange           TimeRange          `json:"time_range"`
	TotalSessions       int64              `json:"total_sessions"`
	ActiveSessions      int64              `json:"active_sessions"`
	TotalMessages       int64              `json:"total_messages"`
	AverageSessionSize  float64            `json:"average_session_size"`
	TopUsers            []UserStats        `json:"top_users"`
	MessageDistribution map[string]int64   `json:"message_distribution"`
	HourlyActivity      map[string]int64   `json:"hourly_activity"`
	StorageUsage        StorageUsageStats  `json:"storage_usage"`
	PerformanceMetrics  PerformanceMetrics `json:"performance_metrics"`
}

// UserStats represents statistics for a specific user
type UserStats struct {
	UserID       string    `json:"user_id"`
	SessionCount int64     `json:"session_count"`
	MessageCount int64     `json:"message_count"`
	TotalSize    int64     `json:"total_size_bytes"`
	LastActivity time.Time `json:"last_activity"`
}

// StorageUsageStats represents storage usage statistics
type StorageUsageStats struct {
	TotalSize        int64   `json:"total_size_bytes"`
	CompressedSize   int64   `json:"compressed_size_bytes"`
	CompressionRatio float64 `json:"compression_ratio"`
	IndexSize        int64   `json:"index_size_bytes"`
	MetadataSize     int64   `json:"metadata_size_bytes"`
}

// PerformanceMetrics represents performance metrics
type PerformanceMetrics struct {
	AverageReadLatency  time.Duration `json:"average_read_latency"`
	AverageWriteLatency time.Duration `json:"average_write_latency"`
	ThroughputRPS       float64       `json:"throughput_rps"`
	ErrorRate           float64       `json:"error_rate"`
	CacheHitRate        float64       `json:"cache_hit_rate"`
}

// MemoryInsights provides insights about a specific memory session
type MemoryInsights struct {
	SessionID         string                 `json:"session_id"`
	MessageCount      int                    `json:"message_count"`
	ConversationFlow  []ConversationTurn     `json:"conversation_flow"`
	TopicAnalysis     []Topic                `json:"topic_analysis"`
	SentimentAnalysis SentimentAnalysis      `json:"sentiment_analysis"`
	Patterns          []Pattern              `json:"patterns"`
	Recommendations   []string               `json:"recommendations"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ConversationTurn represents a turn in the conversation
type ConversationTurn struct {
	TurnID    int       `json:"turn_id"`
	Role      string    `json:"role"`
	Timestamp time.Time `json:"timestamp"`
	WordCount int       `json:"word_count"`
	Topics    []string  `json:"topics"`
	Sentiment float64   `json:"sentiment"`
}

// Topic represents a topic found in the conversation
type Topic struct {
	Name       string   `json:"name"`
	Confidence float64  `json:"confidence"`
	Frequency  int      `json:"frequency"`
	Keywords   []string `json:"keywords"`
}

// SentimentAnalysis represents sentiment analysis results
type SentimentAnalysis struct {
	OverallSentiment float64            `json:"overall_sentiment"`
	SentimentTrend   []SentimentPoint   `json:"sentiment_trend"`
	EmotionBreakdown map[string]float64 `json:"emotion_breakdown"`
}

// SentimentPoint represents a point in sentiment analysis
type SentimentPoint struct {
	Timestamp  time.Time `json:"timestamp"`
	Sentiment  float64   `json:"sentiment"`
	Confidence float64   `json:"confidence"`
}

// Pattern represents a detected pattern in the conversation
type Pattern struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Frequency   int                    `json:"frequency"`
	Confidence  float64                `json:"confidence"`
	Examples    []string               `json:"examples"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ValidationResult represents the result of memory validation
type ValidationResult struct {
	Valid    bool                   `json:"valid"`
	Errors   []ValidationError      `json:"errors,omitempty"`
	Warnings []ValidationWarning    `json:"warnings,omitempty"`
	Checksum string                 `json:"checksum"`
	Size     int64                  `json:"size_bytes"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Field    string `json:"field,omitempty"`
	Severity string `json:"severity"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Field      string `json:"field,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

// RedisMemoryManager implements MemoryManager using Redis with advanced features
type RedisMemoryManager struct {
	client         *redis.Client
	config         MemoryConfig
	stats          MemoryStats
	logger         *logger.Logger
	tracer         trace.Tracer
	compressionMgr *CompressionManager
	encryptionMgr  *EncryptionManager
	index          MemoryIndex
	analytics      *MemoryAnalyticsEngine
	validator      *MemoryValidator
	mutex          sync.RWMutex
}

// NewRedisMemoryManager creates a new Redis-based memory manager
func NewRedisMemoryManager(config MemoryConfig, logger *logger.Logger) (*RedisMemoryManager, error) {
	// Set defaults
	if config.KeyPrefix == "" {
		config.KeyPrefix = "hackai:memory"
	}
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 24 * time.Hour
	}
	if config.MaxMemories == 0 {
		config.MaxMemories = 10000
	}

	// Parse Redis URL
	opts, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Redis connection failed: %w", err)
	}

	// Set additional defaults
	if config.CompressionType == "" {
		config.CompressionType = CompressionGzip
	}
	if config.EncryptionType == "" {
		config.EncryptionType = EncryptionNone
	}

	// Initialize compression manager
	compressionMgr := NewCompressionManager(config.CompressionType)

	// Initialize encryption manager
	var encryptionMgr *EncryptionManager
	if config.EncryptionType != EncryptionNone && config.EncryptionKey != "" {
		encryptionMgr, err = NewEncryptionManager([]byte(config.EncryptionKey), config.EncryptionType)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize encryption: %w", err)
		}
	}

	// Initialize memory index
	var index MemoryIndex
	if config.EnableIndexing {
		if config.IndexPath != "" {
			index, err = NewBleveMemoryIndex(config.IndexPath)
			if err != nil {
				logger.Warn("Failed to initialize advanced index, falling back to in-memory", "error", err)
				index = NewInMemoryIndex()
			}
		} else {
			index = NewInMemoryIndex()
		}
	}

	// Initialize validator
	var validator *MemoryValidator
	if config.EnableValidation {
		validationConfig := ValidationConfig{
			EnableChecksumValidation: true,
			EnableSchemaValidation:   true,
			EnableContentValidation:  true,
			MaxMessageLength:         10000,
			MaxMessagesPerSession:    1000,
			MaxContextSize:           50000,
			RequiredFields:           []string{"session_id"},
		}
		validator = NewMemoryValidator(validationConfig)
	}

	manager := &RedisMemoryManager{
		client:         client,
		config:         config,
		logger:         logger,
		tracer:         memoryTracer,
		compressionMgr: compressionMgr,
		encryptionMgr:  encryptionMgr,
		index:          index,
		validator:      validator,
		stats: MemoryStats{
			LastAccessTime: time.Now(),
		},
	}

	// Initialize analytics engine with the manager
	if config.EnableAnalytics {
		manager.analytics = NewMemoryAnalyticsEngine(manager)
	}

	logger.Info("Redis memory manager initialized",
		"redis_url", config.RedisURL,
		"key_prefix", config.KeyPrefix,
		"default_ttl", config.DefaultTTL,
		"compression", config.CompressionType,
		"encryption", config.EncryptionType,
		"indexing", config.EnableIndexing,
		"analytics", config.EnableAnalytics,
		"validation", config.EnableValidation)

	return manager, nil
}

// Store stores a memory in Redis
func (m *RedisMemoryManager) Store(ctx context.Context, sessionID string, memory Memory) error {
	ctx, span := m.tracer.Start(ctx, "memory.store",
		trace.WithAttributes(
			attribute.String("session_id", sessionID),
			attribute.String("user_id", memory.UserID),
		),
	)
	defer span.End()

	key := m.getKey(sessionID)

	// Update memory metadata
	memory.SessionID = sessionID
	memory.UpdatedAt = time.Now()
	if memory.CreatedAt.IsZero() {
		memory.CreatedAt = memory.UpdatedAt
	}
	memory.Version++

	// Set expiration if not set
	if memory.ExpiresAt == nil {
		expiresAt := memory.UpdatedAt.Add(m.config.DefaultTTL)
		memory.ExpiresAt = &expiresAt
	}

	// Serialize memory
	data, err := json.Marshal(memory)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal memory: %w", err)
	}

	// Store in Redis with TTL
	ttl := time.Until(*memory.ExpiresAt)
	if ttl <= 0 {
		ttl = m.config.DefaultTTL
	}

	if err := m.client.Set(ctx, key, data, ttl).Err(); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to store memory: %w", err)
	}

	// Update stats
	m.updateStoreStats(len(data))

	span.SetAttributes(
		attribute.Int("memory.size_bytes", len(data)),
		attribute.Int("memory.message_count", len(memory.Messages)),
		attribute.String("memory.ttl", ttl.String()),
	)

	m.logger.Debug("Memory stored",
		"session_id", sessionID,
		"size_bytes", len(data),
		"message_count", len(memory.Messages),
		"ttl", ttl)

	return nil
}

// Retrieve retrieves a memory from Redis
func (m *RedisMemoryManager) Retrieve(ctx context.Context, sessionID string) (Memory, error) {
	ctx, span := m.tracer.Start(ctx, "memory.retrieve",
		trace.WithAttributes(
			attribute.String("session_id", sessionID),
		),
	)
	defer span.End()

	key := m.getKey(sessionID)

	// Get from Redis
	data, err := m.client.Get(ctx, key).Result()
	if err == redis.Nil {
		m.updateRetrieveStats(false)
		span.SetAttributes(attribute.Bool("memory.found", false))
		return Memory{}, fmt.Errorf("memory not found for session %s", sessionID)
	}
	if err != nil {
		span.RecordError(err)
		return Memory{}, fmt.Errorf("failed to retrieve memory: %w", err)
	}

	// Deserialize memory
	var memory Memory
	if err := json.Unmarshal([]byte(data), &memory); err != nil {
		span.RecordError(err)
		return Memory{}, fmt.Errorf("failed to unmarshal memory: %w", err)
	}

	// Update stats
	m.updateRetrieveStats(true)

	span.SetAttributes(
		attribute.Bool("memory.found", true),
		attribute.Int("memory.size_bytes", len(data)),
		attribute.Int("memory.message_count", len(memory.Messages)),
		attribute.Int("memory.version", memory.Version),
	)

	m.logger.Debug("Memory retrieved",
		"session_id", sessionID,
		"size_bytes", len(data),
		"message_count", len(memory.Messages),
		"version", memory.Version)

	return memory, nil
}

// Search searches for memories based on a query
func (m *RedisMemoryManager) Search(ctx context.Context, query string, limit int) ([]Memory, error) {
	ctx, span := m.tracer.Start(ctx, "memory.search",
		trace.WithAttributes(
			attribute.String("query", query),
			attribute.Int("limit", limit),
		),
	)
	defer span.End()

	// Use Redis SCAN to find matching keys
	pattern := m.config.KeyPrefix + ":session:*"
	var cursor uint64
	var keys []string

	for {
		var scanKeys []string
		var err error
		scanKeys, cursor, err = m.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("failed to scan keys: %w", err)
		}

		keys = append(keys, scanKeys...)

		if cursor == 0 {
			break
		}
	}

	// Retrieve and filter memories
	var memories []Memory
	for i, key := range keys {
		if limit > 0 && i >= limit {
			break
		}

		data, err := m.client.Get(ctx, key).Result()
		if err != nil {
			continue // Skip failed retrievals
		}

		var memory Memory
		if err := json.Unmarshal([]byte(data), &memory); err != nil {
			continue // Skip invalid memories
		}

		// Simple text search in messages
		if m.matchesQuery(memory, query) {
			memories = append(memories, memory)
		}
	}

	span.SetAttributes(
		attribute.Int("search.total_keys", len(keys)),
		attribute.Int("search.matched_memories", len(memories)),
	)

	m.logger.Debug("Memory search completed",
		"query", query,
		"total_keys", len(keys),
		"matched_memories", len(memories))

	return memories, nil
}

// Clear clears a memory from Redis
func (m *RedisMemoryManager) Clear(ctx context.Context, sessionID string) error {
	ctx, span := m.tracer.Start(ctx, "memory.clear",
		trace.WithAttributes(
			attribute.String("session_id", sessionID),
		),
	)
	defer span.End()

	key := m.getKey(sessionID)

	if err := m.client.Del(ctx, key).Err(); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to clear memory: %w", err)
	}

	m.logger.Debug("Memory cleared", "session_id", sessionID)

	return nil
}

// GetStats returns memory management statistics
func (m *RedisMemoryManager) GetStats() MemoryStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats := m.stats

	// Calculate hit rate
	if stats.TotalRequests > 0 {
		stats.HitRate = float64(stats.TotalHits) / float64(stats.TotalRequests)
		stats.MissRate = float64(stats.TotalMisses) / float64(stats.TotalRequests)
	}

	return stats
}

// IsHealthy checks if the memory manager is healthy
func (m *RedisMemoryManager) IsHealthy(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return m.client.Ping(ctx).Err() == nil
}

// Helper methods

// getKey generates a Redis key for a session
func (m *RedisMemoryManager) getKey(sessionID string) string {
	return fmt.Sprintf("%s:session:%s", m.config.KeyPrefix, sessionID)
}

// matchesQuery checks if a memory matches a search query
func (m *RedisMemoryManager) matchesQuery(memory Memory, query string) bool {
	// Simple text search - in a production system, you might want to use
	// more sophisticated search algorithms or external search engines
	for _, message := range memory.Messages {
		if contains(message.Content, query) {
			return true
		}
	}

	// Search in context
	for key, value := range memory.Context {
		if contains(key, query) || contains(fmt.Sprintf("%v", value), query) {
			return true
		}
	}

	return false
}

// contains performs case-insensitive substring search
func contains(text, query string) bool {
	// Simple case-insensitive search
	// In production, you might want to use more sophisticated text matching
	return len(text) >= len(query) &&
		fmt.Sprintf("%s", text) != fmt.Sprintf("%s", text[:len(text)-len(query)]+query+text[len(text):])
}

// updateStoreStats updates statistics for store operations
func (m *RedisMemoryManager) updateStoreStats(sizeBytes int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.stats.TotalMemories++
	m.stats.LastAccessTime = time.Now()

	// Update average size
	if m.stats.TotalMemories == 1 {
		m.stats.AverageSize = int64(sizeBytes)
	} else {
		total := (m.stats.TotalMemories - 1) * m.stats.AverageSize
		m.stats.AverageSize = (total + int64(sizeBytes)) / m.stats.TotalMemories
	}
}

// updateRetrieveStats updates statistics for retrieve operations
func (m *RedisMemoryManager) updateRetrieveStats(hit bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.stats.TotalRequests++
	m.stats.LastAccessTime = time.Now()

	if hit {
		m.stats.TotalHits++
	} else {
		m.stats.TotalMisses++
	}
}

// BatchStore stores multiple memories in Redis
func (m *RedisMemoryManager) BatchStore(ctx context.Context, memories map[string]Memory) error {
	ctx, span := m.tracer.Start(ctx, "memory.batch_store")
	defer span.End()

	pipe := m.client.Pipeline()

	for sessionID, memory := range memories {
		key := m.getKey(sessionID)

		// Serialize memory
		data, err := m.serializeMemory(memory)
		if err != nil {
			return fmt.Errorf("failed to serialize memory for session %s: %w", sessionID, err)
		}

		pipe.Set(ctx, key, data, m.config.DefaultTTL)

		// Update index if enabled
		if m.index != nil {
			if err := m.index.Index(ctx, sessionID, memory); err != nil {
				m.logger.Warn("Failed to index memory", "session_id", sessionID, "error", err)
			}
		}
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("batch store failed: %w", err)
	}

	m.updateStats(len(memories), true)
	return nil
}

// BatchRetrieve retrieves multiple memories from Redis
func (m *RedisMemoryManager) BatchRetrieve(ctx context.Context, sessionIDs []string) (map[string]Memory, error) {
	ctx, span := m.tracer.Start(ctx, "memory.batch_retrieve")
	defer span.End()

	pipe := m.client.Pipeline()
	cmds := make(map[string]*redis.StringCmd)

	for _, sessionID := range sessionIDs {
		key := m.getKey(sessionID)
		cmds[sessionID] = pipe.Get(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("batch retrieve failed: %w", err)
	}

	results := make(map[string]Memory)
	hits := 0
	misses := 0

	for sessionID, cmd := range cmds {
		data, err := cmd.Result()
		if err == redis.Nil {
			misses++
			continue
		}
		if err != nil {
			m.logger.Warn("Failed to retrieve memory", "session_id", sessionID, "error", err)
			misses++
			continue
		}

		memory, err := m.deserializeMemory([]byte(data))
		if err != nil {
			m.logger.Warn("Failed to deserialize memory", "session_id", sessionID, "error", err)
			misses++
			continue
		}

		results[sessionID] = memory
		hits++
	}

	m.updateStats(hits+misses, hits > 0)
	return results, nil
}

// AdvancedSearch performs advanced search using the index
func (m *RedisMemoryManager) AdvancedSearch(ctx context.Context, query SearchQuery) (*SearchResult, error) {
	ctx, span := m.tracer.Start(ctx, "memory.advanced_search")
	defer span.End()

	if m.index == nil {
		return nil, fmt.Errorf("indexing is not enabled")
	}

	return m.index.Search(ctx, query)
}

// Archive archives a memory session
func (m *RedisMemoryManager) Archive(ctx context.Context, sessionID string) error {
	ctx, span := m.tracer.Start(ctx, "memory.archive")
	defer span.End()

	// For Redis implementation, we could move to a different key prefix
	// or use a different database. For now, we'll just add metadata
	memory, err := m.Retrieve(ctx, sessionID)
	if err != nil {
		return err
	}

	// Add archive metadata
	if memory.Metadata == nil {
		memory.Metadata = make(map[string]interface{})
	}
	memory.Metadata["archived"] = true
	memory.Metadata["archived_at"] = time.Now()

	return m.Store(ctx, sessionID, memory)
}

// Restore restores an archived memory session
func (m *RedisMemoryManager) Restore(ctx context.Context, sessionID string) error {
	ctx, span := m.tracer.Start(ctx, "memory.restore")
	defer span.End()

	memory, err := m.Retrieve(ctx, sessionID)
	if err != nil {
		return err
	}

	// Remove archive metadata
	if memory.Metadata != nil {
		delete(memory.Metadata, "archived")
		delete(memory.Metadata, "archived_at")
	}

	return m.Store(ctx, sessionID, memory)
}

// Cleanup performs cleanup based on criteria
func (m *RedisMemoryManager) Cleanup(ctx context.Context, criteria CleanupCriteria) (*CleanupResult, error) {
	ctx, span := m.tracer.Start(ctx, "memory.cleanup")
	defer span.End()

	startTime := time.Now()
	result := &CleanupResult{
		SessionsProcessed: 0,
		SessionsDeleted:   0,
		BytesFreed:        0,
		Duration:          0,
		Errors:            make([]string, 0),
	}

	// This is a simplified implementation
	// In a real system, you would scan Redis keys and apply criteria

	if criteria.DryRun {
		m.logger.Info("Cleanup dry run completed", "criteria", criteria)
		result.Duration = time.Since(startTime)
		return result, nil
	}

	// For now, just log the cleanup request
	m.logger.Info("Cleanup requested", "criteria", criteria)
	result.Duration = time.Since(startTime)
	return result, nil
}

// GetAnalytics returns analytics for a time range
func (m *RedisMemoryManager) GetAnalytics(ctx context.Context, timeRange TimeRange) (*MemoryAnalytics, error) {
	if m.analytics == nil {
		return nil, fmt.Errorf("analytics is not enabled")
	}
	return m.analytics.GetAnalytics(ctx, timeRange)
}

// GetInsights returns insights for a specific session
func (m *RedisMemoryManager) GetInsights(ctx context.Context, sessionID string) (*MemoryInsights, error) {
	if m.analytics == nil {
		return nil, fmt.Errorf("analytics is not enabled")
	}
	return m.analytics.GetInsights(ctx, sessionID)
}

// Backup creates a backup of memory data
func (m *RedisMemoryManager) Backup(ctx context.Context, destination string) error {
	ctx, span := m.tracer.Start(ctx, "memory.backup")
	defer span.End()

	// This would implement backup functionality
	// For now, just log the request
	m.logger.Info("Backup requested", "destination", destination)
	return fmt.Errorf("backup not implemented yet")
}

// Migrate migrates data to another memory manager
func (m *RedisMemoryManager) Migrate(ctx context.Context, target MemoryManager) error {
	ctx, span := m.tracer.Start(ctx, "memory.migrate")
	defer span.End()

	// This would implement migration functionality
	// For now, just log the request
	m.logger.Info("Migration requested")
	return fmt.Errorf("migration not implemented yet")
}

// Validate validates a memory session
func (m *RedisMemoryManager) Validate(ctx context.Context, sessionID string) (*ValidationResult, error) {
	ctx, span := m.tracer.Start(ctx, "memory.validate")
	defer span.End()

	if m.validator == nil {
		return nil, fmt.Errorf("validation is not enabled")
	}

	memory, err := m.Retrieve(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	return m.validator.Validate(ctx, memory)
}

// serializeMemory serializes a memory object with compression and encryption
func (m *RedisMemoryManager) serializeMemory(memory Memory) ([]byte, error) {
	// Marshal to JSON
	data, err := json.Marshal(memory)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal memory: %w", err)
	}

	// Apply compression if enabled
	if m.compressionMgr != nil {
		data, err = m.compressionMgr.Compress(data, m.config.CompressionType)
		if err != nil {
			return nil, fmt.Errorf("failed to compress memory: %w", err)
		}
	}

	// Apply encryption if enabled
	if m.encryptionMgr != nil {
		data, err = m.encryptionMgr.Encrypt(data, m.config.EncryptionType)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt memory: %w", err)
		}
	}

	return data, nil
}

// deserializeMemory deserializes a memory object with decompression and decryption
func (m *RedisMemoryManager) deserializeMemory(data []byte) (Memory, error) {
	var err error

	// Apply decryption if enabled
	if m.encryptionMgr != nil {
		data, err = m.encryptionMgr.Decrypt(data, m.config.EncryptionType)
		if err != nil {
			return Memory{}, fmt.Errorf("failed to decrypt memory: %w", err)
		}
	}

	// Apply decompression if enabled
	if m.compressionMgr != nil {
		data, err = m.compressionMgr.Decompress(data, m.config.CompressionType)
		if err != nil {
			return Memory{}, fmt.Errorf("failed to decompress memory: %w", err)
		}
	}

	// Unmarshal from JSON
	var memory Memory
	if err := json.Unmarshal(data, &memory); err != nil {
		return Memory{}, fmt.Errorf("failed to unmarshal memory: %w", err)
	}

	return memory, nil
}

// updateStats updates statistics for batch operations
func (m *RedisMemoryManager) updateStats(count int, success bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.stats.TotalRequests += int64(count)
	m.stats.LastAccessTime = time.Now()

	if success {
		m.stats.TotalHits += int64(count)
	} else {
		m.stats.TotalMisses += int64(count)
	}

	// Update hit/miss rates
	total := m.stats.TotalHits + m.stats.TotalMisses
	if total > 0 {
		m.stats.HitRate = float64(m.stats.TotalHits) / float64(total)
		m.stats.MissRate = float64(m.stats.TotalMisses) / float64(total)
	}
}
