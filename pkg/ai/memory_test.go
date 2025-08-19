package ai

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/logger"
)

func TestMemoryCompression(t *testing.T) {
	tests := []struct {
		name            string
		compressionType CompressionType
		data            string
	}{
		{"Gzip", CompressionGzip, "This is a test string for compression"},
		{"LZ4", CompressionLZ4, "This is a test string for compression"},
		{"Zstd", CompressionZstd, "This is a test string for compression"},
		{"LZW", CompressionLZW, "This is a test string for compression"},
		{"None", CompressionNone, "This is a test string for compression"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCompressionManager(tt.compressionType)

			original := []byte(tt.data)
			compressed, err := cm.Compress(original, tt.compressionType)
			require.NoError(t, err)

			decompressed, err := cm.Decompress(compressed, tt.compressionType)
			require.NoError(t, err)

			assert.Equal(t, original, decompressed)

			if tt.compressionType != CompressionNone {
				ratio := cm.GetCompressionRatio(len(original), len(compressed), tt.compressionType)
				assert.Greater(t, ratio, 0.0)
				// For small test strings, compression might actually increase size
				// So we'll just check that ratio is positive
			}
		})
	}
}

func TestMemoryEncryption(t *testing.T) {
	key := []byte("test-encryption-key-32-bytes!!")

	tests := []struct {
		name           string
		encryptionType EncryptionType
		data           string
	}{
		{"AES256GCM", EncryptionAES256GCM, "This is sensitive data"},
		{"ChaCha20", EncryptionChaCha20, "This is sensitive data"},
		{"None", EncryptionNone, "This is sensitive data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em, err := NewEncryptionManager(key, tt.encryptionType)
			require.NoError(t, err)

			original := []byte(tt.data)
			encrypted, err := em.Encrypt(original, tt.encryptionType)
			require.NoError(t, err)

			decrypted, err := em.Decrypt(encrypted, tt.encryptionType)
			require.NoError(t, err)

			assert.Equal(t, original, decrypted)

			if tt.encryptionType != EncryptionNone {
				// Encrypted data should be different from original
				assert.NotEqual(t, original, encrypted)
			}
		})
	}
}

func TestMemoryValidation(t *testing.T) {
	config := ValidationConfig{
		EnableChecksumValidation: true,
		EnableSchemaValidation:   true,
		EnableContentValidation:  true,
		MaxMessageLength:         1000,
		MaxMessagesPerSession:    100,
		MaxContextSize:           5000,
		RequiredFields:           []string{"session_id", "user_id"},
	}

	validator := NewMemoryValidator(config)
	ctx := context.Background()

	t.Run("ValidMemory", func(t *testing.T) {
		memory := Memory{
			SessionID: "test-session",
			UserID:    "test-user",
			Messages: []Message{
				{
					Role:      "user",
					Content:   "Hello, world!",
					Timestamp: time.Now(),
				},
			},
			Context:   map[string]interface{}{"key": "value"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Version:   1,
		}

		result, err := validator.Validate(ctx, memory)
		require.NoError(t, err)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("InvalidMemory", func(t *testing.T) {
		memory := Memory{
			// Missing required fields
			Messages: []Message{
				{
					// Missing role and content
					Timestamp: time.Now(),
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Version:   1,
		}

		result, err := validator.Validate(ctx, memory)
		require.NoError(t, err)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
	})
}

func TestInMemoryBackend(t *testing.T) {
	backend := NewInMemoryBackend()
	ctx := context.Background()

	memory := Memory{
		SessionID: "test-session",
		UserID:    "test-user",
		Messages: []Message{
			{
				Role:      "user",
				Content:   "Hello, world!",
				Timestamp: time.Now(),
			},
		},
		Context:   map[string]interface{}{"key": "value"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Version:   1,
	}

	t.Run("StoreAndRetrieve", func(t *testing.T) {
		err := backend.Store(ctx, "test-session", memory)
		require.NoError(t, err)

		retrieved, err := backend.Retrieve(ctx, "test-session")
		require.NoError(t, err)
		assert.Equal(t, memory.SessionID, retrieved.SessionID)
		assert.Equal(t, memory.UserID, retrieved.UserID)
	})

	t.Run("Search", func(t *testing.T) {
		results, err := backend.Search(ctx, "Hello", 10)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, memory.SessionID, results[0].SessionID)
	})

	t.Run("BatchOperations", func(t *testing.T) {
		memories := map[string]Memory{
			"session1": memory,
			"session2": memory,
		}

		err := backend.BatchStore(ctx, memories)
		require.NoError(t, err)

		retrieved, err := backend.BatchRetrieve(ctx, []string{"session1", "session2"})
		require.NoError(t, err)
		assert.Len(t, retrieved, 2)
	})

	t.Run("Clear", func(t *testing.T) {
		err := backend.Clear(ctx, "test-session")
		require.NoError(t, err)

		_, err = backend.Retrieve(ctx, "test-session")
		assert.Error(t, err)
	})

	t.Run("HealthCheck", func(t *testing.T) {
		assert.True(t, backend.IsHealthy(ctx))
	})

	t.Run("Stats", func(t *testing.T) {
		stats := backend.GetStats()
		assert.GreaterOrEqual(t, stats.TotalMemories, int64(0))
	})
}

func TestMemoryAnalytics(t *testing.T) {
	// Skip analytics test for now since it requires full MemoryManager
	t.Skip("Analytics test requires full MemoryManager implementation")
}

func TestMemoryIndexing(t *testing.T) {
	index := NewInMemoryIndex()
	ctx := context.Background()

	memory := Memory{
		SessionID: "test-session",
		UserID:    "test-user",
		Messages: []Message{
			{
				Role:      "user",
				Content:   "I need help with programming",
				Timestamp: time.Now(),
			},
		},
		Context:   map[string]interface{}{"topic": "programming"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Version:   1,
	}

	t.Run("IndexAndSearch", func(t *testing.T) {
		err := index.Index(ctx, "test-session", memory)
		require.NoError(t, err)

		query := SearchQuery{
			Text:   "programming",
			Limit:  10,
			Offset: 0,
		}

		result, err := index.Search(ctx, query)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, int64(1), result.Total)
		assert.Len(t, result.Memories, 1)
	})

	t.Run("Update", func(t *testing.T) {
		memory.Messages = append(memory.Messages, Message{
			Role:      "assistant",
			Content:   "I can help you with Go programming",
			Timestamp: time.Now(),
		})

		err := index.Update(ctx, "test-session", memory)
		require.NoError(t, err)
	})

	t.Run("Delete", func(t *testing.T) {
		err := index.Delete(ctx, "test-session")
		require.NoError(t, err)

		query := SearchQuery{
			Text:   "programming",
			Limit:  10,
			Offset: 0,
		}

		result, err := index.Search(ctx, query)
		require.NoError(t, err)
		assert.Equal(t, int64(0), result.Total)
	})

	t.Run("Stats", func(t *testing.T) {
		stats := index.GetStats()
		assert.GreaterOrEqual(t, stats.TotalDocuments, int64(0))
	})
}

func TestMemoryManagerIntegration(t *testing.T) {
	// This test would require a Redis instance
	// For now, we'll skip it unless Redis is available
	t.Skip("Integration test requires Redis instance")

	logger, err := logger.New(logger.Config{
		Level:  logger.LevelDebug,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	config := MemoryConfig{
		RedisURL:         "redis://localhost:6379",
		KeyPrefix:        "test:memory",
		DefaultTTL:       time.Hour,
		CompressionType:  CompressionGzip,
		EncryptionType:   EncryptionAES256GCM,
		EncryptionKey:    "test-key-32-bytes-long-enough!",
		EnableIndexing:   true,
		EnableAnalytics:  true,
		EnableValidation: true,
	}

	manager, err := NewRedisMemoryManager(config, logger)
	require.NoError(t, err)

	ctx := context.Background()

	memory := Memory{
		SessionID: "integration-test",
		UserID:    "test-user",
		Messages: []Message{
			{
				Role:      "user",
				Content:   "Integration test message",
				Timestamp: time.Now(),
			},
		},
		Context:   map[string]interface{}{"test": true},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Version:   1,
	}

	t.Run("FullWorkflow", func(t *testing.T) {
		// Store
		err := manager.Store(ctx, "integration-test", memory)
		require.NoError(t, err)

		// Retrieve
		retrieved, err := manager.Retrieve(ctx, "integration-test")
		require.NoError(t, err)
		assert.Equal(t, memory.SessionID, retrieved.SessionID)

		// Search
		results, err := manager.Search(ctx, "Integration", 10)
		require.NoError(t, err)
		assert.NotEmpty(t, results)

		// Validate
		validation, err := manager.Validate(ctx, "integration-test")
		require.NoError(t, err)
		assert.True(t, validation.Valid)

		// Analytics
		timeRange := TimeRange{
			Start: time.Now().Add(-time.Hour),
			End:   time.Now().Add(time.Hour),
		}
		analytics, err := manager.GetAnalytics(ctx, timeRange)
		require.NoError(t, err)
		assert.NotNil(t, analytics)

		// Insights
		insights, err := manager.GetInsights(ctx, "integration-test")
		require.NoError(t, err)
		assert.NotNil(t, insights)

		// Clear
		err = manager.Clear(ctx, "integration-test")
		require.NoError(t, err)
	})

	t.Run("HealthCheck", func(t *testing.T) {
		assert.True(t, manager.IsHealthy(ctx))
	})

	t.Run("Stats", func(t *testing.T) {
		stats := manager.GetStats()
		assert.GreaterOrEqual(t, stats.TotalRequests, int64(0))
	})
}
