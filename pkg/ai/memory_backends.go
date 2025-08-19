package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// InMemoryBackend provides an in-memory storage backend for testing
type InMemoryBackend struct {
	memories map[string]Memory
	stats    MemoryStats
	mutex    sync.RWMutex
}

// NewInMemoryBackend creates a new in-memory storage backend
func NewInMemoryBackend() *InMemoryBackend {
	return &InMemoryBackend{
		memories: make(map[string]Memory),
		stats:    MemoryStats{},
	}
}

// Store stores a memory in memory
func (imb *InMemoryBackend) Store(ctx context.Context, sessionID string, memory Memory) error {
	imb.mutex.Lock()
	defer imb.mutex.Unlock()

	imb.memories[sessionID] = memory
	imb.updateStats()
	return nil
}

// Retrieve retrieves a memory from memory
func (imb *InMemoryBackend) Retrieve(ctx context.Context, sessionID string) (Memory, error) {
	imb.mutex.RLock()
	defer imb.mutex.RUnlock()

	memory, exists := imb.memories[sessionID]
	if !exists {
		imb.stats.TotalMisses++
		return Memory{}, fmt.Errorf("memory not found for session: %s", sessionID)
	}

	imb.stats.TotalHits++
	return memory, nil
}

// Search performs a simple search in memory
func (imb *InMemoryBackend) Search(ctx context.Context, query string, limit int) ([]Memory, error) {
	imb.mutex.RLock()
	defer imb.mutex.RUnlock()

	var results []Memory
	queryLower := strings.ToLower(query)

	for _, memory := range imb.memories {
		if imb.matchesQuery(memory, queryLower) {
			results = append(results, memory)
			if len(results) >= limit {
				break
			}
		}
	}

	return results, nil
}

// Clear removes a memory from storage
func (imb *InMemoryBackend) Clear(ctx context.Context, sessionID string) error {
	imb.mutex.Lock()
	defer imb.mutex.Unlock()

	delete(imb.memories, sessionID)
	imb.updateStats()
	return nil
}

// GetStats returns memory statistics
func (imb *InMemoryBackend) GetStats() MemoryStats {
	imb.mutex.RLock()
	defer imb.mutex.RUnlock()
	return imb.stats
}

// IsHealthy checks if the backend is healthy
func (imb *InMemoryBackend) IsHealthy(ctx context.Context) bool {
	return true
}

// BatchStore stores multiple memories
func (imb *InMemoryBackend) BatchStore(ctx context.Context, memories map[string]Memory) error {
	imb.mutex.Lock()
	defer imb.mutex.Unlock()

	for sessionID, memory := range memories {
		imb.memories[sessionID] = memory
	}
	imb.updateStats()
	return nil
}

// BatchRetrieve retrieves multiple memories
func (imb *InMemoryBackend) BatchRetrieve(ctx context.Context, sessionIDs []string) (map[string]Memory, error) {
	imb.mutex.RLock()
	defer imb.mutex.RUnlock()

	results := make(map[string]Memory)
	for _, sessionID := range sessionIDs {
		if memory, exists := imb.memories[sessionID]; exists {
			results[sessionID] = memory
			imb.stats.TotalHits++
		} else {
			imb.stats.TotalMisses++
		}
	}

	return results, nil
}

// Helper methods for InMemoryBackend

func (imb *InMemoryBackend) matchesQuery(memory Memory, query string) bool {
	// Search in messages
	for _, msg := range memory.Messages {
		if strings.Contains(strings.ToLower(msg.Content), query) {
			return true
		}
	}

	// Search in context
	for key, value := range memory.Context {
		if strings.Contains(strings.ToLower(key), query) ||
			strings.Contains(strings.ToLower(fmt.Sprintf("%v", value)), query) {
			return true
		}
	}

	return false
}

func (imb *InMemoryBackend) updateStats() {
	imb.stats.TotalMemories = int64(len(imb.memories))
	imb.stats.ActiveSessions = int64(len(imb.memories))
	imb.stats.LastAccessTime = time.Now()

	// Calculate average size (simplified)
	if len(imb.memories) > 0 {
		totalSize := int64(0)
		for _, memory := range imb.memories {
			data, _ := json.Marshal(memory)
			totalSize += int64(len(data))
		}
		imb.stats.AverageSize = totalSize / int64(len(imb.memories))
	}

	// Calculate hit rate
	total := imb.stats.TotalHits + imb.stats.TotalMisses
	if total > 0 {
		imb.stats.HitRate = float64(imb.stats.TotalHits) / float64(total)
		imb.stats.MissRate = float64(imb.stats.TotalMisses) / float64(total)
	}
}

// FileBackend provides a file-based storage backend
type FileBackend struct {
	basePath string
	stats    MemoryStats
	mutex    sync.RWMutex
}

// NewFileBackend creates a new file-based storage backend
func NewFileBackend(basePath string) (*FileBackend, error) {
	// Ensure base directory exists
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	return &FileBackend{
		basePath: basePath,
		stats:    MemoryStats{},
	}, nil
}

// Store stores a memory to a file
func (fb *FileBackend) Store(ctx context.Context, sessionID string, memory Memory) error {
	fb.mutex.Lock()
	defer fb.mutex.Unlock()

	filePath := fb.getFilePath(sessionID)
	
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Marshal memory to JSON
	data, err := json.MarshalIndent(memory, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal memory: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fb.updateStats()
	return nil
}

// Retrieve retrieves a memory from a file
func (fb *FileBackend) Retrieve(ctx context.Context, sessionID string) (Memory, error) {
	fb.mutex.RLock()
	defer fb.mutex.RUnlock()

	filePath := fb.getFilePath(sessionID)
	
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fb.stats.TotalMisses++
		return Memory{}, fmt.Errorf("memory not found for session: %s", sessionID)
	}

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return Memory{}, fmt.Errorf("failed to read file: %w", err)
	}

	// Unmarshal JSON
	var memory Memory
	if err := json.Unmarshal(data, &memory); err != nil {
		return Memory{}, fmt.Errorf("failed to unmarshal memory: %w", err)
	}

	fb.stats.TotalHits++
	return memory, nil
}

// Search performs a file-based search
func (fb *FileBackend) Search(ctx context.Context, query string, limit int) ([]Memory, error) {
	fb.mutex.RLock()
	defer fb.mutex.RUnlock()

	var results []Memory
	queryLower := strings.ToLower(query)
	count := 0

	// Walk through all files
	err := filepath.WalkDir(fb.basePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		if count >= limit {
			return filepath.SkipDir
		}

		// Read and check file
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip files that can't be read
		}

		var memory Memory
		if err := json.Unmarshal(data, &memory); err != nil {
			return nil // Skip invalid files
		}

		if fb.matchesQuery(memory, queryLower) {
			results = append(results, memory)
			count++
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	return results, nil
}

// Clear removes a memory file
func (fb *FileBackend) Clear(ctx context.Context, sessionID string) error {
	fb.mutex.Lock()
	defer fb.mutex.Unlock()

	filePath := fb.getFilePath(sessionID)
	
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove file: %w", err)
	}

	fb.updateStats()
	return nil
}

// GetStats returns file backend statistics
func (fb *FileBackend) GetStats() MemoryStats {
	fb.mutex.RLock()
	defer fb.mutex.RUnlock()
	return fb.stats
}

// IsHealthy checks if the file backend is healthy
func (fb *FileBackend) IsHealthy(ctx context.Context) bool {
	// Check if base directory is accessible
	_, err := os.Stat(fb.basePath)
	return err == nil
}

// BatchStore stores multiple memories to files
func (fb *FileBackend) BatchStore(ctx context.Context, memories map[string]Memory) error {
	fb.mutex.Lock()
	defer fb.mutex.Unlock()

	for sessionID, memory := range memories {
		filePath := fb.getFilePath(sessionID)
		
		// Ensure directory exists
		dir := filepath.Dir(filePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory for %s: %w", sessionID, err)
		}

		// Marshal and write
		data, err := json.MarshalIndent(memory, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal memory for %s: %w", sessionID, err)
		}

		if err := os.WriteFile(filePath, data, 0644); err != nil {
			return fmt.Errorf("failed to write file for %s: %w", sessionID, err)
		}
	}

	fb.updateStats()
	return nil
}

// BatchRetrieve retrieves multiple memories from files
func (fb *FileBackend) BatchRetrieve(ctx context.Context, sessionIDs []string) (map[string]Memory, error) {
	fb.mutex.RLock()
	defer fb.mutex.RUnlock()

	results := make(map[string]Memory)
	
	for _, sessionID := range sessionIDs {
		filePath := fb.getFilePath(sessionID)
		
		if data, err := os.ReadFile(filePath); err == nil {
			var memory Memory
			if err := json.Unmarshal(data, &memory); err == nil {
				results[sessionID] = memory
				fb.stats.TotalHits++
			}
		} else {
			fb.stats.TotalMisses++
		}
	}

	return results, nil
}

// Helper methods for FileBackend

func (fb *FileBackend) getFilePath(sessionID string) string {
	// Create a hierarchical directory structure based on session ID
	// This helps with performance when dealing with many files
	if len(sessionID) >= 4 {
		return filepath.Join(fb.basePath, sessionID[:2], sessionID[2:4], sessionID+".json")
	}
	return filepath.Join(fb.basePath, sessionID+".json")
}

func (fb *FileBackend) matchesQuery(memory Memory, query string) bool {
	// Search in messages
	for _, msg := range memory.Messages {
		if strings.Contains(strings.ToLower(msg.Content), query) {
			return true
		}
	}

	// Search in context
	for key, value := range memory.Context {
		if strings.Contains(strings.ToLower(key), query) ||
			strings.Contains(strings.ToLower(fmt.Sprintf("%v", value)), query) {
			return true
		}
	}

	return false
}

func (fb *FileBackend) updateStats() {
	// Count files in directory
	count := int64(0)
	filepath.WalkDir(fb.basePath, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".json") {
			count++
		}
		return nil
	})

	fb.stats.TotalMemories = count
	fb.stats.ActiveSessions = count
	fb.stats.LastAccessTime = time.Now()

	// Calculate hit rate
	total := fb.stats.TotalHits + fb.stats.TotalMisses
	if total > 0 {
		fb.stats.HitRate = float64(fb.stats.TotalHits) / float64(total)
		fb.stats.MissRate = float64(fb.stats.TotalMisses) / float64(total)
	}
}
