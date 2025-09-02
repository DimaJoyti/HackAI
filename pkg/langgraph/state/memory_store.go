package state

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// MemoryStateStore implements StateStore using in-memory storage
type MemoryStateStore struct {
	data     map[string]*StateEntry
	watchers map[string][]chan StateChangeEvent
	mutex    sync.RWMutex
	watchMux sync.RWMutex
}

// NewMemoryStateStore creates a new in-memory state store
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		data:     make(map[string]*StateEntry),
		watchers: make(map[string][]chan StateChangeEvent),
	}
}

// Get retrieves a state entry by key
func (mss *MemoryStateStore) Get(ctx context.Context, key StateKey) (*StateEntry, error) {
	mss.mutex.RLock()
	defer mss.mutex.RUnlock()

	keyStr := mss.keyToString(key)
	entry, exists := mss.data[keyStr]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyStr)
	}

	// Return a copy to avoid external modifications
	entryCopy := *entry
	return &entryCopy, nil
}

// Set stores a state entry
func (mss *MemoryStateStore) Set(ctx context.Context, key StateKey, entry *StateEntry) error {
	mss.mutex.Lock()
	defer mss.mutex.Unlock()

	keyStr := mss.keyToString(key)

	// Check if this is an update or create
	var oldEntry *StateEntry
	if existing, exists := mss.data[keyStr]; exists {
		oldEntry = existing
	}

	// Store the entry
	entryCopy := *entry
	mss.data[keyStr] = &entryCopy

	// Emit change event
	eventType := StateChangeCreated
	var oldValue interface{}
	if oldEntry != nil {
		eventType = StateChangeUpdated
		oldValue = oldEntry.Value
	}

	mss.emitChangeEvent(StateChangeEvent{
		Type:      eventType,
		Key:       key,
		OldValue:  oldValue,
		NewValue:  entry.Value,
		Timestamp: time.Now(),
		Source:    "memory_store",
	})

	return nil
}

// Delete removes a state entry
func (mss *MemoryStateStore) Delete(ctx context.Context, key StateKey) error {
	mss.mutex.Lock()
	defer mss.mutex.Unlock()

	keyStr := mss.keyToString(key)

	// Get old value for event
	var oldValue interface{}
	if existing, exists := mss.data[keyStr]; exists {
		oldValue = existing.Value
	}

	delete(mss.data, keyStr)

	// Emit change event
	mss.emitChangeEvent(StateChangeEvent{
		Type:      StateChangeDeleted,
		Key:       key,
		OldValue:  oldValue,
		Timestamp: time.Now(),
		Source:    "memory_store",
	})

	return nil
}

// List returns all entries matching a pattern
func (mss *MemoryStateStore) List(ctx context.Context, pattern StateKeyPattern) ([]*StateEntry, error) {
	mss.mutex.RLock()
	defer mss.mutex.RUnlock()

	var entries []*StateEntry
	for _, entry := range mss.data {
		if mss.matchesPattern(entry.Key, pattern) {
			entryCopy := *entry
			entries = append(entries, &entryCopy)
		}
	}

	return entries, nil
}

// Exists checks if a key exists
func (mss *MemoryStateStore) Exists(ctx context.Context, key StateKey) (bool, error) {
	mss.mutex.RLock()
	defer mss.mutex.RUnlock()

	keyStr := mss.keyToString(key)
	_, exists := mss.data[keyStr]
	return exists, nil
}

// GetMetadata retrieves metadata for a key
func (mss *MemoryStateStore) GetMetadata(ctx context.Context, key StateKey) (*StateMetadata, error) {
	entry, err := mss.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	return entry.Metadata, nil
}

// SetMetadata updates metadata for a key
func (mss *MemoryStateStore) SetMetadata(ctx context.Context, key StateKey, metadata *StateMetadata) error {
	mss.mutex.Lock()
	defer mss.mutex.Unlock()

	keyStr := mss.keyToString(key)
	entry, exists := mss.data[keyStr]
	if !exists {
		return fmt.Errorf("key not found: %s", keyStr)
	}

	entry.Metadata = metadata
	entry.UpdatedAt = time.Now()

	return nil
}

// Batch performs multiple operations atomically
func (mss *MemoryStateStore) Batch(ctx context.Context, operations []BatchOperation) error {
	mss.mutex.Lock()
	defer mss.mutex.Unlock()

	// Store original state for rollback
	originalData := make(map[string]*StateEntry)
	for key, entry := range mss.data {
		entryCopy := *entry
		originalData[key] = &entryCopy
	}

	// Apply operations
	for i, op := range operations {
		switch op.Type {
		case BatchOpSet:
			if op.Entry == nil {
				// Rollback
				mss.data = originalData
				return fmt.Errorf("operation %d: entry is nil for set operation", i)
			}
			keyStr := mss.keyToString(op.Key)
			entryCopy := *op.Entry
			mss.data[keyStr] = &entryCopy

		case BatchOpDelete:
			keyStr := mss.keyToString(op.Key)
			delete(mss.data, keyStr)

		case BatchOpUpdate:
			if op.Entry == nil {
				// Rollback
				mss.data = originalData
				return fmt.Errorf("operation %d: entry is nil for update operation", i)
			}
			keyStr := mss.keyToString(op.Key)
			if _, exists := mss.data[keyStr]; !exists {
				// Rollback
				mss.data = originalData
				return fmt.Errorf("operation %d: key not found for update: %s", i, keyStr)
			}
			entryCopy := *op.Entry
			mss.data[keyStr] = &entryCopy

		default:
			// Rollback
			mss.data = originalData
			return fmt.Errorf("operation %d: unsupported operation type: %s", i, op.Type)
		}
	}

	// Emit batch change event
	mss.emitChangeEvent(StateChangeEvent{
		Type:      StateChangeUpdated,
		Timestamp: time.Now(),
		Source:    "memory_store_batch",
		Metadata: map[string]interface{}{
			"operation_count": len(operations),
		},
	})

	return nil
}

// Watch watches for changes matching a pattern
func (mss *MemoryStateStore) Watch(ctx context.Context, pattern StateKeyPattern) (<-chan StateChangeEvent, error) {
	mss.watchMux.Lock()
	defer mss.watchMux.Unlock()

	ch := make(chan StateChangeEvent, 100) // Buffered channel
	patternStr := mss.patternToString(pattern)

	mss.watchers[patternStr] = append(mss.watchers[patternStr], ch)

	// Start a goroutine to handle context cancellation
	go func() {
		<-ctx.Done()
		mss.removeWatcher(patternStr, ch)
		close(ch)
	}()

	return ch, nil
}

// Helper methods

func (mss *MemoryStateStore) keyToString(key StateKey) string {
	return fmt.Sprintf("%s:%s:%s:%s", key.Namespace, key.GraphID, key.NodeID, key.Key)
}

func (mss *MemoryStateStore) patternToString(pattern StateKeyPattern) string {
	return fmt.Sprintf("%s:%s:%s:%s", pattern.Namespace, pattern.GraphID, pattern.NodeID, pattern.KeyPrefix)
}

func (mss *MemoryStateStore) matchesPattern(key StateKey, pattern StateKeyPattern) bool {
	// Check namespace
	if pattern.Namespace != "*" && pattern.Namespace != "" && key.Namespace != pattern.Namespace {
		return false
	}

	// Check graph ID
	if pattern.GraphID != "*" && pattern.GraphID != "" && key.GraphID != pattern.GraphID {
		return false
	}

	// Check node ID
	if pattern.NodeID != "*" && pattern.NodeID != "" && key.NodeID != pattern.NodeID {
		return false
	}

	// Check key prefix
	if pattern.KeyPrefix != "" && !strings.HasPrefix(key.Key, pattern.KeyPrefix) {
		return false
	}

	return true
}

func (mss *MemoryStateStore) emitChangeEvent(event StateChangeEvent) {
	mss.watchMux.RLock()
	defer mss.watchMux.RUnlock()

	// Send to all matching watchers
	for patternStr, watchers := range mss.watchers {
		pattern := mss.parsePatternString(patternStr)
		if mss.matchesPattern(event.Key, pattern) {
			for _, ch := range watchers {
				select {
				case ch <- event:
					// Event sent successfully
				default:
					// Channel is full, skip this watcher
				}
			}
		}
	}
}

func (mss *MemoryStateStore) parsePatternString(patternStr string) StateKeyPattern {
	parts := strings.Split(patternStr, ":")
	if len(parts) != 4 {
		return StateKeyPattern{}
	}

	return StateKeyPattern{
		Namespace: parts[0],
		GraphID:   parts[1],
		NodeID:    parts[2],
		KeyPrefix: parts[3],
	}
}

func (mss *MemoryStateStore) removeWatcher(patternStr string, ch chan StateChangeEvent) {
	mss.watchMux.Lock()
	defer mss.watchMux.Unlock()

	watchers := mss.watchers[patternStr]
	for i, watcher := range watchers {
		if watcher == ch {
			// Remove this watcher
			mss.watchers[patternStr] = append(watchers[:i], watchers[i+1:]...)
			break
		}
	}

	// Clean up empty watcher lists
	if len(mss.watchers[patternStr]) == 0 {
		delete(mss.watchers, patternStr)
	}
}

// GetStats returns store statistics
func (mss *MemoryStateStore) GetStats() *StoreStats {
	mss.mutex.RLock()
	defer mss.mutex.RUnlock()

	stats := &StoreStats{
		TotalEntries: int64(len(mss.data)),
		Timestamp:    time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	var totalSize int64
	namespaces := make(map[string]int)
	graphIDs := make(map[string]int)

	for _, entry := range mss.data {
		if entry.Metadata != nil {
			totalSize += entry.Metadata.Size
		}
		namespaces[entry.Key.Namespace]++
		graphIDs[entry.Key.GraphID]++
	}

	stats.TotalSize = totalSize
	stats.Metadata["namespaces"] = len(namespaces)
	stats.Metadata["graph_ids"] = len(graphIDs)

	if stats.TotalEntries > 0 {
		stats.AverageSize = float64(totalSize) / float64(stats.TotalEntries)
	}

	return stats
}

// StoreStats holds store statistics
type StoreStats struct {
	TotalEntries int64                  `json:"total_entries"`
	TotalSize    int64                  `json:"total_size"`
	AverageSize  float64                `json:"average_size"`
	Timestamp    time.Time              `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Clear removes all entries from the store
func (mss *MemoryStateStore) Clear() {
	mss.mutex.Lock()
	defer mss.mutex.Unlock()

	mss.data = make(map[string]*StateEntry)

	// Emit clear event
	mss.emitChangeEvent(StateChangeEvent{
		Type:      StateChangeDeleted,
		Timestamp: time.Now(),
		Source:    "memory_store_clear",
		Metadata: map[string]interface{}{
			"operation": "clear_all",
		},
	})
}

// Size returns the number of entries in the store
func (mss *MemoryStateStore) Size() int {
	mss.mutex.RLock()
	defer mss.mutex.RUnlock()

	return len(mss.data)
}

// Keys returns all keys in the store
func (mss *MemoryStateStore) Keys() []StateKey {
	mss.mutex.RLock()
	defer mss.mutex.RUnlock()

	keys := make([]StateKey, 0, len(mss.data))
	for _, entry := range mss.data {
		keys = append(keys, entry.Key)
	}

	return keys
}

// Close closes the store and cleans up resources
func (mss *MemoryStateStore) Close() error {
	mss.watchMux.Lock()
	defer mss.watchMux.Unlock()

	// Close all watcher channels
	for _, watchers := range mss.watchers {
		for _, ch := range watchers {
			close(ch)
		}
	}

	mss.watchers = make(map[string][]chan StateChangeEvent)
	return nil
}
