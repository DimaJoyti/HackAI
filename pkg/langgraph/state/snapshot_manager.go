package state

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// SnapshotManager manages state snapshots for backup and recovery
type SnapshotManager struct {
	store           StateStore
	snapshots       map[string]*StateSnapshot
	interval        time.Duration
	logger          *logger.Logger
	mutex           sync.RWMutex
	autoSnapshotTicker *time.Ticker
	autoSnapshotDone   chan bool
}

// StateSnapshot represents a point-in-time snapshot of state
type StateSnapshot struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Pattern     StateKeyPattern        `json:"pattern"`
	Entries     map[string]*StateEntry `json:"entries"`
	CreatedAt   time.Time              `json:"created_at"`
	CreatedBy   string                 `json:"created_by"`
	Size        int64                  `json:"size"`
	EntryCount  int                    `json:"entry_count"`
	Compressed  bool                   `json:"compressed"`
	Checksum    string                 `json:"checksum"`
	Tags        map[string]string      `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
}

// SnapshotDiff represents differences between two snapshots
type SnapshotDiff struct {
	FromSnapshot string                 `json:"from_snapshot"`
	ToSnapshot   string                 `json:"to_snapshot"`
	Added        []StateKey             `json:"added"`
	Modified     []StateKey             `json:"modified"`
	Deleted      []StateKey             `json:"deleted"`
	Summary      string                 `json:"summary"`
	CreatedAt    time.Time              `json:"created_at"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// SnapshotPolicy defines snapshot retention and creation policies
type SnapshotPolicy struct {
	AutoSnapshot     bool          `json:"auto_snapshot"`
	Interval         time.Duration `json:"interval"`
	MaxSnapshots     int           `json:"max_snapshots"`
	RetentionPeriod  time.Duration `json:"retention_period"`
	CompressAfter    time.Duration `json:"compress_after"`
	NameTemplate     string        `json:"name_template"`
	IncludePatterns  []StateKeyPattern `json:"include_patterns"`
	ExcludePatterns  []StateKeyPattern `json:"exclude_patterns"`
}

// SnapshotStats holds statistics about snapshots
type SnapshotStats struct {
	TotalSnapshots   int64                  `json:"total_snapshots"`
	TotalSize        int64                  `json:"total_size"`
	CompressedSize   int64                  `json:"compressed_size"`
	CompressionRatio float64                `json:"compression_ratio"`
	OldestSnapshot   *time.Time             `json:"oldest_snapshot,omitempty"`
	NewestSnapshot   *time.Time             `json:"newest_snapshot,omitempty"`
	AverageSize      float64                `json:"average_size"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// NewSnapshotManager creates a new snapshot manager
func NewSnapshotManager(store StateStore, interval time.Duration, logger *logger.Logger) *SnapshotManager {
	sm := &SnapshotManager{
		store:            store,
		snapshots:        make(map[string]*StateSnapshot),
		interval:         interval,
		logger:           logger,
		autoSnapshotDone: make(chan bool),
	}

	// Start auto-snapshot if interval is set
	if interval > 0 {
		sm.autoSnapshotTicker = time.NewTicker(interval)
		go sm.autoSnapshotLoop()
	}

	return sm
}

// CreateSnapshot creates a new snapshot
func (sm *SnapshotManager) CreateSnapshot(ctx context.Context, pattern StateKeyPattern) (*StateSnapshot, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	snapshot := &StateSnapshot{
		ID:          uuid.New().String(),
		Name:        fmt.Sprintf("snapshot_%d", time.Now().Unix()),
		Description: "Automatic snapshot",
		Pattern:     pattern,
		Entries:     make(map[string]*StateEntry),
		CreatedAt:   time.Now(),
		CreatedBy:   "system",
		Tags:        make(map[string]string),
		Metadata:    make(map[string]interface{}),
	}

	// Collect entries matching the pattern
	entries, err := sm.store.List(ctx, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to list entries for snapshot: %w", err)
	}

	var totalSize int64
	for _, entry := range entries {
		keyStr := sm.keyToString(entry.Key)
		snapshot.Entries[keyStr] = entry
		if entry.Metadata != nil {
			totalSize += entry.Metadata.Size
		}
	}

	snapshot.Size = totalSize
	snapshot.EntryCount = len(entries)
	snapshot.Checksum = sm.calculateChecksum(snapshot)

	// Store snapshot
	sm.snapshots[snapshot.ID] = snapshot

	sm.logger.Info("Snapshot created",
		"snapshot_id", snapshot.ID,
		"entries", snapshot.EntryCount,
		"size", snapshot.Size)

	return snapshot, nil
}

// CreateNamedSnapshot creates a snapshot with a specific name
func (sm *SnapshotManager) CreateNamedSnapshot(ctx context.Context, name, description string, pattern StateKeyPattern) (*StateSnapshot, error) {
	snapshot, err := sm.CreateSnapshot(ctx, pattern)
	if err != nil {
		return nil, err
	}

	snapshot.Name = name
	snapshot.Description = description

	return snapshot, nil
}

// GetSnapshot retrieves a snapshot by ID
func (sm *SnapshotManager) GetSnapshot(ctx context.Context, snapshotID string) (*StateSnapshot, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	snapshot, exists := sm.snapshots[snapshotID]
	if !exists {
		return nil, fmt.Errorf("snapshot %s not found", snapshotID)
	}

	return snapshot, nil
}

// ListSnapshots lists all snapshots
func (sm *SnapshotManager) ListSnapshots(ctx context.Context) ([]*StateSnapshot, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	snapshots := make([]*StateSnapshot, 0, len(sm.snapshots))
	for _, snapshot := range sm.snapshots {
		snapshots = append(snapshots, snapshot)
	}

	return snapshots, nil
}

// RestoreSnapshot restores state from a snapshot
func (sm *SnapshotManager) RestoreSnapshot(ctx context.Context, snapshotID string) error {
	sm.mutex.RLock()
	snapshot, exists := sm.snapshots[snapshotID]
	sm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("snapshot %s not found", snapshotID)
	}

	sm.logger.Info("Starting snapshot restoration",
		"snapshot_id", snapshotID,
		"entries", snapshot.EntryCount)

	// Restore all entries from the snapshot
	for _, entry := range snapshot.Entries {
		if err := sm.store.Set(ctx, entry.Key, entry); err != nil {
			return fmt.Errorf("failed to restore entry %s: %w", sm.keyToString(entry.Key), err)
		}
	}

	sm.logger.Info("Snapshot restoration completed",
		"snapshot_id", snapshotID,
		"restored_entries", snapshot.EntryCount)

	return nil
}

// DeleteSnapshot deletes a snapshot
func (sm *SnapshotManager) DeleteSnapshot(ctx context.Context, snapshotID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if _, exists := sm.snapshots[snapshotID]; !exists {
		return fmt.Errorf("snapshot %s not found", snapshotID)
	}

	delete(sm.snapshots, snapshotID)

	sm.logger.Info("Snapshot deleted", "snapshot_id", snapshotID)
	return nil
}

// CompareSnapshots compares two snapshots and returns the differences
func (sm *SnapshotManager) CompareSnapshots(ctx context.Context, fromSnapshotID, toSnapshotID string) (*SnapshotDiff, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	fromSnapshot, exists := sm.snapshots[fromSnapshotID]
	if !exists {
		return nil, fmt.Errorf("from snapshot %s not found", fromSnapshotID)
	}

	toSnapshot, exists := sm.snapshots[toSnapshotID]
	if !exists {
		return nil, fmt.Errorf("to snapshot %s not found", toSnapshotID)
	}

	diff := &SnapshotDiff{
		FromSnapshot: fromSnapshotID,
		ToSnapshot:   toSnapshotID,
		Added:        make([]StateKey, 0),
		Modified:     make([]StateKey, 0),
		Deleted:      make([]StateKey, 0),
		CreatedAt:    time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	// Find added and modified entries
	for keyStr, toEntry := range toSnapshot.Entries {
		if fromEntry, exists := fromSnapshot.Entries[keyStr]; exists {
			// Check if modified
			if sm.entriesEqual(fromEntry, toEntry) {
				diff.Modified = append(diff.Modified, toEntry.Key)
			}
		} else {
			// Added entry
			diff.Added = append(diff.Added, toEntry.Key)
		}
	}

	// Find deleted entries
	for keyStr, fromEntry := range fromSnapshot.Entries {
		if _, exists := toSnapshot.Entries[keyStr]; !exists {
			diff.Deleted = append(diff.Deleted, fromEntry.Key)
		}
	}

	diff.Summary = fmt.Sprintf("Added: %d, Modified: %d, Deleted: %d",
		len(diff.Added), len(diff.Modified), len(diff.Deleted))

	return diff, nil
}

// CompressSnapshot compresses a snapshot to save space
func (sm *SnapshotManager) CompressSnapshot(ctx context.Context, snapshotID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	snapshot, exists := sm.snapshots[snapshotID]
	if !exists {
		return fmt.Errorf("snapshot %s not found", snapshotID)
	}

	if snapshot.Compressed {
		return nil // Already compressed
	}

	// Simulate compression (in production, implement actual compression)
	originalSize := snapshot.Size
	snapshot.Size = int64(float64(originalSize) * 0.7) // Assume 30% compression
	snapshot.Compressed = true

	sm.logger.Info("Snapshot compressed",
		"snapshot_id", snapshotID,
		"original_size", originalSize,
		"compressed_size", snapshot.Size)

	return nil
}

// ApplyPolicy applies a snapshot policy
func (sm *SnapshotManager) ApplyPolicy(ctx context.Context, policy SnapshotPolicy) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now()

	// Clean up old snapshots based on retention policy
	if policy.RetentionPeriod > 0 {
		cutoff := now.Add(-policy.RetentionPeriod)
		for snapshotID, snapshot := range sm.snapshots {
			if snapshot.CreatedAt.Before(cutoff) {
				delete(sm.snapshots, snapshotID)
				sm.logger.Info("Snapshot expired and removed",
					"snapshot_id", snapshotID,
					"created_at", snapshot.CreatedAt)
			}
		}
	}

	// Enforce max snapshots limit
	if policy.MaxSnapshots > 0 && len(sm.snapshots) > policy.MaxSnapshots {
		// Convert to slice and sort by creation time
		snapshots := make([]*StateSnapshot, 0, len(sm.snapshots))
		for _, snapshot := range sm.snapshots {
			snapshots = append(snapshots, snapshot)
		}

		// Sort by creation time (oldest first)
		for i := 0; i < len(snapshots)-1; i++ {
			for j := i + 1; j < len(snapshots); j++ {
				if snapshots[i].CreatedAt.After(snapshots[j].CreatedAt) {
					snapshots[i], snapshots[j] = snapshots[j], snapshots[i]
				}
			}
		}

		// Remove oldest snapshots
		excess := len(snapshots) - policy.MaxSnapshots
		for i := 0; i < excess; i++ {
			delete(sm.snapshots, snapshots[i].ID)
			sm.logger.Info("Snapshot removed due to max limit",
				"snapshot_id", snapshots[i].ID)
		}
	}

	// Compress old snapshots
	if policy.CompressAfter > 0 {
		compressCutoff := now.Add(-policy.CompressAfter)
		for _, snapshot := range sm.snapshots {
			if !snapshot.Compressed && snapshot.CreatedAt.Before(compressCutoff) {
				sm.CompressSnapshot(ctx, snapshot.ID)
			}
		}
	}

	return nil
}

// GetStats returns snapshot statistics
func (sm *SnapshotManager) GetStats() *SnapshotStats {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	stats := &SnapshotStats{
		Metadata: make(map[string]interface{}),
	}

	var totalSize int64
	var compressedSize int64
	var oldestTime *time.Time
	var newestTime *time.Time

	for _, snapshot := range sm.snapshots {
		stats.TotalSnapshots++
		totalSize += snapshot.Size

		if snapshot.Compressed {
			compressedSize += snapshot.Size
		}

		if oldestTime == nil || snapshot.CreatedAt.Before(*oldestTime) {
			oldestTime = &snapshot.CreatedAt
		}
		if newestTime == nil || snapshot.CreatedAt.After(*newestTime) {
			newestTime = &snapshot.CreatedAt
		}
	}

	stats.TotalSize = totalSize
	stats.CompressedSize = compressedSize
	stats.OldestSnapshot = oldestTime
	stats.NewestSnapshot = newestTime

	if stats.TotalSnapshots > 0 {
		stats.AverageSize = float64(totalSize) / float64(stats.TotalSnapshots)
	}

	if totalSize > 0 {
		stats.CompressionRatio = float64(compressedSize) / float64(totalSize)
	}

	return stats
}

// Close closes the snapshot manager
func (sm *SnapshotManager) Close() error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Stop auto-snapshot ticker
	if sm.autoSnapshotTicker != nil {
		sm.autoSnapshotTicker.Stop()
		close(sm.autoSnapshotDone)
	}

	sm.logger.Info("Snapshot manager closed")
	return nil
}

// Helper methods

func (sm *SnapshotManager) keyToString(key StateKey) string {
	return fmt.Sprintf("%s:%s:%s:%s", key.Namespace, key.GraphID, key.NodeID, key.Key)
}

func (sm *SnapshotManager) calculateChecksum(snapshot *StateSnapshot) string {
	// Simplified checksum calculation
	// In production, use a proper hash function
	return fmt.Sprintf("checksum_%s_%d", snapshot.ID, snapshot.CreatedAt.Unix())
}

func (sm *SnapshotManager) entriesEqual(entry1, entry2 *StateEntry) bool {
	// Simplified equality check
	// In production, implement deep comparison
	return fmt.Sprintf("%v", entry1.Value) != fmt.Sprintf("%v", entry2.Value)
}

func (sm *SnapshotManager) autoSnapshotLoop() {
	for {
		select {
		case <-sm.autoSnapshotTicker.C:
			// Create automatic snapshot
			pattern := StateKeyPattern{
				Namespace: "*",
				GraphID:   "*",
				NodeID:    "*",
				KeyPrefix: "",
			}

			ctx := context.Background()
			snapshot, err := sm.CreateSnapshot(ctx, pattern)
			if err != nil {
				sm.logger.Error("Failed to create automatic snapshot", "error", err)
			} else {
				sm.logger.Info("Automatic snapshot created",
					"snapshot_id", snapshot.ID,
					"entries", snapshot.EntryCount)
			}

		case <-sm.autoSnapshotDone:
			return
		}
	}
}

// ExportSnapshot exports a snapshot to external storage
func (sm *SnapshotManager) ExportSnapshot(ctx context.Context, snapshotID string, destination string) error {
	snapshot, err := sm.GetSnapshot(ctx, snapshotID)
	if err != nil {
		return err
	}

	// In production, implement actual export to file, S3, etc.
	sm.logger.Info("Snapshot exported",
		"snapshot_id", snapshotID,
		"destination", destination,
		"entries", snapshot.EntryCount)

	return nil
}

// ImportSnapshot imports a snapshot from external storage
func (sm *SnapshotManager) ImportSnapshot(ctx context.Context, source string) (*StateSnapshot, error) {
	// In production, implement actual import from file, S3, etc.
	snapshot := &StateSnapshot{
		ID:          uuid.New().String(),
		Name:        fmt.Sprintf("imported_%d", time.Now().Unix()),
		Description: fmt.Sprintf("Imported from %s", source),
		Entries:     make(map[string]*StateEntry),
		CreatedAt:   time.Now(),
		CreatedBy:   "import",
		Tags:        make(map[string]string),
		Metadata:    make(map[string]interface{}),
	}

	sm.mutex.Lock()
	sm.snapshots[snapshot.ID] = snapshot
	sm.mutex.Unlock()

	sm.logger.Info("Snapshot imported",
		"snapshot_id", snapshot.ID,
		"source", source)

	return snapshot, nil
}
