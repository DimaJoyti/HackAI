package state

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// StateVersionManager manages state versioning and history
type StateVersionManager struct {
	store       StateStore
	versions    map[string][]*StateVersion
	maxVersions int
	logger      *logger.Logger
	mutex       sync.RWMutex
}

// StateVersion represents a version of state
type StateVersion struct {
	ID         string                 `json:"id"`
	Key        StateKey               `json:"key"`
	Version    int                    `json:"version"`
	Value      interface{}            `json:"value"`
	Metadata   *StateMetadata         `json:"metadata"`
	CreatedAt  time.Time              `json:"created_at"`
	CreatedBy  string                 `json:"created_by"`
	Message    string                 `json:"message"`
	Tags       map[string]string      `json:"tags"`
	ParentID   *string                `json:"parent_id,omitempty"`
	BranchName string                 `json:"branch_name"`
	Checksum   string                 `json:"checksum"`
	Size       int64                  `json:"size"`
	Compressed bool                   `json:"compressed"`
	Attributes map[string]interface{} `json:"attributes"`
}

// VersionDiff represents differences between two versions
type VersionDiff struct {
	FromVersion int                    `json:"from_version"`
	ToVersion   int                    `json:"to_version"`
	Changes     []VersionChange        `json:"changes"`
	Summary     string                 `json:"summary"`
	CreatedAt   time.Time              `json:"created_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// VersionChange represents a single change in a version diff
type VersionChange struct {
	Type     ChangeType  `json:"type"`
	Path     string      `json:"path"`
	OldValue interface{} `json:"old_value,omitempty"`
	NewValue interface{} `json:"new_value,omitempty"`
	Message  string      `json:"message"`
}

// ChangeType defines types of changes between versions
type ChangeType string

const (
	ChangeTypeAdded    ChangeType = "added"
	ChangeTypeModified ChangeType = "modified"
	ChangeTypeDeleted  ChangeType = "deleted"
	ChangeTypeMoved    ChangeType = "moved"
)

// VersionStats holds statistics about versioning
type VersionStats struct {
	TotalVersions    int64                  `json:"total_versions"`
	TotalKeys        int64                  `json:"total_keys"`
	AverageVersions  float64                `json:"average_versions"`
	OldestVersion    *time.Time             `json:"oldest_version,omitempty"`
	NewestVersion    *time.Time             `json:"newest_version,omitempty"`
	TotalSize        int64                  `json:"total_size"`
	CompressedSize   int64                  `json:"compressed_size"`
	CompressionRatio float64                `json:"compression_ratio"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// VersionQuery represents a query for versions
type VersionQuery struct {
	Key         *StateKey         `json:"key,omitempty"`
	KeyPattern  *StateKeyPattern  `json:"key_pattern,omitempty"`
	FromVersion *int              `json:"from_version,omitempty"`
	ToVersion   *int              `json:"to_version,omitempty"`
	FromTime    *time.Time        `json:"from_time,omitempty"`
	ToTime      *time.Time        `json:"to_time,omitempty"`
	CreatedBy   string            `json:"created_by,omitempty"`
	BranchName  string            `json:"branch_name,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Limit       int               `json:"limit,omitempty"`
	Offset      int               `json:"offset,omitempty"`
}

// NewStateVersionManager creates a new state version manager
func NewStateVersionManager(store StateStore, logger *logger.Logger) *StateVersionManager {
	return &StateVersionManager{
		store:       store,
		versions:    make(map[string][]*StateVersion),
		maxVersions: 100, // Default max versions per key
		logger:      logger,
	}
}

// CreateVersion creates a new version of state
func (svm *StateVersionManager) CreateVersion(ctx context.Context, key StateKey, entry *StateEntry) (int, error) {
	svm.mutex.Lock()
	defer svm.mutex.Unlock()

	keyStr := svm.keyToString(key)
	versions := svm.versions[keyStr]

	// Determine next version number
	nextVersion := 1
	if len(versions) > 0 {
		lastVersion := versions[len(versions)-1]
		nextVersion = lastVersion.Version + 1
	}

	// Create version
	version := &StateVersion{
		ID:         uuid.New().String(),
		Key:        key,
		Version:    nextVersion,
		Value:      entry.Value,
		Metadata:   entry.Metadata,
		CreatedAt:  time.Now(),
		CreatedBy:  "system", // Could be extracted from context
		BranchName: "main",   // Default branch
		Tags:       make(map[string]string),
		Attributes: make(map[string]interface{}),
	}

	// Copy tags from entry
	for k, v := range entry.Tags {
		version.Tags[k] = v
	}

	// Calculate checksum and size
	version.Checksum = svm.calculateChecksum(entry.Value)
	version.Size = svm.calculateSize(entry.Value)

	// Add to versions list
	versions = append(versions, version)

	// Enforce max versions limit
	if len(versions) > svm.maxVersions {
		// Remove oldest versions
		excess := len(versions) - svm.maxVersions
		versions = versions[excess:]
	}

	svm.versions[keyStr] = versions

	svm.logger.Debug("Version created",
		"key", key,
		"version", nextVersion,
		"size", version.Size)

	return nextVersion, nil
}

// GetVersion retrieves a specific version
func (svm *StateVersionManager) GetVersion(ctx context.Context, key StateKey, version int) (*StateVersion, error) {
	svm.mutex.RLock()
	defer svm.mutex.RUnlock()

	keyStr := svm.keyToString(key)
	versions := svm.versions[keyStr]

	for _, v := range versions {
		if v.Version == version {
			return v, nil
		}
	}

	return nil, fmt.Errorf("version %d not found for key %s", version, keyStr)
}

// GetLatestVersion retrieves the latest version
func (svm *StateVersionManager) GetLatestVersion(ctx context.Context, key StateKey) (*StateVersion, error) {
	svm.mutex.RLock()
	defer svm.mutex.RUnlock()

	keyStr := svm.keyToString(key)
	versions := svm.versions[keyStr]

	if len(versions) == 0 {
		return nil, fmt.Errorf("no versions found for key %s", keyStr)
	}

	return versions[len(versions)-1], nil
}

// GetVersionHistory retrieves version history for a key
func (svm *StateVersionManager) GetVersionHistory(ctx context.Context, key StateKey) ([]*StateVersion, error) {
	svm.mutex.RLock()
	defer svm.mutex.RUnlock()

	keyStr := svm.keyToString(key)
	versions := svm.versions[keyStr]

	// Return a copy to avoid external modifications
	result := make([]*StateVersion, len(versions))
	copy(result, versions)

	return result, nil
}

// QueryVersions queries versions based on criteria
func (svm *StateVersionManager) QueryVersions(ctx context.Context, query VersionQuery) ([]*StateVersion, error) {
	svm.mutex.RLock()
	defer svm.mutex.RUnlock()

	var result []*StateVersion

	// Collect all versions that match the query
	for _, versions := range svm.versions {
		for _, version := range versions {
			if svm.matchesQuery(version, query) {
				result = append(result, version)
			}
		}
	}

	// Sort by creation time (newest first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	// Apply limit and offset
	if query.Offset > 0 {
		if query.Offset >= len(result) {
			return []*StateVersion{}, nil
		}
		result = result[query.Offset:]
	}

	if query.Limit > 0 && query.Limit < len(result) {
		result = result[:query.Limit]
	}

	return result, nil
}

// CompareVersions compares two versions and returns the differences
func (svm *StateVersionManager) CompareVersions(ctx context.Context, key StateKey, fromVersion, toVersion int) (*VersionDiff, error) {
	svm.mutex.RLock()
	defer svm.mutex.RUnlock()

	fromVer, err := svm.GetVersion(ctx, key, fromVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get from version: %w", err)
	}

	toVer, err := svm.GetVersion(ctx, key, toVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get to version: %w", err)
	}

	changes := svm.calculateChanges(fromVer.Value, toVer.Value)

	diff := &VersionDiff{
		FromVersion: fromVersion,
		ToVersion:   toVersion,
		Changes:     changes,
		Summary:     svm.generateDiffSummary(changes),
		CreatedAt:   time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	return diff, nil
}

// RevertToVersion reverts state to a specific version
func (svm *StateVersionManager) RevertToVersion(ctx context.Context, key StateKey, version int) error {
	svm.mutex.Lock()
	defer svm.mutex.Unlock()

	targetVersion, err := svm.GetVersion(ctx, key, version)
	if err != nil {
		return fmt.Errorf("failed to get target version: %w", err)
	}

	// Create new entry from target version
	entry := &StateEntry{
		Key:         key,
		Value:       targetVersion.Value,
		Metadata:    targetVersion.Metadata,
		Version:     targetVersion.Version + 1, // New version number
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Tags:        targetVersion.Tags,
		Annotations: make(map[string]interface{}),
	}

	// Store the reverted state
	if err := svm.store.Set(ctx, key, entry); err != nil {
		return fmt.Errorf("failed to revert state: %w", err)
	}

	svm.logger.Info("State reverted",
		"key", key,
		"target_version", version,
		"new_version", entry.Version)

	return nil
}

// CreateBranch creates a new branch from a specific version
func (svm *StateVersionManager) CreateBranch(ctx context.Context, key StateKey, version int, branchName string) error {
	svm.mutex.Lock()
	defer svm.mutex.Unlock()

	sourceVersion, err := svm.GetVersion(ctx, key, version)
	if err != nil {
		return fmt.Errorf("failed to get source version: %w", err)
	}

	// Create new version on the branch
	branchVersion := &StateVersion{
		ID:         uuid.New().String(),
		Key:        key,
		Version:    1, // Start from version 1 on new branch
		Value:      sourceVersion.Value,
		Metadata:   sourceVersion.Metadata,
		CreatedAt:  time.Now(),
		CreatedBy:  "system",
		BranchName: branchName,
		ParentID:   &sourceVersion.ID,
		Tags:       make(map[string]string),
		Attributes: make(map[string]interface{}),
	}

	// Copy tags
	for k, v := range sourceVersion.Tags {
		branchVersion.Tags[k] = v
	}

	// Add branch tag
	branchVersion.Tags["branch"] = branchName

	// Store branch version
	branchKey := key
	branchKey.Key = fmt.Sprintf("%s@%s", key.Key, branchName)
	branchKeyStr := svm.keyToString(branchKey)

	svm.versions[branchKeyStr] = []*StateVersion{branchVersion}

	svm.logger.Info("Branch created",
		"key", key,
		"branch", branchName,
		"source_version", version)

	return nil
}

// MergeBranch merges a branch back to main
func (svm *StateVersionManager) MergeBranch(ctx context.Context, key StateKey, branchName string) error {
	svm.mutex.Lock()
	defer svm.mutex.Unlock()

	// Get latest version from branch
	branchKey := key
	branchKey.Key = fmt.Sprintf("%s@%s", key.Key, branchName)
	branchKeyStr := svm.keyToString(branchKey)

	branchVersions := svm.versions[branchKeyStr]
	if len(branchVersions) == 0 {
		return fmt.Errorf("branch %s not found", branchName)
	}

	latestBranchVersion := branchVersions[len(branchVersions)-1]

	// Create new version on main branch
	mainKeyStr := svm.keyToString(key)
	mainVersions := svm.versions[mainKeyStr]

	nextVersion := 1
	if len(mainVersions) > 0 {
		nextVersion = mainVersions[len(mainVersions)-1].Version + 1
	}

	mergedVersion := &StateVersion{
		ID:         uuid.New().String(),
		Key:        key,
		Version:    nextVersion,
		Value:      latestBranchVersion.Value,
		Metadata:   latestBranchVersion.Metadata,
		CreatedAt:  time.Now(),
		CreatedBy:  "system",
		BranchName: "main",
		ParentID:   &latestBranchVersion.ID,
		Tags:       make(map[string]string),
		Attributes: make(map[string]interface{}),
	}

	// Copy tags and add merge info
	for k, v := range latestBranchVersion.Tags {
		mergedVersion.Tags[k] = v
	}
	mergedVersion.Tags["merged_from"] = branchName

	// Add to main versions
	svm.versions[mainKeyStr] = append(mainVersions, mergedVersion)

	svm.logger.Info("Branch merged",
		"key", key,
		"branch", branchName,
		"new_version", nextVersion)

	return nil
}

// GetStats returns versioning statistics
func (svm *StateVersionManager) GetStats() *VersionStats {
	svm.mutex.RLock()
	defer svm.mutex.RUnlock()

	stats := &VersionStats{
		Metadata: make(map[string]interface{}),
	}

	var totalVersions int64
	var totalSize int64
	var compressedSize int64
	var oldestTime *time.Time
	var newestTime *time.Time

	for _, versions := range svm.versions {
		totalVersions += int64(len(versions))

		for _, version := range versions {
			totalSize += version.Size
			if version.Compressed {
				compressedSize += version.Size
			}

			if oldestTime == nil || version.CreatedAt.Before(*oldestTime) {
				oldestTime = &version.CreatedAt
			}
			if newestTime == nil || version.CreatedAt.After(*newestTime) {
				newestTime = &version.CreatedAt
			}
		}
	}

	stats.TotalVersions = totalVersions
	stats.TotalKeys = int64(len(svm.versions))
	stats.TotalSize = totalSize
	stats.CompressedSize = compressedSize
	stats.OldestVersion = oldestTime
	stats.NewestVersion = newestTime

	if stats.TotalKeys > 0 {
		stats.AverageVersions = float64(totalVersions) / float64(stats.TotalKeys)
	}

	if totalSize > 0 {
		stats.CompressionRatio = float64(compressedSize) / float64(totalSize)
	}

	return stats
}

// Helper methods

func (svm *StateVersionManager) keyToString(key StateKey) string {
	return fmt.Sprintf("%s:%s:%s:%s", key.Namespace, key.GraphID, key.NodeID, key.Key)
}

func (svm *StateVersionManager) calculateChecksum(value interface{}) string {
	// Simplified checksum calculation
	// In production, use a proper hash function
	return fmt.Sprintf("checksum_%d", time.Now().UnixNano())
}

func (svm *StateVersionManager) calculateSize(value interface{}) int64 {
	// Simplified size calculation
	// In production, serialize and measure actual size
	return int64(len(fmt.Sprintf("%v", value)))
}

func (svm *StateVersionManager) matchesQuery(version *StateVersion, query VersionQuery) bool {
	// Check key match
	if query.Key != nil {
		if svm.keyToString(*query.Key) != svm.keyToString(version.Key) {
			return false
		}
	}

	// Check version range
	if query.FromVersion != nil && version.Version < *query.FromVersion {
		return false
	}
	if query.ToVersion != nil && version.Version > *query.ToVersion {
		return false
	}

	// Check time range
	if query.FromTime != nil && version.CreatedAt.Before(*query.FromTime) {
		return false
	}
	if query.ToTime != nil && version.CreatedAt.After(*query.ToTime) {
		return false
	}

	// Check created by
	if query.CreatedBy != "" && version.CreatedBy != query.CreatedBy {
		return false
	}

	// Check branch name
	if query.BranchName != "" && version.BranchName != query.BranchName {
		return false
	}

	// Check tags
	for key, value := range query.Tags {
		if version.Tags[key] != value {
			return false
		}
	}

	return true
}

func (svm *StateVersionManager) calculateChanges(oldValue, newValue interface{}) []VersionChange {
	// Simplified change calculation
	// In production, implement deep comparison
	changes := []VersionChange{}

	if fmt.Sprintf("%v", oldValue) != fmt.Sprintf("%v", newValue) {
		changes = append(changes, VersionChange{
			Type:     ChangeTypeModified,
			Path:     "root",
			OldValue: oldValue,
			NewValue: newValue,
			Message:  "Value changed",
		})
	}

	return changes
}

func (svm *StateVersionManager) generateDiffSummary(changes []VersionChange) string {
	if len(changes) == 0 {
		return "No changes"
	}

	return fmt.Sprintf("%d changes detected", len(changes))
}
