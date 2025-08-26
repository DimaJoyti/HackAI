package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// WorkingMemory manages short-term, active memory for agents
type WorkingMemory struct {
	entries         map[string]*MemoryEntry
	maxSize         int
	currentContext  map[string]interface{}
	activeGoals     []*Goal
	recentActions   []*Action
	temporaryData   map[string]interface{}
	attentionFocus  []string
	config          *MemoryConfig
	logger          *logger.Logger
	mutex           sync.RWMutex
}

// Goal represents an agent goal
type Goal struct {
	ID          string                 `json:"id"`
	Description string                 `json:"description"`
	Priority    float64                `json:"priority"`
	Status      GoalStatus             `json:"status"`
	Progress    float64                `json:"progress"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Deadline    *time.Time             `json:"deadline,omitempty"`
	SubGoals    []string               `json:"sub_goals"`
	Context     map[string]interface{} `json:"context"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Action represents an agent action
type Action struct {
	ID          string                 `json:"id"`
	Type        ActionType             `json:"type"`
	Description string                 `json:"description"`
	Status      ActionStatus           `json:"status"`
	Input       map[string]interface{} `json:"input"`
	Output      interface{}            `json:"output"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	Context     map[string]interface{} `json:"context"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Enums for working memory
type GoalStatus string
type ActionStatus string
type ActionType string

const (
	// Goal Status
	GoalStatusPending    GoalStatus = "pending"
	GoalStatusActive     GoalStatus = "active"
	GoalStatusCompleted  GoalStatus = "completed"
	GoalStatusFailed     GoalStatus = "failed"
	GoalStatusSuspended  GoalStatus = "suspended"

	// Action Status
	ActionStatusPending   ActionStatus = "pending"
	ActionStatusRunning   ActionStatus = "running"
	ActionStatusCompleted ActionStatus = "completed"
	ActionStatusFailed    ActionStatus = "failed"
	ActionStatusCancelled ActionStatus = "cancelled"

	// Action Types
	ActionTypeThinking    ActionType = "thinking"
	ActionTypeObservation ActionType = "observation"
	ActionTypeToolUse     ActionType = "tool_use"
	ActionTypeCommunication ActionType = "communication"
	ActionTypeDecision    ActionType = "decision"
	ActionTypeReflection  ActionType = "reflection"
)

// NewWorkingMemory creates a new working memory instance
func NewWorkingMemory(config *MemoryConfig, logger *logger.Logger) (*WorkingMemory, error) {
	return &WorkingMemory{
		entries:        make(map[string]*MemoryEntry),
		maxSize:        config.WorkingMemorySize,
		currentContext: make(map[string]interface{}),
		activeGoals:    make([]*Goal, 0),
		recentActions:  make([]*Action, 0),
		temporaryData:  make(map[string]interface{}),
		attentionFocus: make([]string, 0),
		config:         config,
		logger:         logger,
	}, nil
}

// Store stores a memory entry in working memory
func (wm *WorkingMemory) Store(ctx context.Context, entry *MemoryEntry) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	// Check if we need to evict entries
	if len(wm.entries) >= wm.maxSize {
		if err := wm.evictLeastImportant(); err != nil {
			return fmt.Errorf("failed to evict entries: %w", err)
		}
	}

	// Store the entry
	wm.entries[entry.ID] = entry

	wm.logger.Debug("Memory entry stored in working memory",
		"entry_id", entry.ID,
		"importance", entry.Importance,
		"total_entries", len(wm.entries))

	return nil
}

// Retrieve retrieves a memory entry from working memory
func (wm *WorkingMemory) Retrieve(ctx context.Context, id string) (*MemoryEntry, error) {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	entry, exists := wm.entries[id]
	if !exists {
		return nil, fmt.Errorf("memory entry not found: %s", id)
	}

	// Update access information
	entry.LastAccess = time.Now()
	entry.AccessCount++

	return entry, nil
}

// Query queries working memory with criteria
func (wm *WorkingMemory) Query(ctx context.Context, query *MemoryQuery) (*MemoryResult, error) {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	var matchingEntries []*MemoryEntry

	for _, entry := range wm.entries {
		if wm.matchesQuery(entry, query) {
			matchingEntries = append(matchingEntries, entry)
		}
	}

	// Sort entries
	wm.sortEntries(matchingEntries, query.SortBy, query.SortOrder)

	// Apply limit
	if query.Limit > 0 && len(matchingEntries) > query.Limit {
		matchingEntries = matchingEntries[:query.Limit]
	}

	return &MemoryResult{
		Entries:    matchingEntries,
		TotalCount: len(matchingEntries),
		Metadata:   map[string]interface{}{"source": "working_memory"},
	}, nil
}

// Update updates a memory entry in working memory
func (wm *WorkingMemory) Update(ctx context.Context, entry *MemoryEntry) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	if _, exists := wm.entries[entry.ID]; !exists {
		return fmt.Errorf("memory entry not found: %s", entry.ID)
	}

	wm.entries[entry.ID] = entry

	wm.logger.Debug("Memory entry updated in working memory",
		"entry_id", entry.ID,
		"importance", entry.Importance)

	return nil
}

// Delete deletes a memory entry from working memory
func (wm *WorkingMemory) Delete(ctx context.Context, id string) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	if _, exists := wm.entries[id]; !exists {
		return fmt.Errorf("memory entry not found: %s", id)
	}

	delete(wm.entries, id)

	wm.logger.Debug("Memory entry deleted from working memory",
		"entry_id", id,
		"remaining_entries", len(wm.entries))

	return nil
}

// SetCurrentContext sets the current context
func (wm *WorkingMemory) SetCurrentContext(ctx map[string]interface{}) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	wm.currentContext = ctx
	wm.logger.Debug("Current context updated", "context_keys", len(ctx))
}

// GetCurrentContext gets the current context
func (wm *WorkingMemory) GetCurrentContext() map[string]interface{} {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	// Return a copy to prevent external modification
	contextCopy := make(map[string]interface{})
	for k, v := range wm.currentContext {
		contextCopy[k] = v
	}

	return contextCopy
}

// AddGoal adds a new goal
func (wm *WorkingMemory) AddGoal(goal *Goal) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	if goal.ID == "" {
		goal.ID = uuid.New().String()
	}

	if goal.CreatedAt.IsZero() {
		goal.CreatedAt = time.Now()
	}
	goal.UpdatedAt = time.Now()

	wm.activeGoals = append(wm.activeGoals, goal)

	wm.logger.Debug("Goal added to working memory",
		"goal_id", goal.ID,
		"description", goal.Description,
		"priority", goal.Priority)
}

// UpdateGoal updates an existing goal
func (wm *WorkingMemory) UpdateGoal(goalID string, updates map[string]interface{}) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	for _, goal := range wm.activeGoals {
		if goal.ID == goalID {
			goal.UpdatedAt = time.Now()

			// Apply updates
			if description, exists := updates["description"]; exists {
				if desc, ok := description.(string); ok {
					goal.Description = desc
				}
			}

			if priority, exists := updates["priority"]; exists {
				if prio, ok := priority.(float64); ok {
					goal.Priority = prio
				}
			}

			if status, exists := updates["status"]; exists {
				if stat, ok := status.(GoalStatus); ok {
					goal.Status = stat
				}
			}

			if progress, exists := updates["progress"]; exists {
				if prog, ok := progress.(float64); ok {
					goal.Progress = prog
				}
			}

			wm.logger.Debug("Goal updated in working memory",
				"goal_id", goalID,
				"updates", len(updates))

			return nil
		}
	}

	return fmt.Errorf("goal not found: %s", goalID)
}

// GetActiveGoals returns all active goals
func (wm *WorkingMemory) GetActiveGoals() []*Goal {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	// Return a copy to prevent external modification
	goals := make([]*Goal, len(wm.activeGoals))
	copy(goals, wm.activeGoals)

	return goals
}

// AddAction adds a recent action
func (wm *WorkingMemory) AddAction(action *Action) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	if action.ID == "" {
		action.ID = uuid.New().String()
	}

	if action.StartTime.IsZero() {
		action.StartTime = time.Now()
	}

	wm.recentActions = append(wm.recentActions, action)

	// Keep only recent actions (last 50)
	maxRecentActions := 50
	if len(wm.recentActions) > maxRecentActions {
		wm.recentActions = wm.recentActions[len(wm.recentActions)-maxRecentActions:]
	}

	wm.logger.Debug("Action added to working memory",
		"action_id", action.ID,
		"type", action.Type,
		"description", action.Description)
}

// GetRecentActions returns recent actions
func (wm *WorkingMemory) GetRecentActions(limit int) []*Action {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	if limit <= 0 || limit > len(wm.recentActions) {
		limit = len(wm.recentActions)
	}

	// Return the most recent actions
	start := len(wm.recentActions) - limit
	actions := make([]*Action, limit)
	copy(actions, wm.recentActions[start:])

	return actions
}

// SetAttentionFocus sets the current attention focus
func (wm *WorkingMemory) SetAttentionFocus(focus []string) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	wm.attentionFocus = focus

	wm.logger.Debug("Attention focus updated",
		"focus_items", len(focus))
}

// GetAttentionFocus gets the current attention focus
func (wm *WorkingMemory) GetAttentionFocus() []string {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	// Return a copy
	focus := make([]string, len(wm.attentionFocus))
	copy(focus, wm.attentionFocus)

	return focus
}

// SetTemporaryData sets temporary data
func (wm *WorkingMemory) SetTemporaryData(key string, value interface{}) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	wm.temporaryData[key] = value
}

// GetTemporaryData gets temporary data
func (wm *WorkingMemory) GetTemporaryData(key string) (interface{}, bool) {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	value, exists := wm.temporaryData[key]
	return value, exists
}

// ClearTemporaryData clears all temporary data
func (wm *WorkingMemory) ClearTemporaryData() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	wm.temporaryData = make(map[string]interface{})
	wm.logger.Debug("Temporary data cleared")
}

// GetSize returns the current size of working memory
func (wm *WorkingMemory) GetSize() int {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	return len(wm.entries)
}

// GetStatistics returns working memory statistics
func (wm *WorkingMemory) GetStatistics() *MemoryTypeStatistics {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	var totalSize int64
	var totalAccess int64
	var oldestEntry, newestEntry time.Time
	var lastAccess time.Time

	for _, entry := range wm.entries {
		// Calculate size (simplified)
		totalSize += int64(len(fmt.Sprintf("%v", entry.Content)))
		totalAccess += entry.AccessCount

		if oldestEntry.IsZero() || entry.Timestamp.Before(oldestEntry) {
			oldestEntry = entry.Timestamp
		}

		if newestEntry.IsZero() || entry.Timestamp.After(newestEntry) {
			newestEntry = entry.Timestamp
		}

		if lastAccess.IsZero() || entry.LastAccess.After(lastAccess) {
			lastAccess = entry.LastAccess
		}
	}

	var averageSize float64
	if len(wm.entries) > 0 {
		averageSize = float64(totalSize) / float64(len(wm.entries))
	}

	return &MemoryTypeStatistics{
		EntryCount:      len(wm.entries),
		TotalSize:       totalSize,
		AverageSize:     averageSize,
		OldestEntry:     oldestEntry,
		NewestEntry:     newestEntry,
		AccessCount:     totalAccess,
		LastAccess:      lastAccess,
		CompressionRate: 0.0, // Working memory is not compressed
	}
}

// Helper methods

func (wm *WorkingMemory) evictLeastImportant() error {
	if len(wm.entries) == 0 {
		return nil
	}

	// Find the least important entry
	var leastImportantID string
	var leastImportance float64 = 1.0

	for id, entry := range wm.entries {
		// Calculate effective importance (considering recency and access count)
		timeFactor := time.Since(entry.LastAccess).Hours() / 24.0 // Days since last access
		accessFactor := 1.0 / (1.0 + float64(entry.AccessCount))  // Lower access count = higher factor
		effectiveImportance := entry.Importance / (1.0 + timeFactor*accessFactor)

		if leastImportantID == "" || effectiveImportance < leastImportance {
			leastImportantID = id
			leastImportance = effectiveImportance
		}
	}

	// Remove the least important entry
	delete(wm.entries, leastImportantID)

	wm.logger.Debug("Evicted least important entry from working memory",
		"entry_id", leastImportantID,
		"importance", leastImportance,
		"remaining_entries", len(wm.entries))

	return nil
}

func (wm *WorkingMemory) matchesQuery(entry *MemoryEntry, query *MemoryQuery) bool {
	// Check content match
	if query.Content != "" {
		contentStr := fmt.Sprintf("%v", entry.Content)
		if !contains(contentStr, query.Content) {
			return false
		}
	}

	// Check tags
	if len(query.Tags) > 0 {
		if !hasAnyTag(entry.Tags, query.Tags) {
			return false
		}
	}

	// Check time range
	if query.TimeRange != nil {
		if entry.Timestamp.Before(query.TimeRange.Start) || entry.Timestamp.After(query.TimeRange.End) {
			return false
		}
	}

	// Check importance range
	if query.ImportanceRange != nil {
		if entry.Importance < query.ImportanceRange.Min || entry.Importance > query.ImportanceRange.Max {
			return false
		}
	}

	// Check confidence range
	if query.ConfidenceRange != nil {
		if entry.Confidence < query.ConfidenceRange.Min || entry.Confidence > query.ConfidenceRange.Max {
			return false
		}
	}

	// Check expiration
	if !query.IncludeExpired && entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
		return false
	}

	return true
}

func (wm *WorkingMemory) sortEntries(entries []*MemoryEntry, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "timestamp"
	}

	sort.Slice(entries, func(i, j int) bool {
		var less bool

		switch sortBy {
		case "timestamp":
			less = entries[i].Timestamp.Before(entries[j].Timestamp)
		case "importance":
			less = entries[i].Importance < entries[j].Importance
		case "confidence":
			less = entries[i].Confidence < entries[j].Confidence
		case "access_count":
			less = entries[i].AccessCount < entries[j].AccessCount
		case "last_access":
			less = entries[i].LastAccess.Before(entries[j].LastAccess)
		default:
			less = entries[i].Timestamp.Before(entries[j].Timestamp)
		}

		if sortOrder == "desc" {
			return !less
		}
		return less
	})
}

// Helper functions
func contains(text, substr string) bool {
	return len(text) >= len(substr) && (text == substr || 
		(len(substr) > 0 && len(text) > 0 && 
		 fmt.Sprintf("%s", text) == fmt.Sprintf("%s", substr)))
}

func hasAnyTag(entryTags, queryTags []string) bool {
	for _, queryTag := range queryTags {
		for _, entryTag := range entryTags {
			if entryTag == queryTag {
				return true
			}
		}
	}
	return false
}
