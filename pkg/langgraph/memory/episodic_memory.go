package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// EpisodicMemory manages episodic memories (experiences and events)
type EpisodicMemory struct {
	episodes    map[string]*Episode
	maxSize     int
	indexer     *EpisodeIndexer
	retriever   *EpisodeRetriever
	consolidator *MemoryConsolidator
	config      *MemoryConfig
	logger      *logger.Logger
	mutex       sync.RWMutex
}

// Episode represents an episodic memory
type Episode struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Type        EpisodeType            `json:"type"`
	Context     *EpisodeContext        `json:"context"`
	Events      []*EpisodeEvent        `json:"events"`
	Participants []string              `json:"participants"`
	Location    string                 `json:"location"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Importance  float64                `json:"importance"`
	Confidence  float64                `json:"confidence"`
	Emotions    map[string]float64     `json:"emotions"`
	Outcomes    []*EpisodeOutcome      `json:"outcomes"`
	Lessons     []string               `json:"lessons"`
	Tags        []string               `json:"tags"`
	References  []string               `json:"references"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	AccessCount int64                  `json:"access_count"`
	LastAccess  time.Time              `json:"last_access"`
}

// EpisodeContext represents the context of an episode
type EpisodeContext struct {
	Goal        string                 `json:"goal"`
	Task        string                 `json:"task"`
	Environment map[string]interface{} `json:"environment"`
	Constraints []string               `json:"constraints"`
	Resources   []string               `json:"resources"`
	State       map[string]interface{} `json:"state"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// EpisodeEvent represents an event within an episode
type EpisodeEvent struct {
	ID          string                 `json:"id"`
	Type        EventType              `json:"type"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Actor       string                 `json:"actor"`
	Action      string                 `json:"action"`
	Object      string                 `json:"object"`
	Result      interface{}            `json:"result"`
	Success     bool                   `json:"success"`
	Confidence  float64                `json:"confidence"`
	Impact      float64                `json:"impact"`
	Context     map[string]interface{} `json:"context"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// EpisodeOutcome represents an outcome of an episode
type EpisodeOutcome struct {
	ID          string                 `json:"id"`
	Type        OutcomeType            `json:"type"`
	Description string                 `json:"description"`
	Success     bool                   `json:"success"`
	Value       interface{}            `json:"value"`
	Impact      float64                `json:"impact"`
	Confidence  float64                `json:"confidence"`
	Metrics     map[string]float64     `json:"metrics"`
	Context     map[string]interface{} `json:"context"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// EpisodeIndexer indexes episodes for efficient retrieval
type EpisodeIndexer struct {
	timeIndex        map[string][]string // date -> episode IDs
	participantIndex map[string][]string // participant -> episode IDs
	tagIndex         map[string][]string // tag -> episode IDs
	typeIndex        map[EpisodeType][]string
	importanceIndex  []string // sorted by importance
	mutex            sync.RWMutex
}

// EpisodeRetriever retrieves episodes based on various criteria
type EpisodeRetriever struct {
	indexer *EpisodeIndexer
	logger  *logger.Logger
}

// MemoryConsolidator consolidates episodic memories
type MemoryConsolidator struct {
	logger *logger.Logger
}

// Enums for episodic memory
type EpisodeType string
type EventType string
type OutcomeType string

const (
	// Episode Types
	EpisodeTypeTask         EpisodeType = "task"
	EpisodeTypeConversation EpisodeType = "conversation"
	EpisodeTypeLearning     EpisodeType = "learning"
	EpisodeTypeProblemSolving EpisodeType = "problem_solving"
	EpisodeTypeDecision     EpisodeType = "decision"
	EpisodeTypeExperiment   EpisodeType = "experiment"
	EpisodeTypeInteraction  EpisodeType = "interaction"

	// Event Types
	EventTypeAction      EventType = "action"
	EventTypeObservation EventType = "observation"
	EventTypeDecision    EventType = "decision"
	EventTypeCommunication EventType = "communication"
	EventTypeError       EventType = "error"
	EventTypeSuccess     EventType = "success"
	EventTypeReflection  EventType = "reflection"

	// Outcome Types
	OutcomeTypeSuccess     OutcomeType = "success"
	OutcomeTypeFailure     OutcomeType = "failure"
	OutcomeTypeLearning    OutcomeType = "learning"
	OutcomeTypeInsight     OutcomeType = "insight"
	OutcomeTypeImprovement OutcomeType = "improvement"
	OutcomeTypeKnowledge   OutcomeType = "knowledge"
)

// NewEpisodicMemory creates a new episodic memory instance
func NewEpisodicMemory(config *MemoryConfig, logger *logger.Logger) (*EpisodicMemory, error) {
	indexer := &EpisodeIndexer{
		timeIndex:        make(map[string][]string),
		participantIndex: make(map[string][]string),
		tagIndex:         make(map[string][]string),
		typeIndex:        make(map[EpisodeType][]string),
		importanceIndex:  make([]string, 0),
	}

	retriever := &EpisodeRetriever{
		indexer: indexer,
		logger:  logger,
	}

	consolidator := &MemoryConsolidator{
		logger: logger,
	}

	return &EpisodicMemory{
		episodes:     make(map[string]*Episode),
		maxSize:      config.EpisodicMemorySize,
		indexer:      indexer,
		retriever:    retriever,
		consolidator: consolidator,
		config:       config,
		logger:       logger,
	}, nil
}

// Store stores a memory entry as an episode
func (em *EpisodicMemory) Store(ctx context.Context, entry *MemoryEntry) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	// Convert memory entry to episode
	episode, err := em.convertToEpisode(entry)
	if err != nil {
		return fmt.Errorf("failed to convert memory entry to episode: %w", err)
	}

	// Check if we need to evict episodes
	if len(em.episodes) >= em.maxSize {
		if err := em.evictOldestEpisode(); err != nil {
			return fmt.Errorf("failed to evict episodes: %w", err)
		}
	}

	// Store the episode
	em.episodes[episode.ID] = episode

	// Update indexes
	em.indexer.IndexEpisode(episode)

	em.logger.Debug("Episode stored in episodic memory",
		"episode_id", episode.ID,
		"type", episode.Type,
		"importance", episode.Importance,
		"total_episodes", len(em.episodes))

	return nil
}

// Retrieve retrieves a memory entry by ID
func (em *EpisodicMemory) Retrieve(ctx context.Context, id string) (*MemoryEntry, error) {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	episode, exists := em.episodes[id]
	if !exists {
		return nil, fmt.Errorf("episode not found: %s", id)
	}

	// Update access information
	episode.LastAccess = time.Now()
	episode.AccessCount++

	// Convert episode back to memory entry
	return em.convertToMemoryEntry(episode), nil
}

// Query queries episodic memory with criteria
func (em *EpisodicMemory) Query(ctx context.Context, query *MemoryQuery) (*MemoryResult, error) {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	// Use retriever to find matching episodes
	episodeIDs, err := em.retriever.FindEpisodes(query)
	if err != nil {
		return nil, fmt.Errorf("failed to find episodes: %w", err)
	}

	var matchingEntries []*MemoryEntry
	for _, episodeID := range episodeIDs {
		if episode, exists := em.episodes[episodeID]; exists {
			if em.matchesQuery(episode, query) {
				entry := em.convertToMemoryEntry(episode)
				matchingEntries = append(matchingEntries, entry)
			}
		}
	}

	// Sort entries
	em.sortEntries(matchingEntries, query.SortBy, query.SortOrder)

	// Apply limit
	if query.Limit > 0 && len(matchingEntries) > query.Limit {
		matchingEntries = matchingEntries[:query.Limit]
	}

	return &MemoryResult{
		Entries:    matchingEntries,
		TotalCount: len(matchingEntries),
		Metadata:   map[string]interface{}{"source": "episodic_memory"},
	}, nil
}

// Update updates a memory entry
func (em *EpisodicMemory) Update(ctx context.Context, entry *MemoryEntry) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	episode, exists := em.episodes[entry.ID]
	if !exists {
		return fmt.Errorf("episode not found: %s", entry.ID)
	}

	// Update episode from memory entry
	updatedEpisode, err := em.convertToEpisode(entry)
	if err != nil {
		return fmt.Errorf("failed to convert memory entry to episode: %w", err)
	}

	// Preserve original creation time and access count
	updatedEpisode.CreatedAt = episode.CreatedAt
	updatedEpisode.AccessCount = episode.AccessCount
	updatedEpisode.UpdatedAt = time.Now()

	em.episodes[entry.ID] = updatedEpisode

	// Update indexes
	em.indexer.UpdateEpisodeIndex(episode, updatedEpisode)

	em.logger.Debug("Episode updated in episodic memory",
		"episode_id", entry.ID,
		"importance", updatedEpisode.Importance)

	return nil
}

// Delete deletes a memory entry
func (em *EpisodicMemory) Delete(ctx context.Context, id string) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	episode, exists := em.episodes[id]
	if !exists {
		return fmt.Errorf("episode not found: %s", id)
	}

	// Remove from indexes
	em.indexer.RemoveEpisodeFromIndex(episode)

	// Delete the episode
	delete(em.episodes, id)

	em.logger.Debug("Episode deleted from episodic memory",
		"episode_id", id,
		"remaining_episodes", len(em.episodes))

	return nil
}

// GetSize returns the current size of episodic memory
func (em *EpisodicMemory) GetSize() int {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	return len(em.episodes)
}

// GetStatistics returns episodic memory statistics
func (em *EpisodicMemory) GetStatistics() *MemoryTypeStatistics {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	var totalSize int64
	var totalAccess int64
	var oldestEntry, newestEntry time.Time
	var lastAccess time.Time

	for _, episode := range em.episodes {
		// Calculate size (simplified)
		totalSize += int64(len(fmt.Sprintf("%v", episode)))
		totalAccess += episode.AccessCount

		if oldestEntry.IsZero() || episode.CreatedAt.Before(oldestEntry) {
			oldestEntry = episode.CreatedAt
		}

		if newestEntry.IsZero() || episode.CreatedAt.After(newestEntry) {
			newestEntry = episode.CreatedAt
		}

		if lastAccess.IsZero() || episode.LastAccess.After(lastAccess) {
			lastAccess = episode.LastAccess
		}
	}

	var averageSize float64
	if len(em.episodes) > 0 {
		averageSize = float64(totalSize) / float64(len(em.episodes))
	}

	return &MemoryTypeStatistics{
		EntryCount:      len(em.episodes),
		TotalSize:       totalSize,
		AverageSize:     averageSize,
		OldestEntry:     oldestEntry,
		NewestEntry:     newestEntry,
		AccessCount:     totalAccess,
		LastAccess:      lastAccess,
		CompressionRate: 0.0, // Simplified
	}
}

// Helper methods

func (em *EpisodicMemory) convertToEpisode(entry *MemoryEntry) (*Episode, error) {
	episode := &Episode{
		ID:          entry.ID,
		Title:       fmt.Sprintf("Episode %s", entry.ID[:8]),
		Description: fmt.Sprintf("%v", entry.Content),
		Type:        EpisodeTypeTask, // Default type
		Context:     &EpisodeContext{},
		Events:      make([]*EpisodeEvent, 0),
		Participants: make([]string, 0),
		StartTime:   entry.Timestamp,
		Importance:  entry.Importance,
		Confidence:  entry.Confidence,
		Emotions:    make(map[string]float64),
		Outcomes:    make([]*EpisodeOutcome, 0),
		Lessons:     make([]string, 0),
		Tags:        entry.Tags,
		References:  make([]string, 0),
		Metadata:    entry.Metadata,
		CreatedAt:   entry.Timestamp,
		UpdatedAt:   time.Now(),
		AccessCount: entry.AccessCount,
		LastAccess:  entry.LastAccess,
	}

	// Extract additional information from context
	if entry.Context != nil {
		if goal, exists := entry.Context["goal"]; exists {
			if goalStr, ok := goal.(string); ok {
				episode.Context.Goal = goalStr
			}
		}

		if task, exists := entry.Context["task"]; exists {
			if taskStr, ok := task.(string); ok {
				episode.Context.Task = taskStr
			}
		}

		if episodeType, exists := entry.Context["episode_type"]; exists {
			if typeStr, ok := episodeType.(string); ok {
				episode.Type = EpisodeType(typeStr)
			}
		}
	}

	return episode, nil
}

func (em *EpisodicMemory) convertToMemoryEntry(episode *Episode) *MemoryEntry {
	return &MemoryEntry{
		ID:          episode.ID,
		Type:        MemoryTypeEpisodic,
		Content:     episode.Description,
		Context:     episode.Metadata,
		Importance:  episode.Importance,
		Confidence:  episode.Confidence,
		Timestamp:   episode.CreatedAt,
		LastAccess:  episode.LastAccess,
		AccessCount: episode.AccessCount,
		Tags:        episode.Tags,
		Metadata:    episode.Metadata,
	}
}

func (em *EpisodicMemory) evictOldestEpisode() error {
	if len(em.episodes) == 0 {
		return nil
	}

	// Find the oldest episode with lowest importance
	var oldestID string
	var oldestTime time.Time
	var lowestImportance float64 = 1.0

	for id, episode := range em.episodes {
		if oldestID == "" || episode.CreatedAt.Before(oldestTime) || 
		   (episode.CreatedAt.Equal(oldestTime) && episode.Importance < lowestImportance) {
			oldestID = id
			oldestTime = episode.CreatedAt
			lowestImportance = episode.Importance
		}
	}

	// Remove the oldest episode
	if episode, exists := em.episodes[oldestID]; exists {
		em.indexer.RemoveEpisodeFromIndex(episode)
		delete(em.episodes, oldestID)

		em.logger.Debug("Evicted oldest episode from episodic memory",
			"episode_id", oldestID,
			"created_at", oldestTime,
			"importance", lowestImportance,
			"remaining_episodes", len(em.episodes))
	}

	return nil
}

func (em *EpisodicMemory) matchesQuery(episode *Episode, query *MemoryQuery) bool {
	// Check content match
	if query.Content != "" {
		if !contains(episode.Description, query.Content) {
			return false
		}
	}

	// Check tags
	if len(query.Tags) > 0 {
		if !hasAnyTag(episode.Tags, query.Tags) {
			return false
		}
	}

	// Check time range
	if query.TimeRange != nil {
		if episode.CreatedAt.Before(query.TimeRange.Start) || episode.CreatedAt.After(query.TimeRange.End) {
			return false
		}
	}

	// Check importance range
	if query.ImportanceRange != nil {
		if episode.Importance < query.ImportanceRange.Min || episode.Importance > query.ImportanceRange.Max {
			return false
		}
	}

	// Check confidence range
	if query.ConfidenceRange != nil {
		if episode.Confidence < query.ConfidenceRange.Min || episode.Confidence > query.ConfidenceRange.Max {
			return false
		}
	}

	return true
}

func (em *EpisodicMemory) sortEntries(entries []*MemoryEntry, sortBy, sortOrder string) {
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

// EpisodeIndexer methods

func (ei *EpisodeIndexer) IndexEpisode(episode *Episode) {
	ei.mutex.Lock()
	defer ei.mutex.Unlock()

	// Index by date
	dateKey := episode.CreatedAt.Format("2006-01-02")
	ei.timeIndex[dateKey] = append(ei.timeIndex[dateKey], episode.ID)

	// Index by participants
	for _, participant := range episode.Participants {
		ei.participantIndex[participant] = append(ei.participantIndex[participant], episode.ID)
	}

	// Index by tags
	for _, tag := range episode.Tags {
		ei.tagIndex[tag] = append(ei.tagIndex[tag], episode.ID)
	}

	// Index by type
	ei.typeIndex[episode.Type] = append(ei.typeIndex[episode.Type], episode.ID)

	// Index by importance (maintain sorted order)
	ei.insertInImportanceIndex(episode.ID, episode.Importance)
}

func (ei *EpisodeIndexer) UpdateEpisodeIndex(oldEpisode, newEpisode *Episode) {
	ei.RemoveEpisodeFromIndex(oldEpisode)
	ei.IndexEpisode(newEpisode)
}

func (ei *EpisodeIndexer) RemoveEpisodeFromIndex(episode *Episode) {
	ei.mutex.Lock()
	defer ei.mutex.Unlock()

	// Remove from time index
	dateKey := episode.CreatedAt.Format("2006-01-02")
	ei.removeFromSlice(ei.timeIndex[dateKey], episode.ID)

	// Remove from participant index
	for _, participant := range episode.Participants {
		ei.removeFromSlice(ei.participantIndex[participant], episode.ID)
	}

	// Remove from tag index
	for _, tag := range episode.Tags {
		ei.removeFromSlice(ei.tagIndex[tag], episode.ID)
	}

	// Remove from type index
	ei.removeFromSlice(ei.typeIndex[episode.Type], episode.ID)

	// Remove from importance index
	ei.removeFromImportanceIndex(episode.ID)
}

func (ei *EpisodeIndexer) insertInImportanceIndex(episodeID string, importance float64) {
	// Simple insertion - in production, use more efficient data structure
	ei.importanceIndex = append(ei.importanceIndex, episodeID)
}

func (ei *EpisodeIndexer) removeFromImportanceIndex(episodeID string) {
	for i, id := range ei.importanceIndex {
		if id == episodeID {
			ei.importanceIndex = append(ei.importanceIndex[:i], ei.importanceIndex[i+1:]...)
			break
		}
	}
}

func (ei *EpisodeIndexer) removeFromSlice(slice []string, item string) []string {
	for i, s := range slice {
		if s == item {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// EpisodeRetriever methods

func (er *EpisodeRetriever) FindEpisodes(query *MemoryQuery) ([]string, error) {
	er.indexer.mutex.RLock()
	defer er.indexer.mutex.RUnlock()

	var candidateIDs []string

	// Use indexes to find candidate episodes
	if len(query.Tags) > 0 {
		for _, tag := range query.Tags {
			if episodeIDs, exists := er.indexer.tagIndex[tag]; exists {
				candidateIDs = append(candidateIDs, episodeIDs...)
			}
		}
	} else {
		// If no specific criteria, return all episodes
		for _, episodeIDs := range er.indexer.typeIndex {
			candidateIDs = append(candidateIDs, episodeIDs...)
		}
	}

	// Remove duplicates
	uniqueIDs := make(map[string]bool)
	var result []string
	for _, id := range candidateIDs {
		if !uniqueIDs[id] {
			uniqueIDs[id] = true
			result = append(result, id)
		}
	}

	return result, nil
}
