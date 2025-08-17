package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var episodicTracer = otel.Tracer("hackai/llm/memory/episodic")

// InMemoryEpisodicMemory implements EpisodicMemory using in-memory storage
type InMemoryEpisodicMemory struct {
	episodes map[string]Episode
	tagIndex map[string][]string // tag -> episode IDs
	mutex    sync.RWMutex
	maxSize  int
	logger   *logger.Logger
}

// NewInMemoryEpisodicMemory creates a new in-memory episodic memory
func NewInMemoryEpisodicMemory(maxSize int, logger *logger.Logger) *InMemoryEpisodicMemory {
	return &InMemoryEpisodicMemory{
		episodes: make(map[string]Episode),
		tagIndex: make(map[string][]string),
		maxSize:  maxSize,
		logger:   logger,
	}
}

// StoreEpisode stores an episodic memory
func (m *InMemoryEpisodicMemory) StoreEpisode(ctx context.Context, episode Episode) error {
	ctx, span := episodicTracer.Start(ctx, "episodic_memory.store_episode",
		trace.WithAttributes(
			attribute.String("episode.id", episode.ID),
			attribute.String("episode.title", episode.Title),
		),
	)
	defer span.End()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check size limit
	if len(m.episodes) >= m.maxSize && m.episodes[episode.ID].ID == "" {
		// Remove oldest episode to make space
		if err := m.evictOldestEpisode(); err != nil {
			span.RecordError(err)
			return fmt.Errorf("failed to evict oldest episode: %w", err)
		}
	}

	// Set ID if not provided
	if episode.ID == "" {
		episode.ID = uuid.New().String()
	}

	// Set timestamp if not provided
	if episode.Timestamp.IsZero() {
		episode.Timestamp = time.Now()
	}

	// Store episode
	m.episodes[episode.ID] = episode

	// Update tag index
	m.updateTagIndex(episode.ID, episode.Tags)

	span.SetAttributes(
		attribute.Int("episodes.total", len(m.episodes)),
		attribute.StringSlice("episode.tags", episode.Tags),
		attribute.Bool("success", true),
	)

	m.logger.Debug("Episode stored", 
		"episode_id", episode.ID, 
		"title", episode.Title,
		"tags", episode.Tags,
	)

	return nil
}

// RetrieveEpisodes retrieves episodes based on query
func (m *InMemoryEpisodicMemory) RetrieveEpisodes(ctx context.Context, query EpisodeQuery) ([]Episode, error) {
	ctx, span := episodicTracer.Start(ctx, "episodic_memory.retrieve_episodes",
		trace.WithAttributes(
			attribute.String("query.text", query.Query),
			attribute.StringSlice("query.tags", query.Tags),
			attribute.Int("query.limit", query.Limit),
		),
	)
	defer span.End()

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var candidates []Episode

	// If tags are specified, use tag index for efficient filtering
	if len(query.Tags) > 0 {
		candidateIDs := m.getEpisodesByTags(query.Tags)
		for _, id := range candidateIDs {
			if episode, exists := m.episodes[id]; exists {
				candidates = append(candidates, episode)
			}
		}
	} else {
		// No tags specified, consider all episodes
		for _, episode := range m.episodes {
			candidates = append(candidates, episode)
		}
	}

	// Apply text query filter
	if query.Query != "" {
		candidates = m.filterByTextQuery(candidates, query.Query)
	}

	// Apply time range filter
	if !query.StartTime.IsZero() || !query.EndTime.IsZero() {
		candidates = m.filterByTimeRange(candidates, query.StartTime, query.EndTime)
	}

	// Sort by relevance (timestamp for now, could be enhanced with semantic similarity)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Timestamp.After(candidates[j].Timestamp)
	})

	// Apply limit
	if query.Limit > 0 && len(candidates) > query.Limit {
		candidates = candidates[:query.Limit]
	}

	span.SetAttributes(
		attribute.Int("results.count", len(candidates)),
		attribute.Bool("success", true),
	)

	m.logger.Debug("Episodes retrieved", 
		"query", query.Query,
		"tags", query.Tags,
		"results_count", len(candidates),
	)

	return candidates, nil
}

// UpdateEpisode updates an existing episode
func (m *InMemoryEpisodicMemory) UpdateEpisode(ctx context.Context, episodeID string, episode Episode) error {
	ctx, span := episodicTracer.Start(ctx, "episodic_memory.update_episode",
		trace.WithAttributes(attribute.String("episode.id", episodeID)),
	)
	defer span.End()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	oldEpisode, exists := m.episodes[episodeID]
	if !exists {
		err := fmt.Errorf("episode %s not found", episodeID)
		span.RecordError(err)
		return err
	}

	// Update tag index if tags changed
	if !equalStringSlices(oldEpisode.Tags, episode.Tags) {
		m.removeFromTagIndex(episodeID, oldEpisode.Tags)
		m.updateTagIndex(episodeID, episode.Tags)
	}

	// Preserve ID and update timestamp
	episode.ID = episodeID
	episode.Timestamp = time.Now()

	// Store updated episode
	m.episodes[episodeID] = episode

	span.SetAttributes(attribute.Bool("success", true))
	m.logger.Debug("Episode updated", "episode_id", episodeID)

	return nil
}

// DeleteEpisode deletes an episode
func (m *InMemoryEpisodicMemory) DeleteEpisode(ctx context.Context, episodeID string) error {
	ctx, span := episodicTracer.Start(ctx, "episodic_memory.delete_episode",
		trace.WithAttributes(attribute.String("episode.id", episodeID)),
	)
	defer span.End()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	episode, exists := m.episodes[episodeID]
	if !exists {
		err := fmt.Errorf("episode %s not found", episodeID)
		span.RecordError(err)
		return err
	}

	// Remove from tag index
	m.removeFromTagIndex(episodeID, episode.Tags)

	// Delete episode
	delete(m.episodes, episodeID)

	span.SetAttributes(attribute.Bool("success", true))
	m.logger.Debug("Episode deleted", "episode_id", episodeID)

	return nil
}

// GetEpisodeCount returns the number of stored episodes
func (m *InMemoryEpisodicMemory) GetEpisodeCount(ctx context.Context) (int, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return len(m.episodes), nil
}

// GetEpisodesByTimeRange retrieves episodes within a time range
func (m *InMemoryEpisodicMemory) GetEpisodesByTimeRange(ctx context.Context, start, end time.Time, limit int) ([]Episode, error) {
	query := EpisodeQuery{
		StartTime: start,
		EndTime:   end,
		Limit:     limit,
	}
	return m.RetrieveEpisodes(ctx, query)
}

// GetRecentEpisodes retrieves the most recent episodes
func (m *InMemoryEpisodicMemory) GetRecentEpisodes(ctx context.Context, limit int) ([]Episode, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var episodes []Episode
	for _, episode := range m.episodes {
		episodes = append(episodes, episode)
	}

	// Sort by timestamp (newest first)
	sort.Slice(episodes, func(i, j int) bool {
		return episodes[i].Timestamp.After(episodes[j].Timestamp)
	})

	// Apply limit
	if limit > 0 && len(episodes) > limit {
		episodes = episodes[:limit]
	}

	return episodes, nil
}

// Helper methods

// evictOldestEpisode removes the oldest episode to make space
func (m *InMemoryEpisodicMemory) evictOldestEpisode() error {
	if len(m.episodes) == 0 {
		return nil
	}

	var oldestID string
	var oldestTime time.Time

	for id, episode := range m.episodes {
		if oldestID == "" || episode.Timestamp.Before(oldestTime) {
			oldestID = id
			oldestTime = episode.Timestamp
		}
	}

	if oldestID != "" {
		episode := m.episodes[oldestID]
		m.removeFromTagIndex(oldestID, episode.Tags)
		delete(m.episodes, oldestID)
		m.logger.Debug("Evicted oldest episode", "episode_id", oldestID)
	}

	return nil
}

// updateTagIndex updates the tag index for an episode
func (m *InMemoryEpisodicMemory) updateTagIndex(episodeID string, tags []string) {
	for _, tag := range tags {
		if !contains(m.tagIndex[tag], episodeID) {
			m.tagIndex[tag] = append(m.tagIndex[tag], episodeID)
		}
	}
}

// removeFromTagIndex removes an episode from the tag index
func (m *InMemoryEpisodicMemory) removeFromTagIndex(episodeID string, tags []string) {
	for _, tag := range tags {
		m.tagIndex[tag] = removeString(m.tagIndex[tag], episodeID)
		if len(m.tagIndex[tag]) == 0 {
			delete(m.tagIndex, tag)
		}
	}
}

// getEpisodesByTags gets episode IDs that match any of the given tags
func (m *InMemoryEpisodicMemory) getEpisodesByTags(tags []string) []string {
	episodeSet := make(map[string]bool)
	
	for _, tag := range tags {
		if episodeIDs, exists := m.tagIndex[tag]; exists {
			for _, id := range episodeIDs {
				episodeSet[id] = true
			}
		}
	}

	var result []string
	for id := range episodeSet {
		result = append(result, id)
	}

	return result
}

// filterByTextQuery filters episodes by text query
func (m *InMemoryEpisodicMemory) filterByTextQuery(episodes []Episode, query string) []Episode {
	query = strings.ToLower(query)
	var filtered []Episode

	for _, episode := range episodes {
		if m.episodeMatchesQuery(episode, query) {
			filtered = append(filtered, episode)
		}
	}

	return filtered
}

// episodeMatchesQuery checks if an episode matches a text query
func (m *InMemoryEpisodicMemory) episodeMatchesQuery(episode Episode, query string) bool {
	searchText := strings.ToLower(episode.Title + " " + episode.Description + " " + episode.Context + " " + episode.Outcome)
	return strings.Contains(searchText, query)
}

// filterByTimeRange filters episodes by time range
func (m *InMemoryEpisodicMemory) filterByTimeRange(episodes []Episode, start, end time.Time) []Episode {
	var filtered []Episode

	for _, episode := range episodes {
		if !start.IsZero() && episode.Timestamp.Before(start) {
			continue
		}
		if !end.IsZero() && episode.Timestamp.After(end) {
			continue
		}
		filtered = append(filtered, episode)
	}

	return filtered
}

// Utility functions

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// removeString removes a string from a slice
func removeString(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

// equalStringSlices checks if two string slices are equal
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
