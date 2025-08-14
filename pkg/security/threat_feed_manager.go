package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ThreatFeedManager manages threat intelligence feeds
type ThreatFeedManager struct {
	config *ThreatIntelligenceConfig
	logger Logger
	feeds  map[string]*ThreatFeed
	client *http.Client
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// NewThreatFeedManager creates a new threat feed manager
func NewThreatFeedManager(config *ThreatIntelligenceConfig, logger Logger) *ThreatFeedManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &ThreatFeedManager{
		config: config,
		logger: logger,
		feeds:  make(map[string]*ThreatFeed),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start starts the threat feed manager
func (tfm *ThreatFeedManager) Start() error {
	tfm.logger.Info("Starting threat feed manager")

	// Initialize feeds from configuration
	for _, feedConfig := range tfm.config.FeedConfigs {
		feed := &ThreatFeed{
			ID:         feedConfig.ID,
			Name:       feedConfig.Name,
			URL:        feedConfig.URL,
			Type:       feedConfig.Type,
			Enabled:    feedConfig.Enabled,
			UpdateFreq: feedConfig.UpdateFrequency,
		}

		tfm.mu.Lock()
		tfm.feeds[feed.ID] = feed
		tfm.mu.Unlock()
	}

	// Start feed update worker
	tfm.wg.Add(1)
	go tfm.feedUpdateWorker()

	return nil
}

// Stop stops the threat feed manager
func (tfm *ThreatFeedManager) Stop() error {
	tfm.logger.Info("Stopping threat feed manager")

	tfm.cancel()
	tfm.wg.Wait()

	return nil
}

// GetFeed gets a threat feed by ID
func (tfm *ThreatFeedManager) GetFeed(feedID string) (*ThreatFeed, error) {
	tfm.mu.RLock()
	defer tfm.mu.RUnlock()

	feed, exists := tfm.feeds[feedID]
	if !exists {
		return nil, fmt.Errorf("feed not found: %s", feedID)
	}

	return feed, nil
}

// ListFeeds lists all threat feeds
func (tfm *ThreatFeedManager) ListFeeds() []*ThreatFeed {
	tfm.mu.RLock()
	defer tfm.mu.RUnlock()

	feeds := make([]*ThreatFeed, 0, len(tfm.feeds))
	for _, feed := range tfm.feeds {
		feeds = append(feeds, feed)
	}

	return feeds
}

// UpdateFeed manually updates a specific feed
func (tfm *ThreatFeedManager) UpdateFeed(feedID string) error {
	feed, err := tfm.GetFeed(feedID)
	if err != nil {
		return err
	}

	if !feed.Enabled {
		return fmt.Errorf("feed is disabled: %s", feedID)
	}

	return tfm.fetchFeedData(feed)
}

// GetStatistics returns feed manager statistics
func (tfm *ThreatFeedManager) GetStatistics() map[string]interface{} {
	tfm.mu.RLock()
	defer tfm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_feeds"] = len(tfm.feeds)

	enabledCount := 0
	totalIndicators := 0

	for _, feed := range tfm.feeds {
		if feed.Enabled {
			enabledCount++
		}
		// Note: IndicatorCount not available in base ThreatFeed type
	}

	stats["enabled_feeds"] = enabledCount
	stats["total_indicators"] = totalIndicators

	return stats
}

// feedUpdateWorker background worker for updating feeds
func (tfm *ThreatFeedManager) feedUpdateWorker() {
	defer tfm.wg.Done()

	ticker := time.NewTicker(tfm.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tfm.ctx.Done():
			return
		case <-ticker.C:
			tfm.updateAllFeeds()
		}
	}
}

// updateAllFeeds updates all enabled feeds
func (tfm *ThreatFeedManager) updateAllFeeds() {
	tfm.mu.RLock()
	feeds := make([]*ThreatFeed, 0, len(tfm.feeds))
	for _, feed := range tfm.feeds {
		if feed.Enabled {
			feeds = append(feeds, feed)
		}
	}
	tfm.mu.RUnlock()

	for _, feed := range feeds {
		if time.Since(feed.LastUpdated) >= feed.UpdateFreq {
			if err := tfm.fetchFeedData(feed); err != nil {
				tfm.logger.Error("Failed to update feed", "feed_id", feed.ID, "error", err)
			}
		}
	}
}

// fetchFeedData fetches data from a threat feed
func (tfm *ThreatFeedManager) fetchFeedData(feed *ThreatFeed) error {
	tfm.logger.Info("Updating threat feed", "feed_id", feed.ID, "url", feed.URL)

	req, err := http.NewRequestWithContext(tfm.ctx, "GET", feed.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Note: Authentication not available in base ThreatFeed type
	// Authentication would be handled through configuration

	resp, err := tfm.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch feed data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("feed returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse feed data based on format (using JSON as default)
	indicators, err := tfm.parseFeedData(data, "json")
	if err != nil {
		return fmt.Errorf("failed to parse feed data: %w", err)
	}

	// Update feed metadata
	tfm.mu.Lock()
	feed.LastUpdated = time.Now()
	// Note: IndicatorCount not available in base ThreatFeed type
	tfm.mu.Unlock()

	tfm.logger.Info("Feed updated successfully",
		"feed_id", feed.ID,
		"indicators", len(indicators))

	return nil
}

// addAuthentication adds authentication to HTTP request
func (tfm *ThreatFeedManager) addAuthentication(req *http.Request, auth *FeedAuthentication) {
	switch auth.Type {
	case "api_key":
		req.Header.Set("X-API-Key", auth.APIKey)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+auth.Token)
	case "basic":
		req.SetBasicAuth(auth.Username, auth.Password)
	case "headers":
		for key, value := range auth.Headers {
			req.Header.Set(key, value)
		}
	}
}

// parseFeedData parses threat feed data based on format
func (tfm *ThreatFeedManager) parseFeedData(data []byte, format string) ([]*ThreatIndicator, error) {
	switch format {
	case "json":
		return tfm.parseJSONFeed(data)
	case "csv":
		return tfm.parseCSVFeed(data)
	case "stix":
		return tfm.parseSTIXFeed(data)
	case "misp":
		return tfm.parseMISPFeed(data)
	default:
		return nil, fmt.Errorf("unsupported feed format: %s", format)
	}
}

// parseJSONFeed parses JSON format threat feed
func (tfm *ThreatFeedManager) parseJSONFeed(data []byte) ([]*ThreatIndicator, error) {
	var feedData struct {
		Indicators []*ThreatIndicator `json:"indicators"`
	}

	if err := json.Unmarshal(data, &feedData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON feed: %w", err)
	}

	return feedData.Indicators, nil
}

// parseCSVFeed parses CSV format threat feed
func (tfm *ThreatFeedManager) parseCSVFeed(data []byte) ([]*ThreatIndicator, error) {
	// Simplified CSV parsing - in production, use proper CSV parser
	lines := strings.Split(string(data), "\n")
	var indicators []*ThreatIndicator

	for i, line := range lines {
		if i == 0 || line == "" {
			continue // Skip header and empty lines
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 3 {
			indicator := &ThreatIndicator{
				ID:         fmt.Sprintf("csv_%d_%d", i, time.Now().UnixNano()),
				Type:       strings.TrimSpace(fields[0]),
				Value:      strings.TrimSpace(fields[1]),
				Severity:   strings.TrimSpace(fields[2]),
				Confidence: 0.7, // Default confidence
				Source:     "CSV Feed",
				FirstSeen:  time.Now(),
				LastSeen:   time.Now(),
			}
			indicators = append(indicators, indicator)
		}
	}

	return indicators, nil
}

// parseSTIXFeed parses STIX format threat feed
func (tfm *ThreatFeedManager) parseSTIXFeed(data []byte) ([]*ThreatIndicator, error) {
	// Simplified STIX parsing - in production, use proper STIX parser
	var indicators []*ThreatIndicator

	// For now, return empty slice - full STIX parsing would be complex
	tfm.logger.Info("STIX feed parsing not fully implemented")

	return indicators, nil
}

// parseMISPFeed parses MISP format threat feed
func (tfm *ThreatFeedManager) parseMISPFeed(data []byte) ([]*ThreatIndicator, error) {
	// Simplified MISP parsing - in production, use proper MISP parser
	var indicators []*ThreatIndicator

	// For now, return empty slice - full MISP parsing would be complex
	tfm.logger.Info("MISP feed parsing not fully implemented")

	return indicators, nil
}
