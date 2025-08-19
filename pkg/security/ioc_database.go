package security

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// IOCDatabase manages indicators of compromise
type IOCDatabase struct {
	config     *ThreatIntelligenceConfig
	logger     Logger
	indicators map[string]*ThreatIndicator
	indices    map[string]map[string]*ThreatIndicator // type -> value -> indicator
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
}

// NewIOCDatabase creates a new IOC database
func NewIOCDatabase(config *ThreatIntelligenceConfig, logger Logger) *IOCDatabase {
	ctx, cancel := context.WithCancel(context.Background())

	return &IOCDatabase{
		config:     config,
		logger:     logger,
		indicators: make(map[string]*ThreatIndicator),
		indices:    make(map[string]map[string]*ThreatIndicator),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the IOC database
func (ioc *IOCDatabase) Start() error {
	ioc.logger.Info("Starting IOC database")

	// Initialize indices for each IOC type
	for _, iocType := range ioc.config.IOCTypes {
		ioc.indices[iocType] = make(map[string]*ThreatIndicator)
	}

	// Load initial IOC data
	ioc.loadInitialIOCs()

	// Start cleanup worker
	ioc.wg.Add(1)
	go ioc.cleanupWorker()

	return nil
}

// Stop stops the IOC database
func (ioc *IOCDatabase) Stop() error {
	ioc.logger.Info("Stopping IOC database")

	ioc.cancel()
	ioc.wg.Wait()

	return nil
}

// Add adds a new indicator to the database
func (ioc *IOCDatabase) Add(indicator *ThreatIndicator) error {
	if indicator == nil {
		return fmt.Errorf("indicator cannot be nil")
	}

	if indicator.Value == "" {
		return fmt.Errorf("indicator value cannot be empty")
	}

	ioc.mu.Lock()
	defer ioc.mu.Unlock()

	// Generate ID if not provided
	if indicator.ID == "" {
		indicator.ID = fmt.Sprintf("ioc_%s_%d", indicator.Type, time.Now().UnixNano())
	}

	// Set timestamps if not provided
	if indicator.FirstSeen.IsZero() {
		indicator.FirstSeen = time.Now()
	}
	if indicator.LastSeen.IsZero() {
		indicator.LastSeen = time.Now()
	}

	// Add to main storage
	ioc.indicators[indicator.ID] = indicator

	// Add to type index
	if _, exists := ioc.indices[indicator.Type]; !exists {
		ioc.indices[indicator.Type] = make(map[string]*ThreatIndicator)
	}
	ioc.indices[indicator.Type][indicator.Value] = indicator

	ioc.logger.Info("IOC added",
		"id", indicator.ID,
		"type", indicator.Type,
		"value", indicator.Value,
		"severity", indicator.Severity)

	return nil
}

// Lookup looks up an indicator by value and type
func (ioc *IOCDatabase) Lookup(value, indicatorType string) (*ThreatIndicator, error) {
	ioc.mu.RLock()
	defer ioc.mu.RUnlock()

	if typeIndex, exists := ioc.indices[indicatorType]; exists {
		if indicator, found := typeIndex[value]; found {
			// Update last seen
			indicator.LastSeen = time.Now()
			return indicator, nil
		}
	}

	return nil, nil // Not found, but not an error
}

// Update updates an existing indicator
func (ioc *IOCDatabase) Update(indicator *ThreatIndicator) error {
	if indicator == nil || indicator.ID == "" {
		return fmt.Errorf("invalid indicator for update")
	}

	ioc.mu.Lock()
	defer ioc.mu.Unlock()

	existing, exists := ioc.indicators[indicator.ID]
	if !exists {
		return fmt.Errorf("indicator not found: %s", indicator.ID)
	}

	// Remove from old type index if type changed
	if existing.Type != indicator.Type {
		if typeIndex, exists := ioc.indices[existing.Type]; exists {
			delete(typeIndex, existing.Value)
		}
	}

	// Update indicator
	indicator.LastSeen = time.Now()
	ioc.indicators[indicator.ID] = indicator

	// Update type index
	if _, exists := ioc.indices[indicator.Type]; !exists {
		ioc.indices[indicator.Type] = make(map[string]*ThreatIndicator)
	}
	ioc.indices[indicator.Type][indicator.Value] = indicator

	ioc.logger.Info("IOC updated", "id", indicator.ID)

	return nil
}

// Delete deletes an indicator
func (ioc *IOCDatabase) Delete(indicatorID string) error {
	ioc.mu.Lock()
	defer ioc.mu.Unlock()

	indicator, exists := ioc.indicators[indicatorID]
	if !exists {
		return fmt.Errorf("indicator not found: %s", indicatorID)
	}

	// Remove from main storage
	delete(ioc.indicators, indicatorID)

	// Remove from type index
	if typeIndex, exists := ioc.indices[indicator.Type]; exists {
		delete(typeIndex, indicator.Value)
	}

	ioc.logger.Info("IOC deleted", "id", indicatorID)

	return nil
}

// Search searches for indicators based on criteria
func (ioc *IOCDatabase) Search(criteria *SearchCriteria) ([]*ThreatIndicator, error) {
	ioc.mu.RLock()
	defer ioc.mu.RUnlock()

	var results []*ThreatIndicator

	for _, indicator := range ioc.indicators {
		if ioc.matchesCriteria(indicator, criteria) {
			results = append(results, indicator)
		}
	}

	return results, nil
}

// SearchCriteria search criteria for IOCs
type SearchCriteria struct {
	Type          string     `json:"type,omitempty"`
	Value         string     `json:"value,omitempty"`
	Severity      string     `json:"severity,omitempty"`
	Source        string     `json:"source,omitempty"`
	Tags          []string   `json:"tags,omitempty"`
	MinConfidence float64    `json:"min_confidence,omitempty"`
	Since         *time.Time `json:"since,omitempty"`
	Until         *time.Time `json:"until,omitempty"`
}

// matchesCriteria checks if an indicator matches search criteria
func (ioc *IOCDatabase) matchesCriteria(indicator *ThreatIndicator, criteria *SearchCriteria) bool {
	if criteria.Type != "" && indicator.Type != criteria.Type {
		return false
	}

	if criteria.Value != "" && !strings.Contains(indicator.Value, criteria.Value) {
		return false
	}

	if criteria.Severity != "" && indicator.Severity != criteria.Severity {
		return false
	}

	if criteria.Source != "" && !strings.Contains(indicator.Source, criteria.Source) {
		return false
	}

	if criteria.MinConfidence > 0 && indicator.Confidence < criteria.MinConfidence {
		return false
	}

	if criteria.Since != nil && indicator.FirstSeen.Before(*criteria.Since) {
		return false
	}

	if criteria.Until != nil && indicator.FirstSeen.After(*criteria.Until) {
		return false
	}

	if len(criteria.Tags) > 0 {
		hasTag := false
		for _, criteriaTag := range criteria.Tags {
			for _, indicatorTag := range indicator.Tags {
				if strings.Contains(indicatorTag, criteriaTag) {
					hasTag = true
					break
				}
			}
			if hasTag {
				break
			}
		}
		if !hasTag {
			return false
		}
	}

	return true
}

// GetByType gets all indicators of a specific type
func (ioc *IOCDatabase) GetByType(indicatorType string) ([]*ThreatIndicator, error) {
	ioc.mu.RLock()
	defer ioc.mu.RUnlock()

	var indicators []*ThreatIndicator

	if typeIndex, exists := ioc.indices[indicatorType]; exists {
		for _, indicator := range typeIndex {
			indicators = append(indicators, indicator)
		}
	}

	return indicators, nil
}

// GetStatistics returns IOC database statistics
func (ioc *IOCDatabase) GetStatistics() map[string]interface{} {
	ioc.mu.RLock()
	defer ioc.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_indicators"] = len(ioc.indicators)

	// Count by type
	typeCount := make(map[string]int)
	severityCount := make(map[string]int)
	sourceCount := make(map[string]int)

	for _, indicator := range ioc.indicators {
		typeCount[indicator.Type]++
		severityCount[indicator.Severity]++
		sourceCount[indicator.Source]++
	}

	stats["by_type"] = typeCount
	stats["by_severity"] = severityCount
	stats["by_source"] = sourceCount

	return stats
}

// loadInitialIOCs loads initial IOC data
func (ioc *IOCDatabase) loadInitialIOCs() {
	// Load some sample IOCs for demonstration
	sampleIOCs := []*ThreatIndicator{
		{
			Type:        "ip",
			Value:       "203.0.113.1",
			Confidence:  0.9,
			Severity:    "high",
			Source:      "Internal",
			Description: "Known malicious IP",
			Tags:        []string{"malware", "botnet"},
		},
		{
			Type:        "domain",
			Value:       "malicious.example.com",
			Confidence:  0.8,
			Severity:    "medium",
			Source:      "External Feed",
			Description: "Suspicious domain",
			Tags:        []string{"phishing"},
		},
		{
			Type:        "hash",
			Value:       "d41d8cd98f00b204e9800998ecf8427e",
			Confidence:  0.95,
			Severity:    "high",
			Source:      "Malware Database",
			Description: "Known malware hash",
			Tags:        []string{"malware", "trojan"},
		},
	}

	for _, indicator := range sampleIOCs {
		if err := ioc.Add(indicator); err != nil {
			ioc.logger.Error("Failed to add sample IOC", "error", err)
		}
	}

	ioc.logger.Info("Initial IOCs loaded", "count", len(sampleIOCs))
}

// cleanupWorker background worker for cleaning up expired IOCs
func (ioc *IOCDatabase) cleanupWorker() {
	defer ioc.wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ioc.ctx.Done():
			return
		case <-ticker.C:
			ioc.cleanupExpiredIOCs()
		}
	}
}

// cleanupExpiredIOCs removes expired IOCs
func (ioc *IOCDatabase) cleanupExpiredIOCs() {
	ioc.mu.Lock()
	defer ioc.mu.Unlock()

	now := time.Now()
	var expiredIDs []string

	// Note: ExpiresAt field not available in base ThreatIndicator type
	// Cleanup based on LastSeen timestamp instead
	cutoff := now.Add(-30 * 24 * time.Hour) // 30 days
	for id, indicator := range ioc.indicators {
		if indicator.LastSeen.Before(cutoff) {
			expiredIDs = append(expiredIDs, id)
		}
	}

	for _, id := range expiredIDs {
		indicator := ioc.indicators[id]
		delete(ioc.indicators, id)

		// Remove from type index
		if typeIndex, exists := ioc.indices[indicator.Type]; exists {
			delete(typeIndex, indicator.Value)
		}
	}

	if len(expiredIDs) > 0 {
		ioc.logger.Info("Cleaned up expired IOCs", "count", len(expiredIDs))
	}
}

// GetIOC retrieves an IOC by indicator value
func (ioc *IOCDatabase) GetIOC(ctx context.Context, indicator string) (*ThreatIndicator, error) {
	ioc.mu.RLock()
	defer ioc.mu.RUnlock()

	// Search through all indicators
	for _, threatIndicator := range ioc.indicators {
		if threatIndicator.Value == indicator {
			return threatIndicator, nil
		}
	}

	return nil, fmt.Errorf("IOC not found: %s", indicator)
}
