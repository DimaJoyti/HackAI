package security

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// ReputationEngine manages reputation scoring for indicators
type ReputationEngine struct {
	config         *ThreatIntelligenceConfig
	logger         Logger
	reputationData map[string]*ReputationScore
	sources        map[string]*ReputationSource
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	mu             sync.RWMutex
}

// ReputationScore represents reputation scoring data
type ReputationScore struct {
	Indicator      string                 `json:"indicator"`
	Type           string                 `json:"type"`
	OverallScore   float64                `json:"overall_score"`
	SourceScores   map[string]float64     `json:"source_scores"`
	Categories     map[string]float64     `json:"categories"`
	LastUpdated    time.Time              `json:"last_updated"`
	Confidence     float64                `json:"confidence"`
	Factors        []string               `json:"factors"`
	History        []*ScoreHistory        `json:"history"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// ScoreHistory represents historical reputation scores
type ScoreHistory struct {
	Timestamp time.Time `json:"timestamp"`
	Score     float64   `json:"score"`
	Source    string    `json:"source"`
	Reason    string    `json:"reason"`
}

// ReputationSource represents a reputation data source
type ReputationSource struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Enabled     bool      `json:"enabled"`
	Weight      float64   `json:"weight"`
	Reliability float64   `json:"reliability"`
	LastUpdated time.Time `json:"last_updated"`
	APIKey      string    `json:"api_key,omitempty"`
	URL         string    `json:"url,omitempty"`
}

// NewReputationEngine creates a new reputation engine
func NewReputationEngine(config *ThreatIntelligenceConfig, logger Logger) *ReputationEngine {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &ReputationEngine{
		config:         config,
		logger:         logger,
		reputationData: make(map[string]*ReputationScore),
		sources:        make(map[string]*ReputationSource),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Start starts the reputation engine
func (re *ReputationEngine) Start() error {
	re.logger.Info("Starting reputation engine")
	
	// Initialize reputation sources
	re.initializeSources()
	
	// Start background workers
	re.wg.Add(2)
	go re.scoreUpdateWorker()
	go re.cleanupWorker()
	
	return nil
}

// Stop stops the reputation engine
func (re *ReputationEngine) Stop() error {
	re.logger.Info("Stopping reputation engine")
	
	re.cancel()
	re.wg.Wait()
	
	return nil
}

// GetScore gets reputation score for an indicator
func (re *ReputationEngine) GetScore(indicator, indicatorType string) (float64, error) {
	if !re.config.ReputationScoring {
		return 0.0, nil
	}
	
	re.mu.RLock()
	defer re.mu.RUnlock()
	
	key := fmt.Sprintf("%s:%s", indicatorType, indicator)
	if score, exists := re.reputationData[key]; exists {
		// Update last accessed time
		score.LastUpdated = time.Now()
		return score.OverallScore, nil
	}
	
	// Calculate score if not cached
	return re.calculateScore(indicator, indicatorType)
}

// UpdateScore updates reputation score for an indicator
func (re *ReputationEngine) UpdateScore(indicator, indicatorType string, score float64, source, reason string) error {
	re.mu.Lock()
	defer re.mu.Unlock()
	
	key := fmt.Sprintf("%s:%s", indicatorType, indicator)
	
	reputationScore, exists := re.reputationData[key]
	if !exists {
		reputationScore = &ReputationScore{
			Indicator:    indicator,
			Type:         indicatorType,
			SourceScores: make(map[string]float64),
			Categories:   make(map[string]float64),
			History:      []*ScoreHistory{},
			Metadata:     make(map[string]interface{}),
		}
		re.reputationData[key] = reputationScore
	}
	
	// Update source score
	reputationScore.SourceScores[source] = score
	
	// Add to history
	reputationScore.History = append(reputationScore.History, &ScoreHistory{
		Timestamp: time.Now(),
		Score:     score,
		Source:    source,
		Reason:    reason,
	})
	
	// Recalculate overall score
	reputationScore.OverallScore = re.calculateOverallScore(reputationScore.SourceScores)
	reputationScore.LastUpdated = time.Now()
	reputationScore.Confidence = re.calculateConfidence(reputationScore.SourceScores)
	
	re.logger.Info("Reputation score updated",
		"indicator", indicator,
		"type", indicatorType,
		"score", score,
		"overall", reputationScore.OverallScore,
		"source", source)
	
	return nil
}

// GetReputationData gets detailed reputation data for an indicator
func (re *ReputationEngine) GetReputationData(indicator, indicatorType string) (*ReputationScore, error) {
	re.mu.RLock()
	defer re.mu.RUnlock()
	
	key := fmt.Sprintf("%s:%s", indicatorType, indicator)
	if score, exists := re.reputationData[key]; exists {
		return score, nil
	}
	
	return nil, fmt.Errorf("reputation data not found for %s", indicator)
}

// GetStatistics returns reputation engine statistics
func (re *ReputationEngine) GetStatistics() map[string]interface{} {
	re.mu.RLock()
	defer re.mu.RUnlock()
	
	stats := make(map[string]interface{})
	stats["total_scores"] = len(re.reputationData)
	stats["total_sources"] = len(re.sources)
	
	// Count by type
	typeCount := make(map[string]int)
	scoreDistribution := make(map[string]int)
	
	for _, score := range re.reputationData {
		typeCount[score.Type]++
		
		// Categorize scores
		switch {
		case score.OverallScore >= 0.8:
			scoreDistribution["excellent"]++
		case score.OverallScore >= 0.6:
			scoreDistribution["good"]++
		case score.OverallScore >= 0.4:
			scoreDistribution["fair"]++
		case score.OverallScore >= 0.2:
			scoreDistribution["poor"]++
		default:
			scoreDistribution["bad"]++
		}
	}
	
	stats["by_type"] = typeCount
	stats["score_distribution"] = scoreDistribution
	
	return stats
}

// calculateScore calculates reputation score for an indicator
func (re *ReputationEngine) calculateScore(indicator, indicatorType string) (float64, error) {
	// Simulate reputation calculation
	// In production, this would query multiple reputation sources
	
	baseScore := 0.5 // Neutral score
	
	// Simulate different scoring based on indicator characteristics
	switch indicatorType {
	case "ip":
		baseScore = re.calculateIPReputation(indicator)
	case "domain":
		baseScore = re.calculateDomainReputation(indicator)
	case "url":
		baseScore = re.calculateURLReputation(indicator)
	case "hash":
		baseScore = re.calculateHashReputation(indicator)
	}
	
	return baseScore, nil
}

// calculateIPReputation calculates IP reputation
func (re *ReputationEngine) calculateIPReputation(ip string) float64 {
	score := 0.5
	
	// Simulate reputation factors
	if ip == "203.0.113.1" {
		score = 0.1 // Known bad IP
	} else if ip == "8.8.8.8" {
		score = 0.9 // Known good IP (Google DNS)
	}
	
	return score
}

// calculateDomainReputation calculates domain reputation
func (re *ReputationEngine) calculateDomainReputation(domain string) float64 {
	score := 0.5
	
	// Simulate reputation factors
	if domain == "malicious.example.com" {
		score = 0.1 // Known bad domain
	} else if domain == "google.com" {
		score = 0.95 // Known good domain
	}
	
	return score
}

// calculateURLReputation calculates URL reputation
func (re *ReputationEngine) calculateURLReputation(url string) float64 {
	score := 0.5
	
	// Simulate reputation factors based on URL characteristics
	if contains(url, "phishing") || contains(url, "malware") {
		score = 0.1
	} else if contains(url, "https://") {
		score += 0.1 // Bonus for HTTPS
	}
	
	return score
}

// calculateHashReputation calculates hash reputation
func (re *ReputationEngine) calculateHashReputation(hash string) float64 {
	score := 0.5
	
	// Simulate reputation factors
	if hash == "d41d8cd98f00b204e9800998ecf8427e" {
		score = 0.05 // Known malware hash
	}
	
	return score
}

// calculateOverallScore calculates overall score from source scores
func (re *ReputationEngine) calculateOverallScore(sourceScores map[string]float64) float64 {
	if len(sourceScores) == 0 {
		return 0.5 // Neutral score
	}
	
	totalWeight := 0.0
	weightedSum := 0.0
	
	for source, score := range sourceScores {
		weight := 1.0 // Default weight
		
		if reputationSource, exists := re.sources[source]; exists {
			weight = reputationSource.Weight * reputationSource.Reliability
		}
		
		weightedSum += score * weight
		totalWeight += weight
	}
	
	if totalWeight == 0 {
		return 0.5
	}
	
	return weightedSum / totalWeight
}

// calculateConfidence calculates confidence based on source scores
func (re *ReputationEngine) calculateConfidence(sourceScores map[string]float64) float64 {
	if len(sourceScores) == 0 {
		return 0.0
	}
	
	// Calculate confidence based on number of sources and score variance
	sourceCount := float64(len(sourceScores))
	
	// Base confidence increases with more sources
	baseConfidence := math.Min(sourceCount/10.0, 0.8)
	
	// Reduce confidence if scores vary widely
	if len(sourceScores) > 1 {
		var scores []float64
		for _, score := range sourceScores {
			scores = append(scores, score)
		}
		
		variance := calculateVariance(scores)
		variancePenalty := variance * 0.5
		
		return math.Max(baseConfidence-variancePenalty, 0.1)
	}
	
	return baseConfidence
}

// initializeSources initializes reputation sources
func (re *ReputationEngine) initializeSources() {
	sources := []*ReputationSource{
		{
			ID:          "internal",
			Name:        "Internal Threat Intelligence",
			Type:        "internal",
			Enabled:     true,
			Weight:      1.0,
			Reliability: 0.9,
		},
		{
			ID:          "virustotal",
			Name:        "VirusTotal",
			Type:        "external",
			Enabled:     true,
			Weight:      0.8,
			Reliability: 0.85,
		},
		{
			ID:          "alienvault",
			Name:        "AlienVault OTX",
			Type:        "external",
			Enabled:     true,
			Weight:      0.7,
			Reliability: 0.8,
		},
	}
	
	for _, source := range sources {
		re.sources[source.ID] = source
	}
	
	re.logger.Info("Reputation sources initialized", "count", len(sources))
}

// scoreUpdateWorker background worker for updating scores
func (re *ReputationEngine) scoreUpdateWorker() {
	defer re.wg.Done()
	
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-re.ctx.Done():
			return
		case <-ticker.C:
			re.updateStaleScores()
		}
	}
}

// cleanupWorker background worker for cleaning up old data
func (re *ReputationEngine) cleanupWorker() {
	defer re.wg.Done()
	
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-re.ctx.Done():
			return
		case <-ticker.C:
			re.cleanupOldData()
		}
	}
}

// updateStaleScores updates scores that haven't been updated recently
func (re *ReputationEngine) updateStaleScores() {
	re.mu.RLock()
	staleScores := make([]*ReputationScore, 0)
	cutoff := time.Now().Add(-24 * time.Hour)
	
	for _, score := range re.reputationData {
		if score.LastUpdated.Before(cutoff) {
			staleScores = append(staleScores, score)
		}
	}
	re.mu.RUnlock()
	
	for _, score := range staleScores {
		// Recalculate score
		newScore, _ := re.calculateScore(score.Indicator, score.Type)
		re.UpdateScore(score.Indicator, score.Type, newScore, "auto_update", "scheduled_update")
	}
	
	if len(staleScores) > 0 {
		re.logger.Info("Updated stale reputation scores", "count", len(staleScores))
	}
}

// cleanupOldData removes old reputation data
func (re *ReputationEngine) cleanupOldData() {
	re.mu.Lock()
	defer re.mu.Unlock()
	
	cutoff := time.Now().Add(-30 * 24 * time.Hour) // 30 days
	var removedCount int
	
	for key, score := range re.reputationData {
		if score.LastUpdated.Before(cutoff) {
			delete(re.reputationData, key)
			removedCount++
		}
	}
	
	if removedCount > 0 {
		re.logger.Info("Cleaned up old reputation data", "count", removedCount)
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr || 
		   len(s) >= len(substr) && s[:len(substr)] == substr ||
		   len(s) > len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func calculateVariance(scores []float64) float64 {
	if len(scores) <= 1 {
		return 0.0
	}
	
	// Calculate mean
	sum := 0.0
	for _, score := range scores {
		sum += score
	}
	mean := sum / float64(len(scores))
	
	// Calculate variance
	sumSquaredDiff := 0.0
	for _, score := range scores {
		diff := score - mean
		sumSquaredDiff += diff * diff
	}
	
	return sumSquaredDiff / float64(len(scores))
}
