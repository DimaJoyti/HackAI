package assessment

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// QuantumThreatIntelligence monitors quantum computing advances and threats
type QuantumThreatIntelligence struct {
	logger      *logger.Logger
	config      *ThreatIntelConfig
	sources     map[string]ThreatSource
	cache       *ThreatCache
	subscribers map[string]chan *ThreatUpdate
	mutex       sync.RWMutex
	running     bool
	stopChan    chan struct{}
}

// ThreatIntelConfig holds configuration for threat intelligence
type ThreatIntelConfig struct {
	UpdateInterval  time.Duration      `json:"update_interval"`
	CacheExpiry     time.Duration      `json:"cache_expiry"`
	MaxCacheSize    int                `json:"max_cache_size"`
	EnableRealTime  bool               `json:"enable_real_time"`
	ThreatThreshold float64            `json:"threat_threshold"`
	AlertingEnabled bool               `json:"alerting_enabled"`
	SourceWeights   map[string]float64 `json:"source_weights"`
}

// ThreatSource interface for different threat intelligence sources
type ThreatSource interface {
	GetName() string
	GetType() string
	FetchThreatData(ctx context.Context) ([]*ThreatIndicator, error)
	GetReliability() float64
	GetLastUpdate() time.Time
	IsEnabled() bool
}

// ThreatCache manages cached threat intelligence data
type ThreatCache struct {
	data    map[string]*CachedThreat
	mutex   sync.RWMutex
	maxSize int
	expiry  time.Duration
}

// CachedThreat represents cached threat data
type CachedThreat struct {
	Threat    *ThreatIndicator `json:"threat"`
	Timestamp time.Time        `json:"timestamp"`
	Source    string           `json:"source"`
	TTL       time.Duration    `json:"ttl"`
}

// ThreatIndicator represents a quantum threat indicator
type ThreatIndicator struct {
	ID                 string                 `json:"id"`
	Type               ThreatType             `json:"type"`
	Severity           SeverityLevel          `json:"severity"`
	Confidence         float64                `json:"confidence"`
	Title              string                 `json:"title"`
	Description        string                 `json:"description"`
	Source             string                 `json:"source"`
	SourceURL          string                 `json:"source_url"`
	PublishedAt        time.Time              `json:"published_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
	ExpiresAt          time.Time              `json:"expires_at"`
	Tags               []string               `json:"tags"`
	AffectedAlgorithms []string               `json:"affected_algorithms"`
	ImpactAssessment   *ImpactAssessment      `json:"impact_assessment"`
	Timeline           *ThreatTimeline        `json:"timeline"`
	Mitigations        []*Mitigation          `json:"mitigations"`
	References         []*Reference           `json:"references"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// ThreatType represents different types of quantum threats
type ThreatType string

const (
	ThreatTypeQuantumAdvancement    ThreatType = "quantum_advancement"
	ThreatTypeAlgorithmBreakthrough ThreatType = "algorithm_breakthrough"
	ThreatTypeCryptoVulnerability   ThreatType = "crypto_vulnerability"
	ThreatTypeHardwareProgress      ThreatType = "hardware_progress"
	ThreatTypeResearchPublication   ThreatType = "research_publication"
	ThreatTypeIndustryAnnouncement  ThreatType = "industry_announcement"
	ThreatTypeStandardsUpdate       ThreatType = "standards_update"
	ThreatTypeRegulatory            ThreatType = "regulatory"
)

// SeverityLevel represents threat severity levels
type SeverityLevel string

const (
	SeverityLow      SeverityLevel = "low"
	SeverityMedium   SeverityLevel = "medium"
	SeverityHigh     SeverityLevel = "high"
	SeverityCritical SeverityLevel = "critical"
)

// ImpactAssessment represents the impact assessment of a threat
type ImpactAssessment struct {
	OverallImpact       float64              `json:"overall_impact"`
	CryptographicImpact *CryptographicImpact `json:"cryptographic_impact"`
	BusinessImpact      *BusinessImpact      `json:"business_impact"`
	TechnicalImpact     *TechnicalImpact     `json:"technical_impact"`
	TimelineImpact      *TimelineImpact      `json:"timeline_impact"`
	GeographicScope     []string             `json:"geographic_scope"`
	IndustryScope       []string             `json:"industry_scope"`
}

// CryptographicImpact represents impact on cryptographic systems
type CryptographicImpact struct {
	AffectedAlgorithms   []string           `json:"affected_algorithms"`
	SecurityReduction    map[string]float64 `json:"security_reduction"`
	BreakabilityTimeline map[string]string  `json:"breakability_timeline"`
	MitigationOptions    []string           `json:"mitigation_options"`
	ReplacementUrgency   map[string]string  `json:"replacement_urgency"`
}

// BusinessImpact represents business impact
type BusinessImpact struct {
	RiskLevel          string              `json:"risk_level"`
	FinancialImpact    *FinancialImpact    `json:"financial_impact"`
	OperationalImpact  *OperationalImpact  `json:"operational_impact"`
	ComplianceImpact   *ComplianceImpact   `json:"compliance_impact"`
	ReputationalImpact *ReputationalImpact `json:"reputational_impact"`
	CompetitiveImpact  *CompetitiveImpact  `json:"competitive_impact"`
}

// FinancialImpact represents financial impact
type FinancialImpact struct {
	EstimatedCost      float64            `json:"estimated_cost"`
	CostRange          string             `json:"cost_range"`
	CostCategories     map[string]float64 `json:"cost_categories"`
	ROIConsiderations  []string           `json:"roi_considerations"`
	BudgetImplications []string           `json:"budget_implications"`
}

// OperationalImpact represents operational impact
type OperationalImpact struct {
	SystemsAffected   []string `json:"systems_affected"`
	DowntimeRisk      string   `json:"downtime_risk"`
	PerformanceImpact string   `json:"performance_impact"`
	ScalabilityImpact string   `json:"scalability_impact"`
	MaintenanceImpact string   `json:"maintenance_impact"`
}

// ComplianceImpact represents compliance impact
type ComplianceImpact struct {
	AffectedRegulations []string `json:"affected_regulations"`
	ComplianceGaps      []string `json:"compliance_gaps"`
	AuditImplications   []string `json:"audit_implications"`
	CertificationImpact []string `json:"certification_impact"`
}

// ReputationalImpact represents reputational impact
type ReputationalImpact struct {
	CustomerTrust       string   `json:"customer_trust"`
	MarketPerception    string   `json:"market_perception"`
	BrandImpact         string   `json:"brand_impact"`
	StakeholderConcerns []string `json:"stakeholder_concerns"`
}

// CompetitiveImpact represents competitive impact
type CompetitiveImpact struct {
	CompetitiveAdvantage string   `json:"competitive_advantage"`
	MarketPosition       string   `json:"market_position"`
	InnovationImpact     string   `json:"innovation_impact"`
	PartnershipEffects   []string `json:"partnership_effects"`
}

// TechnicalImpact represents technical impact
type TechnicalImpact struct {
	ArchitectureChanges   []string           `json:"architecture_changes"`
	PerformanceImpact     map[string]float64 `json:"performance_impact"`
	SecurityImplications  []string           `json:"security_implications"`
	IntegrationChallenges []string           `json:"integration_challenges"`
	ScalabilityIssues     []string           `json:"scalability_issues"`
}

// TimelineImpact represents timeline impact
type TimelineImpact struct {
	ImmediateActions  []string `json:"immediate_actions"`
	ShortTermActions  []string `json:"short_term_actions"`
	MediumTermActions []string `json:"medium_term_actions"`
	LongTermActions   []string `json:"long_term_actions"`
	CriticalDeadlines []string `json:"critical_deadlines"`
}

// ThreatTimeline represents the timeline of a threat
type ThreatTimeline struct {
	DiscoveryDate    time.Time           `json:"discovery_date"`
	PublicationDate  time.Time           `json:"publication_date"`
	VerificationDate time.Time           `json:"verification_date"`
	ImpactDate       time.Time           `json:"impact_date"`
	MitigationDate   time.Time           `json:"mitigation_date"`
	Milestones       []*ThreatMilestone  `json:"milestones"`
	Predictions      []*ThreatPrediction `json:"predictions"`
}

// ThreatMilestone represents a milestone in threat development
type ThreatMilestone struct {
	ID           string                 `json:"id"`
	Date         time.Time              `json:"date"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Significance string                 `json:"significance"`
	Source       string                 `json:"source"`
	Verified     bool                   `json:"verified"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ThreatPrediction represents a prediction about threat development
type ThreatPrediction struct {
	ID            string                 `json:"id"`
	PredictedDate time.Time              `json:"predicted_date"`
	Confidence    float64                `json:"confidence"`
	Scenario      string                 `json:"scenario"`
	Description   string                 `json:"description"`
	Assumptions   []string               `json:"assumptions"`
	Source        string                 `json:"source"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// Mitigation represents a threat mitigation strategy
type Mitigation struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	Title          string                 `json:"title"`
	Description    string                 `json:"description"`
	Effectiveness  float64                `json:"effectiveness"`
	Cost           string                 `json:"cost"`
	Complexity     string                 `json:"complexity"`
	Timeline       string                 `json:"timeline"`
	Prerequisites  []string               `json:"prerequisites"`
	Limitations    []string               `json:"limitations"`
	Alternatives   []string               `json:"alternatives"`
	Implementation *ImplementationGuide   `json:"implementation"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// ImplementationGuide provides implementation guidance
type ImplementationGuide struct {
	Steps          []string               `json:"steps"`
	Resources      []string               `json:"resources"`
	Tools          []string               `json:"tools"`
	BestPractices  []string               `json:"best_practices"`
	CommonPitfalls []string               `json:"common_pitfalls"`
	SuccessMetrics []string               `json:"success_metrics"`
	Validation     []string               `json:"validation"`
	Maintenance    []string               `json:"maintenance"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// Reference represents a reference or citation
type Reference struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Authors     []string               `json:"authors"`
	Publication string                 `json:"publication"`
	URL         string                 `json:"url"`
	DOI         string                 `json:"doi"`
	Date        time.Time              `json:"date"`
	Abstract    string                 `json:"abstract"`
	Keywords    []string               `json:"keywords"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatUpdate represents a threat intelligence update
type ThreatUpdate struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Threat    *ThreatIndicator       `json:"threat"`
	Changes   []*ThreatChange        `json:"changes"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ThreatChange represents a change in threat intelligence
type ThreatChange struct {
	Field        string      `json:"field"`
	OldValue     interface{} `json:"old_value"`
	NewValue     interface{} `json:"new_value"`
	ChangeType   string      `json:"change_type"`
	Significance string      `json:"significance"`
	Timestamp    time.Time   `json:"timestamp"`
}

// NewQuantumThreatIntelligence creates a new threat intelligence system
func NewQuantumThreatIntelligence(logger *logger.Logger, config *ThreatIntelConfig) *QuantumThreatIntelligence {
	if config == nil {
		config = &ThreatIntelConfig{
			UpdateInterval:  1 * time.Hour,
			CacheExpiry:     24 * time.Hour,
			MaxCacheSize:    1000,
			EnableRealTime:  true,
			ThreatThreshold: 0.7,
			AlertingEnabled: true,
			SourceWeights: map[string]float64{
				"academic":   0.9,
				"industry":   0.8,
				"government": 0.95,
				"opensource": 0.6,
				"commercial": 0.7,
			},
		}
	}

	cache := &ThreatCache{
		data:    make(map[string]*CachedThreat),
		maxSize: config.MaxCacheSize,
		expiry:  config.CacheExpiry,
	}

	return &QuantumThreatIntelligence{
		logger:      logger,
		config:      config,
		sources:     make(map[string]ThreatSource),
		cache:       cache,
		subscribers: make(map[string]chan *ThreatUpdate),
		stopChan:    make(chan struct{}),
	}
}

// Start starts the threat intelligence monitoring
func (qti *QuantumThreatIntelligence) Start(ctx context.Context) error {
	qti.mutex.Lock()
	defer qti.mutex.Unlock()

	if qti.running {
		return fmt.Errorf("threat intelligence system already running")
	}

	qti.running = true
	qti.logger.Info("Starting quantum threat intelligence system", map[string]interface{}{
		"update_interval": qti.config.UpdateInterval,
		"sources_count":   len(qti.sources),
		"real_time":       qti.config.EnableRealTime,
	})

	// Start monitoring goroutine
	go qti.monitorThreats(ctx)

	// Start cache cleanup goroutine
	go qti.cleanupCache(ctx)

	return nil
}

// Stop stops the threat intelligence monitoring
func (qti *QuantumThreatIntelligence) Stop() error {
	qti.mutex.Lock()
	defer qti.mutex.Unlock()

	if !qti.running {
		return fmt.Errorf("threat intelligence system not running")
	}

	qti.running = false
	close(qti.stopChan)

	qti.logger.Info("Stopped quantum threat intelligence system", nil)
	return nil
}

// AddSource adds a threat intelligence source
func (qti *QuantumThreatIntelligence) AddSource(source ThreatSource) error {
	qti.mutex.Lock()
	defer qti.mutex.Unlock()

	sourceName := source.GetName()
	qti.sources[sourceName] = source

	qti.logger.Info("Added threat intelligence source", map[string]interface{}{
		"source_name": sourceName,
		"source_type": source.GetType(),
		"reliability": source.GetReliability(),
	})

	return nil
}

// RemoveSource removes a threat intelligence source
func (qti *QuantumThreatIntelligence) RemoveSource(sourceName string) error {
	qti.mutex.Lock()
	defer qti.mutex.Unlock()

	if _, exists := qti.sources[sourceName]; !exists {
		return fmt.Errorf("source %s not found", sourceName)
	}

	delete(qti.sources, sourceName)
	qti.logger.Info("Removed threat intelligence source", map[string]interface{}{
		"source_name": sourceName,
	})

	return nil
}

// GetThreats retrieves current threat indicators
func (qti *QuantumThreatIntelligence) GetThreats(ctx context.Context, filters *ThreatFilters) ([]*ThreatIndicator, error) {
	qti.mutex.RLock()
	defer qti.mutex.RUnlock()

	var threats []*ThreatIndicator

	// Get threats from cache
	qti.cache.mutex.RLock()
	for _, cached := range qti.cache.data {
		if time.Since(cached.Timestamp) < qti.cache.expiry {
			if filters == nil || qti.matchesFilters(cached.Threat, filters) {
				threats = append(threats, cached.Threat)
			}
		}
	}
	qti.cache.mutex.RUnlock()

	// Sort by severity and confidence
	sort.Slice(threats, func(i, j int) bool {
		if threats[i].Severity != threats[j].Severity {
			return qti.getSeverityWeight(threats[i].Severity) > qti.getSeverityWeight(threats[j].Severity)
		}
		return threats[i].Confidence > threats[j].Confidence
	})

	return threats, nil
}

// Subscribe subscribes to threat intelligence updates
func (qti *QuantumThreatIntelligence) Subscribe(subscriberID string) (<-chan *ThreatUpdate, error) {
	qti.mutex.Lock()
	defer qti.mutex.Unlock()

	if _, exists := qti.subscribers[subscriberID]; exists {
		return nil, fmt.Errorf("subscriber %s already exists", subscriberID)
	}

	updateChan := make(chan *ThreatUpdate, 100)
	qti.subscribers[subscriberID] = updateChan

	qti.logger.Info("Added threat intelligence subscriber", map[string]interface{}{
		"subscriber_id": subscriberID,
	})

	return updateChan, nil
}

// Unsubscribe unsubscribes from threat intelligence updates
func (qti *QuantumThreatIntelligence) Unsubscribe(subscriberID string) error {
	qti.mutex.Lock()
	defer qti.mutex.Unlock()

	updateChan, exists := qti.subscribers[subscriberID]
	if !exists {
		return fmt.Errorf("subscriber %s not found", subscriberID)
	}

	close(updateChan)
	delete(qti.subscribers, subscriberID)

	qti.logger.Info("Removed threat intelligence subscriber", map[string]interface{}{
		"subscriber_id": subscriberID,
	})

	return nil
}

// ThreatFilters represents filters for threat queries
type ThreatFilters struct {
	ThreatTypes        []ThreatType    `json:"threat_types"`
	SeverityLevels     []SeverityLevel `json:"severity_levels"`
	MinConfidence      float64         `json:"min_confidence"`
	AffectedAlgorithms []string        `json:"affected_algorithms"`
	Sources            []string        `json:"sources"`
	Tags               []string        `json:"tags"`
	DateRange          *DateRange      `json:"date_range"`
	GeographicScope    []string        `json:"geographic_scope"`
	IndustryScope      []string        `json:"industry_scope"`
}

// DateRange represents a date range filter
type DateRange struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

// Helper methods

func (qti *QuantumThreatIntelligence) monitorThreats(ctx context.Context) {
	ticker := time.NewTicker(qti.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-qti.stopChan:
			return
		case <-ticker.C:
			qti.updateThreats(ctx)
		}
	}
}

func (qti *QuantumThreatIntelligence) updateThreats(ctx context.Context) {
	qti.mutex.RLock()
	sources := make([]ThreatSource, 0, len(qti.sources))
	for _, source := range qti.sources {
		if source.IsEnabled() {
			sources = append(sources, source)
		}
	}
	qti.mutex.RUnlock()

	for _, source := range sources {
		go func(src ThreatSource) {
			threats, err := src.FetchThreatData(ctx)
			if err != nil {
				qti.logger.Error("Failed to fetch threat data", map[string]interface{}{
					"source": src.GetName(),
					"error":  err.Error(),
				})
				return
			}

			for _, threat := range threats {
				qti.processThreat(threat, src.GetName())
			}
		}(source)
	}
}

func (qti *QuantumThreatIntelligence) processThreat(threat *ThreatIndicator, sourceName string) {
	// Cache the threat
	qti.cacheThreat(threat, sourceName)

	// Check if this is a new or updated threat
	update := &ThreatUpdate{
		ID:        uuid.New().String(),
		Type:      "threat_update",
		Timestamp: time.Now(),
		Source:    sourceName,
		Threat:    threat,
		Changes:   []*ThreatChange{},
	}

	// Notify subscribers
	qti.notifySubscribers(update)

	// Check for high-severity threats
	if qti.isHighSeverityThreat(threat) {
		qti.handleHighSeverityThreat(threat)
	}
}

func (qti *QuantumThreatIntelligence) cacheThreat(threat *ThreatIndicator, sourceName string) {
	qti.cache.mutex.Lock()
	defer qti.cache.mutex.Unlock()

	cached := &CachedThreat{
		Threat:    threat,
		Timestamp: time.Now(),
		Source:    sourceName,
		TTL:       qti.config.CacheExpiry,
	}

	qti.cache.data[threat.ID] = cached

	// Cleanup old entries if cache is full
	if len(qti.cache.data) > qti.cache.maxSize {
		qti.cleanupOldEntries()
	}
}

func (qti *QuantumThreatIntelligence) cleanupOldEntries() {
	// Remove oldest entries
	var entries []*CachedThreat
	for _, cached := range qti.cache.data {
		entries = append(entries, cached)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	// Remove oldest 10% of entries
	removeCount := len(entries) / 10
	for i := 0; i < removeCount; i++ {
		delete(qti.cache.data, entries[i].Threat.ID)
	}
}

func (qti *QuantumThreatIntelligence) cleanupCache(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-qti.stopChan:
			return
		case <-ticker.C:
			qti.performCacheCleanup()
		}
	}
}

func (qti *QuantumThreatIntelligence) performCacheCleanup() {
	qti.cache.mutex.Lock()
	defer qti.cache.mutex.Unlock()

	now := time.Now()
	for id, cached := range qti.cache.data {
		if now.Sub(cached.Timestamp) > qti.cache.expiry {
			delete(qti.cache.data, id)
		}
	}
}

func (qti *QuantumThreatIntelligence) notifySubscribers(update *ThreatUpdate) {
	qti.mutex.RLock()
	defer qti.mutex.RUnlock()

	for subscriberID, updateChan := range qti.subscribers {
		select {
		case updateChan <- update:
			// Successfully sent update
		default:
			// Channel is full, log warning
			qti.logger.Warn("Subscriber channel full, dropping update", map[string]interface{}{
				"subscriber_id": subscriberID,
				"update_id":     update.ID,
			})
		}
	}
}

func (qti *QuantumThreatIntelligence) isHighSeverityThreat(threat *ThreatIndicator) bool {
	return threat.Severity == SeverityCritical ||
		(threat.Severity == SeverityHigh && threat.Confidence >= qti.config.ThreatThreshold)
}

func (qti *QuantumThreatIntelligence) handleHighSeverityThreat(threat *ThreatIndicator) {
	if !qti.config.AlertingEnabled {
		return
	}

	qti.logger.Warn("High severity quantum threat detected", map[string]interface{}{
		"threat_id":   threat.ID,
		"threat_type": threat.Type,
		"severity":    threat.Severity,
		"confidence":  threat.Confidence,
		"title":       threat.Title,
		"description": threat.Description,
	})

	// Here you could integrate with alerting systems
	// For example: send to Slack, email, PagerDuty, etc.
}

func (qti *QuantumThreatIntelligence) matchesFilters(threat *ThreatIndicator, filters *ThreatFilters) bool {
	// Check threat types
	if len(filters.ThreatTypes) > 0 {
		found := false
		for _, threatType := range filters.ThreatTypes {
			if threat.Type == threatType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check severity levels
	if len(filters.SeverityLevels) > 0 {
		found := false
		for _, severity := range filters.SeverityLevels {
			if threat.Severity == severity {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check minimum confidence
	if threat.Confidence < filters.MinConfidence {
		return false
	}

	// Check affected algorithms
	if len(filters.AffectedAlgorithms) > 0 {
		found := false
		for _, filterAlg := range filters.AffectedAlgorithms {
			for _, threatAlg := range threat.AffectedAlgorithms {
				if filterAlg == threatAlg {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check sources
	if len(filters.Sources) > 0 {
		found := false
		for _, source := range filters.Sources {
			if threat.Source == source {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check tags
	if len(filters.Tags) > 0 {
		found := false
		for _, filterTag := range filters.Tags {
			for _, threatTag := range threat.Tags {
				if filterTag == threatTag {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check date range
	if filters.DateRange != nil {
		if threat.PublishedAt.Before(filters.DateRange.StartDate) ||
			threat.PublishedAt.After(filters.DateRange.EndDate) {
			return false
		}
	}

	return true
}

func (qti *QuantumThreatIntelligence) getSeverityWeight(severity SeverityLevel) int {
	switch severity {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
