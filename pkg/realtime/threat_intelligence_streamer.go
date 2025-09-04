package realtime

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
	"github.com/google/uuid"
)

var threatStreamerTracer = otel.Tracer("hackai/realtime/threat-streamer")

// ThreatIntelligenceStreamer provides real-time threat intelligence streaming
type ThreatIntelligenceStreamer struct {
	config           *ThreatStreamerConfig
	logger           *logger.Logger
	realtimeSystem   *RealtimeSystem
	threatDetector   *security.ThreatIntelligenceEngine
	streamProcessors map[ThreatStreamType]*StreamProcessor
	eventBuffer      chan *ThreatEvent
	running          bool
	stopChan         chan struct{}
	wg               sync.WaitGroup
	mutex            sync.RWMutex
}

// ThreatStreamerConfig configuration for threat intelligence streaming
type ThreatStreamerConfig struct {
	// Stream configuration
	BufferSize          int           `json:"buffer_size"`
	ProcessingInterval  time.Duration `json:"processing_interval"`
	BatchSize           int           `json:"batch_size"`
	MaxEventAge         time.Duration `json:"max_event_age"`
	EnablePersistence   bool          `json:"enable_persistence"`
	
	// Threat detection configuration
	ThreatThreshold     float64       `json:"threat_threshold"`
	AlertThreshold      float64       `json:"alert_threshold"`
	CorrelationWindow   time.Duration `json:"correlation_window"`
	EnableCorrelation   bool          `json:"enable_correlation"`
	EnableEnrichment    bool          `json:"enable_enrichment"`
	
	// Stream types to enable
	EnableIOCStream     bool `json:"enable_ioc_stream"`
	EnableCVEStream     bool `json:"enable_cve_stream"`
	EnableMITREStream   bool `json:"enable_mitre_stream"`
	EnableAlertsStream  bool `json:"enable_alerts_stream"`
	EnableMetricsStream bool `json:"enable_metrics_stream"`
	
	// Performance settings
	MaxConcurrentProcessors int           `json:"max_concurrent_processors"`
	ProcessorTimeout        time.Duration `json:"processor_timeout"`
	RetryAttempts           int           `json:"retry_attempts"`
	RetryDelay              time.Duration `json:"retry_delay"`
}

// ThreatStreamType represents different types of threat intelligence streams
type ThreatStreamType string

const (
	ThreatStreamIOC     ThreatStreamType = "ioc"
	ThreatStreamCVE     ThreatStreamType = "cve"
	ThreatStreamMITRE   ThreatStreamType = "mitre"
	ThreatStreamAlerts  ThreatStreamType = "alerts"
	ThreatStreamMetrics ThreatStreamType = "metrics"
	ThreatStreamEvents  ThreatStreamType = "events"
	ThreatStreamCustom  ThreatStreamType = "custom"
)

// ThreatEvent represents a threat intelligence event for streaming
type ThreatEvent struct {
	ID              string                 `json:"id"`
	Type            ThreatStreamType       `json:"type"`
	Timestamp       time.Time              `json:"timestamp"`
	Source          string                 `json:"source"`
	Severity        string                 `json:"severity"`
	Confidence      float64                `json:"confidence"`
	ThreatScore     float64                `json:"threat_score"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	IOCs            []string               `json:"iocs,omitempty"`
	CVEs            []string               `json:"cves,omitempty"`
	MITRETactics    []string               `json:"mitre_tactics,omitempty"`
	MITRETechniques []string               `json:"mitre_techniques,omitempty"`
	Indicators      []ThreatIndicator      `json:"indicators"`
	Metadata        map[string]interface{} `json:"metadata"`
	RawData         map[string]interface{} `json:"raw_data,omitempty"`
	Correlations    []CorrelationLink      `json:"correlations,omitempty"`
	Enrichment      *ThreatEnrichment      `json:"enrichment,omitempty"`
}

// ThreatIndicator represents an indicator of compromise
type ThreatIndicator struct {
	Type       string                 `json:"type"`
	Value      string                 `json:"value"`
	Confidence float64                `json:"confidence"`
	Severity   string                 `json:"severity"`
	FirstSeen  time.Time              `json:"first_seen"`
	LastSeen   time.Time              `json:"last_seen"`
	Sources    []string               `json:"sources"`
	Tags       []string               `json:"tags"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// CorrelationLink represents a correlation between threat events
type CorrelationLink struct {
	EventID     string    `json:"event_id"`
	Type        string    `json:"type"`
	Confidence  float64   `json:"confidence"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// ThreatEnrichment contains enriched threat intelligence data
type ThreatEnrichment struct {
	GeolocationData   *GeolocationInfo       `json:"geolocation,omitempty"`
	ReputationScores  map[string]float64     `json:"reputation_scores,omitempty"`
	ThreatActorInfo   *ThreatActorInfo       `json:"threat_actor,omitempty"`
	CampaignInfo      *CampaignInfo          `json:"campaign,omitempty"`
	VulnerabilityInfo *VulnerabilityInfo     `json:"vulnerability,omitempty"`
	RelatedEvents     []string               `json:"related_events,omitempty"`
	AdditionalContext map[string]interface{} `json:"additional_context,omitempty"`
}

// Supporting structures for enrichment
type GeolocationInfo struct {
	Country    string  `json:"country"`
	Region     string  `json:"region"`
	City       string  `json:"city"`
	Latitude   float64 `json:"latitude"`
	Longitude  float64 `json:"longitude"`
	ISP        string  `json:"isp"`
	ASN        string  `json:"asn"`
	RiskScore  float64 `json:"risk_score"`
}

type ThreatActorInfo struct {
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases"`
	Attribution string   `json:"attribution"`
	Motivation  string   `json:"motivation"`
	TTPs        []string `json:"ttps"`
	Campaigns   []string `json:"campaigns"`
	LastActive  string   `json:"last_active"`
}

type CampaignInfo struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	StartDate   time.Time `json:"start_date"`
	EndDate     time.Time `json:"end_date,omitempty"`
	Targets     []string  `json:"targets"`
	TTPs        []string  `json:"ttps"`
	Attribution string    `json:"attribution"`
}

type VulnerabilityInfo struct {
	CVEID       string    `json:"cve_id"`
	CVSSScore   float64   `json:"cvss_score"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	References  []string  `json:"references"`
	Exploited   bool      `json:"exploited"`
}

// StreamProcessor processes threat events for specific stream types
type StreamProcessor struct {
	streamType   ThreatStreamType
	config       *ThreatStreamerConfig
	logger       *logger.Logger
	eventChannel chan *ThreatEvent
	running      bool
	mutex        sync.RWMutex
}

// NewThreatIntelligenceStreamer creates a new threat intelligence streamer
func NewThreatIntelligenceStreamer(
	config *ThreatStreamerConfig,
	realtimeSystem *RealtimeSystem,
	threatDetector *security.ThreatIntelligenceEngine,
	logger *logger.Logger,
) *ThreatIntelligenceStreamer {
	if config == nil {
		config = DefaultThreatStreamerConfig()
	}

	return &ThreatIntelligenceStreamer{
		config:           config,
		logger:           logger,
		realtimeSystem:   realtimeSystem,
		threatDetector:   threatDetector,
		streamProcessors: make(map[ThreatStreamType]*StreamProcessor),
		eventBuffer:      make(chan *ThreatEvent, config.BufferSize),
		stopChan:         make(chan struct{}),
	}
}

// DefaultThreatStreamerConfig returns default configuration
func DefaultThreatStreamerConfig() *ThreatStreamerConfig {
	return &ThreatStreamerConfig{
		BufferSize:              10000,
		ProcessingInterval:      1 * time.Second,
		BatchSize:               100,
		MaxEventAge:             1 * time.Hour,
		EnablePersistence:       true,
		ThreatThreshold:         0.5,
		AlertThreshold:          0.7,
		CorrelationWindow:       5 * time.Minute,
		EnableCorrelation:       true,
		EnableEnrichment:        true,
		EnableIOCStream:         true,
		EnableCVEStream:         true,
		EnableMITREStream:       true,
		EnableAlertsStream:      true,
		EnableMetricsStream:     true,
		MaxConcurrentProcessors: 10,
		ProcessorTimeout:        30 * time.Second,
		RetryAttempts:           3,
		RetryDelay:              1 * time.Second,
	}
}

// Start starts the threat intelligence streamer
func (tis *ThreatIntelligenceStreamer) Start(ctx context.Context) error {
	ctx, span := threatStreamerTracer.Start(ctx, "threat_streamer_start")
	defer span.End()

	tis.mutex.Lock()
	defer tis.mutex.Unlock()

	if tis.running {
		return fmt.Errorf("threat intelligence streamer is already running")
	}

	tis.logger.Info("Starting threat intelligence streamer",
		"buffer_size", tis.config.BufferSize,
		"processing_interval", tis.config.ProcessingInterval,
		"batch_size", tis.config.BatchSize)

	// Initialize stream processors
	if err := tis.initializeStreamProcessors(ctx); err != nil {
		return fmt.Errorf("failed to initialize stream processors: %w", err)
	}

	// Start background workers
	tis.wg.Add(4)
	go tis.eventProcessor(ctx)
	go tis.correlationProcessor(ctx)
	go tis.enrichmentProcessor(ctx)
	go tis.metricsCollector(ctx)

	tis.running = true

	span.SetAttributes(
		attribute.Bool("streamer_started", true),
		attribute.Int("buffer_size", tis.config.BufferSize),
		attribute.Int("batch_size", tis.config.BatchSize),
	)

	tis.logger.Info("Threat intelligence streamer started successfully")
	return nil
}

// Stop stops the threat intelligence streamer
func (tis *ThreatIntelligenceStreamer) Stop() error {
	tis.mutex.Lock()
	defer tis.mutex.Unlock()

	if !tis.running {
		return nil
	}

	tis.logger.Info("Stopping threat intelligence streamer")

	// Signal stop to all workers
	close(tis.stopChan)

	// Stop stream processors
	for _, processor := range tis.streamProcessors {
		processor.Stop()
	}

	// Wait for workers to finish
	tis.wg.Wait()

	tis.running = false
	tis.logger.Info("Threat intelligence streamer stopped")
	return nil
}

// StreamThreatEvent streams a threat event
func (tis *ThreatIntelligenceStreamer) StreamThreatEvent(ctx context.Context, event *ThreatEvent) error {
	ctx, span := threatStreamerTracer.Start(ctx, "stream_threat_event")
	defer span.End()

	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Add event to buffer
	select {
	case tis.eventBuffer <- event:
		span.SetAttributes(
			attribute.String("event_id", event.ID),
			attribute.String("event_type", string(event.Type)),
			attribute.String("severity", event.Severity),
			attribute.Float64("confidence", event.Confidence),
		)
		return nil
	default:
		return fmt.Errorf("event buffer is full")
	}
}

// CreateIOCStream creates an IOC-specific threat event
func (tis *ThreatIntelligenceStreamer) CreateIOCStream(ctx context.Context, indicator *ThreatIndicator) error {
	event := &ThreatEvent{
		ID:          uuid.New().String(),
		Type:        ThreatStreamIOC,
		Timestamp:   time.Now(),
		Source:      "ioc-detector",
		Severity:    indicator.Severity,
		Confidence:  indicator.Confidence,
		ThreatScore: tis.calculateThreatScore(indicator),
		Title:       fmt.Sprintf("IOC Detected: %s", indicator.Type),
		Description: fmt.Sprintf("Indicator of type %s with value %s detected", indicator.Type, indicator.Value),
		Indicators:  []ThreatIndicator{*indicator},
		Metadata: map[string]interface{}{
			"detector_version": "1.0.0",
			"detection_time":   time.Now(),
		},
	}

	return tis.StreamThreatEvent(ctx, event)
}

// CreateCVEStream creates a CVE-specific threat event
func (tis *ThreatIntelligenceStreamer) CreateCVEStream(ctx context.Context, cveID string, vulnerability *VulnerabilityInfo) error {
	event := &ThreatEvent{
		ID:          uuid.New().String(),
		Type:        ThreatStreamCVE,
		Timestamp:   time.Now(),
		Source:      "cve-monitor",
		Severity:    vulnerability.Severity,
		Confidence:  0.95, // CVE data is highly reliable
		ThreatScore: vulnerability.CVSSScore / 10.0,
		Title:       fmt.Sprintf("CVE Alert: %s", cveID),
		Description: vulnerability.Description,
		CVEs:        []string{cveID},
		Metadata: map[string]interface{}{
			"cvss_score": vulnerability.CVSSScore,
			"exploited":  vulnerability.Exploited,
			"published":  vulnerability.Published,
		},
		Enrichment: &ThreatEnrichment{
			VulnerabilityInfo: vulnerability,
		},
	}

	return tis.StreamThreatEvent(ctx, event)
}

// CreateMITREStream creates a MITRE ATT&CK-specific threat event
func (tis *ThreatIntelligenceStreamer) CreateMITREStream(ctx context.Context, tactic, technique string, details map[string]interface{}) error {
	event := &ThreatEvent{
		ID:              uuid.New().String(),
		Type:            ThreatStreamMITRE,
		Timestamp:       time.Now(),
		Source:          "mitre-detector",
		Severity:        "medium",
		Confidence:      0.8,
		ThreatScore:     0.6,
		Title:           fmt.Sprintf("MITRE Technique Detected: %s", technique),
		Description:     fmt.Sprintf("MITRE ATT&CK tactic %s with technique %s detected", tactic, technique),
		MITRETactics:    []string{tactic},
		MITRETechniques: []string{technique},
		Metadata:        details,
	}

	return tis.StreamThreatEvent(ctx, event)
}

// CreateAlertStream creates an alert-specific threat event
func (tis *ThreatIntelligenceStreamer) CreateAlertStream(ctx context.Context, alertType, title, description string, severity string, confidence float64) error {
	event := &ThreatEvent{
		ID:          uuid.New().String(),
		Type:        ThreatStreamAlerts,
		Timestamp:   time.Now(),
		Source:      "alert-system",
		Severity:    severity,
		Confidence:  confidence,
		ThreatScore: tis.calculateAlertThreatScore(severity, confidence),
		Title:       title,
		Description: description,
		Metadata: map[string]interface{}{
			"alert_type":     alertType,
			"generation_time": time.Now(),
		},
	}

	return tis.StreamThreatEvent(ctx, event)
}

// initializeStreamProcessors initializes processors for different stream types
func (tis *ThreatIntelligenceStreamer) initializeStreamProcessors(ctx context.Context) error {
	streamTypes := []ThreatStreamType{}

	if tis.config.EnableIOCStream {
		streamTypes = append(streamTypes, ThreatStreamIOC)
	}
	if tis.config.EnableCVEStream {
		streamTypes = append(streamTypes, ThreatStreamCVE)
	}
	if tis.config.EnableMITREStream {
		streamTypes = append(streamTypes, ThreatStreamMITRE)
	}
	if tis.config.EnableAlertsStream {
		streamTypes = append(streamTypes, ThreatStreamAlerts)
	}
	if tis.config.EnableMetricsStream {
		streamTypes = append(streamTypes, ThreatStreamMetrics)
	}

	for _, streamType := range streamTypes {
		processor := &StreamProcessor{
			streamType:   streamType,
			config:       tis.config,
			logger:       tis.logger,
			eventChannel: make(chan *ThreatEvent, 100),
		}

		if err := processor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start processor for stream type %s: %w", streamType, err)
		}

		tis.streamProcessors[streamType] = processor
	}

	return nil
}

// Background workers
func (tis *ThreatIntelligenceStreamer) eventProcessor(ctx context.Context) {
	defer tis.wg.Done()

	ticker := time.NewTicker(tis.config.ProcessingInterval)
	defer ticker.Stop()

	eventBatch := make([]*ThreatEvent, 0, tis.config.BatchSize)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tis.stopChan:
			return
		case event := <-tis.eventBuffer:
			eventBatch = append(eventBatch, event)
			
			// Process batch when full or on ticker
			if len(eventBatch) >= tis.config.BatchSize {
				tis.processBatch(ctx, eventBatch)
				eventBatch = eventBatch[:0]
			}
		case <-ticker.C:
			if len(eventBatch) > 0 {
				tis.processBatch(ctx, eventBatch)
				eventBatch = eventBatch[:0]
			}
		}
	}
}

func (tis *ThreatIntelligenceStreamer) correlationProcessor(ctx context.Context) {
	defer tis.wg.Done()

	if !tis.config.EnableCorrelation {
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tis.stopChan:
			return
		case <-ticker.C:
			tis.performCorrelation(ctx)
		}
	}
}

func (tis *ThreatIntelligenceStreamer) enrichmentProcessor(ctx context.Context) {
	defer tis.wg.Done()

	if !tis.config.EnableEnrichment {
		return
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tis.stopChan:
			return
		case <-ticker.C:
			tis.performEnrichment(ctx)
		}
	}
}

func (tis *ThreatIntelligenceStreamer) metricsCollector(ctx context.Context) {
	defer tis.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tis.stopChan:
			return
		case <-ticker.C:
			tis.collectAndStreamMetrics(ctx)
		}
	}
}

// Helper methods
func (tis *ThreatIntelligenceStreamer) processBatch(ctx context.Context, events []*ThreatEvent) {
	for _, event := range events {
		// Route to appropriate processor
		if processor, exists := tis.streamProcessors[event.Type]; exists {
			select {
			case processor.eventChannel <- event:
				// Event sent to processor
			default:
				tis.logger.Warn("Processor buffer full, dropping event", "event_id", event.ID, "type", event.Type)
			}
		}

		// Stream to real-time system
		channel := fmt.Sprintf("threat.%s", string(event.Type))
		eventData := map[string]interface{}{
			"event": event,
		}

		if err := tis.realtimeSystem.PublishMessage(ctx, channel, eventData); err != nil {
			tis.logger.Error("Failed to publish event to real-time system", "error", err, "event_id", event.ID)
		}
	}

	tis.logger.Debug("Processed event batch", "count", len(events))
}

func (tis *ThreatIntelligenceStreamer) performCorrelation(ctx context.Context) {
	// Placeholder for correlation logic
	tis.logger.Debug("Performing threat event correlation")
}

func (tis *ThreatIntelligenceStreamer) performEnrichment(ctx context.Context) {
	// Placeholder for enrichment logic
	tis.logger.Debug("Performing threat event enrichment")
}

func (tis *ThreatIntelligenceStreamer) collectAndStreamMetrics(ctx context.Context) {
	metrics := map[string]interface{}{
		"active_streams":      len(tis.streamProcessors),
		"buffered_events":     len(tis.eventBuffer),
		"processing_interval": tis.config.ProcessingInterval.Seconds(),
		"batch_size":          tis.config.BatchSize,
		"timestamp":           time.Now(),
	}

	event := &ThreatEvent{
		ID:          uuid.New().String(),
		Type:        ThreatStreamMetrics,
		Timestamp:   time.Now(),
		Source:      "metrics-collector",
		Severity:    "info",
		Confidence:  1.0,
		ThreatScore: 0.0,
		Title:       "Threat Streamer Metrics",
		Description: "Real-time metrics from threat intelligence streamer",
		Metadata:    metrics,
	}

	tis.StreamThreatEvent(ctx, event)
}

func (tis *ThreatIntelligenceStreamer) calculateThreatScore(indicator *ThreatIndicator) float64 {
	baseScore := indicator.Confidence
	
	// Adjust based on severity
	switch indicator.Severity {
	case "critical":
		baseScore *= 1.0
	case "high":
		baseScore *= 0.8
	case "medium":
		baseScore *= 0.6
	case "low":
		baseScore *= 0.4
	default:
		baseScore *= 0.5
	}
	
	return baseScore
}

func (tis *ThreatIntelligenceStreamer) calculateAlertThreatScore(severity string, confidence float64) float64 {
	switch severity {
	case "critical":
		return confidence * 1.0
	case "high":
		return confidence * 0.8
	case "medium":
		return confidence * 0.6
	case "low":
		return confidence * 0.4
	default:
		return confidence * 0.5
	}
}

// StreamProcessor methods
func (sp *StreamProcessor) Start(ctx context.Context) error {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	if sp.running {
		return fmt.Errorf("stream processor for type %s is already running", sp.streamType)
	}

	go sp.processEvents(ctx)
	sp.running = true

	sp.logger.Debug("Stream processor started", "stream_type", sp.streamType)
	return nil
}

func (sp *StreamProcessor) Stop() {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	if !sp.running {
		return
	}

	close(sp.eventChannel)
	sp.running = false

	sp.logger.Debug("Stream processor stopped", "stream_type", sp.streamType)
}

func (sp *StreamProcessor) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-sp.eventChannel:
			if !ok {
				return
			}
			sp.processEvent(ctx, event)
		}
	}
}

func (sp *StreamProcessor) processEvent(ctx context.Context, event *ThreatEvent) {
	// Process event based on stream type
	switch sp.streamType {
	case ThreatStreamIOC:
		sp.processIOCEvent(ctx, event)
	case ThreatStreamCVE:
		sp.processCVEEvent(ctx, event)
	case ThreatStreamMITRE:
		sp.processMITREEvent(ctx, event)
	case ThreatStreamAlerts:
		sp.processAlertEvent(ctx, event)
	case ThreatStreamMetrics:
		sp.processMetricsEvent(ctx, event)
	}
}

func (sp *StreamProcessor) processIOCEvent(ctx context.Context, event *ThreatEvent) {
	sp.logger.Debug("Processing IOC event", "event_id", event.ID, "indicators", len(event.Indicators))
}

func (sp *StreamProcessor) processCVEEvent(ctx context.Context, event *ThreatEvent) {
	sp.logger.Debug("Processing CVE event", "event_id", event.ID, "cves", len(event.CVEs))
}

func (sp *StreamProcessor) processMITREEvent(ctx context.Context, event *ThreatEvent) {
	sp.logger.Debug("Processing MITRE event", "event_id", event.ID, "techniques", len(event.MITRETechniques))
}

func (sp *StreamProcessor) processAlertEvent(ctx context.Context, event *ThreatEvent) {
	sp.logger.Debug("Processing alert event", "event_id", event.ID, "severity", event.Severity)
}

func (sp *StreamProcessor) processMetricsEvent(ctx context.Context, event *ThreatEvent) {
	sp.logger.Debug("Processing metrics event", "event_id", event.ID)
}