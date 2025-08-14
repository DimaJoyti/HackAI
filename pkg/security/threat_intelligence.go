package security

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ThreatIntelligenceEngine provides comprehensive threat intelligence capabilities
type ThreatIntelligenceEngine struct {
	config *ThreatIntelligenceConfig
	logger Logger

	// Feed management
	feedManager *ThreatFeedManager

	// IOC management
	iocDatabase *IOCDatabase

	// Reputation scoring
	reputationEngine *ReputationEngine

	// Real-time integration
	realTimeFeeds map[string]*RealTimeFeed

	// Caching and performance
	cache *ThreatCache

	// Background processing
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Synchronization
	mu sync.RWMutex
}

// ThreatIntelligenceConfig configuration for threat intelligence
type ThreatIntelligenceConfig struct {
	Enabled             bool              `json:"enabled"`
	UpdateInterval      time.Duration     `json:"update_interval"`
	Sources             []string          `json:"sources"`
	APIKeys             map[string]string `json:"api_keys"`
	CacheTimeout        time.Duration     `json:"cache_timeout"`
	MaxCacheSize        int               `json:"max_cache_size"`
	IOCTypes            []string          `json:"ioc_types"`
	ReputationScoring   bool              `json:"reputation_scoring"`
	AutoBlocking        bool              `json:"auto_blocking"`
	RealTimeFeeds       bool              `json:"real_time_feeds"`
	ThreatCorrelation   bool              `json:"threat_correlation"`
	GeolocationAnalysis bool              `json:"geolocation_analysis"`
	BehaviorAnalysis    bool              `json:"behavior_analysis"`
	MachineLearning     bool              `json:"machine_learning"`
	FeedConfigs         []*FeedConfig     `json:"feed_configs"`
}

// Note: Using existing ThreatIndicator and ThreatFeed types from ai_firewall.go

// FeedConfig configuration for individual feeds
type FeedConfig struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	URL             string              `json:"url"`
	Type            string              `json:"type"`
	Format          string              `json:"format"`
	Enabled         bool                `json:"enabled"`
	UpdateFrequency time.Duration       `json:"update_frequency"`
	Authentication  *FeedAuthentication `json:"authentication,omitempty"`
	Parser          string              `json:"parser"`
	Quality         float64             `json:"quality"`
	Reliability     float64             `json:"reliability"`
	Tags            []string            `json:"tags"`
}

// FeedAuthentication authentication for threat feeds
type FeedAuthentication struct {
	Type     string            `json:"type"`
	APIKey   string            `json:"api_key,omitempty"`
	Username string            `json:"username,omitempty"`
	Password string            `json:"password,omitempty"`
	Token    string            `json:"token,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

// GeolocationInfo geolocation information for indicators
type GeolocationInfo struct {
	Country      string  `json:"country"`
	CountryCode  string  `json:"country_code"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	ASN          string  `json:"asn"`
	Organization string  `json:"organization"`
	ISP          string  `json:"isp"`
	RiskLevel    string  `json:"risk_level"`
}

// ThreatReport comprehensive threat analysis report
type ThreatReport struct {
	ID         string    `json:"id"`
	Target     string    `json:"target"`
	TargetType string    `json:"target_type"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	// Analysis results
	ThreatScore float64 `json:"threat_score"`
	RiskLevel   string  `json:"risk_level"`
	Confidence  float64 `json:"confidence"`

	// Indicators
	Indicators     []*ThreatIndicator `json:"indicators"`
	RelatedThreats []*ThreatIndicator `json:"related_threats"`

	// Analysis details
	GeolocationInfo  *GeolocationInfo  `json:"geolocation_info,omitempty"`
	BehaviorAnalysis *BehaviorAnalysis `json:"behavior_analysis,omitempty"`
	ReputationData   *ReputationData   `json:"reputation_data,omitempty"`

	// Recommendations
	Recommendations []string `json:"recommendations"`
	Actions         []string `json:"actions"`

	// Metadata
	Sources  []string               `json:"sources"`
	Metadata map[string]interface{} `json:"metadata"`
}

// BehaviorAnalysis behavioral analysis results
type BehaviorAnalysis struct {
	Patterns        []string  `json:"patterns"`
	Anomalies       []string  `json:"anomalies"`
	ThreatBehaviors []string  `json:"threat_behaviors"`
	RiskFactors     []string  `json:"risk_factors"`
	Confidence      float64   `json:"confidence"`
	LastAnalyzed    time.Time `json:"last_analyzed"`
}

// ReputationData reputation scoring data
type ReputationData struct {
	OverallScore float64            `json:"overall_score"`
	SourceScores map[string]float64 `json:"source_scores"`
	Categories   map[string]float64 `json:"categories"`
	LastUpdated  time.Time          `json:"last_updated"`
	Confidence   float64            `json:"confidence"`
	Factors      []string           `json:"factors"`
}

// RealTimeFeed real-time threat intelligence feed
type RealTimeFeed struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	Connected    bool      `json:"connected"`
	LastMessage  time.Time `json:"last_message"`
	MessageCount int64     `json:"message_count"`
	ErrorCount   int64     `json:"error_count"`
	Quality      float64   `json:"quality"`
}

// ThreatCorrelation threat correlation results
type ThreatCorrelation struct {
	PrimaryIOC       *ThreatIndicator   `json:"primary_ioc"`
	RelatedIOCs      []*ThreatIndicator `json:"related_iocs"`
	CorrelationScore float64            `json:"correlation_score"`
	CorrelationType  string             `json:"correlation_type"`
	Confidence       float64            `json:"confidence"`
	Evidence         []string           `json:"evidence"`
	CreatedAt        time.Time          `json:"created_at"`
}

// Note: Using existing Logger interface from security_metrics.go

// NewThreatIntelligenceEngine creates a new threat intelligence engine
func NewThreatIntelligenceEngine(config *ThreatIntelligenceConfig, logger Logger) *ThreatIntelligenceEngine {
	ctx, cancel := context.WithCancel(context.Background())

	engine := &ThreatIntelligenceEngine{
		config:        config,
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
		realTimeFeeds: make(map[string]*RealTimeFeed),
	}

	// Initialize components
	engine.feedManager = NewThreatFeedManager(config, logger)
	engine.iocDatabase = NewIOCDatabase(config, logger)
	engine.reputationEngine = NewReputationEngine(config, logger)
	engine.cache = NewThreatCache(config, logger)

	return engine
}

// Start starts the threat intelligence engine
func (tie *ThreatIntelligenceEngine) Start() error {
	if !tie.config.Enabled {
		return nil
	}

	tie.logger.Info("Starting threat intelligence engine")

	// Start feed manager
	if err := tie.feedManager.Start(); err != nil {
		return fmt.Errorf("failed to start feed manager: %w", err)
	}

	// Start IOC database
	if err := tie.iocDatabase.Start(); err != nil {
		return fmt.Errorf("failed to start IOC database: %w", err)
	}

	// Start reputation engine
	if err := tie.reputationEngine.Start(); err != nil {
		return fmt.Errorf("failed to start reputation engine: %w", err)
	}

	// Start cache
	if err := tie.cache.Start(); err != nil {
		return fmt.Errorf("failed to start threat cache: %w", err)
	}

	// Start background workers
	tie.wg.Add(3)
	go tie.feedUpdateWorker()
	go tie.correlationWorker()
	go tie.cleanupWorker()

	// Start real-time feeds if enabled
	if tie.config.RealTimeFeeds {
		tie.startRealTimeFeeds()
	}

	tie.logger.Info("Threat intelligence engine started successfully")

	return nil
}

// Stop stops the threat intelligence engine
func (tie *ThreatIntelligenceEngine) Stop() error {
	tie.logger.Info("Stopping threat intelligence engine")

	tie.cancel()
	tie.wg.Wait()

	// Stop components
	if tie.feedManager != nil {
		tie.feedManager.Stop()
	}

	if tie.iocDatabase != nil {
		tie.iocDatabase.Stop()
	}

	if tie.reputationEngine != nil {
		tie.reputationEngine.Stop()
	}

	if tie.cache != nil {
		tie.cache.Stop()
	}

	tie.logger.Info("Threat intelligence engine stopped")

	return nil
}

// AnalyzeThreat performs comprehensive threat analysis
func (tie *ThreatIntelligenceEngine) AnalyzeThreat(ctx context.Context, target string) (*ThreatReport, error) {
	if !tie.config.Enabled {
		return nil, fmt.Errorf("threat intelligence engine is disabled")
	}

	// Check cache first
	if cached := tie.cache.Get(target); cached != nil {
		return cached, nil
	}

	tie.logger.Info("Analyzing threat", "target", target)

	// Determine target type
	targetType := tie.determineTargetType(target)

	report := &ThreatReport{
		ID:         fmt.Sprintf("threat_%d", time.Now().UnixNano()),
		Target:     target,
		TargetType: targetType,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Sources:    []string{},
		Metadata:   make(map[string]interface{}),
	}

	// Perform analysis based on target type
	switch targetType {
	case "ip":
		if err := tie.analyzeIPAddress(ctx, target, report); err != nil {
			return nil, fmt.Errorf("failed to analyze IP address: %w", err)
		}
	case "domain":
		if err := tie.analyzeDomain(ctx, target, report); err != nil {
			return nil, fmt.Errorf("failed to analyze domain: %w", err)
		}
	case "url":
		if err := tie.analyzeURL(ctx, target, report); err != nil {
			return nil, fmt.Errorf("failed to analyze URL: %w", err)
		}
	case "hash":
		if err := tie.analyzeHash(ctx, target, report); err != nil {
			return nil, fmt.Errorf("failed to analyze hash: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported target type: %s", targetType)
	}

	// Calculate overall threat score
	report.ThreatScore = tie.calculateThreatScore(report.Indicators)
	report.RiskLevel = tie.calculateRiskLevel(report.ThreatScore)
	report.Confidence = tie.calculateConfidence(report.Indicators)

	// Perform threat correlation if enabled
	if tie.config.ThreatCorrelation {
		tie.performThreatCorrelation(ctx, report)
	}

	// Generate recommendations
	report.Recommendations = tie.generateRecommendations(report)
	report.Actions = tie.generateActions(report)

	// Cache the result
	tie.cache.Set(target, report)

	tie.logger.Info("Threat analysis completed",
		"target", target,
		"threat_score", report.ThreatScore,
		"risk_level", report.RiskLevel,
		"indicators", len(report.Indicators))

	return report, nil
}

// CheckIOC checks if an indicator is known
func (tie *ThreatIntelligenceEngine) CheckIOC(indicator, indicatorType string) (*ThreatIndicator, error) {
	if !tie.config.Enabled {
		return nil, nil
	}

	return tie.iocDatabase.Lookup(indicator, indicatorType)
}

// AddIOC adds a new indicator of compromise
func (tie *ThreatIntelligenceEngine) AddIOC(indicator *ThreatIndicator) error {
	if !tie.config.Enabled {
		return fmt.Errorf("threat intelligence engine is disabled")
	}

	return tie.iocDatabase.Add(indicator)
}

// GetReputationScore gets reputation score for an indicator
func (tie *ThreatIntelligenceEngine) GetReputationScore(indicator, indicatorType string) (float64, error) {
	if !tie.config.Enabled || !tie.config.ReputationScoring {
		return 0.0, nil
	}

	return tie.reputationEngine.GetScore(indicator, indicatorType)
}

// GetThreatStatistics returns threat intelligence statistics
func (tie *ThreatIntelligenceEngine) GetThreatStatistics() map[string]interface{} {
	stats := make(map[string]interface{})

	if tie.feedManager != nil {
		stats["feeds"] = tie.feedManager.GetStatistics()
	}

	if tie.iocDatabase != nil {
		stats["iocs"] = tie.iocDatabase.GetStatistics()
	}

	if tie.reputationEngine != nil {
		stats["reputation"] = tie.reputationEngine.GetStatistics()
	}

	if tie.cache != nil {
		stats["cache"] = tie.cache.GetStatistics()
	}

	stats["real_time_feeds"] = len(tie.realTimeFeeds)
	stats["enabled"] = tie.config.Enabled

	return stats
}

// Core analysis methods

// determineTargetType determines the type of target being analyzed
func (tie *ThreatIntelligenceEngine) determineTargetType(target string) string {
	// Check if it's an IP address
	if net.ParseIP(target) != nil {
		return "ip"
	}

	// Check if it's a URL
	if u, err := url.Parse(target); err == nil && u.Scheme != "" {
		return "url"
	}

	// Check if it's a hash (MD5, SHA1, SHA256)
	hashRegexes := map[string]*regexp.Regexp{
		"md5":    regexp.MustCompile(`^[a-fA-F0-9]{32}$`),
		"sha1":   regexp.MustCompile(`^[a-fA-F0-9]{40}$`),
		"sha256": regexp.MustCompile(`^[a-fA-F0-9]{64}$`),
	}

	for _, regex := range hashRegexes {
		if regex.MatchString(target) {
			return "hash"
		}
	}

	// Check if it's a domain (more flexible regex)
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)
	if domainRegex.MatchString(target) {
		return "domain"
	}

	return "unknown"
}

// analyzeIPAddress performs comprehensive IP address analysis
func (tie *ThreatIntelligenceEngine) analyzeIPAddress(ctx context.Context, ip string, report *ThreatReport) error {
	var indicators []*ThreatIndicator

	// Check IOC database
	if ioc, err := tie.iocDatabase.Lookup(ip, "ip"); err == nil && ioc != nil {
		indicators = append(indicators, ioc)
		report.Sources = append(report.Sources, ioc.Source)
	}

	// Geolocation analysis
	if tie.config.GeolocationAnalysis {
		geoInfo := tie.analyzeGeolocation(ip)
		if geoInfo != nil {
			report.GeolocationInfo = geoInfo

			// Check for high-risk countries
			if tie.isHighRiskCountry(geoInfo.CountryCode) {
				indicators = append(indicators, &ThreatIndicator{
					ID:          fmt.Sprintf("geo_%s_%d", ip, time.Now().UnixNano()),
					Type:        "ip",
					Value:       ip,
					Confidence:  0.6,
					Severity:    "medium",
					Source:      "Geolocation Analysis",
					Description: fmt.Sprintf("IP from high-risk country: %s", geoInfo.Country),
					Tags:        []string{"geolocation", "high_risk_country"},
					FirstSeen:   time.Now(),
					LastSeen:    time.Now(),
				})
			}
		}
	}

	// Behavior analysis
	if tie.config.BehaviorAnalysis {
		behaviorAnalysis := tie.analyzeBehavior(ip)
		if behaviorAnalysis != nil {
			report.BehaviorAnalysis = behaviorAnalysis

			// Generate indicators based on behavior
			for _, pattern := range behaviorAnalysis.ThreatBehaviors {
				indicators = append(indicators, &ThreatIndicator{
					ID:          fmt.Sprintf("behavior_%s_%d", ip, time.Now().UnixNano()),
					Type:        "ip",
					Value:       ip,
					Confidence:  behaviorAnalysis.Confidence,
					Severity:    "medium",
					Source:      "Behavior Analysis",
					Description: fmt.Sprintf("Suspicious behavior detected: %s", pattern),
					Tags:        []string{"behavior", "suspicious"},
					FirstSeen:   time.Now(),
					LastSeen:    time.Now(),
				})
			}
		}
	}

	// Reputation scoring
	if tie.config.ReputationScoring {
		reputationData := tie.getReputationData(ip, "ip")
		if reputationData != nil {
			report.ReputationData = reputationData

			if reputationData.OverallScore < 0.3 {
				indicators = append(indicators, &ThreatIndicator{
					ID:          fmt.Sprintf("reputation_%s_%d", ip, time.Now().UnixNano()),
					Type:        "ip",
					Value:       ip,
					Confidence:  reputationData.Confidence,
					Severity:    "high",
					Source:      "Reputation Analysis",
					Description: "Low reputation score detected",
					Tags:        []string{"reputation", "low_score"},
					FirstSeen:   time.Now(),
					LastSeen:    time.Now(),
				})
			}
		}
	}

	// Check for suspicious IP ranges
	if tie.isSuspiciousIPRange(ip) {
		indicators = append(indicators, &ThreatIndicator{
			ID:          fmt.Sprintf("range_%s_%d", ip, time.Now().UnixNano()),
			Type:        "ip",
			Value:       ip,
			Confidence:  0.7,
			Severity:    "medium",
			Source:      "Range Analysis",
			Description: "IP in suspicious range",
			Tags:        []string{"suspicious_range"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		})
	}

	report.Indicators = indicators
	return nil
}

// analyzeDomain performs comprehensive domain analysis
func (tie *ThreatIntelligenceEngine) analyzeDomain(ctx context.Context, domain string, report *ThreatReport) error {
	var indicators []*ThreatIndicator

	// Check IOC database
	if ioc, err := tie.iocDatabase.Lookup(domain, "domain"); err == nil && ioc != nil {
		indicators = append(indicators, ioc)
		report.Sources = append(report.Sources, ioc.Source)
	}

	// Domain characteristics analysis
	domainIndicators := tie.analyzeDomainCharacteristics(domain)
	indicators = append(indicators, domainIndicators...)

	// DNS analysis
	dnsIndicators := tie.analyzeDNSRecords(domain)
	indicators = append(indicators, dnsIndicators...)

	// SSL certificate analysis
	sslIndicators := tie.analyzeSSLCertificate(domain)
	indicators = append(indicators, sslIndicators...)

	// Reputation scoring
	if tie.config.ReputationScoring {
		reputationData := tie.getReputationData(domain, "domain")
		if reputationData != nil {
			report.ReputationData = reputationData

			if reputationData.OverallScore < 0.3 {
				indicators = append(indicators, &ThreatIndicator{
					ID:          fmt.Sprintf("reputation_%s_%d", domain, time.Now().UnixNano()),
					Type:        "domain",
					Value:       domain,
					Confidence:  reputationData.Confidence,
					Severity:    "high",
					Source:      "Reputation Analysis",
					Description: "Low reputation score detected",
					Tags:        []string{"reputation", "low_score"},
					FirstSeen:   time.Now(),
					LastSeen:    time.Now(),
				})
			}
		}
	}

	report.Indicators = indicators
	return nil
}

// analyzeURL performs comprehensive URL analysis
func (tie *ThreatIntelligenceEngine) analyzeURL(ctx context.Context, targetURL string, report *ThreatReport) error {
	var indicators []*ThreatIndicator

	// Parse URL
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Check IOC database for full URL
	if ioc, err := tie.iocDatabase.Lookup(targetURL, "url"); err == nil && ioc != nil {
		indicators = append(indicators, ioc)
		report.Sources = append(report.Sources, ioc.Source)
	}

	// Analyze domain component
	if u.Host != "" {
		domainReport := &ThreatReport{}
		if err := tie.analyzeDomain(ctx, u.Host, domainReport); err == nil {
			indicators = append(indicators, domainReport.Indicators...)
			if domainReport.ReputationData != nil {
				report.ReputationData = domainReport.ReputationData
			}
		}
	}

	// URL pattern analysis
	urlIndicators := tie.analyzeURLPatterns(targetURL)
	indicators = append(indicators, urlIndicators...)

	// Check for suspicious URL characteristics
	if tie.isSuspiciousURL(targetURL) {
		indicators = append(indicators, &ThreatIndicator{
			ID:          fmt.Sprintf("url_%s_%d", tie.hashString(targetURL), time.Now().UnixNano()),
			Type:        "url",
			Value:       targetURL,
			Confidence:  0.6,
			Severity:    "medium",
			Source:      "URL Analysis",
			Description: "Suspicious URL characteristics detected",
			Tags:        []string{"suspicious_url"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		})
	}

	report.Indicators = indicators
	return nil
}

// analyzeHash performs comprehensive hash analysis
func (tie *ThreatIntelligenceEngine) analyzeHash(ctx context.Context, hash string, report *ThreatReport) error {
	var indicators []*ThreatIndicator

	// Check IOC database
	if ioc, err := tie.iocDatabase.Lookup(hash, "hash"); err == nil && ioc != nil {
		indicators = append(indicators, ioc)
		report.Sources = append(report.Sources, ioc.Source)
	}

	// Determine hash type
	hashType := tie.determineHashType(hash)

	// Check against malware databases (simulated)
	malwareIndicators := tie.checkMalwareHashes(hash, hashType)
	indicators = append(indicators, malwareIndicators...)

	report.Indicators = indicators
	return nil
}

// Helper methods for analysis

// analyzeGeolocation performs geolocation analysis
func (tie *ThreatIntelligenceEngine) analyzeGeolocation(ip string) *GeolocationInfo {
	// Simulate geolocation lookup
	// In production, this would use actual geolocation services

	// Simple simulation based on IP ranges
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
		return &GeolocationInfo{
			Country:     "Private Network",
			CountryCode: "XX",
			Region:      "Private",
			City:        "Private",
			RiskLevel:   "low",
		}
	}

	// Simulate high-risk countries
	highRiskIPs := map[string]*GeolocationInfo{
		"203.0.113.1": {
			Country:      "Example Country",
			CountryCode:  "EX",
			Region:       "Example Region",
			City:         "Example City",
			ASN:          "AS12345",
			Organization: "Example ISP",
			RiskLevel:    "high",
		},
	}

	if geoInfo, exists := highRiskIPs[ip]; exists {
		return geoInfo
	}

	// Default geolocation
	return &GeolocationInfo{
		Country:     "Unknown",
		CountryCode: "XX",
		Region:      "Unknown",
		City:        "Unknown",
		RiskLevel:   "medium",
	}
}

// isHighRiskCountry checks if a country is considered high-risk
func (tie *ThreatIntelligenceEngine) isHighRiskCountry(countryCode string) bool {
	highRiskCountries := []string{"EX", "XX", "CN", "RU", "KP", "IR"}

	for _, riskCountry := range highRiskCountries {
		if countryCode == riskCountry {
			return true
		}
	}

	return false
}

// analyzeBehavior performs behavioral analysis
func (tie *ThreatIntelligenceEngine) analyzeBehavior(ip string) *BehaviorAnalysis {
	// Simulate behavior analysis
	// In production, this would analyze network logs and patterns

	analysis := &BehaviorAnalysis{
		Patterns:        []string{},
		Anomalies:       []string{},
		ThreatBehaviors: []string{},
		RiskFactors:     []string{},
		Confidence:      0.5,
		LastAnalyzed:    time.Now(),
	}

	// Simulate suspicious behavior detection
	if ip == "203.0.113.1" {
		analysis.ThreatBehaviors = append(analysis.ThreatBehaviors, "port_scanning", "brute_force")
		analysis.RiskFactors = append(analysis.RiskFactors, "multiple_failed_logins", "unusual_traffic_patterns")
		analysis.Confidence = 0.8
	}

	return analysis
}

// getReputationData gets reputation data for an indicator
func (tie *ThreatIntelligenceEngine) getReputationData(indicator, indicatorType string) *ReputationData {
	if tie.reputationEngine == nil {
		return nil
	}

	score, _ := tie.reputationEngine.GetScore(indicator, indicatorType)

	return &ReputationData{
		OverallScore: score,
		SourceScores: map[string]float64{
			"internal": score,
		},
		Categories: map[string]float64{
			"malware":  score * 0.8,
			"phishing": score * 0.6,
			"spam":     score * 0.4,
		},
		LastUpdated: time.Now(),
		Confidence:  0.7,
		Factors:     []string{"threat_intelligence", "behavior_analysis"},
	}
}

// isSuspiciousIPRange checks if IP is in suspicious range
func (tie *ThreatIntelligenceEngine) isSuspiciousIPRange(ip string) bool {
	suspiciousRanges := []string{
		"203.0.113.0/24",  // Example range
		"198.51.100.0/24", // Example range
	}

	for _, cidr := range suspiciousRanges {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			if ipnet.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}

	return false
}

// analyzeDomainCharacteristics analyzes domain characteristics
func (tie *ThreatIntelligenceEngine) analyzeDomainCharacteristics(domain string) []*ThreatIndicator {
	var indicators []*ThreatIndicator

	// Check for suspicious domain patterns
	suspiciousPatterns := []string{
		"[0-9]{4,}",  // Many numbers
		"[a-z]{20,}", // Very long strings
		"(.)\\1{3,}", // Repeated characters
	}

	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, domain); matched {
			indicators = append(indicators, &ThreatIndicator{
				ID:          fmt.Sprintf("domain_pattern_%s_%d", tie.hashString(domain), time.Now().UnixNano()),
				Type:        "domain",
				Value:       domain,
				Confidence:  0.6,
				Severity:    "medium",
				Source:      "Domain Analysis",
				Description: fmt.Sprintf("Suspicious domain pattern detected: %s", pattern),
				Tags:        []string{"suspicious_pattern"},
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
			})
		}
	}

	// Check domain length
	if len(domain) > 50 {
		indicators = append(indicators, &ThreatIndicator{
			ID:          fmt.Sprintf("domain_length_%s_%d", tie.hashString(domain), time.Now().UnixNano()),
			Type:        "domain",
			Value:       domain,
			Confidence:  0.5,
			Severity:    "low",
			Source:      "Domain Analysis",
			Description: "Unusually long domain name",
			Tags:        []string{"long_domain"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		})
	}

	return indicators
}

// analyzeDNSRecords analyzes DNS records for threats
func (tie *ThreatIntelligenceEngine) analyzeDNSRecords(domain string) []*ThreatIndicator {
	var indicators []*ThreatIndicator

	// Simulate DNS analysis
	// In production, this would perform actual DNS lookups

	// Check for suspicious DNS patterns
	if strings.Contains(domain, "malicious") || strings.Contains(domain, "phishing") {
		indicators = append(indicators, &ThreatIndicator{
			ID:          fmt.Sprintf("dns_%s_%d", tie.hashString(domain), time.Now().UnixNano()),
			Type:        "domain",
			Value:       domain,
			Confidence:  0.9,
			Severity:    "high",
			Source:      "DNS Analysis",
			Description: "Suspicious domain name detected",
			Tags:        []string{"suspicious_dns"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		})
	}

	return indicators
}

// analyzeSSLCertificate analyzes SSL certificate
func (tie *ThreatIntelligenceEngine) analyzeSSLCertificate(domain string) []*ThreatIndicator {
	var indicators []*ThreatIndicator

	// Simulate SSL certificate analysis
	// In production, this would check actual SSL certificates

	// Check for suspicious certificate patterns
	if strings.Contains(domain, "secure") && strings.Contains(domain, "bank") {
		indicators = append(indicators, &ThreatIndicator{
			ID:          fmt.Sprintf("ssl_%s_%d", tie.hashString(domain), time.Now().UnixNano()),
			Type:        "domain",
			Value:       domain,
			Confidence:  0.7,
			Severity:    "medium",
			Source:      "SSL Analysis",
			Description: "Potentially deceptive domain name",
			Tags:        []string{"deceptive_ssl"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		})
	}

	return indicators
}

// determineHashType determines the type of hash
func (tie *ThreatIntelligenceEngine) determineHashType(hash string) string {
	switch len(hash) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	default:
		return "unknown"
	}
}

// checkMalwareHashes checks hash against malware databases
func (tie *ThreatIntelligenceEngine) checkMalwareHashes(hash, hashType string) []*ThreatIndicator {
	var indicators []*ThreatIndicator

	// Simulate malware hash database lookup
	malwareHashes := map[string]*ThreatIndicator{
		"d41d8cd98f00b204e9800998ecf8427e": {
			ID:          fmt.Sprintf("malware_%s_%d", hash, time.Now().UnixNano()),
			Type:        "hash",
			Value:       hash,
			Confidence:  0.9,
			Severity:    "high",
			Source:      "Malware Database",
			Description: "Known malware hash",
			Tags:        []string{"malware", "trojan"},
			FirstSeen:   time.Now().Add(-24 * time.Hour),
			LastSeen:    time.Now(),
		},
	}

	if indicator, exists := malwareHashes[hash]; exists {
		indicators = append(indicators, indicator)
	}

	return indicators
}

// analyzeURLPatterns analyzes URL patterns for threats
func (tie *ThreatIntelligenceEngine) analyzeURLPatterns(targetURL string) []*ThreatIndicator {
	var indicators []*ThreatIndicator

	// Check for suspicious URL patterns
	suspiciousPatterns := []string{
		`(?i)(login|signin|account).*?(secure|verify|update)`,
		`(?i)(bank|paypal|amazon).*?(secure|login)`,
		`(?i)(download|install).*?(exe|zip|rar)`,
		`(?i)(click|here|now).*?(urgent|immediate)`,
	}

	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, targetURL); matched {
			indicators = append(indicators, &ThreatIndicator{
				ID:          fmt.Sprintf("url_pattern_%s_%d", tie.hashString(targetURL), time.Now().UnixNano()),
				Type:        "url",
				Value:       targetURL,
				Confidence:  0.7,
				Severity:    "medium",
				Source:      "URL Pattern Analysis",
				Description: fmt.Sprintf("Suspicious URL pattern detected: %s", pattern),
				Tags:        []string{"suspicious_pattern", "phishing"},
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
			})
		}
	}

	return indicators
}

// isSuspiciousURL checks if URL has suspicious characteristics
func (tie *ThreatIntelligenceEngine) isSuspiciousURL(targetURL string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	// Check for suspicious characteristics
	suspiciousIndicators := []string{
		"bit.ly", "tinyurl.com", "t.co", // URL shorteners
		"secure-", "verify-", "update-", // Suspicious prefixes
		".tk", ".ml", ".ga", ".cf", // Suspicious TLDs
	}

	for _, indicator := range suspiciousIndicators {
		if strings.Contains(u.Host, indicator) || strings.Contains(u.Path, indicator) {
			return true
		}
	}

	// Check for excessive subdomains
	parts := strings.Split(u.Host, ".")
	if len(parts) > 4 {
		return true
	}

	// Check for suspicious query parameters
	if strings.Contains(u.RawQuery, "redirect") || strings.Contains(u.RawQuery, "url=") {
		return true
	}

	return false
}

// hashString creates a hash of a string for ID generation
func (tie *ThreatIntelligenceEngine) hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)[:8]
}

// calculateThreatScore calculates overall threat score
func (tie *ThreatIntelligenceEngine) calculateThreatScore(indicators []*ThreatIndicator) float64 {
	if len(indicators) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, indicator := range indicators {
		severityScore := tie.getSeverityScore(indicator.Severity)
		totalScore += severityScore * indicator.Confidence
	}

	// Normalize to 0-10 scale
	avgScore := totalScore / float64(len(indicators))
	return avgScore * 10.0
}

// calculateRiskLevel calculates risk level based on threat score
func (tie *ThreatIntelligenceEngine) calculateRiskLevel(threatScore float64) string {
	switch {
	case threatScore >= 8.0:
		return "critical"
	case threatScore >= 6.0:
		return "high"
	case threatScore >= 4.0:
		return "medium"
	case threatScore >= 2.0:
		return "low"
	default:
		return "minimal"
	}
}

// calculateConfidence calculates overall confidence
func (tie *ThreatIntelligenceEngine) calculateConfidence(indicators []*ThreatIndicator) float64 {
	if len(indicators) == 0 {
		return 0.0
	}

	totalConfidence := 0.0
	for _, indicator := range indicators {
		totalConfidence += indicator.Confidence
	}

	return totalConfidence / float64(len(indicators))
}

// getSeverityScore converts severity to numeric score
func (tie *ThreatIntelligenceEngine) getSeverityScore(severity string) float64 {
	switch severity {
	case "critical":
		return 1.0
	case "high":
		return 0.8
	case "medium":
		return 0.6
	case "low":
		return 0.4
	default:
		return 0.2
	}
}

// performThreatCorrelation performs threat correlation analysis
func (tie *ThreatIntelligenceEngine) performThreatCorrelation(ctx context.Context, report *ThreatReport) {
	// Simulate threat correlation
	// In production, this would correlate threats across multiple indicators

	if len(report.Indicators) > 0 {
		primaryIOC := report.Indicators[0]

		// Find related threats
		relatedThreats := tie.findRelatedThreats(primaryIOC)
		report.RelatedThreats = relatedThreats

		// Note: RelatedIOCs field not available in base ThreatIndicator type
		// Correlation data is stored in the ThreatReport instead
	}
}

// findRelatedThreats finds threats related to an indicator
func (tie *ThreatIntelligenceEngine) findRelatedThreats(indicator *ThreatIndicator) []*ThreatIndicator {
	var relatedThreats []*ThreatIndicator

	// Simulate finding related threats
	// In production, this would query the IOC database for related indicators

	if indicator.Type == "ip" && indicator.Value == "203.0.113.1" {
		relatedThreats = append(relatedThreats, &ThreatIndicator{
			ID:          fmt.Sprintf("related_%d", time.Now().UnixNano()),
			Type:        "domain",
			Value:       "malicious.example.com",
			Confidence:  0.8,
			Severity:    "high",
			Source:      "Correlation Analysis",
			Description: "Related malicious domain",
			Tags:        []string{"related", "correlation"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		})
	}

	return relatedThreats
}

// getRelatedIOCs gets related IOCs for an indicator
func (tie *ThreatIntelligenceEngine) getRelatedIOCs(indicator *ThreatIndicator) []string {
	var relatedIOCs []string

	// Simulate finding related IOCs
	if indicator.Type == "ip" {
		relatedIOCs = append(relatedIOCs, "malicious.example.com", "bad-actor.net")
	} else if indicator.Type == "domain" {
		relatedIOCs = append(relatedIOCs, "203.0.113.1", "198.51.100.1")
	}

	return relatedIOCs
}

// generateRecommendations generates security recommendations
func (tie *ThreatIntelligenceEngine) generateRecommendations(report *ThreatReport) []string {
	var recommendations []string

	if report.ThreatScore >= 8.0 {
		recommendations = append(recommendations, "Immediately block all traffic from this indicator")
		recommendations = append(recommendations, "Investigate all recent connections to this indicator")
		recommendations = append(recommendations, "Review security logs for compromise indicators")
	} else if report.ThreatScore >= 6.0 {
		recommendations = append(recommendations, "Monitor traffic from this indicator closely")
		recommendations = append(recommendations, "Consider blocking if suspicious activity continues")
		recommendations = append(recommendations, "Implement additional logging for this indicator")
	} else if report.ThreatScore >= 4.0 {
		recommendations = append(recommendations, "Add to watch list for monitoring")
		recommendations = append(recommendations, "Review periodically for changes in threat level")
	}

	// Add specific recommendations based on indicator types
	for _, indicator := range report.Indicators {
		switch indicator.Type {
		case "ip":
			recommendations = append(recommendations, "Consider IP-based blocking rules")
		case "domain":
			recommendations = append(recommendations, "Consider DNS-based blocking")
		case "url":
			recommendations = append(recommendations, "Consider URL filtering rules")
		case "hash":
			recommendations = append(recommendations, "Consider file hash blocking")
		}
	}

	return recommendations
}

// generateActions generates actionable security actions
func (tie *ThreatIntelligenceEngine) generateActions(report *ThreatReport) []string {
	var actions []string

	if report.ThreatScore >= 8.0 {
		actions = append(actions, "BLOCK_IMMEDIATELY")
		actions = append(actions, "ALERT_SOC")
		actions = append(actions, "INVESTIGATE_CONNECTIONS")
	} else if report.ThreatScore >= 6.0 {
		actions = append(actions, "MONITOR_CLOSELY")
		actions = append(actions, "ALERT_SECURITY_TEAM")
		actions = append(actions, "INCREASE_LOGGING")
	} else if report.ThreatScore >= 4.0 {
		actions = append(actions, "ADD_TO_WATCHLIST")
		actions = append(actions, "SCHEDULE_REVIEW")
	}

	return actions
}

// Background worker methods

// feedUpdateWorker background worker for updating threat feeds
func (tie *ThreatIntelligenceEngine) feedUpdateWorker() {
	defer tie.wg.Done()

	ticker := time.NewTicker(tie.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tie.ctx.Done():
			return
		case <-ticker.C:
			if tie.feedManager != nil {
				// Trigger feed updates through feed manager
				feeds := tie.feedManager.ListFeeds()
				for _, feed := range feeds {
					if feed.Enabled && time.Since(feed.LastUpdated) >= feed.UpdateFreq {
						if err := tie.feedManager.UpdateFeed(feed.ID); err != nil {
							tie.logger.Error("Failed to update feed", "feed_id", feed.ID, "error", err)
						}
					}
				}
			}
		}
	}
}

// correlationWorker background worker for threat correlation
func (tie *ThreatIntelligenceEngine) correlationWorker() {
	defer tie.wg.Done()

	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-tie.ctx.Done():
			return
		case <-ticker.C:
			if tie.config.ThreatCorrelation {
				tie.performBackgroundCorrelation()
			}
		}
	}
}

// cleanupWorker background worker for cleanup tasks
func (tie *ThreatIntelligenceEngine) cleanupWorker() {
	defer tie.wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-tie.ctx.Done():
			return
		case <-ticker.C:
			tie.performCleanupTasks()
		}
	}
}

// startRealTimeFeeds starts real-time threat intelligence feeds
func (tie *ThreatIntelligenceEngine) startRealTimeFeeds() {
	tie.logger.Info("Starting real-time threat feeds")

	// Initialize real-time feeds
	realTimeFeeds := []*RealTimeFeed{
		{
			ID:        "realtime_feed_1",
			Name:      "Real-time Malware Feed",
			URL:       "wss://threat-feed.example.com/malware",
			Connected: false,
		},
		{
			ID:        "realtime_feed_2",
			Name:      "Real-time IP Reputation Feed",
			URL:       "wss://threat-feed.example.com/ip-reputation",
			Connected: false,
		},
	}

	for _, feed := range realTimeFeeds {
		tie.realTimeFeeds[feed.ID] = feed
		// In production, this would establish WebSocket connections
		tie.logger.Info("Real-time feed initialized", "feed_id", feed.ID, "name", feed.Name)
	}
}

// performBackgroundCorrelation performs background threat correlation
func (tie *ThreatIntelligenceEngine) performBackgroundCorrelation() {
	tie.logger.Debug("Performing background threat correlation")

	// Get recent IOCs for correlation
	if tie.iocDatabase != nil {
		// Correlate recent indicators
		criteria := &SearchCriteria{
			Since: &[]time.Time{time.Now().Add(-24 * time.Hour)}[0],
		}

		indicators, err := tie.iocDatabase.Search(criteria)
		if err != nil {
			tie.logger.Error("Failed to search IOCs for correlation", "error", err)
			return
		}

		// Perform correlation analysis
		correlations := tie.correlateIndicators(indicators)

		tie.logger.Info("Background correlation completed",
			"indicators_analyzed", len(indicators),
			"correlations_found", len(correlations))
	}
}

// correlateIndicators correlates threat indicators
func (tie *ThreatIntelligenceEngine) correlateIndicators(indicators []*ThreatIndicator) []*ThreatCorrelation {
	var correlations []*ThreatCorrelation

	// Simple correlation based on common attributes
	for i, indicator1 := range indicators {
		for j, indicator2 := range indicators {
			if i >= j {
				continue
			}

			correlation := tie.calculateCorrelation(indicator1, indicator2)
			if correlation != nil && correlation.CorrelationScore > 0.5 {
				correlations = append(correlations, correlation)
			}
		}
	}

	return correlations
}

// calculateCorrelation calculates correlation between two indicators
func (tie *ThreatIntelligenceEngine) calculateCorrelation(indicator1, indicator2 *ThreatIndicator) *ThreatCorrelation {
	score := 0.0
	correlationType := "unknown"
	evidence := []string{}

	// Check for common tags
	commonTags := tie.findCommonTags(indicator1.Tags, indicator2.Tags)
	if len(commonTags) > 0 {
		score += 0.3
		correlationType = "tag_similarity"
		evidence = append(evidence, fmt.Sprintf("Common tags: %v", commonTags))
	}

	// Check for same source
	if indicator1.Source == indicator2.Source {
		score += 0.2
		evidence = append(evidence, "Same threat source")
	}

	// Check for same malware family
	if tie.hasSameMalwareFamily(indicator1, indicator2) {
		score += 0.4
		correlationType = "malware_family"
		evidence = append(evidence, "Same malware family")
	}

	// Check for temporal correlation
	timeDiff := indicator1.FirstSeen.Sub(indicator2.FirstSeen)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff < 24*time.Hour {
		score += 0.2
		evidence = append(evidence, "Temporal correlation")
	}

	if score > 0.3 {
		return &ThreatCorrelation{
			PrimaryIOC:       indicator1,
			RelatedIOCs:      []*ThreatIndicator{indicator2},
			CorrelationScore: score,
			CorrelationType:  correlationType,
			Confidence:       score * 0.8,
			Evidence:         evidence,
			CreatedAt:        time.Now(),
		}
	}

	return nil
}

// findCommonTags finds common tags between two tag lists
func (tie *ThreatIntelligenceEngine) findCommonTags(tags1, tags2 []string) []string {
	var common []string

	for _, tag1 := range tags1 {
		for _, tag2 := range tags2 {
			if tag1 == tag2 {
				common = append(common, tag1)
				break
			}
		}
	}

	return common
}

// hasSameMalwareFamily checks if indicators belong to same malware family
func (tie *ThreatIntelligenceEngine) hasSameMalwareFamily(indicator1, indicator2 *ThreatIndicator) bool {
	// Check tags for malware family information since MalwareFamilies field not available
	for _, tag1 := range indicator1.Tags {
		for _, tag2 := range indicator2.Tags {
			if tag1 == tag2 && (strings.Contains(tag1, "malware") || strings.Contains(tag1, "family")) {
				return true
			}
		}
	}
	return false
}

// performCleanupTasks performs various cleanup tasks
func (tie *ThreatIntelligenceEngine) performCleanupTasks() {
	tie.logger.Debug("Performing cleanup tasks")

	// Cleanup cache
	if tie.cache != nil {
		tie.cache.Optimize()
	}

	// Update feed statistics
	if tie.feedManager != nil {
		stats := tie.feedManager.GetStatistics()
		tie.logger.Debug("Feed manager statistics", "stats", stats)
	}

	// Update IOC statistics
	if tie.iocDatabase != nil {
		stats := tie.iocDatabase.GetStatistics()
		tie.logger.Debug("IOC database statistics", "stats", stats)
	}

	// Update reputation statistics
	if tie.reputationEngine != nil {
		stats := tie.reputationEngine.GetStatistics()
		tie.logger.Debug("Reputation engine statistics", "stats", stats)
	}
}
