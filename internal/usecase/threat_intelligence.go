package usecase

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// ThreatIntelligenceUseCase implements AI-powered threat intelligence
type ThreatIntelligenceUseCase struct {
	repo   domain.SecurityRepository
	logger *logger.Logger
	client *http.Client
}

// ThreatIndicator represents an indicator of compromise
type ThreatIndicator struct {
	Type        string    `json:"type"`        // ip, domain, hash, url
	Value       string    `json:"value"`       // the actual indicator
	Confidence  float64   `json:"confidence"`  // 0.0 to 1.0
	Severity    string    `json:"severity"`    // low, medium, high, critical
	Source      string    `json:"source"`      // threat feed source
	Description string    `json:"description"` // threat description
	Tags        []string  `json:"tags"`        // malware family, campaign, etc.
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// ThreatReport represents a comprehensive threat analysis
type ThreatReport struct {
	ID          uuid.UUID         `json:"id"`
	Target      string            `json:"target"`
	Indicators  []ThreatIndicator `json:"indicators"`
	RiskScore   float64           `json:"risk_score"`   // 0.0 to 10.0
	Confidence  float64           `json:"confidence"`   // 0.0 to 1.0
	Summary     string            `json:"summary"`
	Recommendations []string      `json:"recommendations"`
	CreatedAt   time.Time         `json:"created_at"`
}

// NewThreatIntelligenceUseCase creates a new threat intelligence use case
func NewThreatIntelligenceUseCase(repo domain.SecurityRepository, log *logger.Logger) *ThreatIntelligenceUseCase {
	return &ThreatIntelligenceUseCase{
		repo:   repo,
		logger: log,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// AnalyzeThreat performs comprehensive threat analysis on a target
func (t *ThreatIntelligenceUseCase) AnalyzeThreat(ctx context.Context, target string) (*ThreatReport, error) {
	report := &ThreatReport{
		ID:        uuid.New(),
		Target:    target,
		CreatedAt: time.Now(),
	}

	// Determine target type and analyze accordingly
	targetType := t.determineTargetType(target)
	
	var indicators []ThreatIndicator
	var err error

	switch targetType {
	case "ip":
		indicators, err = t.analyzeIPAddress(ctx, target)
	case "domain":
		indicators, err = t.analyzeDomain(ctx, target)
	case "url":
		indicators, err = t.analyzeURL(ctx, target)
	case "hash":
		indicators, err = t.analyzeHash(ctx, target)
	default:
		return nil, fmt.Errorf("unsupported target type: %s", targetType)
	}

	if err != nil {
		return nil, fmt.Errorf("threat analysis failed: %w", err)
	}

	report.Indicators = indicators
	report.RiskScore = t.calculateRiskScore(indicators)
	report.Confidence = t.calculateConfidence(indicators)
	report.Summary = t.generateSummary(indicators)
	report.Recommendations = t.generateRecommendations(indicators)

	t.logger.WithContext(ctx).WithFields(logger.Fields{
		"target":     target,
		"risk_score": report.RiskScore,
		"indicators": len(indicators),
	}).Info("Threat analysis completed")

	return report, nil
}

// analyzeIPAddress performs threat intelligence analysis on an IP address
func (t *ThreatIntelligenceUseCase) analyzeIPAddress(ctx context.Context, ip string) ([]ThreatIndicator, error) {
	var indicators []ThreatIndicator

	// Validate IP address
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check against known malicious IP databases
	indicators = append(indicators, t.checkMaliciousIPDatabases(ip)...)

	// Perform geolocation analysis
	geoIndicator := t.analyzeGeolocation(ip)
	if geoIndicator != nil {
		indicators = append(indicators, *geoIndicator)
	}

	// Check for suspicious network behavior patterns
	behaviorIndicators := t.analyzeBehaviorPatterns(ip)
	indicators = append(indicators, behaviorIndicators...)

	// Check reputation databases
	reputationIndicators := t.checkReputationDatabases(ip)
	indicators = append(indicators, reputationIndicators...)

	return indicators, nil
}

// analyzeDomain performs threat intelligence analysis on a domain
func (t *ThreatIntelligenceUseCase) analyzeDomain(ctx context.Context, domain string) ([]ThreatIndicator, error) {
	var indicators []ThreatIndicator

	// Validate domain format
	if !t.isValidDomain(domain) {
		return nil, fmt.Errorf("invalid domain: %s", domain)
	}

	// Check against known malicious domain databases
	indicators = append(indicators, t.checkMaliciousDomainDatabases(domain)...)

	// Analyze domain characteristics
	domainIndicators := t.analyzeDomainCharacteristics(domain)
	indicators = append(indicators, domainIndicators...)

	// Check DNS records for suspicious patterns
	dnsIndicators := t.analyzeDNSRecords(domain)
	indicators = append(indicators, dnsIndicators...)

	// Check domain reputation
	reputationIndicators := t.checkDomainReputation(domain)
	indicators = append(indicators, reputationIndicators...)

	// Analyze SSL certificate
	sslIndicators := t.analyzeSSLCertificate(domain)
	indicators = append(indicators, sslIndicators...)

	return indicators, nil
}

// analyzeURL performs threat intelligence analysis on a URL
func (t *ThreatIntelligenceUseCase) analyzeURL(ctx context.Context, targetURL string) ([]ThreatIndicator, error) {
	var indicators []ThreatIndicator

	// Parse URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Analyze the domain component
	domainIndicators, err := t.analyzeDomain(ctx, parsedURL.Host)
	if err == nil {
		indicators = append(indicators, domainIndicators...)
	}

	// Check URL against malicious URL databases
	indicators = append(indicators, t.checkMaliciousURLDatabases(targetURL)...)

	// Analyze URL structure for suspicious patterns
	structureIndicators := t.analyzeURLStructure(targetURL)
	indicators = append(indicators, structureIndicators...)

	// Check for phishing patterns
	phishingIndicators := t.checkPhishingPatterns(targetURL)
	indicators = append(indicators, phishingIndicators...)

	return indicators, nil
}

// analyzeHash performs threat intelligence analysis on a file hash
func (t *ThreatIntelligenceUseCase) analyzeHash(ctx context.Context, hash string) ([]ThreatIndicator, error) {
	var indicators []ThreatIndicator

	// Validate hash format
	hashType := t.determineHashType(hash)
	if hashType == "" {
		return nil, fmt.Errorf("invalid hash format: %s", hash)
	}

	// Check against malware databases
	indicators = append(indicators, t.checkMalwareHashes(hash, hashType)...)

	// Check VirusTotal-like databases (simulated)
	vtIndicators := t.checkVirusTotalDatabase(hash)
	indicators = append(indicators, vtIndicators...)

	return indicators, nil
}

// AI-powered threat correlation and analysis methods

func (t *ThreatIntelligenceUseCase) checkMaliciousIPDatabases(ip string) []ThreatIndicator {
	var indicators []ThreatIndicator

	// Simulate checking against various threat feeds
	// In a real implementation, this would query actual threat intelligence APIs

	// Check against simulated malicious IP database
	maliciousIPs := map[string]ThreatIndicator{
		"192.168.1.100": {
			Type:        "ip",
			Value:       ip,
			Confidence:  0.9,
			Severity:    "high",
			Source:      "Internal Blacklist",
			Description: "Known botnet command and control server",
			Tags:        []string{"botnet", "c2"},
			FirstSeen:   time.Now().Add(-24 * time.Hour),
			LastSeen:    time.Now().Add(-1 * time.Hour),
		},
	}

	if indicator, exists := maliciousIPs[ip]; exists {
		indicators = append(indicators, indicator)
	}

	// Check for suspicious IP ranges
	if t.isSuspiciousIPRange(ip) {
		indicators = append(indicators, ThreatIndicator{
			Type:        "ip",
			Value:       ip,
			Confidence:  0.6,
			Severity:    "medium",
			Source:      "AI Analysis",
			Description: "IP address in suspicious range",
			Tags:        []string{"suspicious_range"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		})
	}

	return indicators
}

func (t *ThreatIntelligenceUseCase) analyzeGeolocation(ip string) *ThreatIndicator {
	// Simulate geolocation analysis
	// In a real implementation, this would use actual geolocation services

	// Check for high-risk countries (simplified example)
	highRiskCountries := []string{"CN", "RU", "KP", "IR"}
	
	// Simulate geolocation lookup
	country := t.simulateGeolocation(ip)
	
	for _, riskCountry := range highRiskCountries {
		if country == riskCountry {
			return &ThreatIndicator{
				Type:        "ip",
				Value:       ip,
				Confidence:  0.7,
				Severity:    "medium",
				Source:      "Geolocation Analysis",
				Description: fmt.Sprintf("IP address located in high-risk country: %s", country),
				Tags:        []string{"geolocation", "high_risk_country"},
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
			}
		}
	}

	return nil
}

func (t *ThreatIntelligenceUseCase) analyzeBehaviorPatterns(ip string) []ThreatIndicator {
	var indicators []ThreatIndicator

	// Simulate behavior analysis
	// In a real implementation, this would analyze network logs and patterns

	// Check for port scanning behavior
	if t.detectPortScanningBehavior(ip) {
		indicators = append(indicators, ThreatIndicator{
			Type:        "ip",
			Value:       ip,
			Confidence:  0.8,
			Severity:    "high",
			Source:      "Behavior Analysis",
			Description: "IP address showing port scanning behavior",
			Tags:        []string{"port_scanning", "reconnaissance"},
			FirstSeen:   time.Now().Add(-2 * time.Hour),
			LastSeen:    time.Now(),
		})
	}

	// Check for brute force attempts
	if t.detectBruteForceAttempts(ip) {
		indicators = append(indicators, ThreatIndicator{
			Type:        "ip",
			Value:       ip,
			Confidence:  0.9,
			Severity:    "high",
			Source:      "Behavior Analysis",
			Description: "IP address showing brute force attack patterns",
			Tags:        []string{"brute_force", "authentication_attack"},
			FirstSeen:   time.Now().Add(-1 * time.Hour),
			LastSeen:    time.Now(),
		})
	}

	return indicators
}

func (t *ThreatIntelligenceUseCase) checkMaliciousDomainDatabases(domain string) []ThreatIndicator {
	var indicators []ThreatIndicator

	// Simulate checking against malicious domain databases
	maliciousDomains := map[string]ThreatIndicator{
		"malicious-site.com": {
			Type:        "domain",
			Value:       domain,
			Confidence:  0.95,
			Severity:    "critical",
			Source:      "Domain Blacklist",
			Description: "Known phishing domain",
			Tags:        []string{"phishing", "credential_theft"},
			FirstSeen:   time.Now().Add(-48 * time.Hour),
			LastSeen:    time.Now().Add(-30 * time.Minute),
		},
	}

	if indicator, exists := maliciousDomains[domain]; exists {
		indicators = append(indicators, indicator)
	}

	return indicators
}

func (t *ThreatIntelligenceUseCase) analyzeDomainCharacteristics(domain string) []ThreatIndicator {
	var indicators []ThreatIndicator

	// Check for suspicious domain characteristics
	if t.isSuspiciousDomainLength(domain) {
		indicators = append(indicators, ThreatIndicator{
			Type:        "domain",
			Value:       domain,
			Confidence:  0.6,
			Severity:    "low",
			Source:      "Domain Analysis",
			Description: "Domain has suspicious length characteristics",
			Tags:        []string{"suspicious_length"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		})
	}

	// Check for suspicious character patterns
	if t.hasSuspiciousCharacterPatterns(domain) {
		indicators = append(indicators, ThreatIndicator{
			Type:        "domain",
			Value:       domain,
			Confidence:  0.7,
			Severity:    "medium",
			Source:      "Domain Analysis",
			Description: "Domain contains suspicious character patterns",
			Tags:        []string{"suspicious_characters"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		})
	}

	// Check for typosquatting
	if t.isPotentialTyposquatting(domain) {
		indicators = append(indicators, ThreatIndicator{
			Type:        "domain",
			Value:       domain,
			Confidence:  0.8,
			Severity:    "high",
			Source:      "Domain Analysis",
			Description: "Potential typosquatting domain",
			Tags:        []string{"typosquatting", "brand_abuse"},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
		})
	}

	return indicators
}

func (t *ThreatIntelligenceUseCase) checkPhishingPatterns(targetURL string) []ThreatIndicator {
	var indicators []ThreatIndicator

	// Check for common phishing URL patterns
	phishingPatterns := []struct {
		pattern     string
		description string
		severity    string
	}{
		{`(?i)secure.*update`, "Suspicious security update pattern", "medium"},
		{`(?i)verify.*account`, "Account verification phishing pattern", "high"},
		{`(?i)suspended.*account`, "Account suspension phishing pattern", "high"},
		{`(?i)click.*here.*now`, "Urgent action phishing pattern", "medium"},
		{`(?i)limited.*time.*offer`, "Limited time offer phishing pattern", "low"},
	}

	for _, pattern := range phishingPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, targetURL); matched {
			indicators = append(indicators, ThreatIndicator{
				Type:        "url",
				Value:       targetURL,
				Confidence:  0.7,
				Severity:    pattern.severity,
				Source:      "Phishing Analysis",
				Description: pattern.description,
				Tags:        []string{"phishing", "social_engineering"},
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
			})
		}
	}

	return indicators
}

// Helper methods for AI analysis

func (t *ThreatIntelligenceUseCase) determineTargetType(target string) string {
	// Check if it's an IP address
	if net.ParseIP(target) != nil {
		return "ip"
	}

	// Check if it's a URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return "url"
	}

	// Check if it's a hash
	if t.determineHashType(target) != "" {
		return "hash"
	}

	// Default to domain
	return "domain"
}

func (t *ThreatIntelligenceUseCase) determineHashType(hash string) string {
	switch len(hash) {
	case 32:
		return "md5"
	case 64:
		return "sha256"
	case 40:
		return "sha1"
	default:
		return ""
	}
}

func (t *ThreatIntelligenceUseCase) isValidDomain(domain string) bool {
	// Simple domain validation
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

func (t *ThreatIntelligenceUseCase) calculateRiskScore(indicators []ThreatIndicator) float64 {
	if len(indicators) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, indicator := range indicators {
		severityScore := t.getSeverityScore(indicator.Severity)
		totalScore += severityScore * indicator.Confidence
	}

	// Normalize to 0-10 scale
	avgScore := totalScore / float64(len(indicators))
	return avgScore * 10.0
}

func (t *ThreatIntelligenceUseCase) getSeverityScore(severity string) float64 {
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

func (t *ThreatIntelligenceUseCase) calculateConfidence(indicators []ThreatIndicator) float64 {
	if len(indicators) == 0 {
		return 0.0
	}

	totalConfidence := 0.0
	for _, indicator := range indicators {
		totalConfidence += indicator.Confidence
	}

	return totalConfidence / float64(len(indicators))
}

func (t *ThreatIntelligenceUseCase) generateSummary(indicators []ThreatIndicator) string {
	if len(indicators) == 0 {
		return "No threat indicators found. Target appears to be clean."
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, indicator := range indicators {
		switch indicator.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		}
	}

	summary := fmt.Sprintf("Found %d threat indicators: ", len(indicators))
	if criticalCount > 0 {
		summary += fmt.Sprintf("%d critical, ", criticalCount)
	}
	if highCount > 0 {
		summary += fmt.Sprintf("%d high, ", highCount)
	}
	if mediumCount > 0 {
		summary += fmt.Sprintf("%d medium, ", mediumCount)
	}
	if lowCount > 0 {
		summary += fmt.Sprintf("%d low", lowCount)
	}

	return strings.TrimSuffix(summary, ", ")
}

func (t *ThreatIntelligenceUseCase) generateRecommendations(indicators []ThreatIndicator) []string {
	var recommendations []string

	if len(indicators) == 0 {
		return []string{"Continue monitoring for any changes in threat status"}
	}

	// Generate recommendations based on indicator types and severity
	hasCritical := false
	hasPhishing := false
	hasMalware := false

	for _, indicator := range indicators {
		if indicator.Severity == "critical" {
			hasCritical = true
		}
		for _, tag := range indicator.Tags {
			if strings.Contains(tag, "phishing") {
				hasPhishing = true
			}
			if strings.Contains(tag, "malware") || strings.Contains(tag, "botnet") {
				hasMalware = true
			}
		}
	}

	if hasCritical {
		recommendations = append(recommendations, "Immediate action required: Block access to this target")
		recommendations = append(recommendations, "Investigate any recent interactions with this target")
	}

	if hasPhishing {
		recommendations = append(recommendations, "Warn users about potential phishing attempts")
		recommendations = append(recommendations, "Implement email filtering rules")
	}

	if hasMalware {
		recommendations = append(recommendations, "Scan systems for malware infections")
		recommendations = append(recommendations, "Update antivirus signatures")
	}

	recommendations = append(recommendations, "Monitor for future threat intelligence updates")
	recommendations = append(recommendations, "Document incident for future reference")

	return recommendations
}

// Simulation methods (in a real implementation, these would use actual data sources)

func (t *ThreatIntelligenceUseCase) simulateGeolocation(ip string) string {
	// Simulate geolocation lookup
	geoMap := map[string]string{
		"192.168.1.100": "CN",
		"10.0.0.1":      "US",
		"172.16.0.1":    "RU",
	}
	
	if country, exists := geoMap[ip]; exists {
		return country
	}
	return "US" // Default
}

func (t *ThreatIntelligenceUseCase) isSuspiciousIPRange(ip string) bool {
	// Check for suspicious IP ranges (simplified)
	suspiciousRanges := []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
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

func (t *ThreatIntelligenceUseCase) detectPortScanningBehavior(ip string) bool {
	// Simulate port scanning detection
	return ip == "192.168.1.100"
}

func (t *ThreatIntelligenceUseCase) detectBruteForceAttempts(ip string) bool {
	// Simulate brute force detection
	return ip == "192.168.1.100"
}

func (t *ThreatIntelligenceUseCase) isSuspiciousDomainLength(domain string) bool {
	// Very long or very short domains can be suspicious
	return len(domain) > 50 || len(domain) < 4
}

func (t *ThreatIntelligenceUseCase) hasSuspiciousCharacterPatterns(domain string) bool {
	// Check for excessive hyphens, numbers, or random character patterns
	hyphenCount := strings.Count(domain, "-")
	digitCount := 0
	for _, char := range domain {
		if char >= '0' && char <= '9' {
			digitCount++
		}
	}
	
	return hyphenCount > 3 || digitCount > len(domain)/2
}

func (t *ThreatIntelligenceUseCase) isPotentialTyposquatting(domain string) bool {
	// Check against common legitimate domains (simplified)
	legitimateDomains := []string{"google.com", "facebook.com", "microsoft.com", "apple.com"}
	
	for _, legitDomain := range legitimateDomains {
		if t.calculateLevenshteinDistance(domain, legitDomain) <= 2 && domain != legitDomain {
			return true
		}
	}
	return false
}

func (t *ThreatIntelligenceUseCase) calculateLevenshteinDistance(s1, s2 string) int {
	// Simple Levenshtein distance calculation
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}
	
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}
	
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}
	
	return matrix[len(s1)][len(s2)]
}

func min(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}

// Placeholder methods for additional threat intelligence sources
func (t *ThreatIntelligenceUseCase) checkReputationDatabases(ip string) []ThreatIndicator {
	return []ThreatIndicator{}
}

func (t *ThreatIntelligenceUseCase) analyzeDNSRecords(domain string) []ThreatIndicator {
	return []ThreatIndicator{}
}

func (t *ThreatIntelligenceUseCase) checkDomainReputation(domain string) []ThreatIndicator {
	return []ThreatIndicator{}
}

func (t *ThreatIntelligenceUseCase) analyzeSSLCertificate(domain string) []ThreatIndicator {
	return []ThreatIndicator{}
}

func (t *ThreatIntelligenceUseCase) checkMaliciousURLDatabases(url string) []ThreatIndicator {
	return []ThreatIndicator{}
}

func (t *ThreatIntelligenceUseCase) analyzeURLStructure(url string) []ThreatIndicator {
	return []ThreatIndicator{}
}

func (t *ThreatIntelligenceUseCase) checkMalwareHashes(hash, hashType string) []ThreatIndicator {
	return []ThreatIndicator{}
}

func (t *ThreatIntelligenceUseCase) checkVirusTotalDatabase(hash string) []ThreatIndicator {
	return []ThreatIndicator{}
}
