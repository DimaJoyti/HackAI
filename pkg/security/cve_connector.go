package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"golang.org/x/time/rate"
)

// CVEConnector provides integration with CVE databases
type CVEConnector struct {
	logger      *logger.Logger
	config      *CVEConfig
	httpClient  *http.Client
	rateLimiter *rate.Limiter
	cache       *CVECache
	mu          sync.RWMutex
}

// CVEConfig configuration for CVE connector
type CVEConfig struct {
	NVDURL         string        `json:"nvd_url"`
	NVDAPIKEY      string        `json:"nvd_api_key"`
	MITRECVEUrl    string        `json:"mitre_cve_url"`
	Timeout        time.Duration `json:"timeout"`
	RateLimit      int           `json:"rate_limit"` // requests per minute
	CacheTimeout   time.Duration `json:"cache_timeout"`
	EnableCaching  bool          `json:"enable_caching"`
	EnableRealTime bool          `json:"enable_real_time"`
	UpdateInterval time.Duration `json:"update_interval"`
	MaxRetries     int           `json:"max_retries"`
	RetryDelay     time.Duration `json:"retry_delay"`
	EnableNVD      bool          `json:"enable_nvd"`
	EnableMITRE    bool          `json:"enable_mitre"`
}

// CVECache caches CVE data
type CVECache struct {
	vulnerabilities map[string]*CVEVulnerability
	lastUpdate      time.Time
	mu              sync.RWMutex
}

// CVEVulnerability represents a CVE vulnerability
type CVEVulnerability struct {
	ID               string                 `json:"id"`
	Description      string                 `json:"description"`
	PublishedDate    time.Time              `json:"published_date"`
	LastModifiedDate time.Time              `json:"last_modified_date"`
	CVSS2            *CVSSScore             `json:"cvss2,omitempty"`
	CVSS3            *CVSSScore             `json:"cvss3,omitempty"`
	CWE              []string               `json:"cwe"`
	References       []CVEReference         `json:"references"`
	CPE              []string               `json:"cpe"`
	VendorData       []VendorData           `json:"vendor_data"`
	Configurations   []Configuration        `json:"configurations"`
	Impact           *CVEImpact             `json:"impact,omitempty"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// CVSSScore represents CVSS scoring information
type CVSSScore struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vector_string"`
	BaseScore             float64 `json:"base_score"`
	BaseSeverity          string  `json:"base_severity"`
	TemporalScore         float64 `json:"temporal_score,omitempty"`
	EnvironmentalScore    float64 `json:"environmental_score,omitempty"`
	ExploitabilityScore   float64 `json:"exploitability_score"`
	ImpactScore           float64 `json:"impact_score"`
	AttackVector          string  `json:"attack_vector"`
	AttackComplexity      string  `json:"attack_complexity"`
	PrivilegesRequired    string  `json:"privileges_required"`
	UserInteraction       string  `json:"user_interaction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentiality_impact"`
	IntegrityImpact       string  `json:"integrity_impact"`
	AvailabilityImpact    string  `json:"availability_impact"`
}

// CVEReference represents a reference for a CVE
type CVEReference struct {
	URL       string   `json:"url"`
	Name      string   `json:"name"`
	RefSource string   `json:"ref_source"`
	Tags      []string `json:"tags"`
}

// VendorData represents vendor-specific data
type VendorData struct {
	VendorName string    `json:"vendor_name"`
	Products   []Product `json:"products"`
}

// Product represents a product affected by CVE
type Product struct {
	ProductName string    `json:"product_name"`
	Versions    []Version `json:"versions"`
}

// Version represents version information
type Version struct {
	VersionValue string `json:"version_value"`
	VersionType  string `json:"version_type"`
}

// Configuration represents vulnerability configuration
type Configuration struct {
	Operator string     `json:"operator"`
	Children []CPEMatch `json:"children"`
	CPEMatch []CPEMatch `json:"cpe_match"`
}

// CPEMatch represents CPE matching criteria
type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	CPE23Uri              string `json:"cpe23_uri"`
	VersionStartIncluding string `json:"version_start_including,omitempty"`
	VersionStartExcluding string `json:"version_start_excluding,omitempty"`
	VersionEndIncluding   string `json:"version_end_including,omitempty"`
	VersionEndExcluding   string `json:"version_end_excluding,omitempty"`
}

// CVEImpact represents the impact of a CVE
type CVEImpact struct {
	BaseMetricV2 *BaseMetric `json:"base_metric_v2,omitempty"`
	BaseMetricV3 *BaseMetric `json:"base_metric_v3,omitempty"`
}

// BaseMetric represents base metric information
type BaseMetric struct {
	CVSS                    *CVSSScore `json:"cvss"`
	Severity                string     `json:"severity"`
	ExploitabilityScore     float64    `json:"exploitability_score"`
	ImpactScore             float64    `json:"impact_score"`
	ObtainAllPrivilege      bool       `json:"obtain_all_privilege"`
	ObtainUserPrivilege     bool       `json:"obtain_user_privilege"`
	ObtainOtherPrivilege    bool       `json:"obtain_other_privilege"`
	UserInteractionRequired bool       `json:"user_interaction_required"`
}

// CVEQuery represents a query to CVE databases
type CVEQuery struct {
	CVEID           string            `json:"cve_id"`
	Keyword         string            `json:"keyword"`
	Product         string            `json:"product"`
	Vendor          string            `json:"vendor"`
	Version         string            `json:"version"`
	Severity        string            `json:"severity"`
	CVSSScore       float64           `json:"cvss_score"`
	PublishedAfter  *time.Time        `json:"published_after"`
	PublishedBefore *time.Time        `json:"published_before"`
	ModifiedAfter   *time.Time        `json:"modified_after"`
	ModifiedBefore  *time.Time        `json:"modified_before"`
	HasCVSS         bool              `json:"has_cvss"`
	HasKEV          bool              `json:"has_kev"` // Known Exploited Vulnerabilities
	Filters         map[string]string `json:"filters"`
	MaxResults      int               `json:"max_results"`
	StartIndex      int               `json:"start_index"`
}

// CVEResponse represents response from CVE API
type CVEResponse struct {
	ResultsPerPage  int                 `json:"results_per_page"`
	StartIndex      int                 `json:"start_index"`
	TotalResults    int                 `json:"total_results"`
	Format          string              `json:"format"`
	Version         string              `json:"version"`
	Timestamp       time.Time           `json:"timestamp"`
	Vulnerabilities []*CVEVulnerability `json:"vulnerabilities"`
}

// NewCVEConnector creates a new CVE connector
func NewCVEConnector(config *CVEConfig, logger *logger.Logger) *CVEConnector {
	if config == nil {
		config = DefaultCVEConfig()
	}

	// Create rate limiter (requests per minute)
	rateLimiter := rate.NewLimiter(rate.Limit(config.RateLimit)/60, 1)

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	// Initialize cache
	cache := &CVECache{
		vulnerabilities: make(map[string]*CVEVulnerability),
	}

	return &CVEConnector{
		logger:      logger,
		config:      config,
		httpClient:  httpClient,
		rateLimiter: rateLimiter,
		cache:       cache,
	}
}

// DefaultCVEConfig returns default configuration
func DefaultCVEConfig() *CVEConfig {
	return &CVEConfig{
		NVDURL:         "https://services.nvd.nist.gov/rest/json/cves/2.0",
		MITRECVEUrl:    "https://cve.mitre.org/cgi-bin/cvename.cgi",
		Timeout:        30 * time.Second,
		RateLimit:      50, // 50 requests per minute (NVD limit)
		CacheTimeout:   12 * time.Hour,
		EnableCaching:  true,
		EnableRealTime: true,
		UpdateInterval: 6 * time.Hour,
		MaxRetries:     3,
		RetryDelay:     5 * time.Second,
		EnableNVD:      true,
		EnableMITRE:    true,
	}
}

// Start starts the CVE connector
func (c *CVEConnector) Start(ctx context.Context) error {
	c.logger.Info("Starting CVE connector")

	// Start real-time updates if enabled
	if c.config.EnableRealTime {
		go c.realTimeUpdateWorker(ctx)
	}

	c.logger.Info("CVE connector started successfully")
	return nil
}

// QueryCVEs queries CVE databases
func (c *CVEConnector) QueryCVEs(ctx context.Context, query *CVEQuery) ([]*CVEVulnerability, error) {
	// Check cache first
	if c.config.EnableCaching {
		if vulnerabilities := c.getCachedCVEs(query); vulnerabilities != nil {
			return vulnerabilities, nil
		}
	}

	var vulnerabilities []*CVEVulnerability
	var err error

	// Query NVD if enabled
	if c.config.EnableNVD {
		nvdVulns, nvdErr := c.queryNVD(ctx, query)
		if nvdErr != nil {
			c.logger.Error("Failed to query NVD", "error", nvdErr)
			err = nvdErr
		} else {
			vulnerabilities = append(vulnerabilities, nvdVulns...)
		}
	}

	// Cache results
	if c.config.EnableCaching && len(vulnerabilities) > 0 {
		c.cacheCVEs(query, vulnerabilities)
	}

	c.logger.Debug("Retrieved CVE vulnerabilities",
		"count", len(vulnerabilities),
		"query_type", "cve")

	return vulnerabilities, err
}

// GetCVEByID gets a specific CVE by ID
func (c *CVEConnector) GetCVEByID(ctx context.Context, cveID string) (*CVEVulnerability, error) {
	// Check cache first
	if c.config.EnableCaching {
		c.cache.mu.RLock()
		if vulnerability, exists := c.cache.vulnerabilities[cveID]; exists {
			c.cache.mu.RUnlock()
			return vulnerability, nil
		}
		c.cache.mu.RUnlock()
	}

	query := &CVEQuery{
		CVEID:      cveID,
		MaxResults: 1,
	}

	vulnerabilities, err := c.QueryCVEs(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}

	return vulnerabilities[0], nil
}

// queryNVD queries the NVD database
func (c *CVEConnector) queryNVD(ctx context.Context, query *CVEQuery) ([]*CVEVulnerability, error) {
	// Build API request
	req, err := c.buildNVDRequest(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to build NVD request: %w", err)
	}

	// Execute request with rate limiting
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait failed: %w", err)
	}

	resp, err := c.executeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute NVD request: %w", err)
	}

	var response CVEResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal NVD response: %w", err)
	}

	return response.Vulnerabilities, nil
}

// buildNVDRequest builds HTTP request for NVD API
func (c *CVEConnector) buildNVDRequest(ctx context.Context, query *CVEQuery) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.NVDURL, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameters
	q := req.URL.Query()
	if query.CVEID != "" {
		q.Add("cveId", query.CVEID)
	}
	if query.Keyword != "" {
		q.Add("keywordSearch", query.Keyword)
	}
	if query.Product != "" {
		q.Add("cpeName", fmt.Sprintf("cpe:2.3:*:*:%s:*:*:*:*:*:*:*", query.Product))
	}
	if query.CVSSScore > 0 {
		q.Add("cvssV3Severity", c.getCVSSSeverity(query.CVSSScore))
	}
	if query.PublishedAfter != nil {
		q.Add("pubStartDate", query.PublishedAfter.Format("2006-01-02T15:04:05.000"))
	}
	if query.PublishedBefore != nil {
		q.Add("pubEndDate", query.PublishedBefore.Format("2006-01-02T15:04:05.000"))
	}
	if query.ModifiedAfter != nil {
		q.Add("lastModStartDate", query.ModifiedAfter.Format("2006-01-02T15:04:05.000"))
	}
	if query.ModifiedBefore != nil {
		q.Add("lastModEndDate", query.ModifiedBefore.Format("2006-01-02T15:04:05.000"))
	}
	if query.HasCVSS {
		q.Add("hasCvss", "true")
	}
	if query.HasKEV {
		q.Add("hasKev", "true")
	}
	if query.MaxResults > 0 {
		q.Add("resultsPerPage", fmt.Sprintf("%d", query.MaxResults))
	}
	if query.StartIndex > 0 {
		q.Add("startIndex", fmt.Sprintf("%d", query.StartIndex))
	}

	// Add custom filters
	for key, value := range query.Filters {
		q.Add(key, value)
	}

	req.URL.RawQuery = q.Encode()

	// Add authentication if available
	if c.config.NVDAPIKEY != "" {
		req.Header.Set("apiKey", c.config.NVDAPIKEY)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "HackAI-ThreatIntelligence/1.0")

	return req, nil
}

// executeRequest executes HTTP request with retries
func (c *CVEConnector) executeRequest(req *http.Request) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt < c.config.MaxRetries; attempt++ {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < c.config.MaxRetries-1 {
				time.Sleep(c.config.RetryDelay)
				continue
			}
			break
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			// Rate limited, wait and retry
			lastErr = fmt.Errorf("rate limited")
			if attempt < c.config.MaxRetries-1 {
				time.Sleep(c.config.RetryDelay * time.Duration(attempt+1))
				continue
			}
			break
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("API error: %d", resp.StatusCode)
			if attempt < c.config.MaxRetries-1 {
				time.Sleep(c.config.RetryDelay)
				continue
			}
			break
		}

		// Success, read response
		body := make([]byte, 0, resp.ContentLength)
		_, err = resp.Body.Read(body)
		if err != nil {
			lastErr = err
			if attempt < c.config.MaxRetries-1 {
				time.Sleep(c.config.RetryDelay)
				continue
			}
			break
		}

		return body, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", c.config.MaxRetries, lastErr)
}

// realTimeUpdateWorker handles real-time updates
func (c *CVEConnector) realTimeUpdateWorker(ctx context.Context) {
	ticker := time.NewTicker(c.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.updateCache(ctx); err != nil {
				c.logger.Error("Failed to update CVE cache", "error", err)
			}
		}
	}
}

// updateCache updates the cache with latest data
func (c *CVEConnector) updateCache(ctx context.Context) error {
	c.logger.Debug("Updating CVE cache")

	// Check if cache needs update
	c.cache.mu.RLock()
	lastUpdate := c.cache.lastUpdate
	c.cache.mu.RUnlock()

	if time.Since(lastUpdate) < c.config.CacheTimeout {
		return nil // Cache is still fresh
	}

	// Query recent CVEs
	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)

	query := &CVEQuery{
		ModifiedAfter: &yesterday,
		MaxResults:    1000,
	}

	vulnerabilities, err := c.QueryCVEs(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to update CVE cache: %w", err)
	}

	c.logger.Info("Updated CVE cache", "count", len(vulnerabilities))
	return nil
}

// Cache helper methods
func (c *CVEConnector) getCachedCVEs(query *CVEQuery) []*CVEVulnerability {
	c.cache.mu.RLock()
	defer c.cache.mu.RUnlock()

	if time.Since(c.cache.lastUpdate) > c.config.CacheTimeout {
		return nil
	}

	var vulnerabilities []*CVEVulnerability
	for _, vulnerability := range c.cache.vulnerabilities {
		if c.matchesCVEQuery(vulnerability, query) {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities
}

func (c *CVEConnector) cacheCVEs(query *CVEQuery, vulnerabilities []*CVEVulnerability) {
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()

	for _, vulnerability := range vulnerabilities {
		c.cache.vulnerabilities[vulnerability.ID] = vulnerability
	}
	c.cache.lastUpdate = time.Now()
}

func (c *CVEConnector) matchesCVEQuery(vulnerability *CVEVulnerability, query *CVEQuery) bool {
	if query.CVEID != "" && vulnerability.ID != query.CVEID {
		return false
	}
	if query.Keyword != "" && !strings.Contains(strings.ToLower(vulnerability.Description), strings.ToLower(query.Keyword)) {
		return false
	}
	if query.CVSSScore > 0 {
		if vulnerability.CVSS3 != nil && vulnerability.CVSS3.BaseScore < query.CVSSScore {
			return false
		}
		if vulnerability.CVSS2 != nil && vulnerability.CVSS2.BaseScore < query.CVSSScore {
			return false
		}
	}
	if query.PublishedAfter != nil && vulnerability.PublishedDate.Before(*query.PublishedAfter) {
		return false
	}
	if query.PublishedBefore != nil && vulnerability.PublishedDate.After(*query.PublishedBefore) {
		return false
	}
	return true
}

func (c *CVEConnector) getCVSSSeverity(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	} else if score > 0.0 {
		return "LOW"
	}
	return ""
}
