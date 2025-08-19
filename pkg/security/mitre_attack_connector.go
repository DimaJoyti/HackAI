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

// MITREATTACKConnector provides integration with MITRE ATT&CK framework
type MITREATTACKConnector struct {
	logger      *logger.Logger
	config      *MITREATTACKConfig
	httpClient  *http.Client
	rateLimiter *rate.Limiter
	cache       *MITRECache
	mu          sync.RWMutex
}

// MITREATTACKConfig configuration for MITRE ATT&CK connector
type MITREATTACKConfig struct {
	BaseURL        string        `json:"base_url"`
	APIKey         string        `json:"api_key"`
	Timeout        time.Duration `json:"timeout"`
	RateLimit      int           `json:"rate_limit"` // requests per minute
	CacheTimeout   time.Duration `json:"cache_timeout"`
	EnableCaching  bool          `json:"enable_caching"`
	EnableRealTime bool          `json:"enable_real_time"`
	UpdateInterval time.Duration `json:"update_interval"`
	MaxRetries     int           `json:"max_retries"`
	RetryDelay     time.Duration `json:"retry_delay"`
}

// MITRECache caches MITRE ATT&CK data
type MITRECache struct {
	techniques  map[string]*MITRETechnique
	tactics     map[string]*MITRETactic
	groups      map[string]*MITREGroup
	software    map[string]*MITRESoftware
	mitigations map[string]*MITREMitigation
	lastUpdate  time.Time
	mu          sync.RWMutex
}

// MITRETechnique represents a MITRE ATT&CK technique
type MITRETechnique struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	TacticRefs      []string               `json:"tactic_refs"`
	Platforms       []string               `json:"platforms"`
	DataSources     []string               `json:"data_sources"`
	DefenseBypassed []string               `json:"defense_bypassed"`
	Permissions     []string               `json:"permissions"`
	Detection       string                 `json:"detection"`
	Mitigations     []string               `json:"mitigations"`
	References      []MITREReference       `json:"references"`
	Metadata        map[string]interface{} `json:"metadata"`
	LastModified    time.Time              `json:"last_modified"`
}

// MITRETactic represents a MITRE ATT&CK tactic
type MITRETactic struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	ShortName    string                 `json:"short_name"`
	References   []MITREReference       `json:"references"`
	Metadata     map[string]interface{} `json:"metadata"`
	LastModified time.Time              `json:"last_modified"`
}

// MITREGroup represents a MITRE ATT&CK group
type MITREGroup struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Aliases      []string               `json:"aliases"`
	Techniques   []string               `json:"techniques"`
	Software     []string               `json:"software"`
	References   []MITREReference       `json:"references"`
	Metadata     map[string]interface{} `json:"metadata"`
	LastModified time.Time              `json:"last_modified"`
}

// MITRESoftware represents MITRE ATT&CK software
type MITRESoftware struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Type         string                 `json:"type"` // malware, tool
	Platforms    []string               `json:"platforms"`
	Techniques   []string               `json:"techniques"`
	Groups       []string               `json:"groups"`
	References   []MITREReference       `json:"references"`
	Metadata     map[string]interface{} `json:"metadata"`
	LastModified time.Time              `json:"last_modified"`
}

// MITREMitigation represents MITRE ATT&CK mitigation
type MITREMitigation struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Techniques   []string               `json:"techniques"`
	References   []MITREReference       `json:"references"`
	Metadata     map[string]interface{} `json:"metadata"`
	LastModified time.Time              `json:"last_modified"`
}

// MITREReference represents a reference in MITRE ATT&CK
type MITREReference struct {
	SourceName  string `json:"source_name"`
	URL         string `json:"url"`
	Description string `json:"description"`
	ExternalID  string `json:"external_id"`
}

// MITREQuery represents a query to MITRE ATT&CK
type MITREQuery struct {
	Type        string            `json:"type"` // technique, tactic, group, software, mitigation
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Platform    string            `json:"platform"`
	Tactic      string            `json:"tactic"`
	Group       string            `json:"group"`
	Filters     map[string]string `json:"filters"`
	MaxResults  int               `json:"max_results"`
	IncludeRefs bool              `json:"include_refs"`
}

// MITREResponse represents response from MITRE ATT&CK API
type MITREResponse struct {
	Techniques  []*MITRETechnique  `json:"techniques,omitempty"`
	Tactics     []*MITRETactic     `json:"tactics,omitempty"`
	Groups      []*MITREGroup      `json:"groups,omitempty"`
	Software    []*MITRESoftware   `json:"software,omitempty"`
	Mitigations []*MITREMitigation `json:"mitigations,omitempty"`
	Total       int                `json:"total"`
	Page        int                `json:"page"`
	PerPage     int                `json:"per_page"`
}

// NewMITREATTACKConnector creates a new MITRE ATT&CK connector
func NewMITREATTACKConnector(config *MITREATTACKConfig, logger *logger.Logger) *MITREATTACKConnector {
	if config == nil {
		config = DefaultMITREATTACKConfig()
	}

	// Create rate limiter (requests per minute)
	rateLimiter := rate.NewLimiter(rate.Limit(config.RateLimit)/60, 1)

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	// Initialize cache
	cache := &MITRECache{
		techniques:  make(map[string]*MITRETechnique),
		tactics:     make(map[string]*MITRETactic),
		groups:      make(map[string]*MITREGroup),
		software:    make(map[string]*MITRESoftware),
		mitigations: make(map[string]*MITREMitigation),
	}

	return &MITREATTACKConnector{
		logger:      logger,
		config:      config,
		httpClient:  httpClient,
		rateLimiter: rateLimiter,
		cache:       cache,
	}
}

// DefaultMITREATTACKConfig returns default configuration
func DefaultMITREATTACKConfig() *MITREATTACKConfig {
	return &MITREATTACKConfig{
		BaseURL:        "https://attack.mitre.org/api/v2",
		Timeout:        30 * time.Second,
		RateLimit:      60, // 60 requests per minute
		CacheTimeout:   24 * time.Hour,
		EnableCaching:  true,
		EnableRealTime: true,
		UpdateInterval: 6 * time.Hour,
		MaxRetries:     3,
		RetryDelay:     5 * time.Second,
	}
}

// Start starts the MITRE ATT&CK connector
func (m *MITREATTACKConnector) Start(ctx context.Context) error {
	m.logger.Info("Starting MITRE ATT&CK connector")

	// Initial data load
	if err := m.loadInitialData(ctx); err != nil {
		m.logger.Error("Failed to load initial MITRE data", "error", err)
		return err
	}

	// Start real-time updates if enabled
	if m.config.EnableRealTime {
		go m.realTimeUpdateWorker(ctx)
	}

	m.logger.Info("MITRE ATT&CK connector started successfully")
	return nil
}

// QueryTechniques queries MITRE ATT&CK techniques
func (m *MITREATTACKConnector) QueryTechniques(ctx context.Context, query *MITREQuery) ([]*MITRETechnique, error) {
	// Check cache first
	if m.config.EnableCaching {
		if techniques := m.getCachedTechniques(query); techniques != nil {
			return techniques, nil
		}
	}

	// Build API request
	apiURL := fmt.Sprintf("%s/techniques", m.config.BaseURL)
	req, err := m.buildRequest(ctx, "GET", apiURL, query)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// Execute request with rate limiting
	if err := m.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait failed: %w", err)
	}

	resp, err := m.executeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	var response MITREResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Cache results
	if m.config.EnableCaching {
		m.cacheTechniques(query, response.Techniques)
	}

	m.logger.Debug("Retrieved MITRE techniques",
		"count", len(response.Techniques),
		"query_type", query.Type)

	return response.Techniques, nil
}

// QueryTactics queries MITRE ATT&CK tactics
func (m *MITREATTACKConnector) QueryTactics(ctx context.Context, query *MITREQuery) ([]*MITRETactic, error) {
	// Check cache first
	if m.config.EnableCaching {
		if tactics := m.getCachedTactics(query); tactics != nil {
			return tactics, nil
		}
	}

	// Build API request
	apiURL := fmt.Sprintf("%s/tactics", m.config.BaseURL)
	req, err := m.buildRequest(ctx, "GET", apiURL, query)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// Execute request with rate limiting
	if err := m.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait failed: %w", err)
	}

	resp, err := m.executeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	var response MITREResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Cache results
	if m.config.EnableCaching {
		m.cacheTactics(query, response.Tactics)
	}

	m.logger.Debug("Retrieved MITRE tactics",
		"count", len(response.Tactics),
		"query_type", query.Type)

	return response.Tactics, nil
}

// GetTechniqueByID gets a specific technique by ID
func (m *MITREATTACKConnector) GetTechniqueByID(ctx context.Context, techniqueID string) (*MITRETechnique, error) {
	// Check cache first
	if m.config.EnableCaching {
		m.cache.mu.RLock()
		if technique, exists := m.cache.techniques[techniqueID]; exists {
			m.cache.mu.RUnlock()
			return technique, nil
		}
		m.cache.mu.RUnlock()
	}

	query := &MITREQuery{
		Type: "technique",
		ID:   techniqueID,
	}

	techniques, err := m.QueryTechniques(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(techniques) == 0 {
		return nil, fmt.Errorf("technique not found: %s", techniqueID)
	}

	return techniques[0], nil
}

// buildRequest builds HTTP request for MITRE ATT&CK API
func (m *MITREATTACKConnector) buildRequest(ctx context.Context, method, apiURL string, query *MITREQuery) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, apiURL, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameters
	q := req.URL.Query()
	if query.ID != "" {
		q.Add("id", query.ID)
	}
	if query.Name != "" {
		q.Add("name", query.Name)
	}
	if query.Platform != "" {
		q.Add("platform", query.Platform)
	}
	if query.Tactic != "" {
		q.Add("tactic", query.Tactic)
	}
	if query.Group != "" {
		q.Add("group", query.Group)
	}
	if query.MaxResults > 0 {
		q.Add("limit", fmt.Sprintf("%d", query.MaxResults))
	}
	if query.IncludeRefs {
		q.Add("include_refs", "true")
	}

	// Add custom filters
	for key, value := range query.Filters {
		q.Add(key, value)
	}

	req.URL.RawQuery = q.Encode()

	// Add authentication if available
	if m.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+m.config.APIKey)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "HackAI-ThreatIntelligence/1.0")

	return req, nil
}

// executeRequest executes HTTP request with retries
func (m *MITREATTACKConnector) executeRequest(req *http.Request) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt < m.config.MaxRetries; attempt++ {
		resp, err := m.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < m.config.MaxRetries-1 {
				time.Sleep(m.config.RetryDelay)
				continue
			}
			break
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			// Rate limited, wait and retry
			lastErr = fmt.Errorf("rate limited")
			if attempt < m.config.MaxRetries-1 {
				time.Sleep(m.config.RetryDelay * time.Duration(attempt+1))
				continue
			}
			break
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("API error: %d", resp.StatusCode)
			if attempt < m.config.MaxRetries-1 {
				time.Sleep(m.config.RetryDelay)
				continue
			}
			break
		}

		// Success, read response
		body := make([]byte, 0, resp.ContentLength)
		_, err = resp.Body.Read(body)
		if err != nil {
			lastErr = err
			if attempt < m.config.MaxRetries-1 {
				time.Sleep(m.config.RetryDelay)
				continue
			}
			break
		}

		return body, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", m.config.MaxRetries, lastErr)
}

// loadInitialData loads initial MITRE ATT&CK data
func (m *MITREATTACKConnector) loadInitialData(ctx context.Context) error {
	m.logger.Info("Loading initial MITRE ATT&CK data")

	// Load tactics
	tacticsQuery := &MITREQuery{Type: "tactic", MaxResults: 100}
	tactics, err := m.QueryTactics(ctx, tacticsQuery)
	if err != nil {
		return fmt.Errorf("failed to load tactics: %w", err)
	}
	m.logger.Info("Loaded MITRE tactics", "count", len(tactics))

	// Load techniques
	techniquesQuery := &MITREQuery{Type: "technique", MaxResults: 1000}
	techniques, err := m.QueryTechniques(ctx, techniquesQuery)
	if err != nil {
		return fmt.Errorf("failed to load techniques: %w", err)
	}
	m.logger.Info("Loaded MITRE techniques", "count", len(techniques))

	m.cache.mu.Lock()
	m.cache.lastUpdate = time.Now()
	m.cache.mu.Unlock()

	return nil
}

// realTimeUpdateWorker handles real-time updates
func (m *MITREATTACKConnector) realTimeUpdateWorker(ctx context.Context) {
	ticker := time.NewTicker(m.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.updateCache(ctx); err != nil {
				m.logger.Error("Failed to update MITRE cache", "error", err)
			}
		}
	}
}

// updateCache updates the cache with latest data
func (m *MITREATTACKConnector) updateCache(ctx context.Context) error {
	m.logger.Debug("Updating MITRE ATT&CK cache")

	// Check if cache needs update
	m.cache.mu.RLock()
	lastUpdate := m.cache.lastUpdate
	m.cache.mu.RUnlock()

	if time.Since(lastUpdate) < m.config.CacheTimeout {
		return nil // Cache is still fresh
	}

	return m.loadInitialData(ctx)
}

// Cache helper methods
func (m *MITREATTACKConnector) getCachedTechniques(query *MITREQuery) []*MITRETechnique {
	m.cache.mu.RLock()
	defer m.cache.mu.RUnlock()

	if time.Since(m.cache.lastUpdate) > m.config.CacheTimeout {
		return nil
	}

	var techniques []*MITRETechnique
	for _, technique := range m.cache.techniques {
		if m.matchesTechniqueQuery(technique, query) {
			techniques = append(techniques, technique)
		}
	}

	return techniques
}

func (m *MITREATTACKConnector) getCachedTactics(query *MITREQuery) []*MITRETactic {
	m.cache.mu.RLock()
	defer m.cache.mu.RUnlock()

	if time.Since(m.cache.lastUpdate) > m.config.CacheTimeout {
		return nil
	}

	var tactics []*MITRETactic
	for _, tactic := range m.cache.tactics {
		if m.matchesTacticQuery(tactic, query) {
			tactics = append(tactics, tactic)
		}
	}

	return tactics
}

func (m *MITREATTACKConnector) cacheTechniques(query *MITREQuery, techniques []*MITRETechnique) {
	m.cache.mu.Lock()
	defer m.cache.mu.Unlock()

	for _, technique := range techniques {
		m.cache.techniques[technique.ID] = technique
	}
}

func (m *MITREATTACKConnector) cacheTactics(query *MITREQuery, tactics []*MITRETactic) {
	m.cache.mu.Lock()
	defer m.cache.mu.Unlock()

	for _, tactic := range tactics {
		m.cache.tactics[tactic.ID] = tactic
	}
}

func (m *MITREATTACKConnector) matchesTechniqueQuery(technique *MITRETechnique, query *MITREQuery) bool {
	if query.ID != "" && technique.ID != query.ID {
		return false
	}
	if query.Name != "" && !strings.Contains(strings.ToLower(technique.Name), strings.ToLower(query.Name)) {
		return false
	}
	if query.Platform != "" {
		found := false
		for _, platform := range technique.Platforms {
			if strings.EqualFold(platform, query.Platform) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (m *MITREATTACKConnector) matchesTacticQuery(tactic *MITRETactic, query *MITREQuery) bool {
	if query.ID != "" && tactic.ID != query.ID {
		return false
	}
	if query.Name != "" && !strings.Contains(strings.ToLower(tactic.Name), strings.ToLower(query.Name)) {
		return false
	}
	return true
}
