package integration

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// AdvancedToolRegistry provides advanced tool registration and management
type AdvancedToolRegistry struct {
	integrations map[string]*ToolIntegration
	categories   map[string][]*ToolIntegration
	dependencies map[string][]string
	tags         map[string][]*ToolIntegration
	versions     map[string]map[string]*ToolIntegration
	healthChecks map[string]*HealthCheck
	logger       *logger.Logger
	mutex        sync.RWMutex
}

// HealthCheck represents a health check for a tool
type HealthCheck struct {
	ToolID      string                 `json:"tool_id"`
	Status      HealthStatus           `json:"status"`
	LastCheck   time.Time              `json:"last_check"`
	NextCheck   time.Time              `json:"next_check"`
	Interval    time.Duration          `json:"interval"`
	Failures    int                    `json:"failures"`
	MaxFailures int                    `json:"max_failures"`
	Message     string                 `json:"message"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// HealthStatus represents the health status of a tool
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
	HealthStatusChecking  HealthStatus = "checking"
)

// RegistryQuery represents a query for finding tools
type RegistryQuery struct {
	Categories   []string            `json:"categories,omitempty"`
	Tags         []string            `json:"tags,omitempty"`
	Capabilities []ToolCapability    `json:"capabilities,omitempty"`
	Status       []IntegrationStatus `json:"status,omitempty"`
	NamePattern  string              `json:"name_pattern,omitempty"`
	MinVersion   string              `json:"min_version,omitempty"`
	MaxVersion   string              `json:"max_version,omitempty"`
	HealthStatus []HealthStatus      `json:"health_status,omitempty"`
	Limit        int                 `json:"limit,omitempty"`
	Offset       int                 `json:"offset,omitempty"`
	SortBy       string              `json:"sort_by,omitempty"`
	SortOrder    string              `json:"sort_order,omitempty"`
}

// RegistryStats holds statistics about the registry
type RegistryStats struct {
	TotalIntegrations    int                       `json:"total_integrations"`
	IntegrationsByStatus map[IntegrationStatus]int `json:"integrations_by_status"`
	IntegrationsByHealth map[HealthStatus]int      `json:"integrations_by_health"`
	CategoriesCount      map[string]int            `json:"categories_count"`
	TagsCount            map[string]int            `json:"tags_count"`
	AverageSuccessRate   float64                   `json:"average_success_rate"`
	TotalExecutions      int64                     `json:"total_executions"`
	LastUpdated          time.Time                 `json:"last_updated"`
}

// NewAdvancedToolRegistry creates a new advanced tool registry
func NewAdvancedToolRegistry(logger *logger.Logger) *AdvancedToolRegistry {
	registry := &AdvancedToolRegistry{
		integrations: make(map[string]*ToolIntegration),
		categories:   make(map[string][]*ToolIntegration),
		dependencies: make(map[string][]string),
		tags:         make(map[string][]*ToolIntegration),
		versions:     make(map[string]map[string]*ToolIntegration),
		healthChecks: make(map[string]*HealthCheck),
		logger:       logger,
	}

	// Start health check routine
	go registry.healthCheckRoutine()

	return registry
}

// RegisterIntegration registers a tool integration
func (atr *AdvancedToolRegistry) RegisterIntegration(integration *ToolIntegration) error {
	atr.mutex.Lock()
	defer atr.mutex.Unlock()

	toolID := integration.Tool.ID()

	// Check if already registered
	if _, exists := atr.integrations[toolID]; exists {
		return fmt.Errorf("tool %s already registered", toolID)
	}

	// Register integration
	atr.integrations[toolID] = integration

	// Index by category
	if extTool, ok := integration.Tool.(tools.ExtendedTool); ok {
		category := string(extTool.GetCategory())
		atr.categories[category] = append(atr.categories[category], integration)
	}

	// Index by tags
	for tag := range integration.Metadata {
		if strings.HasPrefix(tag, "tag:") {
			tagName := strings.TrimPrefix(tag, "tag:")
			atr.tags[tagName] = append(atr.tags[tagName], integration)
		}
	}

	// Index by version
	toolName := integration.Tool.Name()
	if atr.versions[toolName] == nil {
		atr.versions[toolName] = make(map[string]*ToolIntegration)
	}

	version := "1.0.0" // Default version
	if versionStr, exists := integration.Metadata["version"]; exists {
		if v, ok := versionStr.(string); ok {
			version = v
		}
	}
	atr.versions[toolName][version] = integration

	// Initialize health check
	atr.healthChecks[toolID] = &HealthCheck{
		ToolID:      toolID,
		Status:      HealthStatusUnknown,
		LastCheck:   time.Time{},
		NextCheck:   time.Now().Add(time.Minute),
		Interval:    time.Minute * 5,
		Failures:    0,
		MaxFailures: 3,
		Metadata:    make(map[string]interface{}),
	}

	atr.logger.Info("Tool integration registered",
		"tool_id", toolID,
		"tool_name", integration.Tool.Name(),
		"integration_id", integration.ID)

	return nil
}

// GetIntegration retrieves a tool integration by ID
func (atr *AdvancedToolRegistry) GetIntegration(toolID string) (*ToolIntegration, error) {
	atr.mutex.RLock()
	defer atr.mutex.RUnlock()

	integration, exists := atr.integrations[toolID]
	if !exists {
		return nil, fmt.Errorf("tool %s not found", toolID)
	}

	return integration, nil
}

// GetAllIntegrations returns all registered integrations
func (atr *AdvancedToolRegistry) GetAllIntegrations() []*ToolIntegration {
	atr.mutex.RLock()
	defer atr.mutex.RUnlock()

	integrations := make([]*ToolIntegration, 0, len(atr.integrations))
	for _, integration := range atr.integrations {
		integrations = append(integrations, integration)
	}

	return integrations
}

// QueryIntegrations finds integrations based on query criteria
func (atr *AdvancedToolRegistry) QueryIntegrations(query RegistryQuery) ([]*ToolIntegration, error) {
	atr.mutex.RLock()
	defer atr.mutex.RUnlock()

	var results []*ToolIntegration

	// Start with all integrations
	for _, integration := range atr.integrations {
		if atr.matchesQuery(integration, query) {
			results = append(results, integration)
		}
	}

	// Sort results
	atr.sortResults(results, query.SortBy, query.SortOrder)

	// Apply pagination
	if query.Offset > 0 {
		if query.Offset >= len(results) {
			return []*ToolIntegration{}, nil
		}
		results = results[query.Offset:]
	}

	if query.Limit > 0 && query.Limit < len(results) {
		results = results[:query.Limit]
	}

	return results, nil
}

// GetIntegrationsByCategory returns integrations in a specific category
func (atr *AdvancedToolRegistry) GetIntegrationsByCategory(category string) []*ToolIntegration {
	atr.mutex.RLock()
	defer atr.mutex.RUnlock()

	if integrations, exists := atr.categories[category]; exists {
		// Return a copy to avoid external modifications
		result := make([]*ToolIntegration, len(integrations))
		copy(result, integrations)
		return result
	}

	return []*ToolIntegration{}
}

// GetIntegrationsByTag returns integrations with a specific tag
func (atr *AdvancedToolRegistry) GetIntegrationsByTag(tag string) []*ToolIntegration {
	atr.mutex.RLock()
	defer atr.mutex.RUnlock()

	if integrations, exists := atr.tags[tag]; exists {
		// Return a copy to avoid external modifications
		result := make([]*ToolIntegration, len(integrations))
		copy(result, integrations)
		return result
	}

	return []*ToolIntegration{}
}

// GetIntegrationsByVersion returns integrations for a specific tool version
func (atr *AdvancedToolRegistry) GetIntegrationsByVersion(toolName, version string) (*ToolIntegration, error) {
	atr.mutex.RLock()
	defer atr.mutex.RUnlock()

	if versions, exists := atr.versions[toolName]; exists {
		if integration, exists := versions[version]; exists {
			return integration, nil
		}
		return nil, fmt.Errorf("version %s not found for tool %s", version, toolName)
	}

	return nil, fmt.Errorf("tool %s not found", toolName)
}

// UnregisterIntegration removes a tool integration
func (atr *AdvancedToolRegistry) UnregisterIntegration(toolID string) error {
	atr.mutex.Lock()
	defer atr.mutex.Unlock()

	integration, exists := atr.integrations[toolID]
	if !exists {
		return fmt.Errorf("tool %s not found", toolID)
	}

	// Remove from main registry
	delete(atr.integrations, toolID)

	// Remove from category index
	if extTool, ok := integration.Tool.(tools.ExtendedTool); ok {
		category := string(extTool.GetCategory())
		atr.removeFromSlice(atr.categories[category], integration)
	}

	// Remove from tag index
	for tag := range integration.Metadata {
		if strings.HasPrefix(tag, "tag:") {
			tagName := strings.TrimPrefix(tag, "tag:")
			atr.removeFromSlice(atr.tags[tagName], integration)
		}
	}

	// Remove from version index
	toolName := integration.Tool.Name()
	if versions, exists := atr.versions[toolName]; exists {
		for version, versionIntegration := range versions {
			if versionIntegration.ID == integration.ID {
				delete(versions, version)
				break
			}
		}
	}

	// Remove health check
	delete(atr.healthChecks, toolID)

	atr.logger.Info("Tool integration unregistered", "tool_id", toolID)
	return nil
}

// GetHealthStatus returns the health status of a tool
func (atr *AdvancedToolRegistry) GetHealthStatus(toolID string) (*HealthCheck, error) {
	atr.mutex.RLock()
	defer atr.mutex.RUnlock()

	healthCheck, exists := atr.healthChecks[toolID]
	if !exists {
		return nil, fmt.Errorf("health check not found for tool %s", toolID)
	}

	return healthCheck, nil
}

// GetAllHealthChecks returns all health checks
func (atr *AdvancedToolRegistry) GetAllHealthChecks() map[string]*HealthCheck {
	atr.mutex.RLock()
	defer atr.mutex.RUnlock()

	// Return a copy to avoid external modifications
	result := make(map[string]*HealthCheck)
	for toolID, healthCheck := range atr.healthChecks {
		result[toolID] = healthCheck
	}

	return result
}

// GetRegistryStats returns statistics about the registry
func (atr *AdvancedToolRegistry) GetRegistryStats() *RegistryStats {
	atr.mutex.RLock()
	defer atr.mutex.RUnlock()

	stats := &RegistryStats{
		TotalIntegrations:    len(atr.integrations),
		IntegrationsByStatus: make(map[IntegrationStatus]int),
		IntegrationsByHealth: make(map[HealthStatus]int),
		CategoriesCount:      make(map[string]int),
		TagsCount:            make(map[string]int),
		LastUpdated:          time.Now(),
	}

	var totalSuccessRate float64
	var totalExecutions int64

	// Collect statistics
	for _, integration := range atr.integrations {
		stats.IntegrationsByStatus[integration.Status]++
		totalSuccessRate += integration.Metrics.SuccessRate
		totalExecutions += integration.Metrics.ExecutionCount
	}

	for _, healthCheck := range atr.healthChecks {
		stats.IntegrationsByHealth[healthCheck.Status]++
	}

	for category, integrations := range atr.categories {
		stats.CategoriesCount[category] = len(integrations)
	}

	for tag, integrations := range atr.tags {
		stats.TagsCount[tag] = len(integrations)
	}

	// Calculate averages
	if stats.TotalIntegrations > 0 {
		stats.AverageSuccessRate = totalSuccessRate / float64(stats.TotalIntegrations)
	}
	stats.TotalExecutions = totalExecutions

	return stats
}

// Helper methods

func (atr *AdvancedToolRegistry) matchesQuery(integration *ToolIntegration, query RegistryQuery) bool {
	// Check categories
	if len(query.Categories) > 0 {
		if extTool, ok := integration.Tool.(tools.ExtendedTool); ok {
			category := string(extTool.GetCategory())
			if !atr.containsString(query.Categories, category) {
				return false
			}
		} else {
			return false
		}
	}

	// Check tags
	if len(query.Tags) > 0 {
		hasMatchingTag := false
		for tag := range integration.Metadata {
			if strings.HasPrefix(tag, "tag:") {
				tagName := strings.TrimPrefix(tag, "tag:")
				if atr.containsString(query.Tags, tagName) {
					hasMatchingTag = true
					break
				}
			}
		}
		if !hasMatchingTag {
			return false
		}
	}

	// Check capabilities
	if len(query.Capabilities) > 0 {
		for _, requiredCap := range query.Capabilities {
			if !atr.containsCapability(integration.Capabilities, requiredCap) {
				return false
			}
		}
	}

	// Check status
	if len(query.Status) > 0 {
		if !atr.containsStatus(query.Status, integration.Status) {
			return false
		}
	}

	// Check name pattern
	if query.NamePattern != "" {
		if !strings.Contains(strings.ToLower(integration.Tool.Name()), strings.ToLower(query.NamePattern)) {
			return false
		}
	}

	// Check health status
	if len(query.HealthStatus) > 0 {
		if healthCheck, exists := atr.healthChecks[integration.Tool.ID()]; exists {
			if !atr.containsHealthStatus(query.HealthStatus, healthCheck.Status) {
				return false
			}
		} else {
			return false
		}
	}

	return true
}

func (atr *AdvancedToolRegistry) sortResults(results []*ToolIntegration, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "name"
	}
	if sortOrder == "" {
		sortOrder = "asc"
	}

	sort.Slice(results, func(i, j int) bool {
		var less bool

		switch sortBy {
		case "name":
			less = results[i].Tool.Name() < results[j].Tool.Name()
		case "registered_at":
			less = results[i].RegisteredAt.Before(results[j].RegisteredAt)
		case "execution_count":
			less = results[i].Metrics.ExecutionCount < results[j].Metrics.ExecutionCount
		case "success_rate":
			less = results[i].Metrics.SuccessRate < results[j].Metrics.SuccessRate
		case "average_latency":
			less = results[i].Metrics.AverageLatency < results[j].Metrics.AverageLatency
		default:
			less = results[i].Tool.Name() < results[j].Tool.Name()
		}

		if sortOrder == "desc" {
			return !less
		}
		return less
	})
}

func (atr *AdvancedToolRegistry) removeFromSlice(slice []*ToolIntegration, integration *ToolIntegration) []*ToolIntegration {
	for i, item := range slice {
		if item.ID == integration.ID {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

func (atr *AdvancedToolRegistry) containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (atr *AdvancedToolRegistry) containsCapability(slice []ToolCapability, item ToolCapability) bool {
	for _, c := range slice {
		if c == item {
			return true
		}
	}
	return false
}

func (atr *AdvancedToolRegistry) containsStatus(slice []IntegrationStatus, item IntegrationStatus) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (atr *AdvancedToolRegistry) containsHealthStatus(slice []HealthStatus, item HealthStatus) bool {
	for _, h := range slice {
		if h == item {
			return true
		}
	}
	return false
}

// healthCheckRoutine runs periodic health checks
func (atr *AdvancedToolRegistry) healthCheckRoutine() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			atr.performHealthChecks()
		}
	}
}

// performHealthChecks performs health checks on all registered tools
func (atr *AdvancedToolRegistry) performHealthChecks() {
	atr.mutex.Lock()
	defer atr.mutex.Unlock()

	now := time.Now()

	for toolID, healthCheck := range atr.healthChecks {
		if now.After(healthCheck.NextCheck) {
			atr.performSingleHealthCheck(toolID, healthCheck)
		}
	}
}

// performSingleHealthCheck performs a health check on a single tool
func (atr *AdvancedToolRegistry) performSingleHealthCheck(toolID string, healthCheck *HealthCheck) {
	healthCheck.Status = HealthStatusChecking
	healthCheck.LastCheck = time.Now()

	integration, exists := atr.integrations[toolID]
	if !exists {
		healthCheck.Status = HealthStatusUnhealthy
		healthCheck.Message = "Integration not found"
		healthCheck.NextCheck = time.Now().Add(healthCheck.Interval)
		return
	}

	// Perform basic health check
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if tool implements health check interface
	if healthyTool, ok := integration.Tool.(HealthyTool); ok {
		if healthyTool.IsHealthy(ctx) {
			healthCheck.Status = HealthStatusHealthy
			healthCheck.Message = "Tool is healthy"
			healthCheck.Failures = 0
		} else {
			healthCheck.Status = HealthStatusUnhealthy
			healthCheck.Message = "Tool health check failed"
			healthCheck.Failures++
		}
	} else {
		// Default health check - just verify tool is accessible
		healthCheck.Status = HealthStatusHealthy
		healthCheck.Message = "Tool is accessible"
		healthCheck.Failures = 0
	}

	// Update integration status based on health
	if healthCheck.Failures >= healthCheck.MaxFailures {
		integration.Status = StatusError
		healthCheck.Status = HealthStatusUnhealthy
	} else if healthCheck.Status == HealthStatusHealthy && integration.Status == StatusError {
		integration.Status = StatusActive
	}

	healthCheck.NextCheck = time.Now().Add(healthCheck.Interval)
}

// HealthyTool interface for tools that support health checks
type HealthyTool interface {
	IsHealthy(ctx context.Context) bool
}
