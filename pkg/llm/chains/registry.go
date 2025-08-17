package chains

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var registryTracer = otel.Tracer("hackai/llm/chains/registry")

// ChainRegistry provides storage and retrieval of chains with metadata
type ChainRegistry interface {
	// Basic operations
	Register(ctx context.Context, chain llm.Chain, metadata ChainMetadata) error
	Unregister(ctx context.Context, chainID string) error
	Get(ctx context.Context, chainID string) (llm.Chain, error)
	Exists(ctx context.Context, chainID string) bool

	// Metadata operations
	GetMetadata(ctx context.Context, chainID string) (ChainMetadata, error)
	UpdateMetadata(ctx context.Context, chainID string, metadata ChainMetadata) error

	// Querying and filtering
	List(ctx context.Context, filter ChainFilter) ([]ChainInfo, error)
	Search(ctx context.Context, query string) ([]ChainInfo, error)
	GetByTag(ctx context.Context, tag string) ([]ChainInfo, error)
	GetByCategory(ctx context.Context, category string) ([]ChainInfo, error)
	GetByAuthor(ctx context.Context, author string) ([]ChainInfo, error)

	// Dependencies
	GetDependencies(ctx context.Context, chainID string) ([]string, error)
	GetDependents(ctx context.Context, chainID string) ([]string, error)
	UpdateDependencies(ctx context.Context, chainID string, dependencies []string) error

	// Versioning
	GetVersions(ctx context.Context, chainID string) ([]string, error)
	GetVersion(ctx context.Context, chainID string, version string) (llm.Chain, error)
	SetVersion(ctx context.Context, chainID string, version string, chain llm.Chain) error

	// Statistics
	GetStats(ctx context.Context) (RegistryStats, error)
	GetChainStats(ctx context.Context, chainID string) (ChainStats, error)
}

// DefaultChainRegistry implements the ChainRegistry interface
type DefaultChainRegistry struct {
	chains       map[string]llm.Chain
	metadata     map[string]ChainMetadata
	versions     map[string]map[string]llm.Chain // chainID -> version -> chain
	dependencies map[string][]string             // chainID -> dependencies
	dependents   map[string][]string             // chainID -> dependents
	tags         map[string][]string             // tag -> chainIDs
	categories   map[string][]string             // category -> chainIDs
	authors      map[string][]string             // author -> chainIDs
	logger       *logger.Logger
	mutex        sync.RWMutex
}

// ChainInfo provides comprehensive information about a registered chain
type ChainInfo struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Type           string                 `json:"type"`
	Status         string                 `json:"status"`
	Version        string                 `json:"version"`
	Author         string                 `json:"author"`
	Tags           []string               `json:"tags"`
	Category       string                 `json:"category"`
	Dependencies   []string               `json:"dependencies"`
	Dependents     []string               `json:"dependents"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	LastExecuted   *time.Time             `json:"last_executed,omitempty"`
	ExecutionCount int64                  `json:"execution_count"`
	Parameters     map[string]interface{} `json:"parameters"`
}

// RegistryStats provides statistics about the registry
type RegistryStats struct {
	TotalChains      int            `json:"total_chains"`
	ChainsByType     map[string]int `json:"chains_by_type"`
	ChainsByStatus   map[string]int `json:"chains_by_status"`
	ChainsByCategory map[string]int `json:"chains_by_category"`
	ChainsByAuthor   map[string]int `json:"chains_by_author"`
	TopTags          []TagStats     `json:"top_tags"`
	RecentlyCreated  []ChainInfo    `json:"recently_created"`
	MostExecuted     []ChainInfo    `json:"most_executed"`
}

// ChainStats provides statistics about a specific chain
type ChainStats struct {
	ChainID         string     `json:"chain_id"`
	TotalVersions   int        `json:"total_versions"`
	DependencyCount int        `json:"dependency_count"`
	DependentCount  int        `json:"dependent_count"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUpdated     time.Time  `json:"last_updated"`
	LastExecuted    *time.Time `json:"last_executed,omitempty"`
	ExecutionCount  int64      `json:"execution_count"`
}

// TagStats provides statistics about tag usage
type TagStats struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

// NewDefaultChainRegistry creates a new default chain registry
func NewDefaultChainRegistry(logger *logger.Logger) *DefaultChainRegistry {
	return &DefaultChainRegistry{
		chains:       make(map[string]llm.Chain),
		metadata:     make(map[string]ChainMetadata),
		versions:     make(map[string]map[string]llm.Chain),
		dependencies: make(map[string][]string),
		dependents:   make(map[string][]string),
		tags:         make(map[string][]string),
		categories:   make(map[string][]string),
		authors:      make(map[string][]string),
		logger:       logger,
	}
}

// Register registers a new chain with metadata
func (r *DefaultChainRegistry) Register(ctx context.Context, chain llm.Chain, metadata ChainMetadata) error {
	ctx, span := registryTracer.Start(ctx, "registry.register",
		trace.WithAttributes(
			attribute.String("chain.id", chain.ID()),
			attribute.String("chain.name", chain.Name()),
		),
	)
	defer span.End()

	r.mutex.Lock()
	defer r.mutex.Unlock()

	chainID := chain.ID()

	// Check if chain already exists
	if _, exists := r.chains[chainID]; exists {
		err := fmt.Errorf("chain %s already exists", chainID)
		span.RecordError(err)
		return err
	}

	// Set timestamps
	now := time.Now()
	if metadata.CreatedAt.IsZero() {
		metadata.CreatedAt = now
	}
	metadata.UpdatedAt = now

	// Store chain and metadata
	r.chains[chainID] = chain
	r.metadata[chainID] = metadata

	// Initialize versions
	if r.versions[chainID] == nil {
		r.versions[chainID] = make(map[string]llm.Chain)
	}
	r.versions[chainID][metadata.Version] = chain

	// Update indexes
	r.updateIndexes(chainID, metadata)

	// Update dependencies
	if len(metadata.Dependencies) > 0 {
		r.dependencies[chainID] = metadata.Dependencies
		r.updateDependents(chainID, metadata.Dependencies)
	}

	span.SetAttributes(
		attribute.String("chain.version", metadata.Version),
		attribute.StringSlice("chain.tags", metadata.Tags),
		attribute.String("chain.category", metadata.Category),
		attribute.Bool("success", true),
	)

	r.logger.Info("Chain registered in registry",
		"chain_id", chainID,
		"version", metadata.Version,
		"author", metadata.Author,
	)

	return nil
}

// Unregister removes a chain from the registry
func (r *DefaultChainRegistry) Unregister(ctx context.Context, chainID string) error {
	ctx, span := registryTracer.Start(ctx, "registry.unregister",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if chain exists
	metadata, exists := r.metadata[chainID]
	if !exists {
		err := fmt.Errorf("chain %s not found", chainID)
		span.RecordError(err)
		return err
	}

	// Remove from main storage
	delete(r.chains, chainID)
	delete(r.metadata, chainID)
	delete(r.versions, chainID)

	// Remove from indexes
	r.removeFromIndexes(chainID, metadata)

	// Clean up dependencies
	r.cleanupDependencies(chainID)

	span.SetAttributes(attribute.Bool("success", true))
	r.logger.Info("Chain unregistered from registry", "chain_id", chainID)

	return nil
}

// Get retrieves a chain by ID
func (r *DefaultChainRegistry) Get(ctx context.Context, chainID string) (llm.Chain, error) {
	ctx, span := registryTracer.Start(ctx, "registry.get",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	chain, exists := r.chains[chainID]
	if !exists {
		err := fmt.Errorf("chain %s not found", chainID)
		span.RecordError(err)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("chain.name", chain.Name()),
		attribute.Bool("success", true),
	)

	return chain, nil
}

// Exists checks if a chain exists in the registry
func (r *DefaultChainRegistry) Exists(ctx context.Context, chainID string) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, exists := r.chains[chainID]
	return exists
}

// GetMetadata retrieves metadata for a chain
func (r *DefaultChainRegistry) GetMetadata(ctx context.Context, chainID string) (ChainMetadata, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	metadata, exists := r.metadata[chainID]
	if !exists {
		return ChainMetadata{}, fmt.Errorf("chain %s not found", chainID)
	}

	return metadata, nil
}

// List returns chains matching the filter
func (r *DefaultChainRegistry) List(ctx context.Context, filter ChainFilter) ([]ChainInfo, error) {
	ctx, span := registryTracer.Start(ctx, "registry.list")
	defer span.End()

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var results []ChainInfo

	for chainID, chain := range r.chains {
		metadata := r.metadata[chainID]

		// Apply filters
		if !r.matchesFilter(chainID, chain, metadata, filter) {
			continue
		}

		info := r.buildChainInfo(chainID, chain, metadata)
		results = append(results, info)
	}

	// Sort results
	sort.Slice(results, func(i, j int) bool {
		return results[i].UpdatedAt.After(results[j].UpdatedAt)
	})

	// Apply pagination
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	span.SetAttributes(
		attribute.Int("results.count", len(results)),
		attribute.Bool("success", true),
	)

	return results, nil
}

// Search searches for chains by query
func (r *DefaultChainRegistry) Search(ctx context.Context, query string) ([]ChainInfo, error) {
	ctx, span := registryTracer.Start(ctx, "registry.search",
		trace.WithAttributes(attribute.String("search.query", query)),
	)
	defer span.End()

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	query = strings.ToLower(query)
	var results []ChainInfo

	for chainID, chain := range r.chains {
		metadata := r.metadata[chainID]

		// Search in various fields
		if r.matchesQuery(chainID, chain, metadata, query) {
			info := r.buildChainInfo(chainID, chain, metadata)
			results = append(results, info)
		}
	}

	span.SetAttributes(
		attribute.Int("results.count", len(results)),
		attribute.Bool("success", true),
	)

	return results, nil
}

// GetDependencies returns the dependencies of a chain
func (r *DefaultChainRegistry) GetDependencies(ctx context.Context, chainID string) ([]string, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	deps, exists := r.dependencies[chainID]
	if !exists {
		return []string{}, nil
	}

	// Return a copy to prevent modification
	result := make([]string, len(deps))
	copy(result, deps)
	return result, nil
}

// GetDependents returns the chains that depend on this chain
func (r *DefaultChainRegistry) GetDependents(ctx context.Context, chainID string) ([]string, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	deps, exists := r.dependents[chainID]
	if !exists {
		return []string{}, nil
	}

	// Return a copy to prevent modification
	result := make([]string, len(deps))
	copy(result, deps)
	return result, nil
}

// Helper methods

// updateIndexes updates the various indexes when a chain is registered
func (r *DefaultChainRegistry) updateIndexes(chainID string, metadata ChainMetadata) {
	// Update tags index
	for _, tag := range metadata.Tags {
		r.tags[tag] = append(r.tags[tag], chainID)
	}

	// Update category index
	if metadata.Category != "" {
		r.categories[metadata.Category] = append(r.categories[metadata.Category], chainID)
	}

	// Update author index
	if metadata.Author != "" {
		r.authors[metadata.Author] = append(r.authors[metadata.Author], chainID)
	}
}

// removeFromIndexes removes a chain from all indexes
func (r *DefaultChainRegistry) removeFromIndexes(chainID string, metadata ChainMetadata) {
	// Remove from tags index
	for _, tag := range metadata.Tags {
		r.removeFromSlice(r.tags[tag], chainID)
		if len(r.tags[tag]) == 0 {
			delete(r.tags, tag)
		}
	}

	// Remove from category index
	if metadata.Category != "" {
		r.removeFromSlice(r.categories[metadata.Category], chainID)
		if len(r.categories[metadata.Category]) == 0 {
			delete(r.categories, metadata.Category)
		}
	}

	// Remove from author index
	if metadata.Author != "" {
		r.removeFromSlice(r.authors[metadata.Author], chainID)
		if len(r.authors[metadata.Author]) == 0 {
			delete(r.authors, metadata.Author)
		}
	}
}

// removeFromSlice removes an element from a slice
func (r *DefaultChainRegistry) removeFromSlice(slice []string, element string) []string {
	for i, v := range slice {
		if v == element {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// updateDependents updates the dependents index
func (r *DefaultChainRegistry) updateDependents(chainID string, dependencies []string) {
	for _, dep := range dependencies {
		r.dependents[dep] = append(r.dependents[dep], chainID)
	}
}

// cleanupDependencies cleans up dependency relationships
func (r *DefaultChainRegistry) cleanupDependencies(chainID string) {
	// Remove from dependencies
	if deps, exists := r.dependencies[chainID]; exists {
		for _, dep := range deps {
			r.removeFromSlice(r.dependents[dep], chainID)
		}
		delete(r.dependencies, chainID)
	}

	// Remove from dependents
	delete(r.dependents, chainID)
}

// matchesFilter checks if a chain matches the given filter
func (r *DefaultChainRegistry) matchesFilter(chainID string, chain llm.Chain, metadata ChainMetadata, filter ChainFilter) bool {
	// Status filter
	if len(filter.Status) > 0 {
		// For now, assume all chains are "active"
		found := false
		for _, status := range filter.Status {
			if status == "active" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Tags filter
	if len(filter.Tags) > 0 {
		hasTag := false
		for _, filterTag := range filter.Tags {
			for _, chainTag := range metadata.Tags {
				if chainTag == filterTag {
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

	// Category filter
	if filter.Category != "" && metadata.Category != filter.Category {
		return false
	}

	// Author filter
	if filter.Author != "" && metadata.Author != filter.Author {
		return false
	}

	// Date filters
	if filter.CreatedAfter != nil && metadata.CreatedAt.Before(*filter.CreatedAfter) {
		return false
	}
	if filter.CreatedBefore != nil && metadata.CreatedAt.After(*filter.CreatedBefore) {
		return false
	}

	return true
}

// matchesQuery checks if a chain matches the search query
func (r *DefaultChainRegistry) matchesQuery(chainID string, chain llm.Chain, metadata ChainMetadata, query string) bool {
	// Search in ID, name, description
	if strings.Contains(strings.ToLower(chainID), query) ||
		strings.Contains(strings.ToLower(chain.Name()), query) ||
		strings.Contains(strings.ToLower(chain.Description()), query) ||
		strings.Contains(strings.ToLower(metadata.Description), query) {
		return true
	}

	// Search in tags
	for _, tag := range metadata.Tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}

	// Search in category and author
	if strings.Contains(strings.ToLower(metadata.Category), query) ||
		strings.Contains(strings.ToLower(metadata.Author), query) {
		return true
	}

	return false
}

// buildChainInfo builds a ChainInfo from chain and metadata
func (r *DefaultChainRegistry) buildChainInfo(chainID string, chain llm.Chain, metadata ChainMetadata) ChainInfo {
	return ChainInfo{
		ID:           chainID,
		Name:         chain.Name(),
		Description:  chain.Description(),
		Type:         "custom", // TODO: determine actual type
		Status:       "active",
		Version:      metadata.Version,
		Author:       metadata.Author,
		Tags:         metadata.Tags,
		Category:     metadata.Category,
		Dependencies: r.dependencies[chainID],
		Dependents:   r.dependents[chainID],
		CreatedAt:    metadata.CreatedAt,
		UpdatedAt:    metadata.UpdatedAt,
		Parameters:   metadata.Parameters,
	}
}

// GetByTag returns chains with a specific tag
func (r *DefaultChainRegistry) GetByTag(ctx context.Context, tag string) ([]ChainInfo, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	chainIDs, exists := r.tags[tag]
	if !exists {
		return []ChainInfo{}, nil
	}

	var results []ChainInfo
	for _, chainID := range chainIDs {
		if chain, exists := r.chains[chainID]; exists {
			metadata := r.metadata[chainID]
			info := r.buildChainInfo(chainID, chain, metadata)
			results = append(results, info)
		}
	}

	return results, nil
}

// GetByCategory returns chains in a specific category
func (r *DefaultChainRegistry) GetByCategory(ctx context.Context, category string) ([]ChainInfo, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	chainIDs, exists := r.categories[category]
	if !exists {
		return []ChainInfo{}, nil
	}

	var results []ChainInfo
	for _, chainID := range chainIDs {
		if chain, exists := r.chains[chainID]; exists {
			metadata := r.metadata[chainID]
			info := r.buildChainInfo(chainID, chain, metadata)
			results = append(results, info)
		}
	}

	return results, nil
}

// GetByAuthor returns chains by a specific author
func (r *DefaultChainRegistry) GetByAuthor(ctx context.Context, author string) ([]ChainInfo, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	chainIDs, exists := r.authors[author]
	if !exists {
		return []ChainInfo{}, nil
	}

	var results []ChainInfo
	for _, chainID := range chainIDs {
		if chain, exists := r.chains[chainID]; exists {
			metadata := r.metadata[chainID]
			info := r.buildChainInfo(chainID, chain, metadata)
			results = append(results, info)
		}
	}

	return results, nil
}

// UpdateDependencies updates dependencies for a chain
func (r *DefaultChainRegistry) UpdateDependencies(ctx context.Context, chainID string, dependencies []string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Clean up old dependencies
	if oldDeps, exists := r.dependencies[chainID]; exists {
		for _, dep := range oldDeps {
			r.removeFromSlice(r.dependents[dep], chainID)
		}
	}

	// Set new dependencies
	r.dependencies[chainID] = dependencies
	r.updateDependents(chainID, dependencies)

	return nil
}

// GetVersions returns all versions of a chain
func (r *DefaultChainRegistry) GetVersions(ctx context.Context, chainID string) ([]string, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	versions, exists := r.versions[chainID]
	if !exists {
		return []string{}, nil
	}

	var versionList []string
	for version := range versions {
		versionList = append(versionList, version)
	}

	return versionList, nil
}

// GetVersion returns a specific version of a chain
func (r *DefaultChainRegistry) GetVersion(ctx context.Context, chainID string, version string) (llm.Chain, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	versions, exists := r.versions[chainID]
	if !exists {
		return nil, fmt.Errorf("chain %s not found", chainID)
	}

	chain, exists := versions[version]
	if !exists {
		return nil, fmt.Errorf("version %s not found for chain %s", version, chainID)
	}

	return chain, nil
}

// SetVersion sets a specific version of a chain
func (r *DefaultChainRegistry) SetVersion(ctx context.Context, chainID string, version string, chain llm.Chain) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.versions[chainID] == nil {
		r.versions[chainID] = make(map[string]llm.Chain)
	}

	r.versions[chainID][version] = chain
	return nil
}

// GetStats returns registry statistics
func (r *DefaultChainRegistry) GetStats(ctx context.Context) (RegistryStats, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	stats := RegistryStats{
		TotalChains:      len(r.chains),
		ChainsByType:     make(map[string]int),
		ChainsByStatus:   make(map[string]int),
		ChainsByCategory: make(map[string]int),
		ChainsByAuthor:   make(map[string]int),
		TopTags:          make([]TagStats, 0),
		RecentlyCreated:  make([]ChainInfo, 0),
		MostExecuted:     make([]ChainInfo, 0),
	}

	// Count by category
	for category, chains := range r.categories {
		stats.ChainsByCategory[category] = len(chains)
	}

	// Count by author
	for author, chains := range r.authors {
		stats.ChainsByAuthor[author] = len(chains)
	}

	// Count by tags
	for tag, chains := range r.tags {
		stats.TopTags = append(stats.TopTags, TagStats{
			Tag:   tag,
			Count: len(chains),
		})
	}

	// All chains are considered "active" for now
	stats.ChainsByStatus["active"] = len(r.chains)

	return stats, nil
}

// GetChainStats returns statistics for a specific chain
func (r *DefaultChainRegistry) GetChainStats(ctx context.Context, chainID string) (ChainStats, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	metadata, exists := r.metadata[chainID]
	if !exists {
		return ChainStats{}, fmt.Errorf("chain %s not found", chainID)
	}

	versions := 0
	if chainVersions, exists := r.versions[chainID]; exists {
		versions = len(chainVersions)
	}

	dependencies := 0
	if deps, exists := r.dependencies[chainID]; exists {
		dependencies = len(deps)
	}

	dependents := 0
	if deps, exists := r.dependents[chainID]; exists {
		dependents = len(deps)
	}

	return ChainStats{
		ChainID:         chainID,
		TotalVersions:   versions,
		DependencyCount: dependencies,
		DependentCount:  dependents,
		CreatedAt:       metadata.CreatedAt,
		LastUpdated:     metadata.UpdatedAt,
		ExecutionCount:  0, // Would be populated from monitoring data
	}, nil
}

// UpdateMetadata updates metadata for a chain
func (r *DefaultChainRegistry) UpdateMetadata(ctx context.Context, chainID string, metadata ChainMetadata) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if chain exists
	if _, exists := r.chains[chainID]; !exists {
		return fmt.Errorf("chain %s not found", chainID)
	}

	// Update metadata
	metadata.UpdatedAt = time.Now()
	r.metadata[chainID] = metadata

	// Update indexes
	r.updateIndexes(chainID, metadata)

	return nil
}
