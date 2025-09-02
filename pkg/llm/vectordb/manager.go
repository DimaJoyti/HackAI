package vectordb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var vectorDBTracer = otel.Tracer("hackai/llm/vectordb")

// VectorDBManager manages multiple vector database providers with fallback logic
type VectorDBManager struct {
	providers       map[string]VectorProvider
	primaryProvider string
	fallbackOrder   []string
	config          VectorDBConfig
	logger          *logger.Logger
	mutex           sync.RWMutex
	healthStatus    map[string]bool
}

// VectorProvider interface for vector database operations
type VectorProvider interface {
	Store(ctx context.Context, documents []Document) error
	Search(ctx context.Context, query SearchQuery) (*SearchResult, error)
	Delete(ctx context.Context, ids []string) error
	Health(ctx context.Context) error
	GetType() string
	Close() error
}

// Document represents a document with vector embedding
type Document struct {
	ID        string                 `json:"id"`
	Content   string                 `json:"content"`
	Embedding []float64              `json:"embedding"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// SearchQuery represents a vector search query
type SearchQuery struct {
	Vector         []float64              `json:"vector"`
	Content        string                 `json:"content,omitempty"`
	Limit          int                    `json:"limit"`
	Threshold      float64                `json:"threshold"`
	Filter         map[string]interface{} `json:"filter,omitempty"`
	IncludeContent bool                   `json:"include_content"`
	IncludeVector  bool                   `json:"include_vector"`
}

// SearchResult represents search results
type SearchResult struct {
	Documents  []ScoredDocument `json:"documents"`
	TotalCount int              `json:"total_count"`
	SearchTime time.Duration    `json:"search_time"`
	Provider   string           `json:"provider"`
	QueryID    string           `json:"query_id"`
}

// ScoredDocument represents a document with similarity score
type ScoredDocument struct {
	Document
	Score float64 `json:"score"`
}

// VectorDBConfig configures the vector database manager
type VectorDBConfig struct {
	PrimaryProvider     string                    `json:"primary_provider"`
	FallbackProviders   []string                  `json:"fallback_providers"`
	HealthCheckInterval time.Duration             `json:"health_check_interval"`
	RetryAttempts       int                       `json:"retry_attempts"`
	RetryDelay          time.Duration             `json:"retry_delay"`
	Providers           map[string]ProviderConfig `json:"providers"`
}

// ProviderConfig represents configuration for a specific provider
type ProviderConfig struct {
	Type     string                 `json:"type"`
	Enabled  bool                   `json:"enabled"`
	Priority int                    `json:"priority"`
	Config   map[string]interface{} `json:"config"`
}

// NewVectorDBManager creates a new vector database manager
func NewVectorDBManager(config VectorDBConfig, logger *logger.Logger) *VectorDBManager {
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}

	manager := &VectorDBManager{
		providers:       make(map[string]VectorProvider),
		primaryProvider: config.PrimaryProvider,
		fallbackOrder:   config.FallbackProviders,
		config:          config,
		logger:          logger,
		healthStatus:    make(map[string]bool),
	}

	return manager
}

// RegisterProvider registers a vector database provider
func (vm *VectorDBManager) RegisterProvider(name string, provider VectorProvider) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	vm.providers[name] = provider
	vm.healthStatus[name] = true // Assume healthy initially

	vm.logger.Info("Vector database provider registered",
		"provider", name,
		"type", provider.GetType())

	return nil
}

// Store stores documents using the primary provider with fallback
func (vm *VectorDBManager) Store(ctx context.Context, documents []Document) error {
	ctx, span := vectorDBTracer.Start(ctx, "vector_db_manager.store",
		trace.WithAttributes(
			attribute.Int("documents_count", len(documents)),
		),
	)
	defer span.End()

	// Try primary provider first
	if vm.primaryProvider != "" {
		if provider, exists := vm.providers[vm.primaryProvider]; exists && vm.isHealthy(vm.primaryProvider) {
			if err := vm.storeWithRetry(ctx, provider, documents, vm.primaryProvider); err == nil {
				span.SetAttributes(attribute.String("provider_used", vm.primaryProvider))
				return nil
			} else {
				vm.logger.Warn("Primary provider failed, trying fallbacks",
					"provider", vm.primaryProvider,
					"error", err)
				vm.markUnhealthy(vm.primaryProvider)
			}
		}
	}

	// Try fallback providers
	for _, providerName := range vm.fallbackOrder {
		if provider, exists := vm.providers[providerName]; exists && vm.isHealthy(providerName) {
			if err := vm.storeWithRetry(ctx, provider, documents, providerName); err == nil {
				span.SetAttributes(attribute.String("provider_used", providerName))
				vm.logger.Info("Fallback provider succeeded", "provider", providerName)
				return nil
			} else {
				vm.logger.Warn("Fallback provider failed",
					"provider", providerName,
					"error", err)
				vm.markUnhealthy(providerName)
			}
		}
	}

	span.RecordError(fmt.Errorf("all providers failed"))
	return fmt.Errorf("all vector database providers failed")
}

// Search performs vector similarity search with fallback
func (vm *VectorDBManager) Search(ctx context.Context, query SearchQuery) (*SearchResult, error) {
	ctx, span := vectorDBTracer.Start(ctx, "vector_db_manager.search",
		trace.WithAttributes(
			attribute.Int("limit", query.Limit),
			attribute.Float64("threshold", query.Threshold),
		),
	)
	defer span.End()

	startTime := time.Now()

	// Try primary provider first
	if vm.primaryProvider != "" {
		if provider, exists := vm.providers[vm.primaryProvider]; exists && vm.isHealthy(vm.primaryProvider) {
			if result, err := vm.searchWithRetry(ctx, provider, query, vm.primaryProvider); err == nil {
				result.SearchTime = time.Since(startTime)
				result.Provider = vm.primaryProvider
				span.SetAttributes(
					attribute.String("provider_used", vm.primaryProvider),
					attribute.Int("results_count", len(result.Documents)),
				)
				return result, nil
			} else {
				vm.logger.Warn("Primary provider search failed, trying fallbacks",
					"provider", vm.primaryProvider,
					"error", err)
				vm.markUnhealthy(vm.primaryProvider)
			}
		}
	}

	// Try fallback providers
	for _, providerName := range vm.fallbackOrder {
		if provider, exists := vm.providers[providerName]; exists && vm.isHealthy(providerName) {
			if result, err := vm.searchWithRetry(ctx, provider, query, providerName); err == nil {
				result.SearchTime = time.Since(startTime)
				result.Provider = providerName
				span.SetAttributes(
					attribute.String("provider_used", providerName),
					attribute.Int("results_count", len(result.Documents)),
				)
				vm.logger.Info("Fallback provider search succeeded", "provider", providerName)
				return result, nil
			} else {
				vm.logger.Warn("Fallback provider search failed",
					"provider", providerName,
					"error", err)
				vm.markUnhealthy(providerName)
			}
		}
	}

	span.RecordError(fmt.Errorf("all providers failed"))
	return nil, fmt.Errorf("all vector database providers failed")
}

// storeWithRetry stores documents with retry logic
func (vm *VectorDBManager) storeWithRetry(ctx context.Context, provider VectorProvider, documents []Document, providerName string) error {
	var lastErr error
	for attempt := 0; attempt < vm.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(vm.config.RetryDelay * time.Duration(attempt)):
			}
		}

		if err := provider.Store(ctx, documents); err != nil {
			lastErr = err
			vm.logger.Warn("Store attempt failed",
				"provider", providerName,
				"attempt", attempt+1,
				"error", err)
			continue
		}

		return nil
	}

	return fmt.Errorf("store failed after %d attempts: %w", vm.config.RetryAttempts, lastErr)
}

// searchWithRetry performs search with retry logic
func (vm *VectorDBManager) searchWithRetry(ctx context.Context, provider VectorProvider, query SearchQuery, providerName string) (*SearchResult, error) {
	var lastErr error
	for attempt := 0; attempt < vm.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(vm.config.RetryDelay * time.Duration(attempt)):
			}
		}

		if result, err := provider.Search(ctx, query); err != nil {
			lastErr = err
			vm.logger.Warn("Search attempt failed",
				"provider", providerName,
				"attempt", attempt+1,
				"error", err)
			continue
		} else {
			return result, nil
		}
	}

	return nil, fmt.Errorf("search failed after %d attempts: %w", vm.config.RetryAttempts, lastErr)
}

// isHealthy checks if a provider is healthy
func (vm *VectorDBManager) isHealthy(providerName string) bool {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()
	return vm.healthStatus[providerName]
}

// markUnhealthy marks a provider as unhealthy
func (vm *VectorDBManager) markUnhealthy(providerName string) {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()
	vm.healthStatus[providerName] = false
}

// StartHealthChecks starts periodic health checks for all providers
func (vm *VectorDBManager) StartHealthChecks(ctx context.Context) {
	ticker := time.NewTicker(vm.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			vm.performHealthChecks(ctx)
		}
	}
}

// performHealthChecks checks health of all providers
func (vm *VectorDBManager) performHealthChecks(ctx context.Context) {
	vm.mutex.RLock()
	providers := make(map[string]VectorProvider)
	for name, provider := range vm.providers {
		providers[name] = provider
	}
	vm.mutex.RUnlock()

	for name, provider := range providers {
		go func(providerName string, p VectorProvider) {
			healthCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			if err := p.Health(healthCtx); err != nil {
				vm.markUnhealthy(providerName)
				vm.logger.Warn("Provider health check failed",
					"provider", providerName,
					"error", err)
			} else {
				vm.mutex.Lock()
				vm.healthStatus[providerName] = true
				vm.mutex.Unlock()
			}
		}(name, provider)
	}
}

// GetHealthStatus returns the health status of all providers
func (vm *VectorDBManager) GetHealthStatus() map[string]bool {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	status := make(map[string]bool)
	for name, health := range vm.healthStatus {
		status[name] = health
	}
	return status
}

// Close closes all providers
func (vm *VectorDBManager) Close() error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	var errors []error
	for name, provider := range vm.providers {
		if err := provider.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close provider %s: %w", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors closing providers: %v", errors)
	}

	return nil
}
