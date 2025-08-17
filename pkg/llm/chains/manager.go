package chains

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var managerTracer = otel.Tracer("hackai/llm/chains/manager")

// ChainManager provides comprehensive chain management capabilities
type ChainManager interface {
	// Registration and lifecycle
	RegisterChain(ctx context.Context, chain llm.Chain, metadata ChainMetadata) error
	UnregisterChain(ctx context.Context, chainID string) error
	UpdateChain(ctx context.Context, chainID string, chain llm.Chain) error
	EnableChain(ctx context.Context, chainID string) error
	DisableChain(ctx context.Context, chainID string) error

	// Retrieval and querying
	GetChain(ctx context.Context, chainID string) (llm.Chain, error)
	ListChains(ctx context.Context, filter ChainFilter) ([]ChainInfo, error)
	SearchChains(ctx context.Context, query string) ([]ChainInfo, error)

	// Execution and monitoring
	ExecuteChain(ctx context.Context, chainID string, input llm.ChainInput, options ExecutionOptions) (llm.ChainOutput, error)
	GetChainMetrics(ctx context.Context, chainID string) (ChainMetrics, error)
	GetChainHealth(ctx context.Context, chainID string) (ChainHealth, error)

	// Templates and configuration
	CreateTemplate(ctx context.Context, template ChainTemplate) error
	InstantiateFromTemplate(ctx context.Context, templateID string, config TemplateConfig) (llm.Chain, error)
	UpdateChainConfig(ctx context.Context, chainID string, config ChainConfiguration) error

	// Dependencies and validation
	ValidateChain(ctx context.Context, chain llm.Chain) (ValidationResult, error)
	ResolveDependencies(ctx context.Context, chainID string) ([]string, error)
	CheckDependencies(ctx context.Context, chainID string) error

	// Security and access control
	SetChainPermissions(ctx context.Context, chainID string, permissions ChainPermissions) error
	CheckAccess(ctx context.Context, chainID string, userID string, action string) error
	AuditChainAccess(ctx context.Context, chainID string, userID string, action string) error
}

// DefaultChainManager implements the ChainManager interface
type DefaultChainManager struct {
	registry  ChainRegistry
	validator ChainValidator
	monitor   ChainMonitor
	security  ChainSecurity
	templates TemplateManager
	logger    *logger.Logger
	mutex     sync.RWMutex
}

// ChainMetadata contains metadata about a chain
type ChainMetadata struct {
	Version      string                 `json:"version"`
	Author       string                 `json:"author"`
	Tags         []string               `json:"tags"`
	Category     string                 `json:"category"`
	Description  string                 `json:"description"`
	Dependencies []string               `json:"dependencies"`
	Parameters   map[string]interface{} `json:"parameters"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// ChainFilter provides filtering options for chain queries
type ChainFilter struct {
	Status        []string   `json:"status"`
	Tags          []string   `json:"tags"`
	Category      string     `json:"category"`
	Author        string     `json:"author"`
	CreatedAfter  *time.Time `json:"created_after"`
	CreatedBefore *time.Time `json:"created_before"`
	Limit         int        `json:"limit"`
	Offset        int        `json:"offset"`
}

// ExecutionOptions provides options for chain execution
type ExecutionOptions struct {
	Timeout    time.Duration          `json:"timeout"`
	MaxRetries int                    `json:"max_retries"`
	Priority   int                    `json:"priority"`
	UserID     string                 `json:"user_id"`
	TraceID    string                 `json:"trace_id"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// ChainMetrics contains performance metrics for a chain
type ChainMetrics struct {
	ChainID              string        `json:"chain_id"`
	TotalExecutions      int64         `json:"total_executions"`
	SuccessfulExecutions int64         `json:"successful_executions"`
	FailedExecutions     int64         `json:"failed_executions"`
	AverageLatency       time.Duration `json:"average_latency"`
	P95Latency           time.Duration `json:"p95_latency"`
	P99Latency           time.Duration `json:"p99_latency"`
	LastExecuted         time.Time     `json:"last_executed"`
	ErrorRate            float64       `json:"error_rate"`
	ThroughputPerMin     float64       `json:"throughput_per_min"`
}

// ChainHealth represents the health status of a chain
type ChainHealth struct {
	ChainID   string                 `json:"chain_id"`
	Status    string                 `json:"status"` // healthy, degraded, unhealthy
	LastCheck time.Time              `json:"last_check"`
	Issues    []HealthIssue          `json:"issues"`
	Metrics   map[string]interface{} `json:"metrics"`
}

// HealthIssue represents a health issue with a chain
type HealthIssue struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	Suggestions []string  `json:"suggestions"`
}

// ChainPermissions defines access permissions for a chain
type ChainPermissions struct {
	ChainID       string              `json:"chain_id"`
	Owners        []string            `json:"owners"`
	Readers       []string            `json:"readers"`
	Executors     []string            `json:"executors"`
	Admins        []string            `json:"admins"`
	Groups        map[string][]string `json:"groups"`
	PublicRead    bool                `json:"public_read"`
	PublicExecute bool                `json:"public_execute"`
}

// ValidationResult contains the result of chain validation
type ValidationResult struct {
	Valid       bool                `json:"valid"`
	Errors      []ValidationError   `json:"errors"`
	Warnings    []ValidationWarning `json:"warnings"`
	Score       float64             `json:"score"`
	Suggestions []string            `json:"suggestions"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Field     string    `json:"field"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Field     string    `json:"field"`
	Timestamp time.Time `json:"timestamp"`
}

// NewDefaultChainManager creates a new default chain manager
func NewDefaultChainManager(
	registry ChainRegistry,
	validator ChainValidator,
	monitor ChainMonitor,
	security ChainSecurity,
	templates TemplateManager,
	logger *logger.Logger,
) *DefaultChainManager {
	return &DefaultChainManager{
		registry:  registry,
		validator: validator,
		monitor:   monitor,
		security:  security,
		templates: templates,
		logger:    logger,
	}
}

// RegisterChain registers a new chain with metadata
func (cm *DefaultChainManager) RegisterChain(ctx context.Context, chain llm.Chain, metadata ChainMetadata) error {
	ctx, span := managerTracer.Start(ctx, "chain_manager.register_chain",
		trace.WithAttributes(
			attribute.String("chain.id", chain.ID()),
			attribute.String("chain.name", chain.Name()),
		),
	)
	defer span.End()

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// Validate the chain
	validationResult, err := cm.validator.ValidateChain(ctx, chain)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("chain validation failed: %w", err)
	}

	if !validationResult.Valid {
		span.SetAttributes(attribute.Bool("validation.valid", false))
		return fmt.Errorf("chain validation failed: %v", validationResult.Errors)
	}

	// Check dependencies
	if err := cm.checkDependencies(ctx, metadata.Dependencies); err != nil {
		span.RecordError(err)
		return fmt.Errorf("dependency check failed: %w", err)
	}

	// Register in registry
	if err := cm.registry.Register(ctx, chain, metadata); err != nil {
		span.RecordError(err)
		return fmt.Errorf("registry registration failed: %w", err)
	}

	// Initialize monitoring
	if err := cm.monitor.InitializeChain(ctx, chain.ID()); err != nil {
		cm.logger.Warn("Failed to initialize monitoring for chain", "chain_id", chain.ID(), "error", err)
	}

	// Set default permissions
	defaultPermissions := ChainPermissions{
		ChainID:       chain.ID(),
		Owners:        []string{metadata.Author},
		PublicRead:    true,
		PublicExecute: false,
	}
	if err := cm.security.SetPermissions(ctx, chain.ID(), defaultPermissions); err != nil {
		cm.logger.Warn("Failed to set default permissions for chain", "chain_id", chain.ID(), "error", err)
	}

	span.SetAttributes(
		attribute.Bool("success", true),
		attribute.String("chain.version", metadata.Version),
		attribute.StringSlice("chain.tags", metadata.Tags),
	)

	cm.logger.Info("Chain registered successfully",
		"chain_id", chain.ID(),
		"chain_name", chain.Name(),
		"version", metadata.Version,
		"author", metadata.Author,
	)

	return nil
}

// UnregisterChain removes a chain from the manager
func (cm *DefaultChainManager) UnregisterChain(ctx context.Context, chainID string) error {
	ctx, span := managerTracer.Start(ctx, "chain_manager.unregister_chain",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// Check if chain exists
	if !cm.registry.Exists(ctx, chainID) {
		err := fmt.Errorf("chain %s not found", chainID)
		span.RecordError(err)
		return err
	}

	// Check dependencies - ensure no other chains depend on this one
	dependents, err := cm.registry.GetDependents(ctx, chainID)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to check dependents: %w", err)
	}

	if len(dependents) > 0 {
		err := fmt.Errorf("cannot unregister chain %s: %d chains depend on it", chainID, len(dependents))
		span.RecordError(err)
		return err
	}

	// Remove from registry
	if err := cm.registry.Unregister(ctx, chainID); err != nil {
		span.RecordError(err)
		return fmt.Errorf("registry unregistration failed: %w", err)
	}

	// Clean up monitoring
	if err := cm.monitor.CleanupChain(ctx, chainID); err != nil {
		cm.logger.Warn("Failed to cleanup monitoring for chain", "chain_id", chainID, "error", err)
	}

	// Remove permissions
	if err := cm.security.RemovePermissions(ctx, chainID); err != nil {
		cm.logger.Warn("Failed to remove permissions for chain", "chain_id", chainID, "error", err)
	}

	span.SetAttributes(attribute.Bool("success", true))
	cm.logger.Info("Chain unregistered successfully", "chain_id", chainID)

	return nil
}

// GetChain retrieves a chain by ID
func (cm *DefaultChainManager) GetChain(ctx context.Context, chainID string) (llm.Chain, error) {
	ctx, span := managerTracer.Start(ctx, "chain_manager.get_chain",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	chain, err := cm.registry.Get(ctx, chainID)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get chain: %w", err)
	}

	span.SetAttributes(
		attribute.String("chain.name", chain.Name()),
		attribute.Bool("success", true),
	)

	return chain, nil
}

// UpdateChain updates an existing chain
func (cm *DefaultChainManager) UpdateChain(ctx context.Context, chainID string, chain llm.Chain) error {
	ctx, span := managerTracer.Start(ctx, "chain_manager.update_chain",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// Check if chain exists
	if !cm.registry.Exists(ctx, chainID) {
		err := fmt.Errorf("chain %s not found", chainID)
		span.RecordError(err)
		return err
	}

	// Validate the updated chain
	validationResult, err := cm.validator.ValidateChain(ctx, chain)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("chain validation failed: %w", err)
	}

	if !validationResult.Valid {
		span.SetAttributes(attribute.Bool("validation.valid", false))
		return fmt.Errorf("chain validation failed: %v", validationResult.Errors)
	}

	// Get current metadata and update it
	metadata, err := cm.registry.GetMetadata(ctx, chainID)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to get current metadata: %w", err)
	}

	metadata.UpdatedAt = time.Now()

	// Update in registry
	if err := cm.registry.Unregister(ctx, chainID); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to unregister old chain: %w", err)
	}

	if err := cm.registry.Register(ctx, chain, metadata); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to register updated chain: %w", err)
	}

	span.SetAttributes(attribute.Bool("success", true))
	cm.logger.Info("Chain updated successfully", "chain_id", chainID)

	return nil
}

// EnableChain enables a chain
func (cm *DefaultChainManager) EnableChain(ctx context.Context, chainID string) error {
	ctx, span := managerTracer.Start(ctx, "chain_manager.enable_chain",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	// Implementation would update chain status to enabled
	cm.logger.Info("Chain enabled", "chain_id", chainID)
	span.SetAttributes(attribute.Bool("success", true))
	return nil
}

// DisableChain disables a chain
func (cm *DefaultChainManager) DisableChain(ctx context.Context, chainID string) error {
	ctx, span := managerTracer.Start(ctx, "chain_manager.disable_chain",
		trace.WithAttributes(attribute.String("chain.id", chainID)),
	)
	defer span.End()

	// Implementation would update chain status to disabled
	cm.logger.Info("Chain disabled", "chain_id", chainID)
	span.SetAttributes(attribute.Bool("success", true))
	return nil
}

// ListChains lists chains with filtering
func (cm *DefaultChainManager) ListChains(ctx context.Context, filter ChainFilter) ([]ChainInfo, error) {
	ctx, span := managerTracer.Start(ctx, "chain_manager.list_chains")
	defer span.End()

	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	chains, err := cm.registry.List(ctx, filter)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to list chains: %w", err)
	}

	span.SetAttributes(
		attribute.Int("chains.count", len(chains)),
		attribute.Bool("success", true),
	)

	return chains, nil
}

// SearchChains searches for chains
func (cm *DefaultChainManager) SearchChains(ctx context.Context, query string) ([]ChainInfo, error) {
	ctx, span := managerTracer.Start(ctx, "chain_manager.search_chains",
		trace.WithAttributes(attribute.String("search.query", query)),
	)
	defer span.End()

	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	chains, err := cm.registry.Search(ctx, query)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to search chains: %w", err)
	}

	span.SetAttributes(
		attribute.Int("results.count", len(chains)),
		attribute.Bool("success", true),
	)

	return chains, nil
}

// ExecuteChain executes a chain with options
func (cm *DefaultChainManager) ExecuteChain(ctx context.Context, chainID string, input llm.ChainInput, options ExecutionOptions) (llm.ChainOutput, error) {
	ctx, span := managerTracer.Start(ctx, "chain_manager.execute_chain",
		trace.WithAttributes(
			attribute.String("chain.id", chainID),
			attribute.String("user.id", options.UserID),
		),
	)
	defer span.End()

	startTime := time.Now()

	// Check access permissions
	if err := cm.security.CheckAccess(ctx, chainID, options.UserID, "execute"); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("access denied: %w", err)
	}

	// Get the chain
	chain, err := cm.GetChain(ctx, chainID)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	// Execute the chain
	output, err := chain.Execute(ctx, input)
	duration := time.Since(startTime)

	// Record execution metrics
	success := err == nil
	if err := cm.monitor.RecordExecution(ctx, chainID, duration, success, map[string]interface{}{
		"user_id":  options.UserID,
		"trace_id": options.TraceID,
	}); err != nil {
		cm.logger.Warn("Failed to record execution metrics", "error", err)
	}

	if err != nil {
		// Record error
		if recordErr := cm.monitor.RecordError(ctx, chainID, err, map[string]interface{}{
			"user_id": options.UserID,
		}); recordErr != nil {
			cm.logger.Warn("Failed to record error", "error", recordErr)
		}
		span.RecordError(err)
		return nil, fmt.Errorf("chain execution failed: %w", err)
	}

	span.SetAttributes(
		attribute.String("execution.duration", duration.String()),
		attribute.Bool("success", true),
	)

	return output, nil
}

// GetChainMetrics retrieves metrics for a chain
func (cm *DefaultChainManager) GetChainMetrics(ctx context.Context, chainID string) (ChainMetrics, error) {
	return cm.monitor.GetMetrics(ctx, chainID)
}

// GetChainHealth retrieves health status for a chain
func (cm *DefaultChainManager) GetChainHealth(ctx context.Context, chainID string) (ChainHealth, error) {
	return cm.monitor.CheckHealth(ctx, chainID)
}

// CreateTemplate creates a new chain template
func (cm *DefaultChainManager) CreateTemplate(ctx context.Context, template ChainTemplate) error {
	return cm.templates.CreateTemplate(ctx, template)
}

// InstantiateFromTemplate creates a chain from a template
func (cm *DefaultChainManager) InstantiateFromTemplate(ctx context.Context, templateID string, config TemplateConfig) (llm.Chain, error) {
	return cm.templates.InstantiateFromTemplate(ctx, templateID, config)
}

// UpdateChainConfig updates chain configuration
func (cm *DefaultChainManager) UpdateChainConfig(ctx context.Context, chainID string, config ChainConfiguration) error {
	// Implementation would update chain configuration
	cm.logger.Info("Chain configuration updated", "chain_id", chainID)
	return nil
}

// ValidateChain validates a chain
func (cm *DefaultChainManager) ValidateChain(ctx context.Context, chain llm.Chain) (ValidationResult, error) {
	return cm.validator.ValidateChain(ctx, chain)
}

// ResolveDependencies resolves dependencies for a chain
func (cm *DefaultChainManager) ResolveDependencies(ctx context.Context, chainID string) ([]string, error) {
	return cm.registry.GetDependencies(ctx, chainID)
}

// CheckDependencies checks if all dependencies are satisfied
func (cm *DefaultChainManager) CheckDependencies(ctx context.Context, chainID string) error {
	dependencies, err := cm.registry.GetDependencies(ctx, chainID)
	if err != nil {
		return err
	}
	return cm.checkDependencies(ctx, dependencies)
}

// SetChainPermissions sets permissions for a chain
func (cm *DefaultChainManager) SetChainPermissions(ctx context.Context, chainID string, permissions ChainPermissions) error {
	return cm.security.SetPermissions(ctx, chainID, permissions)
}

// CheckAccess checks if a user has access to perform an action
func (cm *DefaultChainManager) CheckAccess(ctx context.Context, chainID string, userID string, action string) error {
	return cm.security.CheckAccess(ctx, chainID, userID, action)
}

// AuditChainAccess logs chain access for audit purposes
func (cm *DefaultChainManager) AuditChainAccess(ctx context.Context, chainID string, userID string, action string) error {
	return cm.security.LogAccess(ctx, chainID, userID, action, "success")
}

// checkDependencies validates that all dependencies exist
func (cm *DefaultChainManager) checkDependencies(ctx context.Context, dependencies []string) error {
	for _, dep := range dependencies {
		if !cm.registry.Exists(ctx, dep) {
			return fmt.Errorf("dependency %s not found", dep)
		}
	}
	return nil
}
