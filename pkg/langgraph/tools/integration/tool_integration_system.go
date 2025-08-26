package integration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/tools"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var integrationTracer = otel.Tracer("hackai/langgraph/tools/integration")

// ToolIntegrationSystem manages advanced tool integration capabilities
type ToolIntegrationSystem struct {
	registry         *AdvancedToolRegistry
	executor         *ToolExecutor
	validator        *ToolValidator
	securityManager  *ToolSecurityManager
	workflowEngine   *ToolWorkflowEngine
	pluginManager    *ToolPluginManager
	discoveryService *ToolDiscoveryService
	proxyManager     *ToolProxyManager
	config           *IntegrationConfig
	logger           *logger.Logger
	mutex            sync.RWMutex
}

// IntegrationConfig holds configuration for the tool integration system
type IntegrationConfig struct {
	EnableSecurity     bool           `json:"enable_security"`
	EnableWorkflows    bool           `json:"enable_workflows"`
	EnablePlugins      bool           `json:"enable_plugins"`
	EnableDiscovery    bool           `json:"enable_discovery"`
	EnableProxying     bool           `json:"enable_proxying"`
	EnableMetrics      bool           `json:"enable_metrics"`
	MaxConcurrentTools int            `json:"max_concurrent_tools"`
	DefaultTimeout     time.Duration  `json:"default_timeout"`
	RetryAttempts      int            `json:"retry_attempts"`
	RetryDelay         time.Duration  `json:"retry_delay"`
	SecurityLevel      SecurityLevel  `json:"security_level"`
	ValidationMode     ValidationMode `json:"validation_mode"`
}

// SecurityLevel defines security levels for tool execution
type SecurityLevel string

const (
	SecurityLevelNone     SecurityLevel = "none"
	SecurityLevelBasic    SecurityLevel = "basic"
	SecurityLevelStandard SecurityLevel = "standard"
	SecurityLevelHigh     SecurityLevel = "high"
	SecurityLevelCritical SecurityLevel = "critical"
)

// ValidationMode defines validation modes for tools
type ValidationMode string

const (
	ValidationModeNone   ValidationMode = "none"
	ValidationModeBasic  ValidationMode = "basic"
	ValidationModeStrict ValidationMode = "strict"
)

// ToolIntegration represents an integrated tool with metadata
type ToolIntegration struct {
	ID             string                 `json:"id"`
	Tool           tools.Tool             `json:"tool"`
	Config         *ToolConfig            `json:"config"`
	Security       *ToolSecurity          `json:"security"`
	Metrics        *ToolMetrics           `json:"metrics"`
	Dependencies   []string               `json:"dependencies"`
	Capabilities   []ToolCapability       `json:"capabilities"`
	Status         IntegrationStatus      `json:"status"`
	RegisteredAt   time.Time              `json:"registered_at"`
	LastExecuted   *time.Time             `json:"last_executed,omitempty"`
	ExecutionCount int64                  `json:"execution_count"`
	SuccessRate    float64                `json:"success_rate"`
	AverageLatency time.Duration          `json:"average_latency"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// ToolConfig holds configuration for a tool
type ToolConfig struct {
	Timeout        time.Duration          `json:"timeout"`
	RetryAttempts  int                    `json:"retry_attempts"`
	RetryDelay     time.Duration          `json:"retry_delay"`
	RateLimit      *RateLimit             `json:"rate_limit,omitempty"`
	CircuitBreaker *CircuitBreakerConfig  `json:"circuit_breaker,omitempty"`
	Caching        *CachingConfig         `json:"caching,omitempty"`
	Monitoring     *MonitoringConfig      `json:"monitoring,omitempty"`
	Parameters     map[string]interface{} `json:"parameters"`
}

// ToolSecurity holds security configuration for a tool
type ToolSecurity struct {
	Level          SecurityLevel     `json:"level"`
	Permissions    []Permission      `json:"permissions"`
	AllowedUsers   []string          `json:"allowed_users"`
	AllowedRoles   []string          `json:"allowed_roles"`
	RequiredScopes []string          `json:"required_scopes"`
	Encryption     *EncryptionConfig `json:"encryption,omitempty"`
	Audit          *AuditConfig      `json:"audit,omitempty"`
	Sandbox        *SandboxConfig    `json:"sandbox,omitempty"`
}

// ToolMetrics holds execution metrics for a tool
type ToolMetrics struct {
	ExecutionCount    int64                  `json:"execution_count"`
	SuccessCount      int64                  `json:"success_count"`
	ErrorCount        int64                  `json:"error_count"`
	TimeoutCount      int64                  `json:"timeout_count"`
	TotalLatency      time.Duration          `json:"total_latency"`
	AverageLatency    time.Duration          `json:"average_latency"`
	MinLatency        time.Duration          `json:"min_latency"`
	MaxLatency        time.Duration          `json:"max_latency"`
	LastExecuted      *time.Time             `json:"last_executed,omitempty"`
	ErrorRate         float64                `json:"error_rate"`
	SuccessRate       float64                `json:"success_rate"`
	ThroughputPerHour float64                `json:"throughput_per_hour"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ToolCapability defines capabilities of a tool
type ToolCapability string

const (
	CapabilityAsync      ToolCapability = "async"
	CapabilityBatch      ToolCapability = "batch"
	CapabilityStreaming  ToolCapability = "streaming"
	CapabilityRetryable  ToolCapability = "retryable"
	CapabilityCacheable  ToolCapability = "cacheable"
	CapabilityIdempotent ToolCapability = "idempotent"
	CapabilityStateful   ToolCapability = "stateful"
	CapabilitySecure     ToolCapability = "secure"
	CapabilityMonitored  ToolCapability = "monitored"
	CapabilityVersioned  ToolCapability = "versioned"
)

// IntegrationStatus represents the status of a tool integration
type IntegrationStatus string

const (
	StatusRegistered  IntegrationStatus = "registered"
	StatusActive      IntegrationStatus = "active"
	StatusInactive    IntegrationStatus = "inactive"
	StatusError       IntegrationStatus = "error"
	StatusMaintenance IntegrationStatus = "maintenance"
	StatusDeprecated  IntegrationStatus = "deprecated"
)

// Permission represents a security permission
type Permission string

const (
	PermissionRead    Permission = "read"
	PermissionWrite   Permission = "write"
	PermissionExecute Permission = "execute"
	PermissionAdmin   Permission = "admin"
)

// RateLimit configuration
type RateLimit struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	WindowSize        time.Duration `json:"window_size"`
}

// CircuitBreakerConfig configuration
type CircuitBreakerConfig struct {
	FailureThreshold int           `json:"failure_threshold"`
	RecoveryTimeout  time.Duration `json:"recovery_timeout"`
	HalfOpenRequests int           `json:"half_open_requests"`
}

// CachingConfig configuration
type CachingConfig struct {
	Enabled  bool          `json:"enabled"`
	TTL      time.Duration `json:"ttl"`
	MaxSize  int           `json:"max_size"`
	Strategy string        `json:"strategy"`
}

// MonitoringConfig configuration
type MonitoringConfig struct {
	Enabled         bool               `json:"enabled"`
	MetricsInterval time.Duration      `json:"metrics_interval"`
	AlertThresholds map[string]float64 `json:"alert_thresholds"`
	HealthChecks    bool               `json:"health_checks"`
}

// EncryptionConfig configuration
type EncryptionConfig struct {
	Enabled   bool   `json:"enabled"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
}

// AuditConfig configuration
type AuditConfig struct {
	Enabled    bool          `json:"enabled"`
	LogLevel   string        `json:"log_level"`
	LogInputs  bool          `json:"log_inputs"`
	LogOutputs bool          `json:"log_outputs"`
	Retention  time.Duration `json:"retention"`
}

// SandboxConfig configuration
type SandboxConfig struct {
	Enabled        bool              `json:"enabled"`
	Type           string            `json:"type"`
	ResourceLimits map[string]string `json:"resource_limits"`
	NetworkAccess  bool              `json:"network_access"`
}

// NewToolIntegrationSystem creates a new tool integration system
func NewToolIntegrationSystem(config *IntegrationConfig, logger *logger.Logger) *ToolIntegrationSystem {
	if config == nil {
		config = &IntegrationConfig{
			EnableSecurity:     true,
			EnableWorkflows:    true,
			EnablePlugins:      true,
			EnableDiscovery:    true,
			EnableProxying:     true,
			EnableMetrics:      true,
			MaxConcurrentTools: 10,
			DefaultTimeout:     30 * time.Second,
			RetryAttempts:      3,
			RetryDelay:         time.Second,
			SecurityLevel:      SecurityLevelStandard,
			ValidationMode:     ValidationModeStrict,
		}
	}

	system := &ToolIntegrationSystem{
		registry: NewAdvancedToolRegistry(logger),
		config:   config,
		logger:   logger,
	}

	// Initialize components based on configuration
	system.executor = NewToolExecutor(config, logger)
	system.validator = NewToolValidator(config.ValidationMode, logger)

	if config.EnableSecurity {
		system.securityManager = NewToolSecurityManager(config.SecurityLevel, logger)
	}

	if config.EnableWorkflows {
		system.workflowEngine = NewToolWorkflowEngine(logger)
	}

	if config.EnablePlugins {
		system.pluginManager = NewToolPluginManager(logger)
	}

	if config.EnableDiscovery {
		system.discoveryService = NewToolDiscoveryService(logger)
	}

	if config.EnableProxying {
		system.proxyManager = NewToolProxyManager(logger)
	}

	return system
}

// RegisterTool registers a tool with the integration system
func (tis *ToolIntegrationSystem) RegisterTool(ctx context.Context, tool tools.Tool, config *ToolConfig) (*ToolIntegration, error) {
	ctx, span := integrationTracer.Start(ctx, "tool_integration_system.register_tool",
		trace.WithAttributes(
			attribute.String("tool.id", tool.ID()),
			attribute.String("tool.name", tool.Name()),
		),
	)
	defer span.End()

	tis.mutex.Lock()
	defer tis.mutex.Unlock()

	// Validate tool
	if err := tis.validator.ValidateTool(ctx, tool); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("tool validation failed: %w", err)
	}

	// Create tool integration
	integration := &ToolIntegration{
		ID:           uuid.New().String(),
		Tool:         tool,
		Config:       config,
		Security:     tis.createDefaultSecurity(tool),
		Metrics:      &ToolMetrics{},
		Dependencies: make([]string, 0),
		Capabilities: tis.detectCapabilities(tool),
		Status:       StatusRegistered,
		RegisteredAt: time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	// Apply default configuration if not provided
	if integration.Config == nil {
		integration.Config = tis.createDefaultConfig()
	}

	// Register with registry
	if err := tis.registry.RegisterIntegration(integration); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to register integration: %w", err)
	}

	// Initialize security if enabled
	if tis.config.EnableSecurity && tis.securityManager != nil {
		if err := tis.securityManager.InitializeSecurity(ctx, integration); err != nil {
			tis.logger.Warn("Failed to initialize security for tool",
				"tool_id", tool.ID(),
				"error", err)
		}
	}

	// Start monitoring if enabled
	if tis.config.EnableMetrics {
		go tis.startMetricsCollection(integration)
	}

	integration.Status = StatusActive

	span.SetAttributes(
		attribute.String("integration.id", integration.ID),
		attribute.String("integration.status", string(integration.Status)),
	)

	tis.logger.Info("Tool registered successfully",
		"tool_id", tool.ID(),
		"tool_name", tool.Name(),
		"integration_id", integration.ID,
		"capabilities", len(integration.Capabilities))

	return integration, nil
}

// ExecuteTool executes a tool through the integration system
func (tis *ToolIntegrationSystem) ExecuteTool(ctx context.Context, toolID string, input map[string]interface{}, options *ExecutionOptions) (*ExecutionResult, error) {
	ctx, span := integrationTracer.Start(ctx, "tool_integration_system.execute_tool",
		trace.WithAttributes(
			attribute.String("tool.id", toolID),
		),
	)
	defer span.End()

	// Get tool integration
	integration, err := tis.registry.GetIntegration(toolID)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("tool not found: %w", err)
	}

	// Check security if enabled
	if tis.config.EnableSecurity && tis.securityManager != nil {
		if err := tis.securityManager.CheckPermissions(ctx, integration, options); err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("security check failed: %w", err)
		}
	}

	// Execute tool
	result, err := tis.executor.Execute(ctx, integration, input, options)
	if err != nil {
		span.RecordError(err)
		tis.updateMetrics(integration, false, time.Since(time.Now()))
		return nil, fmt.Errorf("tool execution failed: %w", err)
	}

	// Update metrics
	tis.updateMetrics(integration, true, result.Duration)

	span.SetAttributes(
		attribute.Bool("execution.success", result.Success),
		attribute.Float64("execution.duration", result.Duration.Seconds()),
	)

	return result, nil
}

// Helper methods

func (tis *ToolIntegrationSystem) createDefaultSecurity(tool tools.Tool) *ToolSecurity {
	return &ToolSecurity{
		Level:          tis.config.SecurityLevel,
		Permissions:    []Permission{PermissionExecute},
		AllowedUsers:   make([]string, 0),
		AllowedRoles:   make([]string, 0),
		RequiredScopes: make([]string, 0),
	}
}

func (tis *ToolIntegrationSystem) createDefaultConfig() *ToolConfig {
	return &ToolConfig{
		Timeout:       tis.config.DefaultTimeout,
		RetryAttempts: tis.config.RetryAttempts,
		RetryDelay:    tis.config.RetryDelay,
		Parameters:    make(map[string]interface{}),
	}
}

func (tis *ToolIntegrationSystem) detectCapabilities(tool tools.Tool) []ToolCapability {
	capabilities := make([]ToolCapability, 0)

	// Check if tool implements various interfaces
	if _, ok := tool.(tools.ValidatableTool); ok {
		capabilities = append(capabilities, CapabilityRetryable)
	}

	if _, ok := tool.(tools.ConfigurableTool); ok {
		capabilities = append(capabilities, CapabilityVersioned)
	}

	if _, ok := tool.(tools.MetricsTool); ok {
		capabilities = append(capabilities, CapabilityMonitored)
	}

	// Add default capabilities
	capabilities = append(capabilities, CapabilitySecure)

	return capabilities
}

func (tis *ToolIntegrationSystem) updateMetrics(integration *ToolIntegration, success bool, duration time.Duration) {
	integration.Metrics.ExecutionCount++
	integration.Metrics.TotalLatency += duration

	if success {
		integration.Metrics.SuccessCount++
	} else {
		integration.Metrics.ErrorCount++
	}

	// Update average latency
	if integration.Metrics.ExecutionCount > 0 {
		integration.Metrics.AverageLatency = integration.Metrics.TotalLatency / time.Duration(integration.Metrics.ExecutionCount)
	}

	// Update min/max latency
	if integration.Metrics.MinLatency == 0 || duration < integration.Metrics.MinLatency {
		integration.Metrics.MinLatency = duration
	}
	if duration > integration.Metrics.MaxLatency {
		integration.Metrics.MaxLatency = duration
	}

	// Update rates
	if integration.Metrics.ExecutionCount > 0 {
		integration.Metrics.SuccessRate = float64(integration.Metrics.SuccessCount) / float64(integration.Metrics.ExecutionCount)
		integration.Metrics.ErrorRate = float64(integration.Metrics.ErrorCount) / float64(integration.Metrics.ExecutionCount)
	}

	now := time.Now()
	integration.Metrics.LastExecuted = &now
	integration.LastExecuted = &now
}

func (tis *ToolIntegrationSystem) startMetricsCollection(integration *ToolIntegration) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Collect and update metrics
			tis.collectMetrics(integration)
		}
	}
}

func (tis *ToolIntegrationSystem) collectMetrics(integration *ToolIntegration) {
	// Calculate throughput
	if integration.Metrics.LastExecuted != nil {
		hoursSinceRegistration := time.Since(integration.RegisteredAt).Hours()
		if hoursSinceRegistration > 0 {
			integration.Metrics.ThroughputPerHour = float64(integration.Metrics.ExecutionCount) / hoursSinceRegistration
		}
	}
}

// ExecutionOptions holds options for tool execution
type ExecutionOptions struct {
	UserID   string                 `json:"user_id"`
	Timeout  *time.Duration         `json:"timeout,omitempty"`
	Async    bool                   `json:"async"`
	Priority int                    `json:"priority"`
	Context  map[string]interface{} `json:"context"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ExecutionResult holds the result of tool execution
type ExecutionResult struct {
	Success   bool                   `json:"success"`
	Result    interface{}            `json:"result"`
	Error     string                 `json:"error,omitempty"`
	Duration  time.Duration          `json:"duration"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// GetIntegrations returns all registered tool integrations
func (tis *ToolIntegrationSystem) GetIntegrations() []*ToolIntegration {
	return tis.registry.GetAllIntegrations()
}

// GetIntegration returns a specific tool integration
func (tis *ToolIntegrationSystem) GetIntegration(toolID string) (*ToolIntegration, error) {
	return tis.registry.GetIntegration(toolID)
}

// UnregisterTool removes a tool from the integration system
func (tis *ToolIntegrationSystem) UnregisterTool(ctx context.Context, toolID string) error {
	return tis.registry.UnregisterIntegration(toolID)
}

// SetUserPermissions sets permissions for a user through the security manager
func (tis *ToolIntegrationSystem) SetUserPermissions(userID string, permissions *PermissionSet) error {
	if tis.securityManager == nil {
		return fmt.Errorf("security manager not initialized")
	}
	tis.securityManager.SetUserPermissions(userID, permissions)
	return nil
}

// CreateSecuritySession creates a new security session through the security manager
func (tis *ToolIntegrationSystem) CreateSecuritySession(userID, ipAddress, userAgent string, permissions *PermissionSet) (*SecuritySession, error) {
	if tis.securityManager == nil {
		return nil, fmt.Errorf("security manager not initialized")
	}
	return tis.securityManager.CreateSession(userID, ipAddress, userAgent, permissions)
}

// GetSecurityStats returns security statistics through the security manager
func (tis *ToolIntegrationSystem) GetSecurityStats() (*SecurityStats, error) {
	if tis.securityManager == nil {
		return nil, fmt.Errorf("security manager not initialized")
	}
	return tis.securityManager.GetSecurityStats(), nil
}

// QueryIntegrations finds integrations based on query criteria through the registry
func (tis *ToolIntegrationSystem) QueryIntegrations(query RegistryQuery) ([]*ToolIntegration, error) {
	return tis.registry.QueryIntegrations(query)
}

// GetRegistryStats returns statistics about the registry
func (tis *ToolIntegrationSystem) GetRegistryStats() *RegistryStats {
	return tis.registry.GetRegistryStats()
}

// GetSystemStats returns statistics about the integration system
func (tis *ToolIntegrationSystem) GetSystemStats() *SystemStats {
	integrations := tis.registry.GetAllIntegrations()

	stats := &SystemStats{
		TotalTools:      len(integrations),
		ActiveTools:     0,
		InactiveTools:   0,
		ErrorTools:      0,
		TotalExecutions: 0,
		SuccessRate:     0.0,
		AverageLatency:  0,
		Timestamp:       time.Now(),
	}

	var totalSuccessRate float64
	var totalLatency time.Duration

	for _, integration := range integrations {
		switch integration.Status {
		case StatusActive:
			stats.ActiveTools++
		case StatusInactive:
			stats.InactiveTools++
		case StatusError:
			stats.ErrorTools++
		}

		stats.TotalExecutions += integration.Metrics.ExecutionCount
		totalSuccessRate += integration.Metrics.SuccessRate
		totalLatency += integration.Metrics.AverageLatency
	}

	if len(integrations) > 0 {
		stats.SuccessRate = totalSuccessRate / float64(len(integrations))
		stats.AverageLatency = totalLatency / time.Duration(len(integrations))
	}

	return stats
}

// SystemStats holds statistics about the integration system
type SystemStats struct {
	TotalTools      int           `json:"total_tools"`
	ActiveTools     int           `json:"active_tools"`
	InactiveTools   int           `json:"inactive_tools"`
	ErrorTools      int           `json:"error_tools"`
	TotalExecutions int64         `json:"total_executions"`
	SuccessRate     float64       `json:"success_rate"`
	AverageLatency  time.Duration `json:"average_latency"`
	Timestamp       time.Time     `json:"timestamp"`
}
