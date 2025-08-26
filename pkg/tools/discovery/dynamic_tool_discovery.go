package discovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var discoveryTracer = otel.Tracer("hackai/tools/discovery")

// DynamicToolDiscovery provides automatic tool discovery and integration
type DynamicToolDiscovery struct {
	id                 string
	discoveryEngines   map[string]DiscoveryEngine
	capabilityAssessor *CapabilityAssessor
	securityValidator  *SecurityValidator
	integrationManager *IntegrationManager
	discoveredTools    map[string]*DiscoveredTool
	toolCapabilities   map[string]*ToolCapabilities
	discoveryScheduler *DiscoveryScheduler
	config             *DiscoveryConfig
	logger             *logger.Logger
	mutex              sync.RWMutex
}

// DiscoveryConfig configures the discovery system
type DiscoveryConfig struct {
	EnableAutoDiscovery        bool          `json:"enable_auto_discovery"`
	EnableSecurityValidation   bool          `json:"enable_security_validation"`
	EnableCapabilityAssessment bool          `json:"enable_capability_assessment"`
	DiscoveryInterval          time.Duration `json:"discovery_interval"`
	MaxConcurrentDiscovery     int           `json:"max_concurrent_discovery"`
	SecurityScanTimeout        time.Duration `json:"security_scan_timeout"`
	CapabilityTestTimeout      time.Duration `json:"capability_test_timeout"`
	AutoIntegrationEnabled     bool          `json:"auto_integration_enabled"`
	TrustThreshold             float64       `json:"trust_threshold"`
	PerformanceThreshold       float64       `json:"performance_threshold"`
}

// DiscoveredTool represents a discovered tool
type DiscoveredTool struct {
	ID                 string                 `json:"id"`
	Name               string                 `json:"name"`
	Description        string                 `json:"description"`
	Version            string                 `json:"version"`
	Source             ToolSource             `json:"source"`
	Type               ToolType               `json:"type"`
	Category           ToolCategory           `json:"category"`
	Endpoint           string                 `json:"endpoint"`
	Interface          ToolInterface          `json:"interface"`
	Capabilities       *ToolCapabilities      `json:"capabilities"`
	SecurityStatus     *SecurityStatus        `json:"security_status"`
	PerformanceMetrics *PerformanceMetrics    `json:"performance_metrics"`
	IntegrationStatus  IntegrationStatus      `json:"integration_status"`
	Metadata           map[string]interface{} `json:"metadata"`
	DiscoveredAt       time.Time              `json:"discovered_at"`
	LastValidated      time.Time              `json:"last_validated"`
}

// ToolSource defines where the tool was discovered
type ToolSource string

const (
	SourceRegistry   ToolSource = "registry"
	SourceNetwork    ToolSource = "network"
	SourceFilesystem ToolSource = "filesystem"
	SourceAPI        ToolSource = "api"
	SourceContainer  ToolSource = "container"
	SourcePlugin     ToolSource = "plugin"
	SourceManual     ToolSource = "manual"
)

// ToolType defines the type of tool
type ToolType string

const (
	TypeSecurityTool    ToolType = "security_tool"
	TypeAnalysisTool    ToolType = "analysis_tool"
	TypeAutomationTool  ToolType = "automation_tool"
	TypeMonitoringTool  ToolType = "monitoring_tool"
	TypeIntegrationTool ToolType = "integration_tool"
	TypeUtilityTool     ToolType = "utility_tool"
)

// ToolCategory defines the category of tool
type ToolCategory string

const (
	CategoryVulnerabilityScanning ToolCategory = "vulnerability_scanning"
	CategoryPenetrationTesting    ToolCategory = "penetration_testing"
	CategoryThreatIntelligence    ToolCategory = "threat_intelligence"
	CategoryIncidentResponse      ToolCategory = "incident_response"
	CategoryForensics             ToolCategory = "forensics"
	CategoryCompliance            ToolCategory = "compliance"
	CategoryNetworkSecurity       ToolCategory = "network_security"
	CategoryApplicationSecurity   ToolCategory = "application_security"
)

// ToolInterface defines how to interact with the tool
type ToolInterface struct {
	Type       InterfaceType          `json:"type"`
	Protocol   string                 `json:"protocol"`
	Endpoint   string                 `json:"endpoint"`
	AuthMethod AuthenticationMethod   `json:"auth_method"`
	Parameters map[string]interface{} `json:"parameters"`
	Headers    map[string]string      `json:"headers"`
	Timeout    time.Duration          `json:"timeout"`
}

// InterfaceType defines the interface type
type InterfaceType string

const (
	InterfaceREST      InterfaceType = "rest"
	InterfaceGraphQL   InterfaceType = "graphql"
	InterfaceGRPC      InterfaceType = "grpc"
	InterfaceWebSocket InterfaceType = "websocket"
	InterfaceCLI       InterfaceType = "cli"
	InterfaceSDK       InterfaceType = "sdk"
)

// AuthenticationMethod defines authentication methods
type AuthenticationMethod string

const (
	AuthNone        AuthenticationMethod = "none"
	AuthAPIKey      AuthenticationMethod = "api_key"
	AuthBearer      AuthenticationMethod = "bearer"
	AuthBasic       AuthenticationMethod = "basic"
	AuthOAuth2      AuthenticationMethod = "oauth2"
	AuthCertificate AuthenticationMethod = "certificate"
)

// ToolCapabilities represents tool capabilities
type ToolCapabilities struct {
	ID                   string                 `json:"id"`
	ToolID               string                 `json:"tool_id"`
	SupportedOperations  []Operation            `json:"supported_operations"`
	InputFormats         []string               `json:"input_formats"`
	OutputFormats        []string               `json:"output_formats"`
	PerformanceProfile   *PerformanceProfile    `json:"performance_profile"`
	ResourceRequirements *ResourceRequirements  `json:"resource_requirements"`
	Limitations          []string               `json:"limitations"`
	Dependencies         []string               `json:"dependencies"`
	Metadata             map[string]interface{} `json:"metadata"`
	AssessedAt           time.Time              `json:"assessed_at"`
}

// Operation represents a tool operation
type Operation struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Method      string                 `json:"method"`
	Path        string                 `json:"path"`
	Parameters  []Parameter            `json:"parameters"`
	Response    ResponseSchema         `json:"response"`
	Examples    []OperationExample     `json:"examples"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Parameter represents an operation parameter
type Parameter struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Required    bool        `json:"required"`
	Description string      `json:"description"`
	Default     interface{} `json:"default"`
	Validation  *Validation `json:"validation"`
}

// Validation represents parameter validation rules
type Validation struct {
	Pattern string      `json:"pattern"`
	Min     interface{} `json:"min"`
	Max     interface{} `json:"max"`
	Enum    []string    `json:"enum"`
}

// ResponseSchema represents response schema
type ResponseSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
	Examples   []interface{}          `json:"examples"`
}

// OperationExample represents an operation example
type OperationExample struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Request     map[string]interface{} `json:"request"`
	Response    map[string]interface{} `json:"response"`
}

// PerformanceProfile represents performance characteristics
type PerformanceProfile struct {
	AverageLatency    time.Duration `json:"average_latency"`
	MaxLatency        time.Duration `json:"max_latency"`
	Throughput        float64       `json:"throughput"`
	ErrorRate         float64       `json:"error_rate"`
	AvailabilityScore float64       `json:"availability_score"`
	ReliabilityScore  float64       `json:"reliability_score"`
}

// ResourceRequirements represents resource requirements
type ResourceRequirements struct {
	CPU         float64 `json:"cpu"`
	Memory      int64   `json:"memory"`
	Storage     int64   `json:"storage"`
	Network     int64   `json:"network"`
	Concurrency int     `json:"concurrency"`
	RateLimit   int     `json:"rate_limit"`
}

// SecurityStatus represents security validation status
type SecurityStatus struct {
	ID               string                 `json:"id"`
	ToolID           string                 `json:"tool_id"`
	TrustScore       float64                `json:"trust_score"`
	SecurityLevel    SecurityLevel          `json:"security_level"`
	Vulnerabilities  []*Vulnerability       `json:"vulnerabilities"`
	Certifications   []string               `json:"certifications"`
	ComplianceStatus map[string]bool        `json:"compliance_status"`
	LastScanned      time.Time              `json:"last_scanned"`
	ScanResults      *SecurityScanResults   `json:"scan_results"`
	Recommendations  []string               `json:"recommendations"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// SecurityLevel defines security levels
type SecurityLevel string

const (
	SecurityLevelUntrusted SecurityLevel = "untrusted"
	SecurityLevelLow       SecurityLevel = "low"
	SecurityLevelMedium    SecurityLevel = "medium"
	SecurityLevelHigh      SecurityLevel = "high"
	SecurityLevelCritical  SecurityLevel = "critical"
)

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Impact      string    `json:"impact"`
	Mitigation  string    `json:"mitigation"`
	CVSS        float64   `json:"cvss"`
	References  []string  `json:"references"`
	FoundAt     time.Time `json:"found_at"`
}

// SecurityScanResults represents security scan results
type SecurityScanResults struct {
	ScanID         string                 `json:"scan_id"`
	ScanType       string                 `json:"scan_type"`
	StartTime      time.Time              `json:"start_time"`
	EndTime        time.Time              `json:"end_time"`
	Duration       time.Duration          `json:"duration"`
	TestsRun       int                    `json:"tests_run"`
	TestsPassed    int                    `json:"tests_passed"`
	TestsFailed    int                    `json:"tests_failed"`
	CriticalIssues int                    `json:"critical_issues"`
	HighIssues     int                    `json:"high_issues"`
	MediumIssues   int                    `json:"medium_issues"`
	LowIssues      int                    `json:"low_issues"`
	Details        map[string]interface{} `json:"details"`
}

// PerformanceMetrics represents performance metrics
type PerformanceMetrics struct {
	ID               string                 `json:"id"`
	ToolID           string                 `json:"tool_id"`
	ResponseTime     time.Duration          `json:"response_time"`
	Throughput       float64                `json:"throughput"`
	ErrorRate        float64                `json:"error_rate"`
	Availability     float64                `json:"availability"`
	ResourceUsage    *ResourceUsage         `json:"resource_usage"`
	BenchmarkResults map[string]float64     `json:"benchmark_results"`
	LastMeasured     time.Time              `json:"last_measured"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// ResourceUsage represents resource usage metrics
type ResourceUsage struct {
	CPUUsage     float64 `json:"cpu_usage"`
	MemoryUsage  int64   `json:"memory_usage"`
	StorageUsage int64   `json:"storage_usage"`
	NetworkUsage int64   `json:"network_usage"`
}

// IntegrationStatus defines integration status
type IntegrationStatus string

const (
	IntegrationStatusDiscovered IntegrationStatus = "discovered"
	IntegrationStatusValidating IntegrationStatus = "validating"
	IntegrationStatusTesting    IntegrationStatus = "testing"
	IntegrationStatusIntegrated IntegrationStatus = "integrated"
	IntegrationStatusFailed     IntegrationStatus = "failed"
	IntegrationStatusDisabled   IntegrationStatus = "disabled"
)

// DiscoveryEngine interface for tool discovery engines
type DiscoveryEngine interface {
	Discover(ctx context.Context) ([]*DiscoveredTool, error)
	GetName() string
	GetType() string
	IsEnabled() bool
	Configure(config map[string]interface{}) error
}

// NewDynamicToolDiscovery creates a new dynamic tool discovery system
func NewDynamicToolDiscovery(config *DiscoveryConfig, logger *logger.Logger) *DynamicToolDiscovery {
	if config == nil {
		config = DefaultDiscoveryConfig()
	}

	dtd := &DynamicToolDiscovery{
		id:               uuid.New().String(),
		discoveryEngines: make(map[string]DiscoveryEngine),
		discoveredTools:  make(map[string]*DiscoveredTool),
		toolCapabilities: make(map[string]*ToolCapabilities),
		config:           config,
		logger:           logger,
	}

	// Initialize components
	dtd.capabilityAssessor = NewCapabilityAssessor(logger)
	dtd.securityValidator = NewSecurityValidator(logger)
	dtd.integrationManager = NewIntegrationManager(logger)
	dtd.discoveryScheduler = NewDiscoveryScheduler(config.DiscoveryInterval, logger)

	// Register default discovery engines
	dtd.registerDefaultEngines()

	return dtd
}

// DefaultDiscoveryConfig returns default configuration
func DefaultDiscoveryConfig() *DiscoveryConfig {
	return &DiscoveryConfig{
		EnableAutoDiscovery:        true,
		EnableSecurityValidation:   true,
		EnableCapabilityAssessment: true,
		DiscoveryInterval:          time.Hour,
		MaxConcurrentDiscovery:     5,
		SecurityScanTimeout:        10 * time.Minute,
		CapabilityTestTimeout:      5 * time.Minute,
		AutoIntegrationEnabled:     false,
		TrustThreshold:             0.7,
		PerformanceThreshold:       0.8,
	}
}

// registerDefaultEngines registers default discovery engines
func (dtd *DynamicToolDiscovery) registerDefaultEngines() {
	// Register network discovery engine
	networkEngine := NewNetworkDiscoveryEngine(dtd.logger)
	dtd.discoveryEngines["network"] = networkEngine

	// Register registry discovery engine
	registryEngine := NewRegistryDiscoveryEngine(dtd.logger)
	dtd.discoveryEngines["registry"] = registryEngine

	// Register filesystem discovery engine
	filesystemEngine := NewFilesystemDiscoveryEngine(dtd.logger)
	dtd.discoveryEngines["filesystem"] = filesystemEngine

	// Register API discovery engine
	apiEngine := NewAPIDiscoveryEngine(dtd.logger)
	dtd.discoveryEngines["api"] = apiEngine
}

// StartDiscovery starts the discovery process
func (dtd *DynamicToolDiscovery) StartDiscovery(ctx context.Context) error {
	ctx, span := discoveryTracer.Start(ctx, "dynamic_tool_discovery.start_discovery")
	defer span.End()

	dtd.logger.Info("Starting dynamic tool discovery",
		"discovery_id", dtd.id,
		"engines", len(dtd.discoveryEngines))

	// Start discovery scheduler if auto-discovery is enabled
	if dtd.config.EnableAutoDiscovery {
		go dtd.discoveryScheduler.Start(ctx, dtd.runDiscovery)
	}

	// Run initial discovery
	return dtd.runDiscovery(ctx)
}

// runDiscovery runs the discovery process
func (dtd *DynamicToolDiscovery) runDiscovery(ctx context.Context) error {
	ctx, span := discoveryTracer.Start(ctx, "dynamic_tool_discovery.run_discovery")
	defer span.End()

	var allTools []*DiscoveredTool
	var wg sync.WaitGroup
	toolsChan := make(chan []*DiscoveredTool, len(dtd.discoveryEngines))
	errorsChan := make(chan error, len(dtd.discoveryEngines))

	// Run discovery engines concurrently
	for name, engine := range dtd.discoveryEngines {
		if !engine.IsEnabled() {
			continue
		}

		wg.Add(1)
		go func(name string, engine DiscoveryEngine) {
			defer wg.Done()

			engineCtx, engineSpan := discoveryTracer.Start(ctx, "discovery_engine.discover",
				trace.WithAttributes(attribute.String("engine.name", name)))
			defer engineSpan.End()

			tools, err := engine.Discover(engineCtx)
			if err != nil {
				engineSpan.RecordError(err)
				errorsChan <- fmt.Errorf("discovery engine %s failed: %w", name, err)
				return
			}

			toolsChan <- tools
		}(name, engine)
	}

	// Wait for all engines to complete
	go func() {
		wg.Wait()
		close(toolsChan)
		close(errorsChan)
	}()

	// Collect results
	for tools := range toolsChan {
		allTools = append(allTools, tools...)
	}

	// Log any errors
	for err := range errorsChan {
		dtd.logger.Error("Discovery engine error", "error", err)
	}

	dtd.logger.Info("Discovery completed",
		"tools_discovered", len(allTools))

	// Process discovered tools
	return dtd.processDiscoveredTools(ctx, allTools)
}

// processDiscoveredTools processes newly discovered tools
func (dtd *DynamicToolDiscovery) processDiscoveredTools(ctx context.Context, tools []*DiscoveredTool) error {
	ctx, span := discoveryTracer.Start(ctx, "dynamic_tool_discovery.process_discovered_tools",
		trace.WithAttributes(attribute.Int("tools.count", len(tools))))
	defer span.End()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, dtd.config.MaxConcurrentDiscovery)

	for _, tool := range tools {
		// Skip if already processed
		if _, exists := dtd.discoveredTools[tool.ID]; exists {
			continue
		}

		wg.Add(1)
		go func(tool *DiscoveredTool) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := dtd.processSingleTool(ctx, tool); err != nil {
				dtd.logger.Error("Failed to process tool",
					"tool_id", tool.ID,
					"tool_name", tool.Name,
					"error", err)
			}
		}(tool)
	}

	wg.Wait()
	return nil
}

// processSingleTool processes a single discovered tool
func (dtd *DynamicToolDiscovery) processSingleTool(ctx context.Context, tool *DiscoveredTool) error {
	ctx, span := discoveryTracer.Start(ctx, "dynamic_tool_discovery.process_single_tool",
		trace.WithAttributes(
			attribute.String("tool.id", tool.ID),
			attribute.String("tool.name", tool.Name),
		))
	defer span.End()

	// Step 1: Assess capabilities
	if dtd.config.EnableCapabilityAssessment {
		capabilities, err := dtd.capabilityAssessor.AssessCapabilities(ctx, tool)
		if err != nil {
			span.RecordError(err)
			return fmt.Errorf("capability assessment failed: %w", err)
		}
		tool.Capabilities = capabilities
		dtd.toolCapabilities[tool.ID] = capabilities
	}

	// Step 2: Validate security
	if dtd.config.EnableSecurityValidation {
		securityStatus, err := dtd.securityValidator.ValidateSecurity(ctx, tool)
		if err != nil {
			span.RecordError(err)
			return fmt.Errorf("security validation failed: %w", err)
		}
		tool.SecurityStatus = securityStatus

		// Check trust threshold
		if securityStatus.TrustScore < dtd.config.TrustThreshold {
			dtd.logger.Warn("Tool failed trust threshold",
				"tool_id", tool.ID,
				"trust_score", securityStatus.TrustScore,
				"threshold", dtd.config.TrustThreshold)
			tool.IntegrationStatus = IntegrationStatusFailed
			dtd.discoveredTools[tool.ID] = tool
			return nil
		}
	}

	// Step 3: Measure performance
	performanceMetrics, err := dtd.measurePerformance(ctx, tool)
	if err != nil {
		dtd.logger.Warn("Performance measurement failed",
			"tool_id", tool.ID,
			"error", err)
	} else {
		tool.PerformanceMetrics = performanceMetrics
	}

	// Step 4: Auto-integrate if enabled and thresholds met
	if dtd.config.AutoIntegrationEnabled {
		if dtd.shouldAutoIntegrate(tool) {
			if err := dtd.integrationManager.IntegrateTool(ctx, tool); err != nil {
				span.RecordError(err)
				tool.IntegrationStatus = IntegrationStatusFailed
			} else {
				tool.IntegrationStatus = IntegrationStatusIntegrated
			}
		}
	} else {
		tool.IntegrationStatus = IntegrationStatusDiscovered
	}

	// Store discovered tool
	dtd.mutex.Lock()
	dtd.discoveredTools[tool.ID] = tool
	dtd.mutex.Unlock()

	dtd.logger.Info("Tool processed successfully",
		"tool_id", tool.ID,
		"tool_name", tool.Name,
		"integration_status", tool.IntegrationStatus)

	return nil
}

// shouldAutoIntegrate determines if a tool should be auto-integrated
func (dtd *DynamicToolDiscovery) shouldAutoIntegrate(tool *DiscoveredTool) bool {
	// Check security requirements
	if tool.SecurityStatus != nil {
		if tool.SecurityStatus.TrustScore < dtd.config.TrustThreshold {
			return false
		}
		if tool.SecurityStatus.SecurityLevel == SecurityLevelUntrusted {
			return false
		}
	}

	// Check performance requirements
	if tool.PerformanceMetrics != nil {
		if tool.PerformanceMetrics.Availability < dtd.config.PerformanceThreshold {
			return false
		}
		if tool.PerformanceMetrics.ErrorRate > 0.1 { // 10% error rate threshold
			return false
		}
	}

	// Check if tool has required capabilities
	if tool.Capabilities == nil || len(tool.Capabilities.SupportedOperations) == 0 {
		return false
	}

	return true
}

// measurePerformance measures tool performance
func (dtd *DynamicToolDiscovery) measurePerformance(ctx context.Context, tool *DiscoveredTool) (*PerformanceMetrics, error) {
	// Simple performance measurement - in production, implement comprehensive benchmarking
	metrics := &PerformanceMetrics{
		ID:           uuid.New().String(),
		ToolID:       tool.ID,
		ResponseTime: 100 * time.Millisecond, // Simulated
		Throughput:   100.0,                  // Simulated
		ErrorRate:    0.01,                   // Simulated
		Availability: 0.99,                   // Simulated
		ResourceUsage: &ResourceUsage{
			CPUUsage:     0.1,
			MemoryUsage:  100 * 1024 * 1024, // 100MB
			StorageUsage: 0,
			NetworkUsage: 1024, // 1KB
		},
		BenchmarkResults: make(map[string]float64),
		LastMeasured:     time.Now(),
		Metadata:         make(map[string]interface{}),
	}

	return metrics, nil
}

// GetDiscoveredTools returns all discovered tools
func (dtd *DynamicToolDiscovery) GetDiscoveredTools() []*DiscoveredTool {
	dtd.mutex.RLock()
	defer dtd.mutex.RUnlock()

	tools := make([]*DiscoveredTool, 0, len(dtd.discoveredTools))
	for _, tool := range dtd.discoveredTools {
		tools = append(tools, tool)
	}

	return tools
}

// GetToolByID returns a tool by ID
func (dtd *DynamicToolDiscovery) GetToolByID(toolID string) (*DiscoveredTool, error) {
	dtd.mutex.RLock()
	defer dtd.mutex.RUnlock()

	tool, exists := dtd.discoveredTools[toolID]
	if !exists {
		return nil, fmt.Errorf("tool not found: %s", toolID)
	}

	return tool, nil
}

// GetToolsByCategory returns tools by category
func (dtd *DynamicToolDiscovery) GetToolsByCategory(category ToolCategory) []*DiscoveredTool {
	dtd.mutex.RLock()
	defer dtd.mutex.RUnlock()

	var tools []*DiscoveredTool
	for _, tool := range dtd.discoveredTools {
		if tool.Category == category {
			tools = append(tools, tool)
		}
	}

	return tools
}

// GetToolsByType returns tools by type
func (dtd *DynamicToolDiscovery) GetToolsByType(toolType ToolType) []*DiscoveredTool {
	dtd.mutex.RLock()
	defer dtd.mutex.RUnlock()

	var tools []*DiscoveredTool
	for _, tool := range dtd.discoveredTools {
		if tool.Type == toolType {
			tools = append(tools, tool)
		}
	}

	return tools
}

// IntegrateTool manually integrates a discovered tool
func (dtd *DynamicToolDiscovery) IntegrateTool(ctx context.Context, toolID string) error {
	ctx, span := discoveryTracer.Start(ctx, "dynamic_tool_discovery.integrate_tool",
		trace.WithAttributes(attribute.String("tool.id", toolID)))
	defer span.End()

	tool, err := dtd.GetToolByID(toolID)
	if err != nil {
		span.RecordError(err)
		return err
	}

	if err := dtd.integrationManager.IntegrateTool(ctx, tool); err != nil {
		span.RecordError(err)
		tool.IntegrationStatus = IntegrationStatusFailed
		return fmt.Errorf("integration failed: %w", err)
	}

	tool.IntegrationStatus = IntegrationStatusIntegrated
	dtd.logger.Info("Tool integrated manually", "tool_id", toolID)

	return nil
}

// RemoveTool removes a discovered tool
func (dtd *DynamicToolDiscovery) RemoveTool(toolID string) error {
	dtd.mutex.Lock()
	defer dtd.mutex.Unlock()

	tool, exists := dtd.discoveredTools[toolID]
	if !exists {
		return fmt.Errorf("tool not found: %s", toolID)
	}

	// Remove from integration if integrated
	if tool.IntegrationStatus == IntegrationStatusIntegrated {
		if err := dtd.integrationManager.RemoveTool(toolID); err != nil {
			dtd.logger.Error("Failed to remove tool from integration", "error", err)
		}
	}

	delete(dtd.discoveredTools, toolID)
	delete(dtd.toolCapabilities, toolID)

	dtd.logger.Info("Tool removed", "tool_id", toolID)
	return nil
}

// RegisterDiscoveryEngine registers a new discovery engine
func (dtd *DynamicToolDiscovery) RegisterDiscoveryEngine(name string, engine DiscoveryEngine) error {
	dtd.mutex.Lock()
	defer dtd.mutex.Unlock()

	if _, exists := dtd.discoveryEngines[name]; exists {
		return fmt.Errorf("discovery engine already registered: %s", name)
	}

	dtd.discoveryEngines[name] = engine
	dtd.logger.Info("Discovery engine registered", "name", name)

	return nil
}

// UnregisterDiscoveryEngine unregisters a discovery engine
func (dtd *DynamicToolDiscovery) UnregisterDiscoveryEngine(name string) error {
	dtd.mutex.Lock()
	defer dtd.mutex.Unlock()

	if _, exists := dtd.discoveryEngines[name]; !exists {
		return fmt.Errorf("discovery engine not found: %s", name)
	}

	delete(dtd.discoveryEngines, name)
	dtd.logger.Info("Discovery engine unregistered", "name", name)

	return nil
}

// GetDiscoveryStats returns discovery statistics
func (dtd *DynamicToolDiscovery) GetDiscoveryStats() *DiscoveryStats {
	dtd.mutex.RLock()
	defer dtd.mutex.RUnlock()

	stats := &DiscoveryStats{
		TotalTools:      len(dtd.discoveredTools),
		IntegratedTools: 0,
		FailedTools:     0,
		ByCategory:      make(map[ToolCategory]int),
		ByType:          make(map[ToolType]int),
		BySource:        make(map[ToolSource]int),
		LastDiscovery:   time.Time{},
	}

	for _, tool := range dtd.discoveredTools {
		if tool.IntegrationStatus == IntegrationStatusIntegrated {
			stats.IntegratedTools++
		} else if tool.IntegrationStatus == IntegrationStatusFailed {
			stats.FailedTools++
		}

		stats.ByCategory[tool.Category]++
		stats.ByType[tool.Type]++
		stats.BySource[tool.Source]++

		if tool.DiscoveredAt.After(stats.LastDiscovery) {
			stats.LastDiscovery = tool.DiscoveredAt
		}
	}

	return stats
}

// DiscoveryStats represents discovery statistics
type DiscoveryStats struct {
	TotalTools      int                  `json:"total_tools"`
	IntegratedTools int                  `json:"integrated_tools"`
	FailedTools     int                  `json:"failed_tools"`
	ByCategory      map[ToolCategory]int `json:"by_category"`
	ByType          map[ToolType]int     `json:"by_type"`
	BySource        map[ToolSource]int   `json:"by_source"`
	LastDiscovery   time.Time            `json:"last_discovery"`
}

// Stop stops the discovery system
func (dtd *DynamicToolDiscovery) Stop() error {
	dtd.logger.Info("Stopping dynamic tool discovery")

	if dtd.discoveryScheduler != nil {
		dtd.discoveryScheduler.Stop()
	}

	return nil
}
