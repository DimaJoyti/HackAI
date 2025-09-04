package mcp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var securityMCPTracer = otel.Tracer("hackai/mcp/security_server")

// Constants for error messages
const (
	ErrServerNotInitialized = "Server not initialized"
	ErrServerAlreadyInit    = "Server already initialized"
)

// SecurityMCPServer implements MCP server for security operations
type SecurityMCPServer struct {
	logger               *logger.Logger
	config               *SecurityMCPConfig
	aiSecurityFramework  *security.AgenticSecurityFramework
	threatIntelligence   *security.ThreatIntelligenceOrchestrator
	vulnerabilityScanner *security.VulnerabilityScanner
	complianceEngine     *security.ComplianceEngine
	incidentManager      *security.IncidentManager

	// MCP state
	initialized        bool
	clientCapabilities *ClientCapabilities
	serverCapabilities *ServerCapabilities
	logLevel           LogLevel

	// Security tools registry
	tools     map[string]SecurityTool
	resources map[string]SecurityResource
	prompts   map[string]SecurityPrompt

	// Synchronization
	mu sync.RWMutex

	// Active operations tracking
	activeScans          map[string]*SecurityScanOperation
	activeThreatAnalysis map[string]*ThreatAnalysisOperation

	// Connection management
	connectedClients map[string]*ClientConnection

	// Notification channels
	notificationChan chan *MCPNotification
	shutdownChan     chan struct{}

	// Rate limiting
	rateLimiter *SecurityRateLimiter

	// Metrics and monitoring
	metrics *SecurityMCPMetrics

	// Security integration
	securityIntegration *SimpleSecurityIntegration
}

// SecurityMCPConfig holds configuration for the Security MCP server
type SecurityMCPConfig struct {
	ServerName           string        `json:"server_name"`
	ServerVersion        string        `json:"server_version"`
	MaxConcurrentScans   int           `json:"max_concurrent_scans"`
	ScanTimeout          time.Duration `json:"scan_timeout"`
	EnableRealTimeAlerts bool          `json:"enable_realtime_alerts"`
	ThreatThreshold      float64       `json:"threat_threshold"`
	LogLevel             LogLevel      `json:"log_level"`
	EnableAuditLogging   bool          `json:"enable_audit_logging"`
}

// SecurityTool represents a security tool available via MCP
type SecurityTool struct {
	Name        string
	Description string
	Schema      ToolSchema
	Handler     SecurityToolHandler
}

// SecurityResource represents a security resource available via MCP
type SecurityResource struct {
	URI         string
	Name        string
	Description string
	MimeType    string
	Handler     SecurityResourceHandler
}

// SecurityPrompt represents a security prompt template available via MCP
type SecurityPrompt struct {
	Name        string
	Description string
	Arguments   []PromptArgument
	Handler     SecurityPromptHandler
}

// Handler function types
type SecurityToolHandler func(ctx context.Context, params map[string]interface{}) (*CallToolResult, error)
type SecurityResourceHandler func(ctx context.Context, uri string) (*ReadResourceResult, error)
type SecurityPromptHandler func(ctx context.Context, args map[string]interface{}) (*GetPromptResult, error)

// Operation tracking types
type SecurityScanOperation struct {
	ID        string
	Type      string
	Status    string
	StartTime time.Time
	Context   SecurityContext
	Results   *SecurityScanResult
}

type ThreatAnalysisOperation struct {
	ID        string
	Input     string
	Status    string
	StartTime time.Time
	Context   SecurityContext
	Results   *security.SecurityAnalysis
}

// NewSecurityMCPServer creates a new Security MCP server
func NewSecurityMCPServer(
	config *SecurityMCPConfig,
	logger *logger.Logger,
	aiSecurityFramework *security.AgenticSecurityFramework,
	threatIntelligence *security.ThreatIntelligenceOrchestrator,
) *SecurityMCPServer {
	if config == nil {
		config = DefaultSecurityMCPConfig()
	}

	// Initialize security components if not provided
	if aiSecurityFramework == nil {
		agenticConfig := security.DefaultAgenticConfig()
		aiSecurityFramework = security.NewAgenticSecurityFramework(agenticConfig, logger)
	}

	if threatIntelligence == nil {
		threatConfig := security.DefaultThreatOrchestratorConfig()

		// Initialize with minimal components for MCP integration
		mitreConfig := security.DefaultMITREATTACKConfig()
		mitreConnector := security.NewMITREATTACKConnector(mitreConfig, logger)

		cveConfig := security.DefaultCVEConfig()
		cveConnector := security.NewCVEConnector(cveConfig, logger)

		threatIntelligence = security.NewThreatIntelligenceOrchestrator(
			threatConfig,
			mitreConnector,
			cveConnector,
			nil, // Threat engine
			nil, // Feed manager
			nil, // IOC database
			nil, // Reputation engine
			nil, // Threat cache
			logger,
		)
	}

	server := &SecurityMCPServer{
		logger:               logger,
		config:               config,
		aiSecurityFramework:  aiSecurityFramework,
		threatIntelligence:   threatIntelligence,
		logLevel:             config.LogLevel,
		tools:                make(map[string]SecurityTool),
		resources:            make(map[string]SecurityResource),
		prompts:              make(map[string]SecurityPrompt),
		activeScans:          make(map[string]*SecurityScanOperation),
		activeThreatAnalysis: make(map[string]*ThreatAnalysisOperation),
		connectedClients:     make(map[string]*ClientConnection),
		notificationChan:     make(chan *MCPNotification, 100),
		shutdownChan:         make(chan struct{}),
		rateLimiter:          NewSecurityRateLimiter(config),
		metrics:              NewSecurityMCPMetrics(),
		securityIntegration:  NewSimpleSecurityIntegration(logger),
	}

	// Initialize server capabilities
	server.serverCapabilities = &ServerCapabilities{
		Logging: &LoggingCapability{},
		Tools: &ToolsCapability{
			ListChanged: true,
		},
		Resources: &ResourcesCapability{
			Subscribe:   true,
			ListChanged: true,
		},
		Prompts: &PromptsCapability{
			ListChanged: true,
		},
	}

	// Initialize security integration
	ctx := context.Background()
	if err := server.securityIntegration.Initialize(ctx); err != nil {
		logger.Error("Failed to initialize security integration", "error", err)
		// Continue with limited functionality
	}

	// Register default security tools
	server.registerDefaultTools()
	server.registerAdvancedSecurityTools()
	server.registerDefaultResources()
	server.registerDefaultPrompts()

	return server
}

// DefaultSecurityMCPConfig returns default configuration
func DefaultSecurityMCPConfig() *SecurityMCPConfig {
	return &SecurityMCPConfig{
		ServerName:           "HackAI Security MCP Server",
		ServerVersion:        "1.0.0",
		MaxConcurrentScans:   10,
		ScanTimeout:          5 * time.Minute,
		EnableRealTimeAlerts: true,
		ThreatThreshold:      0.7,
		LogLevel:             LogLevelInfo,
		EnableAuditLogging:   true,
	}
}

// NewSecurityRateLimiter creates a new rate limiter
func NewSecurityRateLimiter(config *SecurityMCPConfig) *SecurityRateLimiter {
	return &SecurityRateLimiter{
		MaxRequestsPerMinute: 1000, // Default rate limit
		MaxConcurrentOps:     config.MaxConcurrentScans,
		ClientLimits:         make(map[string]*RateLimit),
		GlobalLimit: &RateLimit{
			Requests:      0,
			WindowStart:   time.Now(),
			ConcurrentOps: 0,
		},
	}
}

// NewSecurityMCPMetrics creates a new metrics tracker
func NewSecurityMCPMetrics() *SecurityMCPMetrics {
	return &SecurityMCPMetrics{
		TotalRequests:          0,
		SuccessfulRequests:     0,
		FailedRequests:         0,
		ActiveConnections:      0,
		TotalConnections:       0,
		AverageResponseTime:    0,
		ThreatAnalysisCount:    0,
		VulnerabilityScanCount: 0,
		ComplianceCheckCount:   0,
		IncidentResponseCount:  0,
		ThreatIntelCount:       0,
		LastUpdated:            time.Now(),
	}
}

// Initialize implements MCPServer.Initialize
func (s *SecurityMCPServer) Initialize(ctx context.Context, params *InitializeParams) (*InitializeResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.initialize")
	defer span.End()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.initialized {
		return nil, &MCPError{
			Code:    ErrorCodeInvalidRequest,
			Message: ErrServerAlreadyInit,
		}
	}

	// Validate protocol version
	if params.ProtocolVersion != MCPVersion {
		return nil, &MCPError{
			Code:    ErrorCodeInvalidRequest,
			Message: fmt.Sprintf("Unsupported protocol version: %s", params.ProtocolVersion),
		}
	}

	// Store client capabilities
	s.clientCapabilities = &params.Capabilities

	// Create client connection
	clientID := fmt.Sprintf("client-%d", time.Now().UnixNano())
	clientConn := &ClientConnection{
		ID:           clientID,
		ClientInfo:   params.ClientInfo,
		Capabilities: params.Capabilities,
		ConnectedAt:  time.Now(),
		LastActivity: time.Now(),
		Metadata:     params.Meta,
	}
	s.connectedClients[clientID] = clientConn

	// Update metrics
	s.metrics.mu.Lock()
	s.metrics.ActiveConnections++
	s.metrics.TotalConnections++
	s.metrics.LastUpdated = time.Now()
	s.metrics.mu.Unlock()

	// Mark as initialized
	s.initialized = true

	span.SetAttributes(
		attribute.String("client.name", params.ClientInfo.Name),
		attribute.String("client.version", params.ClientInfo.Version),
		attribute.String("protocol.version", params.ProtocolVersion),
	)

	s.logger.Info("Security MCP server initialized",
		"client_name", params.ClientInfo.Name,
		"client_version", params.ClientInfo.Version,
		"protocol_version", params.ProtocolVersion,
	)

	return &InitializeResult{
		ProtocolVersion: MCPVersion,
		Capabilities:    *s.serverCapabilities,
		ServerInfo: ServerInfo{
			Name:    s.config.ServerName,
			Version: s.config.ServerVersion,
		},
		Instructions: "HackAI Security MCP Server provides comprehensive AI security tools, threat analysis, vulnerability scanning, and compliance checking capabilities.",
	}, nil
}

// Shutdown implements MCPServer.Shutdown
func (s *SecurityMCPServer) Shutdown(ctx context.Context) error {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.shutdown")
	defer span.End()

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return &MCPError{
			Code:    ErrorCodeInvalidRequest,
			Message: ErrServerNotInitialized,
		}
	}

	// Signal shutdown
	close(s.shutdownChan)

	// Cancel all active operations
	for scanID := range s.activeScans {
		delete(s.activeScans, scanID)
	}

	for analysisID := range s.activeThreatAnalysis {
		delete(s.activeThreatAnalysis, analysisID)
	}

	// Disconnect all clients
	for clientID := range s.connectedClients {
		delete(s.connectedClients, clientID)
	}

	// Update metrics
	s.metrics.mu.Lock()
	s.metrics.ActiveConnections = 0
	s.metrics.LastUpdated = time.Now()
	s.metrics.mu.Unlock()

	// Close notification channel
	close(s.notificationChan)

	s.initialized = false

	s.logger.Info("Security MCP server shutdown completed")
	return nil
}

// ListTools implements MCPServer.ListTools
func (s *SecurityMCPServer) ListTools(ctx context.Context, params *ListToolsParams) (*ListToolsResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.list_tools")
	defer span.End()

	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, &MCPError{
			Code:    ErrorCodeInvalidRequest,
			Message: ErrServerNotInitialized,
		}
	}

	tools := make([]Tool, 0, len(s.tools))
	for _, secTool := range s.tools {
		tools = append(tools, Tool{
			Name:        secTool.Name,
			Description: secTool.Description,
			InputSchema: secTool.Schema,
		})
	}

	span.SetAttributes(attribute.Int("tools.count", len(tools)))

	return &ListToolsResult{
		Tools: tools,
	}, nil
}

// CallTool implements MCPServer.CallTool
func (s *SecurityMCPServer) CallTool(ctx context.Context, params *CallToolParams) (*CallToolResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.call_tool",
		trace.WithAttributes(attribute.String("tool.name", params.Name)),
	)
	defer span.End()

	// Check rate limiting
	if !s.checkRateLimit("default") {
		s.metrics.mu.Lock()
		s.metrics.FailedRequests++
		s.metrics.mu.Unlock()

		return nil, &MCPError{
			Code:    ErrorCodeServerError,
			Message: "Rate limit exceeded",
		}
	}

	// Update metrics
	s.metrics.mu.Lock()
	s.metrics.TotalRequests++
	s.metrics.mu.Unlock()

	s.mu.RLock()
	tool, exists := s.tools[params.Name]
	s.mu.RUnlock()

	if !exists {
		s.metrics.mu.Lock()
		s.metrics.FailedRequests++
		s.metrics.mu.Unlock()

		return nil, &MCPError{
			Code:    ErrorCodeMethodNotFound,
			Message: fmt.Sprintf("Tool not found: %s", params.Name),
		}
	}

	// Execute the tool
	startTime := time.Now()
	result, err := tool.Handler(ctx, params.Arguments)
	duration := time.Since(startTime)

	// Update metrics
	s.updateToolMetrics(params.Name, err == nil && !result.IsError)

	// Update average response time
	s.metrics.mu.Lock()
	if s.metrics.TotalRequests > 0 {
		s.metrics.AverageResponseTime = (s.metrics.AverageResponseTime*time.Duration(s.metrics.TotalRequests-1) + duration) / time.Duration(s.metrics.TotalRequests)
	} else {
		s.metrics.AverageResponseTime = duration
	}
	s.metrics.mu.Unlock()

	// Release rate limit
	defer s.releaseRateLimit("default")

	if err != nil {
		span.RecordError(err)
		return &CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: fmt.Sprintf("Tool execution failed: %v", err),
			}},
			IsError: true,
		}, nil
	}

	span.SetAttributes(
		attribute.Bool("tool.success", !result.IsError),
		attribute.Int64("tool.duration_ms", duration.Milliseconds()),
	)

	s.logger.Debug("Security tool executed",
		"tool_name", params.Name,
		"success", !result.IsError,
		"duration_ms", duration.Milliseconds(),
	)

	return result, nil
}

// ListResources implements MCPServer.ListResources
func (s *SecurityMCPServer) ListResources(ctx context.Context, params *ListResourcesParams) (*ListResourcesResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.list_resources")
	defer span.End()

	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, &MCPError{
			Code:    ErrorCodeInvalidRequest,
			Message: ErrServerNotInitialized,
		}
	}

	resources := make([]Resource, 0, len(s.resources))
	for _, secResource := range s.resources {
		resources = append(resources, Resource{
			URI:         secResource.URI,
			Name:        secResource.Name,
			Description: secResource.Description,
			MimeType:    secResource.MimeType,
		})
	}

	span.SetAttributes(attribute.Int("resources.count", len(resources)))

	return &ListResourcesResult{
		Resources: resources,
	}, nil
}

// ReadResource implements MCPServer.ReadResource
func (s *SecurityMCPServer) ReadResource(ctx context.Context, params *ReadResourceParams) (*ReadResourceResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.read_resource",
		trace.WithAttributes(attribute.String("resource.uri", params.URI)),
	)
	defer span.End()

	s.mu.RLock()
	resource, exists := s.resources[params.URI]
	s.mu.RUnlock()

	if !exists {
		return nil, &MCPError{
			Code:    ErrorCodeMethodNotFound,
			Message: fmt.Sprintf("Resource not found: %s", params.URI),
		}
	}

	// Execute the resource handler
	result, err := resource.Handler(ctx, params.URI)
	if err != nil {
		span.RecordError(err)
		return nil, &MCPError{
			Code:    ErrorCodeInternalError,
			Message: fmt.Sprintf("Failed to read resource: %v", err),
		}
	}

	s.logger.Debug("Security resource read",
		"resource_uri", params.URI,
	)

	return result, nil
}

// ListPrompts implements MCPServer.ListPrompts
func (s *SecurityMCPServer) ListPrompts(ctx context.Context, params *ListPromptsParams) (*ListPromptsResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.list_prompts")
	defer span.End()

	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, &MCPError{
			Code:    ErrorCodeInvalidRequest,
			Message: ErrServerNotInitialized,
		}
	}

	prompts := make([]Prompt, 0, len(s.prompts))
	for _, secPrompt := range s.prompts {
		prompts = append(prompts, Prompt{
			Name:        secPrompt.Name,
			Description: secPrompt.Description,
			Arguments:   secPrompt.Arguments,
		})
	}

	span.SetAttributes(attribute.Int("prompts.count", len(prompts)))

	return &ListPromptsResult{
		Prompts: prompts,
	}, nil
}

// GetPrompt implements MCPServer.GetPrompt
func (s *SecurityMCPServer) GetPrompt(ctx context.Context, params *GetPromptParams) (*GetPromptResult, error) {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.get_prompt",
		trace.WithAttributes(attribute.String("prompt.name", params.Name)),
	)
	defer span.End()

	s.mu.RLock()
	prompt, exists := s.prompts[params.Name]
	s.mu.RUnlock()

	if !exists {
		return nil, &MCPError{
			Code:    ErrorCodeMethodNotFound,
			Message: fmt.Sprintf("Prompt not found: %s", params.Name),
		}
	}

	// Execute the prompt handler
	result, err := prompt.Handler(ctx, params.Arguments)
	if err != nil {
		span.RecordError(err)
		return nil, &MCPError{
			Code:    ErrorCodeInternalError,
			Message: fmt.Sprintf("Failed to get prompt: %v", err),
		}
	}

	s.logger.Debug("Security prompt retrieved",
		"prompt_name", params.Name,
	)

	return result, nil
}

// SetLogLevel implements MCPServer.SetLogLevel
func (s *SecurityMCPServer) SetLogLevel(ctx context.Context, params *SetLogLevelParams) error {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.set_log_level",
		trace.WithAttributes(attribute.String("log.level", string(params.Level))),
	)
	defer span.End()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.logLevel = params.Level

	s.logger.Info("Log level changed",
		"new_level", string(params.Level),
	)

	return nil
}

// SendNotification implements MCPServer.SendNotification
func (s *SecurityMCPServer) SendNotification(ctx context.Context, method string, params interface{}) error {
	ctx, span := securityMCPTracer.Start(ctx, "security_mcp.send_notification",
		trace.WithAttributes(attribute.String("notification.method", method)),
	)
	defer span.End()

	// In a real implementation, this would send notifications to connected clients
	s.logger.Debug("Notification sent",
		"method", method,
		"params", params,
	)

	return nil
}

// registerDefaultTools registers the default security tools
func (s *SecurityMCPServer) registerDefaultTools() {
	// Threat Analysis Tool
	s.tools["threat_analysis"] = SecurityTool{
		Name:        "threat_analysis",
		Description: "Analyze input for security threats using AI-powered detection",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"input": map[string]interface{}{
					"type":        "string",
					"description": "The input text to analyze for threats",
				},
				"context": map[string]interface{}{
					"type":        "object",
					"description": "Security context for the analysis",
				},
			},
			Required: []string{"input"},
		},
		Handler: s.handleThreatAnalysis,
	}

	// Vulnerability Scan Tool
	s.tools["vulnerability_scan"] = SecurityTool{
		Name:        "vulnerability_scan",
		Description: "Perform vulnerability scanning on targets",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"target": map[string]interface{}{
					"type":        "string",
					"description": "The target to scan (URL, IP, etc.)",
				},
				"scan_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of scan to perform",
					"enum":        []string{"web", "network", "api", "container"},
				},
				"options": map[string]interface{}{
					"type":        "object",
					"description": "Additional scan options",
				},
			},
			Required: []string{"target", "scan_type"},
		},
		Handler: s.handleVulnerabilityScan,
	}

	// Compliance Check Tool
	s.tools["compliance_check"] = SecurityTool{
		Name:        "compliance_check",
		Description: "Check compliance against security frameworks",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"framework": map[string]interface{}{
					"type":        "string",
					"description": "Compliance framework to check against",
					"enum":        []string{"OWASP", "NIST", "ISO27001", "SOC2", "GDPR"},
				},
				"target": map[string]interface{}{
					"type":        "string",
					"description": "Target system or application to check",
				},
				"scope": map[string]interface{}{
					"type":        "array",
					"description": "Specific controls or areas to check",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
			},
			Required: []string{"framework", "target"},
		},
		Handler: s.handleComplianceCheck,
	}

	// Incident Response Tool
	s.tools["incident_response"] = SecurityTool{
		Name:        "incident_response",
		Description: "Manage security incidents and response actions",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"action": map[string]interface{}{
					"type":        "string",
					"description": "Action to perform",
					"enum":        []string{"create", "update", "escalate", "resolve", "investigate"},
				},
				"incident_id": map[string]interface{}{
					"type":        "string",
					"description": "Incident ID (for update/escalate/resolve actions)",
				},
				"details": map[string]interface{}{
					"type":        "object",
					"description": "Incident details",
				},
			},
			Required: []string{"action"},
		},
		Handler: s.handleIncidentResponse,
	}

	// Threat Intelligence Tool
	s.tools["threat_intelligence"] = SecurityTool{
		Name:        "threat_intelligence",
		Description: "Query threat intelligence feeds and databases",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"query_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of threat intelligence query",
					"enum":        []string{"ioc", "cve", "mitre", "reputation", "feed"},
				},
				"indicators": map[string]interface{}{
					"type":        "array",
					"description": "Indicators of compromise to query",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
				"sources": map[string]interface{}{
					"type":        "array",
					"description": "Specific threat intelligence sources to query",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
			},
			Required: []string{"query_type"},
		},
		Handler: s.handleThreatIntelligence,
	}
}

// registerDefaultResources registers the default security resources
func (s *SecurityMCPServer) registerDefaultResources() {
	// Security Reports Resource
	s.resources["security://reports"] = SecurityResource{
		URI:         "security://reports",
		Name:        "Security Reports",
		Description: "Access to security scan reports and analysis results",
		MimeType:    MimeTypeJSON,
		Handler:     s.handleSecurityReports,
	}

	// Threat Intelligence Resource
	s.resources["security://threat-intel"] = SecurityResource{
		URI:         "security://threat-intel",
		Name:        "Threat Intelligence",
		Description: "Access to threat intelligence data and feeds",
		MimeType:    MimeTypeJSON,
		Handler:     s.handleThreatIntelResource,
	}

	// Compliance Reports Resource
	s.resources["security://compliance"] = SecurityResource{
		URI:         "security://compliance",
		Name:        "Compliance Reports",
		Description: "Access to compliance check results and frameworks",
		MimeType:    MimeTypeJSON,
		Handler:     s.handleComplianceResource,
	}

	// Security Metrics Resource
	s.resources["security://metrics"] = SecurityResource{
		URI:         "security://metrics",
		Name:        "Security Metrics",
		Description: "Access to security metrics and KPIs",
		MimeType:    MimeTypeJSON,
		Handler:     s.handleSecurityMetrics,
	}
}

// registerDefaultPrompts registers the default security prompts
func (s *SecurityMCPServer) registerDefaultPrompts() {
	// Threat Analysis Prompt
	s.prompts["threat_analysis_prompt"] = SecurityPrompt{
		Name:        "threat_analysis_prompt",
		Description: "Generate prompts for threat analysis and security assessment",
		Arguments: []PromptArgument{
			{
				Name:        "input_type",
				Description: "Type of input to analyze (text, code, url, etc.)",
				Required:    true,
			},
			{
				Name:        "analysis_depth",
				Description: "Depth of analysis (basic, detailed, comprehensive)",
				Required:    false,
			},
		},
		Handler: s.handleThreatAnalysisPrompt,
	}

	// Security Assessment Prompt
	s.prompts["security_assessment_prompt"] = SecurityPrompt{
		Name:        "security_assessment_prompt",
		Description: "Generate prompts for comprehensive security assessments",
		Arguments: []PromptArgument{
			{
				Name:        "target_type",
				Description: "Type of target to assess (web_app, api, network, etc.)",
				Required:    true,
			},
			{
				Name:        "framework",
				Description: "Security framework to use (OWASP, NIST, etc.)",
				Required:    false,
			},
		},
		Handler: s.handleSecurityAssessmentPrompt,
	}

	// Incident Response Prompt
	s.prompts["incident_response_prompt"] = SecurityPrompt{
		Name:        "incident_response_prompt",
		Description: "Generate prompts for incident response procedures",
		Arguments: []PromptArgument{
			{
				Name:        "incident_type",
				Description: "Type of security incident",
				Required:    true,
			},
			{
				Name:        "severity",
				Description: "Incident severity level",
				Required:    false,
			},
		},
		Handler: s.handleIncidentResponsePrompt,
	}
}

// checkRateLimit checks if the request is within rate limits
func (s *SecurityMCPServer) checkRateLimit(clientID string) bool {
	s.rateLimiter.mu.Lock()
	defer s.rateLimiter.mu.Unlock()

	now := time.Now()

	// Check global rate limit
	if now.Sub(s.rateLimiter.GlobalLimit.WindowStart) > time.Minute {
		s.rateLimiter.GlobalLimit.Requests = 0
		s.rateLimiter.GlobalLimit.WindowStart = now
	}

	if s.rateLimiter.GlobalLimit.Requests >= s.rateLimiter.MaxRequestsPerMinute {
		return false
	}

	// Check client-specific rate limit
	clientLimit, exists := s.rateLimiter.ClientLimits[clientID]
	if !exists {
		clientLimit = &RateLimit{
			Requests:      0,
			WindowStart:   now,
			ConcurrentOps: 0,
		}
		s.rateLimiter.ClientLimits[clientID] = clientLimit
	}

	if now.Sub(clientLimit.WindowStart) > time.Minute {
		clientLimit.Requests = 0
		clientLimit.WindowStart = now
	}

	if clientLimit.Requests >= s.rateLimiter.MaxRequestsPerMinute {
		return false
	}

	// Check concurrent operations
	if clientLimit.ConcurrentOps >= s.rateLimiter.MaxConcurrentOps {
		return false
	}

	// Update counters
	s.rateLimiter.GlobalLimit.Requests++
	clientLimit.Requests++
	clientLimit.ConcurrentOps++

	return true
}

// releaseRateLimit releases a concurrent operation slot
func (s *SecurityMCPServer) releaseRateLimit(clientID string) {
	s.rateLimiter.mu.Lock()
	defer s.rateLimiter.mu.Unlock()

	if clientLimit, exists := s.rateLimiter.ClientLimits[clientID]; exists {
		if clientLimit.ConcurrentOps > 0 {
			clientLimit.ConcurrentOps--
		}
	}
}

// GetMetrics returns current server metrics
func (s *SecurityMCPServer) GetMetrics() *SecurityMCPMetrics {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := *s.metrics
	return &metrics
}

// GetConnectedClients returns information about connected clients
func (s *SecurityMCPServer) GetConnectedClients() map[string]*ClientConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make(map[string]*ClientConnection)
	for id, conn := range s.connectedClients {
		// Create a copy to avoid race conditions
		clientCopy := *conn
		clients[id] = &clientCopy
	}

	return clients
}

// SendNotificationToClients sends a notification to all connected clients
func (s *SecurityMCPServer) SendNotificationToClients(method string, params interface{}) {
	notification := &MCPNotification{
		Method:    method,
		Params:    params,
		Timestamp: time.Now(),
	}

	select {
	case s.notificationChan <- notification:
		s.logger.Debug("Notification queued", "method", method)
	default:
		s.logger.Warn("Notification channel full, dropping notification", "method", method)
	}
}

// updateToolMetrics updates metrics for tool usage
func (s *SecurityMCPServer) updateToolMetrics(toolName string, success bool) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()

	if success {
		s.metrics.SuccessfulRequests++
	} else {
		s.metrics.FailedRequests++
	}

	switch toolName {
	case "threat_analysis":
		s.metrics.ThreatAnalysisCount++
	case "vulnerability_scan":
		s.metrics.VulnerabilityScanCount++
	case "compliance_check":
		s.metrics.ComplianceCheckCount++
	case "incident_response":
		s.metrics.IncidentResponseCount++
	case "threat_intelligence":
		s.metrics.ThreatIntelCount++
	}

	s.metrics.LastUpdated = time.Now()
}

// GetHealthStatus returns the health status of the server
func (s *SecurityMCPServer) GetHealthStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := map[string]interface{}{
		"status":      "healthy",
		"initialized": s.initialized,
		"server_info": map[string]interface{}{
			"name":    s.config.ServerName,
			"version": s.config.ServerVersion,
		},
		"capabilities": map[string]interface{}{
			"tools_count":     len(s.tools),
			"resources_count": len(s.resources),
			"prompts_count":   len(s.prompts),
		},
		"operations": map[string]interface{}{
			"active_scans":           len(s.activeScans),
			"active_threat_analysis": len(s.activeThreatAnalysis),
		},
		"connections": map[string]interface{}{
			"connected_clients": len(s.connectedClients),
		},
		"timestamp": time.Now(),
	}

	// Add metrics if available
	if s.metrics != nil {
		s.metrics.mu.RLock()
		status["metrics"] = map[string]interface{}{
			"total_requests":           s.metrics.TotalRequests,
			"successful_requests":      s.metrics.SuccessfulRequests,
			"failed_requests":          s.metrics.FailedRequests,
			"active_connections":       s.metrics.ActiveConnections,
			"total_connections":        s.metrics.TotalConnections,
			"average_response_time_ms": s.metrics.AverageResponseTime.Milliseconds(),
			"threat_analysis_count":    s.metrics.ThreatAnalysisCount,
			"vulnerability_scan_count": s.metrics.VulnerabilityScanCount,
			"compliance_check_count":   s.metrics.ComplianceCheckCount,
			"incident_response_count":  s.metrics.IncidentResponseCount,
			"threat_intel_count":       s.metrics.ThreatIntelCount,
		}
		s.metrics.mu.RUnlock()
	}

	// Check if any critical issues
	if !s.initialized {
		status["status"] = "unhealthy"
		status["issues"] = []string{"Server not initialized"}
	}

	return status
}

// IsHealthy returns true if the server is healthy
func (s *SecurityMCPServer) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.initialized && s.aiSecurityFramework != nil
}

// GetReadinessStatus returns the readiness status of the server
func (s *SecurityMCPServer) GetReadinessStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ready := s.initialized &&
		s.aiSecurityFramework != nil &&
		s.threatIntelligence != nil &&
		len(s.tools) > 0

	status := map[string]interface{}{
		"ready":       ready,
		"initialized": s.initialized,
		"components": map[string]interface{}{
			"ai_security_framework": s.aiSecurityFramework != nil,
			"threat_intelligence":   s.threatIntelligence != nil,
			"tools_registered":      len(s.tools) > 0,
			"resources_registered":  len(s.resources) > 0,
			"prompts_registered":    len(s.prompts) > 0,
		},
		"timestamp": time.Now(),
	}

	if !ready {
		issues := make([]string, 0)
		if !s.initialized {
			issues = append(issues, "Server not initialized")
		}
		if s.aiSecurityFramework == nil {
			issues = append(issues, "AI Security Framework not available")
		}
		if s.threatIntelligence == nil {
			issues = append(issues, "Threat Intelligence not available")
		}
		if len(s.tools) == 0 {
			issues = append(issues, "No security tools registered")
		}
		status["issues"] = issues
	}

	return status
}
