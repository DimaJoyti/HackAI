package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var securityMCPClientTracer = otel.Tracer("hackai/mcp/security_client")

// SecurityMCPClient implements MCP client for security operations
type SecurityMCPClient struct {
	logger             *logger.Logger
	config             *SecurityMCPClientConfig
	serverURL          string
	httpClient         *http.Client
	connected          bool
	serverCapabilities *ServerCapabilities

	// Event handlers
	notificationHandler NotificationHandler
	errorHandler        ErrorHandler

	// Connection state
	connectionID      string
	lastActivity      time.Time
	reconnectAttempts int

	// Request tracking
	requestCounter int64
	activeRequests map[string]*ActiveRequest

	// Caching
	toolsCache     *ToolsCache
	resourcesCache *ResourcesCache
	promptsCache   *PromptsCache

	// Metrics
	metrics *ClientMetrics

	// Synchronization
	mu sync.RWMutex
}

// SecurityMCPClientConfig holds configuration for the Security MCP client
type SecurityMCPClientConfig struct {
	ClientName    string        `json:"client_name"`
	ClientVersion string        `json:"client_version"`
	Timeout       time.Duration `json:"timeout"`
	MaxRetries    int           `json:"max_retries"`
	RetryDelay    time.Duration `json:"retry_delay"`
	EnableTracing bool          `json:"enable_tracing"`
	EnableMetrics bool          `json:"enable_metrics"`
	CacheTTL      time.Duration `json:"cache_ttl"`
}

// NewSecurityMCPClient creates a new Security MCP client
func NewSecurityMCPClient(config *SecurityMCPClientConfig, logger *logger.Logger) *SecurityMCPClient {
	if config == nil {
		config = DefaultSecurityMCPClientConfig()
	}

	return &SecurityMCPClient{
		logger: logger,
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		connected:         false,
		activeRequests:    make(map[string]*ActiveRequest),
		toolsCache:        &ToolsCache{TTL: config.CacheTTL},
		resourcesCache:    &ResourcesCache{TTL: config.CacheTTL},
		promptsCache:      &PromptsCache{TTL: config.CacheTTL},
		metrics:           &ClientMetrics{},
		reconnectAttempts: 0,
	}
}

// DefaultSecurityMCPClientConfig returns default client configuration
func DefaultSecurityMCPClientConfig() *SecurityMCPClientConfig {
	return &SecurityMCPClientConfig{
		ClientName:    "HackAI Security MCP Client",
		ClientVersion: "1.0.0",
		Timeout:       30 * time.Second,
		MaxRetries:    3,
		RetryDelay:    1 * time.Second,
		EnableTracing: true,
		EnableMetrics: true,
		CacheTTL:      5 * time.Minute,
	}
}

// Connect implements MCPClient.Connect
func (c *SecurityMCPClient) Connect(ctx context.Context, serverURL string) error {
	ctx, span := securityMCPClientTracer.Start(ctx, "security_mcp_client.connect",
		trace.WithAttributes(attribute.String("server.url", serverURL)),
	)
	defer span.End()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return fmt.Errorf("client already connected")
	}

	c.serverURL = serverURL

	// Initialize connection with the server
	initParams := &InitializeParams{
		ProtocolVersion: MCPVersion,
		Capabilities: ClientCapabilities{
			Experimental: map[string]interface{}{
				"security_extensions": true,
			},
		},
		ClientInfo: ClientInfo{
			Name:    c.config.ClientName,
			Version: c.config.ClientVersion,
		},
	}

	result, err := c.Initialize(ctx, initParams)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to initialize connection: %w", err)
	}

	c.serverCapabilities = &result.Capabilities
	c.connected = true

	c.logger.Info("Connected to Security MCP server",
		"server_url", serverURL,
		"server_name", result.ServerInfo.Name,
		"server_version", result.ServerInfo.Version,
	)

	return nil
}

// Disconnect implements MCPClient.Disconnect
func (c *SecurityMCPClient) Disconnect(ctx context.Context) error {
	ctx, span := securityMCPClientTracer.Start(ctx, "security_mcp_client.disconnect")
	defer span.End()

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return fmt.Errorf("client not connected")
	}

	c.connected = false
	c.serverURL = ""
	c.serverCapabilities = nil

	c.logger.Info("Disconnected from Security MCP server")
	return nil
}

// IsConnected implements MCPClient.IsConnected
func (c *SecurityMCPClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// Initialize implements MCPClient.Initialize
func (c *SecurityMCPClient) Initialize(ctx context.Context, params *InitializeParams) (*InitializeResult, error) {
	ctx, span := securityMCPClientTracer.Start(ctx, "security_mcp_client.initialize")
	defer span.End()

	result := &InitializeResult{}
	err := c.sendRequest(ctx, "initialize", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListTools implements MCPClient.ListTools
func (c *SecurityMCPClient) ListTools(ctx context.Context) (*ListToolsResult, error) {
	ctx, span := securityMCPClientTracer.Start(ctx, "security_mcp_client.list_tools")
	defer span.End()

	result := &ListToolsResult{}
	err := c.sendRequest(ctx, "tools/list", &ListToolsParams{}, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// CallTool implements MCPClient.CallTool
func (c *SecurityMCPClient) CallTool(ctx context.Context, name string, arguments map[string]interface{}) (*CallToolResult, error) {
	ctx, span := securityMCPClientTracer.Start(ctx, "security_mcp_client.call_tool",
		trace.WithAttributes(attribute.String("tool.name", name)),
	)
	defer span.End()

	params := &CallToolParams{
		Name:      name,
		Arguments: arguments,
	}

	result := &CallToolResult{}
	err := c.sendRequest(ctx, "tools/call", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListResources implements MCPClient.ListResources
func (c *SecurityMCPClient) ListResources(ctx context.Context) (*ListResourcesResult, error) {
	ctx, span := securityMCPClientTracer.Start(ctx, "security_mcp_client.list_resources")
	defer span.End()

	result := &ListResourcesResult{}
	err := c.sendRequest(ctx, "resources/list", &ListResourcesParams{}, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ReadResource implements MCPClient.ReadResource
func (c *SecurityMCPClient) ReadResource(ctx context.Context, uri string) (*ReadResourceResult, error) {
	ctx, span := securityMCPClientTracer.Start(ctx, "security_mcp_client.read_resource",
		trace.WithAttributes(attribute.String("resource.uri", uri)),
	)
	defer span.End()

	params := &ReadResourceParams{
		URI: uri,
	}

	result := &ReadResourceResult{}
	err := c.sendRequest(ctx, "resources/read", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListPrompts implements MCPClient.ListPrompts
func (c *SecurityMCPClient) ListPrompts(ctx context.Context) (*ListPromptsResult, error) {
	ctx, span := securityMCPClientTracer.Start(ctx, "security_mcp_client.list_prompts")
	defer span.End()

	result := &ListPromptsResult{}
	err := c.sendRequest(ctx, "prompts/list", &ListPromptsParams{}, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetPrompt implements MCPClient.GetPrompt
func (c *SecurityMCPClient) GetPrompt(ctx context.Context, name string, arguments map[string]interface{}) (*GetPromptResult, error) {
	ctx, span := securityMCPClientTracer.Start(ctx, "security_mcp_client.get_prompt",
		trace.WithAttributes(attribute.String("prompt.name", name)),
	)
	defer span.End()

	params := &GetPromptParams{
		Name:      name,
		Arguments: arguments,
	}

	result := &GetPromptResult{}
	err := c.sendRequest(ctx, "prompts/get", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// OnNotification implements MCPClient.OnNotification
func (c *SecurityMCPClient) OnNotification(handler NotificationHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notificationHandler = handler
}

// OnError implements MCPClient.OnError
func (c *SecurityMCPClient) OnError(handler ErrorHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errorHandler = handler
}

// Security-specific convenience methods

// AnalyzeThreat performs threat analysis using the MCP server
func (c *SecurityMCPClient) AnalyzeThreat(ctx context.Context, input string, securityContext map[string]interface{}) (*CallToolResult, error) {
	arguments := map[string]interface{}{
		"input": input,
	}

	if securityContext != nil {
		arguments["context"] = securityContext
	}

	return c.CallTool(ctx, "threat_analysis", arguments)
}

// ScanVulnerabilities performs vulnerability scanning using the MCP server
func (c *SecurityMCPClient) ScanVulnerabilities(ctx context.Context, target, scanType string, options map[string]interface{}) (*CallToolResult, error) {
	arguments := map[string]interface{}{
		"target":    target,
		"scan_type": scanType,
	}

	if options != nil {
		arguments["options"] = options
	}

	return c.CallTool(ctx, "vulnerability_scan", arguments)
}

// CheckCompliance performs compliance checking using the MCP server
func (c *SecurityMCPClient) CheckCompliance(ctx context.Context, framework, target string, scope []string) (*CallToolResult, error) {
	arguments := map[string]interface{}{
		"framework": framework,
		"target":    target,
	}

	if scope != nil {
		arguments["scope"] = scope
	}

	return c.CallTool(ctx, "compliance_check", arguments)
}

// ManageIncident performs incident management using the MCP server
func (c *SecurityMCPClient) ManageIncident(ctx context.Context, action string, incidentID string, details map[string]interface{}) (*CallToolResult, error) {
	arguments := map[string]interface{}{
		"action": action,
	}

	if incidentID != "" {
		arguments["incident_id"] = incidentID
	}

	if details != nil {
		arguments["details"] = details
	}

	return c.CallTool(ctx, "incident_response", arguments)
}

// QueryThreatIntelligence queries threat intelligence using the MCP server
func (c *SecurityMCPClient) QueryThreatIntelligence(ctx context.Context, queryType string, indicators []string, sources []string) (*CallToolResult, error) {
	arguments := map[string]interface{}{
		"query_type": queryType,
	}

	if indicators != nil {
		arguments["indicators"] = indicators
	}

	if sources != nil {
		arguments["sources"] = sources
	}

	return c.CallTool(ctx, "threat_intelligence", arguments)
}

// sendRequest sends an MCP request to the server
func (c *SecurityMCPClient) sendRequest(ctx context.Context, method string, params interface{}, result interface{}) error {
	c.mu.RLock()
	serverURL := c.serverURL
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return fmt.Errorf("client not connected")
	}

	// Create MCP message
	message := MCPMessage{
		JSONRPC: "2.0",
		ID:      stringPtr(fmt.Sprintf("req-%d", time.Now().UnixNano())),
		Method:  method,
		Params:  params,
	}

	// Marshal request
	requestBody, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", serverURL, bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", MimeTypeJSON)
	req.Header.Set("Accept", MimeTypeJSON)

	// Send request with retries
	var resp *http.Response
	for i := 0; i < c.config.MaxRetries; i++ {
		resp, err = c.httpClient.Do(req)
		if err == nil {
			break
		}

		if i < c.config.MaxRetries-1 {
			time.Sleep(c.config.RetryDelay)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Parse MCP response
	var mcpResponse MCPMessage
	if err := json.Unmarshal(responseBody, &mcpResponse); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check for errors
	if mcpResponse.Error != nil {
		return mcpResponse.Error
	}

	// Unmarshal result
	if mcpResponse.Result != nil {
		resultBytes, err := json.Marshal(mcpResponse.Result)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}

		if err := json.Unmarshal(resultBytes, result); err != nil {
			return fmt.Errorf("failed to unmarshal result: %w", err)
		}
	}

	return nil
}

// Helper function
func stringPtr(s string) *string {
	return &s
}
