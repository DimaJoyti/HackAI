package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestLogger() *logger.Logger {
	log, _ := logger.New(logger.Config{
		Level:  logger.LevelDebug,
		Format: "text",
		Output: "stdout",
	})
	return log
}

func createTestSecurityMCPServer() *SecurityMCPServer {
	config := &SecurityMCPConfig{
		ServerName:           "Test Security MCP Server",
		ServerVersion:        "1.0.0-test",
		MaxConcurrentScans:   5,
		ScanTimeout:          1 * time.Minute,
		EnableRealTimeAlerts: true,
		ThreatThreshold:      0.7,
		LogLevel:             LogLevelDebug,
		EnableAuditLogging:   true,
	}

	log := createTestLogger()
	agenticConfig := security.DefaultAgenticConfig()
	agenticFramework := security.NewAgenticSecurityFramework(agenticConfig, log)
	threatOrchestratorConfig := security.DefaultThreatOrchestratorConfig()
	threatIntelligence := security.NewThreatIntelligenceOrchestrator(
		threatOrchestratorConfig,
		nil, nil, nil, nil, nil, nil, nil,
		log,
	)

	return NewSecurityMCPServer(
		config,
		log,
		agenticFramework,
		threatIntelligence,
	)
}

func TestSecurityMCPServer_Initialize(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	// Test successful initialization
	params := &InitializeParams{
		ProtocolVersion: MCPVersion,
		Capabilities: ClientCapabilities{
			Experimental: map[string]interface{}{
				"security_extensions": true,
			},
		},
		ClientInfo: ClientInfo{
			Name:    "Test Client",
			Version: "1.0.0",
		},
	}

	result, err := server.Initialize(ctx, params)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, MCPVersion, result.ProtocolVersion)
	assert.Equal(t, "Test Security MCP Server", result.ServerInfo.Name)
	assert.Equal(t, "1.0.0-test", result.ServerInfo.Version)
	assert.NotNil(t, result.Capabilities.Tools)
	assert.NotNil(t, result.Capabilities.Resources)
	assert.NotNil(t, result.Capabilities.Prompts)

	// Test double initialization (should fail)
	_, err = server.Initialize(ctx, params)
	assert.Error(t, err)
	mcpErr, ok := err.(*MCPError)
	assert.True(t, ok)
	assert.Equal(t, ErrorCodeInvalidRequest, mcpErr.Code)
}

func TestSecurityMCPServer_Initialize_InvalidProtocolVersion(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	params := &InitializeParams{
		ProtocolVersion: "invalid-version",
		Capabilities:    ClientCapabilities{},
		ClientInfo: ClientInfo{
			Name:    "Test Client",
			Version: "1.0.0",
		},
	}

	_, err := server.Initialize(ctx, params)
	assert.Error(t, err)
	mcpErr, ok := err.(*MCPError)
	assert.True(t, ok)
	assert.Equal(t, ErrorCodeInvalidRequest, mcpErr.Code)
}

func TestSecurityMCPServer_ListTools(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	// Initialize server first
	initParams := &InitializeParams{
		ProtocolVersion: MCPVersion,
		Capabilities:    ClientCapabilities{},
		ClientInfo: ClientInfo{
			Name:    "Test Client",
			Version: "1.0.0",
		},
	}
	_, err := server.Initialize(ctx, initParams)
	require.NoError(t, err)

	// Test list tools
	params := &ListToolsParams{}
	result, err := server.ListTools(ctx, params)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, len(result.Tools), 0)

	// Check for expected tools
	toolNames := make(map[string]bool)
	for _, tool := range result.Tools {
		toolNames[tool.Name] = true
	}

	expectedTools := []string{
		"threat_analysis",
		"vulnerability_scan",
		"compliance_check",
		"incident_response",
		"threat_intelligence",
	}

	for _, expectedTool := range expectedTools {
		assert.True(t, toolNames[expectedTool], "Expected tool %s not found", expectedTool)
	}
}

func TestSecurityMCPServer_ListTools_NotInitialized(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	params := &ListToolsParams{}
	_, err := server.ListTools(ctx, params)
	assert.Error(t, err)
	mcpErr, ok := err.(*MCPError)
	assert.True(t, ok)
	assert.Equal(t, ErrorCodeInvalidRequest, mcpErr.Code)
}

func TestSecurityMCPServer_CallTool_ThreatAnalysis(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	// Initialize server
	initParams := &InitializeParams{
		ProtocolVersion: MCPVersion,
		Capabilities:    ClientCapabilities{},
		ClientInfo: ClientInfo{
			Name:    "Test Client",
			Version: "1.0.0",
		},
	}
	_, err := server.Initialize(ctx, initParams)
	require.NoError(t, err)

	// Test threat analysis tool
	params := &CallToolParams{
		Name: "threat_analysis",
		Arguments: map[string]interface{}{
			"input": "This is a test input for threat analysis",
			"context": map[string]interface{}{
				"user_id":    "test-user",
				"session_id": "test-session",
			},
		},
	}

	result, err := server.CallTool(ctx, params)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, len(result.Content), 0)
	assert.False(t, result.IsError)
}

func TestSecurityMCPServer_CallTool_VulnerabilityScan(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	// Initialize server
	initParams := &InitializeParams{
		ProtocolVersion: MCPVersion,
		Capabilities:    ClientCapabilities{},
		ClientInfo: ClientInfo{
			Name:    "Test Client",
			Version: "1.0.0",
		},
	}
	_, err := server.Initialize(ctx, initParams)
	require.NoError(t, err)

	// Test vulnerability scan tool
	params := &CallToolParams{
		Name: "vulnerability_scan",
		Arguments: map[string]interface{}{
			"target":    "https://example.com",
			"scan_type": "web",
			"options": map[string]interface{}{
				"depth": "basic",
			},
		},
	}

	result, err := server.CallTool(ctx, params)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, len(result.Content), 0)
	assert.False(t, result.IsError)
}

func TestSecurityMCPServer_CallTool_InvalidTool(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	// Initialize server
	initParams := &InitializeParams{
		ProtocolVersion: MCPVersion,
		Capabilities:    ClientCapabilities{},
		ClientInfo: ClientInfo{
			Name:    "Test Client",
			Version: "1.0.0",
		},
	}
	_, err := server.Initialize(ctx, initParams)
	require.NoError(t, err)

	// Test invalid tool
	params := &CallToolParams{
		Name:      "invalid_tool",
		Arguments: map[string]interface{}{},
	}

	_, err = server.CallTool(ctx, params)
	assert.Error(t, err)
	mcpErr, ok := err.(*MCPError)
	assert.True(t, ok)
	assert.Equal(t, ErrorCodeMethodNotFound, mcpErr.Code)
}

func TestSecurityMCPServer_ListResources(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	// Initialize server
	initParams := &InitializeParams{
		ProtocolVersion: MCPVersion,
		Capabilities:    ClientCapabilities{},
		ClientInfo: ClientInfo{
			Name:    "Test Client",
			Version: "1.0.0",
		},
	}
	_, err := server.Initialize(ctx, initParams)
	require.NoError(t, err)

	// Test list resources
	params := &ListResourcesParams{}
	result, err := server.ListResources(ctx, params)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, len(result.Resources), 0)

	// Check for expected resources
	resourceURIs := make(map[string]bool)
	for _, resource := range result.Resources {
		resourceURIs[resource.URI] = true
	}

	expectedResources := []string{
		"security://reports",
		"security://threat-intel",
		"security://compliance",
		"security://metrics",
	}

	for _, expectedResource := range expectedResources {
		assert.True(t, resourceURIs[expectedResource], "Expected resource %s not found", expectedResource)
	}
}

func TestSecurityMCPServer_ReadResource(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	// Initialize server
	initParams := &InitializeParams{
		ProtocolVersion: MCPVersion,
		Capabilities:    ClientCapabilities{},
		ClientInfo: ClientInfo{
			Name:    "Test Client",
			Version: "1.0.0",
		},
	}
	_, err := server.Initialize(ctx, initParams)
	require.NoError(t, err)

	// Test read resource
	params := &ReadResourceParams{
		URI: "security://reports",
	}

	result, err := server.ReadResource(ctx, params)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, len(result.Contents), 0)
	assert.Equal(t, MimeTypeJSON, result.Contents[0].MimeType)
}

func TestSecurityMCPServer_ListPrompts(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	// Initialize server
	initParams := &InitializeParams{
		ProtocolVersion: MCPVersion,
		Capabilities:    ClientCapabilities{},
		ClientInfo: ClientInfo{
			Name:    "Test Client",
			Version: "1.0.0",
		},
	}
	_, err := server.Initialize(ctx, initParams)
	require.NoError(t, err)

	// Test list prompts
	params := &ListPromptsParams{}
	result, err := server.ListPrompts(ctx, params)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, len(result.Prompts), 0)

	// Check for expected prompts
	promptNames := make(map[string]bool)
	for _, prompt := range result.Prompts {
		promptNames[prompt.Name] = true
	}

	expectedPrompts := []string{
		"threat_analysis_prompt",
		"security_assessment_prompt",
		"incident_response_prompt",
	}

	for _, expectedPrompt := range expectedPrompts {
		assert.True(t, promptNames[expectedPrompt], "Expected prompt %s not found", expectedPrompt)
	}
}

func TestSecurityMCPServer_GetPrompt(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	// Initialize server
	initParams := &InitializeParams{
		ProtocolVersion: MCPVersion,
		Capabilities:    ClientCapabilities{},
		ClientInfo: ClientInfo{
			Name:    "Test Client",
			Version: "1.0.0",
		},
	}
	_, err := server.Initialize(ctx, initParams)
	require.NoError(t, err)

	// Test get prompt
	params := &GetPromptParams{
		Name: "threat_analysis_prompt",
		Arguments: map[string]interface{}{
			"input_type":     "text",
			"analysis_depth": "detailed",
		},
	}

	result, err := server.GetPrompt(ctx, params)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, len(result.Messages), 0)
	assert.Equal(t, "system", result.Messages[0].Role)
}

func TestSecurityMCPServer_SetLogLevel(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	// Test set log level
	params := &SetLogLevelParams{
		Level: LogLevelError,
	}

	err := server.SetLogLevel(ctx, params)
	require.NoError(t, err)
}

func TestSecurityMCPServer_Shutdown(t *testing.T) {
	server := createTestSecurityMCPServer()
	ctx := context.Background()

	// Initialize server first
	initParams := &InitializeParams{
		ProtocolVersion: MCPVersion,
		Capabilities:    ClientCapabilities{},
		ClientInfo: ClientInfo{
			Name:    "Test Client",
			Version: "1.0.0",
		},
	}
	_, err := server.Initialize(ctx, initParams)
	require.NoError(t, err)

	// Test shutdown
	err = server.Shutdown(ctx)
	require.NoError(t, err)

	// Test operations after shutdown (should fail)
	_, err = server.ListTools(ctx, &ListToolsParams{})
	assert.Error(t, err)
}
