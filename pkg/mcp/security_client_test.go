package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestSecurityMCPClient() *SecurityMCPClient {
	config := &SecurityMCPClientConfig{
		ClientName:    "Test Security MCP Client",
		ClientVersion: "1.0.0-test",
		Timeout:       5 * time.Second,
		MaxRetries:    2,
		RetryDelay:    100 * time.Millisecond,
		EnableTracing: false,
		EnableMetrics: false,
	}

	log := createTestLogger()
	return NewSecurityMCPClient(config, log)
}

func createMockMCPServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request MCPMessage
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		var response MCPMessage
		response.JSONRPC = "2.0"
		response.ID = request.ID

		switch request.Method {
		case "initialize":
			response.Result = &InitializeResult{
				ProtocolVersion: MCPVersion,
				Capabilities: ServerCapabilities{
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
				},
				ServerInfo: ServerInfo{
					Name:    "Mock Security MCP Server",
					Version: "1.0.0-test",
				},
			}

		case "tools/list":
			response.Result = &ListToolsResult{
				Tools: []Tool{
					{
						Name:        "threat_analysis",
						Description: "Analyze input for security threats",
						InputSchema: ToolSchema{
							Type: "object",
							Properties: map[string]interface{}{
								"input": map[string]interface{}{
									"type":        "string",
									"description": "Input to analyze",
								},
							},
							Required: []string{"input"},
						},
					},
				},
			}

		case "tools/call":
			var params CallToolParams
			if paramBytes, err := json.Marshal(request.Params); err == nil {
				json.Unmarshal(paramBytes, &params)
			}

			if params.Name == "threat_analysis" {
				response.Result = &CallToolResult{
					Content: []ToolContent{
						{
							Type: "text",
							Text: "Threat analysis completed successfully",
						},
					},
					IsError: false,
				}
			} else {
				response.Error = &MCPError{
					Code:    ErrorCodeMethodNotFound,
					Message: "Tool not found",
				}
			}

		case "resources/list":
			response.Result = &ListResourcesResult{
				Resources: []Resource{
					{
						URI:         "security://reports",
						Name:        "Security Reports",
						Description: "Access to security reports",
						MimeType:    MimeTypeJSON,
					},
				},
			}

		case "resources/read":
			var params ReadResourceParams
			if paramBytes, err := json.Marshal(request.Params); err == nil {
				json.Unmarshal(paramBytes, &params)
			}

			if params.URI == "security://reports" {
				response.Result = &ReadResourceResult{
					Contents: []ResourceContent{
						{
							URI:      params.URI,
							MimeType: MimeTypeJSON,
							Text:     `{"reports": [], "total_count": 0}`,
						},
					},
				}
			} else {
				response.Error = &MCPError{
					Code:    ErrorCodeMethodNotFound,
					Message: "Resource not found",
				}
			}

		case "prompts/list":
			response.Result = &ListPromptsResult{
				Prompts: []Prompt{
					{
						Name:        "threat_analysis_prompt",
						Description: "Generate threat analysis prompts",
						Arguments: []PromptArgument{
							{
								Name:        "input_type",
								Description: "Type of input to analyze",
								Required:    true,
							},
						},
					},
				},
			}

		case "prompts/get":
			var params GetPromptParams
			if paramBytes, err := json.Marshal(request.Params); err == nil {
				json.Unmarshal(paramBytes, &params)
			}

			if params.Name == "threat_analysis_prompt" {
				response.Result = &GetPromptResult{
					Description: "Threat analysis prompt",
					Messages: []PromptMessage{
						{
							Role: "system",
							Content: PromptContent{
								Type: "text",
								Text: "Analyze the following input for security threats:",
							},
						},
					},
				}
			} else {
				response.Error = &MCPError{
					Code:    ErrorCodeMethodNotFound,
					Message: "Prompt not found",
				}
			}

		default:
			response.Error = &MCPError{
				Code:    ErrorCodeMethodNotFound,
				Message: "Method not found",
			}
		}

		w.Header().Set("Content-Type", MimeTypeJSON)
		json.NewEncoder(w).Encode(response)
	}))
}

func TestSecurityMCPClient_Connect(t *testing.T) {
	client := createTestSecurityMCPClient()
	server := createMockMCPServer()
	defer server.Close()

	ctx := context.Background()

	// Test successful connection
	err := client.Connect(ctx, server.URL)
	require.NoError(t, err)
	assert.True(t, client.IsConnected())

	// Test double connection (should fail)
	err = client.Connect(ctx, server.URL)
	assert.Error(t, err)
}

func TestSecurityMCPClient_Connect_InvalidURL(t *testing.T) {
	client := createTestSecurityMCPClient()
	ctx := context.Background()

	// Test connection to invalid URL
	err := client.Connect(ctx, "http://invalid-url:99999")
	assert.Error(t, err)
	assert.False(t, client.IsConnected())
}

func TestSecurityMCPClient_Disconnect(t *testing.T) {
	client := createTestSecurityMCPClient()
	server := createMockMCPServer()
	defer server.Close()

	ctx := context.Background()

	// Connect first
	err := client.Connect(ctx, server.URL)
	require.NoError(t, err)

	// Test disconnect
	err = client.Disconnect(ctx)
	require.NoError(t, err)
	assert.False(t, client.IsConnected())

	// Test disconnect when not connected
	err = client.Disconnect(ctx)
	assert.Error(t, err)
}

func TestSecurityMCPClient_ListTools(t *testing.T) {
	client := createTestSecurityMCPClient()
	server := createMockMCPServer()
	defer server.Close()

	ctx := context.Background()

	// Connect first
	err := client.Connect(ctx, server.URL)
	require.NoError(t, err)

	// Test list tools
	result, err := client.ListTools(ctx)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Tools, 1)
	assert.Equal(t, "threat_analysis", result.Tools[0].Name)
}

func TestSecurityMCPClient_CallTool(t *testing.T) {
	client := createTestSecurityMCPClient()
	server := createMockMCPServer()
	defer server.Close()

	ctx := context.Background()

	// Connect first
	err := client.Connect(ctx, server.URL)
	require.NoError(t, err)

	// Test call tool
	arguments := map[string]interface{}{
		"input": "test input",
	}

	result, err := client.CallTool(ctx, "threat_analysis", arguments)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Len(t, result.Content, 1)
	assert.Equal(t, "text", result.Content[0].Type)
}

func TestSecurityMCPClient_CallTool_InvalidTool(t *testing.T) {
	client := createTestSecurityMCPClient()
	server := createMockMCPServer()
	defer server.Close()

	ctx := context.Background()

	// Connect first
	err := client.Connect(ctx, server.URL)
	require.NoError(t, err)

	// Test call invalid tool
	arguments := map[string]interface{}{}

	_, err = client.CallTool(ctx, "invalid_tool", arguments)
	assert.Error(t, err)
	mcpErr, ok := err.(*MCPError)
	assert.True(t, ok)
	assert.Equal(t, ErrorCodeMethodNotFound, mcpErr.Code)
}

func TestSecurityMCPClient_ListResources(t *testing.T) {
	client := createTestSecurityMCPClient()
	server := createMockMCPServer()
	defer server.Close()

	ctx := context.Background()

	// Connect first
	err := client.Connect(ctx, server.URL)
	require.NoError(t, err)

	// Test list resources
	result, err := client.ListResources(ctx)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Resources, 1)
	assert.Equal(t, "security://reports", result.Resources[0].URI)
}

func TestSecurityMCPClient_ReadResource(t *testing.T) {
	client := createTestSecurityMCPClient()
	server := createMockMCPServer()
	defer server.Close()

	ctx := context.Background()

	// Connect first
	err := client.Connect(ctx, server.URL)
	require.NoError(t, err)

	// Test read resource
	result, err := client.ReadResource(ctx, "security://reports")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Contents, 1)
	assert.Equal(t, MimeTypeJSON, result.Contents[0].MimeType)
}

func TestSecurityMCPClient_ListPrompts(t *testing.T) {
	client := createTestSecurityMCPClient()
	server := createMockMCPServer()
	defer server.Close()

	ctx := context.Background()

	// Connect first
	err := client.Connect(ctx, server.URL)
	require.NoError(t, err)

	// Test list prompts
	result, err := client.ListPrompts(ctx)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Prompts, 1)
	assert.Equal(t, "threat_analysis_prompt", result.Prompts[0].Name)
}

func TestSecurityMCPClient_GetPrompt(t *testing.T) {
	client := createTestSecurityMCPClient()
	server := createMockMCPServer()
	defer server.Close()

	ctx := context.Background()

	// Connect first
	err := client.Connect(ctx, server.URL)
	require.NoError(t, err)

	// Test get prompt
	arguments := map[string]interface{}{
		"input_type": "text",
	}

	result, err := client.GetPrompt(ctx, "threat_analysis_prompt", arguments)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Messages, 1)
	assert.Equal(t, "system", result.Messages[0].Role)
}

func TestSecurityMCPClient_AnalyzeThreat(t *testing.T) {
	client := createTestSecurityMCPClient()
	server := createMockMCPServer()
	defer server.Close()

	ctx := context.Background()

	// Connect first
	err := client.Connect(ctx, server.URL)
	require.NoError(t, err)

	// Test analyze threat convenience method
	securityContext := map[string]interface{}{
		"user_id": "test-user",
	}

	result, err := client.AnalyzeThreat(ctx, "test input", securityContext)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestSecurityMCPClient_NotConnected(t *testing.T) {
	client := createTestSecurityMCPClient()
	ctx := context.Background()

	// Test operations when not connected
	_, err := client.ListTools(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")

	_, err = client.CallTool(ctx, "test", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")

	_, err = client.ListResources(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")

	_, err = client.ReadResource(ctx, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")

	_, err = client.ListPrompts(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")

	_, err = client.GetPrompt(ctx, "test", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}
