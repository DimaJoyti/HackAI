// Package mcp provides Model Context Protocol (MCP) interfaces and types
package mcp

import (
	"context"
	"sync"
	"time"
)

// MCPVersion represents the MCP protocol version
const MCPVersion = "2024-11-05"

// MessageType represents different types of MCP messages
type MessageType string

const (
	MessageTypeRequest      MessageType = "request"
	MessageTypeResponse     MessageType = "response"
	MessageTypeNotification MessageType = "notification"
	MessageTypeError        MessageType = "error"
)

// MCPMessage represents a base MCP protocol message
type MCPMessage struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *string     `json:"id,omitempty"`
	Method  string      `json:"method,omitempty"`
	Params  interface{} `json:"params,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

// MCPError represents an MCP protocol error
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Error implements the error interface
func (e *MCPError) Error() string {
	return e.Message
}

// Standard MCP error codes
const (
	ErrorCodeParseError     = -32700
	ErrorCodeInvalidRequest = -32600
	ErrorCodeMethodNotFound = -32601
	ErrorCodeInvalidParams  = -32602
	ErrorCodeInternalError  = -32603
	ErrorCodeServerError    = -32000
)

// MCPServer interface defines the core MCP server functionality
type MCPServer interface {
	// Core protocol methods
	Initialize(ctx context.Context, params *InitializeParams) (*InitializeResult, error)
	Shutdown(ctx context.Context) error

	// Tool management
	ListTools(ctx context.Context, params *ListToolsParams) (*ListToolsResult, error)
	CallTool(ctx context.Context, params *CallToolParams) (*CallToolResult, error)

	// Resource management
	ListResources(ctx context.Context, params *ListResourcesParams) (*ListResourcesResult, error)
	ReadResource(ctx context.Context, params *ReadResourceParams) (*ReadResourceResult, error)

	// Prompt management
	ListPrompts(ctx context.Context, params *ListPromptsParams) (*ListPromptsResult, error)
	GetPrompt(ctx context.Context, params *GetPromptParams) (*GetPromptResult, error)

	// Logging and notifications
	SetLogLevel(ctx context.Context, params *SetLogLevelParams) error
	SendNotification(ctx context.Context, method string, params interface{}) error
}

// MCPClient interface defines the core MCP client functionality
type MCPClient interface {
	// Connection management
	Connect(ctx context.Context, serverURL string) error
	Disconnect(ctx context.Context) error
	IsConnected() bool

	// Protocol methods
	Initialize(ctx context.Context, params *InitializeParams) (*InitializeResult, error)

	// Tool operations
	ListTools(ctx context.Context) (*ListToolsResult, error)
	CallTool(ctx context.Context, name string, arguments map[string]interface{}) (*CallToolResult, error)

	// Resource operations
	ListResources(ctx context.Context) (*ListResourcesResult, error)
	ReadResource(ctx context.Context, uri string) (*ReadResourceResult, error)

	// Prompt operations
	ListPrompts(ctx context.Context) (*ListPromptsResult, error)
	GetPrompt(ctx context.Context, name string, arguments map[string]interface{}) (*GetPromptResult, error)

	// Event handling
	OnNotification(handler NotificationHandler)
	OnError(handler ErrorHandler)
}

// Handler types
type NotificationHandler func(method string, params interface{})
type ErrorHandler func(error)

// Initialize parameters and result
type InitializeParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    ClientCapabilities     `json:"capabilities"`
	ClientInfo      ClientInfo             `json:"clientInfo"`
	Meta            map[string]interface{} `json:"meta,omitempty"`
}

type InitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    ServerCapabilities     `json:"capabilities"`
	ServerInfo      ServerInfo             `json:"serverInfo"`
	Instructions    string                 `json:"instructions,omitempty"`
	Meta            map[string]interface{} `json:"meta,omitempty"`
}

// Capabilities
type ClientCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
	Sampling     *SamplingCapability    `json:"sampling,omitempty"`
}

type ServerCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
	Logging      *LoggingCapability     `json:"logging,omitempty"`
	Prompts      *PromptsCapability     `json:"prompts,omitempty"`
	Resources    *ResourcesCapability   `json:"resources,omitempty"`
	Tools        *ToolsCapability       `json:"tools,omitempty"`
}

type SamplingCapability struct{}
type LoggingCapability struct{}
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// Client and Server info
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tool-related types
type ListToolsParams struct {
	Cursor string `json:"cursor,omitempty"`
}

type ListToolsResult struct {
	Tools      []Tool  `json:"tools"`
	NextCursor *string `json:"nextCursor,omitempty"`
}

type Tool struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	InputSchema ToolSchema `json:"inputSchema"`
}

type ToolSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
}

type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type CallToolResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type ToolContent struct {
	Type string      `json:"type"`
	Text string      `json:"text,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

// Resource-related types
type ListResourcesParams struct {
	Cursor string `json:"cursor,omitempty"`
}

type ListResourcesResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor *string    `json:"nextCursor,omitempty"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ReadResourceParams struct {
	URI string `json:"uri"`
}

type ReadResourceResult struct {
	Contents []ResourceContent `json:"contents"`
}

type ResourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     []byte `json:"blob,omitempty"`
}

// Prompt-related types
type ListPromptsParams struct {
	Cursor string `json:"cursor,omitempty"`
}

type ListPromptsResult struct {
	Prompts    []Prompt `json:"prompts"`
	NextCursor *string  `json:"nextCursor,omitempty"`
}

type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type GetPromptParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

type PromptMessage struct {
	Role    string        `json:"role"`
	Content PromptContent `json:"content"`
}

type PromptContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Logging types
type SetLogLevelParams struct {
	Level LogLevel `json:"level"`
}

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// Security-specific MCP extensions
type SecurityContext struct {
	UserID      string                 `json:"user_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// Security tool result types
type SecurityScanResult struct {
	ScanID      string                 `json:"scan_id"`
	Status      string                 `json:"status"`
	ThreatLevel string                 `json:"threat_level"`
	Score       float64                `json:"score"`
	Findings    []SecurityFinding      `json:"findings"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
	Duration    time.Duration          `json:"duration"`
}

type SecurityFinding struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Evidence    []string               `json:"evidence,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	References  []string               `json:"references,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ClientConnection represents a connected MCP client
type ClientConnection struct {
	ID           string                 `json:"id"`
	ClientInfo   ClientInfo             `json:"client_info"`
	Capabilities ClientCapabilities     `json:"capabilities"`
	ConnectedAt  time.Time              `json:"connected_at"`
	LastActivity time.Time              `json:"last_activity"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// MCPNotification represents an MCP notification message
type MCPNotification struct {
	Method    string      `json:"method"`
	Params    interface{} `json:"params,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	ClientID  string      `json:"client_id,omitempty"`
}

// SecurityRateLimiter manages rate limiting for security operations
type SecurityRateLimiter struct {
	MaxRequestsPerMinute int                   `json:"max_requests_per_minute"`
	MaxConcurrentOps     int                   `json:"max_concurrent_ops"`
	ClientLimits         map[string]*RateLimit `json:"client_limits"`
	GlobalLimit          *RateLimit            `json:"global_limit"`
	mu                   sync.RWMutex          `json:"-"`
}

// RateLimit tracks rate limiting state
type RateLimit struct {
	Requests      int       `json:"requests"`
	WindowStart   time.Time `json:"window_start"`
	ConcurrentOps int       `json:"concurrent_ops"`
}

// SecurityMCPMetrics tracks server metrics
type SecurityMCPMetrics struct {
	TotalRequests          int64         `json:"total_requests"`
	SuccessfulRequests     int64         `json:"successful_requests"`
	FailedRequests         int64         `json:"failed_requests"`
	ActiveConnections      int64         `json:"active_connections"`
	TotalConnections       int64         `json:"total_connections"`
	AverageResponseTime    time.Duration `json:"average_response_time"`
	ThreatAnalysisCount    int64         `json:"threat_analysis_count"`
	VulnerabilityScanCount int64         `json:"vulnerability_scan_count"`
	ComplianceCheckCount   int64         `json:"compliance_check_count"`
	IncidentResponseCount  int64         `json:"incident_response_count"`
	ThreatIntelCount       int64         `json:"threat_intel_count"`
	LastUpdated            time.Time     `json:"last_updated"`
	mu                     sync.RWMutex  `json:"-"`
}

// ActiveRequest tracks an active MCP request
type ActiveRequest struct {
	ID        string                 `json:"id"`
	Method    string                 `json:"method"`
	StartTime time.Time              `json:"start_time"`
	Context   context.Context        `json:"-"`
	Cancel    context.CancelFunc     `json:"-"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ToolsCache caches tool information
type ToolsCache struct {
	Tools       []Tool        `json:"tools"`
	LastUpdated time.Time     `json:"last_updated"`
	TTL         time.Duration `json:"ttl"`
	mu          sync.RWMutex  `json:"-"`
}

// ResourcesCache caches resource information
type ResourcesCache struct {
	Resources   []Resource    `json:"resources"`
	LastUpdated time.Time     `json:"last_updated"`
	TTL         time.Duration `json:"ttl"`
	mu          sync.RWMutex  `json:"-"`
}

// PromptsCache caches prompt information
type PromptsCache struct {
	Prompts     []Prompt      `json:"prompts"`
	LastUpdated time.Time     `json:"last_updated"`
	TTL         time.Duration `json:"ttl"`
	mu          sync.RWMutex  `json:"-"`
}

// ClientMetrics tracks client-side metrics
type ClientMetrics struct {
	TotalRequests       int64         `json:"total_requests"`
	SuccessfulRequests  int64         `json:"successful_requests"`
	FailedRequests      int64         `json:"failed_requests"`
	ReconnectAttempts   int64         `json:"reconnect_attempts"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	LastRequestTime     time.Time     `json:"last_request_time"`
	ConnectionUptime    time.Duration `json:"connection_uptime"`
	ConnectionStartTime time.Time     `json:"connection_start_time"`
	CacheHits           int64         `json:"cache_hits"`
	CacheMisses         int64         `json:"cache_misses"`
	mu                  sync.RWMutex  `json:"-"`
}

