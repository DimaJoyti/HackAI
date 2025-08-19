package ai

import (
	"context"
	"time"

	"github.com/dimajoyti/hackai/pkg/llm"
)

// Chain represents a sequential AI workflow with enhanced capabilities
type Chain interface {
	llm.Chain
	GetConfig() ChainConfig
	SetConfig(ChainConfig) error
	GetMetrics() ChainMetrics
	Clone() Chain
}

// ChainConfig extends the base chain configuration
type ChainConfig struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Type            ChainType              `json:"type"`
	Enabled         bool                   `json:"enabled"`
	MaxRetries      int                    `json:"max_retries"`
	Timeout         time.Duration          `json:"timeout"`
	Temperature     float64                `json:"temperature"`
	MaxTokens       int                    `json:"max_tokens"`
	EnableTracing   bool                   `json:"enable_tracing"`
	EnableMetrics   bool                   `json:"enable_metrics"`
	SecurityLevel   SecurityLevel          `json:"security_level"`
	Parameters      map[string]interface{} `json:"parameters"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// ChainMetrics tracks chain execution metrics
type ChainMetrics struct {
	TotalExecutions   int64         `json:"total_executions"`
	SuccessfulRuns    int64         `json:"successful_runs"`
	FailedRuns        int64         `json:"failed_runs"`
	AverageLatency    time.Duration `json:"average_latency"`
	LastExecutionTime time.Time     `json:"last_execution_time"`
	TokensUsed        int64         `json:"tokens_used"`
	TotalCost         float64       `json:"total_cost"`
}

// ChainType represents different types of AI chains
type ChainType string

const (
	ChainTypeSequential      ChainType = "sequential"
	ChainTypeParallel        ChainType = "parallel"
	ChainTypeConditional     ChainType = "conditional"
	ChainTypePromptInjection ChainType = "prompt_injection"
	ChainTypeJailbreak       ChainType = "jailbreak"
	ChainTypeModelExtraction ChainType = "model_extraction"
	ChainTypeAdversarial     ChainType = "adversarial"
	ChainTypeThreatAnalysis  ChainType = "threat_analysis"
	ChainTypeRedTeam         ChainType = "red_team"
)

// SecurityLevel defines the security level for chain execution
type SecurityLevel string

const (
	SecurityLevelLow      SecurityLevel = "low"
	SecurityLevelMedium   SecurityLevel = "medium"
	SecurityLevelHigh     SecurityLevel = "high"
	SecurityLevelCritical SecurityLevel = "critical"
)

// Graph represents a state machine workflow with enhanced capabilities
type Graph interface {
	ID() string
	Name() string
	Description() string
	Execute(ctx context.Context, initialState GraphState) (GraphState, error)
	AddNode(node GraphNode) error
	AddEdge(from, to string) error
	AddConditionalEdge(from string, condition EdgeCondition, edges map[string]string) error
	SetEntryPoint(nodeID string) error
	GetNodes() map[string]GraphNode
	GetEdges() map[string][]string
	GetMetrics() GraphMetrics
	Validate() error
	Clone() Graph
}

// GraphState represents the current state of graph execution
type GraphState map[string]interface{}

// GraphNode represents a single node in the graph
type GraphNode interface {
	ID() string
	Type() NodeType
	Execute(ctx context.Context, state GraphState) (GraphState, error)
	GetConfig() NodeConfig
	SetConfig(NodeConfig) error
	Validate() error
}

// NodeConfig represents configuration for a graph node
type NodeConfig struct {
	ID          string                 `json:"id"`
	Type        NodeType               `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Timeout     time.Duration          `json:"timeout"`
	MaxRetries  int                    `json:"max_retries"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// NodeType represents the type of a graph node
type NodeType string

const (
	NodeTypeLLM               NodeType = "llm"
	NodeTypeCondition         NodeType = "condition"
	NodeTypeTransform         NodeType = "transform"
	NodeTypeMemory            NodeType = "memory"
	NodeTypeAction            NodeType = "action"
	NodeTypeValidator         NodeType = "validator"
	NodeTypeTool              NodeType = "tool"
	NodeTypeAgent             NodeType = "agent"
	NodeTypePromptInjection   NodeType = "prompt_injection"
	NodeTypeJailbreakTest     NodeType = "jailbreak_test"
	NodeTypeThreatAnalysis    NodeType = "threat_analysis"
	NodeTypeSecurityCheck     NodeType = "security_check"
)

// EdgeCondition determines which edge to follow based on state
type EdgeCondition func(state GraphState) string

// GraphMetrics tracks graph execution metrics
type GraphMetrics struct {
	TotalExecutions   int64                    `json:"total_executions"`
	SuccessfulRuns    int64                    `json:"successful_runs"`
	FailedRuns        int64                    `json:"failed_runs"`
	AverageLatency    time.Duration            `json:"average_latency"`
	NodeMetrics       map[string]NodeMetrics   `json:"node_metrics"`
	LastExecutionTime time.Time                `json:"last_execution_time"`
}

// NodeMetrics tracks individual node execution metrics
type NodeMetrics struct {
	ExecutionCount int64         `json:"execution_count"`
	AverageLatency time.Duration `json:"average_latency"`
	ErrorCount     int64         `json:"error_count"`
	LastExecution  time.Time     `json:"last_execution"`
}

// Agent represents an autonomous AI entity that can use tools and make decisions
type Agent interface {
	ID() string
	Name() string
	Description() string
	Execute(ctx context.Context, input AgentInput) (AgentOutput, error)
	AddTool(tool Tool) error
	RemoveTool(toolName string) error
	GetAvailableTools() []Tool
	SetDecisionEngine(engine DecisionEngine) error
	GetMetrics() AgentMetrics
	Validate() error
}

// AgentInput represents input for agent execution
type AgentInput struct {
	Query       string                 `json:"query"`
	Context     map[string]interface{} `json:"context"`
	MaxSteps    int                    `json:"max_steps"`
	Tools       []string               `json:"allowed_tools"`
	Constraints []string               `json:"constraints"`
	Goals       []string               `json:"goals"`
}

// AgentOutput represents agent execution results
type AgentOutput struct {
	Response    string                 `json:"response"`
	Steps       []AgentStep            `json:"steps"`
	ToolsUsed   []string               `json:"tools_used"`
	Confidence  float64                `json:"confidence"`
	Success     bool                   `json:"success"`
	Metadata    map[string]interface{} `json:"metadata"`
	Duration    time.Duration          `json:"duration"`
}

// AgentStep represents a single step in agent execution
type AgentStep struct {
	StepID      string                 `json:"step_id"`
	Action      string                 `json:"action"`
	Tool        string                 `json:"tool,omitempty"`
	Input       map[string]interface{} `json:"input"`
	Output      map[string]interface{} `json:"output"`
	Reasoning   string                 `json:"reasoning"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Timestamp   time.Time              `json:"timestamp"`
}

// DecisionEngine determines which tool to use and how to proceed
type DecisionEngine interface {
	DecideNextAction(ctx context.Context, input AgentInput, history []AgentStep) (AgentAction, error)
	UpdateStrategy(ctx context.Context, results []AgentStep) error
	GetRecommendations(ctx context.Context, input AgentInput) ([]Recommendation, error)
}

// AgentAction represents a decision made by the agent
type AgentAction struct {
	Type        string                 `json:"type"` // "tool_use", "respond", "continue", "stop"
	ToolName    string                 `json:"tool_name,omitempty"`
	ToolInput   map[string]interface{} `json:"tool_input,omitempty"`
	Response    string                 `json:"response,omitempty"`
	Reasoning   string                 `json:"reasoning"`
	Confidence  float64                `json:"confidence"`
}

// Recommendation represents a recommendation from the decision engine
type Recommendation struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Priority    int                    `json:"priority"`
	Impact      string                 `json:"impact"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AgentMetrics tracks agent execution metrics
type AgentMetrics struct {
	TotalExecutions   int64                    `json:"total_executions"`
	SuccessfulRuns    int64                    `json:"successful_runs"`
	FailedRuns        int64                    `json:"failed_runs"`
	AverageSteps      float64                  `json:"average_steps"`
	AverageLatency    time.Duration            `json:"average_latency"`
	ToolUsageStats    map[string]int64         `json:"tool_usage_stats"`
	LastExecutionTime time.Time                `json:"last_execution_time"`
}

// Tool represents an external capability that agents can use
type Tool interface {
	Name() string
	Description() string
	Execute(ctx context.Context, input ToolInput) (ToolOutput, error)
	GetSchema() ToolSchema
	Validate(input ToolInput) error
	GetMetrics() ToolMetrics
	IsHealthy(ctx context.Context) bool
}

// ToolInput represents input parameters for tool execution
type ToolInput map[string]interface{}

// ToolOutput represents tool execution results
type ToolOutput map[string]interface{}

// ToolSchema defines the expected input/output format
type ToolSchema struct {
	Name         string                        `json:"name"`
	Description  string                        `json:"description"`
	InputSchema  map[string]ParameterSchema    `json:"input_schema"`
	OutputSchema map[string]ParameterSchema    `json:"output_schema"`
	Examples     []ToolExample                 `json:"examples"`
}

// ParameterSchema defines parameter requirements
type ParameterSchema struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
	Pattern     string      `json:"pattern,omitempty"`
	MinLength   *int        `json:"min_length,omitempty"`
	MaxLength   *int        `json:"max_length,omitempty"`
}

// ToolExample provides usage examples for tools
type ToolExample struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Input       ToolInput  `json:"input"`
	Output      ToolOutput `json:"output"`
}

// ToolMetrics tracks tool execution metrics
type ToolMetrics struct {
	TotalExecutions   int64         `json:"total_executions"`
	SuccessfulRuns    int64         `json:"successful_runs"`
	FailedRuns        int64         `json:"failed_runs"`
	AverageLatency    time.Duration `json:"average_latency"`
	LastExecutionTime time.Time     `json:"last_execution_time"`
	ErrorRate         float64       `json:"error_rate"`
}

// SecurityContext provides security information for AI operations
type SecurityContext struct {
	UserID      string                 `json:"user_id"`
	SessionID   string                 `json:"session_id"`
	Permissions []string               `json:"permissions"`
	Constraints []string               `json:"constraints"`
	ThreatLevel SecurityLevel          `json:"threat_level"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
}

// ExecutionMetrics provides comprehensive execution metrics
type ExecutionMetrics struct {
	ExecutionID       string        `json:"execution_id"`
	Type              string        `json:"type"` // "chain", "graph", "agent", "tool"
	StartTime         time.Time     `json:"start_time"`
	EndTime           time.Time     `json:"end_time"`
	Duration          time.Duration `json:"duration"`
	Success           bool          `json:"success"`
	TokensUsed        int64         `json:"tokens_used"`
	Cost              float64       `json:"cost"`
	SecurityViolations []string     `json:"security_violations"`
	Metadata          map[string]interface{} `json:"metadata"`
}
