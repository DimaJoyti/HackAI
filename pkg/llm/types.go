package llm

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ChainInput represents input data for chain execution
type ChainInput map[string]interface{}

// ChainOutput represents output data from chain execution
type ChainOutput map[string]interface{}

// GraphState represents the state of a graph execution
type GraphState struct {
	CurrentNode string                 `json:"current_node"`
	Data        map[string]interface{} `json:"data"`
	History     []StateTransition      `json:"history"`
	Metadata    map[string]interface{} `json:"metadata"`
	StartTime   time.Time              `json:"start_time"`
	UpdateTime  time.Time              `json:"update_time"`
}

// StateTransition represents a transition between graph states
type StateTransition struct {
	From      string                 `json:"from"`
	To        string                 `json:"to"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// HealthStatus represents the health status of the orchestrator
type HealthStatus struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Details   map[string]string `json:"details"`
}

// Chain represents a sequential LLM workflow
type Chain interface {
	ID() string
	Name() string
	Description() string
	Execute(ctx context.Context, input ChainInput) (ChainOutput, error)
	GetMemory() Memory
	SetMemory(Memory)
	Validate() error
}

// StateGraph represents a complex workflow with conditional logic
type StateGraph interface {
	ID() string
	Name() string
	Description() string
	Execute(ctx context.Context, initialState GraphState) (GraphState, error)
	GetNodes() map[string]Node
	GetEdges() map[string][]Edge
	Validate() error
}

// Node represents a single operation in a graph
type Node interface {
	ID() string
	Type() NodeType
	Execute(ctx context.Context, state GraphState) (GraphState, error)
	GetConditions() []Condition
	GetNextNodes() []string
	Validate() error
}

// Edge represents a connection between nodes
type Edge struct {
	From      string      `json:"from"`
	To        string      `json:"to"`
	Condition Condition   `json:"condition"`
	Weight    float64     `json:"weight"`
	Metadata  interface{} `json:"metadata"`
}

// Condition represents a conditional logic for graph execution
type Condition interface {
	Evaluate(ctx context.Context, state GraphState) (bool, error)
	String() string
}

// Memory represents memory storage for chains
type Memory interface {
	Store(ctx context.Context, key string, value interface{}) error
	Retrieve(ctx context.Context, key string) (interface{}, error)
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
	Keys(ctx context.Context) ([]string, error)
}

// Orchestrator manages LLM chains and graphs
type Orchestrator interface {
	// Chain operations
	RegisterChain(chain Chain) error
	UnregisterChain(chainID string) error
	ExecuteChain(ctx context.Context, chainID string, input ChainInput) (ChainOutput, error)
	ListChains() []ChainInfo

	// Graph operations
	RegisterGraph(graph StateGraph) error
	UnregisterGraph(graphID string) error
	ExecuteGraph(ctx context.Context, graphID string, initialState GraphState) (GraphState, error)
	ListGraphs() []GraphInfo

	// Lifecycle management
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health() HealthStatus
}

// ChainInfo provides metadata about a registered chain
type ChainInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GraphInfo provides metadata about a registered graph
type GraphInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	NodeCount   int       `json:"node_count"`
	EdgeCount   int       `json:"edge_count"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NodeType represents the type of a node
type NodeType string

const (
	NodeTypeLLM       NodeType = "llm"
	NodeTypeCondition NodeType = "condition"
	NodeTypeTransform NodeType = "transform"
	NodeTypeMemory    NodeType = "memory"
	NodeTypeAction    NodeType = "action"
	NodeTypeValidator NodeType = "validator"
)

// ChainType represents the type of a chain
type ChainType string

const (
	ChainTypeSequential      ChainType = "sequential"
	ChainTypeParallel        ChainType = "parallel"
	ChainTypeConditional     ChainType = "conditional"
	ChainTypePromptInjection ChainType = "prompt_injection"
	ChainTypeModelExtraction ChainType = "model_extraction"
	ChainTypeDataPoisoning   ChainType = "data_poisoning"
	ChainTypeAdversarial     ChainType = "adversarial"
)

// ExecutionContext provides context for chain/graph execution
type ExecutionContext struct {
	ID        string                 `json:"id"`
	ChainID   string                 `json:"chain_id,omitempty"`
	GraphID   string                 `json:"graph_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
	StartTime time.Time              `json:"start_time"`
	Timeout   time.Duration          `json:"timeout"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ExecutionResult represents the result of a chain/graph execution
type ExecutionResult struct {
	ID          string                 `json:"id"`
	ExecutionID string                 `json:"execution_id"`
	Success     bool                   `json:"success"`
	Output      interface{}            `json:"output"`
	Error       string                 `json:"error,omitempty"`
	Duration    time.Duration          `json:"duration"`
	TokensUsed  int                    `json:"tokens_used"`
	Cost        float64                `json:"cost"`
	Metadata    map[string]interface{} `json:"metadata"`
	CompletedAt time.Time              `json:"completed_at"`
}

// ChainConfig represents configuration for a chain
type ChainConfig struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        ChainType              `json:"type"`
	Enabled     bool                   `json:"enabled"`
	MaxRetries  int                    `json:"max_retries"`
	Timeout     time.Duration          `json:"timeout"`
	Memory      MemoryConfig           `json:"memory"`
	Providers   []ProviderConfig       `json:"providers"`
	Parameters  map[string]interface{} `json:"parameters"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// MemoryConfig represents configuration for memory systems
type MemoryConfig struct {
	Type       string                 `json:"type"`
	MaxSize    int                    `json:"max_size"`
	TTL        time.Duration          `json:"ttl"`
	Persistent bool                   `json:"persistent"`
	Config     map[string]interface{} `json:"config"`
}

// ProviderConfig represents configuration for LLM providers
type ProviderConfig struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Enabled  bool                   `json:"enabled"`
	Priority int                    `json:"priority"`
	Config   map[string]interface{} `json:"config"`
}

// NewExecutionContext creates a new execution context
func NewExecutionContext(chainID, graphID string) *ExecutionContext {
	return &ExecutionContext{
		ID:        uuid.New().String(),
		ChainID:   chainID,
		GraphID:   graphID,
		StartTime: time.Now(),
		Timeout:   5 * time.Minute, // Default timeout
		Metadata:  make(map[string]interface{}),
	}
}

// NewExecutionResult creates a new execution result
func NewExecutionResult(executionID string) *ExecutionResult {
	return &ExecutionResult{
		ID:          uuid.New().String(),
		ExecutionID: executionID,
		CompletedAt: time.Now(),
		Metadata:    make(map[string]interface{}),
	}
}
