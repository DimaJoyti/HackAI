package agents

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var businessAgentTracer = otel.Tracer("hackai/agents/business")

// BusinessAgentType defines the type of business agent
type BusinessAgentType string

const (
	AgentTypeResearch   BusinessAgentType = "research"
	AgentTypeCreator    BusinessAgentType = "creator"
	AgentTypeAnalyst    BusinessAgentType = "analyst"
	AgentTypeOperator   BusinessAgentType = "operator"
	AgentTypeStrategist BusinessAgentType = "strategist"
)

// BusinessAgent represents a specialized business-focused AI agent
type BusinessAgent interface {
	ai.Agent
	GetAgentType() BusinessAgentType
	GetSpecializations() []string
	GetPerformanceMetrics() *BusinessAgentMetrics
	ExecuteBusinessTask(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error)
	CollaborateWith(ctx context.Context, otherAgent BusinessAgent, task *CollaborationTask) (*CollaborationResult, error)
}

// BusinessTask represents a business-specific task
type BusinessTask struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Priority    TaskPriority           `json:"priority"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Deadline    *time.Time             `json:"deadline,omitempty"`
	Context     *BusinessContext       `json:"context"`
	CreatedAt   time.Time              `json:"created_at"`
}

// BusinessTaskResult represents the result of a business task execution
type BusinessTaskResult struct {
	TaskID       string                 `json:"task_id"`
	Success      bool                   `json:"success"`
	Result       map[string]interface{} `json:"result"`
	Confidence   float64                `json:"confidence"`
	ExecutionTime time.Duration         `json:"execution_time"`
	Metadata     map[string]interface{} `json:"metadata"`
	Error        string                 `json:"error,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// BusinessContext provides context for business operations
type BusinessContext struct {
	UserID        string                 `json:"user_id"`
	CompanyID     string                 `json:"company_id"`
	MarketData    *MarketContext         `json:"market_data,omitempty"`
	Portfolio     *PortfolioContext      `json:"portfolio,omitempty"`
	RiskProfile   *RiskProfile           `json:"risk_profile,omitempty"`
	Preferences   map[string]interface{} `json:"preferences"`
	Constraints   []string               `json:"constraints"`
}

// MarketContext provides market-related context
type MarketContext struct {
	Symbols       []string               `json:"symbols"`
	TimeFrame     string                 `json:"time_frame"`
	MarketHours   bool                   `json:"market_hours"`
	Volatility    float64                `json:"volatility"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// PortfolioContext provides portfolio-related context
type PortfolioContext struct {
	TotalValue    float64                `json:"total_value"`
	Positions     []Position             `json:"positions"`
	CashBalance   float64                `json:"cash_balance"`
	PnL           float64                `json:"pnl"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// Position represents a trading position
type Position struct {
	Symbol    string  `json:"symbol"`
	Quantity  float64 `json:"quantity"`
	AvgPrice  float64 `json:"avg_price"`
	CurrentPrice float64 `json:"current_price"`
	PnL       float64 `json:"pnl"`
	Side      string  `json:"side"` // "long" or "short"
}

// RiskProfile defines risk management parameters
type RiskProfile struct {
	RiskTolerance    string  `json:"risk_tolerance"` // "conservative", "moderate", "aggressive"
	MaxPositionSize  float64 `json:"max_position_size"`
	MaxDailyLoss     float64 `json:"max_daily_loss"`
	StopLossPercent  float64 `json:"stop_loss_percent"`
	TakeProfitPercent float64 `json:"take_profit_percent"`
}

// TaskPriority defines task priority levels
type TaskPriority int

const (
	PriorityLow TaskPriority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// BusinessAgentMetrics tracks agent performance
type BusinessAgentMetrics struct {
	TasksCompleted     int64         `json:"tasks_completed"`
	TasksSuccessful    int64         `json:"tasks_successful"`
	TasksFailed        int64         `json:"tasks_failed"`
	AvgExecutionTime   time.Duration `json:"avg_execution_time"`
	SuccessRate        float64       `json:"success_rate"`
	LastActivity       time.Time     `json:"last_activity"`
	SpecializationScore map[string]float64 `json:"specialization_score"`
}

// CollaborationTask represents a task requiring multiple agents
type CollaborationTask struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Description  string                 `json:"description"`
	Participants []string               `json:"participants"` // Agent IDs
	Workflow     *CollaborationWorkflow `json:"workflow"`
	Context      *BusinessContext       `json:"context"`
	CreatedAt    time.Time              `json:"created_at"`
}

// CollaborationWorkflow defines the workflow for collaboration
type CollaborationWorkflow struct {
	Steps []CollaborationStep `json:"steps"`
}

// CollaborationStep represents a step in collaboration
type CollaborationStep struct {
	ID          string `json:"id"`
	AgentType   BusinessAgentType `json:"agent_type"`
	Action      string `json:"action"`
	Dependencies []string `json:"dependencies"`
}

// CollaborationResult represents the result of collaboration
type CollaborationResult struct {
	TaskID        string                 `json:"task_id"`
	Success       bool                   `json:"success"`
	Results       map[string]interface{} `json:"results"`
	Contributions map[string]interface{} `json:"contributions"` // Per agent
	ExecutionTime time.Duration          `json:"execution_time"`
	Error         string                 `json:"error,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
}

// BaseBusinessAgent provides common functionality for business agents
type BaseBusinessAgent struct {
	*ai.BaseAgent
	agentType       BusinessAgentType
	specializations []string
	metrics         *BusinessAgentMetrics
	collaborators   map[string]BusinessAgent
	mutex           sync.RWMutex
}

// NewBaseBusinessAgent creates a new base business agent
func NewBaseBusinessAgent(id, name, description string, agentType BusinessAgentType, logger *logger.Logger) *BaseBusinessAgent {
	baseAgent := ai.NewBaseAgent(id, name, description, logger)
	
	return &BaseBusinessAgent{
		BaseAgent:       baseAgent,
		agentType:       agentType,
		specializations: make([]string, 0),
		metrics: &BusinessAgentMetrics{
			LastActivity:        time.Now(),
			SpecializationScore: make(map[string]float64),
		},
		collaborators: make(map[string]BusinessAgent),
	}
}

// GetAgentType returns the agent type
func (b *BaseBusinessAgent) GetAgentType() BusinessAgentType {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	return b.agentType
}

// GetSpecializations returns the agent's specializations
func (b *BaseBusinessAgent) GetSpecializations() []string {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	return b.specializations
}

// GetPerformanceMetrics returns the agent's performance metrics
func (b *BaseBusinessAgent) GetPerformanceMetrics() *BusinessAgentMetrics {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	return b.metrics
}

// AddSpecialization adds a specialization to the agent
func (b *BaseBusinessAgent) AddSpecialization(specialization string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	
	b.specializations = append(b.specializations, specialization)
	b.metrics.SpecializationScore[specialization] = 0.5 // Initial score
}

// UpdateSpecializationScore updates the score for a specialization
func (b *BaseBusinessAgent) UpdateSpecializationScore(specialization string, score float64) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	
	b.metrics.SpecializationScore[specialization] = score
}

// ExecuteBusinessTask executes a business-specific task
func (b *BaseBusinessAgent) ExecuteBusinessTask(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	ctx, span := businessAgentTracer.Start(ctx, "business_agent.execute_task",
		trace.WithAttributes(
			attribute.String("agent.id", b.ID()),
			attribute.String("agent.type", string(b.agentType)),
			attribute.String("task.id", task.ID),
			attribute.String("task.type", task.Type),
		),
	)
	defer span.End()

	startTime := time.Now()
	
	// Update metrics
	b.mutex.Lock()
	b.metrics.LastActivity = startTime
	b.mutex.Unlock()

	// Create result
	result := &BusinessTaskResult{
		TaskID:    task.ID,
		CreatedAt: startTime,
		Metadata:  make(map[string]interface{}),
	}

	// This is a base implementation - specific agents will override this
	result.Success = true
	result.Result = map[string]interface{}{
		"message": fmt.Sprintf("Task %s executed by %s agent", task.Type, b.agentType),
		"agent_id": b.ID(),
		"agent_type": string(b.agentType),
	}
	result.Confidence = 0.8
	result.ExecutionTime = time.Since(startTime)

	// Update metrics
	b.updateTaskMetrics(result.Success, result.ExecutionTime)

	span.SetAttributes(
		attribute.Bool("task.success", result.Success),
		attribute.String("task.execution_time", result.ExecutionTime.String()),
		attribute.Float64("task.confidence", result.Confidence),
	)

	return result, nil
}

// updateTaskMetrics updates task execution metrics
func (b *BaseBusinessAgent) updateTaskMetrics(success bool, executionTime time.Duration) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.metrics.TasksCompleted++
	if success {
		b.metrics.TasksSuccessful++
	} else {
		b.metrics.TasksFailed++
	}

	// Update average execution time
	if b.metrics.TasksCompleted == 1 {
		b.metrics.AvgExecutionTime = executionTime
	} else {
		total := time.Duration(b.metrics.TasksCompleted-1) * b.metrics.AvgExecutionTime
		b.metrics.AvgExecutionTime = (total + executionTime) / time.Duration(b.metrics.TasksCompleted)
	}

	// Update success rate
	b.metrics.SuccessRate = float64(b.metrics.TasksSuccessful) / float64(b.metrics.TasksCompleted)
}

// CollaborateWith enables collaboration with other agents
func (b *BaseBusinessAgent) CollaborateWith(ctx context.Context, otherAgent BusinessAgent, task *CollaborationTask) (*CollaborationResult, error) {
	ctx, span := businessAgentTracer.Start(ctx, "business_agent.collaborate",
		trace.WithAttributes(
			attribute.String("agent.id", b.ID()),
			attribute.String("other_agent.id", otherAgent.ID()),
			attribute.String("task.id", task.ID),
		),
	)
	defer span.End()

	startTime := time.Now()

	// Add collaborator
	b.mutex.Lock()
	b.collaborators[otherAgent.ID()] = otherAgent
	b.mutex.Unlock()

	// Create collaboration result
	result := &CollaborationResult{
		TaskID:        task.ID,
		Success:       true,
		Results:       make(map[string]interface{}),
		Contributions: make(map[string]interface{}),
		ExecutionTime: time.Since(startTime),
		CreatedAt:     startTime,
	}

	// Base collaboration logic - specific agents will override this
	result.Results["collaboration"] = fmt.Sprintf("Collaboration between %s and %s", b.ID(), otherAgent.ID())
	result.Contributions[b.ID()] = "Base collaboration contribution"
	result.Contributions[otherAgent.ID()] = "Partner collaboration contribution"

	return result, nil
}
