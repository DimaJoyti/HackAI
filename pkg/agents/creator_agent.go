package agents

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// CreatorAgent specializes in content generation, strategy creation, and automated reporting
type CreatorAgent struct {
	*BaseBusinessAgent
	templateEngine  *TemplateEngine
	strategyBuilder *StrategyBuilder
	reportGenerator *ReportGenerator
}

// TemplateEngine handles content templates
type TemplateEngine struct {
	templates map[string]*ContentTemplate
}

// StrategyBuilder creates trading strategies
type StrategyBuilder struct {
	strategies map[string]*StrategyTemplate
}

// ReportGenerator creates reports and documentation
type ReportGenerator struct {
	reportTypes map[string]*ReportTemplate
}

// ContentTemplate represents a content template
type ContentTemplate struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	Template  string                 `json:"template"`
	Variables []string               `json:"variables"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// StrategyTemplate represents a trading strategy template
type StrategyTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Parameters  []StrategyParameter    `json:"parameters"`
	Rules       []StrategyRule         `json:"rules"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// StrategyParameter represents a strategy parameter
type StrategyParameter struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	DefaultValue interface{} `json:"default_value"`
	Description  string      `json:"description"`
	Required     bool        `json:"required"`
}

// StrategyRule represents a strategy rule
type StrategyRule struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Condition string                 `json:"condition"`
	Action    string                 `json:"action"`
	Priority  int                    `json:"priority"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ReportTemplate represents a report template
type ReportTemplate struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Sections []ReportSection        `json:"sections"`
	Format   string                 `json:"format"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ReportSection represents a section in a report
type ReportSection struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Type        string                 `json:"type"`
	Content     string                 `json:"content"`
	DataSources []string               `json:"data_sources"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// TradingStrategy represents a complete trading strategy
type TradingStrategy struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Type            string                 `json:"type"`
	Description     string                 `json:"description"`
	Symbol          string                 `json:"symbol"`
	TimeFrame       string                 `json:"time_frame"`
	EntryConditions []string               `json:"entry_conditions"`
	ExitConditions  []string               `json:"exit_conditions"`
	RiskManagement  *RiskManagementRules   `json:"risk_management"`
	Parameters      map[string]interface{} `json:"parameters"`
	Backtesting     *BacktestResults       `json:"backtesting,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// RiskManagementRules defines risk management for a strategy
type RiskManagementRules struct {
	StopLoss     float64 `json:"stop_loss"`
	TakeProfit   float64 `json:"take_profit"`
	PositionSize float64 `json:"position_size"`
	MaxDrawdown  float64 `json:"max_drawdown"`
	RiskReward   float64 `json:"risk_reward"`
}

// BacktestResults contains backtesting results
type BacktestResults struct {
	TotalReturn    float64   `json:"total_return"`
	SharpeRatio    float64   `json:"sharpe_ratio"`
	MaxDrawdown    float64   `json:"max_drawdown"`
	WinRate        float64   `json:"win_rate"`
	ProfitFactor   float64   `json:"profit_factor"`
	TotalTrades    int       `json:"total_trades"`
	BacktestPeriod string    `json:"backtest_period"`
	CreatedAt      time.Time `json:"created_at"`
}

// NewCreatorAgent creates a new creator agent
func NewCreatorAgent(id, name string, logger *logger.Logger) *CreatorAgent {
	baseAgent := NewBaseBusinessAgent(id, name, "Content generation and strategy creation specialist", AgentTypeCreator, logger)

	agent := &CreatorAgent{
		BaseBusinessAgent: baseAgent,
		templateEngine:    NewTemplateEngine(),
		strategyBuilder:   NewStrategyBuilder(),
		reportGenerator:   NewReportGenerator(),
	}

	// Add creator specializations
	agent.AddSpecialization("content_generation")
	agent.AddSpecialization("strategy_creation")
	agent.AddSpecialization("report_generation")
	agent.AddSpecialization("documentation")
	agent.AddSpecialization("template_management")

	return agent
}

// NewTemplateEngine creates a new template engine
func NewTemplateEngine() *TemplateEngine {
	engine := &TemplateEngine{
		templates: make(map[string]*ContentTemplate),
	}
	engine.initializeDefaultTemplates()
	return engine
}

// NewStrategyBuilder creates a new strategy builder
func NewStrategyBuilder() *StrategyBuilder {
	builder := &StrategyBuilder{
		strategies: make(map[string]*StrategyTemplate),
	}
	builder.initializeDefaultStrategies()
	return builder
}

// NewReportGenerator creates a new report generator
func NewReportGenerator() *ReportGenerator {
	generator := &ReportGenerator{
		reportTypes: make(map[string]*ReportTemplate),
	}
	generator.initializeDefaultReports()
	return generator
}

// ExecuteBusinessTask executes creator-specific tasks
func (c *CreatorAgent) ExecuteBusinessTask(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	ctx, span := businessAgentTracer.Start(ctx, "creator_agent.execute_task",
		trace.WithAttributes(
			attribute.String("task.type", task.Type),
			attribute.String("agent.type", string(c.agentType)),
		),
	)
	defer span.End()

	switch task.Type {
	case "create_strategy":
		return c.createStrategy(ctx, task)
	case "generate_report":
		return c.generateReport(ctx, task)
	case "create_content":
		return c.createContent(ctx, task)
	case "generate_documentation":
		return c.generateDocumentation(ctx, task)
	case "create_template":
		return c.createTemplate(ctx, task)
	default:
		return c.BaseBusinessAgent.ExecuteBusinessTask(ctx, task)
	}
}

// createStrategy creates a trading strategy
func (c *CreatorAgent) createStrategy(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	symbol, ok := task.Parameters["symbol"].(string)
	if !ok {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     "symbol parameter is required",
			CreatedAt: time.Now(),
		}, nil
	}

	strategyType, ok := task.Parameters["strategy"].(string)
	if !ok {
		strategyType = "momentum" // Default strategy
	}

	// Get strategy template
	template, exists := c.strategyBuilder.strategies[strategyType]
	if !exists {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     fmt.Sprintf("strategy template %s not found", strategyType),
			CreatedAt: time.Now(),
		}, nil
	}

	// Create strategy based on template
	strategy := &TradingStrategy{
		ID:          fmt.Sprintf("strategy_%s_%d", symbol, time.Now().Unix()),
		Name:        fmt.Sprintf("%s Strategy for %s", template.Name, symbol),
		Type:        strategyType,
		Description: template.Description,
		Symbol:      symbol,
		TimeFrame:   "1h", // Default timeframe
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Parameters:  make(map[string]interface{}),
	}

	// Build entry and exit conditions based on strategy type
	switch strategyType {
	case "momentum":
		strategy.EntryConditions = []string{
			"RSI > 50",
			"Price > MA20",
			"Volume > Average Volume * 1.5",
		}
		strategy.ExitConditions = []string{
			"RSI < 30",
			"Price < MA20",
			"Stop Loss triggered",
		}
		strategy.RiskManagement = &RiskManagementRules{
			StopLoss:     0.02, // 2%
			TakeProfit:   0.06, // 6%
			PositionSize: 0.1,  // 10% of portfolio
			MaxDrawdown:  0.15, // 15%
			RiskReward:   3.0,  // 1:3 risk-reward ratio
		}

	case "mean_reversion":
		strategy.EntryConditions = []string{
			"RSI < 30",
			"Price < Bollinger Lower Band",
			"Volume > Average Volume",
		}
		strategy.ExitConditions = []string{
			"RSI > 70",
			"Price > Bollinger Upper Band",
			"Take Profit triggered",
		}
		strategy.RiskManagement = &RiskManagementRules{
			StopLoss:     0.03, // 3%
			TakeProfit:   0.05, // 5%
			PositionSize: 0.15, // 15% of portfolio
			MaxDrawdown:  0.10, // 10%
			RiskReward:   1.67, // 1:1.67 risk-reward ratio
		}

	case "breakout":
		strategy.EntryConditions = []string{
			"Price breaks above resistance",
			"Volume > Average Volume * 2",
			"RSI > 60",
		}
		strategy.ExitConditions = []string{
			"Price falls below support",
			"Volume decreases significantly",
			"Stop Loss triggered",
		}
		strategy.RiskManagement = &RiskManagementRules{
			StopLoss:     0.025, // 2.5%
			TakeProfit:   0.08,  // 8%
			PositionSize: 0.08,  // 8% of portfolio
			MaxDrawdown:  0.12,  // 12%
			RiskReward:   3.2,   // 1:3.2 risk-reward ratio
		}
	}

	// Add strategy parameters from task
	if params, ok := task.Parameters["parameters"].(map[string]interface{}); ok {
		for key, value := range params {
			strategy.Parameters[key] = value
		}
	}

	result := &BusinessTaskResult{
		TaskID:  task.ID,
		Success: true,
		Result: map[string]interface{}{
			"strategy": strategy,
			"summary":  c.generateStrategySummary(strategy),
		},
		Confidence:    0.85,
		ExecutionTime: time.Since(time.Now()),
		CreatedAt:     time.Now(),
	}

	c.updateTaskMetrics(true, result.ExecutionTime)
	return result, nil
}

// generateReport generates various types of reports
func (c *CreatorAgent) generateReport(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	reportType, ok := task.Parameters["type"].(string)
	if !ok {
		reportType = "market_analysis" // Default report type
	}

	template, exists := c.reportGenerator.reportTypes[reportType]
	if !exists {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     fmt.Sprintf("report template %s not found", reportType),
			CreatedAt: time.Now(),
		}, nil
	}

	// Generate report content
	report := c.buildReport(template, task.Parameters)

	result := &BusinessTaskResult{
		TaskID:  task.ID,
		Success: true,
		Result: map[string]interface{}{
			"report":      report,
			"report_type": reportType,
			"format":      template.Format,
		},
		Confidence:    0.9,
		ExecutionTime: time.Since(time.Now()),
		CreatedAt:     time.Now(),
	}

	c.updateTaskMetrics(true, result.ExecutionTime)
	return result, nil
}

// createContent creates various types of content
func (c *CreatorAgent) createContent(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	contentType, ok := task.Parameters["content_type"].(string)
	if !ok {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     "content_type parameter is required",
			CreatedAt: time.Now(),
		}, nil
	}

	template, exists := c.templateEngine.templates[contentType]
	if !exists {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     fmt.Sprintf("content template %s not found", contentType),
			CreatedAt: time.Now(),
		}, nil
	}

	// Generate content using template
	content := c.generateContentFromTemplate(template, task.Parameters)

	result := &BusinessTaskResult{
		TaskID:  task.ID,
		Success: true,
		Result: map[string]interface{}{
			"content":      content,
			"content_type": contentType,
			"template_id":  template.ID,
		},
		Confidence:    0.8,
		ExecutionTime: time.Since(time.Now()),
		CreatedAt:     time.Now(),
	}

	c.updateTaskMetrics(true, result.ExecutionTime)
	return result, nil
}

// generateDocumentation generates documentation
func (c *CreatorAgent) generateDocumentation(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Implementation for documentation generation
	return &BusinessTaskResult{
		TaskID:     task.ID,
		Success:    true,
		Result:     map[string]interface{}{"message": "Documentation generated"},
		Confidence: 0.85,
		CreatedAt:  time.Now(),
	}, nil
}

// createTemplate creates new templates
func (c *CreatorAgent) createTemplate(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Implementation for template creation
	return &BusinessTaskResult{
		TaskID:     task.ID,
		Success:    true,
		Result:     map[string]interface{}{"message": "Template created"},
		Confidence: 0.8,
		CreatedAt:  time.Now(),
	}, nil
}

// Helper methods

// generateStrategySummary generates a summary of a trading strategy
func (c *CreatorAgent) generateStrategySummary(strategy *TradingStrategy) string {
	summary := fmt.Sprintf("Trading Strategy: %s\n", strategy.Name)
	summary += fmt.Sprintf("Type: %s | Symbol: %s | Timeframe: %s\n", strategy.Type, strategy.Symbol, strategy.TimeFrame)
	summary += fmt.Sprintf("Risk Management: Stop Loss: %.1f%%, Take Profit: %.1f%%\n",
		strategy.RiskManagement.StopLoss*100, strategy.RiskManagement.TakeProfit*100)
	summary += "Entry Conditions:\n"
	for _, condition := range strategy.EntryConditions {
		summary += fmt.Sprintf("- %s\n", condition)
	}
	summary += "Exit Conditions:\n"
	for _, condition := range strategy.ExitConditions {
		summary += fmt.Sprintf("- %s\n", condition)
	}
	return summary
}

// buildReport builds a report from a template
func (c *CreatorAgent) buildReport(template *ReportTemplate, parameters map[string]interface{}) string {
	report := fmt.Sprintf("# %s Report\n\n", template.Name)
	report += fmt.Sprintf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	for _, section := range template.Sections {
		report += fmt.Sprintf("## %s\n\n", section.Title)
		report += c.generateSectionContent(section, parameters)
		report += "\n\n"
	}

	return report
}

// generateSectionContent generates content for a report section
func (c *CreatorAgent) generateSectionContent(section ReportSection, parameters map[string]interface{}) string {
	switch section.Type {
	case "summary":
		return "This section provides a summary of the analysis."
	case "data_table":
		return "| Metric | Value |\n|--------|-------|\n| Sample | Data |"
	case "chart":
		return "[Chart placeholder - would contain actual chart data]"
	default:
		return section.Content
	}
}

// generateContentFromTemplate generates content from a template
func (c *CreatorAgent) generateContentFromTemplate(template *ContentTemplate, parameters map[string]interface{}) string {
	content := template.Template

	// Replace variables in template
	for _, variable := range template.Variables {
		if value, exists := parameters[variable]; exists {
			placeholder := fmt.Sprintf("{{%s}}", variable)
			content = strings.ReplaceAll(content, placeholder, fmt.Sprintf("%v", value))
		}
	}

	return content
}

// Initialize default templates and strategies

// initializeDefaultTemplates initializes default content templates
func (te *TemplateEngine) initializeDefaultTemplates() {
	templates := []*ContentTemplate{
		{
			ID:        "market_alert",
			Name:      "Market Alert",
			Type:      "alert",
			Template:  "🚨 Market Alert for {{symbol}}\nPrice: ${{price}}\nChange: {{change}}%\nVolume: {{volume}}",
			Variables: []string{"symbol", "price", "change", "volume"},
		},
		{
			ID:        "trade_summary",
			Name:      "Trade Summary",
			Type:      "summary",
			Template:  "Trade executed: {{side}} {{quantity}} {{symbol}} at ${{price}}\nP&L: {{pnl}}\nStatus: {{status}}",
			Variables: []string{"side", "quantity", "symbol", "price", "pnl", "status"},
		},
	}

	for _, template := range templates {
		te.templates[template.ID] = template
	}
}

// initializeDefaultStrategies initializes default strategy templates
func (sb *StrategyBuilder) initializeDefaultStrategies() {
	strategies := []*StrategyTemplate{
		{
			ID:          "momentum",
			Name:        "Momentum Strategy",
			Type:        "trend_following",
			Description: "Follows strong price momentum with volume confirmation",
		},
		{
			ID:          "mean_reversion",
			Name:        "Mean Reversion Strategy",
			Type:        "contrarian",
			Description: "Trades against extreme price movements expecting reversion to mean",
		},
		{
			ID:          "breakout",
			Name:        "Breakout Strategy",
			Type:        "momentum",
			Description: "Trades price breakouts from consolidation patterns",
		},
	}

	for _, strategy := range strategies {
		sb.strategies[strategy.ID] = strategy
	}
}

// initializeDefaultReports initializes default report templates
func (rg *ReportGenerator) initializeDefaultReports() {
	reports := []*ReportTemplate{
		{
			ID:     "market_analysis",
			Name:   "Market Analysis",
			Type:   "analysis",
			Format: "markdown",
			Sections: []ReportSection{
				{ID: "summary", Title: "Executive Summary", Type: "summary"},
				{ID: "data", Title: "Market Data", Type: "data_table"},
				{ID: "charts", Title: "Charts", Type: "chart"},
			},
		},
		{
			ID:     "portfolio_performance",
			Name:   "Portfolio Performance",
			Type:   "performance",
			Format: "markdown",
			Sections: []ReportSection{
				{ID: "overview", Title: "Portfolio Overview", Type: "summary"},
				{ID: "performance", Title: "Performance Metrics", Type: "data_table"},
				{ID: "positions", Title: "Current Positions", Type: "data_table"},
			},
		},
	}

	for _, report := range reports {
		rg.reportTypes[report.ID] = report
	}
}
