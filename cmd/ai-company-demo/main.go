package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/dimajoyti/hackai/pkg/agents"
	"github.com/dimajoyti/hackai/pkg/binance"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

func main() {
	fmt.Println("🚀 AI-First Company Demo")
	fmt.Println("========================")

	// Initialize logger
	loggerInstance, err := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
	})
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	// Initialize Binance client (using testnet)
	binanceConfig := binance.BinanceConfig{
		APIKey:    os.Getenv("BINANCE_API_KEY"),
		SecretKey: os.Getenv("BINANCE_SECRET_KEY"),
		Testnet:   true, // Use testnet for demo
		Timeout:   30 * time.Second,
	}

	if binanceConfig.APIKey == "" || binanceConfig.SecretKey == "" {
		loggerInstance.Error("Missing required environment variables", "required", []string{"BINANCE_API_KEY", "BINANCE_SECRET_KEY"})
		os.Exit(1)
	}

	binanceClient := binance.NewBinanceClient(binanceConfig, loggerInstance)

	// Initialize orchestrator
	orchestratorConfig := &agents.OrchestratorConfig{
		MaxConcurrentTasks: 10,
		TaskTimeout:        5 * time.Minute,
		WorkerPoolSize:     5,
		EnableMetrics:      true,
		EnableTracing:      true,
	}

	orchestrator := agents.NewBusinessAgentOrchestrator(orchestratorConfig, loggerInstance)

	// Create and register specialized agents
	fmt.Println("\n📋 Initializing AI Agents...")

	// 1. Research Agent
	researchAgent := agents.NewResearchAgent(
		"research-001",
		"Market Research Specialist",
		binanceClient,
		loggerInstance,
	)
	orchestrator.RegisterAgent(researchAgent)
	fmt.Println("✅ Research Agent registered")

	// 2. Creator Agent
	creatorAgent := agents.NewCreatorAgent(
		"creator-001",
		"Content & Strategy Creator",
		loggerInstance,
	)
	orchestrator.RegisterAgent(creatorAgent)
	fmt.Println("✅ Creator Agent registered")

	// 3. Analyst Agent
	analystAgent := agents.NewAnalystAgent(
		"analyst-001",
		"Data Analysis Specialist",
		loggerInstance,
	)
	orchestrator.RegisterAgent(analystAgent)
	fmt.Println("✅ Analyst Agent registered")

	// 4. Operator Agent
	operatorAgent := agents.NewOperatorAgent(
		"operator-001",
		"Trading Operations Specialist",
		binanceClient,
		loggerInstance,
	)
	orchestrator.RegisterAgent(operatorAgent)
	fmt.Println("✅ Operator Agent registered")

	// 5. Strategist Agent
	strategistAgent := agents.NewStrategistAgent(
		"strategist-001",
		"Strategic Decision Maker",
		loggerInstance,
	)
	orchestrator.RegisterAgent(strategistAgent)
	fmt.Println("✅ Strategist Agent registered")

	// Start orchestrator
	ctx := context.Background()
	if err := orchestrator.Start(ctx); err != nil {
		loggerInstance.Error("Failed to start orchestrator", "error", err)
		os.Exit(1)
	}
	defer orchestrator.Stop()

	fmt.Println("✅ Agent Orchestrator started")

	// Demo scenarios
	fmt.Println("\n🎯 Running AI-First Company Demo Scenarios...")

	// Scenario 1: Market Analysis
	fmt.Println("\n--- Scenario 1: Comprehensive Market Analysis ---")
	runMarketAnalysisDemo(ctx, orchestrator)

	// Scenario 2: Trading Workflow
	fmt.Println("\n--- Scenario 2: Automated Trading Workflow ---")
	runTradingWorkflowDemo(ctx, orchestrator)

	// Scenario 3: Portfolio Management
	fmt.Println("\n--- Scenario 3: Portfolio Management ---")
	runPortfolioManagementDemo(ctx, orchestrator)

	// Scenario 4: Risk Assessment
	fmt.Println("\n--- Scenario 4: Risk Assessment ---")
	runRiskAssessmentDemo(ctx, orchestrator)

	// Display agent performance metrics
	fmt.Println("\n📊 Agent Performance Metrics")
	displayAgentMetrics(orchestrator)

	fmt.Println("\n🎉 AI-First Company Demo completed successfully!")
}

// runMarketAnalysisDemo demonstrates market analysis capabilities
func runMarketAnalysisDemo(ctx context.Context, orchestrator *agents.BusinessAgentOrchestrator) {
	fmt.Println("🔍 Performing comprehensive market analysis for BTCUSDT...")

	// Create market analysis task
	task := &agents.BusinessTask{
		ID:          uuid.New().String(),
		Type:        "market_analysis",
		Priority:    agents.PriorityHigh,
		Description: "Comprehensive market analysis for Bitcoin",
		Parameters: map[string]interface{}{
			"symbol": "BTCUSDT",
			"depth":  "comprehensive",
		},
		Context: &agents.BusinessContext{
			UserID:    "demo-user",
			CompanyID: "ai-company-demo",
			MarketData: &agents.MarketContext{
				Symbols:   []string{"BTCUSDT"},
				TimeFrame: "1h",
			},
			Preferences: map[string]interface{}{
				"analysis_depth":    "comprehensive",
				"include_sentiment": true,
			},
		},
		CreatedAt: time.Now(),
	}

	// Execute task
	result, err := orchestrator.ExecuteTask(ctx, task)
	if err != nil {
		fmt.Printf("❌ Market analysis failed: %v\n", err)
		return
	}

	if result.Success {
		fmt.Printf("✅ Market analysis completed (Confidence: %.2f)\n", result.Confidence)
		if analysis, ok := result.Result["analysis"]; ok {
			fmt.Printf("📈 Analysis: %+v\n", analysis)
		}
		if summary, ok := result.Result["summary"]; ok {
			fmt.Printf("📋 Summary: %s\n", summary)
		}
	} else {
		fmt.Printf("❌ Market analysis failed: %s\n", result.Error)
	}
}

// runTradingWorkflowDemo demonstrates automated trading workflow
func runTradingWorkflowDemo(ctx context.Context, orchestrator *agents.BusinessAgentOrchestrator) {
	fmt.Println("⚙️ Executing automated trading workflow...")

	// Create risk profile
	riskProfile := &agents.RiskProfile{
		RiskTolerance:     "moderate",
		MaxPositionSize:   0.1,  // 10% of portfolio
		MaxDailyLoss:      0.05, // 5% daily loss limit
		StopLossPercent:   0.02, // 2% stop loss
		TakeProfitPercent: 0.06, // 6% take profit
	}

	// Create trading workflow
	tradingWorkflow := orchestrator.CreateTradingWorkflow("BTCUSDT", "momentum", riskProfile)

	fmt.Printf("📋 Created trading workflow: %s\n", tradingWorkflow.Name)
	fmt.Printf("🎯 Target: %s | Strategy: %s | Target Return: %.1f%%\n",
		tradingWorkflow.Symbol, tradingWorkflow.Strategy, tradingWorkflow.TargetReturn*100)

	// Execute workflow
	if err := orchestrator.ExecuteWorkflow(ctx, tradingWorkflow.Workflow); err != nil {
		fmt.Printf("❌ Trading workflow failed: %v\n", err)
		return
	}

	fmt.Printf("✅ Trading workflow completed: %s\n", tradingWorkflow.Workflow.Status)

	// Display workflow results
	for stepID, result := range tradingWorkflow.Workflow.Results {
		fmt.Printf("  📋 Step %s: %+v\n", stepID, result)
	}
}

// runPortfolioManagementDemo demonstrates portfolio management
func runPortfolioManagementDemo(ctx context.Context, orchestrator *agents.BusinessAgentOrchestrator) {
	fmt.Println("💼 Managing portfolio...")

	// Create portfolio management task
	task := &agents.BusinessTask{
		ID:          uuid.New().String(),
		Type:        "manage_portfolio",
		Priority:    agents.PriorityNormal,
		Description: "Portfolio management and optimization",
		Parameters: map[string]interface{}{
			"action": "rebalance",
			"target_allocation": map[string]float64{
				"BTCUSDT": 0.4,
				"ETHUSDT": 0.3,
				"ADAUSDT": 0.2,
				"DOTUSDT": 0.1,
			},
		},
		Context: &agents.BusinessContext{
			UserID:    "demo-user",
			CompanyID: "ai-company-demo",
			Portfolio: &agents.PortfolioContext{
				TotalValue:  100000.0, // $100k portfolio
				CashBalance: 20000.0,  // $20k cash
				Positions: []agents.Position{
					{Symbol: "BTCUSDT", Quantity: 1.5, AvgPrice: 45000, CurrentPrice: 47000, Side: "long"},
					{Symbol: "ETHUSDT", Quantity: 10, AvgPrice: 3000, CurrentPrice: 3200, Side: "long"},
				},
			},
		},
		CreatedAt: time.Now(),
	}

	// Execute task
	result, err := orchestrator.ExecuteTask(ctx, task)
	if err != nil {
		fmt.Printf("❌ Portfolio management failed: %v\n", err)
		return
	}

	if result.Success {
		fmt.Printf("✅ Portfolio management completed (Confidence: %.2f)\n", result.Confidence)
		if summary, ok := result.Result["portfolio_summary"]; ok {
			fmt.Printf("💼 Portfolio Summary: %+v\n", summary)
		}
		if performance, ok := result.Result["performance"]; ok {
			fmt.Printf("📊 Performance: %+v\n", performance)
		}
	} else {
		fmt.Printf("❌ Portfolio management failed: %s\n", result.Error)
	}
}

// runRiskAssessmentDemo demonstrates risk assessment
func runRiskAssessmentDemo(ctx context.Context, orchestrator *agents.BusinessAgentOrchestrator) {
	fmt.Println("⚠️ Performing risk assessment...")

	// Create risk assessment task
	task := &agents.BusinessTask{
		ID:          uuid.New().String(),
		Type:        "risk_assessment",
		Priority:    agents.PriorityHigh,
		Description: "Comprehensive risk assessment",
		Parameters: map[string]interface{}{
			"symbols":      []string{"BTCUSDT", "ETHUSDT", "ADAUSDT"},
			"timeframe":    "1d",
			"risk_metrics": []string{"volatility", "var", "correlation"},
		},
		Context: &agents.BusinessContext{
			UserID:    "demo-user",
			CompanyID: "ai-company-demo",
			RiskProfile: &agents.RiskProfile{
				RiskTolerance:     "moderate",
				MaxPositionSize:   0.1,
				MaxDailyLoss:      0.05,
				StopLossPercent:   0.02,
				TakeProfitPercent: 0.06,
			},
		},
		CreatedAt: time.Now(),
	}

	// Execute task
	result, err := orchestrator.ExecuteTask(ctx, task)
	if err != nil {
		fmt.Printf("❌ Risk assessment failed: %v\n", err)
		return
	}

	if result.Success {
		fmt.Printf("✅ Risk assessment completed (Confidence: %.2f)\n", result.Confidence)
		fmt.Printf("⚠️ Risk Analysis: %+v\n", result.Result)
	} else {
		fmt.Printf("❌ Risk assessment failed: %s\n", result.Error)
	}
}

// displayAgentMetrics shows performance metrics for all agents
func displayAgentMetrics(orchestrator *agents.BusinessAgentOrchestrator) {
	metrics := orchestrator.GetAgentMetrics()

	for agentID, metric := range metrics {
		fmt.Printf("\n🤖 Agent: %s\n", agentID)
		fmt.Printf("  📊 Tasks Completed: %d\n", metric.TasksCompleted)
		fmt.Printf("  ✅ Success Rate: %.2f%%\n", metric.SuccessRate*100)
		fmt.Printf("  ⏱️ Avg Execution Time: %v\n", metric.AvgExecutionTime)
		fmt.Printf("  🎯 Specialization Scores:\n")
		for spec, score := range metric.SpecializationScore {
			fmt.Printf("    - %s: %.2f\n", spec, score)
		}
	}
}
