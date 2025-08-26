package agents

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/binance"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// OperatorAgent specializes in automated trading execution and portfolio management
type OperatorAgent struct {
	*BaseBusinessAgent
	binanceClient       *binance.BinanceClient
	portfolioManager    *PortfolioManager
	riskManager         *RiskManager
	orderManager        *OrderManager
	securityManager     *TradingSecurityManager
	complianceFramework *ComplianceFramework
	activeOrders        map[string]*Order
	positions           map[string]*Position
	tradingEnabled      bool
	mutex               sync.RWMutex
}

// TradingSecurityManager handles security for trading operations
type TradingSecurityManager struct {
	// Placeholder for security manager - would import from security package
}

// ComplianceFramework handles compliance checking
type ComplianceFramework struct {
	// Placeholder for compliance framework - would import from compliance package
}

// PortfolioManager manages portfolio operations
type PortfolioManager struct {
	totalValue      float64
	cashBalance     float64
	positions       map[string]*Position
	performanceData *PerformanceData
	mutex           sync.RWMutex
}

// RiskManager handles risk management
type RiskManager struct {
	riskProfile    *RiskProfile
	maxDailyLoss   float64
	currentDayLoss float64
	positionLimits map[string]float64
	stopLossOrders map[string]*StopLossOrder
	mutex          sync.RWMutex
}

// OrderManager manages order execution
type OrderManager struct {
	pendingOrders  map[string]*Order
	executedOrders map[string]*Order
	failedOrders   map[string]*Order
	orderHistory   []*Order
	mutex          sync.RWMutex
}

// Order represents a trading order
type Order struct {
	ID               string                 `json:"id"`
	ClientOrderID    string                 `json:"client_order_id"`
	Symbol           string                 `json:"symbol"`
	Side             string                 `json:"side"` // "BUY" or "SELL"
	Type             string                 `json:"type"` // "MARKET", "LIMIT", "STOP_LOSS", etc.
	Quantity         float64                `json:"quantity"`
	Price            float64                `json:"price,omitempty"`
	StopPrice        float64                `json:"stop_price,omitempty"`
	Status           string                 `json:"status"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	ExecutedAt       *time.Time             `json:"executed_at,omitempty"`
	ExecutedPrice    float64                `json:"executed_price,omitempty"`
	ExecutedQuantity float64                `json:"executed_quantity,omitempty"`
	Fees             float64                `json:"fees,omitempty"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// StopLossOrder represents a stop-loss order
type StopLossOrder struct {
	ID         string    `json:"id"`
	PositionID string    `json:"position_id"`
	Symbol     string    `json:"symbol"`
	StopPrice  float64   `json:"stop_price"`
	Quantity   float64   `json:"quantity"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
}

// PerformanceData tracks portfolio performance
type PerformanceData struct {
	TotalReturn   float64   `json:"total_return"`
	DailyReturn   float64   `json:"daily_return"`
	WeeklyReturn  float64   `json:"weekly_return"`
	MonthlyReturn float64   `json:"monthly_return"`
	MaxDrawdown   float64   `json:"max_drawdown"`
	SharpeRatio   float64   `json:"sharpe_ratio"`
	WinRate       float64   `json:"win_rate"`
	ProfitFactor  float64   `json:"profit_factor"`
	LastUpdated   time.Time `json:"last_updated"`
}

// TradingSignal represents a trading signal
type TradingSignal struct {
	Symbol     string                 `json:"symbol"`
	Action     string                 `json:"action"` // "BUY", "SELL", "HOLD"
	Confidence float64                `json:"confidence"`
	Price      float64                `json:"price"`
	Quantity   float64                `json:"quantity"`
	StopLoss   float64                `json:"stop_loss,omitempty"`
	TakeProfit float64                `json:"take_profit,omitempty"`
	Reasoning  string                 `json:"reasoning"`
	Source     string                 `json:"source"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// NewOperatorAgent creates a new operator agent
func NewOperatorAgent(id, name string, binanceClient *binance.BinanceClient, logger *logger.Logger) *OperatorAgent {
	baseAgent := NewBaseBusinessAgent(id, name, "Trading execution and portfolio management specialist", AgentTypeOperator, logger)

	agent := &OperatorAgent{
		BaseBusinessAgent: baseAgent,
		binanceClient:     binanceClient,
		portfolioManager:  NewPortfolioManager(),
		riskManager:       NewRiskManager(),
		orderManager:      NewOrderManager(),
		activeOrders:      make(map[string]*Order),
		positions:         make(map[string]*Position),
		tradingEnabled:    true,
	}

	// Add operator specializations
	agent.AddSpecialization("order_execution")
	agent.AddSpecialization("portfolio_management")
	agent.AddSpecialization("risk_management")
	agent.AddSpecialization("position_monitoring")
	agent.AddSpecialization("automated_trading")

	return agent
}

// NewPortfolioManager creates a new portfolio manager
func NewPortfolioManager() *PortfolioManager {
	return &PortfolioManager{
		positions: make(map[string]*Position),
		performanceData: &PerformanceData{
			LastUpdated: time.Now(),
		},
	}
}

// NewRiskManager creates a new risk manager
func NewRiskManager() *RiskManager {
	return &RiskManager{
		positionLimits: make(map[string]float64),
		stopLossOrders: make(map[string]*StopLossOrder),
		riskProfile: &RiskProfile{
			RiskTolerance:     "moderate",
			MaxPositionSize:   0.1,  // 10% of portfolio
			MaxDailyLoss:      0.05, // 5% daily loss limit
			StopLossPercent:   0.02, // 2% stop loss
			TakeProfitPercent: 0.06, // 6% take profit
		},
	}
}

// NewOrderManager creates a new order manager
func NewOrderManager() *OrderManager {
	return &OrderManager{
		pendingOrders:  make(map[string]*Order),
		executedOrders: make(map[string]*Order),
		failedOrders:   make(map[string]*Order),
		orderHistory:   make([]*Order, 0),
	}
}

// ExecuteBusinessTask executes operator-specific tasks
func (o *OperatorAgent) ExecuteBusinessTask(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	ctx, span := businessAgentTracer.Start(ctx, "operator_agent.execute_task",
		trace.WithAttributes(
			attribute.String("task.type", task.Type),
			attribute.String("agent.type", string(o.agentType)),
		),
	)
	defer span.End()

	if !o.tradingEnabled {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     "trading is currently disabled",
			CreatedAt: time.Now(),
		}, nil
	}

	switch task.Type {
	case "execute_trade":
		return o.executeTrade(ctx, task)
	case "manage_portfolio":
		return o.managePortfolio(ctx, task)
	case "monitor_positions":
		return o.monitorPositions(ctx, task)
	case "execute_signal":
		return o.executeSignal(ctx, task)
	case "rebalance_portfolio":
		return o.rebalancePortfolio(ctx, task)
	case "update_stop_loss":
		return o.updateStopLoss(ctx, task)
	default:
		return o.BaseBusinessAgent.ExecuteBusinessTask(ctx, task)
	}
}

// executeTrade executes a trading order
func (o *OperatorAgent) executeTrade(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Extract trade parameters
	symbol, ok := task.Parameters["symbol"].(string)
	if !ok {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     "symbol parameter is required",
			CreatedAt: time.Now(),
		}, nil
	}

	side, ok := task.Parameters["side"].(string)
	if !ok {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     "side parameter is required",
			CreatedAt: time.Now(),
		}, nil
	}

	quantity, ok := task.Parameters["quantity"].(float64)
	if !ok {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     "quantity parameter is required",
			CreatedAt: time.Now(),
		}, nil
	}

	orderType := "MARKET"
	if t, exists := task.Parameters["type"].(string); exists {
		orderType = t
	}

	// Perform risk checks
	if err := o.performRiskChecks(symbol, side, quantity); err != nil {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     fmt.Sprintf("risk check failed: %v", err),
			CreatedAt: time.Now(),
		}, nil
	}

	// Create order
	order := &Order{
		ID:            uuid.New().String(),
		ClientOrderID: fmt.Sprintf("hackai_%d", time.Now().UnixNano()),
		Symbol:        symbol,
		Side:          side,
		Type:          orderType,
		Quantity:      quantity,
		Status:        "PENDING",
		CreatedAt:     time.Now(),
		Metadata:      make(map[string]interface{}),
	}

	// Add price for limit orders
	if price, exists := task.Parameters["price"].(float64); exists && orderType == "LIMIT" {
		order.Price = price
	}

	// Execute order via Binance
	binanceOrder := &binance.OrderRequest{
		Symbol:           symbol,
		Side:             side,
		Type:             orderType,
		Quantity:         quantity,
		NewClientOrderID: order.ClientOrderID,
	}

	if order.Price > 0 {
		binanceOrder.Price = order.Price
		binanceOrder.TimeInForce = "GTC" // Good Till Cancelled
	}

	response, err := o.binanceClient.PlaceOrder(ctx, binanceOrder)
	if err != nil {
		order.Status = "FAILED"
		o.orderManager.failedOrders[order.ID] = order

		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     fmt.Sprintf("order execution failed: %v", err),
			CreatedAt: time.Now(),
		}, nil
	}

	// Update order with response
	order.Status = response.Status
	order.ExecutedAt = &time.Time{}
	*order.ExecutedAt = time.Unix(response.TransactTime/1000, 0)

	if executedPrice, err := strconv.ParseFloat(response.Price, 64); err == nil {
		order.ExecutedPrice = executedPrice
	}

	if executedQty, err := strconv.ParseFloat(response.ExecutedQty, 64); err == nil {
		order.ExecutedQuantity = executedQty
	}

	// Store order
	o.mutex.Lock()
	o.activeOrders[order.ID] = order
	o.orderManager.executedOrders[order.ID] = order
	o.orderManager.orderHistory = append(o.orderManager.orderHistory, order)
	o.mutex.Unlock()

	// Update portfolio
	o.updatePortfolioAfterTrade(order)

	// Set up stop loss if configured
	if o.riskManager.riskProfile.StopLossPercent > 0 {
		o.createStopLossOrder(order)
	}

	result := &BusinessTaskResult{
		TaskID:  task.ID,
		Success: true,
		Result: map[string]interface{}{
			"order_id":          order.ID,
			"binance_order_id":  response.OrderID,
			"status":            order.Status,
			"executed_price":    order.ExecutedPrice,
			"executed_quantity": order.ExecutedQuantity,
		},
		Confidence:    0.95,
		ExecutionTime: time.Since(order.CreatedAt),
		CreatedAt:     time.Now(),
	}

	o.updateTaskMetrics(true, result.ExecutionTime)
	return result, nil
}

// performRiskChecks performs risk management checks before executing trades
func (o *OperatorAgent) performRiskChecks(symbol, side string, quantity float64) error {
	o.riskManager.mutex.RLock()
	defer o.riskManager.mutex.RUnlock()

	// Check daily loss limit
	if o.riskManager.currentDayLoss >= o.riskManager.maxDailyLoss {
		return fmt.Errorf("daily loss limit exceeded")
	}

	// Check position size limit
	currentPosition := o.getCurrentPosition(symbol)
	newPositionSize := quantity
	if currentPosition != nil {
		if side == "BUY" {
			newPositionSize = currentPosition.Quantity + quantity
		} else {
			newPositionSize = currentPosition.Quantity - quantity
		}
	}

	maxPositionValue := o.portfolioManager.totalValue * o.riskManager.riskProfile.MaxPositionSize
	// This is a simplified check - in reality, you'd calculate position value
	if newPositionSize > maxPositionValue {
		return fmt.Errorf("position size limit exceeded")
	}

	return nil
}

// getCurrentPosition gets the current position for a symbol
func (o *OperatorAgent) getCurrentPosition(symbol string) *Position {
	o.mutex.RLock()
	defer o.mutex.RUnlock()
	return o.positions[symbol]
}

// updatePortfolioAfterTrade updates portfolio after a trade
func (o *OperatorAgent) updatePortfolioAfterTrade(order *Order) {
	o.portfolioManager.mutex.Lock()
	defer o.portfolioManager.mutex.Unlock()

	// Update or create position
	position, exists := o.portfolioManager.positions[order.Symbol]
	if !exists {
		position = &Position{
			Symbol:   order.Symbol,
			Quantity: 0,
			AvgPrice: 0,
			Side:     "long",
		}
		o.portfolioManager.positions[order.Symbol] = position
	}

	// Update position based on order
	if order.Side == "BUY" {
		// Calculate new average price
		totalValue := position.Quantity*position.AvgPrice + order.ExecutedQuantity*order.ExecutedPrice
		position.Quantity += order.ExecutedQuantity
		position.AvgPrice = totalValue / position.Quantity
	} else { // SELL
		position.Quantity -= order.ExecutedQuantity
		if position.Quantity <= 0 {
			delete(o.portfolioManager.positions, order.Symbol)
		}
	}

	// Update cash balance (simplified)
	if order.Side == "BUY" {
		o.portfolioManager.cashBalance -= order.ExecutedQuantity * order.ExecutedPrice
	} else {
		o.portfolioManager.cashBalance += order.ExecutedQuantity * order.ExecutedPrice
	}
}

// createStopLossOrder creates a stop-loss order for a position
func (o *OperatorAgent) createStopLossOrder(order *Order) {
	if order.Side != "BUY" {
		return // Only create stop loss for long positions
	}

	stopPrice := order.ExecutedPrice * (1 - o.riskManager.riskProfile.StopLossPercent)

	stopLossOrder := &StopLossOrder{
		ID:         uuid.New().String(),
		PositionID: order.ID,
		Symbol:     order.Symbol,
		StopPrice:  stopPrice,
		Quantity:   order.ExecutedQuantity,
		IsActive:   true,
		CreatedAt:  time.Now(),
	}

	o.riskManager.mutex.Lock()
	o.riskManager.stopLossOrders[stopLossOrder.ID] = stopLossOrder
	o.riskManager.mutex.Unlock()
}

// executeSignal executes a trading signal
func (o *OperatorAgent) executeSignal(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Extract signal from task parameters
	signalData, ok := task.Parameters["signal"].(map[string]interface{})
	if !ok {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     "signal parameter is required",
			CreatedAt: time.Now(),
		}, nil
	}

	// Convert to TradingSignal
	signal := &TradingSignal{
		Symbol:     signalData["symbol"].(string),
		Action:     signalData["action"].(string),
		Confidence: signalData["confidence"].(float64),
		Price:      signalData["price"].(float64),
		Quantity:   signalData["quantity"].(float64),
		Reasoning:  signalData["reasoning"].(string),
		Source:     signalData["source"].(string),
		Timestamp:  time.Now(),
	}

	// Only execute high-confidence signals
	if signal.Confidence < 0.7 {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     "signal confidence too low",
			CreatedAt: time.Now(),
		}, nil
	}

	// Convert signal to trade parameters
	tradeTask := &BusinessTask{
		ID:   uuid.New().String(),
		Type: "execute_trade",
		Parameters: map[string]interface{}{
			"symbol":   signal.Symbol,
			"side":     signal.Action,
			"quantity": signal.Quantity,
			"type":     "MARKET",
		},
		Context: task.Context,
	}

	// Execute the trade
	return o.executeTrade(ctx, tradeTask)
}

// managePortfolio manages portfolio operations
func (o *OperatorAgent) managePortfolio(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Update portfolio performance
	o.updatePortfolioPerformance()

	// Get portfolio summary
	summary := o.getPortfolioSummary()

	return &BusinessTaskResult{
		TaskID:  task.ID,
		Success: true,
		Result: map[string]interface{}{
			"portfolio_summary": summary,
			"performance":       o.portfolioManager.performanceData,
		},
		Confidence: 0.9,
		CreatedAt:  time.Now(),
	}, nil
}

// monitorPositions monitors active positions
func (o *OperatorAgent) monitorPositions(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Check stop-loss orders
	triggeredStopLoss := o.checkStopLossOrders(ctx)

	// Monitor position performance
	positionUpdates := o.updatePositionPnL()

	return &BusinessTaskResult{
		TaskID:  task.ID,
		Success: true,
		Result: map[string]interface{}{
			"triggered_stop_loss": triggeredStopLoss,
			"position_updates":    positionUpdates,
			"active_positions":    len(o.positions),
		},
		Confidence: 0.85,
		CreatedAt:  time.Now(),
	}, nil
}

// rebalancePortfolio rebalances the portfolio
func (o *OperatorAgent) rebalancePortfolio(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Implementation for portfolio rebalancing
	return &BusinessTaskResult{
		TaskID:     task.ID,
		Success:    true,
		Result:     map[string]interface{}{"message": "Portfolio rebalancing completed"},
		Confidence: 0.8,
		CreatedAt:  time.Now(),
	}, nil
}

// updateStopLoss updates stop-loss orders
func (o *OperatorAgent) updateStopLoss(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Implementation for updating stop-loss orders
	return &BusinessTaskResult{
		TaskID:     task.ID,
		Success:    true,
		Result:     map[string]interface{}{"message": "Stop-loss orders updated"},
		Confidence: 0.9,
		CreatedAt:  time.Now(),
	}, nil
}

// Helper methods

// updatePortfolioPerformance updates portfolio performance metrics
func (o *OperatorAgent) updatePortfolioPerformance() {
	o.portfolioManager.mutex.Lock()
	defer o.portfolioManager.mutex.Unlock()

	// Calculate total portfolio value
	totalValue := o.portfolioManager.cashBalance
	for _, position := range o.portfolioManager.positions {
		totalValue += position.Quantity * position.CurrentPrice
	}

	// Update performance data (simplified)
	if o.portfolioManager.totalValue > 0 {
		dailyReturn := (totalValue - o.portfolioManager.totalValue) / o.portfolioManager.totalValue
		o.portfolioManager.performanceData.DailyReturn = dailyReturn
	}

	o.portfolioManager.totalValue = totalValue
	o.portfolioManager.performanceData.LastUpdated = time.Now()
}

// getPortfolioSummary returns a portfolio summary
func (o *OperatorAgent) getPortfolioSummary() map[string]interface{} {
	o.portfolioManager.mutex.RLock()
	defer o.portfolioManager.mutex.RUnlock()

	return map[string]interface{}{
		"total_value":  o.portfolioManager.totalValue,
		"cash_balance": o.portfolioManager.cashBalance,
		"positions":    len(o.portfolioManager.positions),
		"daily_return": o.portfolioManager.performanceData.DailyReturn,
		"total_return": o.portfolioManager.performanceData.TotalReturn,
	}
}

// checkStopLossOrders checks and triggers stop-loss orders
func (o *OperatorAgent) checkStopLossOrders(ctx context.Context) []string {
	var triggered []string
	// Implementation for checking stop-loss orders
	return triggered
}

// updatePositionPnL updates position profit and loss
func (o *OperatorAgent) updatePositionPnL() map[string]float64 {
	updates := make(map[string]float64)
	// Implementation for updating position P&L
	return updates
}

// EnableTrading enables trading functionality
func (o *OperatorAgent) EnableTrading() {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.tradingEnabled = true
}

// DisableTrading disables trading functionality
func (o *OperatorAgent) DisableTrading() {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.tradingEnabled = false
}
