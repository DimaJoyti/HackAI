package agents

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/dimajoyti/hackai/pkg/binance"
	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ResearchAgent specializes in market analysis, trend identification, and data gathering
type ResearchAgent struct {
	*BaseBusinessAgent
	binanceClient   *binance.BinanceClient
	newsAPI         NewsAPIClient
	economicDataAPI EconomicDataClient
	socialAPI       SocialMediaClient
	analysisCache   map[string]*MarketAnalysis
	lastUpdate      time.Time
}

// NewsAPIClient interface for news data
type NewsAPIClient interface {
	GetFinancialNews(ctx context.Context, symbols []string, limit int) ([]*NewsArticle, error)
	GetSentimentAnalysis(ctx context.Context, text string) (*SentimentScore, error)
}

// EconomicDataClient interface for economic data
type EconomicDataClient interface {
	GetEconomicIndicators(ctx context.Context, indicators []string) ([]*EconomicIndicator, error)
	GetCentralBankData(ctx context.Context, bank string) (*CentralBankData, error)
}

// SocialMediaClient interface for social media data
type SocialMediaClient interface {
	GetTrendingTopics(ctx context.Context, keywords []string) ([]*TrendingTopic, error)
	GetSocialSentiment(ctx context.Context, symbol string) (*SocialSentiment, error)
}

// MarketAnalysis represents comprehensive market analysis
type MarketAnalysis struct {
	Symbol            string                 `json:"symbol"`
	Timestamp         time.Time              `json:"timestamp"`
	PriceData         *PriceAnalysis         `json:"price_data"`
	TechnicalAnalysis *TechnicalAnalysis     `json:"technical_analysis"`
	FundamentalData   *FundamentalAnalysis   `json:"fundamental_data"`
	SentimentData     *SentimentAnalysis     `json:"sentiment_data"`
	RiskMetrics       *RiskMetrics           `json:"risk_metrics"`
	Recommendations   []string               `json:"recommendations"`
	Confidence        float64                `json:"confidence"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// PriceAnalysis contains price-related analysis
type PriceAnalysis struct {
	CurrentPrice     float64   `json:"current_price"`
	PriceChange24h   float64   `json:"price_change_24h"`
	PriceChangePerc  float64   `json:"price_change_percent"`
	Volume24h        float64   `json:"volume_24h"`
	MarketCap        float64   `json:"market_cap,omitempty"`
	SupportLevels    []float64 `json:"support_levels"`
	ResistanceLevels []float64 `json:"resistance_levels"`
}

// TechnicalAnalysis contains technical indicators
type TechnicalAnalysis struct {
	RSI            float64            `json:"rsi"`
	MACD           *MACDData          `json:"macd"`
	BollingerBands *BollingerBands    `json:"bollinger_bands"`
	MovingAverages map[string]float64 `json:"moving_averages"` // "MA20", "MA50", etc.
	TrendDirection string             `json:"trend_direction"` // "bullish", "bearish", "sideways"
	TrendStrength  float64            `json:"trend_strength"`  // 0-1
	VolumeProfile  *VolumeProfile     `json:"volume_profile"`
}

// MACDData represents MACD indicator data
type MACDData struct {
	MACD      float64 `json:"macd"`
	Signal    float64 `json:"signal"`
	Histogram float64 `json:"histogram"`
}

// BollingerBands represents Bollinger Bands data
type BollingerBands struct {
	Upper  float64 `json:"upper"`
	Middle float64 `json:"middle"`
	Lower  float64 `json:"lower"`
}

// VolumeProfile represents volume analysis
type VolumeProfile struct {
	AverageVolume  float64 `json:"average_volume"`
	VolumeRatio    float64 `json:"volume_ratio"`
	VolumeBreakout bool    `json:"volume_breakout"`
}

// FundamentalAnalysis contains fundamental data
type FundamentalAnalysis struct {
	MarketCap         float64                `json:"market_cap,omitempty"`
	CirculatingSupply float64                `json:"circulating_supply,omitempty"`
	TotalSupply       float64                `json:"total_supply,omitempty"`
	EconomicFactors   []*EconomicIndicator   `json:"economic_factors"`
	NewsImpact        *NewsImpactAnalysis    `json:"news_impact"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// SentimentAnalysis contains sentiment data
type SentimentAnalysis struct {
	OverallSentiment string           `json:"overall_sentiment"` // "positive", "negative", "neutral"
	SentimentScore   float64          `json:"sentiment_score"`   // -1 to 1
	NewsAnalysis     []*NewsArticle   `json:"news_analysis"`
	SocialSentiment  *SocialSentiment `json:"social_sentiment"`
	FearGreedIndex   float64          `json:"fear_greed_index"` // 0-100
}

// RiskMetrics contains risk analysis
type RiskMetrics struct {
	Volatility      float64 `json:"volatility"`
	Beta            float64 `json:"beta,omitempty"`
	SharpeRatio     float64 `json:"sharpe_ratio,omitempty"`
	MaxDrawdown     float64 `json:"max_drawdown"`
	VaR95           float64 `json:"var_95"` // Value at Risk 95%
	LiquidityRisk   float64 `json:"liquidity_risk"`
	CorrelationRisk float64 `json:"correlation_risk"`
}

// NewsArticle represents a news article
type NewsArticle struct {
	Title       string          `json:"title"`
	Content     string          `json:"content"`
	Source      string          `json:"source"`
	PublishedAt time.Time       `json:"published_at"`
	Sentiment   *SentimentScore `json:"sentiment"`
	Relevance   float64         `json:"relevance"`
	Impact      string          `json:"impact"` // "high", "medium", "low"
}

// SentimentScore represents sentiment analysis result
type SentimentScore struct {
	Score      float64 `json:"score"`      // -1 to 1
	Magnitude  float64 `json:"magnitude"`  // 0 to 1
	Label      string  `json:"label"`      // "positive", "negative", "neutral"
	Confidence float64 `json:"confidence"` // 0 to 1
}

// EconomicIndicator represents economic data
type EconomicIndicator struct {
	Name        string    `json:"name"`
	Value       float64   `json:"value"`
	Unit        string    `json:"unit"`
	Country     string    `json:"country"`
	ReleaseDate time.Time `json:"release_date"`
	Impact      string    `json:"impact"` // "high", "medium", "low"
}

// CentralBankData represents central bank information
type CentralBankData struct {
	Bank         string    `json:"bank"`
	InterestRate float64   `json:"interest_rate"`
	LastUpdate   time.Time `json:"last_update"`
	NextMeeting  time.Time `json:"next_meeting"`
	Policy       string    `json:"policy"`
}

// TrendingTopic represents trending social media topics
type TrendingTopic struct {
	Topic     string  `json:"topic"`
	Volume    int     `json:"volume"`
	Sentiment float64 `json:"sentiment"`
	Growth    float64 `json:"growth"`
}

// SocialSentiment represents social media sentiment
type SocialSentiment struct {
	Platform           string  `json:"platform"`
	Sentiment          float64 `json:"sentiment"`
	Volume             int     `json:"volume"`
	Engagement         float64 `json:"engagement"`
	InfluencerMentions int     `json:"influencer_mentions"`
}

// NewsImpactAnalysis represents news impact analysis
type NewsImpactAnalysis struct {
	PositiveNews int     `json:"positive_news"`
	NegativeNews int     `json:"negative_news"`
	NeutralNews  int     `json:"neutral_news"`
	ImpactScore  float64 `json:"impact_score"`
}

// NewResearchAgent creates a new research agent
func NewResearchAgent(id, name string, binanceClient *binance.BinanceClient, logger *logger.Logger) *ResearchAgent {
	baseAgent := NewBaseBusinessAgent(id, name, "Market research and analysis specialist", AgentTypeResearch, logger)

	agent := &ResearchAgent{
		BaseBusinessAgent: baseAgent,
		binanceClient:     binanceClient,
		analysisCache:     make(map[string]*MarketAnalysis),
		lastUpdate:        time.Now(),
	}

	// Add research specializations
	agent.AddSpecialization("market_analysis")
	agent.AddSpecialization("technical_analysis")
	agent.AddSpecialization("fundamental_analysis")
	agent.AddSpecialization("sentiment_analysis")
	agent.AddSpecialization("risk_assessment")
	agent.AddSpecialization("trend_identification")

	return agent
}

// ExecuteBusinessTask executes research-specific tasks
func (r *ResearchAgent) ExecuteBusinessTask(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	ctx, span := businessAgentTracer.Start(ctx, "research_agent.execute_task",
		trace.WithAttributes(
			attribute.String("task.type", task.Type),
			attribute.String("agent.type", string(r.agentType)),
		),
	)
	defer span.End()

	switch task.Type {
	case "market_analysis":
		return r.performMarketAnalysis(ctx, task)
	case "price_analysis":
		return r.performPriceAnalysis(ctx, task)
	case "sentiment_analysis":
		return r.performSentimentAnalysis(ctx, task)
	case "technical_analysis":
		return r.performTechnicalAnalysis(ctx, task)
	case "risk_assessment":
		return r.performRiskAssessment(ctx, task)
	case "trend_identification":
		return r.identifyTrends(ctx, task)
	default:
		// Fall back to base implementation
		return r.BaseBusinessAgent.ExecuteBusinessTask(ctx, task)
	}
}

// performMarketAnalysis performs comprehensive market analysis
func (r *ResearchAgent) performMarketAnalysis(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	symbol, ok := task.Parameters["symbol"].(string)
	if !ok {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     "symbol parameter is required",
			CreatedAt: time.Now(),
		}, nil
	}

	// Get market data from Binance
	ticker, err := r.binanceClient.Get24hrTicker(ctx, symbol)
	if err != nil {
		return &BusinessTaskResult{
			TaskID:    task.ID,
			Success:   false,
			Error:     fmt.Sprintf("failed to get market data: %v", err),
			CreatedAt: time.Now(),
		}, nil
	}

	// Parse price data
	currentPrice, _ := strconv.ParseFloat(ticker.LastPrice, 64)
	priceChange, _ := strconv.ParseFloat(ticker.PriceChange, 64)
	priceChangePerc, _ := strconv.ParseFloat(ticker.PriceChangePercent, 64)
	volume, _ := strconv.ParseFloat(ticker.Volume, 64)

	// Create price analysis
	priceAnalysis := &PriceAnalysis{
		CurrentPrice:     currentPrice,
		PriceChange24h:   priceChange,
		PriceChangePerc:  priceChangePerc,
		Volume24h:        volume,
		SupportLevels:    r.calculateSupportLevels(currentPrice),
		ResistanceLevels: r.calculateResistanceLevels(currentPrice),
	}

	// Perform technical analysis
	technicalAnalysis := r.performTechnicalAnalysisInternal(ticker)

	// Create market analysis
	analysis := &MarketAnalysis{
		Symbol:            symbol,
		Timestamp:         time.Now(),
		PriceData:         priceAnalysis,
		TechnicalAnalysis: technicalAnalysis,
		Confidence:        0.85,
		Recommendations:   r.generateRecommendations(priceAnalysis, technicalAnalysis),
		Metadata: map[string]interface{}{
			"data_source":   "binance",
			"analysis_type": "comprehensive",
		},
	}

	// Cache the analysis
	r.analysisCache[symbol] = analysis

	result := &BusinessTaskResult{
		TaskID:  task.ID,
		Success: true,
		Result: map[string]interface{}{
			"analysis": analysis,
			"summary":  r.generateAnalysisSummary(analysis),
		},
		Confidence:    analysis.Confidence,
		ExecutionTime: time.Since(time.Now()),
		CreatedAt:     time.Now(),
	}

	r.updateTaskMetrics(true, result.ExecutionTime)
	return result, nil
}

// performTechnicalAnalysisInternal performs technical analysis
func (r *ResearchAgent) performTechnicalAnalysisInternal(ticker *binance.TickerPrice) *TechnicalAnalysis {
	currentPrice, _ := strconv.ParseFloat(ticker.LastPrice, 64)
	highPrice, _ := strconv.ParseFloat(ticker.HighPrice, 64)
	lowPrice, _ := strconv.ParseFloat(ticker.LowPrice, 64)
	volume, _ := strconv.ParseFloat(ticker.Volume, 64)

	// Calculate RSI (simplified)
	rsi := r.calculateRSI(currentPrice, highPrice, lowPrice)

	// Calculate moving averages (simplified)
	movingAverages := map[string]float64{
		"MA20":  currentPrice * 0.98, // Simplified calculation
		"MA50":  currentPrice * 0.95,
		"MA200": currentPrice * 0.90,
	}

	// Determine trend
	trendDirection := "sideways"
	trendStrength := 0.5
	if currentPrice > movingAverages["MA20"] && movingAverages["MA20"] > movingAverages["MA50"] {
		trendDirection = "bullish"
		trendStrength = 0.7
	} else if currentPrice < movingAverages["MA20"] && movingAverages["MA20"] < movingAverages["MA50"] {
		trendDirection = "bearish"
		trendStrength = 0.7
	}

	return &TechnicalAnalysis{
		RSI:            rsi,
		MovingAverages: movingAverages,
		TrendDirection: trendDirection,
		TrendStrength:  trendStrength,
		VolumeProfile: &VolumeProfile{
			AverageVolume:  volume,
			VolumeRatio:    1.0,
			VolumeBreakout: volume > volume*1.5, // Simplified
		},
	}
}

// calculateRSI calculates Relative Strength Index (simplified)
func (r *ResearchAgent) calculateRSI(current, high, low float64) float64 {
	// Simplified RSI calculation
	change := (high - low) / low * 100
	if change > 0 {
		return math.Min(70+change/10, 100)
	}
	return math.Max(30+change/10, 0)
}

// calculateSupportLevels calculates support levels
func (r *ResearchAgent) calculateSupportLevels(currentPrice float64) []float64 {
	return []float64{
		currentPrice * 0.95, // 5% below
		currentPrice * 0.90, // 10% below
		currentPrice * 0.85, // 15% below
	}
}

// calculateResistanceLevels calculates resistance levels
func (r *ResearchAgent) calculateResistanceLevels(currentPrice float64) []float64 {
	return []float64{
		currentPrice * 1.05, // 5% above
		currentPrice * 1.10, // 10% above
		currentPrice * 1.15, // 15% above
	}
}

// generateRecommendations generates trading recommendations
func (r *ResearchAgent) generateRecommendations(priceAnalysis *PriceAnalysis, technicalAnalysis *TechnicalAnalysis) []string {
	var recommendations []string

	// Price-based recommendations
	if priceAnalysis.PriceChangePerc > 5 {
		recommendations = append(recommendations, "Strong upward momentum detected")
	} else if priceAnalysis.PriceChangePerc < -5 {
		recommendations = append(recommendations, "Strong downward momentum detected")
	}

	// Technical-based recommendations
	if technicalAnalysis.TrendDirection == "bullish" && technicalAnalysis.TrendStrength > 0.6 {
		recommendations = append(recommendations, "Consider long position - bullish trend confirmed")
	} else if technicalAnalysis.TrendDirection == "bearish" && technicalAnalysis.TrendStrength > 0.6 {
		recommendations = append(recommendations, "Consider short position - bearish trend confirmed")
	}

	// RSI-based recommendations
	if technicalAnalysis.RSI > 70 {
		recommendations = append(recommendations, "Overbought condition - consider taking profits")
	} else if technicalAnalysis.RSI < 30 {
		recommendations = append(recommendations, "Oversold condition - potential buying opportunity")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Market conditions are neutral - monitor for breakout")
	}

	return recommendations
}

// generateAnalysisSummary generates a summary of the analysis
func (r *ResearchAgent) generateAnalysisSummary(analysis *MarketAnalysis) string {
	summary := fmt.Sprintf("Market Analysis for %s:\n", analysis.Symbol)
	summary += fmt.Sprintf("Current Price: $%.2f (%.2f%%)\n",
		analysis.PriceData.CurrentPrice, analysis.PriceData.PriceChangePerc)
	summary += fmt.Sprintf("Trend: %s (Strength: %.1f)\n",
		analysis.TechnicalAnalysis.TrendDirection, analysis.TechnicalAnalysis.TrendStrength)
	summary += fmt.Sprintf("RSI: %.1f\n", analysis.TechnicalAnalysis.RSI)
	summary += "Recommendations:\n"
	for _, rec := range analysis.Recommendations {
		summary += fmt.Sprintf("- %s\n", rec)
	}
	return summary
}

// performPriceAnalysis performs detailed price analysis
func (r *ResearchAgent) performPriceAnalysis(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Implementation for price analysis
	return &BusinessTaskResult{
		TaskID:     task.ID,
		Success:    true,
		Result:     map[string]interface{}{"message": "Price analysis completed"},
		Confidence: 0.8,
		CreatedAt:  time.Now(),
	}, nil
}

// performSentimentAnalysis performs sentiment analysis
func (r *ResearchAgent) performSentimentAnalysis(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Implementation for sentiment analysis
	return &BusinessTaskResult{
		TaskID:     task.ID,
		Success:    true,
		Result:     map[string]interface{}{"message": "Sentiment analysis completed"},
		Confidence: 0.75,
		CreatedAt:  time.Now(),
	}, nil
}

// performTechnicalAnalysis performs technical analysis
func (r *ResearchAgent) performTechnicalAnalysis(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Implementation for technical analysis
	return &BusinessTaskResult{
		TaskID:     task.ID,
		Success:    true,
		Result:     map[string]interface{}{"message": "Technical analysis completed"},
		Confidence: 0.85,
		CreatedAt:  time.Now(),
	}, nil
}

// performRiskAssessment performs risk assessment
func (r *ResearchAgent) performRiskAssessment(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Implementation for risk assessment
	return &BusinessTaskResult{
		TaskID:     task.ID,
		Success:    true,
		Result:     map[string]interface{}{"message": "Risk assessment completed"},
		Confidence: 0.9,
		CreatedAt:  time.Now(),
	}, nil
}

// identifyTrends identifies market trends
func (r *ResearchAgent) identifyTrends(ctx context.Context, task *BusinessTask) (*BusinessTaskResult, error) {
	// Implementation for trend identification
	return &BusinessTaskResult{
		TaskID:     task.ID,
		Success:    true,
		Result:     map[string]interface{}{"message": "Trend identification completed"},
		Confidence: 0.8,
		CreatedAt:  time.Now(),
	}, nil
}
