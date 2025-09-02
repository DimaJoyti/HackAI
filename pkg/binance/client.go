package binance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var binanceTracer = otel.Tracer("hackai/binance")

// BinanceClient provides secure access to Binance API
type BinanceClient struct {
	apiKey      string
	secretKey   string
	baseURL     string
	testnet     bool
	httpClient  *http.Client
	logger      *logger.Logger
	rateLimiter *RateLimiter
	mutex       sync.RWMutex
}

// BinanceConfig holds configuration for Binance client
type BinanceConfig struct {
	APIKey    string        `json:"api_key"`
	SecretKey string        `json:"secret_key"`
	Testnet   bool          `json:"testnet"`
	Timeout   time.Duration `json:"timeout"`
}

// NewBinanceClient creates a new Binance API client
func NewBinanceClient(config BinanceConfig, logger *logger.Logger) *BinanceClient {
	baseURL := "https://api.binance.com"
	if config.Testnet {
		baseURL = "https://testnet.binance.vision"
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &BinanceClient{
		apiKey:    config.APIKey,
		secretKey: config.SecretKey,
		baseURL:   baseURL,
		testnet:   config.Testnet,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger:      logger,
		rateLimiter: NewRateLimiter(1200, time.Minute), // Binance rate limit
	}
}

// RateLimiter implements rate limiting for API calls
type RateLimiter struct {
	requests chan struct{}
	ticker   *time.Ticker
	mutex    sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, duration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(chan struct{}, limit),
		ticker:   time.NewTicker(duration / time.Duration(limit)),
	}

	// Fill the initial bucket
	for i := 0; i < limit; i++ {
		rl.requests <- struct{}{}
	}

	// Refill the bucket
	go func() {
		for range rl.ticker.C {
			select {
			case rl.requests <- struct{}{}:
			default:
			}
		}
	}()

	return rl
}

// Wait waits for rate limit availability
func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.requests:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// AccountInfo represents Binance account information
type AccountInfo struct {
	MakerCommission  int       `json:"makerCommission"`
	TakerCommission  int       `json:"takerCommission"`
	BuyerCommission  int       `json:"buyerCommission"`
	SellerCommission int       `json:"sellerCommission"`
	CanTrade         bool      `json:"canTrade"`
	CanWithdraw      bool      `json:"canWithdraw"`
	CanDeposit       bool      `json:"canDeposit"`
	UpdateTime       int64     `json:"updateTime"`
	AccountType      string    `json:"accountType"`
	Balances         []Balance `json:"balances"`
	Permissions      []string  `json:"permissions"`
}

// Balance represents account balance for an asset
type Balance struct {
	Asset  string `json:"asset"`
	Free   string `json:"free"`
	Locked string `json:"locked"`
}

// TickerPrice represents 24hr ticker price change statistics
type TickerPrice struct {
	Symbol             string `json:"symbol"`
	PriceChange        string `json:"priceChange"`
	PriceChangePercent string `json:"priceChangePercent"`
	WeightedAvgPrice   string `json:"weightedAvgPrice"`
	PrevClosePrice     string `json:"prevClosePrice"`
	LastPrice          string `json:"lastPrice"`
	LastQty            string `json:"lastQty"`
	BidPrice           string `json:"bidPrice"`
	BidQty             string `json:"bidQty"`
	AskPrice           string `json:"askPrice"`
	AskQty             string `json:"askQty"`
	OpenPrice          string `json:"openPrice"`
	HighPrice          string `json:"highPrice"`
	LowPrice           string `json:"lowPrice"`
	Volume             string `json:"volume"`
	QuoteVolume        string `json:"quoteVolume"`
	OpenTime           int64  `json:"openTime"`
	CloseTime          int64  `json:"closeTime"`
	Count              int    `json:"count"`
}

// OrderRequest represents a new order request
type OrderRequest struct {
	Symbol           string  `json:"symbol"`
	Side             string  `json:"side"` // BUY or SELL
	Type             string  `json:"type"` // LIMIT, MARKET, etc.
	TimeInForce      string  `json:"timeInForce,omitempty"`
	Quantity         float64 `json:"quantity,omitempty"`
	QuoteOrderQty    float64 `json:"quoteOrderQty,omitempty"`
	Price            float64 `json:"price,omitempty"`
	NewClientOrderID string  `json:"newClientOrderId,omitempty"`
	StopPrice        float64 `json:"stopPrice,omitempty"`
	IcebergQty       float64 `json:"icebergQty,omitempty"`
}

// OrderResponse represents the response from placing an order
type OrderResponse struct {
	Symbol                  string `json:"symbol"`
	OrderID                 int64  `json:"orderId"`
	OrderListID             int64  `json:"orderListId"`
	ClientOrderID           string `json:"clientOrderId"`
	TransactTime            int64  `json:"transactTime"`
	Price                   string `json:"price"`
	OrigQty                 string `json:"origQty"`
	ExecutedQty             string `json:"executedQty"`
	CummulativeQuoteQty     string `json:"cummulativeQuoteQty"`
	Status                  string `json:"status"`
	TimeInForce             string `json:"timeInForce"`
	Type                    string `json:"type"`
	Side                    string `json:"side"`
	WorkingTime             int64  `json:"workingTime"`
	SelfTradePreventionMode string `json:"selfTradePreventionMode"`
}

// GetAccountInfo retrieves account information
func (c *BinanceClient) GetAccountInfo(ctx context.Context) (*AccountInfo, error) {
	ctx, span := binanceTracer.Start(ctx, "binance.get_account_info")
	defer span.End()

	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait failed: %w", err)
	}

	endpoint := "/api/v3/account"
	params := url.Values{}
	params.Set("timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))

	signature := c.generateSignature(params.Encode())
	params.Set("signature", signature)

	reqURL := fmt.Sprintf("%s%s?%s", c.baseURL, endpoint, params.Encode())

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-MBX-APIKEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("API error: %d - %s", resp.StatusCode, string(body))
		span.RecordError(err)
		return nil, err
	}

	var accountInfo AccountInfo
	if err := json.NewDecoder(resp.Body).Decode(&accountInfo); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("account.can_trade", accountInfo.CanTrade),
		attribute.String("account.type", accountInfo.AccountType),
		attribute.Int("balances.count", len(accountInfo.Balances)),
	)

	return &accountInfo, nil
}

// Get24hrTicker retrieves 24hr ticker price change statistics
func (c *BinanceClient) Get24hrTicker(ctx context.Context, symbol string) (*TickerPrice, error) {
	ctx, span := binanceTracer.Start(ctx, "binance.get_24hr_ticker",
		trace.WithAttributes(attribute.String("symbol", symbol)))
	defer span.End()

	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait failed: %w", err)
	}

	endpoint := "/api/v3/ticker/24hr"
	params := url.Values{}
	if symbol != "" {
		params.Set("symbol", symbol)
	}

	reqURL := fmt.Sprintf("%s%s", c.baseURL, endpoint)
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("API error: %d - %s", resp.StatusCode, string(body))
		span.RecordError(err)
		return nil, err
	}

	var ticker TickerPrice
	if err := json.NewDecoder(resp.Body).Decode(&ticker); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	span.SetAttributes(
		attribute.String("ticker.last_price", ticker.LastPrice),
		attribute.String("ticker.price_change_percent", ticker.PriceChangePercent),
	)

	return &ticker, nil
}

// PlaceOrder places a new order
func (c *BinanceClient) PlaceOrder(ctx context.Context, order *OrderRequest) (*OrderResponse, error) {
	ctx, span := binanceTracer.Start(ctx, "binance.place_order",
		trace.WithAttributes(
			attribute.String("order.symbol", order.Symbol),
			attribute.String("order.side", order.Side),
			attribute.String("order.type", order.Type),
		))
	defer span.End()

	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait failed: %w", err)
	}

	endpoint := "/api/v3/order"
	params := c.buildOrderParams(order)
	params.Set("timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))

	signature := c.generateSignature(params.Encode())
	params.Set("signature", signature)

	reqURL := fmt.Sprintf("%s%s", c.baseURL, endpoint)

	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(params.Encode()))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-MBX-APIKEY", c.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("API error: %d - %s", resp.StatusCode, string(body))
		span.RecordError(err)
		return nil, err
	}

	var orderResp OrderResponse
	if err := json.NewDecoder(resp.Body).Decode(&orderResp); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	span.SetAttributes(
		attribute.Int64("order.id", orderResp.OrderID),
		attribute.String("order.status", orderResp.Status),
		attribute.String("order.client_id", orderResp.ClientOrderID),
	)

	c.logger.Info("Order placed successfully",
		"order_id", orderResp.OrderID,
		"symbol", orderResp.Symbol,
		"side", orderResp.Side,
		"status", orderResp.Status)

	return &orderResp, nil
}

// generateSignature generates HMAC SHA256 signature for API requests
func (c *BinanceClient) generateSignature(queryString string) string {
	h := hmac.New(sha256.New, []byte(c.secretKey))
	h.Write([]byte(queryString))
	return hex.EncodeToString(h.Sum(nil))
}

// buildOrderParams builds URL parameters for order requests
func (c *BinanceClient) buildOrderParams(order *OrderRequest) url.Values {
	params := url.Values{}
	params.Set("symbol", order.Symbol)
	params.Set("side", order.Side)
	params.Set("type", order.Type)

	if order.TimeInForce != "" {
		params.Set("timeInForce", order.TimeInForce)
	}
	if order.Quantity > 0 {
		params.Set("quantity", fmt.Sprintf("%.8f", order.Quantity))
	}
	if order.QuoteOrderQty > 0 {
		params.Set("quoteOrderQty", fmt.Sprintf("%.8f", order.QuoteOrderQty))
	}
	if order.Price > 0 {
		params.Set("price", fmt.Sprintf("%.8f", order.Price))
	}
	if order.NewClientOrderID != "" {
		params.Set("newClientOrderId", order.NewClientOrderID)
	}
	if order.StopPrice > 0 {
		params.Set("stopPrice", fmt.Sprintf("%.8f", order.StopPrice))
	}
	if order.IcebergQty > 0 {
		params.Set("icebergQty", fmt.Sprintf("%.8f", order.IcebergQty))
	}

	return params
}

// Close closes the Binance client and cleans up resources
func (c *BinanceClient) Close() {
	if c.rateLimiter != nil && c.rateLimiter.ticker != nil {
		c.rateLimiter.ticker.Stop()
	}
}
