package security

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var tradingSecurityTracer = otel.Tracer("hackai/security/trading")

// TradingSecurityManager manages security for trading operations
type TradingSecurityManager struct {
	encryptionManager *EncryptionManager
	auditLogger       *TradingAuditLogger
	riskMonitor       *TradingRiskMonitor
	complianceEngine  *ComplianceEngine
	accessController  *TradingAccessController
	alertManager      *SecurityAlertManager
	config            *TradingSecurityConfig
	logger            *logger.Logger
	mutex             sync.RWMutex
}

// TradingSecurityConfig holds trading security configuration
type TradingSecurityConfig struct {
	EncryptionEnabled     bool          `json:"encryption_enabled"`
	AuditLoggingEnabled   bool          `json:"audit_logging_enabled"`
	RiskMonitoringEnabled bool          `json:"risk_monitoring_enabled"`
	ComplianceEnabled     bool          `json:"compliance_enabled"`
	MaxDailyTrades        int           `json:"max_daily_trades"`
	MaxPositionSize       float64       `json:"max_position_size"`
	RequiredApprovals     []string      `json:"required_approvals"`
	SessionTimeout        time.Duration `json:"session_timeout"`
	IPWhitelist           []string      `json:"ip_whitelist"`
	GeoRestrictions       []string      `json:"geo_restrictions"`
}

// EncryptionManager handles encryption of sensitive data
type EncryptionManager struct {
	masterKey []byte
	gcm       cipher.AEAD
	logger    *logger.Logger
}

// TradingAuditLogger logs all trading-related activities
type TradingAuditLogger struct {
	logger    *logger.Logger
	auditChan chan *TradingAuditEvent
	batchSize int
	shutdown  chan struct{}
	wg        sync.WaitGroup
}

// TradingRiskMonitor monitors trading risks in real-time
type TradingRiskMonitor struct {
	riskMetrics     map[string]*RiskMetric
	alertThresholds map[string]float64
	logger          *logger.Logger
	mutex           sync.RWMutex
}

// ComplianceEngine ensures regulatory compliance
type ComplianceEngine struct {
	regulations map[string]*Regulation
	policies    map[string]*CompliancePolicy
	violations  []*ComplianceViolation
	logger      *logger.Logger
	mutex       sync.RWMutex
}

// TradingAccessController manages access to trading functions
type TradingAccessController struct {
	permissions    map[string]*TradingPermissions
	activeSessions map[string]*TradingSession
	logger         *logger.Logger
	mutex          sync.RWMutex
}

// TradingAuditEvent represents a trading audit event
type TradingAuditEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	UserID       string                 `json:"user_id"`
	SessionID    string                 `json:"session_id"`
	EventType    string                 `json:"event_type"`
	Action       string                 `json:"action"`
	Symbol       string                 `json:"symbol,omitempty"`
	Quantity     float64                `json:"quantity,omitempty"`
	Price        float64                `json:"price,omitempty"`
	OrderID      string                 `json:"order_id,omitempty"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	RiskScore    float64                `json:"risk_score"`
	ComplianceOK bool                   `json:"compliance_ok"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// RiskMetric represents a risk metric
type RiskMetric struct {
	Name        string    `json:"name"`
	Value       float64   `json:"value"`
	Threshold   float64   `json:"threshold"`
	Status      string    `json:"status"`
	LastUpdated time.Time `json:"last_updated"`
}

// Regulation represents a regulatory requirement
type Regulation struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Rules       []*ComplianceRule      `json:"rules"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// CompliancePolicy represents a compliance policy
type CompliancePolicy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Rules       []*PolicyRule          `json:"rules"`
	Enforcement string                 `json:"enforcement"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ComplianceRule represents a compliance rule
type ComplianceRule struct {
	ID        string                 `json:"id"`
	Condition string                 `json:"condition"`
	Action    string                 `json:"action"`
	Severity  string                 `json:"severity"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// PolicyRule represents a policy rule
type PolicyRule struct {
	ID        string                 `json:"id"`
	Condition string                 `json:"condition"`
	Action    string                 `json:"action"`
	Priority  int                    `json:"priority"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ID          string                 `json:"id"`
	PolicyID    string                 `json:"policy_id"`
	UserID      string                 `json:"user_id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Resolved    bool                   `json:"resolved"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// TradingPermissions represents trading permissions
type TradingPermissions struct {
	UserID           string    `json:"user_id"`
	CanTrade         bool      `json:"can_trade"`
	CanViewPortfolio bool      `json:"can_view_portfolio"`
	MaxOrderSize     float64   `json:"max_order_size"`
	AllowedSymbols   []string  `json:"allowed_symbols"`
	TradingHours     []string  `json:"trading_hours"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// TradingSession represents an active trading session
type TradingSession struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	StartTime    time.Time              `json:"start_time"`
	LastActivity time.Time              `json:"last_activity"`
	ExpiresAt    time.Time              `json:"expires_at"`
	IsActive     bool                   `json:"is_active"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// NewTradingSecurityManager creates a new trading security manager
func NewTradingSecurityManager(config *TradingSecurityConfig, logger *logger.Logger) (*TradingSecurityManager, error) {
	encryptionManager, err := NewEncryptionManager(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption manager: %w", err)
	}

	auditLogger := NewTradingAuditLogger(logger)
	riskMonitor := NewTradingRiskMonitor(logger)
	complianceEngine := NewComplianceEngine(logger)
	accessController := NewTradingAccessController(logger)
	alertManager := NewSecurityAlertManager(&AlertingConfig{
		Enabled:              true,
		MaxActiveAlerts:      1000,
		AlertRetentionPeriod: 24 * time.Hour,
		EvaluationInterval:   1 * time.Minute,
		BufferSize:           100,
		Channels:             []*ChannelConfig{},
		Rules:                []*AlertRuleConfig{},
		Escalations:          []*EscalationConfig{},
		Suppressions:         []*SuppressionConfig{},
	}, logger)

	return &TradingSecurityManager{
		encryptionManager: encryptionManager,
		auditLogger:       auditLogger,
		riskMonitor:       riskMonitor,
		complianceEngine:  complianceEngine,
		accessController:  accessController,
		alertManager:      alertManager,
		config:            config,
		logger:            logger,
	}, nil
}

// NewEncryptionManager creates a new encryption manager
func NewEncryptionManager(logger *logger.Logger) (*EncryptionManager, error) {
	// Generate or load master key (in production, this should be from secure key management)
	masterKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &EncryptionManager{
		masterKey: masterKey,
		gcm:       gcm,
		logger:    logger,
	}, nil
}

// EncryptAPIKey encrypts an API key
func (em *EncryptionManager) EncryptAPIKey(apiKey string) (string, error) {
	nonce := make([]byte, em.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := em.gcm.Seal(nonce, nonce, []byte(apiKey), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAPIKey decrypts an API key
func (em *EncryptionManager) DecryptAPIKey(encryptedKey string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	nonceSize := em.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := em.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// ValidateTradingRequest validates a trading request for security and compliance
func (tsm *TradingSecurityManager) ValidateTradingRequest(ctx context.Context, req *TradingRequest) (*ValidationResult, error) {
	ctx, span := tradingSecurityTracer.Start(ctx, "trading_security.validate_request",
		trace.WithAttributes(
			attribute.String("user_id", req.UserID),
			attribute.String("symbol", req.Symbol),
			attribute.String("action", req.Action),
		),
	)
	defer span.End()

	result := &ValidationResult{
		RequestID: req.ID,
		Valid:     true,
		Timestamp: time.Now(),
		Checks:    make(map[string]*CheckResult),
	}

	// Access control check
	accessResult := tsm.accessController.ValidateAccess(ctx, req)
	result.Checks["access_control"] = accessResult
	if !accessResult.Passed {
		result.Valid = false
	}

	// Risk assessment
	riskResult := tsm.riskMonitor.AssessRisk(ctx, req)
	result.Checks["risk_assessment"] = riskResult
	if !riskResult.Passed {
		result.Valid = false
	}

	// Compliance check
	complianceResult := tsm.complianceEngine.CheckCompliance(ctx, req)
	result.Checks["compliance"] = complianceResult
	if !complianceResult.Passed {
		result.Valid = false
	}

	// Log audit event
	auditEvent := &TradingAuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now(),
		UserID:       req.UserID,
		SessionID:    req.SessionID,
		EventType:    "trading_request_validation",
		Action:       req.Action,
		Symbol:       req.Symbol,
		Quantity:     req.Quantity,
		Price:        req.Price,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
		RiskScore:    riskResult.Score,
		ComplianceOK: complianceResult.Passed,
		Metadata: map[string]interface{}{
			"validation_result": result.Valid,
			"request_id":        req.ID,
		},
	}

	tsm.auditLogger.LogEvent(auditEvent)

	// Generate alerts if needed
	if !result.Valid {
		tsm.alertManager.TriggerAlert(
			"trading_validation_failed",
			"trading_validation_failed",
			"high",
			"Trading Request Validation Failed",
			fmt.Sprintf("Trading request validation failed for user %s", req.UserID),
			map[string]interface{}{
				"user_id":    req.UserID,
				"request_id": req.ID,
				"symbol":     req.Symbol,
				"action":     req.Action,
				"source":     "trading_security_manager",
			},
		)
	}

	span.SetAttributes(
		attribute.Bool("validation.valid", result.Valid),
		attribute.Float64("risk.score", riskResult.Score),
		attribute.Bool("compliance.passed", complianceResult.Passed),
	)

	return result, nil
}

// Additional types for completeness

type TradingRequest struct {
	ID        string  `json:"id"`
	UserID    string  `json:"user_id"`
	SessionID string  `json:"session_id"`
	Symbol    string  `json:"symbol"`
	Action    string  `json:"action"`
	Quantity  float64 `json:"quantity"`
	Price     float64 `json:"price"`
	IPAddress string  `json:"ip_address"`
	UserAgent string  `json:"user_agent"`
}

type ValidationResult struct {
	RequestID string                  `json:"request_id"`
	Valid     bool                    `json:"valid"`
	Timestamp time.Time               `json:"timestamp"`
	Checks    map[string]*CheckResult `json:"checks"`
}

type CheckResult struct {
	Name     string                 `json:"name"`
	Passed   bool                   `json:"passed"`
	Score    float64                `json:"score"`
	Message  string                 `json:"message"`
	Metadata map[string]interface{} `json:"metadata"`
}

// NewTradingAuditLogger creates a new trading audit logger
func NewTradingAuditLogger(logger *logger.Logger) *TradingAuditLogger {
	tal := &TradingAuditLogger{
		logger:    logger,
		auditChan: make(chan *TradingAuditEvent, 1000),
		batchSize: 100,
		shutdown:  make(chan struct{}),
	}

	tal.wg.Add(1)
	go tal.processAuditEvents()

	return tal
}

// LogEvent logs a trading audit event
func (tal *TradingAuditLogger) LogEvent(event *TradingAuditEvent) {
	select {
	case tal.auditChan <- event:
	default:
		tal.logger.Warn("Audit channel full, dropping event", "event_id", event.ID)
	}
}

// processAuditEvents processes audit events in batches
func (tal *TradingAuditLogger) processAuditEvents() {
	defer tal.wg.Done()

	batch := make([]*TradingAuditEvent, 0, tal.batchSize)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event := <-tal.auditChan:
			batch = append(batch, event)
			if len(batch) >= tal.batchSize {
				tal.flushBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				tal.flushBatch(batch)
				batch = batch[:0]
			}
		case <-tal.shutdown:
			if len(batch) > 0 {
				tal.flushBatch(batch)
			}
			return
		}
	}
}

// flushBatch flushes a batch of audit events
func (tal *TradingAuditLogger) flushBatch(batch []*TradingAuditEvent) {
	for _, event := range batch {
		eventJSON, _ := json.Marshal(event)
		tal.logger.Info("Trading audit event", "event", string(eventJSON))
	}
}

// NewTradingRiskMonitor creates a new trading risk monitor
func NewTradingRiskMonitor(logger *logger.Logger) *TradingRiskMonitor {
	return &TradingRiskMonitor{
		riskMetrics:     make(map[string]*RiskMetric),
		alertThresholds: make(map[string]float64),
		logger:          logger,
	}
}

// AssessRisk assesses the risk of a trading request
func (trm *TradingRiskMonitor) AssessRisk(ctx context.Context, req *TradingRequest) *CheckResult {
	// Simplified risk assessment
	riskScore := 0.0

	// Position size risk
	if req.Quantity > 1000 {
		riskScore += 0.3
	}

	// Price volatility risk (simplified)
	if req.Price > 100000 {
		riskScore += 0.2
	}

	passed := riskScore < 0.7

	return &CheckResult{
		Name:    "risk_assessment",
		Passed:  passed,
		Score:   riskScore,
		Message: fmt.Sprintf("Risk score: %.2f", riskScore),
		Metadata: map[string]interface{}{
			"position_size_risk": req.Quantity > 1000,
			"price_risk":         req.Price > 100000,
		},
	}
}

// NewComplianceEngine creates a new compliance engine
func NewComplianceEngine(logger *logger.Logger) *ComplianceEngine {
	return &ComplianceEngine{
		regulations: make(map[string]*Regulation),
		policies:    make(map[string]*CompliancePolicy),
		violations:  make([]*ComplianceViolation, 0),
		logger:      logger,
	}
}

// CheckCompliance checks compliance for a trading request
func (ce *ComplianceEngine) CheckCompliance(ctx context.Context, req *TradingRequest) *CheckResult {
	// Simplified compliance check
	passed := true
	message := "Compliance check passed"

	// Check for basic compliance rules
	if req.Quantity <= 0 {
		passed = false
		message = "Invalid quantity"
	}

	if req.Price <= 0 {
		passed = false
		message = "Invalid price"
	}

	return &CheckResult{
		Name:    "compliance_check",
		Passed:  passed,
		Score:   1.0,
		Message: message,
		Metadata: map[string]interface{}{
			"quantity_valid": req.Quantity > 0,
			"price_valid":    req.Price > 0,
		},
	}
}

// NewTradingAccessController creates a new trading access controller
func NewTradingAccessController(logger *logger.Logger) *TradingAccessController {
	return &TradingAccessController{
		permissions:    make(map[string]*TradingPermissions),
		activeSessions: make(map[string]*TradingSession),
		logger:         logger,
	}
}

// ValidateAccess validates access for a trading request
func (tac *TradingAccessController) ValidateAccess(ctx context.Context, req *TradingRequest) *CheckResult {
	// Simplified access control
	passed := true
	message := "Access granted"

	// Check if user has trading permissions (simplified)
	if req.UserID == "" {
		passed = false
		message = "Invalid user ID"
	}

	return &CheckResult{
		Name:    "access_control",
		Passed:  passed,
		Score:   1.0,
		Message: message,
		Metadata: map[string]interface{}{
			"user_id_valid": req.UserID != "",
		},
	}
}
