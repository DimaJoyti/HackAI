package fraud

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var fraudTracer = otel.Tracer("hackai/fraud/engine")

// FraudDetectionEngine is the core fraud detection engine with ensemble AI models
type FraudDetectionEngine struct {
	id               string
	name             string
	config           *EngineConfig
	ensembleManager  *EnsembleManager
	featureExtractor *FeatureExtractor
	riskScorer       *RiskScorer
	decisionEngine   *DecisionEngine
	modelRegistry    *ModelRegistry
	cacheManager     *CacheManager
	metricsCollector *MetricsCollector
	logger           *logger.Logger
	tracer           trace.Tracer
	mutex            sync.RWMutex
	isRunning        bool
	stopChan         chan struct{}
}

// EngineConfig holds configuration for the fraud detection engine
type EngineConfig struct {
	// Core Configuration
	MaxConcurrentRequests int           `json:"max_concurrent_requests"`
	DefaultTimeout        time.Duration `json:"default_timeout"`
	EnableCaching         bool          `json:"enable_caching"`
	CacheTTL              time.Duration `json:"cache_ttl"`

	// Model Configuration
	EnsembleStrategy     string        `json:"ensemble_strategy"` // "voting", "stacking", "blending"
	ConfidenceThreshold  float64       `json:"confidence_threshold"`
	EnableOnlineLearning bool          `json:"enable_online_learning"`
	ModelUpdateInterval  time.Duration `json:"model_update_interval"`

	// Performance Configuration
	MaxLatencyMs        int  `json:"max_latency_ms"`
	TargetThroughputTPS int  `json:"target_throughput_tps"`
	EnableLoadBalancing bool `json:"enable_load_balancing"`
	AutoScalingEnabled  bool `json:"auto_scaling_enabled"`

	// Security Configuration
	EnableAuditLogging    bool `json:"enable_audit_logging"`
	EnableEncryption      bool `json:"enable_encryption"`
	RequireAuthentication bool `json:"require_authentication"`
	MaxRetries            int  `json:"max_retries"`
}

// FraudDetectionRequest represents a fraud detection request
type FraudDetectionRequest struct {
	ID                string                 `json:"id"`
	UserID            string                 `json:"user_id"`
	SessionID         string                 `json:"session_id"`
	TransactionData   map[string]interface{} `json:"transaction_data"`
	UserContext       map[string]interface{} `json:"user_context"`
	DeviceFingerprint map[string]interface{} `json:"device_fingerprint"`
	Timestamp         time.Time              `json:"timestamp"`
	Priority          Priority               `json:"priority"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// FraudDetectionResponse represents the fraud detection result
type FraudDetectionResponse struct {
	RequestID         string                 `json:"request_id"`
	IsFraud           bool                   `json:"is_fraud"`
	FraudScore        float64                `json:"fraud_score"`
	Confidence        float64                `json:"confidence"`
	RiskLevel         RiskLevel              `json:"risk_level"`
	Decision          Decision               `json:"decision"`
	Reasons           []string               `json:"reasons"`
	ModelPredictions  []ModelPrediction      `json:"model_predictions"`
	FeatureImportance map[string]float64     `json:"feature_importance"`
	ProcessingTime    time.Duration          `json:"processing_time"`
	Metadata          map[string]interface{} `json:"metadata"`
	Timestamp         time.Time              `json:"timestamp"`
}

// Priority defines request priority levels
type Priority int

const (
	PriorityLow Priority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// RiskLevel defines risk assessment levels
type RiskLevel string

const (
	RiskLevelVeryLow  RiskLevel = "very_low"
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// Decision defines the final decision
type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionBlock     Decision = "block"
	DecisionReview    Decision = "review"
	DecisionChallenge Decision = "challenge"
)

// ModelPrediction represents a prediction from an individual model
type ModelPrediction struct {
	ModelID     string             `json:"model_id"`
	ModelName   string             `json:"model_name"`
	Prediction  float64            `json:"prediction"`
	Confidence  float64            `json:"confidence"`
	ProcessTime time.Duration      `json:"process_time"`
	Features    map[string]float64 `json:"features"`
}

// NewFraudDetectionEngine creates a new fraud detection engine
func NewFraudDetectionEngine(id, name string, config *EngineConfig, logger *logger.Logger) (*FraudDetectionEngine, error) {
	if config == nil {
		config = DefaultEngineConfig()
	}

	engine := &FraudDetectionEngine{
		id:               id,
		name:             name,
		config:           config,
		logger:           logger,
		tracer:           fraudTracer,
		stopChan:         make(chan struct{}),
		metricsCollector: NewMetricsCollector(),
	}

	// Initialize components
	if err := engine.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize engine components: %w", err)
	}

	return engine, nil
}

// initializeComponents initializes all engine components
func (e *FraudDetectionEngine) initializeComponents() error {
	var err error

	// Initialize ensemble manager
	e.ensembleManager, err = NewEnsembleManager(e.config, e.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize ensemble manager: %w", err)
	}

	// Initialize feature extractor
	e.featureExtractor, err = NewFeatureExtractor(e.config, e.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize feature extractor: %w", err)
	}

	// Initialize risk scorer
	e.riskScorer, err = NewRiskScorer(e.config, e.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize risk scorer: %w", err)
	}

	// Initialize decision engine
	e.decisionEngine, err = NewDecisionEngine(e.config, e.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize decision engine: %w", err)
	}

	// Initialize model registry
	e.modelRegistry, err = NewModelRegistry(e.config, e.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize model registry: %w", err)
	}

	// Initialize cache manager if enabled
	if e.config.EnableCaching {
		e.cacheManager, err = NewCacheManager(e.config, e.logger)
		if err != nil {
			return fmt.Errorf("failed to initialize cache manager: %w", err)
		}
	}

	return nil
}

// DetectFraud performs fraud detection on a request
func (e *FraudDetectionEngine) DetectFraud(ctx context.Context, request *FraudDetectionRequest) (*FraudDetectionResponse, error) {
	// Validate request first
	if request == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	ctx, span := e.tracer.Start(ctx, "fraud_engine.detect_fraud",
		trace.WithAttributes(
			attribute.String("request.id", request.ID),
			attribute.String("user.id", request.UserID),
			attribute.String("session.id", request.SessionID),
		),
	)
	defer span.End()

	startTime := time.Now()

	if err := e.validateRequest(request); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Check cache if enabled
	if e.config.EnableCaching && e.cacheManager != nil {
		if cached := e.cacheManager.Get(ctx, request.ID); cached != nil {
			e.metricsCollector.RecordCacheHit()
			return cached, nil
		}
		e.metricsCollector.RecordCacheMiss()
	}

	// Extract features
	features, err := e.featureExtractor.ExtractFeatures(ctx, request)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("feature extraction failed: %w", err)
	}

	// Get ensemble predictions
	predictions, err := e.ensembleManager.Predict(ctx, features)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("ensemble prediction failed: %w", err)
	}

	// Calculate risk score
	riskScore, riskLevel := e.riskScorer.CalculateRisk(ctx, predictions, features)

	// Make final decision
	decision, reasons := e.decisionEngine.MakeDecision(ctx, riskScore, riskLevel, predictions)

	// Build response
	response := &FraudDetectionResponse{
		RequestID:         request.ID,
		IsFraud:           decision == DecisionBlock,
		FraudScore:        riskScore,
		Confidence:        e.calculateConfidence(predictions),
		RiskLevel:         riskLevel,
		Decision:          decision,
		Reasons:           reasons,
		ModelPredictions:  predictions,
		FeatureImportance: e.calculateFeatureImportance(features, predictions),
		ProcessingTime:    time.Since(startTime),
		Metadata:          make(map[string]interface{}),
		Timestamp:         time.Now(),
	}

	// Cache result if enabled
	if e.config.EnableCaching && e.cacheManager != nil {
		e.cacheManager.Set(ctx, request.ID, response, e.config.CacheTTL)
	}

	// Record metrics
	e.metricsCollector.RecordPrediction(response)

	// Audit logging if enabled
	if e.config.EnableAuditLogging {
		e.auditLog(ctx, request, response)
	}

	span.SetAttributes(
		attribute.Float64("fraud.score", riskScore),
		attribute.String("fraud.decision", string(decision)),
		attribute.String("fraud.risk_level", string(riskLevel)),
		attribute.Int64("processing.time_ms", response.ProcessingTime.Milliseconds()),
	)

	return response, nil
}

// DefaultEngineConfig returns default configuration
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		MaxConcurrentRequests: 1000,
		DefaultTimeout:        30 * time.Second,
		EnableCaching:         true,
		CacheTTL:              5 * time.Minute,
		EnsembleStrategy:      "voting",
		ConfidenceThreshold:   0.7,
		EnableOnlineLearning:  false,
		ModelUpdateInterval:   24 * time.Hour,
		MaxLatencyMs:          50,
		TargetThroughputTPS:   10000,
		EnableLoadBalancing:   true,
		AutoScalingEnabled:    true,
		EnableAuditLogging:    true,
		EnableEncryption:      true,
		RequireAuthentication: true,
		MaxRetries:            3,
	}
}

// validateRequest validates a fraud detection request (assumes request is not nil)
func (e *FraudDetectionEngine) validateRequest(request *FraudDetectionRequest) error {
	if request.ID == "" {
		return fmt.Errorf("request ID cannot be empty")
	}
	if request.UserID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	return nil
}

// calculateConfidence calculates overall confidence from model predictions
func (e *FraudDetectionEngine) calculateConfidence(predictions []ModelPrediction) float64 {
	if len(predictions) == 0 {
		return 0.0
	}

	var totalConfidence float64
	for _, pred := range predictions {
		totalConfidence += pred.Confidence
	}
	return totalConfidence / float64(len(predictions))
}

// calculateFeatureImportance calculates feature importance from predictions
func (e *FraudDetectionEngine) calculateFeatureImportance(features map[string]float64, predictions []ModelPrediction) map[string]float64 {
	importance := make(map[string]float64)

	// Simple stub implementation - assign equal importance to all features
	if len(features) > 0 {
		equalWeight := 1.0 / float64(len(features))
		for feature := range features {
			importance[feature] = equalWeight
		}
	}

	return importance
}

// auditLog logs fraud detection events for audit purposes
func (e *FraudDetectionEngine) auditLog(ctx context.Context, request *FraudDetectionRequest, response *FraudDetectionResponse) {
	e.logger.Info("Fraud detection audit",
		"request_id", request.ID,
		"user_id", request.UserID,
		"session_id", request.SessionID,
		"fraud_score", response.FraudScore,
		"decision", string(response.Decision),
		"risk_level", string(response.RiskLevel),
		"processing_time_ms", response.ProcessingTime.Milliseconds(),
	)
}

// Start starts the fraud detection engine
func (e *FraudDetectionEngine) Start(ctx context.Context) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.isRunning {
		return fmt.Errorf("engine is already running")
	}

	e.isRunning = true
	e.logger.Info("Fraud detection engine started", "engine_id", e.id)
	return nil
}

// Stop stops the fraud detection engine
func (e *FraudDetectionEngine) Stop() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if !e.isRunning {
		return fmt.Errorf("engine is not running")
	}

	close(e.stopChan)
	e.isRunning = false
	e.logger.Info("Fraud detection engine stopped", "engine_id", e.id)
	return nil
}

// IsRunning returns whether the engine is running
func (e *FraudDetectionEngine) IsRunning() bool {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.isRunning
}

// GetStats returns engine statistics
func (e *FraudDetectionEngine) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"engine_id":   e.id,
		"engine_name": e.name,
		"is_running":  e.IsRunning(),
		"models":      e.ensembleManager.GetModelPerformance(),
	}
}
