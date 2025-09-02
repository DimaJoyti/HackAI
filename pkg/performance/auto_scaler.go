package performance

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var autoScalerTracer = otel.Tracer("hackai/performance/auto-scaler")

// AutoScaler provides intelligent auto-scaling capabilities
type AutoScaler struct {
	config                *AutoScalingConfig
	logger                *logger.Logger
	horizontalScaler      *HorizontalScaler
	verticalScaler        *VerticalScaler
	predictiveScaler      *PredictiveScaler
	metricsCollector      *MetricsCollector
	scalingDecisionEngine *ScalingDecisionEngine
	scalingHistory        []*ScalingEvent
	currentScale          *ScaleState
	mutex                 sync.RWMutex
	stopChan              chan struct{}
	running               bool
}

// AutoScalingConfig defines auto-scaling configuration
type AutoScalingConfig struct {
	// General settings
	Enabled         bool          `yaml:"enabled"`
	ScalingInterval time.Duration `yaml:"scaling_interval"`
	MetricsWindow   time.Duration `yaml:"metrics_window"`
	CooldownPeriod  time.Duration `yaml:"cooldown_period"`

	// Horizontal scaling settings
	HorizontalScaling HorizontalScalingConfig `yaml:"horizontal_scaling"`

	// Vertical scaling settings
	VerticalScaling VerticalScalingConfig `yaml:"vertical_scaling"`

	// Predictive scaling settings
	PredictiveScaling PredictiveScalingConfig `yaml:"predictive_scaling"`

	// Scaling triggers
	ScalingTriggers ScalingTriggersConfig `yaml:"scaling_triggers"`

	// Safety limits
	SafetyLimits SafetyLimitsConfig `yaml:"safety_limits"`
}

// HorizontalScalingConfig defines horizontal scaling settings
type HorizontalScalingConfig struct {
	Enabled             bool          `yaml:"enabled"`
	MinInstances        int           `yaml:"min_instances"`
	MaxInstances        int           `yaml:"max_instances"`
	TargetCPUPercent    float64       `yaml:"target_cpu_percent"`
	TargetMemoryPercent float64       `yaml:"target_memory_percent"`
	ScaleUpCooldown     time.Duration `yaml:"scale_up_cooldown"`
	ScaleDownCooldown   time.Duration `yaml:"scale_down_cooldown"`
	ScaleUpStepSize     int           `yaml:"scale_up_step_size"`
	ScaleDownStepSize   int           `yaml:"scale_down_step_size"`
}

// VerticalScalingConfig defines vertical scaling settings
type VerticalScalingConfig struct {
	Enabled          bool    `yaml:"enabled"`
	MinCPU           float64 `yaml:"min_cpu"`
	MaxCPU           float64 `yaml:"max_cpu"`
	MinMemory        int64   `yaml:"min_memory"`
	MaxMemory        int64   `yaml:"max_memory"`
	CPUStepSize      float64 `yaml:"cpu_step_size"`
	MemoryStepSize   int64   `yaml:"memory_step_size"`
	ScalingThreshold float64 `yaml:"scaling_threshold"`
}

// PredictiveScalingConfig defines predictive scaling settings
type PredictiveScalingConfig struct {
	Enabled             bool          `yaml:"enabled"`
	PredictionWindow    time.Duration `yaml:"prediction_window"`
	HistoryWindow       time.Duration `yaml:"history_window"`
	ConfidenceThreshold float64       `yaml:"confidence_threshold"`
	ModelUpdateInterval time.Duration `yaml:"model_update_interval"`
	EnableMLPrediction  bool          `yaml:"enable_ml_prediction"`
}

// ScalingTriggersConfig defines scaling trigger thresholds
type ScalingTriggersConfig struct {
	CPUThresholds     ThresholdConfig       `yaml:"cpu_thresholds"`
	MemoryThresholds  ThresholdConfig       `yaml:"memory_thresholds"`
	LatencyThresholds ThresholdConfig       `yaml:"latency_thresholds"`
	QueueThresholds   ThresholdConfig       `yaml:"queue_thresholds"`
	CustomMetrics     []CustomMetricTrigger `yaml:"custom_metrics"`
}

// ThresholdConfig defines threshold configuration
type ThresholdConfig struct {
	ScaleUpThreshold   float64       `yaml:"scale_up_threshold"`
	ScaleDownThreshold float64       `yaml:"scale_down_threshold"`
	EvaluationPeriod   time.Duration `yaml:"evaluation_period"`
	ConsecutiveChecks  int           `yaml:"consecutive_checks"`
}

// CustomMetricTrigger defines custom metric triggers
type CustomMetricTrigger struct {
	Name               string  `yaml:"name"`
	MetricPath         string  `yaml:"metric_path"`
	ScaleUpThreshold   float64 `yaml:"scale_up_threshold"`
	ScaleDownThreshold float64 `yaml:"scale_down_threshold"`
	Weight             float64 `yaml:"weight"`
}

// SafetyLimitsConfig defines safety limits for scaling
type SafetyLimitsConfig struct {
	MaxScaleUpRate       float64 `yaml:"max_scale_up_rate"`
	MaxScaleDownRate     float64 `yaml:"max_scale_down_rate"`
	EmergencyThreshold   float64 `yaml:"emergency_threshold"`
	EnableCircuitBreaker bool    `yaml:"enable_circuit_breaker"`
}

// ScalingEvent represents a scaling event
type ScalingEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"`
	ScalingType  string                 `json:"scaling_type"`
	Trigger      string                 `json:"trigger"`
	BeforeState  *ScaleState            `json:"before_state"`
	AfterState   *ScaleState            `json:"after_state"`
	Metrics      *ScalingMetrics        `json:"metrics"`
	Success      bool                   `json:"success"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	Duration     time.Duration          `json:"duration"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ScaleState represents the current scaling state
type ScaleState struct {
	Instances        int       `json:"instances"`
	CPUAllocation    float64   `json:"cpu_allocation"`
	MemoryAllocation int64     `json:"memory_allocation"`
	LastScaled       time.Time `json:"last_scaled"`
	ScalingReason    string    `json:"scaling_reason"`
}

// ScalingMetrics represents metrics used for scaling decisions
type ScalingMetrics struct {
	CPUUtilization    float64            `json:"cpu_utilization"`
	MemoryUtilization float64            `json:"memory_utilization"`
	RequestLatency    float64            `json:"request_latency"`
	QueueDepth        int64              `json:"queue_depth"`
	Throughput        float64            `json:"throughput"`
	ErrorRate         float64            `json:"error_rate"`
	CustomMetrics     map[string]float64 `json:"custom_metrics"`
}

// ScalingDecision represents a scaling decision
type ScalingDecision struct {
	ShouldScale bool    `json:"should_scale"`
	ScalingType string  `json:"scaling_type"`
	Direction   string  `json:"direction"`
	Magnitude   float64 `json:"magnitude"`
	Confidence  float64 `json:"confidence"`
	Reason      string  `json:"reason"`
	Urgency     string  `json:"urgency"`
}

// NewAutoScaler creates a new auto-scaler
func NewAutoScaler(config *AutoScalingConfig, logger *logger.Logger) *AutoScaler {
	return &AutoScaler{
		config:                config,
		logger:                logger,
		horizontalScaler:      NewHorizontalScaler(&config.HorizontalScaling, logger),
		verticalScaler:        NewVerticalScaler(&config.VerticalScaling, logger),
		predictiveScaler:      NewPredictiveScaler(&config.PredictiveScaling, logger),
		metricsCollector:      NewMetricsCollector(logger),
		scalingDecisionEngine: NewScalingDecisionEngine(config, logger),
		scalingHistory:        make([]*ScalingEvent, 0),
		currentScale:          &ScaleState{},
		stopChan:              make(chan struct{}),
		running:               false,
	}
}

// Start starts the auto-scaler
func (as *AutoScaler) Start(ctx context.Context) error {
	if !as.config.Enabled {
		as.logger.Info("Auto-scaling is disabled")
		return nil
	}

	as.mutex.Lock()
	if as.running {
		as.mutex.Unlock()
		return fmt.Errorf("auto-scaler is already running")
	}
	as.running = true
	as.mutex.Unlock()

	as.logger.Info("Starting auto-scaler")

	// Start scaling loop
	go as.scalingLoop(ctx)

	// Start predictive scaling if enabled
	if as.config.PredictiveScaling.Enabled {
		go as.predictiveScalingLoop(ctx)
	}

	return nil
}

// Stop stops the auto-scaler
func (as *AutoScaler) Stop() error {
	as.mutex.Lock()
	defer as.mutex.Unlock()

	if !as.running {
		return fmt.Errorf("auto-scaler is not running")
	}

	as.logger.Info("Stopping auto-scaler")
	close(as.stopChan)
	as.running = false

	return nil
}

// scalingLoop runs the main scaling loop
func (as *AutoScaler) scalingLoop(ctx context.Context) {
	ticker := time.NewTicker(as.config.ScalingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-as.stopChan:
			return
		case <-ticker.C:
			if err := as.evaluateAndScale(ctx); err != nil {
				as.logger.WithError(err).Error("Scaling evaluation failed")
			}
		}
	}
}

// predictiveScalingLoop runs the predictive scaling loop
func (as *AutoScaler) predictiveScalingLoop(ctx context.Context) {
	ticker := time.NewTicker(as.config.PredictiveScaling.ModelUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-as.stopChan:
			return
		case <-ticker.C:
			if err := as.performPredictiveScaling(ctx); err != nil {
				as.logger.WithError(err).Error("Predictive scaling failed")
			}
		}
	}
}

// evaluateAndScale evaluates current metrics and performs scaling if needed
func (as *AutoScaler) evaluateAndScale(ctx context.Context) error {
	ctx, span := autoScalerTracer.Start(ctx, "evaluate_and_scale")
	defer span.End()

	// Collect current metrics
	metrics, err := as.metricsCollector.CollectMetrics(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect metrics: %w", err)
	}

	// Make scaling decision
	decision, err := as.scalingDecisionEngine.MakeDecision(ctx, metrics, as.currentScale)
	if err != nil {
		return fmt.Errorf("failed to make scaling decision: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("should_scale", decision.ShouldScale),
		attribute.String("scaling_type", decision.ScalingType),
		attribute.String("direction", decision.Direction),
		attribute.Float64("confidence", decision.Confidence),
	)

	// Execute scaling if needed
	if decision.ShouldScale {
		return as.executeScaling(ctx, decision, metrics)
	}

	return nil
}

// executeScaling executes the scaling decision
func (as *AutoScaler) executeScaling(ctx context.Context, decision *ScalingDecision, metrics *ScalingMetrics) error {
	ctx, span := autoScalerTracer.Start(ctx, "execute_scaling")
	defer span.End()

	event := &ScalingEvent{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		EventType:   "scaling",
		ScalingType: decision.ScalingType,
		Trigger:     decision.Reason,
		BeforeState: as.copyScaleState(as.currentScale),
		Metrics:     metrics,
		Metadata:    make(map[string]interface{}),
	}

	span.SetAttributes(
		attribute.String("scaling.id", event.ID),
		attribute.String("scaling.type", decision.ScalingType),
		attribute.String("scaling.direction", decision.Direction),
	)

	as.logger.WithFields(logger.Fields{
		"scaling_id":   event.ID,
		"scaling_type": decision.ScalingType,
		"direction":    decision.Direction,
		"reason":       decision.Reason,
		"confidence":   decision.Confidence,
	}).Info("Executing scaling operation")

	startTime := time.Now()
	var err error

	// Execute scaling based on type
	switch decision.ScalingType {
	case "horizontal":
		err = as.executeHorizontalScaling(ctx, decision, event)
	case "vertical":
		err = as.executeVerticalScaling(ctx, decision, event)
	case "hybrid":
		err = as.executeHybridScaling(ctx, decision, event)
	default:
		err = fmt.Errorf("unknown scaling type: %s", decision.ScalingType)
	}

	event.Duration = time.Since(startTime)
	event.Success = err == nil
	if err != nil {
		event.ErrorMessage = err.Error()
	}

	event.AfterState = as.copyScaleState(as.currentScale)

	// Record scaling event
	as.mutex.Lock()
	as.scalingHistory = append(as.scalingHistory, event)
	// Keep only last 1000 scaling events
	if len(as.scalingHistory) > 1000 {
		as.scalingHistory = as.scalingHistory[1:]
	}
	as.mutex.Unlock()

	span.SetAttributes(
		attribute.Bool("scaling.success", event.Success),
		attribute.String("scaling.duration", event.Duration.String()),
	)

	if err != nil {
		as.logger.WithError(err).WithField("scaling_id", event.ID).Error("Scaling operation failed")
		return err
	}

	as.logger.WithFields(logger.Fields{
		"scaling_id": event.ID,
		"duration":   event.Duration,
		"success":    event.Success,
	}).Info("Scaling operation completed")

	return nil
}

// executeHorizontalScaling executes horizontal scaling
func (as *AutoScaler) executeHorizontalScaling(ctx context.Context, decision *ScalingDecision, event *ScalingEvent) error {
	var targetInstances int

	if decision.Direction == "up" {
		targetInstances = as.currentScale.Instances + as.config.HorizontalScaling.ScaleUpStepSize
		if targetInstances > as.config.HorizontalScaling.MaxInstances {
			targetInstances = as.config.HorizontalScaling.MaxInstances
		}
	} else {
		targetInstances = as.currentScale.Instances - as.config.HorizontalScaling.ScaleDownStepSize
		if targetInstances < as.config.HorizontalScaling.MinInstances {
			targetInstances = as.config.HorizontalScaling.MinInstances
		}
	}

	if targetInstances == as.currentScale.Instances {
		return fmt.Errorf("target instances same as current instances")
	}

	// Execute horizontal scaling
	err := as.horizontalScaler.ScaleToInstances(ctx, targetInstances)
	if err != nil {
		return fmt.Errorf("horizontal scaling failed: %w", err)
	}

	// Update current scale state
	as.currentScale.Instances = targetInstances
	as.currentScale.LastScaled = time.Now()
	as.currentScale.ScalingReason = decision.Reason

	return nil
}

// executeVerticalScaling executes vertical scaling
func (as *AutoScaler) executeVerticalScaling(ctx context.Context, decision *ScalingDecision, event *ScalingEvent) error {
	var targetCPU float64
	var targetMemory int64

	if decision.Direction == "up" {
		targetCPU = as.currentScale.CPUAllocation + as.config.VerticalScaling.CPUStepSize
		targetMemory = as.currentScale.MemoryAllocation + as.config.VerticalScaling.MemoryStepSize
	} else {
		targetCPU = as.currentScale.CPUAllocation - as.config.VerticalScaling.CPUStepSize
		targetMemory = as.currentScale.MemoryAllocation - as.config.VerticalScaling.MemoryStepSize
	}

	// Apply limits
	targetCPU = math.Max(as.config.VerticalScaling.MinCPU, math.Min(targetCPU, as.config.VerticalScaling.MaxCPU))
	targetMemory = int64(math.Max(float64(as.config.VerticalScaling.MinMemory), math.Min(float64(targetMemory), float64(as.config.VerticalScaling.MaxMemory))))

	// Execute vertical scaling
	err := as.verticalScaler.ScaleResources(ctx, targetCPU, targetMemory)
	if err != nil {
		return fmt.Errorf("vertical scaling failed: %w", err)
	}

	// Update current scale state
	as.currentScale.CPUAllocation = targetCPU
	as.currentScale.MemoryAllocation = targetMemory
	as.currentScale.LastScaled = time.Now()
	as.currentScale.ScalingReason = decision.Reason

	return nil
}

// executeHybridScaling executes hybrid scaling (both horizontal and vertical)
func (as *AutoScaler) executeHybridScaling(ctx context.Context, decision *ScalingDecision, event *ScalingEvent) error {
	// Execute horizontal scaling first
	if err := as.executeHorizontalScaling(ctx, decision, event); err != nil {
		return fmt.Errorf("hybrid scaling horizontal phase failed: %w", err)
	}

	// Execute vertical scaling
	if err := as.executeVerticalScaling(ctx, decision, event); err != nil {
		return fmt.Errorf("hybrid scaling vertical phase failed: %w", err)
	}

	return nil
}

// performPredictiveScaling performs predictive scaling based on forecasted metrics
func (as *AutoScaler) performPredictiveScaling(ctx context.Context) error {
	if !as.config.PredictiveScaling.Enabled {
		return nil
	}

	// Get prediction from predictive scaler
	prediction, err := as.predictiveScaler.PredictFutureLoad(ctx, as.config.PredictiveScaling.PredictionWindow)
	if err != nil {
		return fmt.Errorf("failed to predict future load: %w", err)
	}

	// Make scaling decision based on prediction
	if prediction.Confidence >= as.config.PredictiveScaling.ConfidenceThreshold {
		decision := &ScalingDecision{
			ShouldScale: true,
			ScalingType: "horizontal",
			Direction:   "up",
			Magnitude:   prediction.ScaleFactor,
			Confidence:  prediction.Confidence,
			Reason:      "predictive_scaling",
			Urgency:     "low",
		}

		return as.executeScaling(ctx, decision, &ScalingMetrics{})
	}

	return nil
}

// copyScaleState creates a copy of the scale state
func (as *AutoScaler) copyScaleState(state *ScaleState) *ScaleState {
	return &ScaleState{
		Instances:        state.Instances,
		CPUAllocation:    state.CPUAllocation,
		MemoryAllocation: state.MemoryAllocation,
		LastScaled:       state.LastScaled,
		ScalingReason:    state.ScalingReason,
	}
}

// GetScalingHistory returns the scaling history
func (as *AutoScaler) GetScalingHistory() []*ScalingEvent {
	as.mutex.RLock()
	defer as.mutex.RUnlock()

	history := make([]*ScalingEvent, len(as.scalingHistory))
	copy(history, as.scalingHistory)
	return history
}

// GetCurrentScale returns the current scale state
func (as *AutoScaler) GetCurrentScale() *ScaleState {
	as.mutex.RLock()
	defer as.mutex.RUnlock()

	return as.copyScaleState(as.currentScale)
}

// ForceScale forces a scaling operation
func (as *AutoScaler) ForceScale(ctx context.Context, scalingType, direction string, magnitude float64) error {
	decision := &ScalingDecision{
		ShouldScale: true,
		ScalingType: scalingType,
		Direction:   direction,
		Magnitude:   magnitude,
		Confidence:  1.0,
		Reason:      "manual_override",
		Urgency:     "high",
	}

	metrics, _ := as.metricsCollector.CollectMetrics(ctx)
	return as.executeScaling(ctx, decision, metrics)
}

// Placeholder types for scaling components
type HorizontalScaler struct {
	config *HorizontalScalingConfig
	logger *logger.Logger
}

type VerticalScaler struct {
	config *VerticalScalingConfig
	logger *logger.Logger
}

type PredictiveScaler struct {
	config *PredictiveScalingConfig
	logger *logger.Logger
}

type MetricsCollector struct {
	logger *logger.Logger
}

type ScalingDecisionEngine struct {
	config *AutoScalingConfig
	logger *logger.Logger
}

type LoadPrediction struct {
	ScaleFactor float64
	Confidence  float64
	Timestamp   time.Time
}

// Placeholder implementations
func NewHorizontalScaler(config *HorizontalScalingConfig, logger *logger.Logger) *HorizontalScaler {
	return &HorizontalScaler{config: config, logger: logger}
}

func NewVerticalScaler(config *VerticalScalingConfig, logger *logger.Logger) *VerticalScaler {
	return &VerticalScaler{config: config, logger: logger}
}

func NewPredictiveScaler(config *PredictiveScalingConfig, logger *logger.Logger) *PredictiveScaler {
	return &PredictiveScaler{config: config, logger: logger}
}

func NewMetricsCollector(logger *logger.Logger) *MetricsCollector {
	return &MetricsCollector{logger: logger}
}

func NewScalingDecisionEngine(config *AutoScalingConfig, logger *logger.Logger) *ScalingDecisionEngine {
	return &ScalingDecisionEngine{config: config, logger: logger}
}

func (hs *HorizontalScaler) ScaleToInstances(ctx context.Context, instances int) error {
	// Implementation would interact with container orchestrator (Kubernetes, Docker Swarm, etc.)
	return nil
}

func (vs *VerticalScaler) ScaleResources(ctx context.Context, cpu float64, memory int64) error {
	// Implementation would adjust resource allocations
	return nil
}

func (ps *PredictiveScaler) PredictFutureLoad(ctx context.Context, window time.Duration) (*LoadPrediction, error) {
	// Implementation would use ML models to predict future load
	return &LoadPrediction{
		ScaleFactor: 1.2,
		Confidence:  0.85,
		Timestamp:   time.Now(),
	}, nil
}

func (mc *MetricsCollector) CollectMetrics(ctx context.Context) (*ScalingMetrics, error) {
	// Implementation would collect real metrics from monitoring systems
	return &ScalingMetrics{
		CPUUtilization:    75.0,
		MemoryUtilization: 80.0,
		RequestLatency:    150.0,
		QueueDepth:        10,
		Throughput:        1000.0,
		ErrorRate:         0.01,
		CustomMetrics:     make(map[string]float64),
	}, nil
}

func (sde *ScalingDecisionEngine) MakeDecision(ctx context.Context, metrics *ScalingMetrics, currentState *ScaleState) (*ScalingDecision, error) {
	// Implementation would analyze metrics and make scaling decisions
	shouldScale := metrics.CPUUtilization > 80.0 || metrics.MemoryUtilization > 85.0

	if shouldScale {
		return &ScalingDecision{
			ShouldScale: true,
			ScalingType: "horizontal",
			Direction:   "up",
			Magnitude:   1.0,
			Confidence:  0.9,
			Reason:      "high_resource_utilization",
			Urgency:     "medium",
		}, nil
	}

	return &ScalingDecision{
		ShouldScale: false,
	}, nil
}
