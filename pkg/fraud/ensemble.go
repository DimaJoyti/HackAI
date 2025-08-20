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

var ensembleTracer = otel.Tracer("hackai/fraud/ensemble")

// EnsembleManager manages multiple AI models for fraud detection
type EnsembleManager struct {
	models           map[string]FraudModel
	strategy         EnsembleStrategy
	weights          map[string]float64
	config           *EngineConfig
	logger           *logger.Logger
	tracer           trace.Tracer
	mutex            sync.RWMutex
	performanceStats map[string]*ModelPerformance
}

// FraudModel interface for individual fraud detection models
type FraudModel interface {
	ID() string
	Name() string
	Type() ModelType
	Predict(ctx context.Context, features map[string]float64) (*ModelPrediction, error)
	Train(ctx context.Context, data TrainingData) error
	Evaluate(ctx context.Context, testData TrainingData) (*ModelEvaluation, error)
	GetMetadata() map[string]interface{}
	IsHealthy() bool
}

// ModelType defines the type of fraud detection model
type ModelType string

const (
	ModelTypeRandomForest    ModelType = "random_forest"
	ModelTypeXGBoost         ModelType = "xgboost"
	ModelTypeNeuralNetwork   ModelType = "neural_network"
	ModelTypeIsolationForest ModelType = "isolation_forest"
	ModelTypeLogisticReg     ModelType = "logistic_regression"
	ModelTypeSVM             ModelType = "svm"
	ModelTypeKMeans          ModelType = "kmeans"
	ModelTypeAutoEncoder     ModelType = "autoencoder"
)

// EnsembleStrategy defines how models are combined
type EnsembleStrategy string

const (
	StrategyVoting   EnsembleStrategy = "voting"
	StrategyStacking EnsembleStrategy = "stacking"
	StrategyBlending EnsembleStrategy = "blending"
	StrategyWeighted EnsembleStrategy = "weighted"
	StrategyDynamic  EnsembleStrategy = "dynamic"
)

// ModelPerformance tracks model performance metrics
type ModelPerformance struct {
	ModelID          string        `json:"model_id"`
	Accuracy         float64       `json:"accuracy"`
	Precision        float64       `json:"precision"`
	Recall           float64       `json:"recall"`
	F1Score          float64       `json:"f1_score"`
	AUC              float64       `json:"auc"`
	AvgLatency       time.Duration `json:"avg_latency"`
	TotalPredictions int64         `json:"total_predictions"`
	ErrorRate        float64       `json:"error_rate"`
	LastUpdated      time.Time     `json:"last_updated"`
}

// ModelEvaluation represents model evaluation results
type ModelEvaluation struct {
	ModelID           string             `json:"model_id"`
	Accuracy          float64            `json:"accuracy"`
	Precision         float64            `json:"precision"`
	Recall            float64            `json:"recall"`
	F1Score           float64            `json:"f1_score"`
	AUC               float64            `json:"auc"`
	ConfusionMatrix   map[string]int     `json:"confusion_matrix"`
	FeatureImportance map[string]float64 `json:"feature_importance"`
	Timestamp         time.Time          `json:"timestamp"`
}

// TrainingData represents training data for models
type TrainingData struct {
	Features []map[string]float64   `json:"features"`
	Labels   []bool                 `json:"labels"`
	Weights  []float64              `json:"weights,omitempty"`
	Metadata map[string]interface{} `json:"metadata"`
}

// NewEnsembleManager creates a new ensemble manager
func NewEnsembleManager(config *EngineConfig, logger *logger.Logger) (*EnsembleManager, error) {
	manager := &EnsembleManager{
		models:           make(map[string]FraudModel),
		strategy:         EnsembleStrategy(config.EnsembleStrategy),
		weights:          make(map[string]float64),
		config:           config,
		logger:           logger,
		tracer:           ensembleTracer,
		performanceStats: make(map[string]*ModelPerformance),
	}

	// Initialize default models
	if err := manager.initializeDefaultModels(); err != nil {
		return nil, fmt.Errorf("failed to initialize default models: %w", err)
	}

	return manager, nil
}

// initializeDefaultModels initializes the default set of fraud detection models
func (em *EnsembleManager) initializeDefaultModels() error {
	// Initialize Random Forest model
	rfModel, err := NewRandomForestModel("rf_001", em.config, em.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize Random Forest model: %w", err)
	}
	em.AddModel(rfModel, 0.25)

	// Initialize XGBoost model
	xgbModel, err := NewXGBoostModel("xgb_001", em.config, em.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize XGBoost model: %w", err)
	}
	em.AddModel(xgbModel, 0.30)

	// Initialize Neural Network model
	nnModel, err := NewNeuralNetworkModel("nn_001", em.config, em.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize Neural Network model: %w", err)
	}
	em.AddModel(nnModel, 0.25)

	// Initialize Isolation Forest model (for anomaly detection)
	ifModel, err := NewIsolationForestModel("if_001", em.config, em.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize Isolation Forest model: %w", err)
	}
	em.AddModel(ifModel, 0.20)

	return nil
}

// AddModel adds a model to the ensemble
func (em *EnsembleManager) AddModel(model FraudModel, weight float64) {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	em.models[model.ID()] = model
	em.weights[model.ID()] = weight
	em.performanceStats[model.ID()] = &ModelPerformance{
		ModelID:     model.ID(),
		LastUpdated: time.Now(),
	}

	em.logger.Info("Model added to ensemble",
		"model_id", model.ID(),
		"model_name", model.Name(),
		"model_type", string(model.Type()),
		"weight", weight)
}

// Predict performs ensemble prediction
func (em *EnsembleManager) Predict(ctx context.Context, features map[string]float64) ([]ModelPrediction, error) {
	ctx, span := ensembleTracer.Start(ctx, "ensemble.predict",
		trace.WithAttributes(
			attribute.Int("features.count", len(features)),
			attribute.String("ensemble.strategy", string(em.strategy)),
		),
	)
	defer span.End()

	em.mutex.RLock()
	models := make([]FraudModel, 0, len(em.models))
	for _, model := range em.models {
		if model.IsHealthy() {
			models = append(models, model)
		}
	}
	em.mutex.RUnlock()

	if len(models) == 0 {
		err := fmt.Errorf("no healthy models available for prediction")
		span.RecordError(err)
		return nil, err
	}

	// Predict with all models concurrently
	predictions := make([]ModelPrediction, 0, len(models))
	predictionChan := make(chan ModelPrediction, len(models))
	errorChan := make(chan error, len(models))

	var wg sync.WaitGroup
	for _, model := range models {
		wg.Add(1)
		go func(m FraudModel) {
			defer wg.Done()

			startTime := time.Now()
			pred, err := m.Predict(ctx, features)
			if err != nil {
				errorChan <- fmt.Errorf("model %s prediction failed: %w", m.ID(), err)
				return
			}

			pred.ProcessTime = time.Since(startTime)
			predictionChan <- *pred
		}(model)
	}

	wg.Wait()
	close(predictionChan)
	close(errorChan)

	// Collect predictions
	for pred := range predictionChan {
		predictions = append(predictions, pred)
	}

	// Log any errors
	for err := range errorChan {
		em.logger.Error("Model prediction error", "error", err)
	}

	if len(predictions) == 0 {
		err := fmt.Errorf("all model predictions failed")
		span.RecordError(err)
		return nil, err
	}

	// Update performance stats
	em.updatePerformanceStats(predictions)

	span.SetAttributes(
		attribute.Int("predictions.count", len(predictions)),
		attribute.Int("models.healthy", len(models)),
	)

	return predictions, nil
}

// updatePerformanceStats updates model performance statistics
func (em *EnsembleManager) updatePerformanceStats(predictions []ModelPrediction) {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	for _, pred := range predictions {
		if stats, exists := em.performanceStats[pred.ModelID]; exists {
			stats.TotalPredictions++
			// Update average latency using exponential moving average
			alpha := 0.1
			stats.AvgLatency = time.Duration(float64(stats.AvgLatency)*(1-alpha) + float64(pred.ProcessTime)*alpha)
			stats.LastUpdated = time.Now()
		}
	}
}

// GetModelPerformance returns performance statistics for all models
func (em *EnsembleManager) GetModelPerformance() map[string]*ModelPerformance {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	result := make(map[string]*ModelPerformance)
	for id, stats := range em.performanceStats {
		// Create a copy to avoid race conditions
		statsCopy := *stats
		result[id] = &statsCopy
	}

	return result
}

// RemoveModel removes a model from the ensemble
func (em *EnsembleManager) RemoveModel(modelID string) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	if _, exists := em.models[modelID]; !exists {
		return fmt.Errorf("model %s not found in ensemble", modelID)
	}

	delete(em.models, modelID)
	delete(em.weights, modelID)
	delete(em.performanceStats, modelID)

	em.logger.Info("Model removed from ensemble", "model_id", modelID)
	return nil
}

// UpdateModelWeight updates the weight of a model in the ensemble
func (em *EnsembleManager) UpdateModelWeight(modelID string, weight float64) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	if _, exists := em.models[modelID]; !exists {
		return fmt.Errorf("model %s not found in ensemble", modelID)
	}

	em.weights[modelID] = weight
	em.logger.Info("Model weight updated", "model_id", modelID, "new_weight", weight)
	return nil
}
