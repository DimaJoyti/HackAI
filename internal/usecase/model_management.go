package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/ollama"
)

var modelManagementTracer = otel.Tracer("hackai/usecase/model_management")

// ModelManagementUseCase handles model management operations
type ModelManagementUseCase struct {
	ollamaManager *ollama.Manager
	auditRepo     domain.AuditRepository
	logger        *logger.Logger
}

// NewModelManagementUseCase creates a new model management use case
func NewModelManagementUseCase(
	ollamaManager *ollama.Manager,
	auditRepo domain.AuditRepository,
	logger *logger.Logger,
) *ModelManagementUseCase {
	return &ModelManagementUseCase{
		ollamaManager: ollamaManager,
		auditRepo:     auditRepo,
		logger:        logger,
	}
}

// ListModels returns a list of available models
func (uc *ModelManagementUseCase) ListModels(ctx context.Context) (map[string]*ollama.ModelInfo, error) {
	ctx, span := modelManagementTracer.Start(ctx, "model_management.list_models")
	defer span.End()

	models := uc.ollamaManager.GetModels()

	span.SetAttributes(attribute.Int("models_count", len(models)))
	uc.logger.Debug("Listed models", "count", len(models))

	return models, nil
}

// GetModel returns information about a specific model
func (uc *ModelManagementUseCase) GetModel(ctx context.Context, modelName string) (*ollama.ModelInfo, error) {
	ctx, span := modelManagementTracer.Start(ctx, "model_management.get_model")
	defer span.End()
	span.SetAttributes(attribute.String("model", modelName))

	model, err := uc.ollamaManager.GetModel(modelName)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get model: %w", err)
	}

	uc.logger.Debug("Retrieved model info", "model", modelName)
	return model, nil
}

// GetModelInfo returns detailed information about a model
func (uc *ModelManagementUseCase) GetModelInfo(ctx context.Context, modelName string) (*ollama.ModelInfo, error) {
	ctx, span := modelManagementTracer.Start(ctx, "model_management.get_model_info")
	defer span.End()
	span.SetAttributes(attribute.String("model", modelName))

	model, err := uc.ollamaManager.GetModel(modelName)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get model info: %w", err)
	}

	// Log audit event
	if uc.auditRepo != nil {
		details := map[string]interface{}{
			"model_name": modelName,
			"action":     "get_info",
		}
		if err := uc.auditRepo.LogUserAction(uuid.Nil, nil, "model_info_accessed", "model", details); err != nil {
			uc.logger.Warn("Failed to create audit event", "error", err)
		}
	}

	uc.logger.Info("Retrieved model info", "model", modelName)
	return model, nil
}

// PullModel pulls a model from the OLLAMA registry
func (uc *ModelManagementUseCase) PullModel(ctx context.Context, modelName string) error {
	ctx, span := modelManagementTracer.Start(ctx, "model_management.pull_model")
	defer span.End()
	span.SetAttributes(attribute.String("model", modelName))

	uc.logger.Info("Pulling model", "model", modelName)

	err := uc.ollamaManager.PullModel(ctx, modelName)
	if err != nil {
		span.RecordError(err)
		uc.logger.Error("Failed to pull model", "model", modelName, "error", err)
		return fmt.Errorf("failed to pull model: %w", err)
	}

	// Log audit event
	if uc.auditRepo != nil {
		details := map[string]interface{}{
			"model_name": modelName,
			"action":     "pull",
		}
		if err := uc.auditRepo.LogUserAction(uuid.Nil, nil, "model_pulled", "model", details); err != nil {
			uc.logger.Warn("Failed to create audit event", "error", err)
		}
	}

	uc.logger.Info("Model pulled successfully", "model", modelName)
	return nil
}

// DeleteModel deletes a model from OLLAMA
func (uc *ModelManagementUseCase) DeleteModel(ctx context.Context, modelName string) error {
	ctx, span := modelManagementTracer.Start(ctx, "model_management.delete_model")
	defer span.End()
	span.SetAttributes(attribute.String("model", modelName))

	uc.logger.Info("Deleting model", "model", modelName)

	err := uc.ollamaManager.DeleteModel(ctx, modelName)
	if err != nil {
		span.RecordError(err)
		uc.logger.Error("Failed to delete model", "model", modelName, "error", err)
		return fmt.Errorf("failed to delete model: %w", err)
	}

	// Log audit event
	if uc.auditRepo != nil {
		details := map[string]interface{}{
			"model_name": modelName,
			"action":     "delete",
		}
		if err := uc.auditRepo.LogUserAction(uuid.Nil, nil, "model_deleted", "model", details); err != nil {
			uc.logger.Warn("Failed to create audit event", "error", err)
		}
	}

	uc.logger.Info("Model deleted successfully", "model", modelName)
	return nil
}

// CopyModel creates a copy of an existing model
func (uc *ModelManagementUseCase) CopyModel(ctx context.Context, source, destination string) error {
	ctx, span := modelManagementTracer.Start(ctx, "model_management.copy_model")
	defer span.End()
	span.SetAttributes(
		attribute.String("source", source),
		attribute.String("destination", destination),
	)

	uc.logger.Info("Copying model", "source", source, "destination", destination)

	err := uc.ollamaManager.CopyModel(ctx, source, destination)
	if err != nil {
		span.RecordError(err)
		uc.logger.Error("Failed to copy model", "source", source, "destination", destination, "error", err)
		return fmt.Errorf("failed to copy model: %w", err)
	}

	// Log audit event
	if uc.auditRepo != nil {
		details := map[string]interface{}{
			"source_model":      source,
			"destination_model": destination,
			"action":            "copy",
		}
		if err := uc.auditRepo.LogUserAction(uuid.Nil, nil, "model_copied", "model", details); err != nil {
			uc.logger.Warn("Failed to create audit event", "error", err)
		}
	}

	uc.logger.Info("Model copied successfully", "source", source, "destination", destination)
	return nil
}

// GetStatus returns the current status of the OLLAMA service
func (uc *ModelManagementUseCase) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	ctx, span := modelManagementTracer.Start(ctx, "model_management.get_status")
	defer span.End()

	isHealthy := uc.ollamaManager.IsHealthy()
	models := uc.ollamaManager.GetModels()
	stats := uc.ollamaManager.GetStats()

	status := map[string]interface{}{
		"healthy":           isHealthy,
		"models_count":      len(models),
		"total_requests":    stats.TotalRequests,
		"uptime":            stats.Uptime.String(),
		"last_health_check": stats.LastHealthCheck.Format(time.RFC3339),
		"service":           "ollama",
		"version":           "1.0.0",
		"timestamp":         time.Now().Format(time.RFC3339),
	}

	if !isHealthy {
		status["status"] = "unhealthy"
		uc.logger.Warn("OLLAMA service is unhealthy")
	} else {
		status["status"] = "healthy"
	}

	return status, nil
}

// GetStats returns detailed statistics about the OLLAMA service
func (uc *ModelManagementUseCase) GetStats(ctx context.Context) (*ollama.Stats, error) {
	ctx, span := modelManagementTracer.Start(ctx, "model_management.get_stats")
	defer span.End()

	stats := uc.ollamaManager.GetStats()
	models := uc.ollamaManager.GetModels()

	// Update stats with current model count
	stats.TotalModels = len(models)
	stats.ActiveModels = 0
	for _, model := range models {
		if model.Status == "available" {
			stats.ActiveModels++
		}
	}

	span.SetAttributes(
		attribute.Int("total_models", stats.TotalModels),
		attribute.Int("active_models", stats.ActiveModels),
		attribute.Int64("total_requests", stats.TotalRequests),
	)

	uc.logger.Debug("Retrieved OLLAMA stats",
		"total_models", stats.TotalModels,
		"active_models", stats.ActiveModels,
		"total_requests", stats.TotalRequests)

	return stats, nil
}

// ValidateModel checks if a model is available and ready for use
func (uc *ModelManagementUseCase) ValidateModel(ctx context.Context, modelName string) error {
	ctx, span := modelManagementTracer.Start(ctx, "model_management.validate_model")
	defer span.End()
	span.SetAttributes(attribute.String("model", modelName))

	model, err := uc.ollamaManager.GetModel(modelName)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("model not found: %w", err)
	}

	if model.Status != "available" {
		err := fmt.Errorf("model is not available: %s", model.Status)
		span.RecordError(err)
		return err
	}

	uc.logger.Debug("Model validated", "model", modelName, "status", model.Status)
	return nil
}

// GetModelCapabilities returns the capabilities of a specific model
func (uc *ModelManagementUseCase) GetModelCapabilities(ctx context.Context, modelName string) ([]string, error) {
	ctx, span := modelManagementTracer.Start(ctx, "model_management.get_model_capabilities")
	defer span.End()
	span.SetAttributes(attribute.String("model", modelName))

	model, err := uc.ollamaManager.GetModel(modelName)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get model capabilities: %w", err)
	}

	span.SetAttributes(attribute.StringSlice("capabilities", model.Capabilities))
	uc.logger.Debug("Retrieved model capabilities", "model", modelName, "capabilities", model.Capabilities)

	return model.Capabilities, nil
}
