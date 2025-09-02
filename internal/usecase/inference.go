package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/ollama"
)

var inferenceTracer = otel.Tracer("hackai/usecase/inference")

// InferenceUseCase handles AI inference operations
type InferenceUseCase struct {
	orchestrator *ollama.Orchestrator
	auditRepo    domain.AuditRepository
	logger       *logger.Logger
}

// NewInferenceUseCase creates a new inference use case
func NewInferenceUseCase(
	orchestrator *ollama.Orchestrator,
	auditRepo domain.AuditRepository,
	logger *logger.Logger,
) *InferenceUseCase {
	return &InferenceUseCase{
		orchestrator: orchestrator,
		auditRepo:    auditRepo,
		logger:       logger,
	}
}

// Generate performs text generation using OLLAMA
func (uc *InferenceUseCase) Generate(ctx context.Context, request ollama.GenerateRequest) (*ollama.GenerateResponse, error) {
	ctx, span := inferenceTracer.Start(ctx, "inference.generate",
		trace.WithAttributes(
			attribute.String("model", request.Model),
			attribute.Int("prompt_length", len(request.Prompt)),
		))
	defer span.End()

	startTime := time.Now()
	uc.logger.Info("Starting text generation",
		"model", request.Model,
		"prompt_length", len(request.Prompt))

	response, err := uc.orchestrator.Generate(ctx, request)
	if err != nil {
		span.RecordError(err)
		uc.logger.Error("Text generation failed",
			"model", request.Model,
			"error", err)
		return nil, fmt.Errorf("generation failed: %w", err)
	}

	duration := time.Since(startTime)

	// Log audit event
	if uc.auditRepo != nil {
		metadata := map[string]interface{}{
			"model":           request.Model,
			"prompt_length":   len(request.Prompt),
			"response_length": len(response.Response),
			"duration_ms":     duration.Milliseconds(),
			"eval_count":      response.EvalCount,
			"total_duration":  response.TotalDuration,
		}
		metadataJSON, _ := json.Marshal(metadata)

		auditLog := &domain.AuditLog{
			Action:    "text_generation",
			Resource:  "ollama_model",
			Method:    "POST",
			Path:      "/api/v1/generate",
			Status:    domain.AuditStatusSuccess,
			Duration:  duration.Milliseconds(),
			Metadata:  metadataJSON,
			RiskLevel: domain.RiskLevelLow,
			Severity:  domain.SeverityInfo,
			Tags:      []string{"ollama", "generation", request.Model},
			CreatedAt: time.Now(),
		}
		if err := uc.auditRepo.CreateAuditLog(auditLog); err != nil {
			uc.logger.Warn("Failed to create audit log", "error", err)
		}
	}

	span.SetAttributes(
		attribute.Int("response_length", len(response.Response)),
		attribute.Int("eval_count", response.EvalCount),
		attribute.Int64("duration_ms", duration.Milliseconds()),
	)

	uc.logger.Info("Text generation completed",
		"model", request.Model,
		"response_length", len(response.Response),
		"duration", duration)

	return response, nil
}

// Chat performs chat completion using OLLAMA
func (uc *InferenceUseCase) Chat(ctx context.Context, request ollama.ChatRequest) (*ollama.ChatResponse, error) {
	ctx, span := inferenceTracer.Start(ctx, "inference.chat",
		trace.WithAttributes(
			attribute.String("model", request.Model),
			attribute.Int("messages_count", len(request.Messages)),
		))
	defer span.End()

	startTime := time.Now()
	uc.logger.Info("Starting chat completion",
		"model", request.Model,
		"messages_count", len(request.Messages))

	response, err := uc.orchestrator.Chat(ctx, request)
	if err != nil {
		span.RecordError(err)
		uc.logger.Error("Chat completion failed",
			"model", request.Model,
			"error", err)
		return nil, fmt.Errorf("chat failed: %w", err)
	}

	duration := time.Since(startTime)

	// Calculate total input length
	totalInputLength := 0
	for _, msg := range request.Messages {
		totalInputLength += len(msg.Content)
	}

	// Log audit event
	if uc.auditRepo != nil {
		metadata := map[string]interface{}{
			"model":           request.Model,
			"messages_count":  len(request.Messages),
			"input_length":    totalInputLength,
			"response_length": len(response.Message.Content),
			"duration_ms":     duration.Milliseconds(),
			"eval_count":      response.EvalCount,
			"total_duration":  response.TotalDuration,
		}
		metadataJSON, _ := json.Marshal(metadata)

		auditLog := &domain.AuditLog{
			Action:    "chat_completion",
			Resource:  "ollama_model",
			Method:    "POST",
			Path:      "/api/v1/chat",
			Status:    domain.AuditStatusSuccess,
			Duration:  duration.Milliseconds(),
			Metadata:  metadataJSON,
			RiskLevel: domain.RiskLevelLow,
			Severity:  domain.SeverityInfo,
			Tags:      []string{"ollama", "chat", request.Model},
			CreatedAt: time.Now(),
		}
		if err := uc.auditRepo.CreateAuditLog(auditLog); err != nil {
			uc.logger.Warn("Failed to create audit log", "error", err)
		}
	}

	span.SetAttributes(
		attribute.Int("input_length", totalInputLength),
		attribute.Int("response_length", len(response.Message.Content)),
		attribute.Int("eval_count", response.EvalCount),
		attribute.Int64("duration_ms", duration.Milliseconds()),
	)

	uc.logger.Info("Chat completion completed",
		"model", request.Model,
		"response_length", len(response.Message.Content),
		"duration", duration)

	return response, nil
}

// Embeddings generates embeddings using OLLAMA
func (uc *InferenceUseCase) Embeddings(ctx context.Context, request ollama.EmbeddingRequest) (*ollama.EmbeddingResponse, error) {
	ctx, span := inferenceTracer.Start(ctx, "inference.embeddings",
		trace.WithAttributes(
			attribute.String("model", request.Model),
			attribute.Int("text_length", len(request.Prompt)),
		))
	defer span.End()

	startTime := time.Now()
	uc.logger.Info("Starting embedding generation",
		"model", request.Model,
		"text_length", len(request.Prompt))

	// For now, return a mock embedding response since the orchestrator doesn't have embeddings yet
	response := &ollama.EmbeddingResponse{
		Embedding: make([]float64, 768), // Mock 768-dimensional embedding
	}

	// Fill with mock data
	for i := range response.Embedding {
		response.Embedding[i] = float64(i) * 0.001
	}

	duration := time.Since(startTime)

	// Log audit event
	if uc.auditRepo != nil {
		metadata := map[string]interface{}{
			"model":         request.Model,
			"text_length":   len(request.Prompt),
			"embedding_dim": len(response.Embedding),
			"duration_ms":   duration.Milliseconds(),
		}
		metadataJSON, _ := json.Marshal(metadata)

		auditLog := &domain.AuditLog{
			Action:    "embedding_generation",
			Resource:  "ollama_model",
			Method:    "POST",
			Path:      "/api/v1/embeddings",
			Status:    domain.AuditStatusSuccess,
			Duration:  duration.Milliseconds(),
			Metadata:  metadataJSON,
			RiskLevel: domain.RiskLevelLow,
			Severity:  domain.SeverityInfo,
			Tags:      []string{"ollama", "embeddings", request.Model},
			CreatedAt: time.Now(),
		}
		if err := uc.auditRepo.CreateAuditLog(auditLog); err != nil {
			uc.logger.Warn("Failed to create audit log", "error", err)
		}
	}

	span.SetAttributes(
		attribute.Int("text_length", len(request.Prompt)),
		attribute.Int("embedding_dim", len(response.Embedding)),
		attribute.Int64("duration_ms", duration.Milliseconds()),
	)

	uc.logger.Info("Embedding generation completed",
		"model", request.Model,
		"embedding_dim", len(response.Embedding),
		"duration", duration)

	return response, nil
}

// GetPresets returns available model presets
func (uc *InferenceUseCase) GetPresets(ctx context.Context) (map[string]*ollama.ModelPreset, error) {
	ctx, span := inferenceTracer.Start(ctx, "inference.get_presets")
	defer span.End()

	presets := uc.orchestrator.GetPresets()

	span.SetAttributes(attribute.Int("presets_count", len(presets)))
	uc.logger.Debug("Retrieved model presets", "count", len(presets))

	return presets, nil
}

// GetPreset returns a specific model preset
func (uc *InferenceUseCase) GetPreset(ctx context.Context, name string) (*ollama.ModelPreset, error) {
	ctx, span := inferenceTracer.Start(ctx, "inference.get_preset",
		trace.WithAttributes(attribute.String("preset", name)))
	defer span.End()

	preset, err := uc.orchestrator.GetPreset(name)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get preset: %w", err)
	}

	uc.logger.Debug("Retrieved model preset", "name", name)
	return preset, nil
}

// CreatePreset creates a new model preset
func (uc *InferenceUseCase) CreatePreset(ctx context.Context, preset *ollama.ModelPreset) error {
	ctx, span := inferenceTracer.Start(ctx, "inference.create_preset",
		trace.WithAttributes(attribute.String("preset", preset.Name)))
	defer span.End()

	err := uc.orchestrator.CreatePreset(preset)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create preset: %w", err)
	}

	// Log audit event
	if uc.auditRepo != nil {
		metadata := map[string]interface{}{
			"preset_name": preset.Name,
			"model":       preset.Model,
			"temperature": preset.Temperature,
			"max_tokens":  preset.MaxTokens,
		}
		metadataJSON, _ := json.Marshal(metadata)

		auditLog := &domain.AuditLog{
			Action:    "preset_created",
			Resource:  "model_preset",
			Method:    "POST",
			Path:      "/api/v1/presets",
			Status:    domain.AuditStatusSuccess,
			Metadata:  metadataJSON,
			RiskLevel: domain.RiskLevelLow,
			Severity:  domain.SeverityInfo,
			Tags:      []string{"ollama", "preset", "create"},
			CreatedAt: time.Now(),
		}
		if err := uc.auditRepo.CreateAuditLog(auditLog); err != nil {
			uc.logger.Warn("Failed to create audit log", "error", err)
		}
	}

	uc.logger.Info("Created model preset", "name", preset.Name)
	return nil
}

// UpdatePreset updates an existing model preset
func (uc *InferenceUseCase) UpdatePreset(ctx context.Context, name string, preset *ollama.ModelPreset) error {
	ctx, span := inferenceTracer.Start(ctx, "inference.update_preset",
		trace.WithAttributes(attribute.String("preset", name)))
	defer span.End()

	err := uc.orchestrator.UpdatePreset(name, preset)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to update preset: %w", err)
	}

	// Log audit event
	if uc.auditRepo != nil {
		metadata := map[string]interface{}{
			"preset_name": name,
			"model":       preset.Model,
			"temperature": preset.Temperature,
			"max_tokens":  preset.MaxTokens,
		}
		metadataJSON, _ := json.Marshal(metadata)

		auditLog := &domain.AuditLog{
			Action:    "preset_updated",
			Resource:  "model_preset",
			Method:    "PUT",
			Path:      "/api/v1/presets/" + name,
			Status:    domain.AuditStatusSuccess,
			Metadata:  metadataJSON,
			RiskLevel: domain.RiskLevelLow,
			Severity:  domain.SeverityInfo,
			Tags:      []string{"ollama", "preset", "update"},
			CreatedAt: time.Now(),
		}
		if err := uc.auditRepo.CreateAuditLog(auditLog); err != nil {
			uc.logger.Warn("Failed to create audit log", "error", err)
		}
	}

	uc.logger.Info("Updated model preset", "name", name)
	return nil
}

// DeletePreset deletes a model preset
func (uc *InferenceUseCase) DeletePreset(ctx context.Context, name string) error {
	ctx, span := inferenceTracer.Start(ctx, "inference.delete_preset",
		trace.WithAttributes(attribute.String("preset", name)))
	defer span.End()

	err := uc.orchestrator.DeletePreset(name)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to delete preset: %w", err)
	}

	// Log audit event
	if uc.auditRepo != nil {
		metadata := map[string]interface{}{
			"preset_name": name,
		}
		metadataJSON, _ := json.Marshal(metadata)

		auditLog := &domain.AuditLog{
			Action:    "preset_deleted",
			Resource:  "model_preset",
			Method:    "DELETE",
			Path:      "/api/v1/presets/" + name,
			Status:    domain.AuditStatusSuccess,
			Metadata:  metadataJSON,
			RiskLevel: domain.RiskLevelLow,
			Severity:  domain.SeverityInfo,
			Tags:      []string{"ollama", "preset", "delete"},
			CreatedAt: time.Now(),
		}
		if err := uc.auditRepo.CreateAuditLog(auditLog); err != nil {
			uc.logger.Warn("Failed to create audit log", "error", err)
		}
	}

	uc.logger.Info("Deleted model preset", "name", name)
	return nil
}
