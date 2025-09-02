package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/dimajoyti/hackai/internal/usecase"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/ollama"
)

// OLLAMAHandler handles OLLAMA-related HTTP requests
type OLLAMAHandler struct {
	modelManagementUC *usecase.ModelManagementUseCase
	inferenceUC       *usecase.InferenceUseCase
	logger            *logger.Logger
}

// NewOLLAMAHandler creates a new OLLAMA handler
func NewOLLAMAHandler(
	modelManagementUC *usecase.ModelManagementUseCase,
	inferenceUC *usecase.InferenceUseCase,
	logger *logger.Logger,
) *OLLAMAHandler {
	return &OLLAMAHandler{
		modelManagementUC: modelManagementUC,
		inferenceUC:       inferenceUC,
		logger:            logger,
	}
}

// ListModels handles GET /api/v1/models
func (h *OLLAMAHandler) ListModels(w http.ResponseWriter, r *http.Request) {
	models, err := h.modelManagementUC.ListModels(r.Context())
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list models", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"models": models,
		"count":  len(models),
	})
}

// GetModel handles GET /api/v1/models/{model}
func (h *OLLAMAHandler) GetModel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	modelName := vars["model"]

	if modelName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Model name is required", nil)
		return
	}

	model, err := h.modelManagementUC.GetModel(r.Context(), modelName)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Model not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, model)
}

// PullModel handles POST /api/v1/models/pull
func (h *OLLAMAHandler) PullModel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Name == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Model name is required", nil)
		return
	}

	err := h.modelManagementUC.PullModel(r.Context(), req.Name)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to pull model", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Model pulled successfully",
		"model":   req.Name,
	})
}

// DeleteModel handles DELETE /api/v1/models/{model}
func (h *OLLAMAHandler) DeleteModel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	modelName := vars["model"]

	if modelName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Model name is required", nil)
		return
	}

	err := h.modelManagementUC.DeleteModel(r.Context(), modelName)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete model", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Model deleted successfully",
		"model":   modelName,
	})
}

// GetModelInfo handles GET /api/v1/models/{model}/info
func (h *OLLAMAHandler) GetModelInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	modelName := vars["model"]

	if modelName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Model name is required", nil)
		return
	}

	info, err := h.modelManagementUC.GetModelInfo(r.Context(), modelName)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Model info not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, info)
}

// PushModel handles POST /api/v1/models/push
func (h *OLLAMAHandler) PushModel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Push model functionality not implemented",
		"model":   req.Name,
	})
}

// CreateModel handles POST /api/v1/models/create
func (h *OLLAMAHandler) CreateModel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Modelfile string `json:"modelfile"`
		Stream    bool   `json:"stream,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Create model functionality not implemented",
		"model":   req.Name,
	})
}

// CopyModel handles POST /api/v1/models/copy
func (h *OLLAMAHandler) CopyModel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Source == "" || req.Destination == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Source and destination are required", nil)
		return
	}

	err := h.modelManagementUC.CopyModel(r.Context(), req.Source, req.Destination)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to copy model", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message":     "Model copied successfully",
		"source":      req.Source,
		"destination": req.Destination,
	})
}

// Generate handles POST /api/v1/generate
func (h *OLLAMAHandler) Generate(w http.ResponseWriter, r *http.Request) {
	var req ollama.GenerateRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Model == "" || req.Prompt == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Model and prompt are required", nil)
		return
	}

	response, err := h.inferenceUC.Generate(r.Context(), req)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Generation failed", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// Chat handles POST /api/v1/chat
func (h *OLLAMAHandler) Chat(w http.ResponseWriter, r *http.Request) {
	var req ollama.ChatRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Model == "" || len(req.Messages) == 0 {
		h.writeErrorResponse(w, http.StatusBadRequest, "Model and messages are required", nil)
		return
	}

	response, err := h.inferenceUC.Chat(r.Context(), req)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Chat failed", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// Embeddings handles POST /api/v1/embeddings
func (h *OLLAMAHandler) Embeddings(w http.ResponseWriter, r *http.Request) {
	var req ollama.EmbeddingRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Model == "" || req.Prompt == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Model and prompt are required", nil)
		return
	}

	response, err := h.inferenceUC.Embeddings(r.Context(), req)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Embeddings failed", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GenerateStream handles POST /api/v1/generate/stream
func (h *OLLAMAHandler) GenerateStream(w http.ResponseWriter, r *http.Request) {
	var req ollama.GenerateRequest
	req.Stream = true

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Set up streaming response
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Streaming generation not fully implemented",
		"model":   req.Model,
	})
}

// ChatStream handles POST /api/v1/chat/stream
func (h *OLLAMAHandler) ChatStream(w http.ResponseWriter, r *http.Request) {
	var req ollama.ChatRequest
	req.Stream = true

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Set up streaming response
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Streaming chat not fully implemented",
		"model":   req.Model,
	})
}

// GetStatus handles GET /api/v1/status
func (h *OLLAMAHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.modelManagementUC.GetStatus(r.Context())
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get status", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, status)
}

// GetStats handles GET /api/v1/stats
func (h *OLLAMAHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.modelManagementUC.GetStats(r.Context())
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get stats", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, stats)
}

// GetConfig handles GET /api/v1/config
func (h *OLLAMAHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Get config functionality not implemented",
	})
}

// UpdateConfig handles PUT /api/v1/config
func (h *OLLAMAHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Update config functionality not implemented",
	})
}

// writeJSONResponse writes a JSON response
func (h *OLLAMAHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeErrorResponse writes an error response
func (h *OLLAMAHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	h.logger.Error(message, "error", err, "status_code", statusCode)

	response := map[string]interface{}{
		"error":     message,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err != nil {
		response["details"] = err.Error()
	}

	h.writeJSONResponse(w, statusCode, response)
}

// BatchGenerate handles POST /api/v1/batch/generate
func (h *OLLAMAHandler) BatchGenerate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Requests []ollama.GenerateRequest `json:"requests"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if len(req.Requests) == 0 {
		h.writeErrorResponse(w, http.StatusBadRequest, "At least one request is required", nil)
		return
	}

	responses := make([]*ollama.GenerateResponse, 0, len(req.Requests))
	for i, genReq := range req.Requests {
		response, err := h.inferenceUC.Generate(r.Context(), genReq)
		if err != nil {
			h.logger.Warn("Batch generation failed for request", "index", i, "error", err)
			continue
		}
		responses = append(responses, response)
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"responses": responses,
		"total":     len(responses),
		"requested": len(req.Requests),
	})
}

// BatchEmbeddings handles POST /api/v1/batch/embeddings
func (h *OLLAMAHandler) BatchEmbeddings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Requests []ollama.EmbeddingRequest `json:"requests"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if len(req.Requests) == 0 {
		h.writeErrorResponse(w, http.StatusBadRequest, "At least one request is required", nil)
		return
	}

	responses := make([]*ollama.EmbeddingResponse, 0, len(req.Requests))
	for i, embReq := range req.Requests {
		response, err := h.inferenceUC.Embeddings(r.Context(), embReq)
		if err != nil {
			h.logger.Warn("Batch embedding failed for request", "index", i, "error", err)
			continue
		}
		responses = append(responses, response)
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"responses": responses,
		"total":     len(responses),
		"requested": len(req.Requests),
	})
}

// ListPresets handles GET /api/v1/presets
func (h *OLLAMAHandler) ListPresets(w http.ResponseWriter, r *http.Request) {
	presets, err := h.inferenceUC.GetPresets(r.Context())
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list presets", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"presets": presets,
		"count":   len(presets),
	})
}

// CreatePreset handles POST /api/v1/presets
func (h *OLLAMAHandler) CreatePreset(w http.ResponseWriter, r *http.Request) {
	var preset ollama.ModelPreset

	if err := json.NewDecoder(r.Body).Decode(&preset); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if preset.Name == "" || preset.Model == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Name and model are required", nil)
		return
	}

	err := h.inferenceUC.CreatePreset(r.Context(), &preset)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create preset", err)
		return
	}

	h.writeJSONResponse(w, http.StatusCreated, map[string]interface{}{
		"message": "Preset created successfully",
		"preset":  preset,
	})
}

// GetPreset handles GET /api/v1/presets/{preset}
func (h *OLLAMAHandler) GetPreset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	presetName := vars["preset"]

	if presetName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Preset name is required", nil)
		return
	}

	preset, err := h.inferenceUC.GetPreset(r.Context(), presetName)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Preset not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, preset)
}

// UpdatePreset handles PUT /api/v1/presets/{preset}
func (h *OLLAMAHandler) UpdatePreset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	presetName := vars["preset"]

	if presetName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Preset name is required", nil)
		return
	}

	var preset ollama.ModelPreset
	if err := json.NewDecoder(r.Body).Decode(&preset); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	err := h.inferenceUC.UpdatePreset(r.Context(), presetName, &preset)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update preset", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Preset updated successfully",
		"preset":  preset,
	})
}

// DeletePreset handles DELETE /api/v1/presets/{preset}
func (h *OLLAMAHandler) DeletePreset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	presetName := vars["preset"]

	if presetName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Preset name is required", nil)
		return
	}

	err := h.inferenceUC.DeletePreset(r.Context(), presetName)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete preset", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Preset deleted successfully",
		"preset":  presetName,
	})
}

// SecurityScan handles POST /api/v1/security/scan
func (h *OLLAMAHandler) SecurityScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Model  string `json:"model"`
		Target string `json:"target"`
		Type   string `json:"type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Security scan functionality not implemented",
		"model":   req.Model,
		"target":  req.Target,
		"type":    req.Type,
	})
}

// GetPerformanceMetrics handles GET /api/v1/monitoring/performance
func (h *OLLAMAHandler) GetPerformanceMetrics(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	timeRange := r.URL.Query().Get("time_range")
	if timeRange == "" {
		timeRange = "1h"
	}

	metrics := map[string]interface{}{
		"time_range":        timeRange,
		"average_latency":   "150ms",
		"requests_per_sec":  25.5,
		"success_rate":      99.2,
		"error_rate":        0.8,
		"memory_usage":      "2.1GB",
		"cpu_usage":         "45%",
		"gpu_usage":         "78%",
		"active_models":     3,
		"queue_length":      2,
		"throughput_tokens": 1250,
	}

	h.writeJSONResponse(w, http.StatusOK, metrics)
}

// GetUsageMetrics handles GET /api/v1/monitoring/usage
func (h *OLLAMAHandler) GetUsageMetrics(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	timeRange := r.URL.Query().Get("time_range")
	if timeRange == "" {
		timeRange = "24h"
	}

	metrics := map[string]interface{}{
		"time_range":     timeRange,
		"total_requests": 15420,
		"total_tokens":   2450000,
		"unique_models":  8,
		"top_models": []map[string]interface{}{
			{"name": "llama2", "requests": 8500, "tokens": 1200000},
			{"name": "codellama", "requests": 4200, "tokens": 850000},
			{"name": "mistral", "requests": 2720, "tokens": 400000},
		},
		"usage_by_hour": []map[string]interface{}{
			{"hour": "00:00", "requests": 120, "tokens": 18000},
			{"hour": "01:00", "requests": 95, "tokens": 14250},
			{"hour": "02:00", "requests": 80, "tokens": 12000},
		},
	}

	h.writeJSONResponse(w, http.StatusOK, metrics)
}
