package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/pkg/logger"
)

var managerTracer = otel.Tracer("hackai/pkg/ollama/manager")

// Manager handles OLLAMA model management and operations
type Manager struct {
	client    *http.Client
	config    *Config
	logger    *logger.Logger
	baseURL   string
	models    map[string]*ModelInfo
	modelsMux sync.RWMutex
	stats     *Stats
	statsMux  sync.RWMutex
}

// Config represents OLLAMA configuration
type Config struct {
	BaseURL           string        `yaml:"base_url" json:"base_url"`
	Timeout           time.Duration `yaml:"timeout" json:"timeout"`
	MaxRetries        int           `yaml:"max_retries" json:"max_retries"`
	Models            []string      `yaml:"models" json:"models"`
	DefaultModel      string        `yaml:"default_model" json:"default_model"`
	AutoPull          bool          `yaml:"auto_pull" json:"auto_pull"`
	EmbeddingModel    string        `yaml:"embedding_model" json:"embedding_model"`
	MaxConcurrent     int           `yaml:"max_concurrent" json:"max_concurrent"`
	HealthCheckPeriod time.Duration `yaml:"health_check_period" json:"health_check_period"`
}

// ModelInfo represents information about an OLLAMA model
type ModelInfo struct {
	Name         string            `json:"name"`
	Size         int64             `json:"size"`
	Digest       string            `json:"digest"`
	ModifiedAt   time.Time         `json:"modified_at"`
	Details      ModelDetails      `json:"details"`
	Status       string            `json:"status"`
	LastUsed     time.Time         `json:"last_used"`
	UsageCount   int64             `json:"usage_count"`
	Capabilities []string          `json:"capabilities"`
	Metadata     map[string]string `json:"metadata"`
}

// ModelDetails represents detailed model information
type ModelDetails struct {
	Format            string   `json:"format"`
	Family            string   `json:"family"`
	Families          []string `json:"families"`
	ParameterSize     string   `json:"parameter_size"`
	QuantizationLevel string   `json:"quantization_level"`
	Architecture      string   `json:"architecture"`
	ContextLength     int      `json:"context_length"`
}

// Stats represents OLLAMA service statistics
type Stats struct {
	TotalModels     int              `json:"total_models"`
	ActiveModels    int              `json:"active_models"`
	TotalRequests   int64            `json:"total_requests"`
	SuccessfulReqs  int64            `json:"successful_requests"`
	FailedRequests  int64            `json:"failed_requests"`
	AverageLatency  time.Duration    `json:"average_latency"`
	TotalTokens     int64            `json:"total_tokens"`
	Uptime          time.Duration    `json:"uptime"`
	LastHealthCheck time.Time        `json:"last_health_check"`
	MemoryUsage     int64            `json:"memory_usage"`
	DiskUsage       int64            `json:"disk_usage"`
	ModelUsage      map[string]int64 `json:"model_usage"`
}

// NewManager creates a new OLLAMA manager
func NewManager(config *Config, logger *logger.Logger) (*Manager, error) {
	if config.BaseURL == "" {
		config.BaseURL = "http://localhost:11434"
	}
	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 10
	}
	if config.HealthCheckPeriod == 0 {
		config.HealthCheckPeriod = 30 * time.Second
	}

	client := &http.Client{
		Timeout: config.Timeout,
	}

	manager := &Manager{
		client:  client,
		config:  config,
		logger:  logger,
		baseURL: strings.TrimSuffix(config.BaseURL, "/"),
		models:  make(map[string]*ModelInfo),
		stats: &Stats{
			ModelUsage: make(map[string]int64),
		},
	}

	// Initialize models
	if err := manager.initializeModels(); err != nil {
		return nil, fmt.Errorf("failed to initialize models: %w", err)
	}

	// Start health check routine
	go manager.healthCheckRoutine()

	logger.Info("OLLAMA manager initialized",
		"base_url", config.BaseURL,
		"models", len(manager.models))

	return manager, nil
}

// initializeModels discovers and initializes available models
func (m *Manager) initializeModels() error {
	ctx, span := managerTracer.Start(context.Background(), "manager.initialize_models")
	defer span.End()

	models, err := m.listAvailableModels(ctx)
	if err != nil {
		return fmt.Errorf("failed to list models: %w", err)
	}

	m.modelsMux.Lock()
	defer m.modelsMux.Unlock()

	for _, model := range models {
		m.models[model.Name] = model
		m.logger.Debug("Initialized model", "name", model.Name, "size", model.Size)
	}

	// Auto-pull configured models if enabled
	if m.config.AutoPull {
		for _, modelName := range m.config.Models {
			if _, exists := m.models[modelName]; !exists {
				m.logger.Info("Auto-pulling model", "name", modelName)
				if err := m.PullModel(ctx, modelName); err != nil {
					m.logger.Warn("Failed to auto-pull model", "name", modelName, "error", err)
				}
			}
		}
	}

	return nil
}

// listAvailableModels retrieves list of available models from OLLAMA
func (m *Manager) listAvailableModels(ctx context.Context) ([]*ModelInfo, error) {
	ctx, span := managerTracer.Start(ctx, "manager.list_available_models")
	defer span.End()

	url := m.baseURL + "/api/tags"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("OLLAMA API error: %s", string(body))
		span.RecordError(err)
		return nil, err
	}

	var response struct {
		Models []struct {
			Name       string    `json:"name"`
			Size       int64     `json:"size"`
			Digest     string    `json:"digest"`
			ModifiedAt time.Time `json:"modified_at"`
			Details    struct {
				Format            string   `json:"format"`
				Family            string   `json:"family"`
				Families          []string `json:"families"`
				ParameterSize     string   `json:"parameter_size"`
				QuantizationLevel string   `json:"quantization_level"`
			} `json:"details"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		span.RecordError(err)
		return nil, err
	}

	models := make([]*ModelInfo, 0, len(response.Models))
	for _, model := range response.Models {
		modelInfo := &ModelInfo{
			Name:       model.Name,
			Size:       model.Size,
			Digest:     model.Digest,
			ModifiedAt: model.ModifiedAt,
			Details: ModelDetails{
				Format:            model.Details.Format,
				Family:            model.Details.Family,
				Families:          model.Details.Families,
				ParameterSize:     model.Details.ParameterSize,
				QuantizationLevel: model.Details.QuantizationLevel,
			},
			Status:       "available",
			Capabilities: m.detectCapabilities(model.Name),
			Metadata:     make(map[string]string),
		}
		models = append(models, modelInfo)
	}

	span.SetAttributes(attribute.Int("models_count", len(models)))
	return models, nil
}

// detectCapabilities detects model capabilities based on name and family
func (m *Manager) detectCapabilities(modelName string) []string {
	capabilities := []string{"text_generation"}

	name := strings.ToLower(modelName)

	// Code-specific models
	if strings.Contains(name, "code") || strings.Contains(name, "starcoder") {
		capabilities = append(capabilities, "code_generation", "code_analysis")
	}

	// Embedding models
	if strings.Contains(name, "embed") || strings.Contains(name, "sentence") {
		capabilities = append(capabilities, "embeddings")
	}

	// Chat models
	if strings.Contains(name, "chat") || strings.Contains(name, "instruct") {
		capabilities = append(capabilities, "chat", "instruction_following")
	}

	// Vision models
	if strings.Contains(name, "vision") || strings.Contains(name, "llava") {
		capabilities = append(capabilities, "vision", "multimodal")
	}

	// Math/reasoning models
	if strings.Contains(name, "math") || strings.Contains(name, "wizard") {
		capabilities = append(capabilities, "mathematical_reasoning")
	}

	return capabilities
}

// healthCheckRoutine performs periodic health checks
func (m *Manager) healthCheckRoutine() {
	ticker := time.NewTicker(m.config.HealthCheckPeriod)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := m.healthCheck(ctx); err != nil {
			m.logger.Warn("Health check failed", "error", err)
		}
		cancel()
	}
}

// healthCheck performs a health check on the OLLAMA service
func (m *Manager) healthCheck(ctx context.Context) error {
	ctx, span := managerTracer.Start(ctx, "manager.health_check")
	defer span.End()

	url := m.baseURL + "/api/tags"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		span.RecordError(err)
		return err
	}
	defer resp.Body.Close()

	m.statsMux.Lock()
	m.stats.LastHealthCheck = time.Now()
	m.statsMux.Unlock()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("health check failed with status: %d", resp.StatusCode)
		span.RecordError(err)
		return err
	}

	return nil
}

// GetModels returns list of available models
func (m *Manager) GetModels() map[string]*ModelInfo {
	m.modelsMux.RLock()
	defer m.modelsMux.RUnlock()

	models := make(map[string]*ModelInfo)
	for name, info := range m.models {
		models[name] = info
	}
	return models
}

// GetModel returns information about a specific model
func (m *Manager) GetModel(name string) (*ModelInfo, error) {
	m.modelsMux.RLock()
	defer m.modelsMux.RUnlock()

	model, exists := m.models[name]
	if !exists {
		return nil, fmt.Errorf("model not found: %s", name)
	}

	return model, nil
}

// GetStats returns current statistics
func (m *Manager) GetStats() *Stats {
	m.statsMux.RLock()
	defer m.statsMux.RUnlock()

	// Create a copy to avoid race conditions
	stats := *m.stats
	stats.ModelUsage = make(map[string]int64)
	for k, v := range m.stats.ModelUsage {
		stats.ModelUsage[k] = v
	}

	return &stats
}

// PullModel pulls a model from the OLLAMA registry
func (m *Manager) PullModel(ctx context.Context, modelName string) error {
	ctx, span := managerTracer.Start(ctx, "manager.pull_model",
		trace.WithAttributes(attribute.String("model", modelName)))
	defer span.End()

	url := m.baseURL + "/api/pull"
	reqBody := map[string]string{"name": modelName}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		span.RecordError(err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("OLLAMA pull error: %s", string(body))
		span.RecordError(err)
		return err
	}

	// Refresh models after successful pull
	if err := m.initializeModels(); err != nil {
		m.logger.Warn("Failed to refresh models after pull", "error", err)
	}

	m.logger.Info("Model pulled successfully", "model", modelName)
	return nil
}

// DeleteModel deletes a model from OLLAMA
func (m *Manager) DeleteModel(ctx context.Context, modelName string) error {
	ctx, span := managerTracer.Start(ctx, "manager.delete_model",
		trace.WithAttributes(attribute.String("model", modelName)))
	defer span.End()

	url := m.baseURL + "/api/delete"
	reqBody := map[string]string{"name": modelName}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		span.RecordError(err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("OLLAMA delete error: %s", string(body))
		span.RecordError(err)
		return err
	}

	// Remove from local cache
	m.modelsMux.Lock()
	delete(m.models, modelName)
	m.modelsMux.Unlock()

	m.logger.Info("Model deleted successfully", "model", modelName)
	return nil
}

// CopyModel creates a copy of an existing model
func (m *Manager) CopyModel(ctx context.Context, source, destination string) error {
	ctx, span := managerTracer.Start(ctx, "manager.copy_model",
		trace.WithAttributes(
			attribute.String("source", source),
			attribute.String("destination", destination)))
	defer span.End()

	url := m.baseURL + "/api/copy"
	reqBody := map[string]string{
		"source":      source,
		"destination": destination,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		span.RecordError(err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("OLLAMA copy error: %s", string(body))
		span.RecordError(err)
		return err
	}

	// Refresh models after successful copy
	if err := m.initializeModels(); err != nil {
		m.logger.Warn("Failed to refresh models after copy", "error", err)
	}

	m.logger.Info("Model copied successfully", "source", source, "destination", destination)
	return nil
}

// IsHealthy checks if the OLLAMA service is healthy
func (m *Manager) IsHealthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return m.healthCheck(ctx) == nil
}

// UpdateModelUsage updates usage statistics for a model
func (m *Manager) UpdateModelUsage(modelName string, tokens int64) {
	m.statsMux.Lock()
	defer m.statsMux.Unlock()

	m.stats.TotalRequests++
	m.stats.SuccessfulReqs++
	m.stats.TotalTokens += tokens
	m.stats.ModelUsage[modelName]++

	// Update model last used time
	m.modelsMux.Lock()
	if model, exists := m.models[modelName]; exists {
		model.LastUsed = time.Now()
		model.UsageCount++
	}
	m.modelsMux.Unlock()
}

// UpdateFailedRequest updates failed request statistics
func (m *Manager) UpdateFailedRequest() {
	m.statsMux.Lock()
	defer m.statsMux.Unlock()

	m.stats.TotalRequests++
	m.stats.FailedRequests++
}

// Shutdown gracefully shuts down the manager
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down OLLAMA manager")
	return nil
}
