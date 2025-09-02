package repository

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// ModelRepository implements the domain.ModelRepository interface
type ModelRepository struct {
	db     *gorm.DB
	logger *logger.Logger
}

// NewModelRepository creates a new model repository
func NewModelRepository(db *gorm.DB, logger *logger.Logger) domain.ModelRepository {
	return &ModelRepository{
		db:     db,
		logger: logger,
	}
}

// Create creates a new model
func (r *ModelRepository) Create(model *domain.Model) error {
	if err := r.db.Create(model).Error; err != nil {
		r.logger.Error("Failed to create model", "error", err)
		return err
	}
	r.logger.Debug("Model created", "id", model.ID, "name", model.Name)
	return nil
}

// GetByID retrieves a model by ID
func (r *ModelRepository) GetByID(id uuid.UUID) (*domain.Model, error) {
	var model domain.Model
	if err := r.db.Preload("Deployments").First(&model, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("model not found: %s", id)
		}
		r.logger.Error("Failed to get model by ID", "id", id, "error", err)
		return nil, err
	}
	return &model, nil
}

// GetByName retrieves a model by name
func (r *ModelRepository) GetByName(name string) (*domain.Model, error) {
	var model domain.Model
	if err := r.db.Preload("Deployments").First(&model, "name = ?", name).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("model not found: %s", name)
		}
		r.logger.Error("Failed to get model by name", "name", name, "error", err)
		return nil, err
	}
	return &model, nil
}

// Update updates a model
func (r *ModelRepository) Update(model *domain.Model) error {
	if err := r.db.Save(model).Error; err != nil {
		r.logger.Error("Failed to update model", "id", model.ID, "error", err)
		return err
	}
	r.logger.Debug("Model updated", "id", model.ID, "name", model.Name)
	return nil
}

// Delete deletes a model
func (r *ModelRepository) Delete(id uuid.UUID) error {
	if err := r.db.Delete(&domain.Model{}, "id = ?", id).Error; err != nil {
		r.logger.Error("Failed to delete model", "id", id, "error", err)
		return err
	}
	r.logger.Debug("Model deleted", "id", id)
	return nil
}

// List retrieves models with filters
func (r *ModelRepository) List(filters map[string]interface{}, limit, offset int) ([]*domain.Model, error) {
	var models []*domain.Model
	query := r.db.Preload("Deployments")

	// Apply filters
	for key, value := range filters {
		query = query.Where(fmt.Sprintf("%s = ?", key), value)
	}

	if err := query.Limit(limit).Offset(offset).Find(&models).Error; err != nil {
		r.logger.Error("Failed to list models", "error", err)
		return nil, err
	}

	return models, nil
}

// ListByProvider retrieves models by provider
func (r *ModelRepository) ListByProvider(provider string) ([]*domain.Model, error) {
	var models []*domain.Model
	if err := r.db.Preload("Deployments").Where("provider = ?", provider).Find(&models).Error; err != nil {
		r.logger.Error("Failed to list models by provider", "provider", provider, "error", err)
		return nil, err
	}
	return models, nil
}

// ListByType retrieves models by type
func (r *ModelRepository) ListByType(modelType string) ([]*domain.Model, error) {
	var models []*domain.Model
	if err := r.db.Preload("Deployments").Where("type = ?", modelType).Find(&models).Error; err != nil {
		r.logger.Error("Failed to list models by type", "type", modelType, "error", err)
		return nil, err
	}
	return models, nil
}

// ListByStatus retrieves models by status
func (r *ModelRepository) ListByStatus(status string) ([]*domain.Model, error) {
	var models []*domain.Model
	if err := r.db.Preload("Deployments").Where("status = ?", status).Find(&models).Error; err != nil {
		r.logger.Error("Failed to list models by status", "status", status, "error", err)
		return nil, err
	}
	return models, nil
}

// Search searches models by query
func (r *ModelRepository) Search(query string, filters map[string]interface{}) ([]*domain.Model, error) {
	var models []*domain.Model
	dbQuery := r.db.Preload("Deployments")

	// Apply text search
	if query != "" {
		dbQuery = dbQuery.Where("name ILIKE ? OR description ILIKE ?", "%"+query+"%", "%"+query+"%")
	}

	// Apply filters
	for key, value := range filters {
		dbQuery = dbQuery.Where(fmt.Sprintf("%s = ?", key), value)
	}

	if err := dbQuery.Find(&models).Error; err != nil {
		r.logger.Error("Failed to search models", "query", query, "error", err)
		return nil, err
	}

	return models, nil
}

// UpdateUsage updates model usage statistics
func (r *ModelRepository) UpdateUsage(id uuid.UUID, tokens int64) error {
	now := time.Now()
	if err := r.db.Model(&domain.Model{}).Where("id = ?", id).Updates(map[string]interface{}{
		"usage_count":  gorm.Expr("usage_count + 1"),
		"total_tokens": gorm.Expr("total_tokens + ?", tokens),
		"last_used":    now,
		"updated_at":   now,
	}).Error; err != nil {
		r.logger.Error("Failed to update model usage", "id", id, "error", err)
		return err
	}
	return nil
}

// GetUsageStats retrieves usage statistics for a model
func (r *ModelRepository) GetUsageStats(id uuid.UUID) (*domain.ModelUsageStats, error) {
	var model domain.Model
	if err := r.db.First(&model, "id = ?", id).Error; err != nil {
		return nil, err
	}

	stats := &domain.ModelUsageStats{
		ModelID:       id,
		TotalRequests: model.UsageCount,
		TotalTokens:   model.TotalTokens,
		LastUsed:      model.LastUsed,
		// TODO: Implement more detailed statistics from separate usage tracking table
		AverageLatency: 0.0,
		ErrorRate:      0.0,
		UsageByDay:     []domain.DailyUsage{},
	}

	return stats, nil
}

// CreateDeployment creates a new model deployment
func (r *ModelRepository) CreateDeployment(deployment *domain.ModelDeployment) error {
	if err := r.db.Create(deployment).Error; err != nil {
		r.logger.Error("Failed to create deployment", "error", err)
		return err
	}
	r.logger.Debug("Deployment created", "id", deployment.ID, "name", deployment.Name)
	return nil
}

// GetDeployment retrieves a deployment by ID
func (r *ModelRepository) GetDeployment(id uuid.UUID) (*domain.ModelDeployment, error) {
	var deployment domain.ModelDeployment
	if err := r.db.Preload("Model").First(&deployment, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("deployment not found: %s", id)
		}
		return nil, err
	}
	return &deployment, nil
}

// UpdateDeployment updates a deployment
func (r *ModelRepository) UpdateDeployment(deployment *domain.ModelDeployment) error {
	if err := r.db.Save(deployment).Error; err != nil {
		r.logger.Error("Failed to update deployment", "id", deployment.ID, "error", err)
		return err
	}
	return nil
}

// DeleteDeployment deletes a deployment
func (r *ModelRepository) DeleteDeployment(id uuid.UUID) error {
	if err := r.db.Delete(&domain.ModelDeployment{}, "id = ?", id).Error; err != nil {
		r.logger.Error("Failed to delete deployment", "id", id, "error", err)
		return err
	}
	return nil
}

// ListDeployments retrieves deployments for a model
func (r *ModelRepository) ListDeployments(modelID uuid.UUID) ([]*domain.ModelDeployment, error) {
	var deployments []*domain.ModelDeployment
	if err := r.db.Preload("Model").Where("model_id = ?", modelID).Find(&deployments).Error; err != nil {
		return nil, err
	}
	return deployments, nil
}

// ListAllDeployments retrieves all deployments
func (r *ModelRepository) ListAllDeployments() ([]*domain.ModelDeployment, error) {
	var deployments []*domain.ModelDeployment
	if err := r.db.Preload("Model").Find(&deployments).Error; err != nil {
		return nil, err
	}
	return deployments, nil
}

// StringSlice is a custom type for handling string slices in GORM
type StringSlice []string

// Scan implements the Scanner interface for database deserialization
func (s *StringSlice) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	default:
		return fmt.Errorf("cannot scan %T into StringSlice", value)
	}
}

// Value implements the Valuer interface for database serialization
func (s StringSlice) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}
