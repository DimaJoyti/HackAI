package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var tracer = otel.Tracer("hackai/infrastructure/health")

// HealthStatus represents the health status of a component
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// ComponentHealth represents the health of a single component
type ComponentHealth struct {
	Name        string                 `json:"name"`
	Status      HealthStatus           `json:"status"`
	Message     string                 `json:"message,omitempty"`
	LastChecked time.Time              `json:"last_checked"`
	Duration    time.Duration          `json:"duration"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SystemHealth represents the overall system health
type SystemHealth struct {
	Status     HealthStatus               `json:"status"`
	Timestamp  time.Time                  `json:"timestamp"`
	Version    string                     `json:"version"`
	Uptime     time.Duration              `json:"uptime"`
	Components map[string]ComponentHealth `json:"components"`
	System     SystemMetrics              `json:"system"`
}

// SystemMetrics represents system-level metrics
type SystemMetrics struct {
	Memory     MemoryMetrics `json:"memory"`
	CPU        CPUMetrics    `json:"cpu"`
	Goroutines int           `json:"goroutines"`
	GC         GCMetrics     `json:"gc"`
}

// MemoryMetrics represents memory usage metrics
type MemoryMetrics struct {
	Alloc        uint64  `json:"alloc"`         // bytes allocated and still in use
	TotalAlloc   uint64  `json:"total_alloc"`   // bytes allocated (even if freed)
	Sys          uint64  `json:"sys"`           // bytes obtained from system
	Mallocs      uint64  `json:"mallocs"`       // number of mallocs
	Frees        uint64  `json:"frees"`         // number of frees
	HeapAlloc    uint64  `json:"heap_alloc"`    // bytes allocated and still in use
	HeapSys      uint64  `json:"heap_sys"`      // bytes obtained from system
	HeapIdle     uint64  `json:"heap_idle"`     // bytes in idle spans
	HeapInuse    uint64  `json:"heap_inuse"`    // bytes in non-idle span
	StackInuse   uint64  `json:"stack_inuse"`   // bytes used by stack allocator
	StackSys     uint64  `json:"stack_sys"`     // bytes obtained from system for stack allocator
	UsagePercent float64 `json:"usage_percent"` // calculated usage percentage
}

// CPUMetrics represents CPU usage metrics
type CPUMetrics struct {
	NumCPU       int     `json:"num_cpu"`
	NumGoroutine int     `json:"num_goroutine"`
	UsagePercent float64 `json:"usage_percent,omitempty"` // if available
}

// GCMetrics represents garbage collection metrics
type GCMetrics struct {
	NumGC      uint32        `json:"num_gc"`
	PauseTotal time.Duration `json:"pause_total"`
	LastPause  time.Duration `json:"last_pause"`
	NextGC     uint64        `json:"next_gc"`
	EnabledGC  bool          `json:"enabled_gc"`
}

// HealthChecker interface for health check implementations
type HealthChecker interface {
	Name() string
	Check(ctx context.Context) ComponentHealth
}

// HealthManager manages health checks for all system components
type HealthManager struct {
	checkers   map[string]HealthChecker
	config     *MonitoringConfig
	logger     *logger.Logger
	startTime  time.Time
	version    string
	mutex      sync.RWMutex
	lastHealth *SystemHealth

	// Background health checking
	stopChan   chan struct{}
	healthChan chan *SystemHealth
}

// NewHealthManager creates a new health manager
func NewHealthManager(config *MonitoringConfig, logger *logger.Logger, version string) *HealthManager {
	return &HealthManager{
		checkers:   make(map[string]HealthChecker),
		config:     config,
		logger:     logger,
		startTime:  time.Now(),
		version:    version,
		stopChan:   make(chan struct{}),
		healthChan: make(chan *SystemHealth, 1),
	}
}

// RegisterChecker registers a health checker
func (hm *HealthManager) RegisterChecker(checker HealthChecker) {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	hm.checkers[checker.Name()] = checker
	hm.logger.Info("Health checker registered", "name", checker.Name())
}

// UnregisterChecker unregisters a health checker
func (hm *HealthManager) UnregisterChecker(name string) {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	delete(hm.checkers, name)
	hm.logger.Info("Health checker unregistered", "name", name)
}

// CheckHealth performs a comprehensive health check
func (hm *HealthManager) CheckHealth(ctx context.Context) *SystemHealth {
	ctx, span := tracer.Start(ctx, "health_manager.check_health")
	defer span.End()

	hm.mutex.RLock()
	checkers := make(map[string]HealthChecker)
	for name, checker := range hm.checkers {
		checkers[name] = checker
	}
	hm.mutex.RUnlock()

	components := make(map[string]ComponentHealth)
	overallStatus := HealthStatusHealthy

	// Run health checks concurrently
	type checkResult struct {
		name   string
		health ComponentHealth
	}

	resultChan := make(chan checkResult, len(checkers))

	for name, checker := range checkers {
		go func(n string, c HealthChecker) {
			health := c.Check(ctx)
			resultChan <- checkResult{name: n, health: health}
		}(name, checker)
	}

	// Collect results
	for i := 0; i < len(checkers); i++ {
		select {
		case result := <-resultChan:
			components[result.name] = result.health

			// Determine overall status
			switch result.health.Status {
			case HealthStatusUnhealthy:
				overallStatus = HealthStatusUnhealthy
			case HealthStatusDegraded:
				if overallStatus == HealthStatusHealthy {
					overallStatus = HealthStatusDegraded
				}
			}

		case <-ctx.Done():
			span.RecordError(ctx.Err())
			overallStatus = HealthStatusUnknown
			break
		}
	}

	// Get system metrics
	systemMetrics := hm.getSystemMetrics()

	health := &SystemHealth{
		Status:     overallStatus,
		Timestamp:  time.Now(),
		Version:    hm.version,
		Uptime:     time.Since(hm.startTime),
		Components: components,
		System:     systemMetrics,
	}

	// Cache the result
	hm.mutex.Lock()
	hm.lastHealth = health
	hm.mutex.Unlock()

	span.SetAttributes(
		attribute.String("overall_status", string(overallStatus)),
		attribute.Int("component_count", len(components)),
		attribute.String("uptime", health.Uptime.String()),
	)

	return health
}

// GetLastHealth returns the last health check result
func (hm *HealthManager) GetLastHealth() *SystemHealth {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()

	if hm.lastHealth == nil {
		return &SystemHealth{
			Status:    HealthStatusUnknown,
			Timestamp: time.Now(),
			Version:   hm.version,
			Uptime:    time.Since(hm.startTime),
		}
	}

	return hm.lastHealth
}

// StartBackgroundChecks starts background health checking
func (hm *HealthManager) StartBackgroundChecks(ctx context.Context) {
	if hm.config.MetricsInterval <= 0 {
		hm.logger.Info("Background health checks disabled")
		return
	}

	hm.logger.Info("Starting background health checks", "interval", hm.config.MetricsInterval)

	ticker := time.NewTicker(hm.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			health := hm.CheckHealth(ctx)

			// Send to health channel (non-blocking)
			select {
			case hm.healthChan <- health:
			default:
				// Channel full, skip this update
			}

		case <-hm.stopChan:
			hm.logger.Info("Background health checks stopped")
			return

		case <-ctx.Done():
			hm.logger.Info("Background health checks cancelled")
			return
		}
	}
}

// Stop stops background health checking
func (hm *HealthManager) Stop() {
	close(hm.stopChan)
}

// HealthChannel returns the health update channel
func (hm *HealthManager) HealthChannel() <-chan *SystemHealth {
	return hm.healthChan
}

// HTTPHandler returns an HTTP handler for health checks
func (hm *HealthManager) HTTPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), "health_check_http")
		defer span.End()

		health := hm.CheckHealth(ctx)

		// Set appropriate HTTP status code
		statusCode := http.StatusOK
		switch health.Status {
		case HealthStatusDegraded:
			statusCode = http.StatusPartialContent
		case HealthStatusUnhealthy:
			statusCode = http.StatusServiceUnavailable
		case HealthStatusUnknown:
			statusCode = http.StatusInternalServerError
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)

		if err := json.NewEncoder(w).Encode(health); err != nil {
			span.RecordError(err)
			hm.logger.Error("Failed to encode health response", "error", err)
		}

		span.SetAttributes(
			attribute.Int("http.status_code", statusCode),
			attribute.String("health.status", string(health.Status)),
		)
	}
}

// getSystemMetrics collects system-level metrics
func (hm *HealthManager) getSystemMetrics() SystemMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Calculate memory usage percentage (rough estimate)
	var memUsagePercent float64
	if m.Sys > 0 {
		memUsagePercent = float64(m.Alloc) / float64(m.Sys) * 100
	}

	return SystemMetrics{
		Memory: MemoryMetrics{
			Alloc:        m.Alloc,
			TotalAlloc:   m.TotalAlloc,
			Sys:          m.Sys,
			Mallocs:      m.Mallocs,
			Frees:        m.Frees,
			HeapAlloc:    m.HeapAlloc,
			HeapSys:      m.HeapSys,
			HeapIdle:     m.HeapIdle,
			HeapInuse:    m.HeapInuse,
			StackInuse:   m.StackInuse,
			StackSys:     m.StackSys,
			UsagePercent: memUsagePercent,
		},
		CPU: CPUMetrics{
			NumCPU:       runtime.NumCPU(),
			NumGoroutine: runtime.NumGoroutine(),
		},
		Goroutines: runtime.NumGoroutine(),
		GC: GCMetrics{
			NumGC:      m.NumGC,
			PauseTotal: time.Duration(m.PauseTotalNs),
			NextGC:     m.NextGC,
			EnabledGC:  m.EnableGC,
		},
	}
}

// DatabaseHealthChecker checks database health
type DatabaseHealthChecker struct {
	db     *database.DB
	logger *logger.Logger
}

// NewDatabaseHealthChecker creates a new database health checker
func NewDatabaseHealthChecker(db *database.DB, logger *logger.Logger) *DatabaseHealthChecker {
	return &DatabaseHealthChecker{
		db:     db,
		logger: logger,
	}
}

// Name returns the checker name
func (c *DatabaseHealthChecker) Name() string {
	return "database"
}

// Check performs the database health check
func (c *DatabaseHealthChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()

	// Test database connection
	sqlDB, err := c.db.DB.DB()
	if err != nil {
		return ComponentHealth{
			Name:        c.Name(),
			Status:      HealthStatusUnhealthy,
			Message:     fmt.Sprintf("Failed to get database connection: %v", err),
			LastChecked: time.Now(),
			Duration:    time.Since(start),
		}
	}

	// Ping database
	if err := sqlDB.PingContext(ctx); err != nil {
		return ComponentHealth{
			Name:        c.Name(),
			Status:      HealthStatusUnhealthy,
			Message:     fmt.Sprintf("Database ping failed: %v", err),
			LastChecked: time.Now(),
			Duration:    time.Since(start),
		}
	}

	// Get connection stats
	stats := sqlDB.Stats()
	metadata := map[string]interface{}{
		"open_connections": stats.OpenConnections,
		"in_use":           stats.InUse,
		"idle":             stats.Idle,
		"max_open":         stats.MaxOpenConnections,
	}

	// Determine status based on connection usage
	status := HealthStatusHealthy
	message := "Database is healthy"

	if stats.OpenConnections > int(float64(stats.MaxOpenConnections)*0.8) {
		status = HealthStatusDegraded
		message = "Database connection pool is near capacity"
	}

	return ComponentHealth{
		Name:        c.Name(),
		Status:      status,
		Message:     message,
		LastChecked: time.Now(),
		Duration:    time.Since(start),
		Metadata:    metadata,
	}
}
