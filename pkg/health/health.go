package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// Status represents the health status
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
	StatusUnknown   Status = "unknown"
)

// CheckResult represents the result of a health check
type CheckResult struct {
	Name        string                 `json:"name"`
	Status      Status                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Critical    bool                   `json:"critical"`
}

// HealthResponse represents the overall health response
type HealthResponse struct {
	Status      Status                 `json:"status"`
	Timestamp   time.Time              `json:"timestamp"`
	Duration    time.Duration          `json:"duration"`
	Checks      map[string]CheckResult `json:"checks"`
	Version     string                 `json:"version,omitempty"`
	ServiceName string                 `json:"service_name,omitempty"`
	Environment string                 `json:"environment,omitempty"`
	Uptime      time.Duration          `json:"uptime"`
}

// Checker defines the interface for health checks
type Checker interface {
	Check(ctx context.Context) CheckResult
	Name() string
	IsCritical() bool
}

// CheckerFunc is a function adapter for Checker interface
type CheckerFunc struct {
	name     string
	critical bool
	checkFn  func(ctx context.Context) CheckResult
}

// NewCheckerFunc creates a new CheckerFunc
func NewCheckerFunc(name string, critical bool, checkFn func(ctx context.Context) CheckResult) *CheckerFunc {
	return &CheckerFunc{
		name:     name,
		critical: critical,
		checkFn:  checkFn,
	}
}

// Check implements the Checker interface
func (c *CheckerFunc) Check(ctx context.Context) CheckResult {
	return c.checkFn(ctx)
}

// Name implements the Checker interface
func (c *CheckerFunc) Name() string {
	return c.name
}

// IsCritical implements the Checker interface
func (c *CheckerFunc) IsCritical() bool {
	return c.critical
}

// Manager manages health checks
type Manager struct {
	checkers    map[string]Checker
	mu          sync.RWMutex
	logger      *logger.Logger
	startTime   time.Time
	version     string
	serviceName string
	environment string
	timeout     time.Duration
}

// Config holds health check manager configuration
type Config struct {
	Version     string        `json:"version"`
	ServiceName string        `json:"service_name"`
	Environment string        `json:"environment"`
	Timeout     time.Duration `json:"timeout"`
}

// NewManager creates a new health check manager
func NewManager(config Config, logger *logger.Logger) *Manager {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Manager{
		checkers:    make(map[string]Checker),
		logger:      logger,
		startTime:   time.Now(),
		version:     config.Version,
		serviceName: config.ServiceName,
		environment: config.Environment,
		timeout:     timeout,
	}
}

// RegisterChecker registers a health checker
func (m *Manager) RegisterChecker(checker Checker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkers[checker.Name()] = checker
	m.logger.Infof("Registered health checker: %s (critical: %v)", checker.Name(), checker.IsCritical())
}

// UnregisterChecker removes a health checker
func (m *Manager) UnregisterChecker(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.checkers, name)
	m.logger.Infof("Unregistered health checker: %s", name)
}

// Check performs all health checks
func (m *Manager) Check(ctx context.Context) HealthResponse {
	start := time.Now()
	
	// Create context with timeout
	checkCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	m.mu.RLock()
	checkers := make(map[string]Checker, len(m.checkers))
	for name, checker := range m.checkers {
		checkers[name] = checker
	}
	m.mu.RUnlock()

	// Run all checks concurrently
	results := make(chan CheckResult, len(checkers))
	var wg sync.WaitGroup

	for _, checker := range checkers {
		wg.Add(1)
		go func(c Checker) {
			defer wg.Done()
			
			checkStart := time.Now()
			result := c.Check(checkCtx)
			result.Duration = time.Since(checkStart)
			result.Timestamp = time.Now()
			result.Critical = c.IsCritical()
			
			results <- result
		}(checker)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	checks := make(map[string]CheckResult)
	overallStatus := StatusHealthy
	
	for result := range results {
		checks[result.Name] = result
		
		// Determine overall status
		switch result.Status {
		case StatusUnhealthy:
			if result.Critical {
				overallStatus = StatusUnhealthy
			} else if overallStatus == StatusHealthy {
				overallStatus = StatusDegraded
			}
		case StatusDegraded:
			if overallStatus == StatusHealthy {
				overallStatus = StatusDegraded
			}
		case StatusUnknown:
			if overallStatus == StatusHealthy {
				overallStatus = StatusDegraded
			}
		}
	}

	duration := time.Since(start)
	uptime := time.Since(m.startTime)

	response := HealthResponse{
		Status:      overallStatus,
		Timestamp:   time.Now(),
		Duration:    duration,
		Checks:      checks,
		Version:     m.version,
		ServiceName: m.serviceName,
		Environment: m.environment,
		Uptime:      uptime,
	}

	// Log health check results
	m.logger.WithFields(logger.Fields{
		"status":       overallStatus,
		"duration_ms":  duration.Milliseconds(),
		"checks_count": len(checks),
		"uptime":       uptime.String(),
	}).Info("Health check completed")

	return response
}

// HTTPHandler returns an HTTP handler for health checks
func (m *Manager) HTTPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		
		// Add correlation ID for tracing
		correlationID := r.Header.Get("X-Correlation-ID")
		if correlationID == "" {
			correlationID = fmt.Sprintf("health-%d", time.Now().UnixNano())
		}
		ctx = logger.WithCorrelationID(ctx, correlationID)

		response := m.Check(ctx)

		// Set appropriate HTTP status code
		statusCode := http.StatusOK
		switch response.Status {
		case StatusUnhealthy:
			statusCode = http.StatusServiceUnavailable
		case StatusDegraded:
			statusCode = http.StatusOK // Still return 200 for degraded
		case StatusUnknown:
			statusCode = http.StatusOK
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Correlation-ID", correlationID)
		w.WriteHeader(statusCode)

		if err := json.NewEncoder(w).Encode(response); err != nil {
			m.logger.WithContext(ctx).WithFields(logger.Fields{
				"error": err.Error(),
			}).Error("Failed to encode health check response")
		}
	}
}

// ReadinessHandler returns a simple readiness check handler
func (m *Manager) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		response := m.Check(ctx)

		// For readiness, only return 200 if all critical checks are healthy
		statusCode := http.StatusOK
		for _, check := range response.Checks {
			if check.Critical && check.Status == StatusUnhealthy {
				statusCode = http.StatusServiceUnavailable
				break
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)

		readinessResponse := map[string]interface{}{
			"ready":     statusCode == http.StatusOK,
			"timestamp": time.Now(),
		}

		json.NewEncoder(w).Encode(readinessResponse)
	}
}

// LivenessHandler returns a simple liveness check handler
func (m *Manager) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Simple liveness check - if we can respond, we're alive
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		livenessResponse := map[string]interface{}{
			"alive":     true,
			"timestamp": time.Now(),
			"uptime":    time.Since(m.startTime).String(),
		}

		json.NewEncoder(w).Encode(livenessResponse)
	}
}
