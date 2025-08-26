package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var healthTracer = otel.Tracer("hackai/monitoring/health")

// HealthChecker manages health checks for system components
type HealthChecker struct {
	checks         map[string]*HealthCheck
	overallHealth  *OverallHealth
	config         *MonitoringConfig
	logger         *logger.Logger
	mutex          sync.RWMutex
}

// HealthCheck represents a health check for a component
type HealthCheck struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Type            HealthCheckType        `json:"type"`
	Target          string                 `json:"target"`
	Interval        time.Duration          `json:"interval"`
	Timeout         time.Duration          `json:"timeout"`
	RetryCount      int                    `json:"retry_count"`
	RetryDelay      time.Duration          `json:"retry_delay"`
	Enabled         bool                   `json:"enabled"`
	Critical        bool                   `json:"critical"`
	Dependencies    []string               `json:"dependencies"`
	ExpectedStatus  int                    `json:"expected_status"`
	ExpectedContent string                 `json:"expected_content"`
	Headers         map[string]string      `json:"headers"`
	CustomCheck     HealthCheckFunc        `json:"-"`
	LastResult      *HealthCheckResult     `json:"last_result"`
	History         []*HealthCheckResult   `json:"history"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	CheckID      string                 `json:"check_id"`
	Status       ComponentStatus        `json:"status"`
	ResponseTime time.Duration          `json:"response_time"`
	Message      string                 `json:"message"`
	Details      map[string]interface{} `json:"details"`
	Error        string                 `json:"error,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Attempt      int                    `json:"attempt"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// OverallHealth represents the overall health of the system
type OverallHealth struct {
	Status           OverallHealthStatus       `json:"status"`
	Components       map[string]*HealthStatus  `json:"components"`
	CriticalFailures int                       `json:"critical_failures"`
	TotalChecks      int                       `json:"total_checks"`
	HealthyChecks    int                       `json:"healthy_checks"`
	UnhealthyChecks  int                       `json:"unhealthy_checks"`
	LastUpdate       time.Time                 `json:"last_update"`
	Metadata         map[string]interface{}    `json:"metadata"`
}

// HealthCheckFunc is a custom health check function
type HealthCheckFunc func(ctx context.Context, check *HealthCheck) (*HealthCheckResult, error)

// HealthCheckType defines types of health checks
type HealthCheckType string

const (
	HealthCheckTypeHTTP     HealthCheckType = "http"
	HealthCheckTypeTCP      HealthCheckType = "tcp"
	HealthCheckTypeDatabase HealthCheckType = "database"
	HealthCheckTypeRedis    HealthCheckType = "redis"
	HealthCheckTypeCustom   HealthCheckType = "custom"
	HealthCheckTypeProcess  HealthCheckType = "process"
	HealthCheckTypeFile     HealthCheckType = "file"
	HealthCheckTypeDisk     HealthCheckType = "disk"
	HealthCheckTypeMemory   HealthCheckType = "memory"
)

// NewHealthChecker creates a new health checker
func NewHealthChecker(config *MonitoringConfig, logger *logger.Logger) (*HealthChecker, error) {
	return &HealthChecker{
		checks: make(map[string]*HealthCheck),
		overallHealth: &OverallHealth{
			Status:     HealthStatusUnknown,
			Components: make(map[string]*HealthStatus),
			Metadata:   make(map[string]interface{}),
		},
		config: config,
		logger: logger,
	}, nil
}

// RegisterHealthCheck registers a new health check
func (hc *HealthChecker) RegisterHealthCheck(check *HealthCheck) error {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	if check.ID == "" {
		return fmt.Errorf("health check ID cannot be empty")
	}

	if check.Interval == 0 {
		check.Interval = 30 * time.Second
	}

	if check.Timeout == 0 {
		check.Timeout = 10 * time.Second
	}

	if check.RetryCount == 0 {
		check.RetryCount = 3
	}

	if check.RetryDelay == 0 {
		check.RetryDelay = time.Second
	}

	check.History = make([]*HealthCheckResult, 0)
	check.CreatedAt = time.Now()
	check.UpdatedAt = time.Now()

	hc.checks[check.ID] = check

	hc.logger.Info("Health check registered",
		"check_id", check.ID,
		"name", check.Name,
		"type", check.Type,
		"target", check.Target,
		"critical", check.Critical)

	return nil
}

// PerformHealthChecks performs all registered health checks
func (hc *HealthChecker) PerformHealthChecks(ctx context.Context) error {
	ctx, span := healthTracer.Start(ctx, "health_checker.perform_checks",
		trace.WithAttributes(
			attribute.Int("checks.total", len(hc.checks)),
		),
	)
	defer span.End()

	hc.mutex.RLock()
	checks := make([]*HealthCheck, 0, len(hc.checks))
	for _, check := range hc.checks {
		if check.Enabled {
			checks = append(checks, check)
		}
	}
	hc.mutex.RUnlock()

	// Perform checks concurrently
	var wg sync.WaitGroup
	results := make(chan *HealthCheckResult, len(checks))

	for _, check := range checks {
		wg.Add(1)
		go func(c *HealthCheck) {
			defer wg.Done()
			result := hc.performSingleCheck(ctx, c)
			results <- result
		}(check)
	}

	wg.Wait()
	close(results)

	// Collect results and update overall health
	var healthyCount, unhealthyCount, criticalFailures int
	componentHealth := make(map[string]*HealthStatus)

	for result := range results {
		hc.updateCheckResult(result)

		// Create component health status
		componentHealth[result.CheckID] = &HealthStatus{
			ComponentID:   result.CheckID,
			ComponentName: hc.getCheckName(result.CheckID),
			Status:        result.Status,
			LastCheck:     result.Timestamp,
			ResponseTime:  result.ResponseTime,
			Details:       result.Details,
			Metadata:      result.Metadata,
		}

		// Count health status
		if result.Status == ComponentStatusUp {
			healthyCount++
		} else {
			unhealthyCount++
			if hc.isCheckCritical(result.CheckID) {
				criticalFailures++
			}
		}
	}

	// Update overall health
	hc.mutex.Lock()
	hc.overallHealth.Components = componentHealth
	hc.overallHealth.TotalChecks = len(checks)
	hc.overallHealth.HealthyChecks = healthyCount
	hc.overallHealth.UnhealthyChecks = unhealthyCount
	hc.overallHealth.CriticalFailures = criticalFailures
	hc.overallHealth.LastUpdate = time.Now()

	// Determine overall status
	if criticalFailures > 0 {
		hc.overallHealth.Status = HealthStatusCritical
	} else if unhealthyCount > healthyCount {
		hc.overallHealth.Status = HealthStatusUnhealthy
	} else if unhealthyCount > 0 {
		hc.overallHealth.Status = HealthStatusDegraded
	} else {
		hc.overallHealth.Status = HealthStatusHealthy
	}
	hc.mutex.Unlock()

	span.SetAttributes(
		attribute.Int("checks.healthy", healthyCount),
		attribute.Int("checks.unhealthy", unhealthyCount),
		attribute.Int("checks.critical_failures", criticalFailures),
		attribute.String("overall.status", string(hc.overallHealth.Status)),
	)

	hc.logger.Debug("Health checks completed",
		"total_checks", len(checks),
		"healthy", healthyCount,
		"unhealthy", unhealthyCount,
		"critical_failures", criticalFailures,
		"overall_status", hc.overallHealth.Status)

	return nil
}

// performSingleCheck performs a single health check with retries
func (hc *HealthChecker) performSingleCheck(ctx context.Context, check *HealthCheck) *HealthCheckResult {
	ctx, span := healthTracer.Start(ctx, "health_checker.perform_single_check",
		trace.WithAttributes(
			attribute.String("check.id", check.ID),
			attribute.String("check.type", string(check.Type)),
			attribute.String("check.target", check.Target),
		),
	)
	defer span.End()

	var lastResult *HealthCheckResult

	for attempt := 1; attempt <= check.RetryCount; attempt++ {
		startTime := time.Now()

		// Create timeout context
		checkCtx, cancel := context.WithTimeout(ctx, check.Timeout)

		result := &HealthCheckResult{
			CheckID:   check.ID,
			Timestamp: startTime,
			Attempt:   attempt,
			Details:   make(map[string]interface{}),
			Metadata:  make(map[string]interface{}),
		}

		// Perform the actual check
		var err error
		switch check.Type {
		case HealthCheckTypeHTTP:
			err = hc.performHTTPCheck(checkCtx, check, result)
		case HealthCheckTypeTCP:
			err = hc.performTCPCheck(checkCtx, check, result)
		case HealthCheckTypeDatabase:
			err = hc.performDatabaseCheck(checkCtx, check, result)
		case HealthCheckTypeRedis:
			err = hc.performRedisCheck(checkCtx, check, result)
		case HealthCheckTypeCustom:
			if check.CustomCheck != nil {
				result, err = check.CustomCheck(checkCtx, check)
			} else {
				err = fmt.Errorf("custom check function not provided")
			}
		default:
			err = fmt.Errorf("unsupported health check type: %s", check.Type)
		}

		cancel()

		result.ResponseTime = time.Since(startTime)

		if err != nil {
			result.Status = ComponentStatusDown
			result.Error = err.Error()
			result.Message = fmt.Sprintf("Health check failed: %s", err.Error())
		} else {
			result.Status = ComponentStatusUp
			result.Message = "Health check passed"
		}

		lastResult = result

		// If check passed or this is the last attempt, break
		if result.Status == ComponentStatusUp || attempt == check.RetryCount {
			break
		}

		// Wait before retry
		if attempt < check.RetryCount {
			time.Sleep(check.RetryDelay)
		}
	}

	span.SetAttributes(
		attribute.String("result.status", string(lastResult.Status)),
		attribute.Float64("result.response_time", lastResult.ResponseTime.Seconds()),
		attribute.Int("result.attempts", lastResult.Attempt),
	)

	return lastResult
}

// performHTTPCheck performs an HTTP health check
func (hc *HealthChecker) performHTTPCheck(ctx context.Context, check *HealthCheck, result *HealthCheckResult) error {
	req, err := http.NewRequestWithContext(ctx, "GET", check.Target, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add custom headers
	for key, value := range check.Headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{
		Timeout: check.Timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	result.Details["status_code"] = resp.StatusCode
	result.Details["content_length"] = resp.ContentLength

	// Check expected status code
	expectedStatus := check.ExpectedStatus
	if expectedStatus == 0 {
		expectedStatus = 200
	}

	if resp.StatusCode != expectedStatus {
		return fmt.Errorf("unexpected status code: got %d, expected %d", resp.StatusCode, expectedStatus)
	}

	// TODO: Check expected content if specified
	if check.ExpectedContent != "" {
		// Implementation for content checking
	}

	return nil
}

// performTCPCheck performs a TCP health check
func (hc *HealthChecker) performTCPCheck(ctx context.Context, check *HealthCheck, result *HealthCheckResult) error {
	// TODO: Implement TCP health check
	return fmt.Errorf("TCP health check not implemented")
}

// performDatabaseCheck performs a database health check
func (hc *HealthChecker) performDatabaseCheck(ctx context.Context, check *HealthCheck, result *HealthCheckResult) error {
	// TODO: Implement database health check
	return fmt.Errorf("database health check not implemented")
}

// performRedisCheck performs a Redis health check
func (hc *HealthChecker) performRedisCheck(ctx context.Context, check *HealthCheck, result *HealthCheckResult) error {
	// TODO: Implement Redis health check
	return fmt.Errorf("Redis health check not implemented")
}

// updateCheckResult updates the result for a health check
func (hc *HealthChecker) updateCheckResult(result *HealthCheckResult) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	check, exists := hc.checks[result.CheckID]
	if !exists {
		return
	}

	check.LastResult = result
	check.UpdatedAt = time.Now()

	// Add to history (keep last 100 results)
	check.History = append(check.History, result)
	if len(check.History) > 100 {
		check.History = check.History[1:]
	}
}

// GetOverallHealth returns the overall health status
func (hc *HealthChecker) GetOverallHealth(ctx context.Context) (*OverallHealth, error) {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	// Create a copy to avoid race conditions
	health := &OverallHealth{
		Status:           hc.overallHealth.Status,
		Components:       make(map[string]*HealthStatus),
		CriticalFailures: hc.overallHealth.CriticalFailures,
		TotalChecks:      hc.overallHealth.TotalChecks,
		HealthyChecks:    hc.overallHealth.HealthyChecks,
		UnhealthyChecks:  hc.overallHealth.UnhealthyChecks,
		LastUpdate:       hc.overallHealth.LastUpdate,
		Metadata:         make(map[string]interface{}),
	}

	// Copy component health
	for id, status := range hc.overallHealth.Components {
		health.Components[id] = &HealthStatus{
			ComponentID:   status.ComponentID,
			ComponentName: status.ComponentName,
			Status:        status.Status,
			LastCheck:     status.LastCheck,
			ResponseTime:  status.ResponseTime,
			Details:       status.Details,
			Metadata:      status.Metadata,
		}
	}

	// Copy metadata
	for k, v := range hc.overallHealth.Metadata {
		health.Metadata[k] = v
	}

	return health, nil
}

// GetHealthCheck returns a specific health check
func (hc *HealthChecker) GetHealthCheck(checkID string) (*HealthCheck, error) {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	check, exists := hc.checks[checkID]
	if !exists {
		return nil, fmt.Errorf("health check not found: %s", checkID)
	}

	return check, nil
}

// Helper methods

func (hc *HealthChecker) getCheckName(checkID string) string {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	if check, exists := hc.checks[checkID]; exists {
		return check.Name
	}
	return checkID
}

func (hc *HealthChecker) isCheckCritical(checkID string) bool {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	if check, exists := hc.checks[checkID]; exists {
		return check.Critical
	}
	return false
}

// CreateDefaultHealthChecks creates default health checks for common components
func (hc *HealthChecker) CreateDefaultHealthChecks() error {
	defaultChecks := []*HealthCheck{
		{
			ID:             "system_memory",
			Name:           "System Memory",
			Type:           HealthCheckTypeMemory,
			Target:         "localhost",
			Interval:       30 * time.Second,
			Timeout:        5 * time.Second,
			Enabled:        true,
			Critical:       true,
			ExpectedStatus: 200,
		},
		{
			ID:             "system_disk",
			Name:           "System Disk Space",
			Type:           HealthCheckTypeDisk,
			Target:         "/",
			Interval:       60 * time.Second,
			Timeout:        5 * time.Second,
			Enabled:        true,
			Critical:       true,
		},
		{
			ID:             "http_endpoint",
			Name:           "HTTP Health Endpoint",
			Type:           HealthCheckTypeHTTP,
			Target:         "http://localhost:8080/health",
			Interval:       15 * time.Second,
			Timeout:        10 * time.Second,
			Enabled:        true,
			Critical:       false,
			ExpectedStatus: 200,
		},
	}

	for _, check := range defaultChecks {
		if err := hc.RegisterHealthCheck(check); err != nil {
			return fmt.Errorf("failed to register default health check %s: %w", check.ID, err)
		}
	}

	return nil
}
