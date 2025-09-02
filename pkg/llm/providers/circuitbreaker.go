package providers

import (
	"sync"
	"time"
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(failureThreshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		resetTimeout:     resetTimeout,
		state:            CircuitClosed,
	}
}

// CanExecute checks if the circuit breaker allows execution
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if reset timeout has passed
		if time.Since(cb.lastFailureTime) >= cb.resetTimeout {
			// Transition to half-open state
			cb.mutex.RUnlock()
			cb.mutex.Lock()
			if cb.state == CircuitOpen && time.Since(cb.lastFailureTime) >= cb.resetTimeout {
				cb.state = CircuitHalfOpen
				cb.failures = 0
			}
			cb.mutex.Unlock()
			cb.mutex.RLock()
			return cb.state == CircuitHalfOpen
		}
		return false
	case CircuitHalfOpen:
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful execution
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	switch cb.state {
	case CircuitHalfOpen:
		// Transition back to closed state
		cb.state = CircuitClosed
		cb.failures = 0
	case CircuitClosed:
		// Reset failure count on success
		cb.failures = 0
	}
}

// RecordFailure records a failed execution
func (cb *CircuitBreaker) RecordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitClosed:
		if cb.failures >= cb.failureThreshold {
			cb.state = CircuitOpen
		}
	case CircuitHalfOpen:
		// Transition back to open state
		cb.state = CircuitOpen
	}
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// GetFailures returns the current failure count
func (cb *CircuitBreaker) GetFailures() int {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.failures
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.state = CircuitClosed
	cb.failures = 0
}

// String returns a string representation of the circuit state
func (cs CircuitState) String() string {
	switch cs {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig represents circuit breaker configuration
type CircuitBreakerConfig struct {
	FailureThreshold int           `json:"failure_threshold"`
	ResetTimeout     time.Duration `json:"reset_timeout"`
	Enabled          bool          `json:"enabled"`
}

// DefaultCircuitBreakerConfig returns default circuit breaker configuration
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold: 5,
		ResetTimeout:     30 * time.Second,
		Enabled:          true,
	}
}

// CircuitBreakerManager manages multiple circuit breakers
type CircuitBreakerManager struct {
	breakers map[string]*CircuitBreaker
	config   CircuitBreakerConfig
	mutex    sync.RWMutex
}

// NewCircuitBreakerManager creates a new circuit breaker manager
func NewCircuitBreakerManager(config CircuitBreakerConfig) *CircuitBreakerManager {
	return &CircuitBreakerManager{
		breakers: make(map[string]*CircuitBreaker),
		config:   config,
	}
}

// GetCircuitBreaker gets or creates a circuit breaker for a provider
func (cbm *CircuitBreakerManager) GetCircuitBreaker(providerName string) *CircuitBreaker {
	cbm.mutex.RLock()
	breaker, exists := cbm.breakers[providerName]
	cbm.mutex.RUnlock()

	if exists {
		return breaker
	}

	cbm.mutex.Lock()
	defer cbm.mutex.Unlock()

	// Double-check after acquiring write lock
	if breaker, exists := cbm.breakers[providerName]; exists {
		return breaker
	}

	// Create new circuit breaker
	breaker = NewCircuitBreaker(cbm.config.FailureThreshold, cbm.config.ResetTimeout)
	cbm.breakers[providerName] = breaker

	return breaker
}

// GetAllStates returns the states of all circuit breakers
func (cbm *CircuitBreakerManager) GetAllStates() map[string]CircuitState {
	cbm.mutex.RLock()
	defer cbm.mutex.RUnlock()

	states := make(map[string]CircuitState)
	for name, breaker := range cbm.breakers {
		states[name] = breaker.GetState()
	}

	return states
}

// ResetAll resets all circuit breakers
func (cbm *CircuitBreakerManager) ResetAll() {
	cbm.mutex.RLock()
	defer cbm.mutex.RUnlock()

	for _, breaker := range cbm.breakers {
		breaker.Reset()
	}
}

// ResetProvider resets a specific provider's circuit breaker
func (cbm *CircuitBreakerManager) ResetProvider(providerName string) {
	cbm.mutex.RLock()
	breaker, exists := cbm.breakers[providerName]
	cbm.mutex.RUnlock()

	if exists {
		breaker.Reset()
	}
}

// RemoveProvider removes a provider's circuit breaker
func (cbm *CircuitBreakerManager) RemoveProvider(providerName string) {
	cbm.mutex.Lock()
	defer cbm.mutex.Unlock()

	delete(cbm.breakers, providerName)
}

// GetStats returns circuit breaker statistics
func (cbm *CircuitBreakerManager) GetStats() map[string]CircuitBreakerStats {
	cbm.mutex.RLock()
	defer cbm.mutex.RUnlock()

	stats := make(map[string]CircuitBreakerStats)
	for name, breaker := range cbm.breakers {
		stats[name] = CircuitBreakerStats{
			State:            breaker.GetState(),
			Failures:         breaker.GetFailures(),
			LastFailureTime:  breaker.lastFailureTime,
			FailureThreshold: breaker.failureThreshold,
			ResetTimeout:     breaker.resetTimeout,
		}
	}

	return stats
}

// CircuitBreakerStats represents circuit breaker statistics
type CircuitBreakerStats struct {
	State            CircuitState  `json:"state"`
	Failures         int           `json:"failures"`
	LastFailureTime  time.Time     `json:"last_failure_time"`
	FailureThreshold int           `json:"failure_threshold"`
	ResetTimeout     time.Duration `json:"reset_timeout"`
}

// IsHealthy returns whether the circuit breaker is in a healthy state
func (cbs CircuitBreakerStats) IsHealthy() bool {
	return cbs.State == CircuitClosed || cbs.State == CircuitHalfOpen
}

// TimeUntilReset returns the time until the circuit breaker can reset
func (cbs CircuitBreakerStats) TimeUntilReset() time.Duration {
	if cbs.State != CircuitOpen {
		return 0
	}

	elapsed := time.Since(cbs.LastFailureTime)
	if elapsed >= cbs.ResetTimeout {
		return 0
	}

	return cbs.ResetTimeout - elapsed
}

// AdvancedCircuitBreaker extends the basic circuit breaker with additional features
type AdvancedCircuitBreaker struct {
	*CircuitBreaker

	// Advanced features
	successThreshold int // Number of successes needed in half-open state
	successCount     int // Current success count in half-open state
	maxRequests      int // Maximum requests allowed in half-open state
	requestCount     int // Current request count in half-open state

	// Metrics
	totalRequests  int64
	totalSuccesses int64
	totalFailures  int64

	mutex sync.RWMutex
}

// NewAdvancedCircuitBreaker creates a new advanced circuit breaker
func NewAdvancedCircuitBreaker(failureThreshold, successThreshold, maxRequests int, resetTimeout time.Duration) *AdvancedCircuitBreaker {
	return &AdvancedCircuitBreaker{
		CircuitBreaker:   NewCircuitBreaker(failureThreshold, resetTimeout),
		successThreshold: successThreshold,
		maxRequests:      maxRequests,
	}
}

// CanExecute checks if the advanced circuit breaker allows execution
func (acb *AdvancedCircuitBreaker) CanExecute() bool {
	acb.mutex.Lock()
	defer acb.mutex.Unlock()

	acb.totalRequests++

	switch acb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if reset timeout has passed
		if time.Since(acb.lastFailureTime) >= acb.resetTimeout {
			acb.state = CircuitHalfOpen
			acb.successCount = 0
			acb.requestCount = 0
			return true
		}
		return false
	case CircuitHalfOpen:
		// Allow limited requests in half-open state
		if acb.requestCount < acb.maxRequests {
			acb.requestCount++
			return true
		}
		return false
	default:
		return false
	}
}

// RecordSuccess records a successful execution for advanced circuit breaker
func (acb *AdvancedCircuitBreaker) RecordSuccess() {
	acb.mutex.Lock()
	defer acb.mutex.Unlock()

	acb.totalSuccesses++

	switch acb.state {
	case CircuitHalfOpen:
		acb.successCount++
		if acb.successCount >= acb.successThreshold {
			// Transition back to closed state
			acb.state = CircuitClosed
			acb.failures = 0
			acb.successCount = 0
			acb.requestCount = 0
		}
	case CircuitClosed:
		// Reset failure count on success
		acb.failures = 0
	}
}

// RecordFailure records a failed execution for advanced circuit breaker
func (acb *AdvancedCircuitBreaker) RecordFailure() {
	acb.mutex.Lock()
	defer acb.mutex.Unlock()

	acb.totalFailures++
	acb.failures++
	acb.lastFailureTime = time.Now()

	switch acb.state {
	case CircuitClosed:
		if acb.failures >= acb.failureThreshold {
			acb.state = CircuitOpen
		}
	case CircuitHalfOpen:
		// Transition back to open state
		acb.state = CircuitOpen
		acb.successCount = 0
		acb.requestCount = 0
	}
}

// GetMetrics returns circuit breaker metrics
func (acb *AdvancedCircuitBreaker) GetMetrics() AdvancedCircuitBreakerMetrics {
	acb.mutex.RLock()
	defer acb.mutex.RUnlock()

	return AdvancedCircuitBreakerMetrics{
		State:           acb.state,
		TotalRequests:   acb.totalRequests,
		TotalSuccesses:  acb.totalSuccesses,
		TotalFailures:   acb.totalFailures,
		CurrentFailures: acb.failures,
		SuccessCount:    acb.successCount,
		RequestCount:    acb.requestCount,
		SuccessRate:     float64(acb.totalSuccesses) / float64(acb.totalRequests),
		FailureRate:     float64(acb.totalFailures) / float64(acb.totalRequests),
	}
}

// AdvancedCircuitBreakerMetrics represents advanced circuit breaker metrics
type AdvancedCircuitBreakerMetrics struct {
	State           CircuitState `json:"state"`
	TotalRequests   int64        `json:"total_requests"`
	TotalSuccesses  int64        `json:"total_successes"`
	TotalFailures   int64        `json:"total_failures"`
	CurrentFailures int          `json:"current_failures"`
	SuccessCount    int          `json:"success_count"`
	RequestCount    int          `json:"request_count"`
	SuccessRate     float64      `json:"success_rate"`
	FailureRate     float64      `json:"failure_rate"`
}
