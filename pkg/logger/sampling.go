package logger

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"time"
)

// SamplingLogger wraps a logger with sampling capabilities
type SamplingLogger struct {
	logger   *Logger
	samplers map[string]*Sampler
	mutex    sync.RWMutex
}

// Sampler implements various sampling strategies
type Sampler struct {
	strategy SamplingStrategy
	config   SamplingConfig
	state    *SamplingState
	mutex    sync.RWMutex
}

// SamplingStrategy defines different sampling strategies
type SamplingStrategy string

const (
	// FixedRateSampling samples at a fixed rate
	FixedRateSampling SamplingStrategy = "fixed_rate"
	// AdaptiveSampling adjusts sampling rate based on volume
	AdaptiveSampling SamplingStrategy = "adaptive"
	// BurstSampling allows bursts then samples
	BurstSampling SamplingStrategy = "burst"
	// LevelBasedSampling samples based on log level
	LevelBasedSampling SamplingStrategy = "level_based"
)

// SamplingConfig configures sampling behavior
type SamplingConfig struct {
	Strategy        SamplingStrategy      `json:"strategy"`
	Rate            float64               `json:"rate"`             // 0.0-1.0 for fixed rate
	MaxRate         float64               `json:"max_rate"`         // maximum rate for adaptive
	MinRate         float64               `json:"min_rate"`         // minimum rate for adaptive
	BurstSize       int                   `json:"burst_size"`       // burst size for burst sampling
	WindowSize      time.Duration         `json:"window_size"`      // time window for rate calculation
	LevelRates      map[string]float64    `json:"level_rates"`      // rates per log level
	KeyExtractor    func(Fields) string   `json:"-"`                // function to extract sampling key
	AdaptiveTarget  int                   `json:"adaptive_target"`  // target logs per window for adaptive
}

// SamplingState maintains sampling state
type SamplingState struct {
	lastReset     time.Time
	counter       int64
	burstCounter  int
	currentRate   float64
	recentCounts  []int
	windowIndex   int
}

// RateLimitedLogger wraps a logger with rate limiting
type RateLimitedLogger struct {
	logger      *Logger
	limiters    map[string]*RateLimiter
	mutex       sync.RWMutex
	defaultRate int // logs per second
}

// RateLimiter implements token bucket rate limiting for logs
type RateLimiter struct {
	rate       float64   // tokens per second
	capacity   int       // bucket capacity
	tokens     float64   // current tokens
	lastUpdate time.Time
	mutex      sync.Mutex
}

// NewSamplingLogger creates a new sampling logger
func NewSamplingLogger(logger *Logger) *SamplingLogger {
	return &SamplingLogger{
		logger:   logger,
		samplers: make(map[string]*Sampler),
	}
}

// AddSampler adds a sampler for a specific key pattern
func (sl *SamplingLogger) AddSampler(key string, config SamplingConfig) {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()
	
	sampler := &Sampler{
		strategy: config.Strategy,
		config:   config,
		state: &SamplingState{
			lastReset:   time.Now(),
			currentRate: config.Rate,
		},
	}
	
	// Initialize level rates if not provided
	if config.LevelRates == nil {
		config.LevelRates = map[string]float64{
			"debug": 0.1,  // Sample 10% of debug logs
			"info":  0.5,  // Sample 50% of info logs
			"warn":  0.8,  // Sample 80% of warn logs
			"error": 1.0,  // Sample 100% of error logs
		}
	}
	
	sl.samplers[key] = sampler
}

// ShouldSample determines if a log entry should be sampled
func (sl *SamplingLogger) ShouldSample(level string, fields Fields) bool {
	sl.mutex.RLock()
	defer sl.mutex.RUnlock()
	
	// Find appropriate sampler
	var sampler *Sampler
	for key, s := range sl.samplers {
		if key == "*" || (s.config.KeyExtractor != nil && s.config.KeyExtractor(fields) == key) {
			sampler = s
			break
		}
	}
	
	// If no sampler found, don't sample
	if sampler == nil {
		return true
	}
	
	return sampler.ShouldSample(level, fields)
}

// ShouldSample determines if an entry should be sampled based on the strategy
func (s *Sampler) ShouldSample(level string, fields Fields) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	now := time.Now()
	
	switch s.strategy {
	case FixedRateSampling:
		return s.fixedRateSample()
	case AdaptiveSampling:
		return s.adaptiveSample(now)
	case BurstSampling:
		return s.burstSample(now)
	case LevelBasedSampling:
		return s.levelBasedSample(level)
	default:
		return true
	}
}

// fixedRateSample implements fixed rate sampling
func (s *Sampler) fixedRateSample() bool {
	s.state.counter++
	
	// Use hash-based sampling for deterministic behavior
	hash := fnv.New64a()
	hash.Write([]byte(fmt.Sprintf("%d", s.state.counter)))
	hashValue := hash.Sum64()
	
	threshold := uint64(float64(^uint64(0)) * s.config.Rate)
	return hashValue < threshold
}

// adaptiveSample implements adaptive sampling based on volume
func (s *Sampler) adaptiveSample(now time.Time) bool {
	// Reset window if needed
	if now.Sub(s.state.lastReset) >= s.config.WindowSize {
		s.resetWindow(now)
	}
	
	s.state.counter++
	
	// Calculate current rate based on recent volume
	if s.state.counter > int64(s.config.AdaptiveTarget) {
		// High volume, reduce sampling rate
		s.state.currentRate = max(s.config.MinRate, s.state.currentRate*0.9)
	} else {
		// Low volume, increase sampling rate
		s.state.currentRate = min(s.config.MaxRate, s.state.currentRate*1.1)
	}
	
	return s.fixedRateSample()
}

// burstSample implements burst sampling
func (s *Sampler) burstSample(now time.Time) bool {
	// Reset window if needed
	if now.Sub(s.state.lastReset) >= s.config.WindowSize {
		s.resetWindow(now)
	}
	
	// Allow burst
	if s.state.burstCounter < s.config.BurstSize {
		s.state.burstCounter++
		return true
	}
	
	// After burst, apply sampling
	return s.fixedRateSample()
}

// levelBasedSample implements level-based sampling
func (s *Sampler) levelBasedSample(level string) bool {
	rate, exists := s.config.LevelRates[level]
	if !exists {
		rate = 1.0 // Default to no sampling
	}
	
	s.state.counter++
	hash := fnv.New64a()
	hash.Write([]byte(fmt.Sprintf("%s-%d", level, s.state.counter)))
	hashValue := hash.Sum64()
	
	threshold := uint64(float64(^uint64(0)) * rate)
	return hashValue < threshold
}

// resetWindow resets the sampling window
func (s *Sampler) resetWindow(now time.Time) {
	s.state.lastReset = now
	s.state.counter = 0
	s.state.burstCounter = 0
}

// Sampled logging methods
func (sl *SamplingLogger) Debug(msg string, args ...interface{}) {
	if sl.ShouldSample("debug", nil) {
		sl.logger.Debug(msg, args...)
	}
}

func (sl *SamplingLogger) Info(msg string, args ...interface{}) {
	if sl.ShouldSample("info", nil) {
		sl.logger.Info(msg, args...)
	}
}

func (sl *SamplingLogger) Warn(msg string, args ...interface{}) {
	if sl.ShouldSample("warn", nil) {
		sl.logger.Warn(msg, args...)
	}
}

func (sl *SamplingLogger) Error(msg string, args ...interface{}) {
	if sl.ShouldSample("error", nil) {
		sl.logger.Error(msg, args...)
	}
}

func (sl *SamplingLogger) WithFields(fields Fields) *SamplingLogger {
	return &SamplingLogger{
		logger:   sl.logger.WithFields(fields),
		samplers: sl.samplers,
	}
}

func (sl *SamplingLogger) WithContext(ctx context.Context) *SamplingLogger {
	return &SamplingLogger{
		logger:   sl.logger.WithContext(ctx),
		samplers: sl.samplers,
	}
}

// NewRateLimitedLogger creates a new rate-limited logger
func NewRateLimitedLogger(logger *Logger, defaultRate int) *RateLimitedLogger {
	return &RateLimitedLogger{
		logger:      logger,
		limiters:    make(map[string]*RateLimiter),
		defaultRate: defaultRate,
	}
}

// AddRateLimit adds a rate limit for a specific key
func (rl *RateLimitedLogger) AddRateLimit(key string, rate float64, capacity int) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	rl.limiters[key] = &RateLimiter{
		rate:       rate,
		capacity:   capacity,
		tokens:     float64(capacity),
		lastUpdate: time.Now(),
	}
}

// Allow checks if logging is allowed for the given key
func (rl *RateLimitedLogger) Allow(key string) bool {
	rl.mutex.RLock()
	limiter, exists := rl.limiters[key]
	rl.mutex.RUnlock()
	
	if !exists {
		// Create default limiter
		rl.mutex.Lock()
		limiter = &RateLimiter{
			rate:       float64(rl.defaultRate),
			capacity:   rl.defaultRate * 2, // 2 second burst
			tokens:     float64(rl.defaultRate * 2),
			lastUpdate: time.Now(),
		}
		rl.limiters[key] = limiter
		rl.mutex.Unlock()
	}
	
	return limiter.Allow()
}

// Allow implements token bucket algorithm
func (rl *RateLimiter) Allow() bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	
	// Add tokens based on elapsed time
	rl.tokens = min(float64(rl.capacity), rl.tokens+rl.rate*elapsed)
	rl.lastUpdate = now
	
	// Check if we have tokens available
	if rl.tokens >= 1.0 {
		rl.tokens--
		return true
	}
	
	return false
}

// Rate-limited logging methods
func (rl *RateLimitedLogger) Debug(key, msg string, args ...interface{}) {
	if rl.Allow(key) {
		rl.logger.Debug(msg, args...)
	}
}

func (rl *RateLimitedLogger) Info(key, msg string, args ...interface{}) {
	if rl.Allow(key) {
		rl.logger.Info(msg, args...)
	}
}

func (rl *RateLimitedLogger) Warn(key, msg string, args ...interface{}) {
	if rl.Allow(key) {
		rl.logger.Warn(msg, args...)
	}
}

func (rl *RateLimitedLogger) Error(key, msg string, args ...interface{}) {
	if rl.Allow(key) {
		rl.logger.Error(msg, args...)
	}
}

// LogMetrics tracks logging metrics
type LogMetrics struct {
	TotalLogs     int64            `json:"total_logs"`
	SampledLogs   int64            `json:"sampled_logs"`
	DroppedLogs   int64            `json:"dropped_logs"`
	LevelCounts   map[string]int64 `json:"level_counts"`
	LastReset     time.Time        `json:"last_reset"`
	mutex         sync.RWMutex
}

// NewLogMetrics creates new log metrics
func NewLogMetrics() *LogMetrics {
	return &LogMetrics{
		LevelCounts: make(map[string]int64),
		LastReset:   time.Now(),
	}
}

// IncrementTotal increments total log count
func (lm *LogMetrics) IncrementTotal() {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()
	lm.TotalLogs++
}

// IncrementSampled increments sampled log count
func (lm *LogMetrics) IncrementSampled() {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()
	lm.SampledLogs++
}

// IncrementDropped increments dropped log count
func (lm *LogMetrics) IncrementDropped() {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()
	lm.DroppedLogs++
}

// IncrementLevel increments count for a specific level
func (lm *LogMetrics) IncrementLevel(level string) {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()
	lm.LevelCounts[level]++
}

// GetMetrics returns current metrics
func (lm *LogMetrics) GetMetrics() LogMetrics {
	lm.mutex.RLock()
	defer lm.mutex.RUnlock()
	
	// Create a copy
	levelCounts := make(map[string]int64)
	for k, v := range lm.LevelCounts {
		levelCounts[k] = v
	}
	
	return LogMetrics{
		TotalLogs:   lm.TotalLogs,
		SampledLogs: lm.SampledLogs,
		DroppedLogs: lm.DroppedLogs,
		LevelCounts: levelCounts,
		LastReset:   lm.LastReset,
	}
}

// Reset resets all metrics
func (lm *LogMetrics) Reset() {
	lm.mutex.Lock()
	defer lm.mutex.Unlock()
	
	lm.TotalLogs = 0
	lm.SampledLogs = 0
	lm.DroppedLogs = 0
	lm.LevelCounts = make(map[string]int64)
	lm.LastReset = time.Now()
}

// Helper functions
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
