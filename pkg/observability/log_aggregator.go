package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// LogAggregatorConfig configuration for log aggregation
type LogAggregatorConfig struct {
	Enabled            bool          `yaml:"enabled" json:"enabled"`
	BufferSize         int           `yaml:"buffer_size" json:"buffer_size"`
	FlushInterval      time.Duration `yaml:"flush_interval" json:"flush_interval"`
	RetentionTime      time.Duration `yaml:"retention_time" json:"retention_time"`
	CompressionEnabled bool          `yaml:"compression_enabled" json:"compression_enabled"`
	OutputFormat       string        `yaml:"output_format" json:"output_format"`
	Destinations       []string      `yaml:"destinations" json:"destinations"`
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Level       string                 `json:"level"`
	Message     string                 `json:"message"`
	Service     string                 `json:"service"`
	TraceID     string                 `json:"trace_id,omitempty"`
	SpanID      string                 `json:"span_id,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	Component   string                 `json:"component,omitempty"`
	Fields      map[string]interface{} `json:"fields,omitempty"`
	Error       *ErrorInfo             `json:"error,omitempty"`
}

// ErrorInfo represents error information in logs
type ErrorInfo struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	StackTrace string `json:"stack_trace,omitempty"`
	Code       string `json:"code,omitempty"`
}

// LogAggregator aggregates and processes logs from multiple sources
type LogAggregator struct {
	config   *LogAggregatorConfig
	logger   *logger.Logger
	buffer   chan *LogEntry
	storage  []*LogEntry
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewLogAggregator creates a new log aggregator
func NewLogAggregator(config *LogAggregatorConfig, log *logger.Logger) *LogAggregator {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &LogAggregator{
		config:  config,
		logger:  log,
		buffer:  make(chan *LogEntry, config.BufferSize),
		storage: make([]*LogEntry, 0),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start starts the log aggregator
func (la *LogAggregator) Start(ctx context.Context) error {
	if !la.config.Enabled {
		la.logger.Info("Log aggregator is disabled")
		return nil
	}
	
	la.logger.Info("Starting log aggregator",
		"buffer_size", la.config.BufferSize,
		"flush_interval", la.config.FlushInterval,
	)
	
	// Start background workers
	la.wg.Add(2)
	go la.processLogs()
	go la.flushLogs()
	
	return nil
}

// Stop stops the log aggregator
func (la *LogAggregator) Stop() error {
	la.logger.Info("Stopping log aggregator")
	
	la.cancel()
	close(la.buffer)
	la.wg.Wait()
	
	// Final flush
	la.flush()
	
	return nil
}

// AddLog adds a log entry to the aggregator
func (la *LogAggregator) AddLog(entry *LogEntry) {
	if !la.config.Enabled {
		return
	}
	
	select {
	case la.buffer <- entry:
	default:
		la.logger.Warn("Log buffer full, dropping log entry")
	}
}

// AddLogFromFields creates and adds a log entry from fields
func (la *LogAggregator) AddLogFromFields(
	level, message, service, component string,
	fields map[string]interface{},
) {
	entry := &LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Service:   service,
		Component: component,
		Fields:    fields,
	}
	
	la.AddLog(entry)
}

// processLogs processes incoming log entries
func (la *LogAggregator) processLogs() {
	defer la.wg.Done()
	
	for {
		select {
		case <-la.ctx.Done():
			return
		case entry, ok := <-la.buffer:
			if !ok {
				return
			}
			
			la.mu.Lock()
			la.storage = append(la.storage, entry)
			la.mu.Unlock()
		}
	}
}

// flushLogs periodically flushes logs
func (la *LogAggregator) flushLogs() {
	defer la.wg.Done()
	
	ticker := time.NewTicker(la.config.FlushInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-la.ctx.Done():
			return
		case <-ticker.C:
			la.flush()
		}
	}
}

// flush flushes stored logs
func (la *LogAggregator) flush() {
	la.mu.Lock()
	defer la.mu.Unlock()
	
	if len(la.storage) == 0 {
		return
	}
	
	// Process logs based on configuration
	switch la.config.OutputFormat {
	case "json":
		la.flushAsJSON()
	case "structured":
		la.flushAsStructured()
	default:
		la.flushAsText()
	}
	
	// Clean up old logs
	la.cleanupOldLogs()
	
	// Clear storage after flush
	la.storage = la.storage[:0]
}

// flushAsJSON flushes logs in JSON format
func (la *LogAggregator) flushAsJSON() {
	for _, entry := range la.storage {
		if data, err := json.Marshal(entry); err == nil {
			la.logger.Info("Aggregated log", "data", string(data))
		}
	}
}

// flushAsStructured flushes logs in structured format
func (la *LogAggregator) flushAsStructured() {
	for _, entry := range la.storage {
		fields := map[string]interface{}{
			"timestamp": entry.Timestamp,
			"level":     entry.Level,
			"service":   entry.Service,
			"component": entry.Component,
		}
		
		if entry.TraceID != "" {
			fields["trace_id"] = entry.TraceID
		}
		
		if entry.Error != nil {
			fields["error"] = entry.Error
		}
		
		for k, v := range entry.Fields {
			fields[k] = v
		}
		
		la.logger.WithFields(fields).Info(entry.Message)
	}
}

// flushAsText flushes logs in text format
func (la *LogAggregator) flushAsText() {
	for _, entry := range la.storage {
		logLine := fmt.Sprintf("[%s] %s [%s/%s] %s",
			entry.Timestamp.Format(time.RFC3339),
			entry.Level,
			entry.Service,
			entry.Component,
			entry.Message,
		)
		
		if entry.Error != nil {
			logLine += fmt.Sprintf(" ERROR: %s", entry.Error.Message)
		}
		
		la.logger.Info(logLine)
	}
}

// cleanupOldLogs removes logs older than retention time
func (la *LogAggregator) cleanupOldLogs() {
	if la.config.RetentionTime <= 0 {
		return
	}
	
	cutoff := time.Now().Add(-la.config.RetentionTime)
	filtered := make([]*LogEntry, 0, len(la.storage))
	
	for _, entry := range la.storage {
		if entry.Timestamp.After(cutoff) {
			filtered = append(filtered, entry)
		}
	}
	
	la.storage = filtered
}

// GetLogs returns stored logs (for debugging/monitoring)
func (la *LogAggregator) GetLogs(limit int) []*LogEntry {
	la.mu.RLock()
	defer la.mu.RUnlock()
	
	if limit <= 0 || limit > len(la.storage) {
		limit = len(la.storage)
	}
	
	// Return most recent logs
	start := len(la.storage) - limit
	if start < 0 {
		start = 0
	}
	
	result := make([]*LogEntry, limit)
	copy(result, la.storage[start:])
	
	return result
}

// GetLogStats returns aggregation statistics
func (la *LogAggregator) GetLogStats() map[string]interface{} {
	la.mu.RLock()
	defer la.mu.RUnlock()
	
	levelCounts := make(map[string]int)
	serviceCounts := make(map[string]int)
	
	for _, entry := range la.storage {
		levelCounts[entry.Level]++
		serviceCounts[entry.Service]++
	}
	
	return map[string]interface{}{
		"total_logs":     len(la.storage),
		"buffer_size":    cap(la.buffer),
		"buffer_used":    len(la.buffer),
		"level_counts":   levelCounts,
		"service_counts": serviceCounts,
		"retention_time": la.config.RetentionTime.String(),
		"enabled":        la.config.Enabled,
	}
}
