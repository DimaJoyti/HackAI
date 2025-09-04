package logger

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp     time.Time              `json:"timestamp"`
	Level         string                 `json:"level"`
	Message       string                 `json:"message"`
	Service       string                 `json:"service"`
	Version       string                 `json:"version"`
	Environment   string                 `json:"environment"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	RequestID     string                 `json:"request_id,omitempty"`
	UserID        string                 `json:"user_id,omitempty"`
	TraceID       string                 `json:"trace_id,omitempty"`
	SpanID        string                 `json:"span_id,omitempty"`
	Fields        map[string]interface{} `json:"fields,omitempty"`
}

// LogAggregator aggregates and processes log entries
type LogAggregator struct {
	config      AggregatorConfig
	entries     chan LogEntry
	buffer      []LogEntry
	bufferMutex sync.RWMutex
	stopChan    chan struct{}
	wg          sync.WaitGroup
	writers     []LogWriter
}

// AggregatorConfig configures the log aggregator
type AggregatorConfig struct {
	BufferSize    int           `json:"buffer_size"`
	FlushInterval time.Duration `json:"flush_interval"`
	MaxFileSize   int64         `json:"max_file_size"`  // bytes
	MaxFiles      int           `json:"max_files"`      // number of files to keep
	CompressOld   bool          `json:"compress_old"`   // compress old log files
	OutputDir     string        `json:"output_dir"`     // directory for log files
	FilePattern   string        `json:"file_pattern"`   // filename pattern
	EnableMetrics bool          `json:"enable_metrics"` // enable log metrics
	SampleRate    float64       `json:"sample_rate"`    // sampling rate (0.0-1.0)
}

// LogWriter interface for different log output destinations
type LogWriter interface {
	Write(entries []LogEntry) error
	Close() error
}

// FileLogWriter writes logs to rotating files
type FileLogWriter struct {
	config      AggregatorConfig
	currentFile *os.File
	currentSize int64
	mutex       sync.Mutex
}

// ElasticsearchLogWriter writes logs to Elasticsearch (placeholder)
type ElasticsearchLogWriter struct {
	endpoint string
	index    string
}

// MetricsCollector collects log metrics
type MetricsCollector struct {
	logCounts   map[string]int64
	errorCounts map[string]int64
	lastFlush   time.Time
	mutex       sync.RWMutex
}

// NewLogAggregator creates a new log aggregator
func NewLogAggregator(config AggregatorConfig) (*LogAggregator, error) {
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 5 * time.Second
	}
	if config.MaxFileSize == 0 {
		config.MaxFileSize = 100 * 1024 * 1024 // 100MB
	}
	if config.MaxFiles == 0 {
		config.MaxFiles = 10
	}
	if config.OutputDir == "" {
		config.OutputDir = "logs"
	}
	if config.FilePattern == "" {
		config.FilePattern = "app-%s.log"
	}
	if config.SampleRate == 0 {
		config.SampleRate = 1.0 // No sampling by default
	}

	// Ensure output directory exists
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	aggregator := &LogAggregator{
		config:   config,
		entries:  make(chan LogEntry, config.BufferSize),
		buffer:   make([]LogEntry, 0, config.BufferSize),
		stopChan: make(chan struct{}),
		writers:  make([]LogWriter, 0),
	}

	// Add file writer
	fileWriter, err := NewFileLogWriter(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create file writer: %w", err)
	}
	aggregator.AddWriter(fileWriter)

	return aggregator, nil
}

// NewFileLogWriter creates a new file log writer
func NewFileLogWriter(config AggregatorConfig) (*FileLogWriter, error) {
	writer := &FileLogWriter{
		config: config,
	}

	// Open initial log file
	if err := writer.rotateFile(); err != nil {
		return nil, fmt.Errorf("failed to create initial log file: %w", err)
	}

	return writer, nil
}

// AddWriter adds a log writer to the aggregator
func (la *LogAggregator) AddWriter(writer LogWriter) {
	la.writers = append(la.writers, writer)
}

// Start starts the log aggregator
func (la *LogAggregator) Start(ctx context.Context) {
	la.wg.Add(2)

	// Start buffer processor
	go la.processEntries(ctx)

	// Start periodic flusher
	go la.periodicFlush(ctx)
}

// Stop stops the log aggregator
func (la *LogAggregator) Stop() {
	close(la.stopChan)
	la.wg.Wait()

	// Flush remaining entries
	la.flush()

	// Close all writers
	for _, writer := range la.writers {
		writer.Close()
	}
}

// AddEntry adds a log entry to the aggregator
func (la *LogAggregator) AddEntry(entry LogEntry) {
	// Apply sampling
	if la.config.SampleRate < 1.0 {
		// Simple sampling based on hash of correlation ID
		if entry.CorrelationID != "" {
			hash := simpleHash(entry.CorrelationID)
			if float64(hash%100)/100.0 > la.config.SampleRate {
				return // Skip this entry
			}
		}
	}

	select {
	case la.entries <- entry:
	default:
		// Buffer full, drop entry (or implement backpressure)
	}
}

// processEntries processes log entries from the channel
func (la *LogAggregator) processEntries(ctx context.Context) {
	defer la.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-la.stopChan:
			return
		case entry := <-la.entries:
			la.bufferMutex.Lock()
			la.buffer = append(la.buffer, entry)

			// Flush if buffer is full
			if len(la.buffer) >= la.config.BufferSize {
				la.flushBuffer()
			}
			la.bufferMutex.Unlock()
		}
	}
}

// periodicFlush flushes the buffer periodically
func (la *LogAggregator) periodicFlush(ctx context.Context) {
	defer la.wg.Done()

	ticker := time.NewTicker(la.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-la.stopChan:
			return
		case <-ticker.C:
			la.flush()
		}
	}
}

// flush flushes the current buffer
func (la *LogAggregator) flush() {
	la.bufferMutex.Lock()
	defer la.bufferMutex.Unlock()
	la.flushBuffer()
}

// flushBuffer flushes the buffer (must be called with lock held)
func (la *LogAggregator) flushBuffer() {
	if len(la.buffer) == 0 {
		return
	}

	// Write to all writers
	for _, writer := range la.writers {
		if err := writer.Write(la.buffer); err != nil {
			// Log error (but avoid infinite recursion)
			fmt.Fprintf(os.Stderr, "Failed to write logs: %v\n", err)
		}
	}

	// Clear buffer
	la.buffer = la.buffer[:0]
}

// Write implements LogWriter interface for FileLogWriter
func (flw *FileLogWriter) Write(entries []LogEntry) error {
	flw.mutex.Lock()
	defer flw.mutex.Unlock()

	for _, entry := range entries {
		// Serialize entry to JSON
		data, err := json.Marshal(entry)
		if err != nil {
			continue // Skip malformed entries
		}

		// Add newline
		data = append(data, '\n')

		// Check if we need to rotate
		if flw.currentSize+int64(len(data)) > flw.config.MaxFileSize {
			if err := flw.rotateFile(); err != nil {
				return fmt.Errorf("failed to rotate log file: %w", err)
			}
		}

		// Write to current file
		n, err := flw.currentFile.Write(data)
		if err != nil {
			return fmt.Errorf("failed to write to log file: %w", err)
		}

		flw.currentSize += int64(n)
	}

	// Sync to disk
	return flw.currentFile.Sync()
}

// rotateFile rotates the current log file
func (flw *FileLogWriter) rotateFile() error {
	// Close current file if open
	if flw.currentFile != nil {
		flw.currentFile.Close()
	}

	// Generate new filename
	timestamp := time.Now().Format("2006-01-02-15-04-05")
	filename := fmt.Sprintf(flw.config.FilePattern, timestamp)
	filepath := filepath.Join(flw.config.OutputDir, filename)

	// Open new file
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	flw.currentFile = file
	flw.currentSize = 0

	// Clean up old files
	go flw.cleanupOldFiles()

	return nil
}

// cleanupOldFiles removes old log files beyond the retention limit
func (flw *FileLogWriter) cleanupOldFiles() {
	files, err := filepath.Glob(filepath.Join(flw.config.OutputDir, "*.log"))
	if err != nil {
		return
	}

	// Sort files by modification time (newest first)
	sort.Slice(files, func(i, j int) bool {
		infoI, errI := os.Stat(files[i])
		infoJ, errJ := os.Stat(files[j])
		if errI != nil || errJ != nil {
			return false
		}
		return infoI.ModTime().After(infoJ.ModTime())
	})

	// Remove excess files
	if len(files) > flw.config.MaxFiles {
		for _, file := range files[flw.config.MaxFiles:] {
			os.Remove(file)
		}
	}

	// Compress old files if enabled
	if flw.config.CompressOld && len(files) > 1 {
		// Compress files older than the current one
		// Implementation would go here (using gzip)
	}
}

// Close implements LogWriter interface for FileLogWriter
func (flw *FileLogWriter) Close() error {
	flw.mutex.Lock()
	defer flw.mutex.Unlock()

	if flw.currentFile != nil {
		return flw.currentFile.Close()
	}
	return nil
}

// LogAnalyzer analyzes log files for patterns and metrics
type LogAnalyzer struct {
	config AnalyzerConfig
}

// AnalyzerConfig configures the log analyzer
type AnalyzerConfig struct {
	LogDir          string         `json:"log_dir"`
	AnalysisWindow  time.Duration  `json:"analysis_window"`
	AlertThresholds map[string]int `json:"alert_thresholds"`
}

// AnalysisResult represents the result of log analysis
type AnalysisResult struct {
	TimeWindow     time.Duration          `json:"time_window"`
	TotalEntries   int                    `json:"total_entries"`
	ErrorCount     int                    `json:"error_count"`
	WarnCount      int                    `json:"warn_count"`
	TopErrors      []ErrorSummary         `json:"top_errors"`
	TopPaths       []PathSummary          `json:"top_paths"`
	SecurityEvents []SecurityEventSummary `json:"security_events"`
	Performance    PerformanceSummary     `json:"performance"`
}

// ErrorSummary summarizes error occurrences
type ErrorSummary struct {
	Message string `json:"message"`
	Count   int    `json:"count"`
}

// PathSummary summarizes request path statistics
type PathSummary struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// SecurityEventSummary summarizes security events
type SecurityEventSummary struct {
	Event string   `json:"event"`
	Count int      `json:"count"`
	IPs   []string `json:"ips"`
}

// PerformanceSummary summarizes performance metrics
type PerformanceSummary struct {
	AvgResponseTime time.Duration `json:"avg_response_time"`
	P95ResponseTime time.Duration `json:"p95_response_time"`
	SlowRequests    int           `json:"slow_requests"`
}

// NewLogAnalyzer creates a new log analyzer
func NewLogAnalyzer(config AnalyzerConfig) *LogAnalyzer {
	if config.AnalysisWindow == 0 {
		config.AnalysisWindow = time.Hour
	}

	return &LogAnalyzer{
		config: config,
	}
}

// AnalyzeLogs analyzes log files and returns insights
func (la *LogAnalyzer) AnalyzeLogs() (*AnalysisResult, error) {
	// Find log files in the directory
	files, err := filepath.Glob(filepath.Join(la.config.LogDir, "*.log"))
	if err != nil {
		return nil, fmt.Errorf("failed to find log files: %w", err)
	}

	result := &AnalysisResult{
		TimeWindow:     la.config.AnalysisWindow,
		TopErrors:      make([]ErrorSummary, 0),
		TopPaths:       make([]PathSummary, 0),
		SecurityEvents: make([]SecurityEventSummary, 0),
	}

	cutoff := time.Now().Add(-la.config.AnalysisWindow)

	for _, file := range files {
		if err := la.analyzeFile(file, cutoff, result); err != nil {
			continue // Skip problematic files
		}
	}

	return result, nil
}

// analyzeFile analyzes a single log file
func (la *LogAnalyzer) analyzeFile(filename string, cutoff time.Time, result *AnalysisResult) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue // Skip malformed entries
		}

		// Skip entries outside the analysis window
		if entry.Timestamp.Before(cutoff) {
			continue
		}

		result.TotalEntries++

		// Count by level
		switch strings.ToLower(entry.Level) {
		case "error":
			result.ErrorCount++
		case "warn", "warning":
			result.WarnCount++
		}

		// Analyze specific patterns
		la.analyzeEntry(entry, result)
	}

	return scanner.Err()
}

// analyzeEntry analyzes a single log entry
func (la *LogAnalyzer) analyzeEntry(entry LogEntry, result *AnalysisResult) {
	// This is a simplified analysis - in production you'd want more sophisticated pattern matching
	if entry.Fields != nil {
		// Check for HTTP requests
		if path, ok := entry.Fields["path"].(string); ok {
			// Track path frequency (simplified)
			found := false
			for i, ps := range result.TopPaths {
				if ps.Path == path {
					result.TopPaths[i].Count++
					found = true
					break
				}
			}
			if !found && len(result.TopPaths) < 10 {
				result.TopPaths = append(result.TopPaths, PathSummary{Path: path, Count: 1})
			}
		}

		// Check for security events
		if secEvent, ok := entry.Fields["security_event"].(string); ok {
			found := false
			for i, se := range result.SecurityEvents {
				if se.Event == secEvent {
					result.SecurityEvents[i].Count++
					found = true
					break
				}
			}
			if !found && len(result.SecurityEvents) < 10 {
				result.SecurityEvents = append(result.SecurityEvents, SecurityEventSummary{
					Event: secEvent,
					Count: 1,
					IPs:   make([]string, 0),
				})
			}
		}
	}
}

// Helper function for simple hashing
func simpleHash(s string) uint32 {
	hash := uint32(2166136261)
	for _, b := range []byte(s) {
		hash ^= uint32(b)
		hash *= 16777619
	}
	return hash
}
