package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// Logger wraps slog.Logger with additional functionality
type Logger struct {
	*slog.Logger
	level slog.Level
}

// LogLevel represents log levels
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

// Config holds logger configuration
type Config struct {
	Level          LogLevel `json:"level"`
	Format         string   `json:"format"` // json, text
	Output         string   `json:"output"` // stdout, file
	FilePath       string   `json:"file_path"`
	AddSource      bool     `json:"add_source"`
	TimeFormat     string   `json:"time_format"`
	ServiceName    string   `json:"service_name"`
	ServiceVersion string   `json:"service_version"`
	Environment    string   `json:"environment"`
	MaxSize        int      `json:"max_size"` // megabytes
	MaxBackups     int      `json:"max_backups"`
	MaxAge         int      `json:"max_age"` // days
	Compress       bool     `json:"compress"`
}

// Fields represents structured log fields
type Fields map[string]interface{}

// ContextKey represents context keys for logger
type ContextKey string

const (
	// CorrelationIDKey is the context key for correlation ID
	CorrelationIDKey ContextKey = "correlation_id"
	// RequestIDKey is the context key for request ID
	RequestIDKey ContextKey = "request_id"
	// UserIDKey is the context key for user ID
	UserIDKey ContextKey = "user_id"
	// SessionIDKey is the context key for session ID
	SessionIDKey ContextKey = "session_id"
	// TraceIDKey is the context key for trace ID
	TraceIDKey ContextKey = "trace_id"
	// SpanIDKey is the context key for span ID
	SpanIDKey ContextKey = "span_id"
)

// New creates a new logger instance
func New(config Config) (*Logger, error) {
	level := parseLevel(config.Level)

	var writer io.Writer
	switch config.Output {
	case "file":
		if config.FilePath == "" {
			return nil, fmt.Errorf("file path is required when output is file")
		}
		file, err := os.OpenFile(config.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		writer = file
	default:
		writer = os.Stdout
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: config.AddSource,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Customize time format
			if a.Key == slog.TimeKey && config.TimeFormat != "" {
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.Format(config.TimeFormat))
				}
			}
			return a
		},
	}

	switch config.Format {
	case "json":
		handler = slog.NewJSONHandler(writer, opts)
	default:
		handler = slog.NewTextHandler(writer, opts)
	}

	// Create base logger with service metadata
	baseLogger := slog.New(handler)

	// Add service metadata if provided
	if config.ServiceName != "" || config.ServiceVersion != "" || config.Environment != "" {
		baseLogger = baseLogger.With(
			slog.String("service", config.ServiceName),
			slog.String("version", config.ServiceVersion),
			slog.String("environment", config.Environment),
		)
	}

	logger := &Logger{
		Logger: baseLogger,
		level:  level,
	}

	return logger, nil
}

// NewDefault creates a logger with default configuration
func NewDefault() *Logger {
	config := Config{
		Level:      LevelInfo,
		Format:     "json",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: time.RFC3339,
	}

	logger, _ := New(config)
	return logger
}

// WithContext adds trace information and context values from context
func (l *Logger) WithContext(ctx context.Context) *Logger {
	var args []interface{}

	// Add trace information
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		spanContext := span.SpanContext()
		args = append(args,
			"trace_id", spanContext.TraceID().String(),
			"span_id", spanContext.SpanID().String(),
		)
	}

	// Add correlation ID if present
	if correlationID := ctx.Value(CorrelationIDKey); correlationID != nil {
		if id, ok := correlationID.(string); ok {
			args = append(args, "correlation_id", id)
		}
	}

	// Add request ID if present
	if requestID := ctx.Value(RequestIDKey); requestID != nil {
		if id, ok := requestID.(string); ok {
			args = append(args, "request_id", id)
		}
	}

	// Add user ID if present
	if userID := ctx.Value(UserIDKey); userID != nil {
		if id, ok := userID.(string); ok {
			args = append(args, "user_id", id)
		}
	}

	// Add session ID if present
	if sessionID := ctx.Value(SessionIDKey); sessionID != nil {
		if id, ok := sessionID.(string); ok {
			args = append(args, "session_id", id)
		}
	}

	if len(args) == 0 {
		return l
	}

	return &Logger{
		Logger: l.Logger.With(args...),
		level:  l.level,
	}
}

// WithFields adds structured fields to the logger
func (l *Logger) WithFields(fields Fields) *Logger {
	args := make([]interface{}, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}

	return &Logger{
		Logger: l.Logger.With(args...),
		level:  l.level,
	}
}

// WithField adds a single field to the logger
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return &Logger{
		Logger: l.Logger.With(key, value),
		level:  l.level,
	}
}

// WithError adds error field to the logger
func (l *Logger) WithError(err error) *Logger {
	if err == nil {
		return l
	}

	return &Logger{
		Logger: l.Logger.With("error", err.Error()),
		level:  l.level,
	}
}

// WithUser adds user information to the logger
func (l *Logger) WithUser(userID, username string) *Logger {
	return &Logger{
		Logger: l.Logger.With(
			"user_id", userID,
			"username", username,
		),
		level: l.level,
	}
}

// WithRequest adds request information to the logger
func (l *Logger) WithRequest(method, path, userAgent, ip string) *Logger {
	return &Logger{
		Logger: l.Logger.With(
			"method", method,
			"path", path,
			"user_agent", userAgent,
			"ip", ip,
		),
		level: l.level,
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...interface{}) {
	l.Logger.Debug(msg, args...)
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...interface{}) {
	l.Logger.Info(msg, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...interface{}) {
	l.Logger.Warn(msg, args...)
}

// Error logs an error message
func (l *Logger) Error(msg string, args ...interface{}) {
	l.Logger.Error(msg, args...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.Logger.Error(msg, args...)
	os.Exit(1)
}

// Debugf logs a debug message with formatting
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.Logger.Debug(fmt.Sprintf(format, args...))
}

// Infof logs an info message with formatting
func (l *Logger) Infof(format string, args ...interface{}) {
	l.Logger.Info(fmt.Sprintf(format, args...))
}

// Warnf logs a warning message with formatting
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Logger.Warn(fmt.Sprintf(format, args...))
}

// Errorf logs an error message with formatting
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Logger.Error(fmt.Sprintf(format, args...))
}

// Fatalf logs a fatal message with formatting and exits
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.Logger.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// LogHTTPRequest logs HTTP request details
func (l *Logger) LogHTTPRequest(ctx context.Context, method, path, userAgent, ip string, statusCode int, duration time.Duration, size int64) {
	l.WithContext(ctx).WithFields(Fields{
		"method":      method,
		"path":        path,
		"user_agent":  userAgent,
		"ip":          ip,
		"status_code": statusCode,
		"duration_ms": duration.Milliseconds(),
		"size_bytes":  size,
	}).Info("HTTP request")
}

// LogError logs error with stack trace
func (l *Logger) LogError(ctx context.Context, err error, msg string, fields Fields) {
	if fields == nil {
		fields = make(Fields)
	}

	fields["error"] = err.Error()
	fields["stack_trace"] = getStackTrace()

	l.WithContext(ctx).WithFields(fields).Error(msg)
}

// LogSecurityEvent logs security-related events
func (l *Logger) LogSecurityEvent(ctx context.Context, event string, userID, ip string, fields Fields) {
	if fields == nil {
		fields = make(Fields)
	}

	fields["event_type"] = "security"
	fields["security_event"] = event
	fields["user_id"] = userID
	fields["ip"] = ip
	fields["timestamp"] = time.Now().UTC()

	l.WithContext(ctx).WithFields(fields).Warn("Security event")
}

// LogAuditEvent logs audit events
func (l *Logger) LogAuditEvent(ctx context.Context, action, resource string, userID string, fields Fields) {
	if fields == nil {
		fields = make(Fields)
	}

	fields["event_type"] = "audit"
	fields["action"] = action
	fields["resource"] = resource
	fields["user_id"] = userID
	fields["timestamp"] = time.Now().UTC()

	l.WithContext(ctx).WithFields(fields).Info("Audit event")
}

// LogPerformance logs performance metrics
func (l *Logger) LogPerformance(ctx context.Context, operation string, duration time.Duration, fields Fields) {
	if fields == nil {
		fields = make(Fields)
	}

	fields["event_type"] = "performance"
	fields["operation"] = operation
	fields["duration_ms"] = duration.Milliseconds()
	fields["timestamp"] = time.Now().UTC()

	l.WithContext(ctx).WithFields(fields).Info("Performance metric")
}

// IsDebugEnabled returns true if debug logging is enabled
func (l *Logger) IsDebugEnabled() bool {
	return l.level <= slog.LevelDebug
}

// IsInfoEnabled returns true if info logging is enabled
func (l *Logger) IsInfoEnabled() bool {
	return l.level <= slog.LevelInfo
}

// IsWarnEnabled returns true if warn logging is enabled
func (l *Logger) IsWarnEnabled() bool {
	return l.level <= slog.LevelWarn
}

// IsErrorEnabled returns true if error logging is enabled
func (l *Logger) IsErrorEnabled() bool {
	return l.level <= slog.LevelError
}

// parseLevel converts string level to slog.Level
func parseLevel(level LogLevel) slog.Level {
	switch level {
	case LevelDebug:
		return slog.LevelDebug
	case LevelInfo:
		return slog.LevelInfo
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// getStackTrace returns the current stack trace
func getStackTrace() string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])

	var trace []map[string]interface{}
	for {
		frame, more := frames.Next()
		trace = append(trace, map[string]interface{}{
			"function": frame.Function,
			"file":     frame.File,
			"line":     frame.Line,
		})
		if !more {
			break
		}
	}

	data, _ := json.Marshal(trace)
	return string(data)
}

// Global logger instance
var defaultLogger = NewDefault()

// SetDefault sets the default logger
func SetDefault(logger *Logger) {
	defaultLogger = logger
}

// Default returns the default logger
func Default() *Logger {
	return defaultLogger
}

// Global convenience functions
func Debug(msg string, args ...interface{}) {
	defaultLogger.Debug(msg, args...)
}

func Info(msg string, args ...interface{}) {
	defaultLogger.Info(msg, args...)
}

func Warn(msg string, args ...interface{}) {
	defaultLogger.Warn(msg, args...)
}

func Error(msg string, args ...interface{}) {
	defaultLogger.Error(msg, args...)
}

func Fatal(msg string, args ...interface{}) {
	defaultLogger.Fatal(msg, args...)
}

func WithContext(ctx context.Context) *Logger {
	return defaultLogger.WithContext(ctx)
}

func WithFields(fields Fields) *Logger {
	return defaultLogger.WithFields(fields)
}

// Context helper functions

// WithCorrelationID adds a correlation ID to the context
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, CorrelationIDKey, correlationID)
}

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// WithUserID adds a user ID to the context
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// WithSessionID adds a session ID to the context
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, SessionIDKey, sessionID)
}

// GetCorrelationID extracts correlation ID from context
func GetCorrelationID(ctx context.Context) string {
	if id := ctx.Value(CorrelationIDKey); id != nil {
		if correlationID, ok := id.(string); ok {
			return correlationID
		}
	}
	return ""
}

// GetRequestID extracts request ID from context
func GetRequestID(ctx context.Context) string {
	if id := ctx.Value(RequestIDKey); id != nil {
		if requestID, ok := id.(string); ok {
			return requestID
		}
	}
	return ""
}

// GetUserID extracts user ID from context
func GetUserID(ctx context.Context) string {
	if id := ctx.Value(UserIDKey); id != nil {
		if userID, ok := id.(string); ok {
			return userID
		}
	}
	return ""
}

// GetSessionID extracts session ID from context
func GetSessionID(ctx context.Context) string {
	if id := ctx.Value(SessionIDKey); id != nil {
		if sessionID, ok := id.(string); ok {
			return sessionID
		}
	}
	return ""
}

func WithField(key string, value interface{}) *Logger {
	return defaultLogger.WithField(key, value)
}

func WithError(err error) *Logger {
	return defaultLogger.WithError(err)
}
