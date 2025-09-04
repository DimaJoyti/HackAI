package logger

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// ResponseWriter wraps http.ResponseWriter to capture response details
type ResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int64
	written    bool
}

// NewResponseWriter creates a new ResponseWriter
func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// WriteHeader captures the status code
func (rw *ResponseWriter) WriteHeader(statusCode int) {
	if !rw.written {
		rw.statusCode = statusCode
		rw.written = true
		rw.ResponseWriter.WriteHeader(statusCode)
	}
}

// Write captures the response size
func (rw *ResponseWriter) Write(data []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(data)
	rw.size += int64(n)
	return n, err
}

// Hijack implements http.Hijacker interface
func (rw *ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("hijacking not supported")
}

// StatusCode returns the captured status code
func (rw *ResponseWriter) StatusCode() int {
	return rw.statusCode
}

// Size returns the captured response size
func (rw *ResponseWriter) Size() int64 {
	return rw.size
}

// HTTPMiddleware provides HTTP request/response logging middleware
type HTTPMiddleware struct {
	logger           *Logger
	skipPaths        []string
	skipUserAgents   []string
	logRequestBody   bool
	logResponseBody  bool
	maxBodySize      int64
	sensitiveHeaders []string
}

// HTTPMiddlewareConfig configures the HTTP middleware
type HTTPMiddlewareConfig struct {
	Logger           *Logger
	SkipPaths        []string
	SkipUserAgents   []string
	LogRequestBody   bool
	LogResponseBody  bool
	MaxBodySize      int64
	SensitiveHeaders []string
}

// NewHTTPMiddleware creates a new HTTP logging middleware
func NewHTTPMiddleware(config HTTPMiddlewareConfig) *HTTPMiddleware {
	if config.Logger == nil {
		config.Logger = Default()
	}

	if config.MaxBodySize == 0 {
		config.MaxBodySize = 1024 * 1024 // 1MB default
	}

	if config.SensitiveHeaders == nil {
		config.SensitiveHeaders = []string{
			"authorization", "cookie", "set-cookie", "x-api-key",
			"x-auth-token", "x-csrf-token", "x-forwarded-for",
		}
	}

	return &HTTPMiddleware{
		logger:           config.Logger,
		skipPaths:        config.SkipPaths,
		skipUserAgents:   config.SkipUserAgents,
		logRequestBody:   config.LogRequestBody,
		logResponseBody:  config.LogResponseBody,
		maxBodySize:      config.MaxBodySize,
		sensitiveHeaders: config.SensitiveHeaders,
	}
}

// Handler returns the HTTP middleware handler
func (m *HTTPMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Generate correlation ID if not present
		correlationID := r.Header.Get("X-Correlation-ID")
		if correlationID == "" {
			correlationID = generateCorrelationID()
			r.Header.Set("X-Correlation-ID", correlationID)
		}

		// Generate request ID
		requestID := generateRequestID()

		// Add IDs to context
		ctx := WithCorrelationID(r.Context(), correlationID)
		ctx = WithRequestID(ctx, requestID)
		r = r.WithContext(ctx)

		// Set response headers
		w.Header().Set("X-Correlation-ID", correlationID)
		w.Header().Set("X-Request-ID", requestID)

		// Check if we should skip logging for this request
		if m.shouldSkip(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Wrap response writer
		rw := NewResponseWriter(w)

		// Log request
		m.logRequest(ctx, r)

		// Process request
		next.ServeHTTP(rw, r)

		// Log response
		duration := time.Since(start)
		m.logResponse(ctx, r, rw, duration)

		// Log security events if needed
		m.checkSecurityEvents(ctx, r, rw)
	})
}

// shouldSkip determines if logging should be skipped for this request
func (m *HTTPMiddleware) shouldSkip(r *http.Request) bool {
	// Skip certain paths
	for _, path := range m.skipPaths {
		if strings.HasPrefix(r.URL.Path, path) {
			return true
		}
	}

	// Skip certain user agents
	userAgent := r.Header.Get("User-Agent")
	for _, ua := range m.skipUserAgents {
		if strings.Contains(userAgent, ua) {
			return true
		}
	}

	return false
}

// logRequest logs the incoming HTTP request
func (m *HTTPMiddleware) logRequest(ctx context.Context, r *http.Request) {
	fields := Fields{
		"event_type":     "http_request",
		"method":         r.Method,
		"path":           r.URL.Path,
		"query":          r.URL.RawQuery,
		"user_agent":     r.Header.Get("User-Agent"),
		"content_type":   r.Header.Get("Content-Type"),
		"content_length": r.ContentLength,
		"host":           r.Host,
		"remote_addr":    getClientIP(r),
		"protocol":       r.Proto,
		"headers":        m.sanitizeHeaders(r.Header),
	}

	// Add request body if configured
	if m.logRequestBody && r.ContentLength > 0 && r.ContentLength <= m.maxBodySize {
		// Note: In production, you'd want to be careful about logging request bodies
		// as they might contain sensitive information
		fields["request_body_logged"] = true
	}

	m.logger.WithContext(ctx).WithFields(fields).Info("HTTP request received")
}

// logResponse logs the HTTP response
func (m *HTTPMiddleware) logResponse(ctx context.Context, r *http.Request, rw *ResponseWriter, duration time.Duration) {
	fields := Fields{
		"event_type":  "http_response",
		"method":      r.Method,
		"path":        r.URL.Path,
		"status_code": rw.StatusCode(),
		"size_bytes":  rw.Size(),
		"duration_ms": duration.Milliseconds(),
		"duration_ns": duration.Nanoseconds(),
	}

	// Determine log level based on status code
	var logLevel string
	switch {
	case rw.StatusCode() >= 500:
		logLevel = "error"
		fields["error_class"] = "server_error"
	case rw.StatusCode() >= 400:
		logLevel = "warn"
		fields["error_class"] = "client_error"
	case rw.StatusCode() >= 300:
		logLevel = "info"
	default:
		logLevel = "info"
	}

	// Add performance classification
	switch {
	case duration > 5*time.Second:
		fields["performance"] = "very_slow"
	case duration > 2*time.Second:
		fields["performance"] = "slow"
	case duration > 500*time.Millisecond:
		fields["performance"] = "moderate"
	default:
		fields["performance"] = "fast"
	}

	logger := m.logger.WithContext(ctx).WithFields(fields)

	switch logLevel {
	case "error":
		logger.Error("HTTP response sent")
	case "warn":
		logger.Warn("HTTP response sent")
	default:
		logger.Info("HTTP response sent")
	}
}

// checkSecurityEvents checks for potential security events
func (m *HTTPMiddleware) checkSecurityEvents(ctx context.Context, r *http.Request, rw *ResponseWriter) {
	userAgent := r.Header.Get("User-Agent")
	clientIP := getClientIP(r)

	// Check for suspicious patterns
	var securityEvents []string

	// Check for common attack patterns in URL
	suspiciousPatterns := []string{
		"../", "..\\", "<script", "javascript:", "vbscript:",
		"onload=", "onerror=", "eval(", "alert(", "document.cookie",
		"union select", "drop table", "insert into", "delete from",
		"exec(", "system(", "cmd.exe", "/bin/sh", "passwd",
	}

	path := strings.ToLower(r.URL.Path + "?" + r.URL.RawQuery)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(path, pattern) {
			securityEvents = append(securityEvents, fmt.Sprintf("suspicious_pattern:%s", pattern))
		}
	}

	// Check for suspicious user agents
	suspiciousUAs := []string{
		"sqlmap", "nikto", "nmap", "masscan", "zap", "burp",
		"w3af", "acunetix", "nessus", "openvas", "metasploit",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, ua := range suspiciousUAs {
		if strings.Contains(userAgentLower, ua) {
			securityEvents = append(securityEvents, fmt.Sprintf("suspicious_user_agent:%s", ua))
		}
	}

	// Check for rate limiting violations (status 429)
	if rw.StatusCode() == http.StatusTooManyRequests {
		securityEvents = append(securityEvents, "rate_limit_exceeded")
	}

	// Check for authentication failures
	if rw.StatusCode() == http.StatusUnauthorized {
		securityEvents = append(securityEvents, "authentication_failure")
	}

	// Check for forbidden access
	if rw.StatusCode() == http.StatusForbidden {
		securityEvents = append(securityEvents, "forbidden_access")
	}

	// Log security events
	if len(securityEvents) > 0 {
		fields := Fields{
			"security_events": securityEvents,
			"method":          r.Method,
			"path":            r.URL.Path,
			"user_agent":      userAgent,
			"status_code":     rw.StatusCode(),
		}

		m.logger.LogSecurityEvent(ctx, strings.Join(securityEvents, ","), "", clientIP, fields)
	}
}

// sanitizeHeaders removes sensitive headers from logging
func (m *HTTPMiddleware) sanitizeHeaders(headers http.Header) map[string]string {
	sanitized := make(map[string]string)

	for key, values := range headers {
		keyLower := strings.ToLower(key)

		// Check if this is a sensitive header
		isSensitive := false
		for _, sensitive := range m.sensitiveHeaders {
			if keyLower == sensitive {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			sanitized[key] = "[REDACTED]"
		} else {
			sanitized[key] = strings.Join(values, ", ")
		}
	}

	return sanitized
}

// getClientIP extracts the real client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Check X-Forwarded header
	if xf := r.Header.Get("X-Forwarded"); xf != "" {
		return xf
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

// generateCorrelationID generates a new correlation ID
func generateCorrelationID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateRequestID generates a new request ID
func generateRequestID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// RecoveryMiddleware provides panic recovery with logging
func RecoveryMiddleware(logger *Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Log the panic
					fields := Fields{
						"event_type": "panic_recovery",
						"method":     r.Method,
						"path":       r.URL.Path,
						"panic":      fmt.Sprintf("%v", err),
						"stack":      getStackTrace(),
					}

					logger.WithContext(r.Context()).WithFields(fields).Error("Panic recovered")

					// Return 500 error
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
