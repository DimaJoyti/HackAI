package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"golang.org/x/time/rate"
)

// SecurityMiddleware provides comprehensive security middleware
type SecurityMiddleware struct {
	logger      *logger.Logger
	rateLimiter *RateLimiter
	csrfConfig  *CSRFConfig
}

// SecurityConfig contains security middleware configuration
type SecurityConfig struct {
	RateLimit *RateLimitConfig `json:"rate_limit"`
	CSRF      *CSRFConfig      `json:"csrf"`
	Headers   *HeadersConfig   `json:"headers"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	WindowSize        time.Duration `json:"window_size"`
	CleanupInterval   time.Duration `json:"cleanup_interval"`
	SkipPaths         []string      `json:"skip_paths"`
	CustomLimits      map[string]struct {
		RequestsPerSecond int `json:"requests_per_second"`
		BurstSize         int `json:"burst_size"`
	} `json:"custom_limits"`
}

// CSRFConfig contains CSRF protection configuration
type CSRFConfig struct {
	Enabled        bool          `json:"enabled"`
	TokenLength    int           `json:"token_length"`
	CookieName     string        `json:"cookie_name"`
	HeaderName     string        `json:"header_name"`
	FieldName      string        `json:"field_name"`
	CookieSecure   bool          `json:"cookie_secure"`
	CookieHTTPOnly bool          `json:"cookie_http_only"`
	CookieSameSite http.SameSite `json:"cookie_same_site"`
	TokenLifetime  time.Duration `json:"token_lifetime"`
	SkipPaths      []string      `json:"skip_paths"`
	SafeMethods    []string      `json:"safe_methods"`
}

// HeadersConfig contains security headers configuration
type HeadersConfig struct {
	ContentTypeNosniff    bool   `json:"content_type_nosniff"`
	FrameOptions          string `json:"frame_options"`
	ContentSecurityPolicy string `json:"content_security_policy"`
	StrictTransportSecurity string `json:"strict_transport_security"`
	ReferrerPolicy        string `json:"referrer_policy"`
	PermissionsPolicy     string `json:"permissions_policy"`
	CrossOriginEmbedderPolicy string `json:"cross_origin_embedder_policy"`
	CrossOriginOpenerPolicy   string `json:"cross_origin_opener_policy"`
	CrossOriginResourcePolicy string `json:"cross_origin_resource_policy"`
}

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	limiters        map[string]*rate.Limiter
	mu              sync.RWMutex
	config          *RateLimitConfig
	logger          *logger.Logger
	lastCleanup     time.Time
}

// CSRFToken represents a CSRF token
type CSRFToken struct {
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(logger *logger.Logger, config *SecurityConfig) *SecurityMiddleware {
	if config == nil {
		config = &SecurityConfig{
			RateLimit: &RateLimitConfig{
				RequestsPerSecond: 100,
				BurstSize:         200,
				WindowSize:        time.Minute,
				CleanupInterval:   5 * time.Minute,
			},
			CSRF: &CSRFConfig{
				Enabled:        true,
				TokenLength:    32,
				CookieName:     "csrf_token",
				HeaderName:     "X-CSRF-Token",
				FieldName:      "csrf_token",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				CookieSameSite: http.SameSiteStrictMode,
				TokenLifetime:  24 * time.Hour,
				SafeMethods:    []string{"GET", "HEAD", "OPTIONS"},
			},
			Headers: &HeadersConfig{
				ContentTypeNosniff:    true,
				FrameOptions:          "DENY",
				ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
				StrictTransportSecurity: "max-age=31536000; includeSubDomains",
				ReferrerPolicy:        "strict-origin-when-cross-origin",
				PermissionsPolicy:     "geolocation=(), microphone=(), camera=()",
			},
		}
	}

	rateLimiter := &RateLimiter{
		limiters:    make(map[string]*rate.Limiter),
		config:      config.RateLimit,
		logger:      logger,
		lastCleanup: time.Now(),
	}

	return &SecurityMiddleware{
		logger:      logger,
		rateLimiter: rateLimiter,
		csrfConfig:  config.CSRF,
	}
}

// RateLimit provides rate limiting middleware
func (s *SecurityMiddleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting for certain paths
		if s.shouldSkipRateLimit(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := getClientIP(r)
		
		// Check if request is allowed
		if !s.rateLimiter.Allow(clientIP, r.URL.Path) {
			s.logger.Warn("Rate limit exceeded", map[string]interface{}{
				"ip":   clientIP,
				"path": r.URL.Path,
			})
			
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(s.rateLimiter.config.RequestsPerSecond))
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("Retry-After", strconv.Itoa(int(s.rateLimiter.config.WindowSize.Seconds())))
			
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CSRFProtection provides CSRF protection middleware
func (s *SecurityMiddleware) CSRFProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.csrfConfig.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Skip CSRF protection for certain paths
		if s.shouldSkipCSRF(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Skip CSRF protection for safe methods
		if s.isSafeMethod(r.Method) {
			// Generate and set CSRF token for safe methods
			token := s.generateCSRFToken()
			s.setCSRFCookie(w, token)
			next.ServeHTTP(w, r)
			return
		}

		// Validate CSRF token for unsafe methods
		if !s.validateCSRFToken(r) {
			s.logger.Warn("CSRF token validation failed", map[string]interface{}{
				"ip":     getClientIP(r),
				"path":   r.URL.Path,
				"method": r.Method,
			})
			
			http.Error(w, "CSRF token validation failed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders provides security headers middleware
func (s *SecurityMiddleware) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := w.Header()

		// Content-Type nosniff
		headers.Set("X-Content-Type-Options", "nosniff")

		// Frame options
		headers.Set("X-Frame-Options", "DENY")

		// XSS protection
		headers.Set("X-XSS-Protection", "1; mode=block")

		// Content Security Policy
		headers.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")

		// Strict Transport Security
		if r.TLS != nil {
			headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Referrer Policy
		headers.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions Policy
		headers.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// Cross-Origin policies
		headers.Set("Cross-Origin-Embedder-Policy", "require-corp")
		headers.Set("Cross-Origin-Opener-Policy", "same-origin")
		headers.Set("Cross-Origin-Resource-Policy", "same-origin")

		// Remove server information
		headers.Set("Server", "")

		next.ServeHTTP(w, r)
	})
}

// Rate limiter methods

// Allow checks if a request is allowed based on rate limiting
func (rl *RateLimiter) Allow(clientIP, path string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Cleanup old limiters periodically
	if time.Since(rl.lastCleanup) > rl.config.CleanupInterval {
		rl.cleanup()
		rl.lastCleanup = time.Now()
	}

	// Get or create limiter for this client
	limiter := rl.getLimiter(clientIP, path)
	
	return limiter.Allow()
}

// getLimiter gets or creates a rate limiter for a client
func (rl *RateLimiter) getLimiter(clientIP, path string) *rate.Limiter {
	key := fmt.Sprintf("%s:%s", clientIP, path)
	
	if limiter, exists := rl.limiters[key]; exists {
		return limiter
	}

	// Check for custom limits for this path
	rps := rl.config.RequestsPerSecond
	burst := rl.config.BurstSize

	for pathPattern, limits := range rl.config.CustomLimits {
		if strings.HasPrefix(path, pathPattern) {
			rps = limits.RequestsPerSecond
			burst = limits.BurstSize
			break
		}
	}

	limiter := rate.NewLimiter(rate.Limit(rps), burst)
	rl.limiters[key] = limiter
	
	return limiter
}

// cleanup removes old rate limiters
func (rl *RateLimiter) cleanup() {
	// In a real implementation, you would track last access times
	// and remove limiters that haven't been used recently
	if len(rl.limiters) > 10000 {
		// Simple cleanup: remove half of the limiters
		newLimiters := make(map[string]*rate.Limiter)
		count := 0
		for key, limiter := range rl.limiters {
			if count < len(rl.limiters)/2 {
				newLimiters[key] = limiter
				count++
			}
		}
		rl.limiters = newLimiters
	}
}

// CSRF methods

// generateCSRFToken generates a new CSRF token
func (s *SecurityMiddleware) generateCSRFToken() string {
	bytes := make([]byte, s.csrfConfig.TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		s.logger.WithError(err).Error("Failed to generate CSRF token")
		return ""
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

// setCSRFCookie sets the CSRF token cookie
func (s *SecurityMiddleware) setCSRFCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     s.csrfConfig.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(s.csrfConfig.TokenLifetime),
		Secure:   s.csrfConfig.CookieSecure,
		HttpOnly: s.csrfConfig.CookieHTTPOnly,
		SameSite: s.csrfConfig.CookieSameSite,
	}
	http.SetCookie(w, cookie)
}

// validateCSRFToken validates the CSRF token
func (s *SecurityMiddleware) validateCSRFToken(r *http.Request) bool {
	// Get token from cookie
	cookie, err := r.Cookie(s.csrfConfig.CookieName)
	if err != nil {
		return false
	}
	cookieToken := cookie.Value

	// Get token from header or form
	var requestToken string
	
	// Try header first
	requestToken = r.Header.Get(s.csrfConfig.HeaderName)
	
	// Try form field if header is empty
	if requestToken == "" {
		requestToken = r.FormValue(s.csrfConfig.FieldName)
	}

	// Compare tokens using constant time comparison
	return subtle.ConstantTimeCompare([]byte(cookieToken), []byte(requestToken)) == 1
}

// Helper methods

// shouldSkipRateLimit checks if rate limiting should be skipped for a path
func (s *SecurityMiddleware) shouldSkipRateLimit(path string) bool {
	for _, skipPath := range s.rateLimiter.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// shouldSkipCSRF checks if CSRF protection should be skipped for a path
func (s *SecurityMiddleware) shouldSkipCSRF(path string) bool {
	for _, skipPath := range s.csrfConfig.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// isSafeMethod checks if an HTTP method is considered safe
func (s *SecurityMiddleware) isSafeMethod(method string) bool {
	for _, safeMethod := range s.csrfConfig.SafeMethods {
		if method == safeMethod {
			return true
		}
	}
	return false
}

// AuditLogger provides audit logging middleware
func (s *SecurityMiddleware) AuditLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		// Process request
		next.ServeHTTP(wrapped, r)
		
		// Log audit information
		duration := time.Since(start)
		
		auditData := map[string]interface{}{
			"timestamp":    start.Unix(),
			"method":       r.Method,
			"path":         r.URL.Path,
			"query":        r.URL.RawQuery,
			"status_code":  wrapped.statusCode,
			"duration_ms":  duration.Milliseconds(),
			"ip_address":   getClientIP(r),
			"user_agent":   r.UserAgent(),
			"referer":      r.Referer(),
			"content_length": r.ContentLength,
		}

		// Add user information if available
		if userCtx := GetUserFromContext(r.Context()); userCtx != nil {
			auditData["user_id"] = userCtx.UID
			auditData["user_email"] = userCtx.Email
		}

		s.logger.Info("HTTP request", auditData)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// GetCSRFToken extracts CSRF token from request context
func GetCSRFToken(r *http.Request) string {
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}
