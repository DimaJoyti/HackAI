package security

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAIFirewall(t *testing.T) {
	// Create logger
	log, err := logger.New(logger.Config{
		Level:  "info",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Create firewall with default config
	config := security.DefaultFirewallConfig()
	firewall := security.NewAIFirewall(config, log)

	t.Run("Basic Request Processing", func(t *testing.T) {
		// Create a normal request
		req := createTestRequest("GET", "https://example.com/api/users", "", "192.168.1.100")

		decision, err := firewall.ProcessRequest(context.Background(), req)
		require.NoError(t, err)
		assert.NotNil(t, decision)
		assert.Equal(t, "allow", decision.Action)
		assert.Greater(t, decision.Confidence, 0.0)
	})

	t.Run("SQL Injection Detection", func(t *testing.T) {
		// Create request with SQL injection
		maliciousBody := `{"query": "SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin"}`
		req := createTestRequest("POST", "https://example.com/api/search", maliciousBody, "203.0.113.1")

		decision, err := firewall.ProcessRequest(context.Background(), req)
		require.NoError(t, err)
		assert.NotNil(t, decision)
		assert.Equal(t, "block", decision.Action)
		assert.Greater(t, decision.Confidence, 0.7)
		assert.Contains(t, decision.Reason, "rule")
	})

	t.Run("XSS Detection", func(t *testing.T) {
		// Create request with XSS
		maliciousBody := `{"comment": "<script>alert('xss')</script>"}`
		req := createTestRequest("POST", "https://example.com/api/comments", maliciousBody, "203.0.113.2")

		decision, err := firewall.ProcessRequest(context.Background(), req)
		require.NoError(t, err)
		assert.NotNil(t, decision)
		assert.Equal(t, "block", decision.Action)
		assert.Greater(t, decision.Confidence, 0.7)
	})

	t.Run("Path Traversal Detection", func(t *testing.T) {
		// Create request with path traversal
		req := createTestRequest("GET", "https://example.com/api/files?path=../../../etc/passwd", "", "203.0.113.3")

		decision, err := firewall.ProcessRequest(context.Background(), req)
		require.NoError(t, err)
		assert.NotNil(t, decision)
		assert.Equal(t, "block", decision.Action)
	})

	t.Run("Rate Limiting", func(t *testing.T) {
		ipAddress := "192.168.1.200"

		// Make multiple requests to trigger rate limiting
		for i := 0; i < 105; i++ {
			req := createTestRequest("GET", "https://example.com/api/test", "", ipAddress)
			decision, err := firewall.ProcessRequest(context.Background(), req)
			require.NoError(t, err)

			if i >= 100 {
				// Should be rate limited after 100 requests
				assert.Equal(t, "block", decision.Action)
				assert.Contains(t, decision.Reason, "rate limit")
			}
		}
	})

	t.Run("Threat Intelligence", func(t *testing.T) {
		// Test with known malicious IP from threat intelligence
		req := createTestRequest("GET", "https://example.com/api/test", "", "192.0.2.1")

		decision, err := firewall.ProcessRequest(context.Background(), req)
		require.NoError(t, err)
		assert.NotNil(t, decision)
		// Should have higher threat score due to threat intelligence
		assert.Greater(t, decision.ThreatScore, 0.5)
	})
}

func TestRuleEngine(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "info",
		Output: "stdout",
	})
	require.NoError(t, err)

	ruleEngine := security.NewRuleEngine(log)

	t.Run("Rule Evaluation", func(t *testing.T) {
		requestInfo := &security.RequestInfo{
			ID:        "test-request",
			Method:    "POST",
			URL:       "https://example.com/api/search",
			IPAddress: "192.168.1.100",
			UserAgent: "Mozilla/5.0",
			Headers:   map[string]string{"Content-Type": "application/json"},
			Body:      `{"query": "SELECT * FROM users UNION SELECT password FROM admin"}`,
			Timestamp: time.Now(),
		}

		results := ruleEngine.EvaluateRequest(requestInfo)
		assert.NotEmpty(t, results)

		// Should match SQL injection rule
		sqlInjectionMatched := false
		for _, result := range results {
			if result.RuleID == "sql_injection_basic" && result.Matched {
				sqlInjectionMatched = true
				assert.Greater(t, result.Confidence, 0.0)
				assert.NotEmpty(t, result.Evidence)
			}
		}
		assert.True(t, sqlInjectionMatched, "SQL injection rule should have matched")
	})
}

func TestIntelligentRateLimiter(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "info",
		Output: "stdout",
	})
	require.NoError(t, err)

	rateLimiter := security.NewIntelligentRateLimiter(log)

	t.Run("Basic Rate Limiting", func(t *testing.T) {
		ipAddress := "192.168.1.100"

		// First 100 requests should be allowed
		for i := 0; i < 100; i++ {
			allowed := rateLimiter.IsAllowed(ipAddress)
			assert.True(t, allowed, "Request %d should be allowed", i+1)
		}

		// 101st request should be blocked
		allowed := rateLimiter.IsAllowed(ipAddress)
		assert.False(t, allowed, "Request 101 should be blocked")
	})

	t.Run("Adaptive Rate Limiting", func(t *testing.T) {
		ipAddress := "192.168.1.101"

		// Update adaptive limit based on high threat score
		rateLimiter.UpdateAdaptiveLimit(ipAddress, 0.8)

		// Should only allow 10 requests (100 * 0.1 adjustment factor)
		allowedCount := 0
		for i := 0; i < 20; i++ {
			if rateLimiter.IsAllowed(ipAddress) {
				allowedCount++
			}
		}

		assert.LessOrEqual(t, allowedCount, 10, "Should be limited to ~10 requests due to high threat score")
	})
}

func TestBlockListAllowList(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "info",
		Output: "stdout",
	})
	require.NoError(t, err)

	blockList := security.NewBlockList(log)
	allowList := security.NewAllowList(log)

	t.Run("Block List", func(t *testing.T) {
		ipAddress := "192.168.1.100"

		// Initially not blocked
		assert.False(t, blockList.IsBlocked(ipAddress))

		// Add to block list
		blockList.AddToBlockList(ipAddress, "Testing", 1*time.Hour)

		// Should now be blocked
		assert.True(t, blockList.IsBlocked(ipAddress))

		// Remove from block list
		blockList.RemoveFromBlockList(ipAddress)

		// Should no longer be blocked
		assert.False(t, blockList.IsBlocked(ipAddress))
	})

	t.Run("Allow List", func(t *testing.T) {
		ipAddress := "192.168.1.200"

		// Initially not explicitly allowed
		assert.False(t, allowList.IsAllowed(ipAddress))

		// Add to allow list
		allowList.AddToAllowList(ipAddress, "Trusted IP")

		// Should now be allowed
		assert.True(t, allowList.IsAllowed(ipAddress))
	})
}

func TestSessionTracker(t *testing.T) {
	log, err := logger.New(logger.Config{
		Level:  "info",
		Output: "stdout",
	})
	require.NoError(t, err)

	sessionTracker := security.NewSessionTracker(log)

	t.Run("Session Tracking", func(t *testing.T) {
		sessionID := "test-session-123"
		userID := "user-456"
		ipAddress := "192.168.1.100"
		userAgent := "Mozilla/5.0"

		// Track new session
		session := sessionTracker.TrackSession(sessionID, userID, ipAddress, userAgent)
		assert.NotNil(t, session)
		assert.Equal(t, sessionID, session.ID)
		assert.Equal(t, userID, session.UserID)
		assert.Equal(t, 1, session.RequestCount)

		// Track same session again
		session2 := sessionTracker.TrackSession(sessionID, userID, ipAddress, userAgent)
		assert.Equal(t, 2, session2.RequestCount)

		// Update threat score
		sessionTracker.UpdateSessionThreatScore(sessionID, 0.7)
		session3 := sessionTracker.GetSession(sessionID)
		assert.Equal(t, 0.7, session3.ThreatScore)
	})
}

// Helper function to create test HTTP requests
func createTestRequest(method, urlStr, body, ipAddress string) *http.Request {
	parsedURL, _ := url.Parse(urlStr)
	req := &http.Request{
		Method: method,
		URL:    parsedURL,
		Header: make(http.Header),
		Body:   nil,
	}

	if body != "" {
		req.Body = &testReadCloser{strings.NewReader(body)}
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; test)")
	req.RemoteAddr = ipAddress + ":12345"

	return req
}

// Helper type for request body
type testReadCloser struct {
	*strings.Reader
}

func (t *testReadCloser) Close() error {
	return nil
}
