package testing_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	securitytesting "github.com/dimajoyti/hackai/pkg/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockLogger implements the Logger interface for testing
type MockLogger struct {
	logs []LogEntry
}

type LogEntry struct {
	Level   string
	Message string
	Fields  map[string]interface{}
}

func (m *MockLogger) Info(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "info", Message: msg, Fields: m.parseFields(fields)})
}

func (m *MockLogger) Error(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "error", Message: msg, Fields: m.parseFields(fields)})
}

func (m *MockLogger) Warn(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "warn", Message: msg, Fields: m.parseFields(fields)})
}

func (m *MockLogger) Debug(msg string, fields ...interface{}) {
	m.logs = append(m.logs, LogEntry{Level: "debug", Message: msg, Fields: m.parseFields(fields)})
}

func (m *MockLogger) parseFields(fields []interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			result[key] = fields[i+1]
		}
	}
	return result
}

func TestSecurityTestingFramework(t *testing.T) {
	logger := &MockLogger{}

	config := &securitytesting.SecurityTestConfig{
		EnableVulnerabilityScanning: true,
		EnablePenetrationTesting:    true,
		EnableComplianceChecking:    true,
		EnableThreatModeling:        true,
		ScanDepth:                   "medium",
		MaxScanDuration:             30 * time.Second,
		TargetEndpoints:             []string{"http://localhost:8080"},
		ExcludedPaths:               []string{"/health", "/metrics"},
		AuthenticationTokens:        map[string]string{},
		ComplianceFrameworks:        []string{"OWASP", "NIST"},
	}

	t.Run("Create Security Testing Framework", func(t *testing.T) {
		framework := securitytesting.NewSecurityTestingFramework(config, logger)
		require.NotNil(t, framework)

		// Test basic functionality
		stats := framework.GetTestStatistics()
		assert.Equal(t, 0, stats["total_sessions"])
		assert.Equal(t, 0, stats["total_tests"])
	})

	t.Run("Start Test Session", func(t *testing.T) {
		framework := securitytesting.NewSecurityTestingFramework(config, logger)
		require.NotNil(t, framework)

		// Create test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Test Page</body></html>"))
		}))
		defer server.Close()

		// Start test session
		session, err := framework.StartTestSession("Test Session", server.URL, []string{"penetration"})
		require.NoError(t, err)
		require.NotNil(t, session)

		assert.Equal(t, "Test Session", session.Name)
		assert.Equal(t, server.URL, session.TargetURL)
		assert.Equal(t, []string{"penetration"}, session.TestSuites)
		assert.Equal(t, "running", session.Status)

		// Wait for session to complete
		time.Sleep(2 * time.Second)

		// Get updated session
		updatedSession, err := framework.GetTestSession(session.ID)
		require.NoError(t, err)
		assert.Equal(t, "completed", updatedSession.Status)
		assert.True(t, updatedSession.TotalTests > 0)
	})

	t.Run("List Test Sessions", func(t *testing.T) {
		framework := securitytesting.NewSecurityTestingFramework(config, logger)
		require.NotNil(t, framework)

		// Create test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer server.Close()

		// Start multiple test sessions
		session1, err := framework.StartTestSession("Session 1", server.URL, []string{"vulnerability"})
		require.NoError(t, err)

		session2, err := framework.StartTestSession("Session 2", server.URL, []string{"compliance"})
		require.NoError(t, err)

		// List sessions
		sessions := framework.ListTestSessions()
		assert.Len(t, sessions, 2)

		sessionIDs := make([]string, len(sessions))
		for i, session := range sessions {
			sessionIDs[i] = session.ID
		}

		assert.Contains(t, sessionIDs, session1.ID)
		assert.Contains(t, sessionIDs, session2.ID)
	})

	t.Run("Get Test Statistics", func(t *testing.T) {
		framework := securitytesting.NewSecurityTestingFramework(config, logger)
		require.NotNil(t, framework)

		// Create test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer server.Close()

		// Start test session
		_, err := framework.StartTestSession("Stats Test", server.URL, []string{"fuzzing"})
		require.NoError(t, err)

		// Wait for completion
		time.Sleep(1 * time.Second)

		// Get statistics
		stats := framework.GetTestStatistics()
		assert.Equal(t, 1, stats["total_sessions"])
		assert.True(t, stats["total_tests"].(int) >= 0)
		assert.True(t, stats["success_rate"].(float64) >= 0)
	})
}

func TestPenetrationTester(t *testing.T) {
	logger := &MockLogger{}
	config := securitytesting.DefaultPenetrationConfig()
	config.RequestTimeout = 5 * time.Second

	t.Run("Create Penetration Tester", func(t *testing.T) {
		tester := securitytesting.NewPenetrationTester(config, logger)
		require.NotNil(t, tester)
	})

	t.Run("Run SQL Injection Tests", func(t *testing.T) {
		tester := securitytesting.NewPenetrationTester(config, logger)
		require.NotNil(t, tester)

		// Create vulnerable test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query().Get("id")
			if query != "" && (query == "' OR '1'='1" || query == "'; DROP TABLE users; --") {
				// Simulate SQL error
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("SQL Error: syntax error"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		results := tester.RunTests(ctx, server.URL)
		assert.True(t, len(results) > 0)

		// Check for SQL injection test results
		sqlInjectionFound := false
		for _, result := range results {
			if result.Name == "SQL Injection Test" {
				sqlInjectionFound = true
				assert.Equal(t, securitytesting.TestStatusPassed, result.Status)
				break
			}
		}
		assert.True(t, sqlInjectionFound, "SQL injection test should be present")
	})

	t.Run("Run XSS Tests", func(t *testing.T) {
		tester := securitytesting.NewPenetrationTester(config, logger)
		require.NotNil(t, tester)

		// Create test server that reflects input
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query().Get("q")
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("<html><body>You searched for: %s</body></html>", query)))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		results := tester.RunTests(ctx, server.URL)
		assert.True(t, len(results) > 0)

		// Check for XSS test results
		xssFound := false
		for _, result := range results {
			if result.Name == "Cross-Site Scripting (XSS) Test" {
				xssFound = true
				assert.Equal(t, securitytesting.TestStatusPassed, result.Status)
				break
			}
		}
		assert.True(t, xssFound, "XSS test should be present")
	})
}

func TestVulnerabilityScanner(t *testing.T) {
	logger := &MockLogger{}
	config := securitytesting.DefaultVulnerabilityConfig()
	config.ScanTimeout = 5 * time.Second

	t.Run("Create Vulnerability Scanner", func(t *testing.T) {
		scanner := securitytesting.NewVulnerabilityScanner(config, logger)
		require.NotNil(t, scanner)
	})

	t.Run("Run Security Headers Scan", func(t *testing.T) {
		scanner := securitytesting.NewVulnerabilityScanner(config, logger)
		require.NotNil(t, scanner)

		// Create test server with missing security headers
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Don't set any security headers
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		results := scanner.RunScans(ctx, server.URL)
		assert.True(t, len(results) > 0)

		// Check for security headers scan results
		headersFound := false
		for _, result := range results {
			if result.Name == "Security Headers Scan" {
				headersFound = true
				assert.Equal(t, securitytesting.TestStatusPassed, result.Status)
				// Should find missing headers
				if result.Security != nil {
					assert.True(t, len(result.Security.Vulnerabilities) > 0)
				}
				break
			}
		}
		assert.True(t, headersFound, "Security headers scan should be present")
	})

	t.Run("Run Cookie Security Scan", func(t *testing.T) {
		scanner := securitytesting.NewVulnerabilityScanner(config, logger)
		require.NotNil(t, scanner)

		// Create test server with insecure cookies
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set insecure cookie
			cookie := &http.Cookie{
				Name:     "session",
				Value:    "test123",
				Secure:   false,
				HttpOnly: false,
				SameSite: http.SameSiteDefaultMode,
			}
			http.SetCookie(w, cookie)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		results := scanner.RunScans(ctx, server.URL)
		assert.True(t, len(results) > 0)

		// Check for cookie security scan results
		cookieFound := false
		for _, result := range results {
			if result.Name == "Cookie Security Scan" {
				cookieFound = true
				assert.Equal(t, securitytesting.TestStatusPassed, result.Status)
				// Should find insecure cookies
				if result.Security != nil {
					assert.True(t, len(result.Security.Vulnerabilities) > 0)
				}
				break
			}
		}
		assert.True(t, cookieFound, "Cookie security scan should be present")
	})

	t.Run("Run Technology Detection Scan", func(t *testing.T) {
		scanner := securitytesting.NewVulnerabilityScanner(config, logger)
		require.NotNil(t, scanner)

		// Create test server with technology headers
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "nginx/1.18.0")
			w.Header().Set("X-Powered-By", "PHP/7.4.0")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		results := scanner.RunScans(ctx, server.URL)
		assert.True(t, len(results) > 0)

		// Check for technology detection scan results
		techFound := false
		for _, result := range results {
			if result.Name == "Technology Detection Scan" {
				techFound = true
				assert.Equal(t, securitytesting.TestStatusPassed, result.Status)
				// Technology detection is informational, no vulnerabilities expected
				break
			}
		}
		assert.True(t, techFound, "Technology detection scan should be present")
	})
}

func TestComplianceTester(t *testing.T) {
	logger := &MockLogger{}
	config := &securitytesting.ComplianceConfig{
		Enabled:    true,
		Standards:  []string{"OWASP", "NIST"},
		Frameworks: []string{"SOC2", "ISO27001"},
	}

	t.Run("Create Compliance Tester", func(t *testing.T) {
		tester := securitytesting.NewComplianceTester(config, logger)
		require.NotNil(t, tester)
	})

	t.Run("Run Compliance Tests", func(t *testing.T) {
		tester := securitytesting.NewComplianceTester(config, logger)
		require.NotNil(t, tester)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		results := tester.RunTests(ctx, "http://example.com")
		assert.Len(t, results, 1)

		result := results[0]
		assert.Equal(t, "Basic Compliance Check", result.Name)
		assert.Equal(t, securitytesting.TestStatusPassed, result.Status)
	})
}

func TestFuzzTester(t *testing.T) {
	logger := &MockLogger{}
	config := &securitytesting.FuzzConfig{
		Enabled:      true,
		MaxPayloads:  50,
		PayloadTypes: []string{"random", "boundary", "malformed"},
	}

	t.Run("Create Fuzz Tester", func(t *testing.T) {
		tester := securitytesting.NewFuzzTester(config, logger)
		require.NotNil(t, tester)
	})

	t.Run("Run Fuzz Tests", func(t *testing.T) {
		tester := securitytesting.NewFuzzTester(config, logger)
		require.NotNil(t, tester)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		results := tester.RunTests(ctx, "http://example.com")
		assert.Len(t, results, 1)

		result := results[0]
		assert.Equal(t, "Basic Fuzz Test", result.Name)
		assert.Equal(t, securitytesting.TestStatusPassed, result.Status)
	})
}

func TestTestOrchestrator(t *testing.T) {
	logger := &MockLogger{}
	config := &securitytesting.SecurityTestConfig{
		EnableVulnerabilityScanning: true,
		EnablePenetrationTesting:    true,
		EnableComplianceChecking:    true,
		EnableThreatModeling:        true,
		ScanDepth:                   "medium",
		MaxScanDuration:             30 * time.Second,
		TargetEndpoints:             []string{"http://example.com"},
		ExcludedPaths:               []string{"/health", "/metrics"},
		AuthenticationTokens:        map[string]string{},
		ComplianceFrameworks:        []string{"OWASP", "NIST"},
	}

	t.Run("Create Test Orchestrator", func(t *testing.T) {
		orchestrator := securitytesting.NewTestOrchestrator(config, logger)
		require.NotNil(t, orchestrator)
	})
}
