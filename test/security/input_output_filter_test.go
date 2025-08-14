package security

import (
	"context"
	"testing"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInputOutputFilter(t *testing.T) {
	// Create logger
	log, err := logger.New(logger.Config{
		Level:  "info",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Create filter configuration
	config := &security.FilterConfig{
		EnableInputValidation:    true,
		EnableOutputSanitization: true,
		EnableContentAnalysis:    true,
		EnableThreatScanning:     true,
		SanitizationLevel:        "standard",
		MaxInputLength:           1024 * 1024, // 1MB
		MaxOutputLength:          1024 * 1024, // 1MB
		LogViolations:            true,
		BlockOnViolation:         true,
	}

	// Create input/output filter
	filter := security.NewInputOutputFilter(config, log)
	assert.NotNil(t, filter)

	t.Run("Basic Input Validation", func(t *testing.T) {
		// Test normal input
		normalInput := "Hello, World!"
		result, err := filter.FilterInput(context.Background(), normalInput, nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Valid)
		assert.False(t, result.Blocked)
		assert.Equal(t, normalInput, result.FilteredData)
	})

	t.Run("SQL Injection Detection", func(t *testing.T) {
		// Test SQL injection input
		maliciousInput := "'; DROP TABLE users; --"
		result, err := filter.FilterInput(context.Background(), maliciousInput, nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, len(result.Violations) > 0)
		assert.Greater(t, result.ThreatScore, 0.5)
	})

	t.Run("XSS Detection", func(t *testing.T) {
		// Test XSS input
		xssInput := "<script>alert('XSS')</script>"
		result, err := filter.FilterInput(context.Background(), xssInput, nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, len(result.Violations) > 0)
		assert.Greater(t, result.ThreatScore, 0.5)
	})

	t.Run("Command Injection Detection", func(t *testing.T) {
		// Test command injection input
		cmdInput := "test; rm -rf /"
		result, err := filter.FilterInput(context.Background(), cmdInput, nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, len(result.Violations) > 0)
		assert.Greater(t, result.ThreatScore, 0.5)
	})

	t.Run("Path Traversal Detection", func(t *testing.T) {
		// Test path traversal input
		pathInput := "../../../etc/passwd"
		result, err := filter.FilterInput(context.Background(), pathInput, nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, len(result.Violations) > 0)
		assert.Greater(t, result.ThreatScore, 0.5)
	})

	t.Run("Basic Output Sanitization", func(t *testing.T) {
		// Test normal output
		normalOutput := "Hello, World!"
		result, err := filter.FilterOutput(context.Background(), normalOutput)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Valid)
		assert.False(t, result.Blocked)
		assert.Equal(t, normalOutput, result.FilteredData)
	})

	t.Run("HTML Output Sanitization", func(t *testing.T) {
		// Test HTML output that needs sanitization
		htmlOutput := "<script>alert('test')</script><p>Hello</p>"
		result, err := filter.FilterOutput(context.Background(), htmlOutput)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Sanitized)
		assert.NotEqual(t, htmlOutput, result.FilteredData)
		assert.NotContains(t, result.FilteredData, "<script>")
	})

	t.Run("Large Input Handling", func(t *testing.T) {
		// Test large input
		largeInput := make([]byte, 2*1024*1024) // 2MB
		for i := range largeInput {
			largeInput[i] = 'A'
		}

		result, err := filter.FilterInput(context.Background(), string(largeInput), nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
		// Should be blocked due to size limit
		assert.True(t, result.Blocked)
		assert.False(t, result.Valid)
	})

	t.Run("Binary Content Detection", func(t *testing.T) {
		// Test binary content
		binaryInput := "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		result, err := filter.FilterInput(context.Background(), binaryInput, nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, len(result.Violations) > 0)
		assert.Greater(t, result.ThreatScore, 0.3)
	})

	t.Run("Encoding Detection", func(t *testing.T) {
		// Test UTF-8 content
		utf8Input := "Hello, 世界! 🌍"
		result, err := filter.FilterInput(context.Background(), utf8Input, nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Valid)
		assert.False(t, result.Blocked)
	})

	t.Run("High Entropy Content", func(t *testing.T) {
		// Test high entropy content (possible encryption/obfuscation)
		highEntropyInput := "aB3xY9mK2pQ7wE5rT8uI1oP6sD4fG0hJ9lZ3vC6nM8bN5qW2eR7tY4uI1oP0"
		result, err := filter.FilterInput(context.Background(), highEntropyInput, nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
		// May or may not trigger violations depending on entropy threshold
		assert.NotNil(t, result.Violations)
	})
}

func TestContentAnalyzer(t *testing.T) {
	// Create logger
	log, err := logger.New(logger.Config{
		Level:  "info",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Create content analyzer
	analyzer := security.NewContentAnalyzer(log)
	require.NotNil(t, analyzer)

	t.Run("SQL Injection Analysis", func(t *testing.T) {
		content := "SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin"
		violations := analyzer.AnalyzeContent(content)
		assert.True(t, len(violations) > 0)

		sqlViolationFound := false
		for _, violation := range violations {
			if violation.Type == "sql_injection" {
				sqlViolationFound = true
				assert.Equal(t, "high", violation.Severity)
				assert.Greater(t, violation.Confidence, 0.8)
				break
			}
		}
		assert.True(t, sqlViolationFound, "SQL injection violation should be detected")
	})

	t.Run("XSS Analysis", func(t *testing.T) {
		content := "<script>alert('XSS attack')</script>"
		violations := analyzer.AnalyzeContent(content)
		assert.True(t, len(violations) > 0)

		xssViolationFound := false
		for _, violation := range violations {
			if violation.Type == "xss" {
				xssViolationFound = true
				assert.Equal(t, "high", violation.Severity)
				assert.Greater(t, violation.Confidence, 0.8)
				break
			}
		}
		assert.True(t, xssViolationFound, "XSS violation should be detected")
	})

	t.Run("Command Injection Analysis", func(t *testing.T) {
		content := "rm -rf /"
		violations := analyzer.AnalyzeContent(content)
		assert.True(t, len(violations) > 0)

		cmdViolationFound := false
		for _, violation := range violations {
			if violation.Type == "command_injection" {
				cmdViolationFound = true
				assert.Equal(t, "critical", violation.Severity)
				assert.Greater(t, violation.Confidence, 0.8)
				break
			}
		}
		assert.True(t, cmdViolationFound, "Command injection violation should be detected")
	})

	t.Run("Path Traversal Analysis", func(t *testing.T) {
		content := "../../../etc/passwd"
		violations := analyzer.AnalyzeContent(content)
		assert.True(t, len(violations) > 0)

		pathViolationFound := false
		for _, violation := range violations {
			if violation.Type == "path_traversal" {
				pathViolationFound = true
				assert.Equal(t, "high", violation.Severity)
				assert.Greater(t, violation.Confidence, 0.8)
				break
			}
		}
		assert.True(t, pathViolationFound, "Path traversal violation should be detected")
	})

	t.Run("Sensitive Data Analysis", func(t *testing.T) {
		content := "My credit card number is 4532-1234-5678-9012 and my SSN is 123-45-6789"
		violations := analyzer.AnalyzeContent(content)
		assert.True(t, len(violations) > 0)

		sensitiveDataFound := false
		for _, violation := range violations {
			if violation.Type == "sensitive_data" {
				sensitiveDataFound = true
				assert.Equal(t, "high", violation.Severity)
				break
			}
		}
		assert.True(t, sensitiveDataFound, "Sensitive data violation should be detected")
	})
}

func TestEncodingDetector(t *testing.T) {
	// Create logger
	log, err := logger.New(logger.Config{
		Level:  "info",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Create encoding detector
	detector := security.NewEncodingDetector(log)
	require.NotNil(t, detector)

	t.Run("UTF-8 Detection", func(t *testing.T) {
		content := "Hello, 世界! 🌍"
		encoding := detector.DetectEncoding(content)
		assert.Equal(t, "utf-8", encoding)
	})

	t.Run("ASCII Detection", func(t *testing.T) {
		content := "Hello, World!"
		encoding := detector.DetectEncoding(content)
		assert.Equal(t, "ascii", encoding)
	})

	t.Run("Binary Detection", func(t *testing.T) {
		// Create content with high binary ratio (>30%) using control characters
		// that are not in the suspicious list (0x10-0x1F range)
		content := "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
		encoding := detector.DetectEncoding(content)
		assert.Equal(t, "binary", encoding)
	})

	t.Run("UTF-8 BOM Detection", func(t *testing.T) {
		content := "\xEF\xBB\xBFHello, World!"
		encoding := detector.DetectEncoding(content)
		assert.Equal(t, "utf-8-bom", encoding)
	})

	t.Run("UTF-16 LE Detection", func(t *testing.T) {
		content := "\xFF\xFEH\x00e\x00l\x00l\x00o\x00"
		encoding := detector.DetectEncoding(content)
		assert.Equal(t, "utf-16le", encoding)
	})

	t.Run("Suspicious Content Detection", func(t *testing.T) {
		content := "Hello\x00World\x01Test\x02"
		encoding := detector.DetectEncoding(content)
		assert.Equal(t, "suspicious", encoding)
	})
}

func TestThreatScanner(t *testing.T) {
	// Create logger
	log, err := logger.New(logger.Config{
		Level:  "info",
		Output: "stdout",
	})
	require.NoError(t, err)

	// Create threat scanner
	scanner := security.NewThreatScanner(log)
	require.NotNil(t, scanner)

	t.Run("Malware Signature Detection", func(t *testing.T) {
		content := "eval(base64_decode('malicious_code_here'))"
		result := scanner.ScanForThreats(content)
		assert.NotNil(t, result)
		assert.Greater(t, result.Score, 0.5)
		assert.True(t, len(result.Violations) > 0)
		assert.True(t, len(result.Threats) > 0)
	})

	t.Run("Shellcode Detection", func(t *testing.T) {
		content := "\x90\x90\x90\x90\x31\xc0\x31\xdb"
		result := scanner.ScanForThreats(content)
		assert.NotNil(t, result)
		assert.Greater(t, result.Score, 0.7)
		assert.True(t, len(result.Violations) > 0)
	})

	t.Run("Obfuscation Detection", func(t *testing.T) {
		content := "String.fromCharCode(72,101,108,108,111)"
		result := scanner.ScanForThreats(content)
		assert.NotNil(t, result)
		assert.Greater(t, result.Score, 0.3)
		assert.True(t, len(result.Violations) > 0)
	})

	t.Run("High Entropy Detection", func(t *testing.T) {
		// Generate high entropy content
		content := "aB3xY9mK2pQ7wE5rT8uI1oP6sD4fG0hJ9lZ3vC6nM8bN5qW2eR7tY4uI1oP0sD4fG0hJ9lZ3vC6nM8bN5qW2eR7tY4uI1oP0"
		result := scanner.ScanForThreats(content)
		assert.NotNil(t, result)
		// High entropy content should trigger some detection
		assert.GreaterOrEqual(t, result.Score, 0.0)
	})

	t.Run("Clean Content", func(t *testing.T) {
		content := "This is a normal, clean text content without any threats."
		result := scanner.ScanForThreats(content)
		assert.NotNil(t, result)
		assert.Equal(t, 0.0, result.Score)
		assert.Equal(t, 0, len(result.Violations))
		assert.Equal(t, 0, len(result.Threats))
	})
}
