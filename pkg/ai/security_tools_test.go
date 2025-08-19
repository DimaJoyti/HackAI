package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dimajoyti/hackai/pkg/logger"
)

func TestSecurityScannerTool_Execute(t *testing.T) {
	// Create a proper logger for testing
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	tool := NewSecurityScannerTool(testLogger)
	require.NotNil(t, tool)

	t.Run("basic security scan", func(t *testing.T) {
		input := ToolInput{
			"target":    "localhost",
			"scan_type": "quick",
		}

		output, err := tool.Execute(context.Background(), input)
		require.NoError(t, err)
		require.NotNil(t, output)

		assert.Contains(t, output, "vulnerabilities")
		assert.Contains(t, output, "open_ports")
		assert.Contains(t, output, "scan_summary")

		vulnerabilities, ok := output["vulnerabilities"].([]map[string]interface{})
		assert.True(t, ok)
		assert.NotNil(t, vulnerabilities)

		openPorts, ok := output["open_ports"].([]map[string]interface{})
		assert.True(t, ok)
		assert.NotNil(t, openPorts)

		summary, ok := output["scan_summary"].(map[string]interface{})
		assert.True(t, ok)
		assert.Contains(t, summary, "target")
		assert.Contains(t, summary, "scan_type")
		assert.Contains(t, summary, "risk_level")
	})

	t.Run("comprehensive scan", func(t *testing.T) {
		input := ToolInput{
			"target":    "example.com",
			"scan_type": "comprehensive",
			"ports":     "1-1000",
			"timeout":   300,
		}

		output, err := tool.Execute(context.Background(), input)
		require.NoError(t, err)

		vulnerabilities := output["vulnerabilities"].([]map[string]interface{})
		assert.Greater(t, len(vulnerabilities), 0) // Comprehensive scan should find vulnerabilities

		summary := output["scan_summary"].(map[string]interface{})
		assert.Equal(t, "example.com", summary["target"])
		assert.Equal(t, "comprehensive", summary["scan_type"])
	})

	t.Run("deep scan", func(t *testing.T) {
		input := ToolInput{
			"target":    "test.local",
			"scan_type": "deep",
		}

		output, err := tool.Execute(context.Background(), input)
		require.NoError(t, err)

		vulnerabilities := output["vulnerabilities"].([]map[string]interface{})
		assert.Greater(t, len(vulnerabilities), 1) // Deep scan should find more vulnerabilities
	})

	t.Run("invalid input", func(t *testing.T) {
		input := ToolInput{
			"invalid": "input",
		}

		_, err := tool.Execute(context.Background(), input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "target")
	})
}

func TestSecurityScannerTool_VulnerabilityDetection(t *testing.T) {
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	tool := NewSecurityScannerTool(testLogger)

	t.Run("vulnerability simulation", func(t *testing.T) {
		vulnerabilities := tool.simulateVulnerabilityScanning("test.com", "comprehensive")

		assert.Greater(t, len(vulnerabilities), 0)

		for _, vuln := range vulnerabilities {
			assert.Contains(t, vuln, "id")
			assert.Contains(t, vuln, "title")
			assert.Contains(t, vuln, "severity")
			assert.Contains(t, vuln, "description")
			assert.Contains(t, vuln, "location")
			assert.Contains(t, vuln, "confidence")

			confidence, ok := vuln["confidence"].(float64)
			assert.True(t, ok)
			assert.GreaterOrEqual(t, confidence, 0.0)
			assert.LessOrEqual(t, confidence, 1.0)
		}
	})

	t.Run("port scanning simulation", func(t *testing.T) {
		openPorts := tool.simulatePortScanning("test.com")

		assert.Greater(t, len(openPorts), 0)

		for _, port := range openPorts {
			assert.Contains(t, port, "port")
			assert.Contains(t, port, "protocol")
			assert.Contains(t, port, "service")
			assert.Contains(t, port, "state")

			portNum, ok := port["port"].(int)
			assert.True(t, ok)
			assert.Greater(t, portNum, 0)
			assert.LessOrEqual(t, portNum, 65535)
		}
	})

	t.Run("risk level calculation", func(t *testing.T) {
		// Test with no vulnerabilities
		noVulns := []map[string]interface{}{}
		risk := tool.calculateRiskLevel(noVulns)
		assert.Equal(t, "low", risk)

		// Test with high severity vulnerabilities
		highVulns := []map[string]interface{}{
			{"severity": "high"},
			{"severity": "critical"},
		}
		risk = tool.calculateRiskLevel(highVulns)
		assert.Equal(t, "high", risk)

		// Test with medium severity vulnerabilities
		mediumVulns := []map[string]interface{}{
			{"severity": "medium"},
			{"severity": "medium"},
			{"severity": "medium"},
		}
		risk = tool.calculateRiskLevel(mediumVulns)
		assert.Equal(t, "medium", risk)
	})
}

func TestPenetrationTesterTool_Execute(t *testing.T) {
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	tool := NewPenetrationTesterTool(testLogger)
	require.NotNil(t, tool)

	t.Run("web application penetration test", func(t *testing.T) {
		input := ToolInput{
			"target":      "localhost",
			"attack_type": "web_app",
			"intensity":   "medium",
		}

		output, err := tool.Execute(context.Background(), input)
		require.NoError(t, err)
		require.NotNil(t, output)

		assert.Contains(t, output, "exploits_found")
		assert.Contains(t, output, "attack_vectors")
		assert.Contains(t, output, "recommendations")

		exploits, ok := output["exploits_found"].([]map[string]interface{})
		assert.True(t, ok)
		assert.NotNil(t, exploits)

		attackVectors, ok := output["attack_vectors"].([]map[string]interface{})
		assert.True(t, ok)
		assert.Greater(t, len(attackVectors), 0)

		recommendations, ok := output["recommendations"].([]string)
		assert.True(t, ok)
		assert.Greater(t, len(recommendations), 0)
	})

	t.Run("high intensity test", func(t *testing.T) {
		input := ToolInput{
			"target":      "test.local",
			"attack_type": "web_app",
			"intensity":   "high",
		}

		output, err := tool.Execute(context.Background(), input)
		require.NoError(t, err)

		exploits := output["exploits_found"].([]map[string]interface{})
		assert.Greater(t, len(exploits), 1) // High intensity should find more exploits
	})

	t.Run("network penetration test", func(t *testing.T) {
		input := ToolInput{
			"target":      "192.168.1.1",
			"attack_type": "network",
			"intensity":   "medium",
		}

		output, err := tool.Execute(context.Background(), input)
		require.NoError(t, err)

		attackVectors := output["attack_vectors"].([]map[string]interface{})

		// Check for network-specific attack vectors
		found := false
		for _, vector := range attackVectors {
			if name, ok := vector["name"].(string); ok {
				if name == "Port Scanning" || name == "Service Enumeration" {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "Should include network-specific attack vectors")
	})

	t.Run("invalid input", func(t *testing.T) {
		input := ToolInput{
			"invalid": "input",
		}

		_, err := tool.Execute(context.Background(), input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "target")
	})
}

func TestPenetrationTesterTool_ExploitSimulation(t *testing.T) {
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	tool := NewPenetrationTesterTool(testLogger)

	t.Run("exploit simulation", func(t *testing.T) {
		exploits := tool.simulatePenetrationTesting("test.com", "web_app", "high")

		assert.Greater(t, len(exploits), 0)

		for _, exploit := range exploits {
			assert.Contains(t, exploit, "exploit_id")
			assert.Contains(t, exploit, "name")
			assert.Contains(t, exploit, "success")
			assert.Contains(t, exploit, "impact")
			assert.Contains(t, exploit, "description")

			success, ok := exploit["success"].(bool)
			assert.True(t, ok)
			assert.True(t, success) // Simulated exploits should be successful
		}
	})

	t.Run("attack vectors", func(t *testing.T) {
		vectors := tool.getAttackVectors("web_app")

		assert.Greater(t, len(vectors), 0)

		for _, vector := range vectors {
			assert.Contains(t, vector, "name")
			assert.Contains(t, vector, "tested")
			assert.Contains(t, vector, "success")
		}
	})

	t.Run("recommendations generation", func(t *testing.T) {
		exploits := []map[string]interface{}{
			{
				"name":    "SQL Injection Bypass",
				"success": true,
			},
			{
				"name":    "Directory Traversal",
				"success": true,
			},
		}

		recommendations := tool.generateRecommendations(exploits)

		assert.Greater(t, len(recommendations), 0)

		// Check for specific recommendations based on exploits
		foundSQL := false
		foundTraversal := false
		for _, rec := range recommendations {
			if strings.Contains(strings.ToLower(rec), "sql") {
				foundSQL = true
			}
			if strings.Contains(strings.ToLower(rec), "traversal") || strings.Contains(strings.ToLower(rec), "file") {
				foundTraversal = true
			}
		}

		assert.True(t, foundSQL, "Should include SQL injection recommendations")
		assert.True(t, foundTraversal, "Should include directory traversal recommendations")
	})
}

func TestSecurityTools_ToolInterface(t *testing.T) {
	testLogger, err := logger.New(logger.Config{
		Level:  logger.LevelInfo,
		Format: "text",
		Output: "stdout",
	})
	require.NoError(t, err)

	t.Run("security scanner tool interface", func(t *testing.T) {
		tool := NewSecurityScannerTool(testLogger)

		assert.Equal(t, "security_scanner", tool.Name())
		assert.NotEmpty(t, tool.Description())
		assert.True(t, tool.IsHealthy(context.Background()))

		schema := tool.GetSchema()
		assert.Equal(t, "security_scanner", schema.Name)
		assert.NotEmpty(t, schema.InputSchema)
		assert.NotEmpty(t, schema.OutputSchema)
	})

	t.Run("penetration tester tool interface", func(t *testing.T) {
		tool := NewPenetrationTesterTool(testLogger)

		assert.Equal(t, "penetration_tester", tool.Name())
		assert.NotEmpty(t, tool.Description())
		assert.True(t, tool.IsHealthy(context.Background()))

		schema := tool.GetSchema()
		assert.Equal(t, "penetration_tester", schema.Name)
		assert.NotEmpty(t, schema.InputSchema)
		assert.NotEmpty(t, schema.OutputSchema)
	})
}
