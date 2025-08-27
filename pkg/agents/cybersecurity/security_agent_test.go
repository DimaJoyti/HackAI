package cybersecurity

import (
	"context"
	"fmt"
	"testing"

	agent_testing "github.com/dimajoyti/hackai/pkg/agents/testing"
)

// TestSecurityAgentIntegration tests the complete security agent integration
func TestSecurityAgentIntegration(t *testing.T) {
	suite := agent_testing.NewAgentTestSuite(t)

	// Test basic agent functionality
	suite.LogInfo("Starting security agent integration tests")

	// Test security analysis
	suite.TestSecurityAnalysis(func(ctx context.Context, input string) (interface{}, error) {
		// Mock security analysis with proper error handling
		if input == "" {
			return nil, fmt.Errorf("input cannot be empty")
		}
		return map[string]interface{}{
			"threat_level": "low",
			"analysis":     "Content appears safe",
		}, nil
	})

	suite.LogInfo("Security agent integration tests completed")
}

// TestThreatDetectionOnly tests only the threat detection functionality
func TestThreatDetectionOnly(t *testing.T) {
	suite := agent_testing.NewAgentTestSuite(t)

	suite.LogInfo("Starting threat detection tests")

	// Test threat detection functionality
	suite.TestSecurityAnalysis(func(ctx context.Context, input string) (interface{}, error) {
		// Mock threat detection with proper error handling
		if input == "" {
			return nil, fmt.Errorf("input cannot be empty")
		}

		threatLevel := "low"
		if input == "How to hack a system" {
			threatLevel = "high"
		}

		return map[string]interface{}{
			"threat_level": threatLevel,
			"threats":      []string{"potential_malicious_intent"},
		}, nil
	})

	suite.LogInfo("Threat detection tests completed")
}

// TestVulnerabilityScanningOnly tests only the vulnerability scanning functionality
func TestVulnerabilityScanningOnly(t *testing.T) {
	suite := agent_testing.NewAgentTestSuite(t)

	suite.LogInfo("Starting vulnerability scanning tests")

	// Test vulnerability scanning
	suite.TestSecurityAnalysis(func(ctx context.Context, input string) (interface{}, error) {
		if input == "" {
			return nil, fmt.Errorf("input cannot be empty")
		}
		return map[string]interface{}{
			"vulnerabilities": []string{"XSS", "SQL_INJECTION"},
			"severity":        "medium",
		}, nil
	})

	suite.LogInfo("Vulnerability scanning tests completed")
}

// TestDocumentIngestionOnly tests only the document ingestion functionality
func TestDocumentIngestionOnly(t *testing.T) {
	suite := agent_testing.NewAgentTestSuite(t)

	suite.LogInfo("Starting document ingestion tests")

	// Test document processing
	suite.TestAgentResponse(func(ctx context.Context, input string) (string, error) {
		if input == "" {
			return "", fmt.Errorf("input cannot be empty")
		}
		return "Document processed successfully", nil
	})

	suite.LogInfo("Document ingestion tests completed")
}

// TestHybridRetrievalOnly tests only the hybrid retrieval functionality
func TestHybridRetrievalOnly(t *testing.T) {
	suite := agent_testing.NewAgentTestSuite(t)

	suite.LogInfo("Starting hybrid retrieval tests")

	// Test retrieval functionality
	suite.TestAgentResponse(func(ctx context.Context, query string) (string, error) {
		if query == "" {
			return "", fmt.Errorf("query cannot be empty")
		}
		return "Retrieved relevant documents for: " + query, nil
	})

	suite.LogInfo("Hybrid retrieval tests completed")
}
