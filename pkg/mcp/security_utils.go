package mcp

import (
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/security"
)

// Constants for security references
const (
	OWASPAITop10URL = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
)

// extractSecurityContext extracts SecurityContext from a map
func extractSecurityContext(contextData map[string]interface{}) SecurityContext {
	secCtx := SecurityContext{
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	if userID, ok := contextData["user_id"].(string); ok {
		secCtx.UserID = userID
	}

	if sessionID, ok := contextData["session_id"].(string); ok {
		secCtx.SessionID = sessionID
	}

	if ipAddress, ok := contextData["ip_address"].(string); ok {
		secCtx.IPAddress = ipAddress
	}

	if userAgent, ok := contextData["user_agent"].(string); ok {
		secCtx.UserAgent = userAgent
	}

	if permissions, ok := contextData["permissions"].([]interface{}); ok {
		secCtx.Permissions = make([]string, len(permissions))
		for i, perm := range permissions {
			if permStr, ok := perm.(string); ok {
				secCtx.Permissions[i] = permStr
			}
		}
	}

	if metadata, ok := contextData["metadata"].(map[string]interface{}); ok {
		secCtx.Metadata = metadata
	}

	return secCtx
}

// determineThreatLevel determines threat level based on score
func determineThreatLevel(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.5:
		return "medium"
	case score >= 0.3:
		return "low"
	default:
		return "none"
	}
}

// convertAnalysisToFindings converts security analysis results to SecurityFinding slice
func convertAnalysisToFindings(analysis *security.SecurityAnalysis) []SecurityFinding {
	if analysis == nil {
		return []SecurityFinding{}
	}

	findings := make([]SecurityFinding, 0)

	// Convert threat detections to findings
	for _, threat := range analysis.Threats {
		finding := SecurityFinding{
			ID:          threat.ID,
			Type:        threat.Type,
			Severity:    threat.Severity,
			Title:       fmt.Sprintf("Security Threat: %s", threat.Type),
			Description: threat.Description,
			Evidence:    []string{threat.Description},
			Remediation: "Review and address the identified security threat",
			References:  []string{OWASPAITop10URL},
			Metadata: map[string]interface{}{
				"confidence":  threat.Confidence,
				"detected_at": threat.DetectedAt,
				"threat_id":   threat.ID,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// Note: Legacy convertToFindings function removed due to incompatible types
// Use convertAnalysisToFindings instead for SecurityAnalysis results

// convertVulnerabilitiesToFindings converts vulnerability results to SecurityFinding slice
func convertVulnerabilitiesToFindings(vulnerabilities []security.Vulnerability) []SecurityFinding {
	findings := make([]SecurityFinding, 0, len(vulnerabilities))

	for _, vuln := range vulnerabilities {
		finding := SecurityFinding{
			ID:          vuln.ID,
			Type:        "vulnerability",
			Severity:    vuln.Severity,
			Title:       fmt.Sprintf("Vulnerability: %s", vuln.ID),
			Description: vuln.Description,
			Evidence:    []string{vuln.Description},
			Remediation: "Apply security patches and follow best practices",
			References:  []string{},
			Metadata: map[string]interface{}{
				"vulnerability_id": vuln.ID,
				"severity":         vuln.Severity,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// determineSeverity determines severity based on confidence score
func determineSeverity(confidence float64) string {
	switch {
	case confidence >= 0.9:
		return "critical"
	case confidence >= 0.7:
		return "high"
	case confidence >= 0.5:
		return "medium"
	case confidence >= 0.3:
		return "low"
	default:
		return "info"
	}
}

// validateToolParameters validates common tool parameters
func validateToolParameters(params map[string]interface{}, required []string) error {
	for _, param := range required {
		if _, exists := params[param]; !exists {
			return &MCPError{
				Code:    ErrorCodeInvalidParams,
				Message: "Missing required parameter: " + param,
			}
		}
	}
	return nil
}

// createOperationResult creates a standardized operation result
func createOperationResult(operationID, operationType, status string, data interface{}) map[string]interface{} {
	return map[string]interface{}{
		"operation_id":   operationID,
		"operation_type": operationType,
		"status":         status,
		"data":           data,
		"timestamp":      time.Now(),
	}
}

// createErrorResult creates a standardized error result
func createErrorResult(message string, details interface{}) *CallToolResult {
	return &CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: message,
		}},
		IsError: true,
	}
}

// createSuccessResult creates a standardized success result
func createSuccessResult(message string, data interface{}) *CallToolResult {
	content := []ToolContent{{
		Type: "text",
		Text: message,
	}}

	if data != nil {
		if dataStr, ok := data.(string); ok {
			content = append(content, ToolContent{
				Type: "text",
				Text: dataStr,
			})
		} else {
			content = append(content, ToolContent{
				Type: "text",
				Data: data,
			})
		}
	}

	return &CallToolResult{
		Content: content,
		IsError: false,
	}
}

// sanitizeInput sanitizes input for security analysis
func sanitizeInput(input string) string {
	// Basic input sanitization
	// In a real implementation, this would be more comprehensive
	if len(input) > 10000 {
		return input[:10000] + "... [truncated]"
	}
	return input
}

// generateSecurityRecommendations generates security recommendations based on findings
func generateSecurityRecommendations(findings []SecurityFinding) []string {
	recommendations := make([]string, 0)

	// Track recommendation types to avoid duplicates
	recTypes := make(map[string]bool)

	for _, finding := range findings {
		switch finding.Type {
		case "prompt_injection":
			if !recTypes["input_validation"] {
				recommendations = append(recommendations, "Implement comprehensive input validation and sanitization")
				recTypes["input_validation"] = true
			}
		case "jailbreak":
			if !recTypes["safety_guardrails"] {
				recommendations = append(recommendations, "Strengthen safety guardrails and content filtering")
				recTypes["safety_guardrails"] = true
			}
		case "toxic_content":
			if !recTypes["content_moderation"] {
				recommendations = append(recommendations, "Deploy advanced content moderation systems")
				recTypes["content_moderation"] = true
			}
		case "data_extraction":
			if !recTypes["data_protection"] {
				recommendations = append(recommendations, "Implement data loss prevention and access controls")
				recTypes["data_protection"] = true
			}
		case "social_engineering":
			if !recTypes["user_training"] {
				recommendations = append(recommendations, "Provide security awareness training for users")
				recTypes["user_training"] = true
			}
		}
	}

	// Add general recommendations if no specific ones were added
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Continue monitoring for security threats")
		recommendations = append(recommendations, "Regularly update security policies and procedures")
	}

	return recommendations
}

// calculateRiskScore calculates overall risk score from findings
func calculateRiskScore(findings []SecurityFinding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			totalScore += 1.0
		case "high":
			totalScore += 0.8
		case "medium":
			totalScore += 0.6
		case "low":
			totalScore += 0.4
		case "info":
			totalScore += 0.2
		}
	}

	// Normalize score based on number of findings
	avgScore := totalScore / float64(len(findings))

	// Apply diminishing returns for multiple findings
	multiplier := 1.0 - (1.0 / (1.0 + float64(len(findings))*0.1))

	return avgScore * multiplier
}

// convertVulnerabilityMapsToFindings converts vulnerability maps to SecurityFinding slice
func convertVulnerabilityMapsToFindings(vulnerabilities []map[string]interface{}) []SecurityFinding {
	findings := make([]SecurityFinding, 0, len(vulnerabilities))

	for _, vuln := range vulnerabilities {
		// Extract values from the map with safe type assertions
		id, _ := vuln["id"].(string)
		if id == "" {
			id = fmt.Sprintf("vuln-%d", time.Now().UnixNano())
		}

		severity, _ := vuln["severity"].(string)
		if severity == "" {
			severity = "medium"
		}

		title, _ := vuln["title"].(string)
		if title == "" {
			title = fmt.Sprintf("Vulnerability: %s", id)
		}

		description, _ := vuln["description"].(string)
		if description == "" {
			description = title
		}

		vulnType, _ := vuln["type"].(string)
		if vulnType == "" {
			vulnType = "vulnerability"
		}

		finding := SecurityFinding{
			ID:          id,
			Type:        vulnType,
			Severity:    severity,
			Title:       title,
			Description: description,
			Evidence:    []string{description},
			Remediation: "Apply security patches and follow best practices",
			References:  []string{},
			Metadata: map[string]interface{}{
				"vulnerability_id": id,
				"severity":         severity,
				"original_data":    vuln,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}
