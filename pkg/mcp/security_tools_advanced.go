package mcp

// Note: Imports removed as they are not used in this registration file
// This file only contains tool registration functions

// registerAdvancedSecurityTools registers advanced security-specific MCP tools
func (s *SecurityMCPServer) registerAdvancedSecurityTools() {
	// AI Security Assessment Tool
	s.tools["ai_security_assessment"] = SecurityTool{
		Name:        "ai_security_assessment",
		Description: "Comprehensive AI security assessment including prompt injection, jailbreak, and model safety",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"input": map[string]interface{}{
					"type":        "string",
					"description": "Input to assess for AI security threats",
				},
				"model_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of AI model being assessed",
					"enum":        []string{"llm", "vision", "multimodal", "embedding"},
				},
				"assessment_depth": map[string]interface{}{
					"type":        "string",
					"description": "Depth of security assessment",
					"enum":        []string{"basic", "comprehensive", "deep"},
					"default":     "comprehensive",
				},
				"context": map[string]interface{}{
					"type":        "object",
					"description": "Additional context for assessment",
				},
			},
			Required: []string{"input"},
		},
		Handler: s.handleAISecurityAssessment,
	}

	// Security Policy Validation Tool
	s.tools["security_policy_validation"] = SecurityTool{
		Name:        "security_policy_validation",
		Description: "Validate security policies and configurations against best practices",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"policy_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of security policy to validate",
					"enum":        []string{"access_control", "data_protection", "network_security", "application_security"},
				},
				"policy_content": map[string]interface{}{
					"type":        "string",
					"description": "Policy content to validate (JSON, YAML, or text)",
				},
				"framework": map[string]interface{}{
					"type":        "string",
					"description": "Security framework to validate against",
					"enum":        []string{"NIST", "ISO27001", "CIS", "OWASP", "custom"},
				},
				"validation_level": map[string]interface{}{
					"type":        "string",
					"description": "Level of validation to perform",
					"enum":        []string{"syntax", "semantic", "compliance", "best_practices"},
					"default":     "best_practices",
				},
			},
			Required: []string{"policy_type", "policy_content"},
		},
		Handler: s.handleSecurityPolicyValidation,
	}

	// Threat Modeling Tool
	s.tools["threat_modeling"] = SecurityTool{
		Name:        "threat_modeling",
		Description: "Perform automated threat modeling and risk assessment",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"system_description": map[string]interface{}{
					"type":        "string",
					"description": "Description of the system to model",
				},
				"architecture": map[string]interface{}{
					"type":        "object",
					"description": "System architecture details",
				},
				"assets": map[string]interface{}{
					"type":        "array",
					"description": "Critical assets to protect",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
				"threat_framework": map[string]interface{}{
					"type":        "string",
					"description": "Threat modeling framework to use",
					"enum":        []string{"STRIDE", "PASTA", "OCTAVE", "TRIKE", "VAST"},
					"default":     "STRIDE",
				},
				"scope": map[string]interface{}{
					"type":        "string",
					"description": "Scope of threat modeling",
					"enum":        []string{"application", "infrastructure", "data_flow", "full_system"},
					"default":     "application",
				},
			},
			Required: []string{"system_description"},
		},
		Handler: s.handleThreatModeling,
	}

	// Security Code Analysis Tool
	s.tools["security_code_analysis"] = SecurityTool{
		Name:        "security_code_analysis",
		Description: "Analyze code for security vulnerabilities and best practices",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"code": map[string]interface{}{
					"type":        "string",
					"description": "Source code to analyze",
				},
				"language": map[string]interface{}{
					"type":        "string",
					"description": "Programming language of the code",
					"enum":        []string{"python", "javascript", "java", "go", "rust", "c", "cpp", "csharp", "php"},
				},
				"analysis_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of security analysis to perform",
					"enum":        []string{"static", "dynamic", "interactive", "comprehensive"},
					"default":     "static",
				},
				"rules": map[string]interface{}{
					"type":        "array",
					"description": "Specific security rules to check",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
				"severity_threshold": map[string]interface{}{
					"type":        "string",
					"description": "Minimum severity level to report",
					"enum":        []string{"info", "low", "medium", "high", "critical"},
					"default":     "medium",
				},
			},
			Required: []string{"code", "language"},
		},
		Handler: s.handleSecurityCodeAnalysis,
	}

	// Penetration Testing Tool
	s.tools["penetration_testing"] = SecurityTool{
		Name:        "penetration_testing",
		Description: "Perform automated penetration testing and security assessment",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"target": map[string]interface{}{
					"type":        "string",
					"description": "Target system for penetration testing",
				},
				"test_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of penetration test",
					"enum":        []string{"web_app", "network", "wireless", "social_engineering", "physical"},
				},
				"methodology": map[string]interface{}{
					"type":        "string",
					"description": "Penetration testing methodology",
					"enum":        []string{"OWASP", "NIST", "PTES", "OSSTMM", "custom"},
					"default":     "OWASP",
				},
				"scope": map[string]interface{}{
					"type":        "array",
					"description": "Scope of testing (specific endpoints, services, etc.)",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
				"intensity": map[string]interface{}{
					"type":        "string",
					"description": "Testing intensity level",
					"enum":        []string{"passive", "active", "aggressive"},
					"default":     "active",
				},
				"authorization": map[string]interface{}{
					"type":        "object",
					"description": "Authorization details for testing",
				},
			},
			Required: []string{"target", "test_type", "authorization"},
		},
		Handler: s.handlePenetrationTesting,
	}

	// Security Metrics Analysis Tool
	s.tools["security_metrics_analysis"] = SecurityTool{
		Name:        "security_metrics_analysis",
		Description: "Analyze security metrics and generate insights",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"metrics_data": map[string]interface{}{
					"type":        "object",
					"description": "Security metrics data to analyze",
				},
				"time_range": map[string]interface{}{
					"type":        "object",
					"description": "Time range for analysis",
					"properties": map[string]interface{}{
						"start": map[string]interface{}{
							"type":        "string",
							"description": "Start time (ISO 8601)",
						},
						"end": map[string]interface{}{
							"type":        "string",
							"description": "End time (ISO 8601)",
						},
					},
				},
				"analysis_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of metrics analysis",
					"enum":        []string{"trend", "anomaly", "correlation", "prediction", "benchmark"},
					"default":     "trend",
				},
				"metrics_categories": map[string]interface{}{
					"type":        "array",
					"description": "Categories of metrics to analyze",
					"items": map[string]interface{}{
						"type": "string",
						"enum": []string{"threats", "vulnerabilities", "incidents", "compliance", "performance"},
					},
				},
			},
			Required: []string{"metrics_data"},
		},
		Handler: s.handleSecurityMetricsAnalysis,
	}

	// Risk Assessment Tool
	s.tools["risk_assessment"] = SecurityTool{
		Name:        "risk_assessment",
		Description: "Perform comprehensive security risk assessment",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"asset_inventory": map[string]interface{}{
					"type":        "array",
					"description": "Inventory of assets to assess",
					"items": map[string]interface{}{
						"type": "object",
					},
				},
				"threat_landscape": map[string]interface{}{
					"type":        "object",
					"description": "Current threat landscape information",
				},
				"vulnerability_data": map[string]interface{}{
					"type":        "object",
					"description": "Known vulnerabilities and exposures",
				},
				"risk_framework": map[string]interface{}{
					"type":        "string",
					"description": "Risk assessment framework to use",
					"enum":        []string{"NIST", "ISO27005", "OCTAVE", "FAIR", "custom"},
					"default":     "NIST",
				},
				"risk_appetite": map[string]interface{}{
					"type":        "string",
					"description": "Organization's risk appetite",
					"enum":        []string{"low", "medium", "high"},
					"default":     "medium",
				},
			},
			Required: []string{"asset_inventory"},
		},
		Handler: s.handleRiskAssessment,
	}
}
