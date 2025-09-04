package mcp

// Note: Imports removed as they are not used in this registry file
// This file only contains tool registry management functions

// SecurityToolsRegistry manages all security-specific MCP tools
type SecurityToolsRegistry struct {
	tools map[string]SecurityTool
}

// NewSecurityToolsRegistry creates a new security tools registry
func NewSecurityToolsRegistry() *SecurityToolsRegistry {
	return &SecurityToolsRegistry{
		tools: make(map[string]SecurityTool),
	}
}

// RegisterAllSecurityTools registers all available security tools
func (s *SecurityMCPServer) RegisterAllSecurityTools() {
	// Core security tools
	s.registerCoreSecurityTools()
	
	// Advanced security tools
	s.registerAdvancedSecurityTools()
	
	// Specialized security tools
	s.registerSpecializedSecurityTools()
	
	// AI-specific security tools
	s.registerAISecurityTools()
}

// registerCoreSecurityTools registers core security tools
func (s *SecurityMCPServer) registerCoreSecurityTools() {
	// Threat Analysis Tool (already exists)
	// Vulnerability Scan Tool (already exists)
	// Compliance Check Tool (already exists)
	// Incident Response Tool (already exists)
	// Threat Intelligence Tool (already exists)
}

// registerSpecializedSecurityTools registers specialized security tools
func (s *SecurityMCPServer) registerSpecializedSecurityTools() {
	// Security Audit Tool
	s.tools["security_audit"] = SecurityTool{
		Name:        "security_audit",
		Description: "Perform comprehensive security audit of systems and applications",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"audit_scope": map[string]interface{}{
					"type":        "string",
					"description": "Scope of the security audit",
					"enum":        []string{"infrastructure", "application", "network", "data", "comprehensive"},
				},
				"audit_standards": map[string]interface{}{
					"type":        "array",
					"description": "Security standards to audit against",
					"items": map[string]interface{}{
						"type": "string",
						"enum": []string{"ISO27001", "NIST", "SOC2", "PCI-DSS", "HIPAA", "GDPR"},
					},
				},
				"target_systems": map[string]interface{}{
					"type":        "array",
					"description": "Target systems for audit",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
				"audit_depth": map[string]interface{}{
					"type":        "string",
					"description": "Depth of audit analysis",
					"enum":        []string{"surface", "detailed", "comprehensive"},
					"default":     "detailed",
				},
			},
			Required: []string{"audit_scope"},
		},
		Handler: s.handleSecurityAudit,
	}

	// Security Configuration Assessment Tool
	s.tools["security_config_assessment"] = SecurityTool{
		Name:        "security_config_assessment",
		Description: "Assess security configurations and hardening status",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"config_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of configuration to assess",
					"enum":        []string{"server", "database", "network", "application", "cloud"},
				},
				"config_data": map[string]interface{}{
					"type":        "object",
					"description": "Configuration data to assess",
				},
				"baseline": map[string]interface{}{
					"type":        "string",
					"description": "Security baseline to compare against",
					"enum":        []string{"CIS", "NIST", "OWASP", "custom"},
					"default":     "CIS",
				},
				"severity_filter": map[string]interface{}{
					"type":        "string",
					"description": "Minimum severity level to report",
					"enum":        []string{"info", "low", "medium", "high", "critical"},
					"default":     "medium",
				},
			},
			Required: []string{"config_type", "config_data"},
		},
		Handler: s.handleSecurityConfigAssessment,
	}

	// Security Training Assessment Tool
	s.tools["security_training_assessment"] = SecurityTool{
		Name:        "security_training_assessment",
		Description: "Assess security awareness and training effectiveness",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"assessment_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of training assessment",
					"enum":        []string{"phishing_simulation", "security_quiz", "scenario_based", "comprehensive"},
				},
				"target_audience": map[string]interface{}{
					"type":        "string",
					"description": "Target audience for assessment",
					"enum":        []string{"all_users", "developers", "administrators", "executives", "custom"},
				},
				"difficulty_level": map[string]interface{}{
					"type":        "string",
					"description": "Difficulty level of assessment",
					"enum":        []string{"beginner", "intermediate", "advanced", "expert"},
					"default":     "intermediate",
				},
				"topics": map[string]interface{}{
					"type":        "array",
					"description": "Security topics to cover",
					"items": map[string]interface{}{
						"type": "string",
						"enum": []string{"phishing", "malware", "social_engineering", "data_protection", "incident_response"},
					},
				},
			},
			Required: []string{"assessment_type", "target_audience"},
		},
		Handler: s.handleSecurityTrainingAssessment,
	}
}

// registerAISecurityTools registers AI-specific security tools
func (s *SecurityMCPServer) registerAISecurityTools() {
	// AI Model Security Scanner
	s.tools["ai_model_security_scan"] = SecurityTool{
		Name:        "ai_model_security_scan",
		Description: "Comprehensive security scanning for AI models and systems",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"model_info": map[string]interface{}{
					"type":        "object",
					"description": "Information about the AI model",
					"properties": map[string]interface{}{
						"model_type": map[string]interface{}{
							"type": "string",
							"enum": []string{"llm", "vision", "multimodal", "embedding", "classification"},
						},
						"model_name": map[string]interface{}{
							"type": "string",
						},
						"version": map[string]interface{}{
							"type": "string",
						},
					},
				},
				"scan_categories": map[string]interface{}{
					"type":        "array",
					"description": "Categories of security scans to perform",
					"items": map[string]interface{}{
						"type": "string",
						"enum": []string{"prompt_injection", "data_poisoning", "model_extraction", "adversarial_attacks", "privacy_leakage"},
					},
				},
				"test_intensity": map[string]interface{}{
					"type":        "string",
					"description": "Intensity of security testing",
					"enum":        []string{"light", "moderate", "intensive", "comprehensive"},
					"default":     "moderate",
				},
			},
			Required: []string{"model_info"},
		},
		Handler: s.handleAIModelSecurityScan,
	}

	// AI Data Privacy Assessment Tool
	s.tools["ai_data_privacy_assessment"] = SecurityTool{
		Name:        "ai_data_privacy_assessment",
		Description: "Assess data privacy risks in AI systems",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"data_sources": map[string]interface{}{
					"type":        "array",
					"description": "Data sources used by the AI system",
					"items": map[string]interface{}{
						"type": "object",
					},
				},
				"privacy_regulations": map[string]interface{}{
					"type":        "array",
					"description": "Privacy regulations to assess against",
					"items": map[string]interface{}{
						"type": "string",
						"enum": []string{"GDPR", "CCPA", "PIPEDA", "LGPD", "custom"},
					},
				},
				"assessment_scope": map[string]interface{}{
					"type":        "string",
					"description": "Scope of privacy assessment",
					"enum":        []string{"data_collection", "data_processing", "data_storage", "data_sharing", "comprehensive"},
					"default":     "comprehensive",
				},
			},
			Required: []string{"data_sources"},
		},
		Handler: s.handleAIDataPrivacyAssessment,
	}

	// AI Bias Detection Tool
	s.tools["ai_bias_detection"] = SecurityTool{
		Name:        "ai_bias_detection",
		Description: "Detect and analyze bias in AI models and outputs",
		Schema: ToolSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"model_outputs": map[string]interface{}{
					"type":        "array",
					"description": "Sample model outputs to analyze for bias",
					"items": map[string]interface{}{
						"type": "object",
					},
				},
				"bias_categories": map[string]interface{}{
					"type":        "array",
					"description": "Categories of bias to detect",
					"items": map[string]interface{}{
						"type": "string",
						"enum": []string{"gender", "race", "age", "religion", "nationality", "socioeconomic", "custom"},
					},
				},
				"detection_methods": map[string]interface{}{
					"type":        "array",
					"description": "Methods to use for bias detection",
					"items": map[string]interface{}{
						"type": "string",
						"enum": []string{"statistical", "fairness_metrics", "adversarial_testing", "demographic_parity"},
					},
				},
				"threshold": map[string]interface{}{
					"type":        "number",
					"description": "Bias detection threshold (0.0 - 1.0)",
					"minimum":     0.0,
					"maximum":     1.0,
					"default":     0.1,
				},
			},
			Required: []string{"model_outputs"},
		},
		Handler: s.handleAIBiasDetection,
	}
}

// GetAllTools returns all registered security tools
func (s *SecurityMCPServer) GetAllTools() map[string]SecurityTool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	tools := make(map[string]SecurityTool)
	for name, tool := range s.tools {
		tools[name] = tool
	}
	
	return tools
}

// GetToolsByCategory returns tools filtered by category
func (s *SecurityMCPServer) GetToolsByCategory(category string) map[string]SecurityTool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	tools := make(map[string]SecurityTool)
	
	for name, tool := range s.tools {
		// Simple category matching based on tool name prefixes
		switch category {
		case "core":
			if name == "threat_analysis" || name == "vulnerability_scan" || 
			   name == "compliance_check" || name == "incident_response" || 
			   name == "threat_intelligence" {
				tools[name] = tool
			}
		case "advanced":
			if name == "ai_security_assessment" || name == "security_policy_validation" ||
			   name == "threat_modeling" || name == "security_code_analysis" ||
			   name == "penetration_testing" || name == "security_metrics_analysis" ||
			   name == "risk_assessment" {
				tools[name] = tool
			}
		case "ai":
			if name == "ai_model_security_scan" || name == "ai_data_privacy_assessment" ||
			   name == "ai_bias_detection" || name == "ai_security_assessment" {
				tools[name] = tool
			}
		case "specialized":
			if name == "security_audit" || name == "security_config_assessment" ||
			   name == "security_training_assessment" {
				tools[name] = tool
			}
		default:
			tools[name] = tool
		}
	}
	
	return tools
}

// GetToolsCount returns the total number of registered tools
func (s *SecurityMCPServer) GetToolsCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tools)
}
