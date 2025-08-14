package config

import (
	"time"
)

// SecurityProfile represents different security configuration profiles
type SecurityProfile string

const (
	ProfileDevelopment  SecurityProfile = "development"
	ProfileStaging      SecurityProfile = "staging"
	ProfileProduction   SecurityProfile = "production"
	ProfileHighSecurity SecurityProfile = "high_security"
	ProfileCompliance   SecurityProfile = "compliance"
)

// GetSecurityTemplate returns a pre-configured security template
func GetSecurityTemplate(profile SecurityProfile) *UnifiedSecurityConfig {
	switch profile {
	case ProfileDevelopment:
		return getDevelopmentTemplate()
	case ProfileStaging:
		return getStagingTemplate()
	case ProfileProduction:
		return getProductionTemplate()
	case ProfileHighSecurity:
		return getHighSecurityTemplate()
	case ProfileCompliance:
		return getComplianceTemplate()
	default:
		return getProductionTemplate()
	}
}

// getDevelopmentTemplate returns development security configuration
func getDevelopmentTemplate() *UnifiedSecurityConfig {
	return &UnifiedSecurityConfig{
		Version:     "1.0.0",
		Environment: "development",
		UpdatedAt:   time.Now(),

		AgenticFramework: AgenticFrameworkConfig{
			Enabled:                 true,
			RealTimeAnalysis:        true,
			ThreatResponseThreshold: 0.8,   // Higher threshold for dev
			AutoBlockEnabled:        false, // Don't auto-block in dev
			LearningMode:            true,
			MaxConcurrentAnalysis:   5,
			ThreatRetentionDuration: 1 * time.Hour,
			AlertCooldownPeriod:     1 * time.Minute,
			ConfidenceThreshold:     0.6,
		},

		AIFirewall: AIFirewallConfig{
			Enabled:             true,
			MLDetection:         true,
			BehaviorAnalysis:    false, // Disabled for dev performance
			AnomalyDetection:    false,
			GeoBlocking:         false,
			RateLimiting:        false,
			BlockThreshold:      0.9, // Very high threshold
			AlertThreshold:      0.7,
			Rules:               getBasicFirewallRules(),
			WhitelistedIPs:      []string{"127.0.0.1", "::1", "localhost"},
			BlacklistedIPs:      []string{},
			GeoBlockedCountries: []string{},
		},

		InputOutputFilter: InputOutputFilterConfig{
			Enabled:            true,
			InputValidation:    true,
			OutputSanitization: true,
			ContentAnalysis:    false, // Disabled for dev performance
			ThreatScanning:     false,
			StrictMode:         false,
			MaxInputLength:     1000000,
			MaxOutputLength:    10000000,
			AllowedFileTypes:   []string{"txt", "json", "xml", "csv", "log"},
			BlockedPatterns:    getBasicBlockedPatterns(),
			SanitizationLevel:  "basic",
			LogViolations:      true,
			BlockOnViolation:   false,
			EncodingDetection:  true,
			MalwareScanning:    false,
		},

		PromptGuard: PromptGuardConfig{
			Enabled:                       true,
			SemanticAnalysis:              false, // Disabled for dev performance
			ContextAnalysis:               false,
			StrictMode:                    false,
			ConfidenceThreshold:           0.8,
			MaxPromptLength:               50000,
			EnableLearning:                true,
			BlockSuspiciousPrompts:        false,
			LogAllAttempts:                true,
			RoleManipulationDetection:     false,
			InstructionInjectionDetection: false,
		},

		ThreatIntelligence: ThreatIntelligenceConfig{
			Enabled:           false, // Disabled for dev
			UpdateInterval:    24 * time.Hour,
			Sources:           []string{},
			APIKeys:           map[string]string{},
			CacheTimeout:      1 * time.Hour,
			MaxCacheSize:      1000,
			IOCTypes:          []string{"ip", "domain", "hash"},
			ReputationScoring: false,
			AutoBlocking:      false,
		},

		WebLayer: WebLayerConfig{
			Enabled:         true,
			SecurityHeaders: true,
			CSP: CSPConfig{
				Enabled:                 true,
				Policy:                  "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: *",
				ReportOnly:              true, // Report only in dev
				ReportURI:               "",
				UpgradeInsecureRequests: false,
			},
			HSTS: HSTSConfig{
				Enabled:           false, // Disabled for dev (HTTP)
				MaxAge:            0,
				IncludeSubDomains: false,
				Preload:           false,
			},
			XFrameOptions:   "SAMEORIGIN",
			MaxRequestSize:  50 * 1024 * 1024, // 50MB
			RequestTimeout:  60 * time.Second,
			RateLimiting:    false,
			SessionSecurity: false,
			CookieSecurity:  false,
			IPFiltering:     false,
			GeoBlocking:     false,
		},

		Authentication: AuthenticationConfig{
			PasswordPolicy: PasswordPolicyConfig{
				MinLength:        6, // Relaxed for dev
				RequireUppercase: false,
				RequireLowercase: false,
				RequireNumbers:   false,
				RequireSpecial:   false,
				HistoryCount:     0,
				MaxAge:           0,
				MinAge:           0,
				ComplexityScore:  0,
			},
			MultiFactorAuth: MultiFactorAuthConfig{
				Enabled:       false, // Disabled for dev
				Required:      false,
				Methods:       []string{},
				TOTPIssuer:    "HackAI-Dev",
				TOTPDigits:    6,
				TOTPPeriod:    30,
				BackupCodes:   false,
				SMSProvider:   "",
				EmailProvider: "",
			},
			SessionManagement: SessionManagementConfig{
				Timeout:               24 * time.Hour, // Long timeout for dev
				MaxConcurrentSessions: 10,
				SecureCookies:         false,
				HTTPOnlyCookies:       true,
				SameSiteCookies:       "Lax",
				SessionRotation:       false,
				IdleTimeout:           4 * time.Hour,
			},
			AccountLockout: AccountLockoutConfig{
				Enabled:           false, // Disabled for dev
				MaxFailedAttempts: 100,
				LockoutDuration:   1 * time.Minute,
				ResetOnSuccess:    true,
				NotifyOnLockout:   false,
			},
		},

		Authorization: AuthorizationConfig{
			RBAC: RBACConfig{
				Enabled:     true,
				DefaultRole: "developer",
				Roles:       map[string]string{"developer": "full_access"},
				Inheritance: true,
			},
		},

		Monitoring: MonitoringConfig{
			Enabled:         true,
			MetricsEnabled:  true,
			TracingEnabled:  false, // Disabled for dev performance
			HealthChecks:    true,
			Dashboards:      false,
			Exporters:       []string{"console"},
			SampleRate:      0.1,
			RetentionPeriod: 1 * time.Hour,
		},

		Alerting: AlertingConfig{
			Enabled:  false, // Disabled for dev
			Channels: []AlertChannel{},
			Rules:    []AlertRule{},
		},

		Logging: SecurityLoggingConfig{
			Level:           "debug",
			Format:          "text",
			Output:          []string{"console"},
			SecurityEvents:  true,
			AuditLogs:       false,
			RetentionPeriod: 24 * time.Hour,
			Encryption:      false,
			Compression:     false,
		},

		FeatureToggles: FeatureTogglesConfig{
			SecurityFeatures: map[string]bool{
				"advanced_threat_detection": false,
				"ml_based_analysis":         false,
				"real_time_blocking":        false,
			},
			ExperimentalFeatures: map[string]bool{
				"ai_powered_rules":    true,
				"behavioral_analysis": false,
				"predictive_blocking": false,
			},
			MaintenanceMode: false,
			DebugMode:       true,
		},
	}
}

// getProductionTemplate returns production security configuration
func getProductionTemplate() *UnifiedSecurityConfig {
	return &UnifiedSecurityConfig{
		Version:     "1.0.0",
		Environment: "production",
		UpdatedAt:   time.Now(),

		AgenticFramework: AgenticFrameworkConfig{
			Enabled:                 true,
			RealTimeAnalysis:        true,
			ThreatResponseThreshold: 0.7,
			AutoBlockEnabled:        true,
			LearningMode:            true,
			MaxConcurrentAnalysis:   20,
			ThreatRetentionDuration: 24 * time.Hour,
			AlertCooldownPeriod:     5 * time.Minute,
			ConfidenceThreshold:     0.8,
		},

		AIFirewall: AIFirewallConfig{
			Enabled:             true,
			MLDetection:         true,
			BehaviorAnalysis:    true,
			AnomalyDetection:    true,
			GeoBlocking:         true,
			RateLimiting:        true,
			BlockThreshold:      0.7,
			AlertThreshold:      0.5,
			Rules:               getProductionFirewallRules(),
			WhitelistedIPs:      []string{},
			BlacklistedIPs:      []string{},
			GeoBlockedCountries: []string{"CN", "RU", "KP"},
		},

		InputOutputFilter: InputOutputFilterConfig{
			Enabled:            true,
			InputValidation:    true,
			OutputSanitization: true,
			ContentAnalysis:    true,
			ThreatScanning:     true,
			StrictMode:         true,
			MaxInputLength:     100000,
			MaxOutputLength:    1000000,
			AllowedFileTypes:   []string{"txt", "json", "xml", "csv"},
			BlockedPatterns:    getProductionBlockedPatterns(),
			SanitizationLevel:  "strict",
			LogViolations:      true,
			BlockOnViolation:   true,
			EncodingDetection:  true,
			MalwareScanning:    true,
		},

		PromptGuard: PromptGuardConfig{
			Enabled:                       true,
			SemanticAnalysis:              true,
			ContextAnalysis:               true,
			StrictMode:                    true,
			ConfidenceThreshold:           0.7,
			MaxPromptLength:               10000,
			EnableLearning:                true,
			BlockSuspiciousPrompts:        true,
			LogAllAttempts:                true,
			RoleManipulationDetection:     true,
			InstructionInjectionDetection: true,
		},

		ThreatIntelligence: ThreatIntelligenceConfig{
			Enabled:           true,
			UpdateInterval:    1 * time.Hour,
			Sources:           []string{"virustotal", "alienvault", "malwaredomainlist"},
			APIKeys:           map[string]string{},
			CacheTimeout:      4 * time.Hour,
			MaxCacheSize:      10000,
			IOCTypes:          []string{"ip", "domain", "hash", "url"},
			ReputationScoring: true,
			AutoBlocking:      true,
		},

		WebLayer: WebLayerConfig{
			Enabled:         true,
			SecurityHeaders: true,
			CSP: CSPConfig{
				Enabled:                 true,
				Policy:                  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
				ReportOnly:              false,
				ReportURI:               "/csp-report",
				UpgradeInsecureRequests: true,
			},
			HSTS: HSTSConfig{
				Enabled:           true,
				MaxAge:            31536000, // 1 year
				IncludeSubDomains: true,
				Preload:           true,
			},
			XFrameOptions:   "DENY",
			MaxRequestSize:  10 * 1024 * 1024, // 10MB
			RequestTimeout:  30 * time.Second,
			RateLimiting:    true,
			SessionSecurity: true,
			CookieSecurity:  true,
			IPFiltering:     true,
			GeoBlocking:     true,
		},

		Authentication: AuthenticationConfig{
			PasswordPolicy: PasswordPolicyConfig{
				MinLength:        12,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				HistoryCount:     10,
				MaxAge:           90 * 24 * time.Hour,
				MinAge:           24 * time.Hour,
				ComplexityScore:  80,
			},
			MultiFactorAuth: MultiFactorAuthConfig{
				Enabled:       true,
				Required:      true,
				Methods:       []string{"totp", "sms", "email"},
				TOTPIssuer:    "HackAI",
				TOTPDigits:    6,
				TOTPPeriod:    30,
				BackupCodes:   true,
				SMSProvider:   "twilio",
				EmailProvider: "sendgrid",
			},
			SessionManagement: SessionManagementConfig{
				Timeout:               8 * time.Hour,
				MaxConcurrentSessions: 3,
				SecureCookies:         true,
				HTTPOnlyCookies:       true,
				SameSiteCookies:       "Strict",
				SessionRotation:       true,
				IdleTimeout:           30 * time.Minute,
			},
			AccountLockout: AccountLockoutConfig{
				Enabled:           true,
				MaxFailedAttempts: 5,
				LockoutDuration:   15 * time.Minute,
				ResetOnSuccess:    true,
				NotifyOnLockout:   true,
			},
		},

		Authorization: AuthorizationConfig{
			RBAC: RBACConfig{
				Enabled:     true,
				DefaultRole: "user",
				Roles: map[string]string{
					"admin":    "full_access",
					"user":     "limited_access",
					"readonly": "read_only",
				},
				Inheritance: true,
			},
		},

		Monitoring: MonitoringConfig{
			Enabled:         true,
			MetricsEnabled:  true,
			TracingEnabled:  true,
			HealthChecks:    true,
			Dashboards:      true,
			Exporters:       []string{"prometheus", "jaeger"},
			SampleRate:      1.0,
			RetentionPeriod: 30 * 24 * time.Hour,
		},

		Alerting: AlertingConfig{
			Enabled: true,
			Channels: []AlertChannel{
				{
					Type:     "slack",
					Enabled:  true,
					Config:   map[string]string{"webhook_url": ""},
					Severity: []string{"critical", "high"},
				},
				{
					Type:     "email",
					Enabled:  true,
					Config:   map[string]string{"smtp_server": "", "recipients": ""},
					Severity: []string{"critical", "high", "medium"},
				},
			},
			Rules: getProductionAlertRules(),
		},

		Logging: SecurityLoggingConfig{
			Level:           "info",
			Format:          "json",
			Output:          []string{"file", "syslog"},
			SecurityEvents:  true,
			AuditLogs:       true,
			RetentionPeriod: 90 * 24 * time.Hour,
			Encryption:      true,
			Compression:     true,
		},

		FeatureToggles: FeatureTogglesConfig{
			SecurityFeatures: map[string]bool{
				"advanced_threat_detection": true,
				"ml_based_analysis":         true,
				"real_time_blocking":        true,
			},
			ExperimentalFeatures: map[string]bool{
				"ai_powered_rules":    false,
				"behavioral_analysis": true,
				"predictive_blocking": false,
			},
			MaintenanceMode: false,
			DebugMode:       false,
		},
	}
}

// Helper functions for configuration templates

func getBasicFirewallRules() []FirewallRuleConfig {
	return []FirewallRuleConfig{
		{
			ID:          "sql_injection_basic",
			Name:        "Basic SQL Injection Detection",
			Enabled:     true,
			Priority:    100,
			Pattern:     `(?i)(union|select|insert|update|delete|drop)\s+`,
			Action:      "log",
			Severity:    "medium",
			Confidence:  0.7,
			Description: "Detects basic SQL injection patterns",
		},
		{
			ID:          "xss_basic",
			Name:        "Basic XSS Detection",
			Enabled:     true,
			Priority:    100,
			Pattern:     `(?i)<script[^>]*>`,
			Action:      "log",
			Severity:    "medium",
			Confidence:  0.7,
			Description: "Detects basic XSS patterns",
		},
	}
}

func getProductionFirewallRules() []FirewallRuleConfig {
	rules := getBasicFirewallRules()

	// Add more sophisticated rules for production
	productionRules := []FirewallRuleConfig{
		{
			ID:          "advanced_sql_injection",
			Name:        "Advanced SQL Injection Detection",
			Enabled:     true,
			Priority:    90,
			Pattern:     `(?i)(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|'.*or.*'.*=.*')`,
			Action:      "block",
			Severity:    "critical",
			Confidence:  0.9,
			Description: "Detects advanced SQL injection patterns",
		},
		{
			ID:          "command_injection",
			Name:        "Command Injection Detection",
			Enabled:     true,
			Priority:    90,
			Pattern:     `(?i)(;|\||&|&&|\$\(|` + "`" + `|<|>)`,
			Action:      "block",
			Severity:    "high",
			Confidence:  0.8,
			Description: "Detects command injection patterns",
		},
	}

	return append(rules, productionRules...)
}

func getBasicBlockedPatterns() []string {
	return []string{
		`(?i)(union|select|insert|update|delete|drop)\s+`,
		`(?i)<script[^>]*>`,
		`(?i)javascript:`,
	}
}

func getProductionBlockedPatterns() []string {
	basic := getBasicBlockedPatterns()

	production := []string{
		`(?i)on\w+\s*=`,
		`(?i)data:`,
		`(?i)file://`,
		`(?i)eval\s*\(`,
		`(?i)exec\s*\(`,
		`(?i)system\s*\(`,
		`(?i)shell_exec\s*\(`,
		`(?i)passthru\s*\(`,
	}

	return append(basic, production...)
}

func getProductionAlertRules() []AlertRule {
	return []AlertRule{
		{
			ID:          "high_threat_score",
			Name:        "High Threat Score Alert",
			Enabled:     true,
			Condition:   "threat_score > threshold",
			Threshold:   0.8,
			Severity:    "critical",
			Description: "Alert when threat score exceeds 0.8",
		},
		{
			ID:          "multiple_failed_logins",
			Name:        "Multiple Failed Login Attempts",
			Enabled:     true,
			Condition:   "failed_logins > threshold",
			Threshold:   5,
			Severity:    "high",
			Description: "Alert when multiple failed login attempts detected",
		},
		{
			ID:          "suspicious_activity",
			Name:        "Suspicious Activity Pattern",
			Enabled:     true,
			Condition:   "suspicious_events > threshold",
			Threshold:   10,
			Severity:    "medium",
			Description: "Alert when suspicious activity pattern detected",
		},
	}
}

// getStagingTemplate returns staging security configuration
func getStagingTemplate() *UnifiedSecurityConfig {
	config := getProductionTemplate()
	config.Environment = "staging"

	// Adjust for staging environment
	config.AgenticFramework.ThreatResponseThreshold = 0.8
	config.AIFirewall.BlockThreshold = 0.8
	config.PromptGuard.ConfidenceThreshold = 0.8
	config.WebLayer.MaxRequestSize = 20 * 1024 * 1024 // 20MB
	config.Authentication.PasswordPolicy.MinLength = 8
	config.Logging.Level = "debug"
	config.FeatureToggles.DebugMode = true

	return config
}

// getHighSecurityTemplate returns high security configuration
func getHighSecurityTemplate() *UnifiedSecurityConfig {
	config := getProductionTemplate()
	config.Environment = "high_security"

	// Enhance security settings
	config.AgenticFramework.ThreatResponseThreshold = 0.5
	config.AIFirewall.BlockThreshold = 0.5
	config.PromptGuard.ConfidenceThreshold = 0.5
	config.InputOutputFilter.StrictMode = true
	config.Authentication.PasswordPolicy.MinLength = 16
	config.Authentication.PasswordPolicy.ComplexityScore = 95
	config.Authentication.SessionManagement.Timeout = 4 * time.Hour
	config.Authentication.SessionManagement.IdleTimeout = 15 * time.Minute
	config.Authentication.AccountLockout.MaxFailedAttempts = 3
	config.WebLayer.MaxRequestSize = 5 * 1024 * 1024 // 5MB

	return config
}

// getComplianceTemplate returns compliance-focused configuration
func getComplianceTemplate() *UnifiedSecurityConfig {
	config := getProductionTemplate()
	config.Environment = "compliance"

	// Enable compliance features
	config.Compliance = ComplianceConfig{
		GDPR: GDPRConfig{
			Enabled:         true,
			DataRetention:   2 * 365 * 24 * time.Hour, // 2 years
			ConsentRequired: true,
			RightToErasure:  true,
		},
		HIPAA: HIPAAConfig{
			Enabled:       true,
			PHIProtection: true,
			AuditLogging:  true,
			Encryption:    true,
		},
		SOX: SOXConfig{
			Enabled:       true,
			AuditTrails:   true,
			DataIntegrity: true,
		},
		PCI: PCIConfig{
			Enabled:         true,
			DataProtection:  true,
			NetworkSecurity: true,
		},
		Auditing: AuditingConfig{
			Enabled:         true,
			LogLevel:        "debug",
			RetentionPeriod: 7 * 365 * 24 * time.Hour, // 7 years
			Destinations:    []string{"file", "syslog", "database"},
		},
	}

	// Enhanced logging and monitoring
	config.Logging.AuditLogs = true
	config.Logging.RetentionPeriod = 7 * 365 * 24 * time.Hour
	config.Logging.Encryption = true
	config.Monitoring.RetentionPeriod = 365 * 24 * time.Hour

	return config
}
