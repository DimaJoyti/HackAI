package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/red_team"
)

func main() {
	// Initialize logger
	appLogger, err := logger.New(logger.Config{
		Level:      logger.LevelInfo,
		Format:     "json",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	appLogger.Info("🤖 Starting Red Team Automation Demo")

	// Run comprehensive red team automation demos
	if err := runRedTeamDemos(appLogger); err != nil {
		appLogger.Fatal("Red team automation demos failed", "error", err)
	}

	appLogger.Info("✅ Red Team Automation Demo completed successfully!")
}

func runRedTeamDemos(logger *logger.Logger) error {
	ctx := context.Background()

	logger.Info("=== 🔄 Red Team Automation Demo ===")

	// Demo 1: Automated Reconnaissance
	if err := demoAutomatedReconnaissance(ctx, logger); err != nil {
		return fmt.Errorf("automated reconnaissance demo failed: %w", err)
	}

	// Demo 2: Intelligent Attack Planning
	if err := demoIntelligentAttackPlanning(ctx, logger); err != nil {
		return fmt.Errorf("intelligent attack planning demo failed: %w", err)
	}

	// Demo 3: Automated Exploitation
	if err := demoAutomatedExploitation(ctx, logger); err != nil {
		return fmt.Errorf("automated exploitation demo failed: %w", err)
	}

	// Demo 4: Persistence and Stealth
	if err := demoPersistenceAndStealth(ctx, logger); err != nil {
		return fmt.Errorf("persistence and stealth demo failed: %w", err)
	}

	// Demo 5: Comprehensive Red Team Campaign
	if err := demoComprehensiveRedTeamCampaign(ctx, logger); err != nil {
		return fmt.Errorf("comprehensive red team campaign demo failed: %w", err)
	}

	return nil
}

func demoAutomatedReconnaissance(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🔍 Demo 1: Automated Reconnaissance")

	// Create red team orchestrator
	config := red_team.OrchestratorConfig{
		MaxConcurrentOperations: 5,
		DefaultOperationTimeout: time.Minute * 10,
		EnableStealthMode:       true,
		EnablePersistence:       false,
		EnableReporting:         true,
		AutoAdaptStrategy:       true,
		MaxRetryAttempts:        3,
		StealthLevel:            7,
		AggressivenessLevel:     3,
	}

	orchestrator := red_team.NewRedTeamOrchestrator(config, logger)

	// Create target environment
	target := red_team.TargetEnvironment{
		ID:   "target_corp_network",
		Name: "Corporate Network",
		Type: red_team.EnvTypeEnterprise,
		NetworkRanges: []string{
			"192.168.1.0/24",
			"10.0.0.0/16",
		},
		Domains: []string{
			"example.com",
			"internal.example.com",
		},
		Services: []red_team.ServiceInfo{
			{
				Name:     "Web Server",
				Port:     80,
				Protocol: "TCP",
				Version:  "Apache 2.4",
				Banner:   "Apache/2.4.41 (Ubuntu)",
				Metadata: make(map[string]interface{}),
			},
		},
		Assets: []red_team.AssetInfo{
			{
				ID:          "web_server_01",
				Name:        "Primary Web Server",
				Type:        "server",
				IP:          "192.168.1.100",
				Hostname:    "web.example.com",
				OS:          "Ubuntu 20.04",
				Value:       8,
				Criticality: 7,
				Metadata:    make(map[string]interface{}),
			},
		},
		SecurityControls: []red_team.SecurityControl{
			{
				ID:            "firewall_01",
				Name:          "Perimeter Firewall",
				Type:          "network_security",
				Effectiveness: 0.7,
				Coverage:      []string{"network_perimeter"},
				Metadata:      make(map[string]interface{}),
			},
		},
		Constraints: []string{"no_destructive_actions", "business_hours_only"},
		Metadata:    map[string]interface{}{"environment": "production", "sensitivity": "medium"},
	}

	// Create reconnaissance objectives
	objectives := []red_team.OperationObjective{
		{
			ID:          "obj_network_recon",
			Name:        "Network Reconnaissance",
			Description: "Discover network topology, assets, and services",
			Type:        red_team.ObjTypeRecon,
			Priority:    1,
			Success:     false,
			Evidence:    []string{},
			Metadata:    make(map[string]interface{}),
		},
	}

	// Create operation configuration
	operationConfig := red_team.OperationConfig{
		Timeout:             time.Minute * 5,
		StealthMode:         true,
		AggressiveMode:      false,
		PersistenceEnabled:  false,
		ExfiltrationEnabled: false,
		MaxNoiseLevel:       3,
		MaxDetectionRisk:    0.2,
		AllowedTechniques:   []string{"network_scanning", "service_enumeration", "dns_enumeration"},
		ForbiddenTechniques: []string{"exploitation", "persistence"},
	}

	logger.Info("🔄 Starting automated reconnaissance operation")

	// Start red team operation
	operation, err := orchestrator.StartOperation(ctx, target, objectives, operationConfig)
	if err != nil {
		return fmt.Errorf("failed to start reconnaissance operation: %w", err)
	}

	// Wait for operation completion
	err = waitForOperationCompletion(operation, time.Minute*2, logger)
	if err != nil {
		return err
	}

	logger.Info("📊 Automated reconnaissance completed",
		"operation_id", operation.ID,
		"status", string(operation.Status),
		"duration", operation.Duration,
		"techniques_attempted", operation.Metrics.TechniquesAttempted,
		"techniques_succeeded", operation.Metrics.TechniquesSucceeded,
		"assets_discovered", len(operation.Target.Assets),
	)

	// Show reconnaissance results
	if operation.Results != nil {
		logger.Info("🎯 Reconnaissance results",
			"overall_success", operation.Results.OverallSuccess,
			"success_rate", fmt.Sprintf("%.2f", operation.Results.SuccessRate),
			"objectives_achieved", operation.Results.ObjectivesAchieved,
			"compromised_assets", operation.Results.CompromisedAssets,
		)

		// Show security recommendations
		logger.Info("💡 Security recommendations")
		for i, rec := range operation.Results.Recommendations {
			logger.Info("📋 Recommendation",
				"priority", i+1,
				"title", rec.Title,
				"category", rec.Category,
				"impact", rec.Impact,
				"effort", rec.Effort,
			)
		}
	}

	return nil
}

func demoIntelligentAttackPlanning(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🧠 Demo 2: Intelligent Attack Planning")

	config := red_team.OrchestratorConfig{
		MaxConcurrentOperations: 3,
		DefaultOperationTimeout: time.Minute * 15,
		EnableStealthMode:       true,
		EnablePersistence:       true,
		EnableReporting:         true,
		AutoAdaptStrategy:       true,
		MaxRetryAttempts:        3,
		StealthLevel:            8,
		AggressivenessLevel:     5,
	}

	orchestrator := red_team.NewRedTeamOrchestrator(config, logger)

	// Create target for attack planning
	target := red_team.TargetEnvironment{
		ID:            "target_enterprise",
		Name:          "Enterprise Environment",
		Type:          red_team.EnvTypeEnterprise,
		NetworkRanges: []string{"10.0.0.0/8"},
		Domains:       []string{"enterprise.com"},
		Constraints:   []string{"stealth_required", "no_data_destruction"},
		Metadata:      map[string]interface{}{"complexity": "high", "security_posture": "advanced"},
	}

	// Create comprehensive objectives
	objectives := []red_team.OperationObjective{
		{
			ID:          "obj_initial_access",
			Name:        "Initial Access",
			Description: "Gain initial foothold in the target environment",
			Type:        red_team.ObjTypeInitialAccess,
			Priority:    1,
			Success:     false,
		},
		{
			ID:          "obj_privilege_escalation",
			Name:        "Privilege Escalation",
			Description: "Escalate privileges to administrative level",
			Type:        red_team.ObjTypePrivEsc,
			Priority:    2,
			Success:     false,
		},
		{
			ID:          "obj_persistence",
			Name:        "Establish Persistence",
			Description: "Maintain persistent access to the environment",
			Type:        red_team.ObjTypePersistence,
			Priority:    3,
			Success:     false,
		},
	}

	operationConfig := red_team.OperationConfig{
		Timeout:             time.Minute * 10,
		StealthMode:         true,
		AggressiveMode:      false,
		PersistenceEnabled:  true,
		ExfiltrationEnabled: false,
		MaxNoiseLevel:       2,
		MaxDetectionRisk:    0.15,
		AllowedTechniques:   []string{"spear_phishing", "token_impersonation", "registry_persistence"},
		ForbiddenTechniques: []string{"destructive_actions"},
	}

	logger.Info("🔄 Starting intelligent attack planning operation")

	operation, err := orchestrator.StartOperation(ctx, target, objectives, operationConfig)
	if err != nil {
		return fmt.Errorf("failed to start attack planning operation: %w", err)
	}

	// Wait for operation completion
	err = waitForOperationCompletion(operation, time.Minute*3, logger)
	if err != nil {
		return err
	}

	logger.Info("📊 Intelligent attack planning completed",
		"operation_id", operation.ID,
		"status", string(operation.Status),
		"duration", operation.Duration,
		"phases_executed", len(operation.ExecutionPhases),
		"success_rate", fmt.Sprintf("%.2f", operation.Results.SuccessRate),
	)

	// Show attack plan details
	if operation.AttackPlan != nil {
		logger.Info("🎯 Attack plan details",
			"plan_id", operation.AttackPlan.ID,
			"complexity", string(operation.AttackPlan.Complexity),
			"stealth_level", operation.AttackPlan.StealthLevel,
			"success_rate", fmt.Sprintf("%.2f", operation.AttackPlan.SuccessRate),
			"phases", len(operation.AttackPlan.Phases),
		)

		// Show phase execution results
		for i, phase := range operation.ExecutionPhases {
			logger.Info("📍 Phase execution",
				"phase_number", i+1,
				"phase_id", phase.PhaseID,
				"status", string(phase.Status),
				"duration", phase.Duration,
				"techniques_executed", len(phase.Techniques),
				"adaptations", len(phase.Adaptations),
			)
		}
	}

	return nil
}

func demoAutomatedExploitation(ctx context.Context, logger *logger.Logger) error {
	logger.Info("💥 Demo 3: Automated Exploitation")

	config := red_team.OrchestratorConfig{
		MaxConcurrentOperations: 2,
		DefaultOperationTimeout: time.Minute * 20,
		EnableStealthMode:       false,
		EnablePersistence:       true,
		EnableReporting:         true,
		AutoAdaptStrategy:       true,
		MaxRetryAttempts:        5,
		StealthLevel:            5,
		AggressivenessLevel:     7,
	}

	orchestrator := red_team.NewRedTeamOrchestrator(config, logger)

	target := red_team.TargetEnvironment{
		ID:            "target_vulnerable_app",
		Name:          "Vulnerable Application Environment",
		Type:          red_team.EnvTypeEnterprise,
		NetworkRanges: []string{"172.16.0.0/16"},
		Domains:       []string{"vulnapp.local"},
		Constraints:   []string{"test_environment"},
		Metadata:      map[string]interface{}{"purpose": "exploitation_testing"},
	}

	objectives := []red_team.OperationObjective{
		{
			ID:          "obj_exploit_web",
			Name:        "Web Application Exploitation",
			Description: "Exploit vulnerabilities in web applications",
			Type:        red_team.ObjTypeInitialAccess,
			Priority:    1,
		},
		{
			ID:          "obj_lateral_movement",
			Name:        "Lateral Movement",
			Description: "Move laterally through the network",
			Type:        red_team.ObjTypeLateralMove,
			Priority:    2,
		},
	}

	operationConfig := red_team.OperationConfig{
		Timeout:             time.Minute * 8,
		StealthMode:         false,
		AggressiveMode:      true,
		PersistenceEnabled:  true,
		ExfiltrationEnabled: false,
		MaxNoiseLevel:       8,
		MaxDetectionRisk:    0.7,
		AllowedTechniques:   []string{"sql_injection", "xss", "buffer_overflow", "lateral_movement"},
		ForbiddenTechniques: []string{},
	}

	logger.Info("🔄 Starting automated exploitation operation")

	operation, err := orchestrator.StartOperation(ctx, target, objectives, operationConfig)
	if err != nil {
		return fmt.Errorf("failed to start exploitation operation: %w", err)
	}

	err = waitForOperationCompletion(operation, time.Minute*3, logger)
	if err != nil {
		return err
	}

	logger.Info("📊 Automated exploitation completed",
		"operation_id", operation.ID,
		"status", string(operation.Status),
		"duration", operation.Duration,
		"techniques_attempted", operation.Metrics.TechniquesAttempted,
		"techniques_succeeded", operation.Metrics.TechniquesSucceeded,
		"efficiency_score", fmt.Sprintf("%.2f", operation.Metrics.EfficiencyScore),
	)

	return nil
}

func demoPersistenceAndStealth(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🥷 Demo 4: Persistence and Stealth")

	config := red_team.OrchestratorConfig{
		MaxConcurrentOperations: 1,
		DefaultOperationTimeout: time.Minute * 25,
		EnableStealthMode:       true,
		EnablePersistence:       true,
		EnableReporting:         true,
		AutoAdaptStrategy:       true,
		MaxRetryAttempts:        2,
		StealthLevel:            9,
		AggressivenessLevel:     2,
	}

	orchestrator := red_team.NewRedTeamOrchestrator(config, logger)

	target := red_team.TargetEnvironment{
		ID:            "target_high_security",
		Name:          "High Security Environment",
		Type:          red_team.EnvTypeEnterprise,
		NetworkRanges: []string{"10.10.0.0/16"},
		Domains:       []string{"secure.corp"},
		Constraints:   []string{"maximum_stealth", "no_detection"},
		Metadata:      map[string]interface{}{"security_level": "maximum"},
	}

	objectives := []red_team.OperationObjective{
		{
			ID:          "obj_stealth_persistence",
			Name:        "Stealth Persistence",
			Description: "Establish persistent access without detection",
			Type:        red_team.ObjTypePersistence,
			Priority:    1,
		},
	}

	operationConfig := red_team.OperationConfig{
		Timeout:             time.Minute * 6,
		StealthMode:         true,
		AggressiveMode:      false,
		PersistenceEnabled:  true,
		ExfiltrationEnabled: false,
		MaxNoiseLevel:       1,
		MaxDetectionRisk:    0.05,
		AllowedTechniques:   []string{"registry_persistence", "service_persistence", "wmi_persistence"},
		ForbiddenTechniques: []string{"noisy_techniques", "destructive_actions"},
	}

	logger.Info("🔄 Starting persistence and stealth operation")

	operation, err := orchestrator.StartOperation(ctx, target, objectives, operationConfig)
	if err != nil {
		return fmt.Errorf("failed to start persistence operation: %w", err)
	}

	err = waitForOperationCompletion(operation, time.Minute*2, logger)
	if err != nil {
		return err
	}

	logger.Info("📊 Persistence and stealth operation completed",
		"operation_id", operation.ID,
		"status", string(operation.Status),
		"duration", operation.Duration,
		"stealth_score", fmt.Sprintf("%.2f", operation.Metrics.StealthScore),
		"detection_rate", fmt.Sprintf("%.2f", operation.Metrics.DetectionRate),
	)

	return nil
}

func demoComprehensiveRedTeamCampaign(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🎯 Demo 5: Comprehensive Red Team Campaign")

	config := red_team.OrchestratorConfig{
		MaxConcurrentOperations: 3,
		DefaultOperationTimeout: time.Minute * 30,
		EnableStealthMode:       true,
		EnablePersistence:       true,
		EnableReporting:         true,
		AutoAdaptStrategy:       true,
		MaxRetryAttempts:        3,
		StealthLevel:            7,
		AggressivenessLevel:     6,
	}

	orchestrator := red_team.NewRedTeamOrchestrator(config, logger)

	target := red_team.TargetEnvironment{
		ID:            "target_full_enterprise",
		Name:          "Full Enterprise Environment",
		Type:          red_team.EnvTypeEnterprise,
		NetworkRanges: []string{"192.168.0.0/16", "10.0.0.0/8"},
		Domains:       []string{"enterprise.local", "external.enterprise.com"},
		Constraints:   []string{"comprehensive_assessment"},
		Metadata:      map[string]interface{}{"campaign_type": "full_assessment"},
	}

	// Comprehensive objectives covering full attack lifecycle
	objectives := []red_team.OperationObjective{
		{
			ID:          "obj_full_recon",
			Name:        "Comprehensive Reconnaissance",
			Description: "Complete target environment reconnaissance",
			Type:        red_team.ObjTypeRecon,
			Priority:    1,
		},
		{
			ID:          "obj_full_access",
			Name:        "Initial Access",
			Description: "Gain initial access to target environment",
			Type:        red_team.ObjTypeInitialAccess,
			Priority:    2,
		},
		{
			ID:          "obj_full_privesc",
			Name:        "Privilege Escalation",
			Description: "Escalate to administrative privileges",
			Type:        red_team.ObjTypePrivEsc,
			Priority:    3,
		},
		{
			ID:          "obj_full_persist",
			Name:        "Persistence",
			Description: "Establish persistent access mechanisms",
			Type:        red_team.ObjTypePersistence,
			Priority:    4,
		},
		{
			ID:          "obj_full_exfil",
			Name:        "Data Exfiltration",
			Description: "Simulate data exfiltration scenarios",
			Type:        red_team.ObjTypeExfiltration,
			Priority:    5,
		},
	}

	operationConfig := red_team.OperationConfig{
		Timeout:             time.Minute * 12,
		StealthMode:         true,
		AggressiveMode:      false,
		PersistenceEnabled:  true,
		ExfiltrationEnabled: true,
		MaxNoiseLevel:       5,
		MaxDetectionRisk:    0.3,
		AllowedTechniques:   []string{"all_techniques"},
		ForbiddenTechniques: []string{"destructive_actions"},
	}

	logger.Info("🔄 Starting comprehensive red team campaign")

	operation, err := orchestrator.StartOperation(ctx, target, objectives, operationConfig)
	if err != nil {
		return fmt.Errorf("failed to start comprehensive campaign: %w", err)
	}

	err = waitForOperationCompletion(operation, time.Minute*4, logger)
	if err != nil {
		return err
	}

	logger.Info("📊 Comprehensive red team campaign completed",
		"operation_id", operation.ID,
		"status", string(operation.Status),
		"duration", operation.Duration,
		"total_objectives", len(objectives),
		"objectives_achieved", operation.Results.ObjectivesAchieved,
		"overall_success", operation.Results.OverallSuccess,
		"success_rate", fmt.Sprintf("%.2f", operation.Results.SuccessRate),
		"techniques_attempted", operation.Metrics.TechniquesAttempted,
		"techniques_succeeded", operation.Metrics.TechniquesSucceeded,
		"efficiency_score", fmt.Sprintf("%.2f", operation.Metrics.EfficiencyScore),
	)

	// Show comprehensive results
	if operation.Results != nil {
		logger.Info("🎯 Campaign results summary",
			"compromised_assets", operation.Results.CompromisedAssets,
			"vulnerabilities_found", len(operation.Results.Vulnerabilities),
			"persistence_methods", len(operation.Results.PersistenceMethods),
			"detection_events", len(operation.Results.DetectionEvents),
			"recommendations", len(operation.Results.Recommendations),
		)

		// Show detailed recommendations
		logger.Info("💡 Comprehensive security recommendations")
		for i, rec := range operation.Results.Recommendations {
			logger.Info("📋 Security recommendation",
				"priority", i+1,
				"title", rec.Title,
				"description", rec.Description,
				"category", rec.Category,
				"impact", rec.Impact,
				"effort", rec.Effort,
			)
		}
	}

	return nil
}

// Helper function to wait for operation completion
func waitForOperationCompletion(operation *red_team.RedTeamOperation, timeout time.Duration, logger *logger.Logger) error {
	timeoutChan := time.After(timeout)
	ticker := time.NewTicker(time.Millisecond * 500)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutChan:
			return fmt.Errorf("operation timed out")
		case <-ticker.C:
			if operation.Status == red_team.StatusCompleted || operation.Status == red_team.StatusFailed || operation.Status == red_team.StatusCancelled {
				if operation.Status == red_team.StatusFailed {
					return fmt.Errorf("operation failed")
				}
				return nil
			}
		}
	}
}
