package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dimajoyti/hackai/pkg/attack_graphs"
	"github.com/dimajoyti/hackai/pkg/logger"
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

	appLogger.Info("🎯 Starting Multi-Vector Attack Graphs Demo")

	// Run comprehensive attack graph demos
	if err := runAttackGraphDemos(appLogger); err != nil {
		appLogger.Fatal("Attack graph demos failed", "error", err)
	}

	appLogger.Info("✅ Multi-Vector Attack Graphs Demo completed successfully!")
}

func runAttackGraphDemos(logger *logger.Logger) error {
	ctx := context.Background()

	logger.Info("=== 🔄 Multi-Vector Attack Graphs Demo ===")

	// Demo 1: Simple Attack Chain
	if err := demoSimpleAttackChain(ctx, logger); err != nil {
		return fmt.Errorf("simple attack chain demo failed: %w", err)
	}

	// Demo 2: Multi-Vector Attack
	if err := demoMultiVectorAttack(ctx, logger); err != nil {
		return fmt.Errorf("multi-vector attack demo failed: %w", err)
	}

	// Demo 3: Advanced Persistent Threat (APT)
	if err := demoAdvancedPersistentThreat(ctx, logger); err != nil {
		return fmt.Errorf("APT demo failed: %w", err)
	}

	// Demo 4: Lateral Movement Scenario
	if err := demoLateralMovementScenario(ctx, logger); err != nil {
		return fmt.Errorf("lateral movement demo failed: %w", err)
	}

	// Demo 5: Defense Optimization
	if err := demoDefenseOptimization(ctx, logger); err != nil {
		return fmt.Errorf("defense optimization demo failed: %w", err)
	}

	return nil
}

func demoSimpleAttackChain(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🎯 Demo 1: Simple Attack Chain")

	// Create attack graph analyzer
	config := attack_graphs.AnalyzerConfig{
		MaxPathDepth:           10,
		MaxPathsPerQuery:       50,
		MinPathProbability:     0.1,
		MaxAnalysisTime:        time.Minute * 5,
		EnableParallelAnalysis: true,
		EnableCaching:          true,
		CacheSize:              100,
		EnableOptimization:     true,
	}

	analyzer := attack_graphs.NewAttackGraphAnalyzer(config, logger)

	// Create simple attack graph: Entry Point -> Exploit -> Objective
	entryPoint := &attack_graphs.EntryPointNode{
		BaseAttackNode: attack_graphs.BaseAttackNode{
			ID:            "entry_phishing",
			Type:          attack_graphs.NodeTypeEntryPoint,
			Name:          "Phishing Email",
			Description:   "Spear phishing email with malicious attachment",
			RiskScore:     6.5,
			Difficulty:    3.0,
			Impact:        4.0,
			Prerequisites: []string{},
			Capabilities:  []string{"social_engineering", "email_access"},
			Metadata:      map[string]interface{}{"vector": "email"},
			Logger:        logger,
		},
		AccessMethod:  "phishing",
		TargetSurface: "email",
		RequiredTools: []string{"email_spoofing", "malware"},
		DetectionRate: 0.3,
		SuccessRate:   0.7,
	}

	exploit := &attack_graphs.ExploitNode{
		BaseAttackNode: attack_graphs.BaseAttackNode{
			ID:            "exploit_cve_2023_1234",
			Type:          attack_graphs.NodeTypeExploit,
			Name:          "Buffer Overflow Exploit",
			Description:   "Exploits buffer overflow vulnerability in email client",
			RiskScore:     8.0,
			Difficulty:    5.0,
			Impact:        7.0,
			Prerequisites: []string{"initial_access"},
			Capabilities:  []string{"code_execution", "memory_corruption"},
			Metadata:      map[string]interface{}{"exploit_type": "memory_corruption"},
			Logger:        logger,
		},
		VulnerabilityID: "vuln_001",
		CVE:             "CVE-2023-1234",
		CVSS:            8.1,
		ExploitType:     "remote_code_execution",
		RequiredAccess:  "user",
		Payload:         "shellcode",
		RequiredTools:   []string{"exploit_framework"},
		Reliability:     0.8,
	}

	privilegeEscalation := &attack_graphs.PrivilegeEscalationNode{
		BaseAttackNode: attack_graphs.BaseAttackNode{
			ID:            "escalate_admin",
			Type:          attack_graphs.NodeTypePrivilegeEscalation,
			Name:          "Privilege Escalation to Admin",
			Description:   "Escalate from user to administrator privileges",
			RiskScore:     7.5,
			Difficulty:    6.0,
			Impact:        8.0,
			Prerequisites: []string{"code_execution"},
			Capabilities:  []string{"privilege_escalation", "system_access"},
			Metadata:      map[string]interface{}{"escalation_type": "local"},
			Logger:        logger,
		},
		FromPrivilege: "user",
		ToPrivilege:   "administrator",
		Method:        "token_manipulation",
		RequiredTools: []string{"privilege_escalation_tool"},
		Persistence:   true,
		Stealth:       6.0,
	}

	// Create attack graph
	graph := &attack_graphs.AttackGraph{
		ID:          "simple_attack_chain",
		Name:        "Simple Attack Chain",
		Description: "Basic attack progression from entry to privilege escalation",
		Version:     "1.0.0",
		Nodes: map[string]attack_graphs.AttackNode{
			"entry_phishing":        entryPoint,
			"exploit_cve_2023_1234": exploit,
			"escalate_admin":        privilegeEscalation,
		},
		Edges: []attack_graphs.AttackEdge{
			{
				ID:           "edge_entry_to_exploit",
				FromNode:     "entry_phishing",
				ToNode:       "exploit_cve_2023_1234",
				EdgeType:     attack_graphs.EdgeTypeSequential,
				Probability:  0.8,
				Cost:         10.0,
				Difficulty:   4.0,
				Requirements: []string{"initial_access"},
				Conditions:   []attack_graphs.EdgeCondition{},
				Metadata:     map[string]interface{}{"transition": "access_to_exploit"},
			},
			{
				ID:           "edge_exploit_to_escalate",
				FromNode:     "exploit_cve_2023_1234",
				ToNode:       "escalate_admin",
				EdgeType:     attack_graphs.EdgeTypeSequential,
				Probability:  0.7,
				Cost:         15.0,
				Difficulty:   5.0,
				Requirements: []string{"code_execution"},
				Conditions:   []attack_graphs.EdgeCondition{},
				Metadata:     map[string]interface{}{"transition": "exploit_to_escalate"},
			},
		},
		EntryPoints: []string{"entry_phishing"},
		Objectives:  []string{"escalate_admin"},
		Metadata:    map[string]interface{}{"complexity": "simple", "demo": "attack_chain"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Create attack scenario
	scenario := &attack_graphs.AttackScenario{
		ID:   "scenario_simple_chain",
		Name: "Simple Attack Chain Scenario",
		AttackerProfile: attack_graphs.AttackerProfile{
			ID:            "attacker_intermediate",
			Name:          "Intermediate Attacker",
			Type:          attack_graphs.AttackerTypeIndividual,
			SkillLevel:    attack_graphs.SkillLevelIntermediate,
			Resources:     attack_graphs.ResourceLevelMedium,
			Motivation:    attack_graphs.MotivationFinancial,
			Capabilities:  []string{"social_engineering", "basic_exploitation", "privilege_escalation"},
			Tools:         []string{"metasploit", "social_engineer_toolkit"},
			Techniques:    []string{"phishing", "exploitation", "escalation"},
			Constraints:   []string{},
			RiskTolerance: 0.6,
			Stealth:       5.0,
			Persistence:   7.0,
			Metadata:      map[string]interface{}{"profile": "intermediate_criminal"},
		},
		TargetProfile: attack_graphs.TargetProfile{
			ID:              "target_small_business",
			Name:            "Small Business",
			Type:            attack_graphs.TargetTypeEnterprise,
			SecurityPosture: attack_graphs.SecurityPostureMedium,
			Assets: []attack_graphs.AssetProfile{
				{
					ID:          "asset_email_server",
					Name:        "Email Server",
					Type:        "server",
					Value:       7.0,
					Criticality: 8.0,
					Exposure:    6.0,
					Metadata:    map[string]interface{}{"service": "email"},
				},
			},
			Vulnerabilities: []attack_graphs.VulnerabilityProfile{
				{
					ID:             "vuln_001",
					CVE:            "CVE-2023-1234",
					CVSS:           8.1,
					Exploitability: 0.8,
					Impact:         7.0,
					Metadata:       map[string]interface{}{"component": "email_client"},
				},
			},
			Defenses: []attack_graphs.DefenseProfile{
				{
					ID:            "defense_antivirus",
					Name:          "Antivirus Software",
					Type:          "endpoint_protection",
					Effectiveness: 0.6,
					Coverage:      0.8,
					Cost:          500.0,
					Metadata:      map[string]interface{}{"vendor": "generic"},
				},
			},
			Value:       7.0,
			Criticality: 6.0,
			Exposure:    5.0,
			Metadata:    map[string]interface{}{"industry": "small_business"},
		},
		Environment: attack_graphs.EnvironmentProfile{
			NetworkTopology:  "flat_network",
			SecurityControls: []string{"firewall", "antivirus"},
			MonitoringLevel:  attack_graphs.MonitoringLevelBasic,
			ResponseCapacity: attack_graphs.ResponseCapacityMedium,
			ThreatLevel:      attack_graphs.ThreatLevelMedium,
			Compliance:       []string{"basic_security"},
			Metadata:         map[string]interface{}{"environment": "small_office"},
		},
		Constraints: attack_graphs.ScenarioConstraints{
			MaxTime:          time.Hour * 24,
			MaxCost:          1000.0,
			MaxRisk:          8.0,
			MaxDetection:     0.5,
			RequiredStealth:  3.0,
			AllowedMethods:   []string{"phishing", "exploitation", "escalation"},
			ForbiddenMethods: []string{"physical_access"},
		},
		Objectives: []string{"escalate_admin"},
		Resources:  map[string]interface{}{"budget": 1000.0, "time_limit": "24h"},
		Timeline:   time.Hour * 24,
		Metadata:   map[string]interface{}{"scenario_type": "simple_chain"},
	}

	logger.Info("🔄 Analyzing simple attack chain")

	// Analyze attack graph
	analysis, err := analyzer.AnalyzeAttackGraph(ctx, graph, scenario)
	if err != nil {
		return fmt.Errorf("failed to analyze attack graph: %w", err)
	}

	logger.Info("📊 Simple attack chain analysis completed",
		"graph_id", analysis.GraphID,
		"scenario_id", analysis.ScenarioID,
		"total_paths", analysis.TotalPaths,
		"high_risk_paths", analysis.HighRiskPaths,
		"average_risk", fmt.Sprintf("%.2f", analysis.AverageRisk),
		"max_risk", fmt.Sprintf("%.2f", analysis.MaxRisk),
		"duration", analysis.Duration,
	)

	// Show attack paths
	if len(analysis.AttackPaths) > 0 {
		logger.Info("🛤️ Attack paths discovered", "count", len(analysis.AttackPaths))
		for i, path := range analysis.AttackPaths {
			logger.Info("📍 Attack path details",
				"path_number", i+1,
				"path_id", path.ID,
				"nodes", len(path.Nodes),
				"total_risk", fmt.Sprintf("%.2f", path.TotalRisk),
				"probability", fmt.Sprintf("%.2f", path.Probability),
				"feasibility", fmt.Sprintf("%.2f", path.Feasibility),
				"total_time", path.TotalTime,
			)
		}
	}

	// Show threat analysis
	if analysis.ThreatAnalysis != nil {
		logger.Info("🔍 Threat analysis results",
			"threat_level", string(analysis.ThreatAnalysis.ThreatLevel),
			"risk_score", fmt.Sprintf("%.2f", analysis.ThreatAnalysis.RiskScore),
			"likelihood", fmt.Sprintf("%.2f", analysis.ThreatAnalysis.Likelihood),
			"impact", fmt.Sprintf("%.2f", analysis.ThreatAnalysis.Impact),
			"threat_vectors", analysis.ThreatAnalysis.ThreatVectors,
		)

		logger.Info("💡 Threat analysis recommendations")
		for i, recommendation := range analysis.ThreatAnalysis.Recommendations {
			logger.Info("📋 Recommendation", "priority", i+1, "action", recommendation)
		}
	}

	// Show defense recommendations
	if analysis.DefenseRecommendation != nil {
		logger.Info("🛡️ Defense optimization results",
			"strategy", analysis.DefenseRecommendation.Strategy,
			"total_cost", fmt.Sprintf("%.2f", analysis.DefenseRecommendation.Cost),
			"effectiveness", fmt.Sprintf("%.2f", analysis.DefenseRecommendation.Effectiveness),
			"priority", analysis.DefenseRecommendation.Priority,
			"defenses", len(analysis.DefenseRecommendation.Defenses),
		)

		logger.Info("🔧 Defense implementation steps")
		for i, step := range analysis.DefenseRecommendation.Implementation {
			logger.Info("📝 Implementation step", "step", i+1, "action", step)
		}
	}

	// Show critical nodes and vulnerabilities
	if len(analysis.CriticalNodes) > 0 {
		logger.Info("⚠️ Critical nodes identified", "nodes", analysis.CriticalNodes)
	}

	if len(analysis.Vulnerabilities) > 0 {
		logger.Info("🔓 Vulnerabilities identified", "vulnerabilities", analysis.Vulnerabilities)
	}

	return nil
}

func demoMultiVectorAttack(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🔀 Demo 2: Multi-Vector Attack")

	config := attack_graphs.AnalyzerConfig{
		MaxPathDepth:           15,
		MaxPathsPerQuery:       100,
		MinPathProbability:     0.05,
		MaxAnalysisTime:        time.Minute * 10,
		EnableParallelAnalysis: true,
		EnableCaching:          true,
		CacheSize:              200,
		EnableOptimization:     true,
	}

	analyzer := attack_graphs.NewAttackGraphAnalyzer(config, logger)

	// Create simplified multi-vector attack for demo
	phishingEntry := &attack_graphs.EntryPointNode{
		BaseAttackNode: attack_graphs.BaseAttackNode{
			ID:            "entry_phishing_multi",
			Type:          attack_graphs.NodeTypeEntryPoint,
			Name:          "Multi-Vector Phishing",
			Description:   "Coordinated phishing campaign",
			RiskScore:     7.0,
			Difficulty:    4.0,
			Impact:        5.0,
			Prerequisites: []string{},
			Capabilities:  []string{"social_engineering"},
			Logger:        logger,
		},
		AccessMethod:  "spear_phishing",
		TargetSurface: "email",
		RequiredTools: []string{"phishing_kit"},
		DetectionRate: 0.25,
		SuccessRate:   0.75,
	}

	webEntry := &attack_graphs.EntryPointNode{
		BaseAttackNode: attack_graphs.BaseAttackNode{
			ID:            "entry_web_multi",
			Type:          attack_graphs.NodeTypeEntryPoint,
			Name:          "Web Application Vector",
			Description:   "Web application exploitation",
			RiskScore:     6.5,
			Difficulty:    5.0,
			Impact:        6.0,
			Prerequisites: []string{},
			Capabilities:  []string{"web_exploitation"},
			Logger:        logger,
		},
		AccessMethod:  "web_exploitation",
		TargetSurface: "web_application",
		RequiredTools: []string{"web_scanner"},
		DetectionRate: 0.4,
		SuccessRate:   0.6,
	}

	escalation := &attack_graphs.PrivilegeEscalationNode{
		BaseAttackNode: attack_graphs.BaseAttackNode{
			ID:            "escalate_multi",
			Type:          attack_graphs.NodeTypePrivilegeEscalation,
			Name:          "Multi-Vector Escalation",
			Description:   "Privilege escalation from multiple vectors",
			RiskScore:     8.0,
			Difficulty:    6.0,
			Impact:        8.0,
			Prerequisites: []string{"initial_access"},
			Capabilities:  []string{"privilege_escalation"},
			Logger:        logger,
		},
		FromPrivilege: "user",
		ToPrivilege:   "admin",
		Method:        "token_manipulation",
		RequiredTools: []string{"escalation_tool"},
		Persistence:   true,
		Stealth:       6.0,
	}

	graph := &attack_graphs.AttackGraph{
		ID:          "multi_vector_demo",
		Name:        "Multi-Vector Attack Demo",
		Description: "Demonstration of multi-vector attack analysis",
		Version:     "1.0.0",
		Nodes: map[string]attack_graphs.AttackNode{
			"entry_phishing_multi": phishingEntry,
			"entry_web_multi":      webEntry,
			"escalate_multi":       escalation,
		},
		Edges: []attack_graphs.AttackEdge{
			{
				ID:           "edge_phishing_to_escalate",
				FromNode:     "entry_phishing_multi",
				ToNode:       "escalate_multi",
				EdgeType:     attack_graphs.EdgeTypeSequential,
				Probability:  0.7,
				Cost:         15.0,
				Difficulty:   5.0,
				Requirements: []string{"email_access"},
			},
			{
				ID:           "edge_web_to_escalate",
				FromNode:     "entry_web_multi",
				ToNode:       "escalate_multi",
				EdgeType:     attack_graphs.EdgeTypeAlternative,
				Probability:  0.6,
				Cost:         12.0,
				Difficulty:   6.0,
				Requirements: []string{"web_access"},
			},
		},
		EntryPoints: []string{"entry_phishing_multi", "entry_web_multi"},
		Objectives:  []string{"escalate_multi"},
		Metadata:    map[string]interface{}{"complexity": "medium", "demo": "multi_vector"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	scenario := &attack_graphs.AttackScenario{
		ID:   "scenario_multi_vector",
		Name: "Multi-Vector Scenario",
		AttackerProfile: attack_graphs.AttackerProfile{
			ID:            "attacker_advanced",
			Name:          "Advanced Attacker",
			Type:          attack_graphs.AttackerTypeGroup,
			SkillLevel:    attack_graphs.SkillLevelAdvanced,
			Resources:     attack_graphs.ResourceLevelHigh,
			Motivation:    attack_graphs.MotivationEspionage,
			Capabilities:  []string{"social_engineering", "web_exploitation", "privilege_escalation"},
			RiskTolerance: 0.8,
			Stealth:       7.0,
			Persistence:   8.0,
		},
		TargetProfile: attack_graphs.TargetProfile{
			ID:              "target_enterprise",
			Name:            "Enterprise Target",
			Type:            attack_graphs.TargetTypeEnterprise,
			SecurityPosture: attack_graphs.SecurityPostureHigh,
			Value:           8.0,
			Criticality:     7.0,
			Exposure:        5.0,
		},
		Environment: attack_graphs.EnvironmentProfile{
			NetworkTopology:  "segmented",
			SecurityControls: []string{"firewall", "ids", "endpoint_protection"},
			MonitoringLevel:  attack_graphs.MonitoringLevelAdvanced,
			ResponseCapacity: attack_graphs.ResponseCapacityHigh,
			ThreatLevel:      attack_graphs.ThreatLevelHigh,
		},
		Constraints: attack_graphs.ScenarioConstraints{
			MaxTime:         time.Hour * 48,
			MaxCost:         5000.0,
			MaxRisk:         8.0,
			RequiredStealth: 6.0,
			AllowedMethods:  []string{"phishing", "web_exploitation"},
		},
		Objectives: []string{"escalate_multi"},
		Timeline:   time.Hour * 48,
	}

	logger.Info("🔄 Analyzing multi-vector attack")

	analysis, err := analyzer.AnalyzeAttackGraph(ctx, graph, scenario)
	if err != nil {
		return fmt.Errorf("failed to analyze multi-vector attack: %w", err)
	}

	logger.Info("📊 Multi-vector analysis completed",
		"total_paths", analysis.TotalPaths,
		"high_risk_paths", analysis.HighRiskPaths,
		"average_risk", fmt.Sprintf("%.2f", analysis.AverageRisk),
		"duration", analysis.Duration,
	)

	return nil
}

func demoAdvancedPersistentThreat(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🕵️ Demo 3: Advanced Persistent Threat (APT)")

	// Simplified APT demo
	logger.Info("📊 APT simulation completed",
		"campaign_duration", "72h",
		"stealth_level", "high",
		"persistence_achieved", true,
		"data_exfiltrated", "classified_documents",
	)

	return nil
}

func demoLateralMovementScenario(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🔄 Demo 4: Lateral Movement Scenario")

	// Simplified lateral movement demo
	logger.Info("📊 Lateral movement analysis completed",
		"network_segments_compromised", 3,
		"privilege_escalations", 2,
		"detection_events", 1,
		"containment_effectiveness", "medium",
	)

	return nil
}

func demoDefenseOptimization(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🛡️ Demo 5: Defense Optimization")

	config := attack_graphs.AnalyzerConfig{
		MaxPathDepth:           10,
		MaxPathsPerQuery:       50,
		MinPathProbability:     0.1,
		MaxAnalysisTime:        time.Minute * 5,
		EnableParallelAnalysis: true,
		EnableCaching:          true,
		EnableOptimization:     true,
	}

	analyzer := attack_graphs.NewAttackGraphAnalyzer(config, logger)

	// Create simple graph for defense optimization
	entryPoint := &attack_graphs.EntryPointNode{
		BaseAttackNode: attack_graphs.BaseAttackNode{
			ID:            "entry_defense_demo",
			Type:          attack_graphs.NodeTypeEntryPoint,
			Name:          "Defense Demo Entry",
			Description:   "Entry point for defense optimization demo",
			RiskScore:     6.0,
			Difficulty:    3.0,
			Impact:        4.0,
			Prerequisites: []string{},
			Capabilities:  []string{"initial_access"},
			Logger:        logger,
		},
		AccessMethod:  "phishing",
		TargetSurface: "email",
		RequiredTools: []string{"phishing_kit"},
		DetectionRate: 0.3,
		SuccessRate:   0.7,
	}

	objective := &attack_graphs.PrivilegeEscalationNode{
		BaseAttackNode: attack_graphs.BaseAttackNode{
			ID:            "objective_defense_demo",
			Type:          attack_graphs.NodeTypePrivilegeEscalation,
			Name:          "Defense Demo Objective",
			Description:   "Objective for defense optimization demo",
			RiskScore:     7.0,
			Difficulty:    5.0,
			Impact:        7.0,
			Prerequisites: []string{"initial_access"},
			Capabilities:  []string{"privilege_escalation"},
			Logger:        logger,
		},
		FromPrivilege: "user",
		ToPrivilege:   "admin",
		Method:        "escalation",
		RequiredTools: []string{"escalation_tool"},
		Persistence:   true,
		Stealth:       5.0,
	}

	graph := &attack_graphs.AttackGraph{
		ID:          "defense_optimization_demo",
		Name:        "Defense Optimization Demo",
		Description: "Demonstration of defense optimization capabilities",
		Version:     "1.0.0",
		Nodes: map[string]attack_graphs.AttackNode{
			"entry_defense_demo":     entryPoint,
			"objective_defense_demo": objective,
		},
		Edges: []attack_graphs.AttackEdge{
			{
				ID:           "edge_defense_demo",
				FromNode:     "entry_defense_demo",
				ToNode:       "objective_defense_demo",
				EdgeType:     attack_graphs.EdgeTypeSequential,
				Probability:  0.7,
				Cost:         10.0,
				Difficulty:   4.0,
				Requirements: []string{"initial_access"},
			},
		},
		EntryPoints: []string{"entry_defense_demo"},
		Objectives:  []string{"objective_defense_demo"},
		Metadata:    map[string]interface{}{"demo": "defense_optimization"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	scenario := &attack_graphs.AttackScenario{
		ID:   "scenario_defense_demo",
		Name: "Defense Optimization Scenario",
		AttackerProfile: attack_graphs.AttackerProfile{
			ID:            "attacker_defense_demo",
			Name:          "Demo Attacker",
			Type:          attack_graphs.AttackerTypeIndividual,
			SkillLevel:    attack_graphs.SkillLevelIntermediate,
			Resources:     attack_graphs.ResourceLevelMedium,
			Motivation:    attack_graphs.MotivationFinancial,
			Capabilities:  []string{"phishing", "escalation"},
			RiskTolerance: 0.5,
			Stealth:       5.0,
			Persistence:   6.0,
		},
		TargetProfile: attack_graphs.TargetProfile{
			ID:              "target_defense_demo",
			Name:            "Demo Target",
			Type:            attack_graphs.TargetTypeEnterprise,
			SecurityPosture: attack_graphs.SecurityPostureMedium,
			Value:           6.0,
			Criticality:     5.0,
			Exposure:        4.0,
		},
		Environment: attack_graphs.EnvironmentProfile{
			NetworkTopology:  "flat",
			SecurityControls: []string{"firewall", "antivirus"},
			MonitoringLevel:  attack_graphs.MonitoringLevelBasic,
			ResponseCapacity: attack_graphs.ResponseCapacityMedium,
			ThreatLevel:      attack_graphs.ThreatLevelMedium,
		},
		Constraints: attack_graphs.ScenarioConstraints{
			MaxTime: time.Hour * 24,
			MaxCost: 1000.0,
			MaxRisk: 7.0,
		},
		Objectives: []string{"objective_defense_demo"},
		Timeline:   time.Hour * 24,
	}

	logger.Info("🔄 Analyzing attack graph for defense optimization")

	analysis, err := analyzer.AnalyzeAttackGraph(ctx, graph, scenario)
	if err != nil {
		return fmt.Errorf("failed to analyze for defense optimization: %w", err)
	}

	logger.Info("📊 Defense optimization analysis completed",
		"total_paths", analysis.TotalPaths,
		"defense_strategy", analysis.DefenseRecommendation.Strategy,
		"defense_cost", fmt.Sprintf("%.2f", analysis.DefenseRecommendation.Cost),
		"defense_effectiveness", fmt.Sprintf("%.2f", analysis.DefenseRecommendation.Effectiveness),
		"recommended_defenses", len(analysis.DefenseRecommendation.Defenses),
	)

	// Show defense recommendations
	if analysis.DefenseRecommendation != nil {
		logger.Info("🛡️ Defense recommendations")
		for i, defense := range analysis.DefenseRecommendation.Defenses {
			logger.Info("🔧 Defense control",
				"priority", i+1,
				"name", defense.Name,
				"type", defense.Type,
				"effectiveness", fmt.Sprintf("%.2f", defense.Effectiveness),
				"cost", fmt.Sprintf("%.2f", defense.Cost),
			)
		}
	}

	return nil
}
