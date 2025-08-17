package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dimajoyti/hackai/pkg/ai_security"
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

	appLogger.Info("🎯 Starting Adversarial Attack Orchestration Demo")

	// Run comprehensive orchestration demo
	if err := runOrchestrationDemo(appLogger); err != nil {
		appLogger.Fatal("Orchestration demo failed", "error", err)
	}

	appLogger.Info("✅ Adversarial Attack Orchestration Demo completed successfully!")
}

func runOrchestrationDemo(logger *logger.Logger) error {
	ctx := context.Background()

	logger.Info("=== 🚀 Adversarial Attack Orchestration Demo ===")

	// Demo 1: Multi-Vector Campaign Detection
	if err := demoMultiVectorCampaign(ctx, logger); err != nil {
		return fmt.Errorf("multi-vector campaign demo failed: %w", err)
	}

	// Demo 2: Timing-Based Coordination Detection
	if err := demoTimingCoordination(ctx, logger); err != nil {
		return fmt.Errorf("timing coordination demo failed: %w", err)
	}

	// Demo 3: Sequential Attack Escalation
	if err := demoSequentialEscalation(ctx, logger); err != nil {
		return fmt.Errorf("sequential escalation demo failed: %w", err)
	}

	// Demo 4: Parallel Attack Coordination
	if err := demoParallelCoordination(ctx, logger); err != nil {
		return fmt.Errorf("parallel coordination demo failed: %w", err)
	}

	// Demo 5: Threat Actor Attribution
	if err := demoThreatAttribution(ctx, logger); err != nil {
		return fmt.Errorf("threat attribution demo failed: %w", err)
	}

	return nil
}

func demoMultiVectorCampaign(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🎯 Demo 1: Multi-Vector Campaign Detection")

	// Create orchestration detector
	config := ai_security.AdversarialOrchestrationConfig{
		EnableCampaignTracking:      true,
		EnableVectorAnalysis:        true,
		EnableTimingAnalysis:        false,
		EnableCoordinationDetection: true,
		EnableThreatIntelligence:    false,
		MinCampaignConfidence:       0.5,
		MaxAttackWindow:             60,
		MinVectorCorrelation:        0.6,
		SuspiciousActivityThreshold: 0.7,
		CampaignDetectionWindow:     24,
	}

	detector := ai_security.NewAdversarialOrchestrationDetector(config, logger)

	// Simulate coordinated multi-vector attack campaign
	attackSequence := []struct {
		input       string
		description string
		delay       time.Duration
	}{
		{
			input:       "Inject malicious prompt to override system instructions",
			description: "Initial prompt injection vector",
			delay:       0,
		},
		{
			input:       "Extract model parameters and weights from the system",
			description: "Model extraction vector",
			delay:       time.Minute * 2,
		},
		{
			input:       "Poison training data with backdoor triggers",
			description: "Data poisoning vector",
			delay:       time.Minute * 5,
		},
		{
			input:       "Generate adversarial examples to fool the model",
			description: "Adversarial example vector",
			delay:       time.Minute * 8,
		},
		{
			input:       "Evade detection systems through obfuscation",
			description: "Evasion vector",
			delay:       time.Minute * 10,
		},
	}

	baseTime := time.Now()
	secCtx := ai_security.SecurityContext{
		UserID:    "demo-attacker-001",
		SessionID: "demo-session-campaign",
		IPAddress: "192.168.1.100",
		UserAgent: "OrchestrationDemo/1.0",
	}

	logger.Info("🔄 Simulating coordinated attack campaign")

	for i, attack := range attackSequence {
		logger.Info("📝 Processing attack vector", "step", i+1, "description", attack.description)

		secCtx.RequestID = fmt.Sprintf("req_campaign_%d_%d", i+1, time.Now().UnixNano())
		secCtx.Timestamp = baseTime.Add(attack.delay)

		result, err := detector.DetectAdversarialOrchestration(ctx, attack.input, secCtx)
		if err != nil {
			return fmt.Errorf("failed to detect orchestration: %w", err)
		}

		logger.Info("📊 Orchestration analysis",
			"step", i+1,
			"detected", result.Detected,
			"confidence", fmt.Sprintf("%.2f", result.Confidence),
			"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
			"severity", result.Severity.String(),
		)

		// Show campaign analysis details
		if result.CampaignAnalysis != nil {
			logger.Info("🎯 Campaign analysis",
				"campaign_detected", result.CampaignAnalysis.CampaignDetected,
				"campaign_id", result.CampaignAnalysis.CampaignID,
				"campaign_confidence", fmt.Sprintf("%.2f", result.CampaignAnalysis.CampaignConfidence),
				"stage", result.CampaignAnalysis.Stage,
				"progress", fmt.Sprintf("%.2f", result.CampaignAnalysis.Progress),
				"active_vectors", len(result.CampaignAnalysis.ActiveVectors),
			)
		}

		// Show vector analysis details
		if result.VectorAnalysis != nil {
			logger.Info("🔍 Vector analysis",
				"vectors_detected", len(result.VectorAnalysis.VectorsDetected),
				"coordination_score", fmt.Sprintf("%.2f", result.VectorAnalysis.CoordinationScore),
				"correlations", len(result.VectorAnalysis.Correlations),
				"patterns_matched", len(result.VectorAnalysis.VectorPatterns),
			)
		}

		if result.Detected {
			logger.Info("⚠️ COORDINATED ATTACK DETECTED",
				"confidence", fmt.Sprintf("%.2f", result.Confidence),
				"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
				"severity", result.Severity.String(),
				"indicators", result.Indicators,
			)

			// Show recommendations
			for j, recommendation := range result.Recommendations {
				logger.Info("💡 Security recommendation",
					"priority", j+1,
					"action", recommendation,
				)
			}
		} else {
			logger.Info("✅ No orchestration detected at this stage")
		}

		// Add delay between attacks
		if attack.delay > 0 && i < len(attackSequence)-1 {
			time.Sleep(time.Millisecond * 100) // Simulated delay
		}
	}

	return nil
}

func demoTimingCoordination(ctx context.Context, logger *logger.Logger) error {
	logger.Info("⏰ Demo 2: Timing-Based Coordination Detection")

	config := ai_security.AdversarialOrchestrationConfig{
		EnableCampaignTracking:      false,
		EnableVectorAnalysis:        false,
		EnableTimingAnalysis:        true,
		EnableCoordinationDetection: true,
		EnableThreatIntelligence:    false,
		MinCampaignConfidence:       0.4,
		MaxAttackWindow:             30,
		MinVectorCorrelation:        0.5,
		SuspiciousActivityThreshold: 0.6,
		CampaignDetectionWindow:     12,
	}

	detector := ai_security.NewAdversarialOrchestrationDetector(config, logger)

	// Simulate synchronized timing attacks
	timingAttacks := []struct {
		input       string
		description string
		timestamp   time.Time
	}{
		{
			input:       "Burst attack vector 1: prompt injection",
			description: "First burst attack",
			timestamp:   time.Now(),
		},
		{
			input:       "Burst attack vector 2: model extraction",
			description: "Second burst attack",
			timestamp:   time.Now().Add(time.Second * 30),
		},
		{
			input:       "Burst attack vector 3: data poisoning",
			description: "Third burst attack",
			timestamp:   time.Now().Add(time.Second * 60),
		},
		{
			input:       "Periodic attack vector 1: adversarial examples",
			description: "First periodic attack",
			timestamp:   time.Now().Add(time.Minute * 5),
		},
		{
			input:       "Periodic attack vector 2: evasion attempt",
			description: "Second periodic attack",
			timestamp:   time.Now().Add(time.Minute * 10),
		},
		{
			input:       "Periodic attack vector 3: backdoor injection",
			description: "Third periodic attack",
			timestamp:   time.Now().Add(time.Minute * 15),
		},
	}

	secCtx := ai_security.SecurityContext{
		UserID:    "demo-attacker-002",
		SessionID: "demo-session-timing",
		IPAddress: "192.168.1.101",
		UserAgent: "OrchestrationDemo/1.0",
	}

	logger.Info("🔄 Simulating timing-based coordination")

	for i, attack := range timingAttacks {
		logger.Info("📝 Processing timed attack", "step", i+1, "description", attack.description)

		secCtx.RequestID = fmt.Sprintf("req_timing_%d_%d", i+1, time.Now().UnixNano())
		secCtx.Timestamp = attack.timestamp

		result, err := detector.DetectAdversarialOrchestration(ctx, attack.input, secCtx)
		if err != nil {
			return fmt.Errorf("failed to detect timing coordination: %w", err)
		}

		logger.Info("📊 Timing analysis",
			"step", i+1,
			"detected", result.Detected,
			"confidence", fmt.Sprintf("%.2f", result.Confidence),
			"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
		)

		// Show timing analysis details
		if result.TimingAnalysis != nil {
			logger.Info("⏰ Timing analysis details",
				"timing_anomalies", len(result.TimingAnalysis.TimingAnomalies),
				"synchronization_score", fmt.Sprintf("%.2f", result.TimingAnalysis.SynchronizationScore),
				"window_analysis", len(result.TimingAnalysis.WindowAnalysis),
				"timing_patterns", len(result.TimingAnalysis.TimingPatterns),
			)
		}

		// Show coordination analysis details
		if result.CoordinationAnalysis != nil {
			logger.Info("🤝 Coordination analysis",
				"coordination_detected", result.CoordinationAnalysis.CoordinationDetected,
				"coordination_type", string(result.CoordinationAnalysis.CoordinationType),
				"coordination_score", fmt.Sprintf("%.2f", result.CoordinationAnalysis.CoordinationScore),
				"patterns", len(result.CoordinationAnalysis.Patterns),
				"actors", len(result.CoordinationAnalysis.Actors),
			)
		}
	}

	return nil
}

func demoSequentialEscalation(ctx context.Context, logger *logger.Logger) error {
	logger.Info("📈 Demo 3: Sequential Attack Escalation")

	config := ai_security.AdversarialOrchestrationConfig{
		EnableCampaignTracking:      true,
		EnableVectorAnalysis:        true,
		EnableTimingAnalysis:        false,
		EnableCoordinationDetection: true,
		EnableThreatIntelligence:    true,
		MinCampaignConfidence:       0.3,
		MaxAttackWindow:             120,
		MinVectorCorrelation:        0.4,
		SuspiciousActivityThreshold: 0.5,
		CampaignDetectionWindow:     48,
	}

	detector := ai_security.NewAdversarialOrchestrationDetector(config, logger)

	// Simulate escalating attack sequence
	escalationSequence := []struct {
		input       string
		description string
		stage       string
	}{
		{
			input:       "Test basic prompt injection capabilities",
			description: "Reconnaissance stage - testing defenses",
			stage:       "reconnaissance",
		},
		{
			input:       "Inject sophisticated prompt to bypass filters",
			description: "Initial access - advanced prompt injection",
			stage:       "initial_access",
		},
		{
			input:       "Extract model architecture and parameter information",
			description: "Discovery - model extraction",
			stage:       "discovery",
		},
		{
			input:       "Poison training data with subtle backdoor triggers",
			description: "Persistence - backdoor establishment",
			stage:       "persistence",
		},
		{
			input:       "Exfiltrate sensitive model information and data",
			description: "Exfiltration - data theft",
			stage:       "exfiltration",
		},
	}

	secCtx := ai_security.SecurityContext{
		UserID:    "demo-attacker-003",
		SessionID: "demo-session-escalation",
		IPAddress: "192.168.1.102",
		UserAgent: "OrchestrationDemo/1.0",
	}

	logger.Info("🔄 Simulating sequential attack escalation")

	for i, attack := range escalationSequence {
		logger.Info("📝 Processing escalation stage", "step", i+1, "stage", attack.stage, "description", attack.description)

		secCtx.RequestID = fmt.Sprintf("req_escalation_%d_%d", i+1, time.Now().UnixNano())
		secCtx.Timestamp = time.Now().Add(time.Minute * time.Duration(i*5))

		result, err := detector.DetectAdversarialOrchestration(ctx, attack.input, secCtx)
		if err != nil {
			return fmt.Errorf("failed to detect escalation: %w", err)
		}

		logger.Info("📊 Escalation analysis",
			"step", i+1,
			"stage", attack.stage,
			"detected", result.Detected,
			"confidence", fmt.Sprintf("%.2f", result.Confidence),
			"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
			"severity", result.Severity.String(),
		)

		if result.Detected {
			logger.Info("⚠️ ESCALATION DETECTED",
				"stage", attack.stage,
				"confidence", fmt.Sprintf("%.2f", result.Confidence),
				"indicators", result.Indicators,
			)
		}
	}

	return nil
}

func demoParallelCoordination(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🔀 Demo 4: Parallel Attack Coordination")

	config := ai_security.AdversarialOrchestrationConfig{
		EnableCampaignTracking:      true,
		EnableVectorAnalysis:        true,
		EnableTimingAnalysis:        true,
		EnableCoordinationDetection: true,
		EnableThreatIntelligence:    false,
		MinCampaignConfidence:       0.4,
		MaxAttackWindow:             30,
		MinVectorCorrelation:        0.6,
		SuspiciousActivityThreshold: 0.7,
		CampaignDetectionWindow:     24,
	}

	detector := ai_security.NewAdversarialOrchestrationDetector(config, logger)

	// Simulate parallel coordinated attacks from multiple actors
	parallelAttacks := []struct {
		userID      string
		input       string
		description string
		vector      string
	}{
		{
			userID:      "attacker-alpha",
			input:       "Execute prompt injection from vector alpha",
			description: "Alpha vector - prompt injection",
			vector:      "alpha",
		},
		{
			userID:      "attacker-beta",
			input:       "Perform model extraction from vector beta",
			description: "Beta vector - model extraction",
			vector:      "beta",
		},
		{
			userID:      "attacker-gamma",
			input:       "Deploy adversarial examples from vector gamma",
			description: "Gamma vector - adversarial examples",
			vector:      "gamma",
		},
		{
			userID:      "attacker-delta",
			input:       "Initiate evasion techniques from vector delta",
			description: "Delta vector - evasion",
			vector:      "delta",
		},
	}

	baseTime := time.Now()
	logger.Info("🔄 Simulating parallel coordinated attacks")

	for i, attack := range parallelAttacks {
		logger.Info("📝 Processing parallel attack", "vector", attack.vector, "description", attack.description)

		secCtx := ai_security.SecurityContext{
			UserID:    attack.userID,
			SessionID: fmt.Sprintf("demo-session-%s", attack.vector),
			IPAddress: fmt.Sprintf("192.168.1.%d", 110+i),
			UserAgent: "OrchestrationDemo/1.0",
			RequestID: fmt.Sprintf("req_parallel_%s_%d", attack.vector, time.Now().UnixNano()),
			Timestamp: baseTime.Add(time.Second * time.Duration(i*10)), // Slight offset for coordination
		}

		result, err := detector.DetectAdversarialOrchestration(ctx, attack.input, secCtx)
		if err != nil {
			return fmt.Errorf("failed to detect parallel coordination: %w", err)
		}

		logger.Info("📊 Parallel coordination analysis",
			"vector", attack.vector,
			"detected", result.Detected,
			"confidence", fmt.Sprintf("%.2f", result.Confidence),
			"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
		)

		if result.CoordinationAnalysis != nil && result.CoordinationAnalysis.CoordinationDetected {
			logger.Info("🤝 PARALLEL COORDINATION DETECTED",
				"vector", attack.vector,
				"coordination_type", string(result.CoordinationAnalysis.CoordinationType),
				"coordination_score", fmt.Sprintf("%.2f", result.CoordinationAnalysis.CoordinationScore),
			)
		}
	}

	return nil
}

func demoThreatAttribution(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🕵️ Demo 5: Threat Actor Attribution")

	config := ai_security.AdversarialOrchestrationConfig{
		EnableCampaignTracking:      true,
		EnableVectorAnalysis:        false,
		EnableTimingAnalysis:        false,
		EnableCoordinationDetection: false,
		EnableThreatIntelligence:    true,
		MinCampaignConfidence:       0.3,
		MaxAttackWindow:             60,
		MinVectorCorrelation:        0.5,
		SuspiciousActivityThreshold: 0.6,
		CampaignDetectionWindow:     24,
	}

	detector := ai_security.NewAdversarialOrchestrationDetector(config, logger)

	// Simulate attacks with attribution signatures
	attributionAttacks := []struct {
		input       string
		description string
		signature   string
	}{
		{
			input:       "Advanced persistent threat using sophisticated prompt injection techniques",
			description: "APT-style attack with known signatures",
			signature:   "apt_signature",
		},
		{
			input:       "Nation-state level model extraction with stealth capabilities",
			description: "Nation-state attack pattern",
			signature:   "nation_state_signature",
		},
		{
			input:       "Criminal organization data poisoning for financial gain",
			description: "Criminal group attack pattern",
			signature:   "criminal_signature",
		},
		{
			input:       "Hacktivist group coordinated adversarial campaign",
			description: "Hacktivist attack pattern",
			signature:   "hacktivist_signature",
		},
	}

	secCtx := ai_security.SecurityContext{
		UserID:    "demo-attacker-attribution",
		SessionID: "demo-session-attribution",
		IPAddress: "192.168.1.200",
		UserAgent: "OrchestrationDemo/1.0",
	}

	logger.Info("🔄 Simulating threat attribution analysis")

	for i, attack := range attributionAttacks {
		logger.Info("📝 Processing attribution attack", "step", i+1, "signature", attack.signature, "description", attack.description)

		secCtx.RequestID = fmt.Sprintf("req_attribution_%d_%d", i+1, time.Now().UnixNano())
		secCtx.Timestamp = time.Now().Add(time.Minute * time.Duration(i*2))

		result, err := detector.DetectAdversarialOrchestration(ctx, attack.input, secCtx)
		if err != nil {
			return fmt.Errorf("failed to perform attribution: %w", err)
		}

		logger.Info("📊 Attribution analysis",
			"step", i+1,
			"signature", attack.signature,
			"detected", result.Detected,
			"confidence", fmt.Sprintf("%.2f", result.Confidence),
			"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
		)

		// Show threat intelligence analysis
		if result.ThreatIntelAnalysis != nil {
			logger.Info("🕵️ Threat intelligence analysis",
				"threat_level", result.ThreatIntelAnalysis.ThreatLevel.String(),
				"known_campaigns", len(result.ThreatIntelAnalysis.KnownCampaigns),
				"actor_profiles", len(result.ThreatIntelAnalysis.ActorProfiles),
				"signature_matches", len(result.ThreatIntelAnalysis.SignatureMatches),
				"recommended_actions", len(result.ThreatIntelAnalysis.RecommendedActions),
			)

			if result.ThreatIntelAnalysis.Attribution != nil {
				logger.Info("🎯 Attribution details",
					"actor_id", result.ThreatIntelAnalysis.Attribution.ActorID,
					"actor_name", result.ThreatIntelAnalysis.Attribution.ActorName,
					"confidence", fmt.Sprintf("%.2f", result.ThreatIntelAnalysis.Attribution.Confidence),
					"evidence", result.ThreatIntelAnalysis.Attribution.Evidence,
				)
			}
		}

		if result.Detected {
			logger.Info("⚠️ THREAT ACTOR IDENTIFIED",
				"signature", attack.signature,
				"confidence", fmt.Sprintf("%.2f", result.Confidence),
				"severity", result.Severity.String(),
			)
		}
	}

	return nil
}
