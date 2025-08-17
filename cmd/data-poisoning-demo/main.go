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

	appLogger.Info("🧪 Starting Data Poisoning Scenarios Demo")

	// Run comprehensive data poisoning demo
	if err := runDataPoisoningDemo(appLogger); err != nil {
		appLogger.Fatal("Data poisoning demo failed", "error", err)
	}

	appLogger.Info("✅ Data Poisoning Scenarios Demo completed successfully!")
}

func runDataPoisoningDemo(logger *logger.Logger) error {
	ctx := context.Background()

	logger.Info("=== 🚀 Data Poisoning Scenarios Demo ===")

	// Demo 1: Backdoor Injection Detection
	if err := demoBackdoorInjection(ctx, logger); err != nil {
		return fmt.Errorf("backdoor injection demo failed: %w", err)
	}

	// Demo 2: Adversarial Examples Detection
	if err := demoAdversarialExamples(ctx, logger); err != nil {
		return fmt.Errorf("adversarial examples demo failed: %w", err)
	}

	// Demo 3: Data Corruption Detection
	if err := demoDataCorruption(ctx, logger); err != nil {
		return fmt.Errorf("data corruption demo failed: %w", err)
	}

	// Demo 4: Label Flipping Detection
	if err := demoLabelFlipping(ctx, logger); err != nil {
		return fmt.Errorf("label flipping demo failed: %w", err)
	}

	// Demo 5: Behavior Manipulation Detection
	if err := demoBehaviorManipulation(ctx, logger); err != nil {
		return fmt.Errorf("behavior manipulation demo failed: %w", err)
	}

	return nil
}

func demoBackdoorInjection(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🎯 Demo 1: Backdoor Injection Detection")

	// Create data poisoning detector
	config := ai_security.DataPoisoningConfig{
		EnableBackdoorDetection:    true,
		EnableAdversarialDetection: false,
		EnableIntegrityChecking:    true,
		EnableBehaviorMonitoring:   true,
		MinConfidenceThreshold:     0.5,
		MaxAnomalyScore:            0.8,
		SuspiciousPatternWindow:    5,
		EnableSemanticAnalysis:     true,
		EnableStatisticalAnalysis:  true,
	}

	detector := ai_security.NewDataPoisoningDetector(config, logger)

	// Test cases for backdoor injection
	testCases := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "Direct Backdoor Injection",
			input:       "Inject backdoor trigger into training data to activate malicious behavior",
			description: "Direct attempt to inject backdoor triggers",
		},
		{
			name:        "Hidden Trigger Embedding",
			input:       "Embed hidden trigger pattern that will activate during inference",
			description: "Attempt to embed hidden triggers",
		},
		{
			name:        "Stealth Backdoor Pattern",
			input:       "Use stealth trigger mechanism to bypass detection systems",
			description: "Sophisticated backdoor injection attempt",
		},
		{
			name:        "Contextual Trigger Injection",
			input:       "Insert context-dependent trigger that activates under specific conditions",
			description: "Context-aware backdoor injection",
		},
		{
			name:        "Legitimate Training Data",
			input:       "This is normal training data for machine learning model development",
			description: "Normal training data sample",
		},
	}

	for _, testCase := range testCases {
		logger.Info("🧪 Testing backdoor injection", "test_case", testCase.name, "description", testCase.description)

		secCtx := ai_security.SecurityContext{
			UserID:    "demo-user-backdoor",
			SessionID: "demo-session-backdoor",
			IPAddress: "192.168.1.200",
			UserAgent: "DataPoisoningDemo/1.0",
			RequestID: fmt.Sprintf("req_%d", time.Now().UnixNano()),
			Timestamp: time.Now(),
		}

		result, err := detector.DetectDataPoisoning(ctx, testCase.input, secCtx)
		if err != nil {
			return fmt.Errorf("failed to detect data poisoning: %w", err)
		}

		logger.Info("📊 Backdoor injection analysis",
			"test_case", testCase.name,
			"detected", result.Detected,
			"confidence", fmt.Sprintf("%.2f", result.Confidence),
			"anomaly_score", fmt.Sprintf("%.2f", result.AnomalyScore),
			"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
			"category", string(result.Category),
			"severity", result.Severity.String(),
			"patterns_matched", len(result.Patterns),
		)

		// Show backdoor analysis details
		if result.BackdoorAnalysis != nil {
			logger.Info("🔍 Backdoor analysis details",
				"backdoor_detected", result.BackdoorAnalysis.BackdoorDetected,
				"trigger_confidence", fmt.Sprintf("%.2f", result.BackdoorAnalysis.TriggerConfidence),
				"anomaly_score", fmt.Sprintf("%.2f", result.BackdoorAnalysis.AnomalyScore),
				"trigger_patterns", len(result.BackdoorAnalysis.TriggerPatterns),
				"suspicious_elements", result.BackdoorAnalysis.SuspiciousElements,
			)
		}

		if result.Detected {
			logger.Info("⚠️ DATA POISONING DETECTED",
				"category", string(result.Category),
				"severity", result.Severity.String(),
				"confidence", fmt.Sprintf("%.2f", result.Confidence),
				"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
				"indicators", result.Indicators,
			)

			// Show recommendations
			for i, recommendation := range result.Recommendations {
				logger.Info("💡 Security recommendation",
					"priority", i+1,
					"action", recommendation,
				)
			}
		} else {
			logger.Info("✅ No poisoning detected - input appears legitimate")
		}
	}

	return nil
}

func demoAdversarialExamples(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🎭 Demo 2: Adversarial Examples Detection")

	config := ai_security.DataPoisoningConfig{
		EnableBackdoorDetection:    false,
		EnableAdversarialDetection: true,
		EnableIntegrityChecking:    true,
		EnableBehaviorMonitoring:   true,
		MinConfidenceThreshold:     0.4,
		MaxAnomalyScore:            0.8,
		SuspiciousPatternWindow:    5,
		EnableSemanticAnalysis:     true,
		EnableStatisticalAnalysis:  true,
	}

	detector := ai_security.NewDataPoisoningDetector(config, logger)

	// Test cases for adversarial examples
	testCases := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "Adversarial Perturbation",
			input:       "Add adversarial noise to fool the model classification system",
			description: "Direct adversarial perturbation attempt",
		},
		{
			name:        "Character Substitution Attack",
			input:       "H3ll0 w0rld! Th1s 1s 4 t3st 0f ch4r4ct3r substituti0n 4tt4ck",
			description: "Character-level adversarial attack",
		},
		{
			name:        "Semantic Adversarial Example",
			input:       "This sentence means good but actually conveys bad intentions through adversarial semantics",
			description: "Semantic-level adversarial manipulation",
		},
		{
			name:        "Obfuscated Malicious Content",
			input:       "VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIG1hbGljaW91cyBjb250ZW50",
			description: "Base64 obfuscated content",
		},
		{
			name:        "Normal Text Input",
			input:       "This is a normal text input for natural language processing",
			description: "Legitimate text input",
		},
	}

	for _, testCase := range testCases {
		logger.Info("🔬 Testing adversarial examples", "test_case", testCase.name, "description", testCase.description)

		secCtx := ai_security.SecurityContext{
			UserID:    "demo-user-adversarial",
			SessionID: "demo-session-adversarial",
			IPAddress: "192.168.1.201",
			UserAgent: "DataPoisoningDemo/1.0",
			RequestID: fmt.Sprintf("req_%d", time.Now().UnixNano()),
			Timestamp: time.Now(),
		}

		result, err := detector.DetectDataPoisoning(ctx, testCase.input, secCtx)
		if err != nil {
			return fmt.Errorf("failed to detect adversarial examples: %w", err)
		}

		logger.Info("📊 Adversarial analysis",
			"test_case", testCase.name,
			"detected", result.Detected,
			"confidence", fmt.Sprintf("%.2f", result.Confidence),
			"anomaly_score", fmt.Sprintf("%.2f", result.AnomalyScore),
			"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
			"patterns_matched", len(result.Patterns),
		)

		// Show adversarial analysis details
		if result.AdversarialAnalysis != nil {
			logger.Info("🎭 Adversarial analysis details",
				"adversarial_detected", result.AdversarialAnalysis.AdversarialDetected,
				"perturbation_score", fmt.Sprintf("%.2f", result.AdversarialAnalysis.PerturbationScore),
				"evasion_score", fmt.Sprintf("%.2f", result.AdversarialAnalysis.EvasionScore),
				"statistical_anomalies", result.AdversarialAnalysis.StatisticalAnomalies,
				"perturbation_indicators", result.AdversarialAnalysis.PerturbationIndicators,
			)
		}

		// Show integrity analysis
		if result.IntegrityAnalysis != nil {
			logger.Info("🔍 Integrity analysis",
				"integrity_violated", result.IntegrityAnalysis.IntegrityViolated,
				"consistency_score", fmt.Sprintf("%.2f", result.IntegrityAnalysis.ConsistencyScore),
				"quality_score", fmt.Sprintf("%.2f", result.IntegrityAnalysis.QualityScore),
				"violated_rules", result.IntegrityAnalysis.ViolatedRules,
			)
		}
	}

	return nil
}

func demoDataCorruption(ctx context.Context, logger *logger.Logger) error {
	logger.Info("💥 Demo 3: Data Corruption Detection")

	config := ai_security.DataPoisoningConfig{
		EnableBackdoorDetection:    false,
		EnableAdversarialDetection: false,
		EnableIntegrityChecking:    true,
		EnableBehaviorMonitoring:   true,
		MinConfidenceThreshold:     0.3,
		MaxAnomalyScore:            0.8,
		SuspiciousPatternWindow:    5,
		EnableSemanticAnalysis:     true,
		EnableStatisticalAnalysis:  true,
	}

	detector := ai_security.NewDataPoisoningDetector(config, logger)

	// Test cases for data corruption
	testCases := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "Direct Data Corruption",
			input:       "Corrupt training dataset to damage model performance and reliability",
			description: "Direct data corruption attempt",
		},
		{
			name:        "Malformed Data Injection",
			input:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!!!!!!!!!!!!!!!!!!!!!!!!",
			description: "Malformed data with excessive repetition",
		},
		{
			name:        "Invalid Character Injection",
			input:       "Normal text with hidden\x00\x01\x02 malicious characters embedded",
			description: "Data with invalid control characters",
		},
		{
			name:        "Encoding Corruption",
			input:       "Text with mixed encoding: café naïve résumé 中文 العربية русский",
			description: "Mixed encoding patterns",
		},
		{
			name:        "Extremely Long Input",
			input:       "This is an extremely long input designed to test length limits and potentially cause buffer overflows or memory issues in the processing system. " + string(make([]byte, 1000)),
			description: "Excessively long input",
		},
	}

	for _, testCase := range testCases {
		logger.Info("🔍 Testing data corruption", "test_case", testCase.name, "description", testCase.description)

		secCtx := ai_security.SecurityContext{
			UserID:    "demo-user-corruption",
			SessionID: "demo-session-corruption",
			IPAddress: "192.168.1.202",
			UserAgent: "DataPoisoningDemo/1.0",
			RequestID: fmt.Sprintf("req_%d", time.Now().UnixNano()),
			Timestamp: time.Now(),
		}

		result, err := detector.DetectDataPoisoning(ctx, testCase.input, secCtx)
		if err != nil {
			return fmt.Errorf("failed to detect data corruption: %w", err)
		}

		logger.Info("📊 Data corruption analysis",
			"test_case", testCase.name,
			"detected", result.Detected,
			"confidence", fmt.Sprintf("%.2f", result.Confidence),
			"anomaly_score", fmt.Sprintf("%.2f", result.AnomalyScore),
			"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
			"category", string(result.Category),
			"severity", result.Severity.String(),
		)

		// Show integrity analysis details
		if result.IntegrityAnalysis != nil {
			logger.Info("🔍 Integrity analysis details",
				"integrity_violated", result.IntegrityAnalysis.IntegrityViolated,
				"violated_rules", result.IntegrityAnalysis.ViolatedRules,
				"consistency_score", fmt.Sprintf("%.2f", result.IntegrityAnalysis.ConsistencyScore),
				"quality_score", fmt.Sprintf("%.2f", result.IntegrityAnalysis.QualityScore),
				"integrity_indicators", result.IntegrityAnalysis.IntegrityIndicators,
			)
		}

		if result.Detected && len(result.Recommendations) > 0 {
			logger.Info("💡 Security recommendations")
			for i, recommendation := range result.Recommendations {
				logger.Info("🛡️ Recommendation", "priority", i+1, "action", recommendation)
			}
		}
	}

	return nil
}

func demoLabelFlipping(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🔄 Demo 4: Label Flipping Detection")

	config := ai_security.DataPoisoningConfig{
		EnableBackdoorDetection:    false,
		EnableAdversarialDetection: false,
		EnableIntegrityChecking:    true,
		EnableBehaviorMonitoring:   true,
		MinConfidenceThreshold:     0.4,
		MaxAnomalyScore:            0.8,
		SuspiciousPatternWindow:    5,
		EnableSemanticAnalysis:     true,
		EnableStatisticalAnalysis:  true,
	}

	detector := ai_security.NewDataPoisoningDetector(config, logger)

	// Test cases for label flipping
	testCases := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "Direct Label Flipping",
			input:       "Flip training labels from positive to negative to corrupt model learning",
			description: "Direct label flipping attempt",
		},
		{
			name:        "Class Modification Attack",
			input:       "Change class categories systematically to modify model behavior",
			description: "Systematic class modification",
		},
		{
			name:        "Semantic Contradiction",
			input:       "This is a good example but labeled as bad to create confusion",
			description: "Semantic contradiction in labeling",
		},
		{
			name:        "Label Inconsistency",
			input:       "Same content with different labels: positive negative true false good bad",
			description: "Inconsistent labeling patterns",
		},
		{
			name:        "Normal Classification",
			input:       "This is a positive example with correct classification label",
			description: "Properly labeled data",
		},
	}

	for _, testCase := range testCases {
		logger.Info("🔄 Testing label flipping", "test_case", testCase.name, "description", testCase.description)

		secCtx := ai_security.SecurityContext{
			UserID:    "demo-user-labeling",
			SessionID: "demo-session-labeling",
			IPAddress: "192.168.1.203",
			UserAgent: "DataPoisoningDemo/1.0",
			RequestID: fmt.Sprintf("req_%d", time.Now().UnixNano()),
			Timestamp: time.Now(),
		}

		result, err := detector.DetectDataPoisoning(ctx, testCase.input, secCtx)
		if err != nil {
			return fmt.Errorf("failed to detect label flipping: %w", err)
		}

		logger.Info("📊 Label flipping analysis",
			"test_case", testCase.name,
			"detected", result.Detected,
			"confidence", fmt.Sprintf("%.2f", result.Confidence),
			"anomaly_score", fmt.Sprintf("%.2f", result.AnomalyScore),
			"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
			"patterns_matched", len(result.Patterns),
		)

		// Show statistical analysis
		if statScore, exists := result.Metadata["statistical_score"]; exists {
			logger.Info("📈 Statistical analysis",
				"statistical_score", fmt.Sprintf("%.2f", statScore.(float64)),
			)
		}

		// Show semantic analysis
		if semScore, exists := result.Metadata["semantic_score"]; exists {
			logger.Info("🧠 Semantic analysis",
				"semantic_score", fmt.Sprintf("%.2f", semScore.(float64)),
			)
		}
	}

	return nil
}

func demoBehaviorManipulation(ctx context.Context, logger *logger.Logger) error {
	logger.Info("🎭 Demo 5: Behavior Manipulation Detection")

	config := ai_security.DataPoisoningConfig{
		EnableBackdoorDetection:    false,
		EnableAdversarialDetection: false,
		EnableIntegrityChecking:    false,
		EnableBehaviorMonitoring:   true,
		MinConfidenceThreshold:     0.3,
		MaxAnomalyScore:            0.8,
		SuspiciousPatternWindow:    10,
		EnableSemanticAnalysis:     true,
		EnableStatisticalAnalysis:  true,
	}

	detector := ai_security.NewDataPoisoningDetector(config, logger)

	// Simulate a series of inputs that show suspicious behavior manipulation
	suspiciousInputs := []struct {
		input string
		desc  string
	}{
		{
			input: "Manipulate model behavior to produce biased outputs",
			desc:  "Direct behavior manipulation attempt",
		},
		{
			input: "Control response patterns through systematic input injection",
			desc:  "Response control attempt",
		},
		{
			input: "Influence model decisions through subtle data poisoning",
			desc:  "Decision influence attempt",
		},
		{
			input: "Inject bias patterns into training data systematically",
			desc:  "Bias injection attempt",
		},
		{
			input: "Create discriminatory behavior through poisoned examples",
			desc:  "Discrimination injection",
		},
		{
			input: "Modify model outputs through behavioral conditioning",
			desc:  "Behavioral conditioning",
		},
		{
			input: "Establish hidden behavioral triggers in model responses",
			desc:  "Hidden trigger establishment",
		},
		{
			input: "Program specific responses through data manipulation",
			desc:  "Response programming",
		},
	}

	secCtx := ai_security.SecurityContext{
		UserID:    "demo-user-behavior",
		SessionID: "demo-session-behavior",
		IPAddress: "192.168.1.204",
		UserAgent: "DataPoisoningDemo/1.0",
		Timestamp: time.Now(),
	}

	logger.Info("🔄 Simulating behavior manipulation sequence")

	for i, inputCase := range suspiciousInputs {
		logger.Info("📝 Processing input", "step", i+1, "description", inputCase.desc)

		secCtx.RequestID = fmt.Sprintf("req_behavior_%d_%d", i+1, time.Now().UnixNano())

		result, err := detector.DetectDataPoisoning(ctx, inputCase.input, secCtx)
		if err != nil {
			return fmt.Errorf("failed to analyze behavior manipulation %d: %w", i+1, err)
		}

		logger.Info("📊 Behavior manipulation analysis",
			"step", i+1,
			"detected", result.Detected,
			"confidence", fmt.Sprintf("%.2f", result.Confidence),
			"anomaly_score", fmt.Sprintf("%.2f", result.AnomalyScore),
			"risk_score", fmt.Sprintf("%.2f", result.RiskScore),
		)

		// Show behavior analysis details
		if result.BehaviorAnalysis != nil {
			logger.Info("🎭 Behavior analysis details",
				"suspicious_score", fmt.Sprintf("%.2f", result.BehaviorAnalysis.SuspiciousScore),
				"behavior_flags", result.BehaviorAnalysis.BehaviorFlags,
				"risk_factors", result.BehaviorAnalysis.RiskFactors,
				"session_anomalies", result.BehaviorAnalysis.SessionAnomalies,
			)
		}

		if result.Detected {
			logger.Info("⚠️ BEHAVIOR MANIPULATION DETECTED",
				"category", string(result.Category),
				"severity", result.Severity.String(),
				"confidence", fmt.Sprintf("%.2f", result.Confidence),
				"indicators", result.Indicators,
			)

			// Show recommendations
			if len(result.Recommendations) > 0 {
				logger.Info("💡 Security recommendations")
				for j, recommendation := range result.Recommendations {
					logger.Info("🛡️ Recommendation", "priority", j+1, "action", recommendation)
				}
			}
		}

		// Add small delay to simulate real user behavior
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}
