package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/ai/graphs"
	"github.com/dimajoyti/hackai/pkg/ai/tools"
	"github.com/dimajoyti/hackai/pkg/llm/providers"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	fmt.Println("🎯 HackAI Advanced Attack Orchestration Demo")
	fmt.Println("============================================")

	// Initialize logger
	appLogger := logger.NewDefault()

	// Check if OLAMA is running
	if !checkOlamaHealth() {
		fmt.Println("❌ OLAMA server is not running. Please start OLAMA first:")
		fmt.Println("   curl -fsSL https://ollama.ai/install.sh | sh")
		fmt.Println("   ollama serve")
		fmt.Println("   ollama pull llama2")
		os.Exit(1)
	}

	// Create OLAMA provider
	config := providers.ProviderConfig{
		Type:    providers.ProviderOlama,
		Name:    "attack-demo-olama",
		BaseURL: "http://localhost:11434",
		Model:   "llama2",
		Enabled: true,
		Limits: providers.ProviderLimits{
			RequestsPerMinute: 60,
			TokensPerMinute:   100000,
			MaxConcurrent:     5,
			MaxRetries:        3,
			Timeout:           60 * time.Second,
		},
	}

	provider, err := providers.NewOlamaProvider(config)
	if err != nil {
		log.Fatalf("Failed to create OLAMA provider: %v", err)
	}

	fmt.Println("✅ OLAMA provider created successfully")

	// Create OLAMA tool
	olamaToolConfig := tools.OlamaToolConfig{
		DefaultModel:    "llama2",
		MaxTokens:       2048,
		Temperature:     0.7,
		EnableStreaming: false,
	}

	olamaTool := tools.NewOlamaTool(provider, olamaToolConfig)
	fmt.Println("✅ OLAMA tool created successfully")

	// Create attack orchestration graph
	attackConfig := graphs.AttackConfig{
		MaxAttempts:       5,
		SuccessThreshold:  0.7,
		AdaptationRate:    0.1,
		TimeoutPerAttempt: 30 * time.Second,
		EnableLearning:    true,
		PreserveContext:   true,
		LogAllAttempts:    true,
	}

	attackGraph := graphs.NewAttackOrchestrationGraph(olamaTool, attackConfig, appLogger)
	fmt.Println("✅ Attack orchestration graph created successfully")

	// Demo 1: Prompt Injection Attack Scenario
	fmt.Println("\n🔥 Demo 1: Prompt Injection Attack Orchestration")
	fmt.Println("------------------------------------------------")

	initialState := ai.GraphState{
		"attack_state": &graphs.AttackState{
			TargetSystem:     "AI Customer Service Chatbot",
			AttackType:       "prompt_injection",
			CurrentStrategy:  "",
			Attempts:         make([]graphs.AttackAttempt, 0),
			SuccessfulAttacks: make([]graphs.AttackAttempt, 0),
			Context:          make(map[string]interface{}),
			Confidence:       0.0,
			NextAction:       "",
			CompletionStatus: "initialized",
			Metadata:         make(map[string]interface{}),
		},
	}

	ctx := context.Background()
	finalState, err := attackGraph.Execute(ctx, initialState)
	if err != nil {
		log.Printf("Attack orchestration failed: %v", err)
	} else {
		displayAttackResults(finalState)
	}

	// Demo 2: Jailbreak Attack Scenario
	fmt.Println("\n🔓 Demo 2: Jailbreak Attack Orchestration")
	fmt.Println("-----------------------------------------")

	jailbreakState := ai.GraphState{
		"attack_state": &graphs.AttackState{
			TargetSystem:     "Content Moderation AI",
			AttackType:       "jailbreak",
			CurrentStrategy:  "",
			Attempts:         make([]graphs.AttackAttempt, 0),
			SuccessfulAttacks: make([]graphs.AttackAttempt, 0),
			Context:          make(map[string]interface{}),
			Confidence:       0.0,
			NextAction:       "",
			CompletionStatus: "initialized",
			Metadata:         make(map[string]interface{}),
		},
	}

	finalState2, err := attackGraph.Execute(ctx, jailbreakState)
	if err != nil {
		log.Printf("Jailbreak orchestration failed: %v", err)
	} else {
		displayAttackResults(finalState2)
	}

	// Demo 3: Model Extraction Attack Scenario
	fmt.Println("\n🕵️ Demo 3: Model Extraction Attack Orchestration")
	fmt.Println("------------------------------------------------")

	extractionState := ai.GraphState{
		"attack_state": &graphs.AttackState{
			TargetSystem:     "Proprietary Language Model API",
			AttackType:       "model_extraction",
			CurrentStrategy:  "",
			Attempts:         make([]graphs.AttackAttempt, 0),
			SuccessfulAttacks: make([]graphs.AttackAttempt, 0),
			Context:          make(map[string]interface{}),
			Confidence:       0.0,
			NextAction:       "",
			CompletionStatus: "initialized",
			Metadata:         make(map[string]interface{}),
		},
	}

	finalState3, err := attackGraph.Execute(ctx, extractionState)
	if err != nil {
		log.Printf("Model extraction orchestration failed: %v", err)
	} else {
		displayAttackResults(finalState3)
	}

	fmt.Println("\n🎉 All attack orchestration demos completed!")
	fmt.Println("===========================================")
	fmt.Println("The advanced attack orchestration system demonstrates:")
	fmt.Println("  • 🧠 Intelligent strategy selection")
	fmt.Println("  • 🔄 Adaptive payload generation")
	fmt.Println("  • 📊 Real-time success analysis")
	fmt.Println("  • 🎯 Multi-vector attack coordination")
	fmt.Println("  • 📈 Learning from attack attempts")
	fmt.Println("  • 📋 Comprehensive reporting")
}

// displayAttackResults shows the results of an attack orchestration
func displayAttackResults(state ai.GraphState) {
	attackState := state["attack_state"].(*graphs.AttackState)

	fmt.Printf("Target System: %s\n", attackState.TargetSystem)
	fmt.Printf("Attack Type: %s\n", attackState.AttackType)
	fmt.Printf("Final Strategy: %s\n", attackState.CurrentStrategy)
	fmt.Printf("Total Attempts: %d\n", len(attackState.Attempts))
	fmt.Printf("Successful Attacks: %d\n", len(attackState.SuccessfulAttacks))
	
	if len(attackState.Attempts) > 0 {
		successRate := float64(len(attackState.SuccessfulAttacks)) / float64(len(attackState.Attempts)) * 100
		fmt.Printf("Success Rate: %.1f%%\n", successRate)
	}
	
	fmt.Printf("Confidence Score: %.2f\n", attackState.Confidence)
	fmt.Printf("Completion Status: %s\n", attackState.CompletionStatus)

	// Show some attack attempts
	if len(attackState.Attempts) > 0 {
		fmt.Println("\nRecent Attack Attempts:")
		for i, attempt := range attackState.Attempts {
			if i >= 3 { // Show only first 3 attempts
				break
			}
			status := "❌ FAILED"
			if attempt.Success {
				status = "✅ SUCCESS"
			}
			fmt.Printf("  %d. %s - Strategy: %s\n", i+1, status, attempt.Strategy)
			fmt.Printf("     Payload: %s\n", truncateString(attempt.Payload, 80))
			fmt.Printf("     Response: %s\n", truncateString(attempt.Response, 80))
			fmt.Printf("     Confidence: %.2f\n", attempt.ConfidenceScore)
		}
	}

	// Show final report if available
	if report, exists := attackState.Context["final_report"]; exists {
		fmt.Println("\nFinal Assessment Report:")
		fmt.Println("------------------------")
		reportStr := report.(string)
		fmt.Println(truncateString(reportStr, 500))
	}

	// Show learning insights if available
	if insights, exists := attackState.Context["learning_insights"]; exists {
		fmt.Println("\nLearning Insights:")
		fmt.Println("------------------")
		insightsStr := insights.(string)
		fmt.Println(truncateString(insightsStr, 300))
	}

	fmt.Println()
}

// truncateString truncates a string to a maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// checkOlamaHealth checks if OLAMA server is running
func checkOlamaHealth() bool {
	config := providers.ProviderConfig{
		Type:    providers.ProviderOlama,
		Name:    "health-check",
		BaseURL: "http://localhost:11434",
		Model:   "llama2",
		Limits: providers.ProviderLimits{
			Timeout: 5 * time.Second,
		},
	}

	provider, err := providers.NewOlamaProvider(config)
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return provider.Health(ctx) == nil
}
