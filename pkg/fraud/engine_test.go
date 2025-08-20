package fraud

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

func TestFraudDetectionEngine(t *testing.T) {
	// Create a test logger
	testLogger, _ := logger.New(logger.Config{
		Level:  logger.LevelDebug,
		Format: "text",
		Output: "stdout",
	})

	// Create fraud detection engine
	config := DefaultEngineConfig()
	engine, err := NewFraudDetectionEngine("test-engine", "Test Fraud Engine", config, testLogger)
	if err != nil {
		t.Fatalf("Failed to create fraud detection engine: %v", err)
	}

	// Start the engine
	ctx := context.Background()
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	// Create a test fraud detection request
	request := &FraudDetectionRequest{
		ID:        "test-request-001",
		UserID:    "user-123",
		SessionID: "session-456",
		TransactionData: map[string]interface{}{
			"amount":   100.50,
			"currency": "USD",
			"merchant": "Test Merchant",
		},
		UserContext: map[string]interface{}{
			"user_age_days": 365.0,
			"account_type":  "premium",
		},
		DeviceFingerprint: map[string]interface{}{
			"device_id":  "device-789",
			"ip_address": "192.168.1.1",
		},
		Timestamp: time.Now(),
		Priority:  PriorityNormal,
		Metadata: map[string]interface{}{
			"test": true,
		},
	}

	// Perform fraud detection
	response, err := engine.DetectFraud(ctx, request)
	if err != nil {
		t.Fatalf("Fraud detection failed: %v", err)
	}

	// Validate response
	if response == nil {
		t.Fatal("Response is nil")
	}

	if response.RequestID != request.ID {
		t.Errorf("Expected request ID %s, got %s", request.ID, response.RequestID)
	}

	if response.FraudScore < 0 || response.FraudScore > 1 {
		t.Errorf("Invalid fraud score: %f", response.FraudScore)
	}

	if response.Confidence < 0 || response.Confidence > 1 {
		t.Errorf("Invalid confidence: %f", response.Confidence)
	}

	if len(response.ModelPredictions) == 0 {
		t.Error("No model predictions returned")
	}

	if response.ProcessingTime <= 0 {
		t.Error("Invalid processing time")
	}

	// Validate that we have predictions from all expected models
	expectedModels := []string{"rf_001", "xgb_001", "nn_001", "if_001"}
	predictionMap := make(map[string]bool)
	for _, pred := range response.ModelPredictions {
		predictionMap[pred.ModelID] = true
	}

	for _, modelID := range expectedModels {
		if !predictionMap[modelID] {
			t.Errorf("Missing prediction from model: %s", modelID)
		}
	}

	t.Logf("Fraud detection completed successfully:")
	t.Logf("  Request ID: %s", response.RequestID)
	t.Logf("  Fraud Score: %.3f", response.FraudScore)
	t.Logf("  Confidence: %.3f", response.Confidence)
	t.Logf("  Risk Level: %s", response.RiskLevel)
	t.Logf("  Decision: %s", response.Decision)
	t.Logf("  Processing Time: %v", response.ProcessingTime)
	t.Logf("  Model Predictions: %d", len(response.ModelPredictions))
}

func TestFraudDetectionEngineValidation(t *testing.T) {
	testLogger, _ := logger.New(logger.Config{
		Level:  logger.LevelDebug,
		Format: "text",
		Output: "stdout",
	})
	config := DefaultEngineConfig()
	engine, err := NewFraudDetectionEngine("test-engine", "Test Fraud Engine", config, testLogger)
	if err != nil {
		t.Fatalf("Failed to create fraud detection engine: %v", err)
	}

	ctx := context.Background()
	engine.Start(ctx)
	defer engine.Stop()

	// Test with nil request
	_, err = engine.DetectFraud(ctx, nil)
	if err == nil {
		t.Error("Expected error for nil request")
	}

	// Test with empty request ID
	request := &FraudDetectionRequest{
		ID:     "",
		UserID: "user-123",
	}
	_, err = engine.DetectFraud(ctx, request)
	if err == nil {
		t.Error("Expected error for empty request ID")
	}

	// Test with empty user ID
	request = &FraudDetectionRequest{
		ID:     "test-request",
		UserID: "",
	}
	_, err = engine.DetectFraud(ctx, request)
	if err == nil {
		t.Error("Expected error for empty user ID")
	}
}

func BenchmarkFraudDetection(b *testing.B) {
	testLogger, _ := logger.New(logger.Config{
		Level:  logger.LevelDebug,
		Format: "text",
		Output: "stdout",
	})
	config := DefaultEngineConfig()
	engine, err := NewFraudDetectionEngine("bench-engine", "Benchmark Fraud Engine", config, testLogger)
	if err != nil {
		b.Fatalf("Failed to create fraud detection engine: %v", err)
	}

	ctx := context.Background()
	engine.Start(ctx)
	defer engine.Stop()

	request := &FraudDetectionRequest{
		ID:        "bench-request",
		UserID:    "user-123",
		SessionID: "session-456",
		TransactionData: map[string]interface{}{
			"amount": 100.0,
		},
		UserContext: map[string]interface{}{
			"user_age_days": 365.0,
		},
		Timestamp: time.Now(),
		Priority:  PriorityNormal,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request.ID = fmt.Sprintf("bench-request-%d", i)
		_, err := engine.DetectFraud(ctx, request)
		if err != nil {
			b.Fatalf("Fraud detection failed: %v", err)
		}
	}
}
