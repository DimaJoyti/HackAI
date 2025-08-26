package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FraudDetectionRequest represents a fraud detection request
type FraudDetectionRequest struct {
	ID                string                 `json:"id"`
	UserID            string                 `json:"user_id"`
	SessionID         string                 `json:"session_id"`
	TransactionData   map[string]interface{} `json:"transaction_data"`
	UserContext       map[string]interface{} `json:"user_context"`
	DeviceFingerprint map[string]interface{} `json:"device_fingerprint"`
	Timestamp         time.Time              `json:"timestamp"`
	Priority          int                    `json:"priority"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// FraudDetectionResponse represents the fraud detection result
type FraudDetectionResponse struct {
	RequestID         string                 `json:"request_id"`
	IsFraud           bool                   `json:"is_fraud"`
	FraudScore        float64                `json:"fraud_score"`
	Confidence        float64                `json:"confidence"`
	RiskLevel         string                 `json:"risk_level"`
	Decision          string                 `json:"decision"`
	Reasons           []string               `json:"reasons"`
	ModelPredictions  []ModelPrediction      `json:"model_predictions"`
	FeatureImportance map[string]float64     `json:"feature_importance"`
	ProcessingTime    int64                  `json:"processing_time"`
	Metadata          map[string]interface{} `json:"metadata"`
	Timestamp         time.Time              `json:"timestamp"`
}

// ModelPrediction represents a prediction from an individual model
type ModelPrediction struct {
	ModelID     string             `json:"model_id"`
	ModelName   string             `json:"model_name"`
	Prediction  float64            `json:"prediction"`
	Confidence  float64            `json:"confidence"`
	ProcessTime int64              `json:"process_time"`
	Features    map[string]float64 `json:"features"`
}

func main() {
	fmt.Println("🛡️  HackAI Fraud Detection Demo")
	fmt.Println("================================")

	// Test scenarios
	scenarios := []struct {
		name    string
		request FraudDetectionRequest
	}{
		{
			name: "Low Risk Transaction",
			request: FraudDetectionRequest{
				ID:        "demo-001",
				UserID:    "user-12345",
				SessionID: "session-67890",
				TransactionData: map[string]interface{}{
					"amount":   50.00,
					"currency": "USD",
					"merchant": "Coffee Shop",
					"category": "food_beverage",
				},
				UserContext: map[string]interface{}{
					"user_age_days":         730.0, // 2 years old account
					"account_type":          "verified",
					"previous_transactions": 150,
				},
				DeviceFingerprint: map[string]interface{}{
					"device_id":  "device-abc123",
					"ip_address": "192.168.1.100",
					"user_agent": "Mozilla/5.0...",
				},
				Timestamp: time.Now(),
				Priority:  1, // Normal priority
				Metadata: map[string]interface{}{
					"demo":     true,
					"scenario": "low_risk",
				},
			},
		},
		{
			name: "High Risk Transaction",
			request: FraudDetectionRequest{
				ID:        "demo-002",
				UserID:    "user-99999",
				SessionID: "session-suspicious",
				TransactionData: map[string]interface{}{
					"amount":   5000.00,
					"currency": "USD",
					"merchant": "Unknown Merchant",
					"category": "electronics",
				},
				UserContext: map[string]interface{}{
					"user_age_days":         1.0, // Brand new account
					"account_type":          "unverified",
					"previous_transactions": 0,
				},
				DeviceFingerprint: map[string]interface{}{
					"device_id":  "device-suspicious",
					"ip_address": "10.0.0.1", // Different IP pattern
					"user_agent": "Bot/1.0",
				},
				Timestamp: time.Now(),
				Priority:  3, // High priority
				Metadata: map[string]interface{}{
					"demo":     true,
					"scenario": "high_risk",
				},
			},
		},
		{
			name: "Medium Risk Transaction",
			request: FraudDetectionRequest{
				ID:        "demo-003",
				UserID:    "user-54321",
				SessionID: "session-medium",
				TransactionData: map[string]interface{}{
					"amount":   500.00,
					"currency": "USD",
					"merchant": "Online Store",
					"category": "retail",
				},
				UserContext: map[string]interface{}{
					"user_age_days":         90.0, // 3 months old
					"account_type":          "basic",
					"previous_transactions": 25,
				},
				DeviceFingerprint: map[string]interface{}{
					"device_id":  "device-xyz789",
					"ip_address": "203.0.113.1", // Different country IP
					"user_agent": "Mobile Safari",
				},
				Timestamp: time.Now(),
				Priority:  2, // Medium priority
				Metadata: map[string]interface{}{
					"demo":     true,
					"scenario": "medium_risk",
				},
			},
		},
	}

	// Test each scenario
	for i, scenario := range scenarios {
		fmt.Printf("\n%d. Testing: %s\n", i+1, scenario.name)
		fmt.Println("   " + strings.Repeat("─", 50))

		response, err := callFraudDetectionAPI(scenario.request)
		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		// Display results
		fmt.Printf("   📊 Fraud Score: %.3f\n", response.FraudScore)
		fmt.Printf("   🎯 Confidence: %.3f\n", response.Confidence)
		fmt.Printf("   ⚠️  Risk Level: %s\n", response.RiskLevel)
		fmt.Printf("   🚦 Decision: %s\n", response.Decision)
		fmt.Printf("   ⏱️  Processing Time: %dms\n", response.ProcessingTime)
		fmt.Printf("   🤖 Models Used: %d\n", len(response.ModelPredictions))

		if len(response.Reasons) > 0 {
			fmt.Printf("   📝 Reasons:\n")
			for _, reason := range response.Reasons {
				fmt.Printf("      • %s\n", reason)
			}
		}

		// Show model predictions
		if len(response.ModelPredictions) > 0 {
			fmt.Printf("   🔍 Model Predictions:\n")
			for _, pred := range response.ModelPredictions {
				fmt.Printf("      • %s: %.3f (confidence: %.3f)\n",
					pred.ModelName, pred.Prediction, pred.Confidence)
			}
		}
	}

	fmt.Println("\n🎉 Demo completed!")
	fmt.Println("\nTo test manually, send POST requests to:")
	fmt.Println("   http://localhost:8080/api/v1/fraud/detect")
	fmt.Println("\nHealth check:")
	fmt.Println("   http://localhost:8080/api/v1/fraud/health")
	fmt.Println("\nStatistics:")
	fmt.Println("   http://localhost:8080/api/v1/fraud/stats")
}

func callFraudDetectionAPI(request FraudDetectionRequest) (*FraudDetectionResponse, error) {
	// Convert request to JSON
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make HTTP request
	resp, err := http.Post("http://localhost:8080/api/v1/fraud/detect",
		"application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response FraudDetectionResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response, nil
}
