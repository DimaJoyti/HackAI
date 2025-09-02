package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/ollama"
)

func main() {
	fmt.Println("🤖 HackAI OLLAMA Integration & Local AI Models Demo")
	fmt.Println("===================================================")

	// Initialize logger
	log, err := logger.New(logger.Config{
		Level:      "info",
		Format:     "text",
		Output:     "stdout",
		AddSource:  false,
		TimeFormat: time.RFC3339,
	})
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		return
	}

	// OLLAMA service endpoint
	ollamaURL := "http://localhost:9089"

	fmt.Printf("🔗 OLLAMA Service URL: %s\n", ollamaURL)
	fmt.Println()

	// Test health endpoint first
	fmt.Println("🏥 Testing Health Endpoint")
	fmt.Println("==========================")

	healthResp, err := http.Get(ollamaURL + "/health")
	if err != nil {
		fmt.Printf("❌ Health check failed: %v\n", err)
		fmt.Println("⚠️  Make sure the OLLAMA service is running on port 9089")
		return
	}
	defer healthResp.Body.Close()

	if healthResp.StatusCode == http.StatusOK {
		fmt.Printf("✅ OLLAMA service is healthy\n")
	} else {
		fmt.Printf("⚠️  OLLAMA service health check returned status: %d\n", healthResp.StatusCode)
	}

	// Test model management
	fmt.Println("\n📚 Testing Model Management")
	fmt.Println("============================")

	// List available models
	models, err := listModels(ollamaURL, log)
	if err != nil {
		fmt.Printf("❌ Failed to list models: %v\n", err)
	} else {
		fmt.Printf("✅ Found %d models:\n", len(models))
		for name, model := range models {
			fmt.Printf("   📦 %s (Size: %d bytes, Status: %s)\n", name, model.Size, model.Status)
		}
	}

	// Test inference capabilities
	fmt.Println("\n🧠 Testing AI Inference")
	fmt.Println("========================")

	// Test scenarios for different types of AI tasks
	testScenarios := []struct {
		name        string
		request     ollama.GenerateRequest
		description string
	}{
		{
			name: "Simple Text Generation",
			request: ollama.GenerateRequest{
				Model:  "llama2",
				Prompt: "Explain what artificial intelligence is in simple terms.",
			},
			description: "Basic text generation with a general AI model",
		},
		{
			name: "Code Generation",
			request: ollama.GenerateRequest{
				Model:  "codellama",
				Prompt: "Write a Python function to calculate the factorial of a number.",
			},
			description: "Code generation using a specialized coding model",
		},
		{
			name: "Security Analysis",
			request: ollama.GenerateRequest{
				Model:  "llama2",
				Prompt: "Analyze the security implications of using public Wi-Fi networks.",
				System: "You are a cybersecurity expert. Provide detailed security analysis.",
			},
			description: "Security-focused analysis with system prompt",
		},
		{
			name: "Creative Writing",
			request: ollama.GenerateRequest{
				Model:  "mistral",
				Prompt: "Write a short story about a robot learning to paint.",
			},
			description: "Creative content generation",
		},
	}

	for i, scenario := range testScenarios {
		fmt.Printf("\n%d. %s\n", i+1, scenario.name)
		fmt.Printf("   Description: %s\n", scenario.description)
		fmt.Printf("   Model: %s\n", scenario.request.Model)
		fmt.Printf("   Prompt: %s\n", scenario.request.Prompt)

		response, err := generateText(ollamaURL, scenario.request, log)
		if err != nil {
			fmt.Printf("   ❌ Generation failed: %v\n", err)
			continue
		}

		fmt.Printf("   ✅ Generation successful\n")
		fmt.Printf("   📝 Response: %s\n", truncateString(response.Response, 200))
		if response.EvalCount > 0 {
			fmt.Printf("   📊 Tokens: %d, Duration: %dms\n", response.EvalCount, response.TotalDuration/1000000)
		}
	}

	// Test chat functionality
	fmt.Println("\n💬 Testing Chat Completion")
	fmt.Println("===========================")

	chatRequest := ollama.ChatRequest{
		Model: "llama2",
		Messages: []ollama.ChatMessage{
			{Role: "user", Content: "What are the benefits of using local AI models?"},
		},
	}

	chatResponse, err := chatCompletion(ollamaURL, chatRequest, log)
	if err != nil {
		fmt.Printf("❌ Chat completion failed: %v\n", err)
	} else {
		fmt.Printf("✅ Chat completion successful\n")
		fmt.Printf("💬 Response: %s\n", truncateString(chatResponse.Message.Content, 300))
		if chatResponse.EvalCount > 0 {
			fmt.Printf("📊 Tokens: %d, Duration: %dms\n", chatResponse.EvalCount, chatResponse.TotalDuration/1000000)
		}
	}

	// Test model presets
	fmt.Println("\n🎛️  Testing Model Presets")
	fmt.Println("=========================")

	presets, err := listPresets(ollamaURL, log)
	if err != nil {
		fmt.Printf("❌ Failed to list presets: %v\n", err)
	} else {
		fmt.Printf("✅ Found %d presets:\n", len(presets))
		for name, preset := range presets {
			fmt.Printf("   ⚙️  %s: %s (Model: %s, Temp: %.1f)\n",
				name, preset.Description, preset.Model, preset.Temperature)
		}
	}

	// Test service statistics
	fmt.Println("\n📊 Service Statistics")
	fmt.Println("=====================")

	stats, err := getStats(ollamaURL, log)
	if err != nil {
		fmt.Printf("❌ Failed to get stats: %v\n", err)
	} else {
		fmt.Printf("📈 Total Models: %d\n", stats.TotalModels)
		fmt.Printf("🟢 Active Models: %d\n", stats.ActiveModels)
		fmt.Printf("📊 Total Requests: %d\n", stats.TotalRequests)
		fmt.Printf("✅ Successful Requests: %d\n", stats.SuccessfulReqs)
		fmt.Printf("❌ Failed Requests: %d\n", stats.FailedRequests)
		fmt.Printf("⏱️  Average Latency: %v\n", stats.AverageLatency)
		fmt.Printf("🎯 Total Tokens: %d\n", stats.TotalTokens)
		fmt.Printf("⏰ Uptime: %v\n", stats.Uptime)
		fmt.Printf("💾 Memory Usage: %d bytes\n", stats.MemoryUsage)
	}

	// Test performance metrics
	fmt.Println("\n⚡ Performance Metrics")
	fmt.Println("======================")

	perfMetrics, err := getPerformanceMetrics(ollamaURL, log)
	if err != nil {
		fmt.Printf("❌ Failed to get performance metrics: %v\n", err)
	} else {
		fmt.Printf("⏱️  Average Latency: %v\n", perfMetrics["average_latency"])
		fmt.Printf("📈 Requests/sec: %.1f\n", perfMetrics["requests_per_sec"])
		fmt.Printf("✅ Success Rate: %.1f%%\n", perfMetrics["success_rate"])
		fmt.Printf("💾 Memory Usage: %v\n", perfMetrics["memory_usage"])
		fmt.Printf("🖥️  CPU Usage: %v\n", perfMetrics["cpu_usage"])
		fmt.Printf("🎮 GPU Usage: %v\n", perfMetrics["gpu_usage"])
		fmt.Printf("🔄 Throughput: %v tokens\n", perfMetrics["throughput_tokens"])
	}

	fmt.Println("\n🎉 OLLAMA Integration & Local AI Models Demo Completed!")
	fmt.Println("========================================================")
	fmt.Printf("✅ OLLAMA integration successfully tested\n")
	fmt.Printf("🤖 AI Features Demonstrated:\n")
	fmt.Printf("   - Local model management\n")
	fmt.Printf("   - Text generation\n")
	fmt.Printf("   - Code generation\n")
	fmt.Printf("   - Chat completion\n")
	fmt.Printf("   - Model presets\n")
	fmt.Printf("   - Performance monitoring\n")
	fmt.Printf("   - Security analysis\n")
	fmt.Printf("   - Creative writing\n")
	fmt.Printf("📈 Performance: Local AI inference with comprehensive management\n")
	fmt.Printf("🔧 Integration: Ready for production AI workloads\n")
	fmt.Printf("🛡️  Security: Local processing ensures data privacy\n")
}

// Helper functions for API calls

func listModels(baseURL string, log *logger.Logger) (map[string]*ollama.ModelInfo, error) {
	resp, err := http.Get(baseURL + "/api/v1/models")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response struct {
		Models map[string]*ollama.ModelInfo `json:"models"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return response.Models, nil
}

func generateText(baseURL string, request ollama.GenerateRequest, log *logger.Logger) (*ollama.GenerateResponse, error) {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(baseURL+"/api/v1/generate", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: %s", string(body))
	}

	var response ollama.GenerateResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

func chatCompletion(baseURL string, request ollama.ChatRequest, log *logger.Logger) (*ollama.ChatResponse, error) {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(baseURL+"/api/v1/chat", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: %s", string(body))
	}

	var response ollama.ChatResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

func listPresets(baseURL string, log *logger.Logger) (map[string]*ollama.ModelPreset, error) {
	resp, err := http.Get(baseURL + "/api/v1/presets")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response struct {
		Presets map[string]*ollama.ModelPreset `json:"presets"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return response.Presets, nil
}

func getStats(baseURL string, log *logger.Logger) (*ollama.Stats, error) {
	resp, err := http.Get(baseURL + "/api/v1/stats")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var stats ollama.Stats
	if err := json.Unmarshal(body, &stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

func getPerformanceMetrics(baseURL string, log *logger.Logger) (map[string]interface{}, error) {
	resp, err := http.Get(baseURL + "/api/v1/monitoring/performance")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var metrics map[string]interface{}
	if err := json.Unmarshal(body, &metrics); err != nil {
		return nil, err
	}

	return metrics, nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
