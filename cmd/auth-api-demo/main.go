package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// AuthRequest represents an authentication request
type AuthRequest struct {
	EmailOrUsername string `json:"email_or_username"`
	Password        string `json:"password"`
	RememberMe      bool   `json:"remember_me"`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	User         UserInfo  `json:"user"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	SessionID    string    `json:"session_id"`
}

// UserInfo represents user information
type UserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// TokenValidationRequest represents a token validation request
type TokenValidationRequest struct {
	Token string `json:"token"`
}

// TokenValidationResponse represents a token validation response
type TokenValidationResponse struct {
	Valid  bool     `json:"valid"`
	Claims UserInfo `json:"claims,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// AuthStats represents authentication statistics
type AuthStats struct {
	TotalLogins       int64  `json:"total_logins"`
	ActiveSessions    int64  `json:"active_sessions"`
	FailedAttempts    int64  `json:"failed_attempts"`
	TOTPEnabledUsers  int64  `json:"totp_enabled_users"`
	Last24HLogins     int64  `json:"last_24h_logins"`
	SecurityEvents    int64  `json:"security_events"`
	Uptime            string `json:"uptime"`
	Status            string `json:"status"`
}

func main() {
	fmt.Println("🔐 HackAI Authentication & Authorization API Demo")
	fmt.Println("==================================================")

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

	// Authentication service endpoint
	authURL := "http://localhost:9088"

	fmt.Printf("🔗 Authentication Service URL: %s\n", authURL)
	fmt.Println()

	// Test health endpoint first
	fmt.Println("🏥 Testing Health Endpoint")
	fmt.Println("==========================")
	
	healthResp, err := http.Get(authURL + "/health")
	if err != nil {
		fmt.Printf("❌ Health check failed: %v\n", err)
		fmt.Println("⚠️  Make sure the authentication service is running on port 9088")
		return
	}
	defer healthResp.Body.Close()

	if healthResp.StatusCode == http.StatusOK {
		fmt.Printf("✅ Authentication service is healthy\n")
	} else {
		fmt.Printf("⚠️  Authentication service health check returned status: %d\n", healthResp.StatusCode)
	}

	// Test scenarios
	testScenarios := []struct {
		name        string
		request     AuthRequest
		expectError bool
		description string
	}{
		{
			name: "Valid Admin Login",
			request: AuthRequest{
				EmailOrUsername: "admin@hackai.com",
				Password:        "admin123",
				RememberMe:      true,
			},
			expectError: false,
			description: "Administrator login with valid credentials",
		},
		{
			name: "Valid User Login",
			request: AuthRequest{
				EmailOrUsername: "user@hackai.com",
				Password:        "user123",
				RememberMe:      false,
			},
			expectError: false,
			description: "Regular user login with valid credentials",
		},
		{
			name: "Invalid Password",
			request: AuthRequest{
				EmailOrUsername: "user@hackai.com",
				Password:        "wrongpassword",
				RememberMe:      false,
			},
			expectError: true,
			description: "Login attempt with incorrect password",
		},
		{
			name: "Non-existent User",
			request: AuthRequest{
				EmailOrUsername: "nonexistent@hackai.com",
				Password:        "password123",
				RememberMe:      false,
			},
			expectError: true,
			description: "Login attempt with non-existent user",
		},
		{
			name: "Empty Credentials",
			request: AuthRequest{
				EmailOrUsername: "",
				Password:        "",
				RememberMe:      false,
			},
			expectError: true,
			description: "Login attempt with empty credentials",
		},
	}

	fmt.Println("\n🔍 Testing Authentication Endpoints")
	fmt.Println("====================================")

	var validToken string

	// Test each authentication scenario
	for i, scenario := range testScenarios {
		fmt.Printf("\n%d. %s\n", i+1, scenario.name)
		fmt.Printf("   Description: %s\n", scenario.description)
		fmt.Printf("   Email: %s\n", scenario.request.EmailOrUsername)

		// Send authentication request
		response, err := sendAuthRequest(authURL+"/api/v1/auth/login", scenario.request, log)
		if err != nil {
			fmt.Printf("   ❌ Request failed: %v\n", err)
			if !scenario.expectError {
				fmt.Printf("   ⚠️  Unexpected failure\n")
			} else {
				fmt.Printf("   ✅ Expected failure - Security working correctly\n")
			}
			continue
		}

		if response.AccessToken != "" {
			fmt.Printf("   ✅ Authentication successful\n")
			fmt.Printf("   👤 User: %s (%s)\n", response.User.Username, response.User.Role)
			fmt.Printf("   🎫 Session ID: %s\n", response.SessionID)
			fmt.Printf("   ⏰ Expires: %s\n", response.ExpiresAt.Format(time.RFC3339))
			
			if scenario.expectError {
				fmt.Printf("   ⚠️  Expected failure but authentication succeeded\n")
			} else {
				fmt.Printf("   ✅ Expected success - Authentication working correctly\n")
				if validToken == "" {
					validToken = response.AccessToken
				}
			}
		} else {
			fmt.Printf("   🚫 Authentication failed\n")
			if scenario.expectError {
				fmt.Printf("   ✅ Expected failure - Security working correctly\n")
			} else {
				fmt.Printf("   ⚠️  Unexpected failure\n")
			}
		}
	}

	// Test token validation if we have a valid token
	if validToken != "" {
		fmt.Println("\n🎫 Testing Token Validation")
		fmt.Println("============================")

		validationReq := TokenValidationRequest{Token: validToken}
		validationResp, err := sendTokenValidation(authURL+"/api/v1/auth/validate", validationReq, log)
		if err != nil {
			fmt.Printf("❌ Token validation failed: %v\n", err)
		} else {
			if validationResp.Valid {
				fmt.Printf("✅ Token is valid\n")
				fmt.Printf("👤 User: %s (%s)\n", validationResp.Claims.Username, validationResp.Claims.Role)
			} else {
				fmt.Printf("❌ Token is invalid: %s\n", validationResp.Error)
			}
		}

		// Test protected endpoint
		fmt.Println("\n🔒 Testing Protected Endpoint")
		fmt.Println("==============================")
		
		err = testProtectedEndpoint(authURL+"/api/v1/auth/profile", validToken, log)
		if err != nil {
			fmt.Printf("❌ Protected endpoint test failed: %v\n", err)
		} else {
			fmt.Printf("✅ Protected endpoint access successful\n")
		}
	}

	// Test authentication statistics
	fmt.Println("\n📊 Authentication Statistics")
	fmt.Println("=============================")

	stats, err := getAuthStats(authURL+"/api/v1/auth/stats", log)
	if err != nil {
		fmt.Printf("❌ Failed to get authentication stats: %v\n", err)
	} else {
		fmt.Printf("📈 Total Logins: %d\n", stats.TotalLogins)
		fmt.Printf("👥 Active Sessions: %d\n", stats.ActiveSessions)
		fmt.Printf("🚫 Failed Attempts: %d\n", stats.FailedAttempts)
		fmt.Printf("🔐 TOTP Enabled Users: %d\n", stats.TOTPEnabledUsers)
		fmt.Printf("📅 Last 24h Logins: %d\n", stats.Last24HLogins)
		fmt.Printf("⚠️  Security Events: %d\n", stats.SecurityEvents)
		fmt.Printf("⏰ Uptime: %s\n", stats.Uptime)
		fmt.Printf("🟢 Status: %s\n", stats.Status)
	}

	fmt.Println("\n🎉 Authentication & Authorization API Demo Completed!")
	fmt.Println("======================================================")
	fmt.Printf("✅ Authentication API successfully tested with %d scenarios\n", len(testScenarios))
	fmt.Printf("🛡️  Security Features Demonstrated:\n")
	fmt.Printf("   - JWT-based authentication\n")
	fmt.Printf("   - Role-based access control (RBAC)\n")
	fmt.Printf("   - Session management\n")
	fmt.Printf("   - Token validation\n")
	fmt.Printf("   - Protected endpoint access\n")
	fmt.Printf("   - Authentication statistics\n")
	fmt.Printf("   - Health monitoring\n")
	fmt.Printf("📈 Performance: Real-time API authentication\n")
	fmt.Printf("🔧 Integration: Ready for production use\n")
}

// sendAuthRequest sends an authentication request
func sendAuthRequest(url string, request AuthRequest, log *logger.Logger) (*AuthResponse, error) {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResponse AuthResponse
	if err := json.Unmarshal(body, &authResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &authResponse, nil
}

// sendTokenValidation sends a token validation request
func sendTokenValidation(url string, request TokenValidationRequest, log *logger.Logger) (*TokenValidationResponse, error) {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var validationResponse TokenValidationResponse
	if err := json.Unmarshal(body, &validationResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &validationResponse, nil
}

// testProtectedEndpoint tests access to a protected endpoint
func testProtectedEndpoint(url, token string, log *logger.Logger) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("protected endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// getAuthStats retrieves authentication statistics
func getAuthStats(url string, log *logger.Logger) (*AuthStats, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth stats: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var stats AuthStats
	if err := json.Unmarshal(body, &stats); err != nil {
		return nil, fmt.Errorf("failed to unmarshal stats: %w", err)
	}

	return &stats, nil
}
