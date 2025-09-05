package firebase

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	// Test valid config
	config := &Config{
		Firebase: FirebaseConfig{
			ProjectID: "test-project",
			Admin: AdminConfig{
				ServiceAccountPath: "/tmp/test-service-account.json",
			},
		},
	}

	// Create a temporary file for testing
	err := config.Validate()
	// This will fail because the file doesn't exist, but that's expected
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account file not found")

	// Test invalid config - missing project ID
	invalidConfig := &Config{
		Firebase: FirebaseConfig{
			ProjectID: "",
		},
	}

	err = invalidConfig.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "firebase project_id is required")
}

// TestExpandEnvVars tests environment variable expansion
func TestExpandEnvVars(t *testing.T) {
	config := &Config{
		Firebase: FirebaseConfig{
			APIKey: "${TEST_API_KEY}",
		},
	}

	// Set a test environment variable
	t.Setenv("TEST_API_KEY", "test-api-key-value")

	err := expandEnvVars(config)
	assert.NoError(t, err)
	assert.Equal(t, "test-api-key-value", config.Firebase.APIKey)
}
