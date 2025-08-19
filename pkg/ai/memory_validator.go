package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MemoryValidator provides validation and integrity checking for memory data
type MemoryValidator struct {
	config ValidationConfig
}

// ValidationConfig configures memory validation
type ValidationConfig struct {
	EnableChecksumValidation bool `json:"enable_checksum_validation"`
	EnableSchemaValidation   bool `json:"enable_schema_validation"`
	EnableContentValidation  bool `json:"enable_content_validation"`
	MaxMessageLength         int  `json:"max_message_length"`
	MaxMessagesPerSession    int  `json:"max_messages_per_session"`
	MaxContextSize           int  `json:"max_context_size"`
	RequiredFields           []string `json:"required_fields"`
}

// NewMemoryValidator creates a new memory validator
func NewMemoryValidator(config ValidationConfig) *MemoryValidator {
	// Set defaults
	if config.MaxMessageLength == 0 {
		config.MaxMessageLength = 10000
	}
	if config.MaxMessagesPerSession == 0 {
		config.MaxMessagesPerSession = 1000
	}
	if config.MaxContextSize == 0 {
		config.MaxContextSize = 50000
	}

	return &MemoryValidator{
		config: config,
	}
}

// Validate validates a memory object and returns validation results
func (mv *MemoryValidator) Validate(ctx context.Context, memory Memory) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:    true,
		Errors:   make([]ValidationError, 0),
		Warnings: make([]ValidationWarning, 0),
		Metadata: make(map[string]interface{}),
	}

	// Calculate checksum
	checksum, err := mv.calculateChecksum(memory)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate checksum: %w", err)
	}
	result.Checksum = checksum

	// Calculate size
	size, err := mv.calculateSize(memory)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate size: %w", err)
	}
	result.Size = size

	// Perform validations
	mv.validateSchema(memory, result)
	mv.validateContent(memory, result)
	mv.validateConstraints(memory, result)
	mv.validateIntegrity(memory, result)

	// Set overall validity
	result.Valid = len(result.Errors) == 0

	// Add metadata
	result.Metadata["validation_time"] = time.Now()
	result.Metadata["validator_version"] = "1.0.0"
	result.Metadata["message_count"] = len(memory.Messages)
	result.Metadata["context_keys"] = len(memory.Context)

	return result, nil
}

// validateSchema validates the memory schema
func (mv *MemoryValidator) validateSchema(memory Memory, result *ValidationResult) {
	if !mv.config.EnableSchemaValidation {
		return
	}

	// Check required fields
	for _, field := range mv.config.RequiredFields {
		switch field {
		case "session_id":
			if memory.SessionID == "" {
				result.Errors = append(result.Errors, ValidationError{
					Code:     "MISSING_SESSION_ID",
					Message:  "Session ID is required",
					Field:    "session_id",
					Severity: "error",
				})
			}
		case "user_id":
			if memory.UserID == "" {
				result.Errors = append(result.Errors, ValidationError{
					Code:     "MISSING_USER_ID",
					Message:  "User ID is required",
					Field:    "user_id",
					Severity: "error",
				})
			}
		case "messages":
			if len(memory.Messages) == 0 {
				result.Warnings = append(result.Warnings, ValidationWarning{
					Code:       "EMPTY_MESSAGES",
					Message:    "Memory has no messages",
					Field:      "messages",
					Suggestion: "Consider adding at least one message",
				})
			}
		}
	}

	// Validate message structure
	for i, msg := range memory.Messages {
		if msg.Role == "" {
			result.Errors = append(result.Errors, ValidationError{
				Code:     "MISSING_MESSAGE_ROLE",
				Message:  fmt.Sprintf("Message %d is missing role", i),
				Field:    fmt.Sprintf("messages[%d].role", i),
				Severity: "error",
			})
		}

		if msg.Content == "" {
			result.Errors = append(result.Errors, ValidationError{
				Code:     "EMPTY_MESSAGE_CONTENT",
				Message:  fmt.Sprintf("Message %d has empty content", i),
				Field:    fmt.Sprintf("messages[%d].content", i),
				Severity: "error",
			})
		}

		if msg.Timestamp.IsZero() {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Code:       "MISSING_MESSAGE_TIMESTAMP",
				Message:    fmt.Sprintf("Message %d is missing timestamp", i),
				Field:      fmt.Sprintf("messages[%d].timestamp", i),
				Suggestion: "Add timestamp for better tracking",
			})
		}
	}
}

// validateContent validates the content of the memory
func (mv *MemoryValidator) validateContent(memory Memory, result *ValidationResult) {
	if !mv.config.EnableContentValidation {
		return
	}

	// Check message length limits
	for i, msg := range memory.Messages {
		if len(msg.Content) > mv.config.MaxMessageLength {
			result.Errors = append(result.Errors, ValidationError{
				Code:     "MESSAGE_TOO_LONG",
				Message:  fmt.Sprintf("Message %d exceeds maximum length of %d characters", i, mv.config.MaxMessageLength),
				Field:    fmt.Sprintf("messages[%d].content", i),
				Severity: "error",
			})
		}

		// Check for potentially harmful content
		if mv.containsSuspiciousContent(msg.Content) {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Code:       "SUSPICIOUS_CONTENT",
				Message:    fmt.Sprintf("Message %d may contain suspicious content", i),
				Field:      fmt.Sprintf("messages[%d].content", i),
				Suggestion: "Review content for potential security issues",
			})
		}
	}

	// Check for duplicate messages
	messageHashes := make(map[string]int)
	for i, msg := range memory.Messages {
		hash := mv.hashContent(msg.Content)
		if prevIndex, exists := messageHashes[hash]; exists {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Code:       "DUPLICATE_MESSAGE",
				Message:    fmt.Sprintf("Message %d is identical to message %d", i, prevIndex),
				Field:      fmt.Sprintf("messages[%d].content", i),
				Suggestion: "Consider removing duplicate messages",
			})
		}
		messageHashes[hash] = i
	}
}

// validateConstraints validates memory constraints
func (mv *MemoryValidator) validateConstraints(memory Memory, result *ValidationResult) {
	// Check message count limit
	if len(memory.Messages) > mv.config.MaxMessagesPerSession {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "TOO_MANY_MESSAGES",
			Message:  fmt.Sprintf("Session has %d messages, exceeding limit of %d", len(memory.Messages), mv.config.MaxMessagesPerSession),
			Field:    "messages",
			Severity: "error",
		})
	}

	// Check context size
	contextSize := mv.calculateContextSize(memory.Context)
	if contextSize > mv.config.MaxContextSize {
		result.Errors = append(result.Errors, ValidationError{
			Code:     "CONTEXT_TOO_LARGE",
			Message:  fmt.Sprintf("Context size %d bytes exceeds limit of %d bytes", contextSize, mv.config.MaxContextSize),
			Field:    "context",
			Severity: "error",
		})
	}

	// Check timestamp consistency
	for i := 1; i < len(memory.Messages); i++ {
		if memory.Messages[i].Timestamp.Before(memory.Messages[i-1].Timestamp) {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Code:       "TIMESTAMP_ORDER",
				Message:    fmt.Sprintf("Message %d timestamp is before previous message", i),
				Field:      fmt.Sprintf("messages[%d].timestamp", i),
				Suggestion: "Ensure messages are in chronological order",
			})
		}
	}
}

// validateIntegrity validates data integrity
func (mv *MemoryValidator) validateIntegrity(memory Memory, result *ValidationResult) {
	if !mv.config.EnableChecksumValidation {
		return
	}

	// Check for data corruption indicators
	for i, msg := range memory.Messages {
		// Check for null bytes or control characters
		if strings.Contains(msg.Content, "\x00") {
			result.Errors = append(result.Errors, ValidationError{
				Code:     "CORRUPTED_MESSAGE",
				Message:  fmt.Sprintf("Message %d contains null bytes", i),
				Field:    fmt.Sprintf("messages[%d].content", i),
				Severity: "error",
			})
		}

		// Check for encoding issues
		if !mv.isValidUTF8(msg.Content) {
			result.Errors = append(result.Errors, ValidationError{
				Code:     "INVALID_ENCODING",
				Message:  fmt.Sprintf("Message %d has invalid UTF-8 encoding", i),
				Field:    fmt.Sprintf("messages[%d].content", i),
				Severity: "error",
			})
		}
	}

	// Validate version consistency
	if memory.Version < 1 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Code:       "INVALID_VERSION",
			Message:    "Memory version should be >= 1",
			Field:      "version",
			Suggestion: "Update version to current schema version",
		})
	}
}

// Helper methods

func (mv *MemoryValidator) calculateChecksum(memory Memory) (string, error) {
	// Serialize memory to JSON for consistent hashing
	data, err := json.Marshal(memory)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func (mv *MemoryValidator) calculateSize(memory Memory) (int64, error) {
	data, err := json.Marshal(memory)
	if err != nil {
		return 0, err
	}
	return int64(len(data)), nil
}

func (mv *MemoryValidator) calculateContextSize(context map[string]interface{}) int {
	data, err := json.Marshal(context)
	if err != nil {
		return 0
	}
	return len(data)
}

func (mv *MemoryValidator) containsSuspiciousContent(content string) bool {
	// Simple check for potentially suspicious patterns
	suspiciousPatterns := []string{
		"<script",
		"javascript:",
		"data:text/html",
		"eval(",
		"document.cookie",
		"localStorage",
		"sessionStorage",
	}

	contentLower := strings.ToLower(content)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(contentLower, pattern) {
			return true
		}
	}
	return false
}

func (mv *MemoryValidator) hashContent(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for efficiency
}

func (mv *MemoryValidator) isValidUTF8(s string) bool {
	// Go strings are UTF-8 by default, but we can check for replacement characters
	return !strings.Contains(s, "\uFFFD")
}

// ValidateSession validates an entire session's memory consistency
func (mv *MemoryValidator) ValidateSession(ctx context.Context, sessionID string, memories []Memory) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:    true,
		Errors:   make([]ValidationError, 0),
		Warnings: make([]ValidationWarning, 0),
		Metadata: make(map[string]interface{}),
	}

	// Check session consistency
	for i, memory := range memories {
		if memory.SessionID != sessionID {
			result.Errors = append(result.Errors, ValidationError{
				Code:     "SESSION_ID_MISMATCH",
				Message:  fmt.Sprintf("Memory %d has mismatched session ID", i),
				Field:    fmt.Sprintf("memories[%d].session_id", i),
				Severity: "error",
			})
		}

		// Validate individual memory
		memResult, err := mv.Validate(ctx, memory)
		if err != nil {
			return nil, err
		}

		// Merge results
		result.Errors = append(result.Errors, memResult.Errors...)
		result.Warnings = append(result.Warnings, memResult.Warnings...)
	}

	result.Valid = len(result.Errors) == 0
	result.Metadata["session_id"] = sessionID
	result.Metadata["memory_count"] = len(memories)
	result.Metadata["validation_time"] = time.Now()

	return result, nil
}
