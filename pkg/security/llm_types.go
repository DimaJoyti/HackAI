package security

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// LLMRequest represents an incoming LLM request
type LLMRequest struct {
	ID        string                 `json:"id"`
	UserID    *uuid.UUID             `json:"user_id"`
	SessionID *uuid.UUID             `json:"session_id"`
	Provider  string                 `json:"provider"`
	Model     string                 `json:"model"`
	Endpoint  string                 `json:"endpoint"`
	Method    string                 `json:"method"`
	Headers   map[string]string      `json:"headers"`
	Body      json.RawMessage        `json:"body"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Timestamp time.Time              `json:"timestamp"`
	Context   map[string]interface{} `json:"context"`
}

// LLMResponse represents an LLM response
type LLMResponse struct {
	ID         string                 `json:"id"`
	RequestID  string                 `json:"request_id"`
	StatusCode int                    `json:"status_code"`
	Headers    map[string]string      `json:"headers"`
	Body       json.RawMessage        `json:"body"`
	Duration   time.Duration          `json:"duration"`
	TokensUsed int                    `json:"tokens_used"`
	Cost       float64                `json:"cost"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// SecurityResult represents the result of security analysis
type SecurityResult struct {
	Allowed         bool                   `json:"allowed"`
	ThreatScore     float64                `json:"threat_score"`
	Violations      []PolicyViolation      `json:"violations"`
	BlockReason     string                 `json:"block_reason"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	PolicyID    uuid.UUID              `json:"policy_id"`
	PolicyName  string                 `json:"policy_name"`
	RuleID      uuid.UUID              `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Score       float64                `json:"score"`
}
