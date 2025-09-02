package ai_security

import (
	"context"
	"time"
)

// ThreatLevel represents the severity of a security threat
type ThreatLevel int

const (
	ThreatLevelNone ThreatLevel = iota
	ThreatLevelLow
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

func (t ThreatLevel) String() string {
	switch t {
	case ThreatLevelNone:
		return "none"
	case ThreatLevelLow:
		return "low"
	case ThreatLevelMedium:
		return "medium"
	case ThreatLevelHigh:
		return "high"
	case ThreatLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// AttackType represents different types of AI security attacks
type AttackType string

const (
	AttackTypePromptInjection   AttackType = "prompt_injection"
	AttackTypeJailbreak         AttackType = "jailbreak"
	AttackTypeDataExtraction    AttackType = "data_extraction"
	AttackTypeModelInversion    AttackType = "model_inversion"
	AttackTypeAdversarial       AttackType = "adversarial"
	AttackTypeSocialEngineering AttackType = "social_engineering"
	AttackTypeDenialOfService   AttackType = "denial_of_service"
	AttackTypePrivacyViolation  AttackType = "privacy_violation"
	AttackTypeToxicContent      AttackType = "toxic_content"
	AttackTypeMisinformation    AttackType = "misinformation"
)

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        AttackType             `json:"type"`
	Level       ThreatLevel            `json:"level"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Description string                 `json:"description"`
	Input       string                 `json:"input"`
	Output      string                 `json:"output,omitempty"`
	Confidence  float64                `json:"confidence"`
	Blocked     bool                   `json:"blocked"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatDetection represents the result of threat analysis
type ThreatDetection struct {
	Detected   bool                   `json:"detected"`
	Type       AttackType             `json:"type"`
	Level      ThreatLevel            `json:"level"`
	Confidence float64                `json:"confidence"`
	Reason     string                 `json:"reason"`
	Indicators []string               `json:"indicators"`
	Metadata   map[string]interface{} `json:"metadata"`
	Timestamp  time.Time              `json:"timestamp"`
}

// SecurityContext provides context for security operations
type SecurityContext struct {
	UserID    string                 `json:"user_id"`
	SessionID string                 `json:"session_id"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	RequestID string                 `json:"request_id"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// AttackDetector interface for detecting security threats
type AttackDetector interface {
	// Detect analyzes input for potential security threats
	Detect(ctx context.Context, input string, secCtx SecurityContext) (ThreatDetection, error)

	// GetSupportedAttacks returns the types of attacks this detector can identify
	GetSupportedAttacks() []AttackType

	// UpdateModel updates the detection model (for ML-based detectors)
	UpdateModel(ctx context.Context, modelData []byte) error

	// GetConfidence returns the confidence threshold for this detector
	GetConfidence() float64
}

// SecurityManager is the main interface for the security system
type SecurityManager interface {
	// AnalyzeInput performs comprehensive security analysis on input
	AnalyzeInput(ctx context.Context, input string, secCtx SecurityContext) ([]ThreatDetection, error)

	// ProcessRequest processes a request through the security pipeline
	ProcessRequest(ctx context.Context, input string, secCtx SecurityContext) (SecurityResult, error)
}

// SecurityResult represents the result of security processing
type SecurityResult struct {
	Allowed     bool                   `json:"allowed"`
	Threats     []ThreatDetection      `json:"threats"`
	Actions     []string               `json:"actions"`
	ProcessedAt time.Time              `json:"processed_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SecurityConfig provides configuration for the security system
type SecurityConfig struct {
	Enabled                bool                   `json:"enabled"`
	DefaultThreatLevel     ThreatLevel            `json:"default_threat_level"`
	BlockOnHighThreat      bool                   `json:"block_on_high_threat"`
	LogAllEvents           bool                   `json:"log_all_events"`
	EnableRealTimeAnalysis bool                   `json:"enable_realtime_analysis"`
	DetectorConfigs        map[string]interface{} `json:"detector_configs"`
	PolicyConfigs          map[string]interface{} `json:"policy_configs"`
	ResponseConfigs        map[string]interface{} `json:"response_configs"`
	AnalyticsConfigs       map[string]interface{} `json:"analytics_configs"`
}
