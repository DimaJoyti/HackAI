package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var policyTracer = otel.Tracer("hackai/security/llm_policy_engine")

// LLMPolicyEngine implements the PolicyEngine interface for LLM-specific security policies
type LLMPolicyEngine struct {
	logger          *logger.Logger
	config          *LLMPolicyConfig
	policyRepo      domain.SecurityPolicyRepository
	promptGuard     *PromptInjectionGuard
	contentAnalyzer *ContentAnalyzer
	ruleEvaluators  map[string]RuleEvaluator
	policyCache     map[string]*domain.SecurityPolicy
	executionCache  map[string]*PolicyExecutionResult
	mu              sync.RWMutex
	lastCacheUpdate time.Time
}

// LLMPolicyConfig holds configuration for the LLM policy engine
type LLMPolicyConfig struct {
	// Cache Settings
	CacheEnabled bool          `json:"cache_enabled"`
	CacheTTL     time.Duration `json:"cache_ttl"`
	MaxCacheSize int           `json:"max_cache_size"`

	// Evaluation Settings
	MaxConcurrentEvals int           `json:"max_concurrent_evals"`
	EvaluationTimeout  time.Duration `json:"evaluation_timeout"`
	DefaultThreatScore float64       `json:"default_threat_score"`

	// Rule Processing
	EnablePromptInjection bool `json:"enable_prompt_injection"`
	EnableContentFilter   bool `json:"enable_content_filter"`
	EnableAccessControl   bool `json:"enable_access_control"`
	EnableRateLimit       bool `json:"enable_rate_limit"`
	EnableCompliance      bool `json:"enable_compliance"`

	// Thresholds
	PromptInjectionThreshold float64 `json:"prompt_injection_threshold"`
	ContentFilterThreshold   float64 `json:"content_filter_threshold"`
	AnomalyThreshold         float64 `json:"anomaly_threshold"`
}

// PolicyExecutionResult represents the result of policy execution
type PolicyExecutionResult struct {
	PolicyID        uuid.UUID              `json:"policy_id"`
	PolicyName      string                 `json:"policy_name"`
	ExecutionTime   time.Time              `json:"execution_time"`
	Duration        time.Duration          `json:"duration"`
	Result          string                 `json:"result"`
	ThreatScore     float64                `json:"threat_score"`
	ConfidenceScore float64                `json:"confidence_score"`
	RuleResults     []RuleExecutionResult  `json:"rule_results"`
	Violations      []PolicyViolation      `json:"violations"`
	Actions         []PolicyAction         `json:"actions"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// RuleExecutionResult represents the result of a single rule execution
type RuleExecutionResult struct {
	RuleID     uuid.UUID              `json:"rule_id"`
	RuleName   string                 `json:"rule_name"`
	RuleType   string                 `json:"rule_type"`
	Matched    bool                   `json:"matched"`
	Score      float64                `json:"score"`
	Confidence float64                `json:"confidence"`
	Evidence   string                 `json:"evidence"`
	Duration   time.Duration          `json:"duration"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// PolicyAction represents an action to be taken based on policy evaluation
type PolicyAction struct {
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
	Priority   int                    `json:"priority"`
	Condition  string                 `json:"condition"`
}

// RuleEvaluator interface for different rule types
type RuleEvaluator interface {
	EvaluateRule(ctx context.Context, rule *domain.PolicyRule, req *LLMRequest) (*RuleExecutionResult, error)
	GetRuleType() string
	Health(ctx context.Context) error
}

// NewLLMPolicyEngine creates a new LLM policy engine
func NewLLMPolicyEngine(
	logger *logger.Logger,
	config *LLMPolicyConfig,
	policyRepo domain.SecurityPolicyRepository,
	promptGuard *PromptInjectionGuard,
	contentAnalyzer *ContentAnalyzer,
) *LLMPolicyEngine {
	engine := &LLMPolicyEngine{
		logger:          logger,
		config:          config,
		policyRepo:      policyRepo,
		promptGuard:     promptGuard,
		contentAnalyzer: contentAnalyzer,
		ruleEvaluators:  make(map[string]RuleEvaluator),
		policyCache:     make(map[string]*domain.SecurityPolicy),
		executionCache:  make(map[string]*PolicyExecutionResult),
	}

	// Register built-in rule evaluators
	engine.registerRuleEvaluators()

	return engine
}

// EvaluateRequest evaluates an LLM request against active security policies
func (pe *LLMPolicyEngine) EvaluateRequest(ctx context.Context, req *LLMRequest) (*SecurityResult, error) {
	ctx, span := policyTracer.Start(ctx, "llm_policy_engine.evaluate_request")
	defer span.End()

	span.SetAttributes(
		attribute.String("request.id", req.ID),
		attribute.String("request.provider", req.Provider),
		attribute.String("request.model", req.Model),
	)

	startTime := time.Now()

	// Get active policies for the request
	policies, err := pe.getActivePoliciesForRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get active policies: %w", err)
	}

	if len(policies) == 0 {
		// No policies to evaluate, allow request
		return &SecurityResult{
			Allowed:         true,
			ThreatScore:     0.0,
			Violations:      []PolicyViolation{},
			BlockReason:     "",
			Recommendations: []string{},
			Metadata:        map[string]interface{}{"policies_evaluated": 0},
		}, nil
	}

	// Evaluate each policy
	var allViolations []PolicyViolation
	var maxThreatScore float64
	var blockReasons []string
	var recommendations []string
	var executionResults []*PolicyExecutionResult

	for _, policy := range policies {
		result, err := pe.evaluatePolicy(ctx, policy, req)
		if err != nil {
			pe.logger.WithError(err).WithField("policy_id", policy.ID).Error("Failed to evaluate policy")
			continue
		}

		executionResults = append(executionResults, result)

		// Aggregate results
		if result.ThreatScore > maxThreatScore {
			maxThreatScore = result.ThreatScore
		}

		if len(result.Violations) > 0 {
			allViolations = append(allViolations, result.Violations...)

			// Check if this policy should block the request
			if policy.BlockOnViolation && result.ThreatScore >= policy.ThreatThreshold {
				blockReasons = append(blockReasons, fmt.Sprintf("Policy '%s' violation", policy.Name))
			}
		}

		// Record policy execution
		pe.recordPolicyExecution(ctx, policy, req, result)
	}

	// Determine final result
	allowed := len(blockReasons) == 0
	blockReason := ""
	if !allowed {
		blockReason = strings.Join(blockReasons, "; ")
	}

	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int("policies.evaluated", len(policies)),
		attribute.Int("violations.count", len(allViolations)),
		attribute.Float64("threat.score", maxThreatScore),
		attribute.Bool("request.allowed", allowed),
		attribute.Int64("evaluation.duration_ms", duration.Milliseconds()),
	)

	pe.logger.WithFields(map[string]interface{}{
		"request_id":         req.ID,
		"policies_evaluated": len(policies),
		"violations_count":   len(allViolations),
		"threat_score":       maxThreatScore,
		"allowed":            allowed,
		"duration_ms":        duration.Milliseconds(),
	}).Info("Policy evaluation completed")

	return &SecurityResult{
		Allowed:         allowed,
		ThreatScore:     maxThreatScore,
		Violations:      allViolations,
		BlockReason:     blockReason,
		Recommendations: recommendations,
		Metadata: map[string]interface{}{
			"policies_evaluated":  len(policies),
			"execution_results":   executionResults,
			"evaluation_duration": duration.Milliseconds(),
		},
	}, nil
}

// GetActivePolicies returns active policies for a scope and target
func (pe *LLMPolicyEngine) GetActivePolicies(ctx context.Context, scope string, targetID *uuid.UUID) ([]*domain.SecurityPolicy, error) {
	return pe.policyRepo.GetActivePolicies(ctx, scope, targetID)
}

// Health checks the health of the policy engine
func (pe *LLMPolicyEngine) Health(ctx context.Context) error {
	// Check policy repository
	if _, err := pe.policyRepo.ListPolicies(ctx, domain.PolicyFilter{Limit: 1}); err != nil {
		return fmt.Errorf("policy repository health check failed: %w", err)
	}

	// Check rule evaluators
	for ruleType, evaluator := range pe.ruleEvaluators {
		if err := evaluator.Health(ctx); err != nil {
			return fmt.Errorf("rule evaluator %s health check failed: %w", ruleType, err)
		}
	}

	return nil
}

// getActivePoliciesForRequest gets active policies that apply to the request
func (pe *LLMPolicyEngine) getActivePoliciesForRequest(ctx context.Context, req *LLMRequest) ([]*domain.SecurityPolicy, error) {
	var allPolicies []*domain.SecurityPolicy

	// Get global policies
	globalPolicies, err := pe.GetActivePolicies(ctx, domain.ScopeGlobal, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get global policies: %w", err)
	}
	allPolicies = append(allPolicies, globalPolicies...)

	// Get user-specific policies
	if req.UserID != nil {
		userPolicies, err := pe.GetActivePolicies(ctx, domain.ScopeUser, req.UserID)
		if err != nil {
			pe.logger.WithError(err).WithField("user_id", *req.UserID).Warn("Failed to get user policies")
		} else {
			allPolicies = append(allPolicies, userPolicies...)
		}
	}

	// Get provider-specific policies
	// Note: This would require provider ID lookup, simplified for now

	// Filter and sort policies by priority
	filteredPolicies := pe.filterPoliciesForRequest(allPolicies, req)

	return filteredPolicies, nil
}

// filterPoliciesForRequest filters policies that apply to the specific request
func (pe *LLMPolicyEngine) filterPoliciesForRequest(policies []*domain.SecurityPolicy, req *LLMRequest) []*domain.SecurityPolicy {
	var filtered []*domain.SecurityPolicy

	for _, policy := range policies {
		if pe.policyAppliesTo(policy, req) {
			filtered = append(filtered, policy)
		}
	}

	// Sort by priority (higher priority first)
	for i := 0; i < len(filtered)-1; i++ {
		for j := i + 1; j < len(filtered); j++ {
			if filtered[i].Priority < filtered[j].Priority {
				filtered[i], filtered[j] = filtered[j], filtered[i]
			}
		}
	}

	return filtered
}

// policyAppliesTo checks if a policy applies to the request
func (pe *LLMPolicyEngine) policyAppliesTo(policy *domain.SecurityPolicy, req *LLMRequest) bool {
	// Check if policy is enabled and active
	if !policy.Enabled || policy.Status != domain.StatusActive {
		return false
	}

	// Check expiration
	if policy.ExpiresAt != nil && time.Now().After(*policy.ExpiresAt) {
		return false
	}

	// Check user targeting
	if len(policy.TargetUsers) > 0 && req.UserID != nil {
		found := false
		for _, userID := range policy.TargetUsers {
			if userID == *req.UserID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check provider targeting
	if len(policy.TargetProviders) > 0 {
		// This would require provider ID lookup
		// Simplified for now - assume all providers match
	}

	return true
}

// evaluatePolicy evaluates a single policy against a request
func (pe *LLMPolicyEngine) evaluatePolicy(ctx context.Context, policy *domain.SecurityPolicy, req *LLMRequest) (*PolicyExecutionResult, error) {
	ctx, span := policyTracer.Start(ctx, "llm_policy_engine.evaluate_policy")
	defer span.End()

	span.SetAttributes(
		attribute.String("policy.id", policy.ID.String()),
		attribute.String("policy.name", policy.Name),
		attribute.String("policy.type", policy.PolicyType),
	)

	startTime := time.Now()

	result := &PolicyExecutionResult{
		PolicyID:        policy.ID,
		PolicyName:      policy.Name,
		ExecutionTime:   startTime,
		Result:          domain.ExecutionResultPass,
		ThreatScore:     0.0,
		ConfidenceScore: 0.0,
		RuleResults:     []RuleExecutionResult{},
		Violations:      []PolicyViolation{},
		Actions:         []PolicyAction{},
		Metadata:        make(map[string]interface{}),
	}

	// Get policy rules
	rules, err := pe.policyRepo.ListRules(ctx, policy.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy rules: %w", err)
	}

	// Evaluate each rule
	var maxScore float64
	var totalConfidence float64
	var ruleCount int

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		ruleResult, err := pe.evaluateRule(ctx, rule, req)
		if err != nil {
			pe.logger.WithError(err).WithField("rule_id", rule.ID).Error("Failed to evaluate rule")
			continue
		}

		result.RuleResults = append(result.RuleResults, *ruleResult)
		ruleCount++

		if ruleResult.Matched {
			// Rule matched - potential violation
			if ruleResult.Score > maxScore {
				maxScore = ruleResult.Score
			}
			totalConfidence += ruleResult.Confidence

			// Create violation
			violation := PolicyViolation{
				PolicyID:    policy.ID,
				PolicyName:  policy.Name,
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Severity:    pe.determineSeverity(ruleResult.Score),
				Description: fmt.Sprintf("Rule '%s' matched: %s", rule.Name, ruleResult.Evidence),
				Evidence: map[string]interface{}{
					"rule_type":  rule.RuleType,
					"evidence":   ruleResult.Evidence,
					"score":      ruleResult.Score,
					"confidence": ruleResult.Confidence,
					"metadata":   ruleResult.Metadata,
				},
				Score: ruleResult.Score,
			}
			result.Violations = append(result.Violations, violation)
		}
	}

	// Calculate final scores
	result.ThreatScore = maxScore
	if ruleCount > 0 {
		result.ConfidenceScore = totalConfidence / float64(ruleCount)
	}

	// Determine result
	if len(result.Violations) > 0 {
		if result.ThreatScore >= policy.ThreatThreshold {
			result.Result = domain.ExecutionResultFail
		}
	}

	result.Duration = time.Since(startTime)

	span.SetAttributes(
		attribute.Int("rules.evaluated", ruleCount),
		attribute.Int("violations.count", len(result.Violations)),
		attribute.Float64("threat.score", result.ThreatScore),
		attribute.String("result", result.Result),
	)

	return result, nil
}

// evaluateRule evaluates a single rule against a request
func (pe *LLMPolicyEngine) evaluateRule(ctx context.Context, rule *domain.PolicyRule, req *LLMRequest) (*RuleExecutionResult, error) {
	evaluator, exists := pe.ruleEvaluators[rule.RuleType]
	if !exists {
		return nil, fmt.Errorf("no evaluator found for rule type: %s", rule.RuleType)
	}

	return evaluator.EvaluateRule(ctx, rule, req)
}

// registerRuleEvaluators registers built-in rule evaluators
func (pe *LLMPolicyEngine) registerRuleEvaluators() {
	// TODO: Implement rule evaluators
	// pe.ruleEvaluators[domain.RuleTypeRegex] = NewRegexRuleEvaluator(pe.logger)
	// pe.ruleEvaluators[domain.RuleTypeKeyword] = NewKeywordRuleEvaluator(pe.logger)
	// pe.ruleEvaluators[domain.RuleTypeSemantic] = NewSemanticRuleEvaluator(pe.logger, pe.contentAnalyzer)
	// pe.ruleEvaluators[domain.RuleTypeML] = NewMLRuleEvaluator(pe.logger, pe.promptGuard)
	// pe.ruleEvaluators[domain.RuleTypeThreshold] = NewThresholdRuleEvaluator(pe.logger)
}

// recordPolicyExecution records policy execution for audit and analytics
func (pe *LLMPolicyEngine) recordPolicyExecution(ctx context.Context, policy *domain.SecurityPolicy, req *LLMRequest, result *PolicyExecutionResult) {
	execution := &domain.PolicyExecution{
		PolicyID:        policy.ID,
		RequestID:       req.ID,
		ExecutionTime:   result.ExecutionTime,
		Duration:        result.Duration.Microseconds(),
		Result:          result.Result,
		RulesEvaluated:  len(result.RuleResults),
		ThreatScore:     result.ThreatScore,
		ConfidenceScore: result.ConfidenceScore,
		Blocked:         result.Result == domain.ExecutionResultFail,
	}

	// Count rule results
	for _, ruleResult := range result.RuleResults {
		if ruleResult.Matched {
			execution.RulesFailed++
		} else {
			execution.RulesPassed++
		}
	}

	// Set actions taken
	if len(result.Actions) > 0 {
		actionsJSON, _ := json.Marshal(result.Actions)
		execution.ActionsTaken = actionsJSON
	}

	// Set context
	contextData := map[string]interface{}{
		"request_provider": req.Provider,
		"request_model":    req.Model,
		"request_endpoint": req.Endpoint,
		"user_id":          req.UserID,
		"session_id":       req.SessionID,
	}
	contextJSON, _ := json.Marshal(contextData)
	execution.Context = contextJSON

	if err := pe.policyRepo.CreateExecution(ctx, execution); err != nil {
		pe.logger.WithError(err).Error("Failed to record policy execution")
	}
}

// determineSeverity determines severity based on threat score
func (pe *LLMPolicyEngine) determineSeverity(score float64) string {
	switch {
	case score >= 0.9:
		return string(domain.SeverityCritical)
	case score >= 0.7:
		return string(domain.SeverityHigh)
	case score >= 0.5:
		return string(domain.SeverityMedium)
	case score >= 0.3:
		return string(domain.SeverityLow)
	default:
		return string(domain.SeverityInfo)
	}
}

// DefaultLLMPolicyConfig returns default configuration
func DefaultLLMPolicyConfig() *LLMPolicyConfig {
	return &LLMPolicyConfig{
		CacheEnabled:             true,
		CacheTTL:                 5 * time.Minute,
		MaxCacheSize:             1000,
		MaxConcurrentEvals:       10,
		EvaluationTimeout:        30 * time.Second,
		DefaultThreatScore:       0.0,
		EnablePromptInjection:    true,
		EnableContentFilter:      true,
		EnableAccessControl:      true,
		EnableRateLimit:          true,
		EnableCompliance:         true,
		PromptInjectionThreshold: 0.7,
		ContentFilterThreshold:   0.6,
		AnomalyThreshold:         0.8,
	}
}
