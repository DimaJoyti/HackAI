package attack_graphs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// BaseAttackNode provides common functionality for all attack nodes
type BaseAttackNode struct {
	ID            string                 `json:"id"`
	Type          AttackNodeType         `json:"type"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	RiskScore     float64                `json:"risk_score"`
	Difficulty    float64                `json:"difficulty"`
	Impact        float64                `json:"impact"`
	Prerequisites []string               `json:"prerequisites"`
	Capabilities  []string               `json:"capabilities"`
	Metadata      map[string]interface{} `json:"metadata"`
	Logger        *logger.Logger         `json:"-"`
}

// GetID returns the node ID
func (ban *BaseAttackNode) GetID() string {
	return ban.ID
}

// GetType returns the node type
func (ban *BaseAttackNode) GetType() AttackNodeType {
	return ban.Type
}

// GetName returns the node name
func (ban *BaseAttackNode) GetName() string {
	return ban.Name
}

// GetDescription returns the node description
func (ban *BaseAttackNode) GetDescription() string {
	return ban.Description
}

// GetRiskScore returns the risk score
func (ban *BaseAttackNode) GetRiskScore() float64 {
	return ban.RiskScore
}

// GetDifficulty returns the difficulty score
func (ban *BaseAttackNode) GetDifficulty() float64 {
	return ban.Difficulty
}

// GetImpact returns the impact score
func (ban *BaseAttackNode) GetImpact() float64 {
	return ban.Impact
}

// GetPrerequisites returns the prerequisites
func (ban *BaseAttackNode) GetPrerequisites() []string {
	return ban.Prerequisites
}

// GetCapabilities returns the capabilities
func (ban *BaseAttackNode) GetCapabilities() []string {
	return ban.Capabilities
}

// GetMetadata returns the metadata
func (ban *BaseAttackNode) GetMetadata() map[string]interface{} {
	return ban.Metadata
}

// Validate validates the node configuration
func (ban *BaseAttackNode) Validate() error {
	if ban.ID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	if ban.Name == "" {
		return fmt.Errorf("node name cannot be empty")
	}
	if ban.RiskScore < 0 || ban.RiskScore > 10 {
		return fmt.Errorf("risk score must be between 0 and 10")
	}
	if ban.Difficulty < 0 || ban.Difficulty > 10 {
		return fmt.Errorf("difficulty must be between 0 and 10")
	}
	if ban.Impact < 0 || ban.Impact > 10 {
		return fmt.Errorf("impact must be between 0 and 10")
	}
	return nil
}

// EntryPointNode represents an initial access vector
type EntryPointNode struct {
	BaseAttackNode
	AccessMethod    string   `json:"access_method"`
	TargetSurface   string   `json:"target_surface"`
	RequiredTools   []string `json:"required_tools"`
	DetectionRate   float64  `json:"detection_rate"`
	SuccessRate     float64  `json:"success_rate"`
}

// Execute executes the entry point attack
func (node *EntryPointNode) Execute(ctx context.Context, scenario *AttackScenario) (*AttackResult, error) {
	node.Logger.Debug("Executing entry point attack", "node_id", node.ID, "method", node.AccessMethod)

	// Simulate entry point attack
	success := node.evaluateSuccess(scenario)
	impact := node.calculateImpact(scenario)
	cost := node.calculateCost(scenario)
	detectionRisk := node.calculateDetectionRisk(scenario)

	result := &AttackResult{
		NodeID:       node.ID,
		Success:      success,
		Impact:       impact,
		Cost:         cost,
		Time:         time.Duration(cost*30) * time.Second,
		Risk:         node.RiskScore,
		Detection:    detectionRisk,
		Evidence:     []string{fmt.Sprintf("entry_point_%s", node.AccessMethod)},
		Artifacts:    []string{fmt.Sprintf("access_log_%s", node.ID)},
		Capabilities: []string{"initial_access"},
		Resources:    map[string]interface{}{"access_method": node.AccessMethod},
		Metadata:     map[string]interface{}{"target_surface": node.TargetSurface},
		Timestamp:    time.Now(),
	}

	if success {
		node.Logger.Info("Entry point attack succeeded", "node_id", node.ID, "method", node.AccessMethod)
	} else {
		node.Logger.Info("Entry point attack failed", "node_id", node.ID, "method", node.AccessMethod)
	}

	return result, nil
}

// evaluateSuccess evaluates attack success based on scenario
func (node *EntryPointNode) evaluateSuccess(scenario *AttackScenario) bool {
	baseSuccess := node.SuccessRate

	// Adjust based on attacker skill level
	skillMultiplier := 1.0
	switch scenario.AttackerProfile.SkillLevel {
	case SkillLevelNovice:
		skillMultiplier = 0.5
	case SkillLevelIntermediate:
		skillMultiplier = 0.7
	case SkillLevelAdvanced:
		skillMultiplier = 0.9
	case SkillLevelExpert:
		skillMultiplier = 1.0
	}

	// Adjust based on target security posture
	securityMultiplier := 1.0
	switch scenario.TargetProfile.SecurityPosture {
	case SecurityPostureLow:
		securityMultiplier = 1.2
	case SecurityPostureMedium:
		securityMultiplier = 1.0
	case SecurityPostureHigh:
		securityMultiplier = 0.7
	}

	adjustedSuccess := baseSuccess * skillMultiplier * securityMultiplier
	return adjustedSuccess > 0.5 // 50% threshold for success
}

// calculateImpact calculates the impact of the attack
func (node *EntryPointNode) calculateImpact(scenario *AttackScenario) float64 {
	baseImpact := node.Impact

	// Adjust based on target value
	valueMultiplier := scenario.TargetProfile.Value / 10.0
	if valueMultiplier < 0.1 {
		valueMultiplier = 0.1
	}

	return baseImpact * valueMultiplier
}

// calculateCost calculates the cost of the attack
func (node *EntryPointNode) calculateCost(scenario *AttackScenario) float64 {
	baseCost := node.Difficulty * 10.0

	// Adjust based on attacker resources
	resourceMultiplier := 1.0
	switch scenario.AttackerProfile.Resources {
	case ResourceLevelLow:
		resourceMultiplier = 1.5
	case ResourceLevelMedium:
		resourceMultiplier = 1.0
	case ResourceLevelHigh:
		resourceMultiplier = 0.7
	}

	return baseCost * resourceMultiplier
}

// calculateDetectionRisk calculates the risk of detection
func (node *EntryPointNode) calculateDetectionRisk(scenario *AttackScenario) float64 {
	baseDetection := node.DetectionRate

	// Adjust based on monitoring level
	monitoringMultiplier := 1.0
	switch scenario.Environment.MonitoringLevel {
	case MonitoringLevelBasic:
		monitoringMultiplier = 0.5
	case MonitoringLevelIntermediate:
		monitoringMultiplier = 1.0
	case MonitoringLevelAdvanced:
		monitoringMultiplier = 1.5
	}

	// Adjust based on attacker stealth
	stealthMultiplier := 1.0 - (scenario.AttackerProfile.Stealth / 10.0)

	return baseDetection * monitoringMultiplier * stealthMultiplier
}

// ExploitNode represents a vulnerability exploitation
type ExploitNode struct {
	BaseAttackNode
	VulnerabilityID string   `json:"vulnerability_id"`
	CVE             string   `json:"cve"`
	CVSS            float64  `json:"cvss"`
	ExploitType     string   `json:"exploit_type"`
	RequiredAccess  string   `json:"required_access"`
	Payload         string   `json:"payload"`
	RequiredTools   []string `json:"required_tools"`
	Reliability     float64  `json:"reliability"`
}

// Execute executes the exploit attack
func (node *ExploitNode) Execute(ctx context.Context, scenario *AttackScenario) (*AttackResult, error) {
	node.Logger.Debug("Executing exploit attack", "node_id", node.ID, "cve", node.CVE)

	// Simulate exploit execution
	success := node.evaluateExploitSuccess(scenario)
	impact := node.CVSS // Use CVSS score as impact
	cost := node.calculateExploitCost(scenario)
	detectionRisk := node.calculateExploitDetection(scenario)

	result := &AttackResult{
		NodeID:       node.ID,
		Success:      success,
		Impact:       impact,
		Cost:         cost,
		Time:         time.Duration(cost*20) * time.Second,
		Risk:         node.RiskScore,
		Detection:    detectionRisk,
		Evidence:     []string{fmt.Sprintf("exploit_%s", node.CVE)},
		Artifacts:    []string{fmt.Sprintf("payload_%s", node.ID)},
		Capabilities: []string{"exploitation", node.ExploitType},
		Resources:    map[string]interface{}{"vulnerability_id": node.VulnerabilityID},
		Metadata:     map[string]interface{}{"cvss": node.CVSS, "exploit_type": node.ExploitType},
		Timestamp:    time.Now(),
	}

	if success {
		node.Logger.Info("Exploit attack succeeded", "node_id", node.ID, "cve", node.CVE)
	} else {
		node.Logger.Info("Exploit attack failed", "node_id", node.ID, "cve", node.CVE)
	}

	return result, nil
}

// evaluateExploitSuccess evaluates exploit success
func (node *ExploitNode) evaluateExploitSuccess(scenario *AttackScenario) bool {
	baseSuccess := node.Reliability

	// Adjust based on CVSS exploitability
	exploitabilityFactor := node.CVSS / 10.0

	// Adjust based on attacker skill
	skillMultiplier := 1.0
	switch scenario.AttackerProfile.SkillLevel {
	case SkillLevelNovice:
		skillMultiplier = 0.4
	case SkillLevelIntermediate:
		skillMultiplier = 0.7
	case SkillLevelAdvanced:
		skillMultiplier = 0.9
	case SkillLevelExpert:
		skillMultiplier = 1.0
	}

	adjustedSuccess := baseSuccess * exploitabilityFactor * skillMultiplier
	return adjustedSuccess > 0.6 // 60% threshold for exploit success
}

// calculateExploitCost calculates exploit cost
func (node *ExploitNode) calculateExploitCost(scenario *AttackScenario) float64 {
	baseCost := (10.0 - node.CVSS) * 5.0 // Higher CVSS = lower cost

	// Adjust based on exploit complexity
	if strings.Contains(strings.ToLower(node.ExploitType), "remote") {
		baseCost *= 0.8 // Remote exploits are easier
	}
	if strings.Contains(strings.ToLower(node.ExploitType), "local") {
		baseCost *= 1.2 // Local exploits require more access
	}

	return baseCost
}

// calculateExploitDetection calculates exploit detection risk
func (node *ExploitNode) calculateExploitDetection(scenario *AttackScenario) float64 {
	baseDetection := 0.3 // Base 30% detection rate for exploits

	// Adjust based on exploit type
	if strings.Contains(strings.ToLower(node.ExploitType), "memory") {
		baseDetection *= 0.7 // Memory exploits harder to detect
	}
	if strings.Contains(strings.ToLower(node.ExploitType), "web") {
		baseDetection *= 1.3 // Web exploits easier to detect
	}

	// Adjust based on monitoring
	monitoringMultiplier := 1.0
	switch scenario.Environment.MonitoringLevel {
	case MonitoringLevelBasic:
		monitoringMultiplier = 0.5
	case MonitoringLevelIntermediate:
		monitoringMultiplier = 1.0
	case MonitoringLevelAdvanced:
		monitoringMultiplier = 1.8
	}

	return baseDetection * monitoringMultiplier
}

// PrivilegeEscalationNode represents privilege escalation attacks
type PrivilegeEscalationNode struct {
	BaseAttackNode
	FromPrivilege string   `json:"from_privilege"`
	ToPrivilege   string   `json:"to_privilege"`
	Method        string   `json:"method"`
	RequiredTools []string `json:"required_tools"`
	Persistence   bool     `json:"persistence"`
	Stealth       float64  `json:"stealth"`
}

// Execute executes the privilege escalation attack
func (node *PrivilegeEscalationNode) Execute(ctx context.Context, scenario *AttackScenario) (*AttackResult, error) {
	node.Logger.Debug("Executing privilege escalation", "node_id", node.ID, "method", node.Method)

	// Simulate privilege escalation
	success := node.evaluateEscalationSuccess(scenario)
	impact := node.calculateEscalationImpact()
	cost := node.calculateEscalationCost(scenario)
	detectionRisk := node.calculateEscalationDetection(scenario)

	capabilities := []string{"privilege_escalation"}
	if node.Persistence {
		capabilities = append(capabilities, "persistence")
	}

	result := &AttackResult{
		NodeID:       node.ID,
		Success:      success,
		Impact:       impact,
		Cost:         cost,
		Time:         time.Duration(cost*25) * time.Second,
		Risk:         node.RiskScore,
		Detection:    detectionRisk,
		Evidence:     []string{fmt.Sprintf("privilege_escalation_%s", node.Method)},
		Artifacts:    []string{fmt.Sprintf("escalation_log_%s", node.ID)},
		Capabilities: capabilities,
		Resources:    map[string]interface{}{"from_privilege": node.FromPrivilege, "to_privilege": node.ToPrivilege},
		Metadata:     map[string]interface{}{"method": node.Method, "persistence": node.Persistence},
		Timestamp:    time.Now(),
	}

	if success {
		node.Logger.Info("Privilege escalation succeeded", "node_id", node.ID, "method", node.Method)
	} else {
		node.Logger.Info("Privilege escalation failed", "node_id", node.ID, "method", node.Method)
	}

	return result, nil
}

// evaluateEscalationSuccess evaluates escalation success
func (node *PrivilegeEscalationNode) evaluateEscalationSuccess(scenario *AttackScenario) bool {
	baseSuccess := 0.7 // Base 70% success rate

	// Adjust based on privilege gap
	privilegeGap := node.calculatePrivilegeGap()
	gapMultiplier := 1.0 - (privilegeGap * 0.2) // Larger gap = harder

	// Adjust based on attacker skill
	skillMultiplier := 1.0
	switch scenario.AttackerProfile.SkillLevel {
	case SkillLevelNovice:
		skillMultiplier = 0.5
	case SkillLevelIntermediate:
		skillMultiplier = 0.8
	case SkillLevelAdvanced:
		skillMultiplier = 0.95
	case SkillLevelExpert:
		skillMultiplier = 1.0
	}

	adjustedSuccess := baseSuccess * gapMultiplier * skillMultiplier
	return adjustedSuccess > 0.5
}

// calculatePrivilegeGap calculates the privilege gap
func (node *PrivilegeEscalationNode) calculatePrivilegeGap() float64 {
	// Simple privilege level mapping
	privilegeLevels := map[string]float64{
		"user":          1.0,
		"power_user":    2.0,
		"administrator": 3.0,
		"system":        4.0,
		"root":          5.0,
	}

	fromLevel := privilegeLevels[node.FromPrivilege]
	toLevel := privilegeLevels[node.ToPrivilege]

	if fromLevel == 0 {
		fromLevel = 1.0
	}
	if toLevel == 0 {
		toLevel = 5.0
	}

	return toLevel - fromLevel
}

// calculateEscalationImpact calculates escalation impact
func (node *PrivilegeEscalationNode) calculateEscalationImpact() float64 {
	privilegeGap := node.calculatePrivilegeGap()
	baseImpact := node.Impact

	// Higher privilege gap = higher impact
	return baseImpact * (1.0 + privilegeGap*0.2)
}

// calculateEscalationCost calculates escalation cost
func (node *PrivilegeEscalationNode) calculateEscalationCost(scenario *AttackScenario) float64 {
	baseCost := node.Difficulty * 8.0
	privilegeGap := node.calculatePrivilegeGap()

	// Higher privilege gap = higher cost
	return baseCost * (1.0 + privilegeGap*0.3)
}

// calculateEscalationDetection calculates escalation detection risk
func (node *PrivilegeEscalationNode) calculateEscalationDetection(scenario *AttackScenario) float64 {
	baseDetection := 0.4 // Base 40% detection rate

	// Adjust based on stealth
	stealthMultiplier := 1.0 - (node.Stealth / 10.0)

	// Adjust based on monitoring
	monitoringMultiplier := 1.0
	switch scenario.Environment.MonitoringLevel {
	case MonitoringLevelBasic:
		monitoringMultiplier = 0.6
	case MonitoringLevelIntermediate:
		monitoringMultiplier = 1.0
	case MonitoringLevelAdvanced:
		monitoringMultiplier = 1.6
	}

	return baseDetection * stealthMultiplier * monitoringMultiplier
}
