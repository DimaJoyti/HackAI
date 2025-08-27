package multiagent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dimajoyti/hackai/pkg/ai"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// VotingStrategy resolves conflicts through voting
type VotingStrategy struct {
	logger *logger.Logger
}

// Resolve implements ConflictResolutionStrategy
func (vs *VotingStrategy) Resolve(ctx context.Context, conflict *ConflictRecord, agents map[string]ai.Agent) (*ConflictResolution, error) {
	// Simple majority voting
	votes := make(map[string]int)

	for _, agentID := range conflict.Agents {
		if agent, exists := agents[agentID]; exists {
			// Get agent's vote (simplified - in practice would query agent)
			vote := vs.getAgentVote(agent, conflict)
			votes[vote]++
		}
	}

	// Find majority
	var winner string
	maxVotes := 0
	for option, count := range votes {
		if count > maxVotes {
			maxVotes = count
			winner = option
		}
	}

	confidence := float64(maxVotes) / float64(len(conflict.Agents))

	return &ConflictResolution{
		Strategy:   "voting",
		Decision:   map[string]interface{}{"winner": winner, "votes": votes},
		Confidence: confidence,
		ResolvedBy: "voting_strategy",
		ResolvedAt: time.Now(),
	}, nil
}

// GetType returns the strategy type
func (vs *VotingStrategy) GetType() string {
	return "voting"
}

// GetPriority returns the strategy priority
func (vs *VotingStrategy) GetPriority() int {
	return 1
}

// getAgentVote gets an agent's vote (simplified implementation)
func (vs *VotingStrategy) getAgentVote(agent ai.Agent, conflict *ConflictRecord) string {
	// Simplified voting logic based on agent name patterns
	agentName := strings.ToLower(agent.Name())

	switch conflict.Type {
	case "priority_conflict":
		if strings.Contains(agentName, "strategy") || strings.Contains(agentName, "strategic") {
			return "high_priority"
		}
		return "normal_priority"
	case "resource_conflict":
		if strings.Contains(agentName, "operator") || strings.Contains(agentName, "operations") {
			return "allocate_more"
		}
		return "optimize_current"
	default:
		return "option_a"
	}
}

// PriorityStrategy resolves conflicts based on agent priority
type PriorityStrategy struct {
	logger *logger.Logger
}

// Resolve implements ConflictResolutionStrategy
func (ps *PriorityStrategy) Resolve(ctx context.Context, conflict *ConflictRecord, agents map[string]ai.Agent) (*ConflictResolution, error) {
	// Define agent name pattern priorities
	priorities := map[string]int{
		"strategy": 5,
		"analyst":  4,
		"research": 3,
		"operator": 2,
		"creator":  1,
		"security": 4, // Security agents get high priority
	}

	var highestPriorityAgent ai.Agent
	highestPriority := -1

	for _, agentID := range conflict.Agents {
		if agent, exists := agents[agentID]; exists {
			agentName := strings.ToLower(agent.Name())
			agentIDLower := strings.ToLower(agentID)

			// Find the highest priority pattern match
			for pattern, priority := range priorities {
				if (strings.Contains(agentName, pattern) || strings.Contains(agentIDLower, pattern)) && priority > highestPriority {
					highestPriority = priority
					highestPriorityAgent = agent
				}
			}
		}
	}

	if highestPriorityAgent == nil {
		return nil, fmt.Errorf("no valid agent found for priority resolution")
	}

	// Get decision from highest priority agent
	decision := ps.getAgentDecision(highestPriorityAgent, conflict)

	return &ConflictResolution{
		Strategy:   "priority",
		Decision:   decision,
		Confidence: 0.8, // High confidence in priority-based decisions
		ResolvedBy: highestPriorityAgent.ID(),
		ResolvedAt: time.Now(),
	}, nil
}

// GetType returns the strategy type
func (ps *PriorityStrategy) GetType() string {
	return "priority"
}

// GetPriority returns the strategy priority
func (ps *PriorityStrategy) GetPriority() int {
	return 2
}

// getAgentDecision gets a decision from an agent
func (ps *PriorityStrategy) getAgentDecision(agent ai.Agent, conflict *ConflictRecord) map[string]interface{} {
	// Simplified decision logic
	return map[string]interface{}{
		"decision":   "priority_based_choice",
		"decided_by": agent.ID(),
		"agent_name": agent.Name(),
		"reasoning":  "Decision made based on agent priority hierarchy",
	}
}

// ConsensusStrategy resolves conflicts through consensus building
type ConsensusStrategy struct {
	threshold float64
	logger    *logger.Logger
}

// Resolve implements ConflictResolutionStrategy
func (cs *ConsensusStrategy) Resolve(ctx context.Context, conflict *ConflictRecord, agents map[string]ai.Agent) (*ConflictResolution, error) {
	// Collect proposals from all agents
	proposals := make(map[string]map[string]interface{})

	for _, agentID := range conflict.Agents {
		if agent, exists := agents[agentID]; exists {
			proposal := cs.getAgentProposal(agent, conflict)
			proposals[agentID] = proposal
		}
	}

	// Find consensus
	consensus, consensusScore := cs.findConsensus(proposals)

	if consensusScore < cs.threshold {
		return nil, fmt.Errorf("consensus threshold not met: %.2f < %.2f", consensusScore, cs.threshold)
	}

	return &ConflictResolution{
		Strategy:   "consensus",
		Decision:   consensus,
		Confidence: consensusScore,
		ResolvedBy: "consensus_strategy",
		ResolvedAt: time.Now(),
	}, nil
}

// GetType returns the strategy type
func (cs *ConsensusStrategy) GetType() string {
	return "consensus"
}

// GetPriority returns the strategy priority
func (cs *ConsensusStrategy) GetPriority() int {
	return 3
}

// getAgentProposal gets a proposal from an agent
func (cs *ConsensusStrategy) getAgentProposal(agent ai.Agent, conflict *ConflictRecord) map[string]interface{} {
	// Simplified proposal logic
	return map[string]interface{}{
		"agent_id":   agent.ID(),
		"proposal":   "consensus_proposal",
		"confidence": 0.8,
		"reasoning":  "Proposal for consensus building",
	}
}

// findConsensus finds consensus among proposals
func (cs *ConsensusStrategy) findConsensus(proposals map[string]map[string]interface{}) (map[string]interface{}, float64) {
	if len(proposals) == 0 {
		return nil, 0.0
	}

	// Simplified consensus finding - in practice would use more sophisticated algorithms
	consensusProposal := map[string]interface{}{
		"type":         "consensus_decision",
		"participants": len(proposals),
		"proposals":    proposals,
	}

	// Calculate consensus score (simplified)
	consensusScore := 0.8 // Default high consensus for demo

	return consensusProposal, consensusScore
}

// Consensus engine methods
func (ce *ConsensusEngine) reachConsensus(ctx context.Context, proposals map[string]ai.AgentOutput, collaboration *ActiveCollaboration) (map[string]interface{}, error) {
	if len(proposals) == 0 {
		return nil, fmt.Errorf("no proposals to reach consensus on")
	}

	switch ce.consensusAlgorithm {
	case "majority":
		return ce.majorityConsensus(proposals)
	case "weighted":
		return ce.weightedConsensus(proposals, collaboration)
	case "byzantine":
		return ce.byzantineConsensus(proposals)
	default:
		return ce.majorityConsensus(proposals)
	}
}

// majorityConsensus implements majority-based consensus
func (ce *ConsensusEngine) majorityConsensus(proposals map[string]ai.AgentOutput) (map[string]interface{}, error) {
	// Group similar results
	resultGroups := make(map[string][]string)

	for agentID, result := range proposals {
		// Simplified grouping by confidence level
		confidenceGroup := fmt.Sprintf("confidence_%.1f", result.Confidence)
		resultGroups[confidenceGroup] = append(resultGroups[confidenceGroup], agentID)
	}

	// Find majority group
	var majorityGroup string
	maxCount := 0
	for group, agents := range resultGroups {
		if len(agents) > maxCount {
			maxCount = len(agents)
			majorityGroup = group
		}
	}

	if maxCount < len(proposals)/2+1 {
		return nil, fmt.Errorf("no majority consensus reached")
	}

	// Create consensus result
	consensus := map[string]interface{}{
		"type":           "majority_consensus",
		"majority_group": majorityGroup,
		"supporters":     resultGroups[majorityGroup],
		"confidence":     float64(maxCount) / float64(len(proposals)),
	}

	return consensus, nil
}

// weightedConsensus implements weighted consensus based on agent performance
func (ce *ConsensusEngine) weightedConsensus(proposals map[string]ai.AgentOutput, collaboration *ActiveCollaboration) (map[string]interface{}, error) {
	totalWeight := 0.0
	weightedSum := 0.0
	weights := make(map[string]float64)

	// Calculate weights based on agent performance
	for agentID, result := range proposals {
		if agent, exists := collaboration.Participants[agentID]; exists {
			metrics := agent.GetMetrics()
			successRate := float64(metrics.SuccessfulRuns) / float64(metrics.TotalExecutions)
			if metrics.TotalExecutions == 0 {
				successRate = 0.5 // Default for new agents
			}
			weight := successRate * result.Confidence
			weights[agentID] = weight
			totalWeight += weight
			weightedSum += weight * result.Confidence
		}
	}

	if totalWeight == 0 {
		return nil, fmt.Errorf("no valid weights for consensus")
	}

	consensusConfidence := weightedSum / totalWeight

	consensus := map[string]interface{}{
		"type":                 "weighted_consensus",
		"consensus_confidence": consensusConfidence,
		"weights":              weights,
		"total_weight":         totalWeight,
	}

	return consensus, nil
}

// byzantineConsensus implements Byzantine fault-tolerant consensus
func (ce *ConsensusEngine) byzantineConsensus(proposals map[string]ai.AgentOutput) (map[string]interface{}, error) {
	// Simplified Byzantine consensus - in practice would implement PBFT or similar
	if len(proposals) < 4 {
		return nil, fmt.Errorf("Byzantine consensus requires at least 4 participants")
	}

	// Sort proposals by confidence
	type proposalEntry struct {
		agentID    string
		confidence float64
	}

	var sortedProposals []proposalEntry
	for agentID, result := range proposals {
		sortedProposals = append(sortedProposals, proposalEntry{
			agentID:    agentID,
			confidence: result.Confidence,
		})
	}

	sort.Slice(sortedProposals, func(i, j int) bool {
		return sortedProposals[i].confidence > sortedProposals[j].confidence
	})

	// Take top 2/3 of proposals (Byzantine fault tolerance)
	byzantineThreshold := (len(sortedProposals) * 2) / 3
	validProposals := sortedProposals[:byzantineThreshold]

	consensus := map[string]interface{}{
		"type":                "byzantine_consensus",
		"valid_proposals":     validProposals,
		"byzantine_threshold": byzantineThreshold,
		"fault_tolerance":     len(sortedProposals) - byzantineThreshold,
	}

	return consensus, nil
}
