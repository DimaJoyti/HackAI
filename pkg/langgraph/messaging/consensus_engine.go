package messaging

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var consensusTracer = otel.Tracer("hackai/langgraph/messaging/consensus")

// NewConsensusEngine creates a new consensus engine
func NewConsensusEngine(logger *logger.Logger) *ConsensusEngine {
	return &ConsensusEngine{
		proposals:       make(map[string]*ConsensusProposal),
		votes:           make(map[string]map[string]*Vote),
		consensusRules:  make(map[string]ConsensusRule),
		activeConsensus: make(map[string]*ActiveConsensus),
		logger:          logger,
	}
}

// InitiateConsensus initiates a new consensus process
func (ce *ConsensusEngine) InitiateConsensus(ctx context.Context, proposal *ConsensusProposal) (*ActiveConsensus, error) {
	ctx, span := consensusTracer.Start(ctx, "consensus_engine.initiate_consensus",
		trace.WithAttributes(
			attribute.String("proposal.id", proposal.ID),
			attribute.String("proposal.type", string(proposal.Type)),
		),
	)
	defer span.End()

	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	// Validate proposal
	if err := ce.validateProposal(proposal); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("proposal validation failed: %w", err)
	}

	// Create active consensus
	activeConsensus := &ActiveConsensus{
		Proposal:     proposal,
		Votes:        make(map[string]*Vote),
		Status:       ConsensusStatusActive,
		StartTime:    time.Now(),
		Participants: make(map[string]bool),
	}

	// Initialize participants
	for _, participantID := range proposal.Participants {
		activeConsensus.Participants[participantID] = false // Not voted yet
	}

	// Store consensus
	ce.proposals[proposal.ID] = proposal
	ce.votes[proposal.ID] = make(map[string]*Vote)
	ce.activeConsensus[proposal.ID] = activeConsensus

	// Start consensus timeout
	go ce.handleConsensusTimeout(ctx, proposal.ID, proposal.Deadline)

	ce.logger.Info("Consensus initiated",
		"proposal_id", proposal.ID,
		"type", proposal.Type,
		"participants", len(proposal.Participants))

	return activeConsensus, nil
}

// SubmitVote submits a vote for a consensus proposal
func (ce *ConsensusEngine) SubmitVote(ctx context.Context, proposalID, voterID string, decision VoteDecision, reasoning string) error {
	ctx, span := consensusTracer.Start(ctx, "consensus_engine.submit_vote",
		trace.WithAttributes(
			attribute.String("proposal.id", proposalID),
			attribute.String("voter.id", voterID),
			attribute.String("decision", string(decision)),
		),
	)
	defer span.End()

	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	// Check if consensus exists and is active
	activeConsensus, exists := ce.activeConsensus[proposalID]
	if !exists {
		err := fmt.Errorf("consensus not found: %s", proposalID)
		span.RecordError(err)
		return err
	}

	if activeConsensus.Status != ConsensusStatusActive {
		err := fmt.Errorf("consensus not active: %s", activeConsensus.Status)
		span.RecordError(err)
		return err
	}

	// Check if voter is a participant
	if _, isParticipant := activeConsensus.Participants[voterID]; !isParticipant {
		err := fmt.Errorf("voter not a participant: %s", voterID)
		span.RecordError(err)
		return err
	}

	// Check if already voted
	if _, hasVoted := ce.votes[proposalID][voterID]; hasVoted {
		err := fmt.Errorf("voter already voted: %s", voterID)
		span.RecordError(err)
		return err
	}

	// Create vote
	vote := &Vote{
		VoterID:   voterID,
		Decision:  decision,
		Reasoning: reasoning,
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	// Store vote
	ce.votes[proposalID][voterID] = vote
	activeConsensus.Votes[voterID] = vote
	activeConsensus.Participants[voterID] = true // Marked as voted

	ce.logger.Debug("Vote submitted",
		"proposal_id", proposalID,
		"voter_id", voterID,
		"decision", decision)

	// Check if consensus is reached
	if ce.isConsensusReached(activeConsensus) {
		if err := ce.finalizeConsensus(ctx, proposalID); err != nil {
			span.RecordError(err)
			return fmt.Errorf("failed to finalize consensus: %w", err)
		}
	}

	return nil
}

// GetConsensusStatus returns the status of a consensus
func (ce *ConsensusEngine) GetConsensusStatus(proposalID string) (*ActiveConsensus, error) {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()

	activeConsensus, exists := ce.activeConsensus[proposalID]
	if !exists {
		return nil, fmt.Errorf("consensus not found: %s", proposalID)
	}

	return activeConsensus, nil
}

// validateProposal validates a consensus proposal
func (ce *ConsensusEngine) validateProposal(proposal *ConsensusProposal) error {
	if proposal.ID == "" {
		return fmt.Errorf("proposal ID cannot be empty")
	}

	if proposal.ProposerID == "" {
		return fmt.Errorf("proposer ID cannot be empty")
	}

	if len(proposal.Participants) == 0 {
		return fmt.Errorf("participants cannot be empty")
	}

	if proposal.Deadline.Before(time.Now()) {
		return fmt.Errorf("deadline cannot be in the past")
	}

	return nil
}

// isConsensusReached checks if consensus is reached based on the consensus type
func (ce *ConsensusEngine) isConsensusReached(activeConsensus *ActiveConsensus) bool {
	proposal := activeConsensus.Proposal
	votes := activeConsensus.Votes

	// Get consensus rule for this type
	rule, exists := ce.consensusRules[string(proposal.Type)]
	if !exists {
		// Use default rules
		rule = ce.getDefaultConsensusRule(proposal.Type)
	}

	// Count votes
	voteCount := make(map[VoteDecision]int)
	totalVotes := 0
	totalWeight := 0.0

	for _, vote := range votes {
		voteCount[vote.Decision]++
		totalVotes++

		// Calculate weight if weight function is provided
		if rule.WeightFunction != nil {
			weight := rule.WeightFunction(vote.VoterID, proposal.Metadata)
			totalWeight += weight
		} else {
			totalWeight += 1.0 // Equal weight
		}
	}

	// Check if minimum participation is met
	participationRate := float64(totalVotes) / float64(len(proposal.Participants))
	if participationRate < 0.5 { // Minimum 50% participation
		return false
	}

	// Apply consensus rules
	switch proposal.Type {
	case ConsensusTypeSimpleMajority:
		return voteCount[VoteApprove] > voteCount[VoteReject]

	case ConsensusTypeUnanimous:
		return voteCount[VoteApprove] == totalVotes && voteCount[VoteReject] == 0

	case ConsensusTypeWeightedMajority:
		approveWeight := 0.0
		for voterID, vote := range votes {
			if vote.Decision == VoteApprove {
				if rule.WeightFunction != nil {
					approveWeight += rule.WeightFunction(voterID, proposal.Metadata)
				} else {
					approveWeight += 1.0
				}
			}
		}
		return approveWeight/totalWeight >= rule.RequiredPercentage

	case ConsensusTypeQuorum:
		return participationRate >= rule.RequiredPercentage &&
			voteCount[VoteApprove] > voteCount[VoteReject]

	default:
		return false
	}
}

// getDefaultConsensusRule returns default consensus rules
func (ce *ConsensusEngine) getDefaultConsensusRule(consensusType ConsensusType) ConsensusRule {
	switch consensusType {
	case ConsensusTypeSimpleMajority:
		return ConsensusRule{
			Type:                consensusType,
			MinimumParticipants: 1,
			RequiredPercentage:  0.5,
			Timeout:             60 * time.Second,
		}
	case ConsensusTypeUnanimous:
		return ConsensusRule{
			Type:                consensusType,
			MinimumParticipants: 1,
			RequiredPercentage:  1.0,
			Timeout:             120 * time.Second,
		}
	case ConsensusTypeWeightedMajority:
		return ConsensusRule{
			Type:                consensusType,
			MinimumParticipants: 1,
			RequiredPercentage:  0.6,
			Timeout:             90 * time.Second,
		}
	case ConsensusTypeQuorum:
		return ConsensusRule{
			Type:                consensusType,
			MinimumParticipants: 3,
			RequiredPercentage:  0.67,
			Timeout:             60 * time.Second,
		}
	default:
		return ConsensusRule{
			Type:                ConsensusTypeSimpleMajority,
			MinimumParticipants: 1,
			RequiredPercentage:  0.5,
			Timeout:             60 * time.Second,
		}
	}
}

// finalizeConsensus finalizes a consensus process
func (ce *ConsensusEngine) finalizeConsensus(ctx context.Context, proposalID string) error {
	activeConsensus := ce.activeConsensus[proposalID]
	
	// Calculate result
	result := ce.calculateConsensusResult(activeConsensus)
	
	// Update consensus
	activeConsensus.Status = ConsensusStatusCompleted
	activeConsensus.Result = result
	now := time.Now()
	activeConsensus.EndTime = &now

	ce.logger.Info("Consensus finalized",
		"proposal_id", proposalID,
		"decision", result.Decision,
		"participation", result.Participation)

	return nil
}

// calculateConsensusResult calculates the final consensus result
func (ce *ConsensusEngine) calculateConsensusResult(activeConsensus *ActiveConsensus) *ConsensusResult {
	votes := activeConsensus.Votes
	voteCount := make(map[VoteDecision]int)
	
	for _, vote := range votes {
		voteCount[vote.Decision]++
	}

	// Determine decision
	var decision VoteDecision
	if voteCount[VoteApprove] > voteCount[VoteReject] {
		decision = VoteApprove
	} else if voteCount[VoteReject] > voteCount[VoteApprove] {
		decision = VoteReject
	} else {
		decision = VoteAbstain
	}

	// Calculate participation
	participation := float64(len(votes)) / float64(len(activeConsensus.Proposal.Participants))

	// Calculate confidence (simple implementation)
	confidence := 0.5
	if len(votes) > 0 {
		maxVotes := voteCount[VoteApprove]
		if voteCount[VoteReject] > maxVotes {
			maxVotes = voteCount[VoteReject]
		}
		confidence = float64(maxVotes) / float64(len(votes))
	}

	return &ConsensusResult{
		Decision:      decision,
		VoteCount:     voteCount,
		Participation: participation,
		Confidence:    confidence,
		Metadata:      make(map[string]interface{}),
	}
}

// handleConsensusTimeout handles consensus timeout
func (ce *ConsensusEngine) handleConsensusTimeout(ctx context.Context, proposalID string, deadline time.Time) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	select {
	case <-timer.C:
		ce.mutex.Lock()
		defer ce.mutex.Unlock()

		if activeConsensus, exists := ce.activeConsensus[proposalID]; exists {
			if activeConsensus.Status == ConsensusStatusActive {
				activeConsensus.Status = ConsensusStatusTimeout
				now := time.Now()
				activeConsensus.EndTime = &now

				ce.logger.Warn("Consensus timeout",
					"proposal_id", proposalID,
					"votes_received", len(activeConsensus.Votes),
					"total_participants", len(activeConsensus.Participants))
			}
		}

	case <-ctx.Done():
		return
	}
}
