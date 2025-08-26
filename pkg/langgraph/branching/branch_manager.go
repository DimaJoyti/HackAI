package branching

import (
	"context"
	"fmt"
	"sync"

	"github.com/dimajoyti/hackai/pkg/langgraph/parallel"
	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// BranchMerger interface for merging branch results
type BranchMerger interface {
	Merge(ctx context.Context, branches []*parallel.Branch) (*parallel.MergedResult, error)
}

// ConflictResolver interface for resolving state conflicts
type ConflictResolver interface {
	Resolve(ctx context.Context, conflicts []parallel.StateConflict) (llm.GraphState, error)
}

// BranchSynchronizer interface for synchronizing branch execution
type BranchSynchronizer interface {
	Synchronize(ctx context.Context, branches []*parallel.Branch) error
	WaitForCompletion(ctx context.Context, branchIDs []string) error
}

// DefaultBranchMerger implements basic branch merging
type DefaultBranchMerger struct {
	resolver ConflictResolver
	logger   *logger.Logger
}

// NewDefaultBranchMerger creates a new default branch merger
func NewDefaultBranchMerger() *DefaultBranchMerger {
	return &DefaultBranchMerger{
		resolver: NewDefaultConflictResolver(),
	}
}

// Merge merges multiple branch results
func (bm *DefaultBranchMerger) Merge(ctx context.Context, branches []*parallel.Branch) (*parallel.MergedResult, error) {
	if len(branches) == 0 {
		return &parallel.MergedResult{
			State:    llm.GraphState{},
			Metadata: make(map[string]interface{}),
		}, nil
	}

	// Collect completed branches
	completedBranches := make([]*parallel.Branch, 0)
	for _, branch := range branches {
		if branch.Status == parallel.BranchStatusCompleted && branch.Result != nil {
			completedBranches = append(completedBranches, branch)
		}
	}

	if len(completedBranches) == 0 {
		return nil, fmt.Errorf("no completed branches to merge")
	}

	// Detect conflicts
	conflicts := bm.detectConflicts(completedBranches)

	// Resolve conflicts if any
	var finalState llm.GraphState
	var err error

	if len(conflicts) > 0 {
		finalState, err = bm.resolver.Resolve(ctx, conflicts)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve conflicts: %w", err)
		}
	} else {
		// No conflicts, use the first branch's state
		finalState = completedBranches[0].Result.State
	}

	return &parallel.MergedResult{
		State:     finalState,
		Conflicts: conflicts,
		Resolution: parallel.ConflictResolution{
			Strategy: parallel.ResolutionStrategyPriority,
			Reason:   "Merged branch results",
		},
		Metadata: map[string]interface{}{
			"merged_branches": len(completedBranches),
			"total_branches":  len(branches),
			"conflicts_found": len(conflicts),
		},
	}, nil
}

// detectConflicts detects conflicts between branch states
func (bm *DefaultBranchMerger) detectConflicts(branches []*parallel.Branch) []parallel.StateConflict {
	conflicts := make([]parallel.StateConflict, 0)

	if len(branches) <= 1 {
		return conflicts
	}

	// Compare states between branches
	baseState := branches[0].Result.State
	for i := 1; i < len(branches); i++ {
		branchState := branches[i].Result.State

		// Check for conflicts in state data
		if baseState.Data != nil && branchState.Data != nil {
			for key, baseValue := range baseState.Data {
				if branchValue, exists := branchState.Data[key]; exists {
					if !isEqual(baseValue, branchValue) {
						conflict := parallel.StateConflict{
							Key:  key,
							Type: parallel.ConflictTypeValue,
							Values: []parallel.ConflictValue{
								{
									BranchID: branches[0].ID,
									Value:    baseValue,
									Priority: 1,
								},
								{
									BranchID: branches[i].ID,
									Value:    branchValue,
									Priority: 1,
								},
							},
							Severity: parallel.ConflictSeverityMedium,
						}
						conflicts = append(conflicts, conflict)
					}
				}
			}
		}
	}

	return conflicts
}

// isEqual checks if two values are equal (simplified implementation)
func isEqual(a, b interface{}) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// DefaultConflictResolver implements basic conflict resolution
type DefaultConflictResolver struct {
	logger *logger.Logger
}

// NewDefaultConflictResolver creates a new default conflict resolver
func NewDefaultConflictResolver() *DefaultConflictResolver {
	return &DefaultConflictResolver{}
}

// Resolve resolves conflicts between states
func (cr *DefaultConflictResolver) Resolve(ctx context.Context, conflicts []parallel.StateConflict) (llm.GraphState, error) {
	resolvedState := llm.GraphState{
		Data: make(map[string]interface{}),
	}

	for _, conflict := range conflicts {
		// Simple resolution strategy: use the value with highest priority
		var chosenValue interface{}
		maxPriority := -1

		for _, value := range conflict.Values {
			if value.Priority > maxPriority {
				maxPriority = value.Priority
				chosenValue = value.Value
			}
		}

		// If priorities are equal, use the first value
		if chosenValue == nil && len(conflict.Values) > 0 {
			chosenValue = conflict.Values[0].Value
		}

		resolvedState.Data[conflict.Key] = chosenValue
	}

	return resolvedState, nil
}

// DefaultBranchSynchronizer implements basic branch synchronization
type DefaultBranchSynchronizer struct {
	branches map[string]*parallel.Branch
	mutex    sync.RWMutex
	logger   *logger.Logger
}

// NewDefaultBranchSynchronizer creates a new default branch synchronizer
func NewDefaultBranchSynchronizer() *DefaultBranchSynchronizer {
	return &DefaultBranchSynchronizer{
		branches: make(map[string]*parallel.Branch),
	}
}

// Synchronize synchronizes branch execution
func (bs *DefaultBranchSynchronizer) Synchronize(ctx context.Context, branches []*parallel.Branch) error {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	// Update branch status
	for _, branch := range branches {
		bs.branches[branch.ID] = branch
	}

	return nil
}

// WaitForCompletion waits for specified branches to complete
func (bs *DefaultBranchSynchronizer) WaitForCompletion(ctx context.Context, branchIDs []string) error {
	// Simple implementation: check if all branches are completed
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			allCompleted := true
			bs.mutex.RLock()
			for _, branchID := range branchIDs {
				if branch, exists := bs.branches[branchID]; exists {
					if branch.Status != parallel.BranchStatusCompleted &&
						branch.Status != parallel.BranchStatusFailed &&
						branch.Status != parallel.BranchStatusCancelled {
						allCompleted = false
						break
					}
				} else {
					allCompleted = false
					break
				}
			}
			bs.mutex.RUnlock()

			if allCompleted {
				return nil
			}

			// Wait a bit before checking again
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				// Continue checking
			}
		}
	}
}

// PriorityBranchMerger implements priority-based branch merging
type PriorityBranchMerger struct {
	priorities map[string]int
	resolver   ConflictResolver
	logger     *logger.Logger
}

// NewPriorityBranchMerger creates a new priority-based branch merger
func NewPriorityBranchMerger(priorities map[string]int) *PriorityBranchMerger {
	return &PriorityBranchMerger{
		priorities: priorities,
		resolver:   NewDefaultConflictResolver(),
	}
}

// Merge merges branches based on priority
func (pbm *PriorityBranchMerger) Merge(ctx context.Context, branches []*parallel.Branch) (*parallel.MergedResult, error) {
	if len(branches) == 0 {
		return &parallel.MergedResult{
			State:    llm.GraphState{},
			Metadata: make(map[string]interface{}),
		}, nil
	}

	// Sort branches by priority
	sortedBranches := make([]*parallel.Branch, len(branches))
	copy(sortedBranches, branches)

	// Simple sorting by priority (in a real implementation, use proper sorting)
	for i := 0; i < len(sortedBranches)-1; i++ {
		for j := i + 1; j < len(sortedBranches); j++ {
			iPriority := pbm.getPriority(sortedBranches[i].ID)
			jPriority := pbm.getPriority(sortedBranches[j].ID)
			if jPriority > iPriority {
				sortedBranches[i], sortedBranches[j] = sortedBranches[j], sortedBranches[i]
			}
		}
	}

	// Use the highest priority completed branch
	for _, branch := range sortedBranches {
		if branch.Status == parallel.BranchStatusCompleted && branch.Result != nil {
			return &parallel.MergedResult{
				State:     branch.Result.State,
				Conflicts: []parallel.StateConflict{},
				Resolution: parallel.ConflictResolution{
					Strategy:    parallel.ResolutionStrategyPriority,
					ChosenValue: branch.Result.State,
					Reason:      fmt.Sprintf("Highest priority branch: %s", branch.ID),
				},
				Metadata: map[string]interface{}{
					"chosen_branch": branch.ID,
					"priority":      pbm.getPriority(branch.ID),
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("no completed branches found")
}

// getPriority gets the priority for a branch
func (pbm *PriorityBranchMerger) getPriority(branchID string) int {
	if priority, exists := pbm.priorities[branchID]; exists {
		return priority
	}
	return 0 // Default priority
}

// ConsensusBranchMerger implements consensus-based branch merging
type ConsensusBranchMerger struct {
	threshold float64
	resolver  ConflictResolver
	logger    *logger.Logger
}

// NewConsensusBranchMerger creates a new consensus-based branch merger
func NewConsensusBranchMerger(threshold float64) *ConsensusBranchMerger {
	return &ConsensusBranchMerger{
		threshold: threshold,
		resolver:  NewDefaultConflictResolver(),
	}
}

// Merge merges branches based on consensus
func (cbm *ConsensusBranchMerger) Merge(ctx context.Context, branches []*parallel.Branch) (*parallel.MergedResult, error) {
	if len(branches) == 0 {
		return &parallel.MergedResult{
			State:    llm.GraphState{},
			Metadata: make(map[string]interface{}),
		}, nil
	}

	completedBranches := make([]*parallel.Branch, 0)
	for _, branch := range branches {
		if branch.Status == parallel.BranchStatusCompleted && branch.Result != nil {
			completedBranches = append(completedBranches, branch)
		}
	}

	if len(completedBranches) == 0 {
		return nil, fmt.Errorf("no completed branches to merge")
	}

	// Find consensus values
	consensusState := cbm.findConsensus(completedBranches)

	return &parallel.MergedResult{
		State:     consensusState,
		Conflicts: []parallel.StateConflict{},
		Resolution: parallel.ConflictResolution{
			Strategy: parallel.ResolutionStrategyMajority,
			Reason:   "Consensus-based merge",
		},
		Metadata: map[string]interface{}{
			"consensus_threshold": cbm.threshold,
			"branches_considered": len(completedBranches),
		},
	}, nil
}

// findConsensus finds consensus values across branches
func (cbm *ConsensusBranchMerger) findConsensus(branches []*parallel.Branch) llm.GraphState {
	consensusState := llm.GraphState{
		Data: make(map[string]interface{}),
	}

	if len(branches) == 0 {
		return consensusState
	}

	// For simplicity, use the first branch's state
	// In a real implementation, this would analyze all branches for consensus
	if branches[0].Result != nil {
		consensusState = branches[0].Result.State
	}

	return consensusState
}
