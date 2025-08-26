package orchestration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/langgraph/agents/multiagent"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// CoordinationEngine manages agent coordination patterns
type CoordinationEngine struct {
	coordinators map[CoordinationType]Coordinator
	config       *OrchestratorConfig
	logger       *logger.Logger
	mutex        sync.RWMutex
}

// Coordinator interface for different coordination patterns
type Coordinator interface {
	Initialize(spec *CoordinationSpec) error
	ExecutePhase(ctx context.Context, phase *TaskPhase, agents map[string]multiagent.Agent) (*PhaseResult, error)
	GetStatistics() *CoordinationStatistics
}

// CoordinationStatistics holds statistics for coordination
type CoordinationStatistics struct {
	PhasesExecuted    int64         `json:"phases_executed"`
	SuccessfulPhases  int64         `json:"successful_phases"`
	FailedPhases      int64         `json:"failed_phases"`
	AverageLatency    time.Duration `json:"average_latency"`
	SyncPointsHit     int64         `json:"sync_points_hit"`
	CoordinationEvents int64        `json:"coordination_events"`
}

// NewCoordinationEngine creates a new coordination engine
func NewCoordinationEngine(config *OrchestratorConfig, logger *logger.Logger) *CoordinationEngine {
	engine := &CoordinationEngine{
		coordinators: make(map[CoordinationType]Coordinator),
		config:       config,
		logger:       logger,
	}

	// Initialize coordinators
	engine.initializeCoordinators()

	return engine
}

// ExecuteCoordinatedPhase executes a phase with coordination
func (ce *CoordinationEngine) ExecuteCoordinatedPhase(ctx context.Context, phase *TaskPhase, agents map[string]multiagent.Agent) (*PhaseResult, error) {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()

	if phase.Coordination == nil {
		return nil, fmt.Errorf("no coordination specification provided")
	}

	coordinator, exists := ce.coordinators[phase.Coordination.Type]
	if !exists {
		return nil, fmt.Errorf("coordinator not found for type %s", phase.Coordination.Type)
	}

	ce.logger.Info("Executing coordinated phase",
		"phase_id", phase.ID,
		"coordination_type", phase.Coordination.Type,
		"pattern", phase.Coordination.Pattern)

	return coordinator.ExecutePhase(ctx, phase, agents)
}

// Helper methods

func (ce *CoordinationEngine) initializeCoordinators() {
	// Initialize different coordination types
	ce.coordinators[CoordinationTypeLoose] = NewLooseCoordinator(ce.config, ce.logger)
	ce.coordinators[CoordinationTypeTight] = NewTightCoordinator(ce.config, ce.logger)
	ce.coordinators[CoordinationTypeHierarchical] = NewHierarchicalCoordinator(ce.config, ce.logger)
	ce.coordinators[CoordinationTypePeerToPeer] = NewPeerToPeerCoordinator(ce.config, ce.logger)
}

// LooseCoordinator implements loose coordination
type LooseCoordinator struct {
	config *OrchestratorConfig
	logger *logger.Logger
	stats  *CoordinationStatistics
}

func NewLooseCoordinator(config *OrchestratorConfig, logger *logger.Logger) *LooseCoordinator {
	return &LooseCoordinator{
		config: config,
		logger: logger,
		stats:  &CoordinationStatistics{},
	}
}

func (lc *LooseCoordinator) Initialize(spec *CoordinationSpec) error {
	lc.logger.Debug("Initializing loose coordinator", "spec", spec)
	return nil
}

func (lc *LooseCoordinator) ExecutePhase(ctx context.Context, phase *TaskPhase, agents map[string]multiagent.Agent) (*PhaseResult, error) {
	startTime := time.Now()
	lc.stats.PhasesExecuted++

	result := &PhaseResult{
		PhaseID:       phase.ID,
		Success:       true,
		ActionResults: make(map[string]*ActionResult),
		StartTime:     startTime,
		Metadata:      make(map[string]interface{}),
	}

	// Execute actions with minimal coordination
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var errors []error

	for _, action := range phase.Actions {
		wg.Add(1)
		go func(a *PhaseAction) {
			defer wg.Done()

			agent, exists := agents[a.AgentID]
			if !exists {
				mutex.Lock()
				errors = append(errors, fmt.Errorf("agent %s not found", a.AgentID))
				mutex.Unlock()
				return
			}

			actionResult, err := lc.executeAction(ctx, a, agent)
			
			mutex.Lock()
			if err != nil {
				errors = append(errors, err)
			} else {
				result.ActionResults[a.ID] = actionResult
			}
			mutex.Unlock()
		}(action)
	}

	wg.Wait()

	if len(errors) > 0 {
		lc.stats.FailedPhases++
		result.Success = false
		result.Error = fmt.Sprintf("action execution failed: %v", errors)
		return result, fmt.Errorf("phase execution failed: %v", errors)
	}

	lc.stats.SuccessfulPhases++
	result.Duration = time.Since(startTime)
	lc.stats.AverageLatency = (lc.stats.AverageLatency + result.Duration) / 2

	return result, nil
}

func (lc *LooseCoordinator) executeAction(ctx context.Context, action *PhaseAction, agent multiagent.Agent) (*ActionResult, error) {
	startTime := time.Now()

	agentInput := multiagent.AgentInput{
		Task: multiagent.CollaborativeTask{
			ID:          action.ID,
			Name:        action.Name,
			Description: fmt.Sprintf("Action: %s", action.Name),
		},
		Context: action.Input,
	}

	output, err := agent.Execute(ctx, agentInput)
	if err != nil {
		return nil, err
	}

	return &ActionResult{
		ActionID:  action.ID,
		Success:   true,
		Result:    output.Result,
		Duration:  time.Since(startTime),
		Metadata:  make(map[string]interface{}),
	}, nil
}

func (lc *LooseCoordinator) GetStatistics() *CoordinationStatistics {
	return lc.stats
}

// TightCoordinator implements tight coordination
type TightCoordinator struct {
	config *OrchestratorConfig
	logger *logger.Logger
	stats  *CoordinationStatistics
}

func NewTightCoordinator(config *OrchestratorConfig, logger *logger.Logger) *TightCoordinator {
	return &TightCoordinator{
		config: config,
		logger: logger,
		stats:  &CoordinationStatistics{},
	}
}

func (tc *TightCoordinator) Initialize(spec *CoordinationSpec) error {
	tc.logger.Debug("Initializing tight coordinator", "spec", spec)
	return nil
}

func (tc *TightCoordinator) ExecutePhase(ctx context.Context, phase *TaskPhase, agents map[string]multiagent.Agent) (*PhaseResult, error) {
	startTime := time.Now()
	tc.stats.PhasesExecuted++

	result := &PhaseResult{
		PhaseID:       phase.ID,
		Success:       true,
		ActionResults: make(map[string]*ActionResult),
		StartTime:     startTime,
		Metadata:      make(map[string]interface{}),
	}

	// Execute actions with tight coordination (sequential with sync points)
	for i, action := range phase.Actions {
		// Check sync points
		if tc.isSyncPoint(i, phase.Coordination.SyncPoints) {
			tc.logger.Debug("Hitting sync point", "phase_id", phase.ID, "action_index", i)
			tc.stats.SyncPointsHit++
			
			// Wait for all previous actions to complete
			if err := tc.waitForSyncPoint(ctx, result); err != nil {
				tc.stats.FailedPhases++
				return result, err
			}
		}

		agent, exists := agents[action.AgentID]
		if !exists {
			tc.stats.FailedPhases++
			return result, fmt.Errorf("agent %s not found", action.AgentID)
		}

		actionResult, err := tc.executeAction(ctx, action, agent)
		if err != nil {
			tc.stats.FailedPhases++
			result.Success = false
			result.Error = err.Error()
			return result, err
		}

		result.ActionResults[action.ID] = actionResult
	}

	tc.stats.SuccessfulPhases++
	result.Duration = time.Since(startTime)
	tc.stats.AverageLatency = (tc.stats.AverageLatency + result.Duration) / 2

	return result, nil
}

func (tc *TightCoordinator) executeAction(ctx context.Context, action *PhaseAction, agent multiagent.Agent) (*ActionResult, error) {
	startTime := time.Now()

	agentInput := multiagent.AgentInput{
		Task: multiagent.CollaborativeTask{
			ID:          action.ID,
			Name:        action.Name,
			Description: fmt.Sprintf("Action: %s", action.Name),
		},
		Context: action.Input,
	}

	output, err := agent.Execute(ctx, agentInput)
	if err != nil {
		return nil, err
	}

	return &ActionResult{
		ActionID:  action.ID,
		Success:   true,
		Result:    output.Result,
		Duration:  time.Since(startTime),
		Metadata:  make(map[string]interface{}),
	}, nil
}

func (tc *TightCoordinator) isSyncPoint(actionIndex int, syncPoints []string) bool {
	// Simple implementation - check if action index is in sync points
	for _, syncPoint := range syncPoints {
		if syncPoint == fmt.Sprintf("action_%d", actionIndex) {
			return true
		}
	}
	return false
}

func (tc *TightCoordinator) waitForSyncPoint(ctx context.Context, result *PhaseResult) error {
	// Wait for all actions to complete (simplified implementation)
	timeout := time.After(tc.config.CoordinationTimeout)
	
	select {
	case <-timeout:
		return fmt.Errorf("sync point timeout")
	default:
		// In a real implementation, this would wait for specific conditions
		return nil
	}
}

func (tc *TightCoordinator) GetStatistics() *CoordinationStatistics {
	return tc.stats
}

// HierarchicalCoordinator implements hierarchical coordination
type HierarchicalCoordinator struct {
	config *OrchestratorConfig
	logger *logger.Logger
	stats  *CoordinationStatistics
}

func NewHierarchicalCoordinator(config *OrchestratorConfig, logger *logger.Logger) *HierarchicalCoordinator {
	return &HierarchicalCoordinator{
		config: config,
		logger: logger,
		stats:  &CoordinationStatistics{},
	}
}

func (hc *HierarchicalCoordinator) Initialize(spec *CoordinationSpec) error {
	hc.logger.Debug("Initializing hierarchical coordinator", "spec", spec)
	return nil
}

func (hc *HierarchicalCoordinator) ExecutePhase(ctx context.Context, phase *TaskPhase, agents map[string]multiagent.Agent) (*PhaseResult, error) {
	startTime := time.Now()
	hc.stats.PhasesExecuted++

	result := &PhaseResult{
		PhaseID:       phase.ID,
		Success:       true,
		ActionResults: make(map[string]*ActionResult),
		StartTime:     startTime,
		Metadata:      make(map[string]interface{}),
	}

	// Execute with hierarchical coordination (master-slave pattern)
	masterAgent := hc.selectMasterAgent(agents)
	if masterAgent == nil {
		hc.stats.FailedPhases++
		return result, fmt.Errorf("no master agent available")
	}

	// Master coordinates the execution
	for _, action := range phase.Actions {
		agent, exists := agents[action.AgentID]
		if !exists {
			hc.stats.FailedPhases++
			return result, fmt.Errorf("agent %s not found", action.AgentID)
		}

		// Master agent coordinates the action
		actionResult, err := hc.coordinateAction(ctx, action, agent, masterAgent)
		if err != nil {
			hc.stats.FailedPhases++
			result.Success = false
			result.Error = err.Error()
			return result, err
		}

		result.ActionResults[action.ID] = actionResult
	}

	hc.stats.SuccessfulPhases++
	result.Duration = time.Since(startTime)
	hc.stats.AverageLatency = (hc.stats.AverageLatency + result.Duration) / 2

	return result, nil
}

func (hc *HierarchicalCoordinator) selectMasterAgent(agents map[string]multiagent.Agent) multiagent.Agent {
	// Simple implementation - select first agent as master
	for _, agent := range agents {
		return agent
	}
	return nil
}

func (hc *HierarchicalCoordinator) coordinateAction(ctx context.Context, action *PhaseAction, agent, master multiagent.Agent) (*ActionResult, error) {
	startTime := time.Now()

	// Master coordinates the action execution
	agentInput := multiagent.AgentInput{
		Task: multiagent.CollaborativeTask{
			ID:          action.ID,
			Name:        action.Name,
			Description: fmt.Sprintf("Coordinated Action: %s", action.Name),
		},
		Context: action.Input,
	}

	output, err := agent.Execute(ctx, agentInput)
	if err != nil {
		return nil, err
	}

	return &ActionResult{
		ActionID:  action.ID,
		Success:   true,
		Result:    output.Result,
		Duration:  time.Since(startTime),
		Metadata:  map[string]interface{}{"coordinated_by": master.ID()},
	}, nil
}

func (hc *HierarchicalCoordinator) GetStatistics() *CoordinationStatistics {
	return hc.stats
}

// PeerToPeerCoordinator implements peer-to-peer coordination
type PeerToPeerCoordinator struct {
	config *OrchestratorConfig
	logger *logger.Logger
	stats  *CoordinationStatistics
}

func NewPeerToPeerCoordinator(config *OrchestratorConfig, logger *logger.Logger) *PeerToPeerCoordinator {
	return &PeerToPeerCoordinator{
		config: config,
		logger: logger,
		stats:  &CoordinationStatistics{},
	}
}

func (p2p *PeerToPeerCoordinator) Initialize(spec *CoordinationSpec) error {
	p2p.logger.Debug("Initializing peer-to-peer coordinator", "spec", spec)
	return nil
}

func (p2p *PeerToPeerCoordinator) ExecutePhase(ctx context.Context, phase *TaskPhase, agents map[string]multiagent.Agent) (*PhaseResult, error) {
	startTime := time.Now()
	p2p.stats.PhasesExecuted++

	result := &PhaseResult{
		PhaseID:       phase.ID,
		Success:       true,
		ActionResults: make(map[string]*ActionResult),
		StartTime:     startTime,
		Metadata:      make(map[string]interface{}),
	}

	// Execute with peer-to-peer coordination
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var errors []error

	// Create coordination channels between agents
	coordinationChannels := make(map[string]chan interface{})
	for agentID := range agents {
		coordinationChannels[agentID] = make(chan interface{}, 10)
	}

	for _, action := range phase.Actions {
		wg.Add(1)
		go func(a *PhaseAction) {
			defer wg.Done()

			agent, exists := agents[a.AgentID]
			if !exists {
				mutex.Lock()
				errors = append(errors, fmt.Errorf("agent %s not found", a.AgentID))
				mutex.Unlock()
				return
			}

			actionResult, err := p2p.executeCoordinatedAction(ctx, a, agent, coordinationChannels)
			
			mutex.Lock()
			if err != nil {
				errors = append(errors, err)
			} else {
				result.ActionResults[a.ID] = actionResult
			}
			mutex.Unlock()
		}(action)
	}

	wg.Wait()

	// Close coordination channels
	for _, ch := range coordinationChannels {
		close(ch)
	}

	if len(errors) > 0 {
		p2p.stats.FailedPhases++
		result.Success = false
		result.Error = fmt.Sprintf("action execution failed: %v", errors)
		return result, fmt.Errorf("phase execution failed: %v", errors)
	}

	p2p.stats.SuccessfulPhases++
	result.Duration = time.Since(startTime)
	p2p.stats.AverageLatency = (p2p.stats.AverageLatency + result.Duration) / 2

	return result, nil
}

func (p2p *PeerToPeerCoordinator) executeCoordinatedAction(ctx context.Context, action *PhaseAction, agent multiagent.Agent, channels map[string]chan interface{}) (*ActionResult, error) {
	startTime := time.Now()

	// Coordinate with peer agents through channels
	agentChannel := channels[agent.ID()]
	
	// Send coordination message
	select {
	case agentChannel <- map[string]interface{}{"action": action.ID, "status": "starting"}:
	default:
		// Channel full, continue anyway
	}

	agentInput := multiagent.AgentInput{
		Task: multiagent.CollaborativeTask{
			ID:          action.ID,
			Name:        action.Name,
			Description: fmt.Sprintf("P2P Action: %s", action.Name),
		},
		Context: action.Input,
	}

	output, err := agent.Execute(ctx, agentInput)
	if err != nil {
		return nil, err
	}

	// Send completion message
	select {
	case agentChannel <- map[string]interface{}{"action": action.ID, "status": "completed"}:
	default:
		// Channel full, continue anyway
	}

	return &ActionResult{
		ActionID:  action.ID,
		Success:   true,
		Result:    output.Result,
		Duration:  time.Since(startTime),
		Metadata:  map[string]interface{}{"coordination": "peer_to_peer"},
	}, nil
}

func (p2p *PeerToPeerCoordinator) GetStatistics() *CoordinationStatistics {
	return p2p.stats
}
