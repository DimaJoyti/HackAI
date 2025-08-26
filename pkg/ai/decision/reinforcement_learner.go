package decision

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// ReinforcementLearner implements Q-learning for decision optimization
type ReinforcementLearner struct {
	qTable          map[string]map[string]float64 // state -> action -> Q-value
	learningRate    float64
	explorationRate float64
	discountFactor  float64
	stateEncoder    *StateEncoder
	actionEncoder   *ActionEncoder
	episodeHistory  []*Episode
	logger          *logger.Logger
	mutex           sync.RWMutex
}

// StateEncoder encodes decision context into states
type StateEncoder struct {
	stateSpace map[string]int
	logger     *logger.Logger
}

// ActionEncoder encodes decision options into actions
type ActionEncoder struct {
	actionSpace map[string]int
	logger      *logger.Logger
}

// Episode represents a learning episode
type Episode struct {
	ID        string                 `json:"id"`
	State     string                 `json:"state"`
	Action    string                 `json:"action"`
	Reward    float64                `json:"reward"`
	NextState string                 `json:"next_state"`
	Done      bool                   `json:"done"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// LearningStats represents learning statistics
type LearningStats struct {
	TotalEpisodes     int64   `json:"total_episodes"`
	AverageReward     float64 `json:"average_reward"`
	ExplorationRate   float64 `json:"exploration_rate"`
	LearningRate      float64 `json:"learning_rate"`
	QTableSize        int     `json:"q_table_size"`
	LastUpdated       time.Time `json:"last_updated"`
}

// NewReinforcementLearner creates a new reinforcement learner
func NewReinforcementLearner(learningRate, explorationRate float64, logger *logger.Logger) *ReinforcementLearner {
	return &ReinforcementLearner{
		qTable:          make(map[string]map[string]float64),
		learningRate:    learningRate,
		explorationRate: explorationRate,
		discountFactor:  0.9,
		stateEncoder:    NewStateEncoder(logger),
		actionEncoder:   NewActionEncoder(logger),
		episodeHistory:  make([]*Episode, 0),
		logger:          logger,
	}
}

// NewStateEncoder creates a new state encoder
func NewStateEncoder(logger *logger.Logger) *StateEncoder {
	return &StateEncoder{
		stateSpace: make(map[string]int),
		logger:     logger,
	}
}

// NewActionEncoder creates a new action encoder
func NewActionEncoder(logger *logger.Logger) *ActionEncoder {
	return &ActionEncoder{
		actionSpace: make(map[string]int),
		logger:      logger,
	}
}

// EncodeState encodes a decision context into a state string
func (se *StateEncoder) EncodeState(context *DecisionContext) string {
	if context == nil {
		return "default_state"
	}

	// Create a simplified state representation
	urgencyBucket := int(context.Urgency * 10) // 0-10
	complexityBucket := int(context.Complexity * 10) // 0-10
	
	// Encode resource availability
	resourceLevel := "low"
	if len(context.Resources) > 0 {
		totalResources := 0.0
		for _, amount := range context.Resources {
			totalResources += amount
		}
		avgResource := totalResources / float64(len(context.Resources))
		if avgResource > 0.7 {
			resourceLevel = "high"
		} else if avgResource > 0.3 {
			resourceLevel = "medium"
		}
	}

	state := fmt.Sprintf("u%d_c%d_r%s", urgencyBucket, complexityBucket, resourceLevel)
	
	// Register state if new
	if _, exists := se.stateSpace[state]; !exists {
		se.stateSpace[state] = len(se.stateSpace)
	}

	return state
}

// EncodeAction encodes a decision option into an action string
func (ae *ActionEncoder) EncodeAction(option *DecisionOption) string {
	if option == nil {
		return "default_action"
	}

	// Create a simplified action representation
	costBucket := "low"
	if option.Cost > 0.7 {
		costBucket = "high"
	} else if option.Cost > 0.3 {
		costBucket = "medium"
	}

	riskBucket := "low"
	if option.Risk > 0.7 {
		riskBucket = "high"
	} else if option.Risk > 0.3 {
		riskBucket = "medium"
	}

	action := fmt.Sprintf("c%s_r%s", costBucket, riskBucket)
	
	// Register action if new
	if _, exists := ae.actionSpace[action]; !exists {
		ae.actionSpace[action] = len(ae.actionSpace)
	}

	return action
}

// SelectAction selects an action using epsilon-greedy policy
func (rl *ReinforcementLearner) SelectAction(ctx context.Context, state string, availableActions []string) string {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	// Epsilon-greedy action selection
	if rand.Float64() < rl.explorationRate {
		// Explore: select random action
		if len(availableActions) > 0 {
			return availableActions[rand.Intn(len(availableActions))]
		}
		return "default_action"
	}

	// Exploit: select action with highest Q-value
	bestAction := ""
	bestQValue := math.Inf(-1)

	stateActions, exists := rl.qTable[state]
	if !exists {
		// Initialize state if not exists
		rl.qTable[state] = make(map[string]float64)
		stateActions = rl.qTable[state]
	}

	for _, action := range availableActions {
		qValue, exists := stateActions[action]
		if !exists {
			qValue = 0.0 // Initialize Q-value
			stateActions[action] = qValue
		}

		if qValue > bestQValue {
			bestQValue = qValue
			bestAction = action
		}
	}

	if bestAction == "" && len(availableActions) > 0 {
		bestAction = availableActions[0]
	}

	return bestAction
}

// UpdateFromOutcome updates Q-values based on decision outcome
func (rl *ReinforcementLearner) UpdateFromOutcome(ctx context.Context, decisionID string, outcome *DecisionOutcome) error {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	// Find the corresponding episode
	var episode *Episode
	for _, ep := range rl.episodeHistory {
		if ep.Metadata["decision_id"] == decisionID {
			episode = ep
			break
		}
	}

	if episode == nil {
		return fmt.Errorf("episode not found for decision: %s", decisionID)
	}

	// Calculate reward based on outcome
	reward := rl.calculateReward(outcome)
	episode.Reward = reward
	episode.Done = true

	// Update Q-value using Q-learning formula
	// Q(s,a) = Q(s,a) + α[r + γ*max(Q(s',a')) - Q(s,a)]
	currentQ := rl.getQValue(episode.State, episode.Action)
	
	// For simplicity, assume next state is terminal (no future rewards)
	maxNextQ := 0.0
	
	newQ := currentQ + rl.learningRate*(reward + rl.discountFactor*maxNextQ - currentQ)
	rl.setQValue(episode.State, episode.Action, newQ)

	rl.logger.Debug("Q-value updated",
		"state", episode.State,
		"action", episode.Action,
		"reward", reward,
		"old_q", currentQ,
		"new_q", newQ)

	// Decay exploration rate
	rl.explorationRate *= 0.995
	if rl.explorationRate < 0.01 {
		rl.explorationRate = 0.01
	}

	return nil
}

// calculateReward calculates reward based on decision outcome
func (rl *ReinforcementLearner) calculateReward(outcome *DecisionOutcome) float64 {
	reward := 0.0

	// Base reward from actual value
	reward += outcome.ActualValue * 0.5

	// Success bonus
	if outcome.Success {
		reward += 1.0
	} else {
		reward -= 0.5
	}

	// Time efficiency bonus (faster completion = higher reward)
	if outcome.CompletionTime > 0 {
		// Normalize completion time (assuming 1 hour is baseline)
		timeEfficiency := 1.0 - (outcome.CompletionTime.Hours() / 1.0)
		if timeEfficiency > 0 {
			reward += timeEfficiency * 0.3
		}
	}

	// Resource efficiency bonus
	if len(outcome.ResourceUsage) > 0 {
		totalUsage := 0.0
		for _, usage := range outcome.ResourceUsage {
			totalUsage += usage
		}
		avgUsage := totalUsage / float64(len(outcome.ResourceUsage))
		resourceEfficiency := 1.0 - avgUsage
		reward += resourceEfficiency * 0.2
	}

	return reward
}

// getQValue gets Q-value for state-action pair
func (rl *ReinforcementLearner) getQValue(state, action string) float64 {
	if stateActions, exists := rl.qTable[state]; exists {
		if qValue, exists := stateActions[action]; exists {
			return qValue
		}
	}
	return 0.0 // Default Q-value
}

// setQValue sets Q-value for state-action pair
func (rl *ReinforcementLearner) setQValue(state, action string, qValue float64) {
	if _, exists := rl.qTable[state]; !exists {
		rl.qTable[state] = make(map[string]float64)
	}
	rl.qTable[state][action] = qValue
}

// RecordEpisode records a new learning episode
func (rl *ReinforcementLearner) RecordEpisode(state, action string, metadata map[string]interface{}) *Episode {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	episode := &Episode{
		ID:        uuid.New().String(),
		State:     state,
		Action:    action,
		Reward:    0.0, // Will be updated when outcome is received
		NextState: "", // Will be updated if there's a next state
		Done:      false,
		Metadata:  metadata,
		Timestamp: time.Now(),
	}

	rl.episodeHistory = append(rl.episodeHistory, episode)

	// Limit episode history size
	if len(rl.episodeHistory) > 10000 {
		rl.episodeHistory = rl.episodeHistory[1000:] // Keep last 9000 episodes
	}

	return episode
}

// GetLearningStats returns learning statistics
func (rl *ReinforcementLearner) GetLearningStats() *LearningStats {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	totalReward := 0.0
	completedEpisodes := 0

	for _, episode := range rl.episodeHistory {
		if episode.Done {
			totalReward += episode.Reward
			completedEpisodes++
		}
	}

	averageReward := 0.0
	if completedEpisodes > 0 {
		averageReward = totalReward / float64(completedEpisodes)
	}

	return &LearningStats{
		TotalEpisodes:   int64(len(rl.episodeHistory)),
		AverageReward:   averageReward,
		ExplorationRate: rl.explorationRate,
		LearningRate:    rl.learningRate,
		QTableSize:      len(rl.qTable),
		LastUpdated:     time.Now(),
	}
}

// GetQTable returns a copy of the Q-table
func (rl *ReinforcementLearner) GetQTable() map[string]map[string]float64 {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	qTableCopy := make(map[string]map[string]float64)
	for state, actions := range rl.qTable {
		qTableCopy[state] = make(map[string]float64)
		for action, qValue := range actions {
			qTableCopy[state][action] = qValue
		}
	}

	return qTableCopy
}

// SaveQTable saves Q-table to storage (simplified implementation)
func (rl *ReinforcementLearner) SaveQTable(filepath string) error {
	// In a real implementation, this would serialize and save the Q-table
	rl.logger.Info("Q-table save requested", "filepath", filepath)
	return nil
}

// LoadQTable loads Q-table from storage (simplified implementation)
func (rl *ReinforcementLearner) LoadQTable(filepath string) error {
	// In a real implementation, this would load and deserialize the Q-table
	rl.logger.Info("Q-table load requested", "filepath", filepath)
	return nil
}

// ResetLearning resets the learning state
func (rl *ReinforcementLearner) ResetLearning() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.qTable = make(map[string]map[string]float64)
	rl.episodeHistory = make([]*Episode, 0)
	rl.explorationRate = 0.1 // Reset to initial value

	rl.logger.Info("Reinforcement learning state reset")
}

// UpdateLearningParameters updates learning parameters
func (rl *ReinforcementLearner) UpdateLearningParameters(learningRate, explorationRate, discountFactor float64) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.learningRate = learningRate
	rl.explorationRate = explorationRate
	rl.discountFactor = discountFactor

	rl.logger.Info("Learning parameters updated",
		"learning_rate", learningRate,
		"exploration_rate", explorationRate,
		"discount_factor", discountFactor)
}
