package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// ProceduralMemory manages procedural knowledge (skills, procedures, habits)
type ProceduralMemory struct {
	procedures   map[string]*Procedure
	skills       map[string]*Skill
	habits       map[string]*Habit
	workflows    map[string]*Workflow
	maxSize      int
	skillIndex   *SkillIndex
	config       *MemoryConfig
	logger       *logger.Logger
	mutex        sync.RWMutex
}

// Procedure represents a procedural memory
type Procedure struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        ProcedureType          `json:"type"`
	Steps       []*ProcedureStep       `json:"steps"`
	Conditions  []*Condition           `json:"conditions"`
	Outcomes    []*ProcedureOutcome    `json:"outcomes"`
	Complexity  float64                `json:"complexity"`
	Reliability float64                `json:"reliability"`
	Efficiency  float64                `json:"efficiency"`
	UsageCount  int64                  `json:"usage_count"`
	SuccessRate float64                `json:"success_rate"`
	LastUsed    time.Time              `json:"last_used"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ProcedureStep represents a step in a procedure
type ProcedureStep struct {
	ID          string                 `json:"id"`
	Order       int                    `json:"order"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        StepType               `json:"type"`
	Action      string                 `json:"action"`
	Parameters  map[string]interface{} `json:"parameters"`
	Conditions  []*Condition           `json:"conditions"`
	Expected    interface{}            `json:"expected"`
	Timeout     time.Duration          `json:"timeout"`
	Retries     int                    `json:"retries"`
	Critical    bool                   `json:"critical"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Skill represents a learned skill
type Skill struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Level       SkillLevel             `json:"level"`
	Proficiency float64                `json:"proficiency"`
	Experience  int64                  `json:"experience"`
	Procedures  []string               `json:"procedures"`
	Prerequisites []string             `json:"prerequisites"`
	Metrics     map[string]float64     `json:"metrics"`
	LastPracticed time.Time            `json:"last_practiced"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Habit represents an automated behavior pattern
type Habit struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Trigger     *HabitTrigger          `json:"trigger"`
	Routine     *HabitRoutine          `json:"routine"`
	Reward      *HabitReward           `json:"reward"`
	Strength    float64                `json:"strength"`
	Frequency   float64                `json:"frequency"`
	Consistency float64                `json:"consistency"`
	LastTriggered time.Time            `json:"last_triggered"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Workflow represents a complex procedural workflow
type Workflow struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Procedures  []string               `json:"procedures"`
	Dependencies map[string][]string   `json:"dependencies"`
	Parallel    [][]string             `json:"parallel"`
	Conditions  []*Condition           `json:"conditions"`
	Metrics     map[string]float64     `json:"metrics"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Supporting structures
type Condition struct {
	ID       string                 `json:"id"`
	Type     ConditionType          `json:"type"`
	Field    string                 `json:"field"`
	Operator ConditionOperator      `json:"operator"`
	Value    interface{}            `json:"value"`
	Metadata map[string]interface{} `json:"metadata"`
}

type ProcedureOutcome struct {
	ID          string                 `json:"id"`
	Type        OutcomeType            `json:"type"`
	Description string                 `json:"description"`
	Probability float64                `json:"probability"`
	Impact      float64                `json:"impact"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type HabitTrigger struct {
	Type        TriggerType            `json:"type"`
	Conditions  []*Condition           `json:"conditions"`
	Context     map[string]interface{} `json:"context"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type HabitRoutine struct {
	Steps       []*ProcedureStep       `json:"steps"`
	Duration    time.Duration          `json:"duration"`
	Complexity  float64                `json:"complexity"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type HabitReward struct {
	Type        RewardType             `json:"type"`
	Value       interface{}            `json:"value"`
	Strength    float64                `json:"strength"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type SkillIndex struct {
	categoryIndex    map[string][]string
	levelIndex       map[SkillLevel][]string
	proficiencyIndex []string // sorted by proficiency
	tagIndex         map[string][]string
	mutex            sync.RWMutex
}

// Enums for procedural memory
type ProcedureType string
type StepType string
type SkillLevel string
type ConditionType string
type ConditionOperator string
type TriggerType string
type RewardType string

const (
	// Procedure Types
	ProcedureTypeTask       ProcedureType = "task"
	ProcedureTypeAlgorithm  ProcedureType = "algorithm"
	ProcedureTypeProtocol   ProcedureType = "protocol"
	ProcedureTypeWorkflow   ProcedureType = "workflow"
	ProcedureTypeHeuristic  ProcedureType = "heuristic"
	ProcedureTypeStrategy   ProcedureType = "strategy"

	// Step Types
	StepTypeAction      StepType = "action"
	StepTypeDecision    StepType = "decision"
	StepTypeValidation  StepType = "validation"
	StepTypeComputation StepType = "computation"
	StepTypeCommunication StepType = "communication"
	StepTypeWait        StepType = "wait"

	// Skill Levels
	SkillLevelNovice     SkillLevel = "novice"
	SkillLevelBeginner   SkillLevel = "beginner"
	SkillLevelIntermediate SkillLevel = "intermediate"
	SkillLevelAdvanced   SkillLevel = "advanced"
	SkillLevelExpert     SkillLevel = "expert"
	SkillLevelMaster     SkillLevel = "master"

	// Condition Types
	ConditionTypeContext    ConditionType = "context"
	ConditionTypeState      ConditionType = "state"
	ConditionTypeTime       ConditionType = "time"
	ConditionTypeResource   ConditionType = "resource"
	ConditionTypePerformance ConditionType = "performance"

	// Condition Operators
	ConditionOperatorEquals      ConditionOperator = "equals"
	ConditionOperatorNotEquals   ConditionOperator = "not_equals"
	ConditionOperatorGreaterThan ConditionOperator = "greater_than"
	ConditionOperatorLessThan    ConditionOperator = "less_than"
	ConditionOperatorContains    ConditionOperator = "contains"
	ConditionOperatorExists      ConditionOperator = "exists"

	// Trigger Types
	TriggerTypeTime     TriggerType = "time"
	TriggerTypeEvent    TriggerType = "event"
	TriggerTypeContext  TriggerType = "context"
	TriggerTypeState    TriggerType = "state"
	TriggerTypePattern  TriggerType = "pattern"

	// Reward Types
	RewardTypePositive  RewardType = "positive"
	RewardTypeNegative  RewardType = "negative"
	RewardTypeNeutral   RewardType = "neutral"
	RewardTypeIntrinsic RewardType = "intrinsic"
	RewardTypeExtrinsic RewardType = "extrinsic"
)

// NewProceduralMemory creates a new procedural memory instance
func NewProceduralMemory(config *MemoryConfig, logger *logger.Logger) (*ProceduralMemory, error) {
	skillIndex := &SkillIndex{
		categoryIndex:    make(map[string][]string),
		levelIndex:       make(map[SkillLevel][]string),
		proficiencyIndex: make([]string, 0),
		tagIndex:         make(map[string][]string),
	}

	return &ProceduralMemory{
		procedures: make(map[string]*Procedure),
		skills:     make(map[string]*Skill),
		habits:     make(map[string]*Habit),
		workflows:  make(map[string]*Workflow),
		maxSize:    config.ProceduralMemorySize,
		skillIndex: skillIndex,
		config:     config,
		logger:     logger,
	}, nil
}

// Store stores a memory entry as procedural knowledge
func (pm *ProceduralMemory) Store(ctx context.Context, entry *MemoryEntry) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Convert memory entry to procedure
	procedure, err := pm.convertToProcedure(entry)
	if err != nil {
		return fmt.Errorf("failed to convert memory entry to procedure: %w", err)
	}

	// Check if we need to evict procedures
	if len(pm.procedures) >= pm.maxSize {
		if err := pm.evictLeastUsedProcedure(); err != nil {
			return fmt.Errorf("failed to evict procedures: %w", err)
		}
	}

	// Store the procedure
	pm.procedures[procedure.ID] = procedure

	pm.logger.Debug("Procedure stored in procedural memory",
		"procedure_id", procedure.ID,
		"name", procedure.Name,
		"type", procedure.Type,
		"total_procedures", len(pm.procedures))

	return nil
}

// Retrieve retrieves a memory entry by ID
func (pm *ProceduralMemory) Retrieve(ctx context.Context, id string) (*MemoryEntry, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	procedure, exists := pm.procedures[id]
	if !exists {
		return nil, fmt.Errorf("procedure not found: %s", id)
	}

	// Update usage information
	procedure.LastUsed = time.Now()
	procedure.UsageCount++

	// Convert procedure back to memory entry
	return pm.convertToMemoryEntry(procedure), nil
}

// Query queries procedural memory with criteria
func (pm *ProceduralMemory) Query(ctx context.Context, query *MemoryQuery) (*MemoryResult, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var matchingEntries []*MemoryEntry

	for _, procedure := range pm.procedures {
		if pm.matchesQuery(procedure, query) {
			entry := pm.convertToMemoryEntry(procedure)
			matchingEntries = append(matchingEntries, entry)
		}
	}

	// Sort entries
	pm.sortEntries(matchingEntries, query.SortBy, query.SortOrder)

	// Apply limit
	if query.Limit > 0 && len(matchingEntries) > query.Limit {
		matchingEntries = matchingEntries[:query.Limit]
	}

	return &MemoryResult{
		Entries:    matchingEntries,
		TotalCount: len(matchingEntries),
		Metadata:   map[string]interface{}{"source": "procedural_memory"},
	}, nil
}

// Update updates a memory entry
func (pm *ProceduralMemory) Update(ctx context.Context, entry *MemoryEntry) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	procedure, exists := pm.procedures[entry.ID]
	if !exists {
		return fmt.Errorf("procedure not found: %s", entry.ID)
	}

	// Update procedure from memory entry
	updatedProcedure, err := pm.convertToProcedure(entry)
	if err != nil {
		return fmt.Errorf("failed to convert memory entry to procedure: %w", err)
	}

	// Preserve original creation time and usage count
	updatedProcedure.CreatedAt = procedure.CreatedAt
	updatedProcedure.UsageCount = procedure.UsageCount
	updatedProcedure.UpdatedAt = time.Now()

	pm.procedures[entry.ID] = updatedProcedure

	pm.logger.Debug("Procedure updated in procedural memory",
		"procedure_id", entry.ID,
		"name", updatedProcedure.Name)

	return nil
}

// Delete deletes a memory entry
func (pm *ProceduralMemory) Delete(ctx context.Context, id string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.procedures[id]; !exists {
		return fmt.Errorf("procedure not found: %s", id)
	}

	// Delete the procedure
	delete(pm.procedures, id)

	pm.logger.Debug("Procedure deleted from procedural memory",
		"procedure_id", id,
		"remaining_procedures", len(pm.procedures))

	return nil
}

// AddSkill adds a new skill
func (pm *ProceduralMemory) AddSkill(skill *Skill) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.skills[skill.ID] = skill
	pm.skillIndex.IndexSkill(skill)

	pm.logger.Debug("Skill added to procedural memory",
		"skill_id", skill.ID,
		"name", skill.Name,
		"level", skill.Level,
		"proficiency", skill.Proficiency)

	return nil
}

// GetSkill retrieves a skill by ID
func (pm *ProceduralMemory) GetSkill(skillID string) (*Skill, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	skill, exists := pm.skills[skillID]
	if !exists {
		return nil, fmt.Errorf("skill not found: %s", skillID)
	}

	return skill, nil
}

// UpdateSkillProficiency updates skill proficiency based on usage
func (pm *ProceduralMemory) UpdateSkillProficiency(skillID string, performance float64) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	skill, exists := pm.skills[skillID]
	if !exists {
		return fmt.Errorf("skill not found: %s", skillID)
	}

	// Update proficiency based on performance
	learningRate := 0.1
	skill.Proficiency += learningRate * (performance - skill.Proficiency)
	skill.Experience++
	skill.LastPracticed = time.Now()
	skill.UpdatedAt = time.Now()

	// Update skill level based on proficiency
	pm.updateSkillLevel(skill)

	pm.logger.Debug("Skill proficiency updated",
		"skill_id", skillID,
		"new_proficiency", skill.Proficiency,
		"level", skill.Level)

	return nil
}

// GetSize returns the current size of procedural memory
func (pm *ProceduralMemory) GetSize() int {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	return len(pm.procedures)
}

// GetStatistics returns procedural memory statistics
func (pm *ProceduralMemory) GetStatistics() *MemoryTypeStatistics {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var totalSize int64
	var totalUsage int64
	var oldestEntry, newestEntry time.Time
	var lastUsed time.Time

	for _, procedure := range pm.procedures {
		// Calculate size (simplified)
		totalSize += int64(len(fmt.Sprintf("%v", procedure)))
		totalUsage += procedure.UsageCount

		if oldestEntry.IsZero() || procedure.CreatedAt.Before(oldestEntry) {
			oldestEntry = procedure.CreatedAt
		}

		if newestEntry.IsZero() || procedure.CreatedAt.After(newestEntry) {
			newestEntry = procedure.CreatedAt
		}

		if lastUsed.IsZero() || procedure.LastUsed.After(lastUsed) {
			lastUsed = procedure.LastUsed
		}
	}

	var averageSize float64
	if len(pm.procedures) > 0 {
		averageSize = float64(totalSize) / float64(len(pm.procedures))
	}

	return &MemoryTypeStatistics{
		EntryCount:      len(pm.procedures),
		TotalSize:       totalSize,
		AverageSize:     averageSize,
		OldestEntry:     oldestEntry,
		NewestEntry:     newestEntry,
		AccessCount:     totalUsage,
		LastAccess:      lastUsed,
		CompressionRate: 0.0, // Simplified
	}
}

// Helper methods

func (pm *ProceduralMemory) convertToProcedure(entry *MemoryEntry) (*Procedure, error) {
	procedure := &Procedure{
		ID:          entry.ID,
		Name:        fmt.Sprintf("Procedure_%s", entry.ID[:8]),
		Description: fmt.Sprintf("%v", entry.Content),
		Type:        ProcedureTypeTask, // Default type
		Steps:       make([]*ProcedureStep, 0),
		Conditions:  make([]*Condition, 0),
		Outcomes:    make([]*ProcedureOutcome, 0),
		Complexity:  0.5, // Default complexity
		Reliability: entry.Confidence,
		Efficiency:  0.5, // Default efficiency
		UsageCount:  1,
		SuccessRate: 1.0, // Default success rate
		LastUsed:    entry.LastAccess,
		CreatedAt:   entry.Timestamp,
		UpdatedAt:   time.Now(),
		Tags:        entry.Tags,
		Metadata:    entry.Metadata,
	}

	// Extract additional information from context
	if entry.Context != nil {
		if name, exists := entry.Context["name"]; exists {
			if nameStr, ok := name.(string); ok {
				procedure.Name = nameStr
			}
		}

		if procedureType, exists := entry.Context["procedure_type"]; exists {
			if typeStr, ok := procedureType.(string); ok {
				procedure.Type = ProcedureType(typeStr)
			}
		}

		if complexity, exists := entry.Context["complexity"]; exists {
			if complexityFloat, ok := complexity.(float64); ok {
				procedure.Complexity = complexityFloat
			}
		}
	}

	return procedure, nil
}

func (pm *ProceduralMemory) convertToMemoryEntry(procedure *Procedure) *MemoryEntry {
	return &MemoryEntry{
		ID:          procedure.ID,
		Type:        MemoryTypeProcedural,
		Content:     procedure.Description,
		Context:     procedure.Metadata,
		Importance:  procedure.Reliability,
		Confidence:  procedure.Reliability,
		Timestamp:   procedure.CreatedAt,
		LastAccess:  procedure.LastUsed,
		AccessCount: procedure.UsageCount,
		Tags:        procedure.Tags,
		Metadata:    procedure.Metadata,
	}
}

func (pm *ProceduralMemory) evictLeastUsedProcedure() error {
	if len(pm.procedures) == 0 {
		return nil
	}

	// Find the least used procedure
	var leastUsedID string
	var leastUsage int64 = -1
	var oldestTime time.Time

	for id, procedure := range pm.procedures {
		if leastUsedID == "" || procedure.UsageCount < leastUsage || 
		   (procedure.UsageCount == leastUsage && procedure.LastUsed.Before(oldestTime)) {
			leastUsedID = id
			leastUsage = procedure.UsageCount
			oldestTime = procedure.LastUsed
		}
	}

	// Remove the least used procedure
	delete(pm.procedures, leastUsedID)

	pm.logger.Debug("Evicted least used procedure from procedural memory",
		"procedure_id", leastUsedID,
		"usage_count", leastUsage,
		"last_used", oldestTime,
		"remaining_procedures", len(pm.procedures))

	return nil
}

func (pm *ProceduralMemory) matchesQuery(procedure *Procedure, query *MemoryQuery) bool {
	// Check content match
	if query.Content != "" {
		if !contains(procedure.Description, query.Content) {
			return false
		}
	}

	// Check tags
	if len(query.Tags) > 0 {
		if !hasAnyTag(procedure.Tags, query.Tags) {
			return false
		}
	}

	// Check time range
	if query.TimeRange != nil {
		if procedure.CreatedAt.Before(query.TimeRange.Start) || procedure.CreatedAt.After(query.TimeRange.End) {
			return false
		}
	}

	return true
}

func (pm *ProceduralMemory) sortEntries(entries []*MemoryEntry, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "access_count"
	}

	sort.Slice(entries, func(i, j int) bool {
		var less bool

		switch sortBy {
		case "timestamp":
			less = entries[i].Timestamp.Before(entries[j].Timestamp)
		case "importance":
			less = entries[i].Importance < entries[j].Importance
		case "confidence":
			less = entries[i].Confidence < entries[j].Confidence
		case "access_count":
			less = entries[i].AccessCount < entries[j].AccessCount
		case "last_access":
			less = entries[i].LastAccess.Before(entries[j].LastAccess)
		default:
			less = entries[i].AccessCount < entries[j].AccessCount
		}

		if sortOrder == "desc" {
			return !less
		}
		return less
	})
}

func (pm *ProceduralMemory) updateSkillLevel(skill *Skill) {
	switch {
	case skill.Proficiency >= 0.9:
		skill.Level = SkillLevelMaster
	case skill.Proficiency >= 0.8:
		skill.Level = SkillLevelExpert
	case skill.Proficiency >= 0.7:
		skill.Level = SkillLevelAdvanced
	case skill.Proficiency >= 0.5:
		skill.Level = SkillLevelIntermediate
	case skill.Proficiency >= 0.3:
		skill.Level = SkillLevelBeginner
	default:
		skill.Level = SkillLevelNovice
	}
}

// SkillIndex methods

func (si *SkillIndex) IndexSkill(skill *Skill) {
	si.mutex.Lock()
	defer si.mutex.Unlock()

	// Index by category
	si.categoryIndex[skill.Category] = append(si.categoryIndex[skill.Category], skill.ID)

	// Index by level
	si.levelIndex[skill.Level] = append(si.levelIndex[skill.Level], skill.ID)

	// Index by tags
	for _, tag := range skill.Tags {
		si.tagIndex[tag] = append(si.tagIndex[tag], skill.ID)
	}

	// Index by proficiency (maintain sorted order)
	si.insertInProficiencyIndex(skill.ID, skill.Proficiency)
}

func (si *SkillIndex) insertInProficiencyIndex(skillID string, proficiency float64) {
	// Simple insertion - in production, use more efficient data structure
	si.proficiencyIndex = append(si.proficiencyIndex, skillID)
}
