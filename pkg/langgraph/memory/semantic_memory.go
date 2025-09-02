package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// SemanticMemory manages semantic knowledge and concepts
type SemanticMemory struct {
	concepts       map[string]*Concept
	relations      map[string]*ConceptRelation
	categories     map[string]*Category
	maxSize        int
	knowledgeGraph *KnowledgeGraph
	conceptIndex   *ConceptIndex
	config         *MemoryConfig
	logger         *logger.Logger
	mutex          sync.RWMutex
}

// Concept represents a semantic concept
type Concept struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        ConceptType            `json:"type"`
	Definition  string                 `json:"definition"`
	Description string                 `json:"description"`
	Properties  map[string]interface{} `json:"properties"`
	Attributes  map[string]interface{} `json:"attributes"`
	Examples    []string               `json:"examples"`
	Synonyms    []string               `json:"synonyms"`
	Antonyms    []string               `json:"antonyms"`
	Categories  []string               `json:"categories"`
	Relations   []string               `json:"relations"`
	Confidence  float64                `json:"confidence"`
	Importance  float64                `json:"importance"`
	Frequency   int64                  `json:"frequency"`
	LastUsed    time.Time              `json:"last_used"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ConceptRelation represents a relation between concepts
type ConceptRelation struct {
	ID          string                 `json:"id"`
	Type        RelationType           `json:"type"`
	FromConcept string                 `json:"from_concept"`
	ToConcept   string                 `json:"to_concept"`
	Strength    float64                `json:"strength"`
	Confidence  float64                `json:"confidence"`
	Direction   RelationDirection      `json:"direction"`
	Properties  map[string]interface{} `json:"properties"`
	Context     map[string]interface{} `json:"context"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Category represents a semantic category
type Category struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parent      string                 `json:"parent"`
	Children    []string               `json:"children"`
	Concepts    []string               `json:"concepts"`
	Level       int                    `json:"level"`
	Properties  map[string]interface{} `json:"properties"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// KnowledgeGraph represents the semantic knowledge graph
type KnowledgeGraph struct {
	nodes map[string]*GraphNode
	edges map[string]*GraphEdge
	mutex sync.RWMutex
}

// GraphNode represents a node in the knowledge graph
type GraphNode struct {
	ID         string                 `json:"id"`
	Type       NodeType               `json:"type"`
	Label      string                 `json:"label"`
	Properties map[string]interface{} `json:"properties"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// GraphEdge represents an edge in the knowledge graph
type GraphEdge struct {
	ID         string                 `json:"id"`
	Type       EdgeType               `json:"type"`
	From       string                 `json:"from"`
	To         string                 `json:"to"`
	Weight     float64                `json:"weight"`
	Properties map[string]interface{} `json:"properties"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// ConceptIndex indexes concepts for efficient retrieval
type ConceptIndex struct {
	nameIndex     map[string][]string
	typeIndex     map[ConceptType][]string
	categoryIndex map[string][]string
	tagIndex      map[string][]string
	mutex         sync.RWMutex
}

// Enums for semantic memory
type ConceptType string
type RelationType string
type RelationDirection string
type NodeType string
type EdgeType string

const (
	// Concept Types
	ConceptTypeEntity   ConceptType = "entity"
	ConceptTypeAction   ConceptType = "action"
	ConceptTypeProperty ConceptType = "property"
	ConceptTypeEvent    ConceptType = "event"
	ConceptTypeAbstract ConceptType = "abstract"
	ConceptTypeConcrete ConceptType = "concrete"
	ConceptTypeProcess  ConceptType = "process"
	ConceptTypeState    ConceptType = "state"

	// Relation Types
	RelationTypeIsA        RelationType = "is_a"
	RelationTypePartOf     RelationType = "part_of"
	RelationTypeHasA       RelationType = "has_a"
	RelationTypeCausedBy   RelationType = "caused_by"
	RelationTypeLeadsTo    RelationType = "leads_to"
	RelationTypeSimilarTo  RelationType = "similar_to"
	RelationTypeOppositeOf RelationType = "opposite_of"
	RelationTypeUsedFor    RelationType = "used_for"
	RelationTypeLocatedAt  RelationType = "located_at"

	// Relation Directions
	DirectionBidirectional  RelationDirection = "bidirectional"
	DirectionUnidirectional RelationDirection = "unidirectional"

	// Node Types
	NodeTypeConcept  NodeType = "concept"
	NodeTypeCategory NodeType = "category"
	NodeTypeInstance NodeType = "instance"

	// Edge Types
	EdgeTypeRelation       EdgeType = "relation"
	EdgeTypeCategorization EdgeType = "categorization"
	EdgeTypeInstantiation  EdgeType = "instantiation"
)

// NewSemanticMemory creates a new semantic memory instance
func NewSemanticMemory(config *MemoryConfig, logger *logger.Logger) (*SemanticMemory, error) {
	knowledgeGraph := &KnowledgeGraph{
		nodes: make(map[string]*GraphNode),
		edges: make(map[string]*GraphEdge),
	}

	conceptIndex := &ConceptIndex{
		nameIndex:     make(map[string][]string),
		typeIndex:     make(map[ConceptType][]string),
		categoryIndex: make(map[string][]string),
		tagIndex:      make(map[string][]string),
	}

	return &SemanticMemory{
		concepts:       make(map[string]*Concept),
		relations:      make(map[string]*ConceptRelation),
		categories:     make(map[string]*Category),
		maxSize:        config.SemanticMemorySize,
		knowledgeGraph: knowledgeGraph,
		conceptIndex:   conceptIndex,
		config:         config,
		logger:         logger,
	}, nil
}

// Store stores a memory entry as semantic knowledge
func (sm *SemanticMemory) Store(ctx context.Context, entry *MemoryEntry) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Convert memory entry to concept
	concept, err := sm.convertToConcept(entry)
	if err != nil {
		return fmt.Errorf("failed to convert memory entry to concept: %w", err)
	}

	// Check if we need to evict concepts
	if len(sm.concepts) >= sm.maxSize {
		if err := sm.evictLeastUsedConcept(); err != nil {
			return fmt.Errorf("failed to evict concepts: %w", err)
		}
	}

	// Store the concept
	sm.concepts[concept.ID] = concept

	// Update indexes
	sm.conceptIndex.IndexConcept(concept)

	// Update knowledge graph
	sm.knowledgeGraph.AddNode(&GraphNode{
		ID:         concept.ID,
		Type:       NodeTypeConcept,
		Label:      concept.Name,
		Properties: concept.Properties,
		Metadata:   concept.Metadata,
	})

	sm.logger.Debug("Concept stored in semantic memory",
		"concept_id", concept.ID,
		"name", concept.Name,
		"type", concept.Type,
		"total_concepts", len(sm.concepts))

	return nil
}

// Retrieve retrieves a memory entry by ID
func (sm *SemanticMemory) Retrieve(ctx context.Context, id string) (*MemoryEntry, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	concept, exists := sm.concepts[id]
	if !exists {
		return nil, fmt.Errorf("concept not found: %s", id)
	}

	// Update usage information
	concept.LastUsed = time.Now()
	concept.Frequency++

	// Convert concept back to memory entry
	return sm.convertToMemoryEntry(concept), nil
}

// Query queries semantic memory with criteria
func (sm *SemanticMemory) Query(ctx context.Context, query *MemoryQuery) (*MemoryResult, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	var matchingEntries []*MemoryEntry

	// Use concept index to find candidates
	candidateIDs := sm.findCandidateConcepts(query)

	for _, conceptID := range candidateIDs {
		if concept, exists := sm.concepts[conceptID]; exists {
			if sm.matchesQuery(concept, query) {
				entry := sm.convertToMemoryEntry(concept)
				matchingEntries = append(matchingEntries, entry)
			}
		}
	}

	// Sort entries
	sm.sortEntries(matchingEntries, query.SortBy, query.SortOrder)

	// Apply limit
	if query.Limit > 0 && len(matchingEntries) > query.Limit {
		matchingEntries = matchingEntries[:query.Limit]
	}

	return &MemoryResult{
		Entries:    matchingEntries,
		TotalCount: len(matchingEntries),
		Metadata:   map[string]interface{}{"source": "semantic_memory"},
	}, nil
}

// Update updates a memory entry
func (sm *SemanticMemory) Update(ctx context.Context, entry *MemoryEntry) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	concept, exists := sm.concepts[entry.ID]
	if !exists {
		return fmt.Errorf("concept not found: %s", entry.ID)
	}

	// Update concept from memory entry
	updatedConcept, err := sm.convertToConcept(entry)
	if err != nil {
		return fmt.Errorf("failed to convert memory entry to concept: %w", err)
	}

	// Preserve original creation time and frequency
	updatedConcept.CreatedAt = concept.CreatedAt
	updatedConcept.Frequency = concept.Frequency
	updatedConcept.UpdatedAt = time.Now()

	sm.concepts[entry.ID] = updatedConcept

	// Update indexes
	sm.conceptIndex.UpdateConceptIndex(concept, updatedConcept)

	sm.logger.Debug("Concept updated in semantic memory",
		"concept_id", entry.ID,
		"name", updatedConcept.Name)

	return nil
}

// Delete deletes a memory entry
func (sm *SemanticMemory) Delete(ctx context.Context, id string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	concept, exists := sm.concepts[id]
	if !exists {
		return fmt.Errorf("concept not found: %s", id)
	}

	// Remove from indexes
	sm.conceptIndex.RemoveConceptFromIndex(concept)

	// Remove from knowledge graph
	sm.knowledgeGraph.RemoveNode(id)

	// Delete the concept
	delete(sm.concepts, id)

	sm.logger.Debug("Concept deleted from semantic memory",
		"concept_id", id,
		"remaining_concepts", len(sm.concepts))

	return nil
}

// AddRelation adds a relation between concepts
func (sm *SemanticMemory) AddRelation(relation *ConceptRelation) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Verify that both concepts exist
	if _, exists := sm.concepts[relation.FromConcept]; !exists {
		return fmt.Errorf("from concept not found: %s", relation.FromConcept)
	}

	if _, exists := sm.concepts[relation.ToConcept]; !exists {
		return fmt.Errorf("to concept not found: %s", relation.ToConcept)
	}

	// Store the relation
	sm.relations[relation.ID] = relation

	// Add edge to knowledge graph
	sm.knowledgeGraph.AddEdge(&GraphEdge{
		ID:         relation.ID,
		Type:       EdgeTypeRelation,
		From:       relation.FromConcept,
		To:         relation.ToConcept,
		Weight:     relation.Strength,
		Properties: relation.Properties,
		Metadata:   relation.Metadata,
	})

	sm.logger.Debug("Relation added to semantic memory",
		"relation_id", relation.ID,
		"type", relation.Type,
		"from", relation.FromConcept,
		"to", relation.ToConcept)

	return nil
}

// GetRelatedConcepts gets concepts related to a given concept
func (sm *SemanticMemory) GetRelatedConcepts(conceptID string, relationType RelationType, maxResults int) ([]*Concept, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	var relatedConcepts []*Concept

	for _, relation := range sm.relations {
		var targetConceptID string

		if relation.FromConcept == conceptID && (relationType == "" || relation.Type == relationType) {
			targetConceptID = relation.ToConcept
		} else if relation.ToConcept == conceptID && (relationType == "" || relation.Type == relationType) {
			targetConceptID = relation.FromConcept
		}

		if targetConceptID != "" {
			if concept, exists := sm.concepts[targetConceptID]; exists {
				relatedConcepts = append(relatedConcepts, concept)
			}
		}
	}

	// Sort by strength/importance
	sort.Slice(relatedConcepts, func(i, j int) bool {
		return relatedConcepts[i].Importance > relatedConcepts[j].Importance
	})

	// Apply limit
	if maxResults > 0 && len(relatedConcepts) > maxResults {
		relatedConcepts = relatedConcepts[:maxResults]
	}

	return relatedConcepts, nil
}

// GetSize returns the current size of semantic memory
func (sm *SemanticMemory) GetSize() int {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	return len(sm.concepts)
}

// GetStatistics returns semantic memory statistics
func (sm *SemanticMemory) GetStatistics() *MemoryTypeStatistics {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	var totalSize int64
	var totalFrequency int64
	var oldestEntry, newestEntry time.Time
	var lastUsed time.Time

	for _, concept := range sm.concepts {
		// Calculate size (simplified)
		totalSize += int64(len(fmt.Sprintf("%v", concept)))
		totalFrequency += concept.Frequency

		if oldestEntry.IsZero() || concept.CreatedAt.Before(oldestEntry) {
			oldestEntry = concept.CreatedAt
		}

		if newestEntry.IsZero() || concept.CreatedAt.After(newestEntry) {
			newestEntry = concept.CreatedAt
		}

		if lastUsed.IsZero() || concept.LastUsed.After(lastUsed) {
			lastUsed = concept.LastUsed
		}
	}

	var averageSize float64
	if len(sm.concepts) > 0 {
		averageSize = float64(totalSize) / float64(len(sm.concepts))
	}

	return &MemoryTypeStatistics{
		EntryCount:      len(sm.concepts),
		TotalSize:       totalSize,
		AverageSize:     averageSize,
		OldestEntry:     oldestEntry,
		NewestEntry:     newestEntry,
		AccessCount:     totalFrequency,
		LastAccess:      lastUsed,
		CompressionRate: 0.0, // Simplified
	}
}

// Helper methods

func (sm *SemanticMemory) convertToConcept(entry *MemoryEntry) (*Concept, error) {
	concept := &Concept{
		ID:          entry.ID,
		Name:        fmt.Sprintf("Concept_%s", entry.ID[:8]),
		Type:        ConceptTypeEntity, // Default type
		Definition:  fmt.Sprintf("%v", entry.Content),
		Description: fmt.Sprintf("%v", entry.Content),
		Properties:  make(map[string]interface{}),
		Attributes:  make(map[string]interface{}),
		Examples:    make([]string, 0),
		Synonyms:    make([]string, 0),
		Antonyms:    make([]string, 0),
		Categories:  make([]string, 0),
		Relations:   make([]string, 0),
		Confidence:  entry.Confidence,
		Importance:  entry.Importance,
		Frequency:   1,
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
				concept.Name = nameStr
			}
		}

		if conceptType, exists := entry.Context["concept_type"]; exists {
			if typeStr, ok := conceptType.(string); ok {
				concept.Type = ConceptType(typeStr)
			}
		}

		if definition, exists := entry.Context["definition"]; exists {
			if defStr, ok := definition.(string); ok {
				concept.Definition = defStr
			}
		}
	}

	return concept, nil
}

func (sm *SemanticMemory) convertToMemoryEntry(concept *Concept) *MemoryEntry {
	return &MemoryEntry{
		ID:          concept.ID,
		Type:        MemoryTypeSemantic,
		Content:     concept.Definition,
		Context:     concept.Metadata,
		Importance:  concept.Importance,
		Confidence:  concept.Confidence,
		Timestamp:   concept.CreatedAt,
		LastAccess:  concept.LastUsed,
		AccessCount: concept.Frequency,
		Tags:        concept.Tags,
		Metadata:    concept.Metadata,
	}
}

func (sm *SemanticMemory) evictLeastUsedConcept() error {
	if len(sm.concepts) == 0 {
		return nil
	}

	// Find the least used concept
	var leastUsedID string
	var leastFrequency int64 = -1
	var oldestTime time.Time

	for id, concept := range sm.concepts {
		if leastUsedID == "" || concept.Frequency < leastFrequency ||
			(concept.Frequency == leastFrequency && concept.LastUsed.Before(oldestTime)) {
			leastUsedID = id
			leastFrequency = concept.Frequency
			oldestTime = concept.LastUsed
		}
	}

	// Remove the least used concept
	if concept, exists := sm.concepts[leastUsedID]; exists {
		sm.conceptIndex.RemoveConceptFromIndex(concept)
		sm.knowledgeGraph.RemoveNode(leastUsedID)
		delete(sm.concepts, leastUsedID)

		sm.logger.Debug("Evicted least used concept from semantic memory",
			"concept_id", leastUsedID,
			"frequency", leastFrequency,
			"last_used", oldestTime,
			"remaining_concepts", len(sm.concepts))
	}

	return nil
}

func (sm *SemanticMemory) findCandidateConcepts(query *MemoryQuery) []string {
	sm.conceptIndex.mutex.RLock()
	defer sm.conceptIndex.mutex.RUnlock()

	var candidateIDs []string

	// Use indexes to find candidate concepts
	if len(query.Tags) > 0 {
		for _, tag := range query.Tags {
			if conceptIDs, exists := sm.conceptIndex.tagIndex[tag]; exists {
				candidateIDs = append(candidateIDs, conceptIDs...)
			}
		}
	} else {
		// If no specific criteria, return all concepts
		for _, conceptIDs := range sm.conceptIndex.typeIndex {
			candidateIDs = append(candidateIDs, conceptIDs...)
		}
	}

	// Remove duplicates
	uniqueIDs := make(map[string]bool)
	var result []string
	for _, id := range candidateIDs {
		if !uniqueIDs[id] {
			uniqueIDs[id] = true
			result = append(result, id)
		}
	}

	return result
}

func (sm *SemanticMemory) matchesQuery(concept *Concept, query *MemoryQuery) bool {
	// Check content match
	if query.Content != "" {
		if !contains(concept.Definition, query.Content) && !contains(concept.Description, query.Content) {
			return false
		}
	}

	// Check tags
	if len(query.Tags) > 0 {
		if !hasAnyTag(concept.Tags, query.Tags) {
			return false
		}
	}

	// Check time range
	if query.TimeRange != nil {
		if concept.CreatedAt.Before(query.TimeRange.Start) || concept.CreatedAt.After(query.TimeRange.End) {
			return false
		}
	}

	// Check importance range
	if query.ImportanceRange != nil {
		if concept.Importance < query.ImportanceRange.Min || concept.Importance > query.ImportanceRange.Max {
			return false
		}
	}

	// Check confidence range
	if query.ConfidenceRange != nil {
		if concept.Confidence < query.ConfidenceRange.Min || concept.Confidence > query.ConfidenceRange.Max {
			return false
		}
	}

	return true
}

func (sm *SemanticMemory) sortEntries(entries []*MemoryEntry, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "importance"
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
			less = entries[i].Importance < entries[j].Importance
		}

		if sortOrder == "desc" {
			return !less
		}
		return less
	})
}

// ConceptIndex methods

func (ci *ConceptIndex) IndexConcept(concept *Concept) {
	ci.mutex.Lock()
	defer ci.mutex.Unlock()

	// Index by name
	ci.nameIndex[concept.Name] = append(ci.nameIndex[concept.Name], concept.ID)

	// Index by type
	ci.typeIndex[concept.Type] = append(ci.typeIndex[concept.Type], concept.ID)

	// Index by categories
	for _, category := range concept.Categories {
		ci.categoryIndex[category] = append(ci.categoryIndex[category], concept.ID)
	}

	// Index by tags
	for _, tag := range concept.Tags {
		ci.tagIndex[tag] = append(ci.tagIndex[tag], concept.ID)
	}
}

func (ci *ConceptIndex) UpdateConceptIndex(oldConcept, newConcept *Concept) {
	ci.RemoveConceptFromIndex(oldConcept)
	ci.IndexConcept(newConcept)
}

func (ci *ConceptIndex) RemoveConceptFromIndex(concept *Concept) {
	ci.mutex.Lock()
	defer ci.mutex.Unlock()

	// Remove from name index
	ci.removeFromSlice(ci.nameIndex[concept.Name], concept.ID)

	// Remove from type index
	ci.removeFromSlice(ci.typeIndex[concept.Type], concept.ID)

	// Remove from category index
	for _, category := range concept.Categories {
		ci.removeFromSlice(ci.categoryIndex[category], concept.ID)
	}

	// Remove from tag index
	for _, tag := range concept.Tags {
		ci.removeFromSlice(ci.tagIndex[tag], concept.ID)
	}
}

func (ci *ConceptIndex) removeFromSlice(slice []string, item string) []string {
	for i, s := range slice {
		if s == item {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// KnowledgeGraph methods

func (kg *KnowledgeGraph) AddNode(node *GraphNode) {
	kg.mutex.Lock()
	defer kg.mutex.Unlock()

	kg.nodes[node.ID] = node
}

func (kg *KnowledgeGraph) AddEdge(edge *GraphEdge) {
	kg.mutex.Lock()
	defer kg.mutex.Unlock()

	kg.edges[edge.ID] = edge
}

func (kg *KnowledgeGraph) RemoveNode(nodeID string) {
	kg.mutex.Lock()
	defer kg.mutex.Unlock()

	delete(kg.nodes, nodeID)

	// Remove all edges connected to this node
	for edgeID, edge := range kg.edges {
		if edge.From == nodeID || edge.To == nodeID {
			delete(kg.edges, edgeID)
		}
	}
}

func (kg *KnowledgeGraph) RemoveEdge(edgeID string) {
	kg.mutex.Lock()
	defer kg.mutex.Unlock()

	delete(kg.edges, edgeID)
}
