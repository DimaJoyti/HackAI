package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var semanticTracer = otel.Tracer("hackai/llm/memory/semantic")

// InMemorySemanticMemory implements SemanticMemory using in-memory storage
type InMemorySemanticMemory struct {
	facts         map[string]Fact
	subjectIndex  map[string][]string // subject -> fact IDs
	predicateIndex map[string][]string // predicate -> fact IDs
	objectIndex   map[string][]string // object -> fact IDs
	mutex         sync.RWMutex
	maxSize       int
	logger        *logger.Logger
}

// NewInMemorySemanticMemory creates a new in-memory semantic memory
func NewInMemorySemanticMemory(maxSize int, logger *logger.Logger) *InMemorySemanticMemory {
	return &InMemorySemanticMemory{
		facts:          make(map[string]Fact),
		subjectIndex:   make(map[string][]string),
		predicateIndex: make(map[string][]string),
		objectIndex:    make(map[string][]string),
		maxSize:        maxSize,
		logger:         logger,
	}
}

// StoreFact stores a semantic fact
func (m *InMemorySemanticMemory) StoreFact(ctx context.Context, fact Fact) error {
	ctx, span := semanticTracer.Start(ctx, "semantic_memory.store_fact",
		trace.WithAttributes(
			attribute.String("fact.id", fact.ID),
			attribute.String("fact.subject", fact.Subject),
			attribute.String("fact.predicate", fact.Predicate),
			attribute.String("fact.object", fact.Object),
		),
	)
	defer span.End()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check size limit
	if len(m.facts) >= m.maxSize && m.facts[fact.ID].ID == "" {
		// Remove lowest confidence fact to make space
		if err := m.evictLowestConfidenceFact(); err != nil {
			span.RecordError(err)
			return fmt.Errorf("failed to evict lowest confidence fact: %w", err)
		}
	}

	// Set ID if not provided
	if fact.ID == "" {
		fact.ID = uuid.New().String()
	}

	// Set timestamp if not provided
	if fact.Timestamp.IsZero() {
		fact.Timestamp = time.Now()
	}

	// Validate fact
	if err := m.validateFact(fact); err != nil {
		span.RecordError(err)
		return fmt.Errorf("fact validation failed: %w", err)
	}

	// Store fact
	m.facts[fact.ID] = fact

	// Update indexes
	m.updateIndexes(fact.ID, fact)

	span.SetAttributes(
		attribute.Int("facts.total", len(m.facts)),
		attribute.Float64("fact.confidence", fact.Confidence),
		attribute.Bool("success", true),
	)

	m.logger.Debug("Fact stored", 
		"fact_id", fact.ID, 
		"subject", fact.Subject,
		"predicate", fact.Predicate,
		"object", fact.Object,
		"confidence", fact.Confidence,
	)

	return nil
}

// RetrieveFacts retrieves facts based on query
func (m *InMemorySemanticMemory) RetrieveFacts(ctx context.Context, query string, limit int) ([]Fact, error) {
	ctx, span := semanticTracer.Start(ctx, "semantic_memory.retrieve_facts",
		trace.WithAttributes(
			attribute.String("query", query),
			attribute.Int("limit", limit),
		),
	)
	defer span.End()

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var candidates []Fact

	// Parse query to extract subject, predicate, object patterns
	queryParts := m.parseQuery(query)

	// Use indexes for efficient retrieval
	candidateIDs := m.getFactsByQuery(queryParts)

	// Get facts from IDs
	for _, id := range candidateIDs {
		if fact, exists := m.facts[id]; exists {
			candidates = append(candidates, fact)
		}
	}

	// If no structured query, fall back to text search
	if len(candidates) == 0 {
		candidates = m.searchFactsByText(query)
	}

	// Sort by confidence (highest first)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Confidence > candidates[j].Confidence
	})

	// Apply limit
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}

	span.SetAttributes(
		attribute.Int("results.count", len(candidates)),
		attribute.Bool("success", true),
	)

	m.logger.Debug("Facts retrieved", 
		"query", query,
		"results_count", len(candidates),
	)

	return candidates, nil
}

// UpdateFact updates an existing fact
func (m *InMemorySemanticMemory) UpdateFact(ctx context.Context, factID string, fact Fact) error {
	ctx, span := semanticTracer.Start(ctx, "semantic_memory.update_fact",
		trace.WithAttributes(attribute.String("fact.id", factID)),
	)
	defer span.End()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	oldFact, exists := m.facts[factID]
	if !exists {
		err := fmt.Errorf("fact %s not found", factID)
		span.RecordError(err)
		return err
	}

	// Validate updated fact
	if err := m.validateFact(fact); err != nil {
		span.RecordError(err)
		return fmt.Errorf("fact validation failed: %w", err)
	}

	// Remove old fact from indexes
	m.removeFromIndexes(factID, oldFact)

	// Preserve ID and update timestamp
	fact.ID = factID
	fact.Timestamp = time.Now()

	// Store updated fact
	m.facts[factID] = fact

	// Update indexes with new fact
	m.updateIndexes(factID, fact)

	span.SetAttributes(attribute.Bool("success", true))
	m.logger.Debug("Fact updated", "fact_id", factID)

	return nil
}

// DeleteFact deletes a fact
func (m *InMemorySemanticMemory) DeleteFact(ctx context.Context, factID string) error {
	ctx, span := semanticTracer.Start(ctx, "semantic_memory.delete_fact",
		trace.WithAttributes(attribute.String("fact.id", factID)),
	)
	defer span.End()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	fact, exists := m.facts[factID]
	if !exists {
		err := fmt.Errorf("fact %s not found", factID)
		span.RecordError(err)
		return err
	}

	// Remove from indexes
	m.removeFromIndexes(factID, fact)

	// Delete fact
	delete(m.facts, factID)

	span.SetAttributes(attribute.Bool("success", true))
	m.logger.Debug("Fact deleted", "fact_id", factID)

	return nil
}

// GetFactCount returns the number of stored facts
func (m *InMemorySemanticMemory) GetFactCount(ctx context.Context) (int, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return len(m.facts), nil
}

// GetFactsBySubject retrieves facts by subject
func (m *InMemorySemanticMemory) GetFactsBySubject(ctx context.Context, subject string, limit int) ([]Fact, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	factIDs, exists := m.subjectIndex[strings.ToLower(subject)]
	if !exists {
		return []Fact{}, nil
	}

	var facts []Fact
	for _, id := range factIDs {
		if fact, exists := m.facts[id]; exists {
			facts = append(facts, fact)
		}
		if limit > 0 && len(facts) >= limit {
			break
		}
	}

	return facts, nil
}

// GetFactsByPredicate retrieves facts by predicate
func (m *InMemorySemanticMemory) GetFactsByPredicate(ctx context.Context, predicate string, limit int) ([]Fact, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	factIDs, exists := m.predicateIndex[strings.ToLower(predicate)]
	if !exists {
		return []Fact{}, nil
	}

	var facts []Fact
	for _, id := range factIDs {
		if fact, exists := m.facts[id]; exists {
			facts = append(facts, fact)
		}
		if limit > 0 && len(facts) >= limit {
			break
		}
	}

	return facts, nil
}

// GetRelatedFacts finds facts related to a given fact
func (m *InMemorySemanticMemory) GetRelatedFacts(ctx context.Context, factID string, limit int) ([]Fact, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	fact, exists := m.facts[factID]
	if !exists {
		return []Fact{}, fmt.Errorf("fact %s not found", factID)
	}

	var related []Fact
	relatedSet := make(map[string]bool)

	// Find facts with same subject
	if subjectFacts, exists := m.subjectIndex[strings.ToLower(fact.Subject)]; exists {
		for _, id := range subjectFacts {
			if id != factID && !relatedSet[id] {
				if relatedFact, exists := m.facts[id]; exists {
					related = append(related, relatedFact)
					relatedSet[id] = true
				}
			}
		}
	}

	// Find facts with same object as subject
	if objectFacts, exists := m.subjectIndex[strings.ToLower(fact.Object)]; exists {
		for _, id := range objectFacts {
			if id != factID && !relatedSet[id] {
				if relatedFact, exists := m.facts[id]; exists {
					related = append(related, relatedFact)
					relatedSet[id] = true
				}
			}
		}
	}

	// Sort by confidence
	sort.Slice(related, func(i, j int) bool {
		return related[i].Confidence > related[j].Confidence
	})

	// Apply limit
	if limit > 0 && len(related) > limit {
		related = related[:limit]
	}

	return related, nil
}

// Helper methods

// validateFact validates a fact
func (m *InMemorySemanticMemory) validateFact(fact Fact) error {
	if fact.Subject == "" {
		return fmt.Errorf("fact subject cannot be empty")
	}
	if fact.Predicate == "" {
		return fmt.Errorf("fact predicate cannot be empty")
	}
	if fact.Object == "" {
		return fmt.Errorf("fact object cannot be empty")
	}
	if fact.Confidence < 0 || fact.Confidence > 1 {
		return fmt.Errorf("fact confidence must be between 0 and 1")
	}
	return nil
}

// evictLowestConfidenceFact removes the fact with lowest confidence
func (m *InMemorySemanticMemory) evictLowestConfidenceFact() error {
	if len(m.facts) == 0 {
		return nil
	}

	var lowestID string
	var lowestConfidence float64 = 2.0 // Higher than max possible confidence

	for id, fact := range m.facts {
		if fact.Confidence < lowestConfidence {
			lowestID = id
			lowestConfidence = fact.Confidence
		}
	}

	if lowestID != "" {
		fact := m.facts[lowestID]
		m.removeFromIndexes(lowestID, fact)
		delete(m.facts, lowestID)
		m.logger.Debug("Evicted lowest confidence fact", "fact_id", lowestID, "confidence", lowestConfidence)
	}

	return nil
}

// updateIndexes updates all indexes for a fact
func (m *InMemorySemanticMemory) updateIndexes(factID string, fact Fact) {
	// Subject index
	subject := strings.ToLower(fact.Subject)
	if !contains(m.subjectIndex[subject], factID) {
		m.subjectIndex[subject] = append(m.subjectIndex[subject], factID)
	}

	// Predicate index
	predicate := strings.ToLower(fact.Predicate)
	if !contains(m.predicateIndex[predicate], factID) {
		m.predicateIndex[predicate] = append(m.predicateIndex[predicate], factID)
	}

	// Object index
	object := strings.ToLower(fact.Object)
	if !contains(m.objectIndex[object], factID) {
		m.objectIndex[object] = append(m.objectIndex[object], factID)
	}
}

// removeFromIndexes removes a fact from all indexes
func (m *InMemorySemanticMemory) removeFromIndexes(factID string, fact Fact) {
	// Subject index
	subject := strings.ToLower(fact.Subject)
	m.subjectIndex[subject] = removeString(m.subjectIndex[subject], factID)
	if len(m.subjectIndex[subject]) == 0 {
		delete(m.subjectIndex, subject)
	}

	// Predicate index
	predicate := strings.ToLower(fact.Predicate)
	m.predicateIndex[predicate] = removeString(m.predicateIndex[predicate], factID)
	if len(m.predicateIndex[predicate]) == 0 {
		delete(m.predicateIndex, predicate)
	}

	// Object index
	object := strings.ToLower(fact.Object)
	m.objectIndex[object] = removeString(m.objectIndex[object], factID)
	if len(m.objectIndex[object]) == 0 {
		delete(m.objectIndex, object)
	}
}

// parseQuery parses a query to extract subject, predicate, object patterns
func (m *InMemorySemanticMemory) parseQuery(query string) map[string]string {
	// Simple parsing - in production, this would be more sophisticated
	parts := make(map[string]string)
	
	query = strings.ToLower(strings.TrimSpace(query))
	
	// Look for patterns like "X is Y" or "X has Y"
	if strings.Contains(query, " is ") {
		splitParts := strings.Split(query, " is ")
		if len(splitParts) == 2 {
			parts["subject"] = strings.TrimSpace(splitParts[0])
			parts["predicate"] = "is"
			parts["object"] = strings.TrimSpace(splitParts[1])
		}
	} else if strings.Contains(query, " has ") {
		splitParts := strings.Split(query, " has ")
		if len(splitParts) == 2 {
			parts["subject"] = strings.TrimSpace(splitParts[0])
			parts["predicate"] = "has"
			parts["object"] = strings.TrimSpace(splitParts[1])
		}
	}
	
	return parts
}

// getFactsByQuery gets facts matching query parts
func (m *InMemorySemanticMemory) getFactsByQuery(queryParts map[string]string) []string {
	var candidateIDs []string
	
	if subject, exists := queryParts["subject"]; exists {
		if ids, found := m.subjectIndex[subject]; found {
			candidateIDs = append(candidateIDs, ids...)
		}
	}
	
	if predicate, exists := queryParts["predicate"]; exists {
		if ids, found := m.predicateIndex[predicate]; found {
			if len(candidateIDs) == 0 {
				candidateIDs = append(candidateIDs, ids...)
			} else {
				// Intersect with existing candidates
				candidateIDs = intersectStringSlices(candidateIDs, ids)
			}
		}
	}
	
	if object, exists := queryParts["object"]; exists {
		if ids, found := m.objectIndex[object]; found {
			if len(candidateIDs) == 0 {
				candidateIDs = append(candidateIDs, ids...)
			} else {
				// Intersect with existing candidates
				candidateIDs = intersectStringSlices(candidateIDs, ids)
			}
		}
	}
	
	return candidateIDs
}

// searchFactsByText searches facts by text content
func (m *InMemorySemanticMemory) searchFactsByText(query string) []Fact {
	query = strings.ToLower(query)
	var results []Fact

	for _, fact := range m.facts {
		searchText := strings.ToLower(fact.Subject + " " + fact.Predicate + " " + fact.Object + " " + fact.Context)
		if strings.Contains(searchText, query) {
			results = append(results, fact)
		}
	}

	return results
}

// intersectStringSlices returns the intersection of two string slices
func intersectStringSlices(a, b []string) []string {
	setA := make(map[string]bool)
	for _, item := range a {
		setA[item] = true
	}

	var intersection []string
	for _, item := range b {
		if setA[item] {
			intersection = append(intersection, item)
		}
	}

	return intersection
}
