package providers

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// RoundRobinBalancer implements round-robin load balancing
type RoundRobinBalancer struct {
	counter int
	mutex   sync.Mutex
}

// NewRoundRobinBalancer creates a new round-robin load balancer
func NewRoundRobinBalancer() *RoundRobinBalancer {
	return &RoundRobinBalancer{}
}

// SelectProvider selects a provider using round-robin algorithm
func (rb *RoundRobinBalancer) SelectProvider(providers []LLMProvider, request GenerationRequest) (LLMProvider, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	rb.mutex.Lock()
	defer rb.mutex.Unlock()

	provider := providers[rb.counter%len(providers)]
	rb.counter++

	return provider, nil
}

// RandomBalancer implements random load balancing
type RandomBalancer struct {
	rand *rand.Rand
}

// NewRandomBalancer creates a new random load balancer
func NewRandomBalancer() *RandomBalancer {
	return &RandomBalancer{
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// SelectProvider selects a provider randomly
func (rb *RandomBalancer) SelectProvider(providers []LLMProvider, request GenerationRequest) (LLMProvider, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	index := rb.rand.Intn(len(providers))
	return providers[index], nil
}

// WeightedBalancer implements weighted load balancing based on provider performance
type WeightedBalancer struct {
	statsProvider func() map[string]*ProviderMetrics
	mutex         sync.RWMutex
}

// NewWeightedBalancer creates a new weighted load balancer
func NewWeightedBalancer(statsProvider func() map[string]*ProviderMetrics) *WeightedBalancer {
	return &WeightedBalancer{
		statsProvider: statsProvider,
	}
}

// SelectProvider selects a provider based on performance weights
func (wb *WeightedBalancer) SelectProvider(providers []LLMProvider, request GenerationRequest) (LLMProvider, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	if len(providers) == 1 {
		return providers[0], nil
	}

	// Get provider statistics
	stats := wb.statsProvider()
	if stats == nil {
		// Fallback to round-robin if no stats available
		return providers[0], nil
	}

	// Calculate weights based on performance metrics
	weights := make([]float64, len(providers))
	totalWeight := 0.0

	for i, provider := range providers {
		weight := wb.calculateWeight(provider, stats)
		weights[i] = weight
		totalWeight += weight
	}

	if totalWeight == 0 {
		// All providers have zero weight, use first one
		return providers[0], nil
	}

	// Select provider based on weighted random selection
	target := rand.Float64() * totalWeight
	current := 0.0

	for i, weight := range weights {
		current += weight
		if current >= target {
			return providers[i], nil
		}
	}

	// Fallback to last provider
	return providers[len(providers)-1], nil
}

// calculateWeight calculates the weight for a provider based on performance metrics
func (wb *WeightedBalancer) calculateWeight(provider LLMProvider, stats map[string]*ProviderMetrics) float64 {
	// Find provider stats by matching type (simplified approach)
	var providerStats *ProviderMetrics

	for _, stat := range stats {
		// Simple heuristic: use first available stats
		if stat != nil {
			providerStats = stat
			break
		}
	}

	if providerStats == nil || !providerStats.IsHealthy {
		return 0.0
	}

	// Base weight
	weight := 1.0

	// Adjust based on error rate (lower error rate = higher weight)
	if providerStats.ErrorRate > 0 {
		weight *= (1.0 - providerStats.ErrorRate)
	}

	// Adjust based on latency (lower latency = higher weight)
	if providerStats.AverageLatency > 0 {
		// Normalize latency to a 0-1 scale (assuming max reasonable latency of 10 seconds)
		maxLatency := 10 * time.Second
		latencyFactor := 1.0 - (float64(providerStats.AverageLatency) / float64(maxLatency))
		if latencyFactor < 0 {
			latencyFactor = 0.1 // Minimum weight for very slow providers
		}
		weight *= latencyFactor
	}

	// Adjust based on consecutive errors
	if providerStats.ConsecutiveErrors > 0 {
		weight *= 1.0 / (1.0 + float64(providerStats.ConsecutiveErrors)*0.1)
	}

	return weight
}

// LeastConnectionsBalancer implements least connections load balancing
type LeastConnectionsBalancer struct {
	connections map[LLMProvider]int
	mutex       sync.RWMutex
}

// NewLeastConnectionsBalancer creates a new least connections load balancer
func NewLeastConnectionsBalancer() *LeastConnectionsBalancer {
	return &LeastConnectionsBalancer{
		connections: make(map[LLMProvider]int),
	}
}

// SelectProvider selects the provider with the least active connections
func (lb *LeastConnectionsBalancer) SelectProvider(providers []LLMProvider, request GenerationRequest) (LLMProvider, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	lb.mutex.RLock()
	defer lb.mutex.RUnlock()

	var selectedProvider LLMProvider
	minConnections := int(^uint(0) >> 1) // Max int

	for _, provider := range providers {
		connections := lb.connections[provider]
		if connections < minConnections {
			minConnections = connections
			selectedProvider = provider
		}
	}

	if selectedProvider == nil {
		selectedProvider = providers[0]
	}

	return selectedProvider, nil
}

// IncrementConnections increments the connection count for a provider
func (lb *LeastConnectionsBalancer) IncrementConnections(provider LLMProvider) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	lb.connections[provider]++
}

// DecrementConnections decrements the connection count for a provider
func (lb *LeastConnectionsBalancer) DecrementConnections(provider LLMProvider) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	if lb.connections[provider] > 0 {
		lb.connections[provider]--
	}
}

// CapabilityBasedBalancer selects providers based on request requirements
type CapabilityBasedBalancer struct {
	fallbackBalancer LoadBalancer
}

// NewCapabilityBasedBalancer creates a new capability-based load balancer
func NewCapabilityBasedBalancer(fallback LoadBalancer) *CapabilityBasedBalancer {
	if fallback == nil {
		fallback = NewRoundRobinBalancer()
	}

	return &CapabilityBasedBalancer{
		fallbackBalancer: fallback,
	}
}

// SelectProvider selects a provider based on capabilities required by the request
func (cb *CapabilityBasedBalancer) SelectProvider(providers []LLMProvider, request GenerationRequest) (LLMProvider, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	// Filter providers based on request requirements
	suitableProviders := make([]LLMProvider, 0)

	for _, provider := range providers {
		if cb.isProviderSuitable(provider, request) {
			suitableProviders = append(suitableProviders, provider)
		}
	}

	// If no suitable providers found, use all providers
	if len(suitableProviders) == 0 {
		suitableProviders = providers
	}

	// Use fallback balancer to select from suitable providers
	return cb.fallbackBalancer.SelectProvider(suitableProviders, request)
}

// isProviderSuitable checks if a provider is suitable for the request
func (cb *CapabilityBasedBalancer) isProviderSuitable(provider LLMProvider, request GenerationRequest) bool {
	model := provider.GetModel()

	// Check token limits
	estimatedTokens := cb.estimateTokens(request)
	if estimatedTokens > model.MaxTokens {
		return false
	}

	// Check context size
	if len(request.Messages) > 0 {
		totalContextTokens := 0
		for _, msg := range request.Messages {
			totalContextTokens += len(msg.Content) / 4 // Rough token estimation
		}

		if totalContextTokens > model.ContextSize {
			return false
		}
	}

	// Check capabilities if specified in request
	if requiredCapabilities, ok := request.Metadata["required_capabilities"].([]string); ok {
		for _, required := range requiredCapabilities {
			found := false
			for _, capability := range model.Capabilities {
				if capability == required {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	return true
}

// estimateTokens provides a rough estimate of tokens needed for the request
func (cb *CapabilityBasedBalancer) estimateTokens(request GenerationRequest) int {
	totalChars := 0

	for _, msg := range request.Messages {
		totalChars += len(msg.Content)
	}

	// Add max tokens for response
	totalChars += request.MaxTokens * 4 // Rough character to token ratio

	// Convert characters to tokens (rough estimation: 1 token ≈ 4 characters)
	return totalChars / 4
}

// AdaptiveBalancer combines multiple balancing strategies
type AdaptiveBalancer struct {
	strategies        []LoadBalancer
	currentStrategy   int
	performanceWindow time.Duration
	lastSwitch        time.Time
	mutex             sync.RWMutex
}

// NewAdaptiveBalancer creates a new adaptive load balancer
func NewAdaptiveBalancer(strategies []LoadBalancer, performanceWindow time.Duration) *AdaptiveBalancer {
	if len(strategies) == 0 {
		strategies = []LoadBalancer{NewRoundRobinBalancer()}
	}

	return &AdaptiveBalancer{
		strategies:        strategies,
		currentStrategy:   0,
		performanceWindow: performanceWindow,
		lastSwitch:        time.Now(),
	}
}

// SelectProvider selects a provider using the current strategy
func (ab *AdaptiveBalancer) SelectProvider(providers []LLMProvider, request GenerationRequest) (LLMProvider, error) {
	ab.mutex.RLock()
	strategy := ab.strategies[ab.currentStrategy]
	ab.mutex.RUnlock()

	return strategy.SelectProvider(providers, request)
}

// SwitchStrategy switches to a different balancing strategy
func (ab *AdaptiveBalancer) SwitchStrategy(strategyIndex int) {
	ab.mutex.Lock()
	defer ab.mutex.Unlock()

	if strategyIndex >= 0 && strategyIndex < len(ab.strategies) {
		ab.currentStrategy = strategyIndex
		ab.lastSwitch = time.Now()
	}
}

// GetCurrentStrategy returns the current strategy index
func (ab *AdaptiveBalancer) GetCurrentStrategy() int {
	ab.mutex.RLock()
	defer ab.mutex.RUnlock()
	return ab.currentStrategy
}
