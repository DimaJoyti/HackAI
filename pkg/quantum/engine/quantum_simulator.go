package engine

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/quantum"
)

// QuantumSimulatorImpl implements the QuantumSimulator interface
type QuantumSimulatorImpl struct {
	state      *quantum.QuantumState
	logger     *logger.Logger
	mutex      sync.RWMutex
	config     *SimulatorConfig
	random     *rand.Rand
	operations int64 // Track number of operations for complexity analysis
}

// SimulatorConfig holds configuration for the quantum simulator
type SimulatorConfig struct {
	MaxQubits       int           `json:"max_qubits"`
	Precision       float64       `json:"precision"`
	Timeout         time.Duration `json:"timeout"`
	EnableLogging   bool          `json:"enable_logging"`
	RandomSeed      int64         `json:"random_seed"`
	OptimizeMemory  bool          `json:"optimize_memory"`
}

// NewQuantumSimulator creates a new quantum simulator instance
func NewQuantumSimulator(config *SimulatorConfig, logger *logger.Logger) *QuantumSimulatorImpl {
	if config == nil {
		config = &SimulatorConfig{
			MaxQubits:      20, // Reasonable limit for simulation
			Precision:      1e-10,
			Timeout:        30 * time.Second,
			EnableLogging:  true,
			RandomSeed:     time.Now().UnixNano(),
			OptimizeMemory: true,
		}
	}

	return &QuantumSimulatorImpl{
		logger: logger,
		config: config,
		random: rand.New(rand.NewSource(config.RandomSeed)),
	}
}

// InitializeState initializes a quantum state with the specified number of qubits
func (qs *QuantumSimulatorImpl) InitializeState(numQubits int) (*quantum.QuantumState, error) {
	qs.mutex.Lock()
	defer qs.mutex.Unlock()

	if numQubits > qs.config.MaxQubits {
		return nil, fmt.Errorf("number of qubits (%d) exceeds maximum allowed (%d)", numQubits, qs.config.MaxQubits)
	}

	if numQubits <= 0 {
		return nil, fmt.Errorf("number of qubits must be positive")
	}

	// Initialize state vector for |00...0⟩ state
	stateSize := 1 << numQubits // 2^numQubits
	amplitudes := make([]quantum.Complex, stateSize)
	amplitudes[0] = quantum.Complex{Real: 1.0, Imag: 0.0} // |00...0⟩ state

	// Initialize individual qubits
	qubits := make(map[string]*quantum.Qubit)
	for i := 0; i < numQubits; i++ {
		qubitID := fmt.Sprintf("q%d", i)
		qubits[qubitID] = &quantum.Qubit{
			ID:         qubitID,
			Alpha:      quantum.Complex{Real: 1.0, Imag: 0.0}, // |0⟩ state
			Beta:       quantum.Complex{Real: 0.0, Imag: 0.0},
			Entangled:  false,
			Partners:   make([]string, 0),
			CreatedAt:  time.Now(),
			ModifiedAt: time.Now(),
		}
	}

	qs.state = &quantum.QuantumState{
		Qubits:     qubits,
		Amplitudes: amplitudes,
		NumQubits:  numQubits,
		Entangled:  false,
		Measured:   false,
		CreatedAt:  time.Now(),
		ModifiedAt: time.Now(),
	}

	if qs.config.EnableLogging {
		qs.logger.Info("Quantum state initialized", map[string]interface{}{
			"num_qubits":  numQubits,
			"state_size":  stateSize,
			"initialized": true,
		})
	}

	return qs.state, nil
}

// GetState returns the current quantum state
func (qs *QuantumSimulatorImpl) GetState() *quantum.QuantumState {
	qs.mutex.RLock()
	defer qs.mutex.RUnlock()
	return qs.state
}

// ResetState resets the quantum state to |00...0⟩
func (qs *QuantumSimulatorImpl) ResetState() error {
	qs.mutex.Lock()
	defer qs.mutex.Unlock()

	if qs.state == nil {
		return fmt.Errorf("no state to reset")
	}

	// Reset to |00...0⟩ state
	for i := range qs.state.Amplitudes {
		qs.state.Amplitudes[i] = quantum.Complex{Real: 0.0, Imag: 0.0}
	}
	qs.state.Amplitudes[0] = quantum.Complex{Real: 1.0, Imag: 0.0}

	// Reset individual qubits
	for _, qubit := range qs.state.Qubits {
		qubit.Alpha = quantum.Complex{Real: 1.0, Imag: 0.0}
		qubit.Beta = quantum.Complex{Real: 0.0, Imag: 0.0}
		qubit.Entangled = false
		qubit.Partners = make([]string, 0)
		qubit.ModifiedAt = time.Now()
	}

	qs.state.Entangled = false
	qs.state.Measured = false
	qs.state.ModifiedAt = time.Now()
	qs.operations = 0

	return nil
}

// ApplyGate applies a quantum gate to the current state
func (qs *QuantumSimulatorImpl) ApplyGate(gate *quantum.QuantumGate) error {
	qs.mutex.Lock()
	defer qs.mutex.Unlock()

	if qs.state == nil {
		return fmt.Errorf("no quantum state initialized")
	}

	if err := qs.validateGate(gate); err != nil {
		return fmt.Errorf("invalid gate: %w", err)
	}

	// Apply gate based on type
	switch gate.Type {
	case quantum.GateTypeX:
		return qs.applyPauliX(gate.Targets[0])
	case quantum.GateTypeY:
		return qs.applyPauliY(gate.Targets[0])
	case quantum.GateTypeZ:
		return qs.applyPauliZ(gate.Targets[0])
	case quantum.GateTypeH:
		return qs.applyHadamard(gate.Targets[0])
	case quantum.GateTypeS:
		return qs.applyPhaseGate(gate.Targets[0])
	case quantum.GateTypeT:
		return qs.applyTGate(gate.Targets[0])
	case quantum.GateTypeCNOT:
		return qs.applyCNOT(gate.Controls[0], gate.Targets[0])
	case quantum.GateTypeCZ:
		return qs.applyCZ(gate.Controls[0], gate.Targets[0])
	case quantum.GateTypeRX:
		return qs.applyRotationX(gate.Targets[0], gate.Parameters[0])
	case quantum.GateTypeRY:
		return qs.applyRotationY(gate.Targets[0], gate.Parameters[0])
	case quantum.GateTypeRZ:
		return qs.applyRotationZ(gate.Targets[0], gate.Parameters[0])
	default:
		return fmt.Errorf("unsupported gate type: %s", gate.Type)
	}
}

// ApplyCircuit applies a complete quantum circuit
func (qs *QuantumSimulatorImpl) ApplyCircuit(circuit *quantum.QuantumCircuit) error {
	if circuit == nil {
		return fmt.Errorf("circuit cannot be nil")
	}

	if qs.config.EnableLogging {
		qs.logger.Info("Applying quantum circuit", map[string]interface{}{
			"circuit_id":   circuit.ID,
			"circuit_name": circuit.Name,
			"num_gates":    len(circuit.Gates),
			"depth":        circuit.Depth,
		})
	}

	startTime := time.Now()
	for i, gate := range circuit.Gates {
		if err := qs.ApplyGate(gate); err != nil {
			return fmt.Errorf("failed to apply gate %d (%s): %w", i, gate.Name, err)
		}
	}

	if qs.config.EnableLogging {
		qs.logger.Info("Circuit applied successfully", map[string]interface{}{
			"circuit_id":     circuit.ID,
			"execution_time": time.Since(startTime),
			"operations":     qs.operations,
		})
	}

	return nil
}

// Measure performs a measurement on a specific qubit
func (qs *QuantumSimulatorImpl) Measure(qubitIndex int) (int, error) {
	qs.mutex.Lock()
	defer qs.mutex.Unlock()

	if qs.state == nil {
		return 0, fmt.Errorf("no quantum state initialized")
	}

	if qubitIndex < 0 || qubitIndex >= qs.state.NumQubits {
		return 0, fmt.Errorf("qubit index %d out of range [0, %d)", qubitIndex, qs.state.NumQubits)
	}

	// Calculate probability of measuring |1⟩
	prob1 := qs.calculateMeasurementProbability(qubitIndex)
	
	// Perform measurement based on probability
	measurement := 0
	if qs.random.Float64() < prob1 {
		measurement = 1
	}

	// Collapse the state based on measurement
	if err := qs.collapseState(qubitIndex, measurement); err != nil {
		return 0, fmt.Errorf("failed to collapse state: %w", err)
	}

	qs.state.Measured = true
	qs.state.ModifiedAt = time.Now()

	if qs.config.EnableLogging {
		qs.logger.Info("Qubit measured", map[string]interface{}{
			"qubit_index": qubitIndex,
			"result":      measurement,
			"probability": prob1,
		})
	}

	return measurement, nil
}

// MeasureAll performs measurement on all qubits
func (qs *QuantumSimulatorImpl) MeasureAll() ([]int, error) {
	qs.mutex.Lock()
	defer qs.mutex.Unlock()

	if qs.state == nil {
		return nil, fmt.Errorf("no quantum state initialized")
	}

	results := make([]int, qs.state.NumQubits)
	
	// Calculate probabilities for all computational basis states
	probabilities := make([]float64, len(qs.state.Amplitudes))
	for i, amp := range qs.state.Amplitudes {
		probabilities[i] = amp.Real*amp.Real + amp.Imag*amp.Imag
	}

	// Sample from the probability distribution
	r := qs.random.Float64()
	cumulative := 0.0
	selectedState := 0

	for i, prob := range probabilities {
		cumulative += prob
		if r <= cumulative {
			selectedState = i
			break
		}
	}

	// Convert selected state to binary representation
	for i := 0; i < qs.state.NumQubits; i++ {
		results[i] = (selectedState >> i) & 1
	}

	// Collapse to the measured state
	for i := range qs.state.Amplitudes {
		qs.state.Amplitudes[i] = quantum.Complex{Real: 0.0, Imag: 0.0}
	}
	qs.state.Amplitudes[selectedState] = quantum.Complex{Real: 1.0, Imag: 0.0}

	qs.state.Measured = true
	qs.state.ModifiedAt = time.Now()

	if qs.config.EnableLogging {
		qs.logger.Info("All qubits measured", map[string]interface{}{
			"results":        results,
			"selected_state": selectedState,
		})
	}

	return results, nil
}

// Helper methods for gate operations

func (qs *QuantumSimulatorImpl) validateGate(gate *quantum.QuantumGate) error {
	if gate == nil {
		return fmt.Errorf("gate cannot be nil")
	}

	// Validate target qubits
	for _, target := range gate.Targets {
		if target < 0 || target >= qs.state.NumQubits {
			return fmt.Errorf("target qubit %d out of range", target)
		}
	}

	// Validate control qubits
	for _, control := range gate.Controls {
		if control < 0 || control >= qs.state.NumQubits {
			return fmt.Errorf("control qubit %d out of range", control)
		}
	}

	return nil
}

func (qs *QuantumSimulatorImpl) calculateMeasurementProbability(qubitIndex int) float64 {
	prob1 := 0.0
	mask := 1 << qubitIndex

	for i, amp := range qs.state.Amplitudes {
		if (i & mask) != 0 {
			prob1 += amp.Real*amp.Real + amp.Imag*amp.Imag
		}
	}

	return prob1
}

func (qs *QuantumSimulatorImpl) collapseState(qubitIndex int, measurement int) error {
	mask := 1 << qubitIndex
	norm := 0.0

	// Calculate normalization factor
	for i, amp := range qs.state.Amplitudes {
		if ((i & mask) != 0) == (measurement == 1) {
			norm += amp.Real*amp.Real + amp.Imag*amp.Imag
		}
	}

	if norm == 0 {
		return fmt.Errorf("invalid measurement: zero probability")
	}

	norm = math.Sqrt(norm)

	// Collapse and renormalize
	for i := range qs.state.Amplitudes {
		if ((i & mask) != 0) == (measurement == 1) {
			qs.state.Amplitudes[i].Real /= norm
			qs.state.Amplitudes[i].Imag /= norm
		} else {
			qs.state.Amplitudes[i] = quantum.Complex{Real: 0.0, Imag: 0.0}
		}
	}

	return nil
}
