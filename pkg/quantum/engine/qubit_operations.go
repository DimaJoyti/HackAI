package engine

import (
	"fmt"
	"math"
	"time"

	"github.com/dimajoyti/hackai/pkg/quantum"
)

// Single-qubit gate operations

// applyPauliX applies the Pauli-X (NOT) gate to a qubit
func (qs *QuantumSimulatorImpl) applyPauliX(target int) error {
	mask := 1 << target
	stateSize := len(qs.state.Amplitudes)

	// Apply X gate: |0⟩ ↔ |1⟩
	for i := 0; i < stateSize; i += 2 * mask {
		for j := 0; j < mask; j++ {
			idx0 := i + j
			idx1 := i + j + mask

			// Swap amplitudes
			qs.state.Amplitudes[idx0], qs.state.Amplitudes[idx1] =
				qs.state.Amplitudes[idx1], qs.state.Amplitudes[idx0]
		}
	}

	qs.operations++
	qs.updateQubitState(target)
	return nil
}

// applyPauliY applies the Pauli-Y gate to a qubit
func (qs *QuantumSimulatorImpl) applyPauliY(target int) error {
	mask := 1 << target
	stateSize := len(qs.state.Amplitudes)

	// Apply Y gate: |0⟩ → i|1⟩, |1⟩ → -i|0⟩
	for i := 0; i < stateSize; i += 2 * mask {
		for j := 0; j < mask; j++ {
			idx0 := i + j
			idx1 := i + j + mask

			// Y = iX, so swap and multiply by i and -i
			amp0 := qs.state.Amplitudes[idx0]
			amp1 := qs.state.Amplitudes[idx1]

			qs.state.Amplitudes[idx0] = quantum.Complex{
				Real: -amp1.Imag,
				Imag: amp1.Real,
			}
			qs.state.Amplitudes[idx1] = quantum.Complex{
				Real: amp0.Imag,
				Imag: -amp0.Real,
			}
		}
	}

	qs.operations++
	qs.updateQubitState(target)
	return nil
}

// applyPauliZ applies the Pauli-Z gate to a qubit
func (qs *QuantumSimulatorImpl) applyPauliZ(target int) error {
	mask := 1 << target
	stateSize := len(qs.state.Amplitudes)

	// Apply Z gate: |0⟩ → |0⟩, |1⟩ → -|1⟩
	for i := 0; i < stateSize; i++ {
		if (i & mask) != 0 {
			qs.state.Amplitudes[i].Real = -qs.state.Amplitudes[i].Real
			qs.state.Amplitudes[i].Imag = -qs.state.Amplitudes[i].Imag
		}
	}

	qs.operations++
	qs.updateQubitState(target)
	return nil
}

// applyHadamard applies the Hadamard gate to a qubit
func (qs *QuantumSimulatorImpl) applyHadamard(target int) error {
	mask := 1 << target
	stateSize := len(qs.state.Amplitudes)
	invSqrt2 := 1.0 / math.Sqrt(2.0)

	// Apply H gate: |0⟩ → (|0⟩ + |1⟩)/√2, |1⟩ → (|0⟩ - |1⟩)/√2
	for i := 0; i < stateSize; i += 2 * mask {
		for j := 0; j < mask; j++ {
			idx0 := i + j
			idx1 := i + j + mask

			amp0 := qs.state.Amplitudes[idx0]
			amp1 := qs.state.Amplitudes[idx1]

			qs.state.Amplitudes[idx0] = quantum.Complex{
				Real: invSqrt2 * (amp0.Real + amp1.Real),
				Imag: invSqrt2 * (amp0.Imag + amp1.Imag),
			}
			qs.state.Amplitudes[idx1] = quantum.Complex{
				Real: invSqrt2 * (amp0.Real - amp1.Real),
				Imag: invSqrt2 * (amp0.Imag - amp1.Imag),
			}
		}
	}

	qs.operations++
	qs.updateQubitState(target)
	return nil
}

// applyPhaseGate applies the S (Phase) gate to a qubit
func (qs *QuantumSimulatorImpl) applyPhaseGate(target int) error {
	mask := 1 << target
	stateSize := len(qs.state.Amplitudes)

	// Apply S gate: |0⟩ → |0⟩, |1⟩ → i|1⟩
	for i := 0; i < stateSize; i++ {
		if (i & mask) != 0 {
			amp := qs.state.Amplitudes[i]
			qs.state.Amplitudes[i] = quantum.Complex{
				Real: -amp.Imag,
				Imag: amp.Real,
			}
		}
	}

	qs.operations++
	qs.updateQubitState(target)
	return nil
}

// applyTGate applies the T gate to a qubit
func (qs *QuantumSimulatorImpl) applyTGate(target int) error {
	mask := 1 << target
	stateSize := len(qs.state.Amplitudes)
	invSqrt2 := 1.0 / math.Sqrt(2.0)

	// Apply T gate: |0⟩ → |0⟩, |1⟩ → e^(iπ/4)|1⟩
	for i := 0; i < stateSize; i++ {
		if (i & mask) != 0 {
			amp := qs.state.Amplitudes[i]
			qs.state.Amplitudes[i] = quantum.Complex{
				Real: invSqrt2 * (amp.Real - amp.Imag),
				Imag: invSqrt2 * (amp.Real + amp.Imag),
			}
		}
	}

	qs.operations++
	qs.updateQubitState(target)
	return nil
}

// Rotation gates

// applyRotationX applies rotation around X-axis
func (qs *QuantumSimulatorImpl) applyRotationX(target int, angle float64) error {
	mask := 1 << target
	stateSize := len(qs.state.Amplitudes)
	cosHalf := math.Cos(angle / 2.0)
	sinHalf := math.Sin(angle / 2.0)

	// Apply RX gate
	for i := 0; i < stateSize; i += 2 * mask {
		for j := 0; j < mask; j++ {
			idx0 := i + j
			idx1 := i + j + mask

			amp0 := qs.state.Amplitudes[idx0]
			amp1 := qs.state.Amplitudes[idx1]

			qs.state.Amplitudes[idx0] = quantum.Complex{
				Real: cosHalf*amp0.Real + sinHalf*amp1.Imag,
				Imag: cosHalf*amp0.Imag - sinHalf*amp1.Real,
			}
			qs.state.Amplitudes[idx1] = quantum.Complex{
				Real: cosHalf*amp1.Real + sinHalf*amp0.Imag,
				Imag: cosHalf*amp1.Imag - sinHalf*amp0.Real,
			}
		}
	}

	qs.operations++
	qs.updateQubitState(target)
	return nil
}

// applyRotationY applies rotation around Y-axis
func (qs *QuantumSimulatorImpl) applyRotationY(target int, angle float64) error {
	mask := 1 << target
	stateSize := len(qs.state.Amplitudes)
	cosHalf := math.Cos(angle / 2.0)
	sinHalf := math.Sin(angle / 2.0)

	// Apply RY gate
	for i := 0; i < stateSize; i += 2 * mask {
		for j := 0; j < mask; j++ {
			idx0 := i + j
			idx1 := i + j + mask

			amp0 := qs.state.Amplitudes[idx0]
			amp1 := qs.state.Amplitudes[idx1]

			qs.state.Amplitudes[idx0] = quantum.Complex{
				Real: cosHalf*amp0.Real - sinHalf*amp1.Real,
				Imag: cosHalf*amp0.Imag - sinHalf*amp1.Imag,
			}
			qs.state.Amplitudes[idx1] = quantum.Complex{
				Real: cosHalf*amp1.Real + sinHalf*amp0.Real,
				Imag: cosHalf*amp1.Imag + sinHalf*amp0.Imag,
			}
		}
	}

	qs.operations++
	qs.updateQubitState(target)
	return nil
}

// applyRotationZ applies rotation around Z-axis
func (qs *QuantumSimulatorImpl) applyRotationZ(target int, angle float64) error {
	mask := 1 << target
	stateSize := len(qs.state.Amplitudes)
	cosHalf := math.Cos(angle / 2.0)
	sinHalf := math.Sin(angle / 2.0)

	// Apply RZ gate
	for i := 0; i < stateSize; i++ {
		if (i & mask) == 0 {
			// |0⟩ component: multiply by e^(-iθ/2)
			amp := qs.state.Amplitudes[i]
			qs.state.Amplitudes[i] = quantum.Complex{
				Real: cosHalf*amp.Real + sinHalf*amp.Imag,
				Imag: cosHalf*amp.Imag - sinHalf*amp.Real,
			}
		} else {
			// |1⟩ component: multiply by e^(iθ/2)
			amp := qs.state.Amplitudes[i]
			qs.state.Amplitudes[i] = quantum.Complex{
				Real: cosHalf*amp.Real - sinHalf*amp.Imag,
				Imag: cosHalf*amp.Imag + sinHalf*amp.Real,
			}
		}
	}

	qs.operations++
	qs.updateQubitState(target)
	return nil
}

// Two-qubit gate operations

// applyCNOT applies the CNOT (Controlled-NOT) gate
func (qs *QuantumSimulatorImpl) applyCNOT(control, target int) error {
	if control == target {
		return fmt.Errorf("control and target qubits must be different")
	}

	controlMask := 1 << control
	targetMask := 1 << target
	stateSize := len(qs.state.Amplitudes)

	// Apply CNOT: if control is |1⟩, flip target
	for i := 0; i < stateSize; i++ {
		if (i & controlMask) != 0 {
			// Control is |1⟩, so flip target
			j := i ^ targetMask
			if i < j {
				qs.state.Amplitudes[i], qs.state.Amplitudes[j] =
					qs.state.Amplitudes[j], qs.state.Amplitudes[i]
			}
		}
	}

	qs.operations++
	qs.updateQubitState(control)
	qs.updateQubitState(target)
	qs.markEntangled(control, target)
	return nil
}

// applyCZ applies the Controlled-Z gate
func (qs *QuantumSimulatorImpl) applyCZ(control, target int) error {
	if control == target {
		return fmt.Errorf("control and target qubits must be different")
	}

	controlMask := 1 << control
	targetMask := 1 << target
	stateSize := len(qs.state.Amplitudes)

	// Apply CZ: if both control and target are |1⟩, apply phase
	for i := 0; i < stateSize; i++ {
		if (i&controlMask) != 0 && (i&targetMask) != 0 {
			qs.state.Amplitudes[i].Real = -qs.state.Amplitudes[i].Real
			qs.state.Amplitudes[i].Imag = -qs.state.Amplitudes[i].Imag
		}
	}

	qs.operations++
	qs.updateQubitState(control)
	qs.updateQubitState(target)
	qs.markEntangled(control, target)
	return nil
}

// Helper methods

// updateQubitState updates the individual qubit state representation
func (qs *QuantumSimulatorImpl) updateQubitState(qubitIndex int) {
	qubitID := fmt.Sprintf("q%d", qubitIndex)
	if qubit, exists := qs.state.Qubits[qubitID]; exists {
		// Calculate individual qubit amplitudes from global state
		// This is an approximation for entangled states
		prob0, prob1 := qs.calculateQubitProbabilities(qubitIndex)

		qubit.Alpha = quantum.Complex{Real: math.Sqrt(prob0), Imag: 0.0}
		qubit.Beta = quantum.Complex{Real: math.Sqrt(prob1), Imag: 0.0}
		qubit.ModifiedAt = time.Now()
	}
}

// calculateQubitProbabilities calculates the probabilities for a single qubit
func (qs *QuantumSimulatorImpl) calculateQubitProbabilities(qubitIndex int) (float64, float64) {
	mask := 1 << qubitIndex
	prob0, prob1 := 0.0, 0.0

	for i, amp := range qs.state.Amplitudes {
		prob := amp.Real*amp.Real + amp.Imag*amp.Imag
		if (i & mask) == 0 {
			prob0 += prob
		} else {
			prob1 += prob
		}
	}

	return prob0, prob1
}

// markEntangled marks two qubits as entangled
func (qs *QuantumSimulatorImpl) markEntangled(qubit1, qubit2 int) {
	id1 := fmt.Sprintf("q%d", qubit1)
	id2 := fmt.Sprintf("q%d", qubit2)

	if q1, exists := qs.state.Qubits[id1]; exists {
		q1.Entangled = true
		if !contains(q1.Partners, id2) {
			q1.Partners = append(q1.Partners, id2)
		}
	}

	if q2, exists := qs.state.Qubits[id2]; exists {
		q2.Entangled = true
		if !contains(q2.Partners, id1) {
			q2.Partners = append(q2.Partners, id1)
		}
	}

	qs.state.Entangled = true
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
