package quantum

import (
	"context"
	"math/big"
	"time"
)

// Complex represents a complex number for quantum state amplitudes
type Complex struct {
	Real float64 `json:"real"`
	Imag float64 `json:"imag"`
}

// Qubit represents a quantum bit with its state amplitudes
type Qubit struct {
	ID         string    `json:"id"`
	Alpha      Complex   `json:"alpha"`      // Amplitude for |0⟩ state
	Beta       Complex   `json:"beta"`       // Amplitude for |1⟩ state
	Entangled  bool      `json:"entangled"`
	Partners   []string  `json:"partners"`   // IDs of entangled qubits
	CreatedAt  time.Time `json:"created_at"`
	ModifiedAt time.Time `json:"modified_at"`
}

// QuantumState represents the state of a quantum system
type QuantumState struct {
	Qubits      map[string]*Qubit `json:"qubits"`
	Amplitudes  []Complex         `json:"amplitudes"`  // State vector amplitudes
	NumQubits   int               `json:"num_qubits"`
	Entangled   bool              `json:"entangled"`
	Measured    bool              `json:"measured"`
	CreatedAt   time.Time         `json:"created_at"`
	ModifiedAt  time.Time         `json:"modified_at"`
}

// QuantumGate represents a quantum gate operation
type QuantumGate struct {
	Name        string      `json:"name"`
	Type        GateType    `json:"type"`
	Matrix      [][]Complex `json:"matrix"`      // Gate matrix representation
	Targets     []int       `json:"targets"`     // Target qubit indices
	Controls    []int       `json:"controls"`    // Control qubit indices
	Parameters  []float64   `json:"parameters"`  // Gate parameters (angles, etc.)
	Description string      `json:"description"`
}

// GateType represents different types of quantum gates
type GateType string

const (
	// Single-qubit gates
	GateTypeX        GateType = "X"        // Pauli-X (NOT gate)
	GateTypeY        GateType = "Y"        // Pauli-Y
	GateTypeZ        GateType = "Z"        // Pauli-Z
	GateTypeH        GateType = "H"        // Hadamard
	GateTypeS        GateType = "S"        // Phase gate
	GateTypeT        GateType = "T"        // T gate
	GateTypeRX       GateType = "RX"       // Rotation around X-axis
	GateTypeRY       GateType = "RY"       // Rotation around Y-axis
	GateTypeRZ       GateType = "RZ"       // Rotation around Z-axis
	GateTypePhase    GateType = "PHASE"    // Phase shift gate
	
	// Two-qubit gates
	GateTypeCNOT     GateType = "CNOT"     // Controlled-NOT
	GateTypeCZ       GateType = "CZ"       // Controlled-Z
	GateTypeSWAP     GateType = "SWAP"     // SWAP gate
	GateTypeISWAP    GateType = "ISWAP"    // iSWAP gate
	
	// Multi-qubit gates
	GateTypeToffoli  GateType = "TOFFOLI"  // Toffoli (CCNOT)
	GateTypeFredkin  GateType = "FREDKIN"  // Fredkin (CSWAP)
	
	// Special gates for algorithms
	GateTypeQFT      GateType = "QFT"      // Quantum Fourier Transform
	GateTypeIQFT     GateType = "IQFT"     // Inverse QFT
	GateTypeOracle   GateType = "ORACLE"   // Oracle function
)

// QuantumCircuit represents a quantum circuit
type QuantumCircuit struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	NumQubits   int            `json:"num_qubits"`
	Gates       []*QuantumGate `json:"gates"`
	Depth       int            `json:"depth"`
	CreatedAt   time.Time      `json:"created_at"`
	ModifiedAt  time.Time      `json:"modified_at"`
}

// QuantumAlgorithm represents a quantum algorithm implementation
type QuantumAlgorithm struct {
	Name        string                 `json:"name"`
	Type        AlgorithmType          `json:"type"`
	Description string                 `json:"description"`
	Circuit     *QuantumCircuit        `json:"circuit"`
	Parameters  map[string]interface{} `json:"parameters"`
	Complexity  *ComplexityAnalysis    `json:"complexity"`
	Target      *CryptographicTarget   `json:"target"`
}

// AlgorithmType represents different quantum algorithms
type AlgorithmType string

const (
	AlgorithmTypeShor     AlgorithmType = "SHOR"     // Shor's factoring algorithm
	AlgorithmTypeGrover   AlgorithmType = "GROVER"   // Grover's search algorithm
	AlgorithmTypeQPE      AlgorithmType = "QPE"      // Quantum Phase Estimation
	AlgorithmTypeQFT      AlgorithmType = "QFT"      // Quantum Fourier Transform
	AlgorithmTypeDeutsch  AlgorithmType = "DEUTSCH"  // Deutsch-Jozsa algorithm
	AlgorithmTypeSimon    AlgorithmType = "SIMON"    // Simon's algorithm
	AlgorithmTypeBV       AlgorithmType = "BV"       // Bernstein-Vazirani
)

// ComplexityAnalysis represents algorithm complexity analysis
type ComplexityAnalysis struct {
	ClassicalTime   string  `json:"classical_time"`   // Classical time complexity
	QuantumTime     string  `json:"quantum_time"`     // Quantum time complexity
	SpaceComplexity string  `json:"space_complexity"` // Space complexity
	QuantumAdvantage string `json:"quantum_advantage"` // Speedup description
	Probability     float64 `json:"probability"`      // Success probability
}

// CryptographicTarget represents a cryptographic system to attack
type CryptographicTarget struct {
	Type        CryptoType             `json:"type"`
	Algorithm   string                 `json:"algorithm"`
	KeySize     int                    `json:"key_size"`
	Parameters  map[string]interface{} `json:"parameters"`
	SecurityLevel int                  `json:"security_level"`
	PostQuantum bool                   `json:"post_quantum"`
}

// CryptoType represents different cryptographic systems
type CryptoType string

const (
	CryptoTypeRSA        CryptoType = "RSA"
	CryptoTypeECC        CryptoType = "ECC"
	CryptoTypeDH         CryptoType = "DH"
	CryptoTypeAES        CryptoType = "AES"
	CryptoTypeLattice    CryptoType = "LATTICE"
	CryptoTypeHash       CryptoType = "HASH"
	CryptoTypeCode       CryptoType = "CODE"
	CryptoTypeMultivar   CryptoType = "MULTIVARIATE"
)

// QuantumAttackResult represents the result of a quantum attack simulation
type QuantumAttackResult struct {
	AttackID      string                 `json:"attack_id"`
	Algorithm     AlgorithmType          `json:"algorithm"`
	Target        *CryptographicTarget   `json:"target"`
	Success       bool                   `json:"success"`
	TimeEstimate  time.Duration          `json:"time_estimate"`
	QubitsRequired int                   `json:"qubits_required"`
	GatesRequired  int                   `json:"gates_required"`
	SuccessProb    float64               `json:"success_probability"`
	Result         map[string]interface{} `json:"result"`
	Metadata       map[string]interface{} `json:"metadata"`
	StartTime      time.Time             `json:"start_time"`
	EndTime        time.Time             `json:"end_time"`
}

// QuantumSimulator interface defines quantum simulation capabilities
type QuantumSimulator interface {
	// State management
	InitializeState(numQubits int) (*QuantumState, error)
	GetState() *QuantumState
	ResetState() error
	
	// Gate operations
	ApplyGate(gate *QuantumGate) error
	ApplyCircuit(circuit *QuantumCircuit) error
	
	// Measurement
	Measure(qubitIndex int) (int, error)
	MeasureAll() ([]int, error)
	
	// Algorithms
	RunShor(ctx context.Context, n *big.Int) (*QuantumAttackResult, error)
	RunGrover(ctx context.Context, oracle func([]int) bool, numItems int) (*QuantumAttackResult, error)
	RunQPE(ctx context.Context, unitary [][]Complex, eigenstate []Complex) (*QuantumAttackResult, error)
}

// CryptographicAnalyzer interface defines cryptographic analysis capabilities
type CryptographicAnalyzer interface {
	// Vulnerability assessment
	AnalyzeVulnerability(target *CryptographicTarget) (*VulnerabilityReport, error)
	EstimateQuantumThreat(target *CryptographicTarget) (*ThreatAssessment, error)
	
	// Attack simulation
	SimulateAttack(ctx context.Context, algorithm AlgorithmType, target *CryptographicTarget) (*QuantumAttackResult, error)
	
	// Post-quantum analysis
	AssessPostQuantumSecurity(algorithm string, parameters map[string]interface{}) (*SecurityAssessment, error)
}

// VulnerabilityReport represents a cryptographic vulnerability assessment
type VulnerabilityReport struct {
	TargetID        string                 `json:"target_id"`
	VulnerabilityLevel string              `json:"vulnerability_level"`
	QuantumThreat   bool                   `json:"quantum_threat"`
	Recommendations []string               `json:"recommendations"`
	TimeToBreak     time.Duration          `json:"time_to_break"`
	Details         map[string]interface{} `json:"details"`
	GeneratedAt     time.Time              `json:"generated_at"`
}

// ThreatAssessment represents quantum threat assessment
type ThreatAssessment struct {
	ThreatLevel     string    `json:"threat_level"`
	ImmediateThreat bool      `json:"immediate_threat"`
	TimeHorizon     string    `json:"time_horizon"`
	Mitigation      []string  `json:"mitigation"`
	AssessedAt      time.Time `json:"assessed_at"`
}

// SecurityAssessment represents post-quantum security assessment
type SecurityAssessment struct {
	Algorithm       string                 `json:"algorithm"`
	SecurityLevel   int                    `json:"security_level"`
	QuantumSafe     bool                   `json:"quantum_safe"`
	Confidence      float64                `json:"confidence"`
	Limitations     []string               `json:"limitations"`
	Parameters      map[string]interface{} `json:"parameters"`
	AssessedAt      time.Time              `json:"assessed_at"`
}
