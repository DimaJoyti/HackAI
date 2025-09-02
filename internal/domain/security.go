package domain

import (
	"time"

	"github.com/google/uuid"
)

// VulnerabilityScan represents a security vulnerability scan
type VulnerabilityScan struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID      uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index"`
	Target      string     `json:"target" gorm:"not null"` // URL, IP, domain
	ScanType    ScanType   `json:"scan_type" gorm:"not null"`
	Status      ScanStatus `json:"status" gorm:"default:'pending'"`
	Progress    int        `json:"progress" gorm:"default:0"` // 0-100
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Duration    int64      `json:"duration"` // milliseconds

	// Results
	TotalVulnerabilities int `json:"total_vulnerabilities" gorm:"default:0"`
	CriticalCount        int `json:"critical_count" gorm:"default:0"`
	HighCount            int `json:"high_count" gorm:"default:0"`
	MediumCount          int `json:"medium_count" gorm:"default:0"`
	LowCount             int `json:"low_count" gorm:"default:0"`
	InfoCount            int `json:"info_count" gorm:"default:0"`

	// Configuration
	Config ScanConfig `json:"config" gorm:"type:jsonb"`

	// Audit fields
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	User            User            `json:"user" gorm:"foreignKey:UserID"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities" gorm:"foreignKey:ScanID"`
}

// ScanType defines the type of security scan
type ScanType string

const (
	ScanTypeWeb       ScanType = "web"
	ScanTypeNetwork   ScanType = "network"
	ScanTypePort      ScanType = "port"
	ScanTypeSSL       ScanType = "ssl"
	ScanTypeDNS       ScanType = "dns"
	ScanTypeSubdomain ScanType = "subdomain"
	ScanTypeDirectory ScanType = "directory"
	ScanTypeAPI       ScanType = "api"
)

// ScanStatus defines the status of a scan
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

// ScanConfig holds scan configuration
type ScanConfig struct {
	Timeout         int               `json:"timeout"` // seconds
	MaxDepth        int               `json:"max_depth"`
	FollowRedirects bool              `json:"follow_redirects"`
	UserAgent       string            `json:"user_agent"`
	Headers         map[string]string `json:"headers"`
	ExcludePatterns []string          `json:"exclude_patterns"`
	IncludePatterns []string          `json:"include_patterns"`
	RateLimit       int               `json:"rate_limit"` // requests per second
}

// Vulnerability represents a discovered security vulnerability
type Vulnerability struct {
	ID          uuid.UUID         `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ScanID      uuid.UUID         `json:"scan_id" gorm:"type:uuid;not null;index"`
	Type        VulnerabilityType `json:"type" gorm:"not null"`
	Severity    Severity          `json:"severity" gorm:"not null"`
	Title       string            `json:"title" gorm:"not null"`
	Description string            `json:"description"`

	// Location information
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Method    string `json:"method"`
	Evidence  string `json:"evidence"`

	// Technical details
	CWE   string  `json:"cwe"`   // Common Weakness Enumeration
	OWASP string  `json:"owasp"` // OWASP Top 10 category
	CVE   string  `json:"cve"`   // Common Vulnerabilities and Exposures
	CVSS  float64 `json:"cvss"`  // Common Vulnerability Scoring System

	// Remediation
	Solution   string   `json:"solution"`
	References []string `json:"references" gorm:"type:jsonb"`

	// Status
	Status     VulnStatus `json:"status" gorm:"default:'open'"`
	FixedAt    *time.Time `json:"fixed_at"`
	VerifiedAt *time.Time `json:"verified_at"`

	// Audit fields
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Scan VulnerabilityScan `json:"scan" gorm:"foreignKey:ScanID"`
}

// VulnerabilityType defines types of vulnerabilities
type VulnerabilityType string

const (
	VulnTypeSQLInjection     VulnerabilityType = "sql_injection"
	VulnTypeXSS              VulnerabilityType = "xss"
	VulnTypeCSRF             VulnerabilityType = "csrf"
	VulnTypeOpenRedirect     VulnerabilityType = "open_redirect"
	VulnTypePathTraversal    VulnerabilityType = "path_traversal"
	VulnTypeCommandInjection VulnerabilityType = "command_injection"
	VulnTypeFileUpload       VulnerabilityType = "file_upload"
	VulnTypeAuthBypass       VulnerabilityType = "auth_bypass"
	VulnTypeInfoDisclosure   VulnerabilityType = "info_disclosure"
	VulnTypeSSLIssue         VulnerabilityType = "ssl_issue"
	VulnTypeMisconfiguration VulnerabilityType = "misconfiguration"
)

// Severity defines vulnerability severity levels
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// VulnStatus defines vulnerability status
type VulnStatus string

const (
	VulnStatusOpen          VulnStatus = "open"
	VulnStatusFixed         VulnStatus = "fixed"
	VulnStatusVerified      VulnStatus = "verified"
	VulnStatusIgnored       VulnStatus = "ignored"
	VulnStatusFalsePositive VulnStatus = "false_positive"
)

// NetworkScan represents a network security scan
type NetworkScan struct {
	ID          uuid.UUID       `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID      uuid.UUID       `json:"user_id" gorm:"type:uuid;not null;index"`
	Target      string          `json:"target" gorm:"not null"` // IP range, CIDR
	ScanType    NetworkScanType `json:"scan_type" gorm:"not null"`
	Status      ScanStatus      `json:"status" gorm:"default:'pending'"`
	Progress    int             `json:"progress" gorm:"default:0"`
	StartedAt   *time.Time      `json:"started_at"`
	CompletedAt *time.Time      `json:"completed_at"`
	Duration    int64           `json:"duration"`

	// Results
	HostsFound    int `json:"hosts_found" gorm:"default:0"`
	PortsFound    int `json:"ports_found" gorm:"default:0"`
	ServicesFound int `json:"services_found" gorm:"default:0"`

	// Configuration
	Config NetworkScanConfig `json:"config" gorm:"type:jsonb"`

	// Audit fields
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	User  User          `json:"user" gorm:"foreignKey:UserID"`
	Hosts []NetworkHost `json:"hosts" gorm:"foreignKey:ScanID"`
}

// NetworkScanType defines types of network scans
type NetworkScanType string

const (
	NetworkScanTypePing        NetworkScanType = "ping"
	NetworkScanTypePortScan    NetworkScanType = "port_scan"
	NetworkScanTypeServiceScan NetworkScanType = "service_scan"
	NetworkScanTypeOSScan      NetworkScanType = "os_scan"
	NetworkScanTypeFullScan    NetworkScanType = "full_scan"
)

// NetworkScanConfig holds network scan configuration
type NetworkScanConfig struct {
	Timeout          int    `json:"timeout"`
	Threads          int    `json:"threads"`
	PortRange        string `json:"port_range"`
	ScanTCP          bool   `json:"scan_tcp"`
	ScanUDP          bool   `json:"scan_udp"`
	OSDetection      bool   `json:"os_detection"`
	ServiceDetection bool   `json:"service_detection"`
}

// NetworkHost represents a discovered network host
type NetworkHost struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ScanID    uuid.UUID `json:"scan_id" gorm:"type:uuid;not null;index"`
	IPAddress string    `json:"ip_address" gorm:"not null"`
	Hostname  string    `json:"hostname"`
	MAC       string    `json:"mac"`
	OS        string    `json:"os"`
	Status    string    `json:"status"`

	// Timing
	ResponseTime float64 `json:"response_time"` // milliseconds

	// Audit fields
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Scan  NetworkScan   `json:"scan" gorm:"foreignKey:ScanID"`
	Ports []NetworkPort `json:"ports" gorm:"foreignKey:HostID"`
}

// NetworkPort represents a discovered network port
type NetworkPort struct {
	ID       uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	HostID   uuid.UUID `json:"host_id" gorm:"type:uuid;not null;index"`
	Port     int       `json:"port" gorm:"not null"`
	Protocol string    `json:"protocol" gorm:"not null"` // tcp, udp
	State    string    `json:"state" gorm:"not null"`    // open, closed, filtered
	Service  string    `json:"service"`
	Version  string    `json:"version"`
	Banner   string    `json:"banner"`

	// Audit fields
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Host NetworkHost `json:"host" gorm:"foreignKey:HostID"`
}

// SecurityRepository defines the interface for security data access
type SecurityRepository interface {
	// Vulnerability scans
	CreateVulnerabilityScan(scan *VulnerabilityScan) error
	GetVulnerabilityScan(id uuid.UUID) (*VulnerabilityScan, error)
	UpdateVulnerabilityScan(scan *VulnerabilityScan) error
	ListVulnerabilityScans(userID uuid.UUID, limit, offset int) ([]*VulnerabilityScan, error)
	DeleteVulnerabilityScan(id uuid.UUID) error

	// Vulnerabilities
	CreateVulnerability(vuln *Vulnerability) error
	GetVulnerability(id uuid.UUID) (*Vulnerability, error)
	UpdateVulnerability(vuln *Vulnerability) error
	ListVulnerabilities(scanID uuid.UUID) ([]*Vulnerability, error)
	DeleteVulnerability(id uuid.UUID) error

	// Network scans
	CreateNetworkScan(scan *NetworkScan) error
	GetNetworkScan(id uuid.UUID) (*NetworkScan, error)
	UpdateNetworkScan(scan *NetworkScan) error
	ListNetworkScans(userID uuid.UUID, limit, offset int) ([]*NetworkScan, error)
	DeleteNetworkScan(id uuid.UUID) error

	// Network hosts
	CreateNetworkHost(host *NetworkHost) error
	ListNetworkHosts(scanID uuid.UUID) ([]*NetworkHost, error)

	// Network ports
	CreateNetworkPort(port *NetworkPort) error
	ListNetworkPorts(hostID uuid.UUID) ([]*NetworkPort, error)
}

// SecurityUseCase defines the interface for security business logic
type SecurityUseCase interface {
	// Vulnerability scanning
	StartVulnerabilityScan(userID uuid.UUID, target string, scanType ScanType, config ScanConfig) (*VulnerabilityScan, error)
	GetVulnerabilityScan(userID uuid.UUID, scanID uuid.UUID) (*VulnerabilityScan, error)
	ListVulnerabilityScans(userID uuid.UUID, limit, offset int) ([]*VulnerabilityScan, error)
	CancelVulnerabilityScan(userID uuid.UUID, scanID uuid.UUID) error

	// Network scanning
	StartNetworkScan(userID uuid.UUID, target string, scanType NetworkScanType, config NetworkScanConfig) (*NetworkScan, error)
	GetNetworkScan(userID uuid.UUID, scanID uuid.UUID) (*NetworkScan, error)
	ListNetworkScans(userID uuid.UUID, limit, offset int) ([]*NetworkScan, error)
	CancelNetworkScan(userID uuid.UUID, scanID uuid.UUID) error

	// Vulnerability management
	GetVulnerability(userID uuid.UUID, vulnID uuid.UUID) (*Vulnerability, error)
	UpdateVulnerabilityStatus(userID uuid.UUID, vulnID uuid.UUID, status VulnStatus) error
	ListVulnerabilities(userID uuid.UUID, scanID uuid.UUID) ([]*Vulnerability, error)
}

// TableName returns the table name for VulnerabilityScan model
func (VulnerabilityScan) TableName() string {
	return "vulnerability_scans"
}

// TableName returns the table name for Vulnerability model
func (Vulnerability) TableName() string {
	return "vulnerabilities"
}

// TableName returns the table name for NetworkScan model
func (NetworkScan) TableName() string {
	return "network_scans"
}

// TableName returns the table name for NetworkHost model
func (NetworkHost) TableName() string {
	return "network_hosts"
}

// TableName returns the table name for NetworkPort model
func (NetworkPort) TableName() string {
	return "network_ports"
}

// IsCompleted checks if scan is completed
func (s *VulnerabilityScan) IsCompleted() bool {
	return s.Status == ScanStatusCompleted
}

// IsRunning checks if scan is currently running
func (s *VulnerabilityScan) IsRunning() bool {
	return s.Status == ScanStatusRunning
}

// GetSeverityScore returns numeric score for severity
func (s Severity) GetScore() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
