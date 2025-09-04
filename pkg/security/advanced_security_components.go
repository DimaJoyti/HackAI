package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// DeviceManager handles device tracking and management
type DeviceManager struct {
	config  *DeviceConfig
	logger  *logger.Logger
	devices map[string]*Device
	mutex   sync.RWMutex
}

// Device represents a user device
type Device struct {
	ID                    string                 `json:"id"`
	UserID                string                 `json:"user_id"`
	Fingerprint           string                 `json:"fingerprint"`
	Name                  string                 `json:"name"`
	Type                  string                 `json:"type"`
	OS                    string                 `json:"os"`
	Browser               string                 `json:"browser"`
	IPAddress             string                 `json:"ip_address"`
	UserAgent             string                 `json:"user_agent"`
	IsTrusted             bool                   `json:"is_trusted"`
	IsApproved            bool                   `json:"is_approved"`
	FirstSeen             time.Time              `json:"first_seen"`
	LastSeen              time.Time              `json:"last_seen"`
	LoginCount            int                    `json:"login_count"`
	Metadata              map[string]interface{} `json:"metadata"`
}

// NewDeviceManager creates a new device manager
func NewDeviceManager(config *DeviceConfig, logger *logger.Logger) (*DeviceManager, error) {
	if config == nil {
		return nil, fmt.Errorf("device config is required")
	}
	
	return &DeviceManager{
		config:  config,
		logger:  logger,
		devices: make(map[string]*Device),
	}, nil
}

// RegisterDevice registers a new device or updates existing one
func (dm *DeviceManager) RegisterDevice(userID, userAgent, ipAddress string) (*Device, error) {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()
	
	fingerprint := dm.generateDeviceFingerprint(userAgent, ipAddress)
	
	// Check if device already exists
	for _, device := range dm.devices {
		if device.UserID == userID && device.Fingerprint == fingerprint {
			// Update existing device
			device.LastSeen = time.Now()
			device.LoginCount++
			device.IPAddress = ipAddress
			return device, nil
		}
	}
	
	// Create new device
	device := &Device{
		ID:          uuid.New().String(),
		UserID:      userID,
		Fingerprint: fingerprint,
		Name:        dm.extractDeviceName(userAgent),
		Type:        dm.extractDeviceType(userAgent),
		OS:          dm.extractOS(userAgent),
		Browser:     dm.extractBrowser(userAgent),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		IsTrusted:   dm.config.TrustNewDevices,
		IsApproved:  !dm.config.RequireDeviceApproval,
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		LoginCount:  1,
		Metadata:    make(map[string]interface{}),
	}
	
	dm.devices[device.ID] = device
	
	dm.logger.Info("New device registered",
		"device_id", device.ID,
		"user_id", userID,
		"fingerprint", fingerprint,
		"trusted", device.IsTrusted)
	
	return device, nil
}

// IsDeviceAllowed checks if a device is allowed for login
func (dm *DeviceManager) IsDeviceAllowed(userID, userAgent, ipAddress string) bool {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()
	
	fingerprint := dm.generateDeviceFingerprint(userAgent, ipAddress)
	
	for _, device := range dm.devices {
		if device.UserID == userID && device.Fingerprint == fingerprint {
			return device.IsApproved && !dm.isDeviceExpired(device)
		}
	}
	
	// New device - allow if not requiring approval
	return !dm.config.RequireDeviceApproval
}

// generateDeviceFingerprint generates a device fingerprint
func (dm *DeviceManager) generateDeviceFingerprint(userAgent, ipAddress string) string {
	data := fmt.Sprintf("%s:%s", userAgent, ipAddress)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// extractDeviceName extracts device name from user agent
func (dm *DeviceManager) extractDeviceName(userAgent string) string {
	// Simplified device name extraction
	if strings.Contains(userAgent, "iPhone") {
		return "iPhone"
	} else if strings.Contains(userAgent, "iPad") {
		return "iPad"
	} else if strings.Contains(userAgent, "Android") {
		return "Android Device"
	} else if strings.Contains(userAgent, "Windows") {
		return "Windows PC"
	} else if strings.Contains(userAgent, "Macintosh") {
		return "Mac"
	}
	return "Unknown Device"
}

// extractDeviceType extracts device type from user agent
func (dm *DeviceManager) extractDeviceType(userAgent string) string {
	if strings.Contains(userAgent, "Mobile") {
		return "mobile"
	} else if strings.Contains(userAgent, "Tablet") {
		return "tablet"
	}
	return "desktop"
}

// extractOS extracts operating system from user agent
func (dm *DeviceManager) extractOS(userAgent string) string {
	if strings.Contains(userAgent, "Windows") {
		return "Windows"
	} else if strings.Contains(userAgent, "Macintosh") {
		return "macOS"
	} else if strings.Contains(userAgent, "Linux") {
		return "Linux"
	} else if strings.Contains(userAgent, "Android") {
		return "Android"
	} else if strings.Contains(userAgent, "iOS") {
		return "iOS"
	}
	return "Unknown"
}

// extractBrowser extracts browser from user agent
func (dm *DeviceManager) extractBrowser(userAgent string) string {
	if strings.Contains(userAgent, "Chrome") {
		return "Chrome"
	} else if strings.Contains(userAgent, "Firefox") {
		return "Firefox"
	} else if strings.Contains(userAgent, "Safari") {
		return "Safari"
	} else if strings.Contains(userAgent, "Edge") {
		return "Edge"
	}
	return "Unknown"
}

// isDeviceExpired checks if a device approval has expired
func (dm *DeviceManager) isDeviceExpired(device *Device) bool {
	if dm.config.DeviceApprovalTTL == 0 {
		return false
	}
	return time.Since(device.LastSeen) > dm.config.DeviceApprovalTTL
}

// ThreatDetector detects security threats
type ThreatDetector struct {
	config *SecurityMonitorConfig
	logger *logger.Logger
}

// NewThreatDetector creates a new threat detector
func NewThreatDetector(config *SecurityMonitorConfig, logger *logger.Logger) (*ThreatDetector, error) {
	if config == nil {
		return nil, fmt.Errorf("security monitor config is required")
	}
	
	return &ThreatDetector{
		config: config,
		logger: logger,
	}, nil
}

// CalculateLoginThreatScore calculates threat score for login attempt
func (td *ThreatDetector) CalculateLoginThreatScore(req *LoginRequest, user *User) float64 {
	score := 0.0
	
	// Time-based analysis
	score += td.analyzeLoginTime()
	
	// IP-based analysis
	score += td.analyzeIPAddress(req.IPAddress, user.LastLoginIP)
	
	// User agent analysis
	score += td.analyzeUserAgent(req.UserAgent)
	
	// Behavioral analysis
	score += td.analyzeBehavior(req, user)
	
	// Normalize score to 0-1 range
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

// analyzeLoginTime analyzes login time patterns
func (td *ThreatDetector) analyzeLoginTime() float64 {
	now := time.Now()
	hour := now.Hour()
	
	// Higher risk during unusual hours (2 AM - 6 AM)
	if hour >= 2 && hour <= 6 {
		return 0.3
	}
	
	// Weekend logins might be slightly more suspicious for business accounts
	if now.Weekday() == time.Saturday || now.Weekday() == time.Sunday {
		return 0.1
	}
	
	return 0.0
}

// analyzeIPAddress analyzes IP address patterns
func (td *ThreatDetector) analyzeIPAddress(currentIP, lastIP string) float64 {
	if lastIP == "" {
		return 0.1 // First login, slightly suspicious
	}
	
	if currentIP == lastIP {
		return 0.0 // Same IP, no risk
	}
	
	// Different IP, moderate risk
	return 0.4
}

// analyzeUserAgent analyzes user agent patterns
func (td *ThreatDetector) analyzeUserAgent(userAgent string) float64 {
	// Check for suspicious patterns
	suspicious := []string{
		"bot", "crawler", "spider", "scraper",
		"curl", "wget", "python", "java",
	}
	
	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspicious {
		if strings.Contains(userAgentLower, pattern) {
			return 0.8
		}
	}
	
	// Empty or very short user agent
	if len(userAgent) < 10 {
		return 0.6
	}
	
	return 0.0
}

// analyzeBehavior analyzes behavioral patterns
func (td *ThreatDetector) analyzeBehavior(req *LoginRequest, user *User) float64 {
	score := 0.0
	
	// Multiple rapid login attempts
	if user.FailedLoginAttempts > 3 {
		score += 0.3
	}
	
	// Account hasn't been used recently
	if user.LastLoginAt != nil && time.Since(*user.LastLoginAt) > 30*24*time.Hour {
		score += 0.2
	}
	
	return score
}

// SecurityMonitor monitors security events
type SecurityMonitor struct {
	config *SecurityMonitorConfig
	logger *logger.Logger
	events []*SecurityEvent
	mutex  sync.RWMutex
}

// NewSecurityMonitor creates a new security monitor
func NewSecurityMonitor(config *SecurityMonitorConfig, logger *logger.Logger) (*SecurityMonitor, error) {
	if config == nil {
		return nil, fmt.Errorf("security monitor config is required")
	}
	
	return &SecurityMonitor{
		config: config,
		logger: logger,
		events: make([]*SecurityEvent, 0),
	}, nil
}

// RecordEvent records a security event
func (sm *SecurityMonitor) RecordEvent(event *SecurityEvent) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	sm.events = append(sm.events, event)
	
	// Trigger alerts if necessary
	if event.ThreatScore >= sm.config.ThreatScoreThreshold {
		sm.triggerAlert(event)
	}
}

// triggerAlert triggers a security alert
func (sm *SecurityMonitor) triggerAlert(event *SecurityEvent) {
	sm.logger.Warn("Security alert triggered",
		"event_id", event.ID,
		"event_type", event.Type,
		"threat_score", event.ThreatScore,
		"user_id", event.UserID)
	
	// Here you would integrate with alerting systems
	// like PagerDuty, Slack, email, etc.
}

// SecurityAuditLogger logs security events for audit purposes
type SecurityAuditLogger struct {
	config *AuditConfig
	logger *logger.Logger
}

// NewSecurityAuditLogger creates a new security audit logger
func NewSecurityAuditLogger(config *AuditConfig, logger *logger.Logger) (*SecurityAuditLogger, error) {
	if config == nil {
		return nil, fmt.Errorf("audit config is required")
	}
	
	return &SecurityAuditLogger{
		config: config,
		logger: logger,
	}, nil
}

// LogSecurityEvent logs a security event
func (sal *SecurityAuditLogger) LogSecurityEvent(event *SecurityEvent) {
	if !sal.config.EnableAuditLogging {
		return
	}
	
	// Create audit log entry
	auditEntry := map[string]interface{}{
		"timestamp":    event.Timestamp,
		"event_id":     event.ID,
		"event_type":   event.Type,
		"user_id":      event.UserID,
		"session_id":   event.SessionID,
		"ip_address":   event.IPAddress,
		"user_agent":   event.UserAgent,
		"severity":     event.Severity,
		"description":  event.Description,
		"threat_score": event.ThreatScore,
		"metadata":     event.Metadata,
		"resolved":     event.Resolved,
	}
	
	// Remove sensitive data if configured
	if !sal.config.IncludeSensitiveData {
		delete(auditEntry, "user_agent")
		if metadata, ok := auditEntry["metadata"].(map[string]interface{}); ok {
			delete(metadata, "password")
			delete(metadata, "token")
			delete(metadata, "secret")
		}
	}
	
	sal.logger.Info("Security audit event", auditEntry)
}

// RBACManager handles role-based access control
type RBACManager struct {
	config *AuthorizationConfig
	logger *logger.Logger
	roles  map[string]*Role
	mutex  sync.RWMutex
}

// Role represents a user role
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	IsActive    bool     `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NewRBACManager creates a new RBAC manager
func NewRBACManager(config *AuthorizationConfig, logger *logger.Logger) (*RBACManager, error) {
	if config == nil {
		return nil, fmt.Errorf("authorization config is required")
	}
	
	rbac := &RBACManager{
		config: config,
		logger: logger,
		roles:  make(map[string]*Role),
	}
	
	// Initialize default roles
	rbac.initializeDefaultRoles()
	
	return rbac, nil
}

// initializeDefaultRoles initializes default system roles
func (rbac *RBACManager) initializeDefaultRoles() {
	defaultRoles := []*Role{
		{
			ID:          "user",
			Name:        "User",
			Description: "Standard user role",
			Permissions: []string{"read:profile", "update:profile"},
			IsActive:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "admin",
			Name:        "Administrator",
			Description: "Administrator role",
			Permissions: []string{"*"},
			IsActive:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "super_admin",
			Name:        "Super Administrator",
			Description: "Super administrator role",
			Permissions: []string{"*"},
			IsActive:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}
	
	for _, role := range defaultRoles {
		rbac.roles[role.ID] = role
	}
}

// HasPermission checks if a role has a specific permission
func (rbac *RBACManager) HasPermission(roleID, permission string) bool {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()
	
	role, exists := rbac.roles[roleID]
	if !exists || !role.IsActive {
		return false
	}
	
	// Check for wildcard permission
	for _, perm := range role.Permissions {
		if perm == "*" || perm == permission {
			return true
		}
	}
	
	return false
}

// PermissionManager handles permission management
type PermissionManager struct {
	config *AuthorizationConfig
	logger *logger.Logger
}

// NewPermissionManager creates a new permission manager
func NewPermissionManager(config *AuthorizationConfig, logger *logger.Logger) (*PermissionManager, error) {
	if config == nil {
		return nil, fmt.Errorf("authorization config is required")
	}
	
	return &PermissionManager{
		config: config,
		logger: logger,
	}, nil
}

// PolicyEngine handles policy evaluation
type PolicyEngine struct {
	config *AuthorizationConfig
	logger *logger.Logger
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(config *AuthorizationConfig, logger *logger.Logger) (*PolicyEngine, error) {
	if config == nil {
		return nil, fmt.Errorf("authorization config is required")
	}
	
	return &PolicyEngine{
		config: config,
		logger: logger,
	}, nil
}
