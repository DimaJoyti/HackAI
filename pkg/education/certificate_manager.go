package education

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// CertificateManager manages educational certificates and credentials
type CertificateManager struct {
	logger       *logger.Logger
	certificates map[string]*Certificate
	templates    map[string]*CertificateTemplate
	blockchain   *BlockchainVerifier
	config       *CertificateConfig
	mu           sync.RWMutex
}

// CertificateConfig configuration for certificate management
type CertificateConfig struct {
	EnableBlockchainVerification bool          `json:"enable_blockchain_verification"`
	EnableDigitalSignatures      bool          `json:"enable_digital_signatures"`
	EnableQRCodes                bool          `json:"enable_qr_codes"`
	CertificateValidityPeriod    time.Duration `json:"certificate_validity_period"`
	EnableAutomaticRenewal       bool          `json:"enable_automatic_renewal"`
	RequireProctoring            bool          `json:"require_proctoring"`
	MinimumPassingScore          float64       `json:"minimum_passing_score"`
	EnableSkillBadges            bool          `json:"enable_skill_badges"`
	EnableMicroCredentials       bool          `json:"enable_micro_credentials"`
}

// Certificate represents an educational certificate
type Certificate struct {
	ID                string                 `json:"id"`
	CertificateNumber string                 `json:"certificate_number"`
	Type              string                 `json:"type"`
	Title             string                 `json:"title"`
	Description       string                 `json:"description"`
	RecipientID       string                 `json:"recipient_id"`
	RecipientName     string                 `json:"recipient_name"`
	RecipientEmail    string                 `json:"recipient_email"`
	IssuerID          string                 `json:"issuer_id"`
	IssuerName        string                 `json:"issuer_name"`
	CourseID          string                 `json:"course_id"`
	CourseName        string                 `json:"course_name"`
	CompletionDate    time.Time              `json:"completion_date"`
	IssueDate         time.Time              `json:"issue_date"`
	ExpirationDate    *time.Time             `json:"expiration_date"`
	Status            string                 `json:"status"`
	Grade             string                 `json:"grade"`
	Score             float64                `json:"score"`
	Skills            []string               `json:"skills"`
	Competencies      []string               `json:"competencies"`
	VerificationHash  string                 `json:"verification_hash"`
	BlockchainTxID    string                 `json:"blockchain_tx_id"`
	QRCode            string                 `json:"qr_code"`
	DigitalSignature  string                 `json:"digital_signature"`
	Metadata          map[string]interface{} `json:"metadata"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// CertificateTemplate represents a certificate template
type CertificateTemplate struct {
	ID              string                   `json:"id"`
	Name            string                   `json:"name"`
	Type            string                   `json:"type"`
	Category        string                   `json:"category"`
	Template        string                   `json:"template"`
	Requirements    *CertificateRequirements `json:"requirements"`
	Design          *CertificateDesign       `json:"design"`
	ValidityPeriod  time.Duration            `json:"validity_period"`
	RenewalRequired bool                     `json:"renewal_required"`
	Metadata        map[string]interface{}   `json:"metadata"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
}

// CertificateRequirements represents certificate requirements
type CertificateRequirements struct {
	CompletedCourses     []string `json:"completed_courses"`
	MinimumScore         float64  `json:"minimum_score"`
	RequiredSkills       []string `json:"required_skills"`
	RequiredCompetencies []string `json:"required_competencies"`
	ProctoredExam        bool     `json:"proctored_exam"`
	CapstoneProject      bool     `json:"capstone_project"`
	ContinuingEducation  bool     `json:"continuing_education"`
	ExperienceHours      int      `json:"experience_hours"`
}

// CertificateDesign represents certificate design configuration
type CertificateDesign struct {
	BackgroundImage string                 `json:"background_image"`
	LogoImage       string                 `json:"logo_image"`
	FontFamily      string                 `json:"font_family"`
	FontSize        int                    `json:"font_size"`
	ColorScheme     map[string]string      `json:"color_scheme"`
	Layout          string                 `json:"layout"`
	Dimensions      map[string]int         `json:"dimensions"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// BlockchainVerifier handles blockchain verification
type BlockchainVerifier struct {
	enabled         bool
	networkURL      string
	contractAddress string
	privateKey      string
}

// SkillBadge represents a skill badge
type SkillBadge struct {
	ID         string                 `json:"id"`
	SkillID    string                 `json:"skill_id"`
	SkillName  string                 `json:"skill_name"`
	Level      string                 `json:"level"`
	BadgeImage string                 `json:"badge_image"`
	EarnedDate time.Time              `json:"earned_date"`
	Criteria   map[string]interface{} `json:"criteria"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// MicroCredential represents a micro-credential
type MicroCredential struct {
	ID              string                 `json:"id"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	IssuerID        string                 `json:"issuer_id"`
	RecipientID     string                 `json:"recipient_id"`
	SkillsValidated []string               `json:"skills_validated"`
	EvidenceLinks   []string               `json:"evidence_links"`
	IssueDate       time.Time              `json:"issue_date"`
	ExpirationDate  *time.Time             `json:"expiration_date"`
	VerificationURL string                 `json:"verification_url"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(logger *logger.Logger) *CertificateManager {
	manager := &CertificateManager{
		logger:       logger,
		certificates: make(map[string]*Certificate),
		templates:    make(map[string]*CertificateTemplate),
		blockchain:   &BlockchainVerifier{enabled: false},
		config: &CertificateConfig{
			EnableBlockchainVerification: false,
			EnableDigitalSignatures:      true,
			EnableQRCodes:                true,
			CertificateValidityPeriod:    2 * 365 * 24 * time.Hour, // 2 years
			EnableAutomaticRenewal:       false,
			RequireProctoring:            false,
			MinimumPassingScore:          70.0,
			EnableSkillBadges:            true,
			EnableMicroCredentials:       true,
		},
	}

	manager.initializeDefaultTemplates()
	return manager
}

// initializeDefaultTemplates creates default certificate templates
func (cm *CertificateManager) initializeDefaultTemplates() {
	// AI Security Professional Certificate Template
	aiSecurityTemplate := &CertificateTemplate{
		ID:       "ai-security-professional",
		Name:     "AI Security Professional Certificate",
		Type:     "professional",
		Category: "security",
		Template: `
Certificate of Completion

This is to certify that

{{.RecipientName}}

has successfully completed the

{{.CourseName}}

with a score of {{.Score}}%

Issued on {{.IssueDate}}
Certificate Number: {{.CertificateNumber}}
`,
		Requirements: &CertificateRequirements{
			CompletedCourses:     []string{"ai-security-fundamentals", "advanced-ai-security"},
			MinimumScore:         75.0,
			RequiredSkills:       []string{"ai-threat-modeling", "prompt-injection-testing"},
			RequiredCompetencies: []string{"security-assessment", "risk-analysis"},
			ProctoredExam:        true,
			CapstoneProject:      true,
		},
		Design: &CertificateDesign{
			BackgroundImage: "/templates/ai-security-bg.png",
			LogoImage:       "/templates/logo.png",
			FontFamily:      "Arial",
			FontSize:        14,
			ColorScheme: map[string]string{
				"primary":   "#1e3a8a",
				"secondary": "#3b82f6",
				"accent":    "#fbbf24",
			},
			Layout: "professional",
			Dimensions: map[string]int{
				"width":  800,
				"height": 600,
			},
		},
		ValidityPeriod:  2 * 365 * 24 * time.Hour,
		RenewalRequired: true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		Metadata:        make(map[string]interface{}),
	}

	// Course Completion Certificate Template
	courseCompletionTemplate := &CertificateTemplate{
		ID:       "course-completion",
		Name:     "Course Completion Certificate",
		Type:     "completion",
		Category: "general",
		Template: `
Certificate of Completion

{{.RecipientName}}

has successfully completed

{{.CourseName}}

Completion Date: {{.CompletionDate}}
Certificate ID: {{.ID}}
`,
		Requirements: &CertificateRequirements{
			MinimumScore: 70.0,
		},
		Design: &CertificateDesign{
			BackgroundImage: "/templates/completion-bg.png",
			FontFamily:      "Times New Roman",
			FontSize:        12,
			Layout:          "simple",
		},
		ValidityPeriod:  0, // No expiration
		RenewalRequired: false,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		Metadata:        make(map[string]interface{}),
	}

	cm.templates[aiSecurityTemplate.ID] = aiSecurityTemplate
	cm.templates[courseCompletionTemplate.ID] = courseCompletionTemplate
}

// IssueCertificate issues a new certificate
func (cm *CertificateManager) IssueCertificate(ctx context.Context, templateID, recipientID, courseID string, score float64) (*Certificate, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Get template
	template, exists := cm.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("certificate template not found: %s", templateID)
	}

	// Validate requirements
	if err := cm.validateRequirements(template.Requirements, recipientID, courseID, score); err != nil {
		return nil, fmt.Errorf("certificate requirements not met: %w", err)
	}

	// Generate certificate
	certificate := &Certificate{
		ID:                uuid.New().String(),
		CertificateNumber: cm.generateCertificateNumber(),
		Type:              template.Type,
		Title:             template.Name,
		Description:       fmt.Sprintf("Certificate for completion of %s", courseID),
		RecipientID:       recipientID,
		RecipientName:     cm.getRecipientName(recipientID),
		RecipientEmail:    cm.getRecipientEmail(recipientID),
		IssuerID:          "hackai-platform",
		IssuerName:        "HackAI Security Training Platform",
		CourseID:          courseID,
		CourseName:        cm.getCourseName(courseID),
		CompletionDate:    time.Now(),
		IssueDate:         time.Now(),
		Status:            "active",
		Grade:             cm.calculateGrade(score),
		Score:             score,
		Skills:            template.Requirements.RequiredSkills,
		Competencies:      template.Requirements.RequiredCompetencies,
		Metadata:          make(map[string]interface{}),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	// Set expiration date if required
	if template.ValidityPeriod > 0 {
		expirationDate := certificate.IssueDate.Add(template.ValidityPeriod)
		certificate.ExpirationDate = &expirationDate
	}

	// Generate verification hash
	certificate.VerificationHash = cm.generateVerificationHash(certificate)

	// Generate QR code if enabled
	if cm.config.EnableQRCodes {
		certificate.QRCode = cm.generateQRCode(certificate)
	}

	// Generate digital signature if enabled
	if cm.config.EnableDigitalSignatures {
		certificate.DigitalSignature = cm.generateDigitalSignature(certificate)
	}

	// Record on blockchain if enabled
	if cm.config.EnableBlockchainVerification {
		txID, err := cm.blockchain.recordCertificate(certificate)
		if err != nil {
			cm.logger.WithError(err).Warn("Failed to record certificate on blockchain")
		} else {
			certificate.BlockchainTxID = txID
		}
	}

	cm.certificates[certificate.ID] = certificate

	cm.logger.WithFields(map[string]interface{}{
		"certificate_id": certificate.ID,
		"recipient_id":   recipientID,
		"course_id":      courseID,
		"score":          score,
	}).Info("Certificate issued")

	return certificate, nil
}

// validateRequirements validates certificate requirements
func (cm *CertificateManager) validateRequirements(requirements *CertificateRequirements, recipientID, courseID string, score float64) error {
	// Check minimum score
	if score < requirements.MinimumScore {
		return fmt.Errorf("score %.1f below minimum required %.1f", score, requirements.MinimumScore)
	}

	// Check completed courses (simplified validation)
	if len(requirements.CompletedCourses) > 0 {
		// In a real implementation, this would check user's completed courses
		cm.logger.Info("Validating completed courses requirement")
	}

	// Check required skills (simplified validation)
	if len(requirements.RequiredSkills) > 0 {
		// In a real implementation, this would check user's acquired skills
		cm.logger.Info("Validating required skills")
	}

	return nil
}

// generateCertificateNumber generates a unique certificate number
func (cm *CertificateManager) generateCertificateNumber() string {
	timestamp := time.Now().Unix()
	return fmt.Sprintf("CERT-%d-%s", timestamp, uuid.New().String()[:8])
}

// generateVerificationHash generates a verification hash for the certificate
func (cm *CertificateManager) generateVerificationHash(cert *Certificate) string {
	data := fmt.Sprintf("%s%s%s%s%f%s",
		cert.ID,
		cert.RecipientID,
		cert.CourseID,
		cert.IssueDate.Format(time.RFC3339),
		cert.Score,
		cert.IssuerID,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generateQRCode generates a QR code for certificate verification
func (cm *CertificateManager) generateQRCode(cert *Certificate) string {
	// In a real implementation, this would generate an actual QR code
	verificationURL := fmt.Sprintf("https://verify.hackai.com/certificate/%s", cert.ID)
	return verificationURL
}

// generateDigitalSignature generates a digital signature for the certificate
func (cm *CertificateManager) generateDigitalSignature(cert *Certificate) string {
	// In a real implementation, this would use actual cryptographic signing
	data := fmt.Sprintf("%s%s", cert.VerificationHash, cert.IssuerID)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// getRecipientName gets recipient name (simplified)
func (cm *CertificateManager) getRecipientName(recipientID string) string {
	// In a real implementation, this would query user database
	return fmt.Sprintf("User %s", recipientID[:8])
}

// getRecipientEmail gets recipient email (simplified)
func (cm *CertificateManager) getRecipientEmail(recipientID string) string {
	// In a real implementation, this would query user database
	return fmt.Sprintf("user-%s@example.com", recipientID[:8])
}

// getCourseName gets course name (simplified)
func (cm *CertificateManager) getCourseName(courseID string) string {
	// In a real implementation, this would query course database
	courseNames := map[string]string{
		"ai-security-fundamentals": "AI Security Fundamentals",
		"advanced-ai-security":     "Advanced AI Security",
		"ai-red-teaming":           "AI Red Teaming",
	}

	if name, exists := courseNames[courseID]; exists {
		return name
	}
	return courseID
}

// calculateGrade calculates letter grade from score
func (cm *CertificateManager) calculateGrade(score float64) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 85:
		return "B+"
	case score >= 80:
		return "B"
	case score >= 75:
		return "C+"
	case score >= 70:
		return "C"
	default:
		return "F"
	}
}

// VerifyCertificate verifies a certificate's authenticity
func (cm *CertificateManager) VerifyCertificate(certificateID string) (*CertificateVerification, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	certificate, exists := cm.certificates[certificateID]
	if !exists {
		return &CertificateVerification{
			Valid:   false,
			Message: "Certificate not found",
		}, nil
	}

	verification := &CertificateVerification{
		CertificateID: certificateID,
		Valid:         true,
		Message:       "Certificate is valid and authentic",
		Certificate:   certificate,
		VerifiedAt:    time.Now(),
	}

	// Check expiration
	if certificate.ExpirationDate != nil && time.Now().After(*certificate.ExpirationDate) {
		verification.Valid = false
		verification.Message = "Certificate has expired"
		verification.Warnings = append(verification.Warnings, "Certificate expired on "+certificate.ExpirationDate.Format("2006-01-02"))
	}

	// Verify hash
	expectedHash := cm.generateVerificationHash(certificate)
	if certificate.VerificationHash != expectedHash {
		verification.Valid = false
		verification.Message = "Certificate verification hash is invalid"
		verification.Warnings = append(verification.Warnings, "Verification hash mismatch")
	}

	// Check blockchain if enabled
	if cm.config.EnableBlockchainVerification && certificate.BlockchainTxID != "" {
		blockchainValid := cm.blockchain.verifyCertificate(certificate.BlockchainTxID)
		if !blockchainValid {
			verification.Valid = false
			verification.Message = "Blockchain verification failed"
			verification.Warnings = append(verification.Warnings, "Blockchain record not found or invalid")
		}
	}

	return verification, nil
}

// CertificateVerification represents certificate verification result
type CertificateVerification struct {
	CertificateID string       `json:"certificate_id"`
	Valid         bool         `json:"valid"`
	Message       string       `json:"message"`
	Certificate   *Certificate `json:"certificate,omitempty"`
	Warnings      []string     `json:"warnings"`
	VerifiedAt    time.Time    `json:"verified_at"`
}

// GetUserCertificates retrieves all certificates for a user
func (cm *CertificateManager) GetUserCertificates(userID string) ([]*Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var userCertificates []*Certificate
	for _, cert := range cm.certificates {
		if cert.RecipientID == userID {
			userCertificates = append(userCertificates, cert)
		}
	}

	return userCertificates, nil
}

// recordCertificate records certificate on blockchain (placeholder)
func (bv *BlockchainVerifier) recordCertificate(cert *Certificate) (string, error) {
	if !bv.enabled {
		return "", fmt.Errorf("blockchain verification not enabled")
	}

	// Placeholder for blockchain integration
	txID := fmt.Sprintf("tx_%s", uuid.New().String()[:16])
	return txID, nil
}

// verifyCertificate verifies certificate on blockchain (placeholder)
func (bv *BlockchainVerifier) verifyCertificate(txID string) bool {
	if !bv.enabled {
		return false
	}

	// Placeholder for blockchain verification
	return true
}
