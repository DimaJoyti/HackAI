package repository

import (
	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SecurityRepository implements the domain.SecurityRepository interface
type SecurityRepository struct {
	db     *gorm.DB
	logger *logger.Logger
}

// NewSecurityRepository creates a new security repository
func NewSecurityRepository(db *gorm.DB, log *logger.Logger) domain.SecurityRepository {
	return &SecurityRepository{
		db:     db,
		logger: log,
	}
}

// Vulnerability Scan methods
func (r *SecurityRepository) CreateVulnerabilityScan(scan *domain.VulnerabilityScan) error {
	return r.db.Create(scan).Error
}

func (r *SecurityRepository) GetVulnerabilityScan(id uuid.UUID) (*domain.VulnerabilityScan, error) {
	var scan domain.VulnerabilityScan
	err := r.db.First(&scan, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

func (r *SecurityRepository) UpdateVulnerabilityScan(scan *domain.VulnerabilityScan) error {
	return r.db.Save(scan).Error
}

func (r *SecurityRepository) ListVulnerabilityScans(userID uuid.UUID, limit, offset int) ([]*domain.VulnerabilityScan, error) {
	var scans []*domain.VulnerabilityScan
	err := r.db.Where("user_id = ?", userID).
		Limit(limit).
		Offset(offset).
		Order("created_at DESC").
		Find(&scans).Error
	return scans, err
}

func (r *SecurityRepository) DeleteVulnerabilityScan(id uuid.UUID) error {
	return r.db.Delete(&domain.VulnerabilityScan{}, "id = ?", id).Error
}

// Network Scan methods
func (r *SecurityRepository) CreateNetworkScan(scan *domain.NetworkScan) error {
	return r.db.Create(scan).Error
}

func (r *SecurityRepository) GetNetworkScan(id uuid.UUID) (*domain.NetworkScan, error) {
	var scan domain.NetworkScan
	err := r.db.First(&scan, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

func (r *SecurityRepository) UpdateNetworkScan(scan *domain.NetworkScan) error {
	return r.db.Save(scan).Error
}

func (r *SecurityRepository) ListNetworkScans(userID uuid.UUID, limit, offset int) ([]*domain.NetworkScan, error) {
	var scans []*domain.NetworkScan
	err := r.db.Where("user_id = ?", userID).
		Limit(limit).
		Offset(offset).
		Order("created_at DESC").
		Find(&scans).Error
	return scans, err
}

func (r *SecurityRepository) DeleteNetworkScan(id uuid.UUID) error {
	return r.db.Delete(&domain.NetworkScan{}, "id = ?", id).Error
}

// Network Host methods
func (r *SecurityRepository) CreateNetworkHost(host *domain.NetworkHost) error {
	return r.db.Create(host).Error
}

func (r *SecurityRepository) ListNetworkHosts(scanID uuid.UUID) ([]*domain.NetworkHost, error) {
	var hosts []*domain.NetworkHost
	err := r.db.Preload("Ports").Where("scan_id = ?", scanID).Find(&hosts).Error
	return hosts, err
}

// Network Port methods
func (r *SecurityRepository) CreateNetworkPort(port *domain.NetworkPort) error {
	return r.db.Create(port).Error
}

func (r *SecurityRepository) ListNetworkPorts(hostID uuid.UUID) ([]*domain.NetworkPort, error) {
	var ports []*domain.NetworkPort
	err := r.db.Where("host_id = ?", hostID).Find(&ports).Error
	return ports, err
}

// Vulnerability methods
func (r *SecurityRepository) CreateVulnerability(vuln *domain.Vulnerability) error {
	return r.db.Create(vuln).Error
}

func (r *SecurityRepository) GetVulnerability(id uuid.UUID) (*domain.Vulnerability, error) {
	var vuln domain.Vulnerability
	err := r.db.First(&vuln, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &vuln, nil
}

func (r *SecurityRepository) UpdateVulnerability(vuln *domain.Vulnerability) error {
	return r.db.Save(vuln).Error
}

func (r *SecurityRepository) ListVulnerabilities(scanID uuid.UUID) ([]*domain.Vulnerability, error) {
	var vulns []*domain.Vulnerability
	err := r.db.Where("scan_id = ?", scanID).Order("created_at DESC").Find(&vulns).Error
	return vulns, err
}

func (r *SecurityRepository) DeleteVulnerability(id uuid.UUID) error {
	return r.db.Delete(&domain.Vulnerability{}, "id = ?", id).Error
}
