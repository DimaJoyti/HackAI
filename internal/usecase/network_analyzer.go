package usecase

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// NetworkAnalyzerUseCase implements AI-powered network analysis
type NetworkAnalyzerUseCase struct {
	repo   domain.SecurityRepository
	logger *logger.Logger
}

// NewNetworkAnalyzerUseCase creates a new network analyzer use case
func NewNetworkAnalyzerUseCase(repo domain.SecurityRepository, log *logger.Logger) *NetworkAnalyzerUseCase {
	return &NetworkAnalyzerUseCase{
		repo:   repo,
		logger: log,
	}
}

// StartScan initiates a new network scan
func (n *NetworkAnalyzerUseCase) StartScan(ctx context.Context, userID uuid.UUID, target string, scanType domain.NetworkScanType, config domain.NetworkScanConfig) (*domain.NetworkScan, error) {
	// Validate target
	if err := n.validateTarget(target); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	// Create scan record
	scan := &domain.NetworkScan{
		UserID:   userID,
		Target:   target,
		ScanType: scanType,
		Status:   domain.ScanStatusPending,
		Config:   config,
	}

	if err := n.repo.CreateNetworkScan(scan); err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}

	// Start scan asynchronously
	go n.executeScan(context.Background(), scan)

	n.logger.WithContext(ctx).WithFields(logger.Fields{
		"scan_id":   scan.ID,
		"user_id":   userID,
		"target":    target,
		"scan_type": scanType,
	}).Info("Network scan started")

	return scan, nil
}

// executeScan performs the actual network scanning
func (n *NetworkAnalyzerUseCase) executeScan(ctx context.Context, scan *domain.NetworkScan) {
	// Update scan status to running
	scan.Status = domain.ScanStatusRunning
	scan.Progress = 0
	now := time.Now()
	scan.StartedAt = &now

	if err := n.repo.UpdateNetworkScan(scan); err != nil {
		n.logger.WithError(err).Error("Failed to update scan status")
		return
	}

	defer func() {
		if r := recover(); r != nil {
			n.logger.WithField("panic", r).Error("Network scan panicked")
			scan.Status = domain.ScanStatusFailed
			n.repo.UpdateNetworkScan(scan)
		}
	}()

	var hosts []*domain.NetworkHost
	var err error

	// Execute scan based on type
	switch scan.ScanType {
	case domain.NetworkScanTypePing:
		hosts, err = n.performPingScan(ctx, scan)
	case domain.NetworkScanTypePortScan:
		hosts, err = n.performPortScan(ctx, scan)
	case domain.NetworkScanTypeServiceScan:
		hosts, err = n.performServiceScan(ctx, scan)
	case domain.NetworkScanTypeOSScan:
		hosts, err = n.performOSScan(ctx, scan)
	case domain.NetworkScanTypeFullScan:
		hosts, err = n.performFullScan(ctx, scan)
	default:
		err = fmt.Errorf("unsupported scan type: %s", scan.ScanType)
	}

	// Update scan completion
	completedAt := time.Now()
	scan.CompletedAt = &completedAt
	scan.Duration = completedAt.Sub(*scan.StartedAt).Milliseconds()
	scan.Progress = 100

	if err != nil {
		scan.Status = domain.ScanStatusFailed
		n.logger.WithError(err).Error("Network scan failed")
	} else {
		scan.Status = domain.ScanStatusCompleted
		scan.HostsFound = len(hosts)

		// Count total ports and services
		totalPorts := 0
		totalServices := 0
		for _, host := range hosts {
			totalPorts += len(host.Ports)
			for _, port := range host.Ports {
				if port.Service != "" {
					totalServices++
				}
			}
		}
		scan.PortsFound = totalPorts
		scan.ServicesFound = totalServices

		// Save hosts and their ports
		for _, host := range hosts {
			host.ScanID = scan.ID
			if err := n.repo.CreateNetworkHost(host); err != nil {
				n.logger.WithError(err).Error("Failed to save network host")
				continue
			}

			for _, port := range host.Ports {
				port.HostID = host.ID
				if err := n.repo.CreateNetworkPort(&port); err != nil {
					n.logger.WithError(err).Error("Failed to save network port")
				}
			}
		}
	}

	if err := n.repo.UpdateNetworkScan(scan); err != nil {
		n.logger.WithError(err).Error("Failed to update scan completion")
	}

	n.logger.WithFields(logger.Fields{
		"scan_id":     scan.ID,
		"status":      scan.Status,
		"hosts_found": scan.HostsFound,
		"ports_found": scan.PortsFound,
		"duration_ms": scan.Duration,
	}).Info("Network scan completed")
}

// performPingScan performs a ping sweep to discover live hosts
func (n *NetworkAnalyzerUseCase) performPingScan(ctx context.Context, scan *domain.NetworkScan) ([]*domain.NetworkHost, error) {
	var hosts []*domain.NetworkHost

	// Parse CIDR or IP range
	ips, err := n.parseTargetIPs(scan.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target IPs: %w", err)
	}

	// Limit concurrent scans
	semaphore := make(chan struct{}, scan.Config.Threads)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, ip := range ips {
		// Update progress
		scan.Progress = int((float64(i) / float64(len(ips))) * 100)
		n.repo.UpdateNetworkScan(scan)

		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if n.pingHost(targetIP, scan.Config.Timeout) {
				host := &domain.NetworkHost{
					IPAddress:    targetIP,
					Status:       "up",
					ResponseTime: float64(scan.Config.Timeout),
				}

				// Try to resolve hostname
				if names, err := net.LookupAddr(targetIP); err == nil && len(names) > 0 {
					host.Hostname = names[0]
				}

				mu.Lock()
				hosts = append(hosts, host)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return hosts, nil
}

// performPortScan performs port scanning on discovered hosts
func (n *NetworkAnalyzerUseCase) performPortScan(ctx context.Context, scan *domain.NetworkScan) ([]*domain.NetworkHost, error) {
	// First discover live hosts
	hosts, err := n.performPingScan(ctx, scan)
	if err != nil {
		return nil, err
	}

	// Parse port range
	ports := n.parsePortRange(scan.Config.PortRange)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, scan.Config.Threads)

	for _, host := range hosts {
		wg.Add(1)
		go func(h *domain.NetworkHost) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			hostPorts := n.scanHostPorts(h.IPAddress, ports, scan.Config)
			h.Ports = make([]domain.NetworkPort, len(hostPorts))
			for i, port := range hostPorts {
				h.Ports[i] = *port
			}
		}(host)
	}

	wg.Wait()
	return hosts, nil
}

// performServiceScan performs service detection on open ports
func (n *NetworkAnalyzerUseCase) performServiceScan(ctx context.Context, scan *domain.NetworkScan) ([]*domain.NetworkHost, error) {
	// First perform port scan
	hosts, err := n.performPortScan(ctx, scan)
	if err != nil {
		return nil, err
	}

	// Detect services on open ports
	for _, host := range hosts {
		for _, port := range host.Ports {
			if port.State == "open" {
				service, version, banner := n.detectService(host.IPAddress, port.Port, port.Protocol)
				port.Service = service
				port.Version = version
				port.Banner = banner
			}
		}
	}

	return hosts, nil
}

// performOSScan performs operating system detection
func (n *NetworkAnalyzerUseCase) performOSScan(ctx context.Context, scan *domain.NetworkScan) ([]*domain.NetworkHost, error) {
	// First perform service scan
	hosts, err := n.performServiceScan(ctx, scan)
	if err != nil {
		return nil, err
	}

	// Detect operating system using AI heuristics
	for _, host := range hosts {
		host.OS = n.detectOperatingSystem(host)
	}

	return hosts, nil
}

// performFullScan performs comprehensive network scanning
func (n *NetworkAnalyzerUseCase) performFullScan(ctx context.Context, scan *domain.NetworkScan) ([]*domain.NetworkHost, error) {
	return n.performOSScan(ctx, scan)
}

// AI-powered service detection
func (n *NetworkAnalyzerUseCase) detectService(ip string, port int, protocol string) (service, version, banner string) {
	// Connect to the port and try to grab banner
	conn, err := net.DialTimeout(protocol, fmt.Sprintf("%s:%d", ip, port), 5*time.Second)
	if err != nil {
		return "", "", ""
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Try to read banner
	buffer := make([]byte, 1024)
	bytesRead, err := conn.Read(buffer)
	if err != nil {
		// For some services, we need to send data first
		banner = n.probeBanner(conn, port)
	} else {
		banner = string(buffer[:bytesRead])
	}

	// AI-powered service identification based on port and banner
	service, version = n.identifyService(port, banner)
	return service, version, banner
}

// probeBanner sends probes to elicit service banners
func (n *NetworkAnalyzerUseCase) probeBanner(conn net.Conn, port int) string {
	probes := map[int]string{
		80:   "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
		443:  "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
		21:   "USER anonymous\r\n",
		22:   "\r\n",
		23:   "\r\n",
		25:   "EHLO localhost\r\n",
		53:   "\x00\x1e\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
		110:  "USER test\r\n",
		143:  "A001 CAPABILITY\r\n",
		993:  "A001 CAPABILITY\r\n",
		995:  "USER test\r\n",
		3306: "\x3a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x2d\x31\x30\x2e\x31\x2e\x34\x31\x2d\x4d\x61\x72\x69\x61\x44\x42\x00",
	}

	if probe, exists := probes[port]; exists {
		conn.Write([]byte(probe))
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil {
			return string(buffer[:n])
		}
	}

	return ""
}

// AI-powered service identification
func (n *NetworkAnalyzerUseCase) identifyService(port int, banner string) (service, version string) {
	// Common service patterns
	servicePatterns := map[string]map[string]string{
		"HTTP": {
			"Apache":   `Apache/([0-9.]+)`,
			"nginx":    `nginx/([0-9.]+)`,
			"IIS":      `Microsoft-IIS/([0-9.]+)`,
			"lighttpd": `lighttpd/([0-9.]+)`,
		},
		"SSH": {
			"OpenSSH":  `OpenSSH_([0-9.]+)`,
			"Dropbear": `dropbear_([0-9.]+)`,
		},
		"FTP": {
			"vsftpd":    `vsftpd ([0-9.]+)`,
			"ProFTPD":   `ProFTPD ([0-9.]+)`,
			"FileZilla": `FileZilla Server ([0-9.]+)`,
		},
		"SMTP": {
			"Postfix":  `Postfix`,
			"Sendmail": `Sendmail ([0-9.]+)`,
			"Exim":     `Exim ([0-9.]+)`,
		},
	}

	// Port-based service identification
	portServices := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		993:   "IMAPS",
		995:   "POP3S",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
	}

	// Identify service by port
	if svc, exists := portServices[port]; exists {
		service = svc
	}

	// Refine identification using banner analysis
	if banner != "" {
		for svcType, patterns := range servicePatterns {
			for svcName, pattern := range patterns {
				if strings.Contains(strings.ToLower(banner), strings.ToLower(svcName)) {
					service = svcType
					// Extract version using regex if needed
					version = n.extractVersion(banner, pattern)
					break
				}
			}
		}
	}

	return service, version
}

// AI-powered operating system detection
func (n *NetworkAnalyzerUseCase) detectOperatingSystem(host *domain.NetworkHost) string {
	// OS fingerprinting based on open ports and services
	osIndicators := map[string][]int{
		"Linux":   {22, 80, 443, 25, 53},
		"Windows": {135, 139, 445, 3389, 1433},
		"macOS":   {22, 80, 443, 548, 631},
		"FreeBSD": {22, 80, 443, 25, 53},
	}

	openPorts := make(map[int]bool)
	for _, port := range host.Ports {
		if port.State == "open" {
			openPorts[port.Port] = true
		}
	}

	// Score each OS based on matching ports
	scores := make(map[string]int)
	for os, ports := range osIndicators {
		for _, port := range ports {
			if openPorts[port] {
				scores[os]++
			}
		}
	}

	// Return OS with highest score
	maxScore := 0
	detectedOS := "Unknown"
	for os, score := range scores {
		if score > maxScore {
			maxScore = score
			detectedOS = os
		}
	}

	// Additional heuristics based on service banners
	for _, port := range host.Ports {
		if port.Banner != "" {
			banner := strings.ToLower(port.Banner)
			if strings.Contains(banner, "ubuntu") || strings.Contains(banner, "debian") {
				return "Linux (Ubuntu/Debian)"
			}
			if strings.Contains(banner, "centos") || strings.Contains(banner, "rhel") {
				return "Linux (CentOS/RHEL)"
			}
			if strings.Contains(banner, "windows") || strings.Contains(banner, "microsoft") {
				return "Windows"
			}
		}
	}

	return detectedOS
}

// Helper methods
func (n *NetworkAnalyzerUseCase) validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	// Validate CIDR notation or IP address
	if _, _, err := net.ParseCIDR(target); err != nil {
		if net.ParseIP(target) == nil {
			return fmt.Errorf("invalid IP address or CIDR notation")
		}
	}

	return nil
}

func (n *NetworkAnalyzerUseCase) parseTargetIPs(target string) ([]string, error) {
	var ips []string

	// Check if it's a CIDR notation
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		// Generate IPs from CIDR
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); n.incrementIP(ip) {
			ips = append(ips, ip.String())
			if len(ips) > 1000 { // Limit to prevent abuse
				break
			}
		}
	} else if net.ParseIP(target) != nil {
		// Single IP address
		ips = append(ips, target)
	} else {
		return nil, fmt.Errorf("invalid target format")
	}

	return ips, nil
}

func (n *NetworkAnalyzerUseCase) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (n *NetworkAnalyzerUseCase) parsePortRange(portRange string) []int {
	var ports []int

	if portRange == "" {
		// Default common ports
		commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432}
		return commonPorts
	}

	// Parse port range (e.g., "1-1000" or "80,443,8080")
	if strings.Contains(portRange, "-") {
		parts := strings.Split(portRange, "-")
		if len(parts) == 2 {
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			for i := start; i <= end && i <= 65535; i++ {
				ports = append(ports, i)
			}
		}
	} else if strings.Contains(portRange, ",") {
		for _, portStr := range strings.Split(portRange, ",") {
			if port, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil {
				ports = append(ports, port)
			}
		}
	} else {
		if port, err := strconv.Atoi(portRange); err == nil {
			ports = append(ports, port)
		}
	}

	return ports
}

func (n *NetworkAnalyzerUseCase) pingHost(ip string, timeout int) bool {
	// Simple TCP connect test (since ICMP requires root privileges)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), time.Duration(timeout)*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	// Try other common ports
	commonPorts := []int{22, 23, 25, 53, 80, 443}
	for _, port := range commonPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Duration(timeout)*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}

func (n *NetworkAnalyzerUseCase) scanHostPorts(ip string, ports []int, config domain.NetworkScanConfig) []*domain.NetworkPort {
	var hostPorts []*domain.NetworkPort
	var wg sync.WaitGroup
	var mu sync.Mutex

	semaphore := make(chan struct{}, config.Threads)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if config.ScanTCP {
				if n.isPortOpen(ip, p, "tcp", config.Timeout) {
					mu.Lock()
					hostPorts = append(hostPorts, &domain.NetworkPort{
						Port:     p,
						Protocol: "tcp",
						State:    "open",
					})
					mu.Unlock()
				}
			}

			if config.ScanUDP {
				if n.isPortOpen(ip, p, "udp", config.Timeout) {
					mu.Lock()
					hostPorts = append(hostPorts, &domain.NetworkPort{
						Port:     p,
						Protocol: "udp",
						State:    "open",
					})
					mu.Unlock()
				}
			}
		}(port)
	}

	wg.Wait()
	return hostPorts
}

func (n *NetworkAnalyzerUseCase) isPortOpen(ip string, port int, protocol string, timeout int) bool {
	conn, err := net.DialTimeout(protocol, fmt.Sprintf("%s:%d", ip, port), time.Duration(timeout)*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (n *NetworkAnalyzerUseCase) extractVersion(banner, pattern string) string {
	// Simple version extraction - in a real implementation, use regex
	if strings.Contains(banner, "/") {
		parts := strings.Split(banner, "/")
		if len(parts) > 1 {
			versionPart := strings.Fields(parts[1])
			if len(versionPart) > 0 {
				return versionPart[0]
			}
		}
	}
	return ""
}
