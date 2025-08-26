'use client'

import React, { useState, useEffect } from 'react'
import { 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  BoltIcon,
  EyeIcon,
  CpuChipIcon,
  PlayIcon,
  StopIcon,
  DocumentTextIcon,
  ChartBarIcon,
  ClockIcon
} from '@heroicons/react/24/outline'
import { CyberpunkBackground, MatrixRain, GlitchText, NeonBorder } from '@/components/ui/cyberpunk-background'
import { CyberpunkButton, SecurityButton, MatrixButton } from '@/components/ui/cyberpunk-button'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardDescription, CyberpunkCardHeader, CyberpunkCardTitle, SecurityCard, MatrixCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkNav } from '@/components/ui/cyberpunk-nav'
import { CyberpunkSettingsButton } from '@/components/ui/cyberpunk-settings'

const navItems = [
  { href: '/', label: 'Home', icon: <ShieldCheckIcon className="w-5 h-5" /> },
  { href: '/demo', label: 'Demo', icon: <CpuChipIcon className="w-5 h-5" /> },
  { href: '/scanner', label: 'AI Security Scanner', icon: <EyeIcon className="w-5 h-5" />, badge: 'ACTIVE' },
  { href: '/analytics', label: 'Analytics', icon: <ChartBarIcon className="w-5 h-5" /> },
]

// Mock data based on your Go backend structure
const owaspCategories = [
  { id: 'LLM01', name: 'Prompt Injection', severity: 'critical', count: 3 },
  { id: 'LLM02', name: 'Insecure Output Handling', severity: 'high', count: 2 },
  { id: 'LLM03', name: 'Training Data Poisoning', severity: 'medium', count: 1 },
  { id: 'LLM04', name: 'Model Denial of Service', severity: 'medium', count: 1 },
  { id: 'LLM05', name: 'Supply Chain Vulnerabilities', severity: 'high', count: 2 },
  { id: 'LLM06', name: 'Sensitive Information Disclosure', severity: 'critical', count: 4 },
]

const scannerTypes = [
  { 
    id: 'prompt_injection', 
    name: 'Prompt Injection Scanner', 
    description: 'Detects prompt injection vulnerabilities in LLM systems',
    status: 'active',
    lastScan: '2 min ago',
    findings: 3
  },
  { 
    id: 'data_extraction', 
    name: 'Data Extraction Scanner', 
    description: 'Identifies potential data extraction vulnerabilities',
    status: 'active',
    lastScan: '5 min ago',
    findings: 2
  },
  { 
    id: 'model_inversion', 
    name: 'Model Inversion Scanner', 
    description: 'Scans for model inversion attack vectors',
    status: 'idle',
    lastScan: '15 min ago',
    findings: 1
  },
]

const recentVulnerabilities = [
  {
    id: '1',
    name: 'Prompt Injection Vulnerability',
    severity: 'critical',
    owasp: 'LLM01',
    cvss: 7.5,
    description: 'AI model susceptible to prompt injection attacks',
    discoveredAt: '2 minutes ago',
    status: 'new'
  },
  {
    id: '2',
    name: 'Data Extraction Vulnerability',
    severity: 'high',
    owasp: 'LLM02',
    cvss: 6.5,
    description: 'System allows unauthorized data extraction',
    discoveredAt: '5 minutes ago',
    status: 'analyzing'
  },
  {
    id: '3',
    name: 'Model Inversion Vulnerability',
    severity: 'medium',
    owasp: 'LLM03',
    cvss: 5.5,
    description: 'AI model vulnerable to model inversion attacks',
    discoveredAt: '15 minutes ago',
    status: 'confirmed'
  },
]

export default function SecurityScannerPage() {
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [activeTab, setActiveTab] = useState('overview')
  const [selectedTarget, setSelectedTarget] = useState('localhost:8080')

  // Simulate scanning progress
  useEffect(() => {
    if (isScanning) {
      const interval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 100) {
            setIsScanning(false)
            return 0
          }
          return prev + Math.random() * 10
        })
      }, 500)
      return () => clearInterval(interval)
    }
  }, [isScanning])

  const startScan = () => {
    setIsScanning(true)
    setScanProgress(0)
  }

  const stopScan = () => {
    setIsScanning(false)
    setScanProgress(0)
  }

  const getSeverityLevel = (severity: string) => {
    switch (severity) {
      case 'critical': return 'critical'
      case 'high': return 'high'
      case 'medium': return 'medium'
      case 'low': return 'low'
      default: return 'safe'
    }
  }

  return (
    <CyberpunkBackground variant="circuit" intensity="low" color="blue" className="min-h-screen">
      <MatrixRain intensity="low" color="#00ff41" className="opacity-5" />
      
      <CyberpunkSettingsButton />
      
      <CyberpunkNav 
        items={navItems}
        theme="blue"
        logoText="HackAI"
        logoHref="/"
        className="relative z-20"
      />
      
      <div className="container mx-auto px-4 py-8 relative z-10">
        {/* Header */}
        <div className="mb-12 text-center">
          <h1 className="text-5xl font-display font-bold text-matrix-white mb-4">
            <GlitchText intensity="medium">
              AI Security Scanner
            </GlitchText>
          </h1>
          <p className="text-xl text-matrix-light font-cyber max-w-4xl mx-auto">
            Advanced AI-powered penetration testing with OWASP LLM Top 10 compliance
          </p>
        </div>

        {/* Scan Control Panel */}
        <div className="mb-8">
          <SecurityCard level="critical" size="lg" className="mb-6">
            <CyberpunkCardHeader accent>
              <div className="flex items-center justify-between">
                <CyberpunkCardTitle font="cyber" className="flex items-center gap-3">
                  <ShieldCheckIcon className="w-6 h-6" />
                  Scan Control Center
                </CyberpunkCardTitle>
                <div className="flex items-center gap-2">
                  <NeonBorder color="green" intensity="medium" className="px-3 py-1">
                    <span className="text-cyber-green-neon font-cyber text-sm">
                      {isScanning ? 'SCANNING' : 'READY'}
                    </span>
                  </NeonBorder>
                </div>
              </div>
            </CyberpunkCardHeader>
            <CyberpunkCardContent>
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Target Selection */}
                <div className="space-y-3">
                  <label className="text-sm font-cyber text-matrix-light">Target System</label>
                  <select 
                    value={selectedTarget}
                    onChange={(e) => setSelectedTarget(e.target.value)}
                    className="w-full bg-matrix-surface border border-cyber-blue-neon/30 text-cyber-blue-neon rounded px-3 py-2 font-cyber focus:outline-none focus:border-cyber-blue-neon"
                  >
                    <option value="localhost:8080">localhost:8080 (Development)</option>
                    <option value="staging.hackai.dev">staging.hackai.dev</option>
                    <option value="api.hackai.dev">api.hackai.dev</option>
                  </select>
                </div>

                {/* Scan Progress */}
                <div className="space-y-3">
                  <label className="text-sm font-cyber text-matrix-light">Scan Progress</label>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm font-cyber">
                      <span className="text-matrix-light">Progress</span>
                      <span className="text-cyber-blue-neon">{Math.round(scanProgress)}%</span>
                    </div>
                    <div className="w-full bg-matrix-surface rounded-full h-2 border border-cyber-blue-neon/30">
                      <div 
                        className="bg-gradient-to-r from-cyber-blue-neon to-cyber-pink-neon h-2 rounded-full transition-all duration-300"
                        style={{ width: `${scanProgress}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Scan Controls */}
                <div className="space-y-3">
                  <label className="text-sm font-cyber text-matrix-light">Actions</label>
                  <div className="flex gap-2">
                    {!isScanning ? (
                      <CyberpunkButton 
                        variant="filled-green" 
                        onClick={startScan}
                        className="flex-1"
                        scanLine
                      >
                        <PlayIcon className="w-4 h-4 mr-2" />
                        Start Scan
                      </CyberpunkButton>
                    ) : (
                      <CyberpunkButton 
                        variant="security-critical" 
                        onClick={stopScan}
                        className="flex-1"
                        animation="pulse"
                      >
                        <StopIcon className="w-4 h-4 mr-2" />
                        Stop Scan
                      </CyberpunkButton>
                    )}
                    <CyberpunkButton variant="ghost-blue" size="default">
                      <DocumentTextIcon className="w-4 h-4" />
                    </CyberpunkButton>
                  </div>
                </div>
              </div>
            </CyberpunkCardContent>
          </SecurityCard>
        </div>

        {/* Tab Navigation */}
        <div className="mb-8 flex justify-center">
          <div className="flex space-x-2 bg-matrix-dark/80 p-2 rounded-lg border border-cyber-blue-neon/30">
            {['overview', 'scanners', 'vulnerabilities', 'reports'].map((tab) => (
              <CyberpunkButton
                key={tab}
                variant={activeTab === tab ? 'filled-blue' : 'ghost-blue'}
                size="sm"
                onClick={() => setActiveTab(tab)}
                className="capitalize"
              >
                {tab}
              </CyberpunkButton>
            ))}
          </div>
        </div>

        {/* Content Sections */}
        {activeTab === 'overview' && (
          <div className="space-y-8">
            {/* OWASP LLM Top 10 Overview */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {owaspCategories.map((category) => (
                <SecurityCard 
                  key={category.id} 
                  level={getSeverityLevel(category.severity)}
                  interactive
                  className="hover:scale-105 transition-all duration-300"
                >
                  <CyberpunkCardHeader>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-cyber text-current opacity-80">{category.id}</span>
                      <SecurityButton level={getSeverityLevel(category.severity)} size="sm">
                        {category.count}
                      </SecurityButton>
                    </div>
                    <CyberpunkCardTitle font="cyber" className="text-lg">
                      {category.name}
                    </CyberpunkCardTitle>
                  </CyberpunkCardHeader>
                  <CyberpunkCardContent>
                    <div className="text-sm text-matrix-light font-cyber">
                      {category.count} vulnerabilities detected
                    </div>
                  </CyberpunkCardContent>
                </SecurityCard>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'scanners' && (
          <div className="space-y-6">
            {scannerTypes.map((scanner) => (
              <MatrixCard key={scanner.id} size="lg" interactive>
                <CyberpunkCardHeader accent>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded bg-current/10 border border-current/30">
                        <BoltIcon className="w-5 h-5 text-current" />
                      </div>
                      <div>
                        <CyberpunkCardTitle font="cyber">{scanner.name}</CyberpunkCardTitle>
                        <CyberpunkCardDescription>{scanner.description}</CyberpunkCardDescription>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <div className="text-sm font-cyber text-matrix-light">Last Scan</div>
                        <div className="text-xs text-cyber-green-neon">{scanner.lastScan}</div>
                      </div>
                      <SecurityButton 
                        level={scanner.status === 'active' ? 'safe' : 'medium'} 
                        size="sm"
                      >
                        {scanner.status.toUpperCase()}
                      </SecurityButton>
                    </div>
                  </div>
                </CyberpunkCardHeader>
                <CyberpunkCardContent>
                  <div className="flex items-center justify-between">
                    <div className="text-sm font-cyber text-matrix-light">
                      Findings: <span className="text-cyber-blue-neon">{scanner.findings}</span>
                    </div>
                    <CyberpunkButton variant="ghost-green" size="sm">
                      Configure
                    </CyberpunkButton>
                  </div>
                </CyberpunkCardContent>
              </MatrixCard>
            ))}
          </div>
        )}

        {activeTab === 'vulnerabilities' && (
          <div className="space-y-6">
            {recentVulnerabilities.map((vuln) => (
              <SecurityCard 
                key={vuln.id} 
                level={getSeverityLevel(vuln.severity)}
                size="lg"
                interactive
              >
                <CyberpunkCardHeader accent>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <ExclamationTriangleIcon className="w-6 h-6 text-current" />
                      <div>
                        <CyberpunkCardTitle font="cyber">{vuln.name}</CyberpunkCardTitle>
                        <CyberpunkCardDescription>{vuln.description}</CyberpunkCardDescription>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <div className="text-sm font-cyber text-current">CVSS: {vuln.cvss}</div>
                        <div className="text-xs text-matrix-muted">{vuln.owasp}</div>
                      </div>
                      <SecurityButton level={getSeverityLevel(vuln.severity)} size="sm">
                        {vuln.severity.toUpperCase()}
                      </SecurityButton>
                    </div>
                  </div>
                </CyberpunkCardHeader>
                <CyberpunkCardContent>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="text-sm font-cyber text-matrix-light">
                        <ClockIcon className="w-4 h-4 inline mr-1" />
                        {vuln.discoveredAt}
                      </div>
                      <NeonBorder color="blue" intensity="low" className="px-2 py-1">
                        <span className="text-xs text-cyber-blue-neon font-cyber">
                          {vuln.status.toUpperCase()}
                        </span>
                      </NeonBorder>
                    </div>
                    <div className="flex gap-2">
                      <CyberpunkButton variant="ghost-blue" size="sm">
                        Details
                      </CyberpunkButton>
                      <CyberpunkButton variant="ghost-green" size="sm">
                        Remediate
                      </CyberpunkButton>
                    </div>
                  </div>
                </CyberpunkCardContent>
              </SecurityCard>
            ))}
          </div>
        )}

        {activeTab === 'reports' && (
          <div className="text-center py-12">
            <MatrixCard size="xl">
              <CyberpunkCardContent>
                <GlitchText intensity="medium">
                  <span className="text-4xl font-display">Report Generation</span>
                </GlitchText>
                <p className="text-matrix-light mt-4 font-cyber">
                  Advanced penetration testing reports coming soon...
                </p>
                <div className="mt-8">
                  <CyberpunkButton variant="filled-blue" size="lg" scanLine>
                    Generate Report
                  </CyberpunkButton>
                </div>
              </CyberpunkCardContent>
            </MatrixCard>
          </div>
        )}
      </div>
    </CyberpunkBackground>
  )
}
