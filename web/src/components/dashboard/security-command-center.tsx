'use client'

import React, { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import Link from 'next/link'
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  PlayIcon,
  StopIcon,
  PauseIcon,
  ArrowPathIcon,
  BoltIcon,
  EyeIcon,
  DocumentTextIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  CpuChipIcon,
  ServerIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton, SecurityButton } from '@/components/ui/cyberpunk-button'
import { HolographicDisplay, ParticleSystem } from '@/components/ui/cyberpunk-effects'
import { GlitchText } from '@/components/ui/cyberpunk-background'

// Quick Actions Panel
interface QuickActionsProps {
  className?: string
}

export const QuickActions: React.FC<QuickActionsProps> = ({ className }) => {
  const [activeScans, setActiveScans] = useState<Array<{
    id: string
    type: string
    status: 'running' | 'paused' | 'completed'
    progress: number
  }>>([])

  useEffect(() => {
    // Simulate active scans
    setActiveScans([
      { id: '1', type: 'Vulnerability Scan', status: 'running', progress: 67 },
      { id: '2', type: 'Network Discovery', status: 'paused', progress: 34 },
    ])
  }, [])

  const quickActions = [
    {
      id: 'vuln-scan',
      title: 'Vulnerability Scan',
      description: 'Start comprehensive vulnerability assessment',
      icon: ShieldCheckIcon,
      color: 'pink',
      href: '/dashboard/scans/vulnerability',
      level: 'critical' as const,
    },
    {
      id: 'network-scan',
      title: 'Network Scan',
      description: 'Discover and analyze network assets',
      icon: ServerIcon,
      color: 'green',
      href: '/dashboard/scans/network',
      level: 'safe' as const,
    },
    {
      id: 'threat-hunt',
      title: 'Threat Hunting',
      description: 'Proactive threat detection and analysis',
      icon: EyeIcon,
      color: 'purple',
      href: '/dashboard/threat-hunting',
      level: 'high' as const,
    },
    {
      id: 'incident-response',
      title: 'Incident Response',
      description: 'Manage and respond to security incidents',
      icon: ExclamationTriangleIcon,
      color: 'orange',
      href: '/dashboard/incidents',
      level: 'medium' as const,
    },
    {
      id: 'compliance-check',
      title: 'Compliance Check',
      description: 'Verify compliance with security standards',
      icon: DocumentTextIcon,
      color: 'blue',
      href: '/dashboard/compliance',
      level: 'medium' as const,
    },
    {
      id: 'ai-analysis',
      title: 'AI Analysis',
      description: 'Deploy AI-powered security analysis',
      icon: CpuChipIcon,
      color: 'blue',
      href: '/dashboard/ai-analysis',
      level: 'safe' as const,
    },
  ]

  return (
    <CyberpunkCard variant="security-critical" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={30} 
        color="pink" 
        speed="medium" 
        size="small"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-security-critical">
            <BoltIcon className="w-6 h-6" />
            <GlitchText intensity="low">SECURITY COMMAND CENTER</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="critical" size="sm">ARMED</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-6">
          {/* Active Scans Status */}
          {activeScans.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-sm font-cyber text-matrix-light uppercase tracking-wider">
                Active Operations
              </h4>
              {activeScans.map((scan) => (
                <HolographicDisplay key={scan.id} color="pink" intensity="low" className="p-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${
                        scan.status === 'running' ? 'bg-cyber-green-neon animate-neon-pulse' :
                        scan.status === 'paused' ? 'bg-cyber-orange-neon' :
                        'bg-cyber-blue-neon'
                      }`} />
                      <span className="text-sm font-cyber text-matrix-white">{scan.type}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-matrix-muted font-matrix">{scan.progress}%</span>
                      <div className="flex gap-1">
                        {scan.status === 'running' ? (
                          <CyberpunkButton variant="ghost-blue" size="sm">
                            <PauseIcon className="w-3 h-3" />
                          </CyberpunkButton>
                        ) : (
                          <CyberpunkButton variant="ghost-green" size="sm">
                            <PlayIcon className="w-3 h-3" />
                          </CyberpunkButton>
                        )}
                        <CyberpunkButton variant="ghost-pink" size="sm">
                          <StopIcon className="w-3 h-3" />
                        </CyberpunkButton>
                      </div>
                    </div>
                  </div>
                  <div className="mt-2 h-1 bg-matrix-surface rounded-full overflow-hidden">
                    <div 
                      className="h-full transition-all duration-1000 rounded-full bg-security-critical"
                      style={{ width: `${scan.progress}%` }}
                    />
                  </div>
                </HolographicDisplay>
              ))}
            </div>
          )}

          {/* Quick Action Buttons */}
          <div className="grid grid-cols-2 gap-4">
            {quickActions.map((action) => {
              const IconComponent = action.icon
              
              return (
                <Link key={action.id} href={action.href}>
                  <HolographicDisplay 
                    color={action.color as any} 
                    intensity="medium" 
                    className="p-4 group hover:scale-105 transition-all duration-300 cursor-pointer"
                  >
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className={`p-2 rounded-lg border border-cyber-${action.color}-neon/30 bg-cyber-${action.color}-neon/10`}>
                          <IconComponent className={`w-5 h-5 text-cyber-${action.color}-neon group-hover:animate-neon-pulse`} />
                        </div>
                        <SecurityButton level={action.level} size="sm">
                          {action.level.toUpperCase()}
                        </SecurityButton>
                      </div>
                      
                      <div>
                        <h4 className="font-cyber font-bold text-matrix-white text-sm mb-1">
                          {action.title}
                        </h4>
                        <p className="text-xs text-matrix-light leading-relaxed">
                          {action.description}
                        </p>
                      </div>

                      <CyberpunkButton
                        variant={`ghost-${action.color}` as any}
                        size="sm"
                        className="w-full group-hover:animate-neon-pulse"
                      >
                        <PlayIcon className="w-3 h-3 mr-2" />
                        Execute
                      </CyberpunkButton>
                    </div>
                  </HolographicDisplay>
                </Link>
              )
            })}
          </div>

          {/* Emergency Actions */}
          <div className="border-t border-security-critical/30 pt-4">
            <h4 className="text-sm font-cyber text-security-critical uppercase tracking-wider mb-3">
              Emergency Response
            </h4>
            <div className="grid grid-cols-2 gap-3">
              <CyberpunkButton variant="filled-pink" size="sm" className="animate-neon-pulse">
                <ExclamationTriangleIcon className="w-4 h-4 mr-2" />
                Lockdown
              </CyberpunkButton>
              <CyberpunkButton variant="ghost-pink" size="sm">
                <ArrowPathIcon className="w-4 h-4 mr-2" />
                Reset All
              </CyberpunkButton>
            </div>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Incident Management Panel
interface IncidentManagementProps {
  className?: string
}

export const IncidentManagement: React.FC<IncidentManagementProps> = ({ className }) => {
  const [incidents, setIncidents] = useState<Array<{
    id: string
    title: string
    severity: 'critical' | 'high' | 'medium' | 'low'
    status: 'open' | 'investigating' | 'resolved' | 'closed'
    assignee: string
    createdAt: Date
    lastUpdate: Date
  }>>([])

  useEffect(() => {
    const mockIncidents = [
      {
        id: 'INC-001',
        title: 'Suspicious Network Activity Detected',
        severity: 'high' as const,
        status: 'investigating' as const,
        assignee: 'Security Team Alpha',
        createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
        lastUpdate: new Date(Date.now() - 30 * 60 * 1000),
      },
      {
        id: 'INC-002',
        title: 'Failed Login Attempts Spike',
        severity: 'medium' as const,
        status: 'open' as const,
        assignee: 'SOC Analyst',
        createdAt: new Date(Date.now() - 4 * 60 * 60 * 1000),
        lastUpdate: new Date(Date.now() - 1 * 60 * 60 * 1000),
      },
      {
        id: 'INC-003',
        title: 'Malware Detection in Email',
        severity: 'critical' as const,
        status: 'resolved' as const,
        assignee: 'Incident Response Team',
        createdAt: new Date(Date.now() - 6 * 60 * 60 * 1000),
        lastUpdate: new Date(Date.now() - 10 * 60 * 1000),
      },
    ]

    setIncidents(mockIncidents)
  }, [])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'security-critical'
      case 'high': return 'cyber-orange-neon'
      case 'medium': return 'cyber-blue-neon'
      case 'low': return 'cyber-green-neon'
      default: return 'matrix-muted'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'security-critical'
      case 'investigating': return 'cyber-orange-neon'
      case 'resolved': return 'cyber-green-neon'
      case 'closed': return 'matrix-muted'
      default: return 'matrix-muted'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'open': return ExclamationTriangleIcon
      case 'investigating': return ClockIcon
      case 'resolved': return CheckCircleIcon
      case 'closed': return XCircleIcon
      default: return ClockIcon
    }
  }

  return (
    <CyberpunkCard variant="neon-orange" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={25} 
        color="orange" 
        speed="slow" 
        size="small"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-orange-neon">
            <ExclamationTriangleIcon className="w-6 h-6" />
            <GlitchText intensity="low">INCIDENT MANAGEMENT</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="high" size="sm">ACTIVE</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4">
          {/* Incident Summary */}
          <div className="grid grid-cols-4 gap-3 text-center">
            <div>
              <div className="text-lg font-display font-bold text-security-critical">
                {incidents.filter(i => i.status === 'open').length}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Open</div>
            </div>
            <div>
              <div className="text-lg font-display font-bold text-cyber-orange-neon">
                {incidents.filter(i => i.status === 'investigating').length}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Investigating</div>
            </div>
            <div>
              <div className="text-lg font-display font-bold text-cyber-green-neon">
                {incidents.filter(i => i.status === 'resolved').length}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Resolved</div>
            </div>
            <div>
              <div className="text-lg font-display font-bold text-matrix-muted">
                {incidents.filter(i => i.status === 'closed').length}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Closed</div>
            </div>
          </div>

          {/* Recent Incidents */}
          <div className="space-y-3 max-h-64 overflow-y-auto scrollbar-cyber">
            {incidents.map((incident) => {
              const severityColor = getSeverityColor(incident.severity)
              const statusColor = getStatusColor(incident.status)
              const StatusIcon = getStatusIcon(incident.status)
              
              return (
                <HolographicDisplay
                  key={incident.id}
                  color="orange"
                  intensity="low"
                  className="p-3 cursor-pointer hover:scale-[1.02] transition-all duration-300"
                >
                  <div className="space-y-2">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2">
                        <StatusIcon className={`w-4 h-4 text-${statusColor}`} />
                        <span className="text-xs font-cyber text-matrix-muted">{incident.id}</span>
                        <span className={`text-xs font-cyber uppercase text-${severityColor}`}>
                          {incident.severity}
                        </span>
                      </div>
                      <span className={`text-xs font-cyber uppercase text-${statusColor}`}>
                        {incident.status}
                      </span>
                    </div>
                    
                    <h4 className="font-cyber font-bold text-matrix-white text-sm">
                      {incident.title}
                    </h4>
                    
                    <div className="flex items-center justify-between text-xs text-matrix-muted">
                      <span>Assigned: {incident.assignee}</span>
                      <span>{incident.lastUpdate.toLocaleTimeString()}</span>
                    </div>
                  </div>
                </HolographicDisplay>
              )
            })}
          </div>

          {/* Quick Actions */}
          <div className="flex gap-2">
            <Link href="/dashboard/incidents/new" className="flex-1">
              <CyberpunkButton variant="ghost-orange" size="sm" className="w-full">
                Create Incident
              </CyberpunkButton>
            </Link>
            <Link href="/dashboard/incidents" className="flex-1">
              <CyberpunkButton variant="ghost-blue" size="sm" className="w-full">
                View All
              </CyberpunkButton>
            </Link>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Compliance Monitoring Panel
interface ComplianceMonitoringProps {
  className?: string
}

export const ComplianceMonitoring: React.FC<ComplianceMonitoringProps> = ({ className }) => {
  const [complianceData, setComplianceData] = useState<Array<{
    framework: string
    score: number
    status: 'compliant' | 'partial' | 'non-compliant'
    lastAudit: Date
    nextAudit: Date
    criticalIssues: number
  }>>([])

  useEffect(() => {
    const mockData = [
      {
        framework: 'ISO 27001',
        score: 94,
        status: 'compliant' as const,
        lastAudit: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        nextAudit: new Date(Date.now() + 335 * 24 * 60 * 60 * 1000),
        criticalIssues: 0,
      },
      {
        framework: 'SOC 2 Type II',
        score: 87,
        status: 'partial' as const,
        lastAudit: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000),
        nextAudit: new Date(Date.now() + 320 * 24 * 60 * 60 * 1000),
        criticalIssues: 2,
      },
      {
        framework: 'NIST CSF',
        score: 91,
        status: 'compliant' as const,
        lastAudit: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000),
        nextAudit: new Date(Date.now() + 350 * 24 * 60 * 60 * 1000),
        criticalIssues: 0,
      },
      {
        framework: 'GDPR',
        score: 78,
        status: 'partial' as const,
        lastAudit: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000),
        nextAudit: new Date(Date.now() + 305 * 24 * 60 * 60 * 1000),
        criticalIssues: 3,
      },
    ]

    setComplianceData(mockData)
  }, [])

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant': return 'cyber-green-neon'
      case 'partial': return 'cyber-orange-neon'
      case 'non-compliant': return 'security-critical'
      default: return 'matrix-muted'
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'cyber-green-neon'
    if (score >= 75) return 'cyber-orange-neon'
    return 'security-critical'
  }

  return (
    <CyberpunkCard variant="neon-blue" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem
        particleCount={20}
        color="blue"
        speed="medium"
        size="small"
        className="opacity-20"
      />

      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-blue-neon">
            <DocumentTextIcon className="w-6 h-6" />
            <GlitchText intensity="low">COMPLIANCE MONITORING</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="medium" size="sm">TRACKING</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4">
          {/* Overall Compliance Score */}
          <HolographicDisplay color="blue" intensity="medium" className="p-4 text-center">
            <div className="space-y-2">
              <div className="text-3xl font-display font-bold text-cyber-blue-neon">
                {Math.round(complianceData.reduce((acc, item) => acc + item.score, 0) / complianceData.length)}%
              </div>
              <div className="text-sm font-cyber text-matrix-light uppercase tracking-wider">
                Overall Compliance Score
              </div>
            </div>
          </HolographicDisplay>

          {/* Framework Status */}
          <div className="space-y-3 max-h-64 overflow-y-auto scrollbar-cyber">
            {complianceData.map((framework) => {
              const statusColor = getStatusColor(framework.status)
              const scoreColor = getScoreColor(framework.score)

              return (
                <HolographicDisplay
                  key={framework.framework}
                  color="blue"
                  intensity="low"
                  className="p-3"
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="font-cyber font-bold text-matrix-white">
                        {framework.framework}
                      </h4>
                      <div className="flex items-center gap-2">
                        <span className={`text-sm font-display font-bold text-${scoreColor}`}>
                          {framework.score}%
                        </span>
                        <span className={`text-xs font-cyber uppercase text-${statusColor}`}>
                          {framework.status}
                        </span>
                      </div>
                    </div>

                    <div className="h-2 bg-matrix-surface rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all duration-1000 rounded-full bg-${scoreColor}`}
                        style={{ width: `${framework.score}%` }}
                      />
                    </div>

                    <div className="grid grid-cols-3 gap-4 text-xs">
                      <div>
                        <span className="text-matrix-muted font-cyber">Last Audit:</span>
                        <div className="text-matrix-white font-matrix">
                          {framework.lastAudit.toLocaleDateString()}
                        </div>
                      </div>
                      <div>
                        <span className="text-matrix-muted font-cyber">Next Audit:</span>
                        <div className="text-matrix-white font-matrix">
                          {framework.nextAudit.toLocaleDateString()}
                        </div>
                      </div>
                      <div>
                        <span className="text-matrix-muted font-cyber">Critical Issues:</span>
                        <div className={`font-matrix font-bold ${
                          framework.criticalIssues > 0 ? 'text-security-critical' : 'text-cyber-green-neon'
                        }`}>
                          {framework.criticalIssues}
                        </div>
                      </div>
                    </div>
                  </div>
                </HolographicDisplay>
              )
            })}
          </div>

          {/* Quick Actions */}
          <div className="grid grid-cols-2 gap-3">
            <Link href="/dashboard/compliance/audit">
              <CyberpunkButton variant="ghost-blue" size="sm" className="w-full">
                Run Audit
              </CyberpunkButton>
            </Link>
            <Link href="/dashboard/compliance/reports">
              <CyberpunkButton variant="ghost-green" size="sm" className="w-full">
                View Reports
              </CyberpunkButton>
            </Link>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}
