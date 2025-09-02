'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  FireIcon,
  EyeIcon,
  BoltIcon,
  ChartBarIcon,
  ClockIcon,
  ServerIcon,
  CpuChipIcon,
  GlobeAltIcon,
  LockClosedIcon,
  BugAntIcon,
  CommandLineIcon,
  DocumentTextIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { useAuth } from '@/hooks/use-auth'
import { formatRelativeTime } from '@/lib/utils'

// Mock data for security dashboard - in production this would come from real-time APIs
const securityMetrics = {
  overallThreatLevel: 'Medium',
  threatScore: 0.45,
  activeThreats: 12,
  blockedAttacks: 1247,
  vulnerabilities: {
    critical: 2,
    high: 8,
    medium: 15,
    low: 23,
  },
  systemHealth: 98.5,
  uptime: '99.9%',
  lastScan: new Date(Date.now() - 15 * 60 * 1000),
}

const recentThreats = [
  {
    id: 1,
    type: 'Prompt Injection',
    severity: 'High',
    source: '192.168.1.100',
    timestamp: new Date(Date.now() - 5 * 60 * 1000),
    status: 'Blocked',
    description: 'Attempted prompt injection attack detected and blocked',
    threatScore: 0.85,
  },
  {
    id: 2,
    type: 'Model Extraction',
    severity: 'Critical',
    source: '10.0.0.45',
    timestamp: new Date(Date.now() - 12 * 60 * 1000),
    status: 'Investigating',
    description: 'Suspicious model extraction attempt via API queries',
    threatScore: 0.92,
  },
  {
    id: 3,
    type: 'Data Poisoning',
    severity: 'Medium',
    source: '172.16.0.23',
    timestamp: new Date(Date.now() - 25 * 60 * 1000),
    status: 'Mitigated',
    description: 'Potential data poisoning attempt in training pipeline',
    threatScore: 0.67,
  },
  {
    id: 4,
    type: 'Adversarial Input',
    severity: 'High',
    source: '203.0.113.15',
    timestamp: new Date(Date.now() - 35 * 60 * 1000),
    status: 'Blocked',
    description: 'Adversarial input designed to fool AI model',
    threatScore: 0.78,
  },
]

const systemComponents = [
  {
    name: 'AI Firewall',
    status: 'Healthy',
    uptime: '99.9%',
    lastCheck: new Date(Date.now() - 2 * 60 * 1000),
    threats: 45,
    icon: ShieldCheckIcon,
    color: 'cyber-green-neon',
  },
  {
    name: 'Prompt Injection Guard',
    status: 'Healthy',
    uptime: '99.8%',
    lastCheck: new Date(Date.now() - 1 * 60 * 1000),
    threats: 23,
    icon: LockClosedIcon,
    color: 'cyber-blue-neon',
  },
  {
    name: 'Threat Intelligence',
    status: 'Warning',
    uptime: '98.5%',
    lastCheck: new Date(Date.now() - 3 * 60 * 1000),
    threats: 67,
    icon: EyeIcon,
    color: 'cyber-orange-neon',
  },
  {
    name: 'Vulnerability Scanner',
    status: 'Healthy',
    uptime: '99.7%',
    lastCheck: new Date(Date.now() - 1 * 60 * 1000),
    threats: 12,
    icon: BugAntIcon,
    color: 'cyber-green-neon',
  },
  {
    name: 'Security Orchestrator',
    status: 'Healthy',
    uptime: '99.9%',
    lastCheck: new Date(Date.now() - 30 * 1000),
    threats: 8,
    icon: CpuChipIcon,
    color: 'cyber-purple-neon',
  },
  {
    name: 'Incident Response',
    status: 'Healthy',
    uptime: '100%',
    lastCheck: new Date(Date.now() - 45 * 1000),
    threats: 3,
    icon: BoltIcon,
    color: 'cyber-green-neon',
  },
]

const alertCategories = [
  { name: 'Critical', count: 2, color: 'security-critical', icon: FireIcon },
  { name: 'High', count: 8, color: 'cyber-orange-neon', icon: ExclamationTriangleIcon },
  { name: 'Medium', count: 15, color: 'cyber-blue-neon', icon: EyeIcon },
  { name: 'Low', count: 23, color: 'cyber-green-neon', icon: ShieldCheckIcon },
]

export default function SecurityDashboard() {
  const { user } = useAuth()
  const [activeTab, setActiveTab] = useState('overview')
  const [realTimeData, setRealTimeData] = useState(securityMetrics)

  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      setRealTimeData(prev => ({
        ...prev,
        threatScore: Math.max(0, Math.min(1, prev.threatScore + (Math.random() - 0.5) * 0.1)),
        activeThreats: Math.max(0, prev.activeThreats + Math.floor((Math.random() - 0.5) * 3)),
        blockedAttacks: prev.blockedAttacks + Math.floor(Math.random() * 5),
        systemHealth: Math.max(95, Math.min(100, prev.systemHealth + (Math.random() - 0.5) * 2)),
      }))
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  const getThreatLevelColor = (score: number) => {
    if (score >= 0.8) return 'security-critical'
    if (score >= 0.6) return 'cyber-orange-neon'
    if (score >= 0.4) return 'cyber-blue-neon'
    return 'cyber-green-neon'
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'security-critical'
      case 'high': return 'cyber-orange-neon'
      case 'medium': return 'cyber-blue-neon'
      case 'low': return 'cyber-green-neon'
      default: return 'matrix-text'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'healthy': return 'cyber-green-neon'
      case 'warning': return 'cyber-orange-neon'
      case 'critical': return 'security-critical'
      case 'blocked': return 'cyber-green-neon'
      case 'investigating': return 'cyber-orange-neon'
      case 'mitigated': return 'cyber-blue-neon'
      default: return 'matrix-text'
    }
  }

  return (
    <div className="min-h-screen bg-matrix-void p-4 md:p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-display font-bold text-security-critical">
            Security Dashboard
          </h1>
          <p className="text-matrix-text mt-1">
            Real-time security monitoring and threat intelligence
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          <Badge 
            variant="outline" 
            className={`border-${getThreatLevelColor(realTimeData.threatScore)} text-${getThreatLevelColor(realTimeData.threatScore)}`}
          >
            Threat Level: {realTimeData.overallThreatLevel}
          </Badge>
          
          <CyberpunkButton variant="security-critical" size="sm">
            <BoltIcon className="w-4 h-4" />
            Emergency Response
          </CyberpunkButton>
        </div>
      </div>

      {/* Key Metrics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <CyberpunkCard variant="security-critical" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-security-critical/20 rounded-lg">
              <FireIcon className="w-6 h-6 text-security-critical" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-security-critical">
                {realTimeData.activeThreats}
              </div>
              <div className="text-sm text-matrix-text">Active Threats</div>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-green" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-green-neon/20 rounded-lg">
              <ShieldCheckIcon className="w-6 h-6 text-cyber-green-neon" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-cyber-green-neon">
                {realTimeData.blockedAttacks.toLocaleString()}
              </div>
              <div className="text-sm text-matrix-text">Blocked Attacks</div>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-blue" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-blue-neon/20 rounded-lg">
              <ServerIcon className="w-6 h-6 text-cyber-blue-neon" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-cyber-blue-neon">
                {realTimeData.systemHealth.toFixed(1)}%
              </div>
              <div className="text-sm text-matrix-text">System Health</div>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-orange" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-orange-neon/20 rounded-lg">
              <ChartBarIcon className="w-6 h-6 text-cyber-orange-neon" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-cyber-orange-neon">
                {(realTimeData.threatScore * 100).toFixed(0)}%
              </div>
              <div className="text-sm text-matrix-text">Threat Score</div>
            </div>
          </div>
        </CyberpunkCard>
      </div>

      {/* Threat Level Indicator */}
      <CyberpunkCard variant="glass-blue" size="lg">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-cyber-blue-neon">
              Current Threat Level
            </h3>
            <div className="text-right">
              <div className={`text-2xl font-bold font-cyber text-${getThreatLevelColor(realTimeData.threatScore)}`}>
                {(realTimeData.threatScore * 100).toFixed(0)}%
              </div>
              <div className="text-sm text-matrix-text">Risk Score</div>
            </div>
          </div>
          
          <Progress 
            value={realTimeData.threatScore * 100} 
            className="h-4"
            indicatorClassName={`bg-${getThreatLevelColor(realTimeData.threatScore)}`}
          />
          
          <div className="flex justify-between text-sm text-matrix-text">
            <span>Low Risk</span>
            <span>Current: {realTimeData.overallThreatLevel}</span>
            <span>Critical Risk</span>
          </div>
        </div>
      </CyberpunkCard>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Threats */}
        <div className="lg:col-span-2">
          <CyberpunkCard variant="security-critical" size="lg">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-security-critical">
                  Recent Threats
                </h3>
                <CyberpunkButton variant="ghost-blue" size="sm">
                  View All
                </CyberpunkButton>
              </div>
              
              <div className="space-y-3">
                {recentThreats.map((threat, index) => (
                  <motion.div
                    key={threat.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                  >
                    <CyberpunkCard variant="glass-dark" size="sm">
                      <div className="flex items-start gap-4">
                        <div className={`p-2 rounded-lg bg-${getSeverityColor(threat.severity)}/20`}>
                          <ExclamationTriangleIcon className={`w-5 h-5 text-${getSeverityColor(threat.severity)}`} />
                        </div>
                        
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <h4 className="font-medium text-matrix-white truncate">
                              {threat.type}
                            </h4>
                            <Badge 
                              variant="outline" 
                              className={`border-${getSeverityColor(threat.severity)} text-${getSeverityColor(threat.severity)} text-xs`}
                            >
                              {threat.severity}
                            </Badge>
                          </div>
                          <p className="text-sm text-matrix-text mb-2">
                            {threat.description}
                          </p>
                          <div className="flex items-center justify-between text-xs text-matrix-text">
                            <span>Source: {threat.source}</span>
                            <span>{formatRelativeTime(threat.timestamp)}</span>
                          </div>
                          <div className="flex items-center justify-between mt-2">
                            <div className="flex items-center gap-2">
                              <span className="text-xs text-matrix-text">Threat Score:</span>
                              <span className={`text-xs font-cyber text-${getSeverityColor(threat.severity)}`}>
                                {(threat.threatScore * 100).toFixed(0)}%
                              </span>
                            </div>
                            <Badge 
                              variant="outline" 
                              className={`border-${getStatusColor(threat.status)} text-${getStatusColor(threat.status)} text-xs`}
                            >
                              {threat.status}
                            </Badge>
                          </div>
                        </div>
                      </div>
                    </CyberpunkCard>
                  </motion.div>
                ))}
              </div>
            </div>
          </CyberpunkCard>
        </div>

        {/* System Status & Alerts */}
        <div className="space-y-6">
          {/* Alert Summary */}
          <CyberpunkCard variant="neon-orange" size="lg">
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-cyber-orange-neon">
                Alert Summary
              </h3>
              
              <div className="space-y-3">
                {alertCategories.map((category) => {
                  const IconComponent = category.icon
                  return (
                    <div key={category.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <IconComponent className={`w-5 h-5 text-${category.color}`} />
                        <span className="text-matrix-white">{category.name}</span>
                      </div>
                      <Badge 
                        variant="outline" 
                        className={`border-${category.color} text-${category.color}`}
                      >
                        {category.count}
                      </Badge>
                    </div>
                  )
                })}
              </div>
            </div>
          </CyberpunkCard>

          {/* System Components */}
          <CyberpunkCard variant="neon-green" size="lg">
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-cyber-green-neon">
                System Components
              </h3>
              
              <div className="space-y-3">
                {systemComponents.map((component, index) => {
                  const IconComponent = component.icon
                  return (
                    <motion.div
                      key={component.name}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                      className="flex items-center justify-between p-3 bg-matrix-surface rounded-lg border border-matrix-border"
                    >
                      <div className="flex items-center gap-3">
                        <IconComponent className={`w-5 h-5 text-${component.color}`} />
                        <div>
                          <div className="text-sm font-medium text-matrix-white">
                            {component.name}
                          </div>
                          <div className="text-xs text-matrix-text">
                            Uptime: {component.uptime}
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <Badge 
                          variant="outline" 
                          className={`border-${getStatusColor(component.status)} text-${getStatusColor(component.status)} text-xs mb-1`}
                        >
                          {component.status}
                        </Badge>
                        <div className="text-xs text-matrix-text">
                          {component.threats} threats
                        </div>
                      </div>
                    </motion.div>
                  )
                })}
              </div>
            </div>
          </CyberpunkCard>
        </div>
      </div>
    </div>
  )
}
