'use client'

import React, { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from './cyberpunk-card'
import { HolographicDisplay, ParticleSystem, NeuralNetwork } from './cyberpunk-effects'
import { 
  ShieldCheckIcon, 
  CpuChipIcon, 
  ExclamationTriangleIcon,
  BoltIcon,
  EyeIcon,
  ChartBarIcon,
  ClockIcon,
  ServerIcon
} from '@heroicons/react/24/outline'

// Threat Monitor Component
interface ThreatMonitorProps {
  className?: string
  threats?: Array<{
    id: string
    type: 'critical' | 'high' | 'medium' | 'low'
    source: string
    description: string
    timestamp: Date
    status: 'active' | 'mitigated' | 'investigating'
  }>
}

export const ThreatMonitor: React.FC<ThreatMonitorProps> = ({
  className,
  threats = []
}) => {
  const [currentTime, setCurrentTime] = useState(new Date())

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000)
    return () => clearInterval(timer)
  }, [])

  const threatColors = {
    critical: 'text-security-critical border-security-critical shadow-security-critical',
    high: 'text-security-high border-security-high shadow-security-high',
    medium: 'text-security-medium border-security-medium shadow-security-medium',
    low: 'text-security-low border-security-low shadow-security-low'
  }

  const statusColors = {
    active: 'bg-red-500/20 text-red-400',
    mitigated: 'bg-green-500/20 text-green-400',
    investigating: 'bg-yellow-500/20 text-yellow-400'
  }

  return (
    <CyberpunkCard variant="security-critical" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={30} 
        color="pink" 
        speed="slow" 
        size="small"
        className="opacity-30"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-security-critical">
            <ShieldCheckIcon className="w-6 h-6" />
            THREAT MONITOR
          </CyberpunkCardTitle>
          <div className="text-xs font-matrix text-matrix-light">
            {currentTime.toLocaleTimeString()}
          </div>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-3 max-h-64 overflow-y-auto scrollbar-cyber">
          {threats.length === 0 ? (
            <div className="text-center py-8 text-matrix-muted">
              <ShieldCheckIcon className="w-12 h-12 mx-auto mb-2 text-cyber-green-neon" />
              <p className="font-cyber">ALL SYSTEMS SECURE</p>
            </div>
          ) : (
            threats.map((threat) => (
              <HolographicDisplay
                key={threat.id}
                color="pink"
                intensity="low"
                className="p-3"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <ExclamationTriangleIcon className={cn('w-4 h-4', threatColors[threat.type])} />
                      <span className={cn('text-xs font-cyber uppercase', threatColors[threat.type])}>
                        {threat.type}
                      </span>
                      <span className={cn('px-2 py-1 rounded text-xs font-matrix', statusColors[threat.status])}>
                        {threat.status}
                      </span>
                    </div>
                    <p className="text-sm text-matrix-white font-medium mb-1">{threat.description}</p>
                    <p className="text-xs text-matrix-muted">Source: {threat.source}</p>
                  </div>
                  <div className="text-xs text-matrix-muted font-matrix">
                    {threat.timestamp.toLocaleTimeString()}
                  </div>
                </div>
              </HolographicDisplay>
            ))
          )}
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// AI Agent Status Display
interface AIAgentStatusProps {
  className?: string
  agents?: Array<{
    id: string
    name: string
    type: 'research' | 'creator' | 'analyst' | 'operator' | 'strategist'
    status: 'online' | 'offline' | 'busy' | 'error'
    performance: number
    lastActivity: Date
    currentTask?: string
  }>
}

export const AIAgentStatus: React.FC<AIAgentStatusProps> = ({
  className,
  agents = []
}) => {
  const agentIcons = {
    research: EyeIcon,
    creator: BoltIcon,
    analyst: ChartBarIcon,
    operator: CpuChipIcon,
    strategist: ServerIcon
  }

  const agentColors = {
    research: 'blue',
    creator: 'orange',
    analyst: 'purple',
    operator: 'green',
    strategist: 'pink'
  } as const

  const statusColors = {
    online: 'text-cyber-green-neon shadow-neon-green',
    offline: 'text-matrix-muted',
    busy: 'text-cyber-orange-neon shadow-neon-orange animate-neon-pulse',
    error: 'text-security-critical shadow-security-critical animate-neon-flicker'
  }

  return (
    <CyberpunkCard variant="neon-blue" className={cn('relative overflow-hidden', className)}>
      <NeuralNetwork 
        nodeCount={15} 
        connectionDensity={0.4} 
        color="blue" 
        animationSpeed="medium"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-blue-neon">
          <CpuChipIcon className="w-6 h-6" />
          AI AGENT STATUS
        </CyberpunkCardTitle>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="grid grid-cols-1 gap-4">
          {agents.map((agent) => {
            const IconComponent = agentIcons[agent.type]
            const agentColor = agentColors[agent.type]
            
            return (
              <HolographicDisplay
                key={agent.id}
                color={agentColor}
                intensity="medium"
                className="p-4"
                flicker={agent.status === 'error'}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={cn(
                      'p-2 rounded-lg border',
                      `border-cyber-${agentColor}-neon/30 bg-cyber-${agentColor}-neon/10`
                    )}>
                      <IconComponent className={cn('w-5 h-5', `text-cyber-${agentColor}-neon`)} />
                    </div>
                    <div>
                      <h4 className="font-cyber font-semibold text-matrix-white uppercase">
                        {agent.name}
                      </h4>
                      <p className="text-xs text-matrix-muted font-matrix">
                        {agent.currentTask || 'Standby'}
                      </p>
                    </div>
                  </div>
                  
                  <div className="text-right">
                    <div className={cn('text-sm font-cyber uppercase', statusColors[agent.status])}>
                      {agent.status}
                    </div>
                    <div className="text-xs text-matrix-muted font-matrix">
                      {agent.performance}% efficiency
                    </div>
                  </div>
                </div>

                {/* Performance Bar */}
                <div className="mt-3">
                  <div className="flex justify-between text-xs text-matrix-muted mb-1">
                    <span>Performance</span>
                    <span>{agent.performance}%</span>
                  </div>
                  <div className="h-1 bg-matrix-surface rounded-full overflow-hidden">
                    <div 
                      className={cn(
                        'h-full transition-all duration-1000 rounded-full',
                        `bg-cyber-${agentColor}-neon shadow-neon-${agentColor}`
                      )}
                      style={{ width: `${agent.performance}%` }}
                    />
                  </div>
                </div>
              </HolographicDisplay>
            )
          })}
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Security Metrics Visualization
interface SecurityMetricsProps {
  className?: string
  metrics?: {
    threatLevel: number
    systemIntegrity: number
    networkSecurity: number
    dataProtection: number
    accessControl: number
  }
}

export const SecurityMetrics: React.FC<SecurityMetricsProps> = ({
  className,
  metrics = {
    threatLevel: 25,
    systemIntegrity: 95,
    networkSecurity: 88,
    dataProtection: 92,
    accessControl: 97
  }
}) => {
  const getMetricColor = (value: number, inverse = false) => {
    if (inverse) value = 100 - value
    if (value >= 90) return 'cyber-green-neon'
    if (value >= 70) return 'cyber-orange-neon'
    return 'security-critical'
  }

  const metricItems = [
    { label: 'Threat Level', value: metrics.threatLevel, inverse: true, icon: ExclamationTriangleIcon },
    { label: 'System Integrity', value: metrics.systemIntegrity, icon: ShieldCheckIcon },
    { label: 'Network Security', value: metrics.networkSecurity, icon: ServerIcon },
    { label: 'Data Protection', value: metrics.dataProtection, icon: CpuChipIcon },
    { label: 'Access Control', value: metrics.accessControl, icon: EyeIcon }
  ]

  return (
    <CyberpunkCard variant="neon-green" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={20} 
        color="green" 
        speed="medium" 
        size="small"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-green-neon">
          <ChartBarIcon className="w-6 h-6" />
          SECURITY METRICS
        </CyberpunkCardTitle>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4">
          {metricItems.map((metric) => {
            const color = getMetricColor(metric.value, metric.inverse)
            const IconComponent = metric.icon
            
            return (
              <div key={metric.label} className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <IconComponent className={cn('w-4 h-4', `text-${color}`)} />
                    <span className="text-sm font-cyber text-matrix-white">
                      {metric.label}
                    </span>
                  </div>
                  <span className={cn('text-sm font-matrix', `text-${color}`)}>
                    {metric.value}%
                  </span>
                </div>
                
                <div className="h-2 bg-matrix-surface rounded-full overflow-hidden">
                  <div 
                    className={cn(
                      'h-full transition-all duration-1000 rounded-full',
                      `bg-${color} shadow-neon-${color.split('-')[1]}`
                    )}
                    style={{ width: `${metric.value}%` }}
                  />
                </div>
              </div>
            )
          })}
        </div>

        {/* Overall Security Score */}
        <HolographicDisplay color="green" intensity="high" className="mt-6 p-4 text-center">
          <div className="text-2xl font-display font-bold text-cyber-green-neon mb-1">
            {Math.round((metrics.systemIntegrity + metrics.networkSecurity + metrics.dataProtection + metrics.accessControl) / 4)}%
          </div>
          <div className="text-xs font-cyber text-matrix-light uppercase tracking-wider">
            Overall Security Score
          </div>
        </HolographicDisplay>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}
