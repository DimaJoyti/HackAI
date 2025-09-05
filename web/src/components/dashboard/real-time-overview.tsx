'use client'

import React, { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import {
  ShieldCheckIcon,
  CpuChipIcon,
  ExclamationTriangleIcon,
  BoltIcon,
  EyeIcon,
  ServerIcon,
  ClockIcon,
  SignalIcon,
  WifiIcon,
  CloudIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from '@/components/ui/cyberpunk-card'
import { SecurityButton } from '@/components/ui/cyberpunk-button'
import { HolographicDisplay, ParticleSystem } from '@/components/ui/cyberpunk-effects'
import { GlitchText } from '@/components/ui/cyberpunk-background'
import { CyberpunkProgressRing } from '@/components/ui/cyberpunk-charts'

// Real-time System Status Component
interface SystemStatusProps {
  className?: string
}

export const SystemStatus: React.FC<SystemStatusProps> = ({ className }) => {
  const [currentTime, setCurrentTime] = useState(new Date())
  const [systemMetrics, setSystemMetrics] = useState({
    cpu: 23,
    memory: 67,
    network: 89,
    storage: 45,
    uptime: '7d 14h 32m',
    activeConnections: 1247,
  })

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date())
      // Simulate real-time metrics updates
      setSystemMetrics(prev => ({
        ...prev,
        cpu: Math.max(10, Math.min(90, prev.cpu + (Math.random() - 0.5) * 10)),
        memory: Math.max(30, Math.min(95, prev.memory + (Math.random() - 0.5) * 5)),
        network: Math.max(50, Math.min(100, prev.network + (Math.random() - 0.5) * 8)),
        activeConnections: Math.max(1000, Math.min(2000, prev.activeConnections + Math.floor((Math.random() - 0.5) * 50))),
      }))
    }, 2000)

    return () => clearInterval(timer)
  }, [])

  const getStatusColor = (value: number) => {
    if (value < 30) return 'green'
    if (value < 70) return 'orange'
    return 'pink'
  }

  return (
    <CyberpunkCard variant="neon-blue" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={20} 
        color="blue" 
        speed="slow" 
        size="small"
        className="opacity-30"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-blue-neon">
            <ServerIcon className="w-6 h-6" />
            <GlitchText intensity="low">SYSTEM STATUS</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="safe" size="sm">ONLINE</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-6">
          {/* System Metrics */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-cyber text-matrix-light">CPU Usage</span>
                <span className={`text-sm font-matrix text-cyber-${getStatusColor(systemMetrics.cpu)}-neon`}>
                  {systemMetrics.cpu.toFixed(1)}%
                </span>
              </div>
              <div className="h-2 bg-matrix-surface rounded-full overflow-hidden">
                <div 
                  className={`h-full transition-all duration-1000 rounded-full bg-cyber-${getStatusColor(systemMetrics.cpu)}-neon`}
                  style={{ width: `${systemMetrics.cpu}%` }}
                />
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-cyber text-matrix-light">Memory</span>
                <span className={`text-sm font-matrix text-cyber-${getStatusColor(systemMetrics.memory)}-neon`}>
                  {systemMetrics.memory.toFixed(1)}%
                </span>
              </div>
              <div className="h-2 bg-matrix-surface rounded-full overflow-hidden">
                <div 
                  className={`h-full transition-all duration-1000 rounded-full bg-cyber-${getStatusColor(systemMetrics.memory)}-neon`}
                  style={{ width: `${systemMetrics.memory}%` }}
                />
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-cyber text-matrix-light">Network</span>
                <span className={`text-sm font-matrix text-cyber-${getStatusColor(100 - systemMetrics.network)}-neon`}>
                  {systemMetrics.network.toFixed(1)}%
                </span>
              </div>
              <div className="h-2 bg-matrix-surface rounded-full overflow-hidden">
                <div 
                  className={`h-full transition-all duration-1000 rounded-full bg-cyber-${getStatusColor(100 - systemMetrics.network)}-neon`}
                  style={{ width: `${systemMetrics.network}%` }}
                />
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-cyber text-matrix-light">Storage</span>
                <span className={`text-sm font-matrix text-cyber-${getStatusColor(systemMetrics.storage)}-neon`}>
                  {systemMetrics.storage.toFixed(1)}%
                </span>
              </div>
              <div className="h-2 bg-matrix-surface rounded-full overflow-hidden">
                <div 
                  className={`h-full transition-all duration-1000 rounded-full bg-cyber-${getStatusColor(systemMetrics.storage)}-neon`}
                  style={{ width: `${systemMetrics.storage}%` }}
                />
              </div>
            </div>
          </div>

          {/* System Info */}
          <HolographicDisplay color="blue" intensity="low" className="p-4">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-matrix-muted font-cyber">Uptime:</span>
                <span className="text-cyber-blue-neon font-matrix ml-2">{systemMetrics.uptime}</span>
              </div>
              <div>
                <span className="text-matrix-muted font-cyber">Connections:</span>
                <span className="text-cyber-blue-neon font-matrix ml-2">{systemMetrics.activeConnections.toLocaleString()}</span>
              </div>
              <div>
                <span className="text-matrix-muted font-cyber">Last Update:</span>
                <span className="text-cyber-blue-neon font-matrix ml-2">{currentTime.toLocaleTimeString()}</span>
              </div>
              <div>
                <span className="text-matrix-muted font-cyber">Status:</span>
                <span className="text-cyber-green-neon font-matrix ml-2">OPERATIONAL</span>
              </div>
            </div>
          </HolographicDisplay>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Live Activity Monitor Component
interface LiveActivityMonitorProps {
  className?: string
}

export const LiveActivityMonitor: React.FC<LiveActivityMonitorProps> = ({ className }) => {
  const [activities, setActivities] = useState<Array<{
    id: string
    type: 'scan' | 'alert' | 'login' | 'analysis'
    message: string
    timestamp: Date
    severity: 'low' | 'medium' | 'high' | 'critical'
  }>>([])

  useEffect(() => {
    const generateActivity = () => {
      const types = ['scan', 'alert', 'login', 'analysis'] as const
      const severities = ['low', 'medium', 'high', 'critical'] as const
      const messages = [
        'Vulnerability scan completed on target',
        'New threat detected in network traffic',
        'User authentication successful',
        'AI model analysis in progress',
        'Security policy violation detected',
        'Firewall rule updated',
        'Intrusion attempt blocked',
        'System backup completed',
      ]

      const newActivity = {
        id: Math.random().toString(36).substr(2, 9),
        type: types[Math.floor(Math.random() * types.length)],
        message: messages[Math.floor(Math.random() * messages.length)],
        timestamp: new Date(),
        severity: severities[Math.floor(Math.random() * severities.length)],
      }

      setActivities(prev => [newActivity, ...prev.slice(0, 9)]) // Keep only 10 most recent
    }

    // Generate initial activities
    for (let i = 0; i < 5; i++) {
      setTimeout(() => generateActivity(), i * 1000)
    }

    // Continue generating activities
    const interval = setInterval(generateActivity, 3000 + Math.random() * 4000)

    return () => clearInterval(interval)
  }, [])

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'scan': return ShieldCheckIcon
      case 'alert': return ExclamationTriangleIcon
      case 'login': return EyeIcon
      case 'analysis': return CpuChipIcon
      default: return BoltIcon
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'security-critical'
      case 'high': return 'cyber-orange-neon'
      case 'medium': return 'cyber-blue-neon'
      case 'low': return 'cyber-green-neon'
      default: return 'matrix-muted'
    }
  }

  return (
    <CyberpunkCard variant="neon-green" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={15} 
        color="green" 
        speed="medium" 
        size="small"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-green-neon">
          <SignalIcon className="w-6 h-6" />
          <GlitchText intensity="low">LIVE ACTIVITY</GlitchText>
        </CyberpunkCardTitle>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-3 max-h-80 overflow-y-auto scrollbar-cyber">
          {activities.length === 0 ? (
            <div className="text-center py-8 text-matrix-muted">
              <SignalIcon className="w-12 h-12 mx-auto mb-2 text-cyber-green-neon opacity-50" />
              <p className="font-cyber">Monitoring system activity...</p>
            </div>
          ) : (
            activities.map((activity) => {
              const IconComponent = getActivityIcon(activity.type)
              const severityColor = getSeverityColor(activity.severity)
              
              return (
                <HolographicDisplay
                  key={activity.id}
                  color="green"
                  intensity="low"
                  className="p-3 animate-fade-in"
                >
                  <div className="flex items-start gap-3">
                    <div className={`p-2 rounded-lg border border-${severityColor}/30 bg-${severityColor}/10`}>
                      <IconComponent className={`w-4 h-4 text-${severityColor}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-matrix-white font-medium truncate">
                        {activity.message}
                      </p>
                      <div className="flex items-center gap-2 mt-1">
                        <span className={`text-xs font-cyber uppercase text-${severityColor}`}>
                          {activity.severity}
                        </span>
                        <span className="text-xs text-matrix-muted font-matrix">
                          {activity.timestamp.toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  </div>
                </HolographicDisplay>
              )
            })
          )}
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}
