'use client'

import React, { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import {
  WifiIcon,
  ServerIcon,
  GlobeAltIcon,
  ShieldExclamationIcon,
  ArrowUpIcon,
  ArrowDownIcon,
  ClockIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from '@/components/ui/cyberpunk-card'
import { SecurityButton } from '@/components/ui/cyberpunk-button'
import { HolographicDisplay, ParticleSystem } from '@/components/ui/cyberpunk-effects'
import { GlitchText } from '@/components/ui/cyberpunk-background'
import { CyberpunkLineChart } from '@/components/ui/cyberpunk-charts'

// Network Traffic Monitor Component
interface NetworkTrafficMonitorProps {
  className?: string
}

export const NetworkTrafficMonitor: React.FC<NetworkTrafficMonitorProps> = ({ className }) => {
  const [trafficData, setTrafficData] = useState<Array<{ x: number; y: number }>>([])
  const [currentStats, setCurrentStats] = useState({
    inbound: 0,
    outbound: 0,
    totalConnections: 0,
    blockedAttempts: 0,
    bandwidth: 0,
  })

  useEffect(() => {
    const updateTraffic = () => {
      const now = Date.now()
      const newInbound = Math.random() * 100 + 20
      const newOutbound = Math.random() * 80 + 15
      
      setTrafficData(prev => {
        const newData = [...prev, { x: now, y: newInbound + newOutbound }]
        return newData.slice(-20) // Keep last 20 points
      })

      setCurrentStats(prev => ({
        inbound: newInbound,
        outbound: newOutbound,
        totalConnections: Math.floor(Math.random() * 500 + 1000),
        blockedAttempts: Math.floor(Math.random() * 10 + 5),
        bandwidth: (newInbound + newOutbound) * 1.2,
      }))
    }

    // Initialize with some data
    for (let i = 0; i < 10; i++) {
      setTimeout(() => updateTraffic(), i * 200)
    }

    const interval = setInterval(updateTraffic, 2000)
    return () => clearInterval(interval)
  }, [])

  return (
    <CyberpunkCard variant="neon-purple" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={25} 
        color="purple" 
        speed="medium" 
        size="small"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-purple-neon">
            <WifiIcon className="w-6 h-6" />
            <GlitchText intensity="low">NETWORK TRAFFIC</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="medium" size="sm">MONITORING</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-6">
          {/* Real-time Stats */}
          <div className="grid grid-cols-2 gap-4">
            <HolographicDisplay color="purple" intensity="low" className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <ArrowDownIcon className="w-4 h-4 text-cyber-green-neon" />
                    <span className="text-sm font-cyber text-matrix-light">Inbound</span>
                  </div>
                  <div className="text-xl font-display font-bold text-cyber-green-neon">
                    {currentStats.inbound.toFixed(1)} MB/s
                  </div>
                </div>
              </div>
            </HolographicDisplay>

            <HolographicDisplay color="purple" intensity="low" className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <ArrowUpIcon className="w-4 h-4 text-cyber-blue-neon" />
                    <span className="text-sm font-cyber text-matrix-light">Outbound</span>
                  </div>
                  <div className="text-xl font-display font-bold text-cyber-blue-neon">
                    {currentStats.outbound.toFixed(1)} MB/s
                  </div>
                </div>
              </div>
            </HolographicDisplay>
          </div>

          {/* Traffic Chart */}
          {trafficData.length > 0 && (
            <div className="h-32">
              <CyberpunkLineChart
                data={trafficData}
                color="purple"
                height={120}
                animated={false}
                showGrid={false}
              />
            </div>
          )}

          {/* Additional Stats */}
          <div className="grid grid-cols-3 gap-3 text-sm">
            <div className="text-center">
              <div className="text-cyber-purple-neon font-display font-bold text-lg">
                {currentStats.totalConnections.toLocaleString()}
              </div>
              <div className="text-matrix-muted font-cyber">Active Connections</div>
            </div>
            <div className="text-center">
              <div className="text-cyber-orange-neon font-display font-bold text-lg">
                {currentStats.blockedAttempts}
              </div>
              <div className="text-matrix-muted font-cyber">Blocked Attempts</div>
            </div>
            <div className="text-center">
              <div className="text-cyber-blue-neon font-display font-bold text-lg">
                {currentStats.bandwidth.toFixed(1)}%
              </div>
              <div className="text-matrix-muted font-cyber">Bandwidth Usage</div>
            </div>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Connected Devices Monitor
interface ConnectedDevicesProps {
  className?: string
}

export const ConnectedDevices: React.FC<ConnectedDevicesProps> = ({ className }) => {
  const [devices, setDevices] = useState<Array<{
    id: string
    name: string
    ip: string
    type: 'desktop' | 'mobile' | 'server' | 'iot'
    status: 'online' | 'offline' | 'suspicious'
    lastSeen: Date
    riskLevel: 'low' | 'medium' | 'high'
  }>>([])

  useEffect(() => {
    const mockDevices = [
      {
        id: '1',
        name: 'Admin Workstation',
        ip: '192.168.1.100',
        type: 'desktop' as const,
        status: 'online' as const,
        lastSeen: new Date(),
        riskLevel: 'low' as const,
      },
      {
        id: '2',
        name: 'Security Server',
        ip: '192.168.1.10',
        type: 'server' as const,
        status: 'online' as const,
        lastSeen: new Date(),
        riskLevel: 'low' as const,
      },
      {
        id: '3',
        name: 'Mobile Device',
        ip: '192.168.1.150',
        type: 'mobile' as const,
        status: 'online' as const,
        lastSeen: new Date(Date.now() - 5 * 60 * 1000),
        riskLevel: 'medium' as const,
      },
      {
        id: '4',
        name: 'IoT Sensor',
        ip: '192.168.1.200',
        type: 'iot' as const,
        status: 'suspicious' as const,
        lastSeen: new Date(Date.now() - 15 * 60 * 1000),
        riskLevel: 'high' as const,
      },
    ]

    setDevices(mockDevices)

    // Simulate device status updates
    const interval = setInterval(() => {
      setDevices(prev => prev.map(device => ({
        ...device,
        lastSeen: Math.random() > 0.7 ? new Date() : device.lastSeen,
        status: Math.random() > 0.9 ? 'suspicious' : device.status,
      })))
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'desktop': return ServerIcon
      case 'mobile': return WifiIcon
      case 'server': return ServerIcon
      case 'iot': return GlobeAltIcon
      default: return ServerIcon
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'cyber-green-neon'
      case 'offline': return 'matrix-muted'
      case 'suspicious': return 'security-critical'
      default: return 'matrix-muted'
    }
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'low': return 'cyber-green-neon'
      case 'medium': return 'cyber-orange-neon'
      case 'high': return 'security-critical'
      default: return 'matrix-muted'
    }
  }

  return (
    <CyberpunkCard variant="neon-orange" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={20} 
        color="orange" 
        speed="slow" 
        size="small"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-orange-neon">
          <GlobeAltIcon className="w-6 h-6" />
          <GlitchText intensity="low">CONNECTED DEVICES</GlitchText>
        </CyberpunkCardTitle>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-3 max-h-64 overflow-y-auto scrollbar-cyber">
          {devices.map((device) => {
            const IconComponent = getDeviceIcon(device.type)
            const statusColor = getStatusColor(device.status)
            const riskColor = getRiskColor(device.riskLevel)
            
            return (
              <HolographicDisplay
                key={device.id}
                color="orange"
                intensity="low"
                className="p-3"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg border border-${statusColor}/30 bg-${statusColor}/10`}>
                      <IconComponent className={`w-4 h-4 text-${statusColor}`} />
                    </div>
                    <div>
                      <p className="text-sm font-cyber text-matrix-white font-medium">
                        {device.name}
                      </p>
                      <p className="text-xs text-matrix-muted font-matrix">
                        {device.ip} • {device.type}
                      </p>
                    </div>
                  </div>
                  
                  <div className="text-right">
                    <div className={`text-xs font-cyber uppercase text-${statusColor}`}>
                      {device.status}
                    </div>
                    <div className={`text-xs font-matrix text-${riskColor}`}>
                      {device.riskLevel} risk
                    </div>
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
