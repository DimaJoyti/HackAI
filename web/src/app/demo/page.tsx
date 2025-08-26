'use client'

import React, { useState } from 'react'
import { Metadata } from 'next'
import { 
  ShieldCheckIcon, 
  CpuChipIcon, 
  EyeIcon, 
  BoltIcon, 
  CodeBracketIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon
} from '@heroicons/react/24/outline'
import { CyberpunkBackground, MatrixRain, GlitchText, NeonBorder } from '@/components/ui/cyberpunk-background'
import { CyberpunkButton, SecurityButton, MatrixButton, HologramButton } from '@/components/ui/cyberpunk-button'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardDescription, CyberpunkCardHeader, CyberpunkCardTitle, SecurityCard, MatrixCard, HologramCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkNav } from '@/components/ui/cyberpunk-nav'
import { CyberpunkSettingsButton } from '@/components/ui/cyberpunk-settings'

const navItems = [
  { href: '/', label: 'Home', icon: <ShieldCheckIcon className="w-5 h-5" /> },
  { href: '/demo', label: 'Demo', icon: <CpuChipIcon className="w-5 h-5" />, badge: 'LIVE' },
  { href: '/scanner', label: 'Scanner', icon: <EyeIcon className="w-5 h-5" /> },
  { href: '/analytics', label: 'Analytics', icon: <ChartBarIcon className="w-5 h-5" /> },
]

const securityAlerts = [
  { id: 1, type: 'critical', message: 'SQL Injection vulnerability detected', time: '2 min ago', icon: ExclamationTriangleIcon },
  { id: 2, type: 'high', message: 'Unauthorized access attempt blocked', time: '5 min ago', icon: XCircleIcon },
  { id: 3, type: 'medium', message: 'Suspicious network traffic detected', time: '12 min ago', icon: ClockIcon },
  { id: 4, type: 'safe', message: 'Security scan completed successfully', time: '15 min ago', icon: CheckCircleIcon },
]

const systemStats = [
  { label: 'Active Scans', value: '24', color: 'blue', trend: '+12%' },
  { label: 'Threats Blocked', value: '1,337', color: 'green', trend: '+8%' },
  { label: 'Vulnerabilities', value: '42', color: 'orange', trend: '-15%' },
  { label: 'System Health', value: '98%', color: 'purple', trend: '+2%' },
]

export default function DemoPage() {
  const [activeTab, setActiveTab] = useState('overview')

  return (
    <CyberpunkBackground variant="particles" intensity="low" color="blue" className="min-h-screen">
      <MatrixRain intensity="low" color="#00ff41" className="opacity-10" />

      {/* Settings Button */}
      <CyberpunkSettingsButton />

      {/* Navigation */}
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
              Cyberpunk UI Demo
            </GlitchText>
          </h1>
          <p className="text-xl text-matrix-light font-cyber max-w-3xl mx-auto">
            Experience the future of cybersecurity interfaces with our epic cyberpunk design system
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="mb-8 flex justify-center">
          <div className="flex space-x-2 bg-matrix-dark/80 p-2 rounded-lg border border-cyber-blue-neon/30">
            {['overview', 'security', 'analytics', 'terminal'].map((tab) => (
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

        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="space-y-8">
            {/* System Stats */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {systemStats.map((stat, index) => (
                <MatrixCard key={stat.label} size="default" interactive className="text-center">
                  <div className="space-y-3">
                    <div className={`text-3xl font-display font-bold text-cyber-${stat.color}-neon`}>
                      <GlitchText intensity="low">{stat.value}</GlitchText>
                    </div>
                    <div className="text-sm font-cyber text-matrix-text uppercase tracking-wider">
                      {stat.label}
                    </div>
                    <div className={`text-xs text-cyber-${stat.color}-neon`}>
                      {stat.trend}
                    </div>
                  </div>
                </MatrixCard>
              ))}
            </div>

            {/* Button Showcase */}
            <CyberpunkCard variant="neon-blue" size="lg" cornerAccents>
              <CyberpunkCardHeader>
                <CyberpunkCardTitle font="cyber">Button Variants</CyberpunkCardTitle>
                <CyberpunkCardDescription>
                  Explore different cyberpunk button styles and animations
                </CyberpunkCardDescription>
              </CyberpunkCardHeader>
              <CyberpunkCardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  <div className="space-y-3">
                    <h4 className="text-sm font-cyber text-cyber-blue-neon uppercase">Neon Variants</h4>
                    <div className="space-y-2">
                      <CyberpunkButton variant="neon-blue" size="sm" className="w-full">Neon Blue</CyberpunkButton>
                      <CyberpunkButton variant="neon-pink" size="sm" className="w-full">Neon Pink</CyberpunkButton>
                      <CyberpunkButton variant="neon-green" size="sm" className="w-full">Neon Green</CyberpunkButton>
                    </div>
                  </div>
                  
                  <div className="space-y-3">
                    <h4 className="text-sm font-cyber text-cyber-pink-neon uppercase">Filled Variants</h4>
                    <div className="space-y-2">
                      <CyberpunkButton variant="filled-blue" size="sm" className="w-full">Filled Blue</CyberpunkButton>
                      <CyberpunkButton variant="filled-pink" size="sm" className="w-full">Filled Pink</CyberpunkButton>
                      <CyberpunkButton variant="filled-green" size="sm" className="w-full">Filled Green</CyberpunkButton>
                    </div>
                  </div>
                  
                  <div className="space-y-3">
                    <h4 className="text-sm font-cyber text-cyber-green-neon uppercase">Special Effects</h4>
                    <div className="space-y-2">
                      <HologramButton size="sm" className="w-full">Hologram</HologramButton>
                      <MatrixButton size="sm" className="w-full">Matrix</MatrixButton>
                      <CyberpunkButton variant="neon-purple" animation="glitch" size="sm" className="w-full">
                        Glitch Effect
                      </CyberpunkButton>
                    </div>
                  </div>
                </div>
              </CyberpunkCardContent>
            </CyberpunkCard>
          </div>
        )}

        {/* Security Tab */}
        {activeTab === 'security' && (
          <div className="space-y-8">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {/* Security Alerts */}
              <SecurityCard level="critical" size="lg">
                <CyberpunkCardHeader accent>
                  <CyberpunkCardTitle font="cyber" className="flex items-center gap-2">
                    <ExclamationTriangleIcon className="w-6 h-6" />
                    Security Alerts
                  </CyberpunkCardTitle>
                </CyberpunkCardHeader>
                <CyberpunkCardContent>
                  <div className="space-y-4">
                    {securityAlerts.map((alert) => (
                      <div key={alert.id} className="flex items-start gap-3 p-3 bg-matrix-surface/50 rounded border border-current/20">
                        <alert.icon className="w-5 h-5 mt-0.5 flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-matrix-light">{alert.message}</p>
                          <p className="text-xs text-matrix-muted mt-1">{alert.time}</p>
                        </div>
                        <SecurityButton level={alert.type as any} size="sm">
                          {alert.type.toUpperCase()}
                        </SecurityButton>
                      </div>
                    ))}
                  </div>
                </CyberpunkCardContent>
              </SecurityCard>

              {/* System Status */}
              <HologramCard size="lg">
                <CyberpunkCardHeader accent>
                  <CyberpunkCardTitle font="cyber" className="flex items-center gap-2">
                    <ShieldCheckIcon className="w-6 h-6" />
                    System Status
                  </CyberpunkCardTitle>
                </CyberpunkCardHeader>
                <CyberpunkCardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-cyber">Firewall</span>
                      <NeonBorder color="green" intensity="low" className="px-2 py-1">
                        <span className="text-xs text-cyber-green-neon">ACTIVE</span>
                      </NeonBorder>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-cyber">Intrusion Detection</span>
                      <NeonBorder color="blue" intensity="low" className="px-2 py-1">
                        <span className="text-xs text-cyber-blue-neon">MONITORING</span>
                      </NeonBorder>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-cyber">AI Threat Analysis</span>
                      <NeonBorder color="purple" intensity="low" className="px-2 py-1">
                        <span className="text-xs text-cyber-purple-neon">LEARNING</span>
                      </NeonBorder>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-cyber">Vulnerability Scanner</span>
                      <NeonBorder color="orange" intensity="low" className="px-2 py-1">
                        <span className="text-xs text-cyber-orange-neon">SCANNING</span>
                      </NeonBorder>
                    </div>
                  </div>
                </CyberpunkCardContent>
              </HologramCard>
            </div>
          </div>
        )}

        {/* Analytics Tab */}
        {activeTab === 'analytics' && (
          <div className="space-y-8">
            <CyberpunkCard variant="neon-purple" size="lg" scanLine>
              <CyberpunkCardHeader>
                <CyberpunkCardTitle font="cyber">Analytics Dashboard</CyberpunkCardTitle>
                <CyberpunkCardDescription>
                  Real-time cybersecurity metrics and threat intelligence
                </CyberpunkCardDescription>
              </CyberpunkCardHeader>
              <CyberpunkCardContent>
                <div className="text-center py-12">
                  <GlitchText intensity="medium">
                    <span className="text-4xl font-display">Analytics Module</span>
                  </GlitchText>
                  <p className="text-matrix-light mt-4 font-cyber">
                    Advanced analytics interface coming soon...
                  </p>
                </div>
              </CyberpunkCardContent>
            </CyberpunkCard>
          </div>
        )}

        {/* Terminal Tab */}
        {activeTab === 'terminal' && (
          <div className="space-y-8">
            <MatrixCard size="lg" className="font-matrix">
              <CyberpunkCardHeader>
                <CyberpunkCardTitle font="matrix">Terminal Interface</CyberpunkCardTitle>
              </CyberpunkCardHeader>
              <CyberpunkCardContent>
                <div className="bg-matrix-black p-6 rounded border border-cyber-green-neon/30 font-matrix text-sm">
                  <div className="space-y-2">
                    <div className="text-cyber-green-neon">
                      <span className="animate-terminal-cursor">$</span> hackai --scan --target localhost
                    </div>
                    <div className="text-matrix-light">Initializing security scan...</div>
                    <div className="text-cyber-blue-neon">✓ Port scan completed</div>
                    <div className="text-cyber-blue-neon">✓ Vulnerability assessment running</div>
                    <div className="text-cyber-orange-neon">⚠ Potential SQL injection found</div>
                    <div className="text-cyber-pink-neon">⚠ Weak password policy detected</div>
                    <div className="text-cyber-green-neon">✓ Scan completed - 2 vulnerabilities found</div>
                    <div className="text-cyber-green-neon mt-4">
                      <span className="animate-terminal-cursor">$</span> _
                    </div>
                  </div>
                </div>
              </CyberpunkCardContent>
            </MatrixCard>
          </div>
        )}
      </div>
    </CyberpunkBackground>
  )
}
