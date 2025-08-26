'use client'

import React, { useState, useEffect } from 'react'
import { 
  ChartBarIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  CpuChipIcon,
  EyeIcon,
  BoltIcon,
  TrendingUpIcon,
  TrendingDownIcon
} from '@heroicons/react/24/outline'
import { CyberpunkBackground, MatrixRain, GlitchText, NeonBorder } from '@/components/ui/cyberpunk-background'
import { CyberpunkButton, SecurityButton } from '@/components/ui/cyberpunk-button'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle, SecurityCard, MatrixCard, HologramCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkNav } from '@/components/ui/cyberpunk-nav'
import { CyberpunkSettingsButton } from '@/components/ui/cyberpunk-settings'

const navItems = [
  { href: '/', label: 'Home', icon: <ShieldCheckIcon className="w-5 h-5" /> },
  { href: '/demo', label: 'Demo', icon: <CpuChipIcon className="w-5 h-5" /> },
  { href: '/scanner', label: 'Scanner', icon: <EyeIcon className="w-5 h-5" /> },
  { href: '/analytics', label: 'AI Analytics', icon: <ChartBarIcon className="w-5 h-5" />, badge: 'LIVE' },
]

// Mock analytics data based on your Go backend
const threatMetrics = [
  { 
    name: 'Prompt Injection Attempts', 
    value: 1337, 
    change: '+23%', 
    trend: 'up',
    color: 'pink',
    severity: 'critical'
  },
  { 
    name: 'Data Extraction Queries', 
    value: 892, 
    change: '+15%', 
    trend: 'up',
    color: 'orange',
    severity: 'high'
  },
  { 
    name: 'Model Inversion Attempts', 
    value: 234, 
    change: '-8%', 
    trend: 'down',
    color: 'blue',
    severity: 'medium'
  },
  { 
    name: 'Blocked Attacks', 
    value: 2156, 
    change: '+31%', 
    trend: 'up',
    color: 'green',
    severity: 'safe'
  },
]

const owaspDistribution = [
  { category: 'LLM01', name: 'Prompt Injection', count: 45, percentage: 32 },
  { category: 'LLM02', name: 'Insecure Output', count: 28, percentage: 20 },
  { category: 'LLM03', name: 'Training Data Poisoning', count: 19, percentage: 14 },
  { category: 'LLM04', name: 'Model DoS', count: 15, percentage: 11 },
  { category: 'LLM05', name: 'Supply Chain', count: 12, percentage: 9 },
  { category: 'LLM06', name: 'Info Disclosure', count: 20, percentage: 14 },
]

const realtimeEvents = [
  { id: 1, type: 'attack', message: 'Prompt injection detected from 192.168.1.100', time: '2s ago', severity: 'critical' },
  { id: 2, type: 'block', message: 'Malicious query blocked by AI filter', time: '5s ago', severity: 'safe' },
  { id: 3, type: 'scan', message: 'Vulnerability scan completed on API endpoint', time: '12s ago', severity: 'medium' },
  { id: 4, type: 'alert', message: 'Unusual data access pattern detected', time: '18s ago', severity: 'high' },
  { id: 5, type: 'update', message: 'AI model security patch applied', time: '25s ago', severity: 'safe' },
]

export default function AnalyticsPage() {
  const [activeTimeframe, setActiveTimeframe] = useState('24h')
  const [realtimeData, setRealtimeData] = useState(realtimeEvents)

  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      const newEvent = {
        id: Date.now(),
        type: ['attack', 'block', 'scan', 'alert'][Math.floor(Math.random() * 4)],
        message: [
          'New prompt injection attempt detected',
          'Suspicious API query blocked',
          'Model inversion attack prevented',
          'Data extraction attempt thwarted'
        ][Math.floor(Math.random() * 4)],
        time: 'now',
        severity: ['critical', 'high', 'medium', 'safe'][Math.floor(Math.random() * 4)]
      }
      
      setRealtimeData(prev => [newEvent, ...prev.slice(0, 4)])
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  const getSeverityLevel = (severity: string) => {
    switch (severity) {
      case 'critical': return 'critical'
      case 'high': return 'high'
      case 'medium': return 'medium'
      case 'low': return 'low'
      default: return 'safe'
    }
  }

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'attack': return <ExclamationTriangleIcon className="w-4 h-4" />
      case 'block': return <ShieldCheckIcon className="w-4 h-4" />
      case 'scan': return <EyeIcon className="w-4 h-4" />
      case 'alert': return <BoltIcon className="w-4 h-4" />
      default: return <ClockIcon className="w-4 h-4" />
    }
  }

  return (
    <CyberpunkBackground variant="grid" intensity="low" color="purple" className="min-h-screen">
      <MatrixRain intensity="low" color="#8000ff" className="opacity-5" />
      
      <CyberpunkSettingsButton />
      
      <CyberpunkNav 
        items={navItems}
        theme="purple"
        logoText="HackAI"
        logoHref="/"
        className="relative z-20"
      />
      
      <div className="container mx-auto px-4 py-8 relative z-10">
        {/* Header */}
        <div className="mb-12 text-center">
          <h1 className="text-5xl font-display font-bold text-matrix-white mb-4">
            <GlitchText intensity="medium">
              AI Security Analytics
            </GlitchText>
          </h1>
          <p className="text-xl text-matrix-light font-cyber max-w-4xl mx-auto">
            Real-time threat intelligence and AI vulnerability analytics dashboard
          </p>
        </div>

        {/* Timeframe Selector */}
        <div className="mb-8 flex justify-center">
          <div className="flex space-x-2 bg-matrix-dark/80 p-2 rounded-lg border border-cyber-purple-neon/30">
            {['1h', '24h', '7d', '30d'].map((timeframe) => (
              <CyberpunkButton
                key={timeframe}
                variant={activeTimeframe === timeframe ? 'filled-purple' : 'ghost-purple'}
                size="sm"
                onClick={() => setActiveTimeframe(timeframe)}
              >
                {timeframe}
              </CyberpunkButton>
            ))}
          </div>
        </div>

        {/* Threat Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {threatMetrics.map((metric, index) => (
            <SecurityCard 
              key={metric.name} 
              level={getSeverityLevel(metric.severity)}
              interactive
              className="hover:scale-105 transition-all duration-300"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <CyberpunkCardContent className="text-center space-y-4">
                <div className={`text-4xl font-display font-bold text-cyber-${metric.color}-neon`}>
                  <GlitchText intensity="low">
                    {metric.value.toLocaleString()}
                  </GlitchText>
                </div>
                <div className="text-sm font-cyber text-matrix-text uppercase tracking-wider">
                  {metric.name}
                </div>
                <div className="flex items-center justify-center gap-2">
                  {metric.trend === 'up' ? (
                    <TrendingUpIcon className="w-4 h-4 text-cyber-green-neon" />
                  ) : (
                    <TrendingDownIcon className="w-4 h-4 text-cyber-blue-neon" />
                  )}
                  <span className={`text-sm font-cyber ${
                    metric.trend === 'up' ? 'text-cyber-green-neon' : 'text-cyber-blue-neon'
                  }`}>
                    {metric.change}
                  </span>
                </div>
              </CyberpunkCardContent>
            </SecurityCard>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          {/* OWASP LLM Distribution */}
          <HologramCard size="lg">
            <CyberpunkCardHeader accent>
              <CyberpunkCardTitle font="cyber" className="flex items-center gap-3">
                <ChartBarIcon className="w-6 h-6" />
                OWASP LLM Top 10 Distribution
              </CyberpunkCardTitle>
            </CyberpunkCardHeader>
            <CyberpunkCardContent>
              <div className="space-y-4">
                {owaspDistribution.map((item, index) => (
                  <div key={item.category} className="space-y-2">
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-3">
                        <span className="text-xs font-cyber text-cyber-purple-neon bg-cyber-purple-neon/20 px-2 py-1 rounded">
                          {item.category}
                        </span>
                        <span className="text-sm font-cyber text-matrix-light">
                          {item.name}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-cyber text-cyber-purple-neon">
                          {item.count}
                        </span>
                        <span className="text-xs text-matrix-muted">
                          {item.percentage}%
                        </span>
                      </div>
                    </div>
                    <div className="w-full bg-matrix-surface rounded-full h-2 border border-cyber-purple-neon/30">
                      <div 
                        className="bg-gradient-to-r from-cyber-purple-neon to-cyber-pink-neon h-2 rounded-full transition-all duration-1000"
                        style={{ 
                          width: `${item.percentage}%`,
                          animationDelay: `${index * 0.2}s`
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </CyberpunkCardContent>
          </HologramCard>

          {/* Real-time Event Feed */}
          <MatrixCard size="lg">
            <CyberpunkCardHeader accent>
              <CyberpunkCardTitle font="cyber" className="flex items-center gap-3">
                <BoltIcon className="w-6 h-6" />
                Real-time Security Events
                <div className="ml-auto">
                  <NeonBorder color="green" intensity="medium" className="px-2 py-1">
                    <span className="text-xs text-cyber-green-neon font-cyber">LIVE</span>
                  </NeonBorder>
                </div>
              </CyberpunkCardTitle>
            </CyberpunkCardHeader>
            <CyberpunkCardContent>
              <div className="space-y-3 max-h-80 overflow-y-auto scrollbar-cyber">
                {realtimeData.map((event) => (
                  <div 
                    key={event.id} 
                    className="flex items-start gap-3 p-3 bg-matrix-surface/50 rounded border border-current/20 hover:bg-matrix-border/50 transition-colors"
                  >
                    <div className={`p-1 rounded text-cyber-${
                      event.severity === 'critical' ? 'pink' : 
                      event.severity === 'high' ? 'orange' :
                      event.severity === 'medium' ? 'blue' : 'green'
                    }-neon`}>
                      {getEventIcon(event.type)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-cyber text-matrix-light">
                        {event.message}
                      </p>
                      <p className="text-xs text-matrix-muted mt-1 flex items-center gap-1">
                        <ClockIcon className="w-3 h-3" />
                        {event.time}
                      </p>
                    </div>
                    <SecurityButton level={getSeverityLevel(event.severity)} size="sm">
                      {event.type.toUpperCase()}
                    </SecurityButton>
                  </div>
                ))}
              </div>
            </CyberpunkCardContent>
          </MatrixCard>
        </div>

        {/* AI Model Security Status */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <SecurityCard level="safe" interactive>
            <CyberpunkCardHeader>
              <CyberpunkCardTitle font="cyber" className="text-center">
                Model Integrity
              </CyberpunkCardTitle>
            </CyberpunkCardHeader>
            <CyberpunkCardContent className="text-center">
              <div className="text-3xl font-display font-bold text-cyber-green-neon mb-2">
                <GlitchText intensity="low">98.7%</GlitchText>
              </div>
              <div className="text-sm font-cyber text-matrix-light">
                No tampering detected
              </div>
            </CyberpunkCardContent>
          </SecurityCard>

          <SecurityCard level="medium" interactive>
            <CyberpunkCardHeader>
              <CyberpunkCardTitle font="cyber" className="text-center">
                Input Validation
              </CyberpunkCardTitle>
            </CyberpunkCardHeader>
            <CyberpunkCardContent className="text-center">
              <div className="text-3xl font-display font-bold text-cyber-orange-neon mb-2">
                <GlitchText intensity="low">87.3%</GlitchText>
              </div>
              <div className="text-sm font-cyber text-matrix-light">
                Some bypasses detected
              </div>
            </CyberpunkCardContent>
          </SecurityCard>

          <SecurityCard level="high" interactive>
            <CyberpunkCardHeader>
              <CyberpunkCardTitle font="cyber" className="text-center">
                Output Filtering
              </CyberpunkCardTitle>
            </CyberpunkCardHeader>
            <CyberpunkCardContent className="text-center">
              <div className="text-3xl font-display font-bold text-cyber-pink-neon mb-2">
                <GlitchText intensity="low">76.1%</GlitchText>
              </div>
              <div className="text-sm font-cyber text-matrix-light">
                Needs improvement
              </div>
            </CyberpunkCardContent>
          </SecurityCard>
        </div>

        {/* Terminal-style System Status */}
        <MatrixCard size="lg" className="font-matrix">
          <CyberpunkCardHeader>
            <CyberpunkCardTitle font="matrix">System Status Terminal</CyberpunkCardTitle>
          </CyberpunkCardHeader>
          <CyberpunkCardContent>
            <div className="bg-matrix-black p-6 rounded border border-cyber-green-neon/30 font-matrix text-sm">
              <div className="space-y-2">
                <div className="text-cyber-green-neon">
                  <span className="animate-terminal-cursor">$</span> hackai --status --verbose
                </div>
                <div className="text-matrix-light">AI Security Analytics System v2.0.0</div>
                <div className="text-cyber-blue-neon">✓ Threat Detection Engine: ONLINE</div>
                <div className="text-cyber-blue-neon">✓ OWASP LLM Scanner: ACTIVE</div>
                <div className="text-cyber-blue-neon">✓ Real-time Monitoring: ENABLED</div>
                <div className="text-cyber-green-neon">✓ AI Model Protection: ACTIVE</div>
                <div className="text-cyber-orange-neon">⚠ Input Validation: NEEDS_ATTENTION</div>
                <div className="text-cyber-pink-neon">⚠ Output Filtering: REQUIRES_UPDATE</div>
                <div className="text-matrix-light">Last scan: {new Date().toLocaleString()}</div>
                <div className="text-cyber-green-neon mt-4">
                  <span className="animate-terminal-cursor">$</span> _
                </div>
              </div>
            </div>
          </CyberpunkCardContent>
        </MatrixCard>
      </div>
    </CyberpunkBackground>
  )
}
