'use client'

import React, { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts'
import {
  ChartBarIcon,
  ShieldExclamationIcon,
  ClockIcon,
  ArrowTrendingUpIcon,
  EyeIcon,
  CpuChipIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from '@/components/ui/cyberpunk-card'
import { SecurityButton } from '@/components/ui/cyberpunk-button'
import { ParticleSystem } from '@/components/ui/cyberpunk-effects'
import { GlitchText } from '@/components/ui/cyberpunk-background'

// Threat Intelligence Timeline
interface ThreatTimelineProps {
  className?: string
}

export const ThreatTimeline: React.FC<ThreatTimelineProps> = ({ className }) => {
  const [timelineData, setTimelineData] = useState<Array<{
    time: string
    threats: number
    blocked: number
    mitigated: number
  }>>([])

  useEffect(() => {
    const generateData = () => {
      const data = []
      const now = new Date()
      
      for (let i = 23; i >= 0; i--) {
        const time = new Date(now.getTime() - i * 60 * 60 * 1000)
        data.push({
          time: time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
          threats: Math.floor(Math.random() * 50 + 10),
          blocked: Math.floor(Math.random() * 30 + 5),
          mitigated: Math.floor(Math.random() * 20 + 3),
        })
      }
      
      setTimelineData(data)
    }

    generateData()
    const interval = setInterval(generateData, 60000) // Update every minute

    return () => clearInterval(interval)
  }, [])

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-matrix-black/90 border border-cyber-blue-neon/30 rounded-lg p-3 backdrop-blur-sm">
          <p className="text-cyber-blue-neon font-cyber text-sm">{`Time: ${label}`}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} className="text-sm font-matrix" style={{ color: entry.color }}>
              {`${entry.dataKey}: ${entry.value}`}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  return (
    <CyberpunkCard variant="security-critical" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={20} 
        color="pink" 
        speed="medium" 
        size="small"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-security-critical">
            <ShieldExclamationIcon className="w-6 h-6" />
            <GlitchText intensity="low">THREAT INTELLIGENCE TIMELINE</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="critical" size="sm">LIVE</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timelineData}>
              <defs>
                <linearGradient id="threatsGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff0080" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#ff0080" stopOpacity={0.1}/>
                </linearGradient>
                <linearGradient id="blockedGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00ff41" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#00ff41" stopOpacity={0.1}/>
                </linearGradient>
                <linearGradient id="mitigatedGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#00d4ff" stopOpacity={0.1}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
              <XAxis 
                dataKey="time" 
                stroke="#ffffff" 
                fontSize={12}
                fontFamily="monospace"
              />
              <YAxis 
                stroke="#ffffff" 
                fontSize={12}
                fontFamily="monospace"
              />
              <Tooltip content={<CustomTooltip />} />
              <Legend 
                wrapperStyle={{ color: '#ffffff', fontFamily: 'monospace' }}
              />
              <Area
                type="monotone"
                dataKey="threats"
                stackId="1"
                stroke="#ff0080"
                fill="url(#threatsGradient)"
                strokeWidth={2}
                name="Threats Detected"
              />
              <Area
                type="monotone"
                dataKey="blocked"
                stackId="2"
                stroke="#00ff41"
                fill="url(#blockedGradient)"
                strokeWidth={2}
                name="Threats Blocked"
              />
              <Area
                type="monotone"
                dataKey="mitigated"
                stackId="3"
                stroke="#00d4ff"
                fill="url(#mitigatedGradient)"
                strokeWidth={2}
                name="Threats Mitigated"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Performance Metrics Dashboard
interface PerformanceMetricsProps {
  className?: string
}

export const PerformanceMetrics: React.FC<PerformanceMetricsProps> = ({ className }) => {
  const [performanceData, setPerformanceData] = useState<Array<{
    name: string
    current: number
    average: number
    peak: number
  }>>([])

  useEffect(() => {
    const data = [
      {
        name: 'CPU Usage',
        current: Math.floor(Math.random() * 40 + 20),
        average: 35,
        peak: 78,
      },
      {
        name: 'Memory',
        current: Math.floor(Math.random() * 30 + 40),
        average: 55,
        peak: 89,
      },
      {
        name: 'Network I/O',
        current: Math.floor(Math.random() * 50 + 30),
        average: 45,
        peak: 95,
      },
      {
        name: 'Disk Usage',
        current: Math.floor(Math.random() * 20 + 25),
        average: 35,
        peak: 67,
      },
      {
        name: 'Scan Speed',
        current: Math.floor(Math.random() * 25 + 60),
        average: 75,
        peak: 98,
      },
    ]

    setPerformanceData(data)

    const interval = setInterval(() => {
      setPerformanceData(prev => prev.map(item => ({
        ...item,
        current: Math.floor(Math.random() * 30 + item.average - 15),
      })))
    }, 3000)

    return () => clearInterval(interval)
  }, [])

  return (
    <CyberpunkCard variant="neon-blue" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={25} 
        color="blue" 
        speed="slow" 
        size="small"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-blue-neon">
            <CpuChipIcon className="w-6 h-6" />
            <GlitchText intensity="low">PERFORMANCE METRICS</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="safe" size="sm">OPTIMAL</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={performanceData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
              <XAxis 
                dataKey="name" 
                stroke="#ffffff" 
                fontSize={12}
                fontFamily="monospace"
                angle={-45}
                textAnchor="end"
                height={80}
              />
              <YAxis 
                stroke="#ffffff" 
                fontSize={12}
                fontFamily="monospace"
              />
              <Tooltip 
                contentStyle={{
                  backgroundColor: 'rgba(0, 0, 0, 0.9)',
                  border: '1px solid #00d4ff',
                  borderRadius: '8px',
                  color: '#ffffff',
                  fontFamily: 'monospace',
                }}
              />
              <Legend 
                wrapperStyle={{ color: '#ffffff', fontFamily: 'monospace' }}
              />
              <Bar dataKey="current" fill="#00d4ff" name="Current" radius={[2, 2, 0, 0]} />
              <Bar dataKey="average" fill="#00ff41" name="Average" radius={[2, 2, 0, 0]} />
              <Bar dataKey="peak" fill="#ff6600" name="Peak" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Learning Progress Analytics
interface LearningProgressProps {
  className?: string
}

export const LearningProgress: React.FC<LearningProgressProps> = ({ className }) => {
  const [progressData, setProgressData] = useState<Array<{
    subject: string
    A: number
    B: number
    fullMark: number
  }>>([])

  useEffect(() => {
    const data = [
      {
        subject: 'Web Security',
        A: 85,
        B: 90,
        fullMark: 100,
      },
      {
        subject: 'Network Analysis',
        A: 72,
        B: 78,
        fullMark: 100,
      },
      {
        subject: 'Incident Response',
        A: 68,
        B: 75,
        fullMark: 100,
      },
      {
        subject: 'Threat Intelligence',
        A: 79,
        B: 85,
        fullMark: 100,
      },
      {
        subject: 'Penetration Testing',
        A: 63,
        B: 70,
        fullMark: 100,
      },
      {
        subject: 'Digital Forensics',
        A: 71,
        B: 80,
        fullMark: 100,
      },
    ]

    setProgressData(data)
  }, [])

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
          <ArrowTrendingUpIcon className="w-6 h-6" />
          <GlitchText intensity="low">LEARNING PROGRESS</GlitchText>
        </CyberpunkCardTitle>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart data={progressData}>
              <PolarGrid stroke="rgba(255,255,255,0.2)" />
              <PolarAngleAxis
                dataKey="subject"
                tick={{ fill: '#ffffff', fontSize: 12, fontFamily: 'monospace' }}
              />
              <PolarRadiusAxis
                angle={90}
                domain={[0, 100]}
                tick={{ fill: '#ffffff', fontSize: 10, fontFamily: 'monospace' }}
              />
              <Radar
                name="Current Level"
                dataKey="A"
                stroke="#00ff41"
                fill="#00ff41"
                fillOpacity={0.3}
                strokeWidth={2}
              />
              <Radar
                name="Target Level"
                dataKey="B"
                stroke="#00d4ff"
                fill="#00d4ff"
                fillOpacity={0.1}
                strokeWidth={2}
                strokeDasharray="5 5"
              />
              <Legend
                wrapperStyle={{ color: '#ffffff', fontFamily: 'monospace' }}
              />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Vulnerability Distribution
interface VulnerabilityDistributionProps {
  className?: string
}

export const VulnerabilityDistribution: React.FC<VulnerabilityDistributionProps> = ({ className }) => {
  const [vulnData, setVulnData] = useState<Array<{
    name: string
    value: number
    color: string
  }>>([])

  useEffect(() => {
    const data = [
      { name: 'Critical', value: 5, color: '#ff0080' },
      { name: 'High', value: 12, color: '#ff6600' },
      { name: 'Medium', value: 18, color: '#00d4ff' },
      { name: 'Low', value: 7, color: '#00ff41' },
    ]

    setVulnData(data)
  }, [])

  const CustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }: any) => {
    const RADIAN = Math.PI / 180
    const radius = innerRadius + (outerRadius - innerRadius) * 0.5
    const x = cx + radius * Math.cos(-midAngle * RADIAN)
    const y = cy + radius * Math.sin(-midAngle * RADIAN)

    return (
      <text
        x={x}
        y={y}
        fill="white"
        textAnchor={x > cx ? 'start' : 'end'}
        dominantBaseline="central"
        fontSize={12}
        fontFamily="monospace"
        fontWeight="bold"
      >
        {`${(percent * 100).toFixed(0)}%`}
      </text>
    )
  }

  return (
    <CyberpunkCard variant="neon-orange" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem
        particleCount={15}
        color="orange"
        speed="slow"
        size="small"
        className="opacity-20"
      />

      <CyberpunkCardHeader accent>
        <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-orange-neon">
          <ChartBarIcon className="w-6 h-6" />
          <GlitchText intensity="low">VULNERABILITY DISTRIBUTION</GlitchText>
        </CyberpunkCardTitle>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={vulnData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={CustomLabel}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
                stroke="rgba(255,255,255,0.2)"
                strokeWidth={2}
              >
                {vulnData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: 'rgba(0, 0, 0, 0.9)',
                  border: '1px solid #ff6600',
                  borderRadius: '8px',
                  color: '#ffffff',
                  fontFamily: 'monospace',
                }}
              />
              <Legend
                wrapperStyle={{ color: '#ffffff', fontFamily: 'monospace' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}
