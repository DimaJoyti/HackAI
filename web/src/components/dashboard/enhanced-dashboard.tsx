'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ShieldCheckIcon,
  CpuChipIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  PlayIcon,
  BoltIcon,
  EyeIcon,
  GlobeAltIcon,
  ChartBarIcon,
  ServerIcon,
  CommandLineIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { MetricsChart } from '@/components/charts/metrics-chart'
import { ThreatMap } from '@/components/charts/threat-map'
import { SystemMonitor } from '@/components/monitoring/system-monitor'
import { RealtimeAlerts } from '@/components/alerts/realtime-alerts'
import { QuickActions } from '@/components/dashboard/quick-actions'
import { formatDateTime, formatRelativeTime } from '@/lib/utils'

interface DashboardStats {
  totalScans: number
  activeScans: number
  vulnerabilitiesFound: number
  criticalVulns: number
  highVulns: number
  mediumVulns: number
  lowVulns: number
  systemHealth: number
  aiModelsActive: number
  threatLevel: 'low' | 'medium' | 'high' | 'critical'
  lastScanTime: Date
  uptime: string
}

interface RecentActivity {
  id: string
  type: 'scan' | 'threat' | 'ai' | 'system'
  title: string
  description: string
  status: 'success' | 'warning' | 'error' | 'info'
  timestamp: Date
  severity?: 'low' | 'medium' | 'high' | 'critical'
}

const mockStats: DashboardStats = {
  totalScans: 1247,
  activeScans: 3,
  vulnerabilitiesFound: 89,
  criticalVulns: 2,
  highVulns: 15,
  mediumVulns: 34,
  lowVulns: 38,
  systemHealth: 94,
  aiModelsActive: 5,
  threatLevel: 'medium',
  lastScanTime: new Date(Date.now() - 15 * 60 * 1000),
  uptime: '7d 14h 32m'
}

const mockActivity: RecentActivity[] = [
  {
    id: '1',
    type: 'threat',
    title: 'Suspicious Network Activity Detected',
    description: 'Unusual traffic patterns from IP 192.168.1.45',
    status: 'warning',
    severity: 'high',
    timestamp: new Date(Date.now() - 5 * 60 * 1000)
  },
  {
    id: '2',
    type: 'scan',
    title: 'Vulnerability Scan Completed',
    description: 'Web application scan finished with 3 critical findings',
    status: 'error',
    severity: 'critical',
    timestamp: new Date(Date.now() - 12 * 60 * 1000)
  },
  {
    id: '3',
    type: 'ai',
    title: 'AI Model Updated',
    description: 'CodeLlama model successfully updated to latest version',
    status: 'success',
    timestamp: new Date(Date.now() - 25 * 60 * 1000)
  },
  {
    id: '4',
    type: 'system',
    title: 'System Performance Optimized',
    description: 'Automated optimization improved response time by 15%',
    status: 'info',
    timestamp: new Date(Date.now() - 45 * 60 * 1000)
  }
]

export function EnhancedDashboard() {
  const [stats, setStats] = useState<DashboardStats>(mockStats)
  const [activity, setActivity] = useState<RecentActivity[]>(mockActivity)
  const [isLoading, setIsLoading] = useState(false)
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h')

  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      setStats(prev => ({
        ...prev,
        systemHealth: Math.max(85, Math.min(100, prev.systemHealth + (Math.random() - 0.5) * 2)),
        activeScans: Math.max(0, Math.min(10, prev.activeScans + Math.floor((Math.random() - 0.5) * 3)))
      }))
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  const statCards = [
    {
      title: 'Total Scans',
      value: stats.totalScans.toLocaleString(),
      icon: ShieldCheckIcon,
      variant: 'neon-blue' as const,
      trend: '+12%',
      description: 'Security scans performed'
    },
    {
      title: 'Active Scans',
      value: stats.activeScans.toString(),
      icon: PlayIcon,
      variant: 'neon-green' as const,
      trend: stats.activeScans > 0 ? 'Running' : 'Idle',
      description: 'Currently running scans'
    },
    {
      title: 'Vulnerabilities',
      value: stats.vulnerabilitiesFound.toString(),
      icon: ExclamationTriangleIcon,
      variant: stats.criticalVulns > 0 ? 'security-critical' as const : 'neon-orange' as const,
      trend: `-${stats.criticalVulns + stats.highVulns}`,
      description: 'Security issues found'
    },
    {
      title: 'System Health',
      value: `${stats.systemHealth}%`,
      icon: CpuChipIcon,
      variant: stats.systemHealth > 90 ? 'neon-green' as const : 'neon-orange' as const,
      trend: stats.systemHealth > 90 ? 'Excellent' : 'Good',
      description: 'Overall system status'
    },
    {
      title: 'AI Models',
      value: stats.aiModelsActive.toString(),
      icon: CommandLineIcon,
      variant: 'neon-purple' as const,
      trend: 'Online',
      description: 'Active AI models'
    },
    {
      title: 'Threat Level',
      value: stats.threatLevel.toUpperCase(),
      icon: EyeIcon,
      variant: stats.threatLevel === 'critical' ? 'security-critical' as const : 
              stats.threatLevel === 'high' ? 'security-high' as const :
              stats.threatLevel === 'medium' ? 'security-medium' as const : 'security-low' as const,
      trend: 'Monitored',
      description: 'Current threat assessment'
    }
  ]

  const vulnerabilityBreakdown = [
    { label: 'Critical', count: stats.criticalVulns, color: 'security-critical', percentage: (stats.criticalVulns / stats.vulnerabilitiesFound) * 100 },
    { label: 'High', count: stats.highVulns, color: 'security-high', percentage: (stats.highVulns / stats.vulnerabilitiesFound) * 100 },
    { label: 'Medium', count: stats.mediumVulns, color: 'security-medium', percentage: (stats.mediumVulns / stats.vulnerabilitiesFound) * 100 },
    { label: 'Low', count: stats.lowVulns, color: 'security-low', percentage: (stats.lowVulns / stats.vulnerabilitiesFound) * 100 }
  ]

  return (
    <div className="min-h-screen bg-matrix-void p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-display font-bold text-cyber-blue-neon">
            Security Command Center
          </h1>
          <p className="text-matrix-text mt-1">
            Real-time monitoring and threat intelligence dashboard
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-cyber-green-neon rounded-full animate-neon-pulse" />
            <span className="text-sm text-cyber-green-neon font-cyber">SYSTEMS ONLINE</span>
          </div>
          
          <div className="flex items-center gap-2 text-sm text-matrix-text">
            <ClockIcon className="w-4 h-4" />
            <span>Last updated: {formatRelativeTime(stats.lastScanTime)}</span>
          </div>
          
          <CyberpunkButton
            variant="neon-blue"
            size="sm"
            onClick={() => setIsLoading(true)}
            loading={isLoading}
          >
            <BoltIcon className="w-4 h-4" />
            Refresh
          </CyberpunkButton>
        </div>
      </div>

      {/* Quick Actions */}
      <QuickActions />

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-6">
        {statCards.map((card, index) => (
          <motion.div
            key={card.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <CyberpunkCard variant={card.variant} size="default" className="h-full">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <card.icon className="w-5 h-5" />
                    <span className="text-sm font-medium text-matrix-text">
                      {card.title}
                    </span>
                  </div>
                  <div className="text-2xl font-bold font-cyber mb-1">
                    {card.value}
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-xs">
                      {card.trend}
                    </Badge>
                  </div>
                </div>
              </div>
              <p className="text-xs text-matrix-text mt-3">
                {card.description}
              </p>
            </CyberpunkCard>
          </motion.div>
        ))}
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Vulnerability Breakdown */}
        <CyberpunkCard variant="neon-orange" size="lg">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-cyber-orange-neon">
              Vulnerability Breakdown
            </h3>
            <Badge variant="outline" className="text-xs">
              {stats.vulnerabilitiesFound} Total
            </Badge>
          </div>
          
          <div className="space-y-4">
            {vulnerabilityBreakdown.map((vuln) => (
              <div key={vuln.label} className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-matrix-text">{vuln.label}</span>
                  <span className="font-cyber">{vuln.count}</span>
                </div>
                <Progress 
                  value={vuln.percentage} 
                  className="h-2"
                  indicatorClassName={`bg-${vuln.color}`}
                />
              </div>
            ))}
          </div>
        </CyberpunkCard>

        {/* System Monitor */}
        <CyberpunkCard variant="neon-green" size="lg">
          <SystemMonitor />
        </CyberpunkCard>

        {/* Recent Activity */}
        <CyberpunkCard variant="hologram" size="lg">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-cyber-blue-neon">
              Recent Activity
            </h3>
            <CyberpunkButton variant="ghost-blue" size="sm">
              View All
            </CyberpunkButton>
          </div>
          
          <div className="space-y-4">
            <AnimatePresence>
              {activity.map((item, index) => (
                <motion.div
                  key={item.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  transition={{ delay: index * 0.1 }}
                  className="flex items-start gap-3 p-3 rounded-lg bg-matrix-surface/50 border border-matrix-border hover:border-cyber-blue-neon/30 transition-colors"
                >
                  <div className={`w-2 h-2 rounded-full mt-2 ${
                    item.status === 'success' ? 'bg-cyber-green-neon' :
                    item.status === 'warning' ? 'bg-cyber-orange-neon' :
                    item.status === 'error' ? 'bg-security-critical' :
                    'bg-cyber-blue-neon'
                  } animate-neon-pulse`} />
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-medium text-matrix-white truncate">
                        {item.title}
                      </span>
                      {item.severity && (
                        <Badge 
                          variant="outline" 
                          className={`text-xs ${
                            item.severity === 'critical' ? 'border-security-critical text-security-critical' :
                            item.severity === 'high' ? 'border-security-high text-security-high' :
                            item.severity === 'medium' ? 'border-security-medium text-security-medium' :
                            'border-security-low text-security-low'
                          }`}
                        >
                          {item.severity}
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-matrix-text mb-2">
                      {item.description}
                    </p>
                    <span className="text-xs text-matrix-text">
                      {formatRelativeTime(item.timestamp)}
                    </span>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </CyberpunkCard>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Metrics Chart */}
        <CyberpunkCard variant="glass-blue" size="lg">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-cyber-blue-neon">
              Security Metrics
            </h3>
            <div className="flex items-center gap-2">
              {['24h', '7d', '30d'].map((range) => (
                <button
                  key={range}
                  onClick={() => setSelectedTimeRange(range)}
                  className={`px-3 py-1 text-xs rounded-md transition-colors ${
                    selectedTimeRange === range
                      ? 'bg-cyber-blue-neon/20 text-cyber-blue-neon border border-cyber-blue-neon/40'
                      : 'text-matrix-text hover:text-matrix-white hover:bg-matrix-surface'
                  }`}
                >
                  {range}
                </button>
              ))}
            </div>
          </div>
          <MetricsChart timeRange={selectedTimeRange} />
        </CyberpunkCard>

        {/* Threat Map */}
        <CyberpunkCard variant="glass-dark" size="lg">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-matrix-white">
              Global Threat Map
            </h3>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-security-critical rounded-full animate-neon-pulse" />
              <span className="text-xs text-matrix-text">Live Threats</span>
            </div>
          </div>
          <ThreatMap />
        </CyberpunkCard>
      </div>

      {/* Real-time Alerts */}
      <RealtimeAlerts />
    </div>
  )
}
