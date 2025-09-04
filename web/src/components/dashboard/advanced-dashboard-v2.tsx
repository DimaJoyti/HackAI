'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  CommandLineIcon,
  CpuChipIcon,
  ShieldCheckIcon,
  ChartBarIcon,
  EyeIcon,
  BoltIcon,
  GlobeAltIcon,
  ArrowsPointingOutIcon,
  PlayCircleIcon,
  Cog6ToothIcon,
  CubeTransparentIcon,
  CloudIcon,
  BeakerIcon,
  RocketLaunchIcon,
  LightBulbIcon,
  FireIcon,
  StarIcon,
  MagnifyingGlassIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { RealTimeStreamingChart } from '@/components/charts/real-time-streaming-chart'
import { AIAgentMonitor } from '@/components/monitoring/ai-agent-monitor'
import { EnhancedSystemMonitor } from '@/components/monitoring/enhanced-system-monitor'
import { useWebSocketJSON } from '@/hooks/use-websocket'

interface DashboardMetrics {
  totalRequests: number
  activeUsers: number
  systemHealth: number
  threatLevel: number
  aiAgentsActive: number
  securityEvents: number
  performanceScore: number
  uptime: number
  errorRate: number
  responseTime: number
  dataProcessed: number
  alertsResolved: number
}

interface AdvancedFeature {
  id: string
  name: string
  description: string
  status: 'active' | 'beta' | 'coming_soon' | 'experimental'
  icon: React.ComponentType<any>
  metrics: Record<string, number>
  enabled: boolean
}

interface WorkspaceLayout {
  id: string
  name: string
  widgets: Array<{
    id: string
    type: string
    position: { x: number; y: number; w: number; h: number }
    config: Record<string, any>
  }>
  isDefault: boolean
}

export function AdvancedDashboardV2() {
  const [metrics, setMetrics] = useState<DashboardMetrics>({
    totalRequests: 0,
    activeUsers: 0,
    systemHealth: 0,
    threatLevel: 0,
    aiAgentsActive: 0,
    securityEvents: 0,
    performanceScore: 0,
    uptime: 0,
    errorRate: 0,
    responseTime: 0,
    dataProcessed: 0,
    alertsResolved: 0,
  })
  
  const [features, setFeatures] = useState<AdvancedFeature[]>([])
  const [workspaces, setWorkspaces] = useState<WorkspaceLayout[]>([])
  const [activeWorkspace, setActiveWorkspace] = useState<string>('default')
  const [isConnected, setIsConnected] = useState(false)
  const [dashboardMode, setDashboardMode] = useState<'compact' | 'detailed' | 'custom'>('detailed')

  // WebSocket connection for advanced metrics
  const { lastJsonMessage, sendJsonMessage, connectionStatus } = useWebSocketJSON<any>(
    'ws://localhost:8080/ws/dashboard-v2',
    {
      onOpen: () => {
        setIsConnected(true)
        sendJsonMessage({ 
          type: 'subscribe', 
          streams: ['advanced_metrics', 'feature_status', 'workspace_updates'] 
        })
      },
      onClose: () => setIsConnected(false),
      shouldReconnect: () => true,
    }
  )

  // Initialize advanced features
  useEffect(() => {
    const advancedFeatures: AdvancedFeature[] = [
      {
        id: 'ai-autopilot',
        name: 'AI Autopilot',
        description: 'Autonomous system management and optimization',
        status: 'beta',
        icon: RocketLaunchIcon,
        metrics: { efficiency: 94, decisions: 1247, savings: 23 },
        enabled: true,
      },
      {
        id: 'quantum-security',
        name: 'Quantum Security',
        description: 'Next-generation quantum-resistant encryption',
        status: 'experimental',
        icon: CubeTransparentIcon,
        metrics: { strength: 2048, algorithms: 5, coverage: 78 },
        enabled: false,
      },
      {
        id: 'neural-analytics',
        name: 'Neural Analytics',
        description: 'Deep learning powered predictive analytics',
        status: 'active',
        icon: BeakerIcon,
        metrics: { accuracy: 97.3, predictions: 892, insights: 156 },
        enabled: true,
      },
      {
        id: 'edge-computing',
        name: 'Edge Computing',
        description: 'Distributed processing at network edge',
        status: 'active',
        icon: CloudIcon,
        metrics: { nodes: 47, latency: 12, throughput: 1.2 },
        enabled: true,
      },
      {
        id: 'adaptive-ui',
        name: 'Adaptive UI',
        description: 'AI-powered interface personalization',
        status: 'beta',
        icon: LightBulbIcon,
        metrics: { adaptations: 234, satisfaction: 91, efficiency: 34 },
        enabled: true,
      },
      {
        id: 'zero-trust',
        name: 'Zero Trust Architecture',
        description: 'Comprehensive zero trust security model',
        status: 'active',
        icon: ShieldCheckIcon,
        metrics: { policies: 127, compliance: 99.8, violations: 0 },
        enabled: true,
      },
    ]

    const defaultWorkspaces: WorkspaceLayout[] = [
      {
        id: 'default',
        name: 'Security Operations',
        widgets: [
          { id: 'metrics-overview', type: 'metrics', position: { x: 0, y: 0, w: 12, h: 4 }, config: {} },
          { id: 'threat-monitor', type: 'security', position: { x: 0, y: 4, w: 6, h: 6 }, config: {} },
          { id: 'ai-agents', type: 'ai', position: { x: 6, y: 4, w: 6, h: 6 }, config: {} },
        ],
        isDefault: true,
      },
      {
        id: 'ai-focused',
        name: 'AI Operations',
        widgets: [
          { id: 'ai-overview', type: 'ai', position: { x: 0, y: 0, w: 8, h: 6 }, config: {} },
          { id: 'neural-analytics', type: 'analytics', position: { x: 8, y: 0, w: 4, h: 6 }, config: {} },
          { id: 'performance', type: 'performance', position: { x: 0, y: 6, w: 12, h: 4 }, config: {} },
        ],
        isDefault: false,
      },
      {
        id: 'executive',
        name: 'Executive View',
        widgets: [
          { id: 'kpi-summary', type: 'kpi', position: { x: 0, y: 0, w: 12, h: 3 }, config: {} },
          { id: 'business-metrics', type: 'business', position: { x: 0, y: 3, w: 8, h: 4 }, config: {} },
          { id: 'alerts-summary', type: 'alerts', position: { x: 8, y: 3, w: 4, h: 4 }, config: {} },
        ],
        isDefault: false,
      },
    ]

    setFeatures(advancedFeatures)
    setWorkspaces(defaultWorkspaces)
  }, [])

  // Real-time metrics simulation
  useEffect(() => {
    const interval = setInterval(() => {
      setMetrics(prev => ({
        ...prev,
        totalRequests: prev.totalRequests + Math.floor(Math.random() * 10),
        activeUsers: 1250 + Math.floor(Math.random() * 200),
        systemHealth: Math.max(85, Math.min(100, prev.systemHealth + (Math.random() - 0.5) * 2)),
        threatLevel: Math.max(0, Math.min(100, prev.threatLevel + (Math.random() - 0.5) * 5)),
        aiAgentsActive: 5 + Math.floor(Math.random() * 3),
        securityEvents: prev.securityEvents + Math.floor(Math.random() * 3),
        performanceScore: 92 + Math.floor(Math.random() * 8),
        uptime: 99.97 + Math.random() * 0.03,
        errorRate: Math.max(0, Math.min(5, prev.errorRate + (Math.random() - 0.5))),
        responseTime: 120 + Math.floor(Math.random() * 80),
        dataProcessed: prev.dataProcessed + Math.floor(Math.random() * 50),
        alertsResolved: prev.alertsResolved + (Math.random() < 0.1 ? 1 : 0),
      }))
    }, 2000)

    return () => clearInterval(interval)
  }, [])

  const toggleFeature = useCallback((featureId: string) => {
    setFeatures(prev => prev.map(feature => 
      feature.id === featureId 
        ? { ...feature, enabled: !feature.enabled }
        : feature
    ))
  }, [])

  const switchWorkspace = useCallback((workspaceId: string) => {
    setActiveWorkspace(workspaceId)
    if (isConnected) {
      sendJsonMessage({
        type: 'workspace_change',
        workspace: workspaceId,
        timestamp: new Date().toISOString(),
      })
    }
  }, [isConnected, sendJsonMessage])

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-cyber-green-neon'
      case 'beta': return 'text-cyber-orange-neon'
      case 'experimental': return 'text-cyber-purple-neon'
      case 'coming_soon': return 'text-matrix-text'
      default: return 'text-matrix-text'
    }
  }

  const getStatusBadgeVariant = (status: string) => {
    switch (status) {
      case 'active': return 'default'
      case 'beta': return 'secondary'
      case 'experimental': return 'outline'
      case 'coming_soon': return 'outline'
      default: return 'outline'
    }
  }

  const currentWorkspace = workspaces.find(w => w.id === activeWorkspace) || workspaces[0]

  return (
    <div className="min-h-screen bg-matrix-void p-6 space-y-6">
      {/* Advanced Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="w-12 h-12 rounded-full bg-gradient-to-br from-cyber-blue-neon to-cyber-purple-neon p-0.5">
              <div className="w-full h-full rounded-full bg-matrix-dark flex items-center justify-center">
                <StarIcon className="w-6 h-6 text-cyber-blue-neon" />
              </div>
            </div>
            <div className="absolute -top-1 -right-1 w-4 h-4 bg-cyber-green-neon rounded-full animate-neon-pulse" />
          </div>
          <div>
            <h1 className="text-3xl font-display font-bold bg-gradient-to-r from-cyber-blue-neon to-cyber-purple-neon bg-clip-text text-transparent">
              HackAI Dashboard v2.0
            </h1>
            <p className="text-matrix-text">
              Next-generation security operations center with AI autopilot
            </p>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          {/* Workspace Selector */}
          <div className="flex items-center gap-2">
            <label className="text-sm text-matrix-text">Workspace:</label>
            <select 
              value={activeWorkspace}
              onChange={(e) => switchWorkspace(e.target.value)}
              className="bg-matrix-surface border border-matrix-border rounded-lg px-3 py-1 text-sm text-matrix-white focus:border-cyber-blue-neon"
            >
              {workspaces.map(workspace => (
                <option key={workspace.id} value={workspace.id}>
                  {workspace.name}
                </option>
              ))}
            </select>
          </div>

          {/* Dashboard Mode */}
          <div className="flex items-center gap-1">
            {(['compact', 'detailed', 'custom'] as const).map((mode) => (
              <CyberpunkButton
                key={mode}
                variant={dashboardMode === mode ? 'neon-blue' : 'ghost-blue'}
                size="xs"
                onClick={() => setDashboardMode(mode)}
              >
                {mode.charAt(0).toUpperCase() + mode.slice(1)}
              </CyberpunkButton>
            ))}
          </div>

          {/* Connection Status */}
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full animate-neon-pulse ${
              isConnected ? 'bg-cyber-green-neon' : 'bg-security-critical'
            }`} />
            <span className={`text-sm font-cyber ${
              isConnected ? 'text-cyber-green-neon' : 'text-security-critical'
            }`}>
              {isConnected ? 'CONNECTED' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </div>

      {/* Key Metrics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
        {[
          { label: 'Requests', value: metrics.totalRequests.toLocaleString(), icon: ChartBarIcon, color: 'neon-blue', change: '+12%' },
          { label: 'Users', value: metrics.activeUsers.toLocaleString(), icon: EyeIcon, color: 'neon-green', change: '+8%' },
          { label: 'Health', value: `${metrics.systemHealth.toFixed(1)}%`, icon: CpuChipIcon, color: 'neon-green', change: '+2%' },
          { label: 'Threats', value: metrics.threatLevel.toFixed(0), icon: ShieldCheckIcon, color: metrics.threatLevel > 50 ? 'security-critical' : 'neon-orange', change: '-5%' },
          { label: 'AI Agents', value: metrics.aiAgentsActive.toString(), icon: CommandLineIcon, color: 'neon-purple', change: 'stable' },
          { label: 'Events', value: metrics.securityEvents.toLocaleString(), icon: FireIcon, color: 'neon-orange', change: '+15%' },
        ].map((metric, index) => (
          <motion.div
            key={metric.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <CyberpunkCard variant={metric.color} size="sm">
              <div className="flex items-center justify-between mb-2">
                <metric.icon className="w-5 h-5" />
                <Badge variant="outline" className="text-xs">
                  {metric.change}
                </Badge>
              </div>
              <div className="text-2xl font-bold font-cyber mb-1">
                {metric.value}
              </div>
              <div className="text-xs text-matrix-text">
                {metric.label}
              </div>
            </CyberpunkCard>
          </motion.div>
        ))}
      </div>

      {/* Advanced Features Panel */}
      <CyberpunkCard variant="glass-dark" size="lg">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold text-matrix-white">
            Advanced Features
          </h3>
          <CyberpunkButton variant="ghost-blue" size="sm">
            <Cog6ToothIcon className="w-4 h-4" />
            Configure
          </CyberpunkButton>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map((feature) => (
            <motion.div
              key={feature.id}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              whileHover={{ scale: 1.02 }}
              className={`p-4 rounded-lg border-2 transition-all cursor-pointer ${
                feature.enabled 
                  ? 'border-cyber-blue-neon/30 bg-cyber-blue-neon/5' 
                  : 'border-matrix-border bg-matrix-surface/30'
              }`}
              onClick={() => toggleFeature(feature.id)}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${
                    feature.enabled ? 'bg-cyber-blue-neon/20' : 'bg-matrix-surface'
                  }`}>
                    <feature.icon className={`w-5 h-5 ${getStatusColor(feature.status)}`} />
                  </div>
                  <div>
                    <h4 className="font-semibold text-sm text-matrix-white">
                      {feature.name}
                    </h4>
                    <Badge 
                      variant={getStatusBadgeVariant(feature.status)}
                      className="text-xs mt-1"
                    >
                      {feature.status.replace('_', ' ').toUpperCase()}
                    </Badge>
                  </div>
                </div>
                <div className={`w-3 h-3 rounded-full ${
                  feature.enabled ? 'bg-cyber-green-neon animate-neon-pulse' : 'bg-matrix-text'
                }`} />
              </div>
              
              <p className="text-xs text-matrix-text mb-3">
                {feature.description}
              </p>
              
              <div className="grid grid-cols-3 gap-2">
                {Object.entries(feature.metrics).map(([key, value]) => (
                  <div key={key} className="text-center">
                    <div className="text-sm font-cyber text-cyber-blue-neon">
                      {typeof value === 'number' ? value.toFixed(1) : value}
                    </div>
                    <div className="text-xs text-matrix-text capitalize">
                      {key}
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          ))}
        </div>
      </CyberpunkCard>

      {/* Main Dashboard Content */}
      <Tabs value="overview" className="space-y-6">
        <TabsList className="grid w-full grid-cols-5 bg-matrix-surface border border-matrix-border">
          <TabsTrigger value="overview" className="text-cyber-blue-neon">Overview</TabsTrigger>
          <TabsTrigger value="analytics" className="text-cyber-blue-neon">Analytics</TabsTrigger>
          <TabsTrigger value="security" className="text-cyber-blue-neon">Security</TabsTrigger>
          <TabsTrigger value="ai-ops" className="text-cyber-blue-neon">AI Ops</TabsTrigger>
          <TabsTrigger value="insights" className="text-cyber-blue-neon">Insights</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Real-time Streaming */}
            <CyberpunkCard variant="glass-blue" size="lg">
              <div className="mb-4">
                <h4 className="text-lg font-semibold text-cyber-blue-neon">
                  Live System Metrics
                </h4>
                <p className="text-sm text-matrix-text">
                  Real-time performance and security indicators
                </p>
              </div>
              <RealTimeStreamingChart
                chartType="area"
                height={300}
                showEvents={true}
                maxDataPoints={50}
              />
            </CyberpunkCard>

            {/* AI Agent Status */}
            <CyberpunkCard variant="glass-green" size="lg">
              <div className="mb-4">
                <h4 className="text-lg font-semibold text-cyber-green-neon">
                  AI Agent Operations
                </h4>
                <p className="text-sm text-matrix-text">
                  Autonomous agent performance monitoring
                </p>
              </div>
              <AIAgentMonitor />
            </CyberpunkCard>
          </div>

          {/* System Monitor */}
          <CyberpunkCard variant="glass-dark" size="lg">
            <EnhancedSystemMonitor />
          </CyberpunkCard>
        </TabsContent>

        <TabsContent value="analytics" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <CyberpunkCard variant="neon-purple" size="lg">
              <div className="mb-4">
                <h4 className="text-lg font-semibold text-cyber-purple-neon">
                  Neural Analytics Engine
                </h4>
                <p className="text-sm text-matrix-text">
                  AI-powered predictive insights and pattern recognition
                </p>
              </div>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Prediction Accuracy</span>
                  <span className="text-cyber-purple-neon font-cyber">97.3%</span>
                </div>
                <Progress value={97.3} className="h-2" />
                
                <div className="flex items-center justify-between">
                  <span className="text-sm">Pattern Recognition</span>
                  <span className="text-cyber-purple-neon font-cyber">94.7%</span>
                </div>
                <Progress value={94.7} className="h-2" />
                
                <div className="flex items-center justify-between">
                  <span className="text-sm">Anomaly Detection</span>
                  <span className="text-cyber-purple-neon font-cyber">98.9%</span>
                </div>
                <Progress value={98.9} className="h-2" />
              </div>
            </CyberpunkCard>

            <CyberpunkCard variant="hologram" size="lg">
              <div className="mb-4">
                <h4 className="text-lg font-semibold text-cyber-blue-neon">
                  Performance Insights
                </h4>
                <p className="text-sm text-matrix-text">
                  System optimization recommendations
                </p>
              </div>
              
              <div className="space-y-3">
                {[
                  { insight: 'Database query optimization', impact: 'High', savings: '23%' },
                  { insight: 'Cache invalidation strategy', impact: 'Medium', savings: '15%' },
                  { insight: 'Load balancer configuration', impact: 'Low', savings: '8%' },
                ].map((item, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-matrix-surface/50 rounded">
                    <div>
                      <div className="text-sm font-medium text-matrix-white">{item.insight}</div>
                      <div className="text-xs text-matrix-text">Impact: {item.impact}</div>
                    </div>
                    <Badge variant="outline">{item.savings}</Badge>
                  </div>
                ))}
              </div>
            </CyberpunkCard>
          </div>
        </TabsContent>

        {/* Additional tabs would be implemented here */}
      </Tabs>

      {/* Status Bar */}
      <div className="fixed bottom-4 right-4 left-4 lg:left-auto">
        <CyberpunkCard variant="glass-dark" size="sm">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-4">
              <span className="text-matrix-text">
                Workspace: <span className="text-cyber-blue-neon">{currentWorkspace.name}</span>
              </span>
              <span className="text-matrix-text">
                Performance: <span className="text-cyber-green-neon">{metrics.performanceScore}%</span>
              </span>
              <span className="text-matrix-text">
                Uptime: <span className="text-cyber-green-neon">{metrics.uptime.toFixed(2)}%</span>
              </span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-cyber-green-neon rounded-full animate-neon-pulse" />
              <span className="text-cyber-green-neon">All Systems Operational</span>
            </div>
          </div>
        </CyberpunkCard>
      </div>
    </div>
  )
}