'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  CpuChipIcon,
  ServerIcon,
  CircleStackIcon,
  WifiIcon,
  BoltIcon,
  ClockIcon,
  GlobeAltIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ChartBarIcon,
  EyeIcon,
  CommandLineIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useWebSocketJSON } from '@/hooks/use-websocket'
import { formatRelativeTime } from '@/lib/utils'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area, BarChart, Bar } from 'recharts'

interface SystemMetrics {
  timestamp: string
  cpu: {
    usage: number
    cores: number
    temperature: number
    frequency: number
    loadAverage: number[]
  }
  memory: {
    used: number
    total: number
    percentage: number
    swap: { used: number; total: number }
  }
  disk: {
    used: number
    total: number
    percentage: number
    io: { read: number; write: number }
  }
  network: {
    upload: number
    download: number
    latency: number
    connections: number
    packetsIn: number
    packetsOut: number
  }
  gpu: {
    usage: number
    memory: number
    temperature: number
  }
  services: {
    running: number
    stopped: number
    failed: number
  }
  containers: {
    running: number
    stopped: number
    total: number
  }
}

interface SecurityMetrics {
  firewallStatus: 'active' | 'inactive' | 'error'
  activeConnections: number
  blockedRequests: number
  threatLevel: number
  antivirusStatus: 'active' | 'inactive' | 'updating'
  lastScan: Date
  quarantinedFiles: number
}

interface AISystemMetrics {
  totalAgents: number
  runningAgents: number
  failedAgents: number
  totalRequests: number
  avgResponseTime: number
  successRate: number
  tokensProcessed: number
}

interface ServiceStatus {
  name: string
  status: 'running' | 'stopped' | 'error' | 'starting'
  port: number
  uptime: string
  health: number
  lastCheck: Date
}

interface SystemAlert {
  id: string
  type: 'performance' | 'security' | 'service' | 'resource'
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  description: string
  timestamp: Date
  acknowledged: boolean
}

export function EnhancedSystemMonitor() {
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics[]>([])
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetrics>({
    firewallStatus: 'active',
    activeConnections: 245,
    blockedRequests: 1523,
    threatLevel: 25,
    antivirusStatus: 'active',
    lastScan: new Date(),
    quarantinedFiles: 0,
  })
  const [aiMetrics, setAiMetrics] = useState<AISystemMetrics>({
    totalAgents: 5,
    runningAgents: 4,
    failedAgents: 1,
    totalRequests: 12567,
    avgResponseTime: 850,
    successRate: 97.8,
    tokensProcessed: 2456789,
  })
  const [services, setServices] = useState<ServiceStatus[]>([])
  const [alerts, setAlerts] = useState<SystemAlert[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [selectedTab, setSelectedTab] = useState('overview')

  // WebSocket connection for real-time system monitoring
  const { lastJsonMessage, sendJsonMessage, connectionStatus } = useWebSocketJSON<any>(
    'ws://localhost:8080/ws/system-monitor',
    {
      onOpen: () => {
        setIsConnected(true)
        sendJsonMessage({ 
          type: 'subscribe', 
          streams: ['system_metrics', 'security_metrics', 'service_status', 'ai_metrics'] 
        })
      },
      onClose: () => setIsConnected(false),
      shouldReconnect: () => true,
    }
  )

  // Initialize with mock data and real-time updates
  useEffect(() => {
    initializeMockData()
    
    const interval = setInterval(() => {
      generateMockMetrics()
    }, 2000)

    return () => clearInterval(interval)
  }, [])

  const initializeMockData = () => {
    const mockServices: ServiceStatus[] = [
      {
        name: 'API Gateway',
        status: 'running',
        port: 8080,
        uptime: '7d 14h 32m',
        health: 98,
        lastCheck: new Date(),
      },
      {
        name: 'User Service',
        status: 'running',
        port: 8081,
        uptime: '7d 14h 30m',
        health: 95,
        lastCheck: new Date(),
      },
      {
        name: 'Security Service',
        status: 'running',
        port: 8082,
        uptime: '7d 14h 28m',
        health: 92,
        lastCheck: new Date(),
      },
      {
        name: 'AI Orchestrator',
        status: 'error',
        port: 8083,
        uptime: '0d 0h 0m',
        health: 0,
        lastCheck: new Date(Date.now() - 30 * 60 * 1000),
      },
      {
        name: 'Threat Intelligence',
        status: 'running',
        port: 8084,
        uptime: '7d 12h 15m',
        health: 89,
        lastCheck: new Date(),
      },
      {
        name: 'Database',
        status: 'running',
        port: 5432,
        uptime: '15d 8h 45m',
        health: 97,
        lastCheck: new Date(),
      },
    ]

    const mockAlerts: SystemAlert[] = [
      {
        id: '1',
        type: 'service',
        severity: 'critical',
        title: 'AI Orchestrator Service Down',
        description: 'AI Orchestrator service has been unresponsive for 30 minutes',
        timestamp: new Date(Date.now() - 30 * 60 * 1000),
        acknowledged: false,
      },
      {
        id: '2',
        type: 'performance',
        severity: 'high',
        title: 'High Memory Usage',
        description: 'Memory usage has exceeded 85% for the last 10 minutes',
        timestamp: new Date(Date.now() - 10 * 60 * 1000),
        acknowledged: false,
      },
      {
        id: '3',
        type: 'security',
        severity: 'medium',
        title: 'Increased Failed Login Attempts',
        description: 'Detected 50+ failed login attempts from suspicious IPs',
        timestamp: new Date(Date.now() - 15 * 60 * 1000),
        acknowledged: true,
      },
    ]

    setServices(mockServices)
    setAlerts(mockAlerts)
  }

  const generateMockMetrics = () => {
    const now = new Date()
    const newMetric: SystemMetrics = {
      timestamp: now.toISOString(),
      cpu: {
        usage: 30 + Math.random() * 40,
        cores: 8,
        temperature: 55 + Math.random() * 15,
        frequency: 3.2 + Math.random() * 0.8,
        loadAverage: [1.2 + Math.random(), 1.5 + Math.random(), 1.8 + Math.random()]
      },
      memory: {
        used: 12 + Math.random() * 8,
        total: 32,
        percentage: 35 + Math.random() * 25,
        swap: { used: 0.5 + Math.random(), total: 8 }
      },
      disk: {
        used: 256 + Math.random() * 50,
        total: 1024,
        percentage: 25 + Math.random() * 10,
        io: { read: Math.random() * 100, write: Math.random() * 50 }
      },
      network: {
        upload: Math.random() * 50,
        download: Math.random() * 100,
        latency: 10 + Math.random() * 20,
        connections: 200 + Math.random() * 100,
        packetsIn: Math.random() * 1000,
        packetsOut: Math.random() * 800
      },
      gpu: {
        usage: Math.random() * 60,
        memory: 4 + Math.random() * 8,
        temperature: 45 + Math.random() * 25
      },
      services: {
        running: 5,
        stopped: 0,
        failed: 1
      },
      containers: {
        running: 12,
        stopped: 2,
        total: 14
      }
    }

    setSystemMetrics(prev => [...prev.slice(-49), newMetric])

    // Update security metrics occasionally
    if (Math.random() < 0.1) {
      setSecurityMetrics(prev => ({
        ...prev,
        activeConnections: 200 + Math.floor(Math.random() * 100),
        blockedRequests: prev.blockedRequests + Math.floor(Math.random() * 10),
        threatLevel: Math.max(0, Math.min(100, prev.threatLevel + (Math.random() - 0.5) * 10)),
      }))
    }

    // Update AI metrics
    setAiMetrics(prev => ({
      ...prev,
      totalRequests: prev.totalRequests + Math.floor(Math.random() * 5),
      avgResponseTime: Math.max(500, Math.min(1500, prev.avgResponseTime + (Math.random() - 0.5) * 100)),
      successRate: Math.max(90, Math.min(100, prev.successRate + (Math.random() - 0.5) * 2)),
    }))
  }

  const getCurrentMetrics = () => {
    return systemMetrics.length > 0 ? systemMetrics[systemMetrics.length - 1] : null
  }

  const getStatusColor = (percentage: number, inverted = false) => {
    const threshold = inverted ? 100 - percentage : percentage
    if (threshold < 50) return 'text-cyber-green-neon'
    if (threshold < 75) return 'text-cyber-orange-neon'
    return 'text-security-critical'
  }

  const getServiceStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <CheckCircleIcon className="w-4 h-4 text-cyber-green-neon" />
      case 'error':
        return <XCircleIcon className="w-4 h-4 text-security-critical" />
      case 'starting':
        return <ClockIcon className="w-4 h-4 text-cyber-orange-neon" />
      default:
        return <XCircleIcon className="w-4 h-4 text-matrix-text" />
    }
  }

  const getAlertIcon = (type: string) => {
    switch (type) {
      case 'security':
        return <ShieldCheckIcon className="w-4 h-4" />
      case 'performance':
        return <ChartBarIcon className="w-4 h-4" />
      case 'service':
        return <ServerIcon className="w-4 h-4" />
      case 'resource':
        return <CpuChipIcon className="w-4 h-4" />
      default:
        return <ExclamationTriangleIcon className="w-4 h-4" />
    }
  }

  const acknowledgeAlert = (alertId: string) => {
    setAlerts(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, acknowledged: true } : alert
    ))
  }

  const currentMetrics = getCurrentMetrics()

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-cyber-green-neon">
            Enhanced System Monitor
          </h3>
          <p className="text-sm text-matrix-text mt-1">
            Real-time infrastructure, security, and AI system monitoring
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full animate-neon-pulse ${
              isConnected ? 'bg-cyber-green-neon' : 'bg-security-critical'
            }`} />
            <span className={`text-sm font-cyber ${
              isConnected ? 'text-cyber-green-neon' : 'text-security-critical'
            }`}>
              {isConnected ? 'MONITORING ACTIVE' : 'OFFLINE'}
            </span>
          </div>
          <CyberpunkButton variant="ghost-blue" size="sm">
            <EyeIcon className="w-4 h-4" />
            Full Screen
          </CyberpunkButton>
        </div>
      </div>

      <Tabs value={selectedTab} onValueChange={setSelectedTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-5 bg-matrix-surface border border-matrix-border">
          <TabsTrigger value="overview" className="text-cyber-green-neon">Overview</TabsTrigger>
          <TabsTrigger value="performance" className="text-cyber-green-neon">Performance</TabsTrigger>
          <TabsTrigger value="security" className="text-cyber-green-neon">Security</TabsTrigger>
          <TabsTrigger value="services" className="text-cyber-green-neon">Services</TabsTrigger>
          <TabsTrigger value="alerts" className="text-cyber-green-neon">Alerts</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {/* System Overview Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {currentMetrics && (
              <>
                <CyberpunkCard variant="neon-green" size="sm">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <CpuChipIcon className="w-4 h-4" />
                        <span className="text-sm font-medium">CPU</span>
                      </div>
                      <div className="text-2xl font-bold font-cyber">
                        {currentMetrics.cpu.usage.toFixed(1)}%
                      </div>
                      <div className="text-xs text-matrix-text">
                        {currentMetrics.cpu.cores} cores @ {currentMetrics.cpu.frequency.toFixed(1)}GHz
                      </div>
                    </div>
                  </div>
                </CyberpunkCard>

                <CyberpunkCard variant="neon-blue" size="sm">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <ServerIcon className="w-4 h-4" />
                        <span className="text-sm font-medium">Memory</span>
                      </div>
                      <div className="text-2xl font-bold font-cyber">
                        {currentMetrics.memory.percentage.toFixed(1)}%
                      </div>
                      <div className="text-xs text-matrix-text">
                        {currentMetrics.memory.used.toFixed(1)} / {currentMetrics.memory.total} GB
                      </div>
                    </div>
                  </div>
                </CyberpunkCard>

                <CyberpunkCard variant="neon-purple" size="sm">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <WifiIcon className="w-4 h-4" />
                        <span className="text-sm font-medium">Network</span>
                      </div>
                      <div className="text-2xl font-bold font-cyber">
                        {currentMetrics.network.latency.toFixed(0)}ms
                      </div>
                      <div className="text-xs text-matrix-text">
                        ↑{currentMetrics.network.upload.toFixed(1)} ↓{currentMetrics.network.download.toFixed(1)} MB/s
                      </div>
                    </div>
                  </div>
                </CyberpunkCard>

                <CyberpunkCard variant="neon-orange" size="sm">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <CircleStackIcon className="w-4 h-4" />
                        <span className="text-sm font-medium">Storage</span>
                      </div>
                      <div className="text-2xl font-bold font-cyber">
                        {currentMetrics.disk.percentage.toFixed(1)}%
                      </div>
                      <div className="text-xs text-matrix-text">
                        {currentMetrics.disk.used.toFixed(0)} / {currentMetrics.disk.total} GB
                      </div>
                    </div>
                  </div>
                </CyberpunkCard>
              </>
            )}
          </div>

          {/* System Health Overview */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* System Performance Chart */}
            <CyberpunkCard variant="glass-green" size="lg" className="lg:col-span-2">
              <div className="mb-4">
                <h5 className="font-semibold text-cyber-green-neon">System Performance</h5>
                <p className="text-xs text-matrix-text">Real-time system resource utilization</p>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={systemMetrics.slice(-20)}>
                    <defs>
                      <linearGradient id="cpu" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#00ff41" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#00ff41" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="memory" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#00ffff" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#00ffff" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" opacity={0.3} />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                      stroke="#64748b"
                      fontSize={10}
                    />
                    <YAxis stroke="#64748b" fontSize={10} />
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: '#0a0a0f',
                        border: '1px solid #00ff41',
                        borderRadius: '8px',
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="cpu.usage"
                      stroke="#00ff41"
                      fill="url(#cpu)"
                      name="CPU %"
                    />
                    <Area
                      type="monotone"
                      dataKey="memory.percentage"
                      stroke="#00ffff"
                      fill="url(#memory)"
                      name="Memory %"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CyberpunkCard>

            {/* Security & AI Status */}
            <CyberpunkCard variant="glass-blue" size="lg">
              <div className="mb-4">
                <h5 className="font-semibold text-cyber-blue-neon">Security & AI Status</h5>
                <p className="text-xs text-matrix-text">Current system protection and AI health</p>
              </div>
              
              <div className="space-y-4">
                {/* Security Status */}
                <div className="p-3 bg-matrix-surface/50 rounded">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">Security Systems</span>
                    <Badge variant={securityMetrics.firewallStatus === 'active' ? 'default' : 'destructive'}>
                      {securityMetrics.firewallStatus.toUpperCase()}
                    </Badge>
                  </div>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span>Threat Level:</span>
                      <span className={getStatusColor(securityMetrics.threatLevel)}>
                        {securityMetrics.threatLevel}%
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>Blocked Requests:</span>
                      <span className="text-cyber-green-neon">{securityMetrics.blockedRequests}</span>
                    </div>
                  </div>
                </div>

                {/* AI Systems Status */}
                <div className="p-3 bg-matrix-surface/50 rounded">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">AI Systems</span>
                    <Badge variant={aiMetrics.runningAgents === aiMetrics.totalAgents ? 'default' : 'secondary'}>
                      {aiMetrics.runningAgents}/{aiMetrics.totalAgents}
                    </Badge>
                  </div>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span>Success Rate:</span>
                      <span className="text-cyber-green-neon">{aiMetrics.successRate.toFixed(1)}%</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Avg Response:</span>
                      <span className="text-cyber-blue-neon">{aiMetrics.avgResponseTime}ms</span>
                    </div>
                  </div>
                </div>

                {/* Container Status */}
                {currentMetrics && (
                  <div className="p-3 bg-matrix-surface/50 rounded">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Containers</span>
                      <Badge variant="outline">
                        {currentMetrics.containers.running}/{currentMetrics.containers.total}
                      </Badge>
                    </div>
                    <Progress 
                      value={(currentMetrics.containers.running / currentMetrics.containers.total) * 100}
                      className="h-2"
                    />
                  </div>
                )}
              </div>
            </CyberpunkCard>
          </div>
        </TabsContent>

        <TabsContent value="performance" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* CPU and Memory Usage */}
            <CyberpunkCard variant="glass-green" size="lg">
              <div className="mb-4">
                <h5 className="font-semibold text-cyber-green-neon">CPU & Memory Trends</h5>
                <p className="text-xs text-matrix-text">Historical resource utilization</p>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={systemMetrics.slice(-30)}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" opacity={0.3} />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                      stroke="#64748b"
                      fontSize={10}
                    />
                    <YAxis stroke="#64748b" fontSize={10} />
                    <Tooltip />
                    <Line 
                      type="monotone" 
                      dataKey="cpu.usage" 
                      stroke="#00ff41" 
                      strokeWidth={2}
                      name="CPU %"
                      dot={false}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="memory.percentage" 
                      stroke="#00ffff" 
                      strokeWidth={2}
                      name="Memory %"
                      dot={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CyberpunkCard>

            {/* Network Traffic */}
            <CyberpunkCard variant="glass-blue" size="lg">
              <div className="mb-4">
                <h5 className="font-semibold text-cyber-blue-neon">Network Traffic</h5>
                <p className="text-xs text-matrix-text">Upload and download bandwidth usage</p>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={systemMetrics.slice(-15)}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" opacity={0.3} />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                      stroke="#64748b"
                      fontSize={10}
                    />
                    <YAxis stroke="#64748b" fontSize={10} />
                    <Tooltip />
                    <Bar dataKey="network.upload" fill="#ff0080" name="Upload MB/s" />
                    <Bar dataKey="network.download" fill="#00ffff" name="Download MB/s" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CyberpunkCard>
          </div>
        </TabsContent>

        <TabsContent value="services" className="space-y-6">
          <CyberpunkCard variant="glass-dark" size="lg">
            <div className="mb-4">
              <h5 className="font-semibold text-matrix-white">Service Status Monitor</h5>
              <p className="text-xs text-matrix-text">Real-time monitoring of system services and health</p>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {services.map((service) => (
                <div key={service.name} className="p-4 bg-matrix-surface/50 rounded-lg border border-matrix-border">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      {getServiceStatusIcon(service.status)}
                      <h6 className="font-medium text-sm">{service.name}</h6>
                    </div>
                    <Badge variant="outline" className="text-xs">:{service.port}</Badge>
                  </div>
                  
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span>Status:</span>
                      <span className={
                        service.status === 'running' ? 'text-cyber-green-neon' :
                        service.status === 'error' ? 'text-security-critical' :
                        'text-matrix-text'
                      }>
                        {service.status.toUpperCase()}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>Uptime:</span>
                      <span className="text-matrix-white">{service.uptime}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Health:</span>
                      <span className={getStatusColor(service.health, true)}>
                        {service.health}%
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>Last Check:</span>
                      <span className="text-matrix-text">{formatRelativeTime(service.lastCheck)}</span>
                    </div>
                  </div>
                  
                  <Progress value={service.health} className="h-2 mt-3" />
                </div>
              ))}
            </div>
          </CyberpunkCard>
        </TabsContent>

        <TabsContent value="alerts" className="space-y-6">
          <CyberpunkCard variant="security-critical" size="lg">
            <div className="mb-4">
              <h5 className="font-semibold text-security-critical">System Alerts</h5>
              <p className="text-xs text-matrix-text">Critical system notifications and warnings</p>
            </div>
            
            <div className="space-y-3">
              <AnimatePresence>
                {alerts.map((alert) => (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    className={`p-4 rounded-lg border transition-colors ${
                      alert.acknowledged 
                        ? 'bg-matrix-surface/30 border-matrix-border opacity-60' 
                        : 'bg-matrix-surface/50 border-security-critical/30'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3 flex-1">
                        <div className={`p-1 rounded ${
                          alert.severity === 'critical' ? 'bg-security-critical/20' :
                          alert.severity === 'high' ? 'bg-security-high/20' :
                          alert.severity === 'medium' ? 'bg-security-medium/20' :
                          'bg-security-low/20'
                        }`}>
                          {getAlertIcon(alert.type)}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <h6 className="font-medium text-sm">{alert.title}</h6>
                            <Badge 
                              variant={alert.severity as any}
                              className="text-xs"
                            >
                              {alert.severity.toUpperCase()}
                            </Badge>
                            <Badge variant="outline" className="text-xs">
                              {alert.type}
                            </Badge>
                          </div>
                          <p className="text-xs text-matrix-text mb-2">{alert.description}</p>
                          <p className="text-xs text-matrix-text">
                            {formatRelativeTime(alert.timestamp)}
                          </p>
                        </div>
                      </div>
                      {!alert.acknowledged && (
                        <CyberpunkButton
                          variant="ghost-blue"
                          size="xs"
                          onClick={() => acknowledgeAlert(alert.id)}
                        >
                          Acknowledge
                        </CyberpunkButton>
                      )}
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </CyberpunkCard>
        </TabsContent>
      </Tabs>
    </div>
  )
}