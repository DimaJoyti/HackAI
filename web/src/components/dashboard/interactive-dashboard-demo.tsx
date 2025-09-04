'use client'

import { useState, useEffect } from 'react'
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
  ArrowsPointingInIcon,
  PlayCircleIcon,
  PauseCircleIcon,
  Cog6ToothIcon,
  DocumentTextIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { RealTimeStreamingChart } from '@/components/charts/real-time-streaming-chart'
import { EnhancedThreatIntelligenceDashboard } from '@/components/dashboard/enhanced-threat-intelligence-dashboard'
import { AIAgentMonitor } from '@/components/monitoring/ai-agent-monitor'
import { EnhancedSystemMonitor } from '@/components/monitoring/enhanced-system-monitor'
import { useWebSocketJSON } from '@/hooks/use-websocket'

interface DashboardWidget {
  id: string
  name: string
  type: 'chart' | 'monitor' | 'intel' | 'ai' | 'system'
  icon: React.ComponentType<any>
  component: React.ComponentType<any>
  size: 'sm' | 'md' | 'lg' | 'xl'
  position: { x: number; y: number; w: number; h: number }
  visible: boolean
  minimized: boolean
}

interface DemoSettings {
  theme: 'cyberpunk' | 'matrix' | 'neon'
  animationsEnabled: boolean
  realTimeEnabled: boolean
  autoRotate: boolean
  refreshRate: number
}

export function InteractiveDashboardDemo() {
  const [widgets, setWidgets] = useState<DashboardWidget[]>([])
  const [selectedWidget, setSelectedWidget] = useState<string | null>(null)
  const [fullscreenWidget, setFullscreenWidget] = useState<string | null>(null)
  const [demoMode, setDemoMode] = useState<'overview' | 'detailed' | 'focused'>('overview')
  const [settings, setSettings] = useState<DemoSettings>({
    theme: 'cyberpunk',
    animationsEnabled: true,
    realTimeEnabled: true,
    autoRotate: false,
    refreshRate: 2000,
  })
  const [isConnected, setIsConnected] = useState(false)
  const [currentDemo, setCurrentDemo] = useState<string>('intro')

  // WebSocket connection for demo coordination
  const { lastJsonMessage, sendJsonMessage, connectionStatus } = useWebSocketJSON<any>(
    'ws://localhost:8080/ws/dashboard-demo',
    {
      onOpen: () => {
        setIsConnected(true)
        sendJsonMessage({ type: 'demo_started', timestamp: new Date().toISOString() })
      },
      onClose: () => setIsConnected(false),
      shouldReconnect: () => true,
    }
  )

  // Initialize widgets
  useEffect(() => {
    const initialWidgets: DashboardWidget[] = [
      {
        id: 'real-time-chart',
        name: 'Real-Time Data Stream',
        type: 'chart',
        icon: ChartBarIcon,
        component: RealTimeStreamingChart,
        size: 'lg',
        position: { x: 0, y: 0, w: 8, h: 4 },
        visible: true,
        minimized: false,
      },
      {
        id: 'threat-intelligence',
        name: 'Threat Intelligence',
        type: 'intel',
        icon: ShieldCheckIcon,
        component: EnhancedThreatIntelligenceDashboard,
        size: 'xl',
        position: { x: 8, y: 0, w: 4, h: 4 },
        visible: true,
        minimized: false,
      },
      {
        id: 'ai-agents',
        name: 'AI Agent Monitor',
        type: 'ai',
        icon: CommandLineIcon,
        component: AIAgentMonitor,
        size: 'lg',
        position: { x: 0, y: 4, w: 6, h: 3 },
        visible: true,
        minimized: false,
      },
      {
        id: 'system-monitor',
        name: 'System Monitor',
        type: 'system',
        icon: CpuChipIcon,
        component: EnhancedSystemMonitor,
        size: 'lg',
        position: { x: 6, y: 4, w: 6, h: 3 },
        visible: true,
        minimized: false,
      },
    ]

    setWidgets(initialWidgets)
  }, [])

  // Auto-rotate demo scenarios
  useEffect(() => {
    if (!settings.autoRotate) return

    const scenarios = ['intro', 'streaming', 'intelligence', 'agents', 'system', 'integration']
    let currentIndex = 0

    const interval = setInterval(() => {
      currentIndex = (currentIndex + 1) % scenarios.length
      setCurrentDemo(scenarios[currentIndex])
    }, 15000) // 15 seconds per scenario

    return () => clearInterval(interval)
  }, [settings.autoRotate])

  const toggleWidget = (widgetId: string) => {
    setWidgets(prev => prev.map(widget =>
      widget.id === widgetId
        ? { ...widget, visible: !widget.visible }
        : widget
    ))
  }

  const minimizeWidget = (widgetId: string) => {
    setWidgets(prev => prev.map(widget =>
      widget.id === widgetId
        ? { ...widget, minimized: !widget.minimized }
        : widget
    ))
  }

  const toggleFullscreen = (widgetId: string) => {
    setFullscreenWidget(prev => prev === widgetId ? null : widgetId)
  }

  const startDemo = (scenario: string) => {
    setCurrentDemo(scenario)
    if (isConnected) {
      sendJsonMessage({ type: 'demo_scenario', scenario, timestamp: new Date().toISOString() })
    }
  }

  const DemoIntro = () => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="text-center py-16 space-y-6"
    >
      <h1 className="text-4xl font-display font-bold text-cyber-blue-neon">
        HackAI Dashboard Demo
      </h1>
      <p className="text-xl text-matrix-text max-w-2xl mx-auto">
        Experience the future of cybersecurity monitoring with our comprehensive
        real-time dashboard system featuring AI agents, threat intelligence, 
        and advanced system monitoring.
      </p>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 max-w-4xl mx-auto mt-12">
        {[
          { title: 'Real-Time Streaming', desc: 'Live data visualization', icon: ChartBarIcon },
          { title: 'Threat Intelligence', desc: 'Advanced threat detection', icon: ShieldCheckIcon },
          { title: 'AI Agent Monitor', desc: 'AI system management', icon: CommandLineIcon },
          { title: 'System Monitor', desc: 'Infrastructure monitoring', icon: CpuChipIcon },
        ].map((feature, index) => (
          <CyberpunkCard key={index} variant="hologram" size="sm">
            <div className="text-center space-y-3">
              <feature.icon className="w-8 h-8 mx-auto text-cyber-blue-neon" />
              <h3 className="font-semibold text-matrix-white">{feature.title}</h3>
              <p className="text-xs text-matrix-text">{feature.desc}</p>
            </div>
          </CyberpunkCard>
        ))}
      </div>

      <div className="flex justify-center gap-4 mt-8">
        <CyberpunkButton
          variant="neon-blue"
          onClick={() => startDemo('streaming')}
        >
          <PlayCircleIcon className="w-5 h-5" />
          Start Demo
        </CyberpunkButton>
        <CyberpunkButton
          variant="ghost-blue"
          onClick={() => setSettings(prev => ({ ...prev, autoRotate: !prev.autoRotate }))}
        >
          {settings.autoRotate ? <PauseCircleIcon className="w-5 h-5" /> : <PlayCircleIcon className="w-5 h-5" />}
          {settings.autoRotate ? 'Stop' : 'Auto'} Tour
        </CyberpunkButton>
      </div>
    </motion.div>
  )

  const DemoControls = () => (
    <CyberpunkCard variant="glass-dark" size="sm" className="mb-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <h3 className="font-semibold text-matrix-white">Dashboard Demo Control</h3>
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

        <div className="flex items-center gap-2">
          {/* Demo Scenarios */}
          <div className="flex gap-1">
            {[
              { id: 'intro', label: 'Intro', icon: DocumentTextIcon },
              { id: 'streaming', label: 'Stream', icon: ChartBarIcon },
              { id: 'intelligence', label: 'Intel', icon: ShieldCheckIcon },
              { id: 'agents', label: 'AI', icon: CommandLineIcon },
              { id: 'system', label: 'System', icon: CpuChipIcon },
              { id: 'integration', label: 'All', icon: GlobeAltIcon },
            ].map((scenario) => (
              <CyberpunkButton
                key={scenario.id}
                variant={currentDemo === scenario.id ? 'neon-blue' : 'ghost-blue'}
                size="xs"
                onClick={() => startDemo(scenario.id)}
              >
                <scenario.icon className="w-3 h-3" />
                {scenario.label}
              </CyberpunkButton>
            ))}
          </div>

          {/* Settings */}
          <CyberpunkButton
            variant="ghost-blue"
            size="xs"
            onClick={() => setSettings(prev => ({ ...prev, animationsEnabled: !prev.animationsEnabled }))}
          >
            <BoltIcon className="w-3 h-3" />
            {settings.animationsEnabled ? 'Disable' : 'Enable'} FX
          </CyberpunkButton>
        </div>
      </div>
    </CyberpunkCard>
  )

  const renderWidget = (widget: DashboardWidget) => {
    const Component = widget.component

    if (widget.minimized) {
      return (
        <motion.div
          key={`${widget.id}-minimized`}
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="h-12"
        >
          <CyberpunkCard variant="glass-dark" size="sm" className="h-full">
            <div className="flex items-center justify-between h-full px-4">
              <div className="flex items-center gap-2">
                <widget.icon className="w-4 h-4 text-cyber-blue-neon" />
                <span className="text-sm font-medium text-matrix-white">{widget.name}</span>
              </div>
              <div className="flex items-center gap-1">
                <CyberpunkButton
                  variant="ghost-blue"
                  size="xs"
                  onClick={() => minimizeWidget(widget.id)}
                >
                  <ArrowsPointingOutIcon className="w-3 h-3" />
                </CyberpunkButton>
                <CyberpunkButton
                  variant="ghost-blue"
                  size="xs"
                  onClick={() => toggleFullscreen(widget.id)}
                >
                  <EyeIcon className="w-3 h-3" />
                </CyberpunkButton>
              </div>
            </div>
          </CyberpunkCard>
        </motion.div>
      )
    }

    return (
      <motion.div
        key={widget.id}
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ delay: 0.1, duration: 0.3 }}
        className={`${
          fullscreenWidget === widget.id ? 'fixed inset-4 z-50' : ''
        }`}
      >
        <CyberpunkCard 
          variant="glass-dark" 
          size="lg"
          className={`h-full ${selectedWidget === widget.id ? 'ring-2 ring-cyber-blue-neon' : ''}`}
          onClick={() => setSelectedWidget(widget.id)}
        >
          {/* Widget Header */}
          <div className="flex items-center justify-between mb-4 p-4 border-b border-matrix-border">
            <div className="flex items-center gap-2">
              <widget.icon className="w-5 h-5 text-cyber-blue-neon" />
              <h3 className="font-semibold text-matrix-white">{widget.name}</h3>
              <Badge variant="outline" className="text-xs">{widget.type}</Badge>
            </div>
            <div className="flex items-center gap-1">
              <CyberpunkButton
                variant="ghost-blue"
                size="xs"
                onClick={(e) => {
                  e.stopPropagation()
                  minimizeWidget(widget.id)
                }}
              >
                <ArrowsPointingInIcon className="w-3 h-3" />
              </CyberpunkButton>
              <CyberpunkButton
                variant="ghost-blue"
                size="xs"
                onClick={(e) => {
                  e.stopPropagation()
                  toggleFullscreen(widget.id)
                }}
              >
                {fullscreenWidget === widget.id ? (
                  <ArrowsPointingInIcon className="w-3 h-3" />
                ) : (
                  <ArrowsPointingOutIcon className="w-3 h-3" />
                )}
              </CyberpunkButton>
            </div>
          </div>

          {/* Widget Content */}
          <div className="p-4 flex-1">
            <Component />
          </div>
        </CyberpunkCard>
      </motion.div>
    )
  }

  const renderDemoContent = () => {
    switch (currentDemo) {
      case 'intro':
        return <DemoIntro />
      
      case 'streaming':
        return (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-6"
          >
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-cyber-blue-neon mb-2">
                Real-Time Data Streaming
              </h2>
              <p className="text-matrix-text">
                Experience live data visualization with WebSocket integration
              </p>
            </div>
            <CyberpunkCard variant="glass-blue" size="lg">
              <RealTimeStreamingChart
                chartType="area"
                height={400}
                showEvents={true}
                maxDataPoints={60}
              />
            </CyberpunkCard>
          </motion.div>
        )

      case 'intelligence':
        return (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <EnhancedThreatIntelligenceDashboard />
          </motion.div>
        )

      case 'agents':
        return (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-6"
          >
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-cyber-blue-neon mb-2">
                AI Agent Monitoring
              </h2>
              <p className="text-matrix-text">
                Monitor and manage AI agents with real-time performance metrics
              </p>
            </div>
            <AIAgentMonitor />
          </motion.div>
        )

      case 'system':
        return (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-6"
          >
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-cyber-blue-neon mb-2">
                System Monitoring
              </h2>
              <p className="text-matrix-text">
                Comprehensive infrastructure and security monitoring
              </p>
            </div>
            <EnhancedSystemMonitor />
          </motion.div>
        )

      case 'integration':
        return (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-6"
          >
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-cyber-blue-neon mb-2">
                Integrated Dashboard
              </h2>
              <p className="text-matrix-text">
                All systems unified in a comprehensive monitoring interface
              </p>
            </div>
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {widgets.filter(w => w.visible).map(widget => (
                <div key={widget.id} className="h-96">
                  {renderWidget(widget)}
                </div>
              ))}
            </div>
          </motion.div>
        )

      default:
        return <DemoIntro />
    }
  }

  return (
    <div className="min-h-screen bg-matrix-void p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <DemoControls />
        
        <AnimatePresence mode="wait">
          <motion.div
            key={currentDemo}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
          >
            {renderDemoContent()}
          </motion.div>
        </AnimatePresence>

        {/* Demo Status Bar */}
        <div className="fixed bottom-4 right-4">
          <CyberpunkCard variant="glass-dark" size="sm">
            <div className="flex items-center gap-2 text-xs">
              <div className={`w-2 h-2 rounded-full animate-neon-pulse ${
                settings.realTimeEnabled ? 'bg-cyber-green-neon' : 'bg-matrix-text'
              }`} />
              <span className="text-matrix-text">
                Demo: {currentDemo} | 
                FX: {settings.animationsEnabled ? 'ON' : 'OFF'} |
                Auto: {settings.autoRotate ? 'ON' : 'OFF'}
              </span>
            </div>
          </CyberpunkCard>
        </div>
      </div>
    </div>
  )
}