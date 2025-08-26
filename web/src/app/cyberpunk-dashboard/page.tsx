'use client'

import React, { useState, useEffect } from 'react'
import { CyberpunkBackground, MatrixRain, GlitchText } from '@/components/ui/cyberpunk-background'
import { CyberpunkNav } from '@/components/ui/cyberpunk-nav'
import { ThreatMonitor, AIAgentStatus, SecurityMetrics } from '@/components/ui/cyberpunk-dashboard'
import { 
  ResearchAgentInterface, 
  CreatorAgentInterface, 
  AnalystAgentInterface, 
  OperatorAgentInterface, 
  StrategistAgentInterface 
} from '@/components/ui/ai-agent-interfaces'
import { CyberpunkTerminal } from '@/components/ui/cyberpunk-terminal'
import { CyberpunkLineChart, CyberpunkRadarChart, CyberpunkProgressRing, CyberpunkMetricCard } from '@/components/ui/cyberpunk-charts'
import { CyberpunkForm, CyberpunkInput, CyberpunkSelect, CyberpunkCheckbox } from '@/components/ui/cyberpunk-forms'
import { 
  NotificationProvider, 
  NotificationContainer, 
  NotificationBell, 
  useNotifications,
  createThreatNotification,
  createAgentNotification,
  createSystemNotification
} from '@/components/ui/cyberpunk-notifications'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { 
  ShieldCheckIcon, 
  CpuChipIcon, 
  AcademicCapIcon, 
  EyeIcon,
  ChartBarIcon,
  BoltIcon,
  ServerIcon,
  TerminalIcon
} from '@heroicons/react/24/outline'

// Mock data for demonstrations
const mockThreats = [
  {
    id: '1',
    type: 'critical' as const,
    source: 'Network Scanner',
    description: 'Suspicious activity detected on port 443',
    timestamp: new Date(),
    status: 'active' as const
  },
  {
    id: '2',
    type: 'high' as const,
    source: 'AI Analyzer',
    description: 'Potential SQL injection attempt blocked',
    timestamp: new Date(Date.now() - 300000),
    status: 'mitigated' as const
  }
]

const mockAgents = [
  {
    id: 'research-001',
    name: 'Research Agent',
    type: 'research' as const,
    status: 'busy' as const,
    performance: 94,
    lastActivity: new Date(),
    currentTask: 'Analyzing market trends and patterns'
  },
  {
    id: 'creator-001',
    name: 'Creator Agent',
    type: 'creator' as const,
    status: 'online' as const,
    performance: 87,
    lastActivity: new Date(),
    currentTask: 'Generating trading strategies'
  },
  {
    id: 'analyst-001',
    name: 'Analyst Agent',
    type: 'analyst' as const,
    status: 'busy' as const,
    performance: 91,
    lastActivity: new Date(),
    currentTask: 'Risk assessment and pattern detection'
  },
  {
    id: 'operator-001',
    name: 'Operator Agent',
    type: 'operator' as const,
    status: 'online' as const,
    performance: 98,
    lastActivity: new Date(),
    currentTask: 'Portfolio management and execution'
  },
  {
    id: 'strategist-001',
    name: 'Strategist Agent',
    type: 'strategist' as const,
    status: 'online' as const,
    performance: 89,
    lastActivity: new Date(),
    currentTask: 'Multi-agent coordination'
  }
]

const mockChartData = [
  { x: 1, y: 65 },
  { x: 2, y: 78 },
  { x: 3, y: 82 },
  { x: 4, y: 75 },
  { x: 5, y: 88 },
  { x: 6, y: 92 },
  { x: 7, y: 85 }
]

const mockRadarData = [
  { label: 'Security', value: 95, max: 100 },
  { label: 'Performance', value: 87, max: 100 },
  { label: 'Reliability', value: 92, max: 100 },
  { label: 'Efficiency', value: 89, max: 100 },
  { label: 'Innovation', value: 94, max: 100 }
]

const navItems = [
  { href: '/cyberpunk-dashboard', label: 'Dashboard', icon: <CpuChipIcon className="w-5 h-5" />, active: true },
  { href: '/scanner', label: 'Security Scanner', icon: <ShieldCheckIcon className="w-5 h-5" />, badge: 'AI' },
  { href: '/education', label: 'Learn', icon: <AcademicCapIcon className="w-5 h-5" /> },
  { href: '/analytics', label: 'Analytics', icon: <EyeIcon className="w-5 h-5" /> },
]

// Dashboard Content Component
const DashboardContent: React.FC = () => {
  const { addNotification } = useNotifications()
  const [formData, setFormData] = useState({
    agentConfig: '',
    threshold: '',
    enableAlerts: false
  })

  // Simulate real-time notifications
  useEffect(() => {
    const interval = setInterval(() => {
      const notifications = [
        createThreatNotification('Security Alert', 'Unusual network activity detected', 'medium'),
        createAgentNotification('Research-001', 'Analysis Complete', 'Market analysis finished successfully'),
        createSystemNotification('System Update', 'AI models updated successfully', 'success')
      ]
      
      const randomNotification = notifications[Math.floor(Math.random() * notifications.length)]
      addNotification(randomNotification)
    }, 10000)

    return () => clearInterval(interval)
  }, [addNotification])

  const handleAgentAction = (action: string, agentId: string) => {
    addNotification(createAgentNotification(agentId, `Agent ${action}`, `${agentId} has been ${action.toLowerCase()}`))
  }

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    addNotification(createSystemNotification('Configuration Updated', 'Agent settings have been saved successfully', 'success'))
  }

  return (
    <div className="min-h-screen relative">
      {/* Background Effects */}
      <CyberpunkBackground variant="particles" intensity="medium" color="blue" className="fixed inset-0" />
      <MatrixRain intensity="low" color="#00ff41" className="fixed inset-0 opacity-10" />

      {/* Navigation */}
      <CyberpunkNav
        items={navItems}
        theme="blue"
        logoText="HackAI"
        logoHref="/"
        className="relative z-20"
        rightContent={<NotificationBell />}
      />

      {/* Main Content */}
      <div className="relative z-10 pt-20 pb-12">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          {/* Header */}
          <div className="mb-8 text-center">
            <h1 className="text-4xl font-display font-bold text-matrix-white mb-4">
              <GlitchText intensity="medium">
                AI-First Cybersecurity Platform
              </GlitchText>
            </h1>
            <p className="text-lg text-matrix-light font-cyber">
              Multi-Agent Command & Control Center
            </p>
          </div>

          {/* Top Metrics Row */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <CyberpunkMetricCard
              title="Threat Level"
              value="LOW"
              change={-15}
              trend="down"
              color="green"
              icon={<ShieldCheckIcon className="w-5 h-5" />}
            />
            <CyberpunkMetricCard
              title="Active Agents"
              value={5}
              change={0}
              trend="neutral"
              color="blue"
              icon={<CpuChipIcon className="w-5 h-5" />}
            />
            <CyberpunkMetricCard
              title="System Performance"
              value="94%"
              change={8}
              trend="up"
              color="purple"
              icon={<ChartBarIcon className="w-5 h-5" />}
            />
            <CyberpunkMetricCard
              title="Operations/Hour"
              value="1,247"
              change={23}
              trend="up"
              color="orange"
              icon={<BoltIcon className="w-5 h-5" />}
            />
          </div>

          {/* Main Dashboard Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
            {/* Left Column */}
            <div className="lg:col-span-2 space-y-8">
              {/* Threat Monitor */}
              <ThreatMonitor threats={mockThreats} />

              {/* AI Agents Status */}
              <AIAgentStatus agents={mockAgents} />

              {/* Charts Row */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <CyberpunkLineChart
                  title="Security Metrics Trend"
                  data={mockChartData}
                  color="blue"
                  height={200}
                />
                <CyberpunkRadarChart
                  title="System Performance"
                  data={mockRadarData}
                  color="green"
                  size={200}
                />
              </div>
            </div>

            {/* Right Column */}
            <div className="space-y-8">
              {/* Security Metrics */}
              <SecurityMetrics />

              {/* Progress Rings */}
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center">
                  <CyberpunkProgressRing
                    value={94}
                    color="blue"
                    label="System Health"
                    size={100}
                  />
                </div>
                <div className="text-center">
                  <CyberpunkProgressRing
                    value={87}
                    color="green"
                    label="AI Efficiency"
                    size={100}
                  />
                </div>
              </div>

              {/* Configuration Form */}
              <CyberpunkForm
                title="Agent Configuration"
                color="purple"
                onSubmit={handleFormSubmit}
              >
                <CyberpunkSelect
                  label="Agent Type"
                  value={formData.agentConfig}
                  onChange={(value) => setFormData(prev => ({ ...prev, agentConfig: value }))}
                  options={[
                    { value: 'research', label: 'Research Agent' },
                    { value: 'creator', label: 'Creator Agent' },
                    { value: 'analyst', label: 'Analyst Agent' },
                    { value: 'operator', label: 'Operator Agent' },
                    { value: 'strategist', label: 'Strategist Agent' }
                  ]}
                  color="purple"
                />

                <CyberpunkInput
                  label="Alert Threshold"
                  type="number"
                  value={formData.threshold}
                  onChange={(value) => setFormData(prev => ({ ...prev, threshold: value }))}
                  placeholder="Enter threshold value"
                  color="purple"
                />

                <CyberpunkCheckbox
                  label="Enable Real-time Alerts"
                  checked={formData.enableAlerts}
                  onChange={(checked) => setFormData(prev => ({ ...prev, enableAlerts: checked }))}
                  color="purple"
                />

                <CyberpunkButton variant="filled-purple" type="submit" className="w-full">
                  Update Configuration
                </CyberpunkButton>
              </CyberpunkForm>
            </div>
          </div>

          {/* AI Agent Interfaces */}
          <div className="mb-8">
            <h2 className="text-2xl font-display font-bold text-matrix-white mb-6 text-center">
              <GlitchText intensity="low">AI Agent Control Interfaces</GlitchText>
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-6">
              <ResearchAgentInterface
                agentId="research-001"
                name="Research Agent"
                status="busy"
                performance={94}
                currentTask="Market analysis"
                onStart={() => handleAgentAction('Started', 'Research-001')}
                onConfigure={() => handleAgentAction('Configured', 'Research-001')}
              />
              <CreatorAgentInterface
                agentId="creator-001"
                name="Creator Agent"
                status="online"
                performance={87}
                currentTask="Strategy generation"
                onStart={() => handleAgentAction('Started', 'Creator-001')}
                onConfigure={() => handleAgentAction('Configured', 'Creator-001')}
              />
              <AnalystAgentInterface
                agentId="analyst-001"
                name="Analyst Agent"
                status="busy"
                performance={91}
                currentTask="Risk assessment"
                onStart={() => handleAgentAction('Started', 'Analyst-001')}
                onConfigure={() => handleAgentAction('Configured', 'Analyst-001')}
              />
              <OperatorAgentInterface
                agentId="operator-001"
                name="Operator Agent"
                status="online"
                performance={98}
                currentTask="Portfolio management"
                onStart={() => handleAgentAction('Started', 'Operator-001')}
                onPause={() => handleAgentAction('Paused', 'Operator-001')}
                onConfigure={() => handleAgentAction('Configured', 'Operator-001')}
              />
              <StrategistAgentInterface
                agentId="strategist-001"
                name="Strategist Agent"
                status="online"
                performance={89}
                currentTask="Multi-agent coordination"
                onStart={() => handleAgentAction('Started', 'Strategist-001')}
                onConfigure={() => handleAgentAction('Configured', 'Strategist-001')}
              />
            </div>
          </div>

          {/* Terminal Interface */}
          <div className="mb-8">
            <CyberpunkTerminal
              title="SYSTEM COMMAND INTERFACE"
              theme="green"
              className="max-w-4xl mx-auto"
              onCommand={(command) => {
                addNotification(createSystemNotification('Command Executed', `Executed: ${command}`, 'info'))
              }}
            />
          </div>
        </div>
      </div>

      {/* Notification Container */}
      <NotificationContainer position="top-right" />
    </div>
  )
}

// Main Dashboard Page with Notification Provider
export default function CyberpunkDashboardPage() {
  return (
    <NotificationProvider>
      <DashboardContent />
    </NotificationProvider>
  )
}
