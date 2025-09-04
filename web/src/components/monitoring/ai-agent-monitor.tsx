'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  CpuChipIcon,
  CommandLineIcon,
  BoltIcon,
  EyeIcon,
  ClockIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  PlayIcon,
  PauseIcon,
  StopIcon,
  ArrowPathIcon,
  Cog6ToothIcon,
  DocumentTextIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useWebSocketJSON } from '@/hooks/use-websocket'
import { formatDateTime, formatRelativeTime } from '@/lib/utils'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts'

interface AIAgent {
  id: string
  name: string
  type: 'llm' | 'security' | 'analysis' | 'monitoring' | 'orchestrator'
  model: string
  status: 'running' | 'idle' | 'error' | 'stopped' | 'starting'
  version: string
  startTime: Date
  lastActivity: Date
  metrics: {
    requests: number
    avgResponseTime: number
    successRate: number
    errorCount: number
    tokensProcessed: number
    memoryUsage: number
    cpuUsage: number
  }
  configuration: {
    temperature: number
    maxTokens: number
    topP: number
    frequencyPenalty: number
  }
  tasks: {
    queued: number
    active: number
    completed: number
    failed: number
  }
  health: {
    score: number
    issues: string[]
    lastCheck: Date
  }
}

interface AIAgentPerformance {
  timestamp: string
  agentId: string
  responseTime: number
  tokensPerSecond: number
  memoryUsage: number
  cpuUsage: number
  requestCount: number
  errorRate: number
}

interface AITaskExecution {
  id: string
  agentId: string
  taskType: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  startTime: Date
  endTime?: Date
  duration?: number
  input: string
  output?: string
  error?: string
  metadata: Record<string, any>
}

export function AIAgentMonitor() {
  const [agents, setAgents] = useState<AIAgent[]>([])
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null)
  const [performanceData, setPerformanceData] = useState<AIAgentPerformance[]>([])
  const [taskExecutions, setTaskExecutions] = useState<AITaskExecution[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [selectedTimeRange, setSelectedTimeRange] = useState('1h')

  // WebSocket connection for real-time AI agent monitoring
  const { lastJsonMessage, sendJsonMessage, connectionStatus } = useWebSocketJSON<any>(
    'ws://localhost:8080/ws/ai-agents',
    {
      onOpen: () => {
        setIsConnected(true)
        sendJsonMessage({ 
          type: 'subscribe', 
          streams: ['agent_status', 'agent_metrics', 'task_updates'] 
        })
      },
      onClose: () => setIsConnected(false),
      shouldReconnect: () => true,
    }
  )

  // Initialize with mock data
  useEffect(() => {
    initializeMockData()
  }, [])

  const initializeMockData = () => {
    const mockAgents: AIAgent[] = [
      {
        id: 'agent-1',
        name: 'CodeLlama Security Analyst',
        type: 'security',
        model: 'CodeLlama-34B-Instruct',
        status: 'running',
        version: '1.2.3',
        startTime: new Date(Date.now() - 2 * 60 * 60 * 1000),
        lastActivity: new Date(),
        metrics: {
          requests: 1247,
          avgResponseTime: 850,
          successRate: 98.5,
          errorCount: 18,
          tokensProcessed: 2456789,
          memoryUsage: 12.4,
          cpuUsage: 45.2,
        },
        configuration: {
          temperature: 0.1,
          maxTokens: 4096,
          topP: 0.95,
          frequencyPenalty: 0.0,
        },
        tasks: {
          queued: 3,
          active: 2,
          completed: 1242,
          failed: 18,
        },
        health: {
          score: 95,
          issues: [],
          lastCheck: new Date(),
        },
      },
      {
        id: 'agent-2',
        name: 'GPT-4 Threat Intelligence',
        type: 'analysis',
        model: 'GPT-4-Turbo',
        status: 'running',
        version: '2.1.0',
        startTime: new Date(Date.now() - 4 * 60 * 60 * 1000),
        lastActivity: new Date(Date.now() - 5 * 60 * 1000),
        metrics: {
          requests: 892,
          avgResponseTime: 1200,
          successRate: 97.8,
          errorCount: 20,
          tokensProcessed: 1789234,
          memoryUsage: 8.9,
          cpuUsage: 32.1,
        },
        configuration: {
          temperature: 0.3,
          maxTokens: 8192,
          topP: 0.9,
          frequencyPenalty: 0.1,
        },
        tasks: {
          queued: 1,
          active: 1,
          completed: 870,
          failed: 20,
        },
        health: {
          score: 88,
          issues: ['Elevated response times'],
          lastCheck: new Date(Date.now() - 60 * 1000),
        },
      },
      {
        id: 'agent-3',
        name: 'Claude Security Orchestrator',
        type: 'orchestrator',
        model: 'Claude-3-Sonnet',
        status: 'idle',
        version: '3.0.1',
        startTime: new Date(Date.now() - 6 * 60 * 60 * 1000),
        lastActivity: new Date(Date.now() - 15 * 60 * 1000),
        metrics: {
          requests: 456,
          avgResponseTime: 950,
          successRate: 99.1,
          errorCount: 4,
          tokensProcessed: 987654,
          memoryUsage: 6.2,
          cpuUsage: 18.7,
        },
        configuration: {
          temperature: 0.2,
          maxTokens: 4096,
          topP: 0.9,
          frequencyPenalty: 0.0,
        },
        tasks: {
          queued: 0,
          active: 0,
          completed: 452,
          failed: 4,
        },
        health: {
          score: 92,
          issues: [],
          lastCheck: new Date(),
        },
      },
      {
        id: 'agent-4',
        name: 'Vulnerability Scanner AI',
        type: 'security',
        model: 'Custom-SecBERT',
        status: 'error',
        version: '1.0.8',
        startTime: new Date(Date.now() - 1 * 60 * 60 * 1000),
        lastActivity: new Date(Date.now() - 30 * 60 * 1000),
        metrics: {
          requests: 234,
          avgResponseTime: 2100,
          successRate: 85.2,
          errorCount: 35,
          tokensProcessed: 456789,
          memoryUsage: 15.8,
          cpuUsage: 67.3,
        },
        configuration: {
          temperature: 0.0,
          maxTokens: 2048,
          topP: 1.0,
          frequencyPenalty: 0.0,
        },
        tasks: {
          queued: 5,
          active: 0,
          completed: 199,
          failed: 35,
        },
        health: {
          score: 45,
          issues: ['High error rate', 'Memory leak detected', 'Performance degradation'],
          lastCheck: new Date(Date.now() - 2 * 60 * 1000),
        },
      },
    ]

    const mockTasks: AITaskExecution[] = [
      {
        id: 'task-1',
        agentId: 'agent-1',
        taskType: 'code_analysis',
        status: 'running',
        startTime: new Date(Date.now() - 5 * 60 * 1000),
        input: 'Analyze security vulnerabilities in React component',
        metadata: { priority: 'high', source: 'manual' },
      },
      {
        id: 'task-2',
        agentId: 'agent-2',
        taskType: 'threat_analysis',
        status: 'completed',
        startTime: new Date(Date.now() - 10 * 60 * 1000),
        endTime: new Date(Date.now() - 8 * 60 * 1000),
        duration: 2 * 60 * 1000,
        input: 'Analyze IOC indicators for threat campaign',
        output: 'Identified potential APT29 campaign markers',
        metadata: { confidence: 0.87, severity: 'high' },
      },
      {
        id: 'task-3',
        agentId: 'agent-4',
        taskType: 'vulnerability_scan',
        status: 'failed',
        startTime: new Date(Date.now() - 15 * 60 * 1000),
        endTime: new Date(Date.now() - 13 * 60 * 1000),
        duration: 2 * 60 * 1000,
        input: 'Scan web application for OWASP Top 10',
        error: 'Connection timeout to target application',
        metadata: { retryCount: 3, target: 'web-app-1' },
      },
    ]

    setAgents(mockAgents)
    setTaskExecutions(mockTasks)

    // Generate mock performance data
    const performanceData: AIAgentPerformance[] = []
    for (let i = 0; i < 60; i++) {
      const timestamp = new Date(Date.now() - (60 - i) * 60 * 1000).toISOString()
      mockAgents.forEach(agent => {
        performanceData.push({
          timestamp,
          agentId: agent.id,
          responseTime: agent.metrics.avgResponseTime + (Math.random() - 0.5) * 400,
          tokensPerSecond: 50 + Math.random() * 100,
          memoryUsage: agent.metrics.memoryUsage + (Math.random() - 0.5) * 4,
          cpuUsage: agent.metrics.cpuUsage + (Math.random() - 0.5) * 20,
          requestCount: Math.floor(Math.random() * 10),
          errorRate: Math.random() * 5,
        })
      })
    }
    setPerformanceData(performanceData)
  }

  // Handle WebSocket messages
  useEffect(() => {
    if (lastJsonMessage) {
      const message = lastJsonMessage

      switch (message.type) {
        case 'agent_status_update':
          setAgents(prev => prev.map(agent => 
            agent.id === message.agentId 
              ? { ...agent, ...message.data }
              : agent
          ))
          break
        case 'agent_metrics_update':
          // Update agent metrics
          break
        case 'task_update':
          setTaskExecutions(prev => {
            const existingIndex = prev.findIndex(task => task.id === message.taskId)
            if (existingIndex >= 0) {
              const updated = [...prev]
              updated[existingIndex] = { ...updated[existingIndex], ...message.data }
              return updated
            } else {
              return [message.data, ...prev]
            }
          })
          break
      }
    }
  }, [lastJsonMessage])

  const handleAgentAction = useCallback((agentId: string, action: string) => {
    if (isConnected) {
      sendJsonMessage({
        type: 'agent_action',
        agentId,
        action,
        timestamp: new Date().toISOString(),
      })
    }
    
    // Update local state optimistically
    setAgents(prev => prev.map(agent => {
      if (agent.id === agentId) {
        switch (action) {
          case 'start':
            return { ...agent, status: 'starting' as const }
          case 'stop':
            return { ...agent, status: 'stopped' as const }
          case 'restart':
            return { ...agent, status: 'starting' as const }
          default:
            return agent
        }
      }
      return agent
    }))
  }, [isConnected, sendJsonMessage])

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'text-cyber-green-neon'
      case 'idle':
        return 'text-cyber-blue-neon'
      case 'error':
        return 'text-security-critical'
      case 'stopped':
        return 'text-matrix-text'
      case 'starting':
        return 'text-cyber-orange-neon'
      default:
        return 'text-matrix-text'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <CheckCircleIcon className="w-4 h-4 text-cyber-green-neon" />
      case 'idle':
        return <ClockIcon className="w-4 h-4 text-cyber-blue-neon" />
      case 'error':
        return <XCircleIcon className="w-4 h-4 text-security-critical" />
      case 'stopped':
        return <StopIcon className="w-4 h-4 text-matrix-text" />
      case 'starting':
        return <ArrowPathIcon className="w-4 h-4 text-cyber-orange-neon animate-spin" />
      default:
        return <XCircleIcon className="w-4 h-4 text-matrix-text" />
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'llm':
        return <CommandLineIcon className="w-4 h-4" />
      case 'security':
        return <BoltIcon className="w-4 h-4" />
      case 'analysis':
        return <ChartBarIcon className="w-4 h-4" />
      case 'monitoring':
        return <EyeIcon className="w-4 h-4" />
      case 'orchestrator':
        return <CpuChipIcon className="w-4 h-4" />
      default:
        return <CommandLineIcon className="w-4 h-4" />
    }
  }

  const selectedAgentData = selectedAgent ? agents.find(a => a.id === selectedAgent) : null
  const selectedAgentPerformance = selectedAgent 
    ? performanceData.filter(p => p.agentId === selectedAgent).slice(-20)
    : []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-cyber-blue-neon">
            AI Agent Monitoring Center
          </h3>
          <p className="text-sm text-matrix-text mt-1">
            Real-time monitoring and management of AI agents
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
              {isConnected ? 'AGENTS ONLINE' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </div>

      {/* Agent Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {agents.map((agent) => (
          <motion.div
            key={agent.id}
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            whileHover={{ scale: 1.02 }}
            transition={{ duration: 0.2 }}
          >
            <CyberpunkCard 
              variant={
                agent.status === 'error' ? 'security-critical' :
                agent.status === 'running' ? 'neon-green' :
                agent.status === 'idle' ? 'neon-blue' : 'glass-dark'
              } 
              size="sm"
              className={`cursor-pointer transition-all ${
                selectedAgent === agent.id ? 'ring-2 ring-cyber-blue-neon' : ''
              }`}
              onClick={() => setSelectedAgent(agent.id)}
            >
              <div className="space-y-3">
                {/* Agent Header */}
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    {getTypeIcon(agent.type)}
                    <div>
                      <h4 className="font-medium text-sm truncate">{agent.name}</h4>
                      <p className="text-xs text-matrix-text">{agent.model}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    {getStatusIcon(agent.status)}
                  </div>
                </div>

                {/* Agent Metrics */}
                <div className="space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-matrix-text">Requests</span>
                    <span className="font-cyber">{agent.metrics.requests}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-matrix-text">Success Rate</span>
                    <span className={`font-cyber ${
                      agent.metrics.successRate > 95 ? 'text-cyber-green-neon' :
                      agent.metrics.successRate > 90 ? 'text-cyber-orange-neon' :
                      'text-security-critical'
                    }`}>
                      {agent.metrics.successRate.toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-matrix-text">Avg Response</span>
                    <span className="font-cyber">{agent.metrics.avgResponseTime}ms</span>
                  </div>
                </div>

                {/* Health Score */}
                <div className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="text-matrix-text">Health Score</span>
                    <span className={`font-cyber ${
                      agent.health.score > 90 ? 'text-cyber-green-neon' :
                      agent.health.score > 70 ? 'text-cyber-orange-neon' :
                      'text-security-critical'
                    }`}>
                      {agent.health.score}%
                    </span>
                  </div>
                  <Progress 
                    value={agent.health.score} 
                    className="h-1"
                    indicatorClassName={
                      agent.health.score > 90 ? 'bg-cyber-green-neon' :
                      agent.health.score > 70 ? 'bg-cyber-orange-neon' :
                      'bg-security-critical'
                    }
                  />
                </div>

                {/* Actions */}
                <div className="flex gap-1">
                  <CyberpunkButton
                    variant="ghost-green"
                    size="xs"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleAgentAction(agent.id, 'start')
                    }}
                    disabled={agent.status === 'running'}
                  >
                    <PlayIcon className="w-3 h-3" />
                  </CyberpunkButton>
                  <CyberpunkButton
                    variant="ghost-orange"
                    size="xs"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleAgentAction(agent.id, 'restart')
                    }}
                  >
                    <ArrowPathIcon className="w-3 h-3" />
                  </CyberpunkButton>
                  <CyberpunkButton
                    variant="ghost-red"
                    size="xs"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleAgentAction(agent.id, 'stop')
                    }}
                    disabled={agent.status === 'stopped'}
                  >
                    <StopIcon className="w-3 h-3" />
                  </CyberpunkButton>
                </div>
              </div>
            </CyberpunkCard>
          </motion.div>
        ))}
      </div>

      {/* Detailed Agent View */}
      {selectedAgentData && (
        <Tabs defaultValue="metrics" className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <h4 className="text-lg font-semibold text-matrix-white">
                {selectedAgentData.name}
              </h4>
              <Badge variant="outline">{selectedAgentData.model}</Badge>
              <Badge 
                variant={
                  selectedAgentData.status === 'running' ? 'default' :
                  selectedAgentData.status === 'error' ? 'destructive' :
                  'secondary'
                }
              >
                {selectedAgentData.status.toUpperCase()}
              </Badge>
            </div>
            <TabsList>
              <TabsTrigger value="metrics">Performance</TabsTrigger>
              <TabsTrigger value="tasks">Tasks</TabsTrigger>
              <TabsTrigger value="config">Configuration</TabsTrigger>
              <TabsTrigger value="health">Health</TabsTrigger>
            </TabsList>
          </div>

          <TabsContent value="metrics" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Performance Chart */}
              <CyberpunkCard variant="glass-blue" size="lg">
                <div className="mb-4">
                  <h5 className="font-semibold text-cyber-blue-neon">Response Time Trends</h5>
                  <p className="text-xs text-matrix-text">Last 20 data points</p>
                </div>
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={selectedAgentPerformance}>
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
                          border: '1px solid #00ffff',
                          borderRadius: '8px',
                        }}
                        labelFormatter={(value) => new Date(value).toLocaleTimeString()}
                      />
                      <Line 
                        type="monotone" 
                        dataKey="responseTime" 
                        stroke="#00ffff" 
                        strokeWidth={2}
                        dot={false}
                        name="Response Time (ms)"
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </CyberpunkCard>

              {/* Resource Usage */}
              <CyberpunkCard variant="glass-green" size="lg">
                <div className="mb-4">
                  <h5 className="font-semibold text-cyber-green-neon">Resource Usage</h5>
                  <p className="text-xs text-matrix-text">Current system utilization</p>
                </div>
                <div className="space-y-4">
                  <div>
                    <div className="flex justify-between text-sm mb-2">
                      <span>CPU Usage</span>
                      <span className="font-cyber">{selectedAgentData.metrics.cpuUsage.toFixed(1)}%</span>
                    </div>
                    <Progress value={selectedAgentData.metrics.cpuUsage} className="h-2" />
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-2">
                      <span>Memory Usage</span>
                      <span className="font-cyber">{selectedAgentData.metrics.memoryUsage.toFixed(1)} GB</span>
                    </div>
                    <Progress value={(selectedAgentData.metrics.memoryUsage / 16) * 100} className="h-2" />
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-2">
                      <span>Tokens Processed</span>
                      <span className="font-cyber">{selectedAgentData.metrics.tokensProcessed.toLocaleString()}</span>
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-2">
                      <span>Error Rate</span>
                      <span className={`font-cyber ${
                        (selectedAgentData.metrics.errorCount / selectedAgentData.metrics.requests * 100) < 5 
                          ? 'text-cyber-green-neon' 
                          : 'text-security-critical'
                      }`}>
                        {((selectedAgentData.metrics.errorCount / selectedAgentData.metrics.requests) * 100).toFixed(2)}%
                      </span>
                    </div>
                  </div>
                </div>
              </CyberpunkCard>
            </div>
          </TabsContent>

          <TabsContent value="tasks" className="space-y-6">
            <CyberpunkCard variant="glass-dark" size="lg">
              <div className="mb-4">
                <h5 className="font-semibold text-matrix-white">Task Execution History</h5>
                <p className="text-xs text-matrix-text">Recent task executions and status</p>
              </div>
              
              <div className="space-y-3">
                {taskExecutions
                  .filter(task => task.agentId === selectedAgent)
                  .slice(0, 10)
                  .map((task) => (
                    <div key={task.id} className="p-3 bg-matrix-surface/50 rounded border border-matrix-border">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs">{task.taskType}</Badge>
                          <Badge 
                            variant={
                              task.status === 'completed' ? 'default' :
                              task.status === 'running' ? 'secondary' :
                              task.status === 'failed' ? 'destructive' :
                              'outline'
                            }
                            className="text-xs"
                          >
                            {task.status}
                          </Badge>
                        </div>
                        <span className="text-xs text-matrix-text">
                          {formatRelativeTime(task.startTime)}
                        </span>
                      </div>
                      
                      <p className="text-xs text-matrix-text mb-2 truncate">
                        <strong>Input:</strong> {task.input}
                      </p>
                      
                      {task.output && (
                        <p className="text-xs text-cyber-green-neon mb-2 truncate">
                          <strong>Output:</strong> {task.output}
                        </p>
                      )}
                      
                      {task.error && (
                        <p className="text-xs text-security-critical mb-2 truncate">
                          <strong>Error:</strong> {task.error}
                        </p>
                      )}
                      
                      {task.duration && (
                        <p className="text-xs text-matrix-text">
                          <strong>Duration:</strong> {(task.duration / 1000).toFixed(2)}s
                        </p>
                      )}
                    </div>
                  ))}
              </div>
            </CyberpunkCard>
          </TabsContent>

          <TabsContent value="config" className="space-y-6">
            <CyberpunkCard variant="neon-purple" size="lg">
              <div className="mb-4">
                <h5 className="font-semibold text-cyber-purple-neon">Agent Configuration</h5>
                <p className="text-xs text-matrix-text">Current model parameters and settings</p>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-sm text-matrix-text">Temperature:</span>
                    <span className="text-sm font-cyber">{selectedAgentData.configuration.temperature}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-matrix-text">Max Tokens:</span>
                    <span className="text-sm font-cyber">{selectedAgentData.configuration.maxTokens}</span>
                  </div>
                </div>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-sm text-matrix-text">Top P:</span>
                    <span className="text-sm font-cyber">{selectedAgentData.configuration.topP}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-matrix-text">Frequency Penalty:</span>
                    <span className="text-sm font-cyber">{selectedAgentData.configuration.frequencyPenalty}</span>
                  </div>
                </div>
              </div>
            </CyberpunkCard>
          </TabsContent>

          <TabsContent value="health" className="space-y-6">
            <CyberpunkCard 
              variant={
                selectedAgentData.health.score > 90 ? 'neon-green' :
                selectedAgentData.health.score > 70 ? 'neon-orange' :
                'security-critical'
              } 
              size="lg"
            >
              <div className="mb-4">
                <h5 className="font-semibold">Agent Health Status</h5>
                <p className="text-xs text-matrix-text">System health and diagnostic information</p>
              </div>
              
              <div className="space-y-4">
                <div className="text-center">
                  <div className="text-4xl font-bold font-cyber mb-2">
                    {selectedAgentData.health.score}%
                  </div>
                  <p className="text-sm text-matrix-text">Overall Health Score</p>
                </div>
                
                {selectedAgentData.health.issues.length > 0 ? (
                  <div className="space-y-2">
                    <h6 className="font-medium text-security-critical">Issues Detected:</h6>
                    {selectedAgentData.health.issues.map((issue, index) => (
                      <div key={index} className="flex items-center gap-2 p-2 bg-security-critical/10 rounded">
                        <ExclamationTriangleIcon className="w-4 h-4 text-security-critical" />
                        <span className="text-sm">{issue}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center p-4">
                    <CheckCircleIcon className="w-8 h-8 text-cyber-green-neon mx-auto mb-2" />
                    <p className="text-sm text-cyber-green-neon">No issues detected</p>
                  </div>
                )}
                
                <div className="text-xs text-matrix-text">
                  Last health check: {formatRelativeTime(selectedAgentData.health.lastCheck)}
                </div>
              </div>
            </CyberpunkCard>
          </TabsContent>
        </Tabs>
      )}
    </div>
  )
}