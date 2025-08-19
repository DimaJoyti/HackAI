'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CpuChipIcon,
  ClockIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  EyeIcon,
  BellIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { useWebSocket } from '@/hooks/use-websocket'
import { formatDateTime, formatRelativeTime } from '@/lib/utils'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts'

interface ThreatMetrics {
  timestamp: string
  threatLevel: number
  activeThreats: number
  blockedAttacks: number
  systemHealth: number
}

interface SecurityAlert {
  id: string
  type: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
  source: string
  timestamp: Date
  status: 'active' | 'investigating' | 'resolved'
  affectedSystems: string[]
}

interface SystemMetrics {
  cpu: number
  memory: number
  network: number
  storage: number
  uptime: number
}

export default function RealTimeDashboard() {
  const [threatMetrics, setThreatMetrics] = useState<ThreatMetrics[]>([])
  const [alerts, setAlerts] = useState<SecurityAlert[]>([])
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics>({
    cpu: 0,
    memory: 0,
    network: 0,
    storage: 0,
    uptime: 0,
  })
  const [isConnected, setIsConnected] = useState(false)
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date())

  // WebSocket connection for real-time updates
  const { sendMessage, lastMessage, connectionStatus } = useWebSocket('ws://localhost:8080/ws/dashboard')

  useEffect(() => {
    setIsConnected(connectionStatus === 'Connected')
  }, [connectionStatus])

  // Handle incoming WebSocket messages
  useEffect(() => {
    if (lastMessage) {
      try {
        const data = JSON.parse(lastMessage.data)
        
        switch (data.type) {
          case 'threat_metrics':
            setThreatMetrics(prev => [...prev.slice(-19), data.payload])
            break
          case 'security_alert':
            setAlerts(prev => [data.payload, ...prev.slice(0, 9)])
            break
          case 'system_metrics':
            setSystemMetrics(data.payload)
            break
        }
        
        setLastUpdate(new Date())
      } catch (error) {
        console.error('Error parsing WebSocket message:', error)
      }
    }
  }, [lastMessage])

  // Generate mock data for demonstration
  useEffect(() => {
    const generateMockData = () => {
      const now = new Date()
      
      // Generate threat metrics
      const newMetric: ThreatMetrics = {
        timestamp: now.toISOString(),
        threatLevel: Math.floor(Math.random() * 100),
        activeThreats: Math.floor(Math.random() * 10),
        blockedAttacks: Math.floor(Math.random() * 50),
        systemHealth: 85 + Math.floor(Math.random() * 15),
      }
      
      setThreatMetrics(prev => [...prev.slice(-19), newMetric])
      
      // Generate system metrics
      setSystemMetrics({
        cpu: 20 + Math.floor(Math.random() * 60),
        memory: 30 + Math.floor(Math.random() * 50),
        network: 10 + Math.floor(Math.random() * 40),
        storage: 40 + Math.floor(Math.random() * 30),
        uptime: 99.5 + Math.random() * 0.5,
      })
      
      // Occasionally generate alerts
      if (Math.random() < 0.1) {
        const alertTypes = ['critical', 'high', 'medium', 'low', 'info'] as const
        const alertTitles = [
          'Suspicious Login Attempt',
          'Malware Detection',
          'Network Intrusion Detected',
          'Unusual Data Transfer',
          'Failed Authentication Spike',
          'DDoS Attack Detected',
          'Privilege Escalation Attempt',
        ]
        
        const newAlert: SecurityAlert = {
          id: Math.random().toString(36).substr(2, 9),
          type: alertTypes[Math.floor(Math.random() * alertTypes.length)],
          title: alertTitles[Math.floor(Math.random() * alertTitles.length)],
          description: 'Automated security system detected potential threat activity.',
          source: 'AI Security Engine',
          timestamp: now,
          status: 'active',
          affectedSystems: ['Web Server', 'Database', 'API Gateway'].slice(0, Math.floor(Math.random() * 3) + 1),
        }
        
        setAlerts(prev => [newAlert, ...prev.slice(0, 9)])
      }
      
      setLastUpdate(now)
    }

    // Initial data
    generateMockData()
    
    // Update every 5 seconds
    const interval = setInterval(generateMockData, 5000)
    
    return () => clearInterval(interval)
  }, [])

  const getThreatLevelColor = (level: number) => {
    if (level >= 80) return 'text-red-600'
    if (level >= 60) return 'text-orange-600'
    if (level >= 40) return 'text-yellow-600'
    return 'text-green-600'
  }

  const getThreatLevelBg = (level: number) => {
    if (level >= 80) return 'bg-red-100 dark:bg-red-900/20'
    if (level >= 60) return 'bg-orange-100 dark:bg-orange-900/20'
    if (level >= 40) return 'bg-yellow-100 dark:bg-yellow-900/20'
    return 'bg-green-100 dark:bg-green-900/20'
  }

  const getAlertIcon = (type: string) => {
    switch (type) {
      case 'critical':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-600" />
      case 'high':
        return <ExclamationTriangleIcon className="h-5 w-5 text-orange-600" />
      case 'medium':
        return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-600" />
      case 'low':
        return <ExclamationTriangleIcon className="h-5 w-5 text-blue-600" />
      default:
        return <BellIcon className="h-5 w-5 text-gray-600" />
    }
  }

  const currentThreatLevel = threatMetrics[threatMetrics.length - 1]?.threatLevel || 0

  return (
    <div className="p-6 space-y-6">
      {/* Header with Connection Status */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Real-Time Security Dashboard
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Live monitoring and threat intelligence
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
            <span className="text-sm text-gray-600 dark:text-gray-400">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Last update: {formatRelativeTime(lastUpdate)}
            </p>
          </div>
        </div>
      </div>

      {/* Threat Level Overview */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className={`p-6 rounded-lg border-2 ${getThreatLevelBg(currentThreatLevel)}`}
      >
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
              Current Threat Level
            </h2>
            <p className="text-gray-600 dark:text-gray-400">
              Real-time security assessment
            </p>
          </div>
          <div className="text-right">
            <div className={`text-6xl font-bold ${getThreatLevelColor(currentThreatLevel)}`}>
              {currentThreatLevel}
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              {currentThreatLevel >= 80 ? 'CRITICAL' : 
               currentThreatLevel >= 60 ? 'HIGH' : 
               currentThreatLevel >= 40 ? 'MEDIUM' : 'LOW'}
            </p>
          </div>
        </div>
      </motion.div>

      {/* Real-time Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
            <ShieldCheckIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {threatMetrics[threatMetrics.length - 1]?.activeThreats || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Currently being monitored
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Blocked Attacks</CardTitle>
            <ExclamationTriangleIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {threatMetrics[threatMetrics.length - 1]?.blockedAttacks || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              In the last hour
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Health</CardTitle>
            <CpuChipIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {threatMetrics[threatMetrics.length - 1]?.systemHealth || 0}%
            </div>
            <p className="text-xs text-muted-foreground">
              Overall system status
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Uptime</CardTitle>
            <ClockIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {systemMetrics.uptime.toFixed(2)}%
            </div>
            <p className="text-xs text-muted-foreground">
              Last 30 days
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Metrics Chart */}
        <Card>
          <CardHeader>
            <CardTitle>Threat Level Trends</CardTitle>
            <CardDescription>
              Real-time threat level monitoring over time
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={threatMetrics}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="timestamp" 
                    tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                  />
                  <YAxis />
                  <Tooltip 
                    labelFormatter={(value) => new Date(value).toLocaleString()}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="threatLevel" 
                    stroke="#ef4444" 
                    fill="#ef4444" 
                    fillOpacity={0.3}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* System Performance */}
        <Card>
          <CardHeader>
            <CardTitle>System Performance</CardTitle>
            <CardDescription>
              Real-time system resource utilization
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>CPU Usage</span>
                  <span>{systemMetrics.cpu}%</span>
                </div>
                <Progress value={systemMetrics.cpu} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>Memory Usage</span>
                  <span>{systemMetrics.memory}%</span>
                </div>
                <Progress value={systemMetrics.memory} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>Network I/O</span>
                  <span>{systemMetrics.network}%</span>
                </div>
                <Progress value={systemMetrics.network} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>Storage Usage</span>
                  <span>{systemMetrics.storage}%</span>
                </div>
                <Progress value={systemMetrics.storage} className="h-2" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Security Alerts */}
      <Card>
        <CardHeader>
          <CardTitle>Live Security Alerts</CardTitle>
          <CardDescription>
            Real-time security events and notifications
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <AnimatePresence>
              {alerts.map((alert) => (
                <motion.div
                  key={alert.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  className="flex items-start space-x-3 p-3 border rounded-lg"
                >
                  {getAlertIcon(alert.type)}
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <h4 className="font-medium text-sm">{alert.title}</h4>
                      <Badge variant={alert.type as any}>{alert.type}</Badge>
                    </div>
                    <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                      {alert.description}
                    </p>
                    <div className="flex items-center justify-between mt-2">
                      <span className="text-xs text-gray-500">
                        {alert.source} • {formatRelativeTime(alert.timestamp)}
                      </span>
                      <div className="flex space-x-1">
                        {alert.affectedSystems.map((system, index) => (
                          <Badge key={index} variant="outline" className="text-xs">
                            {system}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
            {alerts.length === 0 && (
              <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                <BellIcon className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No active alerts</p>
                <p className="text-sm">All systems operating normally</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
