'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  ReferenceLine,
} from 'recharts'
import {
  PlayIcon,
  PauseIcon,
  ArrowPathIcon,
  ChartBarIcon,
  EyeIcon,
  BoltIcon,
} from '@heroicons/react/24/outline'
import { useWebSocketJSON } from '@/hooks/use-websocket'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'

interface StreamingDataPoint {
  timestamp: string
  threatLevel: number
  activeThreats: number
  blockedAttacks: number
  systemHealth: number
  networkTraffic: number
  cpuUsage: number
  memoryUsage: number
  anomalyScore: number
}

interface ThreatEvent {
  type: 'threat' | 'attack' | 'anomaly' | 'system'
  severity: 'low' | 'medium' | 'high' | 'critical'
  message: string
  timestamp: string
  value: number
}

interface RealTimeStreamingChartProps {
  streamUrl?: string
  maxDataPoints?: number
  updateInterval?: number
  chartType?: 'line' | 'area' | 'bar'
  showEvents?: boolean
  height?: number
}

const CHART_COLORS = {
  threatLevel: '#ff0080',
  activeThreats: '#ff4500',
  blockedAttacks: '#00ffff',
  systemHealth: '#00ff41',
  networkTraffic: '#8b5cf6',
  cpuUsage: '#f59e0b',
  memoryUsage: '#06b6d4',
  anomalyScore: '#ef4444',
}

const METRIC_CONFIGS = {
  threatLevel: { name: 'Threat Level', unit: '%', threshold: 80 },
  activeThreats: { name: 'Active Threats', unit: '', threshold: 5 },
  blockedAttacks: { name: 'Blocked Attacks', unit: '', threshold: 50 },
  systemHealth: { name: 'System Health', unit: '%', threshold: 70, inverted: true },
  networkTraffic: { name: 'Network Traffic', unit: 'MB/s', threshold: 100 },
  cpuUsage: { name: 'CPU Usage', unit: '%', threshold: 80 },
  memoryUsage: { name: 'Memory Usage', unit: '%', threshold: 85 },
  anomalyScore: { name: 'Anomaly Score', unit: '', threshold: 7 },
}

export function RealTimeStreamingChart({
  streamUrl = 'ws://localhost:8080/ws/dashboard',
  maxDataPoints = 50,
  updateInterval = 1000,
  chartType = 'area',
  showEvents = true,
  height = 400,
}: RealTimeStreamingChartProps) {
  const [data, setData] = useState<StreamingDataPoint[]>([])
  const [events, setEvents] = useState<ThreatEvent[]>([])
  const [selectedMetrics, setSelectedMetrics] = useState<string[]>(['threatLevel', 'systemHealth', 'activeThreats'])
  const [isPaused, setIsPaused] = useState(false)
  const [isConnected, setIsConnected] = useState(false)
  const [alertThresholds, setAlertThresholds] = useState<Record<string, boolean>>({})

  // WebSocket connection for real-time data
  const { lastJsonMessage, sendJsonMessage, connectionStatus } = useWebSocketJSON<any>(
    streamUrl,
    {
      onOpen: () => {
        setIsConnected(true)
        // Request streaming data
        sendJsonMessage({ 
          type: 'subscribe', 
          streams: ['threat_metrics', 'system_metrics', 'security_alerts'] 
        })
      },
      onClose: () => setIsConnected(false),
      shouldReconnect: () => true,
      reconnectInterval: 3000,
    }
  )

  // Generate mock data when WebSocket is not available
  useEffect(() => {
    if (!isConnected && !isPaused) {
      const interval = setInterval(() => {
        const now = new Date()
        const newDataPoint: StreamingDataPoint = {
          timestamp: now.toLocaleTimeString(),
          threatLevel: Math.floor(Math.random() * 100),
          activeThreats: Math.floor(Math.random() * 10),
          blockedAttacks: Math.floor(Math.random() * 100),
          systemHealth: 85 + Math.floor(Math.random() * 15),
          networkTraffic: Math.floor(Math.random() * 200),
          cpuUsage: 20 + Math.floor(Math.random() * 60),
          memoryUsage: 30 + Math.floor(Math.random() * 50),
          anomalyScore: Math.random() * 10,
        }

        setData(prevData => {
          const updatedData = [...prevData, newDataPoint]
          return updatedData.slice(-maxDataPoints)
        })

        // Generate occasional events
        if (Math.random() < 0.1) {
          const eventTypes = ['threat', 'attack', 'anomaly', 'system'] as const
          const severities = ['low', 'medium', 'high', 'critical'] as const
          const messages = [
            'Suspicious activity detected',
            'Attack blocked successfully',
            'System anomaly identified',
            'Performance threshold exceeded',
          ]

          const newEvent: ThreatEvent = {
            type: eventTypes[Math.floor(Math.random() * eventTypes.length)],
            severity: severities[Math.floor(Math.random() * severities.length)],
            message: messages[Math.floor(Math.random() * messages.length)],
            timestamp: now.toISOString(),
            value: Math.random() * 100,
          }

          setEvents(prevEvents => [newEvent, ...prevEvents.slice(0, 9)])
        }
      }, updateInterval)

      return () => clearInterval(interval)
    }
  }, [isConnected, isPaused, maxDataPoints, updateInterval])

  // Handle WebSocket messages
  useEffect(() => {
    if (lastJsonMessage && !isPaused) {
      const message = lastJsonMessage

      switch (message.type) {
        case 'threat_metrics':
        case 'system_metrics':
          const dataPoint: StreamingDataPoint = {
            timestamp: new Date(message.timestamp || Date.now()).toLocaleTimeString(),
            ...message.payload,
          }
          
          setData(prevData => {
            const updatedData = [...prevData, dataPoint]
            return updatedData.slice(-maxDataPoints)
          })
          break

        case 'security_alert':
          const event: ThreatEvent = {
            type: message.payload.type || 'threat',
            severity: message.payload.severity || 'medium',
            message: message.payload.message || 'Security event detected',
            timestamp: message.timestamp || new Date().toISOString(),
            value: message.payload.value || 0,
          }
          
          setEvents(prevEvents => [event, ...prevEvents.slice(0, 9)])
          break
      }
    }
  }, [lastJsonMessage, isPaused, maxDataPoints])

  // Check for threshold violations
  useEffect(() => {
    if (data.length === 0) return

    const latestData = data[data.length - 1]
    const newAlerts: Record<string, boolean> = {}

    Object.entries(METRIC_CONFIGS).forEach(([key, config]) => {
      const value = latestData[key as keyof StreamingDataPoint] as number
      const isAlert = config.inverted 
        ? value < config.threshold 
        : value > config.threshold

      newAlerts[key] = isAlert
    })

    setAlertThresholds(newAlerts)
  }, [data])

  const toggleMetric = useCallback((metric: string) => {
    setSelectedMetrics(prev => 
      prev.includes(metric)
        ? prev.filter(m => m !== metric)
        : [...prev, metric]
    )
  }, [])

  const handlePauseToggle = useCallback(() => {
    setIsPaused(!isPaused)
  }, [isPaused])

  const handleClearData = useCallback(() => {
    setData([])
    setEvents([])
  }, [])

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-matrix-dark/95 backdrop-blur-sm border border-cyber-blue-neon/30 rounded-lg p-3 shadow-neon-blue">
          <p className="text-cyber-blue-neon font-cyber text-sm mb-2">{label}</p>
          {payload.map((entry: any, index: number) => {
            const config = METRIC_CONFIGS[entry.dataKey as keyof typeof METRIC_CONFIGS]
            const isAlert = alertThresholds[entry.dataKey]
            return (
              <div key={index} className="flex items-center justify-between gap-4">
                <span className="text-xs" style={{ color: entry.color }}>
                  {config.name}:
                </span>
                <span 
                  className={`text-xs font-cyber ${isAlert ? 'text-security-critical' : ''}`}
                  style={{ color: isAlert ? '#ef4444' : entry.color }}
                >
                  {entry.value.toFixed(1)}{config.unit}
                </span>
              </div>
            )
          })}
        </div>
      )
    }
    return null
  }

  const renderChart = () => {
    const chartProps = {
      data,
      margin: { top: 5, right: 30, left: 20, bottom: 5 },
    }

    const chartElements = selectedMetrics.map((metric) => {
      const config = METRIC_CONFIGS[metric as keyof typeof METRIC_CONFIGS]
      const color = CHART_COLORS[metric as keyof typeof CHART_COLORS]
      const threshold = config.threshold

      if (chartType === 'area') {
        return (
          <Area
            key={metric}
            type="monotone"
            dataKey={metric}
            stroke={color}
            strokeWidth={2}
            fill={color}
            fillOpacity={0.1}
            name={config.name}
            connectNulls={false}
          />
        )
      } else if (chartType === 'bar') {
        return (
          <Bar
            key={metric}
            dataKey={metric}
            fill={color}
            name={config.name}
            radius={[2, 2, 0, 0]}
          />
        )
      } else {
        return (
          <Line
            key={metric}
            type="monotone"
            dataKey={metric}
            stroke={color}
            strokeWidth={2}
            dot={false}
            name={config.name}
            connectNulls={false}
          />
        )
      }
    })

    const thresholdLines = selectedMetrics.map((metric) => {
      const config = METRIC_CONFIGS[metric as keyof typeof METRIC_CONFIGS]
      const color = CHART_COLORS[metric as keyof typeof CHART_COLORS]
      
      return (
        <ReferenceLine
          key={`${metric}-threshold`}
          y={config.threshold}
          stroke={color}
          strokeDasharray="3 3"
          strokeOpacity={0.5}
        />
      )
    })

    if (chartType === 'bar') {
      return (
        <ResponsiveContainer width="100%" height={height}>
          <BarChart {...chartProps}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" opacity={0.3} />
            <XAxis 
              dataKey="timestamp" 
              stroke="#64748b" 
              fontSize={12}
              tick={{ fill: '#64748b' }}
            />
            <YAxis 
              stroke="#64748b" 
              fontSize={12}
              tick={{ fill: '#64748b' }}
            />
            <Tooltip content={<CustomTooltip />} />
            {chartElements}
            {thresholdLines}
          </BarChart>
        </ResponsiveContainer>
      )
    } else if (chartType === 'area') {
      return (
        <ResponsiveContainer width="100%" height={height}>
          <AreaChart {...chartProps}>
            <defs>
              {selectedMetrics.map((metric) => (
                <linearGradient key={`gradient-${metric}`} id={`gradient-${metric}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={CHART_COLORS[metric as keyof typeof CHART_COLORS]} stopOpacity={0.3}/>
                  <stop offset="95%" stopColor={CHART_COLORS[metric as keyof typeof CHART_COLORS]} stopOpacity={0}/>
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" opacity={0.3} />
            <XAxis 
              dataKey="timestamp" 
              stroke="#64748b" 
              fontSize={12}
              tick={{ fill: '#64748b' }}
            />
            <YAxis 
              stroke="#64748b" 
              fontSize={12}
              tick={{ fill: '#64748b' }}
            />
            <Tooltip content={<CustomTooltip />} />
            {chartElements.map((element, index) => 
              element && React.cloneElement(element, {
                fill: `url(#gradient-${selectedMetrics[index]})`,
                key: element.key,
              })
            )}
            {thresholdLines}
          </AreaChart>
        </ResponsiveContainer>
      )
    } else {
      return (
        <ResponsiveContainer width="100%" height={height}>
          <LineChart {...chartProps}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" opacity={0.3} />
            <XAxis 
              dataKey="timestamp" 
              stroke="#64748b" 
              fontSize={12}
              tick={{ fill: '#64748b' }}
            />
            <YAxis 
              stroke="#64748b" 
              fontSize={12}
              tick={{ fill: '#64748b' }}
            />
            <Tooltip content={<CustomTooltip />} />
            {chartElements}
            {thresholdLines}
          </LineChart>
        </ResponsiveContainer>
      )
    }
  }

  return (
    <div className="space-y-6">
      {/* Chart Controls */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${
              isConnected ? 'bg-cyber-green-neon animate-neon-pulse' : 'bg-security-critical'
            }`} />
            <span className={`text-sm font-cyber ${
              isConnected ? 'text-cyber-green-neon' : 'text-security-critical'
            }`}>
              {isConnected ? 'LIVE STREAM' : 'MOCK DATA'}
            </span>
          </div>
          
          <Badge variant={isPaused ? 'secondary' : 'outline'} className="text-xs">
            {data.length} / {maxDataPoints} points
          </Badge>
        </div>

        <div className="flex items-center gap-2">
          <CyberpunkButton
            variant="ghost-blue"
            size="sm"
            onClick={handlePauseToggle}
          >
            {isPaused ? <PlayIcon className="w-4 h-4" /> : <PauseIcon className="w-4 h-4" />}
            {isPaused ? 'Resume' : 'Pause'}
          </CyberpunkButton>
          
          <CyberpunkButton
            variant="ghost-orange"
            size="sm"
            onClick={handleClearData}
          >
            <ArrowPathIcon className="w-4 h-4" />
            Clear
          </CyberpunkButton>
        </div>
      </div>

      {/* Metric Selection */}
      <div className="flex flex-wrap gap-2">
        {Object.entries(METRIC_CONFIGS).map(([key, config]) => {
          const isSelected = selectedMetrics.includes(key)
          const isAlert = alertThresholds[key]
          const color = CHART_COLORS[key as keyof typeof CHART_COLORS]
          
          return (
            <button
              key={key}
              onClick={() => toggleMetric(key)}
              className={`px-3 py-1 text-xs rounded-md transition-all duration-200 border ${
                isSelected
                  ? `border-${isAlert ? 'security-critical' : 'current'} bg-current/10`
                  : 'border-matrix-border hover:border-current/50'
              }`}
              style={{
                color: isSelected ? (isAlert ? '#ef4444' : color) : '#64748b',
                borderColor: isSelected ? (isAlert ? '#ef4444' : color) : '#374151',
              }}
            >
              {config.name}
              {isAlert && (
                <span className="ml-1 text-security-critical">⚠</span>
              )}
            </button>
          )
        })}
      </div>

      {/* Chart */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="relative bg-gradient-to-br from-matrix-dark/50 to-transparent rounded-lg p-4"
      >
        {/* Chart background effects */}
        <div className="absolute inset-0 bg-cyber-grid opacity-5 pointer-events-none rounded-lg" />
        
        {renderChart()}
        
        {/* Real-time indicator */}
        {isConnected && !isPaused && (
          <div className="absolute top-2 right-2 flex items-center gap-1">
            <div className="w-2 h-2 bg-cyber-green-neon rounded-full animate-neon-pulse" />
            <span className="text-xs text-cyber-green-neon font-cyber">STREAMING</span>
          </div>
        )}
      </motion.div>

      {/* Events Panel */}
      {showEvents && events.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-matrix-white">Recent Events</h4>
          <div className="space-y-1 max-h-32 overflow-y-auto">
            <AnimatePresence>
              {events.slice(0, 5).map((event, index) => (
                <motion.div
                  key={`${event.timestamp}-${index}`}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  className="flex items-center gap-2 p-2 bg-matrix-surface/50 rounded text-xs"
                >
                  <div className={`w-2 h-2 rounded-full ${
                    event.severity === 'critical' ? 'bg-security-critical' :
                    event.severity === 'high' ? 'bg-security-high' :
                    event.severity === 'medium' ? 'bg-security-medium' :
                    'bg-security-low'
                  }`} />
                  <span className="flex-1 text-matrix-text">{event.message}</span>
                  <span className="text-matrix-text/70">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </span>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>
      )}
    </div>
  )
}