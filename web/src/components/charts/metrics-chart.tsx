'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Area,
  AreaChart,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from 'recharts'

interface MetricsChartProps {
  timeRange: string
}

interface MetricData {
  timestamp: string
  vulnerabilities: number
  scans: number
  threats: number
  systemHealth: number
  responseTime: number
  cpuUsage: number
  memoryUsage: number
}

const generateMockData = (timeRange: string): MetricData[] => {
  const now = new Date()
  const dataPoints = timeRange === '24h' ? 24 : timeRange === '7d' ? 7 : 30
  const interval = timeRange === '24h' ? 60 * 60 * 1000 : timeRange === '7d' ? 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000

  return Array.from({ length: dataPoints }, (_, i) => {
    const timestamp = new Date(now.getTime() - (dataPoints - 1 - i) * interval)
    return {
      timestamp: timeRange === '24h' 
        ? timestamp.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
        : timestamp.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      vulnerabilities: Math.floor(Math.random() * 20) + 5,
      scans: Math.floor(Math.random() * 50) + 10,
      threats: Math.floor(Math.random() * 10) + 1,
      systemHealth: Math.floor(Math.random() * 20) + 80,
      responseTime: Math.floor(Math.random() * 200) + 50,
      cpuUsage: Math.floor(Math.random() * 40) + 30,
      memoryUsage: Math.floor(Math.random() * 30) + 40,
    }
  })
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-matrix-dark/95 backdrop-blur-sm border border-cyber-blue-neon/30 rounded-lg p-3 shadow-neon-blue">
        <p className="text-cyber-blue-neon font-cyber text-sm mb-2">{label}</p>
        {payload.map((entry: any, index: number) => (
          <p key={index} className="text-xs" style={{ color: entry.color }}>
            {entry.name}: {entry.value}
            {entry.dataKey === 'systemHealth' && '%'}
            {entry.dataKey === 'responseTime' && 'ms'}
            {(entry.dataKey === 'cpuUsage' || entry.dataKey === 'memoryUsage') && '%'}
          </p>
        ))}
      </div>
    )
  }
  return null
}

export function MetricsChart({ timeRange }: MetricsChartProps) {
  const [data, setData] = useState<MetricData[]>([])
  const [activeChart, setActiveChart] = useState<'security' | 'performance' | 'system'>('security')

  useEffect(() => {
    setData(generateMockData(timeRange))
  }, [timeRange])

  // Simulate real-time updates for current time range
  useEffect(() => {
    if (timeRange === '24h') {
      const interval = setInterval(() => {
        setData(prevData => {
          const newData = [...prevData.slice(1)]
          const now = new Date()
          newData.push({
            timestamp: now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
            vulnerabilities: Math.floor(Math.random() * 20) + 5,
            scans: Math.floor(Math.random() * 50) + 10,
            threats: Math.floor(Math.random() * 10) + 1,
            systemHealth: Math.floor(Math.random() * 20) + 80,
            responseTime: Math.floor(Math.random() * 200) + 50,
            cpuUsage: Math.floor(Math.random() * 40) + 30,
            memoryUsage: Math.floor(Math.random() * 30) + 40,
          })
          return newData
        })
      }, 30000) // Update every 30 seconds for demo

      return () => clearInterval(interval)
    }
  }, [timeRange])

  const chartTabs = [
    { id: 'security', label: 'Security Metrics', color: 'cyber-blue-neon' },
    { id: 'performance', label: 'Performance', color: 'cyber-green-neon' },
    { id: 'system', label: 'System Resources', color: 'cyber-orange-neon' },
  ]

  const renderSecurityChart = () => (
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id="vulnerabilities" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ff0080" stopOpacity={0.3}/>
            <stop offset="95%" stopColor="#ff0080" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="threats" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ff4500" stopOpacity={0.3}/>
            <stop offset="95%" stopColor="#ff4500" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="scans" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#00ffff" stopOpacity={0.3}/>
            <stop offset="95%" stopColor="#00ffff" stopOpacity={0}/>
          </linearGradient>
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
        <Area
          type="monotone"
          dataKey="vulnerabilities"
          stroke="#ff0080"
          strokeWidth={2}
          fill="url(#vulnerabilities)"
          name="Vulnerabilities"
        />
        <Area
          type="monotone"
          dataKey="threats"
          stroke="#ff4500"
          strokeWidth={2}
          fill="url(#threats)"
          name="Threats"
        />
        <Area
          type="monotone"
          dataKey="scans"
          stroke="#00ffff"
          strokeWidth={2}
          fill="url(#scans)"
          name="Scans"
        />
      </AreaChart>
    </ResponsiveContainer>
  )

  const renderPerformanceChart = () => (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={data}>
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
        <Line
          type="monotone"
          dataKey="systemHealth"
          stroke="#00ff41"
          strokeWidth={3}
          dot={{ fill: '#00ff41', strokeWidth: 2, r: 4 }}
          name="System Health"
        />
        <Line
          type="monotone"
          dataKey="responseTime"
          stroke="#ff4500"
          strokeWidth={2}
          dot={{ fill: '#ff4500', strokeWidth: 2, r: 3 }}
          name="Response Time"
        />
      </LineChart>
    </ResponsiveContainer>
  )

  const renderSystemChart = () => (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data}>
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
        <Bar
          dataKey="cpuUsage"
          fill="#00ffff"
          name="CPU Usage"
          radius={[2, 2, 0, 0]}
        />
        <Bar
          dataKey="memoryUsage"
          fill="#ff0080"
          name="Memory Usage"
          radius={[2, 2, 0, 0]}
        />
      </BarChart>
    </ResponsiveContainer>
  )

  return (
    <div>
      {/* Chart tabs */}
      <div className="flex items-center gap-1 mb-6">
        {chartTabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveChart(tab.id as any)}
            className={`px-4 py-2 text-sm rounded-lg transition-all duration-200 ${
              activeChart === tab.id
                ? `bg-${tab.color}/20 text-${tab.color} border border-${tab.color}/40 shadow-neon-blue`
                : 'text-matrix-text hover:text-matrix-white hover:bg-matrix-surface border border-transparent'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Chart container */}
      <motion.div
        key={activeChart}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="relative"
      >
        {/* Chart background */}
        <div className="absolute inset-0 bg-gradient-to-br from-matrix-dark/50 to-transparent rounded-lg" />
        
        {/* Chart content */}
        <div className="relative z-10 p-4">
          {activeChart === 'security' && renderSecurityChart()}
          {activeChart === 'performance' && renderPerformanceChart()}
          {activeChart === 'system' && renderSystemChart()}
        </div>

        {/* Chart overlay effects */}
        <div className="absolute inset-0 bg-gradient-to-t from-matrix-dark/20 to-transparent pointer-events-none rounded-lg" />
        <div className="absolute inset-0 bg-cyber-grid opacity-5 pointer-events-none rounded-lg" />
      </motion.div>

      {/* Chart legend */}
      <div className="mt-4 flex flex-wrap items-center gap-4 text-xs">
        {activeChart === 'security' && (
          <>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-cyber-pink-neon rounded-full" />
              <span className="text-matrix-text">Vulnerabilities Found</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-cyber-orange-neon rounded-full" />
              <span className="text-matrix-text">Active Threats</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-cyber-blue-neon rounded-full" />
              <span className="text-matrix-text">Security Scans</span>
            </div>
          </>
        )}
        
        {activeChart === 'performance' && (
          <>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-cyber-green-neon rounded-full" />
              <span className="text-matrix-text">System Health (%)</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-cyber-orange-neon rounded-full" />
              <span className="text-matrix-text">Response Time (ms)</span>
            </div>
          </>
        )}
        
        {activeChart === 'system' && (
          <>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-cyber-blue-neon rounded-full" />
              <span className="text-matrix-text">CPU Usage (%)</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-cyber-pink-neon rounded-full" />
              <span className="text-matrix-text">Memory Usage (%)</span>
            </div>
          </>
        )}
        
        <div className="ml-auto flex items-center gap-2">
          <div className="w-2 h-2 bg-cyber-green-neon rounded-full animate-neon-pulse" />
          <span className="text-cyber-green-neon font-cyber">LIVE DATA</span>
        </div>
      </div>
    </div>
  )
}
