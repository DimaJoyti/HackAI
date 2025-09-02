'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  CpuChipIcon,
  ServerIcon,
  CircleStackIcon,
  WifiIcon,
  BoltIcon,
  ClockIcon,
} from '@heroicons/react/24/outline'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'

interface SystemMetrics {
  cpu: {
    usage: number
    cores: number
    temperature: number
    frequency: number
  }
  memory: {
    used: number
    total: number
    percentage: number
  }
  disk: {
    used: number
    total: number
    percentage: number
  }
  network: {
    upload: number
    download: number
    latency: number
  }
  gpu: {
    usage: number
    memory: number
    temperature: number
  }
  uptime: string
  loadAverage: number[]
}

export function SystemMonitor() {
  const [metrics, setMetrics] = useState<SystemMetrics>({
    cpu: {
      usage: 45,
      cores: 8,
      temperature: 62,
      frequency: 3.2
    },
    memory: {
      used: 12.4,
      total: 32,
      percentage: 38.75
    },
    disk: {
      used: 256,
      total: 1024,
      percentage: 25
    },
    network: {
      upload: 2.4,
      download: 15.8,
      latency: 12
    },
    gpu: {
      usage: 23,
      memory: 4.2,
      temperature: 58
    },
    uptime: '7d 14h 32m',
    loadAverage: [1.2, 1.5, 1.8]
  })

  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      setMetrics(prev => ({
        ...prev,
        cpu: {
          ...prev.cpu,
          usage: Math.max(10, Math.min(90, prev.cpu.usage + (Math.random() - 0.5) * 10)),
          temperature: Math.max(40, Math.min(80, prev.cpu.temperature + (Math.random() - 0.5) * 4))
        },
        memory: {
          ...prev.memory,
          percentage: Math.max(20, Math.min(85, prev.memory.percentage + (Math.random() - 0.5) * 5))
        },
        network: {
          ...prev.network,
          upload: Math.max(0, Math.min(50, prev.network.upload + (Math.random() - 0.5) * 5)),
          download: Math.max(0, Math.min(100, prev.network.download + (Math.random() - 0.5) * 10)),
          latency: Math.max(5, Math.min(50, prev.network.latency + (Math.random() - 0.5) * 5))
        },
        gpu: {
          ...prev.gpu,
          usage: Math.max(0, Math.min(100, prev.gpu.usage + (Math.random() - 0.5) * 15))
        }
      }))
    }, 2000)

    return () => clearInterval(interval)
  }, [])

  const getStatusColor = (percentage: number) => {
    if (percentage < 50) return 'text-cyber-green-neon'
    if (percentage < 75) return 'text-cyber-orange-neon'
    return 'text-security-critical'
  }

  const getProgressColor = (percentage: number) => {
    if (percentage < 50) return 'bg-cyber-green-neon'
    if (percentage < 75) return 'bg-cyber-orange-neon'
    return 'bg-security-critical'
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold text-cyber-green-neon">
          System Monitor
        </h3>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-cyber-green-neon rounded-full animate-neon-pulse" />
          <span className="text-xs text-cyber-green-neon font-cyber">LIVE</span>
        </div>
      </div>

      <div className="space-y-6">
        {/* CPU */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CpuChipIcon className="w-4 h-4 text-cyber-green-neon" />
              <span className="text-sm font-medium">CPU</span>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-xs">
                {metrics.cpu.cores} cores
              </Badge>
              <span className={`text-sm font-cyber ${getStatusColor(metrics.cpu.usage)}`}>
                {metrics.cpu.usage.toFixed(1)}%
              </span>
            </div>
          </div>
          <Progress 
            value={metrics.cpu.usage} 
            className="h-2"
            indicatorClassName={getProgressColor(metrics.cpu.usage)}
          />
          <div className="flex justify-between text-xs text-matrix-text">
            <span>{metrics.cpu.frequency} GHz</span>
            <span>{metrics.cpu.temperature}°C</span>
          </div>
        </div>

        {/* Memory */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ServerIcon className="w-4 h-4 text-cyber-blue-neon" />
              <span className="text-sm font-medium">Memory</span>
            </div>
            <span className={`text-sm font-cyber ${getStatusColor(metrics.memory.percentage)}`}>
              {metrics.memory.percentage.toFixed(1)}%
            </span>
          </div>
          <Progress 
            value={metrics.memory.percentage} 
            className="h-2"
            indicatorClassName={getProgressColor(metrics.memory.percentage)}
          />
          <div className="flex justify-between text-xs text-matrix-text">
            <span>{metrics.memory.used} GB used</span>
            <span>{metrics.memory.total} GB total</span>
          </div>
        </div>

        {/* Disk */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CircleStackIcon className="w-4 h-4 text-cyber-purple-neon" />
              <span className="text-sm font-medium">Storage</span>
            </div>
            <span className={`text-sm font-cyber ${getStatusColor(metrics.disk.percentage)}`}>
              {metrics.disk.percentage.toFixed(1)}%
            </span>
          </div>
          <Progress 
            value={metrics.disk.percentage} 
            className="h-2"
            indicatorClassName={getProgressColor(metrics.disk.percentage)}
          />
          <div className="flex justify-between text-xs text-matrix-text">
            <span>{metrics.disk.used} GB used</span>
            <span>{metrics.disk.total} GB total</span>
          </div>
        </div>

        {/* Network */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <WifiIcon className="w-4 h-4 text-cyber-orange-neon" />
              <span className="text-sm font-medium">Network</span>
            </div>
            <Badge variant="outline" className="text-xs">
              {metrics.network.latency}ms
            </Badge>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-matrix-text">Upload</span>
                <span className="text-cyber-green-neon font-cyber">
                  {metrics.network.upload.toFixed(1)} MB/s
                </span>
              </div>
              <div className="w-full bg-matrix-surface rounded-full h-1">
                <motion.div 
                  className="bg-cyber-green-neon h-1 rounded-full"
                  initial={{ width: 0 }}
                  animate={{ width: `${Math.min(100, (metrics.network.upload / 50) * 100)}%` }}
                  transition={{ duration: 0.5 }}
                />
              </div>
            </div>
            <div className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-matrix-text">Download</span>
                <span className="text-cyber-blue-neon font-cyber">
                  {metrics.network.download.toFixed(1)} MB/s
                </span>
              </div>
              <div className="w-full bg-matrix-surface rounded-full h-1">
                <motion.div 
                  className="bg-cyber-blue-neon h-1 rounded-full"
                  initial={{ width: 0 }}
                  animate={{ width: `${Math.min(100, (metrics.network.download / 100) * 100)}%` }}
                  transition={{ duration: 0.5 }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* GPU */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <BoltIcon className="w-4 h-4 text-cyber-pink-neon" />
              <span className="text-sm font-medium">GPU</span>
            </div>
            <span className={`text-sm font-cyber ${getStatusColor(metrics.gpu.usage)}`}>
              {metrics.gpu.usage.toFixed(1)}%
            </span>
          </div>
          <Progress 
            value={metrics.gpu.usage} 
            className="h-2"
            indicatorClassName={getProgressColor(metrics.gpu.usage)}
          />
          <div className="flex justify-between text-xs text-matrix-text">
            <span>{metrics.gpu.memory} GB VRAM</span>
            <span>{metrics.gpu.temperature}°C</span>
          </div>
        </div>

        {/* System Info */}
        <div className="pt-4 border-t border-matrix-border">
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div className="flex items-center gap-2">
              <ClockIcon className="w-3 h-3 text-matrix-text" />
              <span className="text-matrix-text">Uptime:</span>
              <span className="text-cyber-green-neon font-cyber">{metrics.uptime}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-matrix-text">Load:</span>
              <span className="text-cyber-blue-neon font-cyber">
                {metrics.loadAverage.map(load => load.toFixed(1)).join(', ')}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
