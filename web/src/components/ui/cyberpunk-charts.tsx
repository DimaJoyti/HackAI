'use client'

import React, { useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from './cyberpunk-card'
import { HolographicDisplay, ParticleSystem } from './cyberpunk-effects'

// Cyberpunk Line Chart
interface CyberpunkLineChartProps {
  className?: string
  title?: string
  data: Array<{ x: number; y: number; label?: string }>
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  showGrid?: boolean
  animated?: boolean
  height?: number
}

export const CyberpunkLineChart: React.FC<CyberpunkLineChartProps> = ({
  className,
  title,
  data,
  color = 'blue',
  showGrid = true,
  animated = true,
  height = 200
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const animationRef = useRef<number>()

  const colorMap = {
    blue: '#00d4ff',
    green: '#00ff41',
    pink: '#ff0080',
    purple: '#8000ff',
    orange: '#ff6600'
  }

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || data.length === 0) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const resizeCanvas = () => {
      const rect = canvas.getBoundingClientRect()
      canvas.width = rect.width * window.devicePixelRatio
      canvas.height = height * window.devicePixelRatio
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio)
    }

    resizeCanvas()
    window.addEventListener('resize', resizeCanvas)

    const padding = 40
    const chartWidth = canvas.width / window.devicePixelRatio - padding * 2
    const chartHeight = height - padding * 2

    const minX = Math.min(...data.map(d => d.x))
    const maxX = Math.max(...data.map(d => d.x))
    const minY = Math.min(...data.map(d => d.y))
    const maxY = Math.max(...data.map(d => d.y))

    const scaleX = (x: number) => padding + ((x - minX) / (maxX - minX)) * chartWidth
    const scaleY = (y: number) => height - padding - ((y - minY) / (maxY - minY)) * chartHeight

    let animationProgress = 0

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width / window.devicePixelRatio, height)

      // Grid
      if (showGrid) {
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)'
        ctx.lineWidth = 1

        // Vertical grid lines
        for (let i = 0; i <= 10; i++) {
          const x = padding + (i / 10) * chartWidth
          ctx.beginPath()
          ctx.moveTo(x, padding)
          ctx.lineTo(x, height - padding)
          ctx.stroke()
        }

        // Horizontal grid lines
        for (let i = 0; i <= 5; i++) {
          const y = padding + (i / 5) * chartHeight
          ctx.beginPath()
          ctx.moveTo(padding, y)
          ctx.lineTo(padding + chartWidth, y)
          ctx.stroke()
        }
      }

      // Data line
      if (data.length > 1) {
        ctx.strokeStyle = colorMap[color]
        ctx.lineWidth = 2
        ctx.shadowBlur = 10
        ctx.shadowColor = colorMap[color]

        ctx.beginPath()
        const startPoint = data[0]
        ctx.moveTo(scaleX(startPoint.x), scaleY(startPoint.y))

        const pointsToShow = animated ? Math.floor(data.length * animationProgress) : data.length
        
        for (let i = 1; i < pointsToShow; i++) {
          const point = data[i]
          ctx.lineTo(scaleX(point.x), scaleY(point.y))
        }
        ctx.stroke()

        // Data points
        ctx.fillStyle = colorMap[color]
        for (let i = 0; i < pointsToShow; i++) {
          const point = data[i]
          ctx.beginPath()
          ctx.arc(scaleX(point.x), scaleY(point.y), 3, 0, Math.PI * 2)
          ctx.fill()
        }
      }

      if (animated && animationProgress < 1) {
        animationProgress += 0.02
        animationRef.current = requestAnimationFrame(draw)
      }
    }

    draw()

    return () => {
      window.removeEventListener('resize', resizeCanvas)
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current)
      }
    }
  }, [data, color, showGrid, animated, height])

  return (
    <CyberpunkCard variant={`neon-${color}` as any} className={cn('relative overflow-hidden', className)}>
      {title && (
        <CyberpunkCardHeader accent>
          <CyberpunkCardTitle className={`text-cyber-${color}-neon`}>
            {title}
          </CyberpunkCardTitle>
        </CyberpunkCardHeader>
      )}
      <CyberpunkCardContent>
        <canvas
          ref={canvasRef}
          className="w-full"
          style={{ height: `${height}px` }}
        />
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Cyberpunk Radar Chart
interface CyberpunkRadarChartProps {
  className?: string
  title?: string
  data: Array<{ label: string; value: number; max?: number }>
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  size?: number
}

export const CyberpunkRadarChart: React.FC<CyberpunkRadarChartProps> = ({
  className,
  title,
  data,
  color = 'green',
  size = 200
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  const colorMap = {
    blue: '#00d4ff',
    green: '#00ff41',
    pink: '#ff0080',
    purple: '#8000ff',
    orange: '#ff6600'
  }

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || data.length === 0) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    canvas.width = size
    canvas.height = size

    const centerX = size / 2
    const centerY = size / 2
    const radius = size / 2 - 40

    ctx.clearRect(0, 0, size, size)

    // Draw radar grid
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)'
    ctx.lineWidth = 1

    // Concentric circles
    for (let i = 1; i <= 5; i++) {
      ctx.beginPath()
      ctx.arc(centerX, centerY, (radius / 5) * i, 0, Math.PI * 2)
      ctx.stroke()
    }

    // Radial lines
    const angleStep = (Math.PI * 2) / data.length
    for (let i = 0; i < data.length; i++) {
      const angle = i * angleStep - Math.PI / 2
      ctx.beginPath()
      ctx.moveTo(centerX, centerY)
      ctx.lineTo(
        centerX + Math.cos(angle) * radius,
        centerY + Math.sin(angle) * radius
      )
      ctx.stroke()
    }

    // Draw data
    ctx.strokeStyle = colorMap[color]
    ctx.fillStyle = colorMap[color] + '40'
    ctx.lineWidth = 2
    ctx.shadowBlur = 10
    ctx.shadowColor = colorMap[color]

    ctx.beginPath()
    data.forEach((item, index) => {
      const angle = index * angleStep - Math.PI / 2
      const value = item.value / (item.max || 100)
      const x = centerX + Math.cos(angle) * radius * value
      const y = centerY + Math.sin(angle) * radius * value

      if (index === 0) {
        ctx.moveTo(x, y)
      } else {
        ctx.lineTo(x, y)
      }
    })
    ctx.closePath()
    ctx.fill()
    ctx.stroke()

    // Draw data points
    ctx.fillStyle = colorMap[color]
    data.forEach((item, index) => {
      const angle = index * angleStep - Math.PI / 2
      const value = item.value / (item.max || 100)
      const x = centerX + Math.cos(angle) * radius * value
      const y = centerY + Math.sin(angle) * radius * value

      ctx.beginPath()
      ctx.arc(x, y, 4, 0, Math.PI * 2)
      ctx.fill()
    })

    // Draw labels
    ctx.fillStyle = '#ffffff'
    ctx.font = '12px monospace'
    ctx.textAlign = 'center'
    data.forEach((item, index) => {
      const angle = index * angleStep - Math.PI / 2
      const labelX = centerX + Math.cos(angle) * (radius + 20)
      const labelY = centerY + Math.sin(angle) * (radius + 20)

      ctx.fillText(item.label, labelX, labelY)
    })
  }, [data, color, size])

  return (
    <CyberpunkCard variant={`neon-${color}` as any} className={cn('relative overflow-hidden', className)}>
      {title && (
        <CyberpunkCardHeader accent>
          <CyberpunkCardTitle className={`text-cyber-${color}-neon`}>
            {title}
          </CyberpunkCardTitle>
        </CyberpunkCardHeader>
      )}
      <CyberpunkCardContent className="flex justify-center">
        <canvas ref={canvasRef} />
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Cyberpunk Progress Ring
interface CyberpunkProgressRingProps {
  className?: string
  value: number
  max?: number
  size?: number
  strokeWidth?: number
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  label?: string
  showValue?: boolean
  animated?: boolean
}

export const CyberpunkProgressRing: React.FC<CyberpunkProgressRingProps> = ({
  className,
  value,
  max = 100,
  size = 120,
  strokeWidth = 8,
  color = 'blue',
  label,
  showValue = true,
  animated = true
}) => {
  const percentage = Math.min((value / max) * 100, 100)
  const radius = (size - strokeWidth) / 2
  const circumference = radius * 2 * Math.PI
  const strokeDasharray = circumference
  const strokeDashoffset = circumference - (percentage / 100) * circumference

  const colorMap = {
    blue: 'stroke-cyber-blue-neon',
    green: 'stroke-cyber-green-neon',
    pink: 'stroke-cyber-pink-neon',
    purple: 'stroke-cyber-purple-neon',
    orange: 'stroke-cyber-orange-neon'
  }

  const glowMap = {
    blue: 'drop-shadow-[0_0_10px_#00d4ff]',
    green: 'drop-shadow-[0_0_10px_#00ff41]',
    pink: 'drop-shadow-[0_0_10px_#ff0080]',
    purple: 'drop-shadow-[0_0_10px_#8000ff]',
    orange: 'drop-shadow-[0_0_10px_#ff6600]'
  }

  return (
    <div className={cn('relative inline-flex items-center justify-center', className)}>
      <svg
        width={size}
        height={size}
        className={cn('transform -rotate-90', glowMap[color])}
      >
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="rgba(255, 255, 255, 0.1)"
          strokeWidth={strokeWidth}
          fill="transparent"
        />
        
        {/* Progress circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={strokeWidth}
          fill="transparent"
          strokeDasharray={strokeDasharray}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className={cn(
            colorMap[color],
            animated && 'transition-all duration-1000 ease-out'
          )}
        />
      </svg>
      
      {/* Center content */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        {showValue && (
          <div className={cn('text-2xl font-display font-bold', `text-cyber-${color}-neon`)}>
            {Math.round(percentage)}%
          </div>
        )}
        {label && (
          <div className="text-xs text-matrix-muted font-cyber text-center">
            {label}
          </div>
        )}
      </div>
    </div>
  )
}

// Cyberpunk Metric Card
interface CyberpunkMetricCardProps {
  className?: string
  title: string
  value: string | number
  change?: number
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  icon?: React.ReactNode
  trend?: 'up' | 'down' | 'neutral'
}

export const CyberpunkMetricCard: React.FC<CyberpunkMetricCardProps> = ({
  className,
  title,
  value,
  change,
  color = 'blue',
  icon,
  trend = 'neutral'
}) => {
  const trendColors = {
    up: 'text-cyber-green-neon',
    down: 'text-security-critical',
    neutral: 'text-matrix-muted'
  }

  const trendSymbols = {
    up: '↗',
    down: '↘',
    neutral: '→'
  }

  return (
    <HolographicDisplay color={color} intensity="medium" className={cn('p-4', className)}>
      <ParticleSystem 
        particleCount={10} 
        color={color} 
        speed="slow" 
        size="small"
        className="opacity-20"
      />
      
      <div className="relative z-10">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-cyber text-matrix-light uppercase tracking-wider">
            {title}
          </h3>
          {icon && (
            <div className={`text-cyber-${color}-neon`}>
              {icon}
            </div>
          )}
        </div>
        
        <div className="flex items-end justify-between">
          <div className={`text-2xl font-display font-bold text-cyber-${color}-neon`}>
            {value}
          </div>
          
          {change !== undefined && (
            <div className={cn('text-sm font-matrix flex items-center gap-1', trendColors[trend])}>
              <span>{trendSymbols[trend]}</span>
              <span>{Math.abs(change)}%</span>
            </div>
          )}
        </div>
      </div>
    </HolographicDisplay>
  )
}
