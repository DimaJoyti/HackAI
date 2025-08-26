'use client'

import React, { useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/utils'

// Particle System Component
interface ParticleSystemProps {
  className?: string
  particleCount?: number
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  speed?: 'slow' | 'medium' | 'fast'
  size?: 'small' | 'medium' | 'large'
  direction?: 'up' | 'down' | 'left' | 'right' | 'random'
}

export const ParticleSystem: React.FC<ParticleSystemProps> = ({
  className,
  particleCount = 50,
  color = 'blue',
  speed = 'medium',
  size = 'medium',
  direction = 'random'
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const resizeCanvas = () => {
      canvas.width = canvas.offsetWidth
      canvas.height = canvas.offsetHeight
    }

    resizeCanvas()
    window.addEventListener('resize', resizeCanvas)

    const colorMap = {
      blue: '#00d4ff',
      green: '#00ff41',
      pink: '#ff0080',
      purple: '#8000ff',
      orange: '#ff6600'
    }

    const speedMap = {
      slow: 0.5,
      medium: 1,
      fast: 2
    }

    const sizeMap = {
      small: 1,
      medium: 2,
      large: 3
    }

    const particles: Array<{
      x: number
      y: number
      vx: number
      vy: number
      size: number
      opacity: number
      life: number
    }> = []

    // Initialize particles
    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * speedMap[speed],
        vy: (Math.random() - 0.5) * speedMap[speed],
        size: Math.random() * sizeMap[size] + 1,
        opacity: Math.random() * 0.8 + 0.2,
        life: Math.random() * 100 + 50
      })
    }

    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height)

      particles.forEach((particle, index) => {
        // Update position
        particle.x += particle.vx
        particle.y += particle.vy
        particle.life--

        // Boundary checks
        if (particle.x < 0 || particle.x > canvas.width) particle.vx *= -1
        if (particle.y < 0 || particle.y > canvas.height) particle.vy *= -1

        // Reset particle if life is over
        if (particle.life <= 0) {
          particle.x = Math.random() * canvas.width
          particle.y = Math.random() * canvas.height
          particle.life = Math.random() * 100 + 50
          particle.opacity = Math.random() * 0.8 + 0.2
        }

        // Draw particle
        ctx.save()
        ctx.globalAlpha = particle.opacity
        ctx.fillStyle = colorMap[color]
        ctx.shadowBlur = 10
        ctx.shadowColor = colorMap[color]
        ctx.beginPath()
        ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2)
        ctx.fill()
        ctx.restore()
      })

      requestAnimationFrame(animate)
    }

    animate()

    return () => {
      window.removeEventListener('resize', resizeCanvas)
    }
  }, [particleCount, color, speed, size, direction])

  return (
    <canvas
      ref={canvasRef}
      className={cn('absolute inset-0 pointer-events-none', className)}
    />
  )
}

// Neural Network Visualization
interface NeuralNetworkProps {
  className?: string
  nodeCount?: number
  connectionDensity?: number
  animationSpeed?: 'slow' | 'medium' | 'fast'
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
}

export const NeuralNetwork: React.FC<NeuralNetworkProps> = ({
  className,
  nodeCount = 20,
  connectionDensity = 0.3,
  animationSpeed = 'medium',
  color = 'blue'
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const resizeCanvas = () => {
      canvas.width = canvas.offsetWidth
      canvas.height = canvas.offsetHeight
    }

    resizeCanvas()
    window.addEventListener('resize', resizeCanvas)

    const colorMap = {
      blue: '#00d4ff',
      green: '#00ff41',
      pink: '#ff0080',
      purple: '#8000ff',
      orange: '#ff6600'
    }

    const speedMap = {
      slow: 0.01,
      medium: 0.02,
      fast: 0.04
    }

    const nodes: Array<{
      x: number
      y: number
      vx: number
      vy: number
      connections: number[]
      pulse: number
    }> = []

    // Initialize nodes
    for (let i = 0; i < nodeCount; i++) {
      const node = {
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.5,
        vy: (Math.random() - 0.5) * 0.5,
        connections: [] as number[],
        pulse: Math.random() * Math.PI * 2
      }

      // Create connections
      for (let j = 0; j < i; j++) {
        if (Math.random() < connectionDensity) {
          node.connections.push(j)
        }
      }

      nodes.push(node)
    }

    let time = 0

    const animate = () => {
      time += speedMap[animationSpeed]
      ctx.clearRect(0, 0, canvas.width, canvas.height)

      // Draw connections
      nodes.forEach((node, i) => {
        node.connections.forEach(connectionIndex => {
          const connectedNode = nodes[connectionIndex]
          if (connectedNode) {
            const distance = Math.sqrt(
              Math.pow(node.x - connectedNode.x, 2) + 
              Math.pow(node.y - connectedNode.y, 2)
            )

            if (distance < 150) {
              ctx.save()
              ctx.strokeStyle = colorMap[color]
              ctx.globalAlpha = 0.3 * (1 - distance / 150)
              ctx.lineWidth = 1
              ctx.beginPath()
              ctx.moveTo(node.x, node.y)
              ctx.lineTo(connectedNode.x, connectedNode.y)
              ctx.stroke()
              ctx.restore()
            }
          }
        })
      })

      // Update and draw nodes
      nodes.forEach(node => {
        // Update position
        node.x += node.vx
        node.y += node.vy
        node.pulse += 0.1

        // Boundary checks
        if (node.x < 0 || node.x > canvas.width) node.vx *= -1
        if (node.y < 0 || node.y > canvas.height) node.vy *= -1

        // Draw node
        const pulseIntensity = Math.sin(node.pulse) * 0.5 + 0.5
        ctx.save()
        ctx.fillStyle = colorMap[color]
        ctx.globalAlpha = 0.8
        ctx.shadowBlur = 15 * pulseIntensity
        ctx.shadowColor = colorMap[color]
        ctx.beginPath()
        ctx.arc(node.x, node.y, 3 + pulseIntensity * 2, 0, Math.PI * 2)
        ctx.fill()
        ctx.restore()
      })

      requestAnimationFrame(animate)
    }

    animate()

    return () => {
      window.removeEventListener('resize', resizeCanvas)
    }
  }, [nodeCount, connectionDensity, animationSpeed, color])

  return (
    <canvas
      ref={canvasRef}
      className={cn('absolute inset-0 pointer-events-none', className)}
    />
  )
}

// Data Stream Component
interface DataStreamProps {
  className?: string
  streamCount?: number
  direction?: 'horizontal' | 'vertical' | 'diagonal'
  speed?: 'slow' | 'medium' | 'fast'
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
}

export const DataStream: React.FC<DataStreamProps> = ({
  className,
  streamCount = 5,
  direction = 'horizontal',
  speed = 'medium',
  color = 'green'
}) => {
  const containerRef = useRef<HTMLDivElement>(null)

  const colorMap = {
    blue: 'text-cyber-blue-neon',
    green: 'text-cyber-green-neon',
    pink: 'text-cyber-pink-neon',
    purple: 'text-cyber-purple-neon',
    orange: 'text-cyber-orange-neon'
  }

  const speedMap = {
    slow: 'animate-[dataStream_20s_linear_infinite]',
    medium: 'animate-[dataStream_15s_linear_infinite]',
    fast: 'animate-[dataStream_10s_linear_infinite]'
  }

  const directionMap = {
    horizontal: 'left-0 top-0 w-full',
    vertical: 'top-0 left-0 h-full writing-mode-vertical',
    diagonal: 'top-0 left-0 transform rotate-45'
  }

  const generateDataString = () => {
    const chars = '01'
    const length = direction === 'horizontal' ? 100 : 50
    return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('')
  }

  return (
    <div ref={containerRef} className={cn('absolute inset-0 overflow-hidden pointer-events-none', className)}>
      {Array.from({ length: streamCount }).map((_, i) => (
        <div
          key={i}
          className={cn(
            'absolute font-matrix text-xs opacity-60',
            colorMap[color],
            speedMap[speed],
            directionMap[direction]
          )}
          style={{
            [direction === 'horizontal' ? 'top' : 'left']: `${(i + 1) * (100 / (streamCount + 1))}%`,
            animationDelay: `${i * 0.5}s`
          }}
        >
          {generateDataString()}
        </div>
      ))}
    </div>
  )
}

// Holographic Display Component
interface HolographicDisplayProps {
  children: React.ReactNode
  className?: string
  intensity?: 'low' | 'medium' | 'high'
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  scanLines?: boolean
  flicker?: boolean
}

export const HolographicDisplay: React.FC<HolographicDisplayProps> = ({
  children,
  className,
  intensity = 'medium',
  color = 'blue',
  scanLines = true,
  flicker = false
}) => {
  const intensityMap = {
    low: 'opacity-80',
    medium: 'opacity-90',
    high: 'opacity-95'
  }

  const colorMap = {
    blue: 'shadow-neon-blue border-cyber-blue-neon/30',
    green: 'shadow-neon-green border-cyber-green-neon/30',
    pink: 'shadow-neon-pink border-cyber-pink-neon/30',
    purple: 'shadow-neon-purple border-cyber-purple-neon/30',
    orange: 'shadow-neon-orange border-cyber-orange-neon/30'
  }

  return (
    <div className={cn(
      'relative backdrop-blur-sm border rounded-lg overflow-hidden',
      intensityMap[intensity],
      colorMap[color],
      flicker && 'animate-neon-flicker',
      className
    )}>
      {/* Holographic background */}
      <div className="absolute inset-0 holographic opacity-20" />
      
      {/* Scan lines */}
      {scanLines && (
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute inset-0 bg-gradient-to-b from-transparent via-current to-transparent opacity-10 animate-scan-line" />
        </div>
      )}
      
      {/* Content */}
      <div className="relative z-10">
        {children}
      </div>
    </div>
  )
}
