'use client'

import React, { useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'

interface CyberpunkBackgroundProps {
  variant?: 'matrix' | 'circuit' | 'grid' | 'particles' | 'hologram'
  intensity?: 'low' | 'medium' | 'high'
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  className?: string
  children?: React.ReactNode
}

export const CyberpunkBackground: React.FC<CyberpunkBackgroundProps> = ({
  variant = 'matrix',
  intensity = 'medium',
  color = 'blue',
  className,
  children,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    if (variant === 'particles' && canvasRef.current) {
      const canvas = canvasRef.current
      const ctx = canvas.getContext('2d')
      if (!ctx) return

      const resizeCanvas = () => {
        canvas.width = window.innerWidth
        canvas.height = window.innerHeight
      }

      resizeCanvas()
      window.addEventListener('resize', resizeCanvas)

      // Particle system
      const particles: Array<{
        x: number
        y: number
        vx: number
        vy: number
        size: number
        opacity: number
        color: string
      }> = []

      const colors = {
        blue: ['#00d4ff', '#0080ff', '#004080'],
        green: ['#00ff41', '#00cc33', '#008000'],
        pink: ['#ff0080', '#cc0066', '#800040'],
        purple: ['#8000ff', '#6600cc', '#400080'],
        orange: ['#ff6600', '#cc5200', '#803300'],
      }

      const particleColors = colors[color]

      // Create particles
      for (let i = 0; i < (intensity === 'low' ? 50 : intensity === 'medium' ? 100 : 150); i++) {
        particles.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          vx: (Math.random() - 0.5) * 0.5,
          vy: (Math.random() - 0.5) * 0.5,
          size: Math.random() * 2 + 1,
          opacity: Math.random() * 0.5 + 0.2,
          color: particleColors[Math.floor(Math.random() * particleColors.length)],
        })
      }

      const animate = () => {
        ctx.clearRect(0, 0, canvas.width, canvas.height)

        particles.forEach((particle, index) => {
          // Update position
          particle.x += particle.vx
          particle.y += particle.vy

          // Wrap around edges
          if (particle.x < 0) particle.x = canvas.width
          if (particle.x > canvas.width) particle.x = 0
          if (particle.y < 0) particle.y = canvas.height
          if (particle.y > canvas.height) particle.y = 0

          // Draw particle
          ctx.save()
          ctx.globalAlpha = particle.opacity
          ctx.fillStyle = particle.color
          ctx.shadowBlur = 10
          ctx.shadowColor = particle.color
          ctx.beginPath()
          ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2)
          ctx.fill()
          ctx.restore()

          // Draw connections
          particles.slice(index + 1).forEach((otherParticle) => {
            const dx = particle.x - otherParticle.x
            const dy = particle.y - otherParticle.y
            const distance = Math.sqrt(dx * dx + dy * dy)

            if (distance < 100) {
              ctx.save()
              ctx.globalAlpha = (1 - distance / 100) * 0.2
              ctx.strokeStyle = particle.color
              ctx.lineWidth = 0.5
              ctx.beginPath()
              ctx.moveTo(particle.x, particle.y)
              ctx.lineTo(otherParticle.x, otherParticle.y)
              ctx.stroke()
              ctx.restore()
            }
          })
        })

        requestAnimationFrame(animate)
      }

      animate()

      return () => {
        window.removeEventListener('resize', resizeCanvas)
      }
    }
  }, [variant, intensity, color])

  const getBackgroundClass = () => {
    const baseClasses = 'absolute inset-0 overflow-hidden'
    
    switch (variant) {
      case 'matrix':
        return cn(baseClasses, 'bg-matrix')
      case 'circuit':
        return cn(baseClasses, 'bg-circuit')
      case 'grid':
        return cn(baseClasses, 'bg-cyber-grid')
      case 'hologram':
        return cn(baseClasses, 'hologram')
      case 'particles':
        return cn(baseClasses, 'bg-matrix-black')
      default:
        return cn(baseClasses, 'bg-matrix')
    }
  }

  const getOverlayClass = () => {
    const intensityClasses = {
      low: 'opacity-20',
      medium: 'opacity-40',
      high: 'opacity-60',
    }

    return cn(
      'absolute inset-0 pointer-events-none',
      intensityClasses[intensity]
    )
  }

  return (
    <div className={cn('relative', className)}>
      <div className={getBackgroundClass()}>
        {variant === 'particles' && (
          <canvas
            ref={canvasRef}
            className="absolute inset-0 w-full h-full"
            style={{ background: 'transparent' }}
          />
        )}
        <div className={getOverlayClass()} />
      </div>
      {children && (
        <div className="relative z-10">
          {children}
        </div>
      )}
    </div>
  )
}

// Matrix Rain Component
export const MatrixRain: React.FC<{
  className?: string
  intensity?: 'low' | 'medium' | 'high'
  color?: string
}> = ({ className, intensity = 'medium', color = '#00ff41' }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const resizeCanvas = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }

    resizeCanvas()
    window.addEventListener('resize', resizeCanvas)

    const chars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    const charArray = chars.split('')

    const fontSize = 14
    const columns = canvas.width / fontSize

    const drops: number[] = []
    for (let i = 0; i < columns; i++) {
      drops[i] = 1
    }

    const draw = () => {
      ctx.fillStyle = 'rgba(0, 0, 0, 0.05)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)

      ctx.fillStyle = color
      ctx.font = `${fontSize}px monospace`

      for (let i = 0; i < drops.length; i++) {
        const text = charArray[Math.floor(Math.random() * charArray.length)]
        ctx.fillText(text, i * fontSize, drops[i] * fontSize)

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0
        }
        drops[i]++
      }
    }

    const intervalTime = intensity === 'low' ? 100 : intensity === 'medium' ? 50 : 25
    const interval = setInterval(draw, intervalTime)

    return () => {
      clearInterval(interval)
      window.removeEventListener('resize', resizeCanvas)
    }
  }, [intensity, color])

  return (
    <canvas
      ref={canvasRef}
      className={cn('absolute inset-0 w-full h-full pointer-events-none', className)}
    />
  )
}

// Glitch Effect Component
export const GlitchText: React.FC<{
  children: React.ReactNode
  className?: string
  intensity?: 'low' | 'medium' | 'high'
}> = ({ children, className, intensity = 'medium' }) => {
  const animationClass = intensity === 'low' 
    ? 'animate-neon-flicker' 
    : intensity === 'medium' 
    ? 'animate-glitch-text' 
    : 'animate-glitch'

  return (
    <span 
      className={cn('relative inline-block', animationClass, className)}
      data-text={typeof children === 'string' ? children : ''}
    >
      {children}
    </span>
  )
}

// Neon Border Component
export const NeonBorder: React.FC<{
  children: React.ReactNode
  className?: string
  color?: 'blue' | 'pink' | 'green' | 'purple' | 'orange'
  intensity?: 'low' | 'medium' | 'high'
}> = ({ children, className, color = 'blue', intensity = 'medium' }) => {
  const colorClasses = {
    blue: 'border-cyber-blue-neon shadow-neon-blue',
    pink: 'border-cyber-pink-neon shadow-neon-pink',
    green: 'border-cyber-green-neon shadow-neon-green',
    purple: 'border-cyber-purple-neon shadow-neon-purple',
    orange: 'border-cyber-orange-neon shadow-neon-orange',
  }

  const intensityClasses = {
    low: '',
    medium: '-lg',
    high: '-lg animate-neon-pulse',
  }

  const shadowClass = colorClasses[color].replace('shadow-neon-', 'shadow-neon-') + intensityClasses[intensity]

  return (
    <div className={cn('border-2 rounded-lg', colorClasses[color], shadowClass, className)}>
      {children}
    </div>
  )
}
