'use client'

import React, { useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/utils'

interface Particle {
  x: number
  y: number
  vx: number
  vy: number
  size: number
  opacity: number
  color: string
  life: number
  maxLife: number
}

interface EnhancedParticleSystemProps {
  className?: string
  particleCount?: number
  colors?: string[]
  speed?: number
  size?: { min: number; max: number }
  opacity?: { min: number; max: number }
  direction?: 'up' | 'down' | 'left' | 'right' | 'random'
  interactive?: boolean
  glow?: boolean
  trail?: boolean
}

export const EnhancedParticleSystem: React.FC<EnhancedParticleSystemProps> = ({
  className,
  particleCount = 50,
  colors = ['#00d4ff', '#ff0080', '#00ff41', '#8000ff', '#ff6600'],
  speed = 1,
  size = { min: 1, max: 3 },
  opacity = { min: 0.3, max: 0.8 },
  direction = 'random',
  interactive = false,
  glow = true,
  trail = false,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const animationRef = useRef<number>()
  const particlesRef = useRef<Particle[]>([])
  const mouseRef = useRef({ x: 0, y: 0 })
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 })

  // Initialize particles
  const initParticles = () => {
    const particles: Particle[] = []
    for (let i = 0; i < particleCount; i++) {
      particles.push(createParticle())
    }
    particlesRef.current = particles
  }

  // Create a single particle
  const createParticle = (): Particle => {
    const canvas = canvasRef.current
    if (!canvas) return {} as Particle

    const particleSize = Math.random() * (size.max - size.min) + size.min
    const particleOpacity = Math.random() * (opacity.max - opacity.min) + opacity.min
    const color = colors[Math.floor(Math.random() * colors.length)]
    const life = Math.random() * 300 + 100
    
    let vx = 0, vy = 0
    switch (direction) {
      case 'up':
        vx = (Math.random() - 0.5) * speed * 0.5
        vy = -Math.random() * speed
        break
      case 'down':
        vx = (Math.random() - 0.5) * speed * 0.5
        vy = Math.random() * speed
        break
      case 'left':
        vx = -Math.random() * speed
        vy = (Math.random() - 0.5) * speed * 0.5
        break
      case 'right':
        vx = Math.random() * speed
        vy = (Math.random() - 0.5) * speed * 0.5
        break
      default:
        vx = (Math.random() - 0.5) * speed
        vy = (Math.random() - 0.5) * speed
    }

    return {
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx,
      vy,
      size: particleSize,
      opacity: particleOpacity,
      color,
      life,
      maxLife: life,
    }
  }

  // Update particle positions and properties
  const updateParticles = () => {
    const canvas = canvasRef.current
    if (!canvas) return

    particlesRef.current.forEach((particle, index) => {
      // Update position
      particle.x += particle.vx
      particle.y += particle.vy

      // Update life
      particle.life -= 1
      particle.opacity = (particle.life / particle.maxLife) * (opacity.max - opacity.min) + opacity.min

      // Interactive mouse effect
      if (interactive) {
        const dx = mouseRef.current.x - particle.x
        const dy = mouseRef.current.y - particle.y
        const distance = Math.sqrt(dx * dx + dy * dy)
        
        if (distance < 100) {
          const force = (100 - distance) / 100
          particle.vx += (dx / distance) * force * 0.1
          particle.vy += (dy / distance) * force * 0.1
        }
      }

      // Wrap around edges or respawn
      if (particle.x < 0 || particle.x > canvas.width || 
          particle.y < 0 || particle.y > canvas.height || 
          particle.life <= 0) {
        particlesRef.current[index] = createParticle()
      }
    })
  }

  // Render particles
  const renderParticles = () => {
    const canvas = canvasRef.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return

    // Clear canvas with trail effect
    if (trail) {
      ctx.fillStyle = 'rgba(0, 0, 0, 0.05)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
    } else {
      ctx.clearRect(0, 0, canvas.width, canvas.height)
    }

    // Render particles
    particlesRef.current.forEach(particle => {
      ctx.save()
      
      // Set particle properties
      ctx.globalAlpha = particle.opacity
      ctx.fillStyle = particle.color
      
      // Add glow effect
      if (glow) {
        ctx.shadowColor = particle.color
        ctx.shadowBlur = particle.size * 3
      }
      
      // Draw particle
      ctx.beginPath()
      ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2)
      ctx.fill()
      
      ctx.restore()
    })
  }

  // Animation loop
  const animate = () => {
    updateParticles()
    renderParticles()
    animationRef.current = requestAnimationFrame(animate)
  }

  // Handle mouse movement
  const handleMouseMove = (event: MouseEvent) => {
    const canvas = canvasRef.current
    if (!canvas) return

    const rect = canvas.getBoundingClientRect()
    mouseRef.current = {
      x: event.clientX - rect.left,
      y: event.clientY - rect.top,
    }
  }

  // Handle resize
  const handleResize = () => {
    const canvas = canvasRef.current
    if (!canvas) return

    const rect = canvas.getBoundingClientRect()
    canvas.width = rect.width
    canvas.height = rect.height
    setDimensions({ width: rect.width, height: rect.height })
  }

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    // Check for reduced motion preference
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (prefersReducedMotion) return

    // Set up canvas
    handleResize()
    initParticles()

    // Start animation with performance optimization
    let lastTime = 0
    const targetFPS = 60
    const frameInterval = 1000 / targetFPS

    const optimizedAnimate = (currentTime: number) => {
      if (currentTime - lastTime >= frameInterval) {
        updateParticles()
        renderParticles()
        lastTime = currentTime
      }
      animationRef.current = requestAnimationFrame(optimizedAnimate)
    }

    animationRef.current = requestAnimationFrame(optimizedAnimate)

    // Event listeners with throttling
    let throttleTimeout: NodeJS.Timeout
    const throttledMouseMove = (event: MouseEvent) => {
      if (throttleTimeout) return
      throttleTimeout = setTimeout(() => {
        handleMouseMove(event)
        throttleTimeout = null as any
      }, 16) // ~60fps
    }

    if (interactive) {
      canvas.addEventListener('mousemove', throttledMouseMove, { passive: true })
    }
    window.addEventListener('resize', handleResize, { passive: true })

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current)
      }
      if (interactive) {
        canvas.removeEventListener('mousemove', throttledMouseMove)
      }
      window.removeEventListener('resize', handleResize)
      if (throttleTimeout) {
        clearTimeout(throttleTimeout)
      }
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className={cn(
        'absolute inset-0 pointer-events-none',
        interactive && 'pointer-events-auto',
        className
      )}
      style={{ width: '100%', height: '100%' }}
    />
  )
}

export default EnhancedParticleSystem
