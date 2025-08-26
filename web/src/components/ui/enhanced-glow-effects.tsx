'use client'

import React from 'react'
import { cn } from '@/lib/utils'

interface GlowOrbProps {
  className?: string
  color?: 'blue' | 'pink' | 'green' | 'purple' | 'orange' | 'cyan'
  size?: 'sm' | 'md' | 'lg' | 'xl'
  intensity?: 'low' | 'medium' | 'high'
  animated?: boolean
  position?: { x: string; y: string }
}

export const GlowOrb: React.FC<GlowOrbProps> = ({
  className,
  color = 'blue',
  size = 'md',
  intensity = 'medium',
  animated = true,
  position = { x: '50%', y: '50%' },
}) => {
  const sizeClasses = {
    sm: 'w-32 h-32',
    md: 'w-48 h-48',
    lg: 'w-64 h-64',
    xl: 'w-96 h-96',
  }

  const colorClasses = {
    blue: 'bg-cyber-blue-neon',
    pink: 'bg-cyber-pink-neon',
    green: 'bg-cyber-green-neon',
    purple: 'bg-cyber-purple-neon',
    orange: 'bg-cyber-orange-neon',
    cyan: 'bg-cyber-cyan-neon',
  }

  const intensityClasses = {
    low: 'opacity-20',
    medium: 'opacity-40',
    high: 'opacity-60',
  }

  return (
    <div
      className={cn(
        'absolute rounded-full blur-3xl',
        sizeClasses[size],
        colorClasses[color],
        intensityClasses[intensity],
        animated && 'animate-pulse-slow',
        className
      )}
      style={{
        left: position.x,
        top: position.y,
        transform: 'translate(-50%, -50%)',
      }}
    />
  )
}

interface FloatingElementsProps {
  className?: string
  count?: number
  colors?: string[]
  sizes?: number[]
  speed?: 'slow' | 'medium' | 'fast'
}

export const FloatingElements: React.FC<FloatingElementsProps> = ({
  className,
  count = 20,
  colors = ['#00d4ff', '#ff0080', '#00ff41', '#8000ff', '#ff6600'],
  sizes = [4, 6, 8, 10, 12],
  speed = 'medium',
}) => {
  const speedClasses = {
    slow: 'animate-float-gentle',
    medium: 'animate-float',
    fast: 'animate-bounce-slow',
  }

  const elements = Array.from({ length: count }, (_, i) => {
    const color = colors[Math.floor(Math.random() * colors.length)]
    const size = sizes[Math.floor(Math.random() * sizes.length)]
    const left = Math.random() * 100
    const top = Math.random() * 100
    const delay = Math.random() * 5

    return (
      <div
        key={i}
        className={cn(
          'absolute rounded-full opacity-60',
          speedClasses[speed]
        )}
        style={{
          left: `${left}%`,
          top: `${top}%`,
          width: `${size}px`,
          height: `${size}px`,
          backgroundColor: color,
          boxShadow: `0 0 ${size * 2}px ${color}`,
          animationDelay: `${delay}s`,
        }}
      />
    )
  })

  return (
    <div className={cn('absolute inset-0 overflow-hidden pointer-events-none', className)}>
      {elements}
    </div>
  )
}

interface ScanLineProps {
  className?: string
  color?: string
  direction?: 'horizontal' | 'vertical'
  speed?: number
  opacity?: number
}

export const ScanLine: React.FC<ScanLineProps> = ({
  className,
  color = '#00d4ff',
  direction = 'horizontal',
  speed = 2,
  opacity = 0.6,
}) => {
  return (
    <div
      className={cn(
        'absolute pointer-events-none',
        direction === 'horizontal' ? 'w-full h-px left-0' : 'h-full w-px top-0',
        className
      )}
      style={{
        background: `linear-gradient(${direction === 'horizontal' ? '90deg' : '0deg'}, transparent, ${color}, transparent)`,
        opacity,
        animation: `scan-line ${speed}s linear infinite`,
      }}
    />
  )
}

interface HologramGridProps {
  className?: string
  color?: string
  spacing?: number
  opacity?: number
  animated?: boolean
}

export const HologramGrid: React.FC<HologramGridProps> = ({
  className,
  color = '#00d4ff',
  spacing = 50,
  opacity = 0.1,
  animated = true,
}) => {
  return (
    <div
      className={cn(
        'absolute inset-0 pointer-events-none',
        animated && 'animate-pulse-slow',
        className
      )}
      style={{
        backgroundImage: `
          linear-gradient(${color} 1px, transparent 1px),
          linear-gradient(90deg, ${color} 1px, transparent 1px)
        `,
        backgroundSize: `${spacing}px ${spacing}px`,
        opacity,
      }}
    />
  )
}

interface DataStreamProps {
  className?: string
  color?: string
  count?: number
  speed?: number
  direction?: 'left' | 'right' | 'up' | 'down'
}

export const DataStream: React.FC<DataStreamProps> = ({
  className,
  color = '#00ff41',
  count = 5,
  speed = 15,
  direction = 'right',
}) => {
  const streams = Array.from({ length: count }, (_, i) => {
    const delay = i * (speed / count)
    const position = (100 / count) * i

    const directionStyles = {
      left: { top: `${position}%`, left: '100%', width: '100px', height: '2px' },
      right: { top: `${position}%`, left: '-100px', width: '100px', height: '2px' },
      up: { left: `${position}%`, top: '100%', width: '2px', height: '100px' },
      down: { left: `${position}%`, top: '-100px', width: '2px', height: '100px' },
    }

    return (
      <div
        key={i}
        className="absolute opacity-60"
        style={{
          ...directionStyles[direction],
          background: `linear-gradient(${direction === 'left' || direction === 'right' ? '90deg' : '0deg'}, transparent, ${color}, transparent)`,
          animation: `data-stream ${speed}s linear infinite`,
          animationDelay: `${delay}s`,
        }}
      />
    )
  })

  return (
    <div className={cn('absolute inset-0 overflow-hidden pointer-events-none', className)}>
      {streams}
    </div>
  )
}

interface EnhancedGlowEffectsProps {
  className?: string
  variant?: 'orbs' | 'floating' | 'scanlines' | 'grid' | 'streams' | 'all'
  intensity?: 'low' | 'medium' | 'high'
  color?: 'blue' | 'pink' | 'green' | 'purple' | 'orange' | 'cyan' | 'multi'
}

export const EnhancedGlowEffects: React.FC<EnhancedGlowEffectsProps> = ({
  className,
  variant = 'all',
  intensity = 'medium',
  color = 'multi',
}) => {
  const colors = color === 'multi' 
    ? ['#00d4ff', '#ff0080', '#00ff41', '#8000ff', '#ff6600', '#00ffff']
    : [`var(--cyber-${color})`]

  return (
    <div className={cn('absolute inset-0 overflow-hidden pointer-events-none', className)}>
      {(variant === 'orbs' || variant === 'all') && (
        <>
          <GlowOrb color="blue" size="lg" position={{ x: '20%', y: '30%' }} intensity={intensity} />
          <GlowOrb color="pink" size="md" position={{ x: '80%', y: '70%' }} intensity={intensity} />
          <GlowOrb color="green" size="xl" position={{ x: '60%', y: '20%' }} intensity={intensity} />
        </>
      )}
      
      {(variant === 'floating' || variant === 'all') && (
        <FloatingElements colors={colors} count={15} />
      )}
      
      {(variant === 'scanlines' || variant === 'all') && (
        <>
          <ScanLine direction="horizontal" color={colors[0]} speed={3} />
          <ScanLine direction="vertical" color={colors[1]} speed={4} />
        </>
      )}
      
      {(variant === 'grid' || variant === 'all') && (
        <HologramGrid color={colors[0]} spacing={60} opacity={0.08} />
      )}
      
      {(variant === 'streams' || variant === 'all') && (
        <DataStream color={colors[2]} direction="right" count={3} speed={12} />
      )}
    </div>
  )
}

export default EnhancedGlowEffects
