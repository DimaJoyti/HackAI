'use client'

import React from 'react'
import { cn } from '@/lib/utils'

interface EnhancedCardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 
    | 'default'
    | 'glass'
    | 'neon-blue'
    | 'neon-pink'
    | 'neon-green'
    | 'neon-purple'
    | 'matrix'
    | 'hologram'
    | 'security'
  size?: 'sm' | 'md' | 'lg' | 'xl'
  interactive?: boolean
  glow?: boolean
  scanLine?: boolean
  cornerAccents?: boolean
  gradient?: boolean
  floating?: boolean
}

export const EnhancedCard = React.forwardRef<HTMLDivElement, EnhancedCardProps>(
  ({ 
    className, 
    variant = 'default',
    size = 'md',
    interactive = false,
    glow = false,
    scanLine = false,
    cornerAccents = false,
    gradient = false,
    floating = false,
    children,
    ...props 
  }, ref) => {
    const baseClasses = [
      'relative rounded-xl border backdrop-blur-sm',
      'transition-all duration-300 ease-out',
      'overflow-hidden',
    ]

    const sizeClasses = {
      sm: 'p-4',
      md: 'p-6',
      lg: 'p-8',
      xl: 'p-10',
    }

    const variantClasses = {
      default: [
        'bg-matrix-surface/80 border-matrix-border',
        'text-matrix-light',
      ],
      glass: [
        'glass-cyber border-cyber-blue-neon/30',
        'text-matrix-white',
      ],
      'neon-blue': [
        'bg-matrix-surface/60 border-cyber-blue-neon/50',
        'text-cyber-blue-neon',
      ],
      'neon-pink': [
        'bg-matrix-surface/60 border-cyber-pink-neon/50',
        'text-cyber-pink-neon',
      ],
      'neon-green': [
        'bg-matrix-surface/60 border-cyber-green-neon/50',
        'text-cyber-green-neon',
      ],
      'neon-purple': [
        'bg-matrix-surface/60 border-cyber-purple-neon/50',
        'text-cyber-purple-neon',
      ],
      matrix: [
        'bg-gradient-to-br from-matrix-black via-matrix-dark to-matrix-surface',
        'border-cyber-green-neon/30 text-cyber-green-neon',
      ],
      hologram: [
        'bg-gradient-to-br from-transparent via-cyber-blue-neon/10 to-transparent',
        'border-cyber-blue-neon/40 text-cyber-blue-neon',
        'hologram',
      ],
      security: [
        'bg-gradient-to-br from-matrix-surface/80 to-matrix-elevated/80',
        'border-security-medium/50 text-matrix-white',
      ],
    }

    const interactiveClasses = interactive ? [
      'cursor-pointer',
      'hover:scale-105 hover:-translate-y-2',
      'hover:shadow-2xl',
      'active:scale-100 active:translate-y-0',
    ] : []

    const effectClasses = []
    
    if (glow) {
      effectClasses.push('hover:shadow-neon-blue-lg')
    }
    
    if (floating) {
      effectClasses.push('animate-float-gentle')
    }
    
    if (gradient) {
      effectClasses.push('bg-gradient-to-br')
    }

    return (
      <div
        className={cn(
          baseClasses,
          sizeClasses[size],
          variantClasses[variant],
          interactiveClasses,
          effectClasses,
          className
        )}
        ref={ref}
        {...props}
      >
        {/* Corner Accents */}
        {cornerAccents && (
          <>
            <div className="absolute top-0 left-0 w-4 h-4 border-t-2 border-l-2 border-current opacity-60" />
            <div className="absolute top-0 right-0 w-4 h-4 border-t-2 border-r-2 border-current opacity-60" />
            <div className="absolute bottom-0 left-0 w-4 h-4 border-b-2 border-l-2 border-current opacity-60" />
            <div className="absolute bottom-0 right-0 w-4 h-4 border-b-2 border-r-2 border-current opacity-60" />
          </>
        )}

        {/* Scan Line Effect */}
        {scanLine && (
          <div className="absolute inset-0 overflow-hidden rounded-inherit">
            <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-current to-transparent animate-scan-line opacity-40" />
          </div>
        )}

        {/* Content */}
        <div className="relative z-10">
          {children}
        </div>

        {/* Hover Glow Effect */}
        <div className="absolute inset-0 rounded-inherit bg-gradient-to-br from-current/5 via-transparent to-current/5 opacity-0 hover:opacity-100 transition-opacity duration-300" />
      </div>
    )
  }
)

EnhancedCard.displayName = 'EnhancedCard'

interface EnhancedCardHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
  accent?: boolean
}

export const EnhancedCardHeader = React.forwardRef<HTMLDivElement, EnhancedCardHeaderProps>(
  ({ className, accent = false, children, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        'flex flex-col space-y-1.5',
        accent && 'pb-4 border-b border-current/20',
        className
      )}
      {...props}
    >
      {children}
    </div>
  )
)

EnhancedCardHeader.displayName = 'EnhancedCardHeader'

interface EnhancedCardTitleProps extends React.HTMLAttributes<HTMLHeadingElement> {
  glow?: boolean
  gradient?: boolean
}

export const EnhancedCardTitle = React.forwardRef<HTMLParagraphElement, EnhancedCardTitleProps>(
  ({ className, glow = false, gradient = false, children, ...props }, ref) => (
    <h3
      ref={ref}
      className={cn(
        'font-cyber font-semibold leading-none tracking-tight',
        glow && 'text-shadow-lg',
        gradient && 'text-gradient-cyber',
        className
      )}
      {...props}
    >
      {children}
    </h3>
  )
)

EnhancedCardTitle.displayName = 'EnhancedCardTitle'

export const EnhancedCardDescription = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
  ({ className, ...props }, ref) => (
    <p
      ref={ref}
      className={cn('text-sm text-matrix-light leading-relaxed', className)}
      {...props}
    />
  )
)

EnhancedCardDescription.displayName = 'EnhancedCardDescription'

export const EnhancedCardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn('pt-0', className)} {...props} />
  )
)

EnhancedCardContent.displayName = 'EnhancedCardContent'

export const EnhancedCardFooter = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('flex items-center pt-4 border-t border-current/20', className)}
      {...props}
    />
  )
)

EnhancedCardFooter.displayName = 'EnhancedCardFooter'

export default EnhancedCard
