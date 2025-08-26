'use client'

import React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const cyberpunkCardVariants = cva(
  'rounded-lg border backdrop-blur-sm transition-all duration-300 relative overflow-hidden group',
  {
    variants: {
      variant: {
        // Neon variants
        'neon-blue': 'bg-matrix-dark/80 border-cyber-blue-neon/30 shadow-neon-blue/20 hover:border-cyber-blue-neon hover:shadow-neon-blue',
        'neon-pink': 'bg-matrix-dark/80 border-cyber-pink-neon/30 shadow-neon-pink/20 hover:border-cyber-pink-neon hover:shadow-neon-pink',
        'neon-green': 'bg-matrix-dark/80 border-cyber-green-neon/30 shadow-neon-green/20 hover:border-cyber-green-neon hover:shadow-neon-green',
        'neon-purple': 'bg-matrix-dark/80 border-cyber-purple-neon/30 shadow-neon-purple/20 hover:border-cyber-purple-neon hover:shadow-neon-purple',
        'neon-orange': 'bg-matrix-dark/80 border-cyber-orange-neon/30 shadow-neon-orange/20 hover:border-cyber-orange-neon hover:shadow-neon-orange',
        
        // Hologram variants
        'hologram': 'bg-gradient-to-br from-cyber-blue-neon/5 via-transparent to-cyber-pink-neon/5 border-cyber-blue-neon/20 backdrop-blur-md hover:from-cyber-blue-neon/10 hover:to-cyber-pink-neon/10',
        'hologram-green': 'bg-gradient-to-br from-cyber-green-neon/5 via-transparent to-cyber-blue-neon/5 border-cyber-green-neon/20 backdrop-blur-md hover:from-cyber-green-neon/10 hover:to-cyber-blue-neon/10',
        
        // Matrix variants
        'matrix': 'bg-matrix-surface/80 border-cyber-green-neon/20 shadow-terminal hover:border-cyber-green-neon/50 hover:shadow-neon-green/30',
        'terminal': 'bg-matrix-black/90 border-cyber-green-neon/30 shadow-inner-neon-green hover:border-cyber-green-neon hover:bg-matrix-dark/90',
        
        // Security status variants
        'security-critical': 'bg-matrix-dark/80 border-security-critical/30 shadow-security-critical/20 hover:border-security-critical hover:shadow-security-critical',
        'security-high': 'bg-matrix-dark/80 border-security-high/30 shadow-security-high/20 hover:border-security-high hover:shadow-security-high',
        'security-medium': 'bg-matrix-dark/80 border-security-medium/30 shadow-security-medium/20 hover:border-security-medium hover:shadow-security-medium',
        'security-low': 'bg-matrix-dark/80 border-security-low/30 shadow-security-low/20 hover:border-security-low hover:shadow-security-low',
        'security-safe': 'bg-matrix-dark/80 border-security-safe/30 shadow-security-safe/20 hover:border-security-safe hover:shadow-security-safe',
        
        // Glass variants
        'glass-blue': 'bg-cyber-blue-neon/5 border-cyber-blue-neon/20 backdrop-blur-xl hover:bg-cyber-blue-neon/10 hover:border-cyber-blue-neon/40',
        'glass-dark': 'bg-matrix-black/40 border-matrix-border backdrop-blur-xl hover:bg-matrix-dark/60 hover:border-matrix-muted',
        
        // Solid variants
        'solid-dark': 'bg-matrix-surface border-matrix-border hover:bg-matrix-muted hover:border-matrix-text',
        'solid-darker': 'bg-matrix-dark border-matrix-surface hover:bg-matrix-surface hover:border-matrix-border',
      },
      size: {
        sm: 'p-4',
        default: 'p-6',
        lg: 'p-8',
        xl: 'p-10',
      },
      animation: {
        none: '',
        pulse: 'animate-neon-pulse',
        glow: 'animate-cyber-glow',
        float: 'animate-float',
        hologram: 'animate-hologram',
      },
      interactive: {
        true: 'cursor-pointer hover:scale-[1.02] active:scale-[0.98]',
        false: '',
      },
    },
    defaultVariants: {
      variant: 'neon-blue',
      size: 'default',
      animation: 'none',
      interactive: false,
    },
  }
)

export interface CyberpunkCardProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof cyberpunkCardVariants> {
  scanLine?: boolean
  glitchEffect?: boolean
  cornerAccents?: boolean
}

const CyberpunkCard = React.forwardRef<HTMLDivElement, CyberpunkCardProps>(
  ({ 
    className, 
    variant, 
    size, 
    animation, 
    interactive, 
    scanLine = false, 
    glitchEffect = false, 
    cornerAccents = false,
    children, 
    ...props 
  }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(cyberpunkCardVariants({ variant, size, animation, interactive, className }))}
        {...props}
      >
        {/* Corner accents */}
        {cornerAccents && (
          <>
            <div className="absolute top-0 left-0 w-4 h-4 border-t-2 border-l-2 border-current opacity-60" />
            <div className="absolute top-0 right-0 w-4 h-4 border-t-2 border-r-2 border-current opacity-60" />
            <div className="absolute bottom-0 left-0 w-4 h-4 border-b-2 border-l-2 border-current opacity-60" />
            <div className="absolute bottom-0 right-0 w-4 h-4 border-b-2 border-r-2 border-current opacity-60" />
          </>
        )}
        
        {/* Scan line effect */}
        {scanLine && (
          <div className="absolute inset-0 overflow-hidden rounded-lg">
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent -skew-x-12 -translate-x-full group-hover:translate-x-full transition-transform duration-2000 ease-out" />
          </div>
        )}
        
        {/* Glitch effect overlay */}
        {glitchEffect && (
          <div className="absolute inset-0 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300">
            <div className="absolute inset-0 bg-cyber-blue-neon/5 animate-glitch" />
            <div className="absolute inset-0 bg-cyber-pink-neon/5 animate-glitch" style={{ animationDelay: '0.1s' }} />
          </div>
        )}
        
        {/* Content */}
        <div className="relative z-10">
          {children}
        </div>
        
        {/* Hover glow effect */}
        <div className="absolute inset-0 rounded-lg bg-gradient-to-br from-current/5 via-transparent to-current/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      </div>
    )
  }
)
CyberpunkCard.displayName = 'CyberpunkCard'

// Card Header Component
const CyberpunkCardHeader = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & {
    accent?: boolean
    glowText?: boolean
  }
>(({ className, accent = false, glowText = false, children, ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      'flex flex-col space-y-1.5 pb-4',
      accent && 'border-b border-current/20',
      className
    )}
    {...props}
  >
    <div className={cn(glowText && 'text-neon-blue')}>
      {children}
    </div>
  </div>
))
CyberpunkCardHeader.displayName = 'CyberpunkCardHeader'

// Card Title Component
const CyberpunkCardTitle = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLHeadingElement> & {
    glow?: boolean
    font?: 'default' | 'cyber' | 'matrix' | 'display'
  }
>(({ className, glow = false, font = 'default', children, ...props }, ref) => {
  const fontClasses = {
    default: 'font-semibold',
    cyber: 'font-cyber font-bold',
    matrix: 'font-matrix font-bold',
    display: 'font-display font-bold',
  }

  return (
    <h3
      ref={ref}
      className={cn(
        'text-2xl leading-none tracking-tight',
        fontClasses[font],
        glow && 'text-neon-blue',
        className
      )}
      {...props}
    >
      {children}
    </h3>
  )
})
CyberpunkCardTitle.displayName = 'CyberpunkCardTitle'

// Card Description Component
const CyberpunkCardDescription = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLParagraphElement> & {
    muted?: boolean
  }
>(({ className, muted = true, ...props }, ref) => (
  <p
    ref={ref}
    className={cn(
      'text-sm leading-relaxed',
      muted ? 'text-matrix-text' : 'text-matrix-light',
      className
    )}
    {...props}
  />
))
CyberpunkCardDescription.displayName = 'CyberpunkCardDescription'

// Card Content Component
const CyberpunkCardContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div ref={ref} className={cn('pt-0', className)} {...props} />
))
CyberpunkCardContent.displayName = 'CyberpunkCardContent'

// Card Footer Component
const CyberpunkCardFooter = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & {
    accent?: boolean
  }
>(({ className, accent = false, ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      'flex items-center pt-4',
      accent && 'border-t border-current/20',
      className
    )}
    {...props}
  />
))
CyberpunkCardFooter.displayName = 'CyberpunkCardFooter'

export {
  CyberpunkCard,
  CyberpunkCardHeader,
  CyberpunkCardTitle,
  CyberpunkCardDescription,
  CyberpunkCardContent,
  CyberpunkCardFooter,
  cyberpunkCardVariants,
}

// Preset card components
export const SecurityCard = React.forwardRef<HTMLDivElement, 
  Omit<CyberpunkCardProps, 'variant'> & { 
    level: 'critical' | 'high' | 'medium' | 'low' | 'safe' 
  }
>(({ level, ...props }, ref) => (
  <CyberpunkCard 
    variant={`security-${level}` as any} 
    cornerAccents 
    {...props} 
    ref={ref} 
  />
))
SecurityCard.displayName = 'SecurityCard'

export const MatrixCard = React.forwardRef<HTMLDivElement, Omit<CyberpunkCardProps, 'variant'>>(
  (props, ref) => <CyberpunkCard variant="matrix" scanLine {...props} ref={ref} />
)
MatrixCard.displayName = 'MatrixCard'

export const HologramCard = React.forwardRef<HTMLDivElement, Omit<CyberpunkCardProps, 'variant' | 'animation'>>(
  (props, ref) => <CyberpunkCard variant="hologram" animation="hologram" scanLine {...props} ref={ref} />
)
HologramCard.displayName = 'HologramCard'
