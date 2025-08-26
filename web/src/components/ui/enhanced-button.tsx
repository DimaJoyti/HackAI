'use client'

import React from 'react'
import { cn } from '@/lib/utils'
import { Slot } from '@radix-ui/react-slot'

interface EnhancedButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 
    | 'primary' 
    | 'secondary' 
    | 'ghost' 
    | 'neon-blue' 
    | 'neon-pink' 
    | 'neon-green' 
    | 'neon-purple'
    | 'glass'
    | 'hologram'
    | 'matrix'
  size?: 'sm' | 'md' | 'lg' | 'xl'
  glow?: boolean
  pulse?: boolean
  scanLine?: boolean
  gradient?: boolean
  asChild?: boolean
  loading?: boolean
}

export const EnhancedButton = React.forwardRef<HTMLButtonElement, EnhancedButtonProps>(
  ({ 
    className, 
    variant = 'primary', 
    size = 'md', 
    glow = false,
    pulse = false,
    scanLine = false,
    gradient = false,
    asChild = false,
    loading = false,
    children,
    disabled,
    ...props 
  }, ref) => {
    const Comp = asChild ? Slot : 'button'

    const baseClasses = [
      'relative inline-flex items-center justify-center',
      'font-cyber font-medium tracking-wide',
      'transition-all duration-300 ease-out',
      'focus:outline-none focus:ring-2 focus:ring-offset-2',
      'disabled:opacity-50 disabled:cursor-not-allowed',
      'overflow-hidden',
    ]

    const sizeClasses = {
      sm: 'px-4 py-2 text-sm rounded-md',
      md: 'px-6 py-3 text-base rounded-lg',
      lg: 'px-8 py-4 text-lg rounded-xl',
      xl: 'px-10 py-5 text-xl rounded-2xl',
    }

    const variantClasses = {
      primary: [
        'bg-gradient-to-r from-cyber-blue-neon to-cyber-blue-glow',
        'text-matrix-white border border-cyber-blue-neon/50',
        'hover:from-cyber-blue-bright hover:to-cyber-blue-neon',
        'hover:border-cyber-blue-bright hover:shadow-neon-blue',
        'focus:ring-cyber-blue-neon/50',
      ],
      secondary: [
        'bg-gradient-to-r from-matrix-surface to-matrix-elevated',
        'text-matrix-light border border-matrix-border',
        'hover:from-matrix-elevated hover:to-matrix-surface',
        'hover:text-matrix-white hover:border-matrix-light/50',
        'focus:ring-matrix-light/50',
      ],
      ghost: [
        'bg-transparent text-matrix-light',
        'border border-matrix-border/50',
        'hover:bg-matrix-surface/50 hover:text-matrix-white',
        'hover:border-matrix-light/30',
        'focus:ring-matrix-light/30',
      ],
      'neon-blue': [
        'bg-transparent text-cyber-blue-neon',
        'border border-cyber-blue-neon/50',
        'hover:bg-cyber-blue-neon/10 hover:text-cyber-blue-bright',
        'hover:border-cyber-blue-bright hover:shadow-neon-blue',
        'focus:ring-cyber-blue-neon/50',
      ],
      'neon-pink': [
        'bg-transparent text-cyber-pink-neon',
        'border border-cyber-pink-neon/50',
        'hover:bg-cyber-pink-neon/10 hover:text-cyber-pink-bright',
        'hover:border-cyber-pink-bright hover:shadow-neon-pink',
        'focus:ring-cyber-pink-neon/50',
      ],
      'neon-green': [
        'bg-transparent text-cyber-green-neon',
        'border border-cyber-green-neon/50',
        'hover:bg-cyber-green-neon/10 hover:text-cyber-green-bright',
        'hover:border-cyber-green-bright hover:shadow-neon-green',
        'focus:ring-cyber-green-neon/50',
      ],
      'neon-purple': [
        'bg-transparent text-cyber-purple-neon',
        'border border-cyber-purple-neon/50',
        'hover:bg-cyber-purple-neon/10 hover:text-cyber-purple-bright',
        'hover:border-cyber-purple-bright hover:shadow-neon-purple',
        'focus:ring-cyber-purple-neon/50',
      ],
      glass: [
        'glass-cyber text-matrix-white',
        'border border-cyber-blue-neon/30',
        'hover:bg-opacity-80 hover:border-cyber-blue-bright/50',
        'hover:shadow-hologram',
        'focus:ring-cyber-blue-neon/50',
      ],
      hologram: [
        'bg-gradient-to-r from-transparent via-cyber-blue-neon/20 to-transparent',
        'text-cyber-blue-neon border border-cyber-blue-neon/30',
        'hover:via-cyber-blue-neon/30 hover:text-cyber-blue-bright',
        'hover:border-cyber-blue-bright/50 hover:shadow-hologram',
        'focus:ring-cyber-blue-neon/50',
        'hologram',
      ],
      matrix: [
        'bg-gradient-to-r from-matrix-black via-matrix-dark to-matrix-black',
        'text-cyber-green-neon border border-cyber-green-neon/50',
        'hover:from-matrix-dark hover:via-matrix-surface hover:to-matrix-dark',
        'hover:text-cyber-green-bright hover:border-cyber-green-bright',
        'hover:shadow-neon-green',
        'focus:ring-cyber-green-neon/50',
      ],
    }

    const effectClasses = []
    
    if (glow) {
      effectClasses.push('hover:animate-glow-pulse')
    }
    
    if (pulse) {
      effectClasses.push('animate-pulse-slow')
    }
    
    if (gradient) {
      effectClasses.push('bg-gradient-to-r animate-gradient-x')
    }

    return (
      <Comp
        className={cn(
          baseClasses,
          sizeClasses[size],
          variantClasses[variant],
          effectClasses,
          loading && 'cursor-wait',
          className
        )}
        ref={ref}
        disabled={disabled || loading}
        aria-busy={loading}
        aria-disabled={disabled || loading}
        {...props}
      >
        {/* Scan Line Effect */}
        {scanLine && (
          <div className="absolute inset-0 overflow-hidden rounded-inherit">
            <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-current to-transparent animate-scan-line opacity-60" />
          </div>
        )}

        {/* Loading Spinner */}
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-5 h-5 border-2 border-current border-t-transparent rounded-full animate-spin" />
          </div>
        )}

        {/* Content */}
        <span className={cn('relative z-10', loading && 'opacity-0')}>
          {children}
        </span>

        {/* Hover Glow Effect */}
        <div className="absolute inset-0 rounded-inherit bg-gradient-to-r from-transparent via-current to-transparent opacity-0 hover:opacity-10 transition-opacity duration-300" />
      </Comp>
    )
  }
)

EnhancedButton.displayName = 'EnhancedButton'

export default EnhancedButton
