'use client'

import React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const cyberpunkButtonVariants = cva(
  'inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 relative overflow-hidden group',
  {
    variants: {
      variant: {
        // Neon variants
        'neon-blue': 'bg-matrix-dark text-cyber-blue-neon border-2 border-cyber-blue-neon shadow-neon-blue hover:shadow-neon-blue-lg hover:bg-cyber-blue-neon/10 active:scale-95',
        'neon-pink': 'bg-matrix-dark text-cyber-pink-neon border-2 border-cyber-pink-neon shadow-neon-pink hover:shadow-neon-pink-lg hover:bg-cyber-pink-neon/10 active:scale-95',
        'neon-green': 'bg-matrix-dark text-cyber-green-neon border-2 border-cyber-green-neon shadow-neon-green hover:shadow-neon-green-lg hover:bg-cyber-green-neon/10 active:scale-95',
        'neon-purple': 'bg-matrix-dark text-cyber-purple-neon border-2 border-cyber-purple-neon shadow-neon-purple hover:shadow-neon-purple-lg hover:bg-cyber-purple-neon/10 active:scale-95',
        'neon-orange': 'bg-matrix-dark text-cyber-orange-neon border-2 border-cyber-orange-neon shadow-neon-orange hover:shadow-neon-orange-lg hover:bg-cyber-orange-neon/10 active:scale-95',
        
        // Filled neon variants
        'filled-blue': 'bg-cyber-blue-neon text-matrix-black border-2 border-cyber-blue-neon shadow-neon-blue-lg hover:bg-cyber-blue-glow hover:shadow-neon-blue active:scale-95 font-semibold',
        'filled-pink': 'bg-cyber-pink-neon text-matrix-black border-2 border-cyber-pink-neon shadow-neon-pink-lg hover:bg-cyber-pink-glow hover:shadow-neon-pink active:scale-95 font-semibold',
        'filled-green': 'bg-cyber-green-neon text-matrix-black border-2 border-cyber-green-neon shadow-neon-green-lg hover:bg-cyber-green-glow hover:shadow-neon-green active:scale-95 font-semibold',
        'filled-purple': 'bg-cyber-purple-neon text-matrix-black border-2 border-cyber-purple-neon shadow-neon-purple-lg hover:bg-cyber-purple-glow hover:shadow-neon-purple active:scale-95 font-semibold',
        'filled-orange': 'bg-cyber-orange-neon text-matrix-black border-2 border-cyber-orange-neon shadow-neon-orange-lg hover:bg-cyber-orange-glow hover:shadow-neon-orange active:scale-95 font-semibold',
        
        // Hologram variants
        'hologram': 'bg-gradient-to-r from-transparent via-cyber-blue-neon/20 to-transparent text-cyber-blue-neon border border-cyber-blue-neon/50 backdrop-blur-sm hover:from-cyber-blue-neon/10 hover:via-cyber-blue-neon/30 hover:to-cyber-blue-neon/10 active:scale-95',
        'hologram-pink': 'bg-gradient-to-r from-transparent via-cyber-pink-neon/20 to-transparent text-cyber-pink-neon border border-cyber-pink-neon/50 backdrop-blur-sm hover:from-cyber-pink-neon/10 hover:via-cyber-pink-neon/30 hover:to-cyber-pink-neon/10 active:scale-95',
        
        // Matrix variants
        'matrix': 'bg-matrix-surface text-cyber-green-neon border border-cyber-green-neon/30 font-matrix hover:bg-matrix-border hover:border-cyber-green-neon hover:shadow-neon-green active:scale-95',
        'terminal': 'bg-matrix-black text-cyber-green-neon border border-cyber-green-neon font-matrix shadow-terminal hover:bg-matrix-dark hover:shadow-neon-green active:scale-95',
        
        // Security status variants
        'security-critical': 'bg-matrix-dark text-security-critical border-2 border-security-critical shadow-security-critical hover:bg-security-critical/10 active:scale-95',
        'security-high': 'bg-matrix-dark text-security-high border-2 border-security-high shadow-security-high hover:bg-security-high/10 active:scale-95',
        'security-medium': 'bg-matrix-dark text-security-medium border-2 border-security-medium shadow-security-medium hover:bg-security-medium/10 active:scale-95',
        'security-low': 'bg-matrix-dark text-security-low border-2 border-security-low shadow-security-low hover:bg-security-low/10 active:scale-95',
        'security-safe': 'bg-matrix-dark text-security-safe border-2 border-security-safe shadow-security-safe hover:bg-security-safe/10 active:scale-95',
        
        // Ghost variants
        'ghost-blue': 'text-cyber-blue-neon hover:bg-cyber-blue-neon/10 hover:text-cyber-blue-glow active:scale-95',
        'ghost-pink': 'text-cyber-pink-neon hover:bg-cyber-pink-neon/10 hover:text-cyber-pink-glow active:scale-95',
        'ghost-green': 'text-cyber-green-neon hover:bg-cyber-green-neon/10 hover:text-cyber-green-glow active:scale-95',
      },
      size: {
        sm: 'h-9 px-3 text-xs',
        default: 'h-10 px-4 py-2',
        lg: 'h-11 px-8 text-base',
        xl: 'h-12 px-10 text-lg',
        icon: 'h-10 w-10',
      },
      animation: {
        none: '',
        pulse: 'animate-neon-pulse',
        flicker: 'animate-neon-flicker',
        glow: 'animate-cyber-glow',
        glitch: 'animate-glitch',
      },
      font: {
        default: 'font-sans',
        cyber: 'font-cyber',
        matrix: 'font-matrix',
        display: 'font-display',
      },
    },
    defaultVariants: {
      variant: 'neon-blue',
      size: 'default',
      animation: 'none',
      font: 'default',
    },
  }
)

export interface CyberpunkButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof cyberpunkButtonVariants> {
  asChild?: boolean
  glitchText?: string
  scanLine?: boolean
}

const CyberpunkButton = React.forwardRef<HTMLButtonElement, CyberpunkButtonProps>(
  ({ className, variant, size, animation, font, asChild = false, glitchText, scanLine = false, children, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button'
    
    return (
      <Comp
        className={cn(cyberpunkButtonVariants({ variant, size, animation, font, className }))}
        ref={ref}
        data-text={glitchText || (typeof children === 'string' ? children : '')}
        {...props}
      >
        {/* Scan line effect */}
        {scanLine && (
          <div className="absolute inset-0 overflow-hidden rounded-md">
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -skew-x-12 -translate-x-full group-hover:translate-x-full transition-transform duration-1000 ease-out" />
          </div>
        )}
        
        {/* Content */}
        <span className="relative z-10 flex items-center justify-center gap-2">
          {children}
        </span>
        
        {/* Hover glow effect */}
        <div className="absolute inset-0 rounded-md bg-gradient-to-r from-transparent via-current to-transparent opacity-0 group-hover:opacity-10 transition-opacity duration-300" />
      </Comp>
    )
  }
)
CyberpunkButton.displayName = 'CyberpunkButton'

export { CyberpunkButton, cyberpunkButtonVariants }

// Preset button components for common use cases
export const NeonButton = React.forwardRef<HTMLButtonElement, Omit<CyberpunkButtonProps, 'variant'>>(
  (props, ref) => <CyberpunkButton variant="neon-blue" {...props} ref={ref} />
)
NeonButton.displayName = 'NeonButton'

export const MatrixButton = React.forwardRef<HTMLButtonElement, Omit<CyberpunkButtonProps, 'variant' | 'font'>>(
  (props, ref) => <CyberpunkButton variant="matrix" font="matrix" {...props} ref={ref} />
)
MatrixButton.displayName = 'MatrixButton'

export const HologramButton = React.forwardRef<HTMLButtonElement, Omit<CyberpunkButtonProps, 'variant'>>(
  (props, ref) => <CyberpunkButton variant="hologram" scanLine {...props} ref={ref} />
)
HologramButton.displayName = 'HologramButton'

export const SecurityButton = React.forwardRef<HTMLButtonElement, 
  Omit<CyberpunkButtonProps, 'variant'> & { 
    level: 'critical' | 'high' | 'medium' | 'low' | 'safe' 
  }
>(({ level, ...props }, ref) => (
  <CyberpunkButton 
    variant={`security-${level}` as any} 
    animation="pulse" 
    {...props} 
    ref={ref} 
  />
))
SecurityButton.displayName = 'SecurityButton'

export const GlitchButton = React.forwardRef<HTMLButtonElement, Omit<CyberpunkButtonProps, 'animation'>>(
  (props, ref) => <CyberpunkButton animation="glitch" {...props} ref={ref} />
)
GlitchButton.displayName = 'GlitchButton'
