'use client'

import React, { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'
import { CyberpunkButton } from './cyberpunk-button'
import { GlitchText } from './cyberpunk-background'

interface NavItem {
  href: string
  label: string
  icon?: React.ReactNode
  badge?: string
  external?: boolean
}

interface CyberpunkNavProps {
  items: NavItem[]
  className?: string
  variant?: 'horizontal' | 'vertical'
  theme?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  showLogo?: boolean
  logoText?: string
  logoHref?: string
}

export const CyberpunkNav: React.FC<CyberpunkNavProps> = ({
  items,
  className,
  variant = 'horizontal',
  theme = 'blue',
  showLogo = true,
  logoText = 'HackAI',
  logoHref = '/',
}) => {
  const pathname = usePathname()
  const [isMenuOpen, setIsMenuOpen] = useState(false)

  const themeClasses = {
    blue: {
      bg: 'bg-matrix-black/95',
      border: 'border-cyber-blue-neon/20',
      accent: 'text-cyber-blue-neon',
      glow: 'shadow-neon-blue/20',
    },
    green: {
      bg: 'bg-matrix-black/95',
      border: 'border-cyber-green-neon/20',
      accent: 'text-cyber-green-neon',
      glow: 'shadow-neon-green/20',
    },
    pink: {
      bg: 'bg-matrix-black/95',
      border: 'border-cyber-pink-neon/20',
      accent: 'text-cyber-pink-neon',
      glow: 'shadow-neon-pink/20',
    },
    purple: {
      bg: 'bg-matrix-black/95',
      border: 'border-cyber-purple-neon/20',
      accent: 'text-cyber-purple-neon',
      glow: 'shadow-neon-purple/20',
    },
    orange: {
      bg: 'bg-matrix-black/95',
      border: 'border-cyber-orange-neon/20',
      accent: 'text-cyber-orange-neon',
      glow: 'shadow-neon-orange/20',
    },
  }

  const currentTheme = themeClasses[theme]

  const isActive = (href: string) => {
    if (href === '/') {
      return pathname === '/'
    }
    return pathname.startsWith(href)
  }

  const NavLink: React.FC<{ item: NavItem }> = ({ item }) => {
    const active = isActive(item.href)
    
    return (
      <Link
        href={item.href}
        target={item.external ? '_blank' : undefined}
        rel={item.external ? 'noopener noreferrer' : undefined}
        className={cn(
          'relative group flex items-center gap-2 px-4 py-2 rounded-md transition-all duration-300',
          'hover:bg-current/10 hover:shadow-neon-blue/30',
          active && 'bg-current/20 shadow-neon-blue/50',
          currentTheme.accent
        )}
      >
        {/* Active indicator */}
        {active && (
          <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-current rounded-r-full shadow-neon-blue" />
        )}
        
        {/* Icon */}
        {item.icon && (
          <span className={cn('w-5 h-5', active && 'animate-neon-pulse')}>
            {item.icon}
          </span>
        )}
        
        {/* Label */}
        <span className={cn(
          'font-medium transition-all duration-300',
          active ? 'text-neon-blue font-cyber' : 'text-matrix-light',
          'group-hover:text-current'
        )}>
          {active ? (
            <GlitchText intensity="low">{item.label}</GlitchText>
          ) : (
            item.label
          )}
        </span>
        
        {/* Badge */}
        {item.badge && (
          <span className="ml-auto px-2 py-1 text-xs bg-current/20 text-current rounded-full border border-current/30">
            {item.badge}
          </span>
        )}
        
        {/* Hover effect */}
        <div className="absolute inset-0 rounded-md bg-gradient-to-r from-transparent via-current/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      </Link>
    )
  }

  if (variant === 'vertical') {
    return (
      <nav className={cn(
        'flex flex-col space-y-2 p-4 rounded-lg border backdrop-blur-sm',
        currentTheme.bg,
        currentTheme.border,
        currentTheme.glow,
        className
      )}>
        {showLogo && (
          <Link href={logoHref} className="mb-4">
            <div className={cn(
              'text-2xl font-display font-bold tracking-wider',
              currentTheme.accent
            )}>
              <GlitchText intensity="medium">{logoText}</GlitchText>
            </div>
          </Link>
        )}
        
        {items.map((item, index) => (
          <NavLink key={index} item={item} />
        ))}
      </nav>
    )
  }

  return (
    <nav className={cn(
      'border-b backdrop-blur-sm sticky top-0 z-50',
      currentTheme.bg,
      currentTheme.border,
      currentTheme.glow,
      className
    )}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          {showLogo && (
            <Link href={logoHref} className="flex items-center">
              <div className={cn(
                'text-2xl font-display font-bold tracking-wider',
                currentTheme.accent
              )}>
                <GlitchText intensity="low">{logoText}</GlitchText>
              </div>
            </Link>
          )}
          
          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-1">
            {items.map((item, index) => (
              <NavLink key={index} item={item} />
            ))}
          </div>
          
          {/* Mobile Menu Button */}
          <div className="md:hidden">
            <CyberpunkButton
              variant={`neon-${theme}` as any}
              size="icon"
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="relative"
            >
              <div className="w-6 h-6 flex flex-col justify-center items-center">
                <span className={cn(
                  'block w-5 h-0.5 bg-current transition-all duration-300',
                  isMenuOpen && 'rotate-45 translate-y-1.5'
                )} />
                <span className={cn(
                  'block w-5 h-0.5 bg-current mt-1 transition-all duration-300',
                  isMenuOpen && 'opacity-0'
                )} />
                <span className={cn(
                  'block w-5 h-0.5 bg-current mt-1 transition-all duration-300',
                  isMenuOpen && '-rotate-45 -translate-y-1.5'
                )} />
              </div>
            </CyberpunkButton>
          </div>
        </div>
        
        {/* Mobile Menu */}
        {isMenuOpen && (
          <div className="md:hidden border-t border-current/20">
            <div className="px-2 pt-2 pb-3 space-y-1">
              {items.map((item, index) => (
                <NavLink key={index} item={item} />
              ))}
            </div>
          </div>
        )}
      </div>
    </nav>
  )
}

// Preset navigation components
export const MatrixNav: React.FC<Omit<CyberpunkNavProps, 'theme'>> = (props) => (
  <CyberpunkNav theme="green" {...props} />
)

export const SecurityNav: React.FC<Omit<CyberpunkNavProps, 'theme'>> = (props) => (
  <CyberpunkNav theme="blue" {...props} />
)

export const HackerNav: React.FC<Omit<CyberpunkNavProps, 'theme'>> = (props) => (
  <CyberpunkNav theme="pink" {...props} />
)

// Breadcrumb Component
interface BreadcrumbItem {
  label: string
  href?: string
}

interface CyberpunkBreadcrumbProps {
  items: BreadcrumbItem[]
  className?: string
  theme?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
}

export const CyberpunkBreadcrumb: React.FC<CyberpunkBreadcrumbProps> = ({
  items,
  className,
  theme = 'blue',
}) => {
  const themeClasses = {
    blue: 'text-cyber-blue-neon',
    green: 'text-cyber-green-neon',
    pink: 'text-cyber-pink-neon',
    purple: 'text-cyber-purple-neon',
    orange: 'text-cyber-orange-neon',
  }

  return (
    <nav className={cn('flex items-center space-x-2 text-sm', className)}>
      {items.map((item, index) => (
        <React.Fragment key={index}>
          {index > 0 && (
            <span className="text-matrix-muted font-matrix">/</span>
          )}
          {item.href ? (
            <Link
              href={item.href}
              className={cn(
                'hover:underline transition-colors duration-200',
                index === items.length - 1 
                  ? themeClasses[theme] 
                  : 'text-matrix-text hover:text-matrix-light'
              )}
            >
              {item.label}
            </Link>
          ) : (
            <span className={cn(
              index === items.length - 1 
                ? themeClasses[theme] 
                : 'text-matrix-text'
            )}>
              {item.label}
            </span>
          )}
        </React.Fragment>
      ))}
    </nav>
  )
}
