'use client'

import React, { useState, useEffect } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'
import { DataStream, ParticleSystem } from './cyberpunk-effects'
import { 
  Bars3Icon, 
  XMarkIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  HomeIcon,
  CommandLineIcon
} from '@heroicons/react/24/outline'

interface NavItem {
  href: string
  label: string
  icon?: React.ReactNode
  badge?: string
  active?: boolean
  children?: NavItem[]
  description?: string
}

interface EnhancedCyberpunkNavProps {
  className?: string
  items: NavItem[]
  theme?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  logoText?: string
  logoHref?: string
  rightContent?: React.ReactNode
  showBreadcrumbs?: boolean
  animated?: boolean
}

export const EnhancedCyberpunkNav: React.FC<EnhancedCyberpunkNavProps> = ({
  className,
  items,
  theme = 'blue',
  logoText = 'CYBER',
  logoHref = '/',
  rightContent,
  showBreadcrumbs = true,
  animated = true
}) => {
  const [isOpen, setIsOpen] = useState(false)
  const [openDropdown, setOpenDropdown] = useState<string | null>(null)
  const [scrolled, setScrolled] = useState(false)
  const pathname = usePathname()

  // Handle scroll effect
  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20)
    }
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  // Close mobile menu on route change
  useEffect(() => {
    setIsOpen(false)
    setOpenDropdown(null)
  }, [pathname])

  const themeColors = {
    blue: {
      primary: 'text-cyber-blue-neon',
      border: 'border-cyber-blue-neon/30',
      bg: 'bg-cyber-blue-neon/10',
      glow: 'shadow-neon-blue',
      hover: 'hover:bg-cyber-blue-neon/20'
    },
    green: {
      primary: 'text-cyber-green-neon',
      border: 'border-cyber-green-neon/30',
      bg: 'bg-cyber-green-neon/10',
      glow: 'shadow-neon-green',
      hover: 'hover:bg-cyber-green-neon/20'
    },
    pink: {
      primary: 'text-cyber-pink-neon',
      border: 'border-cyber-pink-neon/30',
      bg: 'bg-cyber-pink-neon/10',
      glow: 'shadow-neon-pink',
      hover: 'hover:bg-cyber-pink-neon/20'
    },
    purple: {
      primary: 'text-cyber-purple-neon',
      border: 'border-cyber-purple-neon/30',
      bg: 'bg-cyber-purple-neon/10',
      glow: 'shadow-neon-purple',
      hover: 'hover:bg-cyber-purple-neon/20'
    },
    orange: {
      primary: 'text-cyber-orange-neon',
      border: 'border-cyber-orange-neon/30',
      bg: 'bg-cyber-orange-neon/10',
      glow: 'shadow-neon-orange',
      hover: 'hover:bg-cyber-orange-neon/20'
    }
  }

  const colors = themeColors[theme]

  // Generate breadcrumbs from current path
  const generateBreadcrumbs = () => {
    const pathSegments = pathname.split('/').filter(Boolean)
    const breadcrumbs = [{ label: 'Home', href: '/' }]
    
    let currentPath = ''
    pathSegments.forEach((segment) => {
      currentPath += `/${segment}`
      const item = findItemByPath(items, currentPath)
      breadcrumbs.push({
        label: item?.label || segment.charAt(0).toUpperCase() + segment.slice(1),
        href: currentPath
      })
    })
    
    return breadcrumbs
  }

  const findItemByPath = (navItems: NavItem[], path: string): NavItem | undefined => {
    for (const item of navItems) {
      if (item.href === path) return item
      if (item.children) {
        const found = findItemByPath(item.children, path)
        if (found) return found
      }
    }
    return undefined
  }

  const renderNavItem = (item: NavItem, isMobile = false) => {
    const hasChildren = item.children && item.children.length > 0
    const isDropdownOpen = openDropdown === item.label
    const isActive = pathname === item.href || item.active

    if (hasChildren) {
      return (
        <div key={item.label} className="relative group">
          <button
            onClick={() => setOpenDropdown(isDropdownOpen ? null : item.label)}
            onMouseEnter={() => !isMobile && setOpenDropdown(item.label)}
            onMouseLeave={() => !isMobile && setTimeout(() => setOpenDropdown(null), 150)}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-300',
              'text-matrix-light hover:text-matrix-white font-cyber relative overflow-hidden',
              isActive && colors.primary,
              isActive && colors.bg,
              isActive && colors.glow,
              colors.hover,
              isMobile && 'w-full justify-between',
              animated && 'group-hover:animate-neon-pulse'
            )}
          >
            {animated && (
              <div className="absolute inset-0 opacity-0 group-hover:opacity-20 transition-opacity duration-300">
                <DataStream streamCount={2} direction="horizontal" color={theme} speed="fast" />
              </div>
            )}
            
            <div className="flex items-center gap-2 relative z-10">
              {item.icon}
              <span>{item.label}</span>
              {item.badge && (
                <span className={cn(
                  'px-2 py-1 text-xs rounded-full font-matrix animate-neon-pulse',
                  colors.bg,
                  colors.primary
                )}>
                  {item.badge}
                </span>
              )}
            </div>
            <ChevronDownIcon 
              className={cn(
                'w-4 h-4 transition-transform duration-200 relative z-10',
                isDropdownOpen && 'rotate-180'
              )} 
            />
          </button>

          {isDropdownOpen && (
            <div 
              className={cn(
                'absolute top-full left-0 mt-2 min-w-64 rounded-lg border backdrop-blur-sm z-50',
                'bg-matrix-dark/95 shadow-2xl',
                colors.border,
                colors.glow,
                isMobile && 'relative top-0 mt-2 border-none bg-matrix-surface/50 shadow-none'
              )}
              onMouseEnter={() => !isMobile && setOpenDropdown(item.label)}
              onMouseLeave={() => !isMobile && setOpenDropdown(null)}
            >
              {animated && (
                <ParticleSystem 
                  particleCount={15} 
                  color={theme} 
                  speed="slow" 
                  size="small"
                  className="absolute inset-0 opacity-30"
                />
              )}
              
              {item.children.map((child) => (
                <Link
                  key={child.href}
                  href={child.href}
                  className={cn(
                    'flex items-center gap-3 px-4 py-3 text-matrix-light hover:text-matrix-white',
                    'transition-all duration-200 font-matrix relative overflow-hidden group',
                    'first:rounded-t-lg last:rounded-b-lg',
                    pathname === child.href && colors.primary,
                    pathname === child.href && colors.bg,
                    colors.hover
                  )}
                  onClick={() => {
                    setIsOpen(false)
                    setOpenDropdown(null)
                  }}
                >
                  <div className="flex items-center gap-3 relative z-10">
                    {child.icon}
                    <div>
                      <div className="font-semibold">{child.label}</div>
                      {child.description && (
                        <div className="text-xs text-matrix-muted">{child.description}</div>
                      )}
                    </div>
                    {child.badge && (
                      <span className={cn(
                        'px-2 py-1 text-xs rounded-full font-matrix ml-auto',
                        colors.bg,
                        colors.primary
                      )}>
                        {child.badge}
                      </span>
                    )}
                  </div>
                  
                  {animated && (
                    <div className="absolute inset-0 opacity-0 group-hover:opacity-10 transition-opacity duration-300">
                      <DataStream streamCount={1} direction="horizontal" color={theme} speed="medium" />
                    </div>
                  )}
                </Link>
              ))}
            </div>
          )}
        </div>
      )
    }

    return (
      <Link
        key={item.href}
        href={item.href}
        className={cn(
          'flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-300 relative overflow-hidden group',
          'text-matrix-light hover:text-matrix-white font-cyber',
          isActive && colors.primary,
          isActive && colors.bg,
          isActive && colors.glow,
          colors.hover,
          animated && isActive && 'animate-neon-pulse'
        )}
        onClick={() => setIsOpen(false)}
      >
        {animated && (
          <div className="absolute inset-0 opacity-0 group-hover:opacity-20 transition-opacity duration-300">
            <DataStream streamCount={2} direction="horizontal" color={theme} speed="fast" />
          </div>
        )}
        
        <div className="flex items-center gap-2 relative z-10">
          {item.icon}
          <span>{item.label}</span>
          {item.badge && (
            <span className={cn(
              'px-2 py-1 text-xs rounded-full font-matrix animate-neon-pulse',
              colors.bg,
              colors.primary
            )}>
              {item.badge}
            </span>
          )}
        </div>
      </Link>
    )
  }

  const breadcrumbs = showBreadcrumbs ? generateBreadcrumbs() : []

  return (
    <>
      <nav className={cn(
        'fixed top-0 left-0 right-0 z-50 backdrop-blur-md border-b transition-all duration-300',
        scrolled ? 'bg-matrix-black/95 shadow-2xl' : 'bg-matrix-black/80',
        colors.border,
        animated && scrolled && colors.glow,
        className
      )}>
        {animated && (
          <div className="absolute inset-0 opacity-10">
            <DataStream streamCount={3} direction="horizontal" color={theme} speed="slow" />
          </div>
        )}
        
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 relative z-10">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <Link 
              href={logoHref}
              className={cn(
                'flex items-center gap-2 text-2xl font-display font-bold transition-all duration-300 group',
                colors.primary,
                animated && 'hover:animate-neon-pulse'
              )}
            >
              <div className="relative">
                <HomeIcon className="w-8 h-8" />
                {animated && (
                  <div className="absolute inset-0 opacity-0 group-hover:opacity-50 transition-opacity duration-300">
                    <ParticleSystem particleCount={5} color={theme} speed="fast" size="small" />
                  </div>
                )}
              </div>
              <span className="font-cyber tracking-wider">{logoText}</span>
            </Link>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center space-x-2">
              {items.map(renderNavItem)}
            </div>

            {/* Right Content & Mobile Menu Button */}
            <div className="flex items-center gap-4">
              {rightContent}
              
              <button
                onClick={() => setIsOpen(!isOpen)}
                className={cn(
                  'md:hidden p-2 rounded-lg transition-all duration-300 relative overflow-hidden group',
                  'text-matrix-light hover:text-matrix-white',
                  colors.bg,
                  colors.hover,
                  animated && 'hover:animate-neon-pulse'
                )}
              >
                {animated && (
                  <div className="absolute inset-0 opacity-0 group-hover:opacity-30 transition-opacity duration-300">
                    <ParticleSystem particleCount={3} color={theme} speed="medium" size="small" />
                  </div>
                )}
                
                <div className="relative z-10">
                  {isOpen ? (
                    <XMarkIcon className="w-6 h-6" />
                  ) : (
                    <Bars3Icon className="w-6 h-6" />
                  )}
                </div>
              </button>
            </div>
          </div>

          {/* Mobile Navigation */}
          {isOpen && (
            <div className={cn(
              'md:hidden py-4 border-t relative',
              colors.border
            )}>
              {animated && (
                <div className="absolute inset-0 opacity-10">
                  <ParticleSystem particleCount={20} color={theme} speed="slow" size="small" />
                </div>
              )}
              
              <div className="space-y-2 relative z-10">
                {items.map((item) => renderNavItem(item, true))}
              </div>
            </div>
          )}
        </div>
      </nav>

      {/* Breadcrumbs */}
      {showBreadcrumbs && breadcrumbs.length > 1 && (
        <div className={cn(
          'fixed top-16 left-0 right-0 z-40 backdrop-blur-sm border-b py-2',
          'bg-matrix-dark/80',
          colors.border
        )}>
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <nav className="flex items-center space-x-2 text-sm">
              <CommandLineIcon className={cn('w-4 h-4', colors.primary)} />
              {breadcrumbs.map((crumb, index) => (
                <React.Fragment key={crumb.href}>
                  {index > 0 && (
                    <ChevronRightIcon className="w-4 h-4 text-matrix-muted" />
                  )}
                  <Link
                    href={crumb.href}
                    className={cn(
                      'font-matrix transition-colors duration-200',
                      index === breadcrumbs.length - 1 
                        ? cn(colors.primary, 'font-semibold')
                        : 'text-matrix-muted hover:text-matrix-light'
                    )}
                  >
                    {crumb.label}
                  </Link>
                </React.Fragment>
              ))}
            </nav>
          </div>
        </div>
      )}
    </>
  )
}
