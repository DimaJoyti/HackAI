'use client'

import { useState, useEffect } from 'react'
import { usePathname } from 'next/navigation'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
  HomeIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  AcademicCapIcon,
  ChartBarIcon,
  Cog6ToothIcon,
  UserIcon,
  Bars3Icon,
  XMarkIcon,
  BellIcon,
  MagnifyingGlassIcon,
  CommandLineIcon,
  EyeIcon,
  BoltIcon,
  GlobeAltIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { Badge } from '@/components/ui/badge'
import { useAuth } from '@/hooks/use-auth'

interface MainLayoutProps {
  children: React.ReactNode
}

const navigation = [
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: HomeIcon,
    badge: null,
    description: 'Overview and system status'
  },
  {
    name: 'Security Scanner',
    href: '/scanner',
    icon: ShieldCheckIcon,
    badge: 'AI',
    description: 'Vulnerability and security scanning'
  },
  {
    name: 'Network Analysis',
    href: '/network',
    icon: GlobeAltIcon,
    badge: 'NEW',
    description: 'Network monitoring and analysis'
  },
  {
    name: 'Threat Intelligence',
    href: '/threats',
    icon: EyeIcon,
    badge: null,
    description: 'Threat detection and intelligence'
  },
  {
    name: 'AI Models',
    href: '/ai-models',
    icon: CpuChipIcon,
    badge: 'OLLAMA',
    description: 'Local AI model management'
  },
  {
    name: 'Learning Hub',
    href: '/education',
    icon: AcademicCapIcon,
    badge: null,
    description: 'Educational content and tutorials'
  },
  {
    name: 'Analytics',
    href: '/analytics',
    icon: ChartBarIcon,
    badge: null,
    description: 'Performance metrics and insights'
  },
  {
    name: 'Terminal',
    href: '/terminal',
    icon: CommandLineIcon,
    badge: 'BETA',
    description: 'Interactive command interface'
  },
]

const quickActions = [
  {
    name: 'Quick Scan',
    href: '/scanner/quick',
    icon: BoltIcon,
    color: 'blue' as const,
  },
  {
    name: 'System Status',
    href: '/dashboard/status',
    icon: CpuChipIcon,
    color: 'green' as const,
  },
  {
    name: 'Recent Alerts',
    href: '/alerts',
    icon: BellIcon,
    color: 'orange' as const,
  },
]

export function MainLayout({ children }: MainLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [searchOpen, setSearchOpen] = useState(false)
  const pathname = usePathname()
  const { user, isAuthenticated } = useAuth()

  // Close sidebar on route change
  useEffect(() => {
    setSidebarOpen(false)
  }, [pathname])

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey) {
        switch (e.key) {
          case 'k':
            e.preventDefault()
            setSearchOpen(true)
            break
          case 'b':
            e.preventDefault()
            setSidebarOpen(!sidebarOpen)
            break
        }
      }
      if (e.key === 'Escape') {
        setSearchOpen(false)
        setSidebarOpen(false)
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [sidebarOpen])

  if (!isAuthenticated) {
    return <>{children}</>
  }

  return (
    <div className="min-h-screen bg-matrix-void text-matrix-white">
      {/* Background Effects */}
      <div className="fixed inset-0 bg-cyber-grid opacity-5 pointer-events-none" />
      <div className="fixed inset-0 bg-gradient-to-br from-cyber-blue-neon/5 via-transparent to-cyber-pink-neon/5 pointer-events-none" />

      {/* Mobile sidebar backdrop */}
      <AnimatePresence>
        {sidebarOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-40 bg-matrix-black/80 backdrop-blur-sm lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <AnimatePresence>
        <motion.div
          initial={{ x: -320 }}
          animate={{ x: sidebarOpen ? 0 : -320 }}
          transition={{ type: 'spring', damping: 25, stiffness: 200 }}
          className={`fixed inset-y-0 left-0 z-50 w-80 bg-matrix-dark/95 backdrop-blur-xl border-r border-cyber-blue-neon/20 lg:translate-x-0 lg:static lg:inset-0 ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          } lg:translate-x-0 transition-transform duration-300 ease-in-out`}
        >
          <div className="flex h-full flex-col">
            {/* Logo */}
            <div className="flex h-16 items-center justify-between px-6 border-b border-cyber-blue-neon/20">
              <Link href="/dashboard" className="flex items-center space-x-3">
                <div className="w-8 h-8 bg-gradient-to-br from-cyber-blue-neon to-cyber-pink-neon rounded-lg flex items-center justify-center">
                  <ShieldCheckIcon className="w-5 h-5 text-matrix-white" />
                </div>
                <span className="text-xl font-display font-bold text-cyber-blue-neon">
                  HackAI
                </span>
              </Link>
              <button
                onClick={() => setSidebarOpen(false)}
                className="lg:hidden p-2 rounded-lg hover:bg-matrix-surface transition-colors"
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            {/* Navigation */}
            <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto scrollbar-cyber">
              {navigation.map((item) => {
                const isActive = pathname?.startsWith(item.href) || false
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={`group flex items-center px-3 py-3 text-sm font-medium rounded-lg transition-all duration-200 ${
                      isActive
                        ? 'bg-cyber-blue-neon/20 text-cyber-blue-neon border border-cyber-blue-neon/30 shadow-neon-blue'
                        : 'text-matrix-light hover:bg-matrix-surface hover:text-matrix-white border border-transparent hover:border-matrix-border'
                    }`}
                  >
                    <item.icon
                      className={`mr-3 h-5 w-5 transition-colors ${
                        isActive ? 'text-cyber-blue-neon' : 'text-matrix-text group-hover:text-matrix-white'
                      }`}
                    />
                    <span className="flex-1">{item.name}</span>
                    {item.badge && (
                      <Badge
                        variant={isActive ? 'default' : 'secondary'}
                        className={`ml-2 text-xs ${
                          isActive
                            ? 'bg-cyber-blue-neon/20 text-cyber-blue-bright border-cyber-blue-neon/40'
                            : 'bg-matrix-surface text-matrix-text border-matrix-border'
                        }`}
                      >
                        {item.badge}
                      </Badge>
                    )}
                  </Link>
                )
              })}
            </nav>

            {/* Quick Actions */}
            <div className="px-4 py-4 border-t border-matrix-border">
              <h3 className="text-xs font-semibold text-matrix-text uppercase tracking-wider mb-3">
                Quick Actions
              </h3>
              <div className="space-y-2">
                {quickActions.map((action) => (
                  <Link
                    key={action.name}
                    href={action.href}
                    className="flex items-center px-3 py-2 text-sm text-matrix-light hover:text-matrix-white hover:bg-matrix-surface rounded-lg transition-colors group"
                  >
                    <action.icon className={`mr-3 h-4 w-4 text-cyber-${action.color}-neon group-hover:animate-neon-pulse`} />
                    {action.name}
                  </Link>
                ))}
              </div>
            </div>

            {/* User Profile */}
            <div className="px-4 py-4 border-t border-matrix-border">
              <div className="flex items-center space-x-3">
                <div className="w-8 h-8 bg-gradient-to-br from-cyber-purple-neon to-cyber-pink-neon rounded-full flex items-center justify-center">
                  <UserIcon className="w-4 h-4 text-matrix-white" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-matrix-white truncate">
                    {user?.firstName ? `${user.firstName} ${user.lastName || ''}`.trim() : user?.username || 'User'}
                  </p>
                  <p className="text-xs text-matrix-text truncate">
                    {user?.email || 'user@hackai.dev'}
                  </p>
                </div>
                <Link href="/settings">
                  <CyberpunkButton variant="ghost-blue" size="sm">
                    <Cog6ToothIcon className="w-4 h-4" />
                  </CyberpunkButton>
                </Link>
              </div>
            </div>
          </div>
        </motion.div>
      </AnimatePresence>

      {/* Main content */}
      <div className="lg:pl-80">
        {/* Top bar */}
        <div className="sticky top-0 z-30 flex h-16 items-center justify-between bg-matrix-dark/95 backdrop-blur-xl border-b border-cyber-blue-neon/20 px-4 sm:px-6 lg:px-8">
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setSidebarOpen(true)}
              className="lg:hidden p-2 rounded-lg hover:bg-matrix-surface transition-colors"
            >
              <Bars3Icon className="w-5 h-5" />
            </button>

            {/* Search */}
            <div className="relative">
              <button
                onClick={() => setSearchOpen(true)}
                className="flex items-center space-x-2 px-3 py-2 bg-matrix-surface border border-matrix-border rounded-lg hover:border-cyber-blue-neon/40 transition-colors group"
              >
                <MagnifyingGlassIcon className="w-4 h-4 text-matrix-text group-hover:text-cyber-blue-neon" />
                <span className="text-sm text-matrix-text group-hover:text-matrix-white">
                  Search...
                </span>
                <kbd className="hidden sm:inline-flex items-center px-2 py-0.5 text-xs text-matrix-text bg-matrix-border rounded">
                  ⌘K
                </kbd>
              </button>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            {/* Notifications */}
            <button className="relative p-2 rounded-lg hover:bg-matrix-surface transition-colors group">
              <BellIcon className="w-5 h-5 text-matrix-text group-hover:text-cyber-orange-neon" />
              <span className="absolute top-1 right-1 w-2 h-2 bg-cyber-orange-neon rounded-full animate-neon-pulse" />
            </button>

            {/* System Status */}
            <div className="hidden sm:flex items-center space-x-2">
              <div className="w-2 h-2 bg-cyber-green-neon rounded-full animate-neon-pulse" />
              <span className="text-sm text-cyber-green-neon font-cyber">ONLINE</span>
            </div>
          </div>
        </div>

        {/* Page content */}
        <main className="flex-1">
          {children}
        </main>
      </div>

      {/* Search Modal */}
      <AnimatePresence>
        {searchOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-matrix-black/80 backdrop-blur-sm flex items-start justify-center pt-20"
            onClick={() => setSearchOpen(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-2xl mx-4"
              onClick={(e) => e.stopPropagation()}
            >
              <CyberpunkCard variant="neon-blue" size="lg" className="p-6">
                <div className="flex items-center space-x-4 mb-4">
                  <MagnifyingGlassIcon className="w-6 h-6 text-cyber-blue-neon" />
                  <input
                    type="text"
                    placeholder="Search commands, pages, and more..."
                    className="flex-1 bg-transparent text-lg text-matrix-white placeholder-matrix-text border-none outline-none"
                    autoFocus
                  />
                  <kbd className="px-2 py-1 text-xs text-matrix-text bg-matrix-surface border border-matrix-border rounded">
                    ESC
                  </kbd>
                </div>
                <div className="text-sm text-matrix-text">
                  Start typing to search across HackAI...
                </div>
              </CyberpunkCard>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
