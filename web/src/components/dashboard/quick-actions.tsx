'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  BoltIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  EyeIcon,
  CommandLineIcon,
  GlobeAltIcon,
  ChartBarIcon,
  PlayIcon,
  StopIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { useRouter } from 'next/navigation'

interface QuickAction {
  id: string
  title: string
  description: string
  icon: React.ComponentType<{ className?: string }>
  variant: 'neon-blue' | 'neon-green' | 'neon-orange' | 'neon-purple' | 'neon-pink'
  href?: string
  action?: () => void
  badge?: string
  shortcut?: string
  status?: 'idle' | 'running' | 'completed' | 'error'
  progress?: number
}

export function QuickActions() {
  const router = useRouter()
  const [runningActions, setRunningActions] = useState<Set<string>>(new Set())

  const handleAction = async (action: QuickAction) => {
    if (action.href) {
      router.push(action.href)
      return
    }

    if (action.action) {
      setRunningActions(prev => new Set(prev).add(action.id))
      
      try {
        await action.action()
        // Simulate action completion
        setTimeout(() => {
          setRunningActions(prev => {
            const newSet = new Set(prev)
            newSet.delete(action.id)
            return newSet
          })
        }, 2000)
      } catch (error) {
        console.error('Action failed:', error)
        setRunningActions(prev => {
          const newSet = new Set(prev)
          newSet.delete(action.id)
          return newSet
        })
      }
    }
  }

  const quickActions: QuickAction[] = [
    {
      id: 'quick-scan',
      title: 'Quick Security Scan',
      description: 'Run a fast vulnerability assessment',
      icon: BoltIcon,
      variant: 'neon-blue',
      href: '/scanner/quick',
      badge: 'Fast',
      shortcut: 'Q',
      status: 'idle'
    },
    {
      id: 'network-scan',
      title: 'Network Discovery',
      description: 'Scan local network for devices',
      icon: GlobeAltIcon,
      variant: 'neon-green',
      action: async () => {
        // Simulate network scan
        console.log('Starting network scan...')
      },
      badge: 'AI',
      shortcut: 'N',
      status: 'idle'
    },
    {
      id: 'threat-intel',
      title: 'Threat Intelligence',
      description: 'Check latest threat indicators',
      icon: EyeIcon,
      variant: 'neon-orange',
      href: '/threats/intelligence',
      badge: 'Live',
      shortcut: 'T',
      status: 'idle'
    },
    {
      id: 'ai-analysis',
      title: 'AI Security Analysis',
      description: 'Run AI-powered security assessment',
      icon: CpuChipIcon,
      variant: 'neon-purple',
      action: async () => {
        // Simulate AI analysis
        console.log('Starting AI analysis...')
      },
      badge: 'OLLAMA',
      shortcut: 'A',
      status: 'idle'
    },
    {
      id: 'system-health',
      title: 'System Health Check',
      description: 'Verify all systems are operational',
      icon: ShieldCheckIcon,
      variant: 'neon-green',
      action: async () => {
        // Simulate health check
        console.log('Running system health check...')
      },
      badge: 'Health',
      shortcut: 'H',
      status: 'idle'
    },
    {
      id: 'terminal',
      title: 'Security Terminal',
      description: 'Open interactive command interface',
      icon: CommandLineIcon,
      variant: 'neon-pink',
      href: '/terminal',
      badge: 'CLI',
      shortcut: 'C',
      status: 'idle'
    }
  ]

  return (
    <CyberpunkCard variant="hologram" size="lg">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-semibold text-cyber-blue-neon mb-1">
            Quick Actions
          </h2>
          <p className="text-sm text-matrix-text">
            Rapid access to essential security operations
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-xs">
            {quickActions.length} Actions
          </Badge>
          <CyberpunkButton variant="ghost-blue" size="sm">
            <ArrowPathIcon className="w-4 h-4" />
            Refresh
          </CyberpunkButton>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {quickActions.map((action, index) => {
          const isRunning = runningActions.has(action.id)
          
          return (
            <motion.div
              key={action.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <CyberpunkCard 
                variant={action.variant} 
                size="sm" 
                className="h-full cursor-pointer group relative overflow-hidden"
                onClick={() => handleAction(action)}
              >
                {/* Background animation */}
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 -skew-x-12 group-hover:animate-shimmer" />
                
                <div className="relative z-10">
                  <div className="flex items-start justify-between mb-3">
                    <div className={`p-2 rounded-lg bg-current/10 ${
                      isRunning ? 'animate-neon-pulse' : ''
                    }`}>
                      <action.icon className="w-5 h-5" />
                    </div>
                    
                    <div className="flex flex-col items-end gap-1">
                      {action.badge && (
                        <Badge 
                          variant="secondary" 
                          className="text-xs bg-current/20 border-current/40"
                        >
                          {action.badge}
                        </Badge>
                      )}
                      
                      {action.shortcut && (
                        <kbd className="px-1.5 py-0.5 text-xs bg-matrix-surface border border-matrix-border rounded">
                          {action.shortcut}
                        </kbd>
                      )}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <h3 className="font-medium text-sm leading-tight">
                      {action.title}
                    </h3>
                    
                    <p className="text-xs text-matrix-text leading-relaxed">
                      {action.description}
                    </p>
                  </div>

                  {/* Status indicator */}
                  <div className="flex items-center justify-between mt-4">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${
                        isRunning 
                          ? 'bg-cyber-orange-neon animate-neon-pulse' 
                          : 'bg-cyber-green-neon'
                      }`} />
                      <span className="text-xs font-cyber">
                        {isRunning ? 'RUNNING' : 'READY'}
                      </span>
                    </div>
                    
                    {isRunning ? (
                      <StopIcon className="w-4 h-4 text-cyber-orange-neon" />
                    ) : (
                      <PlayIcon className="w-4 h-4 opacity-60 group-hover:opacity-100 transition-opacity" />
                    )}
                  </div>

                  {/* Progress bar for running actions */}
                  {isRunning && (
                    <div className="mt-3">
                      <div className="w-full bg-matrix-surface rounded-full h-1">
                        <div 
                          className="bg-current h-1 rounded-full transition-all duration-300 animate-pulse"
                          style={{ width: '60%' }}
                        />
                      </div>
                    </div>
                  )}
                </div>

                {/* Hover effect overlay */}
                <div className="absolute inset-0 bg-gradient-to-t from-current/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              </CyberpunkCard>
            </motion.div>
          )
        })}
      </div>

      {/* Keyboard shortcuts hint */}
      <div className="mt-6 pt-4 border-t border-matrix-border">
        <div className="flex items-center justify-between text-xs text-matrix-text">
          <span>Use keyboard shortcuts for quick access</span>
          <div className="flex items-center gap-2">
            <kbd className="px-2 py-1 bg-matrix-surface border border-matrix-border rounded">
              Ctrl
            </kbd>
            <span>+</span>
            <kbd className="px-2 py-1 bg-matrix-surface border border-matrix-border rounded">
              Key
            </kbd>
          </div>
        </div>
      </div>
    </CyberpunkCard>
  )
}
