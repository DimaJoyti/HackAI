'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  InformationCircleIcon,
  CheckCircleIcon,
  XMarkIcon,
  BellIcon,
  EyeIcon,
  FireIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { formatRelativeTime } from '@/lib/utils'

interface Alert {
  id: string
  type: 'security' | 'system' | 'network' | 'ai'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  message: string
  timestamp: Date
  source: string
  acknowledged: boolean
  actions?: Array<{
    label: string
    action: () => void
    variant?: 'primary' | 'secondary' | 'danger'
  }>
  metadata?: Record<string, any>
}

const mockAlerts: Alert[] = [
  {
    id: '1',
    type: 'security',
    severity: 'critical',
    title: 'Critical Vulnerability Detected',
    message: 'SQL injection vulnerability found in web application endpoint /api/users',
    timestamp: new Date(Date.now() - 2 * 60 * 1000),
    source: 'Web Scanner',
    acknowledged: false,
    actions: [
      { label: 'Investigate', action: () => console.log('Investigating...'), variant: 'primary' },
      { label: 'Block IP', action: () => console.log('Blocking IP...'), variant: 'danger' }
    ]
  },
  {
    id: '2',
    type: 'network',
    severity: 'high',
    title: 'Suspicious Network Activity',
    message: 'Unusual outbound traffic detected from internal host 192.168.1.45',
    timestamp: new Date(Date.now() - 5 * 60 * 1000),
    source: 'Network Monitor',
    acknowledged: false,
    actions: [
      { label: 'Analyze Traffic', action: () => console.log('Analyzing...'), variant: 'primary' },
      { label: 'Quarantine Host', action: () => console.log('Quarantining...'), variant: 'danger' }
    ]
  },
  {
    id: '3',
    type: 'ai',
    severity: 'medium',
    title: 'AI Model Performance Degraded',
    message: 'CodeLlama model response time increased by 40% in the last hour',
    timestamp: new Date(Date.now() - 8 * 60 * 1000),
    source: 'OLLAMA Monitor',
    acknowledged: false,
    actions: [
      { label: 'Check Resources', action: () => console.log('Checking...'), variant: 'primary' },
      { label: 'Restart Model', action: () => console.log('Restarting...'), variant: 'secondary' }
    ]
  },
  {
    id: '4',
    type: 'system',
    severity: 'info',
    title: 'System Update Available',
    message: 'Security patches available for core system components',
    timestamp: new Date(Date.now() - 15 * 60 * 1000),
    source: 'Update Manager',
    acknowledged: true
  }
]

export function RealtimeAlerts() {
  const [alerts, setAlerts] = useState<Alert[]>(mockAlerts)
  const [filter, setFilter] = useState<'all' | 'unacknowledged' | 'critical'>('unacknowledged')
  const [isExpanded, setIsExpanded] = useState(true)

  // Simulate new alerts
  useEffect(() => {
    const interval = setInterval(() => {
      if (Math.random() < 0.3) { // 30% chance every 10 seconds
        const newAlert: Alert = {
          id: Date.now().toString(),
          type: ['security', 'network', 'system', 'ai'][Math.floor(Math.random() * 4)] as any,
          severity: ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)] as any,
          title: 'New Security Event Detected',
          message: 'Automated security monitoring has detected a new event requiring attention',
          timestamp: new Date(),
          source: 'Auto Monitor',
          acknowledged: false
        }
        
        setAlerts(prev => [newAlert, ...prev.slice(0, 9)]) // Keep only 10 most recent
      }
    }, 10000)

    return () => clearInterval(interval)
  }, [])

  const acknowledgeAlert = (alertId: string) => {
    setAlerts(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, acknowledged: true } : alert
    ))
  }

  const dismissAlert = (alertId: string) => {
    setAlerts(prev => prev.filter(alert => alert.id !== alertId))
  }

  const filteredAlerts = alerts.filter(alert => {
    switch (filter) {
      case 'unacknowledged':
        return !alert.acknowledged
      case 'critical':
        return alert.severity === 'critical'
      default:
        return true
    }
  })

  const getAlertIcon = (type: Alert['type'], severity: Alert['severity']) => {
    if (severity === 'critical') return FireIcon
    
    switch (type) {
      case 'security':
        return ShieldExclamationIcon
      case 'network':
        return EyeIcon
      case 'system':
        return InformationCircleIcon
      case 'ai':
        return ExclamationTriangleIcon
      default:
        return BellIcon
    }
  }

  const getSeverityColor = (severity: Alert['severity']) => {
    switch (severity) {
      case 'critical':
        return 'security-critical'
      case 'high':
        return 'security-high'
      case 'medium':
        return 'security-medium'
      case 'low':
        return 'security-low'
      case 'info':
        return 'cyber-blue-neon'
      default:
        return 'matrix-text'
    }
  }

  const getCardVariant = (severity: Alert['severity']) => {
    switch (severity) {
      case 'critical':
        return 'security-critical' as const
      case 'high':
        return 'security-high' as const
      case 'medium':
        return 'security-medium' as const
      case 'low':
        return 'security-low' as const
      default:
        return 'neon-blue' as const
    }
  }

  const unacknowledgedCount = alerts.filter(alert => !alert.acknowledged).length
  const criticalCount = alerts.filter(alert => alert.severity === 'critical').length

  return (
    <CyberpunkCard variant="glass-dark" size="lg">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <BellIcon className="w-5 h-5 text-cyber-orange-neon" />
            <h3 className="text-lg font-semibold text-matrix-white">
              Real-time Alerts
            </h3>
          </div>
          
          <div className="flex items-center gap-2">
            {criticalCount > 0 && (
              <Badge variant="outline" className="border-security-critical text-security-critical">
                {criticalCount} Critical
              </Badge>
            )}
            {unacknowledgedCount > 0 && (
              <Badge variant="outline" className="border-cyber-orange-neon text-cyber-orange-neon">
                {unacknowledgedCount} New
              </Badge>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Filter buttons */}
          <div className="flex items-center gap-1">
            {(['all', 'unacknowledged', 'critical'] as const).map((filterType) => (
              <button
                key={filterType}
                onClick={() => setFilter(filterType)}
                className={`px-3 py-1 text-xs rounded-md transition-colors capitalize ${
                  filter === filterType
                    ? 'bg-cyber-blue-neon/20 text-cyber-blue-neon border border-cyber-blue-neon/40'
                    : 'text-matrix-text hover:text-matrix-white hover:bg-matrix-surface'
                }`}
              >
                {filterType}
              </button>
            ))}
          </div>

          <CyberpunkButton
            variant="ghost-blue"
            size="sm"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? 'Collapse' : 'Expand'}
          </CyberpunkButton>
        </div>
      </div>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="space-y-4 max-h-96 overflow-y-auto scrollbar-cyber"
          >
            {filteredAlerts.length === 0 ? (
              <div className="text-center py-8">
                <CheckCircleIcon className="w-12 h-12 text-cyber-green-neon mx-auto mb-3" />
                <p className="text-matrix-text">No alerts matching current filter</p>
              </div>
            ) : (
              filteredAlerts.map((alert, index) => {
                const AlertIcon = getAlertIcon(alert.type, alert.severity)
                
                return (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    transition={{ delay: index * 0.1 }}
                  >
                    <CyberpunkCard 
                      variant={getCardVariant(alert.severity)} 
                      size="sm"
                      className={`${alert.acknowledged ? 'opacity-60' : ''}`}
                    >
                      <div className="flex items-start gap-3">
                        <div className={`p-2 rounded-lg bg-current/10 ${
                          !alert.acknowledged ? 'animate-neon-pulse' : ''
                        }`}>
                          <AlertIcon className="w-5 h-5" />
                        </div>

                        <div className="flex-1 min-w-0">
                          <div className="flex items-start justify-between gap-2 mb-2">
                            <div>
                              <h4 className="font-medium text-sm text-matrix-white">
                                {alert.title}
                              </h4>
                              <p className="text-xs text-matrix-text mt-1">
                                {alert.message}
                              </p>
                            </div>
                            
                            <button
                              onClick={() => dismissAlert(alert.id)}
                              className="p-1 rounded hover:bg-matrix-surface transition-colors"
                            >
                              <XMarkIcon className="w-4 h-4 text-matrix-text hover:text-matrix-white" />
                            </button>
                          </div>

                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2 text-xs text-matrix-text">
                              <span>{alert.source}</span>
                              <span>•</span>
                              <span>{formatRelativeTime(alert.timestamp)}</span>
                            </div>

                            <div className="flex items-center gap-2">
                              {!alert.acknowledged && (
                                <CyberpunkButton
                                  variant="ghost-blue"
                                  size="sm"
                                  onClick={() => acknowledgeAlert(alert.id)}
                                >
                                  Acknowledge
                                </CyberpunkButton>
                              )}
                              
                              {alert.actions?.map((action, actionIndex) => (
                                <CyberpunkButton
                                  key={actionIndex}
                                  variant={
                                    action.variant === 'danger' ? 'neon-orange' :
                                    action.variant === 'primary' ? 'neon-blue' : 'ghost-blue'
                                  }
                                  size="sm"
                                  onClick={action.action}
                                >
                                  {action.label}
                                </CyberpunkButton>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    </CyberpunkCard>
                  </motion.div>
                )
              })
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Summary footer */}
      <div className="mt-6 pt-4 border-t border-matrix-border">
        <div className="flex items-center justify-between text-xs text-matrix-text">
          <span>
            Showing {filteredAlerts.length} of {alerts.length} alerts
          </span>
          <div className="flex items-center gap-4">
            <span>Auto-refresh: ON</span>
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 bg-cyber-green-neon rounded-full animate-neon-pulse" />
              <span>Live monitoring active</span>
            </div>
          </div>
        </div>
      </div>
    </CyberpunkCard>
  )
}
