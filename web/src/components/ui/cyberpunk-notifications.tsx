'use client'

import React, { useState, useEffect, createContext, useContext } from 'react'
import { cn } from '@/lib/utils'
import { HolographicDisplay, ParticleSystem } from './cyberpunk-effects'
import { 
  XMarkIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
  BellIcon,
  CheckCircleIcon
} from '@heroicons/react/24/outline'

// Notification Types
export interface CyberpunkNotification {
  id: string
  type: 'threat' | 'success' | 'warning' | 'info' | 'agent'
  title: string
  message: string
  timestamp: Date
  duration?: number
  persistent?: boolean
  actions?: Array<{
    label: string
    action: () => void
    variant?: 'primary' | 'secondary' | 'danger'
  }>
  agentId?: string
  threatLevel?: 'critical' | 'high' | 'medium' | 'low'
}

// Notification Context
interface NotificationContextType {
  notifications: CyberpunkNotification[]
  addNotification: (notification: Omit<CyberpunkNotification, 'id' | 'timestamp'>) => void
  removeNotification: (id: string) => void
  clearAll: () => void
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined)

export const useNotifications = () => {
  const context = useContext(NotificationContext)
  if (!context) {
    throw new Error('useNotifications must be used within a NotificationProvider')
  }
  return context
}

// Notification Provider
export const NotificationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [notifications, setNotifications] = useState<CyberpunkNotification[]>([])

  const addNotification = (notification: Omit<CyberpunkNotification, 'id' | 'timestamp'>) => {
    const newNotification: CyberpunkNotification = {
      ...notification,
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      timestamp: new Date()
    }

    setNotifications(prev => [newNotification, ...prev])

    // Auto-remove non-persistent notifications
    if (!notification.persistent && notification.duration !== 0) {
      setTimeout(() => {
        removeNotification(newNotification.id)
      }, notification.duration || 5000)
    }
  }

  const removeNotification = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id))
  }

  const clearAll = () => {
    setNotifications([])
  }

  return (
    <NotificationContext.Provider value={{ notifications, addNotification, removeNotification, clearAll }}>
      {children}
    </NotificationContext.Provider>
  )
}

// Individual Notification Component
interface NotificationItemProps {
  notification: CyberpunkNotification
  onRemove: (id: string) => void
}

const NotificationItem: React.FC<NotificationItemProps> = ({ notification, onRemove }) => {
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    setIsVisible(true)
  }, [])

  const handleRemove = () => {
    setIsVisible(false)
    setTimeout(() => onRemove(notification.id), 300)
  }

  const getNotificationConfig = () => {
    switch (notification.type) {
      case 'threat':
        return {
          color: 'pink' as const,
          icon: ExclamationTriangleIcon,
          bgColor: 'bg-security-critical/10',
          borderColor: 'border-security-critical/30',
          textColor: 'text-security-critical'
        }
      case 'success':
        return {
          color: 'green' as const,
          icon: CheckCircleIcon,
          bgColor: 'bg-cyber-green-neon/10',
          borderColor: 'border-cyber-green-neon/30',
          textColor: 'text-cyber-green-neon'
        }
      case 'warning':
        return {
          color: 'orange' as const,
          icon: ExclamationTriangleIcon,
          bgColor: 'bg-cyber-orange-neon/10',
          borderColor: 'border-cyber-orange-neon/30',
          textColor: 'text-cyber-orange-neon'
        }
      case 'info':
        return {
          color: 'blue' as const,
          icon: InformationCircleIcon,
          bgColor: 'bg-cyber-blue-neon/10',
          borderColor: 'border-cyber-blue-neon/30',
          textColor: 'text-cyber-blue-neon'
        }
      case 'agent':
        return {
          color: 'purple' as const,
          icon: ShieldCheckIcon,
          bgColor: 'bg-cyber-purple-neon/10',
          borderColor: 'border-cyber-purple-neon/30',
          textColor: 'text-cyber-purple-neon'
        }
      default:
        return {
          color: 'blue' as const,
          icon: InformationCircleIcon,
          bgColor: 'bg-cyber-blue-neon/10',
          borderColor: 'border-cyber-blue-neon/30',
          textColor: 'text-cyber-blue-neon'
        }
    }
  }

  const config = getNotificationConfig()
  const IconComponent = config.icon

  return (
    <div
      className={cn(
        'transform transition-all duration-300 ease-out',
        isVisible ? 'translate-x-0 opacity-100' : 'translate-x-full opacity-0'
      )}
    >
      <HolographicDisplay
        color={config.color}
        intensity="medium"
        className={cn('p-4 mb-3 relative overflow-hidden', config.bgColor)}
        flicker={notification.type === 'threat'}
      >
        <ParticleSystem 
          particleCount={notification.type === 'threat' ? 20 : 10}
          color={config.color}
          speed="slow"
          size="small"
          className="opacity-20"
        />

        <div className="relative z-10">
          <div className="flex items-start justify-between">
            <div className="flex items-start gap-3 flex-1">
              <div className={cn('p-1 rounded', config.textColor)}>
                <IconComponent className="w-5 h-5" />
              </div>
              
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <h4 className={cn('font-cyber font-semibold text-sm', config.textColor)}>
                    {notification.title}
                  </h4>
                  {notification.threatLevel && (
                    <span className={cn(
                      'px-2 py-1 rounded text-xs font-matrix uppercase',
                      notification.threatLevel === 'critical' ? 'bg-security-critical/20 text-security-critical' :
                      notification.threatLevel === 'high' ? 'bg-cyber-orange-neon/20 text-cyber-orange-neon' :
                      notification.threatLevel === 'medium' ? 'bg-cyber-orange-neon/20 text-cyber-orange-neon' :
                      'bg-cyber-blue-neon/20 text-cyber-blue-neon'
                    )}>
                      {notification.threatLevel}
                    </span>
                  )}
                </div>
                
                <p className="text-sm text-matrix-light font-matrix mb-2">
                  {notification.message}
                </p>
                
                <div className="text-xs text-matrix-muted font-matrix">
                  {notification.timestamp.toLocaleTimeString()}
                  {notification.agentId && (
                    <span className="ml-2">• Agent: {notification.agentId}</span>
                  )}
                </div>
                
                {notification.actions && notification.actions.length > 0 && (
                  <div className="flex gap-2 mt-3">
                    {notification.actions.map((action, index) => (
                      <button
                        key={index}
                        onClick={action.action}
                        className={cn(
                          'px-3 py-1 rounded text-xs font-cyber uppercase transition-all duration-200',
                          action.variant === 'danger' ? 'bg-security-critical/20 text-security-critical hover:bg-security-critical/30' :
                          action.variant === 'secondary' ? 'bg-matrix-surface text-matrix-light hover:bg-matrix-border' :
                          `bg-${config.color}/20 ${config.textColor} hover:bg-${config.color}/30`
                        )}
                      >
                        {action.label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
            
            {!notification.persistent && (
              <button
                onClick={handleRemove}
                className="text-matrix-muted hover:text-matrix-white transition-colors p-1"
              >
                <XMarkIcon className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </HolographicDisplay>
    </div>
  )
}

// Notification Container
interface NotificationContainerProps {
  className?: string
  position?: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left'
  maxNotifications?: number
}

export const NotificationContainer: React.FC<NotificationContainerProps> = ({
  className,
  position = 'top-right',
  maxNotifications = 5
}) => {
  const { notifications, removeNotification } = useNotifications()

  const positionClasses = {
    'top-right': 'top-4 right-4',
    'top-left': 'top-4 left-4',
    'bottom-right': 'bottom-4 right-4',
    'bottom-left': 'bottom-4 left-4'
  }

  const visibleNotifications = notifications.slice(0, maxNotifications)

  if (visibleNotifications.length === 0) return null

  return (
    <div className={cn(
      'fixed z-50 w-96 max-w-[calc(100vw-2rem)]',
      positionClasses[position],
      className
    )}>
      {visibleNotifications.map((notification) => (
        <NotificationItem
          key={notification.id}
          notification={notification}
          onRemove={removeNotification}
        />
      ))}
    </div>
  )
}

// Notification Bell Icon with Badge
interface NotificationBellProps {
  className?: string
  onClick?: () => void
}

export const NotificationBell: React.FC<NotificationBellProps> = ({
  className,
  onClick
}) => {
  const { notifications } = useNotifications()
  const unreadCount = notifications.filter(n => !n.persistent).length

  return (
    <button
      onClick={onClick}
      className={cn(
        'relative p-2 text-matrix-light hover:text-cyber-blue-neon transition-colors',
        className
      )}
    >
      <BellIcon className="w-6 h-6" />
      {unreadCount > 0 && (
        <span className="absolute -top-1 -right-1 w-5 h-5 bg-security-critical text-matrix-white text-xs font-bold rounded-full flex items-center justify-center animate-neon-pulse">
          {unreadCount > 9 ? '9+' : unreadCount}
        </span>
      )}
    </button>
  )
}

// Utility functions for common notifications
export const createThreatNotification = (
  title: string,
  message: string,
  threatLevel: 'critical' | 'high' | 'medium' | 'low' = 'medium'
): Omit<CyberpunkNotification, 'id' | 'timestamp'> => ({
  type: 'threat',
  title,
  message,
  threatLevel,
  persistent: threatLevel === 'critical',
  duration: threatLevel === 'critical' ? 0 : 10000
})

export const createAgentNotification = (
  agentId: string,
  title: string,
  message: string
): Omit<CyberpunkNotification, 'id' | 'timestamp'> => ({
  type: 'agent',
  title,
  message,
  agentId,
  duration: 5000
})

export const createSystemNotification = (
  title: string,
  message: string,
  type: 'success' | 'warning' | 'info' = 'info'
): Omit<CyberpunkNotification, 'id' | 'timestamp'> => ({
  type,
  title,
  message,
  duration: 5000
})
