'use client'

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { getWebSocketManager, WebSocketEvents } from '@/lib/websocket'
import { apiClient } from '@/lib/api-client'

interface DataSyncState {
  isConnected: boolean
  lastSync: Date | null
  syncErrors: string[]
  pendingUpdates: number
}

interface DataSyncContextType {
  state: DataSyncState
  connect: () => Promise<void>
  disconnect: () => void
  forceSync: () => Promise<void>
  clearErrors: () => void
}

const DataSyncContext = createContext<DataSyncContextType | undefined>(undefined)

interface DataSyncProviderProps {
  children: ReactNode
  autoConnect?: boolean
  syncInterval?: number
}

export function DataSyncProvider({ 
  children, 
  autoConnect = true,
  syncInterval = 30000 
}: DataSyncProviderProps) {
  const [state, setState] = useState<DataSyncState>({
    isConnected: false,
    lastSync: null,
    syncErrors: [],
    pendingUpdates: 0,
  })

  const wsManager = getWebSocketManager()

  // Connect to WebSocket and setup event listeners
  const connect = async (): Promise<void> => {
    try {
      await wsManager.connect()
      
      setState(prev => ({
        ...prev,
        isConnected: true,
        syncErrors: prev.syncErrors.filter(error => !error.includes('connection')),
      }))

      // Setup global event listeners
      setupEventListeners()
      
      // Initial data sync
      await forceSync()
    } catch (error) {
      setState(prev => ({
        ...prev,
        isConnected: false,
        syncErrors: [...prev.syncErrors, `Connection failed: ${error}`],
      }))
    }
  }

  // Disconnect from WebSocket
  const disconnect = (): void => {
    wsManager.disconnect()
    setState(prev => ({
      ...prev,
      isConnected: false,
    }))
  }

  // Force a complete data synchronization
  const forceSync = async (): Promise<void> => {
    try {
      setState(prev => ({ ...prev, pendingUpdates: prev.pendingUpdates + 1 }))

      // Sync critical data
      const promises = [
        apiClient.getSecurityMetrics(),
        apiClient.getThreatData(),
        apiClient.getSystemStatus(),
        apiClient.getIncidents(),
      ]

      await Promise.allSettled(promises)

      setState(prev => ({
        ...prev,
        lastSync: new Date(),
        pendingUpdates: Math.max(0, prev.pendingUpdates - 1),
      }))
    } catch (error) {
      setState(prev => ({
        ...prev,
        syncErrors: [...prev.syncErrors, `Sync failed: ${error}`],
        pendingUpdates: Math.max(0, prev.pendingUpdates - 1),
      }))
    }
  }

  // Clear sync errors
  const clearErrors = (): void => {
    setState(prev => ({ ...prev, syncErrors: [] }))
  }

  // Setup WebSocket event listeners for real-time updates
  const setupEventListeners = (): void => {
    // Security events
    wsManager.subscribe(WebSocketEvents.THREAT_DETECTED, (data) => {
      console.log('Threat detected:', data)
      // Trigger UI updates or notifications
      dispatchCustomEvent('threatDetected', data)
    })

    wsManager.subscribe(WebSocketEvents.SCAN_COMPLETED, (data) => {
      console.log('Scan completed:', data)
      dispatchCustomEvent('scanCompleted', data)
    })

    wsManager.subscribe(WebSocketEvents.VULNERABILITY_FOUND, (data) => {
      console.log('Vulnerability found:', data)
      dispatchCustomEvent('vulnerabilityFound', data)
    })

    // System events
    wsManager.subscribe(WebSocketEvents.SYSTEM_STATUS, (data) => {
      console.log('System status update:', data)
      dispatchCustomEvent('systemStatusUpdate', data)
    })

    wsManager.subscribe(WebSocketEvents.NETWORK_ACTIVITY, (data) => {
      console.log('Network activity:', data)
      dispatchCustomEvent('networkActivity', data)
    })

    // AI events
    wsManager.subscribe(WebSocketEvents.AI_RECOMMENDATION, (data) => {
      console.log('AI recommendation:', data)
      dispatchCustomEvent('aiRecommendation', data)
    })

    wsManager.subscribe(WebSocketEvents.AI_PREDICTION, (data) => {
      console.log('AI prediction:', data)
      dispatchCustomEvent('aiPrediction', data)
    })

    // Learning events
    wsManager.subscribe(WebSocketEvents.ACHIEVEMENT_UNLOCKED, (data) => {
      console.log('Achievement unlocked:', data)
      dispatchCustomEvent('achievementUnlocked', data)
    })

    wsManager.subscribe(WebSocketEvents.LEARNING_PROGRESS, (data) => {
      console.log('Learning progress update:', data)
      dispatchCustomEvent('learningProgress', data)
    })

    // Incident events
    wsManager.subscribe(WebSocketEvents.INCIDENT_CREATED, (data) => {
      console.log('Incident created:', data)
      dispatchCustomEvent('incidentCreated', data)
    })

    wsManager.subscribe(WebSocketEvents.INCIDENT_UPDATED, (data) => {
      console.log('Incident updated:', data)
      dispatchCustomEvent('incidentUpdated', data)
    })

    // Notifications
    wsManager.subscribe(WebSocketEvents.NOTIFICATION, (data) => {
      console.log('Notification received:', data)
      dispatchCustomEvent('notification', data)
    })

    // Error handling
    wsManager.subscribe(WebSocketEvents.ERROR, (data) => {
      console.error('WebSocket error:', data)
      setState(prev => ({
        ...prev,
        syncErrors: [...prev.syncErrors, `WebSocket error: ${data.message}`],
      }))
    })
  }

  // Dispatch custom events for components to listen to
  const dispatchCustomEvent = (eventType: string, data: any): void => {
    const event = new CustomEvent(`dataSync:${eventType}`, { detail: data })
    window.dispatchEvent(event)
  }

  // Auto-connect on mount
  useEffect(() => {
    if (autoConnect) {
      connect()
    }

    return () => {
      disconnect()
    }
  }, [autoConnect])

  // Periodic sync
  useEffect(() => {
    if (!syncInterval) return

    const interval = setInterval(() => {
      if (state.isConnected) {
        forceSync()
      }
    }, syncInterval)

    return () => clearInterval(interval)
  }, [syncInterval, state.isConnected])

  // Monitor connection health
  useEffect(() => {
    const healthCheck = setInterval(() => {
      const isConnected = wsManager.isConnected()
      if (isConnected !== state.isConnected) {
        setState(prev => ({ ...prev, isConnected }))
      }
    }, 5000)

    return () => clearInterval(healthCheck)
  }, [state.isConnected])

  const contextValue: DataSyncContextType = {
    state,
    connect,
    disconnect,
    forceSync,
    clearErrors,
  }

  return (
    <DataSyncContext.Provider value={contextValue}>
      {children}
    </DataSyncContext.Provider>
  )
}

// Hook to use the data sync context
export function useDataSync(): DataSyncContextType {
  const context = useContext(DataSyncContext)
  if (context === undefined) {
    throw new Error('useDataSync must be used within a DataSyncProvider')
  }
  return context
}

// Hook to listen for specific data sync events
export function useDataSyncEvent(eventType: string, handler: (data: any) => void): void {
  useEffect(() => {
    const eventName = `dataSync:${eventType}`
    const eventHandler = (event: CustomEvent) => {
      handler(event.detail)
    }

    window.addEventListener(eventName, eventHandler as EventListener)
    
    return () => {
      window.removeEventListener(eventName, eventHandler as EventListener)
    }
  }, [eventType, handler])
}

// Connection status indicator component
export function ConnectionStatus(): JSX.Element {
  const { state } = useDataSync()

  return (
    <div className="flex items-center gap-2 text-xs">
      <div
        className={`w-2 h-2 rounded-full ${
          state.isConnected 
            ? 'bg-cyber-green-neon animate-neon-pulse' 
            : 'bg-security-critical'
        }`}
      />
      <span className={`font-cyber ${
        state.isConnected ? 'text-cyber-green-neon' : 'text-security-critical'
      }`}>
        {state.isConnected ? 'CONNECTED' : 'DISCONNECTED'}
      </span>
      {state.pendingUpdates > 0 && (
        <span className="text-cyber-orange-neon font-matrix">
          ({state.pendingUpdates} syncing)
        </span>
      )}
    </div>
  )
}

// Sync errors display component
export function SyncErrors(): JSX.Element | null {
  const { state, clearErrors } = useDataSync()

  if (state.syncErrors.length === 0) return null

  return (
    <div className="bg-security-critical/10 border border-security-critical/30 rounded-lg p-3">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-sm font-cyber text-security-critical">Sync Errors</h4>
        <button
          onClick={clearErrors}
          className="text-xs text-matrix-muted hover:text-matrix-white"
        >
          Clear
        </button>
      </div>
      <div className="space-y-1">
        {state.syncErrors.slice(-3).map((error, index) => (
          <div key={index} className="text-xs text-matrix-light">
            {error}
          </div>
        ))}
      </div>
    </div>
  )
}
