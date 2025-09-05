'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useWebSocket, WebSocketEvents } from '@/lib/websocket'
import { useApiClient, ApiResponse } from '@/lib/api-client'

export interface RealTimeDataConfig {
  enableWebSocket?: boolean
  enablePolling?: boolean
  pollingInterval?: number
  autoConnect?: boolean
}

export interface RealTimeDataState<T> {
  data: T | null
  loading: boolean
  error: string | null
  connected: boolean
  lastUpdate: Date | null
}

/**
 * Hook for real-time data synchronization
 * Combines WebSocket events with API polling for robust data updates
 */
export function useRealTimeData<T>(
  apiEndpoint: string,
  wsEventType?: string,
  config: RealTimeDataConfig = {}
): RealTimeDataState<T> & {
  refresh: () => Promise<void>
  connect: () => Promise<void>
  disconnect: () => void
} {
  const {
    enableWebSocket = true,
    enablePolling = false,
    pollingInterval = 30000,
    autoConnect = true,
  } = config

  const [state, setState] = useState<RealTimeDataState<T>>({
    data: null,
    loading: true,
    error: null,
    connected: false,
    lastUpdate: null,
  })

  const ws = useWebSocket()
  const apiClient = useApiClient()
  const pollingRef = useRef<NodeJS.Timeout | null>(null)
  const mountedRef = useRef(true)

  // Fetch data from API
  const fetchData = useCallback(async (): Promise<void> => {
    if (!mountedRef.current) return

    try {
      setState(prev => ({ ...prev, loading: true, error: null }))
      
      // Use dynamic endpoint calling
      const response: ApiResponse<T> = await (apiClient as any).request(apiEndpoint, { cache: true })
      
      if (!mountedRef.current) return

      if (response.success) {
        setState(prev => ({
          ...prev,
          data: response.data,
          loading: false,
          error: null,
          lastUpdate: new Date(),
        }))
      } else {
        setState(prev => ({
          ...prev,
          loading: false,
          error: response.error || 'Failed to fetch data',
        }))
      }
    } catch (error) {
      if (!mountedRef.current) return
      
      setState(prev => ({
        ...prev,
        loading: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      }))
    }
  }, [apiEndpoint, apiClient])

  // Handle WebSocket data updates
  const handleWebSocketData = useCallback((data: any) => {
    if (!mountedRef.current) return

    setState(prev => ({
      ...prev,
      data: data,
      lastUpdate: new Date(),
      error: null,
    }))
  }, [])

  // Connect to WebSocket
  const connect = useCallback(async (): Promise<void> => {
    if (!enableWebSocket) return

    try {
      await ws.connect()
      setState(prev => ({ ...prev, connected: true }))
    } catch (error) {
      setState(prev => ({
        ...prev,
        connected: false,
        error: error instanceof Error ? error.message : 'WebSocket connection failed',
      }))
    }
  }, [ws, enableWebSocket])

  // Disconnect from WebSocket
  const disconnect = useCallback((): void => {
    ws.disconnect()
    setState(prev => ({ ...prev, connected: false }))
    
    if (pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }
  }, [ws])

  // Setup WebSocket subscription
  useEffect(() => {
    if (!enableWebSocket || !wsEventType) return

    const unsubscribe = ws.subscribe(wsEventType, handleWebSocketData)
    
    return () => {
      unsubscribe()
    }
  }, [ws, wsEventType, enableWebSocket, handleWebSocketData])

  // Setup polling
  useEffect(() => {
    if (!enablePolling) return

    pollingRef.current = setInterval(fetchData, pollingInterval)

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [enablePolling, pollingInterval, fetchData])

  // Initial setup
  useEffect(() => {
    mountedRef.current = true

    const initialize = async () => {
      // Initial data fetch
      await fetchData()

      // Auto-connect to WebSocket
      if (autoConnect && enableWebSocket) {
        await connect()
      }
    }

    initialize()

    return () => {
      mountedRef.current = false
      disconnect()
    }
  }, [fetchData, connect, disconnect, autoConnect, enableWebSocket])

  // Monitor WebSocket connection state
  useEffect(() => {
    const checkConnection = () => {
      const isConnected = ws.isConnected()
      setState(prev => ({ ...prev, connected: isConnected }))
    }

    const interval = setInterval(checkConnection, 5000)
    return () => clearInterval(interval)
  }, [ws])

  return {
    ...state,
    refresh: fetchData,
    connect,
    disconnect,
  }
}

/**
 * Specialized hooks for different data types
 */

// Security metrics hook
export function useSecurityMetrics() {
  return useRealTimeData(
    '/api/security/metrics',
    WebSocketEvents.SYSTEM_STATUS,
    {
      enableWebSocket: true,
      enablePolling: true,
      pollingInterval: 30000,
    }
  )
}

// Threat data hook
export function useThreatData() {
  return useRealTimeData(
    '/api/security/threats',
    WebSocketEvents.THREAT_DETECTED,
    {
      enableWebSocket: true,
      enablePolling: false,
    }
  )
}

// Scan status hook
export function useScanStatus(scanId?: string) {
  const endpoint = scanId ? `/api/scans/${scanId}` : '/api/scans'
  
  return useRealTimeData(
    endpoint,
    WebSocketEvents.SCAN_PROGRESS,
    {
      enableWebSocket: true,
      enablePolling: true,
      pollingInterval: 5000,
    }
  )
}

// AI recommendations hook
export function useAIRecommendations() {
  return useRealTimeData(
    '/api/ai/recommendations',
    WebSocketEvents.AI_RECOMMENDATION,
    {
      enableWebSocket: true,
      enablePolling: true,
      pollingInterval: 60000,
    }
  )
}

// Learning progress hook
export function useLearningProgress(userId: string) {
  return useRealTimeData(
    `/api/learning/progress/${userId}`,
    WebSocketEvents.LEARNING_PROGRESS,
    {
      enableWebSocket: true,
      enablePolling: false,
    }
  )
}

// Incidents hook
export function useIncidents() {
  return useRealTimeData(
    '/api/incidents',
    WebSocketEvents.INCIDENT_UPDATED,
    {
      enableWebSocket: true,
      enablePolling: true,
      pollingInterval: 15000,
    }
  )
}

// System status hook
export function useSystemStatus() {
  return useRealTimeData(
    '/api/system/status',
    WebSocketEvents.SYSTEM_STATUS,
    {
      enableWebSocket: true,
      enablePolling: true,
      pollingInterval: 10000,
    }
  )
}

// Network status hook
export function useNetworkStatus() {
  return useRealTimeData(
    '/api/network/status',
    WebSocketEvents.NETWORK_ACTIVITY,
    {
      enableWebSocket: true,
      enablePolling: true,
      pollingInterval: 5000,
    }
  )
}

// Compliance status hook
export function useComplianceStatus() {
  return useRealTimeData(
    '/api/compliance/status',
    WebSocketEvents.COMPLIANCE_CHECK,
    {
      enableWebSocket: true,
      enablePolling: true,
      pollingInterval: 300000, // 5 minutes
    }
  )
}

// Notifications hook
export function useNotifications() {
  return useRealTimeData(
    '/api/notifications',
    WebSocketEvents.NOTIFICATION,
    {
      enableWebSocket: true,
      enablePolling: false,
    }
  )
}
