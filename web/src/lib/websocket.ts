/**
 * WebSocket connection manager for real-time data synchronization
 * Handles connections to the Go microservices backend
 */

export interface WebSocketMessage {
  type: string
  payload: any
  timestamp: number
  source: string
}

export interface WebSocketConfig {
  url: string
  reconnectInterval: number
  maxReconnectAttempts: number
  heartbeatInterval: number
}

export class WebSocketManager {
  private ws: WebSocket | null = null
  private config: WebSocketConfig
  private reconnectAttempts = 0
  private heartbeatTimer: NodeJS.Timeout | null = null
  private messageHandlers: Map<string, (data: any) => void> = new Map()
  private connectionState: 'connecting' | 'connected' | 'disconnected' | 'error' = 'disconnected'
  private listeners: Map<string, Set<(data: any) => void>> = new Map()

  constructor(config: WebSocketConfig) {
    this.config = config
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        resolve()
        return
      }

      this.connectionState = 'connecting'
      this.ws = new WebSocket(this.config.url)

      this.ws.onopen = () => {
        console.log('WebSocket connected to:', this.config.url)
        this.connectionState = 'connected'
        this.reconnectAttempts = 0
        this.startHeartbeat()
        resolve()
      }

      this.ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data)
          this.handleMessage(message)
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error)
        }
      }

      this.ws.onclose = (event) => {
        console.log('WebSocket disconnected:', event.code, event.reason)
        this.connectionState = 'disconnected'
        this.stopHeartbeat()
        
        if (!event.wasClean && this.reconnectAttempts < this.config.maxReconnectAttempts) {
          this.scheduleReconnect()
        }
      }

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error)
        this.connectionState = 'error'
        reject(error)
      }
    })
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect')
      this.ws = null
    }
    this.stopHeartbeat()
    this.connectionState = 'disconnected'
  }

  send(type: string, payload: any): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      const message: WebSocketMessage = {
        type,
        payload,
        timestamp: Date.now(),
        source: 'client',
      }
      this.ws.send(JSON.stringify(message))
    } else {
      console.warn('WebSocket not connected, cannot send message:', type)
    }
  }

  subscribe(eventType: string, handler: (data: any) => void): () => void {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set())
    }
    this.listeners.get(eventType)!.add(handler)

    // Return unsubscribe function
    return () => {
      const handlers = this.listeners.get(eventType)
      if (handlers) {
        handlers.delete(handler)
        if (handlers.size === 0) {
          this.listeners.delete(eventType)
        }
      }
    }
  }

  private handleMessage(message: WebSocketMessage): void {
    const handlers = this.listeners.get(message.type)
    if (handlers) {
      handlers.forEach(handler => {
        try {
          handler(message.payload)
        } catch (error) {
          console.error('Error in message handler:', error)
        }
      })
    }
  }

  private scheduleReconnect(): void {
    this.reconnectAttempts++
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000) // Exponential backoff, max 30s
    
    console.log(`Scheduling reconnect attempt ${this.reconnectAttempts} in ${delay}ms`)
    
    setTimeout(() => {
      if (this.connectionState !== 'connected') {
        this.connect().catch(error => {
          console.error('Reconnect failed:', error)
        })
      }
    }, delay)
  }

  private startHeartbeat(): void {
    this.heartbeatTimer = setInterval(() => {
      this.send('ping', { timestamp: Date.now() })
    }, this.config.heartbeatInterval)
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
  }

  getConnectionState(): string {
    return this.connectionState
  }

  isConnected(): boolean {
    return this.connectionState === 'connected' && this.ws?.readyState === WebSocket.OPEN
  }
}

// Default WebSocket configuration
export const defaultWebSocketConfig: WebSocketConfig = {
  url: process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8080/ws',
  reconnectInterval: 5000,
  maxReconnectAttempts: 10,
  heartbeatInterval: 30000,
}

// Global WebSocket manager instance
let globalWebSocketManager: WebSocketManager | null = null

export const getWebSocketManager = (): WebSocketManager => {
  if (!globalWebSocketManager) {
    globalWebSocketManager = new WebSocketManager(defaultWebSocketConfig)
  }
  return globalWebSocketManager
}

// Real-time data hooks for React components
export const useWebSocket = () => {
  const manager = getWebSocketManager()
  
  return {
    connect: () => manager.connect(),
    disconnect: () => manager.disconnect(),
    send: (type: string, payload: any) => manager.send(type, payload),
    subscribe: (eventType: string, handler: (data: any) => void) => manager.subscribe(eventType, handler),
    isConnected: () => manager.isConnected(),
    getConnectionState: () => manager.getConnectionState(),
  }
}

// Specific event types for the cybersecurity platform
export const WebSocketEvents = {
  // Security events
  THREAT_DETECTED: 'threat_detected',
  SCAN_STARTED: 'scan_started',
  SCAN_PROGRESS: 'scan_progress',
  SCAN_COMPLETED: 'scan_completed',
  VULNERABILITY_FOUND: 'vulnerability_found',
  
  // System events
  SYSTEM_STATUS: 'system_status',
  AGENT_STATUS: 'agent_status',
  NETWORK_ACTIVITY: 'network_activity',
  
  // AI events
  AI_ANALYSIS: 'ai_analysis',
  AI_RECOMMENDATION: 'ai_recommendation',
  AI_PREDICTION: 'ai_prediction',
  
  // Learning events
  LEARNING_PROGRESS: 'learning_progress',
  ACHIEVEMENT_UNLOCKED: 'achievement_unlocked',
  ASSESSMENT_COMPLETED: 'assessment_completed',
  
  // Incident events
  INCIDENT_CREATED: 'incident_created',
  INCIDENT_UPDATED: 'incident_updated',
  INCIDENT_RESOLVED: 'incident_resolved',
  
  // Compliance events
  COMPLIANCE_CHECK: 'compliance_check',
  AUDIT_COMPLETED: 'audit_completed',
  
  // General events
  NOTIFICATION: 'notification',
  HEARTBEAT: 'ping',
  ERROR: 'error',
} as const

export type WebSocketEventType = typeof WebSocketEvents[keyof typeof WebSocketEvents]
