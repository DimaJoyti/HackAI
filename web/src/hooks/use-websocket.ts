import { useEffect, useRef, useState, useCallback } from 'react'

export type ConnectionStatus = 'Connecting' | 'Connected' | 'Disconnected' | 'Error'

interface UseWebSocketOptions {
  onOpen?: (event: Event) => void
  onClose?: (event: CloseEvent) => void
  onMessage?: (event: MessageEvent) => void
  onError?: (event: Event) => void
  shouldReconnect?: (closeEvent: CloseEvent) => boolean
  reconnectInterval?: number
  reconnectAttempts?: number
  protocols?: string | string[]
}

interface UseWebSocketReturn {
  sendMessage: (message: string | object) => void
  sendJsonMessage: (message: object) => void
  lastMessage: MessageEvent | null
  connectionStatus: ConnectionStatus
  readyState: number
  getWebSocket: () => WebSocket | null
}

const DEFAULT_OPTIONS: UseWebSocketOptions = {
  shouldReconnect: () => true,
  reconnectInterval: 3000,
  reconnectAttempts: 10,
}

export function useWebSocket(
  url: string | null,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn {
  const {
    onOpen,
    onClose,
    onMessage,
    onError,
    shouldReconnect = DEFAULT_OPTIONS.shouldReconnect!,
    reconnectInterval = DEFAULT_OPTIONS.reconnectInterval!,
    reconnectAttempts = DEFAULT_OPTIONS.reconnectAttempts!,
    protocols,
  } = { ...DEFAULT_OPTIONS, ...options }

  const [lastMessage, setLastMessage] = useState<MessageEvent | null>(null)
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('Disconnected')
  const [readyState, setReadyState] = useState<number>(WebSocket.CLOSED)
  
  const webSocketRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const reconnectAttemptsRef = useRef<number>(0)
  const urlRef = useRef<string | null>(url)

  // Update URL ref when URL changes
  useEffect(() => {
    urlRef.current = url
  }, [url])

  const connect = useCallback(() => {
    if (!urlRef.current) return

    try {
      setConnectionStatus('Connecting')
      
      const ws = new WebSocket(urlRef.current, protocols)
      webSocketRef.current = ws

      ws.onopen = (event) => {
        setConnectionStatus('Connected')
        setReadyState(WebSocket.OPEN)
        reconnectAttemptsRef.current = 0
        onOpen?.(event)
      }

      ws.onclose = (event) => {
        setConnectionStatus('Disconnected')
        setReadyState(WebSocket.CLOSED)
        webSocketRef.current = null
        onClose?.(event)

        // Attempt to reconnect if conditions are met
        if (
          shouldReconnect(event) &&
          reconnectAttemptsRef.current < reconnectAttempts &&
          urlRef.current
        ) {
          reconnectAttemptsRef.current++
          reconnectTimeoutRef.current = setTimeout(() => {
            connect()
          }, reconnectInterval)
        }
      }

      ws.onmessage = (event) => {
        setLastMessage(event)
        onMessage?.(event)
      }

      ws.onerror = (event) => {
        setConnectionStatus('Error')
        setReadyState(WebSocket.CLOSED)
        onError?.(event)
      }

      // Update ready state when it changes
      const checkReadyState = () => {
        if (ws.readyState !== readyState) {
          setReadyState(ws.readyState)
        }
      }

      const readyStateInterval = setInterval(checkReadyState, 100)

      return () => {
        clearInterval(readyStateInterval)
      }
    } catch (error) {
      setConnectionStatus('Error')
      setReadyState(WebSocket.CLOSED)
      console.error('WebSocket connection error:', error)
    }
  }, [
    protocols,
    onOpen,
    onClose,
    onMessage,
    onError,
    shouldReconnect,
    reconnectInterval,
    reconnectAttempts,
    readyState,
  ])

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    if (webSocketRef.current) {
      webSocketRef.current.close()
      webSocketRef.current = null
    }

    setConnectionStatus('Disconnected')
    setReadyState(WebSocket.CLOSED)
  }, [])

  const sendMessage = useCallback((message: string | object) => {
    if (webSocketRef.current?.readyState === WebSocket.OPEN) {
      const messageToSend = typeof message === 'string' ? message : JSON.stringify(message)
      webSocketRef.current.send(messageToSend)
    } else {
      console.warn('WebSocket is not connected. Message not sent:', message)
    }
  }, [])

  const sendJsonMessage = useCallback((message: object) => {
    sendMessage(JSON.stringify(message))
  }, [sendMessage])

  const getWebSocket = useCallback(() => {
    return webSocketRef.current
  }, [])

  // Connect when URL is provided and component mounts
  useEffect(() => {
    if (url) {
      connect()
    }

    return () => {
      disconnect()
    }
  }, [url, connect, disconnect])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      if (webSocketRef.current) {
        webSocketRef.current.close()
      }
    }
  }, [])

  return {
    sendMessage,
    sendJsonMessage,
    lastMessage,
    connectionStatus,
    readyState,
    getWebSocket,
  }
}

// Hook for managing multiple WebSocket connections
export function useWebSocketManager() {
  const [connections, setConnections] = useState<Map<string, WebSocket>>(new Map())

  const addConnection = useCallback((id: string, url: string, protocols?: string | string[]) => {
    const ws = new WebSocket(url, protocols)
    
    ws.onopen = () => {
      setConnections(prev => new Map(prev).set(id, ws))
    }

    ws.onclose = () => {
      setConnections(prev => {
        const newMap = new Map(prev)
        newMap.delete(id)
        return newMap
      })
    }

    return ws
  }, [])

  const removeConnection = useCallback((id: string) => {
    const ws = connections.get(id)
    if (ws) {
      ws.close()
      setConnections(prev => {
        const newMap = new Map(prev)
        newMap.delete(id)
        return newMap
      })
    }
  }, [connections])

  const sendToConnection = useCallback((id: string, message: string | object) => {
    const ws = connections.get(id)
    if (ws && ws.readyState === WebSocket.OPEN) {
      const messageToSend = typeof message === 'string' ? message : JSON.stringify(message)
      ws.send(messageToSend)
    }
  }, [connections])

  const broadcastMessage = useCallback((message: string | object) => {
    const messageToSend = typeof message === 'string' ? message : JSON.stringify(message)
    connections.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(messageToSend)
      }
    })
  }, [connections])

  const getConnection = useCallback((id: string) => {
    return connections.get(id) || null
  }, [connections])

  const getConnectionStatus = useCallback((id: string) => {
    const ws = connections.get(id)
    if (!ws) return 'Disconnected'
    
    switch (ws.readyState) {
      case WebSocket.CONNECTING:
        return 'Connecting'
      case WebSocket.OPEN:
        return 'Connected'
      case WebSocket.CLOSING:
        return 'Disconnected'
      case WebSocket.CLOSED:
        return 'Disconnected'
      default:
        return 'Disconnected'
    }
  }, [connections])

  const closeAllConnections = useCallback(() => {
    connections.forEach(ws => ws.close())
    setConnections(new Map())
  }, [connections])

  useEffect(() => {
    return () => {
      closeAllConnections()
    }
  }, [closeAllConnections])

  return {
    addConnection,
    removeConnection,
    sendToConnection,
    broadcastMessage,
    getConnection,
    getConnectionStatus,
    closeAllConnections,
    connections: Array.from(connections.keys()),
  }
}

// Utility hook for WebSocket with automatic JSON parsing
export function useWebSocketJSON<T = any>(
  url: string | null,
  options: Omit<UseWebSocketOptions, 'onMessage'> & {
    onMessage?: (data: T) => void
  } = {}
) {
  const { onMessage, ...restOptions } = options
  const [lastJsonMessage, setLastJsonMessage] = useState<T | null>(null)

  const webSocketReturn = useWebSocket(url, {
    ...restOptions,
    onMessage: (event) => {
      try {
        const data = JSON.parse(event.data)
        setLastJsonMessage(data)
        onMessage?.(data)
      } catch (error) {
        console.error('Failed to parse WebSocket message as JSON:', error)
      }
    },
  })

  return {
    ...webSocketReturn,
    lastJsonMessage,
    sendJsonMessage: webSocketReturn.sendJsonMessage,
  }
}
