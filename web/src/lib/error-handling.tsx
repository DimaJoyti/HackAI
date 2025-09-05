/**
 * Comprehensive error handling utilities for the cybersecurity dashboard
 */

import { useDashboardStore } from '@/stores/dashboard-store'

// Error types
export enum ErrorType {
  NETWORK = 'NETWORK',
  AUTHENTICATION = 'AUTHENTICATION',
  AUTHORIZATION = 'AUTHORIZATION',
  VALIDATION = 'VALIDATION',
  SERVER = 'SERVER',
  CLIENT = 'CLIENT',
  WEBSOCKET = 'WEBSOCKET',
  UNKNOWN = 'UNKNOWN',
}

export enum ErrorSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export interface AppError {
  id: string
  type: ErrorType
  severity: ErrorSeverity
  message: string
  details?: any
  timestamp: Date
  source: string
  stack?: string
  userAgent?: string
  url?: string
  userId?: string
}

// Error classification
export function classifyError(error: any): { type: ErrorType; severity: ErrorSeverity } {
  if (error?.response?.status) {
    const status = error.response.status
    
    if (status === 401) {
      return { type: ErrorType.AUTHENTICATION, severity: ErrorSeverity.HIGH }
    }
    
    if (status === 403) {
      return { type: ErrorType.AUTHORIZATION, severity: ErrorSeverity.HIGH }
    }
    
    if (status >= 400 && status < 500) {
      return { type: ErrorType.CLIENT, severity: ErrorSeverity.MEDIUM }
    }
    
    if (status >= 500) {
      return { type: ErrorType.SERVER, severity: ErrorSeverity.HIGH }
    }
  }
  
  if (error?.code === 'NETWORK_ERROR' || error?.message?.includes('fetch')) {
    return { type: ErrorType.NETWORK, severity: ErrorSeverity.MEDIUM }
  }
  
  if (error?.name === 'ValidationError') {
    return { type: ErrorType.VALIDATION, severity: ErrorSeverity.LOW }
  }
  
  return { type: ErrorType.UNKNOWN, severity: ErrorSeverity.MEDIUM }
}

// Error logger
export class ErrorLogger {
  private static instance: ErrorLogger
  private errors: AppError[] = []
  private maxErrors = 100

  static getInstance(): ErrorLogger {
    if (!ErrorLogger.instance) {
      ErrorLogger.instance = new ErrorLogger()
    }
    return ErrorLogger.instance
  }

  log(error: any, source: string, additionalInfo?: any): AppError {
    const { type, severity } = classifyError(error)
    
    const appError: AppError = {
      id: Math.random().toString(36).substring(2, 11),
      type,
      severity,
      message: error?.message || error?.toString() || 'Unknown error',
      details: additionalInfo,
      timestamp: new Date(),
      source,
      stack: error?.stack,
      userAgent: typeof window !== 'undefined' ? window.navigator.userAgent : undefined,
      url: typeof window !== 'undefined' ? window.location.href : undefined,
    }

    this.errors.unshift(appError)
    
    // Keep only the latest errors
    if (this.errors.length > this.maxErrors) {
      this.errors = this.errors.slice(0, this.maxErrors)
    }

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error(`[${severity}] ${type}: ${appError.message}`, {
        error,
        appError,
        additionalInfo,
      })
    }

    // Send to monitoring service in production
    if (process.env.NODE_ENV === 'production') {
      this.sendToMonitoring(appError)
    }

    // Add notification for critical errors
    if (severity === ErrorSeverity.CRITICAL || severity === ErrorSeverity.HIGH) {
      this.addErrorNotification(appError)
    }

    return appError
  }

  private sendToMonitoring(error: AppError): void {
    // In a real application, send to services like Sentry, LogRocket, etc.
    try {
      fetch('/api/errors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(error),
      }).catch(() => {
        // Silently fail if error reporting fails
      })
    } catch {
      // Silently fail
    }
  }

  private addErrorNotification(error: AppError): void {
    const { addNotification } = useDashboardStore.getState()
    
    addNotification({
      type: 'error',
      title: `${error.type} Error`,
      message: error.message,
      priority: error.severity.toLowerCase() as 'low' | 'medium' | 'high' | 'critical',
      actionRequired: error.severity === ErrorSeverity.CRITICAL,
    })
  }

  getErrors(): AppError[] {
    return [...this.errors]
  }

  getErrorsByType(type: ErrorType): AppError[] {
    return this.errors.filter(error => error.type === type)
  }

  getErrorsBySeverity(severity: ErrorSeverity): AppError[] {
    return this.errors.filter(error => error.severity === severity)
  }

  clearErrors(): void {
    this.errors = []
  }

  getErrorStats(): {
    total: number
    byType: Record<ErrorType, number>
    bySeverity: Record<ErrorSeverity, number>
    recent: number // Last hour
  } {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000)
    
    const stats = {
      total: this.errors.length,
      byType: {} as Record<ErrorType, number>,
      bySeverity: {} as Record<ErrorSeverity, number>,
      recent: this.errors.filter(error => error.timestamp > oneHourAgo).length,
    }

    // Initialize counters
    Object.values(ErrorType).forEach(type => {
      stats.byType[type] = 0
    })
    
    Object.values(ErrorSeverity).forEach(severity => {
      stats.bySeverity[severity] = 0
    })

    // Count errors
    this.errors.forEach(error => {
      stats.byType[error.type]++
      stats.bySeverity[error.severity]++
    })

    return stats
  }
}

// Global error logger instance
export const errorLogger = ErrorLogger.getInstance()

// Error handling utilities
export function handleApiError(error: any, source: string): void {
  errorLogger.log(error, source)
}

export function handleWebSocketError(error: any): void {
  errorLogger.log(error, 'WebSocket')
}

export function handleComponentError(error: any, componentName: string): void {
  errorLogger.log(error, `Component: ${componentName}`)
}

// React error boundary component
import React from 'react'

interface ErrorBoundaryState {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends React.Component<
  React.PropsWithChildren<{ fallback?: React.ComponentType<{ error: Error; reset: () => void }> }>,
  ErrorBoundaryState
> {
  constructor(props: any) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    errorLogger.log(error, 'React Error Boundary', errorInfo)
  }

  render() {
    if (this.state.hasError && this.state.error) {
      const FallbackComponent = this.props.fallback || DefaultErrorFallback
      
      return (
        <FallbackComponent
          error={this.state.error}
          reset={() => this.setState({ hasError: false, error: null })}
        />
      )
    }

    return this.props.children
  }
}

// Default error fallback component
function DefaultErrorFallback({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-matrix-black">
      <div className="max-w-md w-full mx-auto p-6">
        <div className="bg-security-critical/10 border border-security-critical/30 rounded-lg p-6">
          <div className="flex items-center mb-4">
            <div className="w-12 h-12 bg-security-critical/20 rounded-lg flex items-center justify-center mr-4">
              <span className="text-security-critical text-xl">⚠️</span>
            </div>
            <div>
              <h2 className="text-lg font-cyber font-bold text-matrix-white">
                System Error Detected
              </h2>
              <p className="text-sm text-matrix-light">
                An unexpected error has occurred
              </p>
            </div>
          </div>
          
          <div className="bg-matrix-surface rounded p-3 mb-4">
            <p className="text-xs font-matrix text-matrix-light break-all">
              {error.message}
            </p>
          </div>
          
          <div className="flex gap-3">
            <button
              onClick={reset}
              className="flex-1 bg-cyber-blue-neon/20 border border-cyber-blue-neon/30 rounded px-4 py-2 text-sm font-cyber text-cyber-blue-neon hover:bg-cyber-blue-neon/30 transition-colors"
            >
              Retry
            </button>
            <button
              onClick={() => window.location.reload()}
              className="flex-1 bg-security-critical/20 border border-security-critical/30 rounded px-4 py-2 text-sm font-cyber text-security-critical hover:bg-security-critical/30 transition-colors"
            >
              Reload Page
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// React hooks for error handling
export function useErrorHandler() {
  return {
    handleError: (error: any, source: string) => errorLogger.log(error, source),
    getErrors: () => errorLogger.getErrors(),
    getErrorStats: () => errorLogger.getErrorStats(),
    clearErrors: () => errorLogger.clearErrors(),
  }
}

// Async error handler for promises
export function withErrorHandling<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  source: string
): T {
  return (async (...args: Parameters<T>) => {
    try {
      return await fn(...args)
    } catch (error) {
      errorLogger.log(error, source)
      throw error
    }
  }) as T
}

// Retry utility with exponential backoff
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  baseDelay: number = 1000,
  source: string = 'Retry'
): Promise<T> {
  let lastError: any

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error
      
      if (attempt === maxRetries) {
        errorLogger.log(error, `${source} (Final attempt)`)
        throw error
      }

      const delay = baseDelay * Math.pow(2, attempt)
      await new Promise(resolve => setTimeout(resolve, delay))
    }
  }

  throw lastError
}
