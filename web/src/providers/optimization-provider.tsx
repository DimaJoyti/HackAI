'use client'

import React, { createContext, useContext, useEffect, ReactNode } from 'react'
import { ErrorBoundary, errorLogger } from '@/lib/error-handling'
import { PerformanceMonitor, globalCache } from '@/lib/performance'
import { useDashboardStore } from '@/stores/dashboard-store'

interface OptimizationContextType {
  performanceMetrics: Record<string, any>
  errorStats: any
  cacheStats: { size: number; hitRate: number }
  memoryUsage: any
}

const OptimizationContext = createContext<OptimizationContextType | undefined>(undefined)

interface OptimizationProviderProps {
  children: ReactNode
  enablePerformanceMonitoring?: boolean
  enableErrorTracking?: boolean
  enableCaching?: boolean
}

export function OptimizationProvider({
  children,
  enablePerformanceMonitoring = true,
  enableErrorTracking = true,
  enableCaching = true,
}: OptimizationProviderProps) {
  const [performanceMetrics, setPerformanceMetrics] = React.useState<Record<string, any>>({})
  const [errorStats, setErrorStats] = React.useState<any>({})
  const [cacheStats, setCacheStats] = React.useState({ size: 0, hitRate: 0 })
  const [memoryUsage, setMemoryUsage] = React.useState<any>(null)

  // Initialize performance monitoring
  useEffect(() => {
    if (!enablePerformanceMonitoring) return

    const monitor = PerformanceMonitor.getInstance()
    monitor.startMonitoring()

    const updateMetrics = () => {
      setPerformanceMetrics(monitor.getAllMetrics())
    }

    // Update metrics every 5 seconds
    const interval = setInterval(updateMetrics, 5000)

    return () => {
      clearInterval(interval)
      monitor.stopMonitoring()
    }
  }, [enablePerformanceMonitoring])

  // Monitor error statistics
  useEffect(() => {
    if (!enableErrorTracking) return

    const updateErrorStats = () => {
      setErrorStats(errorLogger.getErrorStats())
    }

    // Update error stats every 10 seconds
    const interval = setInterval(updateErrorStats, 10000)
    updateErrorStats() // Initial update

    return () => clearInterval(interval)
  }, [enableErrorTracking])

  // Monitor cache performance
  useEffect(() => {
    if (!enableCaching) return

    let cacheHits = 0
    let cacheMisses = 0

    // Monkey patch cache methods to track hit rate
    const originalGet = globalCache.get.bind(globalCache)
    globalCache.get = function(key: string) {
      const result = originalGet(key)
      if (result !== null) {
        cacheHits++
      } else {
        cacheMisses++
      }
      return result
    }

    const updateCacheStats = () => {
      const total = cacheHits + cacheMisses
      setCacheStats({
        size: globalCache.size(),
        hitRate: total > 0 ? (cacheHits / total) * 100 : 0,
      })
    }

    const interval = setInterval(updateCacheStats, 5000)
    updateCacheStats() // Initial update

    return () => {
      clearInterval(interval)
      // Restore original method
      globalCache.get = originalGet
    }
  }, [enableCaching])

  // Monitor memory usage
  useEffect(() => {
    const updateMemoryUsage = () => {
      if ('memory' in performance) {
        const memory = (performance as any).memory
        setMemoryUsage({
          usedJSHeapSize: memory.usedJSHeapSize,
          totalJSHeapSize: memory.totalJSHeapSize,
          jsHeapSizeLimit: memory.jsHeapSizeLimit,
          usagePercentage: (memory.usedJSHeapSize / memory.jsHeapSizeLimit) * 100,
        })
      }
    }

    updateMemoryUsage()
    const interval = setInterval(updateMemoryUsage, 10000)

    return () => clearInterval(interval)
  }, [])

  // Global error handler
  useEffect(() => {
    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      errorLogger.log(event.reason, 'Unhandled Promise Rejection')
      event.preventDefault()
    }

    const handleError = (event: ErrorEvent) => {
      errorLogger.log(event.error, 'Global Error Handler')
    }

    window.addEventListener('unhandledrejection', handleUnhandledRejection)
    window.addEventListener('error', handleError)

    return () => {
      window.removeEventListener('unhandledrejection', handleUnhandledRejection)
      window.removeEventListener('error', handleError)
    }
  }, [])

  // Performance optimization warnings
  useEffect(() => {
    const checkPerformance = () => {
      // Check memory usage
      if (memoryUsage && memoryUsage.usagePercentage > 80) {
        console.warn('High memory usage detected:', memoryUsage.usagePercentage.toFixed(1) + '%')
        
        // Add notification for high memory usage
        const { addNotification } = useDashboardStore.getState()
        addNotification({
          type: 'warning',
          title: 'High Memory Usage',
          message: `Memory usage is at ${memoryUsage.usagePercentage.toFixed(1)}%. Consider refreshing the page.`,
          priority: 'medium',
          actionRequired: false,
        })
      }

      // Check error rate
      if (errorStats.recent > 10) {
        console.warn('High error rate detected:', errorStats.recent, 'errors in the last hour')
        
        const { addNotification } = useDashboardStore.getState()
        addNotification({
          type: 'error',
          title: 'High Error Rate',
          message: `${errorStats.recent} errors detected in the last hour. System stability may be affected.`,
          priority: 'high',
          actionRequired: true,
        })
      }

      // Check cache hit rate
      if (cacheStats.hitRate < 50 && cacheStats.size > 0) {
        console.warn('Low cache hit rate:', cacheStats.hitRate.toFixed(1) + '%')
      }
    }

    const interval = setInterval(checkPerformance, 30000) // Check every 30 seconds
    return () => clearInterval(interval)
  }, [memoryUsage, errorStats, cacheStats])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      // Clear cache periodically to prevent memory leaks
      globalCache.clear()
      errorLogger.clearErrors()
    }
  }, [])

  const contextValue: OptimizationContextType = {
    performanceMetrics,
    errorStats,
    cacheStats,
    memoryUsage,
  }

  return (
    <OptimizationContext.Provider value={contextValue}>
      <ErrorBoundary>
        {children}
      </ErrorBoundary>
    </OptimizationContext.Provider>
  )
}

// Hook to use optimization context
export function useOptimization(): OptimizationContextType {
  const context = useContext(OptimizationContext)
  if (context === undefined) {
    throw new Error('useOptimization must be used within an OptimizationProvider')
  }
  return context
}

// Performance monitoring component
export function PerformanceMonitorDisplay(): JSX.Element {
  const { performanceMetrics, errorStats, cacheStats, memoryUsage } = useOptimization()

  if (process.env.NODE_ENV !== 'development') {
    return <></>
  }

  return (
    <div className="fixed bottom-4 right-4 bg-matrix-black/90 border border-cyber-blue-neon/30 rounded-lg p-3 text-xs font-matrix max-w-xs z-50">
      <h4 className="text-cyber-blue-neon font-cyber font-bold mb-2">Performance Monitor</h4>
      
      {/* Memory Usage */}
      {memoryUsage && (
        <div className="mb-2">
          <div className="text-matrix-light">Memory Usage:</div>
          <div className="text-cyber-green-neon">
            {(memoryUsage.usedJSHeapSize / 1024 / 1024).toFixed(1)}MB / 
            {(memoryUsage.jsHeapSizeLimit / 1024 / 1024).toFixed(1)}MB
          </div>
          <div className="w-full bg-matrix-surface rounded-full h-1 mt-1">
            <div 
              className="bg-cyber-green-neon h-1 rounded-full transition-all duration-300"
              style={{ width: `${Math.min(memoryUsage.usagePercentage, 100)}%` }}
            />
          </div>
        </div>
      )}

      {/* Cache Stats */}
      <div className="mb-2">
        <div className="text-matrix-light">Cache:</div>
        <div className="text-cyber-blue-neon">
          Size: {cacheStats.size} | Hit Rate: {cacheStats.hitRate.toFixed(1)}%
        </div>
      </div>

      {/* Error Stats */}
      <div className="mb-2">
        <div className="text-matrix-light">Errors:</div>
        <div className="text-security-critical">
          Total: {errorStats.total} | Recent: {errorStats.recent}
        </div>
      </div>

      {/* Performance Metrics */}
      {Object.keys(performanceMetrics).length > 0 && (
        <div>
          <div className="text-matrix-light">Performance:</div>
          {Object.entries(performanceMetrics).slice(0, 3).map(([key, value]: [string, any]) => (
            <div key={key} className="text-cyber-orange-neon">
              {key}: {value?.avg?.toFixed(1)}ms
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// Optimization utilities
export const optimizationUtils = {
  // Preload critical resources
  preloadResource: (url: string, type: 'script' | 'style' | 'image' | 'font' = 'script') => {
    const link = document.createElement('link')
    link.rel = 'preload'
    link.href = url
    link.as = type
    if (type === 'font') {
      link.crossOrigin = 'anonymous'
    }
    document.head.appendChild(link)
  },

  // Lazy load images
  lazyLoadImage: (src: string, placeholder?: string): Promise<HTMLImageElement> => {
    return new Promise((resolve, reject) => {
      const img = new Image()
      img.onload = () => resolve(img)
      img.onerror = reject
      img.src = src
    })
  },

  // Debounce function calls
  debounce: <T extends (...args: any[]) => any>(func: T, wait: number): T => {
    let timeout: NodeJS.Timeout
    return ((...args: Parameters<T>) => {
      clearTimeout(timeout)
      timeout = setTimeout(() => func(...args), wait)
    }) as T
  },

  // Throttle function calls
  throttle: <T extends (...args: any[]) => any>(func: T, limit: number): T => {
    let inThrottle: boolean
    return ((...args: Parameters<T>) => {
      if (!inThrottle) {
        func(...args)
        inThrottle = true
        setTimeout(() => inThrottle = false, limit)
      }
    }) as T
  },

  // Measure function execution time
  measureTime: async function <T>(name: string, fn: () => Promise<T>): Promise<T> {
    const start = performance.now()
    try {
      const result = await fn()
      const duration = performance.now() - start
      PerformanceMonitor.getInstance().recordMetric(name, duration)
      return result
    } catch (error) {
      const duration = performance.now() - start
      PerformanceMonitor.getInstance().recordMetric(`${name}-error`, duration)
      throw error
    }
  },
}
