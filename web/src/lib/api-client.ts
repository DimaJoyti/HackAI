/**
 * API client for integrating with Go microservices backend
 * Handles authentication, caching, and error handling
 */

export interface ApiResponse<T = any> {
  data: T
  success: boolean
  message?: string
  error?: string
  timestamp: number
}

export interface ApiError {
  code: string
  message: string
  details?: any
}

export interface RequestConfig {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'
  headers?: Record<string, string>
  body?: any
  timeout?: number
  cache?: boolean
  retries?: number
}

class ApiClient {
  private baseUrl: string
  private defaultHeaders: Record<string, string>
  private cache: Map<string, { data: any; timestamp: number; ttl: number }> = new Map()
  private authToken: string | null = null

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl
    this.defaultHeaders = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    }
  }

  setAuthToken(token: string): void {
    this.authToken = token
    this.defaultHeaders['Authorization'] = `Bearer ${token}`
  }

  clearAuthToken(): void {
    this.authToken = null
    delete this.defaultHeaders['Authorization']
  }

  async request<T = any>(
    endpoint: string,
    config: RequestConfig = {}
  ): Promise<ApiResponse<T>> {
    const {
      method = 'GET',
      headers = {},
      body,
      timeout = 10000,
      cache = false,
      retries = 3,
    } = config

    const url = `${this.baseUrl}${endpoint}`
    const cacheKey = `${method}:${url}:${JSON.stringify(body)}`

    // Check cache for GET requests
    if (method === 'GET' && cache) {
      const cached = this.getFromCache(cacheKey)
      if (cached) {
        return cached
      }
    }

    const requestHeaders = {
      ...this.defaultHeaders,
      ...headers,
    }

    const requestConfig: RequestInit = {
      method,
      headers: requestHeaders,
      signal: AbortSignal.timeout(timeout),
    }

    if (body && method !== 'GET') {
      requestConfig.body = JSON.stringify(body)
    }

    let lastError: Error | null = null

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const response = await fetch(url, requestConfig)
        
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}))
          throw new Error(`HTTP ${response.status}: ${errorData.message || response.statusText}`)
        }

        const data = await response.json()
        const result: ApiResponse<T> = {
          data,
          success: true,
          timestamp: Date.now(),
        }

        // Cache successful GET requests
        if (method === 'GET' && cache) {
          this.setCache(cacheKey, result, 300000) // 5 minutes TTL
        }

        return result
      } catch (error) {
        lastError = error as Error
        
        if (attempt < retries) {
          // Exponential backoff
          const delay = Math.min(1000 * Math.pow(2, attempt), 10000)
          await new Promise(resolve => setTimeout(resolve, delay))
        }
      }
    }

    return {
      data: null as T,
      success: false,
      error: lastError?.message || 'Request failed',
      timestamp: Date.now(),
    }
  }

  // Security API endpoints
  async getSecurityMetrics(): Promise<ApiResponse<any>> {
    return this.request('/api/security/metrics', { cache: true })
  }

  async getThreatData(): Promise<ApiResponse<any>> {
    return this.request('/api/security/threats', { cache: true })
  }

  async startScan(scanConfig: any): Promise<ApiResponse<any>> {
    return this.request('/api/scans', {
      method: 'POST',
      body: scanConfig,
    })
  }

  async getScanStatus(scanId: string): Promise<ApiResponse<any>> {
    return this.request(`/api/scans/${scanId}`, { cache: true })
  }

  async getVulnerabilities(): Promise<ApiResponse<any>> {
    return this.request('/api/vulnerabilities', { cache: true })
  }

  // AI API endpoints
  async getAIRecommendations(): Promise<ApiResponse<any>> {
    return this.request('/api/ai/recommendations', { cache: true })
  }

  async getAIPredictions(): Promise<ApiResponse<any>> {
    return this.request('/api/ai/predictions', { cache: true })
  }

  async getAIAgentStatus(): Promise<ApiResponse<any>> {
    return this.request('/api/ai/agents', { cache: true })
  }

  // Learning API endpoints
  async getLearningProgress(userId: string): Promise<ApiResponse<any>> {
    return this.request(`/api/learning/progress/${userId}`, { cache: true })
  }

  async getAchievements(userId: string): Promise<ApiResponse<any>> {
    return this.request(`/api/learning/achievements/${userId}`, { cache: true })
  }

  async getSkillAssessments(userId: string): Promise<ApiResponse<any>> {
    return this.request(`/api/learning/assessments/${userId}`, { cache: true })
  }

  // Incident API endpoints
  async getIncidents(): Promise<ApiResponse<any>> {
    return this.request('/api/incidents', { cache: true })
  }

  async createIncident(incident: any): Promise<ApiResponse<any>> {
    return this.request('/api/incidents', {
      method: 'POST',
      body: incident,
    })
  }

  async updateIncident(incidentId: string, updates: any): Promise<ApiResponse<any>> {
    return this.request(`/api/incidents/${incidentId}`, {
      method: 'PATCH',
      body: updates,
    })
  }

  // Compliance API endpoints
  async getComplianceStatus(): Promise<ApiResponse<any>> {
    return this.request('/api/compliance/status', { cache: true })
  }

  async runComplianceAudit(framework: string): Promise<ApiResponse<any>> {
    return this.request('/api/compliance/audit', {
      method: 'POST',
      body: { framework },
    })
  }

  // System API endpoints
  async getSystemStatus(): Promise<ApiResponse<any>> {
    return this.request('/api/system/status', { cache: true })
  }

  async getNetworkStatus(): Promise<ApiResponse<any>> {
    return this.request('/api/network/status', { cache: true })
  }

  // Reports API endpoints
  async getReports(): Promise<ApiResponse<any>> {
    return this.request('/api/reports', { cache: true })
  }

  async generateReport(reportConfig: any): Promise<ApiResponse<any>> {
    return this.request('/api/reports/generate', {
      method: 'POST',
      body: reportConfig,
    })
  }

  // Cache management
  private getFromCache(key: string): ApiResponse<any> | null {
    const cached = this.cache.get(key)
    if (cached && Date.now() - cached.timestamp < cached.ttl) {
      return cached.data
    }
    this.cache.delete(key)
    return null
  }

  private setCache(key: string, data: ApiResponse<any>, ttl: number): void {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl,
    })
  }

  clearCache(): void {
    this.cache.clear()
  }

  // Health check
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.request('/health', { timeout: 5000 })
      return response.success
    } catch {
      return false
    }
  }
}

// Default API client configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080'

// Global API client instance
export const apiClient = new ApiClient(API_BASE_URL)

// React hook for API client
export const useApiClient = () => {
  return apiClient
}

// Error handling utilities
export const handleApiError = (error: ApiResponse<any>): string => {
  if (error.error) {
    return error.error
  }
  return 'An unexpected error occurred'
}

export const isApiError = (response: ApiResponse<any>): boolean => {
  return !response.success
}

// Type definitions for common API responses
export interface SecurityMetrics {
  threatLevel: number
  systemHealth: number
  activeScans: number
  vulnerabilities: number
  incidents: number
}

export interface ThreatData {
  id: string
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  timestamp: string
  status: 'active' | 'mitigated' | 'resolved'
}

export interface ScanResult {
  id: string
  type: string
  status: 'running' | 'completed' | 'failed'
  progress: number
  vulnerabilities: number
  startTime: string
  endTime?: string
}

export interface AIRecommendation {
  id: string
  type: string
  title: string
  description: string
  priority: 'low' | 'medium' | 'high' | 'critical'
  confidence: number
  actionRequired: boolean
}

export interface LearningProgress {
  userId: string
  totalProgress: number
  completedModules: number
  totalModules: number
  skillLevels: Record<string, number>
  achievements: string[]
}
