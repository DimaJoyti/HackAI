import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import { clientStorage } from './storage'

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080'

// Create axios instance
const api: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = clientStorage.get('accessToken')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor to handle token refresh
api.interceptors.response.use(
  (response: AxiosResponse) => {
    return response
  },
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      try {
        const refreshToken = clientStorage.get('refreshToken')
        if (!refreshToken) {
          throw new Error('No refresh token available')
        }

        const response = await axios.post(`${API_BASE_URL}/api/v1/auth/refresh`, {
          refreshToken,
        })

        const { accessToken, refreshToken: newRefreshToken } = response.data

        clientStorage.set('accessToken', accessToken)
        if (newRefreshToken) {
          clientStorage.set('refreshToken', newRefreshToken)
        }

        // Retry the original request with new token
        originalRequest.headers.Authorization = `Bearer ${accessToken}`
        return api(originalRequest)
      } catch (refreshError) {
        // Refresh failed, redirect to login
        clientStorage.remove('accessToken')
        clientStorage.remove('refreshToken')
        if (typeof window !== 'undefined') {
          window.location.href = '/auth/login'
        }
        return Promise.reject(refreshError)
      }
    }

    return Promise.reject(error)
  }
)

// API methods
export const authAPI = {
  login: (email: string, password: string, rememberMe?: boolean) =>
    api.post('/auth/login', { email, password, rememberMe }),
  
  register: (data: {
    email: string
    username: string
    password: string
    firstName: string
    lastName: string
  }) => api.post('/auth/register', data),
  
  logout: () => api.post('/auth/logout'),
  
  refresh: (refreshToken: string) =>
    api.post('/auth/refresh', { refreshToken }),
  
  me: () => api.get('/auth/me'),
  
  changePassword: (oldPassword: string, newPassword: string) =>
    api.post('/auth/change-password', { oldPassword, newPassword }),
  
  forgotPassword: (email: string) =>
    api.post('/auth/forgot-password', { email }),
  
  resetPassword: (token: string, password: string) =>
    api.post('/auth/reset-password', { token, password }),
}

export const userAPI = {
  getProfile: () => api.get('/users/profile'),
  
  updateProfile: (data: any) => api.put('/users/profile', data),
  
  getUsers: (params?: { limit?: number; offset?: number; search?: string }) =>
    api.get('/users', { params }),
  
  getUser: (id: string) => api.get(`/users/${id}`),
  
  updateUserRole: (id: string, role: string) =>
    api.put(`/users/${id}/role`, { role }),
  
  updateUserStatus: (id: string, status: string) =>
    api.put(`/users/${id}/status`, { status }),
}

export const scanAPI = {
  // Vulnerability scans
  startVulnerabilityScan: (data: {
    target: string
    scanType: string
    config?: any
  }) => api.post('/scans/vulnerability', data),
  
  getVulnerabilityScans: (params?: { limit?: number; offset?: number }) =>
    api.get('/scans/vulnerability', { params }),
  
  getVulnerabilityScan: (id: string) =>
    api.get(`/scans/vulnerability/${id}`),
  
  cancelVulnerabilityScan: (id: string) =>
    api.delete(`/scans/vulnerability/${id}`),
  
  // Network scans
  startNetworkScan: (data: {
    target: string
    scanType: string
    config?: any
  }) => api.post('/scans/network', data),
  
  getNetworkScans: (params?: { limit?: number; offset?: number }) =>
    api.get('/scans/network', { params }),
  
  getNetworkScan: (id: string) =>
    api.get(`/scans/network/${id}`),
  
  cancelNetworkScan: (id: string) =>
    api.delete(`/scans/network/${id}`),
}

export const vulnerabilityAPI = {
  getVulnerabilities: (params?: {
    scanId?: string
    severity?: string
    status?: string
    limit?: number
    offset?: number
  }) => api.get('/vulnerabilities', { params }),
  
  getVulnerability: (id: string) =>
    api.get(`/vulnerabilities/${id}`),
  
  updateVulnerabilityStatus: (id: string, status: string) =>
    api.put(`/vulnerabilities/${id}/status`, { status }),
}

export const systemAPI = {
  getStats: () => api.get('/admin/stats'),
  
  getHealth: () => api.get('/health'),
  
  getMetrics: () => api.get('/metrics'),
}

// WebSocket connection
export const createWebSocketConnection = (endpoint: string): WebSocket | null => {
  if (typeof window === 'undefined') {
    return null
  }
  
  const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8080'
  const token = clientStorage.get('accessToken')
  
  const ws = new WebSocket(`${wsUrl}/api/v1/ws/${endpoint}?token=${token}`)
  
  ws.onopen = () => {
    console.log(`WebSocket connected to ${endpoint}`)
  }
  
  ws.onclose = () => {
    console.log(`WebSocket disconnected from ${endpoint}`)
  }
  
  ws.onerror = (error) => {
    console.error(`WebSocket error on ${endpoint}:`, error)
  }
  
  return ws
}

// File upload helper
export const uploadFile = async (
  file: File,
  endpoint: string,
  onProgress?: (progress: number) => void
): Promise<AxiosResponse> => {
  const formData = new FormData()
  formData.append('file', file)
  
  return api.post(endpoint, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      if (onProgress && progressEvent.total) {
        const progress = Math.round(
          (progressEvent.loaded * 100) / progressEvent.total
        )
        onProgress(progress)
      }
    },
  })
}

// Export the main api instance
export { api }
export default api
