'use client'

import { useState, useEffect, createContext, useContext, ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import { api } from '@/lib/api'
import { clientStorage } from '@/lib/storage'

interface User {
  id: string
  email: string
  username: string
  firstName: string
  lastName: string
  role: 'admin' | 'moderator' | 'user' | 'guest'
  status: 'active' | 'inactive' | 'suspended' | 'pending'
  avatar?: string
  createdAt: string
  updatedAt: string
}

interface AuthContextType {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>
  register: (data: RegisterData) => Promise<void>
  logout: () => Promise<void>
  refreshToken: () => Promise<void>
  updateProfile: (data: Partial<User>) => Promise<void>
}

interface RegisterData {
  email: string
  username: string
  password: string
  firstName: string
  lastName: string
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const router = useRouter()

  const isAuthenticated = !!user

  // Check for existing session on mount
  useEffect(() => {
    checkAuth()
  }, [])

  const checkAuth = async () => {
    try {
      const token = clientStorage.get('accessToken')
      if (!token) {
        setIsLoading(false)
        return
      }

      const response = await api.get('/auth/me')
      setUser(response.data.user)
    } catch (error) {
      // Token is invalid, remove it
      clientStorage.remove('accessToken')
      clientStorage.remove('refreshToken')
    } finally {
      setIsLoading(false)
    }
  }

  const login = async (email: string, password: string, rememberMe = false) => {
    setIsLoading(true)
    try {
      const response = await api.post('/auth/login', {
        email,
        password,
        rememberMe,
      })

      const { user, accessToken, refreshToken } = response.data

      // Store tokens
      clientStorage.set('accessToken', accessToken)
      if (refreshToken) {
        clientStorage.set('refreshToken', refreshToken)
      }

      setUser(user)
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Login failed')
    } finally {
      setIsLoading(false)
    }
  }

  const register = async (data: RegisterData) => {
    setIsLoading(true)
    try {
      const response = await api.post('/auth/register', data)
      const { user, accessToken, refreshToken } = response.data

      // Store tokens
      clientStorage.set('accessToken', accessToken)
      if (refreshToken) {
        clientStorage.set('refreshToken', refreshToken)
      }

      setUser(user)
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Registration failed')
    } finally {
      setIsLoading(false)
    }
  }

  const logout = async () => {
    try {
      await api.post('/auth/logout')
    } catch (error) {
      // Ignore logout errors
    } finally {
      // Clear local storage
      clientStorage.remove('accessToken')
      clientStorage.remove('refreshToken')
      setUser(null)
      router.push('/auth/login')
    }
  }

  const refreshToken = async () => {
    try {
      const refreshToken = clientStorage.get('refreshToken')
      if (!refreshToken) {
        throw new Error('No refresh token available')
      }

      const response = await api.post('/auth/refresh', {
        refreshToken,
      })

      const { accessToken, refreshToken: newRefreshToken } = response.data

      clientStorage.set('accessToken', accessToken)
      if (newRefreshToken) {
        clientStorage.set('refreshToken', newRefreshToken)
      }
    } catch (error) {
      // Refresh failed, redirect to login
      clientStorage.remove('accessToken')
      clientStorage.remove('refreshToken')
      setUser(null)
      router.push('/auth/login')
      throw error
    }
  }

  const updateProfile = async (data: Partial<User>) => {
    try {
      const response = await api.put('/users/profile', data)
      setUser(response.data.user)
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Profile update failed')
    }
  }

  const value: AuthContextType = {
    user,
    isLoading,
    isAuthenticated,
    login,
    register,
    logout,
    refreshToken,
    updateProfile,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

// Hook for protected routes
export function useRequireAuth() {
  const { isAuthenticated, isLoading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push('/auth/login')
    }
  }, [isAuthenticated, isLoading, router])

  return { isAuthenticated, isLoading }
}
