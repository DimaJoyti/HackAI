'use client'

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { User } from 'firebase/auth'
import { authService, AuthUser, mapFirebaseUser } from '@/lib/firebase'

// Context types
interface FirebaseAuthContextType {
  user: AuthUser | null
  loading: boolean
  signIn: (email: string, password: string) => Promise<{ user: User | null; error: string | null }>
  signUp: (email: string, password: string, displayName?: string) => Promise<{ user: User | null; error: string | null }>
  signInWithGoogle: () => Promise<{ user: User | null; error: string | null }>
  signInWithGitHub: () => Promise<{ user: User | null; error: string | null }>
  signOut: () => Promise<{ error: string | null }>
  resetPassword: (email: string) => Promise<{ error: string | null }>
  sendEmailVerification: () => Promise<{ error: string | null }>
  updateUserProfile: (profile: { displayName?: string; photoURL?: string }) => Promise<{ error: string | null }>
  getIdToken: (forceRefresh?: boolean) => Promise<string | null>
  refreshUser: () => Promise<void>
}

// Create context
const FirebaseAuthContext = createContext<FirebaseAuthContextType | undefined>(undefined)

// Provider props
interface FirebaseAuthProviderProps {
  children: ReactNode
}

// Provider component
export const FirebaseAuthProvider: React.FC<FirebaseAuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)

  // Initialize auth state listener
  useEffect(() => {
    const unsubscribe = authService.onAuthStateChanged((firebaseUser) => {
      const mappedUser = mapFirebaseUser(firebaseUser)
      setUser(mappedUser)
      setLoading(false)
    })

    return unsubscribe
  }, [])

  // Sign in with email and password
  const signIn = async (email: string, password: string) => {
    setLoading(true)
    try {
      const result = await authService.signInWithEmail(email, password)
      return result
    } finally {
      setLoading(false)
    }
  }

  // Sign up with email and password
  const signUp = async (email: string, password: string, displayName?: string) => {
    setLoading(true)
    try {
      const result = await authService.signUpWithEmail(email, password, displayName)
      return result
    } finally {
      setLoading(false)
    }
  }

  // Sign in with Google
  const signInWithGoogle = async () => {
    setLoading(true)
    try {
      const result = await authService.signInWithGoogle()
      return result
    } finally {
      setLoading(false)
    }
  }

  // Sign in with GitHub
  const signInWithGitHub = async () => {
    setLoading(true)
    try {
      const result = await authService.signInWithGitHub()
      return result
    } finally {
      setLoading(false)
    }
  }

  // Sign out
  const signOut = async () => {
    setLoading(true)
    try {
      const result = await authService.signOut()
      return result
    } finally {
      setLoading(false)
    }
  }

  // Reset password
  const resetPassword = async (email: string) => {
    return await authService.resetPassword(email)
  }

  // Send email verification
  const sendEmailVerification = async () => {
    const currentUser = authService.getCurrentUser()
    if (!currentUser) {
      return { error: 'No user is currently signed in' }
    }
    return await authService.sendEmailVerification(currentUser)
  }

  // Update user profile
  const updateUserProfile = async (profile: { displayName?: string; photoURL?: string }) => {
    const currentUser = authService.getCurrentUser()
    if (!currentUser) {
      return { error: 'No user is currently signed in' }
    }
    const result = await authService.updateProfile(currentUser, profile)
    
    // Refresh user data after profile update
    if (!result.error) {
      await refreshUser()
    }
    
    return result
  }

  // Get ID token
  const getIdToken = async (forceRefresh = false) => {
    return await authService.getIdToken(forceRefresh)
  }

  // Refresh user data
  const refreshUser = async () => {
    const currentUser = authService.getCurrentUser()
    if (currentUser) {
      // Force refresh the user data
      await currentUser.reload()
      const mappedUser = mapFirebaseUser(currentUser)
      setUser(mappedUser)
    }
  }

  const value: FirebaseAuthContextType = {
    user,
    loading,
    signIn,
    signUp,
    signInWithGoogle,
    signInWithGitHub,
    signOut,
    resetPassword,
    sendEmailVerification,
    updateUserProfile,
    getIdToken,
    refreshUser
  }

  return (
    <FirebaseAuthContext.Provider value={value}>
      {children}
    </FirebaseAuthContext.Provider>
  )
}

// Custom hook to use the auth context
export const useFirebaseAuth = (): FirebaseAuthContextType => {
  const context = useContext(FirebaseAuthContext)
  if (context === undefined) {
    throw new Error('useFirebaseAuth must be used within a FirebaseAuthProvider')
  }
  return context
}

// Higher-order component for protected routes
interface WithAuthProps {
  fallback?: ReactNode
  requireEmailVerification?: boolean
}

export const withAuth = <P extends object>(
  Component: React.ComponentType<P>,
  options: WithAuthProps = {}
) => {
  const { fallback = <div>Please sign in to access this page.</div>, requireEmailVerification = false } = options

  return function AuthenticatedComponent(props: P) {
    const { user, loading } = useFirebaseAuth()

    if (loading) {
      return <div>Loading...</div>
    }

    if (!user) {
      return <>{fallback}</>
    }

    if (requireEmailVerification && !user.emailVerified) {
      return <div>Please verify your email address to access this page.</div>
    }

    return <Component {...props} />
  }
}

// Hook for checking authentication status
export const useAuthStatus = () => {
  const { user, loading } = useFirebaseAuth()
  
  return {
    isAuthenticated: !!user,
    isLoading: loading,
    user,
    isEmailVerified: user?.emailVerified ?? false
  }
}

// Hook for protected actions
export const useProtectedAction = () => {
  const { user, getIdToken } = useFirebaseAuth()

  const executeProtectedAction = async <T>(
    action: (token: string) => Promise<T>,
    options: { requireEmailVerification?: boolean } = {}
  ): Promise<{ data: T | null; error: string | null }> => {
    if (!user) {
      return { data: null, error: 'Authentication required' }
    }

    if (options.requireEmailVerification && !user.emailVerified) {
      return { data: null, error: 'Email verification required' }
    }

    try {
      const token = await getIdToken()
      if (!token) {
        return { data: null, error: 'Failed to get authentication token' }
      }

      const data = await action(token)
      return { data, error: null }
    } catch (error: any) {
      return { data: null, error: error.message || 'An error occurred' }
    }
  }

  return { executeProtectedAction }
}

// Custom hook for handling auth errors
export const useAuthError = () => {
  const [error, setError] = useState<string | null>(null)

  const handleAuthError = (error: string | null) => {
    setError(error)
    if (error) {
      // Auto-clear error after 5 seconds
      setTimeout(() => setError(null), 5000)
    }
  }

  const clearError = () => setError(null)

  return { error, handleAuthError, clearError }
}

// Export the context for advanced usage
export { FirebaseAuthContext }
