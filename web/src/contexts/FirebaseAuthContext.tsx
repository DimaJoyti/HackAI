'use client'

import React, { createContext, useContext, useEffect, useState, ReactNode, useMemo } from 'react'
import { User } from 'firebase/auth'
import { authService, AuthUser, mapFirebaseUser } from '@/lib/firebase'
import { enhancedFirebaseAuth, AuthResult, SignUpResult, SignInResult } from '../lib/firebase-enhanced-auth'

// Context types
interface FirebaseAuthContextType {
  user: AuthUser | null
  loading: boolean
  idToken: string | null

  // Enhanced authentication methods
  signIn: (email: string, password: string) => Promise<SignInResult>
  signUp: (email: string, password: string, displayName?: string) => Promise<SignUpResult>
  signInWithGoogle: () => Promise<SignInResult>
  signInWithGitHub: () => Promise<SignInResult>
  signOut: () => Promise<{ error: string | null }>

  // Account management
  resetPassword: (email: string) => Promise<{ error: string | null }>
  sendEmailVerification: () => Promise<{ error: string | null }>
  updateUserProfile: (profile: { displayName?: string; photoURL?: string }) => Promise<{ error: string | null }>
  updatePassword: (currentPassword: string, newPassword: string) => Promise<{ error: string | null }>
  deleteAccount: (password?: string) => Promise<{ error: string | null }>

  // Provider linking
  linkWithGoogle: () => Promise<{ user: User | null; error: string | null }>
  linkWithGitHub: () => Promise<{ user: User | null; error: string | null }>
  unlinkProvider: (providerId: string) => Promise<{ user: User | null; error: string | null }>

  // Token management
  getIdToken: (forceRefresh?: boolean) => Promise<string | null>
  getIdTokenResult: (forceRefresh?: boolean) => Promise<any>
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
  const [idToken, setIdToken] = useState<string | null>(null)

  // Initialize auth state listener with enhanced service
  useEffect(() => {
    const unsubscribe = enhancedFirebaseAuth.onAuthStateChange(async (firebaseUser) => {
      const mappedUser = mapFirebaseUser(firebaseUser)
      setUser(mappedUser)

      // Get ID token if user is authenticated
      if (firebaseUser) {
        const token = await enhancedFirebaseAuth.getIdToken()
        setIdToken(token)
      } else {
        setIdToken(null)
      }

      setLoading(false)
    })

    return unsubscribe
  }, [])

  // Enhanced sign in with email and password
  const signIn = async (email: string, password: string): Promise<SignInResult> => {
    setLoading(true)
    try {
      const result = await enhancedFirebaseAuth.signInWithEmail(email, password)
      return result
    } finally {
      setLoading(false)
    }
  }

  // Enhanced sign up with email and password
  const signUp = async (email: string, password: string, displayName?: string): Promise<SignUpResult> => {
    setLoading(true)
    try {
      const result = await enhancedFirebaseAuth.signUpWithEmail(email, password, displayName)
      return result
    } finally {
      setLoading(false)
    }
  }

  // Enhanced sign in with Google
  const signInWithGoogle = async (): Promise<SignInResult> => {
    setLoading(true)
    try {
      const result = await enhancedFirebaseAuth.signInWithGoogle()
      return result
    } finally {
      setLoading(false)
    }
  }

  // Enhanced sign in with GitHub
  const signInWithGitHub = async (): Promise<SignInResult> => {
    setLoading(true)
    try {
      const result = await enhancedFirebaseAuth.signInWithGitHub()
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

  // Enhanced methods
  const updatePassword = async (currentPassword: string, newPassword: string) => {
    return await enhancedFirebaseAuth.updatePassword(currentPassword, newPassword)
  }

  const deleteAccount = async (password?: string) => {
    return await enhancedFirebaseAuth.deleteAccount(password)
  }

  const linkWithGoogle = async () => {
    return await enhancedFirebaseAuth.linkWithGoogle()
  }

  const linkWithGitHub = async () => {
    return await enhancedFirebaseAuth.linkWithGitHub()
  }

  const unlinkProvider = async (providerId: string) => {
    return await enhancedFirebaseAuth.unlinkProvider(providerId)
  }

  const getIdTokenResult = async (forceRefresh = false) => {
    return await enhancedFirebaseAuth.getIdTokenResult(forceRefresh)
  }

  // Refresh user data
  const refreshUser = async () => {
    const currentUser = enhancedFirebaseAuth.getCurrentUser()
    if (currentUser) {
      // Force refresh the user data
      await currentUser.reload()
      const mappedUser = mapFirebaseUser(currentUser)
      setUser(mappedUser)

      // Refresh token
      const token = await enhancedFirebaseAuth.getIdToken(true)
      setIdToken(token)
    }
  }

  const value: FirebaseAuthContextType = useMemo(() => ({
    user,
    loading,
    idToken,
    signIn,
    signUp,
    signInWithGoogle,
    signInWithGitHub,
    signOut,
    resetPassword,
    sendEmailVerification,
    updateUserProfile,
    updatePassword,
    deleteAccount,
    linkWithGoogle,
    linkWithGitHub,
    unlinkProvider,
    getIdToken,
    getIdTokenResult,
    refreshUser
  }), [user, loading, idToken])

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

  const executeProtectedAction = async <T,>(
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
