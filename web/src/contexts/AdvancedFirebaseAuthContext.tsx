'use client'

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { User } from 'firebase/auth'
import { authService, AuthUser, mapFirebaseUser } from '@/lib/firebase'

// Extended context types for advanced Google authentication
interface AdvancedFirebaseAuthContextType {
  user: AuthUser | null
  loading: boolean
  
  // Basic authentication
  signIn: (email: string, password: string) => Promise<{ user: User | null; error: string | null }>
  signUp: (email: string, password: string, displayName?: string) => Promise<{ user: User | null; error: string | null }>
  signOut: () => Promise<{ error: string | null }>
  
  // Google authentication
  signInWithGoogle: () => Promise<{ user: User | null; error: string | null }>
  signInWithGoogleAdvanced: (customScopes?: string[]) => Promise<{ 
    user: User | null; 
    error: string | null;
    accessToken?: string;
    refreshToken?: string;
    scopes?: string[];
  }>
  
  // GitHub authentication
  signInWithGitHub: () => Promise<{ user: User | null; error: string | null }>
  
  // Password management
  resetPassword: (email: string) => Promise<{ error: string | null }>
  sendEmailVerification: () => Promise<{ error: string | null }>
  
  // Profile management
  updateUserProfile: (profile: { displayName?: string; photoURL?: string }) => Promise<{ error: string | null }>
  refreshUser: () => Promise<void>
  
  // Token management
  getIdToken: (forceRefresh?: boolean) => Promise<string | null>
  getGoogleAccessToken: () => Promise<string | null>
  refreshGoogleTokens: () => Promise<{ tokens: any | null; error: string | null }>
  revokeGoogleTokens: () => Promise<{ error: string | null }>
  
  // Google profile
  getGoogleUserProfile: () => Promise<{ profile: any | null; error: string | null }>
  
  // Account linking
  linkGoogleAccount: () => Promise<{ user: User | null; error: string | null }>
  unlinkGoogleAccount: () => Promise<{ user: User | null; error: string | null }>
  
  // Session management
  getUserSessions: () => Promise<{ sessions: any[] | null; error: string | null }>
  invalidateSession: (sessionId: string) => Promise<{ error: string | null }>
  invalidateAllSessions: () => Promise<{ error: string | null }>
}

// Create context
const AdvancedFirebaseAuthContext = createContext<AdvancedFirebaseAuthContextType | undefined>(undefined)

// Provider props
interface AdvancedFirebaseAuthProviderProps {
  children: ReactNode
}

// Provider component
export const AdvancedFirebaseAuthProvider: React.FC<AdvancedFirebaseAuthProviderProps> = ({ children }) => {
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

  // Basic authentication methods
  const signIn = async (email: string, password: string) => {
    setLoading(true)
    try {
      const result = await authService.signInWithEmail(email, password)
      return result
    } finally {
      setLoading(false)
    }
  }

  const signUp = async (email: string, password: string, displayName?: string) => {
    setLoading(true)
    try {
      const result = await authService.signUpWithEmail(email, password, displayName)
      return result
    } finally {
      setLoading(false)
    }
  }

  const signOut = async () => {
    setLoading(true)
    try {
      const result = await authService.signOut()
      return result
    } finally {
      setLoading(false)
    }
  }

  // Google authentication methods
  const signInWithGoogle = async () => {
    setLoading(true)
    try {
      const result = await authService.signInWithGoogle()
      return result
    } finally {
      setLoading(false)
    }
  }

  const signInWithGoogleAdvanced = async (customScopes?: string[]) => {
    setLoading(true)
    try {
      const result = await authService.signInWithGoogleAdvanced(customScopes)
      return result
    } finally {
      setLoading(false)
    }
  }

  // GitHub authentication
  const signInWithGitHub = async () => {
    setLoading(true)
    try {
      const result = await authService.signInWithGitHub()
      return result
    } finally {
      setLoading(false)
    }
  }

  // Password management
  const resetPassword = async (email: string) => {
    return await authService.resetPassword(email)
  }

  const sendEmailVerification = async () => {
    const currentUser = authService.getCurrentUser()
    if (!currentUser) {
      return { error: 'No user is currently signed in' }
    }
    return await authService.sendEmailVerification(currentUser)
  }

  // Profile management
  const updateUserProfile = async (profile: { displayName?: string; photoURL?: string }) => {
    const currentUser = authService.getCurrentUser()
    if (!currentUser) {
      return { error: 'No user is currently signed in' }
    }
    const result = await authService.updateProfile(currentUser, profile)
    
    if (!result.error) {
      await refreshUser()
    }
    
    return result
  }

  const refreshUser = async () => {
    const currentUser = authService.getCurrentUser()
    if (currentUser) {
      await currentUser.reload()
      const mappedUser = mapFirebaseUser(currentUser)
      setUser(mappedUser)
    }
  }

  // Token management
  const getIdToken = async (forceRefresh = false) => {
    return await authService.getIdToken(forceRefresh)
  }

  const getGoogleAccessToken = async () => {
    return await authService.getGoogleAccessToken()
  }

  const refreshGoogleTokens = async () => {
    return await authService.refreshGoogleTokens()
  }

  const revokeGoogleTokens = async () => {
    return await authService.revokeGoogleTokens()
  }

  // Google profile
  const getGoogleUserProfile = async () => {
    return await authService.getGoogleUserProfile()
  }

  // Account linking
  const linkGoogleAccount = async () => {
    return await authService.linkGoogleAccount()
  }

  const unlinkGoogleAccount = async () => {
    return await authService.unlinkGoogleAccount()
  }

  // Session management
  const getUserSessions = async () => {
    try {
      if (!user) {
        return { sessions: null, error: 'No user signed in' }
      }

      const idToken = await getIdToken()
      if (!idToken) {
        return { sessions: null, error: 'No ID token available' }
      }

      const response = await fetch(`/api/firebase/users/${user.uid}/sessions`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${idToken}`
        }
      })

      if (!response.ok) {
        throw new Error('Failed to get user sessions')
      }

      const data = await response.json()
      return { sessions: data.sessions, error: null }
    } catch (error: any) {
      return { sessions: null, error: error.message }
    }
  }

  const invalidateSession = async (sessionId: string) => {
    try {
      const idToken = await getIdToken()
      if (!idToken) {
        return { error: 'No ID token available' }
      }

      const response = await fetch(`/api/firebase/sessions/${sessionId}/invalidate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${idToken}`
        }
      })

      if (!response.ok) {
        throw new Error('Failed to invalidate session')
      }

      return { error: null }
    } catch (error: any) {
      return { error: error.message }
    }
  }

  const invalidateAllSessions = async () => {
    try {
      if (!user) {
        return { error: 'No user signed in' }
      }

      const idToken = await getIdToken()
      if (!idToken) {
        return { error: 'No ID token available' }
      }

      const response = await fetch(`/api/firebase/users/${user.uid}/sessions/invalidate-all`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${idToken}`
        }
      })

      if (!response.ok) {
        throw new Error('Failed to invalidate all sessions')
      }

      return { error: null }
    } catch (error: any) {
      return { error: error.message }
    }
  }

  const value: AdvancedFirebaseAuthContextType = {
    user,
    loading,
    signIn,
    signUp,
    signOut,
    signInWithGoogle,
    signInWithGoogleAdvanced,
    signInWithGitHub,
    resetPassword,
    sendEmailVerification,
    updateUserProfile,
    refreshUser,
    getIdToken,
    getGoogleAccessToken,
    refreshGoogleTokens,
    revokeGoogleTokens,
    getGoogleUserProfile,
    linkGoogleAccount,
    unlinkGoogleAccount,
    getUserSessions,
    invalidateSession,
    invalidateAllSessions
  }

  return (
    <AdvancedFirebaseAuthContext.Provider value={value}>
      {children}
    </AdvancedFirebaseAuthContext.Provider>
  )
}

// Custom hook to use the advanced auth context
export const useAdvancedFirebaseAuth = (): AdvancedFirebaseAuthContextType => {
  const context = useContext(AdvancedFirebaseAuthContext)
  if (context === undefined) {
    throw new Error('useAdvancedFirebaseAuth must be used within an AdvancedFirebaseAuthProvider')
  }
  return context
}

// Export the context for advanced usage
export { AdvancedFirebaseAuthContext }
