'use client'

import { useState, useEffect } from 'react'
import { User } from 'firebase/auth'
import { authService, mapFirebaseUser, AuthUser } from '@/lib/firebase'

export interface UseAuthReturn {
  user: AuthUser | null
  firebaseUser: User | null
  loading: boolean
  error: string | null
  signIn: (email: string, password: string) => Promise<{ user: User | null; error: string | null }>
  signUp: (email: string, password: string, displayName?: string) => Promise<{ user: User | null; error: string | null }>
  signInWithGoogle: () => Promise<{ user: User | null; error: string | null }>
  signInWithGitHub: () => Promise<{ user: User | null; error: string | null }>
  signOut: () => Promise<{ error: string | null }>
  resetPassword: (email: string) => Promise<{ error: string | null }>
  isAuthenticated: boolean
}

export function useAuth(): UseAuthReturn {
  const [firebaseUser, setFirebaseUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const unsubscribe = authService.onAuthStateChanged((user) => {
      setFirebaseUser(user)
      setLoading(false)
    })

    return () => unsubscribe()
  }, [])

  // Convert Firebase user to our AuthUser interface
  const user = mapFirebaseUser(firebaseUser)

  const signIn = async (email: string, password: string) => {
    setError(null)
    setLoading(true)
    
    try {
      const result = await authService.signInWithEmail(email, password)
      if (result.error) {
        setError(result.error)
      }
      return result
    } catch (err: any) {
      const error = err.message
      setError(error)
      return { user: null, error }
    } finally {
      setLoading(false)
    }
  }

  const signUp = async (email: string, password: string, displayName?: string) => {
    setError(null)
    setLoading(true)
    
    try {
      const result = await authService.signUpWithEmail(email, password, displayName)
      if (result.error) {
        setError(result.error)
      }
      return result
    } catch (err: any) {
      const error = err.message
      setError(error)
      return { user: null, error }
    } finally {
      setLoading(false)
    }
  }

  const signInWithGoogle = async () => {
    setError(null)
    setLoading(true)
    
    try {
      const result = await authService.signInWithGoogle()
      if (result.error) {
        setError(result.error)
      }
      return result
    } catch (err: any) {
      const error = err.message
      setError(error)
      return { user: null, error }
    } finally {
      setLoading(false)
    }
  }

  const signInWithGitHub = async () => {
    setError(null)
    setLoading(true)
    
    try {
      const result = await authService.signInWithGitHub()
      if (result.error) {
        setError(result.error)
      }
      return result
    } catch (err: any) {
      const error = err.message
      setError(error)
      return { user: null, error }
    } finally {
      setLoading(false)
    }
  }

  const signOut = async () => {
    setError(null)
    setLoading(true)
    
    try {
      const result = await authService.signOut()
      if (result.error) {
        setError(result.error)
      }
      return result
    } catch (err: any) {
      const error = err.message
      setError(error)
      return { error }
    } finally {
      setLoading(false)
    }
  }

  const resetPassword = async (email: string) => {
    setError(null)
    setLoading(true)
    
    try {
      const result = await authService.resetPassword(email)
      if (result.error) {
        setError(result.error)
      }
      return result
    } catch (err: any) {
      const error = err.message
      setError(error)
      return { error }
    } finally {
      setLoading(false)
    }
  }

  return {
    user,
    firebaseUser,
    loading,
    error,
    signIn,
    signUp,
    signInWithGoogle,
    signInWithGitHub,
    signOut,
    resetPassword,
    isAuthenticated: !!firebaseUser
  }
}