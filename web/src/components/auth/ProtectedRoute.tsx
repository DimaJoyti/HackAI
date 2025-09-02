'use client'

import React, { ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Loader2, Shield, Mail } from 'lucide-react'

interface ProtectedRouteProps {
  children: ReactNode
  fallback?: ReactNode
  requireEmailVerification?: boolean
  requiredRoles?: string[]
  redirectTo?: string
  showFallback?: boolean
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  fallback,
  requireEmailVerification = false,
  requiredRoles = [],
  redirectTo = '/auth/signin',
  showFallback = true
}) => {
  const { user, loading, sendEmailVerification } = useFirebaseAuth()
  const router = useRouter()

  // Show loading state
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center space-y-4">
          <Loader2 className="h-8 w-8 animate-spin mx-auto" />
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    )
  }

  // User not authenticated
  if (!user) {
    if (fallback) {
      return <>{fallback}</>
    }

    if (!showFallback) {
      router.push(redirectTo)
      return null
    }

    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
            <CardTitle>Authentication Required</CardTitle>
            <CardDescription>
              You need to sign in to access this page
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Button 
              className="w-full" 
              onClick={() => router.push(redirectTo)}
            >
              Sign In
            </Button>
            <Button 
              variant="outline" 
              className="w-full" 
              onClick={() => router.push('/auth/signup')}
            >
              Create Account
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  // Email verification required
  if (requireEmailVerification && !user.emailVerified) {
    const handleSendVerification = async () => {
      const result = await sendEmailVerification()
      if (result.error) {
        console.error('Failed to send verification email:', result.error)
      }
    }

    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <Mail className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
            <CardTitle>Email Verification Required</CardTitle>
            <CardDescription>
              Please verify your email address to continue
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Alert>
              <AlertDescription>
                We've sent a verification link to <strong>{user.email}</strong>. 
                Please check your email and click the link to verify your account.
              </AlertDescription>
            </Alert>
            <Button 
              className="w-full" 
              onClick={handleSendVerification}
            >
              Resend Verification Email
            </Button>
            <Button 
              variant="outline" 
              className="w-full" 
              onClick={() => router.push('/auth/signin')}
            >
              Back to Sign In
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  // Role-based access control
  if (requiredRoles.length > 0) {
    // Note: This would need to be implemented with custom claims from Firebase
    // For now, we'll assume the role is stored in the user's custom claims
    const userRole = user.customClaims?.role || 'user'
    
    if (!requiredRoles.includes(userRole)) {
      return (
        <div className="flex items-center justify-center min-h-screen p-4">
          <Card className="w-full max-w-md">
            <CardHeader className="text-center">
              <Shield className="h-12 w-12 mx-auto mb-4 text-destructive" />
              <CardTitle>Access Denied</CardTitle>
              <CardDescription>
                You don't have permission to access this page
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Alert variant="destructive">
                <AlertDescription>
                  Required role: {requiredRoles.join(' or ')}<br />
                  Your role: {userRole}
                </AlertDescription>
              </Alert>
              <Button 
                className="w-full" 
                onClick={() => router.push('/dashboard')}
              >
                Go to Dashboard
              </Button>
            </CardContent>
          </Card>
        </div>
      )
    }
  }

  // All checks passed, render children
  return <>{children}</>
}

// Higher-order component version
export const withProtectedRoute = <P extends object>(
  Component: React.ComponentType<P>,
  options: Omit<ProtectedRouteProps, 'children'> = {}
) => {
  return function ProtectedComponent(props: P) {
    return (
      <ProtectedRoute {...options}>
        <Component {...props} />
      </ProtectedRoute>
    )
  }
}

// Hook for checking access permissions
export const useAccessControl = () => {
  const { user } = useFirebaseAuth()

  const hasRole = (role: string): boolean => {
    if (!user) return false
    const userRole = user.customClaims?.role || 'user'
    return userRole === role
  }

  const hasAnyRole = (roles: string[]): boolean => {
    if (!user) return false
    const userRole = user.customClaims?.role || 'user'
    return roles.includes(userRole)
  }

  const hasClaim = (claimKey: string, claimValue?: any): boolean => {
    if (!user || !user.customClaims) return false
    
    if (claimValue === undefined) {
      return claimKey in user.customClaims
    }
    
    return user.customClaims[claimKey] === claimValue
  }

  const isEmailVerified = (): boolean => {
    return user?.emailVerified ?? false
  }

  const canAccess = (requirements: {
    requireAuth?: boolean
    requireEmailVerification?: boolean
    requiredRoles?: string[]
    requiredClaims?: Record<string, any>
  }): boolean => {
    const {
      requireAuth = true,
      requireEmailVerification = false,
      requiredRoles = [],
      requiredClaims = {}
    } = requirements

    // Check authentication
    if (requireAuth && !user) return false

    // Check email verification
    if (requireEmailVerification && !isEmailVerified()) return false

    // Check roles
    if (requiredRoles.length > 0 && !hasAnyRole(requiredRoles)) return false

    // Check claims
    for (const [claimKey, claimValue] of Object.entries(requiredClaims)) {
      if (!hasClaim(claimKey, claimValue)) return false
    }

    return true
  }

  return {
    user,
    hasRole,
    hasAnyRole,
    hasClaim,
    isEmailVerified,
    canAccess,
    isAuthenticated: !!user
  }
}

// Component for conditional rendering based on permissions
interface ConditionalRenderProps {
  children: ReactNode
  fallback?: ReactNode
  requireAuth?: boolean
  requireEmailVerification?: boolean
  requiredRoles?: string[]
  requiredClaims?: Record<string, any>
}

export const ConditionalRender: React.FC<ConditionalRenderProps> = ({
  children,
  fallback = null,
  requireAuth = true,
  requireEmailVerification = false,
  requiredRoles = [],
  requiredClaims = {}
}) => {
  const { canAccess } = useAccessControl()

  const hasAccess = canAccess({
    requireAuth,
    requireEmailVerification,
    requiredRoles,
    requiredClaims
  })

  return hasAccess ? <>{children}</> : <>{fallback}</>
}
