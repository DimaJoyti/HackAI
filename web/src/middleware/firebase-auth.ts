import { NextRequest, NextResponse } from 'next/server'
import { getAuth } from 'firebase-admin/auth'
import { initializeApp, getApps, cert } from 'firebase-admin/app'

// Initialize Firebase Admin SDK
const initializeFirebaseAdmin = () => {
  if (getApps().length === 0) {
    const serviceAccount = {
      projectId: process.env.FIREBASE_PROJECT_ID || 'hackai-auth-system',
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }

    initializeApp({
      credential: cert(serviceAccount),
      projectId: process.env.FIREBASE_PROJECT_ID || 'hackai-auth-system',
    })
  }
}

// Initialize Firebase Admin
initializeFirebaseAdmin()

export interface AuthenticatedUser {
  uid: string
  email?: string
  emailVerified: boolean
  displayName?: string
  photoURL?: string
  phoneNumber?: string
  customClaims?: Record<string, any>
  role?: string
  permissions?: string[]
  organization?: string
}

export interface AuthContext {
  user: AuthenticatedUser
  token: string
  isAuthenticated: boolean
}

// Extract Firebase ID token from request
export function extractFirebaseToken(request: NextRequest): string | null {
  // Check Authorization header
  const authHeader = request.headers.get('authorization')
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7)
  }

  // Check cookie
  const tokenCookie = request.cookies.get('firebase_token')
  if (tokenCookie) {
    return tokenCookie.value
  }

  return null
}

// Verify Firebase ID token
export async function verifyFirebaseToken(token: string): Promise<AuthenticatedUser | null> {
  try {
    const auth = getAuth()
    const decodedToken = await auth.verifyIdToken(token)
    
    // Get additional user info
    const userRecord = await auth.getUser(decodedToken.uid)
    
    const user: AuthenticatedUser = {
      uid: decodedToken.uid,
      email: decodedToken.email,
      emailVerified: decodedToken.email_verified || false,
      displayName: userRecord.displayName,
      photoURL: userRecord.photoURL,
      phoneNumber: userRecord.phoneNumber,
      customClaims: decodedToken,
      role: decodedToken.role as string,
      permissions: decodedToken.permissions as string[],
      organization: decodedToken.organization as string,
    }

    return user
  } catch (error) {
    console.error('Firebase token verification failed:', error)
    return null
  }
}

// Firebase Auth middleware for API routes
export async function withFirebaseAuth(
  request: NextRequest,
  handler: (request: NextRequest, context: AuthContext) => Promise<NextResponse> | NextResponse,
  options: {
    requireAuth?: boolean
    requireEmailVerification?: boolean
    requiredRole?: string
    requiredPermissions?: string[]
    allowedOrigins?: string[]
  } = {}
): Promise<NextResponse> {
  const {
    requireAuth = true,
    requireEmailVerification = false,
    requiredRole,
    requiredPermissions = [],
    allowedOrigins = []
  } = options

  // CORS handling
  if (allowedOrigins.length > 0) {
    const origin = request.headers.get('origin')
    if (origin && !allowedOrigins.includes(origin)) {
      return new NextResponse('CORS: Origin not allowed', { status: 403 })
    }
  }

  // Handle preflight requests
  if (request.method === 'OPTIONS') {
    return new NextResponse(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400',
      },
    })
  }

  // Extract token
  const token = extractFirebaseToken(request)
  
  if (!token && requireAuth) {
    return new NextResponse(
      JSON.stringify({ error: 'Authentication required' }),
      { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      }
    )
  }

  let user: AuthenticatedUser | null = null
  
  if (token) {
    user = await verifyFirebaseToken(token)
    
    if (!user && requireAuth) {
      return new NextResponse(
        JSON.stringify({ error: 'Invalid authentication token' }),
        { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }
      )
    }
  }

  // Check email verification
  if (user && requireEmailVerification && !user.emailVerified) {
    return new NextResponse(
      JSON.stringify({ error: 'Email verification required' }),
      { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      }
    )
  }

  // Check role
  if (user && requiredRole && user.role !== requiredRole) {
    return new NextResponse(
      JSON.stringify({ error: 'Insufficient permissions' }),
      { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      }
    )
  }

  // Check permissions
  if (user && requiredPermissions.length > 0) {
    const userPermissions = user.permissions || []
    const hasRequiredPermissions = requiredPermissions.every(permission =>
      userPermissions.includes(permission)
    )
    
    if (!hasRequiredPermissions) {
      return new NextResponse(
        JSON.stringify({ error: 'Insufficient permissions' }),
        { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        }
      )
    }
  }

  // Create auth context
  const authContext: AuthContext = {
    user: user!,
    token: token!,
    isAuthenticated: !!user
  }

  // Call the handler
  try {
    return await handler(request, authContext)
  } catch (error) {
    console.error('API handler error:', error)
    return new NextResponse(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    )
  }
}

// Higher-order function for protecting API routes
export function protectApiRoute(
  handler: (request: NextRequest, context: AuthContext) => Promise<NextResponse> | NextResponse,
  options?: Parameters<typeof withFirebaseAuth>[2]
) {
  return async (request: NextRequest) => {
    return withFirebaseAuth(request, handler, options)
  }
}

// Middleware for role-based access control
export function requireRole(role: string) {
  return (
    handler: (request: NextRequest, context: AuthContext) => Promise<NextResponse> | NextResponse
  ) => {
    return protectApiRoute(handler, { requiredRole: role })
  }
}

// Middleware for permission-based access control
export function requirePermissions(permissions: string[]) {
  return (
    handler: (request: NextRequest, context: AuthContext) => Promise<NextResponse> | NextResponse
  ) => {
    return protectApiRoute(handler, { requiredPermissions: permissions })
  }
}

// Middleware for admin-only routes
export const requireAdmin = requireRole('admin')

// Middleware for moderator or admin routes
export function requireModerator() {
  return (
    handler: (request: NextRequest, context: AuthContext) => Promise<NextResponse> | NextResponse
  ) => {
    return protectApiRoute(async (request, context) => {
      if (context.user.role !== 'admin' && context.user.role !== 'moderator') {
        return new NextResponse(
          JSON.stringify({ error: 'Admin or moderator access required' }),
          { 
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          }
        )
      }
      return handler(request, context)
    })
  }
}

// Utility function to get user from context in API routes
export function getUserFromContext(context: AuthContext): AuthenticatedUser {
  return context.user
}

// Utility function to check if user has permission
export function hasPermission(user: AuthenticatedUser, permission: string): boolean {
  return user.permissions?.includes(permission) || false
}

// Utility function to check if user has role
export function hasRole(user: AuthenticatedUser, role: string): boolean {
  return user.role === role
}

// Utility function to check if user is admin
export function isAdmin(user: AuthenticatedUser): boolean {
  return hasRole(user, 'admin')
}

// Utility function to check if user is moderator or admin
export function isModerator(user: AuthenticatedUser): boolean {
  return hasRole(user, 'admin') || hasRole(user, 'moderator')
}
