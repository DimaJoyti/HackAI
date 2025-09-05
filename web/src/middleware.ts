import { NextRequest, NextResponse } from 'next/server'
import { extractFirebaseToken, verifyFirebaseToken } from './middleware/firebase-auth'

// Define protected routes and their requirements
const protectedRoutes = {
  // Admin routes
  '/admin': { requireAuth: true, requiredRole: 'admin' },
  '/api/admin': { requireAuth: true, requiredRole: 'admin' },
  
  // User dashboard routes
  '/dashboard': { requireAuth: true, requireEmailVerification: true },
  '/profile': { requireAuth: true, requireEmailVerification: true },
  '/settings': { requireAuth: true, requireEmailVerification: true },
  
  // API routes that require authentication
  '/api/user': { requireAuth: true },
  '/api/protected': { requireAuth: true, requireEmailVerification: true },
  
  // Moderator routes
  '/moderation': { requireAuth: true, requiredRole: 'moderator' },
  '/api/moderation': { requireAuth: true, requiredRole: 'moderator' },
}

// Public routes that don't require authentication
const publicRoutes = [
  '/',
  '/auth/login',
  '/auth/register',
  '/login', // legacy route
  '/signup', // legacy route
  '/forgot-password',
  '/about',
  '/contact',
  '/api/public',
  '/api/health',
  '/_next',
  '/favicon.ico',
  '/robots.txt',
  '/sitemap.xml',
]

// Routes that should redirect authenticated users away
const authRoutes = [
  '/auth/login',
  '/auth/register',
  '/login', // legacy route
  '/signup', // legacy route
  '/forgot-password',
  '/firebase-auth-demo',
]

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl
  
  // Skip middleware for static files and Next.js internals
  if (
    pathname.startsWith('/_next/') ||
    pathname.startsWith('/static/') ||
    pathname.includes('.') ||
    pathname === '/favicon.ico'
  ) {
    return NextResponse.next()
  }

  // Check if route is public
  const isPublicRoute = publicRoutes.some(route => 
    pathname === route || pathname.startsWith(route + '/')
  )

  // Check if route is an auth route
  const isAuthRoute = authRoutes.includes(pathname)

  // Check if route is protected
  const protectedRoute = Object.entries(protectedRoutes).find(([route]) =>
    pathname === route || pathname.startsWith(route + '/')
  )?.[1]

  // Extract and verify Firebase token
  const token = extractFirebaseToken(request)
  let user = null
  let isAuthenticated = false

  if (token) {
    try {
      user = await verifyFirebaseToken(token)
      isAuthenticated = !!user
    } catch (error) {
      console.error('Token verification failed:', error)
      // Clear invalid token
      const response = NextResponse.redirect(new URL('/login', request.url))
      response.cookies.delete('firebase_token')
      return response
    }
  }

  // Handle auth routes (login, signup, etc.)
  if (isAuthRoute && isAuthenticated) {
    // Redirect authenticated users away from auth pages
    return NextResponse.redirect(new URL('/dashboard', request.url))
  }

  // Handle protected routes
  if (protectedRoute) {
    // Check authentication
    if (protectedRoute.requireAuth && !isAuthenticated) {
      const loginUrl = new URL('/auth/login', request.url)
      loginUrl.searchParams.set('redirect', pathname)
      return NextResponse.redirect(loginUrl)
    }

    if (user) {
      // Check email verification
      if (protectedRoute.requireEmailVerification && !user.emailVerified) {
        const verifyUrl = new URL('/verify-email', request.url)
        verifyUrl.searchParams.set('redirect', pathname)
        return NextResponse.redirect(verifyUrl)
      }

      // Check role requirements
      if (protectedRoute.requiredRole) {
        if (user.role !== protectedRoute.requiredRole) {
          // Special case: allow admin to access moderator routes
          if (protectedRoute.requiredRole === 'moderator' && user.role === 'admin') {
            // Allow access
          } else {
            return NextResponse.redirect(new URL('/unauthorized', request.url))
          }
        }
      }

      // Check permission requirements
      if (protectedRoute.requiredPermissions) {
        const userPermissions = user.permissions || []
        const hasRequiredPermissions = protectedRoute.requiredPermissions.every(
          (permission: string) => userPermissions.includes(permission)
        )
        
        if (!hasRequiredPermissions) {
          return NextResponse.redirect(new URL('/unauthorized', request.url))
        }
      }
    }
  }

  // Add security headers
  const response = NextResponse.next()
  
  // Security headers
  response.headers.set('X-Content-Type-Options', 'nosniff')
  response.headers.set('X-Frame-Options', 'DENY')
  response.headers.set('X-XSS-Protection', '1; mode=block')
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  
  // Add user context to headers for API routes
  if (pathname.startsWith('/api/') && user) {
    response.headers.set('X-User-ID', user.uid)
    response.headers.set('X-User-Email', user.email || '')
    response.headers.set('X-User-Role', user.role || '')
    response.headers.set('X-User-Verified', user.emailVerified.toString())
  }

  // CORS headers for API routes
  if (pathname.startsWith('/api/')) {
    response.headers.set('Access-Control-Allow-Origin', '*')
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  }

  return response
}

// Configure which paths the middleware should run on
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    '/((?!_next/static|_next/image|favicon.ico|public/).*)',
  ],
}

// Types for route configuration
interface RouteConfig {
  requireAuth?: boolean
  requireEmailVerification?: boolean
  requiredRole?: string
  requiredPermissions?: string[]
}

// Helper function to check if a route is protected
export function isProtectedRoute(pathname: string): RouteConfig | null {
  const route = Object.entries(protectedRoutes).find(([route]) =>
    pathname === route || pathname.startsWith(route + '/')
  )
  return route ? route[1] : null
}

// Helper function to check if a route is public
export function isPublicRoute(pathname: string): boolean {
  return publicRoutes.some(route => 
    pathname === route || pathname.startsWith(route + '/')
  )
}

// Helper function to get redirect URL for unauthenticated users
export function getLoginRedirectUrl(request: NextRequest): string {
  const loginUrl = new URL('/auth/login', request.url)
  loginUrl.searchParams.set('redirect', request.nextUrl.pathname)
  return loginUrl.toString()
}

// Helper function to get redirect URL for unverified users
export function getVerificationRedirectUrl(request: NextRequest): string {
  const verifyUrl = new URL('/verify-email', request.url)
  verifyUrl.searchParams.set('redirect', request.nextUrl.pathname)
  return verifyUrl.toString()
}
