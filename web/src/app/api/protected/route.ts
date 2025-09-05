import { NextRequest, NextResponse } from 'next/server'
import { protectApiRoute, AuthContext, getUserFromContext } from '@/middleware/firebase-auth'

// Protected API route example
async function handler(request: NextRequest, context: AuthContext) {
  const user = getUserFromContext(context)
  
  if (request.method === 'GET') {
    // Return user profile data
    return NextResponse.json({
      message: 'Protected route accessed successfully',
      user: {
        uid: user.uid,
        email: user.email,
        displayName: user.displayName,
        emailVerified: user.emailVerified,
        role: user.role,
        permissions: user.permissions,
        organization: user.organization,
      },
      timestamp: new Date().toISOString(),
    })
  }

  if (request.method === 'POST') {
    try {
      const body = await request.json()
      
      // Example: Update user preferences
      return NextResponse.json({
        message: 'User preferences updated',
        user: user.uid,
        data: body,
        timestamp: new Date().toISOString(),
      })
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid request body' },
        { status: 400 }
      )
    }
  }

  return NextResponse.json(
    { error: 'Method not allowed' },
    { status: 405 }
  )
}

// Export protected route handlers
export const GET = protectApiRoute(handler, {
  requireAuth: true,
  requireEmailVerification: true,
})

export const POST = protectApiRoute(handler, {
  requireAuth: true,
  requireEmailVerification: true,
})
