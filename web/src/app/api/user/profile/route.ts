import { NextRequest, NextResponse } from 'next/server'
import { protectApiRoute, AuthContext, getUserFromContext } from '@/middleware/firebase-auth'

// User profile API route
async function profileHandler(request: NextRequest, context: AuthContext) {
  const user = getUserFromContext(context)
  
  if (request.method === 'GET') {
    // Get user profile
    try {
      // In a real implementation, you would fetch from your database
      const profile = {
        uid: user.uid,
        email: user.email,
        displayName: user.displayName,
        photoURL: user.photoURL,
        phoneNumber: user.phoneNumber,
        emailVerified: user.emailVerified,
        role: user.role,
        organization: user.organization,
        permissions: user.permissions,
        preferences: {
          theme: 'light',
          notifications: true,
          language: 'en',
        },
        metadata: {
          lastLoginAt: new Date().toISOString(),
          profileCompleteness: 85,
        },
      }

      return NextResponse.json({
        profile,
        timestamp: new Date().toISOString(),
      })
    } catch (error) {
      console.error('Error fetching profile:', error)
      return NextResponse.json(
        { error: 'Failed to fetch profile' },
        { status: 500 }
      )
    }
  }

  if (request.method === 'PUT') {
    // Update user profile
    try {
      const body = await request.json()
      const { displayName, photoURL, phoneNumber, preferences } = body

      // Validate input
      if (displayName && typeof displayName !== 'string') {
        return NextResponse.json(
          { error: 'Display name must be a string' },
          { status: 400 }
        )
      }

      if (photoURL && typeof photoURL !== 'string') {
        return NextResponse.json(
          { error: 'Photo URL must be a string' },
          { status: 400 }
        )
      }

      // In a real implementation, you would update Firebase Auth and your database
      const updatedProfile = {
        uid: user.uid,
        email: user.email,
        displayName: displayName || user.displayName,
        photoURL: photoURL || user.photoURL,
        phoneNumber: phoneNumber || user.phoneNumber,
        emailVerified: user.emailVerified,
        role: user.role,
        organization: user.organization,
        permissions: user.permissions,
        preferences: {
          ...preferences,
        },
        updatedAt: new Date().toISOString(),
      }

      return NextResponse.json({
        message: 'Profile updated successfully',
        profile: updatedProfile,
        timestamp: new Date().toISOString(),
      })
    } catch (error) {
      console.error('Error updating profile:', error)
      return NextResponse.json(
        { error: 'Failed to update profile' },
        { status: 500 }
      )
    }
  }

  if (request.method === 'DELETE') {
    // Delete user account
    try {
      // In a real implementation, you would:
      // 1. Verify user password or require re-authentication
      // 2. Delete user data from your database
      // 3. Delete user from Firebase Auth
      // 4. Clean up any associated resources

      return NextResponse.json({
        message: 'Account deletion initiated',
        uid: user.uid,
        timestamp: new Date().toISOString(),
      })
    } catch (error) {
      console.error('Error deleting account:', error)
      return NextResponse.json(
        { error: 'Failed to delete account' },
        { status: 500 }
      )
    }
  }

  return NextResponse.json(
    { error: 'Method not allowed' },
    { status: 405 }
  )
}

// Export protected route handlers
export const GET = protectApiRoute(profileHandler, {
  requireAuth: true,
})

export const PUT = protectApiRoute(profileHandler, {
  requireAuth: true,
})

export const DELETE = protectApiRoute(profileHandler, {
  requireAuth: true,
  requireEmailVerification: true, // Require email verification for account deletion
})
