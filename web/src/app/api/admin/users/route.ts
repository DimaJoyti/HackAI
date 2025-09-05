import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin, AuthContext, getUserFromContext } from '@/middleware/firebase-auth'

// Admin-only API route for user management
async function adminHandler(request: NextRequest, context: AuthContext) {
  const admin = getUserFromContext(context)
  
  if (request.method === 'GET') {
    // List all users (admin only)
    try {
      // In a real implementation, you would fetch from your database
      // This is just an example response
      const users = [
        {
          uid: 'user1',
          email: 'user1@example.com',
          displayName: 'User One',
          role: 'user',
          emailVerified: true,
          createdAt: '2024-01-01T00:00:00Z',
          lastLoginAt: '2024-01-15T10:30:00Z',
        },
        {
          uid: 'user2',
          email: 'user2@example.com',
          displayName: 'User Two',
          role: 'moderator',
          emailVerified: true,
          createdAt: '2024-01-02T00:00:00Z',
          lastLoginAt: '2024-01-14T15:45:00Z',
        },
      ]

      return NextResponse.json({
        users,
        total: users.length,
        requestedBy: admin.uid,
        timestamp: new Date().toISOString(),
      })
    } catch (error) {
      console.error('Error fetching users:', error)
      return NextResponse.json(
        { error: 'Failed to fetch users' },
        { status: 500 }
      )
    }
  }

  if (request.method === 'POST') {
    // Create new user (admin only)
    try {
      const body = await request.json()
      const { email, displayName, role = 'user' } = body

      if (!email || !displayName) {
        return NextResponse.json(
          { error: 'Email and display name are required' },
          { status: 400 }
        )
      }

      // In a real implementation, you would create the user in Firebase Auth
      // and your database. This is just an example response.
      const newUser = {
        uid: `user_${Date.now()}`,
        email,
        displayName,
        role,
        emailVerified: false,
        createdAt: new Date().toISOString(),
        createdBy: admin.uid,
      }

      return NextResponse.json({
        message: 'User created successfully',
        user: newUser,
        timestamp: new Date().toISOString(),
      }, { status: 201 })
    } catch (error) {
      console.error('Error creating user:', error)
      return NextResponse.json(
        { error: 'Failed to create user' },
        { status: 500 }
      )
    }
  }

  return NextResponse.json(
    { error: 'Method not allowed' },
    { status: 405 }
  )
}

// Export admin-protected route handlers
export const GET = requireAdmin(adminHandler)
export const POST = requireAdmin(adminHandler)
