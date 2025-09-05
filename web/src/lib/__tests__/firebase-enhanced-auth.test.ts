import { EnhancedFirebaseAuth } from '../firebase-enhanced-auth'
import {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  signOut,
  sendPasswordResetEmail,
  sendEmailVerification,
  updateProfile,
  updatePassword,
  onAuthStateChanged,
  getIdToken,
  getIdTokenResult,
} from 'firebase/auth'

// Mock Firebase Auth functions
jest.mock('firebase/auth')
jest.mock('../firebase', () => ({
  auth: {},
  googleProvider: {},
  githubProvider: {},
}))

const mockSignInWithEmailAndPassword = signInWithEmailAndPassword as jest.MockedFunction<typeof signInWithEmailAndPassword>
const mockCreateUserWithEmailAndPassword = createUserWithEmailAndPassword as jest.MockedFunction<typeof createUserWithEmailAndPassword>
const mockSignInWithPopup = signInWithPopup as jest.MockedFunction<typeof signInWithPopup>
const mockSignOut = signOut as jest.MockedFunction<typeof signOut>
const mockSendPasswordResetEmail = sendPasswordResetEmail as jest.MockedFunction<typeof sendPasswordResetEmail>
const mockSendEmailVerification = sendEmailVerification as jest.MockedFunction<typeof sendEmailVerification>
const mockUpdateProfile = updateProfile as jest.MockedFunction<typeof updateProfile>
const mockUpdatePassword = updatePassword as jest.MockedFunction<typeof updatePassword>
const mockOnAuthStateChanged = onAuthStateChanged as jest.MockedFunction<typeof onAuthStateChanged>
const mockGetIdToken = getIdToken as jest.MockedFunction<typeof getIdToken>
const mockGetIdTokenResult = getIdTokenResult as jest.MockedFunction<typeof getIdTokenResult>

describe('EnhancedFirebaseAuth', () => {
  let authService: EnhancedFirebaseAuth

  beforeEach(() => {
    jest.clearAllMocks()
    authService = EnhancedFirebaseAuth.getInstance()
  })

  describe('getInstance', () => {
    it('returns singleton instance', () => {
      const instance1 = EnhancedFirebaseAuth.getInstance()
      const instance2 = EnhancedFirebaseAuth.getInstance()
      expect(instance1).toBe(instance2)
    })
  })

  describe('signInWithEmail', () => {
    it('successfully signs in with email and password', async () => {
      const mockUser = {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: true,
      }
      const mockUserCredential = { user: mockUser }
      
      mockSignInWithEmailAndPassword.mockResolvedValue(mockUserCredential as any)

      const result = await authService.signInWithEmail('test@example.com', 'password123')

      expect(result.user).toBe(mockUser)
      expect(result.error).toBeNull()
      expect(result.needsEmailVerification).toBe(false)
      expect(mockSignInWithEmailAndPassword).toHaveBeenCalledWith({}, 'test@example.com', 'password123')
    })

    it('handles sign in errors', async () => {
      const mockError = { code: 'auth/user-not-found' }
      mockSignInWithEmailAndPassword.mockRejectedValue(mockError)

      const result = await authService.signInWithEmail('test@example.com', 'wrongpassword')

      expect(result.user).toBeNull()
      expect(result.error).toBe('No account found with this email address.')
      expect(result.needsEmailVerification).toBe(false)
    })

    it('indicates when email verification is needed', async () => {
      const mockUser = {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: false,
      }
      const mockUserCredential = { user: mockUser }
      
      mockSignInWithEmailAndPassword.mockResolvedValue(mockUserCredential as any)

      const result = await authService.signInWithEmail('test@example.com', 'password123')

      expect(result.needsEmailVerification).toBe(true)
    })
  })

  describe('signUpWithEmail', () => {
    it('successfully signs up with email and password', async () => {
      const mockUser = {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: false,
      }
      const mockUserCredential = { user: mockUser }
      
      mockCreateUserWithEmailAndPassword.mockResolvedValue(mockUserCredential as any)
      mockUpdateProfile.mockResolvedValue(undefined)
      mockSendEmailVerification.mockResolvedValue(undefined)

      const result = await authService.signUpWithEmail('test@example.com', 'password123', 'Test User')

      expect(result.user).toBe(mockUser)
      expect(result.error).toBeNull()
      expect(result.emailVerificationSent).toBe(true)
      expect(mockCreateUserWithEmailAndPassword).toHaveBeenCalledWith({}, 'test@example.com', 'password123')
      expect(mockUpdateProfile).toHaveBeenCalledWith(mockUser, { displayName: 'Test User' })
    })

    it('handles sign up errors', async () => {
      const mockError = { code: 'auth/email-already-in-use' }
      mockCreateUserWithEmailAndPassword.mockRejectedValue(mockError)

      const result = await authService.signUpWithEmail('test@example.com', 'password123')

      expect(result.user).toBeNull()
      expect(result.error).toBe('An account with this email already exists.')
      expect(result.emailVerificationSent).toBe(false)
    })
  })

  describe('signInWithGoogle', () => {
    it('successfully signs in with Google', async () => {
      const mockUser = {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: true,
        metadata: {
          creationTime: '2024-01-01T00:00:00Z',
          lastSignInTime: '2024-01-01T00:00:00Z',
        },
      }
      const mockUserCredential = { user: mockUser }
      
      mockSignInWithPopup.mockResolvedValue(mockUserCredential as any)

      const result = await authService.signInWithGoogle()

      expect(result.user).toBe(mockUser)
      expect(result.error).toBeNull()
      expect(result.isNewUser).toBe(true)
    })

    it('handles Google sign in errors', async () => {
      const mockError = { code: 'auth/popup-closed-by-user' }
      mockSignInWithPopup.mockRejectedValue(mockError)

      const result = await authService.signInWithGoogle()

      expect(result.user).toBeNull()
      expect(result.error).toBe('Sign-in popup was closed before completion.')
      expect(result.isNewUser).toBe(false)
    })
  })

  describe('signOut', () => {
    it('successfully signs out', async () => {
      mockSignOut.mockResolvedValue(undefined)

      const result = await authService.signOut()

      expect(result.error).toBeNull()
      expect(mockSignOut).toHaveBeenCalledWith({})
    })

    it('handles sign out errors', async () => {
      const mockError = new Error('Sign out failed')
      mockSignOut.mockRejectedValue(mockError)

      const result = await authService.signOut()

      expect(result.error).toBe('Authentication error: Sign out failed')
    })
  })

  describe('sendPasswordReset', () => {
    it('successfully sends password reset email', async () => {
      mockSendPasswordResetEmail.mockResolvedValue(undefined)

      const result = await authService.sendPasswordReset('test@example.com')

      expect(result.error).toBeNull()
      expect(mockSendPasswordResetEmail).toHaveBeenCalledWith({}, 'test@example.com')
    })

    it('handles password reset errors', async () => {
      const mockError = { code: 'auth/user-not-found' }
      mockSendPasswordResetEmail.mockRejectedValue(mockError)

      const result = await authService.sendPasswordReset('test@example.com')

      expect(result.error).toBe('No account found with this email address.')
    })
  })

  describe('getIdToken', () => {
    it('returns ID token for authenticated user', async () => {
      const mockToken = 'mock-id-token'
      const mockUser = { uid: 'test-uid' }
      
      // Mock current user
      authService['currentUser'] = mockUser as any
      mockGetIdToken.mockResolvedValue(mockToken)

      const token = await authService.getIdToken()

      expect(token).toBe(mockToken)
      expect(mockGetIdToken).toHaveBeenCalledWith(mockUser, false)
    })

    it('returns null when no user is authenticated', async () => {
      authService['currentUser'] = null

      const token = await authService.getIdToken()

      expect(token).toBeNull()
    })

    it('handles token retrieval errors', async () => {
      const mockUser = { uid: 'test-uid' }
      authService['currentUser'] = mockUser as any
      mockGetIdToken.mockRejectedValue(new Error('Token error'))

      const token = await authService.getIdToken()

      expect(token).toBeNull()
    })
  })

  describe('error message mapping', () => {
    it('maps Firebase error codes to user-friendly messages', async () => {
      const errorCodes = [
        { code: 'auth/user-not-found', expected: 'No account found with this email address.' },
        { code: 'auth/wrong-password', expected: 'Incorrect password. Please try again.' },
        { code: 'auth/email-already-in-use', expected: 'An account with this email already exists.' },
        { code: 'auth/weak-password', expected: 'Password should be at least 6 characters long.' },
        { code: 'auth/invalid-email', expected: 'Please enter a valid email address.' },
        { code: 'auth/too-many-requests', expected: 'Too many failed attempts. Please try again later.' },
      ]

      for (const { code, expected } of errorCodes) {
        mockSignInWithEmailAndPassword.mockRejectedValue({ code })
        
        const result = await authService.signInWithEmail('test@example.com', 'password')
        
        expect(result.error).toBe(expected)
      }
    })

    it('handles unknown error codes', async () => {
      mockSignInWithEmailAndPassword.mockRejectedValue({ code: 'auth/unknown-error' })

      const result = await authService.signInWithEmail('test@example.com', 'password')

      expect(result.error).toBe('Authentication error: auth/unknown-error')
    })
  })

  describe('auth state management', () => {
    it('manages auth state listeners', () => {
      const mockCallback = jest.fn()
      const mockUnsubscribe = jest.fn()
      
      mockOnAuthStateChanged.mockImplementation((auth, callback) => {
        callback(null) // Simulate no user
        return mockUnsubscribe
      })

      const unsubscribe = authService.onAuthStateChange(mockCallback)

      expect(mockCallback).toHaveBeenCalledWith(null)
      expect(typeof unsubscribe).toBe('function')

      // Test unsubscribe
      unsubscribe()
      expect(authService['authStateListeners'].size).toBe(0)
    })
  })
})
