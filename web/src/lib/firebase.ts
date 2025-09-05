import { initializeApp, getApps, FirebaseApp } from 'firebase/app'
import {
  getAuth,
  connectAuthEmulator,
  GoogleAuthProvider,
  GithubAuthProvider,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  signOut,
  sendPasswordResetEmail,
  sendEmailVerification,
  updateProfile,
  User,
  onAuthStateChanged,
  NextOrObserver,
  linkWithPopup,
  unlink
} from 'firebase/auth'
import { 
  getFirestore, 
  connectFirestoreEmulator 
} from 'firebase/firestore'

// Firebase configuration interface
interface FirebaseConfig {
  apiKey: string
  authDomain: string
  projectId: string
  storageBucket: string
  messagingSenderId: string
  appId: string
  measurementId?: string
}

// Environment-specific configurations
const getFirebaseConfig = (): FirebaseConfig => {
  const env = process.env.NEXT_PUBLIC_FIREBASE_ENV || process.env.NODE_ENV || 'development'
  
  switch (env) {
    case 'production':
      return {
        apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY_PROD!,
        authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN_PROD!,
        projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID_PROD!,
        storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET_PROD!,
        messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID_PROD!,
        appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID_PROD!,
        measurementId: process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID_PROD
      }
    case 'staging':
      return {
        apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY_STAGING!,
        authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN_STAGING!,
        projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID_STAGING!,
        storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET_STAGING!,
        messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID_STAGING!,
        appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID_STAGING!,
        measurementId: process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID_STAGING
      }
    default: // development
      return {
        apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY_DEV || 'AIzaSyDWROT1zivWD8RMxKGqo3ZAaHznkUvUoUI',
        authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN_DEV || 'hackai-auth-system.firebaseapp.com',
        projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID_DEV || 'hackai-auth-system',
        storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET_DEV || 'hackai-auth-system.firebasestorage.app',
        messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID_DEV || '436006647060',
        appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID_DEV || '1:436006647060:web:2de55c9b536fed4dc6be01',
        measurementId: process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID_DEV
      }
  }
}

// Initialize Firebase
const initializeFirebase = () => {
  let firebaseApp: FirebaseApp
  
  if (getApps().length === 0) {
    const config = getFirebaseConfig()
    firebaseApp = initializeApp(config)
  } else {
    firebaseApp = getApps()[0]
  }
  
  // Initialize Auth
  const firebaseAuth = getAuth(firebaseApp)
  
  // Initialize Firestore
  const firebaseDb = getFirestore(firebaseApp)
  
  // Connect to emulators in development
  if (process.env.NODE_ENV === 'development' && process.env.NEXT_PUBLIC_USE_FIREBASE_EMULATOR === 'true') {
    try {
      connectAuthEmulator(firebaseAuth, 'http://localhost:9099')
      connectFirestoreEmulator(firebaseDb, 'localhost', 8080)
    } catch (error) {
      console.warn('Firebase emulators already connected or not available:', error)
    }
  }
  
  return { app: firebaseApp, auth: firebaseAuth, db: firebaseDb }
}

// Initialize Firebase
const { app, auth, db } = initializeFirebase()

// Auth providers
export const googleProvider = new GoogleAuthProvider()
export const githubProvider = new GithubAuthProvider()

// Configure providers with advanced scopes
googleProvider.addScope('email')
googleProvider.addScope('profile')
googleProvider.addScope('openid')
googleProvider.addScope('https://www.googleapis.com/auth/userinfo.email')
googleProvider.addScope('https://www.googleapis.com/auth/userinfo.profile')
googleProvider.addScope('https://www.googleapis.com/auth/user.birthday.read')
googleProvider.addScope('https://www.googleapis.com/auth/user.phonenumbers.read')

// Configure for offline access
googleProvider.setCustomParameters({
  'access_type': 'offline',
  'prompt': 'consent'
})

githubProvider.addScope('user:email')
githubProvider.addScope('read:user')

// Auth functions
export const authService = {
  // Sign in with email and password
  signInWithEmail: async (email: string, password: string) => {
    try {
      const result = await signInWithEmailAndPassword(auth, email, password)
      return { user: result.user, error: null }
    } catch (error: any) {
      return { user: null, error: error.message }
    }
  },

  // Sign up with email and password
  signUpWithEmail: async (email: string, password: string, displayName?: string) => {
    try {
      const result = await createUserWithEmailAndPassword(auth, email, password)
      
      // Update profile with display name if provided
      if (displayName && result.user) {
        await updateProfile(result.user, { displayName })
      }
      
      return { user: result.user, error: null }
    } catch (error: any) {
      return { user: null, error: error.message }
    }
  },

  // Sign in with Google
  signInWithGoogle: async () => {
    try {
      const result = await signInWithPopup(auth, googleProvider)
      return { user: result.user, error: null }
    } catch (error: any) {
      return { user: null, error: error.message }
    }
  },

  // Sign in with Google with custom scopes
  signInWithGoogleAdvanced: async (customScopes?: string[]) => {
    try {
      const provider = new GoogleAuthProvider()

      // Add default scopes
      provider.addScope('email')
      provider.addScope('profile')
      provider.addScope('openid')

      // Add custom scopes if provided
      if (customScopes) {
        customScopes.forEach(scope => provider.addScope(scope))
      }

      // Configure for offline access
      provider.setCustomParameters({
        'access_type': 'offline',
        'prompt': 'consent'
      })

      const result = await signInWithPopup(auth, provider)

      // Get additional token information
      const credential = GoogleAuthProvider.credentialFromResult(result)
      const accessToken = credential?.accessToken

      return {
        user: result.user,
        error: null,
        accessToken,
        scopes: customScopes
      }
    } catch (error: any) {
      return { user: null, error: error.message }
    }
  },

  // Sign in with GitHub
  signInWithGitHub: async () => {
    try {
      const result = await signInWithPopup(auth, githubProvider)
      return { user: result.user, error: null }
    } catch (error: any) {
      return { user: null, error: error.message }
    }
  },

  // Sign out
  signOut: async () => {
    try {
      await signOut(auth)
      return { error: null }
    } catch (error: any) {
      return { error: error.message }
    }
  },

  // Send password reset email
  resetPassword: async (email: string) => {
    try {
      await sendPasswordResetEmail(auth, email)
      return { error: null }
    } catch (error: any) {
      return { error: error.message }
    }
  },

  // Send email verification
  sendEmailVerification: async (user: User) => {
    try {
      await sendEmailVerification(user)
      return { error: null }
    } catch (error: any) {
      return { error: error.message }
    }
  },

  // Update user profile
  updateProfile: async (user: User, profile: { displayName?: string; photoURL?: string }) => {
    try {
      await updateProfile(user, profile)
      return { error: null }
    } catch (error: any) {
      return { error: error.message }
    }
  },

  // Get current user
  getCurrentUser: () => auth.currentUser,

  // Listen to auth state changes
  onAuthStateChanged: (callback: NextOrObserver<User>) => {
    return onAuthStateChanged(auth, callback)
  },

  // Get ID token
  getIdToken: async (forceRefresh = false) => {
    const user = auth.currentUser
    if (!user) return null

    try {
      return await user.getIdToken(forceRefresh)
    } catch (error) {
      console.error('Error getting ID token:', error)
      return null
    }
  },

  // Get Google access token
  getGoogleAccessToken: async () => {
    const user = auth.currentUser
    if (!user) return null

    try {
      // Get the Google credential from the user
      const providerData = user.providerData.find(
        provider => provider.providerId === 'google.com'
      )

      if (!providerData) {
        throw new Error('User is not signed in with Google')
      }

      // This would typically require server-side token exchange
      // For now, we'll return the ID token
      return await user.getIdToken()
    } catch (error) {
      console.error('Error getting Google access token:', error)
      return null
    }
  },

  // Refresh Google tokens
  refreshGoogleTokens: async () => {
    try {
      const user = auth.currentUser
      if (!user) throw new Error('No user signed in')

      // Force refresh the ID token
      const idToken = await user.getIdToken(true)

      // In a real implementation, this would call your backend
      // to refresh the Google access token using the refresh token
      const response = await fetch('/api/firebase/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        }
      })

      if (!response.ok) {
        throw new Error('Failed to refresh tokens')
      }

      const tokens = await response.json()
      return { tokens, error: null }
    } catch (error: any) {
      return { tokens: null, error: error.message }
    }
  },

  // Get user profile from Google
  getGoogleUserProfile: async () => {
    try {
      const idToken = await authService.getIdToken()
      if (!idToken) throw new Error('No ID token available')

      const response = await fetch('/api/firebase/auth/profile', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${idToken}`
        }
      })

      if (!response.ok) {
        throw new Error('Failed to get user profile')
      }

      const profile = await response.json()
      return { profile, error: null }
    } catch (error: any) {
      return { profile: null, error: error.message }
    }
  },

  // Revoke Google tokens
  revokeGoogleTokens: async () => {
    try {
      const idToken = await authService.getIdToken()
      if (!idToken) throw new Error('No ID token available')

      const response = await fetch('/api/firebase/auth/revoke', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        }
      })

      if (!response.ok) {
        throw new Error('Failed to revoke tokens')
      }

      return { error: null }
    } catch (error: any) {
      return { error: error.message }
    }
  },

  // Link Google account
  linkGoogleAccount: async () => {
    try {
      const user = auth.currentUser
      if (!user) throw new Error('No user signed in')

      const provider = new GoogleAuthProvider()
      provider.addScope('email')
      provider.addScope('profile')
      provider.setCustomParameters({
        'access_type': 'offline',
        'prompt': 'consent'
      })

      const result = await linkWithPopup(user, provider)
      return { user: result.user, error: null }
    } catch (error: any) {
      return { user: null, error: error.message }
    }
  },

  // Unlink Google account
  unlinkGoogleAccount: async () => {
    try {
      const user = auth.currentUser
      if (!user) throw new Error('No user signed in')

      const result = await unlink(user, 'google.com')
      return { user: result, error: null }
    } catch (error: any) {
      return { user: null, error: error.message }
    }
  }
}

// Export Firebase instances
export { app, auth, db }
export default app

// Types
export interface AuthUser {
  uid: string
  email: string | null
  displayName: string | null
  photoURL: string | null
  emailVerified: boolean
  phoneNumber: string | null
  customClaims?: { [key: string]: any }
}

export interface AuthError {
  code: string
  message: string
}

export interface AuthResult {
  user: User | null
  error: string | null
}

// Helper functions
export const mapFirebaseUser = (user: User | null): AuthUser | null => {
  if (!user) return null
  
  return {
    uid: user.uid,
    email: user.email,
    displayName: user.displayName,
    photoURL: user.photoURL,
    emailVerified: user.emailVerified,
    phoneNumber: user.phoneNumber
  }
}

export const isAuthError = (error: any): error is AuthError => {
  return error && typeof error.code === 'string' && typeof error.message === 'string'
}

// Firebase error codes mapping
export const getAuthErrorMessage = (errorCode: string): string => {
  switch (errorCode) {
    case 'auth/user-not-found':
      return 'No user found with this email address.'
    case 'auth/wrong-password':
      return 'Incorrect password.'
    case 'auth/email-already-in-use':
      return 'An account with this email already exists.'
    case 'auth/weak-password':
      return 'Password should be at least 6 characters.'
    case 'auth/invalid-email':
      return 'Invalid email address.'
    case 'auth/user-disabled':
      return 'This account has been disabled.'
    case 'auth/too-many-requests':
      return 'Too many failed attempts. Please try again later.'
    case 'auth/network-request-failed':
      return 'Network error. Please check your connection.'
    case 'auth/popup-closed-by-user':
      return 'Sign-in popup was closed before completion.'
    case 'auth/cancelled-popup-request':
      return 'Sign-in was cancelled.'
    default:
      return 'An error occurred during authentication.'
  }
}
