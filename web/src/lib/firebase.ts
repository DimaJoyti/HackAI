import { initializeApp, getApps, FirebaseApp } from 'firebase/app'
import { 
  getAuth, 
  Auth,
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
  NextOrObserver
} from 'firebase/auth'
import { 
  getFirestore, 
  Firestore,
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
  const env = process.env.NODE_ENV || 'development'
  
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
        apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY_DEV!,
        authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN_DEV!,
        projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID_DEV!,
        storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET_DEV!,
        messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID_DEV!,
        appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID_DEV!,
        measurementId: process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID_DEV
      }
  }
}

// Initialize Firebase
let app: FirebaseApp
let auth: Auth
let db: Firestore

const initializeFirebase = () => {
  if (getApps().length === 0) {
    const config = getFirebaseConfig()
    app = initializeApp(config)
    
    // Initialize Auth
    auth = getAuth(app)
    
    // Initialize Firestore
    db = getFirestore(app)
    
    // Connect to emulators in development
    if (process.env.NODE_ENV === 'development' && process.env.NEXT_PUBLIC_USE_FIREBASE_EMULATOR === 'true') {
      try {
        connectAuthEmulator(auth, 'http://localhost:9099')
        connectFirestoreEmulator(db, 'localhost', 8080)
      } catch (error) {
        console.warn('Firebase emulators already connected or not available:', error)
      }
    }
  } else {
    app = getApps()[0]
    auth = getAuth(app)
    db = getFirestore(app)
  }
}

// Initialize Firebase
initializeFirebase()

// Auth providers
export const googleProvider = new GoogleAuthProvider()
export const githubProvider = new GithubAuthProvider()

// Configure providers
googleProvider.addScope('email')
googleProvider.addScope('profile')
githubProvider.addScope('user:email')

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
