import {
  User,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  signOut,
  sendPasswordResetEmail,
  sendEmailVerification,
  updateProfile,
  updatePassword,
  reauthenticateWithCredential,
  EmailAuthProvider,
  linkWithPopup,
  unlink,
  deleteUser,
  onAuthStateChanged,
  getIdToken,
  getIdTokenResult
} from 'firebase/auth'
import { auth, googleProvider, githubProvider } from './firebase'

// Enhanced authentication service with comprehensive error handling and security
export class EnhancedFirebaseAuth {
  private static instance: EnhancedFirebaseAuth
  private authStateListeners: Set<(user: User | null) => void> = new Set()
  private currentUser: User | null = null

  private constructor() {
    // Set up auth state listener
    onAuthStateChanged(auth, (user) => {
      this.currentUser = user
      this.authStateListeners.forEach(listener => listener(user))
    })
  }

  static getInstance(): EnhancedFirebaseAuth {
    if (!EnhancedFirebaseAuth.instance) {
      EnhancedFirebaseAuth.instance = new EnhancedFirebaseAuth()
    }
    return EnhancedFirebaseAuth.instance
  }

  // Subscribe to auth state changes
  onAuthStateChange(callback: (user: User | null) => void): () => void {
    this.authStateListeners.add(callback)
    // Call immediately with current state
    callback(this.currentUser)
    
    // Return unsubscribe function
    return () => {
      this.authStateListeners.delete(callback)
    }
  }

  // Get current user
  getCurrentUser(): User | null {
    return this.currentUser
  }

  // Get ID token with refresh
  async getIdToken(forceRefresh = false): Promise<string | null> {
    if (!this.currentUser) return null
    
    try {
      return await getIdToken(this.currentUser, forceRefresh)
    } catch (error) {
      console.error('Failed to get ID token:', error)
      return null
    }
  }

  // Get ID token result with claims
  async getIdTokenResult(forceRefresh = false) {
    if (!this.currentUser) return null
    
    try {
      return await getIdTokenResult(this.currentUser, forceRefresh)
    } catch (error) {
      console.error('Failed to get ID token result:', error)
      return null
    }
  }

  // Enhanced sign in with email and password
  async signInWithEmail(email: string, password: string) {
    try {
      const result = await signInWithEmailAndPassword(auth, email, password)
      
      // Log successful authentication
      this.logAuthEvent('email_sign_in_success', {
        uid: result.user.uid,
        email: result.user.email,
        emailVerified: result.user.emailVerified
      })
      
      return {
        user: result.user,
        error: null,
        needsEmailVerification: !result.user.emailVerified
      }
    } catch (error: any) {
      this.logAuthEvent('email_sign_in_failed', { email, error: error.code })
      return {
        user: null,
        error: this.getEnhancedErrorMessage(error),
        needsEmailVerification: false
      }
    }
  }

  // Enhanced sign up with email and password
  async signUpWithEmail(email: string, password: string, displayName?: string) {
    try {
      const result = await createUserWithEmailAndPassword(auth, email, password)
      
      // Update profile with display name if provided
      if (displayName && result.user) {
        await updateProfile(result.user, { displayName })
      }
      
      // Send email verification
      await this.sendEmailVerification()
      
      this.logAuthEvent('email_sign_up_success', {
        uid: result.user.uid,
        email: result.user.email,
        displayName
      })
      
      return {
        user: result.user,
        error: null,
        emailVerificationSent: true
      }
    } catch (error: any) {
      this.logAuthEvent('email_sign_up_failed', { email, error: error.code })
      return {
        user: null,
        error: this.getEnhancedErrorMessage(error),
        emailVerificationSent: false
      }
    }
  }

  // Enhanced Google sign in
  async signInWithGoogle() {
    try {
      const result = await signInWithPopup(auth, googleProvider)
      
      this.logAuthEvent('google_sign_in_success', {
        uid: result.user.uid,
        email: result.user.email,
        isNewUser: result.user.metadata.creationTime === result.user.metadata.lastSignInTime
      })
      
      return {
        user: result.user,
        error: null,
        isNewUser: result.user.metadata.creationTime === result.user.metadata.lastSignInTime
      }
    } catch (error: any) {
      this.logAuthEvent('google_sign_in_failed', { error: error.code })
      return {
        user: null,
        error: this.getEnhancedErrorMessage(error),
        isNewUser: false
      }
    }
  }

  // Enhanced GitHub sign in
  async signInWithGitHub() {
    try {
      const result = await signInWithPopup(auth, githubProvider)
      
      this.logAuthEvent('github_sign_in_success', {
        uid: result.user.uid,
        email: result.user.email,
        isNewUser: result.user.metadata.creationTime === result.user.metadata.lastSignInTime
      })
      
      return {
        user: result.user,
        error: null,
        isNewUser: result.user.metadata.creationTime === result.user.metadata.lastSignInTime
      }
    } catch (error: any) {
      this.logAuthEvent('github_sign_in_failed', { error: error.code })
      return {
        user: null,
        error: this.getEnhancedErrorMessage(error),
        isNewUser: false
      }
    }
  }

  // Enhanced sign out
  async signOut() {
    try {
      const uid = this.currentUser?.uid
      await signOut(auth)
      
      this.logAuthEvent('sign_out_success', { uid })
      
      return { error: null }
    } catch (error: any) {
      this.logAuthEvent('sign_out_failed', { error: error.code })
      return { error: this.getEnhancedErrorMessage(error) }
    }
  }

  // Send email verification
  async sendEmailVerification() {
    if (!this.currentUser) {
      return { error: 'No user is currently signed in' }
    }

    try {
      await sendEmailVerification(this.currentUser)
      
      this.logAuthEvent('email_verification_sent', {
        uid: this.currentUser.uid,
        email: this.currentUser.email
      })
      
      return { error: null }
    } catch (error: any) {
      this.logAuthEvent('email_verification_failed', {
        uid: this.currentUser.uid,
        error: error.code
      })
      return { error: this.getEnhancedErrorMessage(error) }
    }
  }

  // Send password reset email
  async sendPasswordReset(email: string) {
    try {
      await sendPasswordResetEmail(auth, email)
      
      this.logAuthEvent('password_reset_sent', { email })
      
      return { error: null }
    } catch (error: any) {
      this.logAuthEvent('password_reset_failed', { email, error: error.code })
      return { error: this.getEnhancedErrorMessage(error) }
    }
  }

  // Update user profile
  async updateUserProfile(updates: { displayName?: string; photoURL?: string }) {
    if (!this.currentUser) {
      return { error: 'No user is currently signed in' }
    }

    try {
      await updateProfile(this.currentUser, updates)
      
      this.logAuthEvent('profile_updated', {
        uid: this.currentUser.uid,
        updates
      })
      
      return { error: null }
    } catch (error: any) {
      this.logAuthEvent('profile_update_failed', {
        uid: this.currentUser.uid,
        error: error.code
      })
      return { error: this.getEnhancedErrorMessage(error) }
    }
  }

  // Update password with reauthentication
  async updatePassword(currentPassword: string, newPassword: string) {
    if (!this.currentUser || !this.currentUser.email) {
      return { error: 'No user is currently signed in' }
    }

    try {
      // Reauthenticate user first
      const credential = EmailAuthProvider.credential(this.currentUser.email, currentPassword)
      await reauthenticateWithCredential(this.currentUser, credential)
      
      // Update password
      await updatePassword(this.currentUser, newPassword)
      
      this.logAuthEvent('password_updated', {
        uid: this.currentUser.uid
      })
      
      return { error: null }
    } catch (error: any) {
      this.logAuthEvent('password_update_failed', {
        uid: this.currentUser.uid,
        error: error.code
      })
      return { error: this.getEnhancedErrorMessage(error) }
    }
  }

  // Link account with Google
  async linkWithGoogle() {
    if (!this.currentUser) {
      return { error: 'No user is currently signed in' }
    }

    try {
      const result = await linkWithPopup(this.currentUser, googleProvider)
      
      this.logAuthEvent('google_account_linked', {
        uid: this.currentUser.uid
      })
      
      return { user: result.user, error: null }
    } catch (error: any) {
      this.logAuthEvent('google_account_link_failed', {
        uid: this.currentUser.uid,
        error: error.code
      })
      return { user: null, error: this.getEnhancedErrorMessage(error) }
    }
  }

  // Link account with GitHub
  async linkWithGitHub() {
    if (!this.currentUser) {
      return { error: 'No user is currently signed in' }
    }

    try {
      const result = await linkWithPopup(this.currentUser, githubProvider)
      
      this.logAuthEvent('github_account_linked', {
        uid: this.currentUser.uid
      })
      
      return { user: result.user, error: null }
    } catch (error: any) {
      this.logAuthEvent('github_account_link_failed', {
        uid: this.currentUser.uid,
        error: error.code
      })
      return { user: null, error: this.getEnhancedErrorMessage(error) }
    }
  }

  // Unlink provider
  async unlinkProvider(providerId: string) {
    if (!this.currentUser) {
      return { error: 'No user is currently signed in' }
    }

    try {
      const result = await unlink(this.currentUser, providerId)
      
      this.logAuthEvent('provider_unlinked', {
        uid: this.currentUser.uid,
        providerId
      })
      
      return { user: result, error: null }
    } catch (error: any) {
      this.logAuthEvent('provider_unlink_failed', {
        uid: this.currentUser.uid,
        providerId,
        error: error.code
      })
      return { user: null, error: this.getEnhancedErrorMessage(error) }
    }
  }

  // Delete user account
  async deleteAccount(password?: string) {
    if (!this.currentUser) {
      return { error: 'No user is currently signed in' }
    }

    try {
      // Reauthenticate if password provided
      if (password && this.currentUser.email) {
        const credential = EmailAuthProvider.credential(this.currentUser.email, password)
        await reauthenticateWithCredential(this.currentUser, credential)
      }
      
      const uid = this.currentUser.uid
      await deleteUser(this.currentUser)
      
      this.logAuthEvent('account_deleted', { uid })
      
      return { error: null }
    } catch (error: any) {
      this.logAuthEvent('account_deletion_failed', {
        uid: this.currentUser.uid,
        error: error.code
      })
      return { error: this.getEnhancedErrorMessage(error) }
    }
  }

  // Enhanced error message mapping
  private getEnhancedErrorMessage(error: any): string {
    const errorCode = error.code || error.message

    const errorMessages: Record<string, string> = {
      'auth/user-not-found': 'No account found with this email address.',
      'auth/wrong-password': 'Incorrect password. Please try again.',
      'auth/email-already-in-use': 'An account with this email already exists.',
      'auth/weak-password': 'Password should be at least 6 characters long.',
      'auth/invalid-email': 'Please enter a valid email address.',
      'auth/user-disabled': 'This account has been disabled.',
      'auth/too-many-requests': 'Too many failed attempts. Please try again later.',
      'auth/network-request-failed': 'Network error. Please check your connection.',
      'auth/popup-closed-by-user': 'Sign-in popup was closed before completion.',
      'auth/cancelled-popup-request': 'Sign-in was cancelled.',
      'auth/popup-blocked': 'Sign-in popup was blocked by your browser.',
      'auth/account-exists-with-different-credential': 'An account already exists with the same email but different sign-in credentials.',
      'auth/credential-already-in-use': 'This credential is already associated with a different user account.',
      'auth/requires-recent-login': 'This operation requires recent authentication. Please sign in again.',
      'auth/invalid-verification-code': 'Invalid verification code.',
      'auth/invalid-verification-id': 'Invalid verification ID.',
      'auth/missing-verification-code': 'Missing verification code.',
      'auth/missing-verification-id': 'Missing verification ID.'
    }

    return errorMessages[errorCode] || `Authentication error: ${errorCode}`
  }

  // Log authentication events for monitoring
  private logAuthEvent(event: string, data: any = {}) {
    if (process.env.NODE_ENV === 'development') {
      console.log(`[Firebase Auth] ${event}:`, data)
    }

    // In production, you might want to send this to your analytics service
    if (typeof window !== 'undefined' && window.gtag) {
      window.gtag('event', event, {
        event_category: 'authentication',
        ...data
      })
    }
  }
}

// Export singleton instance
export const enhancedFirebaseAuth = EnhancedFirebaseAuth.getInstance()

// Export types
export interface AuthResult {
  user: User | null
  error: string | null
}

export interface SignUpResult extends AuthResult {
  emailVerificationSent: boolean
}

export interface SignInResult extends AuthResult {
  needsEmailVerification: boolean
  isNewUser?: boolean
}
