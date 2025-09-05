'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { User } from 'firebase/auth'
import { authService, mapFirebaseUser, getAuthErrorMessage } from '@/lib/firebase'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

export default function FirebaseAuthDemo() {
  const router = useRouter()
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [redirecting, setRedirecting] = useState(false)
  
  // Form states
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [resetEmail, setResetEmail] = useState('')

  useEffect(() => {
    // Listen to auth state changes
    const unsubscribe = authService.onAuthStateChanged((user) => {
      console.log('Auth state changed:', user ? `User: ${user.email}` : 'No user')
      setUser(user)
      setLoading(false)
      
      // Redirect to dashboard if user is authenticated
      if (user && !redirecting) {
        console.log('Initiating redirect for authenticated user')
        setRedirecting(true)
        clearMessages()
        setSuccess(
          user ? 'Authentication successful! Redirecting to dashboard...' : 
          'Already authenticated! Redirecting to dashboard...'
        )
        
        // Use a shorter delay for better UX
        const redirectTimer = setTimeout(() => {
          console.log('Executing redirect to dashboard')
          router.push('/dashboard')
        }, 1500)
        
        // Cleanup timer if component unmounts
        return () => clearTimeout(redirectTimer)
      } else if (!user && redirecting) {
        // Reset redirecting state if user logs out
        console.log('User logged out, resetting redirect state')
        setRedirecting(false)
      }
    })

    return () => unsubscribe()
  }, [router, redirecting]) // Keep redirecting in dependencies to handle logout properly

  const clearMessages = () => {
    setError(null)
    setSuccess(null)
  }

  const handleSignUp = async () => {
    clearMessages()
    setLoading(true)
    
    try {
      const { user, error } = await authService.signUpWithEmail(email, password, displayName)
      
      if (error) {
        setError(getAuthErrorMessage(error))
      } else if (user) {
        setSuccess('Account created successfully!')
        setEmail('')
        setPassword('')
        setDisplayName('')
        
        // Send email verification
        await authService.sendEmailVerification(user)
        setSuccess('Account created successfully! Please check your email for verification.')
      }
    } catch (err: any) {
      setError('Failed to create account: ' + err.message)
    }
    
    setLoading(false)
  }

  const handleSignIn = async () => {
    clearMessages()
    setLoading(true)
    
    try {
      const { user, error } = await authService.signInWithEmail(email, password)
      
      if (error) {
        setError(getAuthErrorMessage(error))
      } else if (user) {
        setSuccess('Signed in successfully! Redirecting to dashboard...')
        setEmail('')
        setPassword('')
      }
    } catch (err: any) {
      setError('Failed to sign in: ' + err.message)
    }
    
    setLoading(false)
  }

  const handleGoogleSignIn = async () => {
    clearMessages()
    setLoading(true)
    
    try {
      const { user, error } = await authService.signInWithGoogle()
      
      if (error) {
        const errorMsg = getAuthErrorMessage(error)
        setError(errorMsg)
        
        // Special handling for popup-closed-by-user error
        if (error.includes('popup-closed-by-user')) {
          setError('Sign-in popup was closed. Please try again and complete the sign-in process.')
        }
      } else if (user) {
        setSuccess('Google Authentication Successful! Redirecting to dashboard...')
      }
    } catch (err: any) {
      console.error('Google sign-in error:', err)
      if (err.code === 'auth/popup-closed-by-user') {
        setError('Sign-in popup was closed. Please try again and complete the sign-in process.')
      } else {
        setError('Failed to sign in with Google: ' + err.message)
      }
    }
    
    setLoading(false)
  }

  const handleGitHubSignIn = async () => {
    clearMessages()
    setLoading(true)
    
    try {
      const { user, error } = await authService.signInWithGitHub()
      
      if (error) {
        setError(getAuthErrorMessage(error))
      } else if (user) {
        setSuccess('GitHub Authentication Successful! Redirecting to dashboard...')
      }
    } catch (err: any) {
      setError('Failed to sign in with GitHub: ' + err.message)
    }
    
    setLoading(false)
  }

  const handleSignOut = async () => {
    clearMessages()
    setLoading(true)
    
    try {
      const { error } = await authService.signOut()
      
      if (error) {
        setError('Failed to sign out: ' + error)
      } else {
        setSuccess('Signed out successfully!')
      }
    } catch (err: any) {
      setError('Failed to sign out: ' + err.message)
    }
    
    setLoading(false)
  }

  const handlePasswordReset = async () => {
    if (!resetEmail) {
      setError('Please enter an email address for password reset')
      return
    }
    
    clearMessages()
    setLoading(true)
    
    try {
      const { error } = await authService.resetPassword(resetEmail)
      
      if (error) {
        setError(getAuthErrorMessage(error))
      } else {
        setSuccess('Password reset email sent! Check your inbox.')
        setResetEmail('')
      }
    } catch (err: any) {
      setError('Failed to send password reset email: ' + err.message)
    }
    
    setLoading(false)
  }

  const handleEmailVerification = async () => {
    if (!user) return
    
    clearMessages()
    setLoading(true)
    
    try {
      const { error } = await authService.sendEmailVerification(user)
      
      if (error) {
        setError('Failed to send verification email: ' + error)
      } else {
        setSuccess('Verification email sent! Check your inbox.')
      }
    } catch (err: any) {
      setError('Failed to send verification email: ' + err.message)
    }
    
    setLoading(false)
  }

  if (loading && !user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-black">
        <div className="text-green-400">Loading Firebase Auth...</div>
      </div>
    )
  }

  if (redirecting) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-black">
        <div className="text-center space-y-6 max-w-md mx-auto p-8">
          <div className="text-green-400 text-2xl font-bold">🚀 Redirecting to Dashboard</div>
          <div className="w-12 h-12 border-4 border-green-400 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <div className="text-gray-400 text-sm">
            Taking you to your secure dashboard...
          </div>
          <Button 
            onClick={() => router.push('/dashboard')} 
            variant="outline" 
            className="bg-green-600 hover:bg-green-700 border-green-500 text-white"
          >
            Go Now →
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-black text-green-400 p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-8 text-center text-green-400">
          🔥 Firebase Authentication Demo
        </h1>
        
        {/* Error/Success Messages */}
        {error && (
          <Alert className="mb-4 bg-red-900/20 border-red-500">
            <AlertDescription className="text-red-400">{error}</AlertDescription>
          </Alert>
        )}
        
        {success && (
          <Alert className="mb-4 bg-green-900/20 border-green-500">
            <AlertDescription className="text-green-400 flex items-center justify-between">
              <span>{success}</span>
              {redirecting && (
                <Button 
                  onClick={() => router.push('/dashboard')} 
                  variant="outline" 
                  size="sm"
                  className="ml-4 bg-green-600 hover:bg-green-700 border-green-500"
                >
                  Skip to Dashboard
                </Button>
              )}
            </AlertDescription>
          </Alert>
        )}

        {user ? (
          // User is signed in
          <div className="space-y-6">
            <Card className="bg-gray-900 border-green-500">
              <CardHeader>
                <CardTitle className="text-green-400">👤 User Profile</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <strong className="text-green-300">UID:</strong>
                    <p className="text-gray-300 font-mono text-sm break-all">{user.uid}</p>
                  </div>
                  <div>
                    <strong className="text-green-300">Email:</strong>
                    <p className="text-gray-300">{user.email || 'Not provided'}</p>
                  </div>
                  <div>
                    <strong className="text-green-300">Display Name:</strong>
                    <p className="text-gray-300">{user.displayName || 'Not provided'}</p>
                  </div>
                  <div>
                    <strong className="text-green-300">Email Verified:</strong>
                    <Badge variant={user.emailVerified ? "default" : "destructive"}>
                      {user.emailVerified ? '✅ Verified' : '❌ Not Verified'}
                    </Badge>
                  </div>
                  <div>
                    <strong className="text-green-300">Phone:</strong>
                    <p className="text-gray-300">{user.phoneNumber || 'Not provided'}</p>
                  </div>
                  <div>
                    <strong className="text-green-300">Photo URL:</strong>
                    <p className="text-gray-300 text-sm break-all">{user.photoURL || 'Not provided'}</p>
                  </div>
                </div>
                
                <div>
                  <strong className="text-green-300">Provider Data:</strong>
                  <div className="mt-2 space-y-2">
                    {user.providerData.map((provider, index) => (
                      <div key={index} className="bg-gray-800 p-2 rounded">
                        <Badge className="mr-2">{provider.providerId}</Badge>
                        <span className="text-sm text-gray-300">{provider.email}</span>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="flex gap-2 flex-wrap">
                  <Button 
                    onClick={() => router.push('/dashboard')} 
                    variant="default"
                    className="bg-green-600 hover:bg-green-700"
                  >
                    🚀 Go to Dashboard
                  </Button>
                  <Button onClick={handleSignOut} variant="destructive">
                    Sign Out
                  </Button>
                  {!user.emailVerified && user.email && (
                    <Button onClick={handleEmailVerification} variant="outline">
                      Send Verification Email
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Token Information */}
            <Card className="bg-gray-900 border-green-500">
              <CardHeader>
                <CardTitle className="text-green-400">🔐 Token Information</CardTitle>
              </CardHeader>
              <CardContent>
                <Button
                  onClick={async () => {
                    const token = await authService.getIdToken()
                    if (token) {
                      navigator.clipboard.writeText(token)
                      setSuccess('ID Token copied to clipboard!')
                    }
                  }}
                  variant="outline"
                  className="mr-2"
                >
                  Copy ID Token
                </Button>
                <Button
                  onClick={async () => {
                    const token = await authService.getIdToken(true)
                    if (token) {
                      navigator.clipboard.writeText(token)
                      setSuccess('Refreshed ID Token copied to clipboard!')
                    }
                  }}
                  variant="outline"
                >
                  Refresh & Copy Token
                </Button>
              </CardContent>
            </Card>
          </div>
        ) : (
          // User is not signed in
          <Tabs defaultValue="signin" className="space-y-6">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="signin">Sign In</TabsTrigger>
              <TabsTrigger value="signup">Sign Up</TabsTrigger>
              <TabsTrigger value="social">Social Auth</TabsTrigger>
              <TabsTrigger value="reset">Reset Password</TabsTrigger>
            </TabsList>

            <TabsContent value="signin">
              <Card className="bg-gray-900 border-green-500">
                <CardHeader>
                  <CardTitle className="text-green-400">🔑 Sign In</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <Input
                    type="email"
                    placeholder="Email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="bg-gray-800 border-gray-700 text-green-400"
                  />
                  <Input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="bg-gray-800 border-gray-700 text-green-400"
                  />
                  <Button 
                    onClick={handleSignIn} 
                    disabled={!email || !password || loading}
                    className="w-full"
                  >
                    {loading ? 'Signing in...' : 'Sign In'}
                  </Button>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="signup">
              <Card className="bg-gray-900 border-green-500">
                <CardHeader>
                  <CardTitle className="text-green-400">📝 Sign Up</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <Input
                    type="text"
                    placeholder="Display Name (optional)"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className="bg-gray-800 border-gray-700 text-green-400"
                  />
                  <Input
                    type="email"
                    placeholder="Email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="bg-gray-800 border-gray-700 text-green-400"
                  />
                  <Input
                    type="password"
                    placeholder="Password (min 6 characters)"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="bg-gray-800 border-gray-700 text-green-400"
                  />
                  <Button 
                    onClick={handleSignUp} 
                    disabled={!email || !password || loading}
                    className="w-full"
                  >
                    {loading ? 'Creating Account...' : 'Sign Up'}
                  </Button>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="social">
              <Card className="bg-gray-900 border-green-500">
                <CardHeader>
                  <CardTitle className="text-green-400">🌐 Social Authentication</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <Button 
                    onClick={handleGoogleSignIn} 
                    disabled={loading}
                    className="w-full bg-red-600 hover:bg-red-700"
                  >
                    {loading ? 'Signing in...' : '🔴 Sign in with Google'}
                  </Button>
                  <Button 
                    onClick={handleGitHubSignIn} 
                    disabled={loading}
                    className="w-full bg-gray-800 hover:bg-gray-700"
                  >
                    {loading ? 'Signing in...' : '⚫ Sign in with GitHub'}
                  </Button>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="reset">
              <Card className="bg-gray-900 border-green-500">
                <CardHeader>
                  <CardTitle className="text-green-400">🔄 Reset Password</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <Input
                    type="email"
                    placeholder="Enter your email"
                    value={resetEmail}
                    onChange={(e) => setResetEmail(e.target.value)}
                    className="bg-gray-800 border-gray-700 text-green-400"
                  />
                  <Button 
                    onClick={handlePasswordReset} 
                    disabled={!resetEmail || loading}
                    className="w-full"
                  >
                    {loading ? 'Sending...' : 'Send Reset Email'}
                  </Button>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        )}

        {/* Firebase Status */}
        <Card className="mt-8 bg-gray-900 border-green-500">
          <CardHeader>
            <CardTitle className="text-green-400">🔥 Firebase Status & Links</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 text-sm mb-6">
              <div>
                <strong className="text-green-300">Project ID:</strong>
                <p className="text-gray-300">hackai-auth-system</p>
              </div>
              <div>
                <strong className="text-green-300">Environment:</strong>
                <Badge variant="outline">
                  {process.env.NODE_ENV === 'development' ? '🧪 Development' : '🚀 Production'}
                </Badge>
              </div>
              <div>
                <strong className="text-green-300">Emulator Mode:</strong>
                <Badge variant={process.env.NEXT_PUBLIC_USE_FIREBASE_EMULATOR === 'true' ? "default" : "secondary"}>
                  {process.env.NEXT_PUBLIC_USE_FIREBASE_EMULATOR === 'true' ? '✅ Enabled' : '❌ Disabled'}
                </Badge>
              </div>
              <div>
                <strong className="text-green-300">Auth Domain:</strong>
                <p className="text-gray-300 text-xs">hackai-auth-system.firebaseapp.com</p>
              </div>
            </div>
            
            {/* Quick Links */}
            <div className="border-t border-gray-700 pt-4">
              <h4 className="text-green-300 font-semibold mb-3">🔗 Useful Links</h4>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <a 
                  href="http://localhost:4001" 
                  target="_blank" 
                  className="text-blue-400 hover:text-blue-300 underline"
                >
                  📊 Firebase Emulator UI
                </a>
                <a 
                  href="http://localhost:4001/auth" 
                  target="_blank" 
                  className="text-blue-400 hover:text-blue-300 underline"
                >
                  👤 Auth Emulator
                </a>
                <a 
                  href="http://localhost:4001/firestore" 
                  target="_blank" 
                  className="text-blue-400 hover:text-blue-300 underline"
                >
                  🗃️ Firestore Emulator
                </a>
                <a 
                  href="https://console.firebase.google.com/project/hackai-auth-system" 
                  target="_blank" 
                  className="text-blue-400 hover:text-blue-300 underline"
                >
                  🚀 Firebase Console
                </a>
              </div>
            </div>
            
            {/* Instructions */}
            <div className="border-t border-gray-700 pt-4 mt-4">
              <h4 className="text-green-300 font-semibold mb-2">📖 Instructions</h4>
              <div className="text-xs text-gray-400 space-y-1">
                <p>• Use the tabs above to test different authentication methods</p>
                <p>• Email/Password works with any valid email format</p>
                <p>• Google/GitHub auth will work in emulator mode (test accounts)</p>
                <p>• Check the Firebase Emulator UI to see created users</p>
                <p>• Authentication errors are displayed with helpful messages</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}