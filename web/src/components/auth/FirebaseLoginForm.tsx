'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Eye, EyeOff, Mail, Lock, Github } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { useFirebaseAuth, useAuthError } from '@/contexts/FirebaseAuthContext'
import { getAuthErrorMessage } from '@/lib/firebase'

// Form validation schema
const loginSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
  rememberMe: z.boolean().optional()
})

type LoginFormData = z.infer<typeof loginSchema>

interface FirebaseLoginFormProps {
  onSuccess?: () => void
  redirectTo?: string
  showSignUpLink?: boolean
  className?: string
}

export const FirebaseLoginForm: React.FC<FirebaseLoginFormProps> = ({
  onSuccess,
  redirectTo = '/dashboard',
  showSignUpLink = true,
  className = ''
}) => {
  const router = useRouter()
  const { signIn, signInWithGoogle, signInWithGitHub, loading } = useFirebaseAuth()
  const { error, handleAuthError, clearError } = useAuthError()
  const [showPassword, setShowPassword] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema)
  })

  const handleEmailLogin = async (data: LoginFormData) => {
    setIsSubmitting(true)
    clearError()

    try {
      const result = await signIn(data.email, data.password)
      
      if (result.error) {
        handleAuthError(getAuthErrorMessage(result.error))
      } else if (result.user) {
        reset()
        if (onSuccess) {
          onSuccess()
        } else {
          router.push(redirectTo)
        }
      }
    } catch (err: any) {
      handleAuthError(err.message || 'An unexpected error occurred')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleGoogleLogin = async () => {
    clearError()
    
    try {
      const result = await signInWithGoogle()
      
      if (result.error) {
        handleAuthError(getAuthErrorMessage(result.error))
      } else if (result.user) {
        if (onSuccess) {
          onSuccess()
        } else {
          router.push(redirectTo)
        }
      }
    } catch (err: any) {
      handleAuthError(err.message || 'An unexpected error occurred')
    }
  }

  const handleGitHubLogin = async () => {
    clearError()
    
    try {
      const result = await signInWithGitHub()
      
      if (result.error) {
        handleAuthError(getAuthErrorMessage(result.error))
      } else if (result.user) {
        if (onSuccess) {
          onSuccess()
        } else {
          router.push(redirectTo)
        }
      }
    } catch (err: any) {
      handleAuthError(err.message || 'An unexpected error occurred')
    }
  }

  return (
    <Card className={`w-full max-w-md mx-auto ${className}`}>
      <CardHeader className="space-y-1">
        <CardTitle className="text-2xl font-bold text-center">Sign In</CardTitle>
        <CardDescription className="text-center">
          Enter your credentials to access your account
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Social Login Buttons */}
        <div className="space-y-2">
          <Button
            type="button"
            variant="outline"
            className="w-full"
            onClick={handleGoogleLogin}
            disabled={loading || isSubmitting}
          >
            <svg className="w-4 h-4 mr-2" viewBox="0 0 24 24">
              <path
                fill="currentColor"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="currentColor"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="currentColor"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
              />
              <path
                fill="currentColor"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
              />
            </svg>
            Continue with Google
          </Button>

          <Button
            type="button"
            variant="outline"
            className="w-full"
            onClick={handleGitHubLogin}
            disabled={loading || isSubmitting}
          >
            <Github className="w-4 h-4 mr-2" />
            Continue with GitHub
          </Button>
        </div>

        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <Separator className="w-full" />
          </div>
          <div className="relative flex justify-center text-xs uppercase">
            <span className="bg-background px-2 text-muted-foreground">Or continue with email</span>
          </div>
        </div>

        {/* Email/Password Form */}
        <form onSubmit={handleSubmit(handleEmailLogin)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <div className="relative">
              <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                id="email"
                type="email"
                placeholder="Enter your email"
                className="pl-10"
                {...register('email')}
                disabled={loading || isSubmitting}
              />
            </div>
            {errors.email && (
              <p className="text-sm text-destructive">{errors.email.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                id="password"
                type={showPassword ? 'text' : 'password'}
                placeholder="Enter your password"
                className="pl-10 pr-10"
                {...register('password')}
                disabled={loading || isSubmitting}
              />
              <button
                type="button"
                className="absolute right-3 top-3 h-4 w-4 text-muted-foreground hover:text-foreground"
                onClick={() => setShowPassword(!showPassword)}
                disabled={loading || isSubmitting}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            {errors.password && (
              <p className="text-sm text-destructive">{errors.password.message}</p>
            )}
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <input
                id="rememberMe"
                type="checkbox"
                className="h-4 w-4 rounded border-gray-300"
                {...register('rememberMe')}
                disabled={loading || isSubmitting}
              />
              <Label htmlFor="rememberMe" className="text-sm">
                Remember me
              </Label>
            </div>
            <Button
              type="button"
              variant="link"
              className="px-0 text-sm"
              onClick={() => router.push('/auth/forgot-password')}
              disabled={loading || isSubmitting}
            >
              Forgot password?
            </Button>
          </div>

          <Button
            type="submit"
            className="w-full"
            disabled={loading || isSubmitting}
          >
            {isSubmitting ? 'Signing in...' : 'Sign In'}
          </Button>
        </form>
      </CardContent>

      {showSignUpLink && (
        <CardFooter className="flex justify-center">
          <p className="text-sm text-muted-foreground">
            Don't have an account?{' '}
            <Button
              variant="link"
              className="px-0"
              onClick={() => router.push('/auth/signup')}
              disabled={loading || isSubmitting}
            >
              Sign up
            </Button>
          </p>
        </CardFooter>
      )}
    </Card>
  )
}
