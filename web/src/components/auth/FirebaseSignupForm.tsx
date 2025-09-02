'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Eye, EyeOff, Mail, Lock, User, Github } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { Checkbox } from '@/components/ui/checkbox'
import { useFirebaseAuth, useAuthError } from '@/contexts/FirebaseAuthContext'
import { getAuthErrorMessage } from '@/lib/firebase'

// Form validation schema
const signupSchema = z.object({
  firstName: z.string().min(2, 'First name must be at least 2 characters'),
  lastName: z.string().min(2, 'Last name must be at least 2 characters'),
  email: z.string().email('Please enter a valid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  confirmPassword: z.string(),
  acceptTerms: z.boolean().refine(val => val === true, 'You must accept the terms and conditions')
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"]
})

type SignupFormData = z.infer<typeof signupSchema>

interface FirebaseSignupFormProps {
  onSuccess?: () => void
  redirectTo?: string
  showSignInLink?: boolean
  className?: string
}

export const FirebaseSignupForm: React.FC<FirebaseSignupFormProps> = ({
  onSuccess,
  redirectTo = '/dashboard',
  showSignInLink = true,
  className = ''
}) => {
  const router = useRouter()
  const { signUp, signInWithGoogle, signInWithGitHub, sendEmailVerification, loading } = useFirebaseAuth()
  const { error, handleAuthError, clearError } = useAuthError()
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [emailSent, setEmailSent] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
    watch
  } = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema)
  })

  const handleEmailSignup = async (data: SignupFormData) => {
    setIsSubmitting(true)
    clearError()

    try {
      const displayName = `${data.firstName} ${data.lastName}`
      const result = await signUp(data.email, data.password, displayName)
      
      if (result.error) {
        handleAuthError(getAuthErrorMessage(result.error))
      } else if (result.user) {
        // Send email verification
        const verificationResult = await sendEmailVerification()
        if (!verificationResult.error) {
          setEmailSent(true)
        }
        
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

  const handleGoogleSignup = async () => {
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

  const handleGitHubSignup = async () => {
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

  if (emailSent) {
    return (
      <Card className={`w-full max-w-md mx-auto ${className}`}>
        <CardHeader className="space-y-1">
          <CardTitle className="text-2xl font-bold text-center">Check Your Email</CardTitle>
          <CardDescription className="text-center">
            We've sent a verification link to your email address
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Alert>
            <Mail className="h-4 w-4" />
            <AlertDescription>
              Please check your email and click the verification link to complete your registration.
            </AlertDescription>
          </Alert>
          <Button
            className="w-full"
            onClick={() => router.push('/auth/signin')}
          >
            Continue to Sign In
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className={`w-full max-w-md mx-auto ${className}`}>
      <CardHeader className="space-y-1">
        <CardTitle className="text-2xl font-bold text-center">Create Account</CardTitle>
        <CardDescription className="text-center">
          Enter your information to create your account
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Social Signup Buttons */}
        <div className="space-y-2">
          <Button
            type="button"
            variant="outline"
            className="w-full"
            onClick={handleGoogleSignup}
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
            onClick={handleGitHubSignup}
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
        <form onSubmit={handleSubmit(handleEmailSignup)} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="firstName">First Name</Label>
              <div className="relative">
                <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  id="firstName"
                  type="text"
                  placeholder="John"
                  className="pl-10"
                  {...register('firstName')}
                  disabled={loading || isSubmitting}
                />
              </div>
              {errors.firstName && (
                <p className="text-sm text-destructive">{errors.firstName.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="lastName">Last Name</Label>
              <div className="relative">
                <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  id="lastName"
                  type="text"
                  placeholder="Doe"
                  className="pl-10"
                  {...register('lastName')}
                  disabled={loading || isSubmitting}
                />
              </div>
              {errors.lastName && (
                <p className="text-sm text-destructive">{errors.lastName.message}</p>
              )}
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <div className="relative">
              <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                id="email"
                type="email"
                placeholder="john.doe@example.com"
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
                placeholder="Create a strong password"
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

          <div className="space-y-2">
            <Label htmlFor="confirmPassword">Confirm Password</Label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                id="confirmPassword"
                type={showConfirmPassword ? 'text' : 'password'}
                placeholder="Confirm your password"
                className="pl-10 pr-10"
                {...register('confirmPassword')}
                disabled={loading || isSubmitting}
              />
              <button
                type="button"
                className="absolute right-3 top-3 h-4 w-4 text-muted-foreground hover:text-foreground"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                disabled={loading || isSubmitting}
              >
                {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            {errors.confirmPassword && (
              <p className="text-sm text-destructive">{errors.confirmPassword.message}</p>
            )}
          </div>

          <div className="flex items-center space-x-2">
            <Checkbox
              id="acceptTerms"
              {...register('acceptTerms')}
              disabled={loading || isSubmitting}
            />
            <Label htmlFor="acceptTerms" className="text-sm">
              I agree to the{' '}
              <Button variant="link" className="px-0 h-auto text-sm" type="button">
                Terms of Service
              </Button>{' '}
              and{' '}
              <Button variant="link" className="px-0 h-auto text-sm" type="button">
                Privacy Policy
              </Button>
            </Label>
          </div>
          {errors.acceptTerms && (
            <p className="text-sm text-destructive">{errors.acceptTerms.message}</p>
          )}

          <Button
            type="submit"
            className="w-full"
            disabled={loading || isSubmitting}
          >
            {isSubmitting ? 'Creating account...' : 'Create Account'}
          </Button>
        </form>
      </CardContent>

      {showSignInLink && (
        <CardFooter className="flex justify-center">
          <p className="text-sm text-muted-foreground">
            Already have an account?{' '}
            <Button
              variant="link"
              className="px-0"
              onClick={() => router.push('/auth/signin')}
              disabled={loading || isSubmitting}
            >
              Sign in
            </Button>
          </p>
        </CardFooter>
      )}
    </Card>
  )
}
