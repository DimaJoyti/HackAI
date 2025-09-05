'use client'

import { useState } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { CyberpunkInput } from '@/components/ui/cyberpunk-forms'
import { CyberpunkBackground, GlitchText } from '@/components/ui/cyberpunk-background'
import { HolographicDisplay, DataStream } from '@/components/ui/cyberpunk-effects'
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext'
import { getAuthErrorMessage } from '@/lib/firebase'
import { toast } from 'react-hot-toast'

const signupSchema = z.object({
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required'),
  email: z.string().email('Invalid email address'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
  confirmPassword: z.string().min(6, 'Password confirmation is required'),
  agreeToTerms: z.boolean().refine(val => val === true, 'You must agree to the terms'),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
})

type SignupForm = z.infer<typeof signupSchema>

export default function RegisterPage() {
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const router = useRouter()
  const searchParams = useSearchParams()
  const { signUp, signInWithGoogle, sendEmailVerification, loading } = useFirebaseAuth()
  
  // Get redirect URL from search params, default to dashboard
  const redirectUrl = searchParams.get('redirect') || '/dashboard'

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<SignupForm>({
    resolver: zodResolver(signupSchema),
  })

  const onSubmit = async (data: SignupForm) => {
    setIsLoading(true)
    try {
      const displayName = `${data.firstName} ${data.lastName}`
      const result = await signUp(data.email, data.password, displayName)
      
      if (result.error) {
        toast.error(getAuthErrorMessage(result.error))
      } else if (result.user) {
        // Send email verification
        await sendEmailVerification()
        toast.success('🎉 Account created! Please check your email for verification.')
        // Use the redirect URL from search params or default to dashboard
        router.push(redirectUrl)
      }
    } catch (error: any) {
      toast.error(error.message || 'Registration failed. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const handleGoogleSignUp = async () => {
    try {
      const result = await signInWithGoogle()
      if (result.error) {
        toast.error(getAuthErrorMessage(result.error))
      } else if (result.user) {
        toast.success('🚀 Google Registration Successful!')
        // Use the redirect URL from search params or default to dashboard
        router.push(redirectUrl)
      }
    } catch (error: any) {
      toast.error(error.message || 'Google sign-up failed. Please try again.')
    }
  }

  return (
    <div className="min-h-screen relative overflow-hidden bg-matrix-black">
      {/* Cyberpunk Background */}
      <CyberpunkBackground />
      
      {/* Data Streams */}
      <div className="absolute inset-0 pointer-events-none">
        <DataStream direction="vertical" className="left-10 top-0" />
        <DataStream direction="vertical" className="right-10 top-0" />
        <DataStream direction="horizontal" className="top-20 left-0" />
      </div>

      <div className="relative z-10 min-h-screen flex items-center justify-center px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          {/* Header */}
          <div className="text-center">
            <Link href="/" className="inline-block group">
              <HolographicDisplay className="mx-auto mb-4">
                <h1 className="text-4xl font-bold text-cyber-blue-neon group-hover:text-cyber-blue-glow transition-colors duration-300">
                  <GlitchText text="Hack" className="inline" />
                  <span className="text-cyber-pink-neon">AI</span>
                </h1>
              </HolographicDisplay>
            </Link>
            <h2 className="mt-6 text-2xl font-bold text-cyber-blue-neon">
              <GlitchText text="USER REGISTRATION" />
            </h2>
            <p className="mt-2 text-sm text-cyber-blue-glow">
              Create new user account or{' '}
              <Link
                href="/auth/login"
                className="font-medium text-cyber-pink-neon hover:text-cyber-pink-glow transition-colors duration-300"
              >
                access existing profile
              </Link>
            </p>
          </div>

          {/* Registration Form */}
          <HolographicDisplay className="backdrop-blur-sm">
            <div className="bg-matrix-surface/80 border border-cyber-blue-neon/30 rounded-lg p-6 shadow-neon-blue">
              <div className="text-center mb-6">
                <h3 className="text-xl font-bold text-cyber-blue-neon mb-2">
                  <GlitchText text="NEW USER PROTOCOL" />
                </h3>
                <p className="text-sm text-cyber-blue-glow">
                  Initialize secure user credentials
                </p>
              </div>

              {/* Google Sign-Up Button */}
              <div className="space-y-4">
                <CyberpunkButton
                  variant="neon-pink"
                  size="lg"
                  className="w-full"
                  onClick={handleGoogleSignUp}
                  disabled={isLoading || loading}
                >
                  <svg className="w-5 h-5 mr-3" viewBox="0 0 24 24">
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
                  <GlitchText text="GOOGLE REGISTRATION" className="ml-2" />
                </CyberpunkButton>

                <div className="relative my-6">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-cyber-blue-neon/30"></div>
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-matrix-surface px-4 text-cyber-blue-glow">
                      <GlitchText text="OR MANUAL SETUP" />
                    </span>
                  </div>
                </div>
              </div>

              <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
                <div className="grid grid-cols-2 gap-4">
                  <CyberpunkInput
                    label="FIRST NAME"
                    type="text"
                    placeholder="John"
                    color="blue"
                    {...register('firstName')}
                    error={errors.firstName?.message}
                  />
                  <CyberpunkInput
                    label="LAST NAME"
                    type="text"
                    placeholder="Doe"
                    color="blue"
                    {...register('lastName')}
                    error={errors.lastName?.message}
                  />
                </div>

                <CyberpunkInput
                  label="EMAIL ADDRESS"
                  type="email"
                  placeholder="user@hackai.dev"
                  color="green"
                  {...register('email')}
                  error={errors.email?.message}
                  icon={
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
                    </svg>
                  }
                />

                <div className="relative">
                  <CyberpunkInput
                    label="PASSWORD"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Create secure password"
                    color="pink"
                    {...register('password')}
                    error={errors.password?.message}
                    icon={
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                      </svg>
                    }
                  />
                  <button
                    type="button"
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-cyber-pink-neon hover:text-cyber-pink-glow transition-colors"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? (
                      <EyeSlashIcon className="h-4 w-4" />
                    ) : (
                      <EyeIcon className="h-4 w-4" />
                    )}
                  </button>
                </div>

                <div className="relative">
                  <CyberpunkInput
                    label="CONFIRM PASSWORD"
                    type={showConfirmPassword ? 'text' : 'password'}
                    placeholder="Confirm your password"
                    color="purple"
                    {...register('confirmPassword')}
                    error={errors.confirmPassword?.message}
                    icon={
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    }
                  />
                  <button
                    type="button"
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-cyber-purple-neon hover:text-cyber-purple-glow transition-colors"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  >
                    {showConfirmPassword ? (
                      <EyeSlashIcon className="h-4 w-4" />
                    ) : (
                      <EyeIcon className="h-4 w-4" />
                    )}
                  </button>
                </div>

                <div className="flex items-center">
                  <input
                    id="agree-terms"
                    type="checkbox"
                    {...register('agreeToTerms')}
                    className="h-4 w-4 text-cyber-blue-neon focus:ring-cyber-blue-neon border-cyber-blue-neon/30 rounded bg-matrix-surface"
                  />
                  <label htmlFor="agree-terms" className="ml-2 text-sm text-cyber-blue-glow">
                    I agree to the{' '}
                    <Link href="/terms" className="text-cyber-pink-neon hover:text-cyber-pink-glow transition-colors">
                      Security Protocols
                    </Link>{' '}
                    and{' '}
                    <Link href="/privacy" className="text-cyber-pink-neon hover:text-cyber-pink-glow transition-colors">
                      Data Protection Policy
                    </Link>
                  </label>
                </div>
                {errors.agreeToTerms && (
                  <p className="text-sm text-security-critical">{errors.agreeToTerms.message}</p>
                )}

                <CyberpunkButton
                  type="submit"
                  variant="filled-green"
                  size="lg"
                  className="w-full"
                  disabled={isLoading || loading}
                >
                  {isLoading ? (
                    <GlitchText text="CREATING PROFILE..." />
                  ) : (
                    <GlitchText text="REGISTER USER" />
                  )}
                </CyberpunkButton>
              </form>
            </div>
          </HolographicDisplay>

          {/* Footer */}
          <div className="text-center text-sm text-cyber-blue-glow">
            <p>
              Already have an account?{' '}
              <Link href="/auth/login" className="text-cyber-pink-neon hover:text-cyber-pink-glow transition-colors duration-300">
                <GlitchText text="ACCESS SYSTEM" />
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
