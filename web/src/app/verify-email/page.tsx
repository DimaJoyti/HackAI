import { Metadata } from 'next'
import EmailVerification from '@/components/auth/EmailVerification'

export const metadata: Metadata = {
  title: 'Verify Email - HackAI',
  description: 'Verify your email address to complete your account setup.',
}

export default function VerifyEmailPage() {
  return <EmailVerification />
}
