import { Metadata } from 'next'
import PasswordReset from '@/components/auth/PasswordReset'

export const metadata: Metadata = {
  title: 'Reset Password - HackAI',
  description: 'Reset your password to regain access to your account.',
}

export default function ForgotPasswordPage() {
  return <PasswordReset />
}
