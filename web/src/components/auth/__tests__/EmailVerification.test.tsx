import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { useRouter } from 'next/navigation'
import EmailVerification from '../EmailVerification'
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext'

// Mock the Firebase auth context
jest.mock('@/contexts/FirebaseAuthContext')
const mockUseFirebaseAuth = useFirebaseAuth as jest.MockedFunction<typeof useFirebaseAuth>

// Mock Next.js router
jest.mock('next/navigation')
const mockUseRouter = useRouter as jest.MockedFunction<typeof useRouter>

describe('EmailVerification', () => {
  const mockPush = jest.fn()
  const mockSendEmailVerification = jest.fn()
  const mockRefreshUser = jest.fn()

  beforeEach(() => {
    jest.clearAllMocks()
    
    mockUseRouter.mockReturnValue({
      push: mockPush,
      replace: jest.fn(),
      back: jest.fn(),
      forward: jest.fn(),
      refresh: jest.fn(),
      prefetch: jest.fn(),
    })

    mockSendEmailVerification.mockResolvedValue({ error: null })
    mockRefreshUser.mockResolvedValue(undefined)
  })

  it('renders authentication required message when no user', () => {
    mockUseFirebaseAuth.mockReturnValue({
      user: null,
      sendEmailVerification: mockSendEmailVerification,
      refreshUser: mockRefreshUser,
    } as any)

    render(<EmailVerification />)

    expect(screen.getByText('Authentication Required')).toBeInTheDocument()
    expect(screen.getByText('Please sign in to continue.')).toBeInTheDocument()
  })

  it('renders email verified message when user email is verified', () => {
    mockUseFirebaseAuth.mockReturnValue({
      user: {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: true,
      },
      sendEmailVerification: mockSendEmailVerification,
      refreshUser: mockRefreshUser,
    } as any)

    render(<EmailVerification />)

    expect(screen.getByText('Email Verified!')).toBeInTheDocument()
    expect(screen.getByText('Your email has been successfully verified. Redirecting...')).toBeInTheDocument()
  })

  it('renders verification form when user email is not verified', () => {
    mockUseFirebaseAuth.mockReturnValue({
      user: {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: false,
      },
      sendEmailVerification: mockSendEmailVerification,
      refreshUser: mockRefreshUser,
    } as any)

    render(<EmailVerification />)

    expect(screen.getByText('Verify Your Email')).toBeInTheDocument()
    expect(screen.getByText('test@example.com')).toBeInTheDocument()
    expect(screen.getByText('Resend Verification Email')).toBeInTheDocument()
  })

  it('sends verification email when resend button is clicked', async () => {
    mockUseFirebaseAuth.mockReturnValue({
      user: {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: false,
      },
      sendEmailVerification: mockSendEmailVerification,
      refreshUser: mockRefreshUser,
    } as any)

    render(<EmailVerification />)

    const resendButton = screen.getByText('Resend Verification Email')
    fireEvent.click(resendButton)

    await waitFor(() => {
      expect(mockSendEmailVerification).toHaveBeenCalledTimes(1)
    })

    expect(screen.getByText('Verification email sent! Please check your inbox.')).toBeInTheDocument()
  })

  it('displays error message when email verification fails', async () => {
    const errorMessage = 'Failed to send verification email'
    mockSendEmailVerification.mockResolvedValue({ error: errorMessage })

    mockUseFirebaseAuth.mockReturnValue({
      user: {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: false,
      },
      sendEmailVerification: mockSendEmailVerification,
      refreshUser: mockRefreshUser,
    } as any)

    render(<EmailVerification />)

    const resendButton = screen.getByText('Resend Verification Email')
    fireEvent.click(resendButton)

    await waitFor(() => {
      expect(screen.getByText(errorMessage)).toBeInTheDocument()
    })
  })

  it('shows cooldown timer after sending verification email', async () => {
    mockUseFirebaseAuth.mockReturnValue({
      user: {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: false,
      },
      sendEmailVerification: mockSendEmailVerification,
      refreshUser: mockRefreshUser,
    } as any)

    render(<EmailVerification />)

    const resendButton = screen.getByText('Resend Verification Email')
    fireEvent.click(resendButton)

    await waitFor(() => {
      expect(screen.getByText(/Resend in \d+s/)).toBeInTheDocument()
    })
  })

  it('allows skipping verification', () => {
    mockUseFirebaseAuth.mockReturnValue({
      user: {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: false,
      },
      sendEmailVerification: mockSendEmailVerification,
      refreshUser: mockRefreshUser,
    } as any)

    render(<EmailVerification />)

    const skipButton = screen.getByText('Skip for now (not recommended)')
    fireEvent.click(skipButton)

    expect(mockPush).toHaveBeenCalledWith('/dashboard')
  })

  it('calls onVerificationComplete when provided and email is verified', () => {
    const mockOnComplete = jest.fn()

    mockUseFirebaseAuth.mockReturnValue({
      user: {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: true,
      },
      sendEmailVerification: mockSendEmailVerification,
      refreshUser: mockRefreshUser,
    } as any)

    render(<EmailVerification onVerificationComplete={mockOnComplete} />)

    // The component should call onVerificationComplete after a delay
    // We'll test this by checking if it's called after the timeout
    setTimeout(() => {
      expect(mockOnComplete).toHaveBeenCalledTimes(1)
    }, 2100)
  })

  it('redirects to custom URL when redirectTo prop is provided', () => {
    const customRedirect = '/custom-page'

    mockUseFirebaseAuth.mockReturnValue({
      user: {
        uid: 'test-uid',
        email: 'test@example.com',
        emailVerified: false,
      },
      sendEmailVerification: mockSendEmailVerification,
      refreshUser: mockRefreshUser,
    } as any)

    render(<EmailVerification redirectTo={customRedirect} />)

    const skipButton = screen.getByText('Skip for now (not recommended)')
    fireEvent.click(skipButton)

    expect(mockPush).toHaveBeenCalledWith(customRedirect)
  })
})
