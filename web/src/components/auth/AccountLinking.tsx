'use client'

import React, { useState } from 'react'
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext'

interface LinkedProvider {
  providerId: string
  displayName: string
  email?: string
  photoURL?: string
}

export const AccountLinking: React.FC = () => {
  const { user, linkWithGoogle, linkWithGitHub, unlinkProvider } = useFirebaseAuth()
  const [isLoading, setIsLoading] = useState<string | null>(null)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  // Get linked providers
  const getLinkedProviders = (): LinkedProvider[] => {
    if (!user?.providerData) return []
    
    return user.providerData.map(provider => ({
      providerId: provider.providerId,
      displayName: getProviderDisplayName(provider.providerId),
      email: provider.email || undefined,
      photoURL: provider.photoURL || undefined,
    }))
  }

  const getProviderDisplayName = (providerId: string): string => {
    switch (providerId) {
      case 'google.com':
        return 'Google'
      case 'github.com':
        return 'GitHub'
      case 'password':
        return 'Email/Password'
      case 'phone':
        return 'Phone'
      default:
        return providerId
    }
  }

  const getProviderIcon = (providerId: string): string => {
    switch (providerId) {
      case 'google.com':
        return '🔍'
      case 'github.com':
        return '🐙'
      case 'password':
        return '📧'
      case 'phone':
        return '📱'
      default:
        return '🔗'
    }
  }

  const handleLinkProvider = async (provider: 'google' | 'github') => {
    setIsLoading(provider)
    setError('')
    setMessage('')

    try {
      let result
      if (provider === 'google') {
        result = await linkWithGoogle()
      } else {
        result = await linkWithGitHub()
      }

      if (result.error) {
        setError(result.error)
      } else {
        setMessage(`Successfully linked ${provider === 'google' ? 'Google' : 'GitHub'} account!`)
      }
    } catch (err) {
      setError(`Failed to link ${provider === 'google' ? 'Google' : 'GitHub'} account. Please try again.`)
    } finally {
      setIsLoading(null)
    }
  }

  const handleUnlinkProvider = async (providerId: string) => {
    const linkedProviders = getLinkedProviders()
    
    // Prevent unlinking if it's the only provider
    if (linkedProviders.length <= 1) {
      setError('Cannot unlink the only sign-in method. Please add another method first.')
      return
    }

    if (!confirm(`Are you sure you want to unlink your ${getProviderDisplayName(providerId)} account?`)) {
      return
    }

    setIsLoading(providerId)
    setError('')
    setMessage('')

    try {
      const result = await unlinkProvider(providerId)
      if (result.error) {
        setError(result.error)
      } else {
        setMessage(`Successfully unlinked ${getProviderDisplayName(providerId)} account.`)
      }
    } catch (err) {
      setError(`Failed to unlink ${getProviderDisplayName(providerId)} account. Please try again.`)
    } finally {
      setIsLoading(null)
    }
  }

  const isProviderLinked = (providerId: string): boolean => {
    return getLinkedProviders().some(provider => provider.providerId === providerId)
  }

  if (!user) {
    return (
      <div className="max-w-2xl mx-auto p-6">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-gray-900">Authentication Required</h2>
          <p className="mt-2 text-gray-600">Please sign in to manage your linked accounts.</p>
        </div>
      </div>
    )
  }

  const linkedProviders = getLinkedProviders()

  return (
    <div className="max-w-2xl mx-auto p-6">
      <div className="bg-white shadow rounded-lg">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200">
          <h1 className="text-2xl font-bold text-gray-900">Linked Accounts</h1>
          <p className="mt-1 text-sm text-gray-600">
            Manage your sign-in methods and linked social accounts.
          </p>
        </div>

        <div className="p-6">
          {/* Messages */}
          {message && (
            <div className="mb-6 rounded-md bg-green-50 p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <p className="text-sm font-medium text-green-800">{message}</p>
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="mb-6 rounded-md bg-red-50 p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <p className="text-sm font-medium text-red-800">{error}</p>
                </div>
              </div>
            </div>
          )}

          {/* Current Linked Accounts */}
          <div className="mb-8">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Current Sign-in Methods</h3>
            <div className="space-y-3">
              {linkedProviders.map((provider) => (
                <div
                  key={provider.providerId}
                  className="flex items-center justify-between p-4 border border-gray-200 rounded-lg"
                >
                  <div className="flex items-center">
                    <span className="text-2xl mr-3">{getProviderIcon(provider.providerId)}</span>
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">
                        {provider.displayName}
                      </h4>
                      {provider.email && (
                        <p className="text-sm text-gray-500">{provider.email}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                      Connected
                    </span>
                    {linkedProviders.length > 1 && provider.providerId !== 'password' && (
                      <button
                        onClick={() => handleUnlinkProvider(provider.providerId)}
                        disabled={isLoading === provider.providerId}
                        className="text-sm text-red-600 hover:text-red-800 disabled:opacity-50"
                      >
                        {isLoading === provider.providerId ? 'Unlinking...' : 'Unlink'}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Available Providers to Link */}
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4">Add Sign-in Method</h3>
            <div className="space-y-3">
              {/* Google */}
              {!isProviderLinked('google.com') && (
                <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center">
                    <span className="text-2xl mr-3">🔍</span>
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">Google</h4>
                      <p className="text-sm text-gray-500">Sign in with your Google account</p>
                    </div>
                  </div>
                  <button
                    onClick={() => handleLinkProvider('google')}
                    disabled={isLoading === 'google'}
                    className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                  >
                    {isLoading === 'google' ? (
                      <div className="flex items-center">
                        <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-gray-700" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Linking...
                      </div>
                    ) : (
                      'Link Account'
                    )}
                  </button>
                </div>
              )}

              {/* GitHub */}
              {!isProviderLinked('github.com') && (
                <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center">
                    <span className="text-2xl mr-3">🐙</span>
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">GitHub</h4>
                      <p className="text-sm text-gray-500">Sign in with your GitHub account</p>
                    </div>
                  </div>
                  <button
                    onClick={() => handleLinkProvider('github')}
                    disabled={isLoading === 'github'}
                    className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                  >
                    {isLoading === 'github' ? (
                      <div className="flex items-center">
                        <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-gray-700" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Linking...
                      </div>
                    ) : (
                      'Link Account'
                    )}
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Security Notice */}
          <div className="mt-8 bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-blue-800">Security Tip</h3>
                <div className="mt-2 text-sm text-blue-700">
                  <ul className="list-disc list-inside space-y-1">
                    <li>Linking multiple accounts provides backup sign-in options</li>
                    <li>You must have at least one sign-in method linked</li>
                    <li>Unlinking an account doesn't delete your data</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default AccountLinking
