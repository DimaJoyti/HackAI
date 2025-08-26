'use client'

import { useRequireAuth } from '@/hooks/use-auth'
import FraudDetectionDashboardSimple from '@/components/dashboard/fraud-detection-dashboard-simple'

export default function FraudDetectionPage() {
  // Require authentication to access this page
  const { isAuthenticated, isLoading } = useRequireAuth()

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return null // useRequireAuth will redirect to login
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <FraudDetectionDashboardSimple />
    </div>
  )
}