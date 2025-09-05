'use client'

import { QueryClient, QueryClientProvider } from 'react-query'
import { ThemeProvider } from 'next-themes'
import { useState } from 'react'
import { AuthProvider } from '@/hooks/use-auth'
import { AdvancedFirebaseAuthProvider } from '@/contexts/AdvancedFirebaseAuthContext'
import { CyberpunkThemeProvider } from '@/components/ui/cyberpunk-theme-provider'
import { OptimizationProvider, PerformanceMonitorDisplay } from '@/providers/optimization-provider'

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 60 * 1000, // 1 minute
            cacheTime: 10 * 60 * 1000, // 10 minutes
            retry: (failureCount, error: any) => {
              // Don't retry on 4xx errors
              if (error?.response?.status >= 400 && error?.response?.status < 500) {
                return false
              }
              return failureCount < 3
            },
            refetchOnWindowFocus: false,
          },
          mutations: {
            retry: false,
          },
        },
      })
  )

  return (
    <OptimizationProvider
      enablePerformanceMonitoring={true}
      enableErrorTracking={true}
      enableCaching={true}
    >
      <QueryClientProvider client={queryClient}>
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem={false}
          disableTransitionOnChange
        >
          <CyberpunkThemeProvider>
            <AdvancedFirebaseAuthProvider>
              <AuthProvider>
                {children}
                <PerformanceMonitorDisplay />
              </AuthProvider>
            </AdvancedFirebaseAuthProvider>
          </CyberpunkThemeProvider>
        </ThemeProvider>
      </QueryClientProvider>
    </OptimizationProvider>
  )
}
