import type { Metadata, Viewport } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { Providers } from '@/components/providers'
import { Toaster } from 'react-hot-toast'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'HackAI - Educational Cybersecurity AI Platform',
  description: 'Advanced educational platform demonstrating AI-powered cybersecurity tools and techniques',
  keywords: ['cybersecurity', 'AI', 'education', 'security', 'hacking', 'vulnerability', 'scanning'],
  authors: [{ name: 'HackAI Team' }],
  creator: 'HackAI',
  publisher: 'HackAI',
  robots: 'index, follow',
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://hackai.dev',
    title: 'HackAI - Educational Cybersecurity AI Platform',
    description: 'Advanced educational platform demonstrating AI-powered cybersecurity tools and techniques',
    siteName: 'HackAI',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'HackAI - Educational Cybersecurity AI Platform',
    description: 'Advanced educational platform demonstrating AI-powered cybersecurity tools and techniques',
    creator: '@hackai',
  },
}

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#ffffff' },
    { media: '(prefers-color-scheme: dark)', color: '#0f172a' },
  ],
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.className} antialiased`}>
        <Providers>
          {children}
          <Toaster
            position="top-right"
            toastOptions={{
              duration: 4000,
              style: {
                background: '#363636',
                color: '#fff',
              },
              success: {
                duration: 3000,
                iconTheme: {
                  primary: '#10b981',
                  secondary: '#fff',
                },
              },
              error: {
                duration: 5000,
                iconTheme: {
                  primary: '#ef4444',
                  secondary: '#fff',
                },
              },
            }}
          />
        </Providers>
      </body>
    </html>
  )
}
