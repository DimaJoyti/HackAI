import type { Metadata, Viewport } from 'next'
import { Inter, Orbitron, Rajdhani, Share_Tech_Mono, Audiowide, Exo_2 } from 'next/font/google'
import './globals.css'
import { Providers } from '@/components/providers'
import { Toaster } from 'react-hot-toast'

// Primary font
const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
})

// Cyberpunk fonts
const orbitron = Orbitron({
  subsets: ['latin'],
  variable: '--font-orbitron',
})

const rajdhani = Rajdhani({
  subsets: ['latin'],
  weight: ['300', '400', '500', '600', '700'],
  variable: '--font-rajdhani',
})

const shareTechMono = Share_Tech_Mono({
  subsets: ['latin'],
  weight: ['400'],
  variable: '--font-share-tech-mono',
})

const audiowide = Audiowide({
  subsets: ['latin'],
  weight: ['400'],
  variable: '--font-audiowide',
})

const exo2 = Exo_2({
  subsets: ['latin'],
  variable: '--font-exo-2',
})

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
      <body className={`${inter.variable} ${orbitron.variable} ${rajdhani.variable} ${shareTechMono.variable} ${audiowide.variable} ${exo2.variable} font-sans antialiased`}>
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
