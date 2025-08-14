import { Metadata } from 'next'
import Link from 'next/link'
import { ArrowRightIcon, ShieldCheckIcon, CpuChipIcon, AcademicCapIcon } from '@heroicons/react/24/outline'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

export const metadata: Metadata = {
  title: 'HackAI - Educational Cybersecurity AI Platform',
  description: 'Learn cybersecurity through hands-on AI-powered security tools and interactive educational modules.',
}

const features = [
  {
    name: 'AI-Powered Vulnerability Scanner',
    description: 'Advanced machine learning algorithms detect security vulnerabilities in web applications, APIs, and network services.',
    icon: ShieldCheckIcon,
    color: 'text-red-600',
    bgColor: 'bg-red-50',
  },
  {
    name: 'Network Security Analysis',
    description: 'Real-time network monitoring, port scanning, and traffic analysis with anomaly detection capabilities.',
    icon: CpuChipIcon,
    color: 'text-blue-600',
    bgColor: 'bg-blue-50',
  },
  {
    name: 'Interactive Learning Modules',
    description: 'Hands-on cybersecurity education with guided tutorials, labs, and real-world scenarios.',
    icon: AcademicCapIcon,
    color: 'text-green-600',
    bgColor: 'bg-green-50',
  },
]

const stats = [
  { name: 'Security Scans Performed', value: '10,000+' },
  { name: 'Vulnerabilities Detected', value: '50,000+' },
  { name: 'Students Trained', value: '5,000+' },
  { name: 'Educational Modules', value: '100+' },
]

export default function HomePage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 dark:from-slate-900 dark:via-blue-900 dark:to-indigo-900">
      {/* Navigation */}
      <nav className="border-b border-gray-200 dark:border-gray-800 bg-white/80 dark:bg-gray-900/80 backdrop-blur-sm">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-16 justify-between items-center">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                  Hack<span className="text-blue-600">AI</span>
                </h1>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Link href="/auth/login">
                <Button variant="ghost">Sign In</Button>
              </Link>
              <Link href="/auth/register">
                <Button>Get Started</Button>
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 pt-20 pb-16">
          <div className="text-center">
            <Badge variant="secondary" className="mb-4">
              🚀 Educational Cybersecurity Platform
            </Badge>
            <h1 className="text-4xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-6xl">
              Learn Cybersecurity with{' '}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-purple-600">
                AI-Powered Tools
              </span>
            </h1>
            <p className="mt-6 text-lg leading-8 text-gray-600 dark:text-gray-300 max-w-3xl mx-auto">
              Master cybersecurity through hands-on experience with advanced AI-powered security tools. 
              Scan for vulnerabilities, analyze networks, and learn from real-world scenarios in a safe, 
              educational environment.
            </p>
            <div className="mt-10 flex items-center justify-center gap-x-6">
              <Link href="/auth/register">
                <Button size="lg" className="group">
                  Start Learning
                  <ArrowRightIcon className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
                </Button>
              </Link>
              <Link href="/demo">
                <Button variant="outline" size="lg">
                  View Demo
                </Button>
              </Link>
            </div>
          </div>
        </div>

        {/* Background decoration */}
        <div className="absolute inset-x-0 top-[calc(100%-13rem)] -z-10 transform-gpu overflow-hidden blur-3xl sm:top-[calc(100%-30rem)]">
          <div className="relative left-[calc(50%+3rem)] aspect-[1155/678] w-[36.125rem] -translate-x-1/2 bg-gradient-to-tr from-[#ff80b5] to-[#9089fc] opacity-20 sm:left-[calc(50%+36rem)] sm:w-[72.1875rem]" />
        </div>
      </div>

      {/* Features Section */}
      <div className="py-24 sm:py-32">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="text-base font-semibold leading-7 text-blue-600 dark:text-blue-400">
              Advanced Security Tools
            </h2>
            <p className="mt-2 text-3xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-4xl">
              Everything you need to learn cybersecurity
            </p>
            <p className="mt-6 text-lg leading-8 text-gray-600 dark:text-gray-300">
              Our platform combines cutting-edge AI technology with educational best practices to provide 
              an immersive learning experience.
            </p>
          </div>
          <div className="mx-auto mt-16 max-w-2xl sm:mt-20 lg:mt-24 lg:max-w-none">
            <dl className="grid max-w-xl grid-cols-1 gap-x-8 gap-y-16 lg:max-w-none lg:grid-cols-3">
              {features.map((feature) => (
                <Card key={feature.name} className="hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className={`inline-flex h-12 w-12 items-center justify-center rounded-lg ${feature.bgColor} dark:bg-gray-800`}>
                      <feature.icon className={`h-6 w-6 ${feature.color} dark:text-gray-300`} aria-hidden="true" />
                    </div>
                    <CardTitle className="mt-4">{feature.name}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <CardDescription className="text-base">
                      {feature.description}
                    </CardDescription>
                  </CardContent>
                </Card>
              ))}
            </dl>
          </div>
        </div>
      </div>

      {/* Stats Section */}
      <div className="bg-white dark:bg-gray-900 py-24 sm:py-32">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-2xl lg:max-w-none">
            <div className="text-center">
              <h2 className="text-3xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-4xl">
                Trusted by cybersecurity professionals and students worldwide
              </h2>
              <p className="mt-4 text-lg leading-8 text-gray-600 dark:text-gray-300">
                Join thousands of learners who have enhanced their cybersecurity skills with HackAI.
              </p>
            </div>
            <dl className="mt-16 grid grid-cols-1 gap-0.5 overflow-hidden rounded-2xl text-center sm:grid-cols-2 lg:grid-cols-4">
              {stats.map((stat) => (
                <div key={stat.name} className="flex flex-col bg-gray-50 dark:bg-gray-800 p-8">
                  <dt className="text-sm font-semibold leading-6 text-gray-600 dark:text-gray-400">
                    {stat.name}
                  </dt>
                  <dd className="order-first text-3xl font-bold tracking-tight text-gray-900 dark:text-white">
                    {stat.value}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </div>

      {/* CTA Section */}
      <div className="bg-blue-600 dark:bg-blue-700">
        <div className="px-4 py-16 sm:px-6 sm:py-24 lg:px-8">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
              Ready to start your cybersecurity journey?
            </h2>
            <p className="mx-auto mt-6 max-w-xl text-lg leading-8 text-blue-100">
              Join HackAI today and gain hands-on experience with the latest cybersecurity tools and techniques.
            </p>
            <div className="mt-10 flex items-center justify-center gap-x-6">
              <Link href="/auth/register">
                <Button size="lg" variant="secondary">
                  Get started for free
                </Button>
              </Link>
              <Link href="/contact" className="text-sm font-semibold leading-6 text-white hover:text-blue-100">
                Contact us <span aria-hidden="true">→</span>
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-gray-900 dark:bg-black">
        <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
          <div className="text-center">
            <h3 className="text-2xl font-bold text-white">
              Hack<span className="text-blue-400">AI</span>
            </h3>
            <p className="mt-2 text-gray-400">
              Educational Cybersecurity AI Platform
            </p>
            <p className="mt-4 text-sm text-gray-500">
              © 2024 HackAI. All rights reserved. Built for educational purposes.
            </p>
          </div>
        </div>
      </footer>
    </div>
  )
}
