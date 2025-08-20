'use client'

import { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  HomeIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  ChartBarIcon,
  AcademicCapIcon,
  CogIcon,
  UserIcon,
  Bars3Icon,
  XMarkIcon,
  BellIcon,
  MagnifyingGlassIcon,
} from '@heroicons/react/24/outline'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { useAuth } from '@/hooks/use-auth'
import { useRequireAuth } from '@/hooks/use-auth'
import { cn } from '@/lib/utils'

const navigation = [
  { name: 'Overview', href: '/dashboard', icon: HomeIcon },
  { name: 'Enhanced Dashboard', href: '/dashboard/enhanced', icon: ChartBarIcon },
  { name: 'Fraud Detection', href: '/dashboard/fraud', icon: ShieldCheckIcon },
  { name: 'Vulnerability Scans', href: '/dashboard/scans/vulnerability', icon: ShieldCheckIcon },
  { name: 'Network Scans', href: '/dashboard/scans/network', icon: CpuChipIcon },
  { name: 'Analytics', href: '/dashboard/analytics', icon: ChartBarIcon },
  { name: 'Learning', href: '/dashboard/learning', icon: AcademicCapIcon },
  { name: 'Settings', href: '/dashboard/settings', icon: CogIcon },
]

const adminNavigation = [
  { name: 'User Management', href: '/dashboard/admin/users', icon: UserIcon },
  { name: 'System Stats', href: '/dashboard/admin/stats', icon: ChartBarIcon },
]

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const pathname = usePathname()
  const { user, logout } = useAuth()
  
  // Protect the dashboard routes
  const { isAuthenticated, isLoading } = useRequireAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return null // useRequireAuth will redirect to login
  }

  const isAdmin = user?.role === 'admin'
  const isModerator = user?.role === 'moderator' || user?.role === 'admin'

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Mobile sidebar */}
      <div className={cn(
        "fixed inset-0 z-50 lg:hidden",
        sidebarOpen ? "block" : "hidden"
      )}>
        <div className="fixed inset-0 bg-gray-600 bg-opacity-75" onClick={() => setSidebarOpen(false)} />
        <div className="fixed inset-y-0 left-0 flex w-64 flex-col bg-white dark:bg-gray-800 shadow-xl">
          <div className="flex h-16 items-center justify-between px-4">
            <Link href="/dashboard" className="flex items-center">
              <h1 className="text-xl font-bold text-gray-900 dark:text-white">
                Hack<span className="text-blue-600">AI</span>
              </h1>
            </Link>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setSidebarOpen(false)}
            >
              <XMarkIcon className="h-6 w-6" />
            </Button>
          </div>
          <nav className="flex-1 space-y-1 px-2 py-4">
            {navigation.map((item) => {
              const isActive = pathname === item.href || (pathname?.startsWith(item.href + '/') ?? false)
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={cn(
                    "group flex items-center px-2 py-2 text-sm font-medium rounded-md",
                    isActive
                      ? "bg-blue-100 text-blue-900 dark:bg-blue-900 dark:text-blue-100"
                      : "text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white"
                  )}
                  onClick={() => setSidebarOpen(false)}
                >
                  <item.icon className="mr-3 h-5 w-5 flex-shrink-0" />
                  {item.name}
                </Link>
              )
            })}
            
            {isAdmin && (
              <>
                <div className="border-t border-gray-200 dark:border-gray-700 my-4" />
                <div className="px-2 py-2">
                  <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Administration
                  </h3>
                </div>
                {adminNavigation.map((item) => {
                  const isActive = pathname === item.href || (pathname?.startsWith(item.href + '/') ?? false)
                  return (
                    <Link
                      key={item.name}
                      href={item.href}
                      className={cn(
                        "group flex items-center px-2 py-2 text-sm font-medium rounded-md",
                        isActive
                          ? "bg-blue-100 text-blue-900 dark:bg-blue-900 dark:text-blue-100"
                          : "text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white"
                      )}
                      onClick={() => setSidebarOpen(false)}
                    >
                      <item.icon className="mr-3 h-5 w-5 flex-shrink-0" />
                      {item.name}
                    </Link>
                  )
                })}
              </>
            )}
          </nav>
        </div>
      </div>

      {/* Desktop sidebar */}
      <div className="hidden lg:fixed lg:inset-y-0 lg:flex lg:w-64 lg:flex-col">
        <div className="flex flex-col flex-grow bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700">
          <div className="flex h-16 items-center px-4">
            <Link href="/dashboard" className="flex items-center">
              <h1 className="text-xl font-bold text-gray-900 dark:text-white">
                Hack<span className="text-blue-600">AI</span>
              </h1>
            </Link>
          </div>
          <nav className="flex-1 space-y-1 px-2 py-4">
            {navigation.map((item) => {
              const isActive = pathname === item.href || (pathname?.startsWith(item.href + '/') ?? false)
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={cn(
                    "group flex items-center px-2 py-2 text-sm font-medium rounded-md",
                    isActive
                      ? "bg-blue-100 text-blue-900 dark:bg-blue-900 dark:text-blue-100"
                      : "text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white"
                  )}
                >
                  <item.icon className="mr-3 h-5 w-5 flex-shrink-0" />
                  {item.name}
                </Link>
              )
            })}
            
            {isAdmin && (
              <>
                <div className="border-t border-gray-200 dark:border-gray-700 my-4" />
                <div className="px-2 py-2">
                  <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Administration
                  </h3>
                </div>
                {adminNavigation.map((item) => {
                  const isActive = pathname === item.href || (pathname?.startsWith(item.href + '/') ?? false)
                  return (
                    <Link
                      key={item.name}
                      href={item.href}
                      className={cn(
                        "group flex items-center px-2 py-2 text-sm font-medium rounded-md",
                        isActive
                          ? "bg-blue-100 text-blue-900 dark:bg-blue-900 dark:text-blue-100"
                          : "text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white"
                      )}
                    >
                      <item.icon className="mr-3 h-5 w-5 flex-shrink-0" />
                      {item.name}
                    </Link>
                  )
                })}
              </>
            )}
          </nav>
        </div>
      </div>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Top navigation */}
        <div className="sticky top-0 z-40 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
          <div className="flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8">
            <div className="flex items-center">
              <Button
                variant="ghost"
                size="icon"
                className="lg:hidden"
                onClick={() => setSidebarOpen(true)}
              >
                <Bars3Icon className="h-6 w-6" />
              </Button>
              
              {/* Search */}
              <div className="hidden sm:block ml-4">
                <div className="relative">
                  <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                  <Input
                    type="search"
                    placeholder="Search..."
                    className="pl-10 w-64"
                  />
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              {/* Notifications */}
              <Button variant="ghost" size="icon" className="relative">
                <BellIcon className="h-5 w-5" />
                <Badge
                  variant="danger"
                  className="absolute -top-1 -right-1 h-4 w-4 p-0 flex items-center justify-center text-xs"
                >
                  3
                </Badge>
              </Button>

              {/* User menu */}
              <div className="flex items-center space-x-3">
                <div className="hidden sm:block text-right">
                  <p className="text-sm font-medium text-gray-900 dark:text-white">
                    {user?.firstName} {user?.lastName}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {user?.role}
                  </p>
                </div>
                <div className="h-8 w-8 rounded-full bg-blue-600 flex items-center justify-center">
                  <span className="text-sm font-medium text-white">
                    {user?.firstName?.[0]}{user?.lastName?.[0]}
                  </span>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={logout}
                  className="hidden sm:inline-flex"
                >
                  Sign out
                </Button>
              </div>
            </div>
          </div>
        </div>

        {/* Page content */}
        <main className="flex-1">
          {children}
        </main>
      </div>
    </div>
  )
}
