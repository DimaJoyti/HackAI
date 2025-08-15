'use client'

import { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { motion } from 'framer-motion'
import {
  BookOpenIcon,
  BeakerIcon,
  ClipboardDocumentCheckIcon,
  TrophyIcon,
  ChartBarIcon,
  AcademicCapIcon,
  UserGroupIcon,
  CogIcon,
  Bars3Icon,
  XMarkIcon,
} from '@heroicons/react/24/outline'
import { cn } from '@/lib/utils'

// Types
interface NavigationItem {
  name: string
  href: string
  icon: React.ComponentType<{ className?: string }>
  description?: string
}

const navigation: NavigationItem[] = [
  {
    name: 'Dashboard',
    href: '/education',
    icon: ChartBarIcon,
    description: 'Overview of your learning progress'
  },
  {
    name: 'Courses',
    href: '/education/courses',
    icon: BookOpenIcon,
    description: 'Browse and enroll in AI security courses'
  },
  {
    name: 'Labs',
    href: '/education/labs',
    icon: BeakerIcon,
    description: 'Hands-on security testing environments'
  },
  {
    name: 'Assessments',
    href: '/education/assessments',
    icon: ClipboardDocumentCheckIcon,
    description: 'Test your knowledge and skills'
  },
  {
    name: 'Achievements',
    href: '/education/achievements',
    icon: TrophyIcon,
    description: 'View your badges and certificates'
  },
  {
    name: 'Learning Paths',
    href: '/education/paths',
    icon: AcademicCapIcon,
    description: 'Structured learning journeys'
  },
  {
    name: 'Community',
    href: '/education/community',
    icon: UserGroupIcon,
    description: 'Connect with other learners'
  },
]

const secondaryNavigation = [
  {
    name: 'Settings',
    href: '/education/settings',
    icon: CogIcon,
  },
]

interface EducationLayoutProps {
  children: React.ReactNode
}

export default function EducationLayout({ children }: EducationLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const pathname = usePathname() || '/education'

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Mobile sidebar */}
      <div className={cn(
        "fixed inset-0 z-50 lg:hidden",
        sidebarOpen ? "block" : "hidden"
      )}>
        <div className="fixed inset-0 bg-gray-600 bg-opacity-75" onClick={() => setSidebarOpen(false)} />
        <motion.div
          initial={{ x: -300 }}
          animate={{ x: 0 }}
          exit={{ x: -300 }}
          className="fixed inset-y-0 left-0 z-50 w-64 bg-white dark:bg-gray-800 shadow-xl"
        >
          <div className="flex h-16 items-center justify-between px-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              HackAI Education
            </h2>
            <button
              onClick={() => setSidebarOpen(false)}
              className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              aria-label="Close sidebar"
            >
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>
          <nav className="mt-8 px-4">
            <SidebarNavigation navigation={navigation} pathname={pathname} />
          </nav>
        </motion.div>
      </div>

      {/* Desktop sidebar */}
      <div className="hidden lg:fixed lg:inset-y-0 lg:z-50 lg:flex lg:w-72 lg:flex-col">
        <div className="flex grow flex-col gap-y-5 overflow-y-auto bg-white dark:bg-gray-800 px-6 pb-4 shadow-xl">
          <div className="flex h-16 shrink-0 items-center">
            <h1 className="text-xl font-bold text-gray-900 dark:text-white">
              🎓 HackAI Education
            </h1>
          </div>
          <nav className="flex flex-1 flex-col">
            <ul role="list" className="flex flex-1 flex-col gap-y-7">
              <li>
                <SidebarNavigation navigation={navigation} pathname={pathname} />
              </li>
              <li className="mt-auto">
                <SidebarNavigation navigation={secondaryNavigation} pathname={pathname} />
              </li>
            </ul>
          </nav>
        </div>
      </div>

      {/* Main content */}
      <div className="lg:pl-72">
        {/* Top bar */}
        <div className="sticky top-0 z-40 flex h-16 shrink-0 items-center gap-x-4 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-4 shadow-sm sm:gap-x-6 sm:px-6 lg:px-8">
          <button
            type="button"
            className="-m-2.5 p-2.5 text-gray-700 dark:text-gray-300 lg:hidden"
            onClick={() => setSidebarOpen(true)}
            aria-label="Open sidebar"
          >
            <Bars3Icon className="h-6 w-6" />
          </button>

          <div className="flex flex-1 gap-x-4 self-stretch lg:gap-x-6">
            <div className="flex flex-1 items-center">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                {getPageTitle(pathname)}
              </h2>
            </div>
            
            {/* User menu */}
            <div className="flex items-center gap-x-4 lg:gap-x-6">
              <div className="hidden lg:block lg:h-6 lg:w-px lg:bg-gray-200 dark:lg:bg-gray-700" />
              
              {/* Progress indicator */}
              <div className="flex items-center gap-x-2">
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Level 3
                </div>
                <div className="w-20 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div className="w-3/4 h-full bg-blue-600 rounded-full" />
                </div>
              </div>

              {/* Notifications */}
              <button className="relative p-2 text-gray-400 hover:text-gray-500 dark:hover:text-gray-300">
                <span className="sr-only">View notifications</span>
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
                </svg>
                <span className="absolute top-1 right-1 h-2 w-2 bg-red-500 rounded-full" />
              </button>

              {/* Profile dropdown */}
              <div className="relative">
                <button className="flex items-center gap-x-2 text-sm font-semibold text-gray-900 dark:text-white">
                  <div className="h-8 w-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-sm font-medium">
                    JD
                  </div>
                  <span className="hidden lg:block">John Doe</span>
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Page content */}
        <main className="py-8">
          <div className="px-4 sm:px-6 lg:px-8">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}

function SidebarNavigation({ navigation, pathname }: { navigation: NavigationItem[], pathname: string }) {
  return (
    <ul role="list" className="-mx-2 space-y-1">
      {navigation.map((item) => {
        const isActive = pathname === item.href || pathname.startsWith(item.href + '/')
        return (
          <li key={item.name}>
            <Link
              href={item.href}
              className={cn(
                isActive
                  ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                  : 'text-gray-700 dark:text-gray-300 hover:text-blue-700 dark:hover:text-blue-300 hover:bg-gray-50 dark:hover:bg-gray-700',
                'group flex gap-x-3 rounded-md p-2 text-sm leading-6 font-semibold transition-colors'
              )}
            >
              <item.icon
                className={cn(
                  isActive
                    ? 'text-blue-700 dark:text-blue-300'
                    : 'text-gray-400 group-hover:text-blue-700 dark:group-hover:text-blue-300',
                  'h-6 w-6 shrink-0 transition-colors'
                )}
              />
              <div className="flex flex-col">
                <span>{item.name}</span>
                {item.description && (
                  <span className="text-xs text-gray-500 dark:text-gray-400 font-normal">
                    {item.description}
                  </span>
                )}
              </div>
            </Link>
          </li>
        )
      })}
    </ul>
  )
}

function getPageTitle(pathname: string): string {
  if (!pathname) return 'Education Platform'

  const segments = pathname.split('/').filter(Boolean)
  const lastSegment = segments[segments.length - 1]
  
  const titles: Record<string, string> = {
    'education': 'Learning Dashboard',
    'courses': 'Courses',
    'labs': 'Hands-on Labs',
    'assessments': 'Assessments',
    'achievements': 'Achievements',
    'paths': 'Learning Paths',
    'community': 'Community',
    'settings': 'Settings',
  }
  
  return titles[lastSegment] || 'Education Platform'
}
