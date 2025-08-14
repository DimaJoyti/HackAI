'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import {
  ShieldCheckIcon,
  CpuChipIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  PlayIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { useAuth } from '@/hooks/use-auth'
import { formatDateTime, formatRelativeTime } from '@/lib/utils'

// Mock data - in real app, this would come from API
const mockStats = {
  totalScans: 156,
  activeScans: 3,
  vulnerabilitiesFound: 42,
  criticalVulns: 5,
  highVulns: 12,
  mediumVulns: 18,
  lowVulns: 7,
}

const mockRecentScans = [
  {
    id: '1',
    type: 'vulnerability',
    target: 'https://example.com',
    status: 'completed',
    vulnerabilities: 8,
    severity: 'high',
    startedAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
    completedAt: new Date(Date.now() - 1.5 * 60 * 60 * 1000), // 1.5 hours ago
  },
  {
    id: '2',
    type: 'network',
    target: '192.168.1.0/24',
    status: 'running',
    progress: 65,
    startedAt: new Date(Date.now() - 30 * 60 * 1000), // 30 minutes ago
  },
  {
    id: '3',
    type: 'vulnerability',
    target: 'https://api.example.com',
    status: 'completed',
    vulnerabilities: 3,
    severity: 'medium',
    startedAt: new Date(Date.now() - 4 * 60 * 60 * 1000), // 4 hours ago
    completedAt: new Date(Date.now() - 3.5 * 60 * 60 * 1000), // 3.5 hours ago
  },
]

const mockVulnerabilities = [
  {
    id: '1',
    title: 'SQL Injection in Login Form',
    severity: 'critical',
    target: 'https://example.com/login',
    discoveredAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
  },
  {
    id: '2',
    title: 'Cross-Site Scripting (XSS)',
    severity: 'high',
    target: 'https://example.com/search',
    discoveredAt: new Date(Date.now() - 3 * 60 * 60 * 1000),
  },
  {
    id: '3',
    title: 'Insecure Direct Object Reference',
    severity: 'medium',
    target: 'https://example.com/profile',
    discoveredAt: new Date(Date.now() - 5 * 60 * 60 * 1000),
  },
]

export default function DashboardPage() {
  const { user } = useAuth()
  const [currentTime, setCurrentTime] = useState(new Date())

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date())
    }, 60000) // Update every minute

    return () => clearInterval(timer)
  }, [])

  const getSeverityBadgeVariant = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'critical'
      case 'high':
        return 'high'
      case 'medium':
        return 'medium'
      case 'low':
        return 'low'
      default:
        return 'secondary'
    }
  }

  const getStatusBadgeVariant = (status: string) => {
    switch (status) {
      case 'running':
        return 'running'
      case 'completed':
        return 'completed'
      case 'failed':
        return 'failed'
      case 'pending':
        return 'pending'
      default:
        return 'secondary'
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Welcome back, {user?.firstName}!
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Here's what's happening with your security scans today.
          </p>
        </div>
        <div className="text-right">
          <p className="text-sm text-gray-500 dark:text-gray-400">
            {formatDateTime(currentTime)}
          </p>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Link href="/dashboard/scans/vulnerability">
          <Card className="hover:shadow-lg transition-shadow cursor-pointer">
            <CardHeader className="flex flex-row items-center space-y-0 pb-2">
              <ShieldCheckIcon className="h-6 w-6 text-blue-600" />
              <CardTitle className="ml-2">Start Vulnerability Scan</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Scan web applications and APIs for security vulnerabilities
              </CardDescription>
            </CardContent>
          </Card>
        </Link>

        <Link href="/dashboard/scans/network">
          <Card className="hover:shadow-lg transition-shadow cursor-pointer">
            <CardHeader className="flex flex-row items-center space-y-0 pb-2">
              <CpuChipIcon className="h-6 w-6 text-green-600" />
              <CardTitle className="ml-2">Start Network Scan</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Discover hosts, services, and potential network vulnerabilities
              </CardDescription>
            </CardContent>
          </Card>
        </Link>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <ShieldCheckIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mockStats.totalScans}</div>
            <p className="text-xs text-muted-foreground">
              +12 from last month
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Scans</CardTitle>
            <ClockIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mockStats.activeScans}</div>
            <p className="text-xs text-muted-foreground">
              Currently running
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Vulnerabilities</CardTitle>
            <ExclamationTriangleIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mockStats.vulnerabilitiesFound}</div>
            <p className="text-xs text-muted-foreground">
              {mockStats.criticalVulns} critical, {mockStats.highVulns} high
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
            <CheckCircleIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">98.2%</div>
            <p className="text-xs text-muted-foreground">
              Scan completion rate
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Scans</CardTitle>
            <CardDescription>
              Your latest security scans and their status
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {mockRecentScans.map((scan) => (
                <div key={scan.id} className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center space-x-3">
                    {scan.type === 'vulnerability' ? (
                      <ShieldCheckIcon className="h-5 w-5 text-blue-600" />
                    ) : (
                      <CpuChipIcon className="h-5 w-5 text-green-600" />
                    )}
                    <div>
                      <p className="font-medium text-sm">{scan.target}</p>
                      <p className="text-xs text-gray-500">
                        {formatRelativeTime(scan.startedAt)}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    {scan.status === 'completed' && scan.vulnerabilities && (
                      <Badge variant={getSeverityBadgeVariant(scan.severity!)}>
                        {scan.vulnerabilities} vulns
                      </Badge>
                    )}
                    {scan.status === 'running' && (
                      <span className="text-xs text-blue-600">
                        {scan.progress}%
                      </span>
                    )}
                    <Badge variant={getStatusBadgeVariant(scan.status)}>
                      {scan.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-4">
              <Link href="/dashboard/scans">
                <Button variant="outline" className="w-full">
                  View All Scans
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>

        {/* Recent Vulnerabilities */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Vulnerabilities</CardTitle>
            <CardDescription>
              Latest security issues discovered in your scans
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {mockVulnerabilities.map((vuln) => (
                <div key={vuln.id} className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex-1">
                    <p className="font-medium text-sm">{vuln.title}</p>
                    <p className="text-xs text-gray-500">{vuln.target}</p>
                    <p className="text-xs text-gray-400">
                      {formatRelativeTime(vuln.discoveredAt)}
                    </p>
                  </div>
                  <Badge variant={getSeverityBadgeVariant(vuln.severity)}>
                    {vuln.severity}
                  </Badge>
                </div>
              ))}
            </div>
            <div className="mt-4">
              <Link href="/dashboard/vulnerabilities">
                <Button variant="outline" className="w-full">
                  View All Vulnerabilities
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Learning Section */}
      <Card>
        <CardHeader>
          <CardTitle>Continue Learning</CardTitle>
          <CardDescription>
            Enhance your cybersecurity skills with our educational modules
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 border rounded-lg">
              <h4 className="font-medium mb-2">Web Application Security</h4>
              <p className="text-sm text-gray-600 mb-3">
                Learn about common web vulnerabilities and how to prevent them.
              </p>
              <Link href="/dashboard/learning/web-security">
                <Button size="sm" variant="outline">
                  <PlayIcon className="h-4 w-4 mr-2" />
                  Start Module
                </Button>
              </Link>
            </div>
            <div className="p-4 border rounded-lg">
              <h4 className="font-medium mb-2">Network Security</h4>
              <p className="text-sm text-gray-600 mb-3">
                Understand network protocols and security best practices.
              </p>
              <Link href="/dashboard/learning/network-security">
                <Button size="sm" variant="outline">
                  <PlayIcon className="h-4 w-4 mr-2" />
                  Start Module
                </Button>
              </Link>
            </div>
            <div className="p-4 border rounded-lg">
              <h4 className="font-medium mb-2">Incident Response</h4>
              <p className="text-sm text-gray-600 mb-3">
                Learn how to respond to and manage security incidents.
              </p>
              <Link href="/dashboard/learning/incident-response">
                <Button size="sm" variant="outline">
                  <PlayIcon className="h-4 w-4 mr-2" />
                  Start Module
                </Button>
              </Link>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
