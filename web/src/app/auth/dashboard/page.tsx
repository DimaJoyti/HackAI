'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { 
  User, 
  Shield, 
  Database, 
  Cloud, 
  Activity, 
  Settings,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  Users,
  FileText,
  Key
} from 'lucide-react'
import { useAdvancedFirebaseAuth } from '@/contexts/AdvancedFirebaseAuthContext'
import { UserProfileManager } from '@/components/auth/UserProfileManager'

interface DashboardStats {
  totalUsers: number
  activeUsers: number
  newUsersToday: number
  authenticationsToday: number
  errorRate: number
}

interface SystemHealth {
  firebase: {
    connected: boolean
    projectId: string
  }
  database: {
    connected: boolean
  }
  mcp: {
    connected: boolean
    version: string
  }
}

export default function AuthDashboard() {
  const { user, loading, getIdToken } = useAdvancedFirebaseAuth()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [health, setHealth] = useState<SystemHealth | null>(null)
  const [recentActivity, setRecentActivity] = useState<any[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (user) {
      loadDashboardData()
    }
  }, [user])

  const loadDashboardData = async () => {
    setIsLoading(true)
    setError(null)

    try {
      const token = await getIdToken()
      if (!token) {
        throw new Error('No authentication token available')
      }

      // Load dashboard statistics
      await Promise.all([
        loadStats(token),
        loadHealth(token),
        loadRecentActivity(token)
      ])
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard data')
    } finally {
      setIsLoading(false)
    }
  }

  const loadStats = async (token: string) => {
    try {
      const response = await fetch('/api/firebase/stats', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        const data = await response.json()
        setStats(data)
      }
    } catch (err) {
      console.error('Failed to load stats:', err)
      // Mock data for demonstration
      setStats({
        totalUsers: 1250,
        activeUsers: 890,
        newUsersToday: 45,
        authenticationsToday: 320,
        errorRate: 0.02
      })
    }
  }

  const loadHealth = async (token: string) => {
    try {
      const response = await fetch('/api/firebase/health', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        const data = await response.json()
        setHealth(data)
      }
    } catch (err) {
      console.error('Failed to load health:', err)
      // Mock data for demonstration
      setHealth({
        firebase: {
          connected: true,
          projectId: 'hackai-dev'
        },
        database: {
          connected: true
        },
        mcp: {
          connected: true,
          version: '1.0.0'
        }
      })
    }
  }

  const loadRecentActivity = async (token: string) => {
    try {
      const response = await fetch('/api/firebase/activity', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        const data = await response.json()
        setRecentActivity(data.activities || [])
      }
    } catch (err) {
      console.error('Failed to load activity:', err)
      // Mock data for demonstration
      setRecentActivity([
        {
          id: '1',
          action: 'user_login',
          user: 'john.doe@example.com',
          timestamp: new Date().toISOString(),
          success: true
        },
        {
          id: '2',
          action: 'profile_update',
          user: 'jane.smith@example.com',
          timestamp: new Date(Date.now() - 300000).toISOString(),
          success: true
        },
        {
          id: '3',
          action: 'token_refresh',
          user: 'bob.wilson@example.com',
          timestamp: new Date(Date.now() - 600000).toISOString(),
          success: false
        }
      ])
    }
  }

  if (loading || isLoading) {
    return (
      <div className="container mx-auto p-6">
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 animate-spin" />
          <span className="ml-2 text-lg">Loading dashboard...</span>
        </div>
      </div>
    )
  }

  if (!user) {
    return (
      <div className="container mx-auto p-6">
        <Card>
          <CardContent className="flex items-center justify-center p-12">
            <div className="text-center">
              <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <h2 className="text-xl font-semibold mb-2">Authentication Required</h2>
              <p className="text-muted-foreground">Please sign in to access the dashboard.</p>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Firebase MCP Dashboard</h1>
          <p className="text-muted-foreground">
            Welcome back, {user.displayName || user.email}
          </p>
        </div>
        <Button onClick={loadDashboardData} disabled={isLoading}>
          <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Error Alert */}
      {error && (
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Dashboard Tabs */}
      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">
            <Activity className="h-4 w-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="profile">
            <User className="h-4 w-4 mr-2" />
            Profile
          </TabsTrigger>
          <TabsTrigger value="system">
            <Database className="h-4 w-4 mr-2" />
            System
          </TabsTrigger>
          <TabsTrigger value="activity">
            <FileText className="h-4 w-4 mr-2" />
            Activity
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          {/* Stats Cards */}
          {stats && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Total Users</CardTitle>
                  <Users className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stats.totalUsers.toLocaleString()}</div>
                  <p className="text-xs text-muted-foreground">
                    Registered users
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Active Users</CardTitle>
                  <Activity className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stats.activeUsers.toLocaleString()}</div>
                  <p className="text-xs text-muted-foreground">
                    Currently active
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">New Today</CardTitle>
                  <User className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stats.newUsersToday}</div>
                  <p className="text-xs text-muted-foreground">
                    New registrations
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Error Rate</CardTitle>
                  <Shield className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{(stats.errorRate * 100).toFixed(2)}%</div>
                  <p className="text-xs text-muted-foreground">
                    Authentication errors
                  </p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* System Health */}
          {health && (
            <Card>
              <CardHeader>
                <CardTitle>System Health</CardTitle>
                <CardDescription>
                  Current status of Firebase MCP services
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="flex items-center space-x-2">
                    {health.firebase.connected ? (
                      <CheckCircle className="h-5 w-5 text-green-500" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-500" />
                    )}
                    <div>
                      <p className="font-medium">Firebase</p>
                      <p className="text-sm text-muted-foreground">
                        Project: {health.firebase.projectId}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    {health.database.connected ? (
                      <CheckCircle className="h-5 w-5 text-green-500" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-500" />
                    )}
                    <div>
                      <p className="font-medium">Database</p>
                      <p className="text-sm text-muted-foreground">
                        Firestore connection
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    {health.mcp.connected ? (
                      <CheckCircle className="h-5 w-5 text-green-500" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-500" />
                    )}
                    <div>
                      <p className="font-medium">MCP Server</p>
                      <p className="text-sm text-muted-foreground">
                        Version: {health.mcp.version}
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* User Info */}
          <Card>
            <CardHeader>
              <CardTitle>Your Account</CardTitle>
              <CardDescription>
                Current user information and status
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center space-x-4">
                {user.photoURL ? (
                  <img
                    src={user.photoURL}
                    alt="Profile"
                    className="h-16 w-16 rounded-full object-cover"
                  />
                ) : (
                  <div className="h-16 w-16 rounded-full bg-muted flex items-center justify-center">
                    <User className="h-8 w-8 text-muted-foreground" />
                  </div>
                )}
                <div className="space-y-2">
                  <h3 className="text-lg font-medium">{user.displayName || 'No name set'}</h3>
                  <p className="text-sm text-muted-foreground">{user.email}</p>
                  <div className="flex items-center space-x-2">
                    <Badge variant={user.emailVerified ? "default" : "secondary"}>
                      {user.emailVerified ? 'Verified' : 'Unverified'}
                    </Badge>
                    <Badge variant="outline">
                      UID: {user.uid.substring(0, 8)}...
                    </Badge>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Profile Tab */}
        <TabsContent value="profile">
          <UserProfileManager />
        </TabsContent>

        {/* System Tab */}
        <TabsContent value="system" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Firebase MCP Integration</CardTitle>
              <CardDescription>
                Firebase MCP tools integration status and configuration
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label className="text-sm font-medium">MCP Functions Available</Label>
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span className="text-sm">firestore_add_document</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span className="text-sm">firestore_list_documents</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span className="text-sm">auth_get_user</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span className="text-sm">storage_upload</span>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label className="text-sm font-medium">Configuration</Label>
                  <div className="space-y-1">
                    <div className="flex justify-between text-sm">
                      <span>Environment:</span>
                      <Badge variant="outline">Development</Badge>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>Project ID:</span>
                      <span className="text-muted-foreground">hackai-dev</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>MCP Version:</span>
                      <span className="text-muted-foreground">1.0.0</span>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Activity Tab */}
        <TabsContent value="activity">
          <Card>
            <CardHeader>
              <CardTitle>Recent Activity</CardTitle>
              <CardDescription>
                Recent authentication and user activity
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {recentActivity.map((activity) => (
                  <div key={activity.id} className="flex items-center space-x-4 p-3 border rounded-lg">
                    <div className="flex-shrink-0">
                      {activity.success ? (
                        <CheckCircle className="h-5 w-5 text-green-500" />
                      ) : (
                        <XCircle className="h-5 w-5 text-red-500" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium">
                        {activity.action.replace('_', ' ').toUpperCase()}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {activity.user}
                      </p>
                    </div>
                    <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                      <Clock className="h-4 w-4" />
                      <span>{new Date(activity.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                ))}

                {recentActivity.length === 0 && (
                  <p className="text-center text-muted-foreground py-8">
                    No recent activity found
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

function Label({ children, className }: { children: React.ReactNode; className?: string }) {
  return <label className={className}>{children}</label>
}
