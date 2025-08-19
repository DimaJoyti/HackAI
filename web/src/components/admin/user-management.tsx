'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  UserGroupIcon,
  UserPlusIcon,
  PencilIcon,
  TrashIcon,
  ShieldCheckIcon,
  KeyIcon,
  EyeIcon,
  EyeSlashIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { formatDateTime, formatRelativeTime } from '@/lib/utils'

interface User {
  id: string
  username: string
  email: string
  firstName: string
  lastName: string
  roles: Role[]
  permissions: string[]
  isActive: boolean
  isLocked: boolean
  mfaEnabled: boolean
  lastLogin?: Date
  createdAt: Date
  updatedAt: Date
  loginAttempts: number
  department: string
  avatar?: string
}

interface Role {
  id: string
  name: string
  description: string
  permissions: string[]
  isSystem: boolean
  userCount: number
  color: string
}

interface Permission {
  id: string
  name: string
  description: string
  resource: string
  action: string
  scope: string
}

interface AuditLog {
  id: string
  userId: string
  action: string
  resource: string
  details: string
  ipAddress: string
  userAgent: string
  timestamp: Date
  result: 'success' | 'failure'
}

export default function UserManagement() {
  const [users, setUsers] = useState<User[]>([])
  const [roles, setRoles] = useState<Role[]>([])
  const [permissions, setPermissions] = useState<Permission[]>([])
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([])
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedRole, setSelectedRole] = useState<string>('all')
  const [selectedStatus, setSelectedStatus] = useState<string>('all')
  const [isCreateUserOpen, setIsCreateUserOpen] = useState(false)
  const [isCreateRoleOpen, setIsCreateRoleOpen] = useState(false)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)

  // Generate mock data
  useEffect(() => {
    // Generate roles
    const roleData: Role[] = [
      {
        id: '1',
        name: 'Administrator',
        description: 'Full system access with all permissions',
        permissions: ['*:*'],
        isSystem: true,
        userCount: 3,
        color: '#ef4444',
      },
      {
        id: '2',
        name: 'Security Analyst',
        description: 'Security monitoring and incident response',
        permissions: ['security:read', 'incidents:write', 'reports:read'],
        isSystem: true,
        userCount: 8,
        color: '#f97316',
      },
      {
        id: '3',
        name: 'Compliance Officer',
        description: 'Compliance monitoring and reporting',
        permissions: ['compliance:read', 'reports:read', 'audit:read'],
        isSystem: true,
        userCount: 2,
        color: '#eab308',
      },
      {
        id: '4',
        name: 'Viewer',
        description: 'Read-only access to dashboards and reports',
        permissions: ['dashboard:read', 'reports:read'],
        isSystem: true,
        userCount: 15,
        color: '#22c55e',
      },
    ]

    // Generate users
    const userData: User[] = [
      {
        id: '1',
        username: 'admin',
        email: 'admin@company.com',
        firstName: 'System',
        lastName: 'Administrator',
        roles: [roleData[0]],
        permissions: ['*:*'],
        isActive: true,
        isLocked: false,
        mfaEnabled: true,
        lastLogin: new Date(Date.now() - 2 * 60 * 60 * 1000),
        createdAt: new Date('2023-01-01'),
        updatedAt: new Date(),
        loginAttempts: 0,
        department: 'IT',
      },
      {
        id: '2',
        username: 'j.analyst',
        email: 'john.analyst@company.com',
        firstName: 'John',
        lastName: 'Analyst',
        roles: [roleData[1]],
        permissions: ['security:read', 'incidents:write', 'reports:read'],
        isActive: true,
        isLocked: false,
        mfaEnabled: true,
        lastLogin: new Date(Date.now() - 30 * 60 * 1000),
        createdAt: new Date('2023-03-15'),
        updatedAt: new Date(),
        loginAttempts: 0,
        department: 'Security',
      },
      {
        id: '3',
        username: 's.compliance',
        email: 'sarah.compliance@company.com',
        firstName: 'Sarah',
        lastName: 'Johnson',
        roles: [roleData[2]],
        permissions: ['compliance:read', 'reports:read', 'audit:read'],
        isActive: true,
        isLocked: false,
        mfaEnabled: false,
        lastLogin: new Date(Date.now() - 4 * 60 * 60 * 1000),
        createdAt: new Date('2023-06-01'),
        updatedAt: new Date(),
        loginAttempts: 0,
        department: 'Compliance',
      },
      {
        id: '4',
        username: 'm.viewer',
        email: 'mike.viewer@company.com',
        firstName: 'Mike',
        lastName: 'Wilson',
        roles: [roleData[3]],
        permissions: ['dashboard:read', 'reports:read'],
        isActive: false,
        isLocked: true,
        mfaEnabled: false,
        lastLogin: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
        createdAt: new Date('2023-08-15'),
        updatedAt: new Date(),
        loginAttempts: 5,
        department: 'Operations',
      },
    ]

    // Generate permissions
    const permissionData: Permission[] = [
      {
        id: '1',
        name: 'Dashboard Read',
        description: 'View security dashboards and metrics',
        resource: 'dashboard',
        action: 'read',
        scope: 'application',
      },
      {
        id: '2',
        name: 'Security Read',
        description: 'View security events and alerts',
        resource: 'security',
        action: 'read',
        scope: 'application',
      },
      {
        id: '3',
        name: 'Incident Write',
        description: 'Create and update security incidents',
        resource: 'incidents',
        action: 'write',
        scope: 'application',
      },
      {
        id: '4',
        name: 'User Management',
        description: 'Manage users and permissions',
        resource: 'users',
        action: '*',
        scope: 'global',
      },
    ]

    // Generate audit logs
    const auditData: AuditLog[] = [
      {
        id: '1',
        userId: '2',
        action: 'login',
        resource: 'authentication',
        details: 'Successful login with MFA',
        ipAddress: '192.168.1.100',
        userAgent: 'Mozilla/5.0...',
        timestamp: new Date(Date.now() - 30 * 60 * 1000),
        result: 'success',
      },
      {
        id: '2',
        userId: '4',
        action: 'login_failed',
        resource: 'authentication',
        details: 'Failed login attempt - account locked',
        ipAddress: '192.168.1.150',
        userAgent: 'Mozilla/5.0...',
        timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
        result: 'failure',
      },
      {
        id: '3',
        userId: '1',
        action: 'user_update',
        resource: 'users',
        details: 'Updated user permissions for j.analyst',
        ipAddress: '192.168.1.10',
        userAgent: 'Mozilla/5.0...',
        timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000),
        result: 'success',
      },
    ]

    setUsers(userData)
    setRoles(roleData)
    setPermissions(permissionData)
    setAuditLogs(auditData)
  }, [])

  const filteredUsers = users.filter(user => {
    const matchesSearch = 
      user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
      `${user.firstName} ${user.lastName}`.toLowerCase().includes(searchTerm.toLowerCase())
    
    const matchesRole = selectedRole === 'all' || user.roles.some(role => role.id === selectedRole)
    
    const matchesStatus = 
      selectedStatus === 'all' ||
      (selectedStatus === 'active' && user.isActive && !user.isLocked) ||
      (selectedStatus === 'inactive' && !user.isActive) ||
      (selectedStatus === 'locked' && user.isLocked)
    
    return matchesSearch && matchesRole && matchesStatus
  })

  const handleToggleUserStatus = (userId: string) => {
    setUsers(prev => prev.map(user => 
      user.id === userId 
        ? { ...user, isActive: !user.isActive, updatedAt: new Date() }
        : user
    ))
  }

  const handleToggleUserLock = (userId: string) => {
    setUsers(prev => prev.map(user => 
      user.id === userId 
        ? { ...user, isLocked: !user.isLocked, updatedAt: new Date() }
        : user
    ))
  }

  const handleResetMFA = (userId: string) => {
    setUsers(prev => prev.map(user => 
      user.id === userId 
        ? { ...user, mfaEnabled: false, updatedAt: new Date() }
        : user
    ))
  }

  const getUserStatusBadge = (user: User) => {
    if (user.isLocked) return <Badge variant="destructive">Locked</Badge>
    if (!user.isActive) return <Badge variant="secondary">Inactive</Badge>
    return <Badge variant="default">Active</Badge>
  }

  const getRoleColor = (role: Role) => {
    return role.color || '#6b7280'
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            User Management
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Manage users, roles, and permissions with advanced RBAC controls
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Dialog open={isCreateRoleOpen} onOpenChange={setIsCreateRoleOpen}>
            <DialogTrigger asChild>
              <Button variant="outline">
                <ShieldCheckIcon className="h-4 w-4 mr-2" />
                Create Role
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create New Role</DialogTitle>
                <DialogDescription>
                  Define a new role with specific permissions
                </DialogDescription>
              </DialogHeader>
              {/* Role creation form would go here */}
            </DialogContent>
          </Dialog>
          
          <Dialog open={isCreateUserOpen} onOpenChange={setIsCreateUserOpen}>
            <DialogTrigger asChild>
              <Button>
                <UserPlusIcon className="h-4 w-4 mr-2" />
                Add User
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create New User</DialogTitle>
                <DialogDescription>
                  Add a new user to the system with appropriate roles
                </DialogDescription>
              </DialogHeader>
              {/* User creation form would go here */}
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <UserGroupIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{users.length}</div>
            <p className="text-xs text-muted-foreground">
              {users.filter(u => u.isActive).length} active
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Roles</CardTitle>
            <ShieldCheckIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{roles.length}</div>
            <p className="text-xs text-muted-foreground">
              {roles.filter(r => r.isSystem).length} system roles
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">MFA Enabled</CardTitle>
            <KeyIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {users.filter(u => u.mfaEnabled).length}
            </div>
            <p className="text-xs text-muted-foreground">
              {Math.round((users.filter(u => u.mfaEnabled).length / users.length) * 100)}% coverage
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Locked Accounts</CardTitle>
            <EyeSlashIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {users.filter(u => u.isLocked).length}
            </div>
            <p className="text-xs text-muted-foreground">
              Require admin unlock
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="users" className="space-y-4">
        <TabsList>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="roles">Roles & Permissions</TabsTrigger>
          <TabsTrigger value="audit">Audit Logs</TabsTrigger>
        </TabsList>

        <TabsContent value="users" className="space-y-4">
          {/* Filters */}
          <div className="flex items-center space-x-4">
            <div className="relative flex-1 max-w-sm">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search users..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select value={selectedRole} onValueChange={setSelectedRole}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="Filter by role" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Roles</SelectItem>
                {roles.map(role => (
                  <SelectItem key={role.id} value={role.id}>{role.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={selectedStatus} onValueChange={setSelectedStatus}>
              <SelectTrigger className="w-32">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
                <SelectItem value="locked">Locked</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Users Table */}
          <Card>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="border-b">
                    <tr className="text-left">
                      <th className="p-4 font-medium">User</th>
                      <th className="p-4 font-medium">Roles</th>
                      <th className="p-4 font-medium">Status</th>
                      <th className="p-4 font-medium">Last Login</th>
                      <th className="p-4 font-medium">MFA</th>
                      <th className="p-4 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    <AnimatePresence>
                      {filteredUsers.map((user) => (
                        <motion.tr
                          key={user.id}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          exit={{ opacity: 0 }}
                          className="border-b hover:bg-gray-50 dark:hover:bg-gray-800"
                        >
                          <td className="p-4">
                            <div className="flex items-center space-x-3">
                              <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm font-medium">
                                {user.firstName[0]}{user.lastName[0]}
                              </div>
                              <div>
                                <p className="font-medium">{user.firstName} {user.lastName}</p>
                                <p className="text-sm text-gray-500">{user.email}</p>
                              </div>
                            </div>
                          </td>
                          <td className="p-4">
                            <div className="flex flex-wrap gap-1">
                              {user.roles.map((role) => (
                                <Badge 
                                  key={role.id} 
                                  variant="outline"
                                  style={{ borderColor: getRoleColor(role), color: getRoleColor(role) }}
                                >
                                  {role.name}
                                </Badge>
                              ))}
                            </div>
                          </td>
                          <td className="p-4">
                            {getUserStatusBadge(user)}
                          </td>
                          <td className="p-4">
                            <span className="text-sm text-gray-500">
                              {user.lastLogin ? formatRelativeTime(user.lastLogin) : 'Never'}
                            </span>
                          </td>
                          <td className="p-4">
                            {user.mfaEnabled ? (
                              <Badge variant="default">Enabled</Badge>
                            ) : (
                              <Badge variant="secondary">Disabled</Badge>
                            )}
                          </td>
                          <td className="p-4">
                            <div className="flex items-center space-x-2">
                              <Button size="sm" variant="outline">
                                <PencilIcon className="h-3 w-3" />
                              </Button>
                              <Button 
                                size="sm" 
                                variant="outline"
                                onClick={() => handleToggleUserLock(user.id)}
                              >
                                {user.isLocked ? <EyeIcon className="h-3 w-3" /> : <EyeSlashIcon className="h-3 w-3" />}
                              </Button>
                              <Button 
                                size="sm" 
                                variant="outline"
                                onClick={() => handleResetMFA(user.id)}
                                disabled={!user.mfaEnabled}
                              >
                                <KeyIcon className="h-3 w-3" />
                              </Button>
                            </div>
                          </td>
                        </motion.tr>
                      ))}
                    </AnimatePresence>
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="roles" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Roles */}
            <Card>
              <CardHeader>
                <CardTitle>System Roles</CardTitle>
                <CardDescription>
                  Manage roles and their associated permissions
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {roles.map((role) => (
                    <div key={role.id} className="p-3 border rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <div 
                            className="w-3 h-3 rounded-full" 
                            style={{ backgroundColor: role.color }}
                          />
                          <h3 className="font-medium">{role.name}</h3>
                          {role.isSystem && <Badge variant="outline">System</Badge>}
                        </div>
                        <span className="text-sm text-gray-500">{role.userCount} users</span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                        {role.description}
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {role.permissions.slice(0, 3).map((permission, index) => (
                          <Badge key={index} variant="secondary" className="text-xs">
                            {permission}
                          </Badge>
                        ))}
                        {role.permissions.length > 3 && (
                          <Badge variant="secondary" className="text-xs">
                            +{role.permissions.length - 3} more
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Permissions */}
            <Card>
              <CardHeader>
                <CardTitle>Available Permissions</CardTitle>
                <CardDescription>
                  System permissions that can be assigned to roles
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {permissions.map((permission) => (
                    <div key={permission.id} className="p-3 border rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="font-medium">{permission.name}</h3>
                        <Badge variant="outline">{permission.scope}</Badge>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                        {permission.description}
                      </p>
                      <div className="text-xs text-gray-500">
                        {permission.resource}:{permission.action}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="audit" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Audit Logs</CardTitle>
              <CardDescription>
                Security audit trail for user management activities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {auditLogs.map((log) => (
                  <div key={log.id} className="p-3 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <Badge variant={log.result === 'success' ? 'default' : 'destructive'}>
                          {log.action}
                        </Badge>
                        <span className="text-sm font-medium">{log.resource}</span>
                      </div>
                      <span className="text-sm text-gray-500">
                        {formatRelativeTime(log.timestamp)}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                      {log.details}
                    </p>
                    <div className="flex items-center space-x-4 text-xs text-gray-500">
                      <span>User ID: {log.userId}</span>
                      <span>IP: {log.ipAddress}</span>
                      <span>Result: {log.result}</span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
