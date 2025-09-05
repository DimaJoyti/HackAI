'use client'

import React, { useState, useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { 
  User, 
  Settings, 
  Shield, 
  Bell, 
  Globe, 
  Camera, 
  Save, 
  RefreshCw, 
  LogOut,
  Link,
  Unlink,
  Eye,
  EyeOff
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { Switch } from '@/components/ui/switch'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { useAdvancedFirebaseAuth } from '@/contexts/AdvancedFirebaseAuthContext'

// Form validation schemas
const profileSchema = z.object({
  displayName: z.string().min(2, 'Display name must be at least 2 characters'),
  email: z.string().email('Please enter a valid email address'),
  photoURL: z.string().url('Please enter a valid URL').optional().or(z.literal('')),
})

const preferencesSchema = z.object({
  theme: z.enum(['light', 'dark', 'system']),
  language: z.string(),
  notifications: z.boolean(),
  emailUpdates: z.boolean(),
  privacyLevel: z.enum(['public', 'standard', 'private']),
  twoFactorEnabled: z.boolean(),
})

type ProfileFormData = z.infer<typeof profileSchema>
type PreferencesFormData = z.infer<typeof preferencesSchema>

interface UserProfileManagerProps {
  className?: string
}

export const UserProfileManager: React.FC<UserProfileManagerProps> = ({ className = '' }) => {
  const {
    user,
    loading,
    updateUserProfile,
    refreshUser,
    signOut,
    getGoogleUserProfile,
    linkGoogleAccount,
    unlinkGoogleAccount,
    getUserSessions,
    invalidateAllSessions,
    refreshGoogleTokens,
    revokeGoogleTokens
  } = useAdvancedFirebaseAuth()

  const [isUpdating, setIsUpdating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [googleProfile, setGoogleProfile] = useState<any>(null)
  const [sessions, setSessions] = useState<any[]>([])
  const [showTokens, setShowTokens] = useState(false)
  const [tokens, setTokens] = useState<any>(null)

  // Profile form
  const profileForm = useForm<ProfileFormData>({
    resolver: zodResolver(profileSchema),
    defaultValues: {
      displayName: user?.displayName || '',
      email: user?.email || '',
      photoURL: user?.photoURL || '',
    }
  })

  // Preferences form
  const preferencesForm = useForm<PreferencesFormData>({
    resolver: zodResolver(preferencesSchema),
    defaultValues: {
      theme: 'light',
      language: 'en',
      notifications: true,
      emailUpdates: true,
      privacyLevel: 'standard',
      twoFactorEnabled: false,
    }
  })

  // Update form values when user changes
  useEffect(() => {
    if (user) {
      profileForm.reset({
        displayName: user.displayName || '',
        email: user.email || '',
        photoURL: user.photoURL || '',
      })
    }
  }, [user, profileForm])

  // Load additional data
  useEffect(() => {
    if (user) {
      loadGoogleProfile()
      loadUserSessions()
    }
  }, [user])

  const clearMessages = () => {
    setError(null)
    setSuccess(null)
  }

  const loadGoogleProfile = async () => {
    try {
      const result = await getGoogleUserProfile()
      if (result.profile) {
        setGoogleProfile(result.profile)
      }
    } catch (err) {
      console.error('Failed to load Google profile:', err)
    }
  }

  const loadUserSessions = async () => {
    try {
      const result = await getUserSessions()
      if (result.sessions) {
        setSessions(result.sessions)
      }
    } catch (err) {
      console.error('Failed to load user sessions:', err)
    }
  }

  const handleProfileUpdate = async (data: ProfileFormData) => {
    setIsUpdating(true)
    clearMessages()

    try {
      const result = await updateUserProfile({
        displayName: data.displayName,
        photoURL: data.photoURL || undefined,
      })

      if (result.error) {
        setError(result.error)
      } else {
        setSuccess('Profile updated successfully')
        await refreshUser()
      }
    } catch (err: any) {
      setError(err.message || 'Failed to update profile')
    } finally {
      setIsUpdating(false)
    }
  }

  const handlePreferencesUpdate = async (data: PreferencesFormData) => {
    setIsUpdating(true)
    clearMessages()

    try {
      // In a real implementation, this would call your backend API
      // to update user preferences in Firestore using Firebase MCP tools
      console.log('Updating preferences:', data)
      setSuccess('Preferences updated successfully')
    } catch (err: any) {
      setError(err.message || 'Failed to update preferences')
    } finally {
      setIsUpdating(false)
    }
  }

  const handleLinkGoogle = async () => {
    clearMessages()
    try {
      const result = await linkGoogleAccount()
      if (result.error) {
        setError(result.error)
      } else {
        setSuccess('Google account linked successfully')
        await refreshUser()
        await loadGoogleProfile()
      }
    } catch (err: any) {
      setError(err.message || 'Failed to link Google account')
    }
  }

  const handleUnlinkGoogle = async () => {
    clearMessages()
    try {
      const result = await unlinkGoogleAccount()
      if (result.error) {
        setError(result.error)
      } else {
        setSuccess('Google account unlinked successfully')
        await refreshUser()
        setGoogleProfile(null)
      }
    } catch (err: any) {
      setError(err.message || 'Failed to unlink Google account')
    }
  }

  const handleRefreshTokens = async () => {
    clearMessages()
    try {
      const result = await refreshGoogleTokens()
      if (result.error) {
        setError(result.error)
      } else {
        setTokens(result.tokens)
        setSuccess('Tokens refreshed successfully')
      }
    } catch (err: any) {
      setError(err.message || 'Failed to refresh tokens')
    }
  }

  const handleRevokeTokens = async () => {
    clearMessages()
    try {
      const result = await revokeGoogleTokens()
      if (result.error) {
        setError(result.error)
      } else {
        setTokens(null)
        setSuccess('Tokens revoked successfully')
      }
    } catch (err: any) {
      setError(err.message || 'Failed to revoke tokens')
    }
  }

  const handleInvalidateAllSessions = async () => {
    clearMessages()
    try {
      const result = await invalidateAllSessions()
      if (result.error) {
        setError(result.error)
      } else {
        setSuccess('All sessions invalidated successfully')
        await loadUserSessions()
      }
    } catch (err: any) {
      setError(err.message || 'Failed to invalidate sessions')
    }
  }

  const handleSignOut = async () => {
    try {
      await signOut()
    } catch (err: any) {
      setError(err.message || 'Failed to sign out')
    }
  }

  if (loading) {
    return (
      <Card className={className}>
        <CardContent className="flex items-center justify-center p-6">
          <RefreshCw className="h-6 w-6 animate-spin" />
          <span className="ml-2">Loading profile...</span>
        </CardContent>
      </Card>
    )
  }

  if (!user) {
    return (
      <Card className={className}>
        <CardContent className="flex items-center justify-center p-6">
          <p>Please sign in to manage your profile.</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Messages */}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {success && (
        <Alert>
          <AlertDescription>{success}</AlertDescription>
        </Alert>
      )}

      {/* User Profile Tabs */}
      <Tabs defaultValue="profile" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="profile">
            <User className="h-4 w-4 mr-2" />
            Profile
          </TabsTrigger>
          <TabsTrigger value="preferences">
            <Settings className="h-4 w-4 mr-2" />
            Preferences
          </TabsTrigger>
          <TabsTrigger value="security">
            <Shield className="h-4 w-4 mr-2" />
            Security
          </TabsTrigger>
          <TabsTrigger value="sessions">
            <Globe className="h-4 w-4 mr-2" />
            Sessions
          </TabsTrigger>
        </TabsList>

        {/* Profile Tab */}
        <TabsContent value="profile">
          <Card>
            <CardHeader>
              <CardTitle>Profile Information</CardTitle>
              <CardDescription>
                Update your profile information and photo
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={profileForm.handleSubmit(handleProfileUpdate)} className="space-y-4">
                <div className="flex items-center space-x-4">
                  <div className="relative">
                    {user.photoURL ? (
                      <img
                        src={user.photoURL}
                        alt="Profile"
                        className="h-20 w-20 rounded-full object-cover"
                      />
                    ) : (
                      <div className="h-20 w-20 rounded-full bg-muted flex items-center justify-center">
                        <User className="h-8 w-8 text-muted-foreground" />
                      </div>
                    )}
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      className="absolute -bottom-2 -right-2"
                    >
                      <Camera className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="space-y-2">
                    <h3 className="text-lg font-medium">{user.displayName || 'No name set'}</h3>
                    <p className="text-sm text-muted-foreground">{user.email}</p>
                    <div className="flex items-center space-x-2">
                      <Badge variant={user.emailVerified ? "default" : "secondary"}>
                        {user.emailVerified ? 'Verified' : 'Unverified'}
                      </Badge>
                      {googleProfile && (
                        <Badge variant="outline">
                          Google Connected
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>

                <Separator />

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="displayName">Display Name</Label>
                    <Input
                      id="displayName"
                      {...profileForm.register('displayName')}
                      disabled={isUpdating}
                    />
                    {profileForm.formState.errors.displayName && (
                      <p className="text-sm text-destructive">
                        {profileForm.formState.errors.displayName.message}
                      </p>
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="email">Email</Label>
                    <Input
                      id="email"
                      {...profileForm.register('email')}
                      disabled={true}
                      className="bg-muted"
                    />
                    <p className="text-xs text-muted-foreground">
                      Email cannot be changed directly
                    </p>
                  </div>

                  <div className="space-y-2 md:col-span-2">
                    <Label htmlFor="photoURL">Photo URL</Label>
                    <Input
                      id="photoURL"
                      placeholder="https://example.com/photo.jpg"
                      {...profileForm.register('photoURL')}
                      disabled={isUpdating}
                    />
                    {profileForm.formState.errors.photoURL && (
                      <p className="text-sm text-destructive">
                        {profileForm.formState.errors.photoURL.message}
                      </p>
                    )}
                  </div>
                </div>

                <div className="flex justify-end space-x-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => refreshUser()}
                    disabled={isUpdating}
                  >
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh
                  </Button>
                  <Button type="submit" disabled={isUpdating}>
                    <Save className="h-4 w-4 mr-2" />
                    {isUpdating ? 'Updating...' : 'Update Profile'}
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Preferences Tab */}
        <TabsContent value="preferences">
          <Card>
            <CardHeader>
              <CardTitle>Preferences</CardTitle>
              <CardDescription>
                Customize your experience and notification settings
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={preferencesForm.handleSubmit(handlePreferencesUpdate)} className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="theme">Theme</Label>
                    <Select
                      value={preferencesForm.watch('theme')}
                      onValueChange={(value) => preferencesForm.setValue('theme', value as any)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="light">Light</SelectItem>
                        <SelectItem value="dark">Dark</SelectItem>
                        <SelectItem value="system">System</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="language">Language</Label>
                    <Select
                      value={preferencesForm.watch('language')}
                      onValueChange={(value) => preferencesForm.setValue('language', value)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="en">English</SelectItem>
                        <SelectItem value="es">Spanish</SelectItem>
                        <SelectItem value="fr">French</SelectItem>
                        <SelectItem value="de">German</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <Separator />

                <div className="space-y-4">
                  <h4 className="text-sm font-medium">Notifications</h4>
                  
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label htmlFor="notifications">Push Notifications</Label>
                      <p className="text-sm text-muted-foreground">
                        Receive notifications about important updates
                      </p>
                    </div>
                    <Switch
                      id="notifications"
                      checked={preferencesForm.watch('notifications')}
                      onCheckedChange={(checked) => preferencesForm.setValue('notifications', checked)}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label htmlFor="emailUpdates">Email Updates</Label>
                      <p className="text-sm text-muted-foreground">
                        Receive email updates about new features
                      </p>
                    </div>
                    <Switch
                      id="emailUpdates"
                      checked={preferencesForm.watch('emailUpdates')}
                      onCheckedChange={(checked) => preferencesForm.setValue('emailUpdates', checked)}
                    />
                  </div>
                </div>

                <div className="flex justify-end">
                  <Button type="submit" disabled={isUpdating}>
                    <Save className="h-4 w-4 mr-2" />
                    {isUpdating ? 'Saving...' : 'Save Preferences'}
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security">
          <div className="space-y-6">
            {/* Google Account Management */}
            <Card>
              <CardHeader>
                <CardTitle>Google Account</CardTitle>
                <CardDescription>
                  Manage your Google account connection and tokens
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {googleProfile ? (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium">Connected to Google</p>
                        <p className="text-sm text-muted-foreground">
                          {googleProfile.email}
                        </p>
                      </div>
                      <Button
                        variant="outline"
                        onClick={handleUnlinkGoogle}
                        disabled={isUpdating}
                      >
                        <Unlink className="h-4 w-4 mr-2" />
                        Unlink
                      </Button>
                    </div>

                    <div className="flex space-x-2">
                      <Button
                        variant="outline"
                        onClick={handleRefreshTokens}
                        disabled={isUpdating}
                      >
                        <RefreshCw className="h-4 w-4 mr-2" />
                        Refresh Tokens
                      </Button>
                      <Button
                        variant="outline"
                        onClick={handleRevokeTokens}
                        disabled={isUpdating}
                      >
                        Revoke Tokens
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => setShowTokens(!showTokens)}
                      >
                        {showTokens ? <EyeOff className="h-4 w-4 mr-2" /> : <Eye className="h-4 w-4 mr-2" />}
                        {showTokens ? 'Hide' : 'Show'} Tokens
                      </Button>
                    </div>

                    {showTokens && tokens && (
                      <div className="p-3 bg-muted rounded-lg">
                        <pre className="text-xs overflow-x-auto">
                          {JSON.stringify(tokens, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center space-y-4">
                    <p className="text-muted-foreground">No Google account connected</p>
                    <Button onClick={handleLinkGoogle} disabled={isUpdating}>
                      <Link className="h-4 w-4 mr-2" />
                      Link Google Account
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Sign Out */}
            <Card>
              <CardHeader>
                <CardTitle>Sign Out</CardTitle>
                <CardDescription>
                  Sign out of your account on this device
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Button variant="destructive" onClick={handleSignOut}>
                  <LogOut className="h-4 w-4 mr-2" />
                  Sign Out
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Sessions Tab */}
        <TabsContent value="sessions">
          <Card>
            <CardHeader>
              <CardTitle>Active Sessions</CardTitle>
              <CardDescription>
                Manage your active sessions across devices
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between items-center">
                <p className="text-sm text-muted-foreground">
                  {sessions.length} active session(s)
                </p>
                <Button
                  variant="outline"
                  onClick={handleInvalidateAllSessions}
                  disabled={isUpdating}
                >
                  Invalidate All Sessions
                </Button>
              </div>

              <div className="space-y-2">
                {sessions.map((session, index) => (
                  <div key={index} className="p-3 border rounded-lg">
                    <div className="flex justify-between items-start">
                      <div>
                        <p className="font-medium">Session {index + 1}</p>
                        <p className="text-sm text-muted-foreground">
                          Created: {new Date(session.created_at).toLocaleString()}
                        </p>
                        {session.ip_address && (
                          <p className="text-sm text-muted-foreground">
                            IP: {session.ip_address}
                          </p>
                        )}
                      </div>
                      <Badge variant={session.active ? "default" : "secondary"}>
                        {session.active ? 'Active' : 'Inactive'}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>

              {sessions.length === 0 && (
                <p className="text-center text-muted-foreground py-8">
                  No active sessions found
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
