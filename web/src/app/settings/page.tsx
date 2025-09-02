'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  Cog6ToothIcon,
  UserIcon,
  ShieldCheckIcon,
  BellIcon,
  PaintBrushIcon,
  GlobeAltIcon,
  CpuChipIcon,
  EyeIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { useAuth } from '@/hooks/use-auth'

interface SettingsSection {
  id: string
  name: string
  icon: React.ComponentType<{ className?: string }>
  description: string
}

const settingsSections: SettingsSection[] = [
  {
    id: 'profile',
    name: 'Profile',
    icon: UserIcon,
    description: 'Manage your account and personal information'
  },
  {
    id: 'security',
    name: 'Security',
    icon: ShieldCheckIcon,
    description: 'Security settings and authentication'
  },
  {
    id: 'notifications',
    name: 'Notifications',
    icon: BellIcon,
    description: 'Configure alerts and notification preferences'
  },
  {
    id: 'appearance',
    name: 'Appearance',
    icon: PaintBrushIcon,
    description: 'Customize the cyberpunk theme and UI'
  },
  {
    id: 'api',
    name: 'API & Integrations',
    icon: GlobeAltIcon,
    description: 'API keys and external service integrations'
  },
  {
    id: 'ai-models',
    name: 'AI Models',
    icon: CpuChipIcon,
    description: 'Configure AI model settings and preferences'
  },
  {
    id: 'privacy',
    name: 'Privacy',
    icon: EyeIcon,
    description: 'Data privacy and usage settings'
  }
]

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState('profile')
  const [settings, setSettings] = useState({
    profile: {
      name: 'Security Analyst',
      email: 'analyst@hackai.dev',
      bio: 'Cybersecurity professional specializing in AI-powered threat detection',
      timezone: 'UTC-8',
      language: 'en'
    },
    security: {
      twoFactorEnabled: true,
      sessionTimeout: 30,
      loginNotifications: true,
      apiKeyRotation: 90
    },
    notifications: {
      emailAlerts: true,
      pushNotifications: true,
      criticalOnly: false,
      scanComplete: true,
      threatDetected: true,
      systemUpdates: false
    },
    appearance: {
      theme: 'cyber-blue',
      animations: true,
      glowEffects: true,
      scanlines: true,
      particles: false,
      fontSize: 'medium'
    },
    api: {
      ollamaEndpoint: 'http://localhost:11434',
      maxConcurrentRequests: 10,
      requestTimeout: 30,
      rateLimitEnabled: true
    },
    aiModels: {
      defaultModel: 'llama2',
      autoUpdate: false,
      maxMemoryUsage: 8,
      enableGpu: true
    },
    privacy: {
      dataRetention: 90,
      anonymizeData: true,
      shareAnalytics: false,
      exportData: true
    }
  })

  const { user } = useAuth()

  const handleSettingChange = (section: string, key: string, value: any) => {
    setSettings(prev => ({
      ...prev,
      [section]: {
        ...prev[section as keyof typeof prev],
        [key]: value
      }
    }))
  }

  const renderProfileSettings = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-matrix-white mb-2">
            Display Name
          </label>
          <Input
            value={settings.profile.name}
            onChange={(e) => handleSettingChange('profile', 'name', e.target.value)}
            className="bg-matrix-surface border-matrix-border text-matrix-white"
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-matrix-white mb-2">
            Email Address
          </label>
          <Input
            type="email"
            value={settings.profile.email}
            onChange={(e) => handleSettingChange('profile', 'email', e.target.value)}
            className="bg-matrix-surface border-matrix-border text-matrix-white"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-matrix-white mb-2">
          Bio
        </label>
        <Textarea
          value={settings.profile.bio}
          onChange={(e) => handleSettingChange('profile', 'bio', e.target.value)}
          className="bg-matrix-surface border-matrix-border text-matrix-white"
          rows={3}
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-matrix-white mb-2">
            Timezone
          </label>
          <select
            value={settings.profile.timezone}
            onChange={(e) => handleSettingChange('profile', 'timezone', e.target.value)}
            className="w-full px-3 py-2 bg-matrix-surface border border-matrix-border rounded-lg text-matrix-white"
          >
            <option value="UTC-8">Pacific Time (UTC-8)</option>
            <option value="UTC-5">Eastern Time (UTC-5)</option>
            <option value="UTC+0">UTC</option>
            <option value="UTC+1">Central European Time (UTC+1)</option>
          </select>
        </div>
        
        <div>
          <label className="block text-sm font-medium text-matrix-white mb-2">
            Language
          </label>
          <select
            value={settings.profile.language}
            onChange={(e) => handleSettingChange('profile', 'language', e.target.value)}
            className="w-full px-3 py-2 bg-matrix-surface border border-matrix-border rounded-lg text-matrix-white"
          >
            <option value="en">English</option>
            <option value="es">Spanish</option>
            <option value="fr">French</option>
            <option value="de">German</option>
          </select>
        </div>
      </div>
    </div>
  )

  const renderSecuritySettings = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-between p-4 bg-matrix-surface rounded-lg border border-matrix-border">
        <div>
          <h3 className="font-medium text-matrix-white">Two-Factor Authentication</h3>
          <p className="text-sm text-matrix-text">Add an extra layer of security to your account</p>
        </div>
        <Switch
          checked={settings.security.twoFactorEnabled}
          onCheckedChange={(checked) => handleSettingChange('security', 'twoFactorEnabled', checked)}
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-matrix-white mb-2">
            Session Timeout (minutes)
          </label>
          <Input
            type="number"
            value={settings.security.sessionTimeout}
            onChange={(e) => handleSettingChange('security', 'sessionTimeout', parseInt(e.target.value))}
            className="bg-matrix-surface border-matrix-border text-matrix-white"
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-matrix-white mb-2">
            API Key Rotation (days)
          </label>
          <Input
            type="number"
            value={settings.security.apiKeyRotation}
            onChange={(e) => handleSettingChange('security', 'apiKeyRotation', parseInt(e.target.value))}
            className="bg-matrix-surface border-matrix-border text-matrix-white"
          />
        </div>
      </div>

      <div className="flex items-center justify-between p-4 bg-matrix-surface rounded-lg border border-matrix-border">
        <div>
          <h3 className="font-medium text-matrix-white">Login Notifications</h3>
          <p className="text-sm text-matrix-text">Get notified of new login attempts</p>
        </div>
        <Switch
          checked={settings.security.loginNotifications}
          onCheckedChange={(checked) => handleSettingChange('security', 'loginNotifications', checked)}
        />
      </div>
    </div>
  )

  const renderNotificationSettings = () => (
    <div className="space-y-6">
      {[
        { key: 'emailAlerts', label: 'Email Alerts', description: 'Receive security alerts via email' },
        { key: 'pushNotifications', label: 'Push Notifications', description: 'Browser push notifications' },
        { key: 'criticalOnly', label: 'Critical Only', description: 'Only notify for critical security events' },
        { key: 'scanComplete', label: 'Scan Completion', description: 'Notify when security scans complete' },
        { key: 'threatDetected', label: 'Threat Detection', description: 'Immediate alerts for detected threats' },
        { key: 'systemUpdates', label: 'System Updates', description: 'Notifications about system updates' }
      ].map((setting) => (
        <div key={setting.key} className="flex items-center justify-between p-4 bg-matrix-surface rounded-lg border border-matrix-border">
          <div>
            <h3 className="font-medium text-matrix-white">{setting.label}</h3>
            <p className="text-sm text-matrix-text">{setting.description}</p>
          </div>
          <Switch
            checked={settings.notifications[setting.key as keyof typeof settings.notifications] as boolean}
            onCheckedChange={(checked) => handleSettingChange('notifications', setting.key, checked)}
          />
        </div>
      ))}
    </div>
  )

  const renderAppearanceSettings = () => (
    <div className="space-y-6">
      <div>
        <label className="block text-sm font-medium text-matrix-white mb-3">
          Cyberpunk Theme
        </label>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {['cyber-blue', 'cyber-pink', 'cyber-green', 'cyber-orange'].map((theme) => (
            <button
              key={theme}
              onClick={() => handleSettingChange('appearance', 'theme', theme)}
              className={`p-3 rounded-lg border-2 transition-colors ${
                settings.appearance.theme === theme
                  ? 'border-cyber-blue-neon bg-cyber-blue-neon/20'
                  : 'border-matrix-border hover:border-matrix-border-hover'
              }`}
            >
              <div className={`w-full h-8 rounded mb-2 ${
                theme === 'cyber-blue' ? 'bg-cyber-blue-neon' :
                theme === 'cyber-pink' ? 'bg-cyber-pink-neon' :
                theme === 'cyber-green' ? 'bg-cyber-green-neon' :
                'bg-cyber-orange-neon'
              }`} />
              <span className="text-xs text-matrix-white capitalize">
                {theme.replace('-', ' ')}
              </span>
            </button>
          ))}
        </div>
      </div>

      {[
        { key: 'animations', label: 'Animations', description: 'Enable UI animations and transitions' },
        { key: 'glowEffects', label: 'Glow Effects', description: 'Neon glow effects on UI elements' },
        { key: 'scanlines', label: 'Scanlines', description: 'Retro CRT scanline overlay' },
        { key: 'particles', label: 'Particles', description: 'Floating particle effects' }
      ].map((setting) => (
        <div key={setting.key} className="flex items-center justify-between p-4 bg-matrix-surface rounded-lg border border-matrix-border">
          <div>
            <h3 className="font-medium text-matrix-white">{setting.label}</h3>
            <p className="text-sm text-matrix-text">{setting.description}</p>
          </div>
          <Switch
            checked={settings.appearance[setting.key as keyof typeof settings.appearance] as boolean}
            onCheckedChange={(checked) => handleSettingChange('appearance', setting.key, checked)}
          />
        </div>
      ))}
    </div>
  )

  const renderContent = () => {
    switch (activeSection) {
      case 'profile':
        return renderProfileSettings()
      case 'security':
        return renderSecuritySettings()
      case 'notifications':
        return renderNotificationSettings()
      case 'appearance':
        return renderAppearanceSettings()
      default:
        return (
          <div className="text-center py-12">
            <Cog6ToothIcon className="w-12 h-12 text-matrix-text mx-auto mb-4" />
            <h3 className="text-lg font-medium text-matrix-white mb-2">
              Settings Section
            </h3>
            <p className="text-matrix-text">
              This settings section is under development
            </p>
          </div>
        )
    }
  }

  return (
    <div className="min-h-screen bg-matrix-void p-4 md:p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-display font-bold text-cyber-blue-neon">
            Settings
          </h1>
          <p className="text-matrix-text mt-1">
            Configure your HackAI security platform preferences
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          <Badge variant="outline" className="border-cyber-green-neon text-cyber-green-neon">
            {user?.role || 'User'}
          </Badge>
          
          <CyberpunkButton variant="neon-green" size="sm">
            Save Changes
          </CyberpunkButton>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Settings Navigation */}
        <div className="lg:col-span-1">
          <CyberpunkCard variant="glass-dark" size="lg">
            <h2 className="text-lg font-semibold text-matrix-white mb-4">
              Settings
            </h2>
            
            <nav className="space-y-2">
              {settingsSections.map((section, index) => (
                <motion.button
                  key={section.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.1 }}
                  onClick={() => setActiveSection(section.id)}
                  className={`w-full flex items-center gap-3 px-3 py-3 text-left rounded-lg transition-colors ${
                    activeSection === section.id
                      ? 'bg-cyber-blue-neon/20 text-cyber-blue-neon border border-cyber-blue-neon/40'
                      : 'text-matrix-light hover:text-matrix-white hover:bg-matrix-surface'
                  }`}
                >
                  <section.icon className="w-5 h-5" />
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-sm">{section.name}</div>
                    <div className="text-xs text-matrix-text truncate">
                      {section.description}
                    </div>
                  </div>
                </motion.button>
              ))}
            </nav>
          </CyberpunkCard>
        </div>

        {/* Settings Content */}
        <div className="lg:col-span-3">
          <CyberpunkCard variant="neon-blue" size="lg">
            <div className="mb-6">
              <h2 className="text-xl font-semibold text-cyber-blue-neon">
                {settingsSections.find(s => s.id === activeSection)?.name}
              </h2>
              <p className="text-matrix-text mt-1">
                {settingsSections.find(s => s.id === activeSection)?.description}
              </p>
            </div>

            <motion.div
              key={activeSection}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
            >
              {renderContent()}
            </motion.div>

            {/* Save Button */}
            <div className="flex justify-end pt-6 mt-6 border-t border-matrix-border">
              <div className="flex gap-3">
                <CyberpunkButton variant="ghost-blue" size="default">
                  Reset to Defaults
                </CyberpunkButton>
                <CyberpunkButton variant="neon-green" size="default">
                  Save Changes
                </CyberpunkButton>
              </div>
            </div>
          </CyberpunkCard>
        </div>
      </div>
    </div>
  )
}
