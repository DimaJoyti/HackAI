'use client'

import { useState } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  ChartBarIcon,
  ShieldCheckIcon,
  GlobeAltIcon,
  UserGroupIcon,
  Cog6ToothIcon,
} from '@heroicons/react/24/outline'
import RealTimeDashboard from '@/components/dashboard/real-time-dashboard'
import ThreatIntelligenceDashboard from '@/components/dashboard/threat-intelligence-dashboard'
import AdvancedAnalytics from '@/components/analytics/advanced-analytics'
import UserManagement from '@/components/admin/user-management'

export default function EnhancedDashboardPage() {
  const [activeTab, setActiveTab] = useState('overview')

  return (
    <div className="flex-1 space-y-4 p-8 pt-6">
      <div className="flex items-center justify-between space-y-2">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">HackAI Security Platform</h2>
          <p className="text-muted-foreground">
            Comprehensive AI-powered security monitoring and threat intelligence
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Badge variant="outline" className="text-green-600 border-green-600">
            System Operational
          </Badge>
          <Button variant="outline" size="sm">
            <Cog6ToothIcon className="h-4 w-4 mr-2" />
            Settings
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview" className="flex items-center space-x-2">
            <ChartBarIcon className="h-4 w-4" />
            <span>Overview</span>
          </TabsTrigger>
          <TabsTrigger value="threats" className="flex items-center space-x-2">
            <ShieldCheckIcon className="h-4 w-4" />
            <span>Threat Intel</span>
          </TabsTrigger>
          <TabsTrigger value="analytics" className="flex items-center space-x-2">
            <ChartBarIcon className="h-4 w-4" />
            <span>Analytics</span>
          </TabsTrigger>
          <TabsTrigger value="users" className="flex items-center space-x-2">
            <UserGroupIcon className="h-4 w-4" />
            <span>Users</span>
          </TabsTrigger>
          <TabsTrigger value="global" className="flex items-center space-x-2">
            <GlobeAltIcon className="h-4 w-4" />
            <span>Global View</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <RealTimeDashboard />
        </TabsContent>

        <TabsContent value="threats" className="space-y-4">
          <ThreatIntelligenceDashboard />
        </TabsContent>

        <TabsContent value="analytics" className="space-y-4">
          <AdvancedAnalytics />
        </TabsContent>

        <TabsContent value="users" className="space-y-4">
          <UserManagement />
        </TabsContent>

        <TabsContent value="global" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border bg-card text-card-foreground shadow">
              <div className="p-6 flex flex-row items-center justify-between space-y-0 pb-2">
                <h3 className="tracking-tight text-sm font-medium">Global Threats</h3>
                <ShieldCheckIcon className="h-4 w-4 text-muted-foreground" />
              </div>
              <div className="p-6 pt-0">
                <div className="text-2xl font-bold">12,847</div>
                <p className="text-xs text-muted-foreground">
                  +8.2% from yesterday
                </p>
              </div>
            </div>
            <div className="rounded-xl border bg-card text-card-foreground shadow">
              <div className="p-6 flex flex-row items-center justify-between space-y-0 pb-2">
                <h3 className="tracking-tight text-sm font-medium">Active Campaigns</h3>
                <GlobeAltIcon className="h-4 w-4 text-muted-foreground" />
              </div>
              <div className="p-6 pt-0">
                <div className="text-2xl font-bold">47</div>
                <p className="text-xs text-muted-foreground">
                  3 new this hour
                </p>
              </div>
            </div>
            <div className="rounded-xl border bg-card text-card-foreground shadow">
              <div className="p-6 flex flex-row items-center justify-between space-y-0 pb-2">
                <h3 className="tracking-tight text-sm font-medium">IOCs Detected</h3>
                <ChartBarIcon className="h-4 w-4 text-muted-foreground" />
              </div>
              <div className="p-6 pt-0">
                <div className="text-2xl font-bold">2,156</div>
                <p className="text-xs text-muted-foreground">
                  +12.5% from last week
                </p>
              </div>
            </div>
            <div className="rounded-xl border bg-card text-card-foreground shadow">
              <div className="p-6 flex flex-row items-center justify-between space-y-0 pb-2">
                <h3 className="tracking-tight text-sm font-medium">Coverage</h3>
                <UserGroupIcon className="h-4 w-4 text-muted-foreground" />
              </div>
              <div className="p-6 pt-0">
                <div className="text-2xl font-bold">99.7%</div>
                <p className="text-xs text-muted-foreground">
                  Global monitoring active
                </p>
              </div>
            </div>
          </div>
          
          <div className="text-center py-12">
            <GlobeAltIcon className="h-16 w-16 mx-auto text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">Global Threat Intelligence</h3>
            <p className="text-muted-foreground max-w-md mx-auto">
              Real-time global threat monitoring and intelligence sharing across the HackAI network.
              Advanced features coming soon.
            </p>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
