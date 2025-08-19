'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  GlobeAltIcon,
  ShieldExclamationIcon,
  BugAntIcon,
  UserGroupIcon,
  DocumentTextIcon,
  ArrowTrendingUpIcon,
  MapIcon,
  ClockIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { formatDateTime, formatRelativeTime } from '@/lib/utils'
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, LineChart, Line } from 'recharts'

interface ThreatActor {
  id: string
  name: string
  aliases: string[]
  country: string
  firstSeen: Date
  lastActivity: Date
  techniques: string[]
  campaigns: number
  severity: 'critical' | 'high' | 'medium' | 'low'
}

interface CVEData {
  id: string
  cveId: string
  title: string
  severity: number
  cvssScore: number
  publishedDate: Date
  affectedProducts: string[]
  exploitAvailable: boolean
  trending: boolean
}

interface MITREData {
  id: string
  techniqueId: string
  name: string
  tactic: string
  platform: string[]
  detectionDifficulty: 'easy' | 'medium' | 'hard'
  usage: number
}

interface ThreatTrend {
  date: string
  malware: number
  phishing: number
  ransomware: number
  apt: number
}

export default function ThreatIntelligenceDashboard() {
  const [threatActors, setThreatActors] = useState<ThreatActor[]>([])
  const [cveData, setCveData] = useState<CVEData[]>([])
  const [mitreData, setMitreData] = useState<MITREData[]>([])
  const [threatTrends, setThreatTrends] = useState<ThreatTrend[]>([])
  const [selectedTimeRange, setSelectedTimeRange] = useState('7d')

  // Mock data generation
  useEffect(() => {
    // Generate threat actors
    const actors: ThreatActor[] = [
      {
        id: '1',
        name: 'APT29 (Cozy Bear)',
        aliases: ['The Dukes', 'CozyDuke', 'Dark Halo'],
        country: 'Russia',
        firstSeen: new Date('2014-01-01'),
        lastActivity: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
        techniques: ['T1566.001', 'T1055', 'T1083', 'T1005'],
        campaigns: 15,
        severity: 'critical',
      },
      {
        id: '2',
        name: 'Lazarus Group',
        aliases: ['HIDDEN COBRA', 'Guardians of Peace'],
        country: 'North Korea',
        firstSeen: new Date('2009-01-01'),
        lastActivity: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
        techniques: ['T1566.002', 'T1204.002', 'T1059.003'],
        campaigns: 23,
        severity: 'critical',
      },
      {
        id: '3',
        name: 'FIN7',
        aliases: ['Carbanak Group', 'Navigator Group'],
        country: 'Unknown',
        firstSeen: new Date('2013-01-01'),
        lastActivity: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
        techniques: ['T1566.001', 'T1204.002', 'T1055.012'],
        campaigns: 18,
        severity: 'high',
      },
    ]

    // Generate CVE data
    const cves: CVEData[] = [
      {
        id: '1',
        cveId: 'CVE-2024-0001',
        title: 'Remote Code Execution in Apache HTTP Server',
        severity: 9.8,
        cvssScore: 9.8,
        publishedDate: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
        affectedProducts: ['Apache HTTP Server 2.4.x'],
        exploitAvailable: true,
        trending: true,
      },
      {
        id: '2',
        cveId: 'CVE-2024-0002',
        title: 'SQL Injection in WordPress Plugin',
        severity: 7.5,
        cvssScore: 7.5,
        publishedDate: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
        affectedProducts: ['WordPress Contact Form 7'],
        exploitAvailable: false,
        trending: true,
      },
      {
        id: '3',
        cveId: 'CVE-2024-0003',
        title: 'Buffer Overflow in OpenSSL',
        severity: 8.1,
        cvssScore: 8.1,
        publishedDate: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
        affectedProducts: ['OpenSSL 3.0.x', 'OpenSSL 1.1.1'],
        exploitAvailable: true,
        trending: false,
      },
    ]

    // Generate MITRE data
    const mitre: MITREData[] = [
      {
        id: '1',
        techniqueId: 'T1566.001',
        name: 'Spearphishing Attachment',
        tactic: 'Initial Access',
        platform: ['Windows', 'macOS', 'Linux'],
        detectionDifficulty: 'medium',
        usage: 85,
      },
      {
        id: '2',
        techniqueId: 'T1055',
        name: 'Process Injection',
        tactic: 'Defense Evasion',
        platform: ['Windows'],
        detectionDifficulty: 'hard',
        usage: 72,
      },
      {
        id: '3',
        techniqueId: 'T1083',
        name: 'File and Directory Discovery',
        tactic: 'Discovery',
        platform: ['Windows', 'macOS', 'Linux'],
        detectionDifficulty: 'easy',
        usage: 91,
      },
    ]

    // Generate trend data
    const trends: ThreatTrend[] = Array.from({ length: 30 }, (_, i) => {
      const date = new Date(Date.now() - (29 - i) * 24 * 60 * 60 * 1000)
      return {
        date: date.toISOString().split('T')[0],
        malware: Math.floor(Math.random() * 100) + 50,
        phishing: Math.floor(Math.random() * 80) + 30,
        ransomware: Math.floor(Math.random() * 40) + 10,
        apt: Math.floor(Math.random() * 20) + 5,
      }
    })

    setThreatActors(actors)
    setCveData(cves)
    setMitreData(mitre)
    setThreatTrends(trends)
  }, [])

  const severityColors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
  }

  const threatTypeData = [
    { name: 'Malware', value: 35, color: '#ef4444' },
    { name: 'Phishing', value: 28, color: '#f97316' },
    { name: 'Ransomware', value: 20, color: '#eab308' },
    { name: 'APT', value: 17, color: '#8b5cf6' },
  ]

  const topTechniques = mitreData
    .sort((a, b) => b.usage - a.usage)
    .slice(0, 5)
    .map(technique => ({
      name: technique.name,
      usage: technique.usage,
      id: technique.techniqueId,
    }))

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Threat Intelligence Dashboard
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Real-time threat intelligence from MITRE ATT&CK, CVE databases, and global threat feeds
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant={selectedTimeRange === '24h' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setSelectedTimeRange('24h')}
          >
            24h
          </Button>
          <Button
            variant={selectedTimeRange === '7d' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setSelectedTimeRange('7d')}
          >
            7d
          </Button>
          <Button
            variant={selectedTimeRange === '30d' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setSelectedTimeRange('30d')}
          >
            30d
          </Button>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Threat Actors</CardTitle>
            <UserGroupIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{threatActors.length}</div>
            <p className="text-xs text-muted-foreground">
              {threatActors.filter(a => a.severity === 'critical').length} critical
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">New CVEs</CardTitle>
            <BugAntIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{cveData.length}</div>
            <p className="text-xs text-muted-foreground">
              {cveData.filter(c => c.trending).length} trending
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">MITRE Techniques</CardTitle>
            <DocumentTextIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mitreData.length}</div>
            <p className="text-xs text-muted-foreground">
              Active in campaigns
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Threat Level</CardTitle>
            <ShieldExclamationIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600">HIGH</div>
            <p className="text-xs text-muted-foreground">
              Based on recent activity
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="actors">Threat Actors</TabsTrigger>
          <TabsTrigger value="cves">CVE Intelligence</TabsTrigger>
          <TabsTrigger value="mitre">MITRE ATT&CK</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Threat Type Distribution */}
            <Card>
              <CardHeader>
                <CardTitle>Threat Type Distribution</CardTitle>
                <CardDescription>
                  Current threat landscape breakdown
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={threatTypeData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={100}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {threatTypeData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="grid grid-cols-2 gap-2 mt-4">
                  {threatTypeData.map((item, index) => (
                    <div key={index} className="flex items-center space-x-2">
                      <div 
                        className="w-3 h-3 rounded-full" 
                        style={{ backgroundColor: item.color }}
                      />
                      <span className="text-sm">{item.name}: {item.value}%</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Threat Trends */}
            <Card>
              <CardHeader>
                <CardTitle>Threat Activity Trends</CardTitle>
                <CardDescription>
                  30-day threat activity overview
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={threatTrends}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis 
                        dataKey="date" 
                        tickFormatter={(value) => new Date(value).toLocaleDateString()}
                      />
                      <YAxis />
                      <Tooltip 
                        labelFormatter={(value) => new Date(value).toLocaleDateString()}
                      />
                      <Line type="monotone" dataKey="malware" stroke="#ef4444" strokeWidth={2} />
                      <Line type="monotone" dataKey="phishing" stroke="#f97316" strokeWidth={2} />
                      <Line type="monotone" dataKey="ransomware" stroke="#eab308" strokeWidth={2} />
                      <Line type="monotone" dataKey="apt" stroke="#8b5cf6" strokeWidth={2} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Top MITRE Techniques */}
          <Card>
            <CardHeader>
              <CardTitle>Most Used MITRE ATT&CK Techniques</CardTitle>
              <CardDescription>
                Techniques most commonly observed in recent campaigns
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={topTechniques} layout="horizontal">
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis type="number" />
                    <YAxis dataKey="name" type="category" width={200} />
                    <Tooltip />
                    <Bar dataKey="usage" fill="#3b82f6" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="actors" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Active Threat Actors</CardTitle>
              <CardDescription>
                Known threat actors and their recent activities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {threatActors.map((actor) => (
                  <motion.div
                    key={actor.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="p-4 border rounded-lg"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h3 className="font-semibold">{actor.name}</h3>
                          <Badge variant={actor.severity as any}>{actor.severity}</Badge>
                          <Badge variant="outline">{actor.country}</Badge>
                        </div>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                          Aliases: {actor.aliases.join(', ')}
                        </p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>First seen: {formatDateTime(actor.firstSeen)}</span>
                          <span>Last activity: {formatRelativeTime(actor.lastActivity)}</span>
                          <span>{actor.campaigns} campaigns</span>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-sm font-medium">{actor.techniques.length} techniques</p>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {actor.techniques.slice(0, 3).map((technique, index) => (
                            <Badge key={index} variant="outline" className="text-xs">
                              {technique}
                            </Badge>
                          ))}
                          {actor.techniques.length > 3 && (
                            <Badge variant="outline" className="text-xs">
                              +{actor.techniques.length - 3}
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="cves" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Recent CVE Intelligence</CardTitle>
              <CardDescription>
                Latest vulnerabilities and security advisories
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {cveData.map((cve) => (
                  <motion.div
                    key={cve.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="p-4 border rounded-lg"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h3 className="font-semibold">{cve.cveId}</h3>
                          <Badge 
                            variant={cve.cvssScore >= 9 ? 'critical' : 
                                   cve.cvssScore >= 7 ? 'high' : 
                                   cve.cvssScore >= 4 ? 'medium' : 'low'}
                          >
                            CVSS {cve.cvssScore}
                          </Badge>
                          {cve.trending && <Badge variant="secondary">Trending</Badge>}
                          {cve.exploitAvailable && <Badge variant="destructive">Exploit Available</Badge>}
                        </div>
                        <p className="text-sm font-medium mb-2">{cve.title}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>Published: {formatRelativeTime(cve.publishedDate)}</span>
                          <span>Affected: {cve.affectedProducts.join(', ')}</span>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="mitre" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>MITRE ATT&CK Techniques</CardTitle>
              <CardDescription>
                Active techniques observed in recent campaigns
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {mitreData.map((technique) => (
                  <motion.div
                    key={technique.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="p-4 border rounded-lg"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h3 className="font-semibold">{technique.techniqueId}</h3>
                          <Badge variant="outline">{technique.tactic}</Badge>
                          <Badge 
                            variant={technique.detectionDifficulty === 'hard' ? 'destructive' : 
                                   technique.detectionDifficulty === 'medium' ? 'secondary' : 'default'}
                          >
                            {technique.detectionDifficulty} to detect
                          </Badge>
                        </div>
                        <p className="text-sm font-medium mb-2">{technique.name}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>Platforms: {technique.platform.join(', ')}</span>
                          <span>Usage: {technique.usage}% of campaigns</span>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
