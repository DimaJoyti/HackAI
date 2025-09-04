'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  GlobeAltIcon,
  ShieldExclamationIcon,
  BugAntIcon,
  UserGroupIcon,
  DocumentTextIcon,
  ArrowTrendingUpIcon,
  MapIcon,
  ClockIcon,
  EyeIcon,
  BoltIcon,
  ExclamationTriangleIcon,
  FireIcon,
  CpuChipIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { RealTimeStreamingChart } from '@/components/charts/real-time-streaming-chart'
import { useWebSocketJSON } from '@/hooks/use-websocket'
import { formatDateTime, formatRelativeTime } from '@/lib/utils'
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, LineChart, Line, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts'

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
  confidence: number
  attribution: string
  targets: string[]
}

interface ThreatIntelligence {
  ioc: {
    ips: number
    domains: number
    hashes: number
    urls: number
  }
  cve: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    exploitable: number
  }
  mitre: {
    techniques: number
    tactics: number
    activeCampaigns: number
  }
  feeds: {
    active: number
    lastUpdate: Date
    totalIndicators: number
  }
}

interface LiveThreat {
  id: string
  type: 'malware' | 'phishing' | 'apt' | 'ransomware' | 'botnet'
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence: number
  firstSeen: Date
  lastSeen: Date
  indicators: string[]
  countries: string[]
  targets: string[]
  status: 'active' | 'monitoring' | 'contained'
}

interface GlobalThreatMetrics {
  timestamp: string
  globalThreatLevel: number
  activeThreats: number
  newIOCs: number
  blockedConnections: number
  honeypotHits: number
  malwareSamples: number
  phishingAttempts: number
}

export function EnhancedThreatIntelligenceDashboard() {
  const [threatActors, setThreatActors] = useState<ThreatActor[]>([])
  const [threatIntel, setThreatIntel] = useState<ThreatIntelligence>({
    ioc: { ips: 0, domains: 0, hashes: 0, urls: 0 },
    cve: { total: 0, critical: 0, high: 0, medium: 0, low: 0, exploitable: 0 },
    mitre: { techniques: 0, tactics: 0, activeCampaigns: 0 },
    feeds: { active: 0, lastUpdate: new Date(), totalIndicators: 0 }
  })
  const [liveThreats, setLiveThreats] = useState<LiveThreat[]>([])
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h')
  const [isConnected, setIsConnected] = useState(false)
  const [globalMetrics, setGlobalMetrics] = useState<GlobalThreatMetrics[]>([])

  // WebSocket connection for real-time threat intelligence
  const { lastJsonMessage, sendJsonMessage, connectionStatus } = useWebSocketJSON<any>(
    'ws://localhost:8080/ws/threat-intelligence',
    {
      onOpen: () => {
        setIsConnected(true)
        sendJsonMessage({ 
          type: 'subscribe', 
          streams: ['threat_actors', 'ioc_updates', 'cve_feed', 'mitre_updates', 'live_threats'] 
        })
      },
      onClose: () => setIsConnected(false),
      shouldReconnect: () => true,
    }
  )

  // Initialize with mock data
  useEffect(() => {
    initializeMockData()
  }, [])

  const initializeMockData = () => {
    // Mock threat actors
    const actors: ThreatActor[] = [
      {
        id: '1',
        name: 'APT29 (Cozy Bear)',
        aliases: ['The Dukes', 'CozyDuke', 'Dark Halo'],
        country: 'Russia',
        firstSeen: new Date('2014-01-01'),
        lastActivity: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
        techniques: ['T1566.001', 'T1055', 'T1083', 'T1005', 'T1053.005'],
        campaigns: 15,
        severity: 'critical',
        confidence: 95,
        attribution: 'State-sponsored',
        targets: ['Government', 'Healthcare', 'Technology']
      },
      {
        id: '2',
        name: 'Lazarus Group',
        aliases: ['HIDDEN COBRA', 'Guardians of Peace', 'Zinc'],
        country: 'North Korea',
        firstSeen: new Date('2009-01-01'),
        lastActivity: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
        techniques: ['T1566.002', 'T1204.002', 'T1059.003', 'T1027', 'T1082'],
        campaigns: 23,
        severity: 'critical',
        confidence: 98,
        attribution: 'State-sponsored',
        targets: ['Financial', 'Cryptocurrency', 'Entertainment']
      },
      {
        id: '3',
        name: 'FIN7',
        aliases: ['Carbanak Group', 'Navigator Group'],
        country: 'Unknown',
        firstSeen: new Date('2013-01-01'),
        lastActivity: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
        techniques: ['T1566.001', 'T1204.002', 'T1055.012', 'T1190', 'T1078'],
        campaigns: 18,
        severity: 'high',
        confidence: 87,
        attribution: 'Financially motivated',
        targets: ['Retail', 'Hospitality', 'Payment processors']
      }
    ]

    // Mock threat intelligence
    const intel: ThreatIntelligence = {
      ioc: {
        ips: 12547,
        domains: 8923,
        hashes: 45231,
        urls: 23456
      },
      cve: {
        total: 2847,
        critical: 23,
        high: 156,
        medium: 892,
        low: 1776,
        exploitable: 89
      },
      mitre: {
        techniques: 188,
        tactics: 14,
        activeCampaigns: 42
      },
      feeds: {
        active: 15,
        lastUpdate: new Date(),
        totalIndicators: 90157
      }
    }

    // Mock live threats
    const threats: LiveThreat[] = [
      {
        id: '1',
        type: 'ransomware',
        name: 'BlackCat (ALPHV)',
        severity: 'critical',
        confidence: 92,
        firstSeen: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
        lastSeen: new Date(Date.now() - 2 * 60 * 60 * 1000),
        indicators: ['192.168.1.45', 'malware.exe', 'evil.domain.com'],
        countries: ['Russia', 'Belarus'],
        targets: ['Healthcare', 'Manufacturing'],
        status: 'active'
      },
      {
        id: '2',
        type: 'phishing',
        name: 'Office 365 Credential Harvesting',
        severity: 'high',
        confidence: 85,
        firstSeen: new Date(Date.now() - 24 * 60 * 60 * 1000),
        lastSeen: new Date(Date.now() - 30 * 60 * 1000),
        indicators: ['phishing-site.com', '203.0.113.45', 'login.html'],
        countries: ['China', 'Vietnam'],
        targets: ['Corporate', 'Government'],
        status: 'monitoring'
      }
    ]

    setThreatActors(actors)
    setThreatIntel(intel)
    setLiveThreats(threats)
  }

  // Handle WebSocket messages
  useEffect(() => {
    if (lastJsonMessage) {
      const message = lastJsonMessage

      switch (message.type) {
        case 'threat_actor_update':
          // Update threat actors
          break
        case 'ioc_update':
          // Update IOCs
          break
        case 'cve_update':
          // Update CVE data
          break
        case 'live_threat':
          // Add new live threat
          break
      }
    }
  }, [lastJsonMessage])

  // Generate mock real-time data
  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date()
      const newMetric: GlobalThreatMetrics = {
        timestamp: now.toISOString(),
        globalThreatLevel: 40 + Math.floor(Math.random() * 40),
        activeThreats: 5 + Math.floor(Math.random() * 15),
        newIOCs: Math.floor(Math.random() * 50),
        blockedConnections: 100 + Math.floor(Math.random() * 900),
        honeypotHits: Math.floor(Math.random() * 20),
        malwareSamples: Math.floor(Math.random() * 10),
        phishingAttempts: Math.floor(Math.random() * 30),
      }

      setGlobalMetrics(prev => [...prev.slice(-49), newMetric])
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  const threatTypeData = [
    { name: 'APT', value: 35, color: '#ef4444', count: 15 },
    { name: 'Ransomware', value: 28, color: '#f97316', count: 12 },
    { name: 'Phishing', value: 20, color: '#eab308', count: 8 },
    { name: 'Malware', value: 17, color: '#8b5cf6', count: 7 },
  ]

  const severityDistribution = [
    { name: 'Critical', value: threatIntel.cve.critical, color: '#ef4444' },
    { name: 'High', value: threatIntel.cve.high, color: '#f97316' },
    { name: 'Medium', value: threatIntel.cve.medium, color: '#eab308' },
    { name: 'Low', value: threatIntel.cve.low, color: '#22c55e' },
  ]

  const radarData = [
    { subject: 'Initial Access', A: 85, B: 65 },
    { subject: 'Execution', A: 72, B: 58 },
    { subject: 'Persistence', A: 91, B: 73 },
    { subject: 'Privilege Escalation', A: 67, B: 45 },
    { subject: 'Defense Evasion', A: 88, B: 71 },
    { subject: 'Credential Access', A: 79, B: 62 },
  ]

  return (
    <div className="min-h-screen bg-matrix-void p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-display font-bold text-cyber-blue-neon">
            Threat Intelligence Command Center
          </h1>
          <p className="text-matrix-text mt-1">
            Advanced threat monitoring with real-time intelligence feeds and MITRE ATT&CK mapping
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full animate-neon-pulse ${
              isConnected ? 'bg-cyber-green-neon' : 'bg-security-critical'
            }`} />
            <span className={`text-sm font-cyber ${
              isConnected ? 'text-cyber-green-neon' : 'text-security-critical'
            }`}>
              {isConnected ? 'INTEL FEEDS ACTIVE' : 'OFFLINE MODE'}
            </span>
          </div>
          
          <div className="flex items-center gap-2 text-sm text-matrix-text">
            <ClockIcon className="w-4 h-4" />
            <span>Last update: {formatRelativeTime(threatIntel.feeds.lastUpdate)}</span>
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
        <CyberpunkCard variant="security-critical" size="sm">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <ExclamationTriangleIcon className="w-4 h-4" />
                <span className="text-xs font-medium">Global Threat Level</span>
              </div>
              <div className="text-2xl font-bold font-cyber">
                {globalMetrics.length > 0 ? globalMetrics[globalMetrics.length - 1]?.globalThreatLevel || 0 : 75}
              </div>
              <Badge variant="destructive" className="text-xs mt-1">ELEVATED</Badge>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-orange" size="sm">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <FireIcon className="w-4 h-4" />
                <span className="text-xs font-medium">Active Threats</span>
              </div>
              <div className="text-2xl font-bold font-cyber">{liveThreats.filter(t => t.status === 'active').length}</div>
              <Badge variant="secondary" className="text-xs mt-1">
                {liveThreats.length} Total
              </Badge>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-blue" size="sm">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <DocumentTextIcon className="w-4 h-4" />
                <span className="text-xs font-medium">IOC Database</span>
              </div>
              <div className="text-2xl font-bold font-cyber">
                {(threatIntel.ioc.ips + threatIntel.ioc.domains + threatIntel.ioc.hashes + threatIntel.ioc.urls).toLocaleString()}
              </div>
              <Badge variant="outline" className="text-xs mt-1">Indicators</Badge>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-purple" size="sm">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <BugAntIcon className="w-4 h-4" />
                <span className="text-xs font-medium">CVE Database</span>
              </div>
              <div className="text-2xl font-bold font-cyber">{threatIntel.cve.total.toLocaleString()}</div>
              <Badge variant="destructive" className="text-xs mt-1">
                {threatIntel.cve.exploitable} Exploitable
              </Badge>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-green" size="sm">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <UserGroupIcon className="w-4 h-4" />
                <span className="text-xs font-medium">Threat Actors</span>
              </div>
              <div className="text-2xl font-bold font-cyber">{threatActors.length}</div>
              <Badge variant="destructive" className="text-xs mt-1">
                {threatActors.filter(a => a.severity === 'critical').length} Critical
              </Badge>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="hologram" size="sm">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <CpuChipIcon className="w-4 h-4" />
                <span className="text-xs font-medium">Intel Feeds</span>
              </div>
              <div className="text-2xl font-bold font-cyber">{threatIntel.feeds.active}</div>
              <Badge variant="default" className="text-xs mt-1">Active</Badge>
            </div>
          </div>
        </CyberpunkCard>
      </div>

      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList className="grid w-full grid-cols-5 bg-matrix-surface border border-matrix-border">
          <TabsTrigger value="overview" className="text-cyber-blue-neon">Overview</TabsTrigger>
          <TabsTrigger value="live-threats" className="text-cyber-blue-neon">Live Threats</TabsTrigger>
          <TabsTrigger value="actors" className="text-cyber-blue-neon">Threat Actors</TabsTrigger>
          <TabsTrigger value="intelligence" className="text-cyber-blue-neon">Intelligence</TabsTrigger>
          <TabsTrigger value="mitre" className="text-cyber-blue-neon">MITRE ATT&CK</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {/* Real-time Streaming Chart */}
          <CyberpunkCard variant="glass-blue" size="lg">
            <div className="mb-6">
              <h3 className="text-lg font-semibold text-cyber-blue-neon mb-2">
                Global Threat Intelligence Stream
              </h3>
              <p className="text-sm text-matrix-text">
                Real-time threat metrics and intelligence indicators
              </p>
            </div>
            <RealTimeStreamingChart
              streamUrl="ws://localhost:8080/ws/threat-intelligence"
              chartType="area"
              height={350}
              selectedMetrics={['threatLevel', 'activeThreats', 'blockedAttacks']}
            />
          </CyberpunkCard>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Threat Type Distribution */}
            <CyberpunkCard variant="neon-orange" size="lg">
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-cyber-orange-neon">
                  Active Threat Types
                </h3>
                <p className="text-sm text-matrix-text">Current threat landscape</p>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={threatTypeData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={90}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {threatTypeData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: '#0a0a0f',
                        border: '1px solid #00ffff',
                        borderRadius: '8px',
                        color: '#ffffff'
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="grid grid-cols-2 gap-2 mt-4">
                {threatTypeData.map((item, index) => (
                  <div key={index} className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <div 
                        className="w-3 h-3 rounded-full" 
                        style={{ backgroundColor: item.color }}
                      />
                      <span>{item.name}</span>
                    </div>
                    <Badge variant="outline" className="text-xs">{item.count}</Badge>
                  </div>
                ))}
              </div>
            </CyberpunkCard>

            {/* CVE Severity Distribution */}
            <CyberpunkCard variant="security-high" size="lg">
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-security-high">
                  CVE Severity Breakdown
                </h3>
                <p className="text-sm text-matrix-text">Vulnerability distribution</p>
              </div>
              <div className="space-y-4">
                {severityDistribution.map((severity) => (
                  <div key={severity.name} className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-matrix-text">{severity.name}</span>
                      <span className="font-cyber" style={{ color: severity.color }}>
                        {severity.value}
                      </span>
                    </div>
                    <Progress 
                      value={(severity.value / threatIntel.cve.total) * 100} 
                      className="h-2"
                      style={{ backgroundColor: `${severity.color}20` }}
                      indicatorClassName={`bg-[${severity.color}]`}
                    />
                  </div>
                ))}
              </div>
            </CyberpunkCard>

            {/* MITRE ATT&CK Radar */}
            <CyberpunkCard variant="neon-purple" size="lg">
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-cyber-purple-neon">
                  MITRE ATT&CK Coverage
                </h3>
                <p className="text-sm text-matrix-text">Technique detection coverage</p>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart data={radarData} margin={{ top: 20, right: 30, bottom: 20, left: 30 }}>
                    <PolarGrid stroke="#1a1a2e" />
                    <PolarAngleAxis dataKey="subject" tick={{ fontSize: 10, fill: '#64748b' }} />
                    <PolarRadiusAxis 
                      angle={90} 
                      domain={[0, 100]} 
                      tick={{ fontSize: 10, fill: '#64748b' }} 
                    />
                    <Radar
                      name="Current"
                      dataKey="A"
                      stroke="#8b5cf6"
                      fill="#8b5cf6"
                      fillOpacity={0.3}
                      strokeWidth={2}
                    />
                    <Radar
                      name="Target"
                      dataKey="B"
                      stroke="#00ffff"
                      fill="#00ffff"
                      fillOpacity={0.1}
                      strokeWidth={2}
                    />
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: '#0a0a0f',
                        border: '1px solid #8b5cf6',
                        borderRadius: '8px',
                        color: '#ffffff'
                      }}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </CyberpunkCard>
          </div>
        </TabsContent>

        <TabsContent value="live-threats" className="space-y-6">
          <CyberpunkCard variant="security-critical" size="lg">
            <div className="mb-6">
              <h3 className="text-lg font-semibold text-security-critical">
                Active Threat Campaigns
              </h3>
              <p className="text-sm text-matrix-text">
                Real-time monitoring of active threat campaigns
              </p>
            </div>
            
            <div className="space-y-4">
              <AnimatePresence>
                {liveThreats.map((threat) => (
                  <motion.div
                    key={threat.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    className="p-4 border border-matrix-border rounded-lg bg-matrix-surface/50 hover:border-cyber-blue-neon/30 transition-colors"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h4 className="font-semibold text-matrix-white">{threat.name}</h4>
                          <Badge 
                            variant={threat.severity as any}
                            className="text-xs"
                          >
                            {threat.severity.toUpperCase()}
                          </Badge>
                          <Badge 
                            variant={threat.status === 'active' ? 'destructive' : 'secondary'}
                            className="text-xs"
                          >
                            {threat.status.toUpperCase()}
                          </Badge>
                          <Badge variant="outline" className="text-xs">
                            {threat.confidence}% confidence
                          </Badge>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-matrix-text mb-2">
                          <span>Type: {threat.type}</span>
                          <span>First seen: {formatRelativeTime(threat.firstSeen)}</span>
                          <span>Last seen: {formatRelativeTime(threat.lastSeen)}</span>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <div className="text-xs">
                            <span className="text-matrix-text">Indicators: </span>
                            {threat.indicators.slice(0, 3).map((indicator, i) => (
                              <Badge key={i} variant="outline" className="text-xs mx-1">
                                {indicator}
                              </Badge>
                            ))}
                            {threat.indicators.length > 3 && (
                              <Badge variant="outline" className="text-xs">
                                +{threat.indicators.length - 3}
                              </Badge>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </CyberpunkCard>
        </TabsContent>

        <TabsContent value="actors" className="space-y-6">
          <CyberpunkCard variant="neon-green" size="lg">
            <div className="mb-6">
              <h3 className="text-lg font-semibold text-cyber-green-neon">
                Threat Actor Intelligence
              </h3>
              <p className="text-sm text-matrix-text">
                Known threat actors and attribution analysis
              </p>
            </div>
            
            <div className="space-y-4">
              <AnimatePresence>
                {threatActors.map((actor) => (
                  <motion.div
                    key={actor.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="p-4 border border-matrix-border rounded-lg bg-matrix-surface/50 hover:border-cyber-green-neon/30 transition-colors"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h4 className="font-semibold text-matrix-white">{actor.name}</h4>
                          <Badge variant={actor.severity as any}>{actor.severity.toUpperCase()}</Badge>
                          <Badge variant="outline">{actor.country}</Badge>
                          <Badge variant="secondary">{actor.confidence}% confidence</Badge>
                        </div>
                        <p className="text-sm text-matrix-text mb-2">
                          <strong>Aliases:</strong> {actor.aliases.join(', ')}
                        </p>
                        <p className="text-sm text-matrix-text mb-2">
                          <strong>Attribution:</strong> {actor.attribution}
                        </p>
                        <div className="flex items-center gap-4 text-xs text-matrix-text mb-3">
                          <span>First seen: {formatDateTime(actor.firstSeen)}</span>
                          <span>Last activity: {formatRelativeTime(actor.lastActivity)}</span>
                          <span>{actor.campaigns} campaigns</span>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <div className="text-xs">
                            <span className="text-matrix-text">Techniques: </span>
                            {actor.techniques.slice(0, 5).map((technique, i) => (
                              <Badge key={i} variant="outline" className="text-xs mx-1">
                                {technique}
                              </Badge>
                            ))}
                            {actor.techniques.length > 5 && (
                              <Badge variant="outline" className="text-xs">
                                +{actor.techniques.length - 5}
                              </Badge>
                            )}
                          </div>
                        </div>
                        <div className="flex flex-wrap gap-2 mt-2">
                          <div className="text-xs">
                            <span className="text-matrix-text">Targets: </span>
                            {actor.targets.map((target, i) => (
                              <Badge key={i} variant="secondary" className="text-xs mx-1">
                                {target}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </CyberpunkCard>
        </TabsContent>

        {/* Additional tabs for Intelligence and MITRE would go here */}
      </Tabs>
    </div>
  )
}