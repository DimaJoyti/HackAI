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
  ChartBarIcon,
  AcademicCapIcon,
} from '@heroicons/react/24/outline'
import { useAuth } from '@/hooks/use-auth'
import { formatDateTime } from '@/lib/utils'

// Import cyberpunk components
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton, SecurityButton } from '@/components/ui/cyberpunk-button'
import { ThreatMonitor, AIAgentStatus, SecurityMetrics } from '@/components/ui/cyberpunk-dashboard'
import { CyberpunkLineChart, CyberpunkRadarChart, CyberpunkProgressRing, CyberpunkMetricCard } from '@/components/ui/cyberpunk-charts'
import { HolographicDisplay, ParticleSystem } from '@/components/ui/cyberpunk-effects'
import { CyberpunkBackground, MatrixRain, GlitchText } from '@/components/ui/cyberpunk-background'

// Import new dashboard components
import { SystemStatus, LiveActivityMonitor } from '@/components/dashboard/real-time-overview'
import { NetworkTrafficMonitor, ConnectedDevices } from '@/components/dashboard/network-monitor'
import { AIRecommendations, PredictiveAnalytics } from '@/components/dashboard/ai-insights-panel'
import { ThreatTimeline, PerformanceMetrics, LearningProgress, VulnerabilityDistribution } from '@/components/dashboard/advanced-analytics'
import { QuickActions, IncidentManagement, ComplianceMonitoring } from '@/components/dashboard/security-command-center'
import { LearningPath, AchievementSystem, SkillAssessment } from '@/components/dashboard/education-hub'
import { AIThreatAnalysis, SmartNotifications, AutomatedReports } from '@/components/dashboard/ai-powered-insights'

// Enhanced Mock Data - in real app, this would come from API
const mockStats = {
  totalScans: 156,
  activeScans: 3,
  vulnerabilitiesFound: 42,
  criticalVulns: 5,
  highVulns: 12,
  mediumVulns: 18,
  lowVulns: 7,
  systemHealth: 94,
  aiModelsActive: 8,
  learningProgress: 67,
  threatLevel: 23,
}

const mockThreats = [
  {
    id: '1',
    type: 'critical' as const,
    source: 'External Scanner',
    description: 'Potential SQL injection attempt detected',
    timestamp: new Date(Date.now() - 15 * 60 * 1000),
    status: 'active' as const,
  },
  {
    id: '2',
    type: 'high' as const,
    source: 'Network Monitor',
    description: 'Unusual traffic pattern from 192.168.1.100',
    timestamp: new Date(Date.now() - 30 * 60 * 1000),
    status: 'investigating' as const,
  },
  {
    id: '3',
    type: 'medium' as const,
    source: 'AI Firewall',
    description: 'Suspicious API request pattern detected',
    timestamp: new Date(Date.now() - 45 * 60 * 1000),
    status: 'mitigated' as const,
  },
]

const mockAIAgents = [
  {
    id: '1',
    name: 'Threat Hunter',
    type: 'research' as const,
    status: 'online' as const,
    performance: 94,
    lastActivity: new Date(Date.now() - 5 * 60 * 1000),
    currentTask: 'Analyzing network traffic patterns',
  },
  {
    id: '2',
    name: 'Vulnerability Scanner',
    type: 'analyst' as const,
    status: 'busy' as const,
    performance: 87,
    lastActivity: new Date(Date.now() - 2 * 60 * 1000),
    currentTask: 'Scanning web application endpoints',
  },
  {
    id: '3',
    name: 'Response Coordinator',
    type: 'operator' as const,
    status: 'online' as const,
    performance: 98,
    lastActivity: new Date(Date.now() - 1 * 60 * 1000),
    currentTask: 'Monitoring incident response queue',
  },
]

const mockSecurityMetrics = {
  threatLevel: 23,
  systemIntegrity: 94,
  networkSecurity: 88,
  dataProtection: 92,
  accessControl: 97,
}

const mockThreatData = [
  { x: 1, y: 15 },
  { x: 2, y: 23 },
  { x: 3, y: 18 },
  { x: 4, y: 31 },
  { x: 5, y: 25 },
  { x: 6, y: 19 },
  { x: 7, y: 28 },
  { x: 8, y: 22 },
  { x: 9, y: 16 },
  { x: 10, y: 20 },
]

const mockSkillsData = [
  { label: 'Web Security', value: 85, max: 100 },
  { label: 'Network Analysis', value: 72, max: 100 },
  { label: 'Incident Response', value: 68, max: 100 },
  { label: 'Threat Intelligence', value: 79, max: 100 },
  { label: 'Penetration Testing', value: 63, max: 100 },
  { label: 'Forensics', value: 71, max: 100 },
]

export default function DashboardPage() {
  const { user } = useAuth()
  const [currentTime, setCurrentTime] = useState(new Date())
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date())
    }, 1000) // Update every second for real-time feel

    // Simulate loading
    setTimeout(() => setIsLoading(false), 1500)

    return () => clearInterval(timer)
  }, [])



  if (isLoading) {
    return (
      <CyberpunkBackground variant="particles" intensity="low" color="blue" className="min-h-screen flex items-center justify-center">
        <div className="text-center space-y-4">
          <div className="w-16 h-16 border-4 border-cyber-blue-neon border-t-transparent rounded-full animate-spin mx-auto"></div>
          <GlitchText intensity="medium">
            <span className="text-cyber-blue-neon font-cyber text-xl">INITIALIZING DASHBOARD</span>
          </GlitchText>
          <div className="text-matrix-light font-matrix text-sm">Loading security modules...</div>
        </div>
      </CyberpunkBackground>
    )
  }

  return (
    <CyberpunkBackground variant="matrix" intensity="low" color="blue" className="min-h-screen">
      <MatrixRain intensity="low" color="#00ff41" className="opacity-10" />

      <div className="p-6 space-y-8 relative z-10">
        {/* Enhanced Header */}
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <h1 className="text-4xl font-display font-bold text-matrix-white">
              <GlitchText intensity="low">
                Welcome back, <span className="text-cyber-blue-neon">{user?.firstName}</span>!
              </GlitchText>
            </h1>
            <p className="text-matrix-light font-cyber">
              Your cybersecurity command center is online and monitoring threats.
            </p>
          </div>
          <div className="text-right space-y-2">
            <div className="text-cyber-green-neon font-matrix text-lg">
              {formatDateTime(currentTime)}
            </div>
            <div className="flex items-center gap-2">
              <SecurityButton level="safe" size="sm">SECURE</SecurityButton>
              <SecurityButton level="medium" size="sm">AI ACTIVE</SecurityButton>
            </div>
          </div>
        </div>

        {/* Enhanced Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Link href="/dashboard/scans/vulnerability">
            <CyberpunkCard variant="security-critical" size="lg" interactive scanLine cornerAccents className="group hover:scale-105 transition-all duration-300">
              <CyberpunkCardHeader accent>
                <div className="flex items-center justify-between">
                  <ShieldCheckIcon className="h-8 w-8 text-security-critical group-hover:animate-neon-pulse" />
                  <SecurityButton level="critical" size="sm">SCAN</SecurityButton>
                </div>
                <CyberpunkCardTitle className="text-security-critical mt-3">
                  <GlitchText intensity="low">Vulnerability Scan</GlitchText>
                </CyberpunkCardTitle>
              </CyberpunkCardHeader>
              <CyberpunkCardContent>
                <p className="text-matrix-light text-sm">
                  Deploy AI-powered scanners to detect security vulnerabilities in web applications and APIs
                </p>
              </CyberpunkCardContent>
            </CyberpunkCard>
          </Link>

          <Link href="/dashboard/scans/network">
            <CyberpunkCard variant="neon-green" size="lg" interactive scanLine cornerAccents className="group hover:scale-105 transition-all duration-300">
              <CyberpunkCardHeader accent>
                <div className="flex items-center justify-between">
                  <CpuChipIcon className="h-8 w-8 text-cyber-green-neon group-hover:animate-neon-pulse" />
                  <SecurityButton level="safe" size="sm">READY</SecurityButton>
                </div>
                <CyberpunkCardTitle className="text-cyber-green-neon mt-3">
                  <GlitchText intensity="low">Network Scan</GlitchText>
                </CyberpunkCardTitle>
              </CyberpunkCardHeader>
              <CyberpunkCardContent>
                <p className="text-matrix-light text-sm">
                  Discover network hosts, services, and analyze potential security vulnerabilities
                </p>
              </CyberpunkCardContent>
            </CyberpunkCard>
          </Link>

          <Link href="/dashboard/analytics">
            <CyberpunkCard variant="neon-purple" size="lg" interactive scanLine cornerAccents className="group hover:scale-105 transition-all duration-300">
              <CyberpunkCardHeader accent>
                <div className="flex items-center justify-between">
                  <ChartBarIcon className="h-8 w-8 text-cyber-purple-neon group-hover:animate-neon-pulse" />
                  <SecurityButton level="medium" size="sm">ACTIVE</SecurityButton>
                </div>
                <CyberpunkCardTitle className="text-cyber-purple-neon mt-3">
                  <GlitchText intensity="low">Threat Analytics</GlitchText>
                </CyberpunkCardTitle>
              </CyberpunkCardHeader>
              <CyberpunkCardContent>
                <p className="text-matrix-light text-sm">
                  Advanced threat intelligence and predictive security analytics
                </p>
              </CyberpunkCardContent>
            </CyberpunkCard>
          </Link>

          <Link href="/dashboard/learning">
            <CyberpunkCard variant="neon-orange" size="lg" interactive scanLine cornerAccents className="group hover:scale-105 transition-all duration-300">
              <CyberpunkCardHeader accent>
                <div className="flex items-center justify-between">
                  <AcademicCapIcon className="h-8 w-8 text-cyber-orange-neon group-hover:animate-neon-pulse" />
                  <SecurityButton level="high" size="sm">LEARN</SecurityButton>
                </div>
                <CyberpunkCardTitle className="text-cyber-orange-neon mt-3">
                  <GlitchText intensity="low">Cyber Training</GlitchText>
                </CyberpunkCardTitle>
              </CyberpunkCardHeader>
              <CyberpunkCardContent>
                <p className="text-matrix-light text-sm">
                  Interactive cybersecurity education modules and skill assessments
                </p>
              </CyberpunkCardContent>
            </CyberpunkCard>
          </Link>
        </div>

        {/* Enhanced Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
          <CyberpunkMetricCard
            title="Total Scans"
            value={mockStats.totalScans}
            change={12}
            trend="up"
            color="blue"
            icon={<ShieldCheckIcon className="w-5 h-5" />}
            className="hover:scale-105 transition-all duration-300"
          />

          <CyberpunkMetricCard
            title="Active Scans"
            value={mockStats.activeScans}
            color="orange"
            icon={<ClockIcon className="w-5 h-5" />}
            className="hover:scale-105 transition-all duration-300"
          />

          <CyberpunkMetricCard
            title="Vulnerabilities"
            value={mockStats.vulnerabilitiesFound}
            change={-8}
            trend="down"
            color="pink"
            icon={<ExclamationTriangleIcon className="w-5 h-5" />}
            className="hover:scale-105 transition-all duration-300"
          />

          <CyberpunkMetricCard
            title="System Health"
            value={`${mockStats.systemHealth}%`}
            change={2}
            trend="up"
            color="green"
            icon={<CheckCircleIcon className="w-5 h-5" />}
            className="hover:scale-105 transition-all duration-300"
          />

          <CyberpunkMetricCard
            title="AI Models"
            value={mockStats.aiModelsActive}
            color="purple"
            icon={<CpuChipIcon className="w-5 h-5" />}
            className="hover:scale-105 transition-all duration-300"
          />

          <CyberpunkMetricCard
            title="Learning Progress"
            value={`${mockStats.learningProgress}%`}
            change={15}
            trend="up"
            color="blue"
            icon={<AcademicCapIcon className="w-5 h-5" />}
            className="hover:scale-105 transition-all duration-300"
          />
        </div>

        {/* Security Command Center Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Quick Actions Command Center */}
          <div className="lg:col-span-1">
            <QuickActions className="h-full" />
          </div>

          {/* Incident Management */}
          <div className="lg:col-span-1">
            <IncidentManagement className="h-full" />
          </div>

          {/* Compliance Monitoring */}
          <div className="lg:col-span-1">
            <ComplianceMonitoring className="h-full" />
          </div>
        </div>

        {/* Enhanced Main Dashboard Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Threat Monitor */}
          <div className="lg:col-span-1">
            <ThreatMonitor threats={mockThreats} className="h-full" />
          </div>

          {/* Security Metrics */}
          <div className="lg:col-span-1">
            <SecurityMetrics metrics={mockSecurityMetrics} className="h-full" />
          </div>

          {/* AI Agent Status */}
          <div className="lg:col-span-1">
            <AIAgentStatus agents={mockAIAgents} className="h-full" />
          </div>
        </div>

        {/* Analytics and Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Threat Trends Chart */}
          <CyberpunkLineChart
            title="THREAT ACTIVITY TRENDS"
            data={mockThreatData}
            color="pink"
            height={250}
            animated
            className="hover:scale-[1.02] transition-all duration-300"
          />

          {/* Skills Radar Chart */}
          <CyberpunkRadarChart
            title="CYBERSECURITY SKILLS"
            data={mockSkillsData}
            color="green"
            size={250}
            className="hover:scale-[1.02] transition-all duration-300"
          />
        </div>

        {/* Progress Rings Section */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <div className="text-center space-y-4">
            <CyberpunkProgressRing
              value={mockStats.systemHealth}
              color="green"
              size={120}
              label="System Health"
              animated
            />
          </div>

          <div className="text-center space-y-4">
            <CyberpunkProgressRing
              value={100 - mockStats.threatLevel}
              color="blue"
              size={120}
              label="Security Level"
              animated
            />
          </div>

          <div className="text-center space-y-4">
            <CyberpunkProgressRing
              value={mockStats.learningProgress}
              color="purple"
              size={120}
              label="Learning Progress"
              animated
            />
          </div>

          <div className="text-center space-y-4">
            <CyberpunkProgressRing
              value={85}
              color="orange"
              size={120}
              label="AI Efficiency"
              animated
            />
          </div>
        </div>

        {/* Real-time Monitoring Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* System Status */}
          <SystemStatus className="hover:scale-[1.02] transition-all duration-300" />

          {/* Live Activity Monitor */}
          <LiveActivityMonitor className="hover:scale-[1.02] transition-all duration-300" />
        </div>

        {/* Network Monitoring Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Network Traffic Monitor */}
          <NetworkTrafficMonitor className="hover:scale-[1.02] transition-all duration-300" />

          {/* Connected Devices */}
          <ConnectedDevices className="hover:scale-[1.02] transition-all duration-300" />
        </div>

        {/* AI Insights Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* AI Recommendations */}
          <AIRecommendations className="hover:scale-[1.02] transition-all duration-300" />

          {/* Predictive Analytics */}
          <PredictiveAnalytics className="hover:scale-[1.02] transition-all duration-300" />
        </div>

        {/* Advanced Analytics Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Threat Timeline */}
          <ThreatTimeline className="hover:scale-[1.02] transition-all duration-300" />

          {/* Performance Metrics */}
          <PerformanceMetrics className="hover:scale-[1.02] transition-all duration-300" />
        </div>

        {/* Learning & Vulnerability Analytics */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Learning Progress */}
          <LearningProgress className="hover:scale-[1.02] transition-all duration-300" />

          {/* Vulnerability Distribution */}
          <VulnerabilityDistribution className="hover:scale-[1.02] transition-all duration-300" />
        </div>

        {/* Educational Progress Hub */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Learning Paths */}
          <div className="lg:col-span-1">
            <LearningPath className="h-full hover:scale-[1.02] transition-all duration-300" />
          </div>

          {/* Achievement System */}
          <div className="lg:col-span-1">
            <AchievementSystem className="h-full hover:scale-[1.02] transition-all duration-300" />
          </div>

          {/* Skill Assessment */}
          <div className="lg:col-span-1">
            <SkillAssessment className="h-full hover:scale-[1.02] transition-all duration-300" />
          </div>
        </div>

        {/* AI-Powered Insights Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* AI Threat Analysis */}
          <div className="lg:col-span-1">
            <AIThreatAnalysis className="h-full hover:scale-[1.02] transition-all duration-300" />
          </div>

          {/* Smart Notifications */}
          <div className="lg:col-span-1">
            <SmartNotifications className="h-full hover:scale-[1.02] transition-all duration-300" />
          </div>

          {/* Automated Reports */}
          <div className="lg:col-span-1">
            <AutomatedReports className="h-full hover:scale-[1.02] transition-all duration-300" />
          </div>
        </div>

        {/* Enhanced Learning Section */}
        <CyberpunkCard variant="neon-blue" size="xl" interactive scanLine cornerAccents className="relative overflow-hidden">
          <ParticleSystem
            particleCount={25}
            color="blue"
            speed="medium"
            size="small"
            className="opacity-20"
          />

          <CyberpunkCardHeader accent>
            <div className="flex items-center justify-between">
              <CyberpunkCardTitle className="text-cyber-blue-neon text-2xl">
                <GlitchText intensity="medium">CONTINUE LEARNING</GlitchText>
              </CyberpunkCardTitle>
              <SecurityButton level="medium" size="sm">ACTIVE</SecurityButton>
            </div>
            <p className="text-matrix-light font-cyber mt-2">
              Enhance your cybersecurity skills with AI-powered educational modules
            </p>
          </CyberpunkCardHeader>

          <CyberpunkCardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <HolographicDisplay color="blue" intensity="medium" className="p-6 group hover:scale-105 transition-all duration-300">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <ShieldCheckIcon className="h-8 w-8 text-cyber-blue-neon group-hover:animate-neon-pulse" />
                    <span className="text-xs font-cyber text-cyber-blue-neon">85% COMPLETE</span>
                  </div>
                  <h4 className="font-cyber font-bold text-matrix-white text-lg">
                    Web Application Security
                  </h4>
                  <p className="text-sm text-matrix-light">
                    Master common web vulnerabilities and prevention techniques with hands-on labs.
                  </p>
                  <Link href="/dashboard/learning/web-security">
                    <CyberpunkButton variant="ghost-blue" size="sm" className="w-full group-hover:animate-neon-pulse">
                      <PlayIcon className="h-4 w-4 mr-2" />
                      Continue Module
                    </CyberpunkButton>
                  </Link>
                </div>
              </HolographicDisplay>

              <HolographicDisplay color="green" intensity="medium" className="p-6 group hover:scale-105 transition-all duration-300">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <CpuChipIcon className="h-8 w-8 text-cyber-green-neon group-hover:animate-neon-pulse" />
                    <span className="text-xs font-cyber text-cyber-green-neon">72% COMPLETE</span>
                  </div>
                  <h4 className="font-cyber font-bold text-matrix-white text-lg">
                    Network Security
                  </h4>
                  <p className="text-sm text-matrix-light">
                    Understand network protocols, monitoring, and advanced security practices.
                  </p>
                  <Link href="/dashboard/learning/network-security">
                    <CyberpunkButton variant="ghost-green" size="sm" className="w-full group-hover:animate-neon-pulse">
                      <PlayIcon className="h-4 w-4 mr-2" />
                      Continue Module
                    </CyberpunkButton>
                  </Link>
                </div>
              </HolographicDisplay>

              <HolographicDisplay color="orange" intensity="medium" className="p-6 group hover:scale-105 transition-all duration-300">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <ExclamationTriangleIcon className="h-8 w-8 text-cyber-orange-neon group-hover:animate-neon-pulse" />
                    <span className="text-xs font-cyber text-cyber-orange-neon">NEW MODULE</span>
                  </div>
                  <h4 className="font-cyber font-bold text-matrix-white text-lg">
                    Incident Response
                  </h4>
                  <p className="text-sm text-matrix-light">
                    Learn to respond to and manage security incidents with AI assistance.
                  </p>
                  <Link href="/dashboard/learning/incident-response">
                    <CyberpunkButton variant="ghost-orange" size="sm" className="w-full group-hover:animate-neon-pulse">
                      <PlayIcon className="h-4 w-4 mr-2" />
                      Start Module
                    </CyberpunkButton>
                  </Link>
                </div>
              </HolographicDisplay>
            </div>
          </CyberpunkCardContent>
        </CyberpunkCard>
      </div>
    </CyberpunkBackground>
  )
}
