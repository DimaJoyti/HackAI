'use client'

import React, { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import {
  CpuChipIcon,
  BoltIcon,
  ExclamationTriangleIcon,
  LightBulbIcon,
  DocumentTextIcon,
  ClockIcon,
  TrendingUpIcon,
  TrendingDownIcon,
  EyeIcon,
  ShieldCheckIcon,
  BeakerIcon,
  ChartBarIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton, SecurityButton } from '@/components/ui/cyberpunk-button'
import { HolographicDisplay, ParticleSystem, NeuralNetwork } from '@/components/ui/cyberpunk-effects'
import { GlitchText } from '@/components/ui/cyberpunk-background'

// AI Threat Analysis Engine
interface AIThreatAnalysisProps {
  className?: string
}

export const AIThreatAnalysis: React.FC<AIThreatAnalysisProps> = ({ className }) => {
  const [analysisData, setAnalysisData] = useState<{
    threatLevel: number
    confidence: number
    predictions: Array<{
      threat: string
      probability: number
      impact: 'low' | 'medium' | 'high' | 'critical'
      timeframe: string
      mitigation: string
    }>
    trends: Array<{
      category: string
      direction: 'up' | 'down' | 'stable'
      change: number
    }>
  }>({
    threatLevel: 0,
    confidence: 0,
    predictions: [],
    trends: [],
  })

  useEffect(() => {
    const mockData = {
      threatLevel: 23,
      confidence: 94,
      predictions: [
        {
          threat: 'DDoS Attack Vector',
          probability: 78,
          impact: 'high' as const,
          timeframe: 'Next 24 hours',
          mitigation: 'Activate DDoS protection and scale infrastructure',
        },
        {
          threat: 'Phishing Campaign',
          probability: 65,
          impact: 'medium' as const,
          timeframe: 'Next 48 hours',
          mitigation: 'Enhance email filtering and user awareness',
        },
        {
          threat: 'Insider Threat Activity',
          probability: 34,
          impact: 'critical' as const,
          timeframe: 'Next 7 days',
          mitigation: 'Review access controls and monitor user behavior',
        },
      ],
      trends: [
        { category: 'Malware Detection', direction: 'down' as const, change: -15 },
        { category: 'Failed Logins', direction: 'up' as const, change: 23 },
        { category: 'Network Anomalies', direction: 'stable' as const, change: 2 },
        { category: 'Data Exfiltration', direction: 'down' as const, change: -8 },
      ],
    }

    setAnalysisData(mockData)

    // Simulate real-time updates
    const interval = setInterval(() => {
      setAnalysisData(prev => ({
        ...prev,
        threatLevel: Math.max(10, Math.min(90, prev.threatLevel + (Math.random() - 0.5) * 10)),
        confidence: Math.max(80, Math.min(99, prev.confidence + (Math.random() - 0.5) * 5)),
      }))
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  const getThreatColor = (level: number) => {
    if (level < 25) return 'cyber-green-neon'
    if (level < 50) return 'cyber-blue-neon'
    if (level < 75) return 'cyber-orange-neon'
    return 'security-critical'
  }

  const getImpactColor = (impact: string) => {
    switch (impact) {
      case 'low': return 'cyber-green-neon'
      case 'medium': return 'cyber-blue-neon'
      case 'high': return 'cyber-orange-neon'
      case 'critical': return 'security-critical'
      default: return 'matrix-muted'
    }
  }

  const getTrendIcon = (direction: string) => {
    switch (direction) {
      case 'up': return TrendingUpIcon
      case 'down': return TrendingDownIcon
      default: return ClockIcon
    }
  }

  const getTrendColor = (direction: string) => {
    switch (direction) {
      case 'up': return 'security-critical'
      case 'down': return 'cyber-green-neon'
      default: return 'cyber-blue-neon'
    }
  }

  const threatColor = getThreatColor(analysisData.threatLevel)

  return (
    <CyberpunkCard variant="security-critical" className={cn('relative overflow-hidden', className)}>
      <NeuralNetwork 
        nodeCount={15} 
        connectionDensity="medium" 
        animationSpeed="slow"
        color="pink"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-security-critical">
            <CpuChipIcon className="w-6 h-6" />
            <GlitchText intensity="medium">AI THREAT ANALYSIS</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="critical" size="sm">ANALYZING</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-6">
          {/* Threat Level Indicator */}
          <HolographicDisplay color="pink" intensity="high" className="p-4 text-center">
            <div className="space-y-2">
              <div className={`text-4xl font-display font-bold text-${threatColor}`}>
                {analysisData.threatLevel}%
              </div>
              <div className="text-sm font-cyber text-matrix-light uppercase tracking-wider">
                Current Threat Level
              </div>
              <div className="text-xs text-matrix-muted font-matrix">
                Confidence: {analysisData.confidence}%
              </div>
            </div>
          </HolographicDisplay>

          {/* AI Predictions */}
          <div className="space-y-3">
            <h4 className="text-sm font-cyber text-security-critical uppercase tracking-wider">
              AI Predictions
            </h4>
            {analysisData.predictions.map((prediction, index) => {
              const impactColor = getImpactColor(prediction.impact)
              
              return (
                <HolographicDisplay
                  key={index}
                  color="pink"
                  intensity="low"
                  className="p-3"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <h5 className="font-cyber font-bold text-matrix-white text-sm">
                        {prediction.threat}
                      </h5>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-matrix text-security-critical">
                          {prediction.probability}%
                        </span>
                        <span className={`text-xs font-cyber uppercase text-${impactColor}`}>
                          {prediction.impact}
                        </span>
                      </div>
                    </div>
                    
                    <div className="text-xs text-matrix-light">
                      <span className="text-matrix-muted">Timeframe:</span> {prediction.timeframe}
                    </div>
                    
                    <div className="text-xs text-matrix-light">
                      <span className="text-matrix-muted">Mitigation:</span> {prediction.mitigation}
                    </div>

                    <div className="h-1 bg-matrix-surface rounded-full overflow-hidden">
                      <div 
                        className="h-full transition-all duration-1000 rounded-full bg-security-critical"
                        style={{ width: `${prediction.probability}%` }}
                      />
                    </div>
                  </div>
                </HolographicDisplay>
              )
            })}
          </div>

          {/* Threat Trends */}
          <div className="space-y-3">
            <h4 className="text-sm font-cyber text-security-critical uppercase tracking-wider">
              Threat Trends (24h)
            </h4>
            <div className="grid grid-cols-2 gap-2">
              {analysisData.trends.map((trend, index) => {
                const TrendIcon = getTrendIcon(trend.direction)
                const trendColor = getTrendColor(trend.direction)
                
                return (
                  <HolographicDisplay
                    key={index}
                    color="pink"
                    intensity="low"
                    className="p-2"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-xs font-cyber text-matrix-white">
                          {trend.category}
                        </div>
                        <div className={`text-xs font-matrix text-${trendColor}`}>
                          {trend.direction === 'up' ? '+' : trend.direction === 'down' ? '' : '±'}{trend.change}%
                        </div>
                      </div>
                      <TrendIcon className={`w-4 h-4 text-${trendColor}`} />
                    </div>
                  </HolographicDisplay>
                )
              })}
            </div>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Smart Notifications Center
interface SmartNotificationsProps {
  className?: string
}

export const SmartNotifications: React.FC<SmartNotificationsProps> = ({ className }) => {
  const [notifications, setNotifications] = useState<Array<{
    id: string
    type: 'alert' | 'recommendation' | 'update' | 'achievement'
    priority: 'low' | 'medium' | 'high' | 'critical'
    title: string
    message: string
    timestamp: Date
    read: boolean
    actionRequired: boolean
    aiGenerated: boolean
    source: string
  }>>([])

  useEffect(() => {
    const mockNotifications = [
      {
        id: '1',
        type: 'alert' as const,
        priority: 'critical' as const,
        title: 'Anomalous Network Activity Detected',
        message: 'AI detected unusual traffic patterns from 192.168.1.100. Immediate investigation recommended.',
        timestamp: new Date(Date.now() - 5 * 60 * 1000),
        read: false,
        actionRequired: true,
        aiGenerated: true,
        source: 'Network AI Monitor',
      },
      {
        id: '2',
        type: 'recommendation' as const,
        priority: 'medium' as const,
        title: 'Security Policy Update Suggested',
        message: 'Based on recent threat patterns, consider updating firewall rules for enhanced protection.',
        timestamp: new Date(Date.now() - 15 * 60 * 1000),
        read: false,
        actionRequired: false,
        aiGenerated: true,
        source: 'Policy AI Advisor',
      },
      {
        id: '3',
        type: 'achievement' as const,
        priority: 'low' as const,
        title: 'Learning Milestone Reached',
        message: 'Congratulations! You\'ve completed 85% of the Web Security learning path.',
        timestamp: new Date(Date.now() - 30 * 60 * 1000),
        read: true,
        actionRequired: false,
        aiGenerated: false,
        source: 'Learning System',
      },
      {
        id: '4',
        type: 'update' as const,
        priority: 'high' as const,
        title: 'Threat Intelligence Update',
        message: 'New IOCs detected for ongoing APT campaign. Updating detection rules automatically.',
        timestamp: new Date(Date.now() - 45 * 60 * 1000),
        read: false,
        actionRequired: false,
        aiGenerated: true,
        source: 'Threat Intel AI',
      },
    ]

    setNotifications(mockNotifications)

    // Simulate new notifications
    const interval = setInterval(() => {
      const newNotification = {
        id: Math.random().toString(36).substring(2, 11),
        type: ['alert', 'recommendation', 'update'][Math.floor(Math.random() * 3)] as any,
        priority: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)] as any,
        title: 'AI Generated Alert',
        message: 'New security event detected and analyzed by AI systems.',
        timestamp: new Date(),
        read: false,
        actionRequired: Math.random() > 0.7,
        aiGenerated: true,
        source: 'AI Security Engine',
      }

      setNotifications(prev => [newNotification, ...prev.slice(0, 9)])
    }, 30000) // New notification every 30 seconds

    return () => clearInterval(interval)
  }, [])

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'alert': return ExclamationTriangleIcon
      case 'recommendation': return LightBulbIcon
      case 'update': return BoltIcon
      case 'achievement': return ShieldCheckIcon
      default: return DocumentTextIcon
    }
  }

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'alert': return 'security-critical'
      case 'recommendation': return 'cyber-blue-neon'
      case 'update': return 'cyber-green-neon'
      case 'achievement': return 'cyber-purple-neon'
      default: return 'cyber-orange-neon'
    }
  }

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'security-critical'
      case 'high': return 'cyber-orange-neon'
      case 'medium': return 'cyber-blue-neon'
      case 'low': return 'cyber-green-neon'
      default: return 'matrix-muted'
    }
  }

  const unreadCount = notifications.filter(n => !n.read).length

  return (
    <CyberpunkCard variant="neon-blue" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem
        particleCount={20}
        color="blue"
        speed="medium"
        size="small"
        className="opacity-20"
      />

      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-blue-neon">
            <BoltIcon className="w-6 h-6" />
            <GlitchText intensity="low">SMART NOTIFICATIONS</GlitchText>
          </CyberpunkCardTitle>
          <div className="flex items-center gap-2">
            {unreadCount > 0 && (
              <span className="px-2 py-1 text-xs font-cyber bg-security-critical/20 border border-security-critical/30 rounded text-security-critical">
                {unreadCount} new
              </span>
            )}
            <SecurityButton level="medium" size="sm">ACTIVE</SecurityButton>
          </div>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-3 max-h-80 overflow-y-auto scrollbar-cyber">
          {notifications.map((notification) => {
            const TypeIcon = getTypeIcon(notification.type)
            const typeColor = getTypeColor(notification.type)
            const priorityColor = getPriorityColor(notification.priority)

            return (
              <HolographicDisplay
                key={notification.id}
                color="blue"
                intensity={notification.read ? "low" : "medium"}
                className={`p-3 cursor-pointer hover:scale-[1.02] transition-all duration-300 ${
                  !notification.read ? 'border-l-4 border-l-cyber-blue-neon' : ''
                }`}
              >
                <div className="space-y-2">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-2">
                      <TypeIcon className={`w-4 h-4 text-${typeColor}`} />
                      <span className={`text-xs font-cyber uppercase text-${priorityColor}`}>
                        {notification.priority}
                      </span>
                      {notification.aiGenerated && (
                        <span className="text-xs font-cyber text-cyber-purple-neon">AI</span>
                      )}
                    </div>
                    <span className="text-xs text-matrix-muted font-matrix">
                      {notification.timestamp.toLocaleTimeString()}
                    </span>
                  </div>

                  <h4 className={`font-cyber font-bold text-sm ${
                    notification.read ? 'text-matrix-light' : 'text-matrix-white'
                  }`}>
                    {notification.title}
                  </h4>

                  <p className="text-xs text-matrix-light leading-relaxed">
                    {notification.message}
                  </p>

                  <div className="flex items-center justify-between pt-2 border-t border-matrix-border">
                    <span className="text-xs text-matrix-muted font-cyber">
                      {notification.source}
                    </span>
                    {notification.actionRequired && (
                      <CyberpunkButton variant="ghost-blue" size="sm">
                        Take Action
                      </CyberpunkButton>
                    )}
                  </div>
                </div>
              </HolographicDisplay>
            )
          })}
        </div>

        <div className="mt-4 pt-4 border-t border-matrix-border">
          <div className="flex gap-2">
            <CyberpunkButton variant="ghost-blue" size="sm" className="flex-1">
              Mark All Read
            </CyberpunkButton>
            <CyberpunkButton variant="ghost-green" size="sm" className="flex-1">
              View All
            </CyberpunkButton>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Automated Security Reports
interface AutomatedReportsProps {
  className?: string
}

export const AutomatedReports: React.FC<AutomatedReportsProps> = ({ className }) => {
  const [reports, setReports] = useState<Array<{
    id: string
    title: string
    type: 'daily' | 'weekly' | 'monthly' | 'incident' | 'compliance'
    status: 'generating' | 'ready' | 'sent' | 'failed'
    generatedAt: Date
    aiGenerated: boolean
    insights: number
    recommendations: number
    size: string
    recipients: string[]
  }>>([])

  useEffect(() => {
    const mockReports = [
      {
        id: '1',
        title: 'Daily Security Summary',
        type: 'daily' as const,
        status: 'ready' as const,
        generatedAt: new Date(Date.now() - 30 * 60 * 1000),
        aiGenerated: true,
        insights: 12,
        recommendations: 5,
        size: '2.3 MB',
        recipients: ['security-team@company.com', 'ciso@company.com'],
      },
      {
        id: '2',
        title: 'Weekly Threat Intelligence Report',
        type: 'weekly' as const,
        status: 'generating' as const,
        generatedAt: new Date(),
        aiGenerated: true,
        insights: 0,
        recommendations: 0,
        size: 'Generating...',
        recipients: ['threat-intel@company.com'],
      },
      {
        id: '3',
        title: 'Compliance Assessment Report',
        type: 'compliance' as const,
        status: 'sent' as const,
        generatedAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
        aiGenerated: true,
        insights: 8,
        recommendations: 3,
        size: '4.7 MB',
        recipients: ['compliance@company.com', 'audit@company.com'],
      },
      {
        id: '4',
        title: 'Incident Response Analysis',
        type: 'incident' as const,
        status: 'ready' as const,
        generatedAt: new Date(Date.now() - 45 * 60 * 1000),
        aiGenerated: true,
        insights: 15,
        recommendations: 8,
        size: '1.8 MB',
        recipients: ['incident-response@company.com'],
      },
    ]

    setReports(mockReports)
  }, [])

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'daily': return 'cyber-green-neon'
      case 'weekly': return 'cyber-blue-neon'
      case 'monthly': return 'cyber-purple-neon'
      case 'incident': return 'security-critical'
      case 'compliance': return 'cyber-orange-neon'
      default: return 'matrix-muted'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'generating': return 'cyber-orange-neon'
      case 'ready': return 'cyber-green-neon'
      case 'sent': return 'cyber-blue-neon'
      case 'failed': return 'security-critical'
      default: return 'matrix-muted'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'generating': return ClockIcon
      case 'ready': return CheckCircleIcon
      case 'sent': return DocumentTextIcon
      case 'failed': return ExclamationTriangleIcon
      default: return DocumentTextIcon
    }
  }

  return (
    <CyberpunkCard variant="neon-green" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem
        particleCount={15}
        color="green"
        speed="slow"
        size="small"
        className="opacity-20"
      />

      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-green-neon">
            <DocumentTextIcon className="w-6 h-6" />
            <GlitchText intensity="low">AUTOMATED REPORTS</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="safe" size="sm">ACTIVE</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4">
          {/* Report Generation Stats */}
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <div className="text-lg font-display font-bold text-cyber-green-neon">
                {reports.filter(r => r.status === 'ready').length}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Ready</div>
            </div>
            <div>
              <div className="text-lg font-display font-bold text-cyber-orange-neon">
                {reports.filter(r => r.status === 'generating').length}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Generating</div>
            </div>
            <div>
              <div className="text-lg font-display font-bold text-cyber-blue-neon">
                {reports.filter(r => r.status === 'sent').length}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Sent Today</div>
            </div>
          </div>

          {/* Recent Reports */}
          <div className="space-y-3 max-h-64 overflow-y-auto scrollbar-cyber">
            {reports.map((report) => {
              const typeColor = getTypeColor(report.type)
              const statusColor = getStatusColor(report.status)
              const StatusIcon = getStatusIcon(report.status)

              return (
                <HolographicDisplay
                  key={report.id}
                  color="green"
                  intensity="low"
                  className="p-3 cursor-pointer hover:scale-[1.02] transition-all duration-300"
                >
                  <div className="space-y-3">
                    <div className="flex items-start justify-between">
                      <div>
                        <h4 className="font-cyber font-bold text-matrix-white text-sm">
                          {report.title}
                        </h4>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`text-xs font-cyber uppercase text-${typeColor}`}>
                            {report.type}
                          </span>
                          {report.aiGenerated && (
                            <span className="text-xs font-cyber text-cyber-purple-neon">AI Generated</span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <StatusIcon className={`w-4 h-4 text-${statusColor}`} />
                        <span className={`text-xs font-cyber uppercase text-${statusColor}`}>
                          {report.status}
                        </span>
                      </div>
                    </div>

                    {report.status !== 'generating' && (
                      <div className="grid grid-cols-3 gap-4 text-xs">
                        <div>
                          <span className="text-matrix-muted font-cyber">Insights:</span>
                          <div className="text-cyber-green-neon font-matrix font-bold">
                            {report.insights}
                          </div>
                        </div>
                        <div>
                          <span className="text-matrix-muted font-cyber">Recommendations:</span>
                          <div className="text-cyber-blue-neon font-matrix font-bold">
                            {report.recommendations}
                          </div>
                        </div>
                        <div>
                          <span className="text-matrix-muted font-cyber">Size:</span>
                          <div className="text-matrix-white font-matrix">
                            {report.size}
                          </div>
                        </div>
                      </div>
                    )}

                    <div className="flex items-center justify-between pt-2 border-t border-matrix-border">
                      <span className="text-xs text-matrix-muted font-matrix">
                        {report.generatedAt.toLocaleString()}
                      </span>
                      <div className="flex gap-2">
                        {report.status === 'ready' && (
                          <>
                            <CyberpunkButton variant="ghost-green" size="sm">
                              Download
                            </CyberpunkButton>
                            <CyberpunkButton variant="ghost-blue" size="sm">
                              Send
                            </CyberpunkButton>
                          </>
                        )}
                        {report.status === 'sent' && (
                          <CyberpunkButton variant="ghost-blue" size="sm">
                            View
                          </CyberpunkButton>
                        )}
                      </div>
                    </div>
                  </div>
                </HolographicDisplay>
              )
            })}
          </div>

          {/* Quick Actions */}
          <div className="grid grid-cols-2 gap-3">
            <CyberpunkButton variant="ghost-green" size="sm" className="w-full">
              <BeakerIcon className="w-4 h-4 mr-2" />
              Generate Report
            </CyberpunkButton>
            <CyberpunkButton variant="ghost-blue" size="sm" className="w-full">
              <ChartBarIcon className="w-4 h-4 mr-2" />
              Schedule Reports
            </CyberpunkButton>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}
