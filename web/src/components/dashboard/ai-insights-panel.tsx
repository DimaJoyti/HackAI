'use client'

import React, { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import {
  CpuChipIcon,
  LightBulbIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  BoltIcon,
  EyeIcon,
  ShieldCheckIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton, SecurityButton } from '@/components/ui/cyberpunk-button'
import { HolographicDisplay, ParticleSystem } from '@/components/ui/cyberpunk-effects'
import { GlitchText } from '@/components/ui/cyberpunk-background'

// AI Recommendations Component
interface AIRecommendationsProps {
  className?: string
}

export const AIRecommendations: React.FC<AIRecommendationsProps> = ({ className }) => {
  const [recommendations, setRecommendations] = useState<Array<{
    id: string
    type: 'security' | 'performance' | 'learning' | 'optimization'
    title: string
    description: string
    priority: 'low' | 'medium' | 'high' | 'critical'
    confidence: number
    estimatedImpact: string
    actionRequired: boolean
  }>>([])

  useEffect(() => {
    const mockRecommendations = [
      {
        id: '1',
        type: 'security' as const,
        title: 'Update Firewall Rules',
        description: 'AI detected unusual traffic patterns. Consider updating firewall rules to block suspicious IPs.',
        priority: 'high' as const,
        confidence: 94,
        estimatedImpact: 'Reduce threat exposure by 23%',
        actionRequired: true,
      },
      {
        id: '2',
        type: 'performance' as const,
        title: 'Optimize Scan Scheduling',
        description: 'Machine learning analysis suggests optimal scan times to minimize system impact.',
        priority: 'medium' as const,
        confidence: 87,
        estimatedImpact: 'Improve performance by 15%',
        actionRequired: false,
      },
      {
        id: '3',
        type: 'learning' as const,
        title: 'Recommended Training Module',
        description: 'Based on your activity, focus on advanced penetration testing techniques.',
        priority: 'low' as const,
        confidence: 78,
        estimatedImpact: 'Enhance skills by 20%',
        actionRequired: false,
      },
      {
        id: '4',
        type: 'optimization' as const,
        title: 'Resource Allocation',
        description: 'AI suggests reallocating compute resources for better threat detection coverage.',
        priority: 'medium' as const,
        confidence: 91,
        estimatedImpact: 'Increase detection rate by 12%',
        actionRequired: true,
      },
    ]

    setRecommendations(mockRecommendations)
  }, [])

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'security': return ShieldCheckIcon
      case 'performance': return BoltIcon
      case 'learning': return LightBulbIcon
      case 'optimization': return CpuChipIcon
      default: return EyeIcon
    }
  }

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'security': return 'pink'
      case 'performance': return 'blue'
      case 'learning': return 'green'
      case 'optimization': return 'purple'
      default: return 'orange'
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

  return (
    <CyberpunkCard variant="neon-blue" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={30} 
        color="blue" 
        speed="medium" 
        size="small"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-blue-neon">
            <CpuChipIcon className="w-6 h-6" />
            <GlitchText intensity="low">AI RECOMMENDATIONS</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="medium" size="sm">ANALYZING</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4 max-h-96 overflow-y-auto scrollbar-cyber">
          {recommendations.map((rec) => {
            const IconComponent = getTypeIcon(rec.type)
            const typeColor = getTypeColor(rec.type)
            const priorityColor = getPriorityColor(rec.priority)
            
            return (
              <HolographicDisplay
                key={rec.id}
                color={typeColor}
                intensity="medium"
                className="p-4 group hover:scale-[1.02] transition-all duration-300"
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg border border-cyber-${typeColor}-neon/30 bg-cyber-${typeColor}-neon/10`}>
                        <IconComponent className={`w-5 h-5 text-cyber-${typeColor}-neon`} />
                      </div>
                      <div>
                        <h4 className="font-cyber font-bold text-matrix-white">
                          {rec.title}
                        </h4>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`text-xs font-cyber uppercase text-${priorityColor}`}>
                            {rec.priority}
                          </span>
                          <span className="text-xs text-matrix-muted font-matrix">
                            {rec.confidence}% confidence
                          </span>
                        </div>
                      </div>
                    </div>
                    {rec.actionRequired && (
                      <SecurityButton level="high" size="sm">ACTION REQUIRED</SecurityButton>
                    )}
                  </div>

                  <p className="text-sm text-matrix-light leading-relaxed">
                    {rec.description}
                  </p>

                  <div className="flex items-center justify-between pt-2 border-t border-matrix-border">
                    <span className="text-xs text-matrix-muted font-cyber">
                      Impact: <span className={`text-cyber-${typeColor}-neon`}>{rec.estimatedImpact}</span>
                    </span>
                    <CyberpunkButton
                      variant={`ghost-${typeColor}` as any}
                      size="sm"
                      className="group-hover:animate-neon-pulse"
                    >
                      View Details
                    </CyberpunkButton>
                  </div>
                </div>
              </HolographicDisplay>
            )
          })}
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Predictive Analytics Component
interface PredictiveAnalyticsProps {
  className?: string
}

export const PredictiveAnalytics: React.FC<PredictiveAnalyticsProps> = ({ className }) => {
  const [predictions, setPredictions] = useState<Array<{
    id: string
    category: string
    prediction: string
    probability: number
    timeframe: string
    riskLevel: 'low' | 'medium' | 'high' | 'critical'
    confidence: number
  }>>([])

  useEffect(() => {
    const mockPredictions = [
      {
        id: '1',
        category: 'Threat Intelligence',
        prediction: 'Potential DDoS attack targeting web services',
        probability: 73,
        timeframe: 'Next 24 hours',
        riskLevel: 'high' as const,
        confidence: 89,
      },
      {
        id: '2',
        category: 'System Performance',
        prediction: 'Database performance degradation expected',
        probability: 45,
        timeframe: 'Next 7 days',
        riskLevel: 'medium' as const,
        confidence: 76,
      },
      {
        id: '3',
        category: 'Security Breach',
        prediction: 'Increased phishing attempts likely',
        probability: 82,
        timeframe: 'Next 48 hours',
        riskLevel: 'high' as const,
        confidence: 94,
      },
      {
        id: '4',
        category: 'Resource Usage',
        prediction: 'Storage capacity will reach 90%',
        probability: 67,
        timeframe: 'Next 14 days',
        riskLevel: 'medium' as const,
        confidence: 85,
      },
    ]

    setPredictions(mockPredictions)
  }, [])

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'security-critical'
      case 'high': return 'cyber-orange-neon'
      case 'medium': return 'cyber-blue-neon'
      case 'low': return 'cyber-green-neon'
      default: return 'matrix-muted'
    }
  }

  return (
    <CyberpunkCard variant="neon-purple" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={25} 
        color="purple" 
        speed="slow" 
        size="small"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-purple-neon">
          <EyeIcon className="w-6 h-6" />
          <GlitchText intensity="low">PREDICTIVE ANALYTICS</GlitchText>
        </CyberpunkCardTitle>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4">
          {predictions.map((prediction) => {
            const riskColor = getRiskColor(prediction.riskLevel)
            
            return (
              <HolographicDisplay
                key={prediction.id}
                color="purple"
                intensity="low"
                className="p-4"
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="font-cyber font-bold text-matrix-white text-sm">
                        {prediction.category}
                      </h4>
                      <p className="text-sm text-matrix-light mt-1">
                        {prediction.prediction}
                      </p>
                    </div>
                    <span className={`text-xs font-cyber uppercase text-${riskColor}`}>
                      {prediction.riskLevel}
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-4 text-xs">
                    <div>
                      <span className="text-matrix-muted font-cyber">Probability:</span>
                      <div className={`text-cyber-purple-neon font-matrix font-bold`}>
                        {prediction.probability}%
                      </div>
                    </div>
                    <div>
                      <span className="text-matrix-muted font-cyber">Timeframe:</span>
                      <div className="text-matrix-white font-matrix">
                        {prediction.timeframe}
                      </div>
                    </div>
                    <div>
                      <span className="text-matrix-muted font-cyber">Confidence:</span>
                      <div className="text-cyber-green-neon font-matrix font-bold">
                        {prediction.confidence}%
                      </div>
                    </div>
                  </div>

                  {/* Probability Bar */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-matrix-muted">Likelihood</span>
                      <span className="text-cyber-purple-neon">{prediction.probability}%</span>
                    </div>
                    <div className="h-1 bg-matrix-surface rounded-full overflow-hidden">
                      <div 
                        className="h-full transition-all duration-1000 rounded-full bg-cyber-purple-neon shadow-neon-purple"
                        style={{ width: `${prediction.probability}%` }}
                      />
                    </div>
                  </div>
                </div>
              </HolographicDisplay>
            )
          })}
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}
