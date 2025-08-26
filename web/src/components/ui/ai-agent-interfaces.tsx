'use client'

import React, { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from './cyberpunk-card'
import { CyberpunkButton } from './cyberpunk-button'
import { HolographicDisplay, ParticleSystem, NeuralNetwork, DataStream } from './cyberpunk-effects'
import { 
  EyeIcon, 
  BoltIcon, 
  ChartBarIcon, 
  CpuChipIcon, 
  ServerIcon,
  PlayIcon,
  PauseIcon,
  StopIcon,
  Cog6ToothIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline'

// Base AI Agent Interface
interface BaseAgentProps {
  className?: string
  agentId: string
  name: string
  status: 'online' | 'offline' | 'busy' | 'error'
  performance: number
  currentTask?: string
  onStart?: () => void
  onPause?: () => void
  onStop?: () => void
  onConfigure?: () => void
}

// Research Agent Interface
export const ResearchAgentInterface: React.FC<BaseAgentProps> = ({
  className,
  agentId,
  name,
  status,
  performance,
  currentTask,
  onStart,
  onPause,
  onStop,
  onConfigure
}) => {
  const [scanProgress, setScanProgress] = useState(0)
  const [dataPoints, setDataPoints] = useState(0)

  useEffect(() => {
    if (status === 'busy') {
      const interval = setInterval(() => {
        setScanProgress(prev => (prev + 1) % 100)
        setDataPoints(prev => prev + Math.floor(Math.random() * 5))
      }, 100)
      return () => clearInterval(interval)
    }
  }, [status])

  return (
    <CyberpunkCard variant="neon-blue" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={40} 
        color="blue" 
        speed="fast" 
        size="small"
        className="opacity-30"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-blue-neon">
            <EyeIcon className="w-6 h-6" />
            RESEARCH AGENT
          </CyberpunkCardTitle>
          <div className={cn(
            'px-2 py-1 rounded text-xs font-cyber uppercase',
            status === 'online' ? 'bg-cyber-green-neon/20 text-cyber-green-neon' :
            status === 'busy' ? 'bg-cyber-orange-neon/20 text-cyber-orange-neon animate-neon-pulse' :
            status === 'error' ? 'bg-security-critical/20 text-security-critical' :
            'bg-matrix-muted/20 text-matrix-muted'
          )}>
            {status}
          </div>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4">
          {/* Current Task */}
          <HolographicDisplay color="blue" intensity="medium" className="p-3">
            <div className="text-sm font-cyber text-matrix-white mb-1">Current Analysis:</div>
            <div className="text-xs text-matrix-light font-matrix">
              {currentTask || 'Market data analysis - BTCUSDT patterns'}
            </div>
          </HolographicDisplay>

          {/* Scan Progress */}
          {status === 'busy' && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-matrix-light">
                <span>Data Scanning</span>
                <span>{scanProgress}%</span>
              </div>
              <div className="h-1 bg-matrix-surface rounded-full overflow-hidden">
                <div 
                  className="h-full bg-cyber-blue-neon shadow-neon-blue transition-all duration-100"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
            </div>
          )}

          {/* Metrics */}
          <div className="grid grid-cols-2 gap-4">
            <div className="text-center">
              <div className="text-lg font-display font-bold text-cyber-blue-neon">
                {dataPoints.toLocaleString()}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Data Points</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-display font-bold text-cyber-blue-neon">
                {performance}%
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Accuracy</div>
            </div>
          </div>

          {/* Controls */}
          <div className="flex gap-2">
            <CyberpunkButton 
              variant="filled-blue" 
              size="sm" 
              onClick={onStart}
              disabled={status === 'busy'}
              className="flex-1"
            >
              <PlayIcon className="w-4 h-4 mr-1" />
              Analyze
            </CyberpunkButton>
            <CyberpunkButton 
              variant="ghost-blue" 
              size="sm" 
              onClick={onConfigure}
            >
              <Cog6ToothIcon className="w-4 h-4" />
            </CyberpunkButton>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Creator Agent Interface
export const CreatorAgentInterface: React.FC<BaseAgentProps> = ({
  className,
  agentId,
  name,
  status,
  performance,
  currentTask,
  onStart,
  onPause,
  onStop,
  onConfigure
}) => {
  const [generationProgress, setGenerationProgress] = useState(0)
  const [contentGenerated, setContentGenerated] = useState(0)

  useEffect(() => {
    if (status === 'busy') {
      const interval = setInterval(() => {
        setGenerationProgress(prev => (prev + 2) % 100)
        if (Math.random() > 0.8) {
          setContentGenerated(prev => prev + 1)
        }
      }, 150)
      return () => clearInterval(interval)
    }
  }, [status])

  return (
    <CyberpunkCard variant="neon-orange" className={cn('relative overflow-hidden', className)}>
      <DataStream 
        streamCount={6} 
        direction="diagonal" 
        color="orange" 
        speed="medium"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-orange-neon">
            <BoltIcon className="w-6 h-6" />
            CREATOR AGENT
          </CyberpunkCardTitle>
          <div className={cn(
            'px-2 py-1 rounded text-xs font-cyber uppercase',
            status === 'online' ? 'bg-cyber-green-neon/20 text-cyber-green-neon' :
            status === 'busy' ? 'bg-cyber-orange-neon/20 text-cyber-orange-neon animate-neon-pulse' :
            status === 'error' ? 'bg-security-critical/20 text-security-critical' :
            'bg-matrix-muted/20 text-matrix-muted'
          )}>
            {status}
          </div>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4">
          {/* Current Task */}
          <HolographicDisplay color="orange" intensity="medium" className="p-3">
            <div className="text-sm font-cyber text-matrix-white mb-1">Creating:</div>
            <div className="text-xs text-matrix-light font-matrix">
              {currentTask || 'Trading strategy documentation'}
            </div>
          </HolographicDisplay>

          {/* Generation Progress */}
          {status === 'busy' && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-matrix-light">
                <span>Content Generation</span>
                <span>{generationProgress}%</span>
              </div>
              <div className="h-1 bg-matrix-surface rounded-full overflow-hidden">
                <div 
                  className="h-full bg-cyber-orange-neon shadow-neon-orange transition-all duration-150"
                  style={{ width: `${generationProgress}%` }}
                />
              </div>
            </div>
          )}

          {/* Metrics */}
          <div className="grid grid-cols-2 gap-4">
            <div className="text-center">
              <div className="text-lg font-display font-bold text-cyber-orange-neon">
                {contentGenerated}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Items Created</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-display font-bold text-cyber-orange-neon">
                {performance}%
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Quality Score</div>
            </div>
          </div>

          {/* Controls */}
          <div className="flex gap-2">
            <CyberpunkButton 
              variant="filled-orange" 
              size="sm" 
              onClick={onStart}
              disabled={status === 'busy'}
              className="flex-1"
            >
              <BoltIcon className="w-4 h-4 mr-1" />
              Generate
            </CyberpunkButton>
            <CyberpunkButton 
              variant="ghost-orange" 
              size="sm" 
              onClick={onConfigure}
            >
              <Cog6ToothIcon className="w-4 h-4" />
            </CyberpunkButton>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Analyst Agent Interface
export const AnalystAgentInterface: React.FC<BaseAgentProps> = ({
  className,
  agentId,
  name,
  status,
  performance,
  currentTask,
  onStart,
  onPause,
  onStop,
  onConfigure
}) => {
  const [analysisDepth, setAnalysisDepth] = useState(0)
  const [patternsFound, setPatternsFound] = useState(0)

  useEffect(() => {
    if (status === 'busy') {
      const interval = setInterval(() => {
        setAnalysisDepth(prev => Math.min(prev + 1, 100))
        if (Math.random() > 0.9) {
          setPatternsFound(prev => prev + 1)
        }
      }, 200)
      return () => clearInterval(interval)
    }
  }, [status])

  return (
    <CyberpunkCard variant="neon-purple" className={cn('relative overflow-hidden', className)}>
      <NeuralNetwork 
        nodeCount={25} 
        connectionDensity={0.5} 
        color="purple" 
        animationSpeed="fast"
        className="opacity-25"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-purple-neon">
            <ChartBarIcon className="w-6 h-6" />
            ANALYST AGENT
          </CyberpunkCardTitle>
          <div className={cn(
            'px-2 py-1 rounded text-xs font-cyber uppercase',
            status === 'online' ? 'bg-cyber-green-neon/20 text-cyber-green-neon' :
            status === 'busy' ? 'bg-cyber-purple-neon/20 text-cyber-purple-neon animate-neon-pulse' :
            status === 'error' ? 'bg-security-critical/20 text-security-critical' :
            'bg-matrix-muted/20 text-matrix-muted'
          )}>
            {status}
          </div>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4">
          {/* Current Task */}
          <HolographicDisplay color="purple" intensity="medium" className="p-3">
            <div className="text-sm font-cyber text-matrix-white mb-1">Analyzing:</div>
            <div className="text-xs text-matrix-light font-matrix">
              {currentTask || 'Risk assessment and pattern detection'}
            </div>
          </HolographicDisplay>

          {/* Analysis Progress */}
          {status === 'busy' && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-matrix-light">
                <span>Analysis Depth</span>
                <span>{analysisDepth}%</span>
              </div>
              <div className="h-1 bg-matrix-surface rounded-full overflow-hidden">
                <div 
                  className="h-full bg-cyber-purple-neon shadow-neon-purple transition-all duration-200"
                  style={{ width: `${analysisDepth}%` }}
                />
              </div>
            </div>
          )}

          {/* Metrics */}
          <div className="grid grid-cols-2 gap-4">
            <div className="text-center">
              <div className="text-lg font-display font-bold text-cyber-purple-neon">
                {patternsFound}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Patterns Found</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-display font-bold text-cyber-purple-neon">
                {performance}%
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Confidence</div>
            </div>
          </div>

          {/* Controls */}
          <div className="flex gap-2">
            <CyberpunkButton
              variant="filled-purple"
              size="sm"
              onClick={onStart}
              disabled={status === 'busy'}
              className="flex-1"
            >
              <ChartBarIcon className="w-4 h-4 mr-1" />
              Analyze
            </CyberpunkButton>
            <CyberpunkButton
              variant="ghost-purple"
              size="sm"
              onClick={onConfigure}
            >
              <Cog6ToothIcon className="w-4 h-4" />
            </CyberpunkButton>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Operator Agent Interface
export const OperatorAgentInterface: React.FC<BaseAgentProps> = ({
  className,
  agentId,
  name,
  status,
  performance,
  currentTask,
  onStart,
  onPause,
  onStop,
  onConfigure
}) => {
  const [operationsCount, setOperationsCount] = useState(0)
  const [successRate, setSuccessRate] = useState(98.5)

  useEffect(() => {
    if (status === 'busy') {
      const interval = setInterval(() => {
        if (Math.random() > 0.7) {
          setOperationsCount(prev => prev + 1)
          setSuccessRate(prev => Math.min(prev + (Math.random() - 0.5) * 0.1, 100))
        }
      }, 500)
      return () => clearInterval(interval)
    }
  }, [status])

  return (
    <CyberpunkCard variant="neon-green" className={cn('relative overflow-hidden', className)}>
      <DataStream
        streamCount={8}
        direction="vertical"
        color="green"
        speed="fast"
        className="opacity-20"
      />

      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-green-neon">
            <CpuChipIcon className="w-6 h-6" />
            OPERATOR AGENT
          </CyberpunkCardTitle>
          <div className={cn(
            'px-2 py-1 rounded text-xs font-cyber uppercase',
            status === 'online' ? 'bg-cyber-green-neon/20 text-cyber-green-neon' :
            status === 'busy' ? 'bg-cyber-green-neon/20 text-cyber-green-neon animate-neon-pulse' :
            status === 'error' ? 'bg-security-critical/20 text-security-critical' :
            'bg-matrix-muted/20 text-matrix-muted'
          )}>
            {status}
          </div>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4">
          {/* Current Task */}
          <HolographicDisplay color="green" intensity="medium" className="p-3">
            <div className="text-sm font-cyber text-matrix-white mb-1">Executing:</div>
            <div className="text-xs text-matrix-light font-matrix">
              {currentTask || 'Portfolio rebalancing and risk management'}
            </div>
          </HolographicDisplay>

          {/* Metrics */}
          <div className="grid grid-cols-2 gap-4">
            <div className="text-center">
              <div className="text-lg font-display font-bold text-cyber-green-neon">
                {operationsCount}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Operations</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-display font-bold text-cyber-green-neon">
                {successRate.toFixed(1)}%
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Success Rate</div>
            </div>
          </div>

          {/* Controls */}
          <div className="flex gap-2">
            <CyberpunkButton
              variant="filled-green"
              size="sm"
              onClick={onStart}
              disabled={status === 'busy'}
              className="flex-1"
            >
              <PlayIcon className="w-4 h-4 mr-1" />
              Execute
            </CyberpunkButton>
            <CyberpunkButton
              variant="ghost-green"
              size="sm"
              onClick={onPause}
              disabled={status !== 'busy'}
            >
              <PauseIcon className="w-4 h-4" />
            </CyberpunkButton>
            <CyberpunkButton
              variant="ghost-green"
              size="sm"
              onClick={onConfigure}
            >
              <Cog6ToothIcon className="w-4 h-4" />
            </CyberpunkButton>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Strategist Agent Interface
export const StrategistAgentInterface: React.FC<BaseAgentProps> = ({
  className,
  agentId,
  name,
  status,
  performance,
  currentTask,
  onStart,
  onPause,
  onStop,
  onConfigure
}) => {
  const [decisionsCount, setDecisionsCount] = useState(0)
  const [coordinationLevel, setCoordinationLevel] = useState(85)

  useEffect(() => {
    if (status === 'busy') {
      const interval = setInterval(() => {
        if (Math.random() > 0.8) {
          setDecisionsCount(prev => prev + 1)
          setCoordinationLevel(prev => Math.min(prev + (Math.random() - 0.5) * 2, 100))
        }
      }, 1000)
      return () => clearInterval(interval)
    }
  }, [status])

  return (
    <CyberpunkCard variant="neon-pink" className={cn('relative overflow-hidden', className)}>
      <NeuralNetwork
        nodeCount={30}
        connectionDensity={0.6}
        color="pink"
        animationSpeed="slow"
        className="opacity-25"
      />

      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-pink-neon">
            <ServerIcon className="w-6 h-6" />
            STRATEGIST AGENT
          </CyberpunkCardTitle>
          <div className={cn(
            'px-2 py-1 rounded text-xs font-cyber uppercase',
            status === 'online' ? 'bg-cyber-green-neon/20 text-cyber-green-neon' :
            status === 'busy' ? 'bg-cyber-pink-neon/20 text-cyber-pink-neon animate-neon-pulse' :
            status === 'error' ? 'bg-security-critical/20 text-security-critical' :
            'bg-matrix-muted/20 text-matrix-muted'
          )}>
            {status}
          </div>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4">
          {/* Current Task */}
          <HolographicDisplay color="pink" intensity="medium" className="p-3">
            <div className="text-sm font-cyber text-matrix-white mb-1">Coordinating:</div>
            <div className="text-xs text-matrix-light font-matrix">
              {currentTask || 'Multi-agent workflow optimization'}
            </div>
          </HolographicDisplay>

          {/* Metrics */}
          <div className="grid grid-cols-2 gap-4">
            <div className="text-center">
              <div className="text-lg font-display font-bold text-cyber-pink-neon">
                {decisionsCount}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Decisions</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-display font-bold text-cyber-pink-neon">
                {coordinationLevel}%
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Coordination</div>
            </div>
          </div>

          {/* Controls */}
          <div className="flex gap-2">
            <CyberpunkButton
              variant="filled-pink"
              size="sm"
              onClick={onStart}
              disabled={status === 'busy'}
              className="flex-1"
            >
              <ServerIcon className="w-4 h-4 mr-1" />
              Coordinate
            </CyberpunkButton>
            <CyberpunkButton
              variant="ghost-pink"
              size="sm"
              onClick={onConfigure}
            >
              <Cog6ToothIcon className="w-4 h-4" />
            </CyberpunkButton>
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}
