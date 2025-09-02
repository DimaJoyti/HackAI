'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  CpuChipIcon,
  CommandLineIcon,
  PlayIcon,
  StopIcon,
  ArrowDownTrayIcon,
  TrashIcon,
  Cog6ToothIcon,
  ChartBarIcon,
  ClockIcon,
  ServerIcon,
  BoltIcon,
  EyeIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { formatRelativeTime } from '@/lib/utils'

interface AIModel {
  id: string
  name: string
  provider: 'ollama' | 'openai' | 'anthropic' | 'local'
  type: 'chat' | 'code' | 'embedding' | 'vision' | 'security'
  status: 'running' | 'stopped' | 'downloading' | 'error' | 'updating'
  version: string
  size: number // in GB
  description: string
  capabilities: string[]
  performance: {
    tokensPerSecond: number
    averageLatency: number
    memoryUsage: number
    cpuUsage: number
  }
  usage: {
    totalRequests: number
    successRate: number
    lastUsed: Date
  }
  config: {
    temperature: number
    maxTokens: number
    contextLength: number
  }
}

const mockModels: AIModel[] = [
  {
    id: 'llama2',
    name: 'Llama 2 7B',
    provider: 'ollama',
    type: 'chat',
    status: 'running',
    version: '7b-chat',
    size: 3.8,
    description: 'General-purpose conversational AI model optimized for chat applications',
    capabilities: ['text-generation', 'conversation', 'reasoning', 'summarization'],
    performance: {
      tokensPerSecond: 45,
      averageLatency: 120,
      memoryUsage: 4.2,
      cpuUsage: 35
    },
    usage: {
      totalRequests: 1247,
      successRate: 98.5,
      lastUsed: new Date(Date.now() - 5 * 60 * 1000)
    },
    config: {
      temperature: 0.7,
      maxTokens: 2048,
      contextLength: 4096
    }
  },
  {
    id: 'codellama',
    name: 'Code Llama 7B',
    provider: 'ollama',
    type: 'code',
    status: 'running',
    version: '7b-instruct',
    size: 3.8,
    description: 'Specialized code generation and analysis model for programming tasks',
    capabilities: ['code-generation', 'code-analysis', 'debugging', 'documentation'],
    performance: {
      tokensPerSecond: 38,
      averageLatency: 150,
      memoryUsage: 4.1,
      cpuUsage: 42
    },
    usage: {
      totalRequests: 892,
      successRate: 97.2,
      lastUsed: new Date(Date.now() - 12 * 60 * 1000)
    },
    config: {
      temperature: 0.1,
      maxTokens: 4096,
      contextLength: 8192
    }
  },
  {
    id: 'mistral',
    name: 'Mistral 7B',
    provider: 'ollama',
    type: 'chat',
    status: 'stopped',
    version: '7b-instruct',
    size: 4.1,
    description: 'High-performance instruction-following model for creative tasks',
    capabilities: ['creative-writing', 'analysis', 'reasoning', 'multilingual'],
    performance: {
      tokensPerSecond: 52,
      averageLatency: 95,
      memoryUsage: 0,
      cpuUsage: 0
    },
    usage: {
      totalRequests: 634,
      successRate: 99.1,
      lastUsed: new Date(Date.now() - 2 * 60 * 60 * 1000)
    },
    config: {
      temperature: 0.9,
      maxTokens: 2048,
      contextLength: 4096
    }
  },
  {
    id: 'nomic-embed',
    name: 'Nomic Embed Text',
    provider: 'ollama',
    type: 'embedding',
    status: 'running',
    version: 'v1.5',
    size: 0.27,
    description: 'High-quality text embeddings for semantic search and similarity',
    capabilities: ['text-embedding', 'semantic-search', 'similarity', 'clustering'],
    performance: {
      tokensPerSecond: 1200,
      averageLatency: 25,
      memoryUsage: 0.8,
      cpuUsage: 15
    },
    usage: {
      totalRequests: 3421,
      successRate: 99.8,
      lastUsed: new Date(Date.now() - 1 * 60 * 1000)
    },
    config: {
      temperature: 0,
      maxTokens: 512,
      contextLength: 2048
    }
  }
]

export default function AIModelsPage() {
  const [models, setModels] = useState<AIModel[]>(mockModels)
  const [filter, setFilter] = useState<'all' | 'running' | 'stopped'>('all')
  const [selectedModel, setSelectedModel] = useState<AIModel | null>(null)

  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      setModels(prev => prev.map(model => ({
        ...model,
        performance: {
          ...model.performance,
          tokensPerSecond: model.status === 'running' 
            ? Math.max(10, model.performance.tokensPerSecond + (Math.random() - 0.5) * 10)
            : 0,
          averageLatency: model.status === 'running'
            ? Math.max(50, model.performance.averageLatency + (Math.random() - 0.5) * 20)
            : 0,
          cpuUsage: model.status === 'running'
            ? Math.max(5, Math.min(80, model.performance.cpuUsage + (Math.random() - 0.5) * 10))
            : 0
        }
      })))
    }, 3000)

    return () => clearInterval(interval)
  }, [])

  const filteredModels = models.filter(model => {
    if (filter === 'all') return true
    return model.status === filter
  })

  const runningModels = models.filter(m => m.status === 'running').length
  const totalModels = models.length
  const totalMemoryUsage = models.reduce((sum, m) => sum + m.performance.memoryUsage, 0)

  const getStatusColor = (status: AIModel['status']) => {
    switch (status) {
      case 'running':
        return 'cyber-green-neon'
      case 'stopped':
        return 'matrix-text'
      case 'downloading':
        return 'cyber-blue-neon'
      case 'error':
        return 'security-critical'
      case 'updating':
        return 'cyber-orange-neon'
      default:
        return 'matrix-text'
    }
  }

  const getTypeIcon = (type: AIModel['type']) => {
    switch (type) {
      case 'chat':
        return CommandLineIcon
      case 'code':
        return CpuChipIcon
      case 'embedding':
        return ChartBarIcon
      case 'vision':
        return EyeIcon
      case 'security':
        return ServerIcon
      default:
        return CpuChipIcon
    }
  }

  const handleModelAction = (modelId: string, action: 'start' | 'stop' | 'restart' | 'delete') => {
    setModels(prev => prev.map(model => {
      if (model.id === modelId) {
        switch (action) {
          case 'start':
            return { ...model, status: 'running' as const }
          case 'stop':
            return { ...model, status: 'stopped' as const }
          case 'restart':
            return { ...model, status: 'running' as const }
          case 'delete':
            return model // Handle deletion separately
          default:
            return model
        }
      }
      return model
    }))

    if (action === 'delete') {
      setModels(prev => prev.filter(model => model.id !== modelId))
    }
  }

  return (
    <div className="min-h-screen bg-matrix-void p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-display font-bold text-cyber-blue-neon">
            AI Models Management
          </h1>
          <p className="text-matrix-text mt-1">
            Manage and monitor local AI models powered by OLLAMA
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-cyber-green-neon rounded-full animate-neon-pulse" />
            <span className="text-sm text-cyber-green-neon font-cyber">
              {runningModels}/{totalModels} ACTIVE
            </span>
          </div>
          
          <CyberpunkButton variant="neon-blue" size="sm">
            <ArrowDownTrayIcon className="w-4 h-4" />
            Pull Model
          </CyberpunkButton>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <CyberpunkCard variant="neon-green" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-green-neon/20 rounded-lg">
              <PlayIcon className="w-5 h-5 text-cyber-green-neon" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-cyber-green-neon">
                {runningModels}
              </div>
              <div className="text-sm text-matrix-text">Active Models</div>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-blue" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-blue-neon/20 rounded-lg">
              <ServerIcon className="w-5 h-5 text-cyber-blue-neon" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-cyber-blue-neon">
                {totalMemoryUsage.toFixed(1)}GB
              </div>
              <div className="text-sm text-matrix-text">Memory Usage</div>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-orange" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-orange-neon/20 rounded-lg">
              <BoltIcon className="w-5 h-5 text-cyber-orange-neon" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-cyber-orange-neon">
                {models.reduce((sum, m) => sum + m.usage.totalRequests, 0).toLocaleString()}
              </div>
              <div className="text-sm text-matrix-text">Total Requests</div>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-purple" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-purple-neon/20 rounded-lg">
              <ChartBarIcon className="w-5 h-5 text-cyber-purple-neon" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-cyber-purple-neon">
                {(models.reduce((sum, m) => sum + m.usage.successRate, 0) / models.length).toFixed(1)}%
              </div>
              <div className="text-sm text-matrix-text">Success Rate</div>
            </div>
          </div>
        </CyberpunkCard>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-1">
        {(['all', 'running', 'stopped'] as const).map((filterType) => (
          <button
            key={filterType}
            onClick={() => setFilter(filterType)}
            className={`px-4 py-2 text-sm rounded-lg transition-colors capitalize ${
              filter === filterType
                ? 'bg-cyber-blue-neon/20 text-cyber-blue-neon border border-cyber-blue-neon/40'
                : 'text-matrix-text hover:text-matrix-white hover:bg-matrix-surface'
            }`}
          >
            {filterType} {filterType !== 'all' && `(${models.filter(m => m.status === filterType).length})`}
          </button>
        ))}
      </div>

      {/* Models Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        <AnimatePresence>
          {filteredModels.map((model, index) => {
            const TypeIcon = getTypeIcon(model.type)
            
            return (
              <motion.div
                key={model.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ delay: index * 0.1 }}
              >
                <CyberpunkCard 
                  variant={model.status === 'running' ? 'neon-green' : 'glass-dark'} 
                  size="lg"
                  className="h-full cursor-pointer group"
                  onClick={() => setSelectedModel(model)}
                >
                  <div className="space-y-4">
                    {/* Header */}
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg bg-${getStatusColor(model.status)}/20`}>
                          <TypeIcon className={`w-5 h-5 text-${getStatusColor(model.status)}`} />
                        </div>
                        <div>
                          <h3 className="font-semibold text-matrix-white">{model.name}</h3>
                          <p className="text-xs text-matrix-text">{model.provider} • {model.version}</p>
                        </div>
                      </div>
                      
                      <div className="flex items-center gap-2">
                        <Badge 
                          variant="outline" 
                          className={`text-xs border-${getStatusColor(model.status)} text-${getStatusColor(model.status)}`}
                        >
                          {model.status}
                        </Badge>
                        <Badge variant="secondary" className="text-xs">
                          {model.type}
                        </Badge>
                      </div>
                    </div>

                    {/* Description */}
                    <p className="text-sm text-matrix-text leading-relaxed">
                      {model.description}
                    </p>

                    {/* Performance Metrics */}
                    {model.status === 'running' && (
                      <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-4 text-xs">
                          <div>
                            <span className="text-matrix-text">Tokens/sec</span>
                            <div className="font-cyber text-cyber-green-neon">
                              {model.performance.tokensPerSecond.toFixed(0)}
                            </div>
                          </div>
                          <div>
                            <span className="text-matrix-text">Latency</span>
                            <div className="font-cyber text-cyber-blue-neon">
                              {model.performance.averageLatency.toFixed(0)}ms
                            </div>
                          </div>
                        </div>
                        
                        <div className="space-y-2">
                          <div className="flex justify-between text-xs">
                            <span className="text-matrix-text">CPU Usage</span>
                            <span className="font-cyber text-cyber-orange-neon">
                              {model.performance.cpuUsage.toFixed(0)}%
                            </span>
                          </div>
                          <Progress 
                            value={model.performance.cpuUsage} 
                            className="h-1"
                            indicatorClassName="bg-cyber-orange-neon"
                          />
                        </div>
                      </div>
                    )}

                    {/* Usage Stats */}
                    <div className="flex items-center justify-between text-xs text-matrix-text">
                      <span>{model.usage.totalRequests.toLocaleString()} requests</span>
                      <span>{formatRelativeTime(model.usage.lastUsed)}</span>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 pt-2 border-t border-matrix-border">
                      {model.status === 'running' ? (
                        <CyberpunkButton
                          variant="neon-orange"
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation()
                            handleModelAction(model.id, 'stop')
                          }}
                        >
                          <StopIcon className="w-4 h-4" />
                          Stop
                        </CyberpunkButton>
                      ) : (
                        <CyberpunkButton
                          variant="neon-green"
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation()
                            handleModelAction(model.id, 'start')
                          }}
                        >
                          <PlayIcon className="w-4 h-4" />
                          Start
                        </CyberpunkButton>
                      )}
                      
                      <CyberpunkButton
                        variant="ghost-blue"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation()
                          // Handle config
                        }}
                      >
                        <Cog6ToothIcon className="w-4 h-4" />
                      </CyberpunkButton>
                      
                      <CyberpunkButton
                        variant="ghost-blue"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation()
                          handleModelAction(model.id, 'delete')
                        }}
                      >
                        <TrashIcon className="w-4 h-4" />
                      </CyberpunkButton>
                    </div>
                  </div>
                </CyberpunkCard>
              </motion.div>
            )
          })}
        </AnimatePresence>
      </div>

      {/* Model Details Modal */}
      <AnimatePresence>
        {selectedModel && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-matrix-black/80 backdrop-blur-sm flex items-center justify-center p-4"
            onClick={() => setSelectedModel(null)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-2xl"
              onClick={(e) => e.stopPropagation()}
            >
              <CyberpunkCard variant="neon-blue" size="lg">
                <div className="space-y-6">
                  <div className="flex items-start justify-between">
                    <div>
                      <h2 className="text-xl font-semibold text-cyber-blue-neon">
                        {selectedModel.name}
                      </h2>
                      <p className="text-matrix-text mt-1">
                        {selectedModel.description}
                      </p>
                    </div>
                    <button
                      onClick={() => setSelectedModel(null)}
                      className="text-matrix-text hover:text-matrix-white transition-colors"
                    >
                      ×
                    </button>
                  </div>

                  {/* Detailed metrics and configuration would go here */}
                  <div className="grid grid-cols-2 gap-6 text-sm">
                    <div>
                      <h3 className="font-medium text-matrix-white mb-3">Configuration</h3>
                      <div className="space-y-2">
                        <div className="flex justify-between">
                          <span className="text-matrix-text">Temperature:</span>
                          <span className="font-cyber text-cyber-blue-neon">
                            {selectedModel.config.temperature}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-matrix-text">Max Tokens:</span>
                          <span className="font-cyber text-cyber-blue-neon">
                            {selectedModel.config.maxTokens}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-matrix-text">Context Length:</span>
                          <span className="font-cyber text-cyber-blue-neon">
                            {selectedModel.config.contextLength}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div>
                      <h3 className="font-medium text-matrix-white mb-3">Capabilities</h3>
                      <div className="flex flex-wrap gap-2">
                        {selectedModel.capabilities.map((capability) => (
                          <Badge key={capability} variant="secondary" className="text-xs">
                            {capability}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </CyberpunkCard>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
