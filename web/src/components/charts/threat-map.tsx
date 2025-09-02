'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  FireIcon,
  EyeIcon,
} from '@heroicons/react/24/outline'
import { Badge } from '@/components/ui/badge'

interface ThreatLocation {
  id: string
  country: string
  city: string
  lat: number
  lng: number
  threatType: 'malware' | 'phishing' | 'ddos' | 'intrusion' | 'botnet'
  severity: 'critical' | 'high' | 'medium' | 'low'
  count: number
  timestamp: Date
  description: string
}

const mockThreats: ThreatLocation[] = [
  {
    id: '1',
    country: 'Russia',
    city: 'Moscow',
    lat: 55.7558,
    lng: 37.6176,
    threatType: 'ddos',
    severity: 'critical',
    count: 1247,
    timestamp: new Date(Date.now() - 2 * 60 * 1000),
    description: 'Large-scale DDoS attack targeting financial institutions'
  },
  {
    id: '2',
    country: 'China',
    city: 'Beijing',
    lat: 39.9042,
    lng: 116.4074,
    threatType: 'intrusion',
    severity: 'high',
    count: 892,
    timestamp: new Date(Date.now() - 5 * 60 * 1000),
    description: 'Advanced persistent threat targeting government networks'
  },
  {
    id: '3',
    country: 'North Korea',
    city: 'Pyongyang',
    lat: 39.0392,
    lng: 125.7625,
    threatType: 'malware',
    severity: 'high',
    count: 634,
    timestamp: new Date(Date.now() - 8 * 60 * 1000),
    description: 'Sophisticated malware campaign targeting cryptocurrency exchanges'
  },
  {
    id: '4',
    country: 'Iran',
    city: 'Tehran',
    lat: 35.6892,
    lng: 51.3890,
    threatType: 'phishing',
    severity: 'medium',
    count: 423,
    timestamp: new Date(Date.now() - 12 * 60 * 1000),
    description: 'Coordinated phishing campaign targeting energy sector'
  },
  {
    id: '5',
    country: 'Brazil',
    city: 'São Paulo',
    lat: -23.5505,
    lng: -46.6333,
    threatType: 'botnet',
    severity: 'medium',
    count: 356,
    timestamp: new Date(Date.now() - 15 * 60 * 1000),
    description: 'Banking trojan botnet activity detected'
  },
  {
    id: '6',
    country: 'Romania',
    city: 'Bucharest',
    lat: 44.4268,
    lng: 26.1025,
    threatType: 'malware',
    severity: 'low',
    count: 189,
    timestamp: new Date(Date.now() - 20 * 60 * 1000),
    description: 'Ransomware distribution network identified'
  }
]

export function ThreatMap() {
  const [threats, setThreats] = useState<ThreatLocation[]>(mockThreats)
  const [selectedThreat, setSelectedThreat] = useState<ThreatLocation | null>(null)
  const [filter, setFilter] = useState<'all' | 'critical' | 'high'>('all')

  // Simulate real-time threat updates
  useEffect(() => {
    const interval = setInterval(() => {
      setThreats(prev => prev.map(threat => ({
        ...threat,
        count: Math.max(0, threat.count + Math.floor((Math.random() - 0.7) * 50))
      })))
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  const getThreatIcon = (type: ThreatLocation['threatType']) => {
    switch (type) {
      case 'ddos':
        return FireIcon
      case 'intrusion':
        return ShieldExclamationIcon
      case 'malware':
        return ExclamationTriangleIcon
      case 'phishing':
        return EyeIcon
      case 'botnet':
        return ExclamationTriangleIcon
      default:
        return ExclamationTriangleIcon
    }
  }

  const getSeverityColor = (severity: ThreatLocation['severity']) => {
    switch (severity) {
      case 'critical':
        return 'security-critical'
      case 'high':
        return 'security-high'
      case 'medium':
        return 'security-medium'
      case 'low':
        return 'security-low'
      default:
        return 'matrix-text'
    }
  }

  const filteredThreats = threats.filter(threat => {
    if (filter === 'all') return true
    return threat.severity === filter
  })

  const totalThreats = threats.reduce((sum, threat) => sum + threat.count, 0)
  const criticalThreats = threats.filter(t => t.severity === 'critical').length
  const highThreats = threats.filter(t => t.severity === 'high').length

  return (
    <div className="space-y-6">
      {/* Filter and Stats */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1">
            {(['all', 'critical', 'high'] as const).map((filterType) => (
              <button
                key={filterType}
                onClick={() => setFilter(filterType)}
                className={`px-3 py-1 text-xs rounded-md transition-colors capitalize ${
                  filter === filterType
                    ? 'bg-security-critical/20 text-security-critical border border-security-critical/40'
                    : 'text-matrix-text hover:text-matrix-white hover:bg-matrix-surface'
                }`}
              >
                {filterType}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-security-critical rounded-full animate-neon-pulse" />
            <span className="text-security-critical font-cyber">{criticalThreats} CRITICAL</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-security-high rounded-full" />
            <span className="text-security-high font-cyber">{highThreats} HIGH</span>
          </div>
        </div>
      </div>

      {/* World Map Visualization */}
      <div className="relative bg-matrix-dark/50 rounded-lg p-6 min-h-[300px] overflow-hidden">
        {/* Background grid */}
        <div className="absolute inset-0 bg-cyber-grid opacity-10" />
        
        {/* Simplified world map representation */}
        <div className="relative w-full h-64 bg-gradient-to-b from-matrix-surface/30 to-matrix-dark/30 rounded-lg border border-matrix-border">
          {/* Threat markers */}
          {filteredThreats.map((threat, index) => {
            const ThreatIcon = getThreatIcon(threat.threatType)
            
            // Simple positioning based on lat/lng (simplified for demo)
            const x = ((threat.lng + 180) / 360) * 100
            const y = ((90 - threat.lat) / 180) * 100
            
            return (
              <motion.div
                key={threat.id}
                initial={{ scale: 0, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ delay: index * 0.1 }}
                className="absolute cursor-pointer group"
                style={{ 
                  left: `${Math.max(5, Math.min(95, x))}%`, 
                  top: `${Math.max(5, Math.min(95, y))}%`,
                  transform: 'translate(-50%, -50%)'
                }}
                onClick={() => setSelectedThreat(threat)}
              >
                {/* Threat pulse effect */}
                <div className={`absolute inset-0 w-6 h-6 rounded-full bg-${getSeverityColor(threat.severity)} opacity-30 animate-ping`} />
                
                {/* Threat marker */}
                <div className={`relative w-6 h-6 rounded-full bg-${getSeverityColor(threat.severity)}/80 border-2 border-${getSeverityColor(threat.severity)} flex items-center justify-center group-hover:scale-125 transition-transform`}>
                  <ThreatIcon className="w-3 h-3 text-matrix-white" />
                </div>

                {/* Hover tooltip */}
                <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
                  <div className="bg-matrix-dark/95 backdrop-blur-sm border border-cyber-blue-neon/30 rounded-lg p-2 text-xs whitespace-nowrap">
                    <div className="font-medium text-matrix-white">{threat.city}, {threat.country}</div>
                    <div className="text-matrix-text">{threat.threatType} • {threat.count} events</div>
                  </div>
                </div>
              </motion.div>
            )
          })}

          {/* Connection lines between threats (simplified) */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none">
            {filteredThreats.slice(0, 3).map((threat, index) => {
              const nextThreat = filteredThreats[(index + 1) % filteredThreats.length]
              const x1 = ((threat.lng + 180) / 360) * 100
              const y1 = ((90 - threat.lat) / 180) * 100
              const x2 = ((nextThreat.lng + 180) / 360) * 100
              const y2 = ((90 - nextThreat.lat) / 180) * 100
              
              return (
                <motion.line
                  key={`${threat.id}-${nextThreat.id}`}
                  x1={`${x1}%`}
                  y1={`${y1}%`}
                  x2={`${x2}%`}
                  y2={`${y2}%`}
                  stroke="url(#threatGradient)"
                  strokeWidth="1"
                  strokeDasharray="4 4"
                  opacity="0.3"
                  initial={{ pathLength: 0 }}
                  animate={{ pathLength: 1 }}
                  transition={{ duration: 2, delay: index * 0.5 }}
                />
              )
            })}
            <defs>
              <linearGradient id="threatGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#ff0080" />
                <stop offset="100%" stopColor="#00ffff" />
              </linearGradient>
            </defs>
          </svg>
        </div>

        {/* Map overlay effects */}
        <div className="absolute inset-0 bg-gradient-to-t from-matrix-dark/40 to-transparent pointer-events-none rounded-lg" />
      </div>

      {/* Threat Details Panel */}
      <AnimatePresence>
        {selectedThreat && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="bg-matrix-surface/80 backdrop-blur-sm border border-cyber-blue-neon/30 rounded-lg p-4"
          >
            <div className="flex items-start justify-between mb-3">
              <div>
                <h4 className="font-medium text-matrix-white">
                  {selectedThreat.city}, {selectedThreat.country}
                </h4>
                <p className="text-sm text-matrix-text mt-1">
                  {selectedThreat.description}
                </p>
              </div>
              <button
                onClick={() => setSelectedThreat(null)}
                className="text-matrix-text hover:text-matrix-white transition-colors"
              >
                ×
              </button>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
              <div>
                <span className="text-matrix-text">Threat Type</span>
                <div className="font-cyber text-matrix-white capitalize mt-1">
                  {selectedThreat.threatType}
                </div>
              </div>
              <div>
                <span className="text-matrix-text">Severity</span>
                <Badge 
                  variant="outline" 
                  className={`mt-1 border-${getSeverityColor(selectedThreat.severity)} text-${getSeverityColor(selectedThreat.severity)}`}
                >
                  {selectedThreat.severity}
                </Badge>
              </div>
              <div>
                <span className="text-matrix-text">Event Count</span>
                <div className="font-cyber text-cyber-orange-neon mt-1">
                  {selectedThreat.count.toLocaleString()}
                </div>
              </div>
              <div>
                <span className="text-matrix-text">Last Updated</span>
                <div className="font-cyber text-cyber-green-neon mt-1">
                  {selectedThreat.timestamp.toLocaleTimeString()}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
        <div className="bg-matrix-surface/50 rounded-lg p-3 border border-matrix-border">
          <div className="text-matrix-text">Total Threats</div>
          <div className="text-lg font-cyber text-cyber-orange-neon mt-1">
            {totalThreats.toLocaleString()}
          </div>
        </div>
        <div className="bg-matrix-surface/50 rounded-lg p-3 border border-matrix-border">
          <div className="text-matrix-text">Active Locations</div>
          <div className="text-lg font-cyber text-cyber-blue-neon mt-1">
            {threats.length}
          </div>
        </div>
        <div className="bg-matrix-surface/50 rounded-lg p-3 border border-matrix-border">
          <div className="text-matrix-text">Critical Events</div>
          <div className="text-lg font-cyber text-security-critical mt-1">
            {threats.filter(t => t.severity === 'critical').reduce((sum, t) => sum + t.count, 0)}
          </div>
        </div>
        <div className="bg-matrix-surface/50 rounded-lg p-3 border border-matrix-border">
          <div className="text-matrix-text">Threat Types</div>
          <div className="text-lg font-cyber text-cyber-green-neon mt-1">
            {new Set(threats.map(t => t.threatType)).size}
          </div>
        </div>
      </div>
    </div>
  )
}
