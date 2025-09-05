'use client'

import { CyberpunkBackground, MatrixRain, GlitchText } from '@/components/ui/cyberpunk-background'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from '@/components/ui/cyberpunk-card'
import { ChartBarIcon, ShieldCheckIcon, CpuChipIcon } from '@heroicons/react/24/outline'

export default function DashboardOverviewPage() {
  return (
    <CyberpunkBackground variant="grid" intensity="low" color="blue" className="min-h-screen">
      <MatrixRain intensity="low" color="#00d4ff" className="opacity-10" />
      
      <div className="container mx-auto px-4 py-8 relative z-10">
        <div className="mb-8">
          <h1 className="text-4xl font-display font-bold text-matrix-white mb-4">
            <GlitchText intensity="medium">
              Dashboard Overview
            </GlitchText>
          </h1>
          <p className="text-xl text-matrix-light font-cyber">
            High-level system status and security metrics
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <CyberpunkCard variant="neon-blue" interactive>
            <CyberpunkCardHeader accent>
              <div className="flex items-center gap-3">
                <ChartBarIcon className="w-6 h-6 text-cyber-blue-neon" />
                <CyberpunkCardTitle>System Analytics</CyberpunkCardTitle>
              </div>
            </CyberpunkCardHeader>
            <CyberpunkCardContent>
              <p className="text-matrix-light">
                Real-time monitoring and analytics dashboard for security operations.
              </p>
            </CyberpunkCardContent>
          </CyberpunkCard>

          <CyberpunkCard variant="neon-green" interactive>
            <CyberpunkCardHeader accent>
              <div className="flex items-center gap-3">
                <ShieldCheckIcon className="w-6 h-6 text-cyber-green-neon" />
                <CyberpunkCardTitle>Security Status</CyberpunkCardTitle>
              </div>
            </CyberpunkCardHeader>
            <CyberpunkCardContent>
              <p className="text-matrix-light">
                Current security posture and threat detection status.
              </p>
            </CyberpunkCardContent>
          </CyberpunkCard>

          <CyberpunkCard variant="neon-purple" interactive>
            <CyberpunkCardHeader accent>
              <div className="flex items-center gap-3">
                <CpuChipIcon className="w-6 h-6 text-cyber-purple-neon" />
                <CyberpunkCardTitle>AI Systems</CyberpunkCardTitle>
              </div>
            </CyberpunkCardHeader>
            <CyberpunkCardContent>
              <p className="text-matrix-light">
                AI agent performance and machine learning model status.
              </p>
            </CyberpunkCardContent>
          </CyberpunkCard>
        </div>
      </div>
    </CyberpunkBackground>
  )
}