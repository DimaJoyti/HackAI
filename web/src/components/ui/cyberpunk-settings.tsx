'use client'

import React, { useState } from 'react'
import { 
  CogIcon, 
  SpeakerWaveIcon, 
  SpeakerXMarkIcon,
  EyeIcon,
  EyeSlashIcon,
  ChartBarIcon,
  XMarkIcon
} from '@heroicons/react/24/outline'
import { CyberpunkButton } from './cyberpunk-button'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from './cyberpunk-card'
import { NeonBorder } from './cyberpunk-background'
import { 
  CyberpunkThemeSwitcher, 
  CyberpunkThemePreview, 
  useCyberpunkSounds,
  CyberpunkPerformanceMonitor,
  useResponsiveDesign
} from './cyberpunk-theme-provider'

interface CyberpunkSettingsProps {
  isOpen: boolean
  onClose: () => void
}

export function CyberpunkSettings({ isOpen, onClose }: CyberpunkSettingsProps) {
  const { soundEnabled, toggleSound, playSound } = useCyberpunkSounds()
  const { screenSize } = useResponsiveDesign()
  const [showPerformanceMonitor, setShowPerformanceMonitor] = useState(false)
  const [animationIntensity, setAnimationIntensity] = useState('medium')
  const [particleCount, setParticleCount] = useState('normal')

  if (!isOpen) return null

  const handleSoundToggle = () => {
    toggleSound()
    playSound('click')
  }

  const handleAnimationChange = (intensity: string) => {
    setAnimationIntensity(intensity)
    playSound('hover')
    
    // Apply animation intensity to document
    document.documentElement.setAttribute('data-animation-intensity', intensity)
  }

  const handleParticleChange = (count: string) => {
    setParticleCount(count)
    playSound('hover')
    
    // Apply particle count to document
    document.documentElement.setAttribute('data-particle-count', count)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-matrix-black/80 backdrop-blur-sm">
      <CyberpunkCard 
        variant="neon-blue" 
        size="lg" 
        className="w-full max-w-4xl max-h-[90vh] overflow-y-auto"
        cornerAccents
        scanLine
      >
        <CyberpunkCardHeader accent className="flex items-center justify-between">
          <CyberpunkCardTitle font="cyber" className="flex items-center gap-3">
            <CogIcon className="w-6 h-6" />
            Cyberpunk Settings
          </CyberpunkCardTitle>
          <CyberpunkButton 
            variant="ghost-blue" 
            size="icon"
            onClick={onClose}
          >
            <XMarkIcon className="w-5 h-5" />
          </CyberpunkButton>
        </CyberpunkCardHeader>

        <CyberpunkCardContent className="space-y-8">
          {/* Theme Settings */}
          <div className="space-y-4">
            <h3 className="text-lg font-cyber text-cyber-blue-neon">Theme Configuration</h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-4">
                <CyberpunkThemeSwitcher />
                <div className="text-sm text-matrix-light font-cyber">
                  Current screen size: <span className="text-cyber-blue-neon">{screenSize}</span>
                </div>
              </div>
              <div>
                <h4 className="text-sm font-cyber text-matrix-light mb-3">Theme Preview</h4>
                <CyberpunkThemePreview />
              </div>
            </div>
          </div>

          {/* Audio Settings */}
          <div className="space-y-4">
            <h3 className="text-lg font-cyber text-cyber-green-neon">Audio Configuration</h3>
            <div className="flex items-center justify-between p-4 bg-matrix-surface/50 rounded border border-cyber-green-neon/30">
              <div className="flex items-center gap-3">
                {soundEnabled ? (
                  <SpeakerWaveIcon className="w-5 h-5 text-cyber-green-neon" />
                ) : (
                  <SpeakerXMarkIcon className="w-5 h-5 text-matrix-muted" />
                )}
                <span className="font-cyber text-matrix-light">Sound Effects</span>
              </div>
              <CyberpunkButton
                variant={soundEnabled ? "filled-green" : "ghost-blue"}
                size="sm"
                onClick={handleSoundToggle}
              >
                {soundEnabled ? 'Enabled' : 'Disabled'}
              </CyberpunkButton>
            </div>
            
            {soundEnabled && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                <CyberpunkButton 
                  variant="ghost-blue" 
                  size="sm" 
                  onClick={() => playSound('click')}
                >
                  Click
                </CyberpunkButton>
                <CyberpunkButton 
                  variant="ghost-green" 
                  size="sm" 
                  onClick={() => playSound('hover')}
                >
                  Hover
                </CyberpunkButton>
                <CyberpunkButton 
                  variant="ghost-green" 
                  size="sm" 
                  onClick={() => playSound('success')}
                >
                  Success
                </CyberpunkButton>
                <CyberpunkButton 
                  variant="security-critical" 
                  size="sm" 
                  onClick={() => playSound('error')}
                >
                  Error
                </CyberpunkButton>
                <CyberpunkButton 
                  variant="ghost-purple" 
                  size="sm" 
                  onClick={() => playSound('scan')}
                >
                  Scan
                </CyberpunkButton>
              </div>
            )}
          </div>

          {/* Performance Settings */}
          <div className="space-y-4">
            <h3 className="text-lg font-cyber text-cyber-purple-neon">Performance Configuration</h3>
            
            {/* Animation Intensity */}
            <div className="space-y-3">
              <label className="text-sm font-cyber text-matrix-light">Animation Intensity</label>
              <div className="flex gap-2">
                {['low', 'medium', 'high'].map((intensity) => (
                  <CyberpunkButton
                    key={intensity}
                    variant={animationIntensity === intensity ? "filled-purple" : "ghost-purple"}
                    size="sm"
                    onClick={() => handleAnimationChange(intensity)}
                    className="capitalize"
                  >
                    {intensity}
                  </CyberpunkButton>
                ))}
              </div>
            </div>

            {/* Particle Count */}
            <div className="space-y-3">
              <label className="text-sm font-cyber text-matrix-light">Particle Effects</label>
              <div className="flex gap-2">
                {['minimal', 'normal', 'maximum'].map((count) => (
                  <CyberpunkButton
                    key={count}
                    variant={particleCount === count ? "filled-purple" : "ghost-purple"}
                    size="sm"
                    onClick={() => handleParticleChange(count)}
                    className="capitalize"
                  >
                    {count}
                  </CyberpunkButton>
                ))}
              </div>
            </div>

            {/* Performance Monitor Toggle */}
            <div className="flex items-center justify-between p-4 bg-matrix-surface/50 rounded border border-cyber-purple-neon/30">
              <div className="flex items-center gap-3">
                <ChartBarIcon className="w-5 h-5 text-cyber-purple-neon" />
                <span className="font-cyber text-matrix-light">Performance Monitor</span>
              </div>
              <CyberpunkButton
                variant={showPerformanceMonitor ? "filled-purple" : "ghost-purple"}
                size="sm"
                onClick={() => setShowPerformanceMonitor(!showPerformanceMonitor)}
              >
                {showPerformanceMonitor ? 'Hide' : 'Show'}
              </CyberpunkButton>
            </div>
          </div>

          {/* Visual Effects Settings */}
          <div className="space-y-4">
            <h3 className="text-lg font-cyber text-cyber-orange-neon">Visual Effects</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <NeonBorder color="orange" intensity="low" className="p-4">
                <div className="space-y-3">
                  <h4 className="text-sm font-cyber text-cyber-orange-neon">Matrix Rain</h4>
                  <div className="flex gap-2">
                    <CyberpunkButton variant="ghost-orange" size="sm">Off</CyberpunkButton>
                    <CyberpunkButton variant="filled-orange" size="sm">On</CyberpunkButton>
                  </div>
                </div>
              </NeonBorder>
              
              <NeonBorder color="orange" intensity="low" className="p-4">
                <div className="space-y-3">
                  <h4 className="text-sm font-cyber text-cyber-orange-neon">Glitch Effects</h4>
                  <div className="flex gap-2">
                    <CyberpunkButton variant="ghost-orange" size="sm">Minimal</CyberpunkButton>
                    <CyberpunkButton variant="filled-orange" size="sm">Full</CyberpunkButton>
                  </div>
                </div>
              </NeonBorder>
            </div>
          </div>

          {/* System Information */}
          <div className="space-y-4">
            <h3 className="text-lg font-cyber text-cyber-pink-neon">System Information</h3>
            <div className="bg-matrix-black p-4 rounded border border-cyber-pink-neon/30 font-matrix text-sm">
              <div className="space-y-2">
                <div className="text-cyber-pink-neon">CYBERPUNK UI SYSTEM v2.0.0</div>
                <div className="text-matrix-light">
                  <div>Browser: <span className="text-cyber-blue-neon">{navigator.userAgent.split(' ')[0]}</span></div>
                  <div>Screen: <span className="text-cyber-green-neon">{window.screen.width}x{window.screen.height}</span></div>
                  <div>Viewport: <span className="text-cyber-purple-neon">{window.innerWidth}x{window.innerHeight}</span></div>
                  <div>Theme: <span className="text-cyber-orange-neon">Cyberpunk Enhanced</span></div>
                </div>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex justify-end gap-4 pt-6 border-t border-matrix-border">
            <CyberpunkButton variant="ghost-blue" onClick={onClose}>
              Close
            </CyberpunkButton>
            <CyberpunkButton 
              variant="filled-blue" 
              onClick={() => {
                playSound('success')
                onClose()
              }}
            >
              Apply Settings
            </CyberpunkButton>
          </div>
        </CyberpunkCardContent>
      </CyberpunkCard>

      {/* Performance Monitor */}
      {showPerformanceMonitor && <CyberpunkPerformanceMonitor />}
    </div>
  )
}

// Settings Button Component
export function CyberpunkSettingsButton() {
  const [isOpen, setIsOpen] = useState(false)
  const { playSound } = useCyberpunkSounds()

  const handleOpen = () => {
    setIsOpen(true)
    playSound('click')
  }

  return (
    <>
      <CyberpunkButton
        variant="ghost-blue"
        size="icon"
        onClick={handleOpen}
        className="fixed top-4 left-4 z-40"
        title="Cyberpunk Settings"
      >
        <CogIcon className="w-5 h-5" />
      </CyberpunkButton>
      
      <CyberpunkSettings isOpen={isOpen} onClose={() => setIsOpen(false)} />
    </>
  )
}
