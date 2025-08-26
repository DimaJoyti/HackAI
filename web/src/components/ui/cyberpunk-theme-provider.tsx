'use client'

import React, { createContext, useContext, useState, useEffect } from 'react'

export type CyberpunkTheme = 'neon-blue' | 'toxic-green' | 'cyber-red' | 'purple-haze' | 'orange-burn'

interface CyberpunkThemeContextType {
  theme: CyberpunkTheme
  setTheme: (theme: CyberpunkTheme) => void
  themes: Record<CyberpunkTheme, {
    name: string
    primary: string
    secondary: string
    accent: string
    background: string
    surface: string
  }>
}

const CyberpunkThemeContext = createContext<CyberpunkThemeContextType | undefined>(undefined)

const themes = {
  'neon-blue': {
    name: 'Neon Blue',
    primary: '#00d4ff',
    secondary: '#0080ff',
    accent: '#004080',
    background: '#000011',
    surface: '#111122',
  },
  'toxic-green': {
    name: 'Toxic Green',
    primary: '#00ff41',
    secondary: '#00cc33',
    accent: '#008000',
    background: '#001100',
    surface: '#112211',
  },
  'cyber-red': {
    name: 'Cyber Red',
    primary: '#ff0040',
    secondary: '#cc0033',
    accent: '#800020',
    background: '#110000',
    surface: '#221111',
  },
  'purple-haze': {
    name: 'Purple Haze',
    primary: '#8000ff',
    secondary: '#6600cc',
    accent: '#400080',
    background: '#110011',
    surface: '#221122',
  },
  'orange-burn': {
    name: 'Orange Burn',
    primary: '#ff6600',
    secondary: '#cc5200',
    accent: '#803300',
    background: '#111100',
    surface: '#222211',
  },
}

export function CyberpunkThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<CyberpunkTheme>('neon-blue')

  useEffect(() => {
    // Load theme from localStorage
    const savedTheme = localStorage.getItem('cyberpunk-theme') as CyberpunkTheme
    if (savedTheme && themes[savedTheme]) {
      setTheme(savedTheme)
    }
  }, [])

  useEffect(() => {
    // Save theme to localStorage
    localStorage.setItem('cyberpunk-theme', theme)
    
    // Apply CSS custom properties
    const root = document.documentElement
    const currentTheme = themes[theme]
    
    root.style.setProperty('--cyber-primary', currentTheme.primary)
    root.style.setProperty('--cyber-secondary', currentTheme.secondary)
    root.style.setProperty('--cyber-accent', currentTheme.accent)
    root.style.setProperty('--cyber-background', currentTheme.background)
    root.style.setProperty('--cyber-surface', currentTheme.surface)
    
    // Update body class for theme-specific styles
    document.body.className = document.body.className.replace(/theme-\w+/g, '')
    document.body.classList.add(`theme-${theme}`)
  }, [theme])

  return (
    <CyberpunkThemeContext.Provider value={{ theme, setTheme, themes }}>
      {children}
    </CyberpunkThemeContext.Provider>
  )
}

export function useCyberpunkTheme() {
  const context = useContext(CyberpunkThemeContext)
  if (context === undefined) {
    throw new Error('useCyberpunkTheme must be used within a CyberpunkThemeProvider')
  }
  return context
}

// Theme Switcher Component
export function CyberpunkThemeSwitcher({ className }: { className?: string }) {
  const { theme, setTheme, themes } = useCyberpunkTheme()

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <span className="text-sm font-cyber text-matrix-light">Theme:</span>
      <select
        value={theme}
        onChange={(e) => setTheme(e.target.value as CyberpunkTheme)}
        className="bg-matrix-surface border border-cyber-blue-neon/30 text-cyber-blue-neon rounded px-3 py-1 text-sm font-cyber focus:outline-none focus:border-cyber-blue-neon"
      >
        {Object.entries(themes).map(([key, themeData]) => (
          <option key={key} value={key} className="bg-matrix-dark">
            {themeData.name}
          </option>
        ))}
      </select>
    </div>
  )
}

// Theme Preview Component
export function CyberpunkThemePreview() {
  const { themes } = useCyberpunkTheme()

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
      {Object.entries(themes).map(([key, themeData]) => (
        <div
          key={key}
          className="p-4 rounded-lg border border-matrix-border bg-matrix-surface"
        >
          <h3 className="text-sm font-cyber text-matrix-light mb-3">{themeData.name}</h3>
          <div className="space-y-2">
            <div
              className="h-3 rounded"
              style={{ backgroundColor: themeData.primary }}
            />
            <div
              className="h-3 rounded"
              style={{ backgroundColor: themeData.secondary }}
            />
            <div
              className="h-3 rounded"
              style={{ backgroundColor: themeData.accent }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

// Sound Effects Hook
export function useCyberpunkSounds() {
  const [soundEnabled, setSoundEnabled] = useState(false)

  useEffect(() => {
    const savedSoundSetting = localStorage.getItem('cyberpunk-sound-enabled')
    setSoundEnabled(savedSoundSetting === 'true')
  }, [])

  const toggleSound = () => {
    const newSetting = !soundEnabled
    setSoundEnabled(newSetting)
    localStorage.setItem('cyberpunk-sound-enabled', newSetting.toString())
  }

  const playSound = (soundType: 'click' | 'hover' | 'success' | 'error' | 'scan') => {
    if (!soundEnabled) return

    // Create audio context for cyberpunk sounds
    const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)()
    
    const createBeep = (frequency: number, duration: number, type: OscillatorType = 'sine') => {
      const oscillator = audioContext.createOscillator()
      const gainNode = audioContext.createGain()
      
      oscillator.connect(gainNode)
      gainNode.connect(audioContext.destination)
      
      oscillator.frequency.value = frequency
      oscillator.type = type
      
      gainNode.gain.setValueAtTime(0.1, audioContext.currentTime)
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + duration)
      
      oscillator.start(audioContext.currentTime)
      oscillator.stop(audioContext.currentTime + duration)
    }

    switch (soundType) {
      case 'click':
        createBeep(800, 0.1, 'square')
        break
      case 'hover':
        createBeep(600, 0.05, 'sine')
        break
      case 'success':
        createBeep(523, 0.1, 'sine') // C note
        setTimeout(() => createBeep(659, 0.1, 'sine'), 100) // E note
        break
      case 'error':
        createBeep(200, 0.2, 'sawtooth')
        break
      case 'scan':
        // Scanning sound effect
        for (let i = 0; i < 5; i++) {
          setTimeout(() => createBeep(400 + i * 100, 0.1, 'triangle'), i * 100)
        }
        break
    }
  }

  return { soundEnabled, toggleSound, playSound }
}

// Performance Monitor Component
export function CyberpunkPerformanceMonitor() {
  const [fps, setFps] = useState(0)
  const [memoryUsage, setMemoryUsage] = useState(0)

  useEffect(() => {
    let frameCount = 0
    let lastTime = performance.now()

    const measureFPS = () => {
      frameCount++
      const currentTime = performance.now()
      
      if (currentTime - lastTime >= 1000) {
        setFps(Math.round((frameCount * 1000) / (currentTime - lastTime)))
        frameCount = 0
        lastTime = currentTime
      }

      // Measure memory usage if available
      if ('memory' in performance) {
        const memory = (performance as any).memory
        setMemoryUsage(Math.round(memory.usedJSHeapSize / 1024 / 1024))
      }

      requestAnimationFrame(measureFPS)
    }

    measureFPS()
  }, [])

  return (
    <div className="fixed bottom-4 right-4 bg-matrix-dark/90 border border-cyber-green-neon/30 rounded p-3 text-xs font-matrix z-50">
      <div className="text-cyber-green-neon">SYSTEM MONITOR</div>
      <div className="text-matrix-light mt-1">
        <div>FPS: <span className="text-cyber-blue-neon">{fps}</span></div>
        <div>MEM: <span className="text-cyber-pink-neon">{memoryUsage}MB</span></div>
      </div>
    </div>
  )
}

// Responsive Design Hook
export function useResponsiveDesign() {
  const [screenSize, setScreenSize] = useState<'mobile' | 'tablet' | 'desktop'>('desktop')

  useEffect(() => {
    const updateScreenSize = () => {
      const width = window.innerWidth
      if (width < 768) {
        setScreenSize('mobile')
      } else if (width < 1024) {
        setScreenSize('tablet')
      } else {
        setScreenSize('desktop')
      }
    }

    updateScreenSize()
    window.addEventListener('resize', updateScreenSize)
    return () => window.removeEventListener('resize', updateScreenSize)
  }, [])

  return { screenSize }
}
