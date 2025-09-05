import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import { immer } from 'zustand/middleware/immer'

// Types for dashboard state
export interface SecurityMetrics {
  threatLevel: number
  systemHealth: number
  activeScans: number
  vulnerabilities: number
  incidents: number
  lastUpdate: Date
}

export interface ThreatData {
  id: string
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  timestamp: Date
  status: 'active' | 'investigating' | 'mitigated' | 'resolved'
  source: string
}

export interface AIAgent {
  id: string
  name: string
  type: 'research' | 'analyst' | 'operator'
  status: 'online' | 'busy' | 'offline'
  performance: number
  lastActivity: Date
  currentTask: string
}

export interface ScanStatus {
  id: string
  type: string
  status: 'running' | 'completed' | 'failed' | 'paused'
  progress: number
  target: string
  startTime: Date
  endTime?: Date
  vulnerabilities?: number
}

export interface Notification {
  id: string
  type: 'alert' | 'info' | 'success' | 'warning' | 'error'
  title: string
  message: string
  timestamp: Date
  read: boolean
  actionRequired: boolean
  priority: 'low' | 'medium' | 'high' | 'critical'
}

export interface DashboardState {
  // Security data
  securityMetrics: SecurityMetrics | null
  threats: ThreatData[]
  aiAgents: AIAgent[]
  scans: ScanStatus[]
  
  // UI state
  notifications: Notification[]
  sidebarOpen: boolean
  theme: 'light' | 'dark' | 'cyberpunk'
  
  // Loading states
  loading: {
    metrics: boolean
    threats: boolean
    scans: boolean
    agents: boolean
  }
  
  // Error states
  errors: {
    metrics: string | null
    threats: string | null
    scans: string | null
    agents: string | null
  }
  
  // Cache timestamps
  lastFetch: {
    metrics: Date | null
    threats: Date | null
    scans: Date | null
    agents: Date | null
  }
}

export interface DashboardActions {
  // Security metrics actions
  setSecurityMetrics: (metrics: SecurityMetrics) => void
  updateSecurityMetrics: (updates: Partial<SecurityMetrics>) => void
  
  // Threats actions
  setThreats: (threats: ThreatData[]) => void
  addThreat: (threat: ThreatData) => void
  updateThreat: (id: string, updates: Partial<ThreatData>) => void
  removeThreat: (id: string) => void
  
  // AI agents actions
  setAIAgents: (agents: AIAgent[]) => void
  updateAIAgent: (id: string, updates: Partial<AIAgent>) => void
  
  // Scans actions
  setScans: (scans: ScanStatus[]) => void
  addScan: (scan: ScanStatus) => void
  updateScan: (id: string, updates: Partial<ScanStatus>) => void
  removeScan: (id: string) => void
  
  // Notifications actions
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp'>) => void
  markNotificationRead: (id: string) => void
  markAllNotificationsRead: () => void
  removeNotification: (id: string) => void
  clearNotifications: () => void
  
  // UI actions
  setSidebarOpen: (open: boolean) => void
  toggleSidebar: () => void
  setTheme: (theme: 'light' | 'dark' | 'cyberpunk') => void
  
  // Loading actions
  setLoading: (key: keyof DashboardState['loading'], loading: boolean) => void
  
  // Error actions
  setError: (key: keyof DashboardState['errors'], error: string | null) => void
  clearErrors: () => void
  
  // Cache actions
  updateLastFetch: (key: keyof DashboardState['lastFetch']) => void
  shouldRefresh: (key: keyof DashboardState['lastFetch'], maxAge: number) => boolean
  
  // Reset actions
  reset: () => void
}

const initialState: DashboardState = {
  securityMetrics: null,
  threats: [],
  aiAgents: [],
  scans: [],
  notifications: [],
  sidebarOpen: false,
  theme: 'cyberpunk',
  loading: {
    metrics: false,
    threats: false,
    scans: false,
    agents: false,
  },
  errors: {
    metrics: null,
    threats: null,
    scans: null,
    agents: null,
  },
  lastFetch: {
    metrics: null,
    threats: null,
    scans: null,
    agents: null,
  },
}

export const useDashboardStore = create<DashboardState & DashboardActions>()(
  devtools(
    persist(
      immer((set, get) => ({
        ...initialState,

        // Security metrics actions
        setSecurityMetrics: (metrics) =>
          set((state) => {
            state.securityMetrics = { ...metrics, lastUpdate: new Date() }
            state.errors.metrics = null
          }),

        updateSecurityMetrics: (updates) =>
          set((state) => {
            if (state.securityMetrics) {
              Object.assign(state.securityMetrics, updates)
              state.securityMetrics.lastUpdate = new Date()
            }
          }),

        // Threats actions
        setThreats: (threats) =>
          set((state) => {
            state.threats = threats
            state.errors.threats = null
          }),

        addThreat: (threat) =>
          set((state) => {
            state.threats.unshift(threat)
            // Keep only the latest 100 threats
            if (state.threats.length > 100) {
              state.threats = state.threats.slice(0, 100)
            }
          }),

        updateThreat: (id, updates) =>
          set((state) => {
            const index = state.threats.findIndex((t) => t.id === id)
            if (index !== -1) {
              Object.assign(state.threats[index], updates)
            }
          }),

        removeThreat: (id) =>
          set((state) => {
            state.threats = state.threats.filter((t) => t.id !== id)
          }),

        // AI agents actions
        setAIAgents: (agents) =>
          set((state) => {
            state.aiAgents = agents
            state.errors.agents = null
          }),

        updateAIAgent: (id, updates) =>
          set((state) => {
            const index = state.aiAgents.findIndex((a) => a.id === id)
            if (index !== -1) {
              Object.assign(state.aiAgents[index], updates)
            }
          }),

        // Scans actions
        setScans: (scans) =>
          set((state) => {
            state.scans = scans
            state.errors.scans = null
          }),

        addScan: (scan) =>
          set((state) => {
            state.scans.unshift(scan)
            // Keep only the latest 50 scans
            if (state.scans.length > 50) {
              state.scans = state.scans.slice(0, 50)
            }
          }),

        updateScan: (id, updates) =>
          set((state) => {
            const index = state.scans.findIndex((s) => s.id === id)
            if (index !== -1) {
              Object.assign(state.scans[index], updates)
            }
          }),

        removeScan: (id) =>
          set((state) => {
            state.scans = state.scans.filter((s) => s.id !== id)
          }),

        // Notifications actions
        addNotification: (notification) =>
          set((state) => {
            const newNotification: Notification = {
              ...notification,
              id: Math.random().toString(36).substring(2, 11),
              timestamp: new Date(),
              read: false,
            }
            state.notifications.unshift(newNotification)
            // Keep only the latest 50 notifications
            if (state.notifications.length > 50) {
              state.notifications = state.notifications.slice(0, 50)
            }
          }),

        markNotificationRead: (id) =>
          set((state) => {
            const notification = state.notifications.find((n) => n.id === id)
            if (notification) {
              notification.read = true
            }
          }),

        markAllNotificationsRead: () =>
          set((state) => {
            state.notifications.forEach((n) => {
              n.read = true
            })
          }),

        removeNotification: (id) =>
          set((state) => {
            state.notifications = state.notifications.filter((n) => n.id !== id)
          }),

        clearNotifications: () =>
          set((state) => {
            state.notifications = []
          }),

        // UI actions
        setSidebarOpen: (open) =>
          set((state) => {
            state.sidebarOpen = open
          }),

        toggleSidebar: () =>
          set((state) => {
            state.sidebarOpen = !state.sidebarOpen
          }),

        setTheme: (theme) =>
          set((state) => {
            state.theme = theme
          }),

        // Loading actions
        setLoading: (key, loading) =>
          set((state) => {
            state.loading[key] = loading
          }),

        // Error actions
        setError: (key, error) =>
          set((state) => {
            state.errors[key] = error
          }),

        clearErrors: () =>
          set((state) => {
            Object.keys(state.errors).forEach((key) => {
              state.errors[key as keyof typeof state.errors] = null
            })
          }),

        // Cache actions
        updateLastFetch: (key) =>
          set((state) => {
            state.lastFetch[key] = new Date()
          }),

        shouldRefresh: (key, maxAge) => {
          const lastFetch = get().lastFetch[key]
          if (!lastFetch) return true
          return Date.now() - lastFetch.getTime() > maxAge
        },

        // Reset actions
        reset: () => set(initialState),
      })),
      {
        name: 'dashboard-store',
        partialize: (state) => ({
          theme: state.theme,
          sidebarOpen: state.sidebarOpen,
          // Don't persist sensitive data or real-time data
        }),
      }
    ),
    {
      name: 'dashboard-store',
    }
  )
)

// Selectors for optimized component re-renders
export const useSecurityMetrics = () => useDashboardStore((state) => state.securityMetrics)
export const useThreats = () => useDashboardStore((state) => state.threats)
export const useAIAgents = () => useDashboardStore((state) => state.aiAgents)
export const useScans = () => useDashboardStore((state) => state.scans)
export const useNotifications = () => useDashboardStore((state) => state.notifications)
export const useUnreadNotifications = () => 
  useDashboardStore((state) => state.notifications.filter((n) => !n.read))
export const useTheme = () => useDashboardStore((state) => state.theme)
export const useSidebarOpen = () => useDashboardStore((state) => state.sidebarOpen)
export const useLoading = () => useDashboardStore((state) => state.loading)
export const useErrors = () => useDashboardStore((state) => state.errors)
