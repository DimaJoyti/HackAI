// Safe client-side storage utilities to prevent SSR issues

export const clientStorage = {
  get: (key: string): string | null => {
    if (typeof window === 'undefined') {
      return null
    }
    try {
      return localStorage.getItem(key)
    } catch (error) {
      console.warn('Failed to get item from localStorage:', error)
      return null
    }
  },

  set: (key: string, value: string): boolean => {
    if (typeof window === 'undefined') {
      return false
    }
    try {
      localStorage.setItem(key, value)
      return true
    } catch (error) {
      console.warn('Failed to set item in localStorage:', error)
      return false
    }
  },

  remove: (key: string): boolean => {
    if (typeof window === 'undefined') {
      return false
    }
    try {
      localStorage.removeItem(key)
      return true
    } catch (error) {
      console.warn('Failed to remove item from localStorage:', error)
      return false
    }
  },

  clear: (): boolean => {
    if (typeof window === 'undefined') {
      return false
    }
    try {
      localStorage.clear()
      return true
    } catch (error) {
      console.warn('Failed to clear localStorage:', error)
      return false
    }
  }
}