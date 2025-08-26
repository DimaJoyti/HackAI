'use client'

import React, { useState, useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from './cyberpunk-card'
import { DataStream } from './cyberpunk-effects'
import { 
  TerminalIcon,
  ChevronRightIcon,
  XMarkIcon,
  MinusIcon,
  Square2StackIcon
} from '@heroicons/react/24/outline'

interface TerminalLine {
  id: string
  type: 'command' | 'output' | 'error' | 'system' | 'warning'
  content: string
  timestamp: Date
}

interface CyberpunkTerminalProps {
  className?: string
  title?: string
  theme?: 'green' | 'blue' | 'amber' | 'red'
  onCommand?: (command: string) => void
  initialLines?: TerminalLine[]
  showHeader?: boolean
  autoScroll?: boolean
}

export const CyberpunkTerminal: React.FC<CyberpunkTerminalProps> = ({
  className,
  title = 'SYSTEM TERMINAL',
  theme = 'green',
  onCommand,
  initialLines = [],
  showHeader = true,
  autoScroll = true
}) => {
  const [lines, setLines] = useState<TerminalLine[]>(initialLines)
  const [currentCommand, setCurrentCommand] = useState('')
  const [commandHistory, setCommandHistory] = useState<string[]>([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const [isTyping, setIsTyping] = useState(false)
  const terminalRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const themeColors = {
    green: {
      primary: 'text-cyber-green-neon',
      secondary: 'text-green-400',
      border: 'border-cyber-green-neon/30',
      bg: 'bg-cyber-green-neon/5',
      glow: 'shadow-neon-green'
    },
    blue: {
      primary: 'text-cyber-blue-neon',
      secondary: 'text-blue-400',
      border: 'border-cyber-blue-neon/30',
      bg: 'bg-cyber-blue-neon/5',
      glow: 'shadow-neon-blue'
    },
    amber: {
      primary: 'text-cyber-orange-neon',
      secondary: 'text-amber-400',
      border: 'border-cyber-orange-neon/30',
      bg: 'bg-cyber-orange-neon/5',
      glow: 'shadow-neon-orange'
    },
    red: {
      primary: 'text-security-critical',
      secondary: 'text-red-400',
      border: 'border-security-critical/30',
      bg: 'bg-security-critical/5',
      glow: 'shadow-security-critical'
    }
  }

  const colors = themeColors[theme]

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll && terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [lines, autoScroll])

  // Focus input when terminal is clicked
  const handleTerminalClick = () => {
    inputRef.current?.focus()
  }

  // Handle command submission
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!currentCommand.trim()) return

    const newLine: TerminalLine = {
      id: Date.now().toString(),
      type: 'command',
      content: currentCommand,
      timestamp: new Date()
    }

    setLines(prev => [...prev, newLine])
    setCommandHistory(prev => [...prev, currentCommand])
    setHistoryIndex(-1)

    // Execute command
    if (onCommand) {
      onCommand(currentCommand)
    } else {
      // Default command handling
      executeCommand(currentCommand)
    }

    setCurrentCommand('')
  }

  // Default command execution
  const executeCommand = (command: string) => {
    setIsTyping(true)
    
    setTimeout(() => {
      const cmd = command.toLowerCase().trim()
      let response: TerminalLine

      switch (cmd) {
        case 'help':
          response = {
            id: Date.now().toString(),
            type: 'output',
            content: 'Available commands: help, status, scan, agents, clear, exit',
            timestamp: new Date()
          }
          break
        case 'status':
          response = {
            id: Date.now().toString(),
            type: 'system',
            content: '✓ All systems operational\n✓ AI agents online\n✓ Security protocols active',
            timestamp: new Date()
          }
          break
        case 'scan':
          response = {
            id: Date.now().toString(),
            type: 'output',
            content: 'Initiating security scan...\nScanning network interfaces...\nNo threats detected.',
            timestamp: new Date()
          }
          break
        case 'agents':
          response = {
            id: Date.now().toString(),
            type: 'output',
            content: 'Research Agent: ONLINE\nCreator Agent: ONLINE\nAnalyst Agent: ONLINE\nOperator Agent: ONLINE\nStrategist Agent: ONLINE',
            timestamp: new Date()
          }
          break
        case 'clear':
          setLines([])
          setIsTyping(false)
          return
        case 'exit':
          response = {
            id: Date.now().toString(),
            type: 'system',
            content: 'Connection terminated.',
            timestamp: new Date()
          }
          break
        default:
          response = {
            id: Date.now().toString(),
            type: 'error',
            content: `Command not found: ${command}. Type 'help' for available commands.`,
            timestamp: new Date()
          }
      }

      setLines(prev => [...prev, response])
      setIsTyping(false)
    }, 500)
  }

  // Handle keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (commandHistory.length > 0) {
        const newIndex = historyIndex === -1 ? commandHistory.length - 1 : Math.max(0, historyIndex - 1)
        setHistoryIndex(newIndex)
        setCurrentCommand(commandHistory[newIndex])
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (historyIndex !== -1) {
        const newIndex = historyIndex + 1
        if (newIndex >= commandHistory.length) {
          setHistoryIndex(-1)
          setCurrentCommand('')
        } else {
          setHistoryIndex(newIndex)
          setCurrentCommand(commandHistory[newIndex])
        }
      }
    }
  }

  const getLineColor = (type: TerminalLine['type']) => {
    switch (type) {
      case 'command':
        return colors.primary
      case 'output':
        return 'text-matrix-light'
      case 'error':
        return 'text-security-critical'
      case 'system':
        return colors.secondary
      case 'warning':
        return 'text-cyber-orange-neon'
      default:
        return 'text-matrix-light'
    }
  }

  return (
    <CyberpunkCard 
      variant={`neon-${theme}` as any} 
      className={cn('relative overflow-hidden font-matrix', className)}
    >
      <DataStream 
        streamCount={3} 
        direction="vertical" 
        color={theme} 
        speed="slow"
        className="opacity-10"
      />

      {showHeader && (
        <CyberpunkCardHeader accent className={cn('border-b', colors.border)}>
          <div className="flex items-center justify-between">
            <CyberpunkCardTitle className={cn('flex items-center gap-2', colors.primary)}>
              <TerminalIcon className="w-5 h-5" />
              {title}
            </CyberpunkCardTitle>
            <div className="flex items-center gap-1">
              <button className="w-3 h-3 rounded-full bg-cyber-orange-neon/60 hover:bg-cyber-orange-neon transition-colors" />
              <button className="w-3 h-3 rounded-full bg-cyber-blue-neon/60 hover:bg-cyber-blue-neon transition-colors" />
              <button className="w-3 h-3 rounded-full bg-security-critical/60 hover:bg-security-critical transition-colors" />
            </div>
          </div>
        </CyberpunkCardHeader>
      )}

      <CyberpunkCardContent className="p-0">
        <div 
          ref={terminalRef}
          className={cn(
            'h-96 overflow-y-auto scrollbar-cyber p-4 cursor-text',
            colors.bg
          )}
          onClick={handleTerminalClick}
        >
          {/* Terminal Lines */}
          <div className="space-y-1">
            {lines.map((line) => (
              <div key={line.id} className="flex items-start gap-2 text-sm">
                {line.type === 'command' && (
                  <span className={cn('flex-shrink-0', colors.primary)}>
                    $
                  </span>
                )}
                <div className={cn('flex-1 whitespace-pre-wrap', getLineColor(line.type))}>
                  {line.content}
                </div>
                <span className="text-xs text-matrix-muted flex-shrink-0">
                  {line.timestamp.toLocaleTimeString()}
                </span>
              </div>
            ))}
            
            {/* Typing indicator */}
            {isTyping && (
              <div className="flex items-center gap-2 text-sm">
                <span className={cn('flex-shrink-0', colors.primary)}>
                  $
                </span>
                <div className={cn('flex items-center gap-1', colors.secondary)}>
                  <span>Processing</span>
                  <div className="flex gap-1">
                    <div className="w-1 h-1 bg-current rounded-full animate-bounce" />
                    <div className="w-1 h-1 bg-current rounded-full animate-bounce" style={{ animationDelay: '0.1s' }} />
                    <div className="w-1 h-1 bg-current rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Command Input */}
          <form onSubmit={handleSubmit} className="flex items-center gap-2 mt-2">
            <span className={cn('flex-shrink-0', colors.primary)}>
              $
            </span>
            <input
              ref={inputRef}
              type="text"
              value={currentCommand}
              onChange={(e) => setCurrentCommand(e.target.value)}
              onKeyDown={handleKeyDown}
              className={cn(
                'flex-1 bg-transparent border-none outline-none text-matrix-white placeholder-matrix-muted',
                colors.primary
              )}
              placeholder="Enter command..."
              autoFocus
            />
            <div className={cn('w-2 h-4 animate-terminal-cursor', colors.primary)}>
              |
            </div>
          </form>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Add line to terminal programmatically
export const useTerminal = () => {
  const addLine = (
    setLines: React.Dispatch<React.SetStateAction<TerminalLine[]>>,
    type: TerminalLine['type'],
    content: string
  ) => {
    const newLine: TerminalLine = {
      id: Date.now().toString(),
      type,
      content,
      timestamp: new Date()
    }
    setLines(prev => [...prev, newLine])
  }

  return { addLine }
}
