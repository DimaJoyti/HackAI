'use client'

import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  CommandLineIcon,
  ArrowUpIcon,
  ArrowDownIcon,
  XMarkIcon,
  DocumentDuplicateIcon,
  TrashIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { formatDateTime } from '@/lib/utils'

interface TerminalCommand {
  id: string
  command: string
  output: string[]
  timestamp: Date
  status: 'success' | 'error' | 'warning' | 'info'
  duration?: number
}

interface TerminalSession {
  id: string
  name: string
  isActive: boolean
  commands: TerminalCommand[]
  workingDirectory: string
}

const mockCommands = [
  {
    id: '1',
    command: 'hackai scan --target https://example.com --type vulnerability',
    output: [
      '🔍 Starting vulnerability scan...',
      '📊 Target: https://example.com',
      '⚡ Scan type: Comprehensive vulnerability assessment',
      '',
      '✅ Port scan completed - 3 open ports found',
      '🔍 Web application analysis in progress...',
      '⚠️  SQL injection vulnerability detected in /login endpoint',
      '🚨 XSS vulnerability found in search parameter',
      '✅ SSL/TLS configuration verified',
      '',
      '📋 Scan Summary:',
      '   • Critical: 1',
      '   • High: 2', 
      '   • Medium: 5',
      '   • Low: 8',
      '',
      '✅ Scan completed in 2m 34s'
    ],
    timestamp: new Date(Date.now() - 5 * 60 * 1000),
    status: 'success' as const,
    duration: 154000
  },
  {
    id: '2',
    command: 'hackai models list',
    output: [
      '🤖 Available AI Models:',
      '',
      '┌─────────────────┬──────────┬──────────┬─────────────┐',
      '│ Model           │ Provider │ Status   │ Last Used   │',
      '├─────────────────┼──────────┼──────────┼─────────────┤',
      '│ llama2:7b       │ OLLAMA   │ Running  │ 2 min ago   │',
      '│ codellama:7b    │ OLLAMA   │ Running  │ 5 min ago   │',
      '│ mistral:7b      │ OLLAMA   │ Stopped  │ 1 hour ago  │',
      '│ nomic-embed     │ OLLAMA   │ Running  │ 30 sec ago  │',
      '└─────────────────┴──────────┴──────────┴─────────────┘',
      '',
      '📊 Total: 4 models | Active: 3 | Memory: 12.4GB'
    ],
    timestamp: new Date(Date.now() - 3 * 60 * 1000),
    status: 'info' as const
  }
]

const availableCommands = [
  {
    command: 'hackai scan',
    description: 'Run security scans',
    usage: 'hackai scan --target <url> --type <scan_type>',
    examples: [
      'hackai scan --target https://example.com --type vulnerability',
      'hackai scan --target 192.168.1.1 --type network',
      'hackai scan --target api.example.com --type api'
    ]
  },
  {
    command: 'hackai models',
    description: 'Manage AI models',
    usage: 'hackai models <action> [options]',
    examples: [
      'hackai models list',
      'hackai models start llama2',
      'hackai models stop mistral',
      'hackai models pull codellama:13b'
    ]
  },
  {
    command: 'hackai analyze',
    description: 'AI-powered security analysis',
    usage: 'hackai analyze <input> [options]',
    examples: [
      'hackai analyze --file report.json',
      'hackai analyze --text "suspicious network activity"',
      'hackai analyze --logs /var/log/security.log'
    ]
  },
  {
    command: 'hackai status',
    description: 'Show system status',
    usage: 'hackai status [component]',
    examples: [
      'hackai status',
      'hackai status scanner',
      'hackai status models',
      'hackai status network'
    ]
  }
]

export default function TerminalPage() {
  const [sessions, setSessions] = useState<TerminalSession[]>([
    {
      id: '1',
      name: 'Main Terminal',
      isActive: true,
      commands: mockCommands,
      workingDirectory: '/home/security'
    }
  ])
  
  const [currentInput, setCurrentInput] = useState('')
  const [commandHistory, setCommandHistory] = useState<string[]>([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const [isExecuting, setIsExecuting] = useState(false)
  const [showHelp, setShowHelp] = useState(false)
  
  const inputRef = useRef<HTMLInputElement>(null)
  const terminalRef = useRef<HTMLDivElement>(null)

  const activeSession = sessions.find(s => s.isActive) || sessions[0]

  // Auto-focus input and scroll to bottom
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [activeSession.commands])

  const executeCommand = async (command: string) => {
    if (!command.trim()) return

    setIsExecuting(true)
    setCommandHistory(prev => [...prev, command])
    setHistoryIndex(-1)

    const newCommand: TerminalCommand = {
      id: Date.now().toString(),
      command,
      output: [],
      timestamp: new Date(),
      status: 'info'
    }

    // Add command to session
    setSessions(prev => prev.map(session => 
      session.isActive 
        ? { ...session, commands: [...session.commands, newCommand] }
        : session
    ))

    // Simulate command execution
    await new Promise(resolve => setTimeout(resolve, 500))

    let output: string[] = []
    let status: TerminalCommand['status'] = 'success'

    // Process different commands
    if (command.startsWith('hackai scan')) {
      output = [
        '🔍 Initializing security scanner...',
        '📊 Loading scan modules...',
        '⚡ Starting scan process...',
        '',
        '✅ Scan completed successfully',
        '📋 Results saved to /tmp/scan_results.json'
      ]
    } else if (command.startsWith('hackai models')) {
      if (command.includes('list')) {
        output = [
          '🤖 Available AI Models:',
          '',
          '• llama2:7b (Running) - General purpose chat model',
          '• codellama:7b (Running) - Code generation and analysis',
          '• mistral:7b (Stopped) - Creative writing and analysis',
          '• nomic-embed (Running) - Text embeddings',
          '',
          '📊 Total: 4 models | Active: 3'
        ]
      } else {
        output = ['✅ Model operation completed']
      }
    } else if (command.startsWith('hackai analyze')) {
      output = [
        '🧠 Starting AI analysis...',
        '🔍 Processing input data...',
        '⚡ Running security assessment...',
        '',
        '📊 Analysis Results:',
        '• Threat Level: Medium',
        '• Confidence: 87%',
        '• Recommendations: 3',
        '',
        '✅ Analysis completed'
      ]
    } else if (command.startsWith('hackai status')) {
      output = [
        '🟢 HackAI System Status',
        '',
        '┌─────────────────┬─────────┬──────────────┐',
        '│ Component       │ Status  │ Last Check   │',
        '├─────────────────┼─────────┼──────────────┤',
        '│ Scanner Engine  │ Online  │ 30 sec ago   │',
        '│ AI Models       │ Online  │ 1 min ago    │',
        '│ Database        │ Online  │ 2 min ago    │',
        '│ API Gateway     │ Online  │ 30 sec ago   │',
        '└─────────────────┴─────────┴──────────────┘',
        '',
        '🚀 All systems operational'
      ]
    } else if (command === 'help' || command === 'hackai help') {
      setShowHelp(true)
      output = ['📚 Help panel opened. Type any command to continue.']
    } else if (command === 'clear') {
      setSessions(prev => prev.map(session => 
        session.isActive 
          ? { ...session, commands: [] }
          : session
      ))
      setIsExecuting(false)
      setCurrentInput('')
      return
    } else {
      output = [
        `❌ Command not found: ${command}`,
        '',
        '💡 Try one of these commands:',
        '• hackai scan --target <url> --type <type>',
        '• hackai models list',
        '• hackai analyze --text "<input>"',
        '• hackai status',
        '• help'
      ]
      status = 'error'
    }

    // Update command with output
    setSessions(prev => prev.map(session => 
      session.isActive 
        ? {
            ...session,
            commands: session.commands.map(cmd => 
              cmd.id === newCommand.id 
                ? { ...cmd, output, status, duration: 500 }
                : cmd
            )
          }
        : session
    ))

    setIsExecuting(false)
    setCurrentInput('')
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      executeCommand(currentInput)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (commandHistory.length > 0) {
        const newIndex = historyIndex === -1 ? commandHistory.length - 1 : Math.max(0, historyIndex - 1)
        setHistoryIndex(newIndex)
        setCurrentInput(commandHistory[newIndex])
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (historyIndex !== -1) {
        const newIndex = historyIndex + 1
        if (newIndex >= commandHistory.length) {
          setHistoryIndex(-1)
          setCurrentInput('')
        } else {
          setHistoryIndex(newIndex)
          setCurrentInput(commandHistory[newIndex])
        }
      }
    } else if (e.key === 'Tab') {
      e.preventDefault()
      // Simple autocomplete
      const matches = availableCommands.filter(cmd => 
        cmd.command.startsWith(currentInput)
      )
      if (matches.length === 1) {
        setCurrentInput(matches[0].command + ' ')
      }
    }
  }

  const getStatusColor = (status: TerminalCommand['status']) => {
    switch (status) {
      case 'success': return 'text-cyber-green-neon'
      case 'error': return 'text-security-critical'
      case 'warning': return 'text-cyber-orange-neon'
      default: return 'text-cyber-blue-neon'
    }
  }

  return (
    <div className="min-h-screen bg-matrix-void p-4 md:p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-display font-bold text-cyber-green-neon">
            Security Terminal
          </h1>
          <p className="text-matrix-text mt-1">
            Interactive command-line interface for HackAI security operations
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-cyber-green-neon rounded-full animate-neon-pulse" />
            <span className="text-sm text-cyber-green-neon font-cyber">TERMINAL ACTIVE</span>
          </div>
          
          <CyberpunkButton
            variant="ghost-blue"
            size="sm"
            onClick={() => setShowHelp(!showHelp)}
          >
            Help
          </CyberpunkButton>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Terminal */}
        <div className="lg:col-span-3">
          <CyberpunkCard variant="glass-dark" size="lg" className="h-[600px] flex flex-col">
            {/* Terminal Header */}
            <div className="flex items-center justify-between p-4 border-b border-matrix-border">
              <div className="flex items-center gap-3">
                <CommandLineIcon className="w-5 h-5 text-cyber-green-neon" />
                <span className="font-cyber text-cyber-green-neon">
                  {activeSession.name}
                </span>
                <Badge variant="outline" className="text-xs border-cyber-green-neon text-cyber-green-neon">
                  {activeSession.workingDirectory}
                </Badge>
              </div>
              
              <div className="flex items-center gap-2">
                <CyberpunkButton
                  variant="ghost-blue"
                  size="sm"
                  onClick={() => setSessions(prev => prev.map(session => 
                    session.isActive 
                      ? { ...session, commands: [] }
                      : session
                  ))}
                >
                  <TrashIcon className="w-4 h-4" />
                  Clear
                </CyberpunkButton>
              </div>
            </div>

            {/* Terminal Content */}
            <div 
              ref={terminalRef}
              className="flex-1 p-4 overflow-y-auto font-mono text-sm bg-matrix-dark/50 scrollbar-cyber"
            >
              {/* Welcome Message */}
              {activeSession.commands.length === 0 && (
                <div className="text-cyber-green-neon mb-4">
                  <div>Welcome to HackAI Security Terminal v2.0</div>
                  <div>Type 'help' for available commands</div>
                  <div className="mt-2 text-matrix-text">
                    {formatDateTime(new Date())}
                  </div>
                </div>
              )}

              {/* Command History */}
              <AnimatePresence>
                {activeSession.commands.map((cmd, index) => (
                  <motion.div
                    key={cmd.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mb-4"
                  >
                    {/* Command Input */}
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-cyber-green-neon">$</span>
                      <span className="text-matrix-white">{cmd.command}</span>
                      <span className="text-matrix-text text-xs ml-auto">
                        {formatDateTime(cmd.timestamp)}
                      </span>
                    </div>
                    
                    {/* Command Output */}
                    <div className={`ml-4 ${getStatusColor(cmd.status)}`}>
                      {cmd.output.map((line, lineIndex) => (
                        <div key={lineIndex} className="leading-relaxed">
                          {line}
                        </div>
                      ))}
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>

              {/* Current Input */}
              <div className="flex items-center gap-2">
                <span className="text-cyber-green-neon">$</span>
                <input
                  ref={inputRef}
                  type="text"
                  value={currentInput}
                  onChange={(e) => setCurrentInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  disabled={isExecuting}
                  className="flex-1 bg-transparent text-matrix-white outline-none font-mono"
                  placeholder={isExecuting ? "Executing..." : "Enter command..."}
                />
                {isExecuting && (
                  <div className="w-2 h-4 bg-cyber-green-neon animate-pulse" />
                )}
              </div>
            </div>
          </CyberpunkCard>
        </div>

        {/* Help Panel */}
        <div className="space-y-6">
          <CyberpunkCard variant="neon-blue" size="lg">
            <h3 className="text-lg font-semibold text-cyber-blue-neon mb-4">
              Quick Commands
            </h3>
            
            <div className="space-y-3 text-sm">
              {availableCommands.slice(0, 4).map((cmd) => (
                <div key={cmd.command} className="space-y-1">
                  <div className="font-cyber text-matrix-white">
                    {cmd.command}
                  </div>
                  <div className="text-matrix-text text-xs">
                    {cmd.description}
                  </div>
                </div>
              ))}
            </div>
          </CyberpunkCard>

          <CyberpunkCard variant="glass-dark" size="lg">
            <h3 className="text-lg font-semibold text-matrix-white mb-4">
              Keyboard Shortcuts
            </h3>
            
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-matrix-text">↑/↓</span>
                <span className="text-matrix-white">Command history</span>
              </div>
              <div className="flex justify-between">
                <span className="text-matrix-text">Tab</span>
                <span className="text-matrix-white">Autocomplete</span>
              </div>
              <div className="flex justify-between">
                <span className="text-matrix-text">Ctrl+C</span>
                <span className="text-matrix-white">Cancel command</span>
              </div>
              <div className="flex justify-between">
                <span className="text-matrix-text">clear</span>
                <span className="text-matrix-white">Clear terminal</span>
              </div>
            </div>
          </CyberpunkCard>

          {/* System Status */}
          <CyberpunkCard variant="neon-green" size="lg">
            <h3 className="text-lg font-semibold text-cyber-green-neon mb-4">
              System Status
            </h3>
            
            <div className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-matrix-text">Scanner Engine</span>
                <Badge variant="outline" className="border-cyber-green-neon text-cyber-green-neon text-xs">
                  Online
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-matrix-text">AI Models</span>
                <Badge variant="outline" className="border-cyber-blue-neon text-cyber-blue-neon text-xs">
                  3 Active
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-matrix-text">Database</span>
                <Badge variant="outline" className="border-cyber-green-neon text-cyber-green-neon text-xs">
                  Connected
                </Badge>
              </div>
            </div>
          </CyberpunkCard>
        </div>
      </div>

      {/* Help Modal */}
      <AnimatePresence>
        {showHelp && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-matrix-black/80 backdrop-blur-sm flex items-center justify-center p-4"
            onClick={() => setShowHelp(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-4xl max-h-[80vh] overflow-y-auto"
              onClick={(e) => e.stopPropagation()}
            >
              <CyberpunkCard variant="neon-blue" size="lg">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-semibold text-cyber-blue-neon">
                    Terminal Help
                  </h2>
                  <button
                    onClick={() => setShowHelp(false)}
                    className="text-matrix-text hover:text-matrix-white transition-colors"
                  >
                    <XMarkIcon className="w-6 h-6" />
                  </button>
                </div>

                <div className="space-y-6">
                  {availableCommands.map((cmd) => (
                    <div key={cmd.command} className="space-y-3">
                      <div>
                        <h3 className="font-cyber text-matrix-white text-lg">
                          {cmd.command}
                        </h3>
                        <p className="text-matrix-text text-sm">
                          {cmd.description}
                        </p>
                      </div>
                      
                      <div>
                        <h4 className="text-cyber-blue-neon text-sm font-medium mb-2">
                          Usage:
                        </h4>
                        <code className="text-xs bg-matrix-surface px-2 py-1 rounded text-cyber-green-neon">
                          {cmd.usage}
                        </code>
                      </div>
                      
                      <div>
                        <h4 className="text-cyber-blue-neon text-sm font-medium mb-2">
                          Examples:
                        </h4>
                        <div className="space-y-1">
                          {cmd.examples.map((example, index) => (
                            <code 
                              key={index}
                              className="block text-xs bg-matrix-surface px-2 py-1 rounded text-matrix-white"
                            >
                              {example}
                            </code>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CyberpunkCard>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
