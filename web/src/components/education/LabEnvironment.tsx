'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  PlayIcon,
  StopIcon,
  ArrowPathIcon,
  CommandLineIcon,
  DocumentTextIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  CpuChipIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { Input } from '@/components/ui/input'

interface LabEnvironmentProps {
  labId: string
  title: string
  description: string
  instructions: LabInstruction[]
  environment: LabEnvironmentConfig
  onComplete?: (results: LabResults) => void
}

interface LabInstruction {
  id: string
  step: number
  title: string
  description: string
  commands?: string[]
  expected?: string
  hints?: string[]
  validation?: ValidationCriteria
}

interface LabEnvironmentConfig {
  type: 'web' | 'terminal' | 'jupyter' | 'docker'
  endpoint?: string
  credentials?: Record<string, string>
  resources?: Record<string, string>
}

interface ValidationCriteria {
  type: 'output' | 'file' | 'api' | 'manual'
  criteria: string[]
  autoCheck: boolean
}

interface LabResults {
  stepResults: StepResult[]
  overallScore: number
  timeSpent: number
  hintsUsed: number
}

interface StepResult {
  stepId: string
  completed: boolean
  score: number
  attempts: number
  timeSpent: number
  feedback?: string
}

export default function LabEnvironment({
  labId,
  title,
  description,
  instructions,
  environment,
  onComplete,
}: LabEnvironmentProps) {
  const [currentStep, setCurrentStep] = useState(0)
  const [environmentStatus, setEnvironmentStatus] = useState<'initializing' | 'ready' | 'error'>('initializing')
  const [stepResults, setStepResults] = useState<StepResult[]>([])
  const [startTime] = useState(Date.now())
  const [stepStartTime, setStepStartTime] = useState(Date.now())
  const [userInput, setUserInput] = useState('')
  const [terminalOutput, setTerminalOutput] = useState<string[]>([])
  const [showHints, setShowHints] = useState(false)
  const [hintsUsed, setHintsUsed] = useState(0)

  useEffect(() => {
    // Simulate environment initialization
    const timer = setTimeout(() => {
      setEnvironmentStatus('ready')
    }, 3000)

    return () => clearTimeout(timer)
  }, [])

  useEffect(() => {
    setStepStartTime(Date.now())
  }, [currentStep])

  const currentInstruction = instructions[currentStep]
  const isLastStep = currentStep === instructions.length - 1
  const completedSteps = stepResults.filter(r => r.completed).length

  const handleStartEnvironment = () => {
    setEnvironmentStatus('ready')
    addTerminalOutput('Environment initialized successfully!')
    addTerminalOutput('Type "help" for available commands.')
  }

  const handleStopEnvironment = () => {
    setEnvironmentStatus('initializing')
    setTerminalOutput([])
  }

  const addTerminalOutput = (output: string) => {
    setTerminalOutput(prev => [...prev, `$ ${output}`])
  }

  const executeCommand = (command: string) => {
    addTerminalOutput(command)
    
    // Simulate command execution
    setTimeout(() => {
      if (command.toLowerCase().includes('help')) {
        addTerminalOutput('Available commands: ls, cat, grep, curl, python, node')
      } else if (command.toLowerCase().includes('ls')) {
        addTerminalOutput('file1.txt  file2.py  config.json  logs/')
      } else if (command.toLowerCase().includes('cat')) {
        addTerminalOutput('File contents would appear here...')
      } else {
        addTerminalOutput('Command executed successfully.')
      }
    }, 500)
  }

  const handleSubmitStep = () => {
    const timeSpent = Date.now() - stepStartTime
    const stepResult: StepResult = {
      stepId: currentInstruction.id,
      completed: true,
      score: Math.random() > 0.3 ? 100 : 75, // Simulate scoring
      attempts: 1,
      timeSpent,
      feedback: 'Good work! You completed this step successfully.',
    }

    setStepResults(prev => [...prev, stepResult])

    if (isLastStep) {
      // Lab completed
      const results: LabResults = {
        stepResults: [...stepResults, stepResult],
        overallScore: Math.round(
          ([...stepResults, stepResult].reduce((sum, r) => sum + r.score, 0) / instructions.length)
        ),
        timeSpent: Date.now() - startTime,
        hintsUsed,
      }
      onComplete?.(results)
    } else {
      setCurrentStep(prev => prev + 1)
    }
  }

  const handleUseHint = () => {
    setShowHints(true)
    setHintsUsed(prev => prev + 1)
  }

  const getStepStatus = (stepIndex: number) => {
    if (stepIndex < currentStep) return 'completed'
    if (stepIndex === currentStep) return 'current'
    return 'pending'
  }

  const renderEnvironmentInterface = () => {
    switch (environment.type) {
      case 'terminal':
        return (
          <div className="bg-black text-green-400 p-4 rounded-lg font-mono text-sm h-64 overflow-y-auto">
            {terminalOutput.map((line, index) => (
              <div key={index} className="mb-1">
                {line}
              </div>
            ))}
            <div className="flex items-center">
              <span className="text-blue-400">user@lab:~$ </span>
              <input
                type="text"
                value={userInput}
                onChange={(e) => setUserInput(e.target.value)}
                onKeyPress={(e) => {
                  if (e.key === 'Enter') {
                    executeCommand(userInput)
                    setUserInput('')
                  }
                }}
                className="bg-transparent border-none outline-none flex-1 text-green-400"
                placeholder="Type your command here..."
              />
            </div>
          </div>
        )

      case 'web':
        return (
          <div className="border rounded-lg h-64 bg-white dark:bg-gray-900 flex items-center justify-center">
            <div className="text-center">
              <CpuChipIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600 dark:text-gray-400">
                Web interface would be embedded here
              </p>
              {environment.endpoint && (
                <p className="text-sm text-blue-600 mt-2">
                  Endpoint: {environment.endpoint}
                </p>
              )}
            </div>
          </div>
        )

      case 'jupyter':
        return (
          <div className="border rounded-lg h-64 bg-gray-50 dark:bg-gray-800 flex items-center justify-center">
            <div className="text-center">
              <DocumentTextIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600 dark:text-gray-400">
                Jupyter notebook interface would be embedded here
              </p>
            </div>
          </div>
        )

      default:
        return (
          <div className="border rounded-lg h-64 bg-gray-50 dark:bg-gray-800 flex items-center justify-center">
            <div className="text-center">
              <CommandLineIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600 dark:text-gray-400">
                Environment interface loading...
              </p>
            </div>
          </div>
        )
    }
  }

  return (
    <div className="space-y-6">
      {/* Lab Header */}
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between">
            <div>
              <CardTitle className="text-xl">{title}</CardTitle>
              <CardDescription className="mt-2">{description}</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant={environmentStatus === 'ready' ? 'default' : 'secondary'}>
                {environmentStatus === 'ready' ? 'Ready' : 'Initializing'}
              </Badge>
              <Badge variant="outline">
                Step {currentStep + 1} of {instructions.length}
              </Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* Progress */}
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span>Progress</span>
                <span>{Math.round((completedSteps / instructions.length) * 100)}%</span>
              </div>
              <Progress value={(completedSteps / instructions.length) * 100} />
            </div>

            {/* Environment Controls */}
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                onClick={handleStartEnvironment}
                disabled={environmentStatus === 'ready'}
              >
                <PlayIcon className="h-4 w-4 mr-1" />
                Start Environment
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={handleStopEnvironment}
                disabled={environmentStatus !== 'ready'}
              >
                <StopIcon className="h-4 w-4 mr-1" />
                Stop
              </Button>
              <Button size="sm" variant="outline">
                <ArrowPathIcon className="h-4 w-4 mr-1" />
                Reset
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Instructions Panel */}
        <div className="lg:col-span-1">
          <Card className="h-fit">
            <CardHeader>
              <CardTitle className="text-lg">Instructions</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {/* Step Navigation */}
                <div className="space-y-2">
                  {instructions.map((instruction, index) => (
                    <div
                      key={instruction.id}
                      className={`flex items-center gap-2 p-2 rounded-lg cursor-pointer transition-colors ${
                        getStepStatus(index) === 'completed'
                          ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300'
                          : getStepStatus(index) === 'current'
                          ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                          : 'text-gray-500 dark:text-gray-400'
                      }`}
                      onClick={() => index <= currentStep && setCurrentStep(index)}
                    >
                      <div className="flex-shrink-0">
                        {getStepStatus(index) === 'completed' ? (
                          <CheckCircleIcon className="h-5 w-5" />
                        ) : (
                          <div className="w-5 h-5 rounded-full border-2 flex items-center justify-center text-xs">
                            {index + 1}
                          </div>
                        )}
                      </div>
                      <span className="text-sm font-medium truncate">
                        {instruction.title}
                      </span>
                    </div>
                  ))}
                </div>

                {/* Current Step Details */}
                <div className="border-t pt-4">
                  <h3 className="font-medium mb-2">{currentInstruction.title}</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                    {currentInstruction.description}
                  </p>

                  {/* Commands */}
                  {currentInstruction.commands && (
                    <div className="mb-3">
                      <h4 className="text-sm font-medium mb-1">Commands:</h4>
                      <div className="bg-gray-100 dark:bg-gray-800 rounded p-2 text-sm font-mono">
                        {currentInstruction.commands.map((cmd, index) => (
                          <div key={index}>{cmd}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Expected Output */}
                  {currentInstruction.expected && (
                    <div className="mb-3">
                      <h4 className="text-sm font-medium mb-1">Expected:</h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        {currentInstruction.expected}
                      </p>
                    </div>
                  )}

                  {/* Hints */}
                  {currentInstruction.hints && currentInstruction.hints.length > 0 && (
                    <div className="mb-3">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={handleUseHint}
                        className="mb-2"
                      >
                        Show Hint ({hintsUsed} used)
                      </Button>
                      <AnimatePresence>
                        {showHints && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded p-2"
                          >
                            <div className="flex items-start gap-2">
                              <ExclamationTriangleIcon className="h-4 w-4 text-yellow-600 mt-0.5" />
                              <div className="text-sm">
                                {currentInstruction.hints.map((hint, index) => (
                                  <p key={index} className="mb-1 last:mb-0">
                                    {hint}
                                  </p>
                                ))}
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )}

                  {/* Submit Button */}
                  <Button
                    onClick={handleSubmitStep}
                    disabled={environmentStatus !== 'ready'}
                    className="w-full"
                  >
                    {isLastStep ? 'Complete Lab' : 'Next Step'}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Environment Panel */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CommandLineIcon className="h-5 w-5" />
                Lab Environment
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="environment">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="environment">Environment</TabsTrigger>
                  <TabsTrigger value="notes">Notes</TabsTrigger>
                  <TabsTrigger value="resources">Resources</TabsTrigger>
                </TabsList>

                <TabsContent value="environment" className="mt-4">
                  {environmentStatus === 'initializing' ? (
                    <div className="flex items-center justify-center h-64 border rounded-lg">
                      <div className="text-center">
                        <ArrowPathIcon className="h-8 w-8 text-blue-600 animate-spin mx-auto mb-2" />
                        <p className="text-gray-600 dark:text-gray-400">
                          Initializing environment...
                        </p>
                      </div>
                    </div>
                  ) : (
                    renderEnvironmentInterface()
                  )}
                </TabsContent>

                <TabsContent value="notes" className="mt-4">
                  <div className="space-y-4">
                    <Textarea
                      placeholder="Take notes about your lab work..."
                      className="min-h-[200px]"
                    />
                    <Button size="sm" variant="outline">
                      Save Notes
                    </Button>
                  </div>
                </TabsContent>

                <TabsContent value="resources" className="mt-4">
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <h4 className="font-medium mb-2">Environment Info</h4>
                        <div className="space-y-1 text-gray-600 dark:text-gray-400">
                          <div>Type: {environment.type}</div>
                          {environment.endpoint && (
                            <div>Endpoint: {environment.endpoint}</div>
                          )}
                          {environment.resources && (
                            <div>
                              Resources: {Object.entries(environment.resources).map(
                                ([key, value]) => `${key}: ${value}`
                              ).join(', ')}
                            </div>
                          )}
                        </div>
                      </div>
                      <div>
                        <h4 className="font-medium mb-2">Session Info</h4>
                        <div className="space-y-1 text-gray-600 dark:text-gray-400">
                          <div>Time Elapsed: {Math.round((Date.now() - startTime) / 1000 / 60)}m</div>
                          <div>Steps Completed: {completedSteps}/{instructions.length}</div>
                          <div>Hints Used: {hintsUsed}</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
