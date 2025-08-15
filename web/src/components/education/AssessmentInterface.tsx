'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  QuestionMarkCircleIcon,
  FlagIcon,
  ArrowLeftIcon,
  ArrowRightIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Checkbox } from '@/components/ui/checkbox'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'

interface AssessmentInterfaceProps {
  assessmentId: string
  title: string
  description: string
  questions: Question[]
  timeLimit?: number
  onComplete: (results: AssessmentResults) => void
  onSave?: (responses: QuestionResponse[]) => void
}

interface Question {
  id: string
  type: 'multiple_choice' | 'multiple_select' | 'short_answer' | 'essay' | 'code'
  title: string
  content: string
  points: number
  options?: QuestionOption[]
  correctAnswers?: string[]
  explanation?: string
  hints?: string[]
  codeLanguage?: string
  estimatedTime?: number
}

interface QuestionOption {
  id: string
  text: string
  isCorrect?: boolean
}

interface QuestionResponse {
  questionId: string
  response: any
  timeSpent: number
  confidence?: number
  flagged?: boolean
}

interface AssessmentResults {
  responses: QuestionResponse[]
  score: number
  maxScore: number
  timeSpent: number
  completed: boolean
}

export default function AssessmentInterface({
  assessmentId,
  title,
  description,
  questions,
  timeLimit,
  onComplete,
  onSave,
}: AssessmentInterfaceProps) {
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0)
  const [responses, setResponses] = useState<QuestionResponse[]>([])
  const [startTime] = useState(Date.now())
  const [questionStartTime, setQuestionStartTime] = useState(Date.now())
  const [timeRemaining, setTimeRemaining] = useState(timeLimit ? timeLimit * 60 : null)
  const [showResults, setShowResults] = useState(false)
  const [confidence, setConfidence] = useState(3)
  const [flaggedQuestions, setFlaggedQuestions] = useState<Set<string>>(new Set())

  const currentQuestion = questions[currentQuestionIndex]
  const currentResponse = responses.find(r => r.questionId === currentQuestion.id)
  const isLastQuestion = currentQuestionIndex === questions.length - 1
  const answeredQuestions = responses.filter(r => r.response !== null && r.response !== '').length

  // Timer effect
  useEffect(() => {
    if (!timeRemaining) return

    const timer = setInterval(() => {
      setTimeRemaining(prev => {
        if (prev && prev <= 1) {
          handleSubmitAssessment()
          return 0
        }
        return prev ? prev - 1 : null
      })
    }, 1000)

    return () => clearInterval(timer)
  }, [timeRemaining])

  // Reset question timer when question changes
  useEffect(() => {
    setQuestionStartTime(Date.now())
  }, [currentQuestionIndex])

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60)
    const secs = seconds % 60
    return `${mins}:${secs.toString().padStart(2, '0')}`
  }

  const handleResponseChange = (response: any) => {
    const timeSpent = Date.now() - questionStartTime
    const newResponse: QuestionResponse = {
      questionId: currentQuestion.id,
      response,
      timeSpent,
      confidence,
      flagged: flaggedQuestions.has(currentQuestion.id),
    }

    setResponses(prev => {
      const filtered = prev.filter(r => r.questionId !== currentQuestion.id)
      return [...filtered, newResponse]
    })

    onSave?.(responses)
  }

  const handleNextQuestion = () => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex(prev => prev + 1)
    }
  }

  const handlePreviousQuestion = () => {
    if (currentQuestionIndex > 0) {
      setCurrentQuestionIndex(prev => prev - 1)
    }
  }

  const handleFlagQuestion = () => {
    setFlaggedQuestions(prev => {
      const newSet = new Set(prev)
      if (newSet.has(currentQuestion.id)) {
        newSet.delete(currentQuestion.id)
      } else {
        newSet.add(currentQuestion.id)
      }
      return newSet
    })
  }

  const handleSubmitAssessment = () => {
    const totalTimeSpent = Date.now() - startTime
    const maxScore = questions.reduce((sum, q) => sum + q.points, 0)
    
    // Calculate score (simplified)
    const score = responses.reduce((sum, response) => {
      const question = questions.find(q => q.id === response.questionId)
      if (!question) return sum
      
      // Simple scoring logic - in real app this would be more sophisticated
      if (question.type === 'multiple_choice' && question.correctAnswers) {
        return sum + (question.correctAnswers.includes(response.response) ? question.points : 0)
      }
      
      return sum + (question.points * 0.8) // Partial credit for other types
    }, 0)

    const results: AssessmentResults = {
      responses,
      score,
      maxScore,
      timeSpent: totalTimeSpent,
      completed: true,
    }

    setShowResults(true)
    onComplete(results)
  }

  const renderQuestionContent = () => {
    switch (currentQuestion.type) {
      case 'multiple_choice':
        return (
          <RadioGroup
            value={currentResponse?.response || ''}
            onValueChange={handleResponseChange}
          >
            <div className="space-y-3">
              {currentQuestion.options?.map((option) => (
                <div key={option.id} className="flex items-center space-x-2">
                  <RadioGroupItem value={option.id} id={option.id} />
                  <Label htmlFor={option.id} className="flex-1 cursor-pointer">
                    {option.text}
                  </Label>
                </div>
              ))}
            </div>
          </RadioGroup>
        )

      case 'multiple_select':
        const selectedOptions = currentResponse?.response || []
        return (
          <div className="space-y-3">
            {currentQuestion.options?.map((option) => (
              <div key={option.id} className="flex items-center space-x-2">
                <Checkbox
                  id={option.id}
                  checked={selectedOptions.includes(option.id)}
                  onCheckedChange={(checked) => {
                    const newSelection = checked
                      ? [...selectedOptions, option.id]
                      : selectedOptions.filter((id: string) => id !== option.id)
                    handleResponseChange(newSelection)
                  }}
                />
                <Label htmlFor={option.id} className="flex-1 cursor-pointer">
                  {option.text}
                </Label>
              </div>
            ))}
          </div>
        )

      case 'short_answer':
        return (
          <Textarea
            placeholder="Enter your answer..."
            value={currentResponse?.response || ''}
            onChange={(e) => handleResponseChange(e.target.value)}
            className="min-h-[100px]"
          />
        )

      case 'essay':
        return (
          <Textarea
            placeholder="Write your essay response..."
            value={currentResponse?.response || ''}
            onChange={(e) => handleResponseChange(e.target.value)}
            className="min-h-[200px]"
          />
        )

      case 'code':
        return (
          <div className="space-y-2">
            <Label>Code ({currentQuestion.codeLanguage || 'text'})</Label>
            <Textarea
              placeholder={`Write your ${currentQuestion.codeLanguage || 'code'} here...`}
              value={currentResponse?.response || ''}
              onChange={(e) => handleResponseChange(e.target.value)}
              className="min-h-[150px] font-mono text-sm"
            />
          </div>
        )

      default:
        return <div>Unsupported question type</div>
    }
  }

  if (showResults) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="space-y-6"
      >
        <Card>
          <CardHeader className="text-center">
            <CardTitle className="text-2xl text-green-600">Assessment Complete!</CardTitle>
            <CardDescription>
              You have successfully completed the assessment
            </CardDescription>
          </CardHeader>
          <CardContent className="text-center space-y-4">
            <div className="text-4xl font-bold text-green-600">
              {Math.round((responses.reduce((sum, r) => sum + (r.response ? 1 : 0), 0) / questions.length) * 100)}%
            </div>
            <div className="text-gray-600 dark:text-gray-400">
              {answeredQuestions} of {questions.length} questions answered
            </div>
            <div className="grid grid-cols-2 gap-4 max-w-md mx-auto">
              <div className="text-center">
                <div className="text-lg font-semibold">Time Spent</div>
                <div className="text-gray-600 dark:text-gray-400">
                  {formatTime(Math.floor((Date.now() - startTime) / 1000))}
                </div>
              </div>
              <div className="text-center">
                <div className="text-lg font-semibold">Flagged</div>
                <div className="text-gray-600 dark:text-gray-400">
                  {flaggedQuestions.size} questions
                </div>
              </div>
            </div>
            <Button onClick={() => window.location.reload()}>
              View Detailed Results
            </Button>
          </CardContent>
        </Card>
      </motion.div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Assessment Header */}
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between">
            <div>
              <CardTitle className="text-xl">{title}</CardTitle>
              <CardDescription className="mt-2">{description}</CardDescription>
            </div>
            <div className="flex items-center gap-4">
              {timeRemaining && (
                <div className="flex items-center gap-2 text-orange-600">
                  <ClockIcon className="h-4 w-4" />
                  <span className="font-mono">{formatTime(timeRemaining)}</span>
                </div>
              )}
              <Badge variant="outline">
                Question {currentQuestionIndex + 1} of {questions.length}
              </Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span>Progress</span>
                <span>{Math.round(((currentQuestionIndex + 1) / questions.length) * 100)}%</span>
              </div>
              <Progress value={((currentQuestionIndex + 1) / questions.length) * 100} />
            </div>
            <div className="text-sm text-gray-600 dark:text-gray-400">
              {answeredQuestions} of {questions.length} questions answered
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Question Navigation */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Questions</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-5 lg:grid-cols-1 gap-2">
                {questions.map((question, index) => {
                  const hasResponse = responses.some(r => r.questionId === question.id && r.response)
                  const isFlagged = flaggedQuestions.has(question.id)
                  const isCurrent = index === currentQuestionIndex
                  
                  return (
                    <button
                      key={question.id}
                      onClick={() => setCurrentQuestionIndex(index)}
                      className={`relative p-2 rounded-lg text-sm font-medium transition-colors ${
                        isCurrent
                          ? 'bg-blue-600 text-white'
                          : hasResponse
                          ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'
                          : 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'
                      }`}
                    >
                      {index + 1}
                      {isFlagged && (
                        <FlagIcon className="absolute -top-1 -right-1 h-3 w-3 text-orange-500" />
                      )}
                    </button>
                  )
                })}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Question Content */}
        <div className="lg:col-span-3">
          <Card>
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <QuestionMarkCircleIcon className="h-5 w-5 text-blue-600" />
                    <CardTitle className="text-lg">
                      Question {currentQuestionIndex + 1}
                    </CardTitle>
                    <Badge variant="outline">{currentQuestion.points} pts</Badge>
                  </div>
                  <CardDescription className="text-base">
                    {currentQuestion.content}
                  </CardDescription>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={handleFlagQuestion}
                  className={flaggedQuestions.has(currentQuestion.id) ? 'text-orange-600' : ''}
                >
                  <FlagIcon className="h-4 w-4" />
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Question Response */}
              <div>
                <Label className="text-base font-medium mb-4 block">
                  {currentQuestion.title}
                </Label>
                {renderQuestionContent()}
              </div>

              {/* Confidence Slider */}
              <div>
                <Label className="text-sm font-medium mb-2 block">
                  Confidence Level: {confidence}/5
                </Label>
                <input
                  type="range"
                  min="1"
                  max="5"
                  value={confidence}
                  onChange={(e) => setConfidence(parseInt(e.target.value))}
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-gray-500 mt-1">
                  <span>Not confident</span>
                  <span>Very confident</span>
                </div>
              </div>

              {/* Navigation */}
              <div className="flex items-center justify-between pt-4 border-t">
                <Button
                  variant="outline"
                  onClick={handlePreviousQuestion}
                  disabled={currentQuestionIndex === 0}
                >
                  <ArrowLeftIcon className="h-4 w-4 mr-1" />
                  Previous
                </Button>

                <div className="flex gap-2">
                  {isLastQuestion ? (
                    <Button onClick={handleSubmitAssessment} className="bg-green-600 hover:bg-green-700">
                      Submit Assessment
                    </Button>
                  ) : (
                    <Button onClick={handleNextQuestion}>
                      Next
                      <ArrowRightIcon className="h-4 w-4 ml-1" />
                    </Button>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
