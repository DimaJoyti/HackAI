'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  ClipboardDocumentCheckIcon,
  ClockIcon,
  QuestionMarkCircleIcon,
  CheckCircleIcon,
  XCircleIcon,
  PlayIcon,
  TrophyIcon,
  ChartBarIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

// Mock assessment data
const assessments = [
  {
    id: 1,
    title: 'AI Security Fundamentals Quiz',
    description: 'Test your understanding of basic AI security concepts, threat models, and common vulnerabilities.',
    type: 'quiz',
    category: 'Fundamentals',
    difficulty: 'Beginner',
    questions: 20,
    timeLimit: 45,
    passingScore: 70,
    maxAttempts: 3,
    attempts: 0,
    bestScore: null,
    status: 'available',
    prerequisites: ['AI Security Fundamentals Course'],
    topics: ['Threat Modeling', 'Common Vulnerabilities', 'Security Principles'],
    estimatedTime: '45 minutes',
    certificate: true,
    lastUpdated: '2024-01-10',
  },
  {
    id: 2,
    title: 'Prompt Injection Assessment',
    description: 'Comprehensive assessment of prompt injection attack techniques and defense mechanisms.',
    type: 'practical',
    category: 'Prompt Security',
    difficulty: 'Intermediate',
    questions: 15,
    timeLimit: 60,
    passingScore: 75,
    maxAttempts: 2,
    attempts: 1,
    bestScore: 82,
    status: 'completed',
    prerequisites: ['Advanced Prompt Engineering Security'],
    topics: ['Injection Techniques', 'Defense Strategies', 'Real-world Scenarios'],
    estimatedTime: '1 hour',
    certificate: true,
    lastUpdated: '2024-01-08',
  },
  {
    id: 3,
    title: 'AI Model Security Evaluation',
    description: 'Advanced assessment covering adversarial attacks, model extraction, and security testing methodologies.',
    type: 'comprehensive',
    category: 'Model Security',
    difficulty: 'Advanced',
    questions: 25,
    timeLimit: 90,
    passingScore: 80,
    maxAttempts: 2,
    attempts: 0,
    bestScore: null,
    status: 'locked',
    prerequisites: ['AI Model Security Assessment Course', 'Prompt Injection Assessment'],
    topics: ['Adversarial Attacks', 'Model Extraction', 'Security Testing', 'Vulnerability Assessment'],
    estimatedTime: '1.5 hours',
    certificate: true,
    lastUpdated: '2024-01-05',
  },
  {
    id: 4,
    title: 'Privacy-Preserving AI Techniques',
    description: 'Test your knowledge of differential privacy, federated learning, and other privacy-preserving methods.',
    type: 'technical',
    category: 'Privacy',
    difficulty: 'Expert',
    questions: 30,
    timeLimit: 120,
    passingScore: 85,
    maxAttempts: 1,
    attempts: 0,
    bestScore: null,
    status: 'available',
    prerequisites: ['Privacy-Preserving AI Techniques Course'],
    topics: ['Differential Privacy', 'Federated Learning', 'Secure Computation', 'Privacy Metrics'],
    estimatedTime: '2 hours',
    certificate: true,
    lastUpdated: '2024-01-03',
  },
  {
    id: 5,
    title: 'Red Team Operations Certification',
    description: 'Comprehensive certification exam for AI red team operations and attack simulation.',
    type: 'certification',
    category: 'Red Teaming',
    difficulty: 'Expert',
    questions: 50,
    timeLimit: 180,
    passingScore: 90,
    maxAttempts: 1,
    attempts: 0,
    bestScore: null,
    status: 'locked',
    prerequisites: ['AI Red Team Operations Course', 'AI Model Security Evaluation'],
    topics: ['Attack Planning', 'Simulation Techniques', 'Tool Usage', 'Report Writing'],
    estimatedTime: '3 hours',
    certificate: true,
    lastUpdated: '2024-01-01',
  },
  {
    id: 6,
    title: 'Secure Development Practices',
    description: 'Assessment of secure AI development lifecycle and DevSecOps practices.',
    type: 'practical',
    category: 'Development',
    difficulty: 'Intermediate',
    questions: 18,
    timeLimit: 75,
    passingScore: 75,
    maxAttempts: 3,
    attempts: 2,
    bestScore: 68,
    status: 'in_progress',
    prerequisites: ['Secure AI Development Lifecycle Course'],
    topics: ['Secure SDLC', 'DevSecOps', 'Security Testing', 'Deployment Security'],
    estimatedTime: '1.25 hours',
    certificate: false,
    lastUpdated: '2023-12-28',
  },
]

const categories = ['All', 'Fundamentals', 'Prompt Security', 'Model Security', 'Privacy', 'Red Teaming', 'Development']
const difficulties = ['All', 'Beginner', 'Intermediate', 'Advanced', 'Expert']
const types = ['All', 'Quiz', 'Practical', 'Technical', 'Comprehensive', 'Certification']
const statuses = ['All', 'Available', 'In Progress', 'Completed', 'Locked']

export default function AssessmentsPage() {
  const [selectedCategory, setSelectedCategory] = useState('All')
  const [selectedDifficulty, setSelectedDifficulty] = useState('All')
  const [selectedType, setSelectedType] = useState('All')
  const [selectedStatus, setSelectedStatus] = useState('All')
  const [filteredAssessments, setFilteredAssessments] = useState(assessments)

  useEffect(() => {
    let filtered = assessments.filter(assessment => {
      const matchesCategory = selectedCategory === 'All' || assessment.category === selectedCategory
      const matchesDifficulty = selectedDifficulty === 'All' || assessment.difficulty === selectedDifficulty
      const matchesType = selectedType === 'All' || assessment.type.toLowerCase() === selectedType.toLowerCase()
      const matchesStatus = selectedStatus === 'All' || 
        (selectedStatus === 'Available' && assessment.status === 'available') ||
        (selectedStatus === 'In Progress' && assessment.status === 'in_progress') ||
        (selectedStatus === 'Completed' && assessment.status === 'completed') ||
        (selectedStatus === 'Locked' && assessment.status === 'locked')
      
      return matchesCategory && matchesDifficulty && matchesType && matchesStatus
    })

    setFilteredAssessments(filtered)
  }, [selectedCategory, selectedDifficulty, selectedType, selectedStatus])

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'available':
        return <PlayIcon className="h-4 w-4 text-green-600" />
      case 'in_progress':
        return <ClockIcon className="h-4 w-4 text-blue-600" />
      case 'completed':
        return <CheckCircleIcon className="h-4 w-4 text-green-600" />
      case 'locked':
        return <XCircleIcon className="h-4 w-4 text-gray-400" />
      default:
        return null
    }
  }

  const getStatusBadge = (assessment: any) => {
    switch (assessment.status) {
      case 'available':
        return <Badge variant="secondary">Available</Badge>
      case 'in_progress':
        return <Badge variant="default">In Progress</Badge>
      case 'completed':
        return (
          <Badge variant="outline" className="text-green-600 border-green-600">
            Completed ({assessment.bestScore}%)
          </Badge>
        )
      case 'locked':
        return <Badge variant="outline" className="text-gray-400 border-gray-400">Locked</Badge>
      default:
        return null
    }
  }

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'Beginner':
        return 'text-green-600 bg-green-50 border-green-200'
      case 'Intermediate':
        return 'text-blue-600 bg-blue-50 border-blue-200'
      case 'Advanced':
        return 'text-orange-600 bg-orange-50 border-orange-200'
      case 'Expert':
        return 'text-red-600 bg-red-50 border-red-200'
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200'
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'quiz':
        return <QuestionMarkCircleIcon className="h-4 w-4" />
      case 'practical':
        return <ClipboardDocumentCheckIcon className="h-4 w-4" />
      case 'technical':
        return <ChartBarIcon className="h-4 w-4" />
      case 'comprehensive':
        return <ClipboardDocumentCheckIcon className="h-4 w-4" />
      case 'certification':
        return <TrophyIcon className="h-4 w-4" />
      default:
        return <ClipboardDocumentCheckIcon className="h-4 w-4" />
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Assessments</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Test your knowledge and earn certifications
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-sm">
            {filteredAssessments.length} assessments
          </Badge>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Select value={selectedCategory} onValueChange={setSelectedCategory}>
              <SelectTrigger>
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent>
                {categories.map(category => (
                  <SelectItem key={category} value={category}>
                    {category}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={selectedDifficulty} onValueChange={setSelectedDifficulty}>
              <SelectTrigger>
                <SelectValue placeholder="Difficulty" />
              </SelectTrigger>
              <SelectContent>
                {difficulties.map(difficulty => (
                  <SelectItem key={difficulty} value={difficulty}>
                    {difficulty}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={selectedType} onValueChange={setSelectedType}>
              <SelectTrigger>
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                {types.map(type => (
                  <SelectItem key={type} value={type}>
                    {type}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={selectedStatus} onValueChange={setSelectedStatus}>
              <SelectTrigger>
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                {statuses.map(status => (
                  <SelectItem key={status} value={status}>
                    {status}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Assessments Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {filteredAssessments.map((assessment, index) => (
          <motion.div
            key={assessment.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <Card className="h-full hover:shadow-lg transition-shadow duration-200">
              <CardHeader>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      {getTypeIcon(assessment.type)}
                      <CardTitle className="text-lg">{assessment.title}</CardTitle>
                      {assessment.certificate && (
                        <TrophyIcon className="h-4 w-4 text-yellow-500" />
                      )}
                    </div>
                    <CardDescription className="text-sm">
                      {assessment.description}
                    </CardDescription>
                  </div>
                  <div className="flex flex-col items-end gap-2">
                    {getStatusBadge(assessment)}
                    <Badge className={`text-xs ${getDifficultyColor(assessment.difficulty)}`}>
                      {assessment.difficulty}
                    </Badge>
                  </div>
                </div>
              </CardHeader>

              <CardContent className="space-y-4">
                {/* Assessment Info */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div className="flex items-center gap-2">
                    <QuestionMarkCircleIcon className="h-4 w-4 text-gray-400" />
                    <span>{assessment.questions} questions</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <ClockIcon className="h-4 w-4 text-gray-400" />
                    <span>{assessment.timeLimit} minutes</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircleIcon className="h-4 w-4 text-gray-400" />
                    <span>{assessment.passingScore}% to pass</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <ClipboardDocumentCheckIcon className="h-4 w-4 text-gray-400" />
                    <span>{assessment.maxAttempts} attempts</span>
                  </div>
                </div>

                {/* Attempt History */}
                {assessment.attempts > 0 && (
                  <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
                    <div className="flex justify-between items-center text-sm">
                      <span>Attempts: {assessment.attempts}/{assessment.maxAttempts}</span>
                      {assessment.bestScore && (
                        <span className={`font-medium ${assessment.bestScore >= assessment.passingScore ? 'text-green-600' : 'text-red-600'}`}>
                          Best: {assessment.bestScore}%
                        </span>
                      )}
                    </div>
                    {assessment.bestScore && (
                      <div className="mt-2">
                        <Progress 
                          value={assessment.bestScore} 
                          className={`h-2 ${assessment.bestScore >= assessment.passingScore ? 'bg-green-200' : 'bg-red-200'}`}
                        />
                      </div>
                    )}
                  </div>
                )}

                {/* Topics */}
                <div>
                  <h4 className="text-sm font-medium mb-2">Topics Covered</h4>
                  <div className="flex flex-wrap gap-1">
                    {assessment.topics.map(topic => (
                      <Badge key={topic} variant="outline" className="text-xs">
                        {topic}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Prerequisites */}
                {assessment.prerequisites.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Prerequisites</h4>
                    <div className="flex flex-wrap gap-1">
                      {assessment.prerequisites.map(prereq => (
                        <Badge key={prereq} variant="secondary" className="text-xs">
                          {prereq}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Action Button */}
                <div className="pt-4">
                  <Button 
                    className="w-full" 
                    disabled={assessment.status === 'locked' || (assessment.attempts >= assessment.maxAttempts && assessment.status !== 'completed')}
                    variant={assessment.status === 'completed' ? 'outline' : 'default'}
                  >
                    <div className="flex items-center gap-2">
                      {getStatusIcon(assessment.status)}
                      {assessment.status === 'available' && 'Start Assessment'}
                      {assessment.status === 'in_progress' && 'Continue Assessment'}
                      {assessment.status === 'completed' && 'Review Results'}
                      {assessment.status === 'locked' && 'Complete Prerequisites'}
                      {assessment.attempts >= assessment.maxAttempts && assessment.status !== 'completed' && 'No Attempts Left'}
                    </div>
                  </Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Empty State */}
      {filteredAssessments.length === 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center py-12"
        >
          <ClipboardDocumentCheckIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            No assessments found
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Try adjusting your filters to see more assessments
          </p>
          <Button 
            variant="outline" 
            onClick={() => {
              setSelectedCategory('All')
              setSelectedDifficulty('All')
              setSelectedType('All')
              setSelectedStatus('All')
            }}
          >
            Clear Filters
          </Button>
        </motion.div>
      )}
    </div>
  )
}
