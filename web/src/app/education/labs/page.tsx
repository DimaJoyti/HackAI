'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  BeakerIcon,
  PlayIcon,
  ClockIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  CpuChipIcon,
  ServerIcon,
  CodeBracketIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

// Mock lab data
const labs = [
  {
    id: 1,
    title: 'Prompt Injection Attack Lab',
    description: 'Learn to identify and exploit prompt injection vulnerabilities in AI systems through hands-on testing.',
    category: 'Prompt Security',
    difficulty: 'Intermediate',
    estimatedTime: '90 minutes',
    environment: 'AI Chat Interface',
    status: 'available',
    progress: 0,
    isCompleted: false,
    prerequisites: ['AI Security Fundamentals'],
    objectives: [
      'Identify prompt injection vulnerabilities',
      'Execute successful injection attacks',
      'Implement defensive measures',
      'Validate security controls'
    ],
    tools: ['Custom AI Model', 'Security Scanner', 'Log Analyzer'],
    skills: ['Prompt Engineering', 'Security Testing', 'Vulnerability Assessment'],
    rating: 4.8,
    completions: 1234,
    lastUpdated: '2024-01-10',
  },
  {
    id: 2,
    title: 'AI Model Security Assessment',
    description: 'Comprehensive security testing of machine learning models including adversarial attacks and model extraction.',
    category: 'Model Security',
    difficulty: 'Advanced',
    estimatedTime: '2 hours',
    environment: 'Jupyter Notebook',
    status: 'in_progress',
    progress: 45,
    isCompleted: false,
    prerequisites: ['AI Security Fundamentals', 'Python Programming'],
    objectives: [
      'Perform model reconnaissance',
      'Generate adversarial examples',
      'Test model robustness',
      'Document security findings'
    ],
    tools: ['TensorFlow', 'PyTorch', 'Adversarial Robustness Toolbox'],
    skills: ['Machine Learning', 'Security Testing', 'Python'],
    rating: 4.9,
    completions: 856,
    lastUpdated: '2024-01-08',
  },
  {
    id: 3,
    title: 'Data Privacy Protection Lab',
    description: 'Implement differential privacy and other privacy-preserving techniques in machine learning workflows.',
    category: 'Privacy',
    difficulty: 'Expert',
    estimatedTime: '2.5 hours',
    environment: 'Cloud Environment',
    status: 'available',
    progress: 0,
    isCompleted: false,
    prerequisites: ['Statistics', 'Machine Learning', 'Cryptography Basics'],
    objectives: [
      'Implement differential privacy',
      'Configure privacy budgets',
      'Test privacy guarantees',
      'Measure utility trade-offs'
    ],
    tools: ['Opacus', 'TensorFlow Privacy', 'PySyft'],
    skills: ['Privacy Engineering', 'Differential Privacy', 'Secure Computation'],
    rating: 4.7,
    completions: 432,
    lastUpdated: '2024-01-05',
  },
  {
    id: 4,
    title: 'AI Red Team Exercise',
    description: 'Conduct a comprehensive red team assessment of an AI-powered application with realistic attack scenarios.',
    category: 'Red Teaming',
    difficulty: 'Expert',
    estimatedTime: '3 hours',
    environment: 'Virtual Network',
    status: 'locked',
    progress: 0,
    isCompleted: false,
    prerequisites: ['AI Model Security Assessment', 'Network Security'],
    objectives: [
      'Plan attack scenarios',
      'Execute multi-vector attacks',
      'Bypass security controls',
      'Generate assessment report'
    ],
    tools: ['Metasploit', 'Burp Suite', 'Custom AI Tools'],
    skills: ['Red Teaming', 'Penetration Testing', 'Attack Planning'],
    rating: 4.6,
    completions: 234,
    lastUpdated: '2024-01-03',
  },
  {
    id: 5,
    title: 'Secure AI Development Pipeline',
    description: 'Build a secure CI/CD pipeline for AI model development with integrated security testing and monitoring.',
    category: 'DevSecOps',
    difficulty: 'Advanced',
    estimatedTime: '2 hours',
    environment: 'Docker Environment',
    status: 'available',
    progress: 0,
    isCompleted: false,
    prerequisites: ['DevOps Fundamentals', 'Container Security'],
    objectives: [
      'Set up secure development environment',
      'Implement automated security testing',
      'Configure monitoring and alerting',
      'Deploy with security controls'
    ],
    tools: ['Docker', 'Jenkins', 'SonarQube', 'OWASP ZAP'],
    skills: ['DevSecOps', 'Container Security', 'CI/CD'],
    rating: 4.5,
    completions: 678,
    lastUpdated: '2024-01-01',
  },
  {
    id: 6,
    title: 'Federated Learning Security',
    description: 'Explore security challenges in federated learning systems and implement protection mechanisms.',
    category: 'Distributed AI',
    difficulty: 'Expert',
    estimatedTime: '2.5 hours',
    environment: 'Multi-node Cluster',
    status: 'completed',
    progress: 100,
    isCompleted: true,
    prerequisites: ['Distributed Systems', 'Machine Learning', 'Cryptography'],
    objectives: [
      'Set up federated learning environment',
      'Implement secure aggregation',
      'Test against poisoning attacks',
      'Validate privacy guarantees'
    ],
    tools: ['TensorFlow Federated', 'PySyft', 'Flower'],
    skills: ['Federated Learning', 'Secure Aggregation', 'Privacy'],
    rating: 4.8,
    completions: 345,
    lastUpdated: '2023-12-28',
  },
]

const categories = ['All', 'Prompt Security', 'Model Security', 'Privacy', 'Red Teaming', 'DevSecOps', 'Distributed AI']
const difficulties = ['All', 'Beginner', 'Intermediate', 'Advanced', 'Expert']
const statuses = ['All', 'Available', 'In Progress', 'Completed', 'Locked']

export default function LabsPage() {
  const [selectedCategory, setSelectedCategory] = useState('All')
  const [selectedDifficulty, setSelectedDifficulty] = useState('All')
  const [selectedStatus, setSelectedStatus] = useState('All')
  const [filteredLabs, setFilteredLabs] = useState(labs)

  useEffect(() => {
    let filtered = labs.filter(lab => {
      const matchesCategory = selectedCategory === 'All' || lab.category === selectedCategory
      const matchesDifficulty = selectedDifficulty === 'All' || lab.difficulty === selectedDifficulty
      const matchesStatus = selectedStatus === 'All' || 
        (selectedStatus === 'Available' && lab.status === 'available') ||
        (selectedStatus === 'In Progress' && lab.status === 'in_progress') ||
        (selectedStatus === 'Completed' && lab.status === 'completed') ||
        (selectedStatus === 'Locked' && lab.status === 'locked')
      
      return matchesCategory && matchesDifficulty && matchesStatus
    })

    setFilteredLabs(filtered)
  }, [selectedCategory, selectedDifficulty, selectedStatus])

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'available':
        return <PlayIcon className="h-4 w-4 text-green-600" />
      case 'in_progress':
        return <ClockIcon className="h-4 w-4 text-blue-600" />
      case 'completed':
        return <CheckCircleIcon className="h-4 w-4 text-green-600" />
      case 'locked':
        return <ExclamationTriangleIcon className="h-4 w-4 text-gray-400" />
      default:
        return null
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'available':
        return <Badge variant="secondary">Available</Badge>
      case 'in_progress':
        return <Badge variant="default">In Progress</Badge>
      case 'completed':
        return <Badge variant="outline" className="text-green-600 border-green-600">Completed</Badge>
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Hands-on Labs</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Practice AI security skills in realistic environments
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-sm">
            {filteredLabs.length} labs
          </Badge>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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

      {/* Labs Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {filteredLabs.map((lab, index) => (
          <motion.div
            key={lab.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <Card className="h-full hover:shadow-lg transition-shadow duration-200">
              <CardHeader>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <BeakerIcon className="h-5 w-5 text-blue-600" />
                      <CardTitle className="text-lg">{lab.title}</CardTitle>
                    </div>
                    <CardDescription className="text-sm">
                      {lab.description}
                    </CardDescription>
                  </div>
                  <div className="flex flex-col items-end gap-2">
                    {getStatusBadge(lab.status)}
                    <Badge className={`text-xs ${getDifficultyColor(lab.difficulty)}`}>
                      {lab.difficulty}
                    </Badge>
                  </div>
                </div>
              </CardHeader>

              <CardContent className="space-y-4">
                {/* Progress Bar (if in progress) */}
                {lab.status === 'in_progress' && (
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Progress</span>
                      <span>{lab.progress}%</span>
                    </div>
                    <Progress value={lab.progress} />
                  </div>
                )}

                {/* Lab Info */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div className="flex items-center gap-2">
                    <ClockIcon className="h-4 w-4 text-gray-400" />
                    <span>{lab.estimatedTime}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <ServerIcon className="h-4 w-4 text-gray-400" />
                    <span>{lab.environment}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <ShieldCheckIcon className="h-4 w-4 text-gray-400" />
                    <span>{lab.completions} completed</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CpuChipIcon className="h-4 w-4 text-gray-400" />
                    <span>★ {lab.rating}</span>
                  </div>
                </div>

                {/* Objectives */}
                <div>
                  <h4 className="text-sm font-medium mb-2">Learning Objectives</h4>
                  <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                    {lab.objectives.slice(0, 3).map((objective, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-blue-600 mt-1">•</span>
                        <span>{objective}</span>
                      </li>
                    ))}
                    {lab.objectives.length > 3 && (
                      <li className="text-xs text-gray-500">
                        +{lab.objectives.length - 3} more objectives
                      </li>
                    )}
                  </ul>
                </div>

                {/* Tools */}
                <div>
                  <h4 className="text-sm font-medium mb-2">Tools & Technologies</h4>
                  <div className="flex flex-wrap gap-1">
                    {lab.tools.map(tool => (
                      <Badge key={tool} variant="outline" className="text-xs">
                        {tool}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Prerequisites */}
                {lab.prerequisites.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Prerequisites</h4>
                    <div className="flex flex-wrap gap-1">
                      {lab.prerequisites.map(prereq => (
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
                    disabled={lab.status === 'locked'}
                    variant={lab.status === 'completed' ? 'outline' : 'default'}
                  >
                    <div className="flex items-center gap-2">
                      {getStatusIcon(lab.status)}
                      {lab.status === 'available' && 'Start Lab'}
                      {lab.status === 'in_progress' && 'Continue Lab'}
                      {lab.status === 'completed' && 'Review Lab'}
                      {lab.status === 'locked' && 'Complete Prerequisites'}
                    </div>
                  </Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Empty State */}
      {filteredLabs.length === 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center py-12"
        >
          <BeakerIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            No labs found
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Try adjusting your filters to see more labs
          </p>
          <Button 
            variant="outline" 
            onClick={() => {
              setSelectedCategory('All')
              setSelectedDifficulty('All')
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
