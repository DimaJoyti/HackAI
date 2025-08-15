'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  BookOpenIcon,
  ClockIcon,
  UserGroupIcon,
  StarIcon,
  PlayIcon,
  CheckCircleIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

// Mock course data
const courses = [
  {
    id: 1,
    title: 'AI Security Fundamentals',
    description: 'Learn the basics of AI security, threat modeling, and common vulnerabilities in machine learning systems.',
    instructor: 'Dr. Sarah Chen',
    level: 'Beginner',
    duration: '6h 30m',
    modules: 8,
    enrolled: 2341,
    rating: 4.8,
    reviews: 156,
    price: 'Free',
    category: 'Fundamentals',
    tags: ['AI Security', 'Machine Learning', 'Threat Modeling'],
    thumbnail: '/api/placeholder/400/200',
    progress: 0,
    isEnrolled: false,
    lastUpdated: '2024-01-10',
    skills: ['Threat Assessment', 'Security Analysis', 'Risk Management'],
    prerequisites: [],
    certificate: true,
  },
  {
    id: 2,
    title: 'Advanced Prompt Engineering Security',
    description: 'Deep dive into prompt injection attacks, defense mechanisms, and secure prompt design patterns.',
    instructor: 'Prof. Michael Rodriguez',
    level: 'Intermediate',
    duration: '4h 45m',
    modules: 6,
    enrolled: 1876,
    rating: 4.9,
    reviews: 203,
    price: '$49',
    category: 'Prompt Security',
    tags: ['Prompt Injection', 'LLM Security', 'Defense Strategies'],
    thumbnail: '/api/placeholder/400/200',
    progress: 65,
    isEnrolled: true,
    lastUpdated: '2024-01-08',
    skills: ['Prompt Engineering', 'Attack Detection', 'Security Design'],
    prerequisites: ['AI Security Fundamentals'],
    certificate: true,
  },
  {
    id: 3,
    title: 'AI Model Security Assessment',
    description: 'Comprehensive course on testing AI models for vulnerabilities, including adversarial attacks and model extraction.',
    instructor: 'Dr. Emily Watson',
    level: 'Advanced',
    duration: '8h 15m',
    modules: 12,
    enrolled: 943,
    rating: 4.7,
    reviews: 87,
    price: '$99',
    category: 'Security Testing',
    tags: ['Model Testing', 'Adversarial Attacks', 'Security Assessment'],
    thumbnail: '/api/placeholder/400/200',
    progress: 0,
    isEnrolled: false,
    lastUpdated: '2024-01-05',
    skills: ['Security Testing', 'Vulnerability Assessment', 'Penetration Testing'],
    prerequisites: ['AI Security Fundamentals', 'Advanced Prompt Engineering Security'],
    certificate: true,
  },
  {
    id: 4,
    title: 'Privacy-Preserving AI Techniques',
    description: 'Learn differential privacy, federated learning, and other techniques to protect data privacy in AI systems.',
    instructor: 'Dr. James Liu',
    level: 'Expert',
    duration: '10h 30m',
    modules: 15,
    enrolled: 567,
    rating: 4.6,
    reviews: 45,
    price: '$149',
    category: 'Privacy',
    tags: ['Differential Privacy', 'Federated Learning', 'Data Protection'],
    thumbnail: '/api/placeholder/400/200',
    progress: 0,
    isEnrolled: false,
    lastUpdated: '2024-01-03',
    skills: ['Privacy Engineering', 'Cryptography', 'Secure Computation'],
    prerequisites: ['AI Security Fundamentals', 'AI Model Security Assessment'],
    certificate: true,
  },
  {
    id: 5,
    title: 'AI Red Team Operations',
    description: 'Hands-on course on conducting red team exercises against AI systems and developing attack scenarios.',
    instructor: 'Alex Thompson',
    level: 'Expert',
    duration: '12h 45m',
    modules: 18,
    enrolled: 234,
    rating: 4.9,
    reviews: 28,
    price: '$199',
    category: 'Red Teaming',
    tags: ['Red Team', 'Attack Simulation', 'Security Operations'],
    thumbnail: '/api/placeholder/400/200',
    progress: 0,
    isEnrolled: false,
    lastUpdated: '2024-01-01',
    skills: ['Red Teaming', 'Attack Planning', 'Security Operations'],
    prerequisites: ['AI Model Security Assessment'],
    certificate: true,
  },
  {
    id: 6,
    title: 'Secure AI Development Lifecycle',
    description: 'Integrate security practices into AI development from design to deployment and monitoring.',
    instructor: 'Dr. Rachel Green',
    level: 'Intermediate',
    duration: '7h 20m',
    modules: 10,
    enrolled: 1456,
    rating: 4.5,
    reviews: 112,
    price: '$79',
    category: 'Development',
    tags: ['Secure Development', 'DevSecOps', 'AI Lifecycle'],
    thumbnail: '/api/placeholder/400/200',
    progress: 0,
    isEnrolled: false,
    lastUpdated: '2023-12-28',
    skills: ['Secure Development', 'DevSecOps', 'Security Architecture'],
    prerequisites: ['AI Security Fundamentals'],
    certificate: true,
  },
]

const categories = ['All', 'Fundamentals', 'Prompt Security', 'Security Testing', 'Privacy', 'Red Teaming', 'Development']
const levels = ['All', 'Beginner', 'Intermediate', 'Advanced', 'Expert']
const sortOptions = ['Newest', 'Popular', 'Rating', 'Duration']

export default function CoursesPage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('All')
  const [selectedLevel, setSelectedLevel] = useState('All')
  const [sortBy, setSortBy] = useState('Popular')
  const [filteredCourses, setFilteredCourses] = useState(courses)

  useEffect(() => {
    let filtered = courses.filter(course => {
      const matchesSearch = course.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           course.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           course.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()))
      
      const matchesCategory = selectedCategory === 'All' || course.category === selectedCategory
      const matchesLevel = selectedLevel === 'All' || course.level === selectedLevel
      
      return matchesSearch && matchesCategory && matchesLevel
    })

    // Sort courses
    switch (sortBy) {
      case 'Newest':
        filtered.sort((a, b) => new Date(b.lastUpdated).getTime() - new Date(a.lastUpdated).getTime())
        break
      case 'Popular':
        filtered.sort((a, b) => b.enrolled - a.enrolled)
        break
      case 'Rating':
        filtered.sort((a, b) => b.rating - a.rating)
        break
      case 'Duration':
        filtered.sort((a, b) => {
          const getDuration = (duration: string) => {
            const hours = parseInt(duration.split('h')[0])
            const minutes = parseInt(duration.split('h')[1]?.split('m')[0] || '0')
            return hours * 60 + minutes
          }
          return getDuration(a.duration) - getDuration(b.duration)
        })
        break
    }

    setFilteredCourses(filtered)
  }, [searchQuery, selectedCategory, selectedLevel, sortBy])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Courses</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Discover and enroll in AI security courses
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-sm">
            {filteredCourses.length} courses
          </Badge>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Search */}
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search courses..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>

            {/* Category Filter */}
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

            {/* Level Filter */}
            <Select value={selectedLevel} onValueChange={setSelectedLevel}>
              <SelectTrigger>
                <SelectValue placeholder="Level" />
              </SelectTrigger>
              <SelectContent>
                {levels.map(level => (
                  <SelectItem key={level} value={level}>
                    {level}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Sort */}
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger>
                <SelectValue placeholder="Sort by" />
              </SelectTrigger>
              <SelectContent>
                {sortOptions.map(option => (
                  <SelectItem key={option} value={option}>
                    {option}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Course Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredCourses.map((course, index) => (
          <motion.div
            key={course.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <Card className="h-full hover:shadow-lg transition-shadow duration-200">
              <div className="relative">
                <div className="aspect-video bg-gradient-to-br from-blue-500 to-purple-600 rounded-t-lg flex items-center justify-center">
                  <BookOpenIcon className="h-12 w-12 text-white" />
                </div>
                {course.isEnrolled && (
                  <Badge className="absolute top-2 right-2 bg-green-600">
                    Enrolled
                  </Badge>
                )}
                {course.progress > 0 && (
                  <div className="absolute bottom-0 left-0 right-0 bg-black bg-opacity-50 text-white text-xs p-2">
                    Progress: {course.progress}%
                  </div>
                )}
              </div>

              <CardHeader className="pb-3">
                <div className="flex items-start justify-between gap-2">
                  <CardTitle className="text-lg leading-tight">{course.title}</CardTitle>
                  <Badge variant={course.level === 'Beginner' ? 'secondary' : 
                                 course.level === 'Intermediate' ? 'default' :
                                 course.level === 'Advanced' ? 'destructive' : 'outline'}>
                    {course.level}
                  </Badge>
                </div>
                <CardDescription className="text-sm line-clamp-2">
                  {course.description}
                </CardDescription>
              </CardHeader>

              <CardContent className="space-y-4">
                {/* Course Stats */}
                <div className="grid grid-cols-2 gap-4 text-sm text-gray-600 dark:text-gray-400">
                  <div className="flex items-center gap-1">
                    <ClockIcon className="h-4 w-4" />
                    <span>{course.duration}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <BookOpenIcon className="h-4 w-4" />
                    <span>{course.modules} modules</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <UserGroupIcon className="h-4 w-4" />
                    <span>{course.enrolled.toLocaleString()}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <StarIcon className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                    <span>{course.rating} ({course.reviews})</span>
                  </div>
                </div>

                {/* Tags */}
                <div className="flex flex-wrap gap-1">
                  {course.tags.slice(0, 3).map(tag => (
                    <Badge key={tag} variant="outline" className="text-xs">
                      {tag}
                    </Badge>
                  ))}
                </div>

                {/* Instructor */}
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  by {course.instructor}
                </div>

                {/* Price and Action */}
                <div className="flex items-center justify-between pt-2">
                  <div className="text-lg font-bold text-green-600">
                    {course.price}
                  </div>
                  <Button 
                    size="sm" 
                    variant={course.isEnrolled ? "outline" : "default"}
                    className="flex items-center gap-1"
                  >
                    {course.isEnrolled ? (
                      <>
                        <PlayIcon className="h-4 w-4" />
                        Continue
                      </>
                    ) : (
                      <>
                        <CheckCircleIcon className="h-4 w-4" />
                        Enroll
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Empty State */}
      {filteredCourses.length === 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center py-12"
        >
          <BookOpenIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            No courses found
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Try adjusting your search criteria or filters
          </p>
          <Button 
            variant="outline" 
            onClick={() => {
              setSearchQuery('')
              setSelectedCategory('All')
              setSelectedLevel('All')
            }}
          >
            Clear Filters
          </Button>
        </motion.div>
      )}
    </div>
  )
}
