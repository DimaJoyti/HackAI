'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import Link from 'next/link'
import {
  BookOpenIcon,
  ClockIcon,
  UserGroupIcon,
  StarIcon,
  PlayIcon,
  CheckCircleIcon,
  AcademicCapIcon,
  ChartBarIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  BeakerIcon,
  GlobeAltIcon,
  LockClosedIcon,
  EyeIcon,
  DocumentTextIcon,
  TrophyIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Input } from '@/components/ui/input'
import { useAuth } from '@/hooks/use-auth'

// Comprehensive course data for AI Security Learning Management System
const courses = [
  {
    id: 1,
    title: 'AI Security Fundamentals',
    description: 'Master the essential concepts of AI security, including threat modeling, vulnerability assessment, and defense strategies for AI systems.',
    level: 'Beginner',
    duration: '8 hours',
    modules: 12,
    enrolled: 1247,
    rating: 4.8,
    reviews: 156,
    progress: 0,
    category: 'AI Security',
    instructor: 'Dr. Sarah Chen',
    instructorAvatar: '/instructors/sarah-chen.jpg',
    thumbnail: '/courses/ai-security-fundamentals.jpg',
    price: 'Free',
    skills: ['Threat Modeling', 'Risk Assessment', 'Security Frameworks'],
    prerequisites: ['Basic Programming', 'Computer Science Fundamentals'],
    certification: true,
    difficulty: 1,
    tags: ['AI', 'Security', 'Fundamentals', 'Beginner'],
    lastUpdated: '2024-01-15',
    language: 'English',
    subtitles: ['English', 'Spanish', 'French'],
  },
  {
    id: 2,
    title: 'Advanced AI Red Teaming',
    description: 'Learn sophisticated techniques for testing AI system security through adversarial attacks, model inversion, and advanced penetration testing.',
    level: 'Advanced',
    duration: '16 hours',
    modules: 24,
    enrolled: 892,
    rating: 4.9,
    reviews: 98,
    progress: 100,
    category: 'Red Teaming',
    instructor: 'Prof. Marcus Rodriguez',
    instructorAvatar: '/instructors/marcus-rodriguez.jpg',
    thumbnail: '/courses/ai-red-teaming.jpg',
    price: '$199',
    skills: ['Adversarial Attacks', 'Model Inversion', 'Penetration Testing'],
    prerequisites: ['AI Security Fundamentals', 'Machine Learning Basics'],
    certification: true,
    difficulty: 4,
    tags: ['Red Team', 'Advanced', 'Adversarial', 'Penetration Testing'],
    lastUpdated: '2024-01-10',
    language: 'English',
    subtitles: ['English', 'Spanish'],
  },
  {
    id: 3,
    title: 'Machine Learning Security',
    description: 'Protect ML models from adversarial attacks, data poisoning, and model extraction. Learn defensive techniques and secure ML deployment.',
    level: 'Intermediate',
    duration: '12 hours',
    modules: 18,
    enrolled: 1156,
    rating: 4.7,
    reviews: 134,
    progress: 65,
    category: 'ML Security',
    instructor: 'Dr. Alex Kim',
    instructorAvatar: '/instructors/alex-kim.jpg',
    thumbnail: '/courses/ml-security.jpg',
    price: '$149',
    skills: ['Adversarial Defense', 'Data Poisoning Detection', 'Secure Deployment'],
    prerequisites: ['Machine Learning Fundamentals', 'Python Programming'],
    certification: true,
    difficulty: 3,
    tags: ['Machine Learning', 'Security', 'Defense', 'Intermediate'],
    lastUpdated: '2024-01-08',
    language: 'English',
    subtitles: ['English', 'Spanish', 'French', 'German'],
  },
  {
    id: 4,
    title: 'AI Ethics and Governance',
    description: 'Explore ethical considerations in AI development, regulatory compliance, and governance frameworks for responsible AI deployment.',
    level: 'Intermediate',
    duration: '10 hours',
    modules: 15,
    enrolled: 987,
    rating: 4.6,
    reviews: 87,
    progress: 0,
    category: 'Ethics',
    instructor: 'Dr. Emily Watson',
    instructorAvatar: '/instructors/emily-watson.jpg',
    thumbnail: '/courses/ai-ethics.jpg',
    price: '$99',
    skills: ['AI Ethics', 'Regulatory Compliance', 'Governance Frameworks'],
    prerequisites: ['AI Fundamentals'],
    certification: true,
    difficulty: 2,
    tags: ['Ethics', 'Governance', 'Compliance', 'Responsible AI'],
    lastUpdated: '2024-01-12',
    language: 'English',
    subtitles: ['English', 'Spanish', 'French'],
  },
  {
    id: 5,
    title: 'Prompt Engineering Security',
    description: 'Master secure prompt engineering techniques, prevent prompt injection attacks, and build robust AI applications.',
    level: 'Intermediate',
    duration: '6 hours',
    modules: 10,
    enrolled: 743,
    rating: 4.8,
    reviews: 65,
    progress: 30,
    category: 'Prompt Security',
    instructor: 'Dr. James Liu',
    instructorAvatar: '/instructors/james-liu.jpg',
    thumbnail: '/courses/prompt-security.jpg',
    price: '$79',
    skills: ['Prompt Engineering', 'Injection Prevention', 'Secure Design'],
    prerequisites: ['LLM Fundamentals', 'Basic Security'],
    certification: true,
    difficulty: 2,
    tags: ['Prompt Engineering', 'LLM', 'Security', 'Injection'],
    lastUpdated: '2024-01-05',
    language: 'English',
    subtitles: ['English', 'Spanish'],
  },
  {
    id: 6,
    title: 'AI Model Forensics',
    description: 'Learn to investigate AI model breaches, analyze attack patterns, and conduct digital forensics on compromised AI systems.',
    level: 'Advanced',
    duration: '14 hours',
    modules: 20,
    enrolled: 456,
    rating: 4.9,
    reviews: 42,
    progress: 0,
    category: 'Forensics',
    instructor: 'Dr. Rachel Green',
    instructorAvatar: '/instructors/rachel-green.jpg',
    thumbnail: '/courses/ai-forensics.jpg',
    price: '$249',
    skills: ['Digital Forensics', 'Incident Response', 'Attack Analysis'],
    prerequisites: ['AI Security Fundamentals', 'Cybersecurity Basics'],
    certification: true,
    difficulty: 4,
    tags: ['Forensics', 'Investigation', 'Incident Response', 'Advanced'],
    lastUpdated: '2024-01-03',
    language: 'English',
    subtitles: ['English'],
  },
]

const categories = [
  { id: 'all', name: 'All Courses', count: courses.length, icon: BookOpenIcon },
  { id: 'AI Security', name: 'AI Security', count: 2, icon: ShieldCheckIcon },
  { id: 'Red Teaming', name: 'Red Teaming', count: 1, icon: BeakerIcon },
  { id: 'ML Security', name: 'ML Security', count: 1, icon: CpuChipIcon },
  { id: 'Ethics', name: 'Ethics', count: 1, icon: EyeIcon },
  { id: 'Prompt Security', name: 'Prompt Security', count: 1, icon: DocumentTextIcon },
  { id: 'Forensics', name: 'Forensics', count: 1, icon: GlobeAltIcon },
]

const levels = ['All Levels', 'Beginner', 'Intermediate', 'Advanced']
const sortOptions = ['Newest', 'Most Popular', 'Highest Rated', 'Duration']

export default function ComprehensiveCoursesPage() {
  const { user } = useAuth()
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [selectedLevel, setSelectedLevel] = useState('All Levels')
  const [sortBy, setSortBy] = useState('Newest')
  const [filteredCourses, setFilteredCourses] = useState(courses)

  // Filter and sort courses
  useEffect(() => {
    let filtered = courses.filter(course => {
      const matchesSearch = course.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           course.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           course.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()))
      
      const matchesCategory = selectedCategory === 'all' || course.category === selectedCategory
      const matchesLevel = selectedLevel === 'All Levels' || course.level === selectedLevel
      
      return matchesSearch && matchesCategory && matchesLevel
    })

    // Sort courses
    switch (sortBy) {
      case 'Most Popular':
        filtered.sort((a, b) => b.enrolled - a.enrolled)
        break
      case 'Highest Rated':
        filtered.sort((a, b) => b.rating - a.rating)
        break
      case 'Duration':
        filtered.sort((a, b) => parseInt(a.duration) - parseInt(b.duration))
        break
      default: // Newest
        filtered.sort((a, b) => new Date(b.lastUpdated).getTime() - new Date(a.lastUpdated).getTime())
    }

    setFilteredCourses(filtered)
  }, [searchTerm, selectedCategory, selectedLevel, sortBy])

  const getCategoryIcon = (categoryId: string) => {
    const category = categories.find(cat => cat.id === categoryId)
    return category?.icon || BookOpenIcon
  }

  const getDifficultyColor = (difficulty: number) => {
    if (difficulty <= 1) return 'cyber-green-neon'
    if (difficulty <= 2) return 'cyber-blue-neon'
    if (difficulty <= 3) return 'cyber-orange-neon'
    return 'security-critical'
  }

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'Beginner': return 'cyber-green-neon'
      case 'Intermediate': return 'cyber-blue-neon'
      case 'Advanced': return 'cyber-orange-neon'
      default: return 'matrix-text'
    }
  }

  return (
    <div className="min-h-screen bg-matrix-void p-4 md:p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-display font-bold text-cyber-blue-neon">
            AI Security Courses
          </h1>
          <p className="text-matrix-text mt-1">
            Master AI security with our comprehensive course catalog
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          <Badge variant="outline" className="border-cyber-green-neon text-cyber-green-neon">
            {filteredCourses.length} courses available
          </Badge>
        </div>
      </div>

      {/* Search and Filters */}
      <CyberpunkCard variant="glass-blue" size="lg">
        <div className="space-y-4">
          <div className="flex flex-col md:flex-row gap-4">
            {/* Search */}
            <div className="flex-1 relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-matrix-text" />
              <Input
                placeholder="Search courses, skills, or topics..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 bg-matrix-surface border-matrix-border text-matrix-white"
              />
            </div>
            
            {/* Level Filter */}
            <select
              value={selectedLevel}
              onChange={(e) => setSelectedLevel(e.target.value)}
              className="px-3 py-2 bg-matrix-surface border border-matrix-border rounded-lg text-matrix-white"
            >
              {levels.map(level => (
                <option key={level} value={level}>{level}</option>
              ))}
            </select>
            
            {/* Sort */}
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="px-3 py-2 bg-matrix-surface border border-matrix-border rounded-lg text-matrix-white"
            >
              {sortOptions.map(option => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
          </div>
        </div>
      </CyberpunkCard>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Categories Sidebar */}
        <div className="lg:col-span-1">
          <CyberpunkCard variant="neon-green" size="lg">
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-cyber-green-neon">
                Categories
              </h3>
              
              <div className="space-y-2">
                {categories.map((category) => {
                  const IconComponent = category.icon
                  return (
                    <button
                      key={category.id}
                      onClick={() => setSelectedCategory(category.id)}
                      className={`w-full flex items-center gap-3 px-3 py-2 text-left rounded-lg transition-colors ${
                        selectedCategory === category.id
                          ? 'bg-cyber-green-neon/20 text-cyber-green-neon border border-cyber-green-neon/40'
                          : 'text-matrix-light hover:text-matrix-white hover:bg-matrix-surface'
                      }`}
                    >
                      <IconComponent className="w-5 h-5" />
                      <span className="flex-1">{category.name}</span>
                      <Badge variant="secondary" className="text-xs">
                        {category.count}
                      </Badge>
                    </button>
                  )
                })}
              </div>
            </div>
          </CyberpunkCard>
        </div>

        {/* Courses Grid */}
        <div className="lg:col-span-3">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
            <AnimatePresence>
              {filteredCourses.map((course, index) => (
                <motion.div
                  key={course.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ delay: index * 0.1 }}
                >
                  <CyberpunkCard 
                    variant={course.progress > 0 ? 'neon-blue' : 'glass-dark'} 
                    size="lg"
                    className="h-full group cursor-pointer"
                  >
                    <div className="space-y-4">
                      {/* Course Thumbnail */}
                      <div className="relative h-32 bg-gradient-to-br from-cyber-blue-neon/20 to-cyber-purple-neon/20 rounded-lg overflow-hidden">
                        <div className="absolute inset-0 flex items-center justify-center">
                          <BookOpenIcon className="w-12 h-12 text-cyber-blue-neon" />
                        </div>
                        
                        {course.progress > 0 && (
                          <div className="absolute top-2 right-2">
                            <Badge variant="outline" className="border-cyber-green-neon text-cyber-green-neon text-xs">
                              {course.progress}% Complete
                            </Badge>
                          </div>
                        )}
                        
                        <div className="absolute bottom-2 left-2">
                          <Badge 
                            variant="outline" 
                            className={`border-${getLevelColor(course.level)} text-${getLevelColor(course.level)} text-xs`}
                          >
                            {course.level}
                          </Badge>
                        </div>
                      </div>

                      {/* Course Info */}
                      <div className="space-y-2">
                        <h3 className="font-semibold text-matrix-white group-hover:text-cyber-blue-neon transition-colors">
                          {course.title}
                        </h3>
                        <p className="text-sm text-matrix-text line-clamp-2">
                          {course.description}
                        </p>
                      </div>

                      {/* Course Meta */}
                      <div className="flex items-center gap-4 text-xs text-matrix-text">
                        <div className="flex items-center gap-1">
                          <ClockIcon className="w-4 h-4" />
                          {course.duration}
                        </div>
                        <div className="flex items-center gap-1">
                          <UserGroupIcon className="w-4 h-4" />
                          {course.enrolled.toLocaleString()}
                        </div>
                        <div className="flex items-center gap-1">
                          <StarIcon className="w-4 h-4 text-cyber-orange-neon" />
                          {course.rating}
                        </div>
                      </div>

                      {/* Progress Bar */}
                      {course.progress > 0 && (
                        <div className="space-y-1">
                          <Progress 
                            value={course.progress} 
                            className="h-2"
                            indicatorClassName="bg-cyber-green-neon"
                          />
                          <div className="flex justify-between text-xs text-matrix-text">
                            <span>{course.progress}% complete</span>
                            <span>{course.modules} modules</span>
                          </div>
                        </div>
                      )}

                      {/* Skills Tags */}
                      <div className="flex flex-wrap gap-1">
                        {course.skills.slice(0, 3).map((skill) => (
                          <Badge key={skill} variant="secondary" className="text-xs">
                            {skill}
                          </Badge>
                        ))}
                        {course.skills.length > 3 && (
                          <Badge variant="secondary" className="text-xs">
                            +{course.skills.length - 3} more
                          </Badge>
                        )}
                      </div>

                      {/* Action Button */}
                      <div className="flex items-center justify-between pt-2">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-cyber text-cyber-green-neon">
                            {course.price}
                          </span>
                          {course.certification && (
                            <AcademicCapIcon className="w-4 h-4 text-cyber-purple-neon" />
                          )}
                        </div>
                        
                        <Link href={`/education/courses/${course.id}`}>
                          <CyberpunkButton 
                            variant={course.progress > 0 ? "neon-green" : "neon-blue"} 
                            size="sm"
                          >
                            {course.progress > 0 ? (
                              <>
                                <PlayIcon className="w-4 h-4" />
                                Continue
                              </>
                            ) : (
                              <>
                                <BookOpenIcon className="w-4 h-4" />
                                Enroll
                              </>
                            )}
                          </CyberpunkButton>
                        </Link>
                      </div>
                    </div>
                  </CyberpunkCard>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>

          {filteredCourses.length === 0 && (
            <CyberpunkCard variant="glass-dark" size="lg">
              <div className="text-center py-12">
                <BookOpenIcon className="w-12 h-12 text-matrix-text mx-auto mb-4" />
                <h3 className="text-lg font-medium text-matrix-white mb-2">No courses found</h3>
                <p className="text-matrix-text">
                  Try adjusting your search criteria or browse different categories
                </p>
              </div>
            </CyberpunkCard>
          )}
        </div>
      </div>
    </div>
  )
}
