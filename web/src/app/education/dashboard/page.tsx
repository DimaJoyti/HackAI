'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import Link from 'next/link'
import {
  BookOpenIcon,
  BeakerIcon,
  ClipboardDocumentCheckIcon,
  TrophyIcon,
  FireIcon,
  ClockIcon,
  ChartBarIcon,
  ArrowTrendingUpIcon,
  AcademicCapIcon,
  PlayIcon,
  CheckCircleIcon,
  StarIcon,
  UserGroupIcon,
  LightBulbIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  GlobeAltIcon,
  DocumentTextIcon,
  RocketLaunchIcon,
  BoltIcon,
  EyeIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton } from '@/components/ui/cyberpunk-button'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { useAuth } from '@/hooks/use-auth'
import { formatRelativeTime } from '@/lib/utils'

// Mock data for the Learning Management System
const mockUserData = {
  name: 'Security Analyst',
  level: 'Advanced',
  xp: 4250,
  nextLevelXP: 5000,
  coursesCompleted: 12,
  totalCourses: 18,
  labsCompleted: 25,
  totalLabs: 30,
  assessmentsPassed: 15,
  totalAssessments: 18,
  certificatesEarned: 5,
  currentStreak: 14,
  totalStudyTime: '127h 45m',
  learningVelocity: 8.5,
  engagementScore: 92,
  performanceScore: 88,
  overallProgress: 78,
}

const recentActivity = [
  {
    id: 1,
    type: 'course_completed',
    title: 'Advanced AI Red Teaming',
    description: 'Completed with 94% score',
    timestamp: '2 hours ago',
    icon: BookOpenIcon,
    color: 'cyber-blue-neon',
    points: 150,
  },
  {
    id: 2,
    type: 'lab_completed',
    title: 'AI Model Poisoning Detection',
    description: 'Successfully identified 8 attack vectors',
    timestamp: '1 day ago',
    icon: BeakerIcon,
    color: 'cyber-green-neon',
    points: 75,
  },
  {
    id: 3,
    type: 'assessment_passed',
    title: 'Machine Learning Security Assessment',
    description: 'Scored 94% on first attempt',
    timestamp: '2 days ago',
    icon: ClipboardDocumentCheckIcon,
    color: 'cyber-orange-neon',
    points: 100,
  },
  {
    id: 4,
    type: 'achievement_unlocked',
    title: 'AI Security Expert',
    description: 'Mastered advanced AI security concepts',
    timestamp: '3 days ago',
    icon: TrophyIcon,
    color: 'cyber-purple-neon',
    points: 250,
  },
]

const featuredCourses = [
  {
    id: 1,
    title: 'AI Security Fundamentals',
    description: 'Learn the basics of securing AI systems and models',
    level: 'Beginner',
    duration: '8 hours',
    modules: 12,
    enrolled: 1247,
    rating: 4.8,
    progress: 0,
    category: 'AI Security',
    instructor: 'Dr. Sarah Chen',
    thumbnail: '/courses/ai-security-fundamentals.jpg',
  },
  {
    id: 2,
    title: 'Advanced AI Red Teaming',
    description: 'Master advanced techniques for testing AI system security',
    level: 'Advanced',
    duration: '16 hours',
    modules: 24,
    enrolled: 892,
    rating: 4.9,
    progress: 100,
    category: 'Red Teaming',
    instructor: 'Prof. Marcus Rodriguez',
    thumbnail: '/courses/ai-red-teaming.jpg',
  },
  {
    id: 3,
    title: 'Machine Learning Security',
    description: 'Protect ML models from adversarial attacks and data poisoning',
    level: 'Intermediate',
    duration: '12 hours',
    modules: 18,
    enrolled: 1156,
    rating: 4.7,
    progress: 65,
    category: 'ML Security',
    instructor: 'Dr. Alex Kim',
    thumbnail: '/courses/ml-security.jpg',
  },
]

const upcomingDeadlines = [
  {
    id: 1,
    title: 'AI Ethics Assessment',
    type: 'assessment',
    dueDate: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
    course: 'AI Security Fundamentals',
    priority: 'high',
  },
  {
    id: 2,
    title: 'Adversarial ML Lab',
    type: 'lab',
    dueDate: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
    course: 'Machine Learning Security',
    priority: 'medium',
  },
  {
    id: 3,
    title: 'Final Project Submission',
    type: 'project',
    dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    course: 'Advanced AI Red Teaming',
    priority: 'high',
  },
]

const achievements = [
  { id: 1, name: 'AI Security Expert', icon: '🛡️', earned: true, category: 'expertise' },
  { id: 2, name: 'Lab Virtuoso', icon: '🧪', earned: true, category: 'practical' },
  { id: 3, name: 'Speed Learner', icon: '⚡', earned: true, category: 'efficiency' },
  { id: 4, name: 'Perfect Score', icon: '💯', earned: true, category: 'performance' },
  { id: 5, name: 'Mentor', icon: '👨‍🏫', earned: false, category: 'community' },
  { id: 6, name: 'Research Pioneer', icon: '🔬', earned: false, category: 'innovation' },
]

export default function EducationDashboard() {
  const { user } = useAuth()
  const [activeTab, setActiveTab] = useState('overview')

  const progressPercentage = (mockUserData.xp / mockUserData.nextLevelXP) * 100

  return (
    <div className="min-h-screen bg-matrix-void p-4 md:p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-display font-bold text-cyber-blue-neon">
            Learning Dashboard
          </h1>
          <p className="text-matrix-text mt-1">
            Welcome back, {mockUserData.name}! Continue your AI security journey.
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <FireIcon className="w-5 h-5 text-cyber-orange-neon" />
            <span className="text-cyber-orange-neon font-cyber">
              {mockUserData.currentStreak} day streak
            </span>
          </div>
          
          <CyberpunkButton variant="neon-green" size="sm">
            <PlayIcon className="w-4 h-4" />
            Continue Learning
          </CyberpunkButton>
        </div>
      </div>

      {/* Progress Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <CyberpunkCard variant="neon-blue" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-blue-neon/20 rounded-lg">
              <BookOpenIcon className="w-6 h-6 text-cyber-blue-neon" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-cyber-blue-neon">
                {mockUserData.coursesCompleted}/{mockUserData.totalCourses}
              </div>
              <div className="text-sm text-matrix-text">Courses Completed</div>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-green" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-green-neon/20 rounded-lg">
              <BeakerIcon className="w-6 h-6 text-cyber-green-neon" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-cyber-green-neon">
                {mockUserData.labsCompleted}/{mockUserData.totalLabs}
              </div>
              <div className="text-sm text-matrix-text">Labs Completed</div>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-orange" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-orange-neon/20 rounded-lg">
              <ClipboardDocumentCheckIcon className="w-6 h-6 text-cyber-orange-neon" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-cyber-orange-neon">
                {mockUserData.assessmentsPassed}/{mockUserData.totalAssessments}
              </div>
              <div className="text-sm text-matrix-text">Assessments Passed</div>
            </div>
          </div>
        </CyberpunkCard>

        <CyberpunkCard variant="neon-purple" size="default">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-purple-neon/20 rounded-lg">
              <AcademicCapIcon className="w-6 h-6 text-cyber-purple-neon" />
            </div>
            <div>
              <div className="text-2xl font-bold font-cyber text-cyber-purple-neon">
                {mockUserData.certificatesEarned}
              </div>
              <div className="text-sm text-matrix-text">Certificates Earned</div>
            </div>
          </div>
        </CyberpunkCard>
      </div>

      {/* Level Progress */}
      <CyberpunkCard variant="glass-blue" size="lg">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-cyber-blue-neon">
                Level Progress
              </h3>
              <p className="text-matrix-text">
                {mockUserData.level} • {mockUserData.xp} / {mockUserData.nextLevelXP} XP
              </p>
            </div>
            <div className="text-right">
              <div className="text-2xl font-bold font-cyber text-cyber-blue-neon">
                {progressPercentage.toFixed(0)}%
              </div>
              <div className="text-sm text-matrix-text">to next level</div>
            </div>
          </div>
          
          <Progress 
            value={progressPercentage} 
            className="h-3"
            indicatorClassName="bg-cyber-blue-neon"
          />
          
          <div className="flex justify-between text-sm text-matrix-text">
            <span>Current Level: {mockUserData.level}</span>
            <span>{mockUserData.nextLevelXP - mockUserData.xp} XP to Expert</span>
          </div>
        </div>
      </CyberpunkCard>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Featured Courses */}
        <div className="lg:col-span-2">
          <CyberpunkCard variant="neon-green" size="lg">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-cyber-green-neon">
                  Continue Learning
                </h3>
                <Link href="/education/courses">
                  <CyberpunkButton variant="ghost-blue" size="sm">
                    View All Courses
                  </CyberpunkButton>
                </Link>
              </div>
              
              <div className="space-y-4">
                {featuredCourses.map((course, index) => (
                  <motion.div
                    key={course.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                  >
                    <CyberpunkCard variant="glass-dark" size="sm">
                      <div className="flex items-center gap-4">
                        <div className="w-16 h-16 bg-gradient-to-br from-cyber-blue-neon/20 to-cyber-purple-neon/20 rounded-lg flex items-center justify-center">
                          <BookOpenIcon className="w-8 h-8 text-cyber-blue-neon" />
                        </div>
                        
                        <div className="flex-1 min-w-0">
                          <h4 className="font-medium text-matrix-white truncate">
                            {course.title}
                          </h4>
                          <p className="text-sm text-matrix-text truncate">
                            {course.description}
                          </p>
                          <div className="flex items-center gap-4 mt-2">
                            <Badge variant="secondary" className="text-xs">
                              {course.level}
                            </Badge>
                            <span className="text-xs text-matrix-text">
                              {course.duration}
                            </span>
                            <div className="flex items-center gap-1">
                              <StarIcon className="w-3 h-3 text-cyber-orange-neon" />
                              <span className="text-xs text-cyber-orange-neon">
                                {course.rating}
                              </span>
                            </div>
                          </div>
                          
                          {course.progress > 0 && (
                            <div className="mt-2">
                              <Progress 
                                value={course.progress} 
                                className="h-1"
                                indicatorClassName="bg-cyber-green-neon"
                              />
                              <span className="text-xs text-matrix-text">
                                {course.progress}% complete
                              </span>
                            </div>
                          )}
                        </div>
                        
                        <CyberpunkButton 
                          variant={course.progress > 0 ? "neon-green" : "neon-blue"} 
                          size="sm"
                        >
                          {course.progress > 0 ? "Continue" : "Start"}
                        </CyberpunkButton>
                      </div>
                    </CyberpunkCard>
                  </motion.div>
                ))}
              </div>
            </div>
          </CyberpunkCard>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Recent Activity */}
          <CyberpunkCard variant="neon-orange" size="lg">
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-cyber-orange-neon">
                Recent Activity
              </h3>
              
              <div className="space-y-3">
                {recentActivity.map((activity, index) => (
                  <motion.div
                    key={activity.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="flex items-start gap-3 p-3 bg-matrix-surface rounded-lg border border-matrix-border"
                  >
                    <div className={`p-1 rounded bg-${activity.color}/20`}>
                      <activity.icon className={`w-4 h-4 text-${activity.color}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-medium text-matrix-white truncate">
                        {activity.title}
                      </h4>
                      <p className="text-xs text-matrix-text">
                        {activity.description}
                      </p>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-xs text-matrix-text">
                          {activity.timestamp}
                        </span>
                        <span className={`text-xs font-cyber text-${activity.color}`}>
                          +{activity.points} XP
                        </span>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          </CyberpunkCard>

          {/* Upcoming Deadlines */}
          <CyberpunkCard variant="security-critical" size="lg">
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-security-critical">
                Upcoming Deadlines
              </h3>
              
              <div className="space-y-3">
                {upcomingDeadlines.map((deadline, index) => (
                  <motion.div
                    key={deadline.id}
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="flex items-center justify-between p-3 bg-matrix-surface rounded-lg border border-matrix-border"
                  >
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-medium text-matrix-white truncate">
                        {deadline.title}
                      </h4>
                      <p className="text-xs text-matrix-text truncate">
                        {deadline.course}
                      </p>
                      <span className="text-xs text-matrix-text">
                        Due {formatRelativeTime(deadline.dueDate)}
                      </span>
                    </div>
                    <Badge 
                      variant={deadline.priority === 'high' ? 'destructive' : 'secondary'}
                      className="text-xs"
                    >
                      {deadline.priority}
                    </Badge>
                  </motion.div>
                ))}
              </div>
            </div>
          </CyberpunkCard>
        </div>
      </div>
    </div>
  )
}
