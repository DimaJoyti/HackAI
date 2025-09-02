'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  BookOpenIcon,
  BeakerIcon,
  ClipboardDocumentCheckIcon,
  TrophyIcon,
  FireIcon,
  ClockIcon,
  ChartBarIcon,
  ArrowTrendingUpIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

// Mock data - in real app this would come from API
const mockUserData = {
  name: 'John Doe',
  level: 3,
  experience: 750,
  nextLevelExp: 1000,
  streak: 7,
  currentStreak: 7,
  totalTimeSpent: '24h 30m',
  coursesCompleted: 3,
  coursesInProgress: 2,
  labsCompleted: 8,
  assessmentsPassed: 12,
  achievements: 15,
  overallProgress: 68,
}

const recentActivity = [
  {
    id: 1,
    type: 'course_completed',
    title: 'AI Security Fundamentals',
    description: 'Completed with 92% score',
    timestamp: '2 hours ago',
    icon: BookOpenIcon,
    color: 'text-green-600',
  },
  {
    id: 2,
    type: 'lab_completed',
    title: 'Prompt Injection Testing',
    description: 'Successfully identified 5 vulnerabilities',
    timestamp: '1 day ago',
    icon: BeakerIcon,
    color: 'text-blue-600',
  },
  {
    id: 3,
    type: 'assessment_passed',
    title: 'Advanced AI Security Quiz',
    description: 'Scored 88% on first attempt',
    timestamp: '2 days ago',
    icon: ClipboardDocumentCheckIcon,
    color: 'text-purple-600',
  },
  {
    id: 4,
    type: 'achievement_earned',
    title: 'Week Warrior Badge',
    description: '7-day learning streak achieved',
    timestamp: '3 days ago',
    icon: TrophyIcon,
    color: 'text-yellow-600',
  },
]

const upcomingDeadlines = [
  {
    id: 1,
    title: 'Advanced AI Security Assessment',
    dueDate: '2024-01-15',
    priority: 'high',
    type: 'assessment',
  },
  {
    id: 2,
    title: 'Model Security Lab',
    dueDate: '2024-01-18',
    priority: 'medium',
    type: 'lab',
  },
  {
    id: 3,
    title: 'Red Team Exercise',
    dueDate: '2024-01-22',
    priority: 'low',
    type: 'exercise',
  },
]

const recommendedCourses = [
  {
    id: 1,
    title: 'Advanced Prompt Engineering',
    description: 'Learn advanced techniques for secure prompt design',
    level: 'Intermediate',
    duration: '4h 30m',
    rating: 4.8,
    enrolled: 1234,
  },
  {
    id: 2,
    title: 'AI Model Security Assessment',
    description: 'Comprehensive security testing for AI models',
    level: 'Advanced',
    duration: '6h 15m',
    rating: 4.9,
    enrolled: 856,
  },
  {
    id: 3,
    title: 'Privacy-Preserving AI',
    description: 'Implement differential privacy and federated learning',
    level: 'Expert',
    duration: '8h 45m',
    rating: 4.7,
    enrolled: 432,
  },
]

export default function EducationDashboard() {
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return <div>Loading...</div>
  }

  return (
    <div className="space-y-8">
      {/* Welcome Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg p-6 text-white"
      >
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Welcome back, {mockUserData.name}! 🎓</h1>
            <p className="text-blue-100 mt-1">
              You're on a {mockUserData.currentStreak}-day learning streak. Keep it up!
            </p>
          </div>
          <div className="text-right">
            <div className="text-sm text-blue-100">Level {mockUserData.level}</div>
            <div className="text-2xl font-bold">{mockUserData.experience} XP</div>
            <div className="text-sm text-blue-100">
              {mockUserData.nextLevelExp - mockUserData.experience} XP to next level
            </div>
          </div>
        </div>
        <div className="mt-4">
          <Progress 
            value={(mockUserData.experience / mockUserData.nextLevelExp) * 100} 
            className="h-2 bg-blue-500"
          />
        </div>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Courses Completed</CardTitle>
              <BookOpenIcon className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{mockUserData.coursesCompleted}</div>
              <p className="text-xs text-muted-foreground">
                {mockUserData.coursesInProgress} in progress
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Labs Completed</CardTitle>
              <BeakerIcon className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{mockUserData.labsCompleted}</div>
              <p className="text-xs text-muted-foreground">
                +2 this week
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Assessments Passed</CardTitle>
              <ClipboardDocumentCheckIcon className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{mockUserData.assessmentsPassed}</div>
              <p className="text-xs text-muted-foreground">
                92% average score
              </p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Learning Streak</CardTitle>
              <FireIcon className="h-4 w-4 text-orange-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{mockUserData.streak} days</div>
              <p className="text-xs text-muted-foreground">
                Personal best: 12 days
              </p>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Recent Activity */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
          className="lg:col-span-2"
        >
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ChartBarIcon className="h-5 w-5" />
                Recent Activity
              </CardTitle>
              <CardDescription>
                Your latest learning achievements and progress
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {recentActivity.map((activity, index) => (
                  <motion.div
                    key={activity.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.6 + index * 0.1 }}
                    className="flex items-start gap-3 p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                  >
                    <div className={`p-2 rounded-full bg-gray-100 dark:bg-gray-800 ${activity.color}`}>
                      <activity.icon className="h-4 w-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 dark:text-white">
                        {activity.title}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {activity.description}
                      </p>
                      <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                        {activity.timestamp}
                      </p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Upcoming Deadlines */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.7 }}
          >
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ClockIcon className="h-5 w-5" />
                  Upcoming Deadlines
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {upcomingDeadlines.map((deadline) => (
                    <div key={deadline.id} className="flex items-center justify-between p-2 rounded-lg border">
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{deadline.title}</p>
                        <p className="text-xs text-gray-500">{deadline.dueDate}</p>
                      </div>
                      <Badge 
                        variant={deadline.priority === 'high' ? 'destructive' : 
                                deadline.priority === 'medium' ? 'default' : 'secondary'}
                      >
                        {deadline.priority}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </motion.div>

          {/* Progress Overview */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.8 }}
          >
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ArrowTrendingUpIcon className="h-5 w-5" />
                  Overall Progress
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <div className="flex justify-between text-sm mb-2">
                      <span>Course Completion</span>
                      <span>{mockUserData.overallProgress}%</span>
                    </div>
                    <Progress value={mockUserData.overallProgress} />
                  </div>
                  <div className="grid grid-cols-2 gap-4 text-center">
                    <div>
                      <div className="text-2xl font-bold text-blue-600">{mockUserData.totalTimeSpent}</div>
                      <div className="text-xs text-gray-500">Time Spent</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-green-600">{mockUserData.achievements}</div>
                      <div className="text-xs text-gray-500">Achievements</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </div>

      {/* Recommended Courses */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.9 }}
      >
        <Card>
          <CardHeader>
            <CardTitle>Recommended for You</CardTitle>
            <CardDescription>
              Courses tailored to your learning path and interests
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {recommendedCourses.map((course, index) => (
                <motion.div
                  key={course.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 1.0 + index * 0.1 }}
                  className="border rounded-lg p-4 hover:shadow-md transition-shadow"
                >
                  <h3 className="font-semibold text-sm mb-2">{course.title}</h3>
                  <p className="text-xs text-gray-600 dark:text-gray-400 mb-3">
                    {course.description}
                  </p>
                  <div className="flex items-center justify-between text-xs text-gray-500 mb-3">
                    <Badge variant="outline">{course.level}</Badge>
                    <span>{course.duration}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1">
                      <span className="text-yellow-500">★</span>
                      <span className="text-xs">{course.rating}</span>
                      <span className="text-xs text-gray-500">({course.enrolled})</span>
                    </div>
                    <Button size="sm" variant="outline">
                      Enroll
                    </Button>
                  </div>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  )
}
