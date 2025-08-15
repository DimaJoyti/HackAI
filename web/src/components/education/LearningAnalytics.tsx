'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  ChartBarIcon,
  TrendingUpIcon,
  TrendingDownIcon,
  ClockIcon,
  FireIcon,
  TargetIcon,
  AcademicCapIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts'

// Mock analytics data
const learningProgressData = [
  { date: '2024-01-01', hours: 2.5, score: 85, courses: 1 },
  { date: '2024-01-02', hours: 3.2, score: 88, courses: 1 },
  { date: '2024-01-03', hours: 1.8, score: 82, courses: 1 },
  { date: '2024-01-04', hours: 4.1, score: 91, courses: 2 },
  { date: '2024-01-05', hours: 2.9, score: 89, courses: 2 },
  { date: '2024-01-06', hours: 3.5, score: 93, courses: 2 },
  { date: '2024-01-07', hours: 2.2, score: 87, courses: 2 },
]

const skillProgressData = [
  { skill: 'Threat Modeling', current: 85, target: 90 },
  { skill: 'Prompt Security', current: 92, target: 95 },
  { skill: 'Model Testing', current: 78, target: 85 },
  { skill: 'Risk Assessment', current: 88, target: 90 },
  { skill: 'Incident Response', current: 65, target: 80 },
  { skill: 'Compliance', current: 82, target: 85 },
]

const categoryPerformanceData = [
  { category: 'Fundamentals', score: 92, time: 12.5, color: '#3b82f6' },
  { category: 'Prompt Security', score: 88, time: 8.2, color: '#10b981' },
  { category: 'Model Security', score: 85, time: 15.3, color: '#f59e0b' },
  { category: 'Privacy', score: 78, time: 6.8, color: '#ef4444' },
  { category: 'Red Teaming', score: 82, time: 11.2, color: '#8b5cf6' },
]

const learningPatternData = [
  { time: '6 AM', activity: 15 },
  { time: '8 AM', activity: 45 },
  { time: '10 AM', activity: 78 },
  { time: '12 PM', activity: 65 },
  { time: '2 PM', activity: 82 },
  { time: '4 PM', activity: 95 },
  { time: '6 PM', activity: 88 },
  { time: '8 PM', activity: 72 },
  { time: '10 PM', activity: 35 },
]

const competencyRadarData = [
  { subject: 'Technical Skills', A: 85, fullMark: 100 },
  { subject: 'Security Knowledge', A: 92, fullMark: 100 },
  { subject: 'Practical Application', A: 78, fullMark: 100 },
  { subject: 'Problem Solving', A: 88, fullMark: 100 },
  { subject: 'Communication', A: 82, fullMark: 100 },
  { subject: 'Leadership', A: 65, fullMark: 100 },
]

interface LearningAnalyticsProps {
  userId: string
  timeRange?: '7d' | '30d' | '90d' | '1y'
}

export default function LearningAnalytics({ userId, timeRange = '30d' }: LearningAnalyticsProps) {
  const [activeTab, setActiveTab] = useState('overview')
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return <div>Loading analytics...</div>
  }

  const totalHours = learningProgressData.reduce((sum, day) => sum + day.hours, 0)
  const averageScore = Math.round(
    learningProgressData.reduce((sum, day) => sum + day.score, 0) / learningProgressData.length
  )
  const currentStreak = 7 // Mock data
  const completionRate = 85 // Mock data

  return (
    <div className="space-y-6">
      {/* Analytics Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Learning Analytics</h2>
          <p className="text-gray-600 dark:text-gray-400">
            Insights into your learning progress and performance
          </p>
        </div>
        <Badge variant="outline" className="text-sm">
          Last {timeRange}
        </Badge>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Study Time</CardTitle>
              <ClockIcon className="h-4 w-4 text-blue-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">{totalHours.toFixed(1)}h</div>
              <p className="text-xs text-muted-foreground">
                <TrendingUpIcon className="inline h-3 w-3 mr-1" />
                +12% from last period
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
              <CardTitle className="text-sm font-medium">Average Score</CardTitle>
              <TargetIcon className="h-4 w-4 text-green-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{averageScore}%</div>
              <p className="text-xs text-muted-foreground">
                <TrendingUpIcon className="inline h-3 w-3 mr-1" />
                +5% improvement
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
              <CardTitle className="text-sm font-medium">Learning Streak</CardTitle>
              <FireIcon className="h-4 w-4 text-orange-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-500">{currentStreak} days</div>
              <p className="text-xs text-muted-foreground">
                Personal best: 12 days
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
              <CardTitle className="text-sm font-medium">Completion Rate</CardTitle>
              <AcademicCapIcon className="h-4 w-4 text-purple-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-600">{completionRate}%</div>
              <p className="text-xs text-muted-foreground">
                <TrendingDownIcon className="inline h-3 w-3 mr-1" />
                -2% from target
              </p>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Analytics Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="skills">Skills</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="patterns">Patterns</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Learning Progress Chart */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.5 }}
            >
              <Card>
                <CardHeader>
                  <CardTitle>Learning Progress</CardTitle>
                  <CardDescription>Daily study hours and performance scores</CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={learningProgressData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="date" tickFormatter={(date) => new Date(date).toLocaleDateString()} />
                      <YAxis yAxisId="left" />
                      <YAxis yAxisId="right" orientation="right" />
                      <Tooltip />
                      <Bar yAxisId="left" dataKey="hours" fill="#3b82f6" opacity={0.3} />
                      <Line yAxisId="right" type="monotone" dataKey="score" stroke="#10b981" strokeWidth={2} />
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </motion.div>

            {/* Category Performance */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.6 }}
            >
              <Card>
                <CardHeader>
                  <CardTitle>Category Performance</CardTitle>
                  <CardDescription>Performance across different learning categories</CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={categoryPerformanceData}
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        dataKey="score"
                        label={({ category, score }) => `${category}: ${score}%`}
                      >
                        {categoryPerformanceData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </motion.div>
          </div>
        </TabsContent>

        <TabsContent value="skills" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Skill Progress */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
            >
              <Card>
                <CardHeader>
                  <CardTitle>Skill Development</CardTitle>
                  <CardDescription>Progress towards skill targets</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {skillProgressData.map((skill, index) => (
                    <div key={skill.skill} className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="font-medium">{skill.skill}</span>
                        <span className="text-gray-600 dark:text-gray-400">
                          {skill.current}% / {skill.target}%
                        </span>
                      </div>
                      <div className="relative">
                        <Progress value={skill.current} className="h-2" />
                        <div
                          className="absolute top-0 h-2 w-1 bg-red-500 rounded"
                          style={{ left: `${skill.target}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </motion.div>

            {/* Competency Radar */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.6 }}
            >
              <Card>
                <CardHeader>
                  <CardTitle>Competency Overview</CardTitle>
                  <CardDescription>Multi-dimensional skill assessment</CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <RadarChart data={competencyRadarData}>
                      <PolarGrid />
                      <PolarAngleAxis dataKey="subject" />
                      <PolarRadiusAxis angle={90} domain={[0, 100]} />
                      <Radar
                        name="Current Level"
                        dataKey="A"
                        stroke="#3b82f6"
                        fill="#3b82f6"
                        fillOpacity={0.3}
                      />
                    </RadarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </motion.div>
          </div>
        </TabsContent>

        <TabsContent value="performance" className="space-y-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
          >
            <Card>
              <CardHeader>
                <CardTitle>Performance Trends</CardTitle>
                <CardDescription>Detailed performance analysis over time</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={400}>
                  <AreaChart data={learningProgressData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" tickFormatter={(date) => new Date(date).toLocaleDateString()} />
                    <YAxis />
                    <Tooltip />
                    <Area
                      type="monotone"
                      dataKey="score"
                      stroke="#3b82f6"
                      fill="#3b82f6"
                      fillOpacity={0.3}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </motion.div>
        </TabsContent>

        <TabsContent value="patterns" className="space-y-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
          >
            <Card>
              <CardHeader>
                <CardTitle>Learning Patterns</CardTitle>
                <CardDescription>When you're most active and productive</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={learningPatternData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="activity" fill="#10b981" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </motion.div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
