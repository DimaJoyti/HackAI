'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  TrophyIcon,
  StarIcon,
  FireIcon,
  ShieldCheckIcon,
  AcademicCapIcon,
  ClockIcon,
  CheckCircleIcon,
  DocumentTextIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

// Mock achievements data
const achievements = [
  {
    id: 1,
    title: 'First Steps',
    description: 'Complete your first lesson',
    category: 'learning',
    type: 'milestone',
    icon: AcademicCapIcon,
    points: 10,
    rarity: 'common',
    earned: true,
    earnedAt: '2024-01-10T10:30:00Z',
    progress: 100,
    requirement: 'Complete 1 lesson',
  },
  {
    id: 2,
    title: 'Week Warrior',
    description: 'Maintain a 7-day learning streak',
    category: 'engagement',
    type: 'streak',
    icon: FireIcon,
    points: 50,
    rarity: 'uncommon',
    earned: true,
    earnedAt: '2024-01-08T14:20:00Z',
    progress: 100,
    requirement: 'Learn for 7 consecutive days',
  },
  {
    id: 3,
    title: 'Security Scholar',
    description: 'Complete AI Security Fundamentals course',
    category: 'learning',
    type: 'course',
    icon: ShieldCheckIcon,
    points: 100,
    rarity: 'rare',
    earned: true,
    earnedAt: '2024-01-05T16:45:00Z',
    progress: 100,
    requirement: 'Complete AI Security Fundamentals',
  },
  {
    id: 4,
    title: 'Lab Master',
    description: 'Complete 10 hands-on labs',
    category: 'practical',
    type: 'milestone',
    icon: CheckCircleIcon,
    points: 150,
    rarity: 'rare',
    earned: false,
    earnedAt: null,
    progress: 80,
    requirement: 'Complete 10 labs (8/10)',
  },
  {
    id: 5,
    title: 'Perfect Score',
    description: 'Score 100% on any assessment',
    category: 'assessment',
    type: 'performance',
    icon: StarIcon,
    points: 75,
    rarity: 'uncommon',
    earned: false,
    earnedAt: null,
    progress: 92,
    requirement: 'Score 100% on assessment (Best: 92%)',
  },
  {
    id: 6,
    title: 'Speed Learner',
    description: 'Complete a course in under 4 hours',
    category: 'efficiency',
    type: 'performance',
    icon: ClockIcon,
    points: 60,
    rarity: 'uncommon',
    earned: false,
    earnedAt: null,
    progress: 0,
    requirement: 'Complete course in <4 hours',
  },
  {
    id: 7,
    title: 'AI Security Expert',
    description: 'Earn certification in AI Security',
    category: 'certification',
    type: 'certification',
    icon: TrophyIcon,
    points: 500,
    rarity: 'legendary',
    earned: false,
    earnedAt: null,
    progress: 65,
    requirement: 'Complete certification requirements',
  },
  {
    id: 8,
    title: 'Knowledge Sharer',
    description: 'Help 5 community members',
    category: 'community',
    type: 'social',
    icon: DocumentTextIcon,
    points: 80,
    rarity: 'rare',
    earned: false,
    earnedAt: null,
    progress: 40,
    requirement: 'Help community members (2/5)',
  },
]

const certificates = [
  {
    id: 1,
    title: 'AI Security Fundamentals Certificate',
    issuer: 'HackAI Education',
    issuedAt: '2024-01-05T16:45:00Z',
    certificateNumber: 'CERT-2024-001234',
    verificationUrl: 'https://verify.hackai.com/cert/001234',
    skills: ['Threat Modeling', 'Security Analysis', 'Risk Assessment'],
    grade: 'A',
    score: 92,
  },
  {
    id: 2,
    title: 'Prompt Security Specialist',
    issuer: 'HackAI Education',
    issuedAt: '2024-01-08T11:30:00Z',
    certificateNumber: 'CERT-2024-001235',
    verificationUrl: 'https://verify.hackai.com/cert/001235',
    skills: ['Prompt Engineering', 'Injection Detection', 'Defense Design'],
    grade: 'A+',
    score: 96,
  },
]

const stats = {
  totalPoints: 260,
  achievementsEarned: 3,
  totalAchievements: 8,
  certificatesEarned: 2,
  currentStreak: 7,
  longestStreak: 12,
  rank: 'Advanced Learner',
  nextRank: 'Security Expert',
  rankProgress: 68,
}

export default function AchievementsPage() {
  const [activeTab, setActiveTab] = useState('achievements')

  const getRarityColor = (rarity: string) => {
    switch (rarity) {
      case 'common':
        return 'text-gray-600 bg-gray-100 border-gray-300'
      case 'uncommon':
        return 'text-green-600 bg-green-100 border-green-300'
      case 'rare':
        return 'text-blue-600 bg-blue-100 border-blue-300'
      case 'epic':
        return 'text-purple-600 bg-purple-100 border-purple-300'
      case 'legendary':
        return 'text-yellow-600 bg-yellow-100 border-yellow-300'
      default:
        return 'text-gray-600 bg-gray-100 border-gray-300'
    }
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'learning':
        return AcademicCapIcon
      case 'engagement':
        return FireIcon
      case 'practical':
        return CheckCircleIcon
      case 'assessment':
        return StarIcon
      case 'efficiency':
        return ClockIcon
      case 'certification':
        return TrophyIcon
      case 'community':
        return DocumentTextIcon
      default:
        return TrophyIcon
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Achievements</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Track your progress and celebrate your accomplishments
          </p>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Points</CardTitle>
              <TrophyIcon className="h-4 w-4 text-yellow-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-yellow-600">{stats.totalPoints}</div>
              <p className="text-xs text-muted-foreground">
                Rank: {stats.rank}
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
              <CardTitle className="text-sm font-medium">Achievements</CardTitle>
              <StarIcon className="h-4 w-4 text-blue-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.achievementsEarned}/{stats.totalAchievements}</div>
              <p className="text-xs text-muted-foreground">
                {Math.round((stats.achievementsEarned / stats.totalAchievements) * 100)}% completed
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
              <CardTitle className="text-sm font-medium">Certificates</CardTitle>
              <AcademicCapIcon className="h-4 w-4 text-green-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.certificatesEarned}</div>
              <p className="text-xs text-muted-foreground">
                Verified credentials
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
              <div className="text-2xl font-bold text-orange-500">{stats.currentStreak} days</div>
              <p className="text-xs text-muted-foreground">
                Best: {stats.longestStreak} days
              </p>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Rank Progress */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrophyIcon className="h-5 w-5 text-yellow-600" />
              Rank Progress
            </CardTitle>
            <CardDescription>
              Progress towards {stats.nextRank}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>{stats.rank}</span>
                <span>{stats.nextRank}</span>
              </div>
              <Progress value={stats.rankProgress} className="h-3" />
              <div className="text-center text-sm text-gray-600 dark:text-gray-400">
                {stats.rankProgress}% complete
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="achievements">Achievements</TabsTrigger>
          <TabsTrigger value="certificates">Certificates</TabsTrigger>
        </TabsList>

        <TabsContent value="achievements" className="space-y-6">
          {/* Achievements Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {achievements.map((achievement, index) => {
              const IconComponent = achievement.icon
              return (
                <motion.div
                  key={achievement.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.6 + index * 0.1 }}
                >
                  <Card className={`h-full transition-all duration-200 ${
                    achievement.earned 
                      ? 'hover:shadow-lg border-green-200 bg-green-50/50 dark:bg-green-900/10' 
                      : 'hover:shadow-md opacity-75'
                  }`}>
                    <CardHeader className="text-center">
                      <div className={`mx-auto w-16 h-16 rounded-full flex items-center justify-center mb-2 ${
                        achievement.earned 
                          ? 'bg-green-100 text-green-600 dark:bg-green-900 dark:text-green-400' 
                          : 'bg-gray-100 text-gray-400 dark:bg-gray-800'
                      }`}>
                        <IconComponent className="h-8 w-8" />
                      </div>
                      <CardTitle className="text-lg">{achievement.title}</CardTitle>
                      <CardDescription className="text-sm">
                        {achievement.description}
                      </CardDescription>
                    </CardHeader>

                    <CardContent className="space-y-4">
                      {/* Rarity and Points */}
                      <div className="flex items-center justify-between">
                        <Badge className={`text-xs ${getRarityColor(achievement.rarity)}`}>
                          {achievement.rarity}
                        </Badge>
                        <div className="text-sm font-medium text-yellow-600">
                          {achievement.points} pts
                        </div>
                      </div>

                      {/* Progress */}
                      {!achievement.earned && (
                        <div className="space-y-2">
                          <div className="flex justify-between text-sm">
                            <span>Progress</span>
                            <span>{achievement.progress}%</span>
                          </div>
                          <Progress value={achievement.progress} />
                          <div className="text-xs text-gray-600 dark:text-gray-400">
                            {achievement.requirement}
                          </div>
                        </div>
                      )}

                      {/* Earned Date */}
                      {achievement.earned && achievement.earnedAt && (
                        <div className="text-center">
                          <div className="text-xs text-gray-600 dark:text-gray-400">
                            Earned on {formatDate(achievement.earnedAt)}
                          </div>
                          <CheckCircleIcon className="h-5 w-5 text-green-600 mx-auto mt-1" />
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </motion.div>
              )
            })}
          </div>
        </TabsContent>

        <TabsContent value="certificates" className="space-y-6">
          {/* Certificates Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {certificates.map((certificate, index) => (
              <motion.div
                key={certificate.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.6 + index * 0.1 }}
              >
                <Card className="hover:shadow-lg transition-shadow duration-200">
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <CardTitle className="text-lg mb-2">{certificate.title}</CardTitle>
                        <CardDescription>
                          Issued by {certificate.issuer}
                        </CardDescription>
                      </div>
                      <div className="text-right">
                        <Badge variant="outline" className="text-green-600 border-green-600">
                          Grade: {certificate.grade}
                        </Badge>
                        <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                          Score: {certificate.score}%
                        </div>
                      </div>
                    </div>
                  </CardHeader>

                  <CardContent className="space-y-4">
                    {/* Certificate Details */}
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-gray-600 dark:text-gray-400">Issued:</span>
                        <div className="font-medium">{formatDate(certificate.issuedAt)}</div>
                      </div>
                      <div>
                        <span className="text-gray-600 dark:text-gray-400">Certificate #:</span>
                        <div className="font-medium text-xs">{certificate.certificateNumber}</div>
                      </div>
                    </div>

                    {/* Skills */}
                    <div>
                      <h4 className="text-sm font-medium mb-2">Skills Validated</h4>
                      <div className="flex flex-wrap gap-1">
                        {certificate.skills.map(skill => (
                          <Badge key={skill} variant="secondary" className="text-xs">
                            {skill}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex gap-2 pt-2">
                      <Button size="sm" variant="outline" className="flex-1">
                        Download PDF
                      </Button>
                      <Button size="sm" variant="outline" className="flex-1">
                        Verify
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>

          {/* Empty State for Certificates */}
          {certificates.length === 0 && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-center py-12"
            >
              <AcademicCapIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                No certificates yet
              </h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Complete courses and assessments to earn certificates
              </p>
              <Button variant="outline">
                Browse Courses
              </Button>
            </motion.div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
