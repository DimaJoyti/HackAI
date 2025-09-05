'use client'

import React, { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import Link from 'next/link'
import {
  AcademicCapIcon,
  TrophyIcon,
  StarIcon,
  ClockIcon,
  PlayIcon,
  CheckCircleIcon,
  BookOpenIcon,
  BeakerIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  EyeIcon,
  BoltIcon,
  ArrowRightIcon,
} from '@heroicons/react/24/outline'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardHeader, CyberpunkCardTitle } from '@/components/ui/cyberpunk-card'
import { CyberpunkButton, SecurityButton } from '@/components/ui/cyberpunk-button'
import { HolographicDisplay, ParticleSystem } from '@/components/ui/cyberpunk-effects'
import { GlitchText } from '@/components/ui/cyberpunk-background'
import { CyberpunkProgressRing } from '@/components/ui/cyberpunk-charts'

// Learning Path Visualization
interface LearningPathProps {
  className?: string
}

export const LearningPath: React.FC<LearningPathProps> = ({ className }) => {
  const [learningPaths, setLearningPaths] = useState<Array<{
    id: string
    title: string
    description: string
    difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert'
    progress: number
    modules: number
    completedModules: number
    estimatedTime: string
    category: 'web-security' | 'network-security' | 'incident-response' | 'penetration-testing'
    prerequisites: string[]
    skills: string[]
  }>>([])

  useEffect(() => {
    const mockPaths = [
      {
        id: '1',
        title: 'Web Application Security Fundamentals',
        description: 'Master the basics of web application security, including OWASP Top 10 vulnerabilities.',
        difficulty: 'beginner' as const,
        progress: 85,
        modules: 8,
        completedModules: 7,
        estimatedTime: '12 hours',
        category: 'web-security' as const,
        prerequisites: ['Basic HTML/CSS', 'HTTP Protocol'],
        skills: ['XSS Prevention', 'SQL Injection', 'CSRF Protection'],
      },
      {
        id: '2',
        title: 'Advanced Network Security',
        description: 'Deep dive into network security protocols, monitoring, and threat detection.',
        difficulty: 'intermediate' as const,
        progress: 45,
        modules: 12,
        completedModules: 5,
        estimatedTime: '20 hours',
        category: 'network-security' as const,
        prerequisites: ['Networking Basics', 'TCP/IP'],
        skills: ['IDS/IPS', 'Network Forensics', 'Traffic Analysis'],
      },
      {
        id: '3',
        title: 'Incident Response & Digital Forensics',
        description: 'Learn to respond to security incidents and conduct digital forensic investigations.',
        difficulty: 'advanced' as const,
        progress: 20,
        modules: 15,
        completedModules: 3,
        estimatedTime: '30 hours',
        category: 'incident-response' as const,
        prerequisites: ['Security Fundamentals', 'Operating Systems'],
        skills: ['Incident Handling', 'Evidence Collection', 'Malware Analysis'],
      },
      {
        id: '4',
        title: 'Ethical Hacking & Penetration Testing',
        description: 'Master ethical hacking techniques and penetration testing methodologies.',
        difficulty: 'expert' as const,
        progress: 10,
        modules: 20,
        completedModules: 2,
        estimatedTime: '40 hours',
        category: 'penetration-testing' as const,
        prerequisites: ['Web Security', 'Network Security', 'Linux Administration'],
        skills: ['Vulnerability Assessment', 'Exploitation', 'Post-Exploitation'],
      },
    ]

    setLearningPaths(mockPaths)
  }, [])

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'cyber-green-neon'
      case 'intermediate': return 'cyber-blue-neon'
      case 'advanced': return 'cyber-orange-neon'
      case 'expert': return 'security-critical'
      default: return 'matrix-muted'
    }
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'web-security': return ShieldCheckIcon
      case 'network-security': return CpuChipIcon
      case 'incident-response': return EyeIcon
      case 'penetration-testing': return BoltIcon
      default: return BookOpenIcon
    }
  }

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'web-security': return 'pink'
      case 'network-security': return 'blue'
      case 'incident-response': return 'orange'
      case 'penetration-testing': return 'purple'
      default: return 'green'
    }
  }

  return (
    <CyberpunkCard variant="neon-green" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem 
        particleCount={25} 
        color="green" 
        speed="medium" 
        size="small"
        className="opacity-20"
      />
      
      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-green-neon">
            <AcademicCapIcon className="w-6 h-6" />
            <GlitchText intensity="low">LEARNING PATHS</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="safe" size="sm">ACTIVE</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4 max-h-96 overflow-y-auto scrollbar-cyber">
          {learningPaths.map((path) => {
            const difficultyColor = getDifficultyColor(path.difficulty)
            const CategoryIcon = getCategoryIcon(path.category)
            const categoryColor = getCategoryColor(path.category)
            
            return (
              <HolographicDisplay
                key={path.id}
                color={categoryColor}
                intensity="medium"
                className="p-4 group hover:scale-[1.02] transition-all duration-300"
              >
                <div className="space-y-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg border border-cyber-${categoryColor}-neon/30 bg-cyber-${categoryColor}-neon/10`}>
                        <CategoryIcon className={`w-5 h-5 text-cyber-${categoryColor}-neon`} />
                      </div>
                      <div>
                        <h4 className="font-cyber font-bold text-matrix-white">
                          {path.title}
                        </h4>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`text-xs font-cyber uppercase text-${difficultyColor}`}>
                            {path.difficulty}
                          </span>
                          <span className="text-xs text-matrix-muted font-matrix">
                            {path.estimatedTime}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`text-lg font-display font-bold text-cyber-${categoryColor}-neon`}>
                        {path.progress}%
                      </div>
                      <div className="text-xs text-matrix-muted font-cyber">
                        {path.completedModules}/{path.modules} modules
                      </div>
                    </div>
                  </div>

                  <p className="text-sm text-matrix-light leading-relaxed">
                    {path.description}
                  </p>

                  {/* Progress Bar */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-matrix-muted">Progress</span>
                      <span className={`text-cyber-${categoryColor}-neon`}>{path.progress}%</span>
                    </div>
                    <div className="h-2 bg-matrix-surface rounded-full overflow-hidden">
                      <div 
                        className={`h-full transition-all duration-1000 rounded-full bg-cyber-${categoryColor}-neon shadow-neon-${categoryColor}`}
                        style={{ width: `${path.progress}%` }}
                      />
                    </div>
                  </div>

                  {/* Skills Tags */}
                  <div className="flex flex-wrap gap-2">
                    {path.skills.slice(0, 3).map((skill, index) => (
                      <span
                        key={index}
                        className={`px-2 py-1 text-xs font-cyber bg-cyber-${categoryColor}-neon/10 border border-cyber-${categoryColor}-neon/30 rounded text-cyber-${categoryColor}-neon`}
                      >
                        {skill}
                      </span>
                    ))}
                    {path.skills.length > 3 && (
                      <span className="px-2 py-1 text-xs font-cyber text-matrix-muted">
                        +{path.skills.length - 3} more
                      </span>
                    )}
                  </div>

                  <div className="flex gap-2 pt-2 border-t border-matrix-border">
                    <Link href={`/dashboard/learning/path/${path.id}`} className="flex-1">
                      <CyberpunkButton
                        variant={`ghost-${categoryColor}` as any}
                        size="sm"
                        className="w-full group-hover:animate-neon-pulse"
                      >
                        <PlayIcon className="w-3 h-3 mr-2" />
                        Continue
                      </CyberpunkButton>
                    </Link>
                    <Link href={`/dashboard/learning/path/${path.id}/details`}>
                      <CyberpunkButton
                        variant="ghost-blue"
                        size="sm"
                        className="group-hover:animate-neon-pulse"
                      >
                        Details
                      </CyberpunkButton>
                    </Link>
                  </div>
                </div>
              </HolographicDisplay>
            )
          })}
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Achievement System
interface AchievementSystemProps {
  className?: string
}

export const AchievementSystem: React.FC<AchievementSystemProps> = ({ className }) => {
  const [achievements, setAchievements] = useState<Array<{
    id: string
    title: string
    description: string
    category: 'learning' | 'security' | 'practice' | 'community'
    rarity: 'common' | 'rare' | 'epic' | 'legendary'
    progress: number
    maxProgress: number
    unlocked: boolean
    unlockedAt?: Date
    icon: string
    points: number
  }>>([])

  useEffect(() => {
    const mockAchievements = [
      {
        id: '1',
        title: 'First Steps',
        description: 'Complete your first cybersecurity module',
        category: 'learning' as const,
        rarity: 'common' as const,
        progress: 1,
        maxProgress: 1,
        unlocked: true,
        unlockedAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
        icon: '🎯',
        points: 100,
      },
      {
        id: '2',
        title: 'Vulnerability Hunter',
        description: 'Discover 10 vulnerabilities in practice labs',
        category: 'security' as const,
        rarity: 'rare' as const,
        progress: 7,
        maxProgress: 10,
        unlocked: false,
        icon: '🔍',
        points: 500,
      },
      {
        id: '3',
        title: 'Knowledge Seeker',
        description: 'Complete 5 different learning paths',
        category: 'learning' as const,
        rarity: 'epic' as const,
        progress: 2,
        maxProgress: 5,
        unlocked: false,
        icon: '📚',
        points: 1000,
      },
      {
        id: '4',
        title: 'Security Expert',
        description: 'Achieve 90% or higher in all skill assessments',
        category: 'practice' as const,
        rarity: 'legendary' as const,
        progress: 3,
        maxProgress: 6,
        unlocked: false,
        icon: '🏆',
        points: 2500,
      },
      {
        id: '5',
        title: 'Incident Responder',
        description: 'Successfully handle 5 simulated security incidents',
        category: 'practice' as const,
        rarity: 'rare' as const,
        progress: 5,
        maxProgress: 5,
        unlocked: true,
        unlockedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
        icon: '🚨',
        points: 750,
      },
    ]

    setAchievements(mockAchievements)
  }, [])

  const getRarityColor = (rarity: string) => {
    switch (rarity) {
      case 'common': return 'cyber-green-neon'
      case 'rare': return 'cyber-blue-neon'
      case 'epic': return 'cyber-purple-neon'
      case 'legendary': return 'cyber-orange-neon'
      default: return 'matrix-muted'
    }
  }

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'learning': return 'green'
      case 'security': return 'pink'
      case 'practice': return 'blue'
      case 'community': return 'purple'
      default: return 'orange'
    }
  }

  const totalPoints = achievements.filter(a => a.unlocked).reduce((sum, a) => sum + a.points, 0)

  return (
    <CyberpunkCard variant="neon-purple" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem
        particleCount={20}
        color="purple"
        speed="slow"
        size="small"
        className="opacity-20"
      />

      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-purple-neon">
            <TrophyIcon className="w-6 h-6" />
            <GlitchText intensity="low">ACHIEVEMENTS</GlitchText>
          </CyberpunkCardTitle>
          <div className="text-right">
            <div className="text-lg font-display font-bold text-cyber-purple-neon">
              {totalPoints}
            </div>
            <div className="text-xs text-matrix-muted font-cyber">Total Points</div>
          </div>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-3 max-h-80 overflow-y-auto scrollbar-cyber">
          {achievements.map((achievement) => {
            const rarityColor = getRarityColor(achievement.rarity)
            const categoryColor = getCategoryColor(achievement.category)

            return (
              <HolographicDisplay
                key={achievement.id}
                color={categoryColor}
                intensity={achievement.unlocked ? "medium" : "low"}
                className={`p-3 ${achievement.unlocked ? '' : 'opacity-60'}`}
              >
                <div className="flex items-start gap-3">
                  <div className="text-2xl">{achievement.icon}</div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between mb-1">
                      <h4 className={`font-cyber font-bold ${achievement.unlocked ? 'text-matrix-white' : 'text-matrix-muted'}`}>
                        {achievement.title}
                      </h4>
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-cyber uppercase text-${rarityColor}`}>
                          {achievement.rarity}
                        </span>
                        <span className={`text-xs font-matrix text-cyber-${categoryColor}-neon`}>
                          {achievement.points} pts
                        </span>
                      </div>
                    </div>

                    <p className="text-sm text-matrix-light mb-2">
                      {achievement.description}
                    </p>

                    {!achievement.unlocked && (
                      <div className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="text-matrix-muted">Progress</span>
                          <span className={`text-cyber-${categoryColor}-neon`}>
                            {achievement.progress}/{achievement.maxProgress}
                          </span>
                        </div>
                        <div className="h-1 bg-matrix-surface rounded-full overflow-hidden">
                          <div
                            className={`h-full transition-all duration-1000 rounded-full bg-cyber-${categoryColor}-neon`}
                            style={{ width: `${(achievement.progress / achievement.maxProgress) * 100}%` }}
                          />
                        </div>
                      </div>
                    )}

                    {achievement.unlocked && achievement.unlockedAt && (
                      <div className="flex items-center gap-2 text-xs text-cyber-green-neon">
                        <CheckCircleIcon className="w-3 h-3" />
                        <span>Unlocked {achievement.unlockedAt.toLocaleDateString()}</span>
                      </div>
                    )}
                  </div>
                </div>
              </HolographicDisplay>
            )
          })}
        </div>

        <div className="mt-4 pt-4 border-t border-matrix-border">
          <Link href="/dashboard/achievements">
            <CyberpunkButton variant="ghost-purple" size="sm" className="w-full">
              <TrophyIcon className="w-4 h-4 mr-2" />
              View All Achievements
            </CyberpunkButton>
          </Link>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}

// Skill Assessment Dashboard
interface SkillAssessmentProps {
  className?: string
}

export const SkillAssessment: React.FC<SkillAssessmentProps> = ({ className }) => {
  const [skillAreas, setSkillAreas] = useState<Array<{
    id: string
    name: string
    category: string
    currentLevel: number
    targetLevel: number
    lastAssessment: Date
    nextAssessment: Date
    strengths: string[]
    improvements: string[]
    assessmentAvailable: boolean
  }>>([])

  useEffect(() => {
    const mockSkills = [
      {
        id: '1',
        name: 'Web Application Security',
        category: 'Security Testing',
        currentLevel: 85,
        targetLevel: 90,
        lastAssessment: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000),
        nextAssessment: new Date(Date.now() + 16 * 24 * 60 * 60 * 1000),
        strengths: ['XSS Prevention', 'Input Validation'],
        improvements: ['Advanced SQL Injection', 'CSRF Tokens'],
        assessmentAvailable: true,
      },
      {
        id: '2',
        name: 'Network Security',
        category: 'Infrastructure',
        currentLevel: 72,
        targetLevel: 85,
        lastAssessment: new Date(Date.now() - 21 * 24 * 60 * 60 * 1000),
        nextAssessment: new Date(Date.now() + 9 * 24 * 60 * 60 * 1000),
        strengths: ['Firewall Configuration', 'VPN Setup'],
        improvements: ['IDS/IPS Tuning', 'Network Forensics'],
        assessmentAvailable: true,
      },
      {
        id: '3',
        name: 'Incident Response',
        category: 'Operations',
        currentLevel: 68,
        targetLevel: 80,
        lastAssessment: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
        nextAssessment: new Date(Date.now() + 23 * 24 * 60 * 60 * 1000),
        strengths: ['Initial Response', 'Documentation'],
        improvements: ['Forensic Analysis', 'Recovery Planning'],
        assessmentAvailable: false,
      },
      {
        id: '4',
        name: 'Threat Intelligence',
        category: 'Analysis',
        currentLevel: 79,
        targetLevel: 85,
        lastAssessment: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
        nextAssessment: new Date(Date.now() + 20 * 24 * 60 * 60 * 1000),
        strengths: ['OSINT Gathering', 'IOC Analysis'],
        improvements: ['Attribution Analysis', 'Predictive Modeling'],
        assessmentAvailable: true,
      },
    ]

    setSkillAreas(mockSkills)
  }, [])

  const getSkillColor = (level: number) => {
    if (level >= 85) return 'cyber-green-neon'
    if (level >= 70) return 'cyber-blue-neon'
    if (level >= 50) return 'cyber-orange-neon'
    return 'security-critical'
  }

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Security Testing': return 'pink'
      case 'Infrastructure': return 'blue'
      case 'Operations': return 'orange'
      case 'Analysis': return 'purple'
      default: return 'green'
    }
  }

  return (
    <CyberpunkCard variant="neon-blue" className={cn('relative overflow-hidden', className)}>
      <ParticleSystem
        particleCount={25}
        color="blue"
        speed="medium"
        size="small"
        className="opacity-20"
      />

      <CyberpunkCardHeader accent>
        <div className="flex items-center justify-between">
          <CyberpunkCardTitle className="flex items-center gap-2 text-cyber-blue-neon">
            <BeakerIcon className="w-6 h-6" />
            <GlitchText intensity="low">SKILL ASSESSMENTS</GlitchText>
          </CyberpunkCardTitle>
          <SecurityButton level="medium" size="sm">TRACKING</SecurityButton>
        </div>
      </CyberpunkCardHeader>

      <CyberpunkCardContent>
        <div className="space-y-4">
          {/* Overall Progress */}
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <CyberpunkProgressRing
                value={Math.round(skillAreas.reduce((acc, skill) => acc + skill.currentLevel, 0) / skillAreas.length)}
                color="blue"
                size={80}
                label="Overall"
                animated
              />
            </div>
            <div className="space-y-2">
              <div className="text-lg font-display font-bold text-cyber-green-neon">
                {skillAreas.filter(s => s.assessmentAvailable).length}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Available Assessments</div>
            </div>
            <div className="space-y-2">
              <div className="text-lg font-display font-bold text-cyber-blue-neon">
                {skillAreas.filter(s => s.currentLevel >= s.targetLevel).length}
              </div>
              <div className="text-xs text-matrix-muted font-cyber">Goals Achieved</div>
            </div>
          </div>

          {/* Skill Areas */}
          <div className="space-y-3 max-h-64 overflow-y-auto scrollbar-cyber">
            {skillAreas.map((skill) => {
              const skillColor = getSkillColor(skill.currentLevel)
              const categoryColor = getCategoryColor(skill.category)

              return (
                <HolographicDisplay
                  key={skill.id}
                  color={categoryColor}
                  intensity="low"
                  className="p-3"
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-cyber font-bold text-matrix-white">
                          {skill.name}
                        </h4>
                        <span className={`text-xs font-cyber text-cyber-${categoryColor}-neon`}>
                          {skill.category}
                        </span>
                      </div>
                      <div className="text-right">
                        <div className={`text-lg font-display font-bold text-${skillColor}`}>
                          {skill.currentLevel}%
                        </div>
                        <div className="text-xs text-matrix-muted font-matrix">
                          Target: {skill.targetLevel}%
                        </div>
                      </div>
                    </div>

                    {/* Progress Bar */}
                    <div className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="text-matrix-muted">Current Level</span>
                        <span className={`text-${skillColor}`}>{skill.currentLevel}%</span>
                      </div>
                      <div className="h-2 bg-matrix-surface rounded-full overflow-hidden">
                        <div
                          className={`h-full transition-all duration-1000 rounded-full bg-${skillColor}`}
                          style={{ width: `${skill.currentLevel}%` }}
                        />
                      </div>
                    </div>

                    {/* Strengths and Improvements */}
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div>
                        <span className="text-cyber-green-neon font-cyber">Strengths:</span>
                        <div className="text-matrix-light">
                          {skill.strengths.slice(0, 2).join(', ')}
                        </div>
                      </div>
                      <div>
                        <span className="text-cyber-orange-neon font-cyber">Improve:</span>
                        <div className="text-matrix-light">
                          {skill.improvements.slice(0, 2).join(', ')}
                        </div>
                      </div>
                    </div>

                    {/* Assessment Action */}
                    <div className="flex gap-2">
                      {skill.assessmentAvailable ? (
                        <Link href={`/dashboard/assessments/${skill.id}`} className="flex-1">
                          <CyberpunkButton
                            variant={`ghost-${categoryColor}` as any}
                            size="sm"
                            className="w-full animate-neon-pulse"
                          >
                            <PlayIcon className="w-3 h-3 mr-2" />
                            Take Assessment
                          </CyberpunkButton>
                        </Link>
                      ) : (
                        <CyberpunkButton
                          variant="ghost-blue"
                          size="sm"
                          className="flex-1 opacity-50 cursor-not-allowed"
                          disabled
                        >
                          <ClockIcon className="w-3 h-3 mr-2" />
                          Next: {skill.nextAssessment.toLocaleDateString()}
                        </CyberpunkButton>
                      )}
                      <Link href={`/dashboard/skills/${skill.id}/progress`}>
                        <CyberpunkButton variant="ghost-blue" size="sm">
                          <ArrowRightIcon className="w-3 h-3" />
                        </CyberpunkButton>
                      </Link>
                    </div>
                  </div>
                </HolographicDisplay>
              )
            })}
          </div>
        </div>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}
