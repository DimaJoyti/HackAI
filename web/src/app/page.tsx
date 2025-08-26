import { Metadata } from 'next'
import Link from 'next/link'
import { ArrowRightIcon, ShieldCheckIcon, CpuChipIcon, AcademicCapIcon, EyeIcon, BoltIcon, CodeBracketIcon } from '@heroicons/react/24/outline'
import { CyberpunkButton, NeonButton, HologramButton, SecurityButton } from '@/components/ui/cyberpunk-button'
import { CyberpunkCard, CyberpunkCardContent, CyberpunkCardDescription, CyberpunkCardHeader, CyberpunkCardTitle, SecurityCard, MatrixCard, HologramCard } from '@/components/ui/cyberpunk-card'
import { CyberpunkBackground, MatrixRain, GlitchText, NeonBorder } from '@/components/ui/cyberpunk-background'
import { CyberpunkNav } from '@/components/ui/cyberpunk-nav'
import { EnhancedParticleSystem } from '@/components/ui/enhanced-particle-system'
import { EnhancedGlowEffects } from '@/components/ui/enhanced-glow-effects'

export const metadata: Metadata = {
  title: 'HackAI - Educational Cybersecurity AI Platform',
  description: 'Learn cybersecurity through hands-on AI-powered security tools and interactive educational modules.',
}

const features = [
  {
    name: 'AI-Powered Vulnerability Scanner',
    description: 'Advanced machine learning algorithms detect security vulnerabilities in web applications, APIs, and network services with real-time threat analysis.',
    icon: ShieldCheckIcon,
    variant: 'security-critical' as const,
    level: 'critical' as const,
  },
  {
    name: 'Network Security Analysis',
    description: 'Real-time network monitoring, port scanning, and traffic analysis with anomaly detection capabilities and behavioral pattern recognition.',
    icon: CpuChipIcon,
    variant: 'neon-blue' as const,
    level: 'high' as const,
  },
  {
    name: 'Interactive Learning Modules',
    description: 'Hands-on cybersecurity education with guided tutorials, labs, and real-world scenarios in immersive virtual environments.',
    icon: AcademicCapIcon,
    variant: 'neon-green' as const,
    level: 'safe' as const,
  },
  {
    name: 'Advanced Threat Intelligence',
    description: 'AI-driven threat intelligence gathering and analysis with predictive modeling and automated response systems.',
    icon: EyeIcon,
    variant: 'neon-purple' as const,
    level: 'medium' as const,
  },
  {
    name: 'Penetration Testing Suite',
    description: 'Comprehensive penetration testing tools with automated exploit generation and vulnerability assessment frameworks.',
    icon: BoltIcon,
    variant: 'neon-orange' as const,
    level: 'high' as const,
  },
  {
    name: 'Code Security Analysis',
    description: 'Static and dynamic code analysis with machine learning-powered vulnerability detection and secure coding recommendations.',
    icon: CodeBracketIcon,
    variant: 'neon-pink' as const,
    level: 'medium' as const,
  },
]

const stats = [
  { name: 'Security Scans Performed', value: '10,000+', color: 'blue' as const },
  { name: 'Vulnerabilities Detected', value: '50,000+', color: 'pink' as const },
  { name: 'Students Trained', value: '5,000+', color: 'green' as const },
  { name: 'Educational Modules', value: '100+', color: 'purple' as const },
  { name: 'Threat Patterns Analyzed', value: '1M+', color: 'orange' as const },
  { name: 'AI Models Deployed', value: '25+', color: 'blue' as const },
]

const navItems = [
  { href: '/dashboard', label: 'Dashboard', icon: <CpuChipIcon className="w-5 h-5" /> },
  { href: '/scanner', label: 'Security Scanner', icon: <ShieldCheckIcon className="w-5 h-5" />, badge: 'AI' },
  { href: '/education', label: 'Learn', icon: <AcademicCapIcon className="w-5 h-5" /> },
  { href: '/analytics', label: 'Analytics', icon: <EyeIcon className="w-5 h-5" /> },
  { href: '/showcase', label: 'Showcase', icon: <EyeIcon className="w-5 h-5" />, badge: 'NEW' },
]

export default function HomePage() {
  return (
    <CyberpunkBackground variant="particles" intensity="medium" color="blue" className="min-h-screen">
      {/* Matrix Rain Background */}
      <MatrixRain intensity="low" color="#00ff41" className="opacity-20" />

      {/* Navigation */}
      <CyberpunkNav
        items={navItems}
        theme="blue"
        logoText="HackAI"
        logoHref="/"
        className="relative z-20"
      />

      {/* Additional Navigation Actions */}
      <div className="absolute top-4 right-4 z-30 flex items-center space-x-4">
        <Link href="/auth/login">
          <CyberpunkButton variant="ghost-blue" size="sm">
            Sign In
          </CyberpunkButton>
        </Link>
        <Link href="/auth/register">
          <NeonButton size="sm" scanLine>
            <GlitchText intensity="low">Get Started</GlitchText>
          </NeonButton>
        </Link>
      </div>

      {/* Enhanced Hero Section */}
      <div className="relative overflow-hidden pt-24 pb-40 min-h-screen flex items-center">
        <div className="mx-auto max-w-8xl px-6 sm:px-8 lg:px-12">
          <div className="text-center relative z-10">
            {/* Cyberpunk Badge */}
            <NeonBorder color="blue" intensity="medium" className="inline-block mb-8">
              <div className="px-6 py-2 bg-matrix-dark/80 backdrop-blur-sm">
                <span className="text-cyber-blue-neon font-cyber text-sm tracking-wider">
                  🚀 EDUCATIONAL CYBERSECURITY PLATFORM
                </span>
              </div>
            </NeonBorder>

            {/* Enhanced Main Title */}
            <h1 className="text-4xl font-display font-bold tracking-tight text-matrix-white sm:text-7xl lg:text-8xl mb-8 animate-float-gentle">
              <GlitchText intensity="medium">
                <span className="text-gradient-cyber animate-text-shimmer">
                  Learn Cybersecurity
                </span>
              </GlitchText>
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-blue-bright via-cyber-pink-bright to-cyber-purple-bright animate-glow-pulse">
                with AI-Powered Tools
              </span>
            </h1>

            {/* Enhanced Subtitle */}
            <p className="mt-8 text-xl leading-8 text-matrix-lighter max-w-4xl mx-auto font-cyber opacity-0 animate-fade-in" style={{ animationDelay: '0.5s', animationFillMode: 'forwards' }}>
              Master cybersecurity through hands-on experience with advanced AI-powered security tools.
              Scan for vulnerabilities, analyze networks, and learn from real-world scenarios in a safe,
              educational environment powered by cutting-edge artificial intelligence.
            </p>

            {/* Enhanced CTA Buttons */}
            <div className="mt-12 flex items-center justify-center gap-x-8 opacity-0 animate-fade-in" style={{ animationDelay: '1s', animationFillMode: 'forwards' }}>
              <Link href="/auth/register" className="group">
                <CyberpunkButton
                  variant="filled-blue"
                  size="xl"
                  animation="glow"
                  font="cyber"
                  scanLine
                  className="group-hover:scale-105 transition-all duration-300 hover:shadow-neon-blue-lg"
                >
                  <GlitchText intensity="low">Start Learning</GlitchText>
                  <ArrowRightIcon className="ml-3 h-5 w-5 transition-all duration-300 group-hover:translate-x-2 group-hover:scale-110" />
                </CyberpunkButton>
              </Link>
              <Link href="/demo" className="group">
                <HologramButton size="xl" font="cyber" className="group-hover:scale-105 transition-all duration-300 hover:shadow-hologram">
                  <EyeIcon className="mr-3 h-5 w-5 transition-all duration-300 group-hover:scale-110" />
                  <span className="transition-all duration-300 group-hover:text-cyber-blue-bright">View Demo</span>
                </HologramButton>
              </Link>
            </div>

            {/* Security Status Indicators */}
            <div className="mt-16 flex items-center justify-center gap-4 flex-wrap">
              <SecurityButton level="safe" size="sm">
                System Online
              </SecurityButton>
              <SecurityButton level="medium" size="sm">
                AI Active
              </SecurityButton>
              <SecurityButton level="low" size="sm">
                Secure Connection
              </SecurityButton>
            </div>
          </div>
        </div>

        {/* Enhanced Cyberpunk Background Effects */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          {/* Enhanced Particle System */}
          <EnhancedParticleSystem
            particleCount={80}
            colors={['#00d4ff', '#ff0080', '#00ff41', '#8000ff', '#ff6600']}
            speed={0.5}
            direction="random"
            interactive={true}
            glow={true}
            className="opacity-60"
          />

          {/* Enhanced Glow Effects */}
          <EnhancedGlowEffects
            variant="all"
            intensity="medium"
            color="multi"
            className="opacity-40"
          />

          {/* Holographic Grid */}
          <div className="absolute inset-0 bg-cyber-grid opacity-5" />

          {/* Enhanced Scan Lines */}
          <div className="absolute inset-0">
            <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyber-blue-bright to-transparent animate-scan-line opacity-40" />
            <div className="absolute top-1/2 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyber-pink-bright to-transparent animate-scan-line opacity-30" style={{ animationDelay: '1s' }} />
            <div className="absolute bottom-1/4 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyber-green-bright to-transparent animate-scan-line opacity-25" style={{ animationDelay: '2s' }} />
          </div>
        </div>
      </div>

      {/* Enhanced Features Section */}
      <div className="py-32 sm:py-40 relative">
        <div className="mx-auto max-w-8xl px-6 sm:px-8 lg:px-12">
          <div className="mx-auto max-w-5xl text-center mb-24">
            <NeonBorder color="green" intensity="low" className="inline-block mb-6">
              <div className="px-4 py-2 bg-matrix-dark/60 backdrop-blur-sm">
                <span className="text-cyber-green-neon font-cyber text-sm tracking-wider uppercase">
                  Advanced Security Tools
                </span>
              </div>
            </NeonBorder>

            <h2 className="text-4xl font-display font-bold tracking-tight text-matrix-white sm:text-5xl mb-6">
              <GlitchText intensity="low">
                Everything you need to learn cybersecurity
              </GlitchText>
            </h2>

            <p className="text-lg leading-8 text-matrix-light font-cyber max-w-3xl mx-auto">
              Our platform combines cutting-edge AI technology with educational best practices to provide
              an immersive learning experience in the world of cybersecurity and ethical hacking.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8 lg:gap-12 max-w-none">
            {features.map((feature, index) => (
              <CyberpunkCard
                key={feature.name}
                variant={feature.variant}
                size="lg"
                interactive
                scanLine
                cornerAccents
                className="group hover:scale-105 hover:-translate-y-2 transition-all duration-500 ease-out opacity-0 animate-fade-in hover:shadow-2xl"
                style={{
                  animationDelay: `${index * 0.2}s`,
                  animationFillMode: 'forwards'
                }}
              >
                <CyberpunkCardHeader accent>
                  <div className="flex items-center justify-between mb-4">
                    <div className="p-3 rounded-lg bg-current/10 border border-current/30 shadow-neon-blue/30 group-hover:bg-current/20 group-hover:shadow-neon-blue transition-all duration-300">
                      <feature.icon className="h-8 w-8 text-current transition-all duration-300 group-hover:scale-110 group-hover:rotate-3" aria-hidden="true" />
                    </div>
                    <SecurityButton level={feature.level} size="sm" className="group-hover:animate-glow-pulse">
                      {feature.level.toUpperCase()}
                    </SecurityButton>
                  </div>
                  <CyberpunkCardTitle glow font="cyber" className="text-xl group-hover:text-gradient-cyber transition-all duration-300">
                    <GlitchText intensity="low">
                      {feature.name}
                    </GlitchText>
                  </CyberpunkCardTitle>
                </CyberpunkCardHeader>

                <CyberpunkCardContent>
                  <CyberpunkCardDescription className="text-base leading-relaxed transition-all duration-300 group-hover:text-matrix-white">
                    {feature.description}
                  </CyberpunkCardDescription>

                  <div className="mt-6 pt-4 border-t border-current/20 group-hover:border-current/40 transition-all duration-300">
                    <CyberpunkButton
                      variant="ghost-blue"
                      size="sm"
                      className="w-full group-hover:animate-neon-pulse transform transition-all duration-300 hover:scale-105"
                    >
                      <span className="transition-all duration-300 group-hover:text-cyber-blue-bright">Learn More</span>
                      <ArrowRightIcon className="ml-2 h-4 w-4 transition-all duration-300 group-hover:translate-x-2 group-hover:text-cyber-blue-bright" />
                    </CyberpunkButton>
                  </div>
                </CyberpunkCardContent>
              </CyberpunkCard>
            ))}
          </div>
        </div>

        {/* Enhanced Background Effects */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <EnhancedParticleSystem
            particleCount={40}
            colors={['#00d4ff', '#00ff41']}
            speed={0.3}
            direction="up"
            glow={true}
            className="opacity-30"
          />
          <div className="absolute inset-0 bg-circuit opacity-3" />
          <EnhancedGlowEffects variant="grid" intensity="low" color="blue" className="opacity-20" />
        </div>
      </div>

      {/* Enhanced Stats Section */}
      <div className="relative py-32 sm:py-40 overflow-hidden">
        {/* Enhanced Matrix Background */}
        <div className="absolute inset-0 bg-matrix opacity-15" />
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-matrix-dark/20 to-transparent" />

        <div className="mx-auto max-w-8xl px-6 sm:px-8 lg:px-12 relative z-10">
          <div className="mx-auto max-w-5xl text-center mb-20">
            <h2 className="text-4xl font-display font-bold tracking-tight text-matrix-white sm:text-5xl mb-6">
              <GlitchText intensity="medium">
                Trusted by cybersecurity professionals
              </GlitchText>
              <br />
              <span className="text-cyber-green-neon">worldwide</span>
            </h2>
            <p className="text-lg leading-8 text-matrix-light font-cyber">
              Join thousands of learners who have enhanced their cybersecurity skills with HackAI's
              cutting-edge AI-powered educational platform.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-6 sm:grid-cols-3 lg:grid-cols-6 lg:gap-8">
            {stats.map((stat, index) => (
              <MatrixCard
                key={stat.name}
                size="lg"
                interactive
                className="text-center group hover:scale-110 hover:-translate-y-3 transition-all duration-500 ease-out opacity-0 animate-fade-in glass-cyber"
                style={{
                  animationDelay: `${index * 0.15}s`,
                  animationFillMode: 'forwards'
                }}
              >
                <div className="space-y-4 relative">
                  <div className={`text-4xl font-display font-bold tracking-tight text-cyber-${stat.color}-neon group-hover:animate-glow-pulse group-hover:text-cyber-${stat.color}-bright transition-all duration-300`}>
                    <GlitchText intensity="low">
                      <span className="relative">
                        {stat.value}
                        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-current to-transparent opacity-0 group-hover:opacity-30 animate-text-shimmer" />
                      </span>
                    </GlitchText>
                  </div>
                  <div className="text-sm font-cyber font-semibold leading-6 text-matrix-text uppercase tracking-wider transition-all duration-300 group-hover:text-matrix-lighter">
                    {stat.name}
                  </div>

                  {/* Enhanced Data Stream Effect */}
                  <div className="h-1 bg-gradient-to-r from-transparent via-current to-transparent opacity-0 group-hover:opacity-100 transition-all duration-500 animate-pulse" />

                  {/* Floating particles effect */}
                  <div className="absolute -top-2 -right-2 w-2 h-2 bg-current rounded-full opacity-0 group-hover:opacity-100 group-hover:animate-float-gentle transition-all duration-300" />
                  <div className="absolute -bottom-2 -left-2 w-1 h-1 bg-current rounded-full opacity-0 group-hover:opacity-100 group-hover:animate-float-gentle transition-all duration-300" style={{ animationDelay: '0.5s' }} />
                </div>
              </MatrixCard>
            ))}
          </div>

          {/* Floating Security Indicators */}
          <div className="mt-16 flex items-center justify-center gap-6 flex-wrap">
            <NeonBorder color="green" intensity="medium" className="px-4 py-2">
              <div className="flex items-center gap-2 text-cyber-green-neon font-cyber">
                <div className="w-2 h-2 bg-cyber-green-neon rounded-full animate-neon-pulse" />
                <span className="text-sm">SYSTEM SECURE</span>
              </div>
            </NeonBorder>

            <NeonBorder color="blue" intensity="medium" className="px-4 py-2">
              <div className="flex items-center gap-2 text-cyber-blue-neon font-cyber">
                <div className="w-2 h-2 bg-cyber-blue-neon rounded-full animate-neon-pulse" />
                <span className="text-sm">AI ACTIVE</span>
              </div>
            </NeonBorder>

            <NeonBorder color="purple" intensity="medium" className="px-4 py-2">
              <div className="flex items-center gap-2 text-cyber-purple-neon font-cyber">
                <div className="w-2 h-2 bg-cyber-purple-neon rounded-full animate-neon-pulse" />
                <span className="text-sm">LEARNING MODE</span>
              </div>
            </NeonBorder>
          </div>
        </div>
      </div>

      {/* Enhanced CTA Section */}
      <div className="relative py-32 sm:py-40 overflow-hidden">
        {/* Enhanced Holographic Background */}
        <CyberpunkBackground variant="hologram" intensity="high" color="blue" />
        <div className="absolute inset-0 bg-gradient-to-t from-matrix-void via-transparent to-matrix-void opacity-60" />

        <div className="mx-auto max-w-6xl px-6 sm:px-8 lg:px-12 relative z-10">
          <HologramCard size="xl" className="text-center backdrop-blur-xl">
            <div className="space-y-8">
              <h2 className="text-4xl font-display font-bold tracking-tight text-matrix-white sm:text-5xl">
                <GlitchText intensity="medium">
                  Ready to start your
                </GlitchText>
                <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-blue-neon to-cyber-pink-neon">
                  cybersecurity journey?
                </span>
              </h2>

              <p className="mx-auto max-w-2xl text-lg leading-8 text-matrix-light font-cyber">
                Join HackAI today and gain hands-on experience with the latest cybersecurity tools and techniques
                powered by cutting-edge artificial intelligence and machine learning algorithms.
              </p>

              <div className="flex items-center justify-center gap-8 flex-wrap">
                <Link href="/auth/register">
                  <CyberpunkButton
                    variant="filled-blue"
                    size="xl"
                    animation="glow"
                    font="cyber"
                    scanLine
                  >
                    <GlitchText intensity="low">Get Started for Free</GlitchText>
                  </CyberpunkButton>
                </Link>

                <Link href="/contact">
                  <CyberpunkButton
                    variant="ghost-blue"
                    size="xl"
                    font="cyber"
                    className="group"
                  >
                    Contact Us
                    <ArrowRightIcon className="ml-2 h-5 w-5 transition-transform group-hover:translate-x-1" />
                  </CyberpunkButton>
                </Link>
              </div>

              {/* Terminal-style info */}
              <div className="mt-12 p-6 bg-matrix-black/80 border border-cyber-green-neon/30 rounded-lg font-matrix text-sm">
                <div className="text-cyber-green-neon mb-2">
                  <span className="animate-terminal-cursor">$</span> hackai --status
                </div>
                <div className="text-matrix-light space-y-1">
                  <div>✓ AI Systems: <span className="text-cyber-green-neon">ONLINE</span></div>
                  <div>✓ Security Scanners: <span className="text-cyber-green-neon">READY</span></div>
                  <div>✓ Learning Modules: <span className="text-cyber-green-neon">LOADED</span></div>
                  <div>✓ Threat Intelligence: <span className="text-cyber-green-neon">ACTIVE</span></div>
                </div>
              </div>
            </div>
          </HologramCard>
        </div>
      </div>

      {/* Footer */}
      <footer className="relative bg-matrix-black border-t border-cyber-blue-neon/20">
        <div className="absolute inset-0 bg-cyber-grid opacity-5" />

        <div className="mx-auto max-w-7xl px-4 py-16 sm:px-6 lg:px-8 relative z-10">
          <div className="text-center space-y-8">
            <div className="flex items-center justify-center">
              <h3 className="text-4xl font-display font-bold text-matrix-white">
                <GlitchText intensity="low">
                  Hack<span className="text-cyber-blue-neon">AI</span>
                </GlitchText>
              </h3>
            </div>

            <p className="text-lg text-matrix-light font-cyber">
              Educational Cybersecurity AI Platform
            </p>

            <div className="flex items-center justify-center gap-8 flex-wrap">
              <NeonBorder color="blue" intensity="low" className="px-3 py-1">
                <span className="text-cyber-blue-neon font-cyber text-sm">SECURE</span>
              </NeonBorder>
              <NeonBorder color="green" intensity="low" className="px-3 py-1">
                <span className="text-cyber-green-neon font-cyber text-sm">EDUCATIONAL</span>
              </NeonBorder>
              <NeonBorder color="purple" intensity="low" className="px-3 py-1">
                <span className="text-cyber-purple-neon font-cyber text-sm">AI-POWERED</span>
              </NeonBorder>
            </div>

            <div className="pt-8 border-t border-matrix-border">
              <p className="text-sm text-matrix-muted font-matrix">
                © 2024 HackAI. All rights reserved. Built for educational purposes.
                <br />
                <span className="text-cyber-green-neon">SYSTEM STATUS: OPERATIONAL</span>
              </p>
            </div>
          </div>
        </div>
      </footer>
    </CyberpunkBackground>
  )
}
