import { Metadata } from 'next'
import Link from 'next/link'
import { ArrowLeftIcon, SparklesIcon, EyeIcon, CpuChipIcon } from '@heroicons/react/24/outline'
import { EnhancedButton } from '@/components/ui/enhanced-button'
import { EnhancedCard, EnhancedCardContent, EnhancedCardDescription, EnhancedCardHeader, EnhancedCardTitle } from '@/components/ui/enhanced-card'
import { EnhancedParticleSystem } from '@/components/ui/enhanced-particle-system'
import { EnhancedGlowEffects, GlowOrb, FloatingElements, ScanLine, HologramGrid, DataStream } from '@/components/ui/enhanced-glow-effects'
import { CyberpunkBackground, GlitchText, NeonBorder } from '@/components/ui/cyberpunk-background'

export const metadata: Metadata = {
  title: 'Visual Showcase - HackAI Enhanced Design',
  description: 'Showcase of enhanced visual effects, animations, and UI components for the HackAI platform.',
}

const buttonVariants = [
  { variant: 'primary' as const, label: 'Primary Button' },
  { variant: 'neon-blue' as const, label: 'Neon Blue' },
  { variant: 'neon-pink' as const, label: 'Neon Pink' },
  { variant: 'neon-green' as const, label: 'Neon Green' },
  { variant: 'glass' as const, label: 'Glass Effect' },
  { variant: 'hologram' as const, label: 'Hologram' },
  { variant: 'matrix' as const, label: 'Matrix Style' },
]

const cardVariants = [
  { variant: 'glass' as const, title: 'Glass Morphism', description: 'Advanced glass effect with backdrop blur' },
  { variant: 'neon-blue' as const, title: 'Neon Blue', description: 'Cyberpunk blue neon styling' },
  { variant: 'neon-pink' as const, title: 'Neon Pink', description: 'Vibrant pink neon effects' },
  { variant: 'matrix' as const, title: 'Matrix Theme', description: 'Classic matrix green styling' },
  { variant: 'hologram' as const, title: 'Hologram Effect', description: 'Futuristic holographic appearance' },
  { variant: 'security' as const, title: 'Security Theme', description: 'Professional security styling' },
]

export default function ShowcasePage() {
  return (
    <CyberpunkBackground variant="particles" intensity="medium" color="blue" className="min-h-screen">
      {/* Enhanced Background Effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <EnhancedParticleSystem
          particleCount={60}
          colors={['#00d4ff', '#ff0080', '#00ff41', '#8000ff']}
          speed={0.4}
          direction="random"
          interactive={true}
          glow={true}
          className="opacity-40"
        />
        <EnhancedGlowEffects variant="all" intensity="low" color="multi" className="opacity-30" />
      </div>

      <div className="relative z-10">
        {/* Header */}
        <div className="px-6 py-8">
          <div className="max-w-8xl mx-auto">
            <Link href="/" className="inline-flex items-center text-cyber-blue-neon hover:text-cyber-blue-bright transition-colors">
              <ArrowLeftIcon className="w-5 h-5 mr-2" />
              Back to Home
            </Link>
            
            <div className="mt-8 text-center">
              <NeonBorder color="blue" intensity="medium" className="inline-block mb-6">
                <div className="px-6 py-2 bg-matrix-dark/80 backdrop-blur-sm">
                  <span className="text-cyber-blue-neon font-cyber text-sm tracking-wider">
                    ✨ ENHANCED VISUAL SHOWCASE
                  </span>
                </div>
              </NeonBorder>

              <h1 className="text-4xl sm:text-6xl font-display font-bold text-matrix-white mb-6">
                <GlitchText intensity="medium">
                  <span className="text-gradient-cyber">Enhanced Design System</span>
                </GlitchText>
              </h1>

              <p className="text-xl text-matrix-lighter max-w-4xl mx-auto font-cyber">
                Experience the enhanced visual effects, animations, and UI components that make HackAI look even more stunning.
              </p>
            </div>
          </div>
        </div>

        {/* Enhanced Buttons Section */}
        <div className="px-6 py-16">
          <div className="max-w-8xl mx-auto">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-display font-bold text-matrix-white mb-4">
                <GlitchText intensity="low">Enhanced Buttons</GlitchText>
              </h2>
              <p className="text-matrix-light font-cyber">Interactive buttons with advanced animations and effects</p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              {buttonVariants.map((button, index) => (
                <div key={button.variant} className="text-center space-y-4">
                  <EnhancedButton
                    variant={button.variant}
                    size="lg"
                    glow={true}
                    scanLine={true}
                    className="w-full opacity-0 animate-fade-in"
                    style={{ 
                      animationDelay: `${index * 0.1}s`,
                      animationFillMode: 'forwards'
                    }}
                  >
                    <SparklesIcon className="w-5 h-5 mr-2" />
                    {button.label}
                  </EnhancedButton>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Enhanced Cards Section */}
        <div className="px-6 py-16">
          <div className="max-w-8xl mx-auto">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-display font-bold text-matrix-white mb-4">
                <GlitchText intensity="low">Enhanced Cards</GlitchText>
              </h2>
              <p className="text-matrix-light font-cyber">Advanced card components with glass morphism and neon effects</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
              {cardVariants.map((card, index) => (
                <EnhancedCard
                  key={card.variant}
                  variant={card.variant}
                  size="lg"
                  interactive={true}
                  glow={true}
                  scanLine={true}
                  cornerAccents={true}
                  floating={true}
                  className="opacity-0 animate-fade-in"
                  style={{ 
                    animationDelay: `${index * 0.15}s`,
                    animationFillMode: 'forwards'
                  }}
                >
                  <EnhancedCardHeader accent>
                    <div className="flex items-center justify-between mb-4">
                      <div className="p-3 rounded-lg bg-current/10 border border-current/30">
                        <CpuChipIcon className="h-8 w-8 text-current" />
                      </div>
                      <div className="w-2 h-2 bg-current rounded-full animate-pulse" />
                    </div>
                    <EnhancedCardTitle glow gradient className="text-xl">
                      {card.title}
                    </EnhancedCardTitle>
                  </EnhancedCardHeader>

                  <EnhancedCardContent>
                    <EnhancedCardDescription className="text-base leading-relaxed mb-6">
                      {card.description}
                    </EnhancedCardDescription>

                    <EnhancedButton
                      variant="ghost"
                      size="sm"
                      className="w-full"
                    >
                      <EyeIcon className="w-4 h-4 mr-2" />
                      Explore
                    </EnhancedButton>
                  </EnhancedCardContent>
                </EnhancedCard>
              ))}
            </div>
          </div>
        </div>

        {/* Visual Effects Showcase */}
        <div className="px-6 py-16">
          <div className="max-w-8xl mx-auto">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-display font-bold text-matrix-white mb-4">
                <GlitchText intensity="low">Visual Effects</GlitchText>
              </h2>
              <p className="text-matrix-light font-cyber">Advanced particle systems, glow effects, and animations</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {/* Particle System Demo */}
              <EnhancedCard variant="glass" size="lg" className="h-64 relative">
                <EnhancedCardHeader>
                  <EnhancedCardTitle>Particle System</EnhancedCardTitle>
                  <EnhancedCardDescription>Interactive particle effects with mouse interaction</EnhancedCardDescription>
                </EnhancedCardHeader>
                <EnhancedParticleSystem
                  particleCount={30}
                  colors={['#00d4ff', '#ff0080']}
                  speed={1}
                  interactive={true}
                  glow={true}
                  className="absolute inset-0 rounded-xl"
                />
              </EnhancedCard>

              {/* Glow Effects Demo */}
              <EnhancedCard variant="matrix" size="lg" className="h-64 relative">
                <EnhancedCardHeader>
                  <EnhancedCardTitle>Glow Effects</EnhancedCardTitle>
                  <EnhancedCardDescription>Advanced lighting and glow systems</EnhancedCardDescription>
                </EnhancedCardHeader>
                <GlowOrb color="green" size="md" position={{ x: '30%', y: '60%' }} />
                <GlowOrb color="blue" size="sm" position={{ x: '70%', y: '40%' }} />
                <FloatingElements count={10} colors={['#00ff41', '#00d4ff']} />
              </EnhancedCard>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-16 text-center">
          <div className="max-w-4xl mx-auto">
            <h3 className="text-2xl font-display font-bold text-matrix-white mb-4">
              <GlitchText intensity="low">Ready to Experience HackAI?</GlitchText>
            </h3>
            <p className="text-matrix-light font-cyber mb-8">
              These enhanced visual effects are now integrated throughout the entire platform.
            </p>
            <Link href="/">
              <EnhancedButton variant="primary" size="xl" glow={true} scanLine={true}>
                <ArrowLeftIcon className="w-5 h-5 mr-2" />
                Return to Platform
              </EnhancedButton>
            </Link>
          </div>
        </div>
      </div>
    </CyberpunkBackground>
  )
}
