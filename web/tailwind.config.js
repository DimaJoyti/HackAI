/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
    './src/lib/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Enhanced Cyberpunk Primary Palette
        cyber: {
          // Neon Blue - Enhanced with more vibrant variations
          blue: {
            50: '#e6f8ff',
            100: '#b3e8ff',
            200: '#80d8ff',
            300: '#4dc8ff',
            400: '#1ab8ff',
            500: '#00a8ff',
            600: '#0088cc',
            700: '#006899',
            800: '#004866',
            900: '#002833',
            neon: '#00d4ff',
            bright: '#00e6ff',
            glow: '#00a8cc',
            dark: '#0099cc',
            electric: '#00ccff',
          },
          // Neon Pink/Magenta - Enhanced with more depth
          pink: {
            50: '#ffe6f9',
            100: '#ffb3ec',
            200: '#ff80df',
            300: '#ff4dd2',
            400: '#ff1ac5',
            500: '#e600b8',
            600: '#b30092',
            700: '#80006c',
            800: '#4d0046',
            900: '#1a0020',
            neon: '#ff0080',
            bright: '#ff1a99',
            glow: '#cc0066',
            dark: '#cc0066',
            electric: '#ff3399',
          },
          // Neon Green - Enhanced with matrix-style variations
          green: {
            50: '#e6ffe8',
            100: '#b3ffb8',
            200: '#80ff88',
            300: '#4dff58',
            400: '#1aff28',
            500: '#00e600',
            600: '#00b300',
            700: '#008000',
            800: '#004d00',
            900: '#001a00',
            neon: '#00ff41',
            bright: '#00ff55',
            glow: '#00cc33',
            dark: '#00cc33',
            matrix: '#00ff41',
          },
          // Neon Purple - Enhanced with mystical variations
          purple: {
            50: '#f0e6ff',
            100: '#d4b3ff',
            200: '#b880ff',
            300: '#9c4dff',
            400: '#801aff',
            500: '#6400e6',
            600: '#5000b3',
            700: '#3c0080',
            800: '#28004d',
            900: '#14001a',
            neon: '#8000ff',
            bright: '#9933ff',
            glow: '#6600cc',
            dark: '#6600cc',
            mystic: '#7700ff',
          },
          // Neon Orange/Yellow - Enhanced with energy variations
          orange: {
            50: '#fff5e6',
            100: '#ffe0b3',
            200: '#ffcb80',
            300: '#ffb64d',
            400: '#ffa11a',
            500: '#e68c00',
            600: '#b36f00',
            700: '#805200',
            800: '#4d3500',
            900: '#1a1800',
            neon: '#ff6600',
            bright: '#ff7700',
            glow: '#cc5200',
            dark: '#cc5200',
            energy: '#ff8800',
          },
          // New: Neon Cyan for additional variety
          cyan: {
            50: '#e6ffff',
            100: '#b3ffff',
            200: '#80ffff',
            300: '#4dffff',
            400: '#1affff',
            500: '#00e6e6',
            600: '#00b3b3',
            700: '#008080',
            800: '#004d4d',
            900: '#001a1a',
            neon: '#00ffff',
            bright: '#33ffff',
            glow: '#00cccc',
            dark: '#00cccc',
            electric: '#00dddd',
          },
        },
        // Enhanced Cyberpunk Dark Palette
        matrix: {
          void: '#000000',
          black: '#0a0a0a',
          deep: '#111111',
          dark: '#1a1a1a',
          darker: '#222222',
          surface: '#2a2a2a',
          elevated: '#333333',
          border: '#404040',
          muted: '#555555',
          subtle: '#666666',
          text: '#888888',
          light: '#aaaaaa',
          lighter: '#cccccc',
          white: '#ffffff',
          // New gradient stops for better depth
          'surface-glass': 'rgba(42, 42, 42, 0.8)',
          'surface-blur': 'rgba(42, 42, 42, 0.6)',
          'border-glow': 'rgba(64, 64, 64, 0.8)',
        },
        // Brand colors (enhanced)
        brand: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
          950: '#082f49',
        },
        // Enhanced Security status colors with gradients
        security: {
          critical: '#ff0040',
          'critical-glow': '#ff1a5a',
          'critical-dark': '#cc0033',
          high: '#ff4000',
          'high-glow': '#ff5a1a',
          'high-dark': '#cc3300',
          medium: '#ff8000',
          'medium-glow': '#ff9933',
          'medium-dark': '#cc6600',
          low: '#40ff00',
          'low-glow': '#5aff33',
          'low-dark': '#33cc00',
          info: '#0080ff',
          'info-glow': '#3399ff',
          'info-dark': '#0066cc',
          safe: '#00ff80',
          'safe-glow': '#33ff99',
          'safe-dark': '#00cc66',
        },
        // Enhanced Scan status colors with better visual feedback
        scan: {
          pending: '#666666',
          'pending-glow': '#808080',
          running: '#00d4ff',
          'running-glow': '#33ddff',
          'running-pulse': '#00a8cc',
          completed: '#00ff41',
          'completed-glow': '#33ff5a',
          failed: '#ff0040',
          'failed-glow': '#ff1a5a',
          cancelled: '#888888',
          'cancelled-glow': '#999999',
          warning: '#ff8000',
          'warning-glow': '#ff9933',
        },
        // New: Enhanced gradient colors
        gradient: {
          'cyber-blue': ['#00d4ff', '#0088cc'],
          'cyber-pink': ['#ff0080', '#cc0066'],
          'cyber-green': ['#00ff41', '#00cc33'],
          'cyber-purple': ['#8000ff', '#6600cc'],
          'cyber-orange': ['#ff6600', '#cc5200'],
          'matrix-depth': ['#000000', '#1a1a1a', '#333333'],
          'neon-glow': ['#00d4ff', '#ff0080', '#00ff41'],
          'security-alert': ['#ff0040', '#ff4000', '#ff8000'],
          'success-flow': ['#00ff41', '#00ff80', '#40ff00'],
        },
        // Dark mode colors
        dark: {
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
          950: '#020617',
        },
      },
      fontFamily: {
        sans: ['var(--font-inter)', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        cyber: ['var(--font-orbitron)', 'var(--font-exo-2)', 'var(--font-rajdhani)', 'Orbitron', 'Exo 2', 'Rajdhani', 'sans-serif'],
        matrix: ['var(--font-share-tech-mono)', 'Share Tech Mono', 'Courier New', 'monospace'],
        display: ['var(--font-audiowide)', 'var(--font-orbitron)', 'Audiowide', 'Orbitron', 'sans-serif'],
        orbitron: ['var(--font-orbitron)', 'Orbitron', 'sans-serif'],
        rajdhani: ['var(--font-rajdhani)', 'Rajdhani', 'sans-serif'],
        audiowide: ['var(--font-audiowide)', 'Audiowide', 'sans-serif'],
        'share-tech': ['var(--font-share-tech-mono)', 'Share Tech Mono', 'monospace'],
        'exo-2': ['var(--font-exo-2)', 'Exo 2', 'sans-serif'],
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.75rem' }],
        '10xl': ['10rem', { lineHeight: '1' }],
        '11xl': ['12rem', { lineHeight: '1' }],
        '12xl': ['14rem', { lineHeight: '1' }],
      },
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '128': '32rem',
        '144': '36rem',
        '160': '40rem',
        '192': '48rem',
      },
      animation: {
        // Original animations
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'fade-out': 'fadeOut 0.5s ease-in-out',
        'slide-in': 'slideIn 0.3s ease-out',
        'slide-out': 'slideOut 0.3s ease-in',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'bounce-slow': 'bounce 2s infinite',
        'spin-slow': 'spin 3s linear infinite',
        'ping-slow': 'ping 3s cubic-bezier(0, 0, 0.2, 1) infinite',

        // Cyberpunk animations
        'neon-pulse': 'neonPulse 2s ease-in-out infinite alternate',
        'neon-flicker': 'neonFlicker 0.15s ease-in-out infinite alternate',
        'glitch': 'glitch 0.3s ease-in-out infinite',
        'glitch-text': 'glitchText 2s ease-in-out infinite',
        'matrix-rain': 'matrixRain 20s linear infinite',
        'cyber-glow': 'cyberGlow 3s ease-in-out infinite alternate',
        'data-stream': 'dataStream 15s linear infinite',
        'hologram': 'hologram 4s ease-in-out infinite',
        'scan-line': 'scanLine 2s linear infinite',
        'terminal-cursor': 'terminalCursor 1s ease-in-out infinite',
        'float': 'float 6s ease-in-out infinite',
        'rotate-slow': 'rotate 20s linear infinite',
        'bounce-glow': 'bounceGlow 2s ease-in-out infinite',
        'slide-glow': 'slideGlow 3s ease-in-out infinite',
        'zoom-pulse': 'zoomPulse 2s ease-in-out infinite',
      },
      keyframes: {
        // Original keyframes
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        fadeOut: {
          '0%': { opacity: '1' },
          '100%': { opacity: '0' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(0)' },
        },
        slideOut: {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-100%)' },
        },

        // Cyberpunk keyframes
        neonPulse: {
          '0%': {
            boxShadow: '0 0 5px currentColor, 0 0 10px currentColor, 0 0 15px currentColor',
            textShadow: '0 0 5px currentColor'
          },
          '100%': {
            boxShadow: '0 0 10px currentColor, 0 0 20px currentColor, 0 0 30px currentColor',
            textShadow: '0 0 10px currentColor, 0 0 20px currentColor'
          },
        },
        neonFlicker: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.8' },
        },
        glitch: {
          '0%': { transform: 'translate(0)' },
          '20%': { transform: 'translate(-2px, 2px)' },
          '40%': { transform: 'translate(-2px, -2px)' },
          '60%': { transform: 'translate(2px, 2px)' },
          '80%': { transform: 'translate(2px, -2px)' },
          '100%': { transform: 'translate(0)' },
        },
        glitchText: {
          '0%': {
            textShadow: '0.05em 0 0 #00ffff, -0.05em -0.025em 0 #ff00ff, 0.025em 0.05em 0 #ffff00',
            transform: 'translate(0)'
          },
          '15%': {
            textShadow: '0.05em 0 0 #00ffff, -0.05em -0.025em 0 #ff00ff, 0.025em 0.05em 0 #ffff00',
            transform: 'translate(-0.05em, -0.025em)'
          },
          '16%': {
            textShadow: '-0.05em -0.025em 0 #00ffff, 0.025em 0.025em 0 #ff00ff, -0.05em -0.05em 0 #ffff00',
            transform: 'translate(0.05em, 0.025em)'
          },
          '49%': {
            textShadow: '-0.05em -0.025em 0 #00ffff, 0.025em 0.025em 0 #ff00ff, -0.05em -0.05em 0 #ffff00',
            transform: 'translate(0.05em, 0.025em)'
          },
          '50%': {
            textShadow: '0.025em 0.05em 0 #00ffff, 0.05em 0 0 #ff00ff, 0 -0.05em 0 #ffff00',
            transform: 'translate(-0.025em, -0.05em)'
          },
          '99%': {
            textShadow: '0.025em 0.05em 0 #00ffff, 0.05em 0 0 #ff00ff, 0 -0.05em 0 #ffff00',
            transform: 'translate(-0.025em, -0.05em)'
          },
          '100%': {
            textShadow: '0.05em 0 0 #00ffff, -0.05em -0.025em 0 #ff00ff, 0.025em 0.05em 0 #ffff00',
            transform: 'translate(0)'
          },
        },
        matrixRain: {
          '0%': { transform: 'translateY(-100vh)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        cyberGlow: {
          '0%': {
            boxShadow: '0 0 5px currentColor, inset 0 0 5px currentColor',
            filter: 'brightness(1)'
          },
          '100%': {
            boxShadow: '0 0 20px currentColor, inset 0 0 10px currentColor',
            filter: 'brightness(1.2)'
          },
        },
        dataStream: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100vw)' },
        },
        hologram: {
          '0%, 100%': {
            opacity: '0.8',
            transform: 'translateY(0px)'
          },
          '50%': {
            opacity: '1',
            transform: 'translateY(-10px)'
          },
        },
        scanLine: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        terminalCursor: {
          '0%, 50%': { opacity: '1' },
          '51%, 100%': { opacity: '0' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-20px)' },
        },
        bounceGlow: {
          '0%, 100%': {
            transform: 'translateY(0)',
            boxShadow: '0 0 10px currentColor'
          },
          '50%': {
            transform: 'translateY(-10px)',
            boxShadow: '0 10px 20px currentColor'
          },
        },
        slideGlow: {
          '0%': {
            transform: 'translateX(-100%)',
            boxShadow: '0 0 10px currentColor'
          },
          '50%': {
            transform: 'translateX(0)',
            boxShadow: '0 0 30px currentColor'
          },
          '100%': {
            transform: 'translateX(100%)',
            boxShadow: '0 0 10px currentColor'
          },
        },
        zoomPulse: {
          '0%, 100%': {
            transform: 'scale(1)',
            filter: 'brightness(1)'
          },
          '50%': {
            transform: 'scale(1.05)',
            filter: 'brightness(1.2)'
          },
        },
      },
      backdropBlur: {
        xs: '2px',
        '4xl': '72px',
        '5xl': '96px',
      },
      backdropBrightness: {
        25: '.25',
        175: '1.75',
        200: '2',
      },
      boxShadow: {
        // Original shadows
        'inner-lg': 'inset 0 10px 15px -3px rgba(0, 0, 0, 0.1), inset 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
        'glow': '0 0 20px rgba(59, 130, 246, 0.5)',
        'glow-lg': '0 0 40px rgba(59, 130, 246, 0.6)',

        // Cyberpunk neon glows
        'neon-blue': '0 0 5px #00d4ff, 0 0 10px #00d4ff, 0 0 15px #00d4ff',
        'neon-blue-lg': '0 0 10px #00d4ff, 0 0 20px #00d4ff, 0 0 30px #00d4ff, 0 0 40px #00d4ff',
        'neon-pink': '0 0 5px #ff0080, 0 0 10px #ff0080, 0 0 15px #ff0080',
        'neon-pink-lg': '0 0 10px #ff0080, 0 0 20px #ff0080, 0 0 30px #ff0080, 0 0 40px #ff0080',
        'neon-green': '0 0 5px #00ff41, 0 0 10px #00ff41, 0 0 15px #00ff41',
        'neon-green-lg': '0 0 10px #00ff41, 0 0 20px #00ff41, 0 0 30px #00ff41, 0 0 40px #00ff41',
        'neon-purple': '0 0 5px #8000ff, 0 0 10px #8000ff, 0 0 15px #8000ff',
        'neon-purple-lg': '0 0 10px #8000ff, 0 0 20px #8000ff, 0 0 30px #8000ff, 0 0 40px #8000ff',
        'neon-orange': '0 0 5px #ff6600, 0 0 10px #ff6600, 0 0 15px #ff6600',
        'neon-orange-lg': '0 0 10px #ff6600, 0 0 20px #ff6600, 0 0 30px #ff6600, 0 0 40px #ff6600',

        // Cyberpunk inner glows
        'inner-neon-blue': 'inset 0 0 10px #00d4ff, inset 0 0 20px rgba(0, 212, 255, 0.3)',
        'inner-neon-pink': 'inset 0 0 10px #ff0080, inset 0 0 20px rgba(255, 0, 128, 0.3)',
        'inner-neon-green': 'inset 0 0 10px #00ff41, inset 0 0 20px rgba(0, 255, 65, 0.3)',

        // Matrix/Terminal effects
        'terminal': '0 0 10px rgba(0, 255, 65, 0.5), inset 0 0 10px rgba(0, 255, 65, 0.1)',
        'hologram': '0 0 20px rgba(0, 212, 255, 0.4), 0 0 40px rgba(0, 212, 255, 0.2)',
        'cyber-border': '0 0 1px #00d4ff, inset 0 0 1px #00d4ff',

        // Security status glows
        'security-critical': '0 0 10px #ff0040, 0 0 20px rgba(255, 0, 64, 0.5)',
        'security-high': '0 0 10px #ff4000, 0 0 20px rgba(255, 64, 0, 0.5)',
        'security-medium': '0 0 10px #ff8000, 0 0 20px rgba(255, 128, 0, 0.5)',
        'security-low': '0 0 10px #40ff00, 0 0 20px rgba(64, 255, 0, 0.5)',
        'security-safe': '0 0 10px #00ff80, 0 0 20px rgba(0, 255, 128, 0.5)',
      },
      borderRadius: {
        '4xl': '2rem',
        '5xl': '3rem',
        '6xl': '4rem',
      },
      borderWidth: {
        '3': '3px',
        '5': '5px',
        '6': '6px',
      },
      maxWidth: {
        '8xl': '88rem',
        '9xl': '96rem',
        '10xl': '120rem',
      },
      minHeight: {
        '128': '32rem',
        '144': '36rem',
        '160': '40rem',
      },
      zIndex: {
        '60': '60',
        '70': '70',
        '80': '80',
        '90': '90',
        '100': '100',
        '110': '110',
        '120': '120',
      },
      screens: {
        '3xl': '1600px',
        '4xl': '1920px',
      },
      blur: {
        '4xl': '72px',
        '5xl': '96px',
      },
      brightness: {
        25: '.25',
        175: '1.75',
        200: '2',
      },
      contrast: {
        25: '.25',
        175: '1.75',
        200: '2',
      },
      saturate: {
        25: '.25',
        175: '1.75',
        200: '2',
      },
      typography: (theme) => ({
        DEFAULT: {
          css: {
            color: theme('colors.gray.700'),
            maxWidth: 'none',
            hr: {
              borderColor: theme('colors.gray.200'),
              marginTop: '3em',
              marginBottom: '3em',
            },
            'h1, h2, h3, h4': {
              color: theme('colors.gray.900'),
            },
            code: {
              color: theme('colors.pink.600'),
              backgroundColor: theme('colors.gray.100'),
              paddingLeft: '4px',
              paddingRight: '4px',
              paddingTop: '2px',
              paddingBottom: '2px',
              borderRadius: '0.25rem',
            },
            'code::before': {
              content: '""',
            },
            'code::after': {
              content: '""',
            },
            pre: {
              backgroundColor: theme('colors.gray.900'),
              color: theme('colors.gray.100'),
            },
            blockquote: {
              borderLeftColor: theme('colors.brand.500'),
              color: theme('colors.gray.700'),
            },
            a: {
              color: theme('colors.brand.600'),
              '&:hover': {
                color: theme('colors.brand.700'),
              },
            },
          },
        },
        dark: {
          css: {
            color: theme('colors.gray.300'),
            'h1, h2, h3, h4': {
              color: theme('colors.gray.100'),
            },
            code: {
              color: theme('colors.pink.400'),
              backgroundColor: theme('colors.gray.800'),
            },
            blockquote: {
              borderLeftColor: theme('colors.brand.400'),
              color: theme('colors.gray.300'),
            },
            a: {
              color: theme('colors.brand.400'),
              '&:hover': {
                color: theme('colors.brand.300'),
              },
            },
          },
        },
      }),
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
    // Custom cyberpunk utilities plugin
    function({ addUtilities, theme }) {
      const newUtilities = {
        // Original utilities
        '.text-shadow': {
          textShadow: '0 2px 4px rgba(0,0,0,0.10)',
        },
        '.text-shadow-md': {
          textShadow: '0 4px 8px rgba(0,0,0,0.12), 0 2px 4px rgba(0,0,0,0.08)',
        },
        '.text-shadow-lg': {
          textShadow: '0 15px 35px rgba(0,0,0,0.1), 0 5px 15px rgba(0,0,0,0.07)',
        },
        '.text-shadow-none': {
          textShadow: 'none',
        },

        // Cyberpunk text effects
        '.text-neon-blue': {
          color: '#00d4ff',
          textShadow: '0 0 5px #00d4ff, 0 0 10px #00d4ff, 0 0 15px #00d4ff',
        },
        '.text-neon-pink': {
          color: '#ff0080',
          textShadow: '0 0 5px #ff0080, 0 0 10px #ff0080, 0 0 15px #ff0080',
        },
        '.text-neon-green': {
          color: '#00ff41',
          textShadow: '0 0 5px #00ff41, 0 0 10px #00ff41, 0 0 15px #00ff41',
        },
        '.text-neon-purple': {
          color: '#8000ff',
          textShadow: '0 0 5px #8000ff, 0 0 10px #8000ff, 0 0 15px #8000ff',
        },
        '.text-neon-orange': {
          color: '#ff6600',
          textShadow: '0 0 5px #ff6600, 0 0 10px #ff6600, 0 0 15px #ff6600',
        },

        // Glitch effects
        '.text-glitch': {
          position: 'relative',
          '&::before, &::after': {
            content: 'attr(data-text)',
            position: 'absolute',
            top: '0',
            left: '0',
            width: '100%',
            height: '100%',
          },
          '&::before': {
            animation: 'glitch 0.3s ease-in-out infinite alternate-reverse',
            color: '#ff0080',
            zIndex: '-1',
          },
          '&::after': {
            animation: 'glitch 0.3s ease-in-out infinite alternate-reverse',
            color: '#00d4ff',
            zIndex: '-2',
          },
        },

        // Scrollbar styles
        '.scrollbar-hide': {
          '-ms-overflow-style': 'none',
          'scrollbar-width': 'none',
          '&::-webkit-scrollbar': {
            display: 'none',
          },
        },
        '.scrollbar-thin': {
          'scrollbar-width': 'thin',
          '&::-webkit-scrollbar': {
            width: '6px',
            height: '6px',
          },
          '&::-webkit-scrollbar-track': {
            backgroundColor: theme('colors.matrix.surface'),
          },
          '&::-webkit-scrollbar-thumb': {
            backgroundColor: theme('colors.cyber.blue.neon'),
            borderRadius: '3px',
          },
          '&::-webkit-scrollbar-thumb:hover': {
            backgroundColor: theme('colors.cyber.blue.glow'),
          },
        },
        '.scrollbar-cyber': {
          'scrollbar-width': 'thin',
          'scrollbar-color': `${theme('colors.cyber.blue.neon')} ${theme('colors.matrix.surface')}`,
          '&::-webkit-scrollbar': {
            width: '8px',
            height: '8px',
          },
          '&::-webkit-scrollbar-track': {
            backgroundColor: theme('colors.matrix.surface'),
            borderRadius: '4px',
          },
          '&::-webkit-scrollbar-thumb': {
            backgroundColor: theme('colors.cyber.blue.neon'),
            borderRadius: '4px',
            border: `1px solid ${theme('colors.matrix.border')}`,
          },
          '&::-webkit-scrollbar-thumb:hover': {
            backgroundColor: theme('colors.cyber.blue.glow'),
            boxShadow: `0 0 10px ${theme('colors.cyber.blue.neon')}`,
          },
        },

        // Cyberpunk backgrounds
        '.bg-matrix': {
          backgroundColor: theme('colors.matrix.black'),
          backgroundImage: `
            radial-gradient(circle at 1px 1px, ${theme('colors.cyber.green.neon')}40 1px, transparent 0),
            linear-gradient(0deg, transparent 24%, ${theme('colors.cyber.green.neon')}10 25%, ${theme('colors.cyber.green.neon')}10 26%, transparent 27%, transparent 74%, ${theme('colors.cyber.green.neon')}10 75%, ${theme('colors.cyber.green.neon')}10 76%, transparent 77%, transparent)
          `,
          backgroundSize: '20px 20px',
        },
        '.bg-circuit': {
          backgroundColor: theme('colors.matrix.dark'),
          backgroundImage: `
            linear-gradient(90deg, ${theme('colors.cyber.blue.neon')}20 1px, transparent 1px),
            linear-gradient(180deg, ${theme('colors.cyber.blue.neon')}20 1px, transparent 1px)
          `,
          backgroundSize: '20px 20px',
        },
        '.bg-cyber-grid': {
          backgroundColor: theme('colors.matrix.black'),
          backgroundImage: `
            linear-gradient(${theme('colors.cyber.blue.neon')}40 1px, transparent 1px),
            linear-gradient(90deg, ${theme('colors.cyber.blue.neon')}40 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px',
        },

        // Cyberpunk borders
        '.border-neon': {
          borderColor: theme('colors.cyber.blue.neon'),
          boxShadow: `0 0 5px ${theme('colors.cyber.blue.neon')}`,
        },
        '.border-neon-pink': {
          borderColor: theme('colors.cyber.pink.neon'),
          boxShadow: `0 0 5px ${theme('colors.cyber.pink.neon')}`,
        },
        '.border-neon-green': {
          borderColor: theme('colors.cyber.green.neon'),
          boxShadow: `0 0 5px ${theme('colors.cyber.green.neon')}`,
        },

        // Hologram effect
        '.hologram': {
          background: `linear-gradient(45deg, transparent 30%, ${theme('colors.cyber.blue.neon')}20 50%, transparent 70%)`,
          backgroundSize: '20px 20px',
          animation: 'hologram 4s ease-in-out infinite',
        },

        // Matrix rain effect container
        '.matrix-rain': {
          position: 'relative',
          overflow: 'hidden',
          '&::before': {
            content: '""',
            position: 'absolute',
            top: '-100%',
            left: '0',
            width: '100%',
            height: '200%',
            background: `linear-gradient(180deg, transparent, ${theme('colors.cyber.green.neon')}20, transparent)`,
            animation: 'matrixRain 20s linear infinite',
            pointerEvents: 'none',
          },
        },
      };

      addUtilities(newUtilities);
    },
  ],
  darkMode: 'class',
};
