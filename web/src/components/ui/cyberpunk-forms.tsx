'use client'

import React, { useState } from 'react'
import { cn } from '@/lib/utils'
import {
  EyeIcon,
  EyeSlashIcon,
  CheckCircleIcon,
  ExclamationCircleIcon
} from '@heroicons/react/24/outline'

// Cyberpunk Input Field
interface CyberpunkInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
  success?: boolean
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  icon?: React.ReactNode
}

export const CyberpunkInput = React.forwardRef<HTMLInputElement, CyberpunkInputProps>(({
  className,
  label,
  type = 'text',
  error,
  success,
  color = 'blue',
  icon,
  required,
  ...props
}, ref) => {
  const [focused, setFocused] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  const colorMap = {
    blue: {
      border: 'border-cyber-blue-neon/30 focus:border-cyber-blue-neon',
      text: 'text-cyber-blue-neon',
      glow: 'focus:shadow-neon-blue'
    },
    green: {
      border: 'border-cyber-green-neon/30 focus:border-cyber-green-neon',
      text: 'text-cyber-green-neon',
      glow: 'focus:shadow-neon-green'
    },
    pink: {
      border: 'border-cyber-pink-neon/30 focus:border-cyber-pink-neon',
      text: 'text-cyber-pink-neon',
      glow: 'focus:shadow-neon-pink'
    },
    purple: {
      border: 'border-cyber-purple-neon/30 focus:border-cyber-purple-neon',
      text: 'text-cyber-purple-neon',
      glow: 'focus:shadow-neon-purple'
    },
    orange: {
      border: 'border-cyber-orange-neon/30 focus:border-cyber-orange-neon',
      text: 'text-cyber-orange-neon',
      glow: 'focus:shadow-neon-orange'
    }
  }

  const colors = colorMap[color]

  const inputType = type === 'password' && showPassword ? 'text' : type

  return (
    <div className={cn('space-y-2', className)}>
      {label && (
        <label className={cn('block text-sm font-cyber uppercase tracking-wider', colors.text)}>
          {label}
          {required && <span className="text-security-critical ml-1">*</span>}
        </label>
      )}
      
      <div className="relative">
        {icon && (
          <div className={cn('absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5', colors.text)}>
            {icon}
          </div>
        )}
        
        <input
          ref={ref}
          type={inputType}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          className={cn(
            'w-full px-4 py-3 bg-matrix-dark/50 border rounded-lg',
            'text-matrix-white placeholder-matrix-muted font-matrix',
            'transition-all duration-300 outline-none backdrop-blur-sm',
            icon && 'pl-12',
            type === 'password' && 'pr-12',
            error && 'border-security-critical shadow-security-critical',
            success && 'border-cyber-green-neon shadow-neon-green',
            !error && !success && colors.border,
            !error && !success && colors.glow,
            props.disabled && 'opacity-50 cursor-not-allowed',
            focused && 'animate-neon-pulse',
            className
          )}
          {...props}
        />
        
        {type === 'password' && (
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className={cn(
              'absolute right-3 top-1/2 transform -translate-y-1/2 w-5 h-5',
              'text-matrix-muted hover:text-matrix-white transition-colors'
            )}
          >
            {showPassword ? <EyeSlashIcon /> : <EyeIcon />}
          </button>
        )}
      </div>
      
      {error && (
        <div className="flex items-center gap-2 text-sm text-security-critical">
          <ExclamationCircleIcon className="w-4 h-4" />
          <span className="font-matrix">{error}</span>
        </div>
      )}
      
      {success && (
        <div className="flex items-center gap-2 text-sm text-cyber-green-neon">
          <CheckCircleIcon className="w-4 h-4" />
          <span className="font-matrix">Valid input</span>
        </div>
      )}
    </div>
  )
})

CyberpunkInput.displayName = 'CyberpunkInput'

// Cyberpunk Select Field
interface CyberpunkSelectProps {
  className?: string
  label?: string
  value?: string
  onChange?: (value: string) => void
  options: Array<{ value: string; label: string }>
  placeholder?: string
  error?: string
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  required?: boolean
  disabled?: boolean
}

export const CyberpunkSelect: React.FC<CyberpunkSelectProps> = ({
  className,
  label,
  value,
  onChange,
  options,
  placeholder = 'Select an option',
  error,
  color = 'blue',
  required,
  disabled
}) => {
  const [isOpen, setIsOpen] = useState(false)

  const colorMap = {
    blue: {
      border: 'border-cyber-blue-neon/30 focus:border-cyber-blue-neon',
      text: 'text-cyber-blue-neon',
      glow: 'focus:shadow-neon-blue',
      bg: 'bg-cyber-blue-neon/10'
    },
    green: {
      border: 'border-cyber-green-neon/30 focus:border-cyber-green-neon',
      text: 'text-cyber-green-neon',
      glow: 'focus:shadow-neon-green',
      bg: 'bg-cyber-green-neon/10'
    },
    pink: {
      border: 'border-cyber-pink-neon/30 focus:border-cyber-pink-neon',
      text: 'text-cyber-pink-neon',
      glow: 'focus:shadow-neon-pink',
      bg: 'bg-cyber-pink-neon/10'
    },
    purple: {
      border: 'border-cyber-purple-neon/30 focus:border-cyber-purple-neon',
      text: 'text-cyber-purple-neon',
      glow: 'focus:shadow-neon-purple',
      bg: 'bg-cyber-purple-neon/10'
    },
    orange: {
      border: 'border-cyber-orange-neon/30 focus:border-cyber-orange-neon',
      text: 'text-cyber-orange-neon',
      glow: 'focus:shadow-neon-orange',
      bg: 'bg-cyber-orange-neon/10'
    }
  }

  const colors = colorMap[color]
  const selectedOption = options.find(opt => opt.value === value)

  return (
    <div className={cn('space-y-2', className)}>
      {label && (
        <label className={cn('block text-sm font-cyber uppercase tracking-wider', colors.text)}>
          {label}
          {required && <span className="text-security-critical ml-1">*</span>}
        </label>
      )}
      
      <div className="relative">
        <button
          type="button"
          onClick={() => !disabled && setIsOpen(!isOpen)}
          disabled={disabled}
          className={cn(
            'w-full px-4 py-3 bg-matrix-dark/50 border rounded-lg text-left',
            'text-matrix-white font-matrix transition-all duration-300 outline-none backdrop-blur-sm',
            error && 'border-security-critical shadow-security-critical',
            !error && colors.border,
            !error && colors.glow,
            disabled && 'opacity-50 cursor-not-allowed',
            isOpen && 'animate-neon-pulse'
          )}
        >
          <span className={selectedOption ? 'text-matrix-white' : 'text-matrix-muted'}>
            {selectedOption?.label || placeholder}
          </span>
          <span className={cn('absolute right-3 top-1/2 transform -translate-y-1/2', colors.text)}>
            ▼
          </span>
        </button>
        
        {isOpen && (
          <div className={cn(
            'absolute top-full left-0 right-0 mt-1 bg-matrix-dark border rounded-lg z-50',
            'backdrop-blur-sm shadow-lg max-h-60 overflow-y-auto scrollbar-cyber',
            colors.border
          )}>
            {options.map((option) => (
              <button
                key={option.value}
                type="button"
                onClick={() => {
                  onChange?.(option.value)
                  setIsOpen(false)
                }}
                className={cn(
                  'w-full px-4 py-3 text-left text-matrix-white font-matrix',
                  'hover:bg-matrix-surface transition-colors',
                  value === option.value && colors.bg,
                  value === option.value && colors.text
                )}
              >
                {option.label}
              </button>
            ))}
          </div>
        )}
      </div>
      
      {error && (
        <div className="flex items-center gap-2 text-sm text-security-critical">
          <ExclamationCircleIcon className="w-4 h-4" />
          <span className="font-matrix">{error}</span>
        </div>
      )}
    </div>
  )
}

// Cyberpunk Checkbox
interface CyberpunkCheckboxProps {
  className?: string
  label?: string
  checked?: boolean
  onChange?: (checked: boolean) => void
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  disabled?: boolean
}

export const CyberpunkCheckbox: React.FC<CyberpunkCheckboxProps> = ({
  className,
  label,
  checked,
  onChange,
  color = 'blue',
  disabled
}) => {
  const colorMap = {
    blue: 'text-cyber-blue-neon border-cyber-blue-neon/30 checked:bg-cyber-blue-neon',
    green: 'text-cyber-green-neon border-cyber-green-neon/30 checked:bg-cyber-green-neon',
    pink: 'text-cyber-pink-neon border-cyber-pink-neon/30 checked:bg-cyber-pink-neon',
    purple: 'text-cyber-purple-neon border-cyber-purple-neon/30 checked:bg-cyber-purple-neon',
    orange: 'text-cyber-orange-neon border-cyber-orange-neon/30 checked:bg-cyber-orange-neon'
  }

  return (
    <label className={cn('flex items-center gap-3 cursor-pointer', disabled && 'opacity-50 cursor-not-allowed', className)}>
      <div className="relative">
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange?.(e.target.checked)}
          disabled={disabled}
          className={cn(
            'w-5 h-5 bg-matrix-dark border-2 rounded transition-all duration-300',
            'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-matrix-black',
            colorMap[color],
            checked && 'animate-neon-pulse'
          )}
        />
        {checked && (
          <CheckCircleIcon className={cn('absolute inset-0 w-5 h-5 text-matrix-black', colorMap[color])} />
        )}
      </div>
      {label && (
        <span className="text-matrix-white font-matrix select-none">
          {label}
        </span>
      )}
    </label>
  )
}

// Cyberpunk Form Container
interface CyberpunkFormProps {
  className?: string
  title?: string
  children: React.ReactNode
  onSubmit?: (e: React.FormEvent) => void
  color?: 'blue' | 'green' | 'pink' | 'purple' | 'orange'
  loading?: boolean
}

export const CyberpunkForm: React.FC<CyberpunkFormProps> = ({
  className,
  title,
  children,
  onSubmit,
  color = 'blue',
  loading
}) => {
  return (
    <CyberpunkCard variant={`neon-${color}` as any} className={cn('relative overflow-hidden', className)}>
      <DataStream 
        streamCount={4} 
        direction="diagonal" 
        color={color} 
        speed="slow"
        className="opacity-10"
      />
      
      {title && (
        <CyberpunkCardHeader accent>
          <CyberpunkCardTitle className={`text-cyber-${color}-neon`}>
            {title}
          </CyberpunkCardTitle>
        </CyberpunkCardHeader>
      )}
      
      <CyberpunkCardContent>
        <form onSubmit={onSubmit} className="space-y-6 relative z-10">
          {children}
          
          {loading && (
            <div className="absolute inset-0 bg-matrix-black/50 backdrop-blur-sm flex items-center justify-center z-20">
              <div className={`text-cyber-${color}-neon font-cyber`}>
                Processing...
              </div>
            </div>
          )}
        </form>
      </CyberpunkCardContent>
    </CyberpunkCard>
  )
}
