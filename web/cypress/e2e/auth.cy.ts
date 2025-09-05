describe('Firebase Authentication', () => {
  beforeEach(() => {
    // Visit the login page
    cy.visit('/login')
  })

  it('should display login form', () => {
    cy.get('[data-testid="login-form"]').should('be.visible')
    cy.get('input[type="email"]').should('be.visible')
    cy.get('input[type="password"]').should('be.visible')
    cy.get('button[type="submit"]').should('contain', 'Sign In')
  })

  it('should show validation errors for invalid inputs', () => {
    // Try to submit empty form
    cy.get('button[type="submit"]').click()
    
    // Should show validation errors
    cy.get('[data-testid="error-message"]').should('be.visible')
  })

  it('should navigate to signup page', () => {
    cy.get('[data-testid="signup-link"]').click()
    cy.url().should('include', '/signup')
  })

  it('should navigate to forgot password page', () => {
    cy.get('[data-testid="forgot-password-link"]').click()
    cy.url().should('include', '/forgot-password')
  })

  it('should attempt login with test credentials', () => {
    // Fill in test credentials
    cy.get('input[type="email"]').type('test@example.com')
    cy.get('input[type="password"]').type('testpassword123')
    
    // Submit form
    cy.get('button[type="submit"]').click()
    
    // Should show loading state or error (since we're using emulators)
    cy.get('[data-testid="loading"]').should('be.visible')
      .or(cy.get('[data-testid="error-message"]').should('be.visible'))
  })

  it('should display Google sign-in button', () => {
    cy.get('[data-testid="google-signin-button"]').should('be.visible')
    cy.get('[data-testid="google-signin-button"]').should('contain', 'Google')
  })

  it('should display GitHub sign-in button', () => {
    cy.get('[data-testid="github-signin-button"]').should('be.visible')
    cy.get('[data-testid="github-signin-button"]').should('contain', 'GitHub')
  })
})

describe('Firebase Authentication - Signup', () => {
  beforeEach(() => {
    cy.visit('/signup')
  })

  it('should display signup form', () => {
    cy.get('[data-testid="signup-form"]').should('be.visible')
    cy.get('input[type="email"]').should('be.visible')
    cy.get('input[type="password"]').should('be.visible')
    cy.get('input[name="displayName"]').should('be.visible')
    cy.get('button[type="submit"]').should('contain', 'Sign Up')
  })

  it('should validate password strength', () => {
    cy.get('input[type="email"]').type('test@example.com')
    cy.get('input[type="password"]').type('weak')
    cy.get('button[type="submit"]').click()
    
    cy.get('[data-testid="error-message"]').should('contain', 'Password')
  })

  it('should navigate back to login', () => {
    cy.get('[data-testid="login-link"]').click()
    cy.url().should('include', '/login')
  })
})

describe('Firebase Authentication - Password Reset', () => {
  beforeEach(() => {
    cy.visit('/forgot-password')
  })

  it('should display password reset form', () => {
    cy.get('[data-testid="password-reset-form"]').should('be.visible')
    cy.get('input[type="email"]').should('be.visible')
    cy.get('button[type="submit"]').should('contain', 'Send Reset Email')
  })

  it('should validate email format', () => {
    cy.get('input[type="email"]').type('invalid-email')
    cy.get('button[type="submit"]').click()
    
    cy.get('[data-testid="error-message"]').should('be.visible')
  })

  it('should show success message for valid email', () => {
    cy.get('input[type="email"]').type('test@example.com')
    cy.get('button[type="submit"]').click()
    
    // Should show success message or loading state
    cy.get('[data-testid="success-message"]').should('be.visible')
      .or(cy.get('[data-testid="loading"]').should('be.visible'))
  })
})

describe('Protected Routes', () => {
  it('should redirect to login when accessing protected route without auth', () => {
    cy.visit('/dashboard')
    cy.url().should('include', '/login')
  })

  it('should redirect to login when accessing profile without auth', () => {
    cy.visit('/profile')
    cy.url().should('include', '/login')
  })

  it('should redirect to login when accessing settings without auth', () => {
    cy.visit('/settings')
    cy.url().should('include', '/login')
  })
})

describe('Email Verification', () => {
  beforeEach(() => {
    // Mock an unverified user state
    cy.visit('/verify-email')
  })

  it('should display email verification page', () => {
    cy.get('[data-testid="email-verification"]').should('be.visible')
    cy.get('[data-testid="resend-button"]').should('be.visible')
  })

  it('should allow resending verification email', () => {
    cy.get('[data-testid="resend-button"]').click()
    
    // Should show loading state or success message
    cy.get('[data-testid="loading"]').should('be.visible')
      .or(cy.get('[data-testid="success-message"]').should('be.visible'))
  })

  it('should allow skipping verification', () => {
    cy.get('[data-testid="skip-button"]').click()
    cy.url().should('include', '/dashboard')
  })
})
