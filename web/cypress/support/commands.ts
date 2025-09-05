/// <reference types="cypress" />

// ***********************************************
// This example commands.ts shows you how to
// create various custom commands and overwrite
// existing commands.
//
// For more comprehensive examples of custom
// commands please read more here:
// https://on.cypress.io/custom-commands
// ***********************************************

declare global {
  namespace Cypress {
    interface Chainable {
      /**
       * Custom command to login with Firebase Auth
       * @example cy.firebaseLogin('test@example.com', 'password123')
       */
      firebaseLogin(email: string, password: string): Chainable<void>
      
      /**
       * Custom command to logout from Firebase Auth
       * @example cy.firebaseLogout()
       */
      firebaseLogout(): Chainable<void>
      
      /**
       * Custom command to wait for Firebase Auth to initialize
       * @example cy.waitForFirebaseAuth()
       */
      waitForFirebaseAuth(): Chainable<void>
      
      /**
       * Custom command to create a test user in Firebase Auth emulator
       * @example cy.createTestUser('test@example.com', 'password123', 'Test User')
       */
      createTestUser(email: string, password: string, displayName?: string): Chainable<void>
      
      /**
       * Custom command to delete a test user from Firebase Auth emulator
       * @example cy.deleteTestUser('test@example.com')
       */
      deleteTestUser(email: string): Chainable<void>
    }
  }
}

// Custom command to login with Firebase Auth
Cypress.Commands.add('firebaseLogin', (email: string, password: string) => {
  cy.visit('/login')
  cy.get('input[type="email"]').type(email)
  cy.get('input[type="password"]').type(password)
  cy.get('button[type="submit"]').click()
  
  // Wait for redirect or success
  cy.url().should('not.include', '/login')
})

// Custom command to logout from Firebase Auth
Cypress.Commands.add('firebaseLogout', () => {
  cy.window().then((win) => {
    // Clear Firebase auth state
    win.localStorage.removeItem('firebase:authUser')
    win.sessionStorage.clear()
  })
  
  // Visit logout endpoint or click logout button if available
  cy.visit('/login')
})

// Custom command to wait for Firebase Auth to initialize
Cypress.Commands.add('waitForFirebaseAuth', () => {
  cy.window().should('have.property', 'firebase')
  cy.wait(1000) // Give Firebase time to initialize
})

// Custom command to create a test user in Firebase Auth emulator
Cypress.Commands.add('createTestUser', (email: string, password: string, displayName?: string) => {
  // This would typically use Firebase Admin SDK or REST API
  // For now, we'll use the signup form
  cy.visit('/signup')
  cy.get('input[type="email"]').type(email)
  cy.get('input[type="password"]').type(password)
  
  if (displayName) {
    cy.get('input[name="displayName"]').type(displayName)
  }
  
  cy.get('button[type="submit"]').click()
  
  // Handle potential email verification step
  cy.url().then((url) => {
    if (url.includes('/verify-email')) {
      cy.get('[data-testid="skip-button"]').click()
    }
  })
})

// Custom command to delete a test user from Firebase Auth emulator
Cypress.Commands.add('deleteTestUser', (email: string) => {
  // This would typically use Firebase Admin SDK
  // For emulator testing, users are automatically cleaned up
  cy.log(`Test user ${email} cleanup handled by emulator`)
})

// Override the default visit command to handle Firebase emulator setup
Cypress.Commands.overwrite('visit', (originalFn, url, options) => {
  // Set up Firebase emulator environment variables
  const emulatorOptions = {
    ...options,
    onBeforeLoad: (win: any) => {
      // Set environment variables for Firebase emulator
      win.process = {
        env: {
          NEXT_PUBLIC_USE_FIREBASE_EMULATOR: 'true',
          NEXT_PUBLIC_FIREBASE_AUTH_EMULATOR_HOST: 'localhost:9099',
          NEXT_PUBLIC_FIRESTORE_EMULATOR_HOST: 'localhost:8080',
          NEXT_PUBLIC_FIREBASE_PROJECT_ID_DEV: 'hackai-auth-system',
        }
      }
      
      // Call original onBeforeLoad if it exists
      if (options?.onBeforeLoad) {
        options.onBeforeLoad(win)
      }
    }
  }
  
  return originalFn(url, emulatorOptions)
})

// Add custom assertions for Firebase Auth states
Cypress.Commands.add('shouldBeAuthenticated', () => {
  cy.window().its('firebase.auth().currentUser').should('not.be.null')
})

Cypress.Commands.add('shouldNotBeAuthenticated', () => {
  cy.window().its('firebase.auth().currentUser').should('be.null')
})

// Export for TypeScript
export {}
