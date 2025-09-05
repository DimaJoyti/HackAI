// ***********************************************************
// This example support/e2e.ts is processed and
// loaded automatically before your test files.
//
// This is a great place to put global configuration and
// behavior that modifies Cypress.
//
// You can change the location of this file or turn off
// automatically serving support files with the
// 'supportFile' configuration option.
//
// You can read more here:
// https://on.cypress.io/configuration
// ***********************************************************

// Import commands.js using ES2015 syntax:
import './commands'

// Alternatively you can use CommonJS syntax:
// require('./commands')

// Set up Firebase emulator for E2E tests
beforeEach(() => {
  // Clear any existing auth state
  cy.window().then((win) => {
    win.localStorage.clear()
    win.sessionStorage.clear()
  })

  // Set up Firebase emulator environment
  cy.window().then((win) => {
    win.localStorage.setItem('firebase:emulator:auth', 'true')
    win.localStorage.setItem('firebase:emulator:firestore', 'true')
  })
})

// Global error handling
Cypress.on('uncaught:exception', (err, runnable) => {
  // Ignore Firebase emulator connection errors in tests
  if (err.message.includes('Firebase') || err.message.includes('emulator')) {
    return false
  }
  
  // Ignore Next.js hydration errors in tests
  if (err.message.includes('Hydration') || err.message.includes('hydration')) {
    return false
  }
  
  // Let other errors fail the test
  return true
})
