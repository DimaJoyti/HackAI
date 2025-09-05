#!/bin/bash

# Firebase Authentication Setup Script for HackAI
# This script configures Firebase Authentication with security best practices

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="hackai-auth-system"
ENVIRONMENT=${ENVIRONMENT:-development}

echo -e "${BLUE}🔥 Setting up Firebase Authentication for HackAI${NC}"
echo -e "${BLUE}Project: ${PROJECT_ID}${NC}"
echo -e "${BLUE}Environment: ${ENVIRONMENT}${NC}"
echo ""

# Check if Firebase CLI is installed
if ! command -v firebase &> /dev/null; then
    echo -e "${RED}❌ Firebase CLI is not installed${NC}"
    echo -e "${YELLOW}Please install it with: npm install -g firebase-tools${NC}"
    exit 1
fi

# Check if logged in to Firebase
if ! firebase projects:list &> /dev/null; then
    echo -e "${RED}❌ Not logged in to Firebase${NC}"
    echo -e "${YELLOW}Please login with: firebase login${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Firebase CLI is ready${NC}"

# Set the active project
echo -e "${BLUE}📋 Setting active Firebase project...${NC}"
firebase use $PROJECT_ID

# Deploy Firestore rules
echo -e "${BLUE}🔒 Deploying Firestore security rules...${NC}"
firebase deploy --only firestore:rules

# Deploy Firestore indexes
echo -e "${BLUE}📊 Deploying Firestore indexes...${NC}"
firebase deploy --only firestore:indexes

# Function to enable authentication providers
enable_auth_providers() {
    echo -e "${BLUE}🔐 Authentication providers need to be enabled manually in Firebase Console${NC}"
    echo -e "${YELLOW}Please visit: https://console.firebase.google.com/project/${PROJECT_ID}/authentication/providers${NC}"
    echo ""
    echo -e "${YELLOW}Enable the following providers:${NC}"
    echo -e "${YELLOW}1. Email/Password${NC}"
    echo -e "${YELLOW}2. Google${NC}"
    echo -e "${YELLOW}3. GitHub${NC}"
    echo ""
    echo -e "${YELLOW}For Google OAuth:${NC}"
    echo -e "${YELLOW}- Add your domain to authorized domains${NC}"
    echo -e "${YELLOW}- Configure OAuth consent screen${NC}"
    echo ""
    echo -e "${YELLOW}For GitHub OAuth:${NC}"
    echo -e "${YELLOW}- Create GitHub OAuth App${NC}"
    echo -e "${YELLOW}- Add Client ID and Secret to Firebase${NC}"
    echo ""
}

# Function to configure authentication settings
configure_auth_settings() {
    echo -e "${BLUE}⚙️  Authentication settings need to be configured manually${NC}"
    echo -e "${YELLOW}Please visit: https://console.firebase.google.com/project/${PROJECT_ID}/authentication/settings${NC}"
    echo ""
    echo -e "${YELLOW}Recommended settings:${NC}"
    echo -e "${YELLOW}- Enable email enumeration protection${NC}"
    echo -e "${YELLOW}- Set password policy requirements${NC}"
    echo -e "${YELLOW}- Configure authorized domains${NC}"
    echo -e "${YELLOW}- Set up email templates${NC}"
    echo ""
}

# Function to set up security monitoring
setup_security_monitoring() {
    echo -e "${BLUE}🛡️  Security monitoring recommendations:${NC}"
    echo ""
    echo -e "${YELLOW}1. Enable Cloud Logging for Authentication${NC}"
    echo -e "${YELLOW}2. Set up alerting for suspicious activities${NC}"
    echo -e "${YELLOW}3. Monitor failed login attempts${NC}"
    echo -e "${YELLOW}4. Track user registration patterns${NC}"
    echo -e "${YELLOW}5. Set up rate limiting${NC}"
    echo ""
}

# Function to validate service account
validate_service_account() {
    local service_account_path="./configs/firebase/service-accounts/hackai-auth-system-service-account.json"
    
    echo -e "${BLUE}🔑 Checking service account configuration...${NC}"
    
    if [ ! -f "$service_account_path" ]; then
        echo -e "${RED}❌ Service account file not found: $service_account_path${NC}"
        echo -e "${YELLOW}Please download the service account key from:${NC}"
        echo -e "${YELLOW}https://console.firebase.google.com/project/${PROJECT_ID}/settings/serviceaccounts/adminsdk${NC}"
        echo -e "${YELLOW}And save it as: $service_account_path${NC}"
        return 1
    else
        echo -e "${GREEN}✅ Service account file found${NC}"
        
        # Validate JSON format
        if jq empty "$service_account_path" 2>/dev/null; then
            echo -e "${GREEN}✅ Service account file is valid JSON${NC}"
            
            # Check if it's for the correct project
            local file_project_id=$(jq -r '.project_id' "$service_account_path")
            if [ "$file_project_id" = "$PROJECT_ID" ]; then
                echo -e "${GREEN}✅ Service account is for the correct project${NC}"
            else
                echo -e "${RED}❌ Service account is for project: $file_project_id, expected: $PROJECT_ID${NC}"
                return 1
            fi
        else
            echo -e "${RED}❌ Service account file is not valid JSON${NC}"
            return 1
        fi
    fi
}

# Function to test Firebase connection
test_firebase_connection() {
    echo -e "${BLUE}🧪 Testing Firebase connection...${NC}"
    
    # Test Firestore connection
    if firebase firestore:databases:list &> /dev/null; then
        echo -e "${GREEN}✅ Firestore connection successful${NC}"
    else
        echo -e "${RED}❌ Firestore connection failed${NC}"
    fi
    
    # Test Authentication connection
    echo -e "${YELLOW}ℹ️  Authentication connection test requires manual verification${NC}"
}

# Function to generate environment variables template
generate_env_template() {
    echo -e "${BLUE}📝 Generating environment variables template...${NC}"
    
    cat > .env.firebase.template << EOF
# Firebase Configuration for HackAI
# Copy this to .env.local and fill in the values

# Firebase Project Configuration
NEXT_PUBLIC_FIREBASE_PROJECT_ID=${PROJECT_ID}
NEXT_PUBLIC_FIREBASE_API_KEY=your_api_key_here
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=${PROJECT_ID}.firebaseapp.com
NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=${PROJECT_ID}.firebasestorage.app
NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=your_sender_id_here
NEXT_PUBLIC_FIREBASE_APP_ID=your_app_id_here

# Firebase Admin SDK (Backend)
FIREBASE_SERVICE_ACCOUNT_PATH=./configs/firebase/service-accounts/${PROJECT_ID}-service-account.json
FIREBASE_PROJECT_ID=${PROJECT_ID}
FIREBASE_DATABASE_URL=https://${PROJECT_ID}-default-rtdb.firebaseio.com

# OAuth Provider Configuration
GOOGLE_OAUTH_CLIENT_ID=your_google_client_id
GOOGLE_OAUTH_CLIENT_SECRET=your_google_client_secret
GITHUB_OAUTH_CLIENT_ID=your_github_client_id
GITHUB_OAUTH_CLIENT_SECRET=your_github_client_secret

# Security Settings
FIREBASE_ENABLE_AUTH_LOGGING=true
FIREBASE_REQUIRE_EMAIL_VERIFICATION=true
FIREBASE_ENABLE_RATE_LIMITING=true

# Development Settings
NEXT_PUBLIC_USE_FIREBASE_EMULATOR=false
FIREBASE_EMULATOR_AUTH_PORT=9099
FIREBASE_EMULATOR_FIRESTORE_PORT=8080
EOF

    echo -e "${GREEN}✅ Environment template created: .env.firebase.template${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}🚀 Starting Firebase Authentication setup...${NC}"
    echo ""
    
    # Validate service account
    if ! validate_service_account; then
        echo -e "${RED}❌ Service account validation failed${NC}"
        echo -e "${YELLOW}Please set up the service account before continuing${NC}"
        exit 1
    fi
    
    # Test Firebase connection
    test_firebase_connection
    echo ""
    
    # Generate environment template
    generate_env_template
    echo ""
    
    # Show manual configuration steps
    enable_auth_providers
    configure_auth_settings
    setup_security_monitoring
    
    echo -e "${GREEN}🎉 Firebase Authentication setup completed!${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo -e "${YELLOW}1. Enable authentication providers in Firebase Console${NC}"
    echo -e "${YELLOW}2. Configure OAuth providers (Google, GitHub)${NC}"
    echo -e "${YELLOW}3. Copy .env.firebase.template to .env.local and fill in values${NC}"
    echo -e "${YELLOW}4. Test authentication in your application${NC}"
    echo ""
    echo -e "${BLUE}Firebase Console: https://console.firebase.google.com/project/${PROJECT_ID}${NC}"
}

# Run main function
main "$@"
