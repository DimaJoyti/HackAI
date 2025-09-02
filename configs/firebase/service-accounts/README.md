# Firebase Service Account Configuration

This directory contains Firebase service account JSON files for different environments.

## Setup Instructions

1. **Create Firebase Projects**
   - Go to [Firebase Console](https://console.firebase.google.com/)
   - Create three projects: `hackai-dev`, `hackai-staging`, `hackai-prod`

2. **Generate Service Account Keys**
   For each project:
   - Go to Project Settings > Service Accounts
   - Click "Generate new private key"
   - Download the JSON file
   - Rename and place in this directory:
     - `hackai-dev-service-account.json`
     - `hackai-staging-service-account.json`
     - `hackai-prod-service-account.json`

3. **Configure Authentication**
   For each project:
   - Go to Authentication > Sign-in method
   - Enable desired providers:
     - Email/Password
     - Google
     - GitHub
     - Phone (optional)

4. **Set Environment Variables**
   Add these to your `.env` file:
   ```bash
   # Development
   FIREBASE_API_KEY_DEV=your_dev_api_key
   FIREBASE_MESSAGING_SENDER_ID_DEV=your_dev_sender_id
   FIREBASE_APP_ID_DEV=your_dev_app_id
   FIREBASE_MEASUREMENT_ID_DEV=your_dev_measurement_id
   
   # Staging
   FIREBASE_API_KEY_STAGING=your_staging_api_key
   FIREBASE_MESSAGING_SENDER_ID_STAGING=your_staging_sender_id
   FIREBASE_APP_ID_STAGING=your_staging_app_id
   FIREBASE_MEASUREMENT_ID_STAGING=your_staging_measurement_id
   
   # Production
   FIREBASE_API_KEY_PROD=your_prod_api_key
   FIREBASE_MESSAGING_SENDER_ID_PROD=your_prod_sender_id
   FIREBASE_APP_ID_PROD=your_prod_app_id
   FIREBASE_MEASUREMENT_ID_PROD=your_prod_measurement_id
   
   # OAuth Providers
   GOOGLE_OAUTH_CLIENT_ID_DEV=your_google_client_id_dev
   GOOGLE_OAUTH_CLIENT_SECRET_DEV=your_google_client_secret_dev
   GITHUB_OAUTH_CLIENT_ID_DEV=your_github_client_id_dev
   GITHUB_OAUTH_CLIENT_SECRET_DEV=your_github_client_secret_dev
   
   # Webhooks
   WEBHOOK_USER_CREATED_URL=https://your-api.com/webhooks/user-created
   WEBHOOK_USER_UPDATED_URL=https://your-api.com/webhooks/user-updated
   WEBHOOK_USER_DELETED_URL=https://your-api.com/webhooks/user-deleted
   ```

## Security Notes

- **Never commit service account JSON files to version control**
- Use environment variables or secure secret management
- Rotate service account keys regularly
- Use least privilege principle for service account permissions

## File Structure

```
service-accounts/
├── README.md                              # This file
├── .gitignore                            # Ignore service account files
├── hackai-dev-service-account.json       # Development service account (not in git)
├── hackai-staging-service-account.json   # Staging service account (not in git)
├── hackai-prod-service-account.json      # Production service account (not in git)
└── example-service-account.json          # Example structure (safe to commit)
```

## Testing Service Account

You can test your service account configuration using the Firebase Admin SDK:

```go
import (
    "context"
    "firebase.google.com/go/v4"
    "firebase.google.com/go/v4/auth"
    "google.golang.org/api/option"
)

func testServiceAccount() error {
    ctx := context.Background()
    
    opt := option.WithCredentialsFile("path/to/service-account.json")
    app, err := firebase.NewApp(ctx, nil, opt)
    if err != nil {
        return err
    }
    
    client, err := app.Auth(ctx)
    if err != nil {
        return err
    }
    
    // Test by listing users (requires appropriate permissions)
    iter := client.Users(ctx, "")
    for {
        user, err := iter.Next()
        if err == iterator.Done {
            break
        }
        if err != nil {
            return err
        }
        fmt.Printf("User: %s\n", user.UID)
        break // Just test one user
    }
    
    return nil
}
```
