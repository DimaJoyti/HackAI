package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/firebase"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/dimajoyti/hackai/pkg/middleware"
)

func main() {
	// Initialize logger
	logger, err := logger.New(logger.Config{
		Level:      logger.LevelInfo,
		Format:     "json",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: "2006-01-02T15:04:05.000Z",
	})
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	logger.Info("Starting Firebase MCP Server")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}

	// Initialize Firebase configuration
	firebaseConfig, err := firebase.LoadConfig("configs/firebase/firebase.yaml", cfg.Environment)
	if err != nil {
		logger.WithError(err).Fatal("Failed to load Firebase configuration")
	}

	// Initialize Firebase MCP service
	mcpService := firebase.NewMCPService(firebaseConfig, logger)
	logger.Info("Firebase MCP service initialized")

	// Initialize Firebase MCP handlers
	mcpHandlers := firebase.NewMCPHandlers(mcpService, logger)
	logger.Info("Firebase MCP handlers initialized")

	// Setup HTTP router
	router := setupRouter(mcpHandlers, logger)

	// Setup CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",
			"http://localhost:3001",
			"https://hackai-dev.firebaseapp.com",
			"https://hackai-staging.firebaseapp.com",
			"https://hackai-prod.firebaseapp.com",
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
			"X-Requested-With",
		},
		ExposedHeaders: []string{
			"X-Total-Count",
			"X-Page-Token",
		},
		AllowCredentials: true,
		MaxAge:           300,
	})

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", getPort()),
		Handler:      c.Handler(router),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Firebase MCP Server starting", map[string]interface{}{
			"port": getPort(),
			"env":  cfg.Environment,
		})
		
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down Firebase MCP Server...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	}

	logger.Info("Firebase MCP Server stopped")
}

// setupRouter sets up the HTTP router with all routes
func setupRouter(handlers *firebase.MCPHandlers, logger *logger.Logger) *mux.Router {
	router := mux.NewRouter()

	// Add middleware
	router.Use(middleware.RequestID)
	router.Use(middleware.Logging(logger))
	router.Use(middleware.Recovery(logger))
	router.Use(middleware.SecurityHeaders())

	// API routes
	api := router.PathPrefix("/api/firebase").Subrouter()

	// Authentication routes
	auth := api.PathPrefix("/auth").Subrouter()
	auth.HandleFunc("/google", handlers.GoogleAuthHandler).Methods("POST", "OPTIONS")
	auth.HandleFunc("/refresh", handlers.RefreshTokenHandler).Methods("POST", "OPTIONS")
	auth.HandleFunc("/validate", handlers.ValidateTokenHandler).Methods("POST", "OPTIONS")
	auth.HandleFunc("/profile", handlers.GetUserProfileHandler).Methods("GET", "OPTIONS")
	auth.HandleFunc("/revoke", handlers.RevokeTokenHandler).Methods("POST", "OPTIONS")

	// User management routes
	users := api.PathPrefix("/users").Subrouter()
	users.HandleFunc("", handlers.ListUsersHandler).Methods("GET", "OPTIONS")
	users.HandleFunc("/search", handlers.SearchUsersHandler).Methods("GET", "OPTIONS")
	users.HandleFunc("/{userID}/sessions", handlers.GetUserSessionsHandler).Methods("GET", "OPTIONS")

	// Health check
	router.HandleFunc("/health", handlers.HealthCheckHandler).Methods("GET")
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
			"service": "Firebase MCP Server",
			"version": "1.0.0",
			"status": "running",
			"timestamp": "%s",
			"endpoints": {
				"auth": "/api/firebase/auth",
				"users": "/api/firebase/users",
				"health": "/health"
			}
		}`, time.Now().Format(time.RFC3339))
	}).Methods("GET")

	return router
}

// getPort returns the port to listen on
func getPort() string {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return port
}

// Firebase MCP Integration Examples

// Example of how to use Firebase MCP tools in your application:

/*
// 1. Initialize Firebase MCP Service
config := &firebase.Config{...}
logger := logger.New("app", "info")
mcpService := firebase.NewMCPService(config, logger)

// 2. Authenticate with Google
authRequest := &firebase.GoogleAuthRequest{
	IDToken: "google_id_token_here",
	Scopes:  []string{"openid", "email", "profile"},
}

ctx := context.Background()
authResponse, err := mcpService.AuthenticateWithGoogle(ctx, authRequest)
if err != nil {
	log.Fatal(err)
}

// 3. Use the authenticated user
user := authResponse.User
fmt.Printf("Authenticated user: %s (%s)\n", user.DisplayName, user.Email)

// 4. Create MCP client for Firestore operations
mcpClient := firebase.NewMCPClient(config, logger)

// 5. Create a user document
userData := map[string]interface{}{
	"email":        user.Email,
	"display_name": user.DisplayName,
	"photo_url":    user.PhotoURL,
	"provider":     "google.com",
}

userDoc, err := mcpClient.CreateUser(ctx, userData)
if err != nil {
	log.Fatal(err)
}

// 6. Query users
users, _, err := mcpClient.ListUsers(ctx, 10, "")
if err != nil {
	log.Fatal(err)
}

// 7. Search users
searchResults, err := mcpClient.SearchUsers(ctx, "john", 5)
if err != nil {
	log.Fatal(err)
}

// 8. Manage user sessions
session, err := mcpClient.CreateUserSession(ctx, user.UID, map[string]interface{}{
	"ip_address": "192.168.1.1",
	"user_agent": "Mozilla/5.0...",
})
if err != nil {
	log.Fatal(err)
}

// 9. Upload files to Firebase Storage
fileInfo, err := mcpClient.UploadFile(ctx, "users/profile.jpg", "file_content", "image/jpeg", nil)
if err != nil {
	log.Fatal(err)
}

// 10. Refresh Google tokens
newTokens, err := mcpService.RefreshGoogleToken(ctx, "refresh_token_here")
if err != nil {
	log.Fatal(err)
}
*/

// Environment Variables Required:
/*
# Firebase Configuration
FIREBASE_API_KEY_DEV=your_dev_api_key
FIREBASE_AUTH_DOMAIN_DEV=your_dev_auth_domain
FIREBASE_PROJECT_ID_DEV=your_dev_project_id
FIREBASE_STORAGE_BUCKET_DEV=your_dev_storage_bucket
FIREBASE_MESSAGING_SENDER_ID_DEV=your_dev_messaging_sender_id
FIREBASE_APP_ID_DEV=your_dev_app_id

# Google OAuth Configuration
GOOGLE_OAUTH_CLIENT_ID_DEV=your_google_client_id
GOOGLE_OAUTH_CLIENT_SECRET_DEV=your_google_client_secret

# Server Configuration
PORT=8080
ENVIRONMENT=development

# Service Account
GOOGLE_APPLICATION_CREDENTIALS=./configs/firebase/service-accounts/hackai-dev-service-account.json
*/

// Docker Configuration:
/*
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o firebase-mcp-server ./cmd/firebase-mcp-server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/firebase-mcp-server .
COPY --from=builder /app/configs ./configs

EXPOSE 8080
CMD ["./firebase-mcp-server"]
*/

// Kubernetes Deployment:
/*
apiVersion: apps/v1
kind: Deployment
metadata:
  name: firebase-mcp-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: firebase-mcp-server
  template:
    metadata:
      labels:
        app: firebase-mcp-server
    spec:
      containers:
      - name: firebase-mcp-server
        image: hackai/firebase-mcp-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: PORT
          value: "8080"
        - name: ENVIRONMENT
          value: "production"
        envFrom:
        - secretRef:
            name: firebase-secrets
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: firebase-mcp-service
spec:
  selector:
    app: firebase-mcp-server
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
*/
