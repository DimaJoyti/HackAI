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

	"github.com/dimajoyti/hackai/internal/repository"
	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/firebase"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	// Initialize logger
	loggerInstance := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
	})

	loggerInstance.Info("Starting Firebase Auth Service")

	// Load configuration
	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		loggerInstance.WithError(err).Fatal("Failed to load configuration")
	}

	// Initialize database
	db, err := database.New(&database.Config{
		Host:            cfg.Database.Host,
		Port:            cfg.Database.Port,
		Name:            cfg.Database.Name,
		User:            cfg.Database.User,
		Password:        cfg.Database.Password,
		SSLMode:         cfg.Database.SSLMode,
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
		ConnMaxIdleTime: cfg.Database.ConnMaxIdleTime,
	})
	if err != nil {
		loggerInstance.WithError(err).Fatal("Failed to initialize database")
	}
	defer db.Close()

	// Initialize repositories
	userRepo := repository.NewUserRepository(db.DB, loggerInstance)

	// Load Firebase configuration
	environment := os.Getenv("ENVIRONMENT")
	if environment == "" {
		environment = "development"
	}

	firebaseConfig, err := firebase.LoadConfig("configs/firebase/firebase-config.yaml", environment)
	if err != nil {
		loggerInstance.WithError(err).Fatal("Failed to load Firebase configuration")
	}

	// Validate Firebase configuration
	if err := firebaseConfig.Validate(); err != nil {
		loggerInstance.WithError(err).Fatal("Invalid Firebase configuration")
	}

	// Initialize Firebase service
	firebaseService, err := firebase.NewService(firebaseConfig, loggerInstance, userRepo)
	if err != nil {
		loggerInstance.WithError(err).Fatal("Failed to initialize Firebase service")
	}

	// Initialize Firebase handlers
	firebaseHandler := firebase.NewHandler(firebaseService, loggerInstance)

	// Initialize Firebase middleware
	firebaseMiddleware := firebase.NewMiddleware(firebaseService, loggerInstance)

	// Setup router
	router := mux.NewRouter()

	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"firebase-auth-service"}`))
	}).Methods("GET")

	// Register Firebase routes
	firebaseHandler.RegisterRoutes(router)

	// Protected routes example
	protected := router.PathPrefix("/api/protected").Subrouter()
	protected.Use(firebaseMiddleware.AuthRequired)
	
	protected.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		user := firebase.GetUserFromContext(r.Context())
		if user == nil {
			http.Error(w, "User not found in context", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message":"Hello %s","user":{"uid":"%s","email":"%s"}}`, 
			user.DisplayName, user.UID, user.Email)
	}).Methods("GET")

	// Admin routes example
	admin := router.PathPrefix("/api/admin").Subrouter()
	admin.Use(firebaseMiddleware.AuthRequired)
	admin.Use(firebaseMiddleware.RequireRole("admin"))
	
	admin.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Admin access granted"}`))
	}).Methods("GET")

	// Setup CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",
			"http://localhost:5000",
			"https://hackai.dev",
			"https://staging.hackai.dev",
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
			"Link",
		},
		AllowCredentials: true,
		MaxAge:           300,
	})

	// Wrap router with CORS
	handler := c.Handler(router)

	// Setup server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		loggerInstance.Info("Firebase Auth Service starting", map[string]interface{}{
			"port":        port,
			"environment": environment,
			"firebase_project": firebaseConfig.Firebase.ProjectID,
		})

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			loggerInstance.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	loggerInstance.Info("Shutting down Firebase Auth Service...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		loggerInstance.WithError(err).Error("Server forced to shutdown")
	}

	loggerInstance.Info("Firebase Auth Service stopped")
}

// Example of how to use Firebase MCP tools in the service
func demonstrateFirebaseMCPIntegration(firebaseService *firebase.Service, logger *logger.Logger) {
	ctx := context.Background()

	// Example: Create a user using Firebase MCP tools
	createUserReq := &firebase.CreateUserRequest{
		Email:         "demo@example.com",
		Password:      "securePassword123",
		DisplayName:   "Demo User",
		EmailVerified: false,
		Username:      "demouser",
		FirstName:     "Demo",
		LastName:      "User",
		Role:          "user",
	}

	user, err := firebaseService.CreateUser(ctx, createUserReq)
	if err != nil {
		logger.WithError(err).Error("Failed to create user with Firebase MCP")
		return
	}

	logger.Info("User created successfully with Firebase MCP", map[string]interface{}{
		"uid":   user.UID,
		"email": user.Email,
	})

	// Example: Set custom claims
	claims := map[string]interface{}{
		"role":         "user",
		"organization": "hackai",
		"permissions":  []string{"read", "write"},
	}

	err = firebaseService.SetCustomUserClaims(ctx, user.UID, claims)
	if err != nil {
		logger.WithError(err).Error("Failed to set custom claims")
		return
	}

	logger.Info("Custom claims set successfully", map[string]interface{}{
		"uid":    user.UID,
		"claims": claims,
	})

	// Example: Sync user to database
	err = firebaseService.SyncFirebaseUserToDatabase(ctx, user.UID)
	if err != nil {
		logger.WithError(err).Error("Failed to sync user to database")
		return
	}

	logger.Info("User synced to database successfully", map[string]interface{}{
		"uid": user.UID,
	})
}
