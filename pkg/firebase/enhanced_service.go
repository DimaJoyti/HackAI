package firebase

import (
	"context"
	"fmt"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"firebase.google.com/go/v4/db"
	"firebase.google.com/go/v4/messaging"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/api/option"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var firebaseTracer = otel.Tracer("hackai/firebase/enhanced_service")

// EnhancedService provides comprehensive Firebase services with observability
type EnhancedService struct {
	app             *firebase.App
	authClient      *auth.Client
	dbClient        *db.Client
	messagingClient *messaging.Client
	config          *Config
	logger          *logger.Logger
	userRepo        domain.UserRepository

	// Metrics and monitoring
	metrics       *FirebaseMetrics
	healthChecker *HealthChecker
}

// FirebaseMetrics tracks Firebase service metrics
type FirebaseMetrics struct {
	AuthVerifications  int64
	UserCreations      int64
	TokenGenerations   int64
	DatabaseOperations int64
	Errors             int64
	LastHealthCheck    time.Time
	ServiceUptime      time.Time
}

// HealthChecker monitors Firebase service health
type HealthChecker struct {
	lastCheck     time.Time
	isHealthy     bool
	lastError     error
	checkInterval time.Duration
}

// NewEnhancedService creates a new enhanced Firebase service
func NewEnhancedService(config *Config, log *logger.Logger, userRepo domain.UserRepository) (*EnhancedService, error) {
	ctx, span := firebaseTracer.Start(context.Background(), "firebase.NewEnhancedService")
	defer span.End()

	// Initialize Firebase app with service account
	opt := option.WithCredentialsFile(config.Firebase.Admin.ServiceAccountPath)
	firebaseConfig := &firebase.Config{
		ProjectID:   config.Firebase.ProjectID,
		DatabaseURL: config.Firebase.Admin.DatabaseURL,
	}

	app, err := firebase.NewApp(ctx, firebaseConfig, opt)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to initialize Firebase app: %w", err)
	}

	// Get Auth client
	authClient, err := app.Auth(ctx)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get Firebase Auth client: %w", err)
	}

	// Get Database client (optional)
	var dbClient *db.Client
	if config.Firebase.Admin.DatabaseURL != "" {
		dbClient, err = app.Database(ctx)
		if err != nil {
			log.WithError(err).Warn("Failed to initialize Firebase Database client")
		}
	}

	// Get Messaging client (optional)
	messagingClient, err := app.Messaging(ctx)
	if err != nil {
		log.WithError(err).Warn("Failed to initialize Firebase Messaging client")
	}

	service := &EnhancedService{
		app:             app,
		authClient:      authClient,
		dbClient:        dbClient,
		messagingClient: messagingClient,
		config:          config,
		logger:          log,
		userRepo:        userRepo,
		metrics: &FirebaseMetrics{
			ServiceUptime: time.Now(),
		},
		healthChecker: &HealthChecker{
			checkInterval: 30 * time.Second,
			isHealthy:     true,
		},
	}

	// Start health monitoring
	go service.startHealthMonitoring()

	span.SetAttributes(
		attribute.String("firebase.project_id", config.Firebase.ProjectID),
		attribute.Bool("firebase.database_enabled", dbClient != nil),
		attribute.Bool("firebase.messaging_enabled", messagingClient != nil),
	)

	log.Info("Enhanced Firebase service initialized successfully", map[string]interface{}{
		"project_id":        config.Firebase.ProjectID,
		"database_enabled":  dbClient != nil,
		"messaging_enabled": messagingClient != nil,
	})

	return service, nil
}

// VerifyIDTokenWithContext verifies a Firebase ID token with enhanced context
func (s *EnhancedService) VerifyIDTokenWithContext(ctx context.Context, idToken string) (*auth.Token, error) {
	ctx, span := firebaseTracer.Start(ctx, "firebase.VerifyIDToken")
	defer span.End()

	start := time.Now()
	defer func() {
		s.metrics.AuthVerifications++
		span.SetAttributes(
			attribute.Int64("firebase.auth_verifications_total", s.metrics.AuthVerifications),
			attribute.String("duration", time.Since(start).String()),
		)
	}()

	token, err := s.authClient.VerifyIDToken(ctx, idToken)
	if err != nil {
		s.metrics.Errors++
		span.RecordError(err)
		s.logger.WithError(err).Error("Failed to verify Firebase ID token")
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	span.SetAttributes(
		attribute.String("firebase.user_id", token.UID),
		attribute.String("firebase.issuer", token.Issuer),
		attribute.Bool("firebase.email_verified", token.Claims["email_verified"].(bool)),
	)

	s.logger.Debug("Firebase ID token verified successfully", map[string]interface{}{
		"uid":            token.UID,
		"email":          token.Claims["email"],
		"email_verified": token.Claims["email_verified"],
		"auth_time":      token.AuthTime,
	})

	return token, nil
}

// CreateUserWithEnhancedLogging creates a user with comprehensive logging
func (s *EnhancedService) CreateUserWithEnhancedLogging(ctx context.Context, req *CreateUserRequest) (*UserResponse, error) {
	ctx, span := firebaseTracer.Start(ctx, "firebase.CreateUser")
	defer span.End()

	start := time.Now()
	defer func() {
		s.metrics.UserCreations++
		span.SetAttributes(
			attribute.Int64("firebase.user_creations_total", s.metrics.UserCreations),
			attribute.String("duration", time.Since(start).String()),
		)
	}()

	span.SetAttributes(
		attribute.String("firebase.user_email", req.Email),
		attribute.Bool("firebase.email_verified", req.EmailVerified),
		attribute.Bool("firebase.user_disabled", req.Disabled),
	)

	s.logger.Info("Creating Firebase user", map[string]interface{}{
		"email":          req.Email,
		"display_name":   req.DisplayName,
		"email_verified": req.EmailVerified,
		"has_password":   req.Password != "",
		"has_phone":      req.PhoneNumber != "",
	})

	// Create user in Firebase
	params := (&auth.UserToCreate{}).
		UID(req.UID).
		Email(req.Email).
		EmailVerified(req.EmailVerified).
		DisplayName(req.DisplayName).
		Disabled(req.Disabled)

	if req.Password != "" {
		params = params.Password(req.Password)
	}

	if req.PhoneNumber != "" {
		params = params.PhoneNumber(req.PhoneNumber)
	}

	firebaseUser, err := s.authClient.CreateUser(ctx, params)
	if err != nil {
		s.metrics.Errors++
		span.RecordError(err)
		s.logger.WithError(err).Error("Failed to create Firebase user", map[string]interface{}{
			"email": req.Email,
		})
		return nil, fmt.Errorf("failed to create Firebase user: %w", err)
	}

	// Set custom claims if provided
	if len(req.CustomClaims) > 0 {
		if err := s.authClient.SetCustomUserClaims(ctx, firebaseUser.UID, req.CustomClaims); err != nil {
			s.logger.WithError(err).Warn("Failed to set custom claims", map[string]interface{}{
				"uid":    firebaseUser.UID,
				"claims": req.CustomClaims,
			})
		} else {
			span.SetAttributes(attribute.String("firebase.custom_claims_set", "true"))
		}
	}

	// Sync with local database if enabled
	if s.config.Common.Integration.DatabaseSync.Enabled && s.config.Common.Integration.DatabaseSync.SyncOnCreate {
		if err := s.syncUserToDatabase(ctx, firebaseUser, req); err != nil {
			s.logger.WithError(err).Error("Failed to sync user to database", map[string]interface{}{
				"uid":   firebaseUser.UID,
				"email": firebaseUser.Email,
			})
			// Don't fail the entire operation, just log the error
		} else {
			span.SetAttributes(attribute.String("firebase.database_sync", "success"))
		}
	}

	response := &UserResponse{
		UID:           firebaseUser.UID,
		Email:         firebaseUser.Email,
		DisplayName:   firebaseUser.DisplayName,
		EmailVerified: firebaseUser.EmailVerified,
		PhoneNumber:   firebaseUser.PhoneNumber,
		Disabled:      firebaseUser.Disabled,
		CreatedAt:     firebaseUser.UserMetadata.CreationTimestamp,
		LastLoginAt:   firebaseUser.UserMetadata.LastLogInTimestamp,
		CustomClaims:  req.CustomClaims,
	}

	span.SetAttributes(
		attribute.String("firebase.created_user_id", firebaseUser.UID),
		attribute.String("firebase.created_user_email", firebaseUser.Email),
	)

	s.logger.Info("Firebase user created successfully", map[string]interface{}{
		"uid":            firebaseUser.UID,
		"email":          firebaseUser.Email,
		"display_name":   firebaseUser.DisplayName,
		"email_verified": firebaseUser.EmailVerified,
		"creation_time":  firebaseUser.UserMetadata.CreationTimestamp,
	})

	return response, nil
}

// GetMetrics returns current service metrics
func (s *EnhancedService) GetMetrics() *FirebaseMetrics {
	return s.metrics
}

// GetHealthStatus returns current health status
func (s *EnhancedService) GetHealthStatus() *HealthStatus {
	return &HealthStatus{
		IsHealthy:        s.healthChecker.isHealthy,
		LastCheck:        s.healthChecker.lastCheck,
		LastError:        s.healthChecker.lastError,
		ServiceUptime:    time.Since(s.metrics.ServiceUptime),
		ProjectID:        s.config.Firebase.ProjectID,
		DatabaseEnabled:  s.dbClient != nil,
		MessagingEnabled: s.messagingClient != nil,
	}
}

// HealthStatus represents the health status of Firebase service
type HealthStatus struct {
	IsHealthy        bool          `json:"is_healthy"`
	LastCheck        time.Time     `json:"last_check"`
	LastError        error         `json:"last_error,omitempty"`
	ServiceUptime    time.Duration `json:"service_uptime"`
	ProjectID        string        `json:"project_id"`
	DatabaseEnabled  bool          `json:"database_enabled"`
	MessagingEnabled bool          `json:"messaging_enabled"`
}

// startHealthMonitoring starts the health monitoring goroutine
func (s *EnhancedService) startHealthMonitoring() {
	ticker := time.NewTicker(s.healthChecker.checkInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.performHealthCheck()
	}
}

// performHealthCheck performs a health check on Firebase services
func (s *EnhancedService) performHealthCheck() {
	ctx, span := firebaseTracer.Start(context.Background(), "firebase.HealthCheck")
	defer span.End()

	s.healthChecker.lastCheck = time.Now()
	s.metrics.LastHealthCheck = time.Now()

	// Test Auth service
	_, err := s.authClient.GetUser(ctx, "health-check-test-user")
	if err != nil && !auth.IsUserNotFound(err) {
		s.healthChecker.isHealthy = false
		s.healthChecker.lastError = err
		span.RecordError(err)
		s.logger.WithError(err).Warn("Firebase Auth health check failed")
		return
	}

	s.healthChecker.isHealthy = true
	s.healthChecker.lastError = nil
	span.SetAttributes(attribute.Bool("firebase.health_check_passed", true))
}

// syncUserToDatabase syncs Firebase user to local database
func (s *EnhancedService) syncUserToDatabase(ctx context.Context, firebaseUser *auth.UserRecord, req *CreateUserRequest) error {
	if s.userRepo == nil {
		return fmt.Errorf("user repository not available")
	}

	// Create domain user from Firebase user
	user := &domain.User{
		ID:            uuid.New(),
		FirebaseUID:   firebaseUser.UID,
		Email:         firebaseUser.Email,
		Username:      req.Username,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		DisplayName:   firebaseUser.DisplayName,
		EmailVerified: firebaseUser.EmailVerified,
		PhoneNumber:   firebaseUser.PhoneNumber,
		Role:          domain.UserRole(req.Role),
		Status:        domain.UserStatusActive,
		Organization:  req.Organization,
		CreatedAt:     time.Unix(firebaseUser.UserMetadata.CreationTimestamp, 0),
		UpdatedAt:     time.Now(),
	}

	if firebaseUser.UserMetadata.LastLogInTimestamp != 0 {
		lastLogin := time.Unix(firebaseUser.UserMetadata.LastLogInTimestamp, 0)
		user.LastLoginAt = &lastLogin
	}

	return s.userRepo.Create(user)
}

// GetUser retrieves a user by UID
func (s *EnhancedService) GetUser(ctx context.Context, uid string) (*UserResponse, error) {
	ctx, span := firebaseTracer.Start(ctx, "firebase.GetUser")
	defer span.End()

	firebaseUser, err := s.authClient.GetUser(ctx, uid)
	if err != nil {
		s.metrics.Errors++
		span.RecordError(err)
		s.logger.WithError(err).Error("Failed to get Firebase user", map[string]interface{}{
			"uid": uid,
		})
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	response := &UserResponse{
		UID:           firebaseUser.UID,
		Email:         firebaseUser.Email,
		DisplayName:   firebaseUser.DisplayName,
		EmailVerified: firebaseUser.EmailVerified,
		PhoneNumber:   firebaseUser.PhoneNumber,
		Disabled:      firebaseUser.Disabled,
		CreatedAt:     firebaseUser.UserMetadata.CreationTimestamp,
		LastLoginAt:   firebaseUser.UserMetadata.LastLogInTimestamp,
		CustomClaims:  firebaseUser.CustomClaims,
	}

	span.SetAttributes(
		attribute.String("firebase.user_id", firebaseUser.UID),
		attribute.String("firebase.user_email", firebaseUser.Email),
	)

	return response, nil
}

// CreateCustomToken creates a custom token for a user
func (s *EnhancedService) CreateCustomToken(ctx context.Context, uid string, claims map[string]interface{}) (string, error) {
	ctx, span := firebaseTracer.Start(ctx, "firebase.CreateCustomToken")
	defer span.End()

	start := time.Now()
	defer func() {
		s.metrics.TokenGenerations++
		span.SetAttributes(
			attribute.Int64("firebase.token_generations_total", s.metrics.TokenGenerations),
			attribute.String("duration", time.Since(start).String()),
		)
	}()

	var token string
	var err error

	if len(claims) > 0 {
		token, err = s.authClient.CustomTokenWithClaims(ctx, uid, claims)
	} else {
		token, err = s.authClient.CustomToken(ctx, uid)
	}

	if err != nil {
		s.metrics.Errors++
		span.RecordError(err)
		s.logger.WithError(err).Error("Failed to create custom token", map[string]interface{}{
			"uid": uid,
		})
		return "", fmt.Errorf("failed to create custom token: %w", err)
	}

	span.SetAttributes(
		attribute.String("firebase.custom_token_uid", uid),
		attribute.Int("firebase.custom_token_claims_count", len(claims)),
	)

	s.logger.Debug("Custom token created successfully", map[string]interface{}{
		"uid":          uid,
		"claims_count": len(claims),
	})

	return token, nil
}

// SetCustomUserClaims sets custom claims for a user
func (s *EnhancedService) SetCustomUserClaims(ctx context.Context, uid string, claims map[string]interface{}) error {
	ctx, span := firebaseTracer.Start(ctx, "firebase.SetCustomUserClaims")
	defer span.End()

	if err := s.authClient.SetCustomUserClaims(ctx, uid, claims); err != nil {
		s.metrics.Errors++
		span.RecordError(err)
		s.logger.WithError(err).Error("Failed to set custom user claims", map[string]interface{}{
			"uid":    uid,
			"claims": claims,
		})
		return fmt.Errorf("failed to set custom user claims: %w", err)
	}

	span.SetAttributes(
		attribute.String("firebase.claims_uid", uid),
		attribute.Int("firebase.claims_count", len(claims)),
	)

	s.logger.Info("Custom claims set successfully", map[string]interface{}{
		"uid":    uid,
		"claims": claims,
	})

	return nil
}

// RevokeRefreshTokens revokes all refresh tokens for a user
func (s *EnhancedService) RevokeRefreshTokens(ctx context.Context, uid string) error {
	ctx, span := firebaseTracer.Start(ctx, "firebase.RevokeRefreshTokens")
	defer span.End()

	if err := s.authClient.RevokeRefreshTokens(ctx, uid); err != nil {
		s.metrics.Errors++
		span.RecordError(err)
		s.logger.WithError(err).Error("Failed to revoke refresh tokens", map[string]interface{}{
			"uid": uid,
		})
		return fmt.Errorf("failed to revoke refresh tokens: %w", err)
	}

	span.SetAttributes(attribute.String("firebase.revoked_tokens_uid", uid))

	s.logger.Info("Refresh tokens revoked successfully", map[string]interface{}{
		"uid": uid,
	})

	return nil
}

// UpdateUser updates a user's profile
func (s *EnhancedService) UpdateUser(ctx context.Context, uid string, req *UpdateUserRequest) (*UserResponse, error) {
	ctx, span := firebaseTracer.Start(ctx, "firebase.UpdateUser")
	defer span.End()

	params := &auth.UserToUpdate{}

	if req.Email != nil {
		params = params.Email(*req.Email)
	}
	if req.DisplayName != nil {
		params = params.DisplayName(*req.DisplayName)
	}
	if req.PhoneNumber != nil {
		params = params.PhoneNumber(*req.PhoneNumber)
	}
	if req.Password != nil {
		params = params.Password(*req.Password)
	}
	if req.EmailVerified != nil {
		params = params.EmailVerified(*req.EmailVerified)
	}
	if req.Disabled != nil {
		params = params.Disabled(*req.Disabled)
	}

	firebaseUser, err := s.authClient.UpdateUser(ctx, uid, params)
	if err != nil {
		s.metrics.Errors++
		span.RecordError(err)
		s.logger.WithError(err).Error("Failed to update Firebase user", map[string]interface{}{
			"uid": uid,
		})
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	response := &UserResponse{
		UID:           firebaseUser.UID,
		Email:         firebaseUser.Email,
		DisplayName:   firebaseUser.DisplayName,
		EmailVerified: firebaseUser.EmailVerified,
		PhoneNumber:   firebaseUser.PhoneNumber,
		Disabled:      firebaseUser.Disabled,
		CreatedAt:     firebaseUser.UserMetadata.CreationTimestamp,
		LastLoginAt:   firebaseUser.UserMetadata.LastLogInTimestamp,
		CustomClaims:  firebaseUser.CustomClaims,
	}

	span.SetAttributes(
		attribute.String("firebase.updated_user_id", firebaseUser.UID),
		attribute.String("firebase.updated_user_email", firebaseUser.Email),
	)

	s.logger.Info("Firebase user updated successfully", map[string]interface{}{
		"uid":   firebaseUser.UID,
		"email": firebaseUser.Email,
	})

	return response, nil
}

// DeleteUser deletes a user
func (s *EnhancedService) DeleteUser(ctx context.Context, uid string) error {
	ctx, span := firebaseTracer.Start(ctx, "firebase.DeleteUser")
	defer span.End()

	if err := s.authClient.DeleteUser(ctx, uid); err != nil {
		s.metrics.Errors++
		span.RecordError(err)
		s.logger.WithError(err).Error("Failed to delete Firebase user", map[string]interface{}{
			"uid": uid,
		})
		return fmt.Errorf("failed to delete user: %w", err)
	}

	span.SetAttributes(attribute.String("firebase.deleted_user_id", uid))

	s.logger.Info("Firebase user deleted successfully", map[string]interface{}{
		"uid": uid,
	})

	return nil
}

// ListUsers lists users with pagination
func (s *EnhancedService) ListUsers(ctx context.Context, maxResults int, pageToken string) (*ListUsersResponse, error) {
	ctx, span := firebaseTracer.Start(ctx, "firebase.ListUsers")
	defer span.End()

	iter := s.authClient.Users(ctx, pageToken)

	var users []*UserResponse
	var nextPageToken string
	count := 0

	for count < maxResults {
		user, err := iter.Next()
		if err != nil {
			break
		}
		users = append(users, s.mapFirebaseUserToResponse(user.UserRecord))
		count++
	}

	// Get next page token if available
	if iter.PageInfo().Token != "" {
		nextPageToken = iter.PageInfo().Token
	}

	span.SetAttributes(
		attribute.Int("firebase.listed_users_count", len(users)),
		attribute.Bool("firebase.has_next_page", nextPageToken != ""),
	)

	s.logger.Debug("Firebase users listed successfully", map[string]interface{}{
		"count":           len(users),
		"has_next_page":   nextPageToken != "",
		"next_page_token": nextPageToken,
	})

	return &ListUsersResponse{
		Users:         users,
		NextPageToken: nextPageToken,
	}, nil
}

// mapFirebaseUserToResponse maps a Firebase user record to a response
func (s *EnhancedService) mapFirebaseUserToResponse(user *auth.UserRecord) *UserResponse {
	return &UserResponse{
		UID:           user.UID,
		Email:         user.Email,
		DisplayName:   user.DisplayName,
		EmailVerified: user.EmailVerified,
		PhoneNumber:   user.PhoneNumber,
		Disabled:      user.Disabled,
		CreatedAt:     user.UserMetadata.CreationTimestamp,
		LastLoginAt:   user.UserMetadata.LastLogInTimestamp,
		CustomClaims:  user.CustomClaims,
	}
}
