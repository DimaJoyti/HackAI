package firebase

import (
	"context"
	"fmt"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// ProfileService provides comprehensive user profile management
type ProfileService struct {
	mcpIntegration *MCPIntegration
	logger         *logger.Logger
	config         *Config
}

// NewProfileService creates a new profile service
func NewProfileService(mcpIntegration *MCPIntegration, logger *logger.Logger, config *Config) *ProfileService {
	return &ProfileService{
		mcpIntegration: mcpIntegration,
		logger:         logger,
		config:         config,
	}
}

// UserProfile represents a comprehensive user profile
type UserProfile struct {
	// Basic Information
	UID           string    `json:"uid"`
	Email         string    `json:"email"`
	DisplayName   string    `json:"display_name"`
	PhotoURL      string    `json:"photo_url"`
	EmailVerified bool      `json:"email_verified"`
	PhoneNumber   string    `json:"phone_number"`
	Provider      string    `json:"provider"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastLoginAt   time.Time `json:"last_login_at"`

	// Google Profile Information
	GoogleProfile *GoogleProfileInfo `json:"google_profile,omitempty"`

	// Role and Permissions
	Role         string                 `json:"role"`
	Permissions  []string               `json:"permissions"`
	CustomClaims map[string]interface{} `json:"custom_claims"`

	// Profile Settings
	Settings *ProfileSettings `json:"settings"`

	// Account Status
	Active    bool `json:"active"`
	Suspended bool `json:"suspended"`
	Verified  bool `json:"verified"`

	// Metadata
	Metadata *ProfileMetadata `json:"metadata"`
}

// GoogleProfileInfo contains Google-specific profile information
type GoogleProfileInfo struct {
	GoogleID     string    `json:"google_id"`
	GivenName    string    `json:"given_name"`
	FamilyName   string    `json:"family_name"`
	Locale       string    `json:"locale"`
	HostedDomain string    `json:"hosted_domain,omitempty"`
	PictureURL   string    `json:"picture_url"`
	LastSyncAt   time.Time `json:"last_sync_at"`
	SyncEnabled  bool      `json:"sync_enabled"`
}

// ProfileSettings contains user preferences and settings
type ProfileSettings struct {
	Theme                string `json:"theme"`
	Language             string `json:"language"`
	Timezone             string `json:"timezone"`
	NotificationsEnabled bool   `json:"notifications_enabled"`
	EmailUpdates         bool   `json:"email_updates"`
	PrivacyLevel         string `json:"privacy_level"`
	TwoFactorEnabled     bool   `json:"two_factor_enabled"`
	ProfileVisibility    string `json:"profile_visibility"`
}

// ProfileMetadata contains additional profile metadata
type ProfileMetadata struct {
	LoginCount     int      `json:"login_count"`
	LastIPAddress  string   `json:"last_ip_address"`
	LastUserAgent  string   `json:"last_user_agent"`
	RegistrationIP string   `json:"registration_ip"`
	RegistrationUA string   `json:"registration_ua"`
	AccountSource  string   `json:"account_source"`
	ReferralCode   string   `json:"referral_code,omitempty"`
	Tags           []string `json:"tags,omitempty"`
}

// CreateUserProfile creates a new user profile with Google sync
func (s *ProfileService) CreateUserProfile(ctx context.Context, googleUserInfo map[string]interface{}, metadata *ProfileMetadata) (*UserProfile, error) {
	s.logger.Info("Creating user profile with Google sync", map[string]interface{}{
		"email": googleUserInfo["email"],
	})

	// Create Google profile info
	googleProfile := &GoogleProfileInfo{
		GoogleID:     getStringValue(googleUserInfo, "sub"),
		GivenName:    getStringValue(googleUserInfo, "given_name"),
		FamilyName:   getStringValue(googleUserInfo, "family_name"),
		Locale:       getStringValue(googleUserInfo, "locale"),
		HostedDomain: getStringValue(googleUserInfo, "hd"),
		PictureURL:   getStringValue(googleUserInfo, "picture"),
		LastSyncAt:   time.Now(),
		SyncEnabled:  true,
	}

	// Create default settings
	settings := &ProfileSettings{
		Theme:                "light",
		Language:             googleProfile.Locale,
		Timezone:             "UTC",
		NotificationsEnabled: true,
		EmailUpdates:         true,
		PrivacyLevel:         "standard",
		TwoFactorEnabled:     false,
		ProfileVisibility:    "private",
	}

	// Create user profile
	profile := &UserProfile{
		UID:           fmt.Sprintf("user_%d", time.Now().UnixNano()),
		Email:         getStringValue(googleUserInfo, "email"),
		DisplayName:   getStringValue(googleUserInfo, "name"),
		PhotoURL:      getStringValue(googleUserInfo, "picture"),
		EmailVerified: getBoolValue(googleUserInfo, "email_verified"),
		Provider:      "google.com",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		LastLoginAt:   time.Now(),
		GoogleProfile: googleProfile,
		Role:          "user", // Default role
		Permissions:   []string{"profile:read", "profile:write"},
		CustomClaims:  make(map[string]interface{}),
		Settings:      settings,
		Active:        true,
		Suspended:     false,
		Verified:      getBoolValue(googleUserInfo, "email_verified"),
		Metadata:      metadata,
	}

	// Save profile to Firestore using MCP
	profileData := s.profileToMap(profile)
	doc, err := s.mcpIntegration.CreateUserWithMCP(ctx, profileData)
	if err != nil {
		return nil, fmt.Errorf("failed to create user profile: %w", err)
	}

	profile.UID = doc.ID

	// Create user preferences document
	preferencesData := map[string]interface{}{
		"user_id":    profile.UID,
		"settings":   s.settingsToMap(settings),
		"created_at": time.Now().Unix(),
		"updated_at": time.Now().Unix(),
	}

	_, err = s.mcpIntegration.callFirestoreAddDocument(ctx, &FirestoreAddDocumentRequest{
		Collection: "user_preferences",
		Data:       preferencesData,
	})
	if err != nil {
		s.logger.WithError(err).Warn("Failed to create user preferences")
	}

	// Create user roles document
	rolesData := map[string]interface{}{
		"user_id":       profile.UID,
		"role":          profile.Role,
		"permissions":   profile.Permissions,
		"custom_claims": profile.CustomClaims,
		"created_at":    time.Now().Unix(),
		"updated_at":    time.Now().Unix(),
	}

	_, err = s.mcpIntegration.callFirestoreAddDocument(ctx, &FirestoreAddDocumentRequest{
		Collection: "user_roles",
		Data:       rolesData,
	})
	if err != nil {
		s.logger.WithError(err).Warn("Failed to create user roles")
	}

	s.logger.Info("User profile created successfully", map[string]interface{}{
		"user_id": profile.UID,
		"email":   profile.Email,
		"role":    profile.Role,
	})

	return profile, nil
}

// GetUserProfile retrieves a complete user profile
func (s *ProfileService) GetUserProfile(ctx context.Context, userID string) (*UserProfile, error) {
	s.logger.Info("Getting user profile", map[string]interface{}{
		"user_id": userID,
	})

	// Get user document
	userDoc, err := s.mcpIntegration.callFirestoreListDocuments(ctx, &FirestoreListDocumentsRequest{
		Collection: "users",
		Filters: []FirestoreFilter{
			{Field: "uid", Operator: "==", Value: userID},
		},
		Limit: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if len(userDoc.Documents) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	profile := s.mapToProfile(userDoc.Documents[0])

	// Get user preferences
	preferencesDoc, err := s.mcpIntegration.callFirestoreListDocuments(ctx, &FirestoreListDocumentsRequest{
		Collection: "user_preferences",
		Filters: []FirestoreFilter{
			{Field: "user_id", Operator: "==", Value: userID},
		},
		Limit: 1,
	})
	if err == nil && len(preferencesDoc.Documents) > 0 {
		if settingsData, ok := preferencesDoc.Documents[0]["settings"].(map[string]interface{}); ok {
			profile.Settings = s.mapToSettings(settingsData)
		}
	}

	// Get user roles
	rolesDoc, err := s.mcpIntegration.callFirestoreListDocuments(ctx, &FirestoreListDocumentsRequest{
		Collection: "user_roles",
		Filters: []FirestoreFilter{
			{Field: "user_id", Operator: "==", Value: userID},
		},
		Limit: 1,
	})
	if err == nil && len(rolesDoc.Documents) > 0 {
		roleData := rolesDoc.Documents[0]
		profile.Role = getStringFromMap(roleData, "role")
		if perms, ok := roleData["permissions"].([]interface{}); ok {
			profile.Permissions = make([]string, len(perms))
			for i, perm := range perms {
				if str, ok := perm.(string); ok {
					profile.Permissions[i] = str
				}
			}
		}
		if claims, ok := roleData["custom_claims"].(map[string]interface{}); ok {
			profile.CustomClaims = claims
		}
	}

	return profile, nil
}

// UpdateUserProfile updates a user profile
func (s *ProfileService) UpdateUserProfile(ctx context.Context, userID string, updates map[string]interface{}) (*UserProfile, error) {
	s.logger.Info("Updating user profile", map[string]interface{}{
		"user_id": userID,
		"updates": len(updates),
	})

	// Add update timestamp
	updates["updated_at"] = time.Now().Unix()

	// Update user document
	_, err := s.mcpIntegration.callFirestoreUpdateDocument(ctx, "users", userID, updates)
	if err != nil {
		return nil, fmt.Errorf("failed to update user profile: %w", err)
	}

	// Get updated profile
	return s.GetUserProfile(ctx, userID)
}

// SyncGoogleProfile syncs user profile with Google profile information
func (s *ProfileService) SyncGoogleProfile(ctx context.Context, userID string, googleUserInfo map[string]interface{}) error {
	s.logger.Info("Syncing Google profile", map[string]interface{}{
		"user_id": userID,
	})

	updates := map[string]interface{}{
		"google_profile.given_name":   getStringValue(googleUserInfo, "given_name"),
		"google_profile.family_name":  getStringValue(googleUserInfo, "family_name"),
		"google_profile.locale":       getStringValue(googleUserInfo, "locale"),
		"google_profile.picture_url":  getStringValue(googleUserInfo, "picture"),
		"google_profile.last_sync_at": time.Now().Unix(),
		"display_name":                getStringValue(googleUserInfo, "name"),
		"photo_url":                   getStringValue(googleUserInfo, "picture"),
		"updated_at":                  time.Now().Unix(),
	}

	_, err := s.UpdateUserProfile(ctx, userID, updates)
	return err
}

// UpdateUserRole updates a user's role and permissions
func (s *ProfileService) UpdateUserRole(ctx context.Context, userID, role string, permissions []string, customClaims map[string]interface{}) error {
	s.logger.Info("Updating user role", map[string]interface{}{
		"user_id":     userID,
		"role":        role,
		"permissions": permissions,
	})

	// Update user roles document
	rolesData := map[string]interface{}{
		"role":          role,
		"permissions":   permissions,
		"custom_claims": customClaims,
		"updated_at":    time.Now().Unix(),
	}

	_, err := s.mcpIntegration.callFirestoreUpdateDocument(ctx, "user_roles", userID, rolesData)
	if err != nil {
		return fmt.Errorf("failed to update user role: %w", err)
	}

	// Update user profile with role
	profileUpdates := map[string]interface{}{
		"role":          role,
		"permissions":   permissions,
		"custom_claims": customClaims,
		"updated_at":    time.Now().Unix(),
	}

	_, err = s.UpdateUserProfile(ctx, userID, profileUpdates)
	return err
}

// UpdateUserSettings updates user settings and preferences
func (s *ProfileService) UpdateUserSettings(ctx context.Context, userID string, settings *ProfileSettings) error {
	s.logger.Info("Updating user settings", map[string]interface{}{
		"user_id": userID,
	})

	// Update preferences document
	preferencesData := map[string]interface{}{
		"settings":   s.settingsToMap(settings),
		"updated_at": time.Now().Unix(),
	}

	_, err := s.mcpIntegration.callFirestoreUpdateDocument(ctx, "user_preferences", userID, preferencesData)
	if err != nil {
		return fmt.Errorf("failed to update user settings: %w", err)
	}

	// Update profile with settings
	profileUpdates := map[string]interface{}{
		"settings":   s.settingsToMap(settings),
		"updated_at": time.Now().Unix(),
	}

	_, err = s.UpdateUserProfile(ctx, userID, profileUpdates)
	return err
}

// ActivateUser activates a user account
func (s *ProfileService) ActivateUser(ctx context.Context, userID string) error {
	s.logger.Info("Activating user", map[string]interface{}{
		"user_id": userID,
	})

	updates := map[string]interface{}{
		"active":     true,
		"suspended":  false,
		"updated_at": time.Now().Unix(),
	}

	_, err := s.UpdateUserProfile(ctx, userID, updates)
	return err
}

// SuspendUser suspends a user account
func (s *ProfileService) SuspendUser(ctx context.Context, userID string, reason string) error {
	s.logger.Info("Suspending user", map[string]interface{}{
		"user_id": userID,
		"reason":  reason,
	})

	updates := map[string]interface{}{
		"active":            false,
		"suspended":         true,
		"suspension_reason": reason,
		"suspended_at":      time.Now().Unix(),
		"updated_at":        time.Now().Unix(),
	}

	_, err := s.UpdateUserProfile(ctx, userID, updates)
	return err
}

// DeleteUserProfile deletes a user profile (soft delete)
func (s *ProfileService) DeleteUserProfile(ctx context.Context, userID string) error {
	s.logger.Info("Deleting user profile", map[string]interface{}{
		"user_id": userID,
	})

	updates := map[string]interface{}{
		"active":     false,
		"deleted":    true,
		"deleted_at": time.Now().Unix(),
		"updated_at": time.Now().Unix(),
	}

	_, err := s.UpdateUserProfile(ctx, userID, updates)
	return err
}

// Helper methods for data conversion

func (s *ProfileService) profileToMap(profile *UserProfile) map[string]interface{} {
	data := map[string]interface{}{
		"uid":            profile.UID,
		"email":          profile.Email,
		"display_name":   profile.DisplayName,
		"photo_url":      profile.PhotoURL,
		"email_verified": profile.EmailVerified,
		"phone_number":   profile.PhoneNumber,
		"created_at":     profile.CreatedAt.Unix(),
		"updated_at":     profile.UpdatedAt.Unix(),
		"last_login_at":  profile.LastLoginAt.Unix(),
		"role":           profile.Role,
		"permissions":    profile.Permissions,
		"custom_claims":  profile.CustomClaims,
		"active":         profile.Active,
		"suspended":      profile.Suspended,
		"verified":       profile.Verified,
	}

	if profile.GoogleProfile != nil {
		data["google_profile"] = map[string]interface{}{
			"google_id":     profile.GoogleProfile.GoogleID,
			"given_name":    profile.GoogleProfile.GivenName,
			"family_name":   profile.GoogleProfile.FamilyName,
			"locale":        profile.GoogleProfile.Locale,
			"hosted_domain": profile.GoogleProfile.HostedDomain,
			"picture_url":   profile.GoogleProfile.PictureURL,
			"last_sync_at":  profile.GoogleProfile.LastSyncAt.Unix(),
			"sync_enabled":  profile.GoogleProfile.SyncEnabled,
		}
	}

	if profile.Settings != nil {
		data["settings"] = s.settingsToMap(profile.Settings)
	}

	if profile.Metadata != nil {
		data["metadata"] = map[string]interface{}{
			"login_count":     profile.Metadata.LoginCount,
			"last_ip_address": profile.Metadata.LastIPAddress,
			"last_user_agent": profile.Metadata.LastUserAgent,
			"registration_ip": profile.Metadata.RegistrationIP,
			"registration_ua": profile.Metadata.RegistrationUA,
			"account_source":  profile.Metadata.AccountSource,
			"referral_code":   profile.Metadata.ReferralCode,
			"tags":            profile.Metadata.Tags,
		}
	}

	return data
}

func (s *ProfileService) mapToProfile(data map[string]interface{}) *UserProfile {
	profile := &UserProfile{
		UID:           getStringFromMap(data, "uid"),
		Email:         getStringFromMap(data, "email"),
		DisplayName:   getStringFromMap(data, "display_name"),
		PhotoURL:      getStringFromMap(data, "photo_url"),
		EmailVerified: getBoolFromMap(data, "email_verified"),
		PhoneNumber:   getStringFromMap(data, "phone_number"),
		CreatedAt:     time.Unix(getInt64FromMap(data, "created_at"), 0),
		UpdatedAt:     time.Unix(getInt64FromMap(data, "updated_at"), 0),
		LastLoginAt:   time.Unix(getInt64FromMap(data, "last_login_at"), 0),
		Role:          getStringFromMap(data, "role"),
		Active:        getBoolFromMap(data, "active"),
		Suspended:     getBoolFromMap(data, "suspended"),
		Verified:      getBoolFromMap(data, "verified"),
	}

	// Parse Google profile
	if googleData, ok := data["google_profile"].(map[string]interface{}); ok {
		profile.GoogleProfile = &GoogleProfileInfo{
			GoogleID:     getStringFromMap(googleData, "google_id"),
			GivenName:    getStringFromMap(googleData, "given_name"),
			FamilyName:   getStringFromMap(googleData, "family_name"),
			Locale:       getStringFromMap(googleData, "locale"),
			HostedDomain: getStringFromMap(googleData, "hosted_domain"),
			PictureURL:   getStringFromMap(googleData, "picture_url"),
			LastSyncAt:   time.Unix(getInt64FromMap(googleData, "last_sync_at"), 0),
			SyncEnabled:  getBoolFromMap(googleData, "sync_enabled"),
		}
	}

	// Parse settings
	if settingsData, ok := data["settings"].(map[string]interface{}); ok {
		profile.Settings = s.mapToSettings(settingsData)
	}

	// Parse metadata
	if metadataData, ok := data["metadata"].(map[string]interface{}); ok {
		profile.Metadata = &ProfileMetadata{
			LoginCount:     int(getInt64FromMap(metadataData, "login_count")),
			LastIPAddress:  getStringFromMap(metadataData, "last_ip_address"),
			LastUserAgent:  getStringFromMap(metadataData, "last_user_agent"),
			RegistrationIP: getStringFromMap(metadataData, "registration_ip"),
			RegistrationUA: getStringFromMap(metadataData, "registration_ua"),
			AccountSource:  getStringFromMap(metadataData, "account_source"),
			ReferralCode:   getStringFromMap(metadataData, "referral_code"),
		}

		if tags, ok := metadataData["tags"].([]interface{}); ok {
			profile.Metadata.Tags = make([]string, len(tags))
			for i, tag := range tags {
				if str, ok := tag.(string); ok {
					profile.Metadata.Tags[i] = str
				}
			}
		}
	}

	return profile
}

func (s *ProfileService) settingsToMap(settings *ProfileSettings) map[string]interface{} {
	return map[string]interface{}{
		"theme":                 settings.Theme,
		"language":              settings.Language,
		"timezone":              settings.Timezone,
		"notifications_enabled": settings.NotificationsEnabled,
		"email_updates":         settings.EmailUpdates,
		"privacy_level":         settings.PrivacyLevel,
		"two_factor_enabled":    settings.TwoFactorEnabled,
		"profile_visibility":    settings.ProfileVisibility,
	}
}

func (s *ProfileService) mapToSettings(data map[string]interface{}) *ProfileSettings {
	return &ProfileSettings{
		Theme:                getStringFromMap(data, "theme"),
		Language:             getStringFromMap(data, "language"),
		Timezone:             getStringFromMap(data, "timezone"),
		NotificationsEnabled: getBoolFromMap(data, "notifications_enabled"),
		EmailUpdates:         getBoolFromMap(data, "email_updates"),
		PrivacyLevel:         getStringFromMap(data, "privacy_level"),
		TwoFactorEnabled:     getBoolFromMap(data, "two_factor_enabled"),
		ProfileVisibility:    getStringFromMap(data, "profile_visibility"),
	}
}
