package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dimajoyti/hackai/internal/domain"
	"github.com/dimajoyti/hackai/pkg/logger"
)

var oauth2Tracer = otel.Tracer("hackai/auth/oauth2")

// OAuth2Provider represents an OAuth2 provider configuration
type OAuth2Provider struct {
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	AuthURL      string `json:"auth_url"`
	TokenURL     string `json:"token_url"`
	UserInfoURL  string `json:"user_info_url"`
	Scopes       []string `json:"scopes"`
	RedirectURL  string `json:"redirect_url"`
}

// OAuth2Config represents OAuth2 configuration
type OAuth2Config struct {
	Providers       map[string]*OAuth2Provider `json:"providers"`
	StateExpiration time.Duration              `json:"state_expiration"`
	CodeExpiration  time.Duration              `json:"code_expiration"`
}

// OAuth2Manager handles OAuth2 operations
type OAuth2Manager struct {
	config   *OAuth2Config
	logger   *logger.Logger
	stateStore map[string]*OAuth2State // In production, use Redis or database
}

// OAuth2State represents OAuth2 state information
type OAuth2State struct {
	State       string    `json:"state"`
	Provider    string    `json:"provider"`
	RedirectURL string    `json:"redirect_url"`
	UserID      uuid.UUID `json:"user_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// OAuth2AuthorizationRequest represents an OAuth2 authorization request
type OAuth2AuthorizationRequest struct {
	Provider    string `json:"provider"`
	RedirectURL string `json:"redirect_url,omitempty"`
	State       string `json:"state,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

// OAuth2AuthorizationResponse represents an OAuth2 authorization response
type OAuth2AuthorizationResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	State           string `json:"state"`
	Provider        string `json:"provider"`
}

// OAuth2TokenRequest represents an OAuth2 token exchange request
type OAuth2TokenRequest struct {
	Provider string `json:"provider"`
	Code     string `json:"code"`
	State    string `json:"state"`
}

// OAuth2TokenResponse represents an OAuth2 token response
type OAuth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OAuth2UserInfo represents user information from OAuth2 provider
type OAuth2UserInfo struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Username string `json:"username,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Provider string `json:"provider"`
}

// OAuth2AuthenticationResult represents the result of OAuth2 authentication
type OAuth2AuthenticationResult struct {
	User        *domain.User `json:"user"`
	TokenPair   *TokenPair   `json:"token_pair"`
	UserInfo    *OAuth2UserInfo `json:"user_info"`
	IsNewUser   bool         `json:"is_new_user"`
}

// NewOAuth2Manager creates a new OAuth2 manager
func NewOAuth2Manager(config *OAuth2Config, logger *logger.Logger) *OAuth2Manager {
	if config.StateExpiration == 0 {
		config.StateExpiration = 10 * time.Minute
	}
	if config.CodeExpiration == 0 {
		config.CodeExpiration = 10 * time.Minute
	}

	return &OAuth2Manager{
		config:     config,
		logger:     logger,
		stateStore: make(map[string]*OAuth2State),
	}
}

// GetAuthorizationURL generates an OAuth2 authorization URL
func (om *OAuth2Manager) GetAuthorizationURL(ctx context.Context, req *OAuth2AuthorizationRequest) (*OAuth2AuthorizationResponse, error) {
	ctx, span := oauth2Tracer.Start(ctx, "oauth2.get_authorization_url",
		trace.WithAttributes(attribute.String("provider", req.Provider)))
	defer span.End()

	provider, exists := om.config.Providers[req.Provider]
	if !exists {
		return nil, fmt.Errorf("unknown OAuth2 provider: %s", req.Provider)
	}

	// Generate state parameter
	state, err := om.generateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Store state information
	stateInfo := &OAuth2State{
		State:       state,
		Provider:    req.Provider,
		RedirectURL: req.RedirectURL,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(om.config.StateExpiration),
	}
	om.stateStore[state] = stateInfo

	// Build authorization URL
	authURL, err := url.Parse(provider.AuthURL)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization URL: %w", err)
	}

	params := url.Values{}
	params.Set("client_id", provider.ClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", provider.RedirectURL)
	params.Set("state", state)
	
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = provider.Scopes
	}
	if len(scopes) > 0 {
		params.Set("scope", strings.Join(scopes, " "))
	}

	authURL.RawQuery = params.Encode()

	om.logger.Info("Generated OAuth2 authorization URL",
		"provider", req.Provider,
		"state", state)

	return &OAuth2AuthorizationResponse{
		AuthorizationURL: authURL.String(),
		State:           state,
		Provider:        req.Provider,
	}, nil
}

// ExchangeCodeForToken exchanges authorization code for access token
func (om *OAuth2Manager) ExchangeCodeForToken(ctx context.Context, req *OAuth2TokenRequest) (*OAuth2TokenResponse, error) {
	ctx, span := oauth2Tracer.Start(ctx, "oauth2.exchange_code_for_token",
		trace.WithAttributes(
			attribute.String("provider", req.Provider),
			attribute.String("state", req.State)))
	defer span.End()

	// Validate state
	stateInfo, exists := om.stateStore[req.State]
	if !exists {
		return nil, fmt.Errorf("invalid or expired state")
	}

	if time.Now().After(stateInfo.ExpiresAt) {
		delete(om.stateStore, req.State)
		return nil, fmt.Errorf("state expired")
	}

	if stateInfo.Provider != req.Provider {
		return nil, fmt.Errorf("provider mismatch")
	}

	provider, exists := om.config.Providers[req.Provider]
	if !exists {
		return nil, fmt.Errorf("unknown OAuth2 provider: %s", req.Provider)
	}

	// Exchange code for token
	tokenResp, err := om.exchangeCode(ctx, provider, req.Code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Clean up state
	delete(om.stateStore, req.State)

	om.logger.Info("Successfully exchanged OAuth2 code for token",
		"provider", req.Provider,
		"token_type", tokenResp.TokenType)

	return tokenResp, nil
}

// GetUserInfo retrieves user information using access token
func (om *OAuth2Manager) GetUserInfo(ctx context.Context, provider string, accessToken string) (*OAuth2UserInfo, error) {
	ctx, span := oauth2Tracer.Start(ctx, "oauth2.get_user_info",
		trace.WithAttributes(attribute.String("provider", provider)))
	defer span.End()

	providerConfig, exists := om.config.Providers[provider]
	if !exists {
		return nil, fmt.Errorf("unknown OAuth2 provider: %s", provider)
	}

	// Make request to user info endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", providerConfig.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info request failed: %s", string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse user info based on provider
	userInfo, err := om.parseUserInfo(provider, body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	userInfo.Provider = provider

	om.logger.Info("Retrieved OAuth2 user info",
		"provider", provider,
		"user_id", userInfo.ID,
		"email", userInfo.Email)

	return userInfo, nil
}

// ValidateState validates OAuth2 state parameter
func (om *OAuth2Manager) ValidateState(state string) (*OAuth2State, error) {
	stateInfo, exists := om.stateStore[state]
	if !exists {
		return nil, fmt.Errorf("invalid state")
	}

	if time.Now().After(stateInfo.ExpiresAt) {
		delete(om.stateStore, state)
		return nil, fmt.Errorf("state expired")
	}

	return stateInfo, nil
}

// generateState generates a cryptographically secure state parameter
func (om *OAuth2Manager) generateState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// exchangeCode exchanges authorization code for access token
func (om *OAuth2Manager) exchangeCode(ctx context.Context, provider *OAuth2Provider, code string) (*OAuth2TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", provider.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", provider.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp OAuth2TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// parseUserInfo parses user information based on provider
func (om *OAuth2Manager) parseUserInfo(provider string, data []byte) (*OAuth2UserInfo, error) {
	var userInfo OAuth2UserInfo

	switch provider {
	case "google":
		var googleUser struct {
			ID      string `json:"sub"`
			Email   string `json:"email"`
			Name    string `json:"name"`
			Picture string `json:"picture"`
		}
		if err := json.Unmarshal(data, &googleUser); err != nil {
			return nil, err
		}
		userInfo = OAuth2UserInfo{
			ID:      googleUser.ID,
			Email:   googleUser.Email,
			Name:    googleUser.Name,
			Picture: googleUser.Picture,
		}

	case "github":
		var githubUser struct {
			ID       int    `json:"id"`
			Login    string `json:"login"`
			Email    string `json:"email"`
			Name     string `json:"name"`
			AvatarURL string `json:"avatar_url"`
		}
		if err := json.Unmarshal(data, &githubUser); err != nil {
			return nil, err
		}
		userInfo = OAuth2UserInfo{
			ID:       fmt.Sprintf("%d", githubUser.ID),
			Email:    githubUser.Email,
			Name:     githubUser.Name,
			Username: githubUser.Login,
			Picture:  githubUser.AvatarURL,
		}

	case "microsoft":
		var msUser struct {
			ID                string `json:"id"`
			UserPrincipalName string `json:"userPrincipalName"`
			DisplayName       string `json:"displayName"`
			Mail              string `json:"mail"`
		}
		if err := json.Unmarshal(data, &msUser); err != nil {
			return nil, err
		}
		email := msUser.Mail
		if email == "" {
			email = msUser.UserPrincipalName
		}
		userInfo = OAuth2UserInfo{
			ID:    msUser.ID,
			Email: email,
			Name:  msUser.DisplayName,
		}

	default:
		// Generic parsing
		if err := json.Unmarshal(data, &userInfo); err != nil {
			return nil, err
		}
	}

	return &userInfo, nil
}

// CleanupExpiredStates removes expired state entries
func (om *OAuth2Manager) CleanupExpiredStates() {
	now := time.Now()
	for state, stateInfo := range om.stateStore {
		if now.After(stateInfo.ExpiresAt) {
			delete(om.stateStore, state)
		}
	}
}
