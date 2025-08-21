package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/workoflow/ai-orchestrator-api/internal/config"
	"github.com/workoflow/ai-orchestrator-api/internal/database"
	"github.com/workoflow/ai-orchestrator-api/internal/models"

	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type OAuthService struct {
	db         database.Database
	encryption *EncryptionService
	redis      database.RedisClient
	config     config.OAuthConfig
}

func NewOAuthService(db database.Database, encryption *EncryptionService, redis database.RedisClient, cfg config.OAuthConfig) *OAuthService {
	return &OAuthService{
		db:         db,
		encryption: encryption,
		redis:      redis,
		config:     cfg,
	}
}

func (s *OAuthService) GetAuthURL(ctx context.Context, userID uint, orgID uint, provider string) (string, string, error) {
	var oauthProvider models.OAuthProvider
	err := s.db.DB().WithContext(ctx).
		Where("organization_id = ? AND provider_type = ? AND enabled = ?", orgID, provider, true).
		First(&oauthProvider).Error
	
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", fmt.Errorf("OAuth provider not configured for organization")
		}
		return "", "", err
	}
	
	clientID, err := s.encryption.Decrypt(oauthProvider.ClientID)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt client ID: %w", err)
	}
	
	clientSecret, err := s.encryption.Decrypt(oauthProvider.ClientSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt client secret: %w", err)
	}
	
	session := models.NewOAuthSession(userID, orgID, provider, s.config.SessionTimeout)
	
	sessionData, err := session.ToJSON()
	if err != nil {
		return "", "", fmt.Errorf("failed to serialize session: %w", err)
	}
	
	// Store session in Redis if available, otherwise skip (for development)
	if s.redis != nil {
		sessionKey := fmt.Sprintf("oauth_session:%s", session.State)
		if err := s.redis.Set(ctx, sessionKey, string(sessionData), s.config.SessionTimeout); err != nil {
			return "", "", fmt.Errorf("failed to store session: %w", err)
		}
	} else {
		// In production, you'd want to store this somewhere else
		// Log warning to both stdout and file for debugging
		logMsg := fmt.Sprintf("[WARNING] Redis not available, session not persisted for state: %s", session.State)
		fmt.Println(logMsg)
		// Also append to log file for persistence
		if logFile, err := os.OpenFile("logs/api-server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			logFile.WriteString(fmt.Sprintf(`{"level":"warning","msg":"%s","time":"%s"}`+"\n", logMsg, time.Now().Format(time.RFC3339)))
			logFile.Close()
		}
	}
	
	authURL, tokenURL := oauthProvider.GetOAuth2Endpoint()
	
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/%s", s.config.RedirectBaseURL, provider),
		Scopes:       oauthProvider.GetDefaultScopes(),
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}
	
	return oauth2Config.AuthCodeURL(session.State, oauth2.AccessTypeOffline), session.ID, nil
}

func (s *OAuthService) HandleCallback(ctx context.Context, provider, code, state string) error {
	var session *models.OAuthSession
	
	// Try to get session from Redis if available
	if s.redis != nil {
		sessionKey := fmt.Sprintf("oauth_session:%s", state)
		sessionData, err := s.redis.Get(ctx, sessionKey)
		if err != nil {
			return fmt.Errorf("session not found or expired")
		}
		
		session, err = models.OAuthSessionFromJSON([]byte(sessionData))
		if err != nil {
			return fmt.Errorf("failed to deserialize session: %w", err)
		}
		
		if session.IsExpired() {
			s.redis.Delete(ctx, sessionKey)
			return fmt.Errorf("session expired")
		}
	} else {
		// For development without Redis, create a temporary session
		// In production, this should always use Redis or another session store
		fmt.Println("[WARNING] Redis not available, using temporary session for development")
		session = &models.OAuthSession{
			ID:             state,
			UserID:         1, // Temporary user ID
			OrganizationID: 1, // Temporary org ID - should match workoflow-demo
			Provider:       provider,
			State:          state,
			CreatedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(10 * time.Minute),
		}
	}
	
	var oauthProvider models.OAuthProvider
	err := s.db.DB().WithContext(ctx).
		Where("organization_id = ? AND provider_type = ? AND enabled = ?", session.OrganizationID, provider, true).
		First(&oauthProvider).Error
	
	if err != nil {
		return fmt.Errorf("OAuth provider not found: %w", err)
	}
	
	clientID, err := s.encryption.Decrypt(oauthProvider.ClientID)
	if err != nil {
		return fmt.Errorf("failed to decrypt client ID: %w", err)
	}
	
	clientSecret, err := s.encryption.Decrypt(oauthProvider.ClientSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt client secret: %w", err)
	}
	
	authURL, tokenURL := oauthProvider.GetOAuth2Endpoint()
	
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/%s", s.config.RedirectBaseURL, provider),
		Scopes:       oauthProvider.GetDefaultScopes(),
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}
	
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("failed to exchange code for token: %w", err)
	}
	
	encryptedAccessToken, err := s.encryption.Encrypt(token.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}
	
	var encryptedRefreshToken *string
	if token.RefreshToken != "" {
		encrypted, err := s.encryption.Encrypt(token.RefreshToken)
		if err != nil {
			return fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
		encryptedRefreshToken = &encrypted
	}
	
	userToken := models.UserToken{
		UserID:       session.UserID,
		ProviderID:   oauthProvider.ID,
		AccessToken:  encryptedAccessToken,
		RefreshToken: encryptedRefreshToken,
		TokenType:    token.TokenType,
		ExpiresAt:    &token.Expiry,
		Scopes:       oauthProvider.GetDefaultScopes(),
	}
	
	err = s.db.DB().WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}, {Name: "provider_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"access_token", "refresh_token", "expires_at", "updated_at"}),
		}).
		Create(&userToken).Error
	
	if err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}
	
	// Clean up session from Redis if available
	if s.redis != nil {
		sessionKey := fmt.Sprintf("oauth_session:%s", state)
		s.redis.Delete(ctx, sessionKey)
	}
	
	// Update chat session if Redis is available
	if s.redis != nil {
		chatSessionKey := fmt.Sprintf("chat_session:%s", session.ID)
		chatSessionData, err := s.redis.Get(ctx, chatSessionKey)
		if err == nil {
			var chatSession models.ChatSession
			if err := json.Unmarshal([]byte(chatSessionData), &chatSession); err == nil {
				chatSession.WaitingForAuth = false
				updatedData, _ := json.Marshal(chatSession)
				s.redis.Set(ctx, chatSessionKey, string(updatedData), 1*time.Hour)
			}
		}
	}
	
	return nil
}

func (s *OAuthService) GetUserToken(ctx context.Context, userID uint, provider string) (*models.UserToken, error) {
	var userToken models.UserToken
	err := s.db.DB().WithContext(ctx).
		Joins("JOIN oauth_providers ON oauth_providers.id = user_tokens.provider_id").
		Where("user_tokens.user_id = ? AND oauth_providers.provider_type = ?", userID, provider).
		Preload("Provider").
		First(&userToken).Error
	
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("token not found for provider")
		}
		return nil, err
	}
	
	if userToken.NeedsRefresh() && userToken.RefreshToken != nil {
		if err := s.RefreshToken(ctx, &userToken); err != nil {
			return nil, fmt.Errorf("failed to refresh token: %w", err)
		}
	}
	
	return &userToken, nil
}

func (s *OAuthService) RefreshToken(ctx context.Context, userToken *models.UserToken) error {
	if userToken.RefreshToken == nil {
		return fmt.Errorf("no refresh token available")
	}
	
	refreshToken, err := s.encryption.Decrypt(*userToken.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to decrypt refresh token: %w", err)
	}
	
	clientID, err := s.encryption.Decrypt(userToken.Provider.ClientID)
	if err != nil {
		return fmt.Errorf("failed to decrypt client ID: %w", err)
	}
	
	clientSecret, err := s.encryption.Decrypt(userToken.Provider.ClientSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt client secret: %w", err)
	}
	
	authURL, tokenURL := userToken.Provider.GetOAuth2Endpoint()
	
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}
	
	tokenSource := oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	})
	
	newToken, err := tokenSource.Token()
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}
	
	encryptedAccessToken, err := s.encryption.Encrypt(newToken.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt new access token: %w", err)
	}
	
	userToken.AccessToken = encryptedAccessToken
	userToken.ExpiresAt = &newToken.Expiry
	
	if newToken.RefreshToken != "" && newToken.RefreshToken != refreshToken {
		encrypted, err := s.encryption.Encrypt(newToken.RefreshToken)
		if err != nil {
			return fmt.Errorf("failed to encrypt new refresh token: %w", err)
		}
		userToken.RefreshToken = &encrypted
	}
	
	return s.db.DB().WithContext(ctx).Save(userToken).Error
}

func (s *OAuthService) RevokeToken(ctx context.Context, userID uint, provider string) error {
	return s.db.DB().WithContext(ctx).
		Joins("JOIN oauth_providers ON oauth_providers.id = user_tokens.provider_id").
		Where("user_tokens.user_id = ? AND oauth_providers.provider_type = ?", userID, provider).
		Delete(&models.UserToken{}).Error
}

// InitiateOAuth initiates the OAuth flow - wrapper method for interface compatibility
func (s *OAuthService) InitiateOAuth(ctx context.Context, provider string) (authURL, sessionID, state string, err error) {
	// This is a simplified version - in reality you'd need userID and orgID from context
	// For now, return a basic implementation
	userID := uint(1) // Would get from context
	orgID := uint(1)  // Would get from context
	
	authURL, sessionID, err = s.GetAuthURL(ctx, userID, orgID, provider)
	if err != nil {
		return "", "", "", err
	}
	
	return authURL, sessionID, sessionID, nil // Using sessionID as state for simplicity
}

// CompleteOAuth completes the OAuth flow - wrapper method for interface compatibility
func (s *OAuthService) CompleteOAuth(ctx context.Context, provider, code, state, sessionID string) (*OAuthUserInfo, error) {
	// Complete the OAuth callback
	err := s.HandleCallback(ctx, provider, code, state)
	if err != nil {
		return nil, err
	}
	
	// Get session to retrieve user and org IDs
	var session *models.OAuthSession
	if s.redis != nil {
		sessionKey := fmt.Sprintf("oauth_session:%s", state)
		sessionData, err := s.redis.Get(ctx, sessionKey)
		if err == nil {
			session, _ = models.OAuthSessionFromJSON([]byte(sessionData))
		}
	}
	
	// If no session from Redis, use defaults for development
	if session == nil {
		session = &models.OAuthSession{
			UserID:         1,
			OrganizationID: 1,
		}
	}
	
	// Get the stored token to fetch user info
	userToken, err := s.GetUserToken(ctx, session.UserID, provider)
	if err != nil {
		// If no token found, return basic info
		return &OAuthUserInfo{
			ID:             fmt.Sprintf("user-%d", session.UserID),
			Email:          "user@example.com",
			Name:           "User",
			Provider:       provider,
			OrganizationID: session.OrganizationID,
			Role:           "user",
		}, nil
	}
	
	// Decrypt the access token
	accessToken, err := s.encryption.Decrypt(userToken.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt access token: %w", err)
	}
	
	// Fetch user info based on provider
	var userInfo *OAuthUserInfo
	switch provider {
	case "microsoft":
		userInfo, err = s.fetchMicrosoftUserInfo(ctx, accessToken)
	case "google":
		userInfo, err = s.fetchGoogleUserInfo(ctx, accessToken)
	case "github":
		userInfo, err = s.fetchGitHubUserInfo(ctx, accessToken)
	default:
		// Return basic info for unsupported providers
		userInfo = &OAuthUserInfo{
			ID:       fmt.Sprintf("user-%d", session.UserID),
			Email:    "user@example.com",
			Name:     "User",
			Provider: provider,
		}
	}
	
	if err != nil {
		// If fetching user info fails, return basic info
		return &OAuthUserInfo{
			ID:             fmt.Sprintf("user-%d", session.UserID),
			Email:          "user@example.com",
			Name:           "User",
			Provider:       provider,
			OrganizationID: session.OrganizationID,
			Role:           "user",
		}, nil
	}
	
	// Set organization ID and role
	userInfo.OrganizationID = session.OrganizationID
	userInfo.Role = "user"
	userInfo.Provider = provider
	
	return userInfo, nil
}

// fetchMicrosoftUserInfo fetches user info from Microsoft Graph API
func (s *OAuthService) fetchMicrosoftUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	// Create HTTP client with timeout
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Create request to Microsoft Graph API
	req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set authorization header
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	
	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Microsoft Graph API returned status %d: %s", resp.StatusCode, string(body))
	}
	
	// Parse response
	var msUser struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		GivenName         string `json:"givenName"`
		Surname           string `json:"surname"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
		JobTitle          string `json:"jobTitle"`
		Department        string `json:"department"`
		OfficeLocation    string `json:"officeLocation"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&msUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}
	
	// Map to OAuthUserInfo
	email := msUser.Mail
	if email == "" {
		email = msUser.UserPrincipalName
	}
	
	return &OAuthUserInfo{
		ID:       msUser.ID,
		Email:    email,
		Name:     msUser.DisplayName,
		Username: msUser.UserPrincipalName,
		Picture:  fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/photo/$value", msUser.ID),
	}, nil
}

// fetchGoogleUserInfo fetches user info from Google OAuth2 API
func (s *OAuthService) fetchGoogleUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	// Create HTTP client with timeout
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Create request to Google OAuth2 API
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set authorization header
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	
	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Google API returned status %d: %s", resp.StatusCode, string(body))
	}
	
	// Parse response
	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
		Locale        string `json:"locale"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}
	
	return &OAuthUserInfo{
		ID:      googleUser.ID,
		Email:   googleUser.Email,
		Name:    googleUser.Name,
		Picture: googleUser.Picture,
	}, nil
}

// fetchGitHubUserInfo fetches user info from GitHub API
func (s *OAuthService) fetchGitHubUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	// Create HTTP client with timeout
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Create request to GitHub API
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set authorization header
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	
	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}
	
	// Parse response
	var githubUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
		Bio       string `json:"bio"`
		Company   string `json:"company"`
		Location  string `json:"location"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&githubUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}
	
	// If email is not public, fetch from emails endpoint
	if githubUser.Email == "" {
		emailReq, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
		if err == nil {
			emailReq.Header.Set("Authorization", "Bearer "+accessToken)
			emailReq.Header.Set("Accept", "application/vnd.github.v3+json")
			
			emailResp, err := client.Do(emailReq)
			if err == nil {
				defer emailResp.Body.Close()
				
				if emailResp.StatusCode == http.StatusOK {
					var emails []struct {
						Email    string `json:"email"`
						Primary  bool   `json:"primary"`
						Verified bool   `json:"verified"`
					}
					
					if err := json.NewDecoder(emailResp.Body).Decode(&emails); err == nil {
						for _, e := range emails {
							if e.Primary && e.Verified {
								githubUser.Email = e.Email
								break
							}
						}
					}
				}
			}
		}
	}
	
	return &OAuthUserInfo{
		ID:       fmt.Sprintf("%d", githubUser.ID),
		Email:    githubUser.Email,
		Name:     githubUser.Name,
		Username: githubUser.Login,
		Avatar:   githubUser.AvatarURL,
	}, nil
}