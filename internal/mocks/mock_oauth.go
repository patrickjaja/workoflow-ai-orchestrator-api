package mocks

import (
	"errors"
	"fmt"
	"time"

	"github.com/workoflow/ai-orchestrator-api/internal/services"
)

// MockOAuthService implements OAuthServiceInterface for testing
type MockOAuthService struct {
	// Configuration for mock responses
	ShouldError         bool
	ErrorMessage        string
	MockAccessToken     string
	MockRefreshToken    string
	MockUserInfo        *services.OAuthUserInfo
	
	// Call tracking
	GetAuthURLCalls     []GetAuthURLCall
	ExchangeCodeCalls   []ExchangeCodeCall
	RefreshTokenCalls   []RefreshTokenCall
	GetUserInfoCalls    []GetUserInfoCall
	ValidateProviderCalls []ValidateProviderCall
	TotalCalls          int
}

type GetAuthURLCall struct {
	Provider       string
	State          string
	OrganizationID uint
	Timestamp      time.Time
}

type ExchangeCodeCall struct {
	Provider  string
	Code      string
	State     string
	Timestamp time.Time
}

type RefreshTokenCall struct {
	Provider     string
	RefreshToken string
	Timestamp    time.Time
}

type GetUserInfoCall struct {
	Provider    string
	AccessToken string
	Timestamp   time.Time
}

type ValidateProviderCall struct {
	Provider  string
	Timestamp time.Time
}

// NewMockOAuthService creates a new mock OAuth service
func NewMockOAuthService() *MockOAuthService {
	return &MockOAuthService{
		MockAccessToken:  "mock_access_token_12345",
		MockRefreshToken: "mock_refresh_token_67890",
		MockUserInfo: &services.OAuthUserInfo{
			ID:       "mock_user_123",
			Email:    "test@example.com",
			Name:     "Test User",
			Picture:  "https://example.com/avatar.jpg",
			Provider: "google",
		},
	}
}

// GetAuthURL mocks OAuth authorization URL generation
func (m *MockOAuthService) GetAuthURL(provider string, state string, organizationID uint) (string, error) {
	m.GetAuthURLCalls = append(m.GetAuthURLCalls, GetAuthURLCall{
		Provider:       provider,
		State:          state,
		OrganizationID: organizationID,
		Timestamp:      time.Now(),
	})
	m.TotalCalls++
	
	if m.ShouldError {
		return "", errors.New(m.ErrorMessage)
	}
	
	// Generate mock auth URL based on provider
	var authURL string
	switch provider {
	case "google":
		authURL = fmt.Sprintf("https://accounts.google.com/oauth/authorize?client_id=mock_client_id&redirect_uri=mock_redirect_uri&scope=email+profile&response_type=code&state=%s", state)
	case "github":
		authURL = fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=mock_client_id&redirect_uri=mock_redirect_uri&scope=user:email&state=%s", state)
	case "microsoft":
		authURL = fmt.Sprintf("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=mock_client_id&redirect_uri=mock_redirect_uri&scope=openid+email+profile&response_type=code&state=%s", state)
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
	
	return authURL, nil
}

// ExchangeCode mocks OAuth code exchange
func (m *MockOAuthService) ExchangeCode(provider string, code string, state string) (*services.OAuthTokenResponse, error) {
	m.ExchangeCodeCalls = append(m.ExchangeCodeCalls, ExchangeCodeCall{
		Provider:  provider,
		Code:      code,
		State:     state,
		Timestamp: time.Now(),
	})
	m.TotalCalls++
	
	if m.ShouldError {
		return nil, errors.New(m.ErrorMessage)
	}
	
	// Mock successful token exchange
	return &services.OAuthTokenResponse{
		AccessToken:  m.MockAccessToken,
		RefreshToken: m.MockRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        m.generateMockScope(provider),
		CreatedAt:    time.Now().Format(time.RFC3339),
	}, nil
}

// RefreshToken mocks OAuth token refresh
func (m *MockOAuthService) RefreshToken(provider string, refreshToken string) (*services.OAuthTokenResponse, error) {
	m.RefreshTokenCalls = append(m.RefreshTokenCalls, RefreshTokenCall{
		Provider:     provider,
		RefreshToken: refreshToken,
		Timestamp:    time.Now(),
	})
	m.TotalCalls++
	
	if m.ShouldError {
		return nil, errors.New(m.ErrorMessage)
	}
	
	// Mock successful token refresh
	return &services.OAuthTokenResponse{
		AccessToken:  fmt.Sprintf("refreshed_%s", m.MockAccessToken),
		RefreshToken: refreshToken, // Keep same refresh token
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        m.generateMockScope(provider),
		CreatedAt:    time.Now().Format(time.RFC3339),
	}, nil
}

// GetUserInfo mocks OAuth user information retrieval
func (m *MockOAuthService) GetUserInfo(provider string, accessToken string) (*services.OAuthUserInfo, error) {
	m.GetUserInfoCalls = append(m.GetUserInfoCalls, GetUserInfoCall{
		Provider:    provider,
		AccessToken: accessToken,
		Timestamp:   time.Now(),
	})
	m.TotalCalls++
	
	if m.ShouldError {
		return nil, errors.New(m.ErrorMessage)
	}
	
	// Return mock user info with provider-specific adjustments
	userInfo := *m.MockUserInfo // Copy the struct
	userInfo.Provider = provider
	
	// Customize based on provider
	switch provider {
	case "google":
		userInfo.ID = "google_123456789"
		userInfo.Picture = "https://lh3.googleusercontent.com/mock-avatar"
	case "github":
		userInfo.ID = "github_123456"
		userInfo.Picture = "https://avatars.githubusercontent.com/u/123456"
		userInfo.Username = "testuser"
	case "microsoft":
		userInfo.ID = "microsoft_abcd-1234-efgh-5678"
		userInfo.Picture = "https://graph.microsoft.com/v1.0/me/photo/$value"
	}
	
	return &userInfo, nil
}

// ValidateProvider mocks OAuth provider validation
func (m *MockOAuthService) ValidateProvider(provider string) error {
	m.ValidateProviderCalls = append(m.ValidateProviderCalls, ValidateProviderCall{
		Provider:  provider,
		Timestamp: time.Now(),
	})
	m.TotalCalls++
	
	if m.ShouldError {
		return errors.New(m.ErrorMessage)
	}
	
	// Mock provider validation
	supportedProviders := []string{"google", "github", "microsoft", "slack", "discord"}
	for _, supported := range supportedProviders {
		if provider == supported {
			return nil
		}
	}
	
	return fmt.Errorf("unsupported OAuth provider: %s", provider)
}

// generateMockScope generates mock OAuth scopes based on provider
func (m *MockOAuthService) generateMockScope(provider string) string {
	switch provider {
	case "google":
		return "email profile openid"
	case "github":
		return "user:email read:user"
	case "microsoft":
		return "openid email profile"
	case "slack":
		return "identity.basic identity.email"
	case "discord":
		return "identify email"
	default:
		return "basic_profile email"
	}
}

// Helper methods for testing

// SetError configures the mock to return an error
func (m *MockOAuthService) SetError(shouldError bool, errorMessage string) {
	m.ShouldError = shouldError
	m.ErrorMessage = errorMessage
}

// SetTokens configures the mock tokens
func (m *MockOAuthService) SetTokens(accessToken, refreshToken string) {
	m.MockAccessToken = accessToken
	m.MockRefreshToken = refreshToken
}

// SetUserInfo configures the mock user info
func (m *MockOAuthService) SetUserInfo(userInfo *services.OAuthUserInfo) {
	m.MockUserInfo = userInfo
}

// GetCallCount returns the total number of calls made
func (m *MockOAuthService) GetCallCount() int {
	return m.TotalCalls
}

// GetLastGetAuthURLCall returns the last GetAuthURL call
func (m *MockOAuthService) GetLastGetAuthURLCall() *GetAuthURLCall {
	if len(m.GetAuthURLCalls) == 0 {
		return nil
	}
	return &m.GetAuthURLCalls[len(m.GetAuthURLCalls)-1]
}

// GetLastExchangeCodeCall returns the last ExchangeCode call
func (m *MockOAuthService) GetLastExchangeCodeCall() *ExchangeCodeCall {
	if len(m.ExchangeCodeCalls) == 0 {
		return nil
	}
	return &m.ExchangeCodeCalls[len(m.ExchangeCodeCalls)-1]
}

// GetLastGetUserInfoCall returns the last GetUserInfo call
func (m *MockOAuthService) GetLastGetUserInfoCall() *GetUserInfoCall {
	if len(m.GetUserInfoCalls) == 0 {
		return nil
	}
	return &m.GetUserInfoCalls[len(m.GetUserInfoCalls)-1]
}

// Reset clears all call tracking
func (m *MockOAuthService) Reset() {
	m.GetAuthURLCalls = []GetAuthURLCall{}
	m.ExchangeCodeCalls = []ExchangeCodeCall{}
	m.RefreshTokenCalls = []RefreshTokenCall{}
	m.GetUserInfoCalls = []GetUserInfoCall{}
	m.ValidateProviderCalls = []ValidateProviderCall{}
	m.TotalCalls = 0
	m.ShouldError = false
	m.ErrorMessage = ""
}

// Predefined scenarios for testing

// SetupGoogleOAuthScenario configures the mock for Google OAuth testing
func (m *MockOAuthService) SetupGoogleOAuthScenario() {
	m.MockUserInfo = &services.OAuthUserInfo{
		ID:       "google_123456789",
		Email:    "user@gmail.com",
		Name:     "John Doe",
		Picture:  "https://lh3.googleusercontent.com/a-/mock-avatar",
		Provider: "google",
		Username: "",
	}
}

// SetupGitHubOAuthScenario configures the mock for GitHub OAuth testing
func (m *MockOAuthService) SetupGitHubOAuthScenario() {
	m.MockUserInfo = &services.OAuthUserInfo{
		ID:       "github_123456",
		Email:    "user@users.noreply.github.com",
		Name:     "John Doe",
		Picture:  "https://avatars.githubusercontent.com/u/123456",
		Provider: "github",
		Username: "johndoe",
	}
}

// SetupMicrosoftOAuthScenario configures the mock for Microsoft OAuth testing
func (m *MockOAuthService) SetupMicrosoftOAuthScenario() {
	m.MockUserInfo = &services.OAuthUserInfo{
		ID:       "microsoft_abcd-1234-efgh-5678",
		Email:    "user@outlook.com",
		Name:     "John Doe",
		Picture:  "https://graph.microsoft.com/v1.0/me/photo/$value",
		Provider: "microsoft",
		Username: "",
	}
}

// SetupErrorScenario configures the mock to simulate OAuth errors
func (m *MockOAuthService) SetupErrorScenario(errorType string) {
	m.ShouldError = true
	switch errorType {
	case "invalid_code":
		m.ErrorMessage = "invalid authorization code"
	case "expired_token":
		m.ErrorMessage = "token has expired"
	case "invalid_provider":
		m.ErrorMessage = "unsupported OAuth provider"
	case "network_error":
		m.ErrorMessage = "network error occurred"
	default:
		m.ErrorMessage = "OAuth error occurred"
	}
}