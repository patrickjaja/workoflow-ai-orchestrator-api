package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/mock"

	"github.com/workoflow/ai-orchestrator-api/internal/config"
	"github.com/workoflow/ai-orchestrator-api/internal/database"
	"github.com/workoflow/ai-orchestrator-api/internal/handlers"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
	"gorm.io/gorm"
)

// OAuthTestSuite provides comprehensive OAuth flow testing
type OAuthTestSuite struct {
	suite.Suite
	db           *gorm.DB
	config       *config.Config
	
	// Services
	jwtService        *services.JWTService
	oauthService      *services.OAuthService
	tenantService     *services.TenantService
	encryptionService *services.EncryptionService
	
	// Auth handler
	authHandler *handlers.SimpleAuthHandler
	
	// Mock services
	mockRedis *MockRedisClient
	
	// Test data
	testOrg      *models.Organization
	testUser     *models.User
	testProvider *models.OAuthProvider
	
	// Test helpers
	helpers *TestHelpers
}

// MockRedisClient provides Redis mocking for session management
type MockRedisClient struct {
	mock.Mock
	data map[string]string
}

func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		data: make(map[string]string),
	}
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	args := m.Called(ctx, key, value, expiration)
	if args.Error(0) == nil {
		// Store the value for retrieval
		if str, ok := value.(string); ok {
			m.data[key] = str
		}
	}
	return args.Error(0)
}

func (m *MockRedisClient) Get(ctx context.Context, key string) (string, error) {
	args := m.Called(ctx, key)
	if args.Error(1) != nil {
		return "", args.Error(1)
	}
	
	// Return stored value or from mock expectation
	if value, exists := m.data[key]; exists {
		return value, nil
	}
	return args.String(0), args.Error(1)
}

func (m *MockRedisClient) Delete(ctx context.Context, keys ...string) error {
	args := m.Called(ctx, keys)
	for _, key := range keys {
		delete(m.data, key)
	}
	return args.Error(0)
}

func (m *MockRedisClient) Exists(ctx context.Context, keys ...string) (int64, error) {
	args := m.Called(ctx, keys)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRedisClient) Expire(ctx context.Context, key string, expiration time.Duration) error {
	args := m.Called(ctx, key, expiration)
	return args.Error(0)
}

func (m *MockRedisClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockRedisClient) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// SetupSuite initializes the test suite
func (suite *OAuthTestSuite) SetupSuite() {
	var err error
	
	// Use the global test database
	suite.db = testDB
	suite.config = testConfig
	require.NotNil(suite.T(), suite.db, "Test database must be initialized")
	require.NotNil(suite.T(), suite.config, "Test config must be initialized")
	
	// Initialize mock Redis
	suite.mockRedis = NewMockRedisClient()
	
	// Initialize encryption service
	suite.encryptionService = services.NewEncryptionService(suite.config.Security.EncryptionKey)
	
	// Initialize JWT service
	suite.jwtService = services.NewJWTService(
		suite.config.Security.JWTSecret,
		suite.config.Security.JWTExpiry,
	)
	
	// Initialize OAuth service with mock Redis
	suite.oauthService = services.NewOAuthService(
		database.Database{DB: suite.db}, // Wrapper for interface compatibility
		suite.encryptionService,
		suite.mockRedis,
		suite.config.OAuth,
	)
	
	// Initialize tenant service
	suite.tenantService = services.NewTenantService(suite.db)
	
	// Initialize auth handler
	suite.authHandler = handlers.NewSimpleAuthHandler(
		suite.oauthService,
		suite.jwtService,
		suite.tenantService,
	)
	
	// Initialize test helpers
	suite.helpers = NewTestHelpers("http://localhost:8080", suite.db)
	
	suite.T().Log("OAuth test suite initialized successfully")
}

// SetupTest creates fresh test data for each test
func (suite *OAuthTestSuite) SetupTest() {
	// Clean up any existing test data
	suite.db.Where("1 = 1").Delete(&models.UserToken{})
	suite.db.Where("1 = 1").Delete(&models.OAuthProvider{})
	suite.db.Where("1 = 1").Delete(&models.User{})
	suite.db.Where("1 = 1").Delete(&models.Organization{})
	
	// Reset mock Redis
	suite.mockRedis = NewMockRedisClient()
	
	// Create test organization
	suite.testOrg = &models.Organization{
		ID:          1,
		Name:        "Test Organization",
		Slug:        "test-org",
		Description: "Test organization for OAuth tests",
		Settings:    models.JSON{"theme": "light"},
	}
	err := suite.db.Create(suite.testOrg).Error
	require.NoError(suite.T(), err, "Failed to create test organization")
	
	// Create test user
	suite.testUser = &models.User{
		ID:             1,
		Email:          "test@example.com",
		FirstName:      "Test",
		LastName:       "User",
		Role:           "user",
		IsActive:       true,
		IsVerified:     true,
		OrganizationID: suite.testOrg.ID,
		Settings:       models.JSON{"language": "en"},
	}
	err = suite.db.Create(suite.testUser).Error
	require.NoError(suite.T(), err, "Failed to create test user")
	
	// Create encrypted test credentials
	encryptedClientID, err := suite.encryptionService.Encrypt("test-client-id-12345")
	require.NoError(suite.T(), err, "Failed to encrypt client ID")
	
	encryptedClientSecret, err := suite.encryptionService.Encrypt("test-client-secret-67890")
	require.NoError(suite.T(), err, "Failed to encrypt client secret")
	
	// Create test OAuth provider for Microsoft
	suite.testProvider = &models.OAuthProvider{
		ID:             1,
		OrganizationID: suite.testOrg.ID,
		ProviderType:   models.ProviderTypeMicrosoft,
		ClientID:       encryptedClientID,
		ClientSecret:   encryptedClientSecret,
		TenantID:       stringPtr("common"),
		Scopes:         []string{"openid", "profile", "email", "User.Read"},
		Enabled:        true,
	}
	err = suite.db.Create(suite.testProvider).Error
	require.NoError(suite.T(), err, "Failed to create OAuth provider")
}

// TearDownTest cleans up test data
func (suite *OAuthTestSuite) TearDownTest() {
	// Clean up test data
	suite.db.Where("1 = 1").Delete(&models.UserToken{})
	suite.db.Where("1 = 1").Delete(&models.OAuthProvider{})
	suite.db.Where("1 = 1").Delete(&models.User{})
	suite.db.Where("1 = 1").Delete(&models.Organization{})
	
	// Clear mock data
	suite.mockRedis.data = make(map[string]string)
}

// TestOAuthProviderInitiation tests initiating OAuth flow for different providers
func (suite *OAuthTestSuite) TestOAuthProviderInitiation() {
	ctx := context.Background()
	
	testCases := []struct {
		name         string
		providerType models.ProviderType
		expectError  bool
		expectedURL  string
	}{
		{
			name:         "Microsoft OAuth Initiation",
			providerType: models.ProviderTypeMicrosoft,
			expectError:  false,
			expectedURL:  "https://login.microsoftonline.com",
		},
		{
			name:         "Slack OAuth Initiation",
			providerType: models.ProviderTypeSlack,
			expectError:  false,
			expectedURL:  "https://slack.com/oauth",
		},
		{
			name:         "Atlassian OAuth Initiation",
			providerType: models.ProviderTypeAtlassian,
			expectError:  false,
			expectedURL:  "https://auth.atlassian.com",
		},
		{
			name:         "Invalid Provider",
			providerType: models.ProviderType("invalid"),
			expectError:  true,
			expectedURL:  "",
		},
	}
	
	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Create provider for test case if it's not Microsoft (already exists)
			if tc.providerType != models.ProviderTypeMicrosoft && tc.providerType != "invalid" {
				encryptedClientID, err := suite.encryptionService.Encrypt("test-client-id")
				require.NoError(suite.T(), err)
				
				encryptedClientSecret, err := suite.encryptionService.Encrypt("test-client-secret")
				require.NoError(suite.T(), err)
				
				provider := &models.OAuthProvider{
					OrganizationID: suite.testOrg.ID,
					ProviderType:   tc.providerType,
					ClientID:       encryptedClientID,
					ClientSecret:   encryptedClientSecret,
					Enabled:        true,
				}
				err = suite.db.Create(provider).Error
				require.NoError(suite.T(), err)
			}
			
			// Mock Redis SET operation for session storage
			if !tc.expectError {
				suite.mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(nil).Once()
			}
			
			// Call GetAuthURL
			authURL, sessionID, err := suite.oauthService.GetAuthURL(
				ctx,
				suite.testUser.ID,
				suite.testOrg.ID,
				string(tc.providerType),
			)
			
			if tc.expectError {
				assert.Error(suite.T(), err)
				assert.Empty(suite.T(), authURL)
				assert.Empty(suite.T(), sessionID)
			} else {
				assert.NoError(suite.T(), err)
				assert.NotEmpty(suite.T(), authURL)
				assert.NotEmpty(suite.T(), sessionID)
				assert.Contains(suite.T(), authURL, tc.expectedURL)
				
				// Verify session ID is valid
				assert.NotEmpty(suite.T(), sessionID)
			}
			
			// Verify Redis SET was called if expected
			if !tc.expectError {
				suite.mockRedis.AssertExpectations(suite.T())
			}
		})
	}
}

// TestOAuthCallbackHandling tests OAuth callback processing
func (suite *OAuthTestSuite) TestOAuthCallbackHandling() {
	ctx := context.Background()
	
	// Create OAuth session
	session := models.NewOAuthSession(
		suite.testUser.ID,
		suite.testOrg.ID,
		"microsoft",
		5*time.Minute,
	)
	sessionData, err := session.ToJSON()
	require.NoError(suite.T(), err)
	
	// Mock Redis operations for callback
	sessionKey := fmt.Sprintf("oauth_session:%s", session.State)
	suite.mockRedis.On("Get", mock.Anything, sessionKey).Return(string(sessionData), nil).Once()
	suite.mockRedis.On("Delete", mock.Anything, mock.Anything).Return(nil).Once()
	
	// Mock potential chat session cleanup
	chatSessionKey := fmt.Sprintf("chat_session:%s", session.ID)
	suite.mockRedis.On("Get", mock.Anything, chatSessionKey).Return("", fmt.Errorf("not found")).Once()
	
	testCases := []struct {
		name        string
		code        string
		state       string
		provider    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid OAuth Callback",
			code:        "test-auth-code-12345",
			state:       session.State,
			provider:    "microsoft",
			expectError: true, // Will fail due to actual OAuth exchange, but validates session handling
			errorMsg:    "failed to exchange code for token",
		},
		{
			name:        "Invalid State Parameter",
			code:        "test-auth-code-12345",
			state:       "invalid-state",
			provider:    "microsoft",
			expectError: true,
			errorMsg:    "session not found or expired",
		},
		{
			name:        "Invalid Provider",
			code:        "test-auth-code-12345",
			state:       session.State,
			provider:    "invalid-provider",
			expectError: true,
			errorMsg:    "OAuth provider not found",
		},
	}
	
	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			if tc.state != "invalid-state" {
				// Reset Redis mock for valid state tests
				suite.mockRedis.On("Get", mock.Anything, sessionKey).Return(string(sessionData), nil).Once()
				suite.mockRedis.On("Delete", mock.Anything, mock.Anything).Return(nil).Maybe()
				suite.mockRedis.On("Get", mock.Anything, chatSessionKey).Return("", fmt.Errorf("not found")).Maybe()
			} else {
				// Mock invalid session
				invalidSessionKey := fmt.Sprintf("oauth_session:%s", tc.state)
				suite.mockRedis.On("Get", mock.Anything, invalidSessionKey).Return("", fmt.Errorf("redis: nil")).Once()
			}
			
			// Handle OAuth callback
			err := suite.oauthService.HandleCallback(ctx, tc.provider, tc.code, tc.state)
			
			if tc.expectError {
				assert.Error(suite.T(), err)
				if tc.errorMsg != "" {
					assert.Contains(suite.T(), err.Error(), tc.errorMsg)
				}
			} else {
				assert.NoError(suite.T(), err)
			}
		})
	}
}

// TestJWTTokenGeneration tests JWT token creation and validation
func (suite *OAuthTestSuite) TestJWTTokenGeneration() {
	testCases := []struct {
		name           string
		userID         uint
		organizationID uint
		email          string
		role           string
		expectError    bool
	}{
		{
			name:           "Valid Admin Token Generation",
			userID:         1,
			organizationID: 1,
			email:          "admin@example.com",
			role:           "admin",
			expectError:    false,
		},
		{
			name:           "Valid User Token Generation",
			userID:         2,
			organizationID: 1,
			email:          "user@example.com",
			role:           "user",
			expectError:    false,
		},
		{
			name:           "Token with Empty Email",
			userID:         3,
			organizationID: 1,
			email:          "",
			role:           "user",
			expectError:    false, // Email is optional in JWT
		},
	}
	
	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Generate access token
			accessToken, err := suite.jwtService.GenerateAccessToken(
				tc.userID,
				tc.organizationID,
				tc.email,
				tc.role,
			)
			
			if tc.expectError {
				assert.Error(suite.T(), err)
				assert.Empty(suite.T(), accessToken)
			} else {
				assert.NoError(suite.T(), err)
				assert.NotEmpty(suite.T(), accessToken)
				
				// Validate the generated token
				claims, err := suite.jwtService.ValidateAccessToken(accessToken)
				assert.NoError(suite.T(), err)
				assert.NotNil(suite.T(), claims)
				
				// Verify claims (note: ValidateAccessToken returns simplified claims due to UUID conversion)
				assert.Equal(suite.T(), tc.email, claims.Email)
				assert.Equal(suite.T(), tc.role == "admin", claims.IsAdmin)
				assert.True(suite.T(), claims.ExpiresAt > time.Now().Unix())
			}
		})
	}
	
	// Test token validation with invalid tokens
	suite.Run("Invalid Token Validation", func() {
		invalidTokens := []string{
			"invalid.jwt.token",
			"",
			"not-a-jwt-at-all",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
		}
		
		for _, token := range invalidTokens {
			claims, err := suite.jwtService.ValidateAccessToken(token)
			assert.Error(suite.T(), err)
			assert.Nil(suite.T(), claims)
		}
	})
}

// TestRefreshTokenFlow tests JWT refresh token mechanism
func (suite *OAuthTestSuite) TestRefreshTokenFlow() {
	userID := uint(1)
	orgID := uint(1)
	
	suite.Run("Successful Refresh Token Flow", func() {
		// Generate initial refresh token
		refreshToken, err := suite.jwtService.GenerateRefreshToken(
			uuid.New(), // Convert uint to UUID in real implementation
			uuid.New(),
		)
		require.NoError(suite.T(), err)
		require.NotEmpty(suite.T(), refreshToken)
		
		// Validate refresh token
		claims, err := suite.jwtService.ValidateRefreshTokenWrapper(refreshToken)
		assert.NoError(suite.T(), err)
		assert.NotNil(suite.T(), claims)
		
		// Test refresh token pair generation
		newAccessToken, newRefreshToken, err := suite.jwtService.RefreshTokenPair(refreshToken)
		assert.NoError(suite.T(), err)
		assert.NotEmpty(suite.T(), newAccessToken)
		assert.NotEmpty(suite.T(), newRefreshToken)
		assert.NotEqual(suite.T(), refreshToken, newRefreshToken)
		
		// Validate new tokens
		accessClaims, err := suite.jwtService.ValidateAccessToken(newAccessToken)
		assert.NoError(suite.T(), err)
		assert.NotNil(suite.T(), accessClaims)
		
		refreshClaims, err := suite.jwtService.ValidateRefreshTokenWrapper(newRefreshToken)
		assert.NoError(suite.T(), err)
		assert.NotNil(suite.T(), refreshClaims)
	})
	
	suite.Run("Invalid Refresh Token", func() {
		invalidTokens := []string{
			"invalid.refresh.token",
			"",
			"not-a-refresh-token",
		}
		
		for _, token := range invalidTokens {
			newAccessToken, newRefreshToken, err := suite.jwtService.RefreshTokenPair(token)
			assert.Error(suite.T(), err)
			assert.Empty(suite.T(), newAccessToken)
			assert.Empty(suite.T(), newRefreshToken)
		}
	})
}

// TestOAuthSessionManagement tests OAuth session storage and retrieval with Redis
func (suite *OAuthTestSuite) TestOAuthSessionManagement() {
	ctx := context.Background()
	
	suite.Run("Session Storage and Retrieval", func() {
		// Create OAuth session
		session := models.NewOAuthSession(
			suite.testUser.ID,
			suite.testOrg.ID,
			"microsoft",
			5*time.Minute,
		)
		
		sessionData, err := session.ToJSON()
		require.NoError(suite.T(), err)
		
		sessionKey := fmt.Sprintf("oauth_session:%s", session.State)
		
		// Mock Redis SET operation
		suite.mockRedis.On("Set", mock.Anything, sessionKey, string(sessionData), 5*time.Minute).Return(nil).Once()
		
		// Store session
		err = suite.mockRedis.Set(ctx, sessionKey, string(sessionData), 5*time.Minute)
		assert.NoError(suite.T(), err)
		
		// Mock Redis GET operation
		suite.mockRedis.On("Get", mock.Anything, sessionKey).Return(string(sessionData), nil).Once()
		
		// Retrieve session
		retrievedData, err := suite.mockRedis.Get(ctx, sessionKey)
		assert.NoError(suite.T(), err)
		
		// Validate retrieved session
		retrievedSession, err := models.OAuthSessionFromJSON([]byte(retrievedData))
		assert.NoError(suite.T(), err)
		assert.Equal(suite.T(), session.ID, retrievedSession.ID)
		assert.Equal(suite.T(), session.UserID, retrievedSession.UserID)
		assert.Equal(suite.T(), session.OrganizationID, retrievedSession.OrganizationID)
		assert.Equal(suite.T(), session.Provider, retrievedSession.Provider)
		assert.Equal(suite.T(), session.State, retrievedSession.State)
		
		// Mock Redis DELETE operation
		suite.mockRedis.On("Delete", mock.Anything, []string{sessionKey}).Return(nil).Once()
		
		// Delete session
		err = suite.mockRedis.Delete(ctx, sessionKey)
		assert.NoError(suite.T(), err)
		
		suite.mockRedis.AssertExpectations(suite.T())
	})
	
	suite.Run("Session Expiration", func() {
		// Create expired session
		session := models.NewOAuthSession(
			suite.testUser.ID,
			suite.testOrg.ID,
			"microsoft",
			-1*time.Minute, // Already expired
		)
		
		// Check expiration
		assert.True(suite.T(), session.IsExpired())
		
		// Create valid session
		validSession := models.NewOAuthSession(
			suite.testUser.ID,
			suite.testOrg.ID,
			"microsoft",
			5*time.Minute,
		)
		
		// Check validity
		assert.False(suite.T(), validSession.IsExpired())
	})
	
	suite.Run("Session Not Found", func() {
		sessionKey := "oauth_session:nonexistent"
		
		// Mock Redis GET operation returning error
		suite.mockRedis.On("Get", mock.Anything, sessionKey).Return("", fmt.Errorf("redis: nil")).Once()
		
		// Try to retrieve non-existent session
		_, err := suite.mockRedis.Get(ctx, sessionKey)
		assert.Error(suite.T(), err)
		
		suite.mockRedis.AssertExpectations(suite.T())
	})
}

// TestMultiProviderSupport tests multiple OAuth providers per organization
func (suite *OAuthTestSuite) TestMultiProviderSupport() {
	ctx := context.Background()
	
	// Create additional OAuth providers
	providers := []struct {
		providerType models.ProviderType
		clientID     string
		clientSecret string
		scopes       []string
	}{
		{
			providerType: models.ProviderTypeSlack,
			clientID:     "slack-client-id",
			clientSecret: "slack-client-secret",
			scopes:       []string{"channels:read", "chat:write"},
		},
		{
			providerType: models.ProviderTypeAtlassian,
			clientID:     "atlassian-client-id",
			clientSecret: "atlassian-client-secret",
			scopes:       []string{"read:jira-work", "read:confluence-content.all"},
		},
	}
	
	createdProviders := make([]*models.OAuthProvider, 0, len(providers))
	
	// Create providers
	for _, p := range providers {
		encryptedClientID, err := suite.encryptionService.Encrypt(p.clientID)
		require.NoError(suite.T(), err)
		
		encryptedClientSecret, err := suite.encryptionService.Encrypt(p.clientSecret)
		require.NoError(suite.T(), err)
		
		provider := &models.OAuthProvider{
			OrganizationID: suite.testOrg.ID,
			ProviderType:   p.providerType,
			ClientID:       encryptedClientID,
			ClientSecret:   encryptedClientSecret,
			Scopes:         p.scopes,
			Enabled:        true,
		}
		
		err = suite.db.Create(provider).Error
		require.NoError(suite.T(), err)
		createdProviders = append(createdProviders, provider)
	}
	
	// Test OAuth initiation for each provider
	for i, provider := range createdProviders {
		suite.Run(fmt.Sprintf("OAuth Initiation for %s", provider.ProviderType), func() {
			// Mock Redis SET for session storage
			suite.mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(nil).Once()
			
			authURL, sessionID, err := suite.oauthService.GetAuthURL(
				ctx,
				suite.testUser.ID,
				suite.testOrg.ID,
				string(provider.ProviderType),
			)
			
			assert.NoError(suite.T(), err)
			assert.NotEmpty(suite.T(), authURL)
			assert.NotEmpty(suite.T(), sessionID)
			
			// Verify provider-specific URLs
			switch provider.ProviderType {
			case models.ProviderTypeSlack:
				assert.Contains(suite.T(), authURL, "slack.com/oauth")
			case models.ProviderTypeAtlassian:
				assert.Contains(suite.T(), authURL, "auth.atlassian.com")
			}
			
			suite.mockRedis.AssertExpectations(suite.T())
		})
	}
	
	// Test retrieving all providers for organization
	suite.Run("List Organization OAuth Providers", func() {
		allProviders, err := suite.tenantService.ListOAuthProviders(ctx, suite.testOrg.ID)
		assert.NoError(suite.T(), err)
		
		// Should have Microsoft (from setup) + Slack + Atlassian = 3 providers
		assert.Len(suite.T(), allProviders, 3)
		
		providerTypes := make(map[models.ProviderType]bool)
		for _, p := range allProviders {
			providerTypes[p.ProviderType] = true
		}
		
		assert.True(suite.T(), providerTypes[models.ProviderTypeMicrosoft])
		assert.True(suite.T(), providerTypes[models.ProviderTypeSlack])
		assert.True(suite.T(), providerTypes[models.ProviderTypeAtlassian])
	})
	
	// Test provider isolation between organizations
	suite.Run("Provider Organization Isolation", func() {
		// Create another organization
		org2 := &models.Organization{
			Name:        "Test Organization 2",
			Slug:        "test-org-2",
			Description: "Second test organization",
		}
		err := suite.db.Create(org2).Error
		require.NoError(suite.T(), err)
		
		// Try to get provider from different organization
		_, err = suite.tenantService.GetOAuthProvider(ctx, org2.ID, "microsoft")
		assert.Error(suite.T(), err)
		assert.Contains(suite.T(), err.Error(), "OAuth provider not found or not enabled")
		
		// Clean up
		suite.db.Delete(org2)
	})
}

// TestUserTokenStorage tests OAuth token storage and retrieval
func (suite *OAuthTestSuite) TestUserTokenStorage() {
	ctx := context.Background()
	
	// Create encrypted tokens
	encryptedAccessToken, err := suite.encryptionService.Encrypt("access-token-12345")
	require.NoError(suite.T(), err)
	
	encryptedRefreshToken, err := suite.encryptionService.Encrypt("refresh-token-67890")
	require.NoError(suite.T(), err)
	
	expiresAt := time.Now().Add(1 * time.Hour)
	
	userToken := &models.UserToken{
		UserID:       suite.testUser.ID,
		ProviderID:   suite.testProvider.ID,
		AccessToken:  encryptedAccessToken,
		RefreshToken: &encryptedRefreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    &expiresAt,
		Scopes:       []string{"openid", "profile", "email"},
	}
	
	suite.Run("Store User Token", func() {
		err := suite.db.Create(userToken).Error
		assert.NoError(suite.T(), err)
		assert.NotZero(suite.T(), userToken.ID)
	})
	
	suite.Run("Retrieve User Token", func() {
		retrievedToken, err := suite.oauthService.GetUserToken(
			ctx,
			suite.testUser.ID,
			string(suite.testProvider.ProviderType),
		)
		
		assert.NoError(suite.T(), err)
		assert.NotNil(suite.T(), retrievedToken)
		assert.Equal(suite.T(), userToken.UserID, retrievedToken.UserID)
		assert.Equal(suite.T(), userToken.ProviderID, retrievedToken.ProviderID)
		assert.Equal(suite.T(), userToken.TokenType, retrievedToken.TokenType)
	})
	
	suite.Run("Token Expiration Check", func() {
		// Test non-expired token
		assert.False(suite.T(), userToken.IsExpired())
		assert.False(suite.T(), userToken.NeedsRefresh())
		
		// Test expired token
		expiredToken := &models.UserToken{
			ExpiresAt: &time.Time{}, // Zero time is in the past
		}
		assert.True(suite.T(), expiredToken.IsExpired())
		
		// Test token needing refresh (expires in less than 5 minutes)
		soonExpiring := time.Now().Add(2 * time.Minute)
		needsRefreshToken := &models.UserToken{
			ExpiresAt: &soonExpiring,
		}
		assert.True(suite.T(), needsRefreshToken.NeedsRefresh())
	})
	
	suite.Run("Revoke User Token", func() {
		err := suite.oauthService.RevokeToken(
			ctx,
			suite.testUser.ID,
			string(suite.testProvider.ProviderType),
		)
		assert.NoError(suite.T(), err)
		
		// Verify token is deleted
		_, err = suite.oauthService.GetUserToken(
			ctx,
			suite.testUser.ID,
			string(suite.testProvider.ProviderType),
		)
		assert.Error(suite.T(), err)
		assert.Contains(suite.T(), err.Error(), "token not found for provider")
	})
}

// TestOAuthErrors tests various error scenarios
func (suite *OAuthTestSuite) TestOAuthErrors() {
	ctx := context.Background()
	
	suite.Run("OAuth Initiation Errors", func() {
		// Test with non-existent organization
		_, _, err := suite.oauthService.GetAuthURL(ctx, 999, 999, "microsoft")
		assert.Error(suite.T(), err)
		
		// Test with disabled provider
		suite.testProvider.Enabled = false
		suite.db.Save(suite.testProvider)
		
		_, _, err = suite.oauthService.GetAuthURL(
			ctx,
			suite.testUser.ID,
			suite.testOrg.ID,
			"microsoft",
		)
		assert.Error(suite.T(), err)
		
		// Restore provider
		suite.testProvider.Enabled = true
		suite.db.Save(suite.testProvider)
	})
	
	suite.Run("Session Storage Errors", func() {
		// Mock Redis error
		suite.mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(fmt.Errorf("redis connection failed")).Once()
		
		_, _, err := suite.oauthService.GetAuthURL(
			ctx,
			suite.testUser.ID,
			suite.testOrg.ID,
			"microsoft",
		)
		assert.Error(suite.T(), err)
		assert.Contains(suite.T(), err.Error(), "failed to store session")
		
		suite.mockRedis.AssertExpectations(suite.T())
	})
}

// Helper functions

func stringPtr(s string) *string {
	return &s
}

// TestSuite runner
func TestOAuthTestSuite(t *testing.T) {
	suite.Run(t, new(OAuthTestSuite))
}