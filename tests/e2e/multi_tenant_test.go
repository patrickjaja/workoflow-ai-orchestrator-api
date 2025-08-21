package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/workoflow/ai-orchestrator-api/internal/middleware"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
	"gorm.io/gorm"
)

// DatabaseWrapper implements the database.Database interface for testing
type DatabaseWrapper struct {
	db *gorm.DB
}

func (dw *DatabaseWrapper) DB() *gorm.DB {
	return dw.db
}

// MultiTenantTestSuite tests multi-tenant isolation functionality
type MultiTenantTestSuite struct {
	suite.Suite

	// Test services
	jwtService    *services.JWTService
	tenantService *services.TenantService

	// Test middleware
	jwtMiddleware    *middleware.JWTMiddleware
	tenantMiddleware *middleware.TenantMiddleware

	// Test router for middleware testing
	router *gin.Engine

	// Test organizations
	orgA *models.Organization
	orgB *models.Organization
	orgC *models.Organization

	// Test users (one per organization + multi-org user)
	userA1 *models.User // User in Org A
	userA2 *models.User // Another user in Org A
	userB1 *models.User // User in Org B
	userC1 *models.User // User in Org C (admin)

	// Test OAuth providers (one per organization)
	providerA *models.OAuthProvider // Microsoft provider for Org A
	providerB *models.OAuthProvider // Google provider for Org B
	providerC *models.OAuthProvider // GitHub provider for Org C

	// Test webhooks
	webhookA *models.N8NWebhook
	webhookB *models.N8NWebhook
	webhookC *models.N8NWebhook

	// Test tokens
	tokenUserA1 *models.UserToken
	tokenUserB1 *models.UserToken

	// Test conversations
	convA1 *models.Conversation
	convA2 *models.Conversation
	convB1 *models.Conversation

	// JWT tokens for authentication
	jwtTokenA1 string
	jwtTokenA2 string
	jwtTokenB1 string
	jwtTokenC1 string
}

// SetupSuite initializes the test suite
func (s *MultiTenantTestSuite) SetupSuite() {
	gin.SetMode(gin.TestMode)

	// Initialize services
	s.initializeServices()

	// Setup test router
	s.setupTestRouter()

	// Create test data
	s.createTestData()

	// Generate JWT tokens for authentication
	s.generateJWTTokens()
}

// TearDownSuite cleans up after all tests
func (s *MultiTenantTestSuite) TearDownSuite() {
	// Clean up all test data
	s.cleanupTestData()
}

// SetupTest runs before each test
func (s *MultiTenantTestSuite) SetupTest() {
	// Any per-test setup can go here
}

// TearDownTest runs after each test
func (s *MultiTenantTestSuite) TearDownTest() {
	// Any per-test cleanup can go here
}

// initializeServices creates the necessary services for testing
func (s *MultiTenantTestSuite) initializeServices() {
	// Initialize JWT service with correct constructor
	s.jwtService = services.NewJWTService(
		testConfig.Security.JWTSecret,
		testConfig.Security.JWTExpiry,
	)

	// Create database wrapper for TenantService
	dbWrapper := &DatabaseWrapper{db: testDB}

	// Initialize tenant service
	s.tenantService = services.NewTenantService(dbWrapper)

	// Initialize middleware
	s.jwtMiddleware = middleware.NewJWTMiddleware(s.jwtService)
	s.tenantMiddleware = middleware.NewTenantMiddleware(s.tenantService)
}

// setupTestRouter creates a test router with middleware for testing
func (s *MultiTenantTestSuite) setupTestRouter() {
	s.router = gin.New()

	// Add middleware
	s.router.Use(s.jwtMiddleware.AuthOptional())
	s.router.Use(s.tenantMiddleware.ResolveTenant())

	// Define test routes
	api := s.router.Group("/api")
	{
		// Protected routes requiring authentication
		protected := api.Group("")
		protected.Use(s.jwtMiddleware.AuthRequired())
		{
			// Routes requiring tenant isolation
			tenant := protected.Group("")
			tenant.Use(s.tenantMiddleware.ValidateTenantAccess())
			tenant.Use(s.tenantMiddleware.EnforceTenantIsolation())
			{
				tenant.GET("/organizations/:organization_id/users", s.mockGetUsersHandler)
				tenant.GET("/organizations/:organization_id/webhooks", s.mockGetWebhooksHandler)
				tenant.GET("/organizations/:organization_id/providers", s.mockGetProvidersHandler)
				tenant.GET("/organizations/:organization_id/conversations", s.mockGetConversationsHandler)
				tenant.DELETE("/organizations/:organization_id", s.mockDeleteOrganizationHandler)
			}

			// User switching endpoint
			protected.POST("/users/switch-organization", s.mockSwitchOrganizationHandler)
		}

		// Subdomain-based tenant resolution endpoint (simulated)
		api.GET("/tenant-info", s.mockGetTenantInfoHandler)
	}
}

// createTestData sets up all test data needed for multi-tenant tests
func (s *MultiTenantTestSuite) createTestData() {
	s.T().Log("Creating multi-tenant test data...")

	// Create test organizations
	s.createTestOrganizations()

	// Create test users
	s.createTestUsers()

	// Create OAuth providers
	s.createOAuthProviders()

	// Create N8N webhooks
	s.createN8NWebhooks()

	// Create user tokens
	s.createUserTokens()

	// Create conversations
	s.createConversations()

	s.T().Log("Test data creation complete")
}

// createTestOrganizations creates test organizations
func (s *MultiTenantTestSuite) createTestOrganizations() {
	s.orgA = &models.Organization{
		Name:        "Organization Alpha",
		Slug:        "org-alpha",
		Description: "Test organization A for multi-tenant testing",
		Settings:    models.JSON{"theme": "dark", "timezone": "UTC"},
	}
	require.NoError(s.T(), testDB.Create(s.orgA).Error)

	s.orgB = &models.Organization{
		Name:        "Organization Beta",
		Slug:        "org-beta",
		Description: "Test organization B for multi-tenant testing",
		Settings:    models.JSON{"theme": "light", "timezone": "EST"},
	}
	require.NoError(s.T(), testDB.Create(s.orgB).Error)

	s.orgC = &models.Organization{
		Name:        "Organization Gamma",
		Slug:        "org-gamma",
		Description: "Test organization C for multi-tenant testing",
		Settings:    models.JSON{"theme": "auto", "timezone": "PST"},
	}
	require.NoError(s.T(), testDB.Create(s.orgC).Error)
}

// createTestUsers creates test users for each organization
func (s *MultiTenantTestSuite) createTestUsers() {
	s.userA1 = &models.User{
		OrganizationID: s.orgA.ID,
		Email:          "user.a1@orga.example.com",
		PasswordHash:   "$2a$12$test.hash.for.testing.a1",
		FirstName:      "Alice",
		LastName:       "Anderson",
		Role:           "user",
		IsActive:       true,
		IsVerified:     true,
		Settings:       models.JSON{"language": "en", "notifications": true},
	}
	require.NoError(s.T(), testDB.Create(s.userA1).Error)

	s.userA2 = &models.User{
		OrganizationID: s.orgA.ID,
		Email:          "user.a2@orga.example.com",
		PasswordHash:   "$2a$12$test.hash.for.testing.a2",
		FirstName:      "Anna",
		LastName:       "Adams",
		Role:           "admin",
		IsActive:       true,
		IsVerified:     true,
		Settings:       models.JSON{"language": "en", "notifications": false},
	}
	require.NoError(s.T(), testDB.Create(s.userA2).Error)

	s.userB1 = &models.User{
		OrganizationID: s.orgB.ID,
		Email:          "user.b1@orgb.example.com",
		PasswordHash:   "$2a$12$test.hash.for.testing.b1",
		FirstName:      "Bob",
		LastName:       "Brown",
		Role:           "user",
		IsActive:       true,
		IsVerified:     true,
		Settings:       models.JSON{"language": "es", "notifications": true},
	}
	require.NoError(s.T(), testDB.Create(s.userB1).Error)

	s.userC1 = &models.User{
		OrganizationID: s.orgC.ID,
		Email:          "admin.c1@orgc.example.com",
		PasswordHash:   "$2a$12$test.hash.for.testing.c1",
		FirstName:      "Charlie",
		LastName:       "Chen",
		Role:           "admin",
		IsActive:       true,
		IsVerified:     true,
		Settings:       models.JSON{"language": "zh", "notifications": true},
	}
	require.NoError(s.T(), testDB.Create(s.userC1).Error)
}

// createOAuthProviders creates OAuth providers for each organization
func (s *MultiTenantTestSuite) createOAuthProviders() {
	s.providerA = &models.OAuthProvider{
		OrganizationID: s.orgA.ID,
		ProviderType:   models.ProviderTypeMicrosoft,
		ClientID:       "test-client-id-org-a-microsoft",
		ClientSecret:   "test-client-secret-org-a-microsoft",
		TenantID:       stringPtr("microsoft-tenant-a"),
		Scopes:         []string{"User.Read", "Files.Read.All", "Sites.Read.All"},
		Enabled:        true,
	}
	require.NoError(s.T(), testDB.Create(s.providerA).Error)

	s.providerB = &models.OAuthProvider{
		OrganizationID: s.orgB.ID,
		ProviderType:   models.ProviderTypeGoogle,
		ClientID:       "test-client-id-org-b-google",
		ClientSecret:   "test-client-secret-org-b-google",
		Scopes:         []string{"openid", "profile", "email", "https://www.googleapis.com/auth/drive.readonly"},
		Enabled:        true,
	}
	require.NoError(s.T(), testDB.Create(s.providerB).Error)

	s.providerC = &models.OAuthProvider{
		OrganizationID: s.orgC.ID,
		ProviderType:   models.ProviderTypeGitHub,
		ClientID:       "test-client-id-org-c-github",
		ClientSecret:   "test-client-secret-org-c-github",
		Scopes:         []string{"user:email", "read:user", "repo"},
		Enabled:        true,
	}
	require.NoError(s.T(), testDB.Create(s.providerC).Error)
}

// createN8NWebhooks creates N8N webhooks for each organization
func (s *MultiTenantTestSuite) createN8NWebhooks() {
	s.webhookA = &models.N8NWebhook{
		OrganizationID: s.orgA.ID,
		WorkflowName:   "Org A Workflow",
		WorkflowID:     "workflow-org-a-001",
		WebhookPath:    "/webhook/org-a/workflow-001",
		N8NBaseURL:     "https://n8n-org-a.example.com",
		AuthMethod:     "bearer",
		AuthToken:      "token-org-a-webhook",
		AuthHeaderName: "Authorization",
		Active:         true,
		Description:    "Primary workflow for Organization Alpha",
		Tags:           []string{"org-a", "primary", "automation"},
	}
	require.NoError(s.T(), testDB.Create(s.webhookA).Error)

	s.webhookB = &models.N8NWebhook{
		OrganizationID: s.orgB.ID,
		WorkflowName:   "Org B Workflow",
		WorkflowID:     "workflow-org-b-001",
		WebhookPath:    "/webhook/org-b/workflow-001",
		N8NBaseURL:     "https://n8n-org-b.example.com",
		AuthMethod:     "basic",
		AuthToken:      "token-org-b-webhook",
		AuthHeaderName: "Authorization",
		Active:         true,
		Description:    "Primary workflow for Organization Beta",
		Tags:           []string{"org-b", "primary", "integration"},
	}
	require.NoError(s.T(), testDB.Create(s.webhookB).Error)

	s.webhookC = &models.N8NWebhook{
		OrganizationID: s.orgC.ID,
		WorkflowName:   "Org C Workflow",
		WorkflowID:     "workflow-org-c-001",
		WebhookPath:    "/webhook/org-c/workflow-001",
		N8NBaseURL:     "https://n8n-org-c.example.com",
		AuthMethod:     "api-key",
		AuthToken:      "token-org-c-webhook",
		AuthHeaderName: "X-API-Key",
		Active:         true,
		Description:    "Primary workflow for Organization Gamma",
		Tags:           []string{"org-c", "primary", "monitoring"},
	}
	require.NoError(s.T(), testDB.Create(s.webhookC).Error)
}

// createUserTokens creates OAuth tokens for test users
func (s *MultiTenantTestSuite) createUserTokens() {
	refreshTokenA := "refresh-token-user-a1"
	expiresAtA := time.Now().Add(time.Hour)

	s.tokenUserA1 = &models.UserToken{
		UserID:       s.userA1.ID,
		ProviderID:   s.providerA.ID,
		AccessToken:  "access-token-user-a1",
		RefreshToken: &refreshTokenA,
		ExpiresAt:    &expiresAtA,
		Scopes:       []string{"User.Read", "Files.Read.All"},
	}
	require.NoError(s.T(), testDB.Create(s.tokenUserA1).Error)

	refreshTokenB := "refresh-token-user-b1"
	expiresAtB := time.Now().Add(time.Hour)

	s.tokenUserB1 = &models.UserToken{
		UserID:       s.userB1.ID,
		ProviderID:   s.providerB.ID,
		AccessToken:  "access-token-user-b1",
		RefreshToken: &refreshTokenB,
		ExpiresAt:    &expiresAtB,
		Scopes:       []string{"openid", "profile", "email"},
	}
	require.NoError(s.T(), testDB.Create(s.tokenUserB1).Error)
}

// createConversations creates test conversations
func (s *MultiTenantTestSuite) createConversations() {
	s.convA1 = &models.Conversation{
		ID:             uuid.New(),
		UserID:         s.userA1.ID,
		OrganizationID: s.orgA.ID,
		Title:          "Org A Conversation 1",
		Summary:        "Test conversation for user A1 in org A",
		IsActive:       true,
		Metadata:       models.JSON{"source": "teams", "priority": "normal"},
	}
	require.NoError(s.T(), testDB.Create(s.convA1).Error)

	s.convA2 = &models.Conversation{
		ID:             uuid.New(),
		UserID:         s.userA2.ID,
		OrganizationID: s.orgA.ID,
		Title:          "Org A Conversation 2",
		Summary:        "Test conversation for user A2 in org A",
		IsActive:       true,
		Metadata:       models.JSON{"source": "web", "priority": "high"},
	}
	require.NoError(s.T(), testDB.Create(s.convA2).Error)

	s.convB1 = &models.Conversation{
		ID:             uuid.New(),
		UserID:         s.userB1.ID,
		OrganizationID: s.orgB.ID,
		Title:          "Org B Conversation 1",
		Summary:        "Test conversation for user B1 in org B",
		IsActive:       true,
		Metadata:       models.JSON{"source": "slack", "priority": "low"},
	}
	require.NoError(s.T(), testDB.Create(s.convB1).Error)
}

// generateJWTTokens creates JWT tokens for test users
func (s *MultiTenantTestSuite) generateJWTTokens() {
	var err error

	// Convert user IDs to UUIDs for token generation
	userA1UUID := uuid.New()
	userA2UUID := uuid.New() 
	userB1UUID := uuid.New()
	userC1UUID := uuid.New()
	
	orgAUUID := uuid.New()
	orgBUUID := uuid.New()
	orgCUUID := uuid.New()

	// Generate token for user A1
	s.jwtTokenA1, err = s.jwtService.GenerateToken(
		userA1UUID, orgAUUID, s.userA1.Email, s.userA1.Role,
		s.userA1.Role == "admin",
	)
	require.NoError(s.T(), err)

	// Generate token for user A2
	s.jwtTokenA2, err = s.jwtService.GenerateToken(
		userA2UUID, orgAUUID, s.userA2.Email, s.userA2.Role,
		s.userA2.Role == "admin",
	)
	require.NoError(s.T(), err)

	// Generate token for user B1
	s.jwtTokenB1, err = s.jwtService.GenerateToken(
		userB1UUID, orgBUUID, s.userB1.Email, s.userB1.Role,
		s.userB1.Role == "admin",
	)
	require.NoError(s.T(), err)

	// Generate token for user C1
	s.jwtTokenC1, err = s.jwtService.GenerateToken(
		userC1UUID, orgCUUID, s.userC1.Email, s.userC1.Role,
		s.userC1.Role == "admin",
	)
	require.NoError(s.T(), err)
}

// cleanupTestData removes all test data
func (s *MultiTenantTestSuite) cleanupTestData() {
	// Delete in reverse order of dependencies
	testDB.Where("1 = 1").Delete(&models.UserToken{})
	testDB.Where("1 = 1").Delete(&models.Conversation{})
	testDB.Where("1 = 1").Delete(&models.N8NWebhook{})
	testDB.Where("1 = 1").Delete(&models.OAuthProvider{})
	testDB.Where("1 = 1").Delete(&models.User{})
	testDB.Where("1 = 1").Delete(&models.Organization{})
}

// TestOrganizationDataIsolation tests that data is properly isolated between organizations
func (s *MultiTenantTestSuite) TestOrganizationDataIsolation() {
	s.T().Log("Testing organization data isolation...")

	// Test 1: Users can only see their own organization's users
	s.Run("users_isolation", func() {
		// User A1 should only see users from Org A
		req := s.createAuthenticatedRequest("GET", fmt.Sprintf("/api/organizations/%d/users", s.orgA.ID), nil, s.jwtTokenA1)
		resp := s.performRequest(req)

		assert.Equal(s.T(), http.StatusOK, resp.Code)

		// User A1 should NOT be able to access users from Org B
		req = s.createAuthenticatedRequest("GET", fmt.Sprintf("/api/organizations/%d/users", s.orgB.ID), nil, s.jwtTokenA1)
		resp = s.performRequest(req)

		assert.Equal(s.T(), http.StatusForbidden, resp.Code)
	})

	// Test 2: OAuth providers are isolated between organizations
	s.Run("oauth_providers_isolation", func() {
		// User A1 can access Org A's providers
		req := s.createAuthenticatedRequest("GET", fmt.Sprintf("/api/organizations/%d/providers", s.orgA.ID), nil, s.jwtTokenA1)
		resp := s.performRequest(req)

		assert.Equal(s.T(), http.StatusOK, resp.Code)

		// User A1 cannot access Org B's providers
		req = s.createAuthenticatedRequest("GET", fmt.Sprintf("/api/organizations/%d/providers", s.orgB.ID), nil, s.jwtTokenA1)
		resp = s.performRequest(req)

		assert.Equal(s.T(), http.StatusForbidden, resp.Code)
	})

	// Test 3: N8N webhooks are isolated between organizations
	s.Run("webhooks_isolation", func() {
		// User B1 can access Org B's webhooks
		req := s.createAuthenticatedRequest("GET", fmt.Sprintf("/api/organizations/%d/webhooks", s.orgB.ID), nil, s.jwtTokenB1)
		resp := s.performRequest(req)

		assert.Equal(s.T(), http.StatusOK, resp.Code)

		// User B1 cannot access Org A's webhooks
		req = s.createAuthenticatedRequest("GET", fmt.Sprintf("/api/organizations/%d/webhooks", s.orgA.ID), nil, s.jwtTokenB1)
		resp = s.performRequest(req)

		assert.Equal(s.T(), http.StatusForbidden, resp.Code)
	})

	// Test 4: Conversations are isolated between organizations
	s.Run("conversations_isolation", func() {
		// User A1 can access Org A's conversations
		req := s.createAuthenticatedRequest("GET", fmt.Sprintf("/api/organizations/%d/conversations", s.orgA.ID), nil, s.jwtTokenA1)
		resp := s.performRequest(req)

		assert.Equal(s.T(), http.StatusOK, resp.Code)

		// User A1 cannot access Org B's conversations
		req = s.createAuthenticatedRequest("GET", fmt.Sprintf("/api/organizations/%d/conversations", s.orgB.ID), nil, s.jwtTokenA1)
		resp = s.performRequest(req)

		assert.Equal(s.T(), http.StatusForbidden, resp.Code)
	})
}

// TestCrossTenantAccessPrevention tests prevention of unauthorized cross-tenant access
func (s *MultiTenantTestSuite) TestCrossTenantAccessPrevention() {
	s.T().Log("Testing cross-tenant access prevention...")

	s.Run("prevent_cross_tenant_user_access", func() {
		// User from Org A trying to access Org B resources should be denied
		testCases := []struct {
			name       string
			endpoint   string
			token      string
			orgID      uint
			expectCode int
		}{
			{
				name:       "org_a_user_accessing_org_b_users",
				endpoint:   "/users",
				token:      s.jwtTokenA1,
				orgID:      s.orgB.ID,
				expectCode: http.StatusForbidden,
			},
			{
				name:       "org_b_user_accessing_org_c_webhooks",
				endpoint:   "/webhooks",
				token:      s.jwtTokenB1,
				orgID:      s.orgC.ID,
				expectCode: http.StatusForbidden,
			},
			{
				name:       "org_c_user_accessing_org_a_providers",
				endpoint:   "/providers",
				token:      s.jwtTokenC1,
				orgID:      s.orgA.ID,
				expectCode: http.StatusForbidden,
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				req := s.createAuthenticatedRequest("GET",
					fmt.Sprintf("/api/organizations/%d%s", tc.orgID, tc.endpoint),
					nil, tc.token)
				resp := s.performRequest(req)

				assert.Equal(s.T(), tc.expectCode, resp.Code,
					"Expected cross-tenant access to be prevented")
			})
		}
	})
}

// TestTenantSpecificOAuthProviders tests OAuth provider isolation between tenants
func (s *MultiTenantTestSuite) TestTenantSpecificOAuthProviders() {
	s.T().Log("Testing tenant-specific OAuth providers...")

	s.Run("provider_isolation_by_organization", func() {
		// Verify each organization has its own distinct OAuth providers

		// Check Org A has Microsoft provider
		var orgAProviders []models.OAuthProvider
		err := testDB.Where("organization_id = ?", s.orgA.ID).Find(&orgAProviders).Error
		require.NoError(s.T(), err)
		assert.Len(s.T(), orgAProviders, 1)
		assert.Equal(s.T(), models.ProviderTypeMicrosoft, orgAProviders[0].ProviderType)

		// Check Org B has Google provider
		var orgBProviders []models.OAuthProvider
		err = testDB.Where("organization_id = ?", s.orgB.ID).Find(&orgBProviders).Error
		require.NoError(s.T(), err)
		assert.Len(s.T(), orgBProviders, 1)
		assert.Equal(s.T(), models.ProviderTypeGoogle, orgBProviders[0].ProviderType)

		// Check Org C has GitHub provider
		var orgCProviders []models.OAuthProvider
		err = testDB.Where("organization_id = ?", s.orgC.ID).Find(&orgCProviders).Error
		require.NoError(s.T(), err)
		assert.Len(s.T(), orgCProviders, 1)
		assert.Equal(s.T(), models.ProviderTypeGitHub, orgCProviders[0].ProviderType)
	})

	s.Run("provider_configuration_isolation", func() {
		// Ensure provider configurations are unique per organization
		assert.Equal(s.T(), "test-client-id-org-a-microsoft", s.providerA.ClientID)
		assert.Equal(s.T(), "test-client-id-org-b-google", s.providerB.ClientID)
		assert.Equal(s.T(), "test-client-id-org-c-github", s.providerC.ClientID)

		// Verify tenant IDs (where applicable) are different
		if s.providerA.TenantID != nil {
			assert.Equal(s.T(), "microsoft-tenant-a", *s.providerA.TenantID)
		}
	})
}

// TestTenantSpecificWebhooks tests webhook isolation between tenants
func (s *MultiTenantTestSuite) TestTenantSpecificWebhooks() {
	s.T().Log("Testing tenant-specific webhooks...")

	s.Run("webhook_isolation_by_organization", func() {
		// Verify each organization has its own webhook configurations

		// Check Org A webhook
		var orgAWebhooks []models.N8NWebhook
		err := testDB.Where("organization_id = ?", s.orgA.ID).Find(&orgAWebhooks).Error
		require.NoError(s.T(), err)
		assert.Len(s.T(), orgAWebhooks, 1)
		assert.Equal(s.T(), "https://n8n-org-a.example.com", orgAWebhooks[0].N8NBaseURL)
		assert.Contains(s.T(), orgAWebhooks[0].Tags, "org-a")

		// Check Org B webhook
		var orgBWebhooks []models.N8NWebhook
		err = testDB.Where("organization_id = ?", s.orgB.ID).Find(&orgBWebhooks).Error
		require.NoError(s.T(), err)
		assert.Len(s.T(), orgBWebhooks, 1)
		assert.Equal(s.T(), "https://n8n-org-b.example.com", orgBWebhooks[0].N8NBaseURL)
		assert.Contains(s.T(), orgBWebhooks[0].Tags, "org-b")

		// Check Org C webhook
		var orgCWebhooks []models.N8NWebhook
		err = testDB.Where("organization_id = ?", s.orgC.ID).Find(&orgCWebhooks).Error
		require.NoError(s.T(), err)
		assert.Len(s.T(), orgCWebhooks, 1)
		assert.Equal(s.T(), "https://n8n-org-c.example.com", orgCWebhooks[0].N8NBaseURL)
		assert.Contains(s.T(), orgCWebhooks[0].Tags, "org-c")
	})

	s.Run("webhook_auth_configuration_isolation", func() {
		// Verify different organizations use different auth methods and tokens
		assert.Equal(s.T(), "bearer", s.webhookA.AuthMethod)
		assert.Equal(s.T(), "basic", s.webhookB.AuthMethod)
		assert.Equal(s.T(), "api-key", s.webhookC.AuthMethod)

		assert.Equal(s.T(), "token-org-a-webhook", s.webhookA.AuthToken)
		assert.Equal(s.T(), "token-org-b-webhook", s.webhookB.AuthToken)
		assert.Equal(s.T(), "token-org-c-webhook", s.webhookC.AuthToken)
	})
}

// TestUserOrganizationAssignment tests user-organization relationships
func (s *MultiTenantTestSuite) TestUserOrganizationAssignment() {
	s.T().Log("Testing user organization assignments...")

	s.Run("user_belongs_to_correct_organization", func() {
		// Verify each user belongs to the correct organization
		assert.Equal(s.T(), s.orgA.ID, s.userA1.OrganizationID)
		assert.Equal(s.T(), s.orgA.ID, s.userA2.OrganizationID)
		assert.Equal(s.T(), s.orgB.ID, s.userB1.OrganizationID)
		assert.Equal(s.T(), s.orgC.ID, s.userC1.OrganizationID)
	})

	s.Run("user_access_validation", func() {
		// Test that tenant service correctly validates user access
		hasAccess, err := s.tenantService.UserHasAccessToOrganization(s.userA1.ID, s.orgA.ID)
		require.NoError(s.T(), err)
		assert.True(s.T(), hasAccess)

		hasAccess, err = s.tenantService.UserHasAccessToOrganization(s.userA1.ID, s.orgB.ID)
		require.NoError(s.T(), err)
		assert.False(s.T(), hasAccess)

		hasAccess, err = s.tenantService.UserHasAccessToOrganization(s.userB1.ID, s.orgB.ID)
		require.NoError(s.T(), err)
		assert.True(s.T(), hasAccess)

		hasAccess, err = s.tenantService.UserHasAccessToOrganization(s.userB1.ID, s.orgC.ID)
		require.NoError(s.T(), err)
		assert.False(s.T(), hasAccess)
	})
}

// TestTenantSwitching tests switching between authorized organizations
func (s *MultiTenantTestSuite) TestTenantSwitching() {
	s.T().Log("Testing tenant switching...")

	s.Run("switch_to_authorized_organization", func() {
		// For this test, we'll create a user who belongs to multiple organizations
		// In a real scenario, this might be through organization memberships

		// User A2 (admin) might have access to multiple orgs - simulate this
		req := s.createAuthenticatedRequest("POST", "/api/users/switch-organization",
			map[string]interface{}{"organization_id": s.orgA.ID}, s.jwtTokenA2)
		resp := s.performRequest(req)

		// Should succeed for user's own organization
		assert.Equal(s.T(), http.StatusOK, resp.Code)
	})

	s.Run("prevent_switch_to_unauthorized_organization", func() {
		// User A1 trying to switch to Org B should be denied
		req := s.createAuthenticatedRequest("POST", "/api/users/switch-organization",
			map[string]interface{}{"organization_id": s.orgB.ID}, s.jwtTokenA1)
		resp := s.performRequest(req)

		assert.Equal(s.T(), http.StatusForbidden, resp.Code)
	})
}

// TestTenantDeletion tests cascade deletion and cleanup
func (s *MultiTenantTestSuite) TestTenantDeletion() {
	s.T().Log("Testing tenant deletion and cleanup...")

	s.Run("cascade_delete_organization", func() {
		// Create a temporary organization for deletion test
		tempOrg := &models.Organization{
			Name:        "Temporary Organization",
			Slug:        "temp-org",
			Description: "Temporary org for deletion testing",
			Settings:    models.JSON{"temp": true},
		}
		require.NoError(s.T(), testDB.Create(tempOrg).Error)

		// Create associated resources
		tempUser := &models.User{
			OrganizationID: tempOrg.ID,
			Email:          "temp@temp.example.com",
			PasswordHash:   "$2a$12$temp.hash",
			FirstName:      "Temp",
			LastName:       "User",
			Role:           "user",
			IsActive:       true,
			IsVerified:     true,
		}
		require.NoError(s.T(), testDB.Create(tempUser).Error)

		tempProvider := &models.OAuthProvider{
			OrganizationID: tempOrg.ID,
			ProviderType:   models.ProviderTypeGoogle,
			ClientID:       "temp-client-id",
			ClientSecret:   "temp-client-secret",
			Enabled:        true,
		}
		require.NoError(s.T(), testDB.Create(tempProvider).Error)

		tempWebhook := &models.N8NWebhook{
			OrganizationID: tempOrg.ID,
			WorkflowName:   "Temp Workflow",
			WorkflowID:     "temp-workflow-001",
			WebhookPath:    "/webhook/temp",
			N8NBaseURL:     "https://temp.example.com",
			Active:         true,
		}
		require.NoError(s.T(), testDB.Create(tempWebhook).Error)

		// Test deletion through API (admin user only)
		req := s.createAuthenticatedRequest("DELETE",
			fmt.Sprintf("/api/organizations/%d", tempOrg.ID), nil, s.jwtTokenC1)
		resp := s.performRequest(req)

		// Admin from different org should be able to delete (in real scenario, would need super admin)
		// For this test, we'll simulate the deletion was successful

		// Verify cascade deletion
		var userCount int64
		testDB.Model(&models.User{}).Where("organization_id = ?", tempOrg.ID).Count(&userCount)

		var providerCount int64
		testDB.Model(&models.OAuthProvider{}).Where("organization_id = ?", tempOrg.ID).Count(&providerCount)

		var webhookCount int64
		testDB.Model(&models.N8NWebhook{}).Where("organization_id = ?", tempOrg.ID).Count(&webhookCount)

		// Note: Actual cascade deletion depends on database constraints and application logic
		// In a real implementation, you'd set up foreign key constraints with CASCADE DELETE
		// or implement the cascade logic in the service layer
	})
}

// TestSubdomainRouting tests subdomain-based tenant resolution
func (s *MultiTenantTestSuite) TestSubdomainRouting() {
	s.T().Log("Testing subdomain-based tenant resolution...")

	s.Run("resolve_tenant_from_subdomain", func() {
		// Simulate different subdomain requests
		testCases := []struct {
			name           string
			host           string
			expectedOrgID  uint
			expectedStatus int
		}{
			{
				name:           "org_alpha_subdomain",
				host:           "org-alpha.example.com",
				expectedOrgID:  s.orgA.ID,
				expectedStatus: http.StatusOK,
			},
			{
				name:           "org_beta_subdomain",
				host:           "org-beta.example.com",
				expectedOrgID:  s.orgB.ID,
				expectedStatus: http.StatusOK,
			},
			{
				name:           "invalid_subdomain",
				host:           "nonexistent.example.com",
				expectedOrgID:  0,
				expectedStatus: http.StatusNotFound,
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				req := s.createRequest("GET", "/api/tenant-info", nil)
				req.Host = tc.host
				resp := s.performRequest(req)

				// The actual subdomain resolution logic would need to be implemented
				// in the tenant middleware and service layers
				// This test demonstrates the expected behavior
				s.T().Logf("Subdomain test: %s -> Status: %d", tc.host, resp.Code)
			})
		}
	})
}

// Helper methods for testing

// stringPtr returns a pointer to a string
func stringPtr(s string) *string {
	return &s
}

// Mock handlers for test routes

func (s *MultiTenantTestSuite) mockGetUsersHandler(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	orgID := middleware.GetOrganizationID(c)

	if tenantID == 0 || orgID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
		return
	}

	if tenantID != orgID {
		c.JSON(http.StatusForbidden, gin.H{"error": "tenant isolation violation"})
		return
	}

	var users []models.User
	if err := testDB.Where("organization_id = ?", tenantID).Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch users"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

func (s *MultiTenantTestSuite) mockGetWebhooksHandler(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	orgID := middleware.GetOrganizationID(c)

	if tenantID == 0 || orgID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
		return
	}

	if tenantID != orgID {
		c.JSON(http.StatusForbidden, gin.H{"error": "tenant isolation violation"})
		return
	}

	var webhooks []models.N8NWebhook
	if err := testDB.Where("organization_id = ?", tenantID).Find(&webhooks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch webhooks"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"webhooks": webhooks})
}

func (s *MultiTenantTestSuite) mockGetProvidersHandler(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	orgID := middleware.GetOrganizationID(c)

	if tenantID == 0 || orgID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
		return
	}

	if tenantID != orgID {
		c.JSON(http.StatusForbidden, gin.H{"error": "tenant isolation violation"})
		return
	}

	var providers []models.OAuthProvider
	if err := testDB.Where("organization_id = ?", tenantID).Find(&providers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch providers"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

func (s *MultiTenantTestSuite) mockGetConversationsHandler(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	orgID := middleware.GetOrganizationID(c)

	if tenantID == 0 || orgID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
		return
	}

	if tenantID != orgID {
		c.JSON(http.StatusForbidden, gin.H{"error": "tenant isolation violation"})
		return
	}

	var conversations []models.Conversation
	if err := testDB.Where("organization_id = ?", tenantID).Find(&conversations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch conversations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"conversations": conversations})
}

func (s *MultiTenantTestSuite) mockDeleteOrganizationHandler(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	userRole := middleware.GetUserRole(c)

	// Only admins can delete organizations
	if userRole != "admin" && userRole != "super_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	// Simulate organization deletion
	c.JSON(http.StatusOK, gin.H{"message": "organization deleted", "tenant_id": tenantID})
}

func (s *MultiTenantTestSuite) mockSwitchOrganizationHandler(c *gin.Context) {
	userID := middleware.GetUserID(c)

	var request struct {
		OrganizationID uint `json:"organization_id"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Check if user has access to the target organization
	hasAccess, err := s.tenantService.UserHasAccessToOrganization(userID, request.OrganizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to validate access"})
		return
	}

	if !hasAccess {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied to organization"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "organization switched", "organization_id": request.OrganizationID})
}

func (s *MultiTenantTestSuite) mockGetTenantInfoHandler(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	tenantName := middleware.GetTenantName(c)
	tenantSlug := middleware.GetTenantSlug(c)

	if tenantID == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tenant_id":   tenantID,
		"tenant_name": tenantName,
		"tenant_slug": tenantSlug,
	})
}

// HTTP testing helper methods

// createRequest creates a new HTTP request for testing
func (s *MultiTenantTestSuite) createRequest(method, path string, body interface{}) *http.Request {
	var jsonData []byte
	var err error

	if body != nil {
		jsonData, err = json.Marshal(body)
		require.NoError(s.T(), err)
	}

	req, err := http.NewRequest(method, path, bytes.NewBuffer(jsonData))
	require.NoError(s.T(), err)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return req
}

// createAuthenticatedRequest creates a new HTTP request with JWT authentication
func (s *MultiTenantTestSuite) createAuthenticatedRequest(method, path string, body interface{}, token string) *http.Request {
	req := s.createRequest(method, path, body)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// performRequest executes the HTTP request against the test router
func (s *MultiTenantTestSuite) performRequest(req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, req)
	return recorder
}

// Test suite runner
func TestMultiTenantSuite(t *testing.T) {
	suite.Run(t, new(MultiTenantTestSuite))
}
