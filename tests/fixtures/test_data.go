package fixtures

import (
	"time"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// TestOrganizations returns test organization fixtures
func TestOrganizations() []models.Organization {
	return []models.Organization{
		{
			ID:          1,
			Name:        "Test Organization Alpha",
			Slug:        "test-org-alpha",
			Description: "Primary test organization",
			Settings:    models.JSON{"theme": "dark", "notifications": true},
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		},
		{
			ID:          2,
			Name:        "Test Organization Beta",
			Slug:        "test-org-beta",
			Description: "Secondary test organization for multi-tenant testing",
			Settings:    models.JSON{"theme": "light", "notifications": false},
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		},
		{
			ID:          3,
			Name:        "Test Organization Gamma",
			Slug:        "test-org-gamma",
			Description: "Tertiary test organization for isolation testing",
			Settings:    models.JSON{"theme": "auto", "notifications": true},
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		},
	}
}

// TestUsers returns test user fixtures
func TestUsers() []models.User {
	// Generate test password hash
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testPassword123!"), bcrypt.DefaultCost)
	
	return []models.User{
		{
			ID:             1,
			Email:          "admin@test-org-alpha.com",
			PasswordHash:   string(hashedPassword),
			FirstName:      "Admin",
			LastName:       "Alpha",
			Role:           "admin",
			IsActive:       true,
			IsVerified:     true,
			OrganizationID: 1,
			Settings:       models.JSON{"language": "en", "timezone": "UTC"},
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
		{
			ID:             2,
			Email:          "user@test-org-alpha.com",
			PasswordHash:   string(hashedPassword),
			FirstName:      "User",
			LastName:       "Alpha",
			Role:           "user",
			IsActive:       true,
			IsVerified:     true,
			OrganizationID: 1,
			Settings:       models.JSON{"language": "en", "timezone": "America/New_York"},
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
		{
			ID:             3,
			Email:          "admin@test-org-beta.com",
			PasswordHash:   string(hashedPassword),
			FirstName:      "Admin",
			LastName:       "Beta",
			Role:           "admin",
			IsActive:       true,
			IsVerified:     true,
			OrganizationID: 2,
			Settings:       models.JSON{"language": "en", "timezone": "Europe/London"},
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
		{
			ID:             4,
			Email:          "viewer@test-org-alpha.com",
			PasswordHash:   string(hashedPassword),
			FirstName:      "Viewer",
			LastName:       "Alpha",
			Role:           "viewer",
			IsActive:       true,
			IsVerified:     true,
			OrganizationID: 1,
			Settings:       models.JSON{"language": "en", "timezone": "UTC"},
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
		{
			ID:             5,
			Email:          "inactive@test-org-alpha.com",
			PasswordHash:   string(hashedPassword),
			FirstName:      "Inactive",
			LastName:       "User",
			Role:           "user",
			IsActive:       false,
			IsVerified:     false,
			OrganizationID: 1,
			Settings:       models.JSON{"language": "en", "timezone": "UTC"},
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
	}
}

// TestOAuthProviders returns test OAuth provider fixtures
func TestOAuthProviders() []models.OAuthProvider {
	return []models.OAuthProvider{
		{
			ID:             1,
			OrganizationID: 1,
			ProviderType:   "microsoft",
			ClientID:       "encrypted_client_id_alpha_microsoft",
			ClientSecret:   "encrypted_client_secret_alpha_microsoft",
			TenantID:       stringPtr("alpha-tenant-id"),
			AdditionalConfig: models.JSON{
				"scopes": []string{"User.Read", "Files.Read", "Sites.Read.All"},
			},
			Enabled:   true,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			ID:             2,
			OrganizationID: 1,
			ProviderType:   "atlassian",
			ClientID:       "encrypted_client_id_alpha_atlassian",
			ClientSecret:   "encrypted_client_secret_alpha_atlassian",
			AdditionalConfig: models.JSON{
				"cloud_id": "alpha-cloud-id",
				"scopes":   []string{"read:jira-work", "write:jira-work"},
			},
			Enabled:   true,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			ID:             3,
			OrganizationID: 2,
			ProviderType:   "microsoft",
			ClientID:       "encrypted_client_id_beta_microsoft",
			ClientSecret:   "encrypted_client_secret_beta_microsoft",
			TenantID:       stringPtr("beta-tenant-id"),
			AdditionalConfig: models.JSON{
				"scopes": []string{"User.Read", "Mail.Read"},
			},
			Enabled:   true,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			ID:             4,
			OrganizationID: 1,
			ProviderType:   "slack",
			ClientID:       "encrypted_client_id_alpha_slack",
			ClientSecret:   "encrypted_client_secret_alpha_slack",
			AdditionalConfig: models.JSON{
				"workspace_id": "alpha-workspace",
				"scopes":       []string{"channels:read", "chat:write"},
			},
			Enabled:   false, // Disabled provider for testing
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
	}
}

// TestN8NWebhooks returns test webhook fixtures
func TestN8NWebhooks() []models.N8NWebhook {
	return []models.N8NWebhook{
		{
			ID:             1,
			WorkflowName:   "test_workflow_alpha",
			WorkflowID:     "wf_alpha_123",
			WebhookPath:    "/webhook/test-alpha",
			N8NBaseURL:     "http://n8n-mock",
			OrganizationID: 1,
			Active:         true,
			AuthMethod:     "bearer",
			AuthToken:      "encrypted_token_alpha",
			Description:    "Primary test webhook for organization alpha",
			Tags:           []string{"test", "primary", "alpha"},
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
		{
			ID:             2,
			WorkflowName:   "jira_integration",
			WorkflowID:     "wf_jira_456",
			WebhookPath:    "/webhook/jira",
			N8NBaseURL:     "http://n8n-mock",
			OrganizationID: 1,
			Active:         true,
			AuthMethod:     "header",
			AuthToken:      "encrypted_token_jira",
			AuthHeader:     stringPtr("X-API-Key"),
			Description:    "Jira integration webhook",
			Tags:           []string{"jira", "integration"},
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
		{
			ID:             3,
			WorkflowName:   "test_workflow_beta",
			WorkflowID:     "wf_beta_789",
			WebhookPath:    "/webhook/test-beta",
			N8NBaseURL:     "http://n8n-mock",
			OrganizationID: 2,
			Active:         true,
			AuthMethod:     "basic",
			AuthToken:      "encrypted_basic_auth_beta",
			Description:    "Primary test webhook for organization beta",
			Tags:           []string{"test", "beta"},
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
		{
			ID:             4,
			WorkflowName:   "inactive_workflow",
			WorkflowID:     "wf_inactive_001",
			WebhookPath:    "/webhook/inactive",
			N8NBaseURL:     "http://n8n-mock",
			OrganizationID: 1,
			Active:         false, // Inactive webhook for testing
			AuthMethod:     "bearer",
			AuthToken:      "encrypted_token_inactive",
			Description:    "Inactive webhook for testing",
			Tags:           []string{"test", "inactive"},
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
	}
}

// TestUserTokens returns test user token fixtures
func TestUserTokens() []models.UserToken {
	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	expiredAt := time.Now().UTC().Add(-24 * time.Hour)
	
	return []models.UserToken{
		{
			ID:           1,
			UserID:       1, // admin@test-org-alpha.com
			ProviderID:   1, // microsoft provider for org alpha
			AccessToken:  "encrypted_access_token_admin_microsoft",
			RefreshToken: stringPtr("encrypted_refresh_token_admin_microsoft"),
			ExpiresAt:    &expiresAt,
			Scopes:       []string{"User.Read", "Files.Read", "Sites.Read.All"},
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
		},
		{
			ID:           2,
			UserID:       1, // admin@test-org-alpha.com
			ProviderID:   2, // atlassian provider for org alpha
			AccessToken:  "encrypted_access_token_admin_atlassian",
			RefreshToken: stringPtr("encrypted_refresh_token_admin_atlassian"),
			ExpiresAt:    &expiresAt,
			Scopes:       []string{"read:jira-work", "write:jira-work"},
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
		},
		{
			ID:           3,
			UserID:       2, // user@test-org-alpha.com
			ProviderID:   1, // microsoft provider for org alpha
			AccessToken:  "encrypted_access_token_user_microsoft",
			RefreshToken: stringPtr("encrypted_refresh_token_user_microsoft"),
			ExpiresAt:    &expiredAt, // Expired token for testing refresh
			Scopes:       []string{"User.Read"},
			CreatedAt:    time.Now().UTC().Add(-48 * time.Hour),
			UpdatedAt:    time.Now().UTC().Add(-24 * time.Hour),
		},
		{
			ID:           4,
			UserID:       3, // admin@test-org-beta.com
			ProviderID:   3, // microsoft provider for org beta
			AccessToken:  "encrypted_access_token_beta_microsoft",
			RefreshToken: stringPtr("encrypted_refresh_token_beta_microsoft"),
			ExpiresAt:    &expiresAt,
			Scopes:       []string{"User.Read", "Mail.Read"},
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
		},
	}
}

// TestConversations returns test conversation fixtures
func TestConversations() []models.Conversation {
	return []models.Conversation{
		{
			ID:            1,
			UserID:        1, // admin@test-org-alpha.com
			Status:        models.ConversationStatusActive,
			MessageCount:  5,
			LastMessageAt: timePtr(time.Now().UTC().Add(-1 * time.Hour)),
			CreatedAt:     time.Now().UTC().Add(-24 * time.Hour),
			UpdatedAt:     time.Now().UTC().Add(-1 * time.Hour),
		},
		{
			ID:            2,
			UserID:        2, // user@test-org-alpha.com
			Status:        models.ConversationStatusActive,
			MessageCount:  2,
			LastMessageAt: timePtr(time.Now().UTC().Add(-30 * time.Minute)),
			CreatedAt:     time.Now().UTC().Add(-2 * time.Hour),
			UpdatedAt:     time.Now().UTC().Add(-30 * time.Minute),
		},
		{
			ID:            3,
			UserID:        1, // admin@test-org-alpha.com
			Status:        models.ConversationStatusArchived,
			MessageCount:  10,
			LastMessageAt: timePtr(time.Now().UTC().Add(-7 * 24 * time.Hour)),
			CreatedAt:     time.Now().UTC().Add(-30 * 24 * time.Hour),
			UpdatedAt:     time.Now().UTC().Add(-7 * 24 * time.Hour),
		},
		{
			ID:            4,
			UserID:        3, // admin@test-org-beta.com
			Status:        models.ConversationStatusActive,
			MessageCount:  1,
			LastMessageAt: timePtr(time.Now().UTC()),
			CreatedAt:     time.Now().UTC(),
			UpdatedAt:     time.Now().UTC(),
		},
	}
}

// TestMessages returns test message fixtures
func TestMessages() []models.Message {
	return []models.Message{
		{
			ID:             1,
			ConversationID: 1,
			Role:           "user",
			Content:        "Search for vacation policy in SharePoint",
			CreatedAt:      time.Now().UTC().Add(-24 * time.Hour),
		},
		{
			ID:             2,
			ConversationID: 1,
			Role:           "assistant",
			Content:        "I'll search for the vacation policy in SharePoint. Let me access your SharePoint documents.",
			CreatedAt:      time.Now().UTC().Add(-24 * time.Hour).Add(30 * time.Second),
		},
		{
			ID:             3,
			ConversationID: 1,
			Role:           "user",
			Content:        "What about sick leave policy?",
			CreatedAt:      time.Now().UTC().Add(-23 * time.Hour),
		},
		{
			ID:             4,
			ConversationID: 1,
			Role:           "assistant",
			Content:        "Let me search for the sick leave policy as well.",
			CreatedAt:      time.Now().UTC().Add(-23 * time.Hour).Add(15 * time.Second),
		},
		{
			ID:             5,
			ConversationID: 1,
			Role:           "user",
			Content:        "Thank you!",
			CreatedAt:      time.Now().UTC().Add(-1 * time.Hour),
		},
		{
			ID:             6,
			ConversationID: 2,
			Role:           "user",
			Content:        "What is the weather today?",
			CreatedAt:      time.Now().UTC().Add(-2 * time.Hour),
		},
		{
			ID:             7,
			ConversationID: 2,
			Role:           "assistant",
			Content:        "I'm an AI assistant focused on workplace tools integration. I don't have access to weather information. However, I can help you with tasks related to SharePoint, Jira, and other workplace tools.",
			CreatedAt:      time.Now().UTC().Add(-30 * time.Minute),
		},
	}
}

// TestSessions returns test session fixtures
func TestSessions() []models.Session {
	return []models.Session{
		{
			ID:        1,
			UserID:    1, // admin@test-org-alpha.com
			Token:     "test_session_token_admin_alpha",
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			ID:        2,
			UserID:    2, // user@test-org-alpha.com
			Token:     "test_session_token_user_alpha",
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			ID:        3,
			UserID:    3, // admin@test-org-beta.com
			Token:     "test_session_token_admin_beta",
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			ID:        4,
			UserID:    1, // admin@test-org-alpha.com
			Token:     "expired_session_token",
			ExpiresAt: time.Now().UTC().Add(-1 * time.Hour), // Expired session
			CreatedAt: time.Now().UTC().Add(-25 * time.Hour),
			UpdatedAt: time.Now().UTC().Add(-1 * time.Hour),
		},
	}
}

// Helper functions

func stringPtr(s string) *string {
	return &s
}

func timePtr(t time.Time) *time.Time {
	return &t
}

// SeedDatabase seeds the database with test fixtures
func SeedDatabase(db interface{}) error {
	// This function would be implemented to insert all fixtures into the database
	// The implementation depends on your database interface
	return nil
}