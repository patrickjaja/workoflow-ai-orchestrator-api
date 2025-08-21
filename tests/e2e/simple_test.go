package e2e_test

import (
	"testing"
	"time"

	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatabaseConnection tests basic database connectivity
func TestDatabaseConnection(t *testing.T) {
	// This test runs with the initialized testDB from TestMain
	require.NotNil(t, testDB, "Database should be initialized")
	
	// Test we can query the database
	var count int64
	err := testDB.Model(&models.Organization{}).Count(&count).Error
	assert.NoError(t, err, "Should be able to query organizations table")
}

// TestCreateOrganization tests creating an organization
func TestCreateOrganization(t *testing.T) {
	org := &models.Organization{
		Name: "Test Organization",
		Slug: "test-org-" + uuid.New().String()[:8],
	}
	
	err := testDB.Create(org).Error
	require.NoError(t, err, "Should create organization")
	
	// Verify it was created
	var retrieved models.Organization
	err = testDB.Where("id = ?", org.ID).First(&retrieved).Error
	require.NoError(t, err, "Should retrieve organization")
	assert.Equal(t, org.Name, retrieved.Name)
	
	// Cleanup
	testDB.Delete(org)
}

// TestMultiTenantOAuthProviders tests multi-tenant OAuth provider isolation
func TestMultiTenantOAuthProviders(t *testing.T) {
	// Create two organizations
	org1 := &models.Organization{
		Name: "Organization A",
		Slug: "org-a-" + uuid.New().String()[:8],
	}
	org2 := &models.Organization{
		Name: "Organization B",
		Slug: "org-b-" + uuid.New().String()[:8],
	}
	
	err := testDB.Create(org1).Error
	require.NoError(t, err)
	err = testDB.Create(org2).Error
	require.NoError(t, err)
	
	// Create OAuth providers for each org
	provider1 := &models.OAuthProvider{
		OrganizationID: org1.ID,
		ProviderType:   models.ProviderTypeMicrosoft,
		ClientID:       "encrypted-client-a",
		ClientSecret:   "encrypted-secret-a",
		Enabled:        true,
	}
	provider2 := &models.OAuthProvider{
		OrganizationID: org2.ID,
		ProviderType:   models.ProviderTypeMicrosoft,
		ClientID:       "encrypted-client-b",
		ClientSecret:   "encrypted-secret-b",
		Enabled:        true,
	}
	
	err = testDB.Create(provider1).Error
	require.NoError(t, err)
	err = testDB.Create(provider2).Error
	require.NoError(t, err)
	
	// Verify each org can only see their own provider
	var providers []models.OAuthProvider
	err = testDB.Where("organization_id = ?", org1.ID).Find(&providers).Error
	require.NoError(t, err)
	assert.Len(t, providers, 1)
	assert.Equal(t, "encrypted-client-a", providers[0].ClientID)
	
	err = testDB.Where("organization_id = ?", org2.ID).Find(&providers).Error
	require.NoError(t, err)
	assert.Len(t, providers, 1)
	assert.Equal(t, "encrypted-client-b", providers[0].ClientID)
	
	// Cleanup
	testDB.Delete(provider1)
	testDB.Delete(provider2)
	testDB.Delete(org1)
	testDB.Delete(org2)
}

// TestUserTokenStorage tests storing and retrieving user tokens
func TestUserTokenStorage(t *testing.T) {
	// Create org and user
	org := &models.Organization{
		Name: "Test Org",
		Slug: "test-org-" + uuid.New().String()[:8],
	}
	err := testDB.Create(org).Error
	require.NoError(t, err)
	
	user := &models.User{
		OrganizationID: org.ID,
		Email:          "testuser@example.com",
		FirstName:      "Test",
		LastName:       "User",
		Role:           "user",
	}
	err = testDB.Create(user).Error
	require.NoError(t, err)
	
	provider := &models.OAuthProvider{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		ProviderType:   models.ProviderTypeMicrosoft,
		ClientID:       "test-client",
		ClientSecret:   "test-secret",
		Enabled:        true,
	}
	err = testDB.Create(provider).Error
	require.NoError(t, err)
	
	// Create token
	refreshToken := "test-refresh"
	expiresAt := time.Now().Add(time.Hour)
	token := &models.UserToken{
		ID:           uuid.New(),
		UserID:       user.ID,
		ProviderID:   provider.ID,
		AccessToken:  "encrypted-access-token",
		RefreshToken: &refreshToken,
		ExpiresAt:    &expiresAt,
	}
	err = testDB.Create(token).Error
	require.NoError(t, err)
	
	// Verify token can be retrieved
	var retrieved models.UserToken
	err = testDB.Where("user_id = ? AND provider_id = ?", user.ID, provider.ID).First(&retrieved).Error
	require.NoError(t, err)
	assert.Equal(t, token.AccessToken, retrieved.AccessToken)
	assert.False(t, retrieved.IsExpired())
	
	// Cleanup
	testDB.Delete(token)
	testDB.Delete(provider)
	testDB.Delete(user)
	testDB.Delete(org)
}

// TestN8NWebhookConfiguration tests N8N webhook setup
func TestN8NWebhookConfiguration(t *testing.T) {
	org := &models.Organization{
		ID:   uuid.New(),
		Name: "Test Org",
	}
	err := testDB.Create(org).Error
	require.NoError(t, err)
	
	// Create default webhook
	webhook := &models.N8NWebhook{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Name:           "Default Webhook",
		WebhookURL:     "http://n8n:5678/webhook/test",
		IsDefault:      true,
		Enabled:        true,
	}
	err = testDB.Create(webhook).Error
	require.NoError(t, err)
	
	// Verify default webhook
	var retrieved models.N8NWebhook
	err = testDB.Where("organization_id = ? AND is_default = ?", org.ID, true).First(&retrieved).Error
	require.NoError(t, err)
	assert.Equal(t, webhook.WebhookURL, retrieved.WebhookURL)
	
	// Try to create another default webhook (should update the first one)
	webhook2 := &models.N8NWebhook{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Name:           "Second Webhook",
		WebhookURL:     "http://n8n:5678/webhook/test2",
		IsDefault:      true,
		Enabled:        true,
	}
	err = testDB.Create(webhook2).Error
	require.NoError(t, err)
	
	// Verify only one default
	var count int64
	err = testDB.Model(&models.N8NWebhook{}).Where("organization_id = ? AND is_default = ?", org.ID, true).Count(&count).Error
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "Should only have one default webhook")
	
	// Cleanup
	testDB.Delete(webhook)
	testDB.Delete(webhook2)
	testDB.Delete(org)
}

// TestConversationManagement tests conversation and message storage
func TestConversationManagement(t *testing.T) {
	// Create org and user
	org := &models.Organization{
		ID:   uuid.New(),
		Name: "Test Org",
	}
	err := testDB.Create(org).Error
	require.NoError(t, err)
	
	user := &models.User{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		ExternalID:     "user-123",
		ChannelType:    models.ChannelTypeTeams,
	}
	err = testDB.Create(user).Error
	require.NoError(t, err)
	
	// Create conversation
	conversation := &models.Conversation{
		ID:     uuid.New(),
		UserID: user.ID,
		Status: models.ConversationStatusActive,
	}
	err = testDB.Create(conversation).Error
	require.NoError(t, err)
	
	// Add messages
	messages := []models.Message{
		{
			ID:             uuid.New(),
			ConversationID: conversation.ID,
			Role:           "user",
			Content:        "Hello AI",
		},
		{
			ID:             uuid.New(),
			ConversationID: conversation.ID,
			Role:           "assistant",
			Content:        "Hello! How can I help you today?",
		},
	}
	
	for _, msg := range messages {
		err = testDB.Create(&msg).Error
		require.NoError(t, err)
	}
	
	// Verify messages
	var retrievedMessages []models.Message
	err = testDB.Where("conversation_id = ?", conversation.ID).Order("created_at").Find(&retrievedMessages).Error
	require.NoError(t, err)
	assert.Len(t, retrievedMessages, 2)
	assert.Equal(t, "user", retrievedMessages[0].Role)
	assert.Equal(t, "assistant", retrievedMessages[1].Role)
	
	// Cleanup
	testDB.Where("conversation_id = ?", conversation.ID).Delete(&models.Message{})
	testDB.Delete(conversation)
	testDB.Delete(user)
	testDB.Delete(org)
}