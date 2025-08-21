package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"gorm.io/gorm"
)

// TestHelpers provides utilities for E2E tests
type TestHelpers struct {
	BaseURL      string
	DB           *gorm.DB
	Organizations map[string]*models.Organization
	Users        map[string]*models.User
	Providers    map[string]*models.OAuthProvider
	Webhooks     map[string]*models.N8NWebhook
	HTTPClient   *http.Client
}

// ChatRequest represents the request payload for chat API
type ChatRequest struct {
	Message         string                 `json:"message"`
	UserID          string                 `json:"user_id"`
	Channel         string                 `json:"channel"`
	ConversationID  string                 `json:"conversation_id"`
	OrganizationID  string                 `json:"organization_id"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ChatResponse represents the response from chat API
type ChatResponse struct {
	Type      string                 `json:"type"` // "message", "auth_required", "error"
	Content   string                 `json:"content,omitempty"`
	AuthURL   string                 `json:"auth_url,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
	Provider  string                 `json:"provider,omitempty"`
	Actions   []Action               `json:"actions,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Action represents an action in the chat response
type Action struct {
	Type        string                 `json:"type"`
	Target      string                 `json:"target"`
	Parameters  map[string]interface{} `json:"parameters"`
	Priority    int                    `json:"priority"`
}

// OAuthCallbackRequest for OAuth callback testing
type OAuthCallbackRequest struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status   string            `json:"status"`
	Version  string            `json:"version,omitempty"`
	Services map[string]string `json:"services,omitempty"`
}

// Mock N8N server for testing webhooks
type MockN8NServer struct {
	server     *httptest.Server
	callCount  int
	lastRequest *http.Request
	lastBody   []byte
	responses  map[string]interface{}
	mutex      sync.RWMutex
}

// NewTestHelpers creates a new test helpers instance
func NewTestHelpers(baseURL string, db *gorm.DB) *TestHelpers {
	return &TestHelpers{
		BaseURL:       baseURL,
		DB:            db,
		Organizations: make(map[string]*models.Organization),
		Users:        make(map[string]*models.User),
		Providers:    make(map[string]*models.OAuthProvider),
		Webhooks:     make(map[string]*models.N8NWebhook),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetupTestOrganization creates a test organization with OAuth providers
func (h *TestHelpers) SetupTestOrganization(t *testing.T, name, clientID, clientSecret string) *models.Organization {
	t.Helper()

	org := &models.Organization{
		ID:        uuid.New(),
		Name:      name,
		Subdomain: &name,
	}

	err := h.DB.Create(org).Error
	require.NoError(t, err, "Failed to create test organization")

	// Create Microsoft OAuth provider for the organization
	provider := &models.OAuthProvider{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		ProviderType:   models.ProviderTypeMicrosoft,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		Enabled:        true,
	}

	err = h.DB.Create(provider).Error
	require.NoError(t, err, "Failed to create OAuth provider")

	// Store references
	h.Organizations[name] = org
	h.Providers[name+"-microsoft"] = provider

	return org
}

// SetupTestUser creates a test user for an organization
func (h *TestHelpers) SetupTestUser(t *testing.T, orgName, externalID string, channelType models.ChannelType) *models.User {
	t.Helper()

	org := h.Organizations[orgName]
	require.NotNil(t, org, "Organization not found: %s", orgName)

	user := &models.User{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		ExternalID:     externalID,
		ChannelType:    channelType,
	}

	err := h.DB.Create(user).Error
	require.NoError(t, err, "Failed to create test user")

	h.Users[externalID] = user
	return user
}

// SetupN8NWebhook creates a test N8N webhook configuration
func (h *TestHelpers) SetupN8NWebhook(t *testing.T, orgName, webhookURL string) *models.N8NWebhook {
	t.Helper()

	org := h.Organizations[orgName]
	require.NotNil(t, org, "Organization not found: %s", orgName)

	webhook := &models.N8NWebhook{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		WebhookURL:     webhookURL,
		IsDefault:      true,
	}

	err := h.DB.Create(webhook).Error
	require.NoError(t, err, "Failed to create N8N webhook")

	h.Webhooks[orgName] = webhook
	return webhook
}

// CreateUserToken creates an OAuth token for a user
func (h *TestHelpers) CreateUserToken(t *testing.T, userID, providerID string) *models.UserToken {
	t.Helper()

	userUUID, err := uuid.Parse(userID)
	require.NoError(t, err, "Invalid user ID: %s", userID)

	providerUUID, err := uuid.Parse(providerID)
	require.NoError(t, err, "Invalid provider ID: %s", providerID)

	refreshToken := "test-refresh-token"
	expiresAt := time.Now().Add(time.Hour)
	token := &models.UserToken{
		ID:           uuid.New(),
		UserID:       userUUID,
		ProviderID:   providerUUID,
		AccessToken:  "test-access-token",
		RefreshToken: &refreshToken,
		ExpiresAt:    &expiresAt,
		Scopes:       []string{"User.Read", "Files.Read.All"},
	}

	err = h.DB.Create(token).Error
	require.NoError(t, err, "Failed to create user token")

	return token
}

// CallChatAPI makes a call to the chat API endpoint
func (h *TestHelpers) CallChatAPI(t *testing.T, request ChatRequest) *ChatResponse {
	t.Helper()

	jsonData, err := json.Marshal(request)
	require.NoError(t, err, "Failed to marshal chat request")

	resp, err := h.HTTPClient.Post(
		h.BaseURL+"/api/chat",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	require.NoError(t, err, "Failed to make chat API request")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read response body")

	var chatResponse ChatResponse
	err = json.Unmarshal(body, &chatResponse)
	require.NoError(t, err, "Failed to unmarshal chat response: %s", string(body))

	return &chatResponse
}

// CallOAuthCallback simulates an OAuth callback
func (h *TestHelpers) CallOAuthCallback(t *testing.T, provider, code, state string) (*http.Response, []byte) {
	t.Helper()

	url := fmt.Sprintf("%s/api/oauth/callback/%s?code=%s&state=%s",
		h.BaseURL, provider, code, state)

	resp, err := h.HTTPClient.Get(url)
	require.NoError(t, err, "Failed to make OAuth callback request")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read OAuth callback response")

	return resp, body
}

// CheckHealth calls the health endpoint
func (h *TestHelpers) CheckHealth(t *testing.T) *HealthResponse {
	t.Helper()

	resp, err := h.HTTPClient.Get(h.BaseURL + "/health")
	require.NoError(t, err, "Failed to make health check request")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Health check should return 200")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read health response")

	var healthResponse HealthResponse
	err = json.Unmarshal(body, &healthResponse)
	require.NoError(t, err, "Failed to unmarshal health response")

	return &healthResponse
}

// WaitForService waits for a service to become available
func (h *TestHelpers) WaitForService(t *testing.T, timeout time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatal("Service did not become available within timeout")
		case <-ticker.C:
			resp, err := h.HTTPClient.Get(h.BaseURL + "/health")
			if err == nil && resp.StatusCode == http.StatusOK {
				resp.Body.Close()
				return
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
	}
}

// CleanupTestData removes all test data from the database
func (h *TestHelpers) CleanupTestData(t *testing.T) {
	t.Helper()

	// Delete in reverse order of dependencies
	h.DB.Where("1 = 1").Delete(&models.UserToken{})
	h.DB.Where("1 = 1").Delete(&models.Conversation{})
	// Sessions are stored in Redis, not in the database
	h.DB.Where("1 = 1").Delete(&models.N8NWebhook{})
	h.DB.Where("1 = 1").Delete(&models.OAuthProvider{})
	h.DB.Where("1 = 1").Delete(&models.User{})
	h.DB.Where("1 = 1").Delete(&models.Organization{})

	// Clear helper maps
	h.Organizations = make(map[string]*models.Organization)
	h.Users = make(map[string]*models.User)
	h.Providers = make(map[string]*models.OAuthProvider)
	h.Webhooks = make(map[string]*models.N8NWebhook)
}

// NewMockN8NServer creates a mock N8N server for testing
func NewMockN8NServer() *MockN8NServer {
	mock := &MockN8NServer{
		responses: make(map[string]interface{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/", mock.handleWebhook)
	mux.HandleFunc("/", mock.handleRoot)

	mock.server = httptest.NewServer(mux)
	return mock
}

// URL returns the mock server URL
func (m *MockN8NServer) URL() string {
	return m.server.URL
}

// Close closes the mock server
func (m *MockN8NServer) Close() {
	m.server.Close()
}

// CallCount returns the number of webhook calls received
func (m *MockN8NServer) CallCount() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.callCount
}

// LastRequest returns the last HTTP request received
func (m *MockN8NServer) LastRequest() (*http.Request, []byte) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.lastRequest, m.lastBody
}

// SetResponse sets a custom response for a specific webhook path
func (m *MockN8NServer) SetResponse(path string, response interface{}) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.responses[path] = response
}

// Reset resets the mock server state
func (m *MockN8NServer) Reset() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.callCount = 0
	m.lastRequest = nil
	m.lastBody = nil
	m.responses = make(map[string]interface{})
}

func (m *MockN8NServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("N8N Mock Server OK"))
}

func (m *MockN8NServer) handleWebhook(w http.ResponseWriter, r *http.Request) {
	m.mutex.Lock()
	m.callCount++
	m.lastRequest = r.Clone(context.Background())
	
	body, _ := io.ReadAll(r.Body)
	m.lastBody = body
	m.mutex.Unlock()

	// Check for custom response
	m.mutex.RLock()
	customResponse, hasCustom := m.responses[r.URL.Path]
	m.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	
	if hasCustom {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(customResponse)
	} else {
		// Default successful response
		response := map[string]interface{}{
			"success":   true,
			"message":   "Webhook received",
			"timestamp": time.Now().Format(time.RFC3339),
			"path":      r.URL.Path,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// AssertChatResponseType checks if the chat response has the expected type
func AssertChatResponseType(t *testing.T, response *ChatResponse, expectedType string) {
	t.Helper()
	assert.Equal(t, expectedType, response.Type, "Chat response type should be %s", expectedType)
}

// AssertAuthRequired checks if the response requires authentication
func AssertAuthRequired(t *testing.T, response *ChatResponse, expectedProvider string) {
	t.Helper()
	AssertChatResponseType(t, response, "auth_required")
	assert.NotEmpty(t, response.AuthURL, "Auth URL should not be empty")
	assert.NotEmpty(t, response.SessionID, "Session ID should not be empty")
	if expectedProvider != "" {
		assert.Equal(t, expectedProvider, response.Provider, "Provider should be %s", expectedProvider)
	}
}

// AssertSuccessfulMessage checks if the response is a successful message
func AssertSuccessfulMessage(t *testing.T, response *ChatResponse) {
	t.Helper()
	AssertChatResponseType(t, response, "message")
	assert.NotEmpty(t, response.Content, "Content should not be empty")
}

// AssertContainsURL checks if the auth URL contains expected components
func AssertContainsURL(t *testing.T, authURL, expectedComponent string) {
	t.Helper()
	assert.Contains(t, authURL, expectedComponent, "Auth URL should contain %s", expectedComponent)
}

// GetStoredToken retrieves a token from the database
func (h *TestHelpers) GetStoredToken(t *testing.T, userID, providerType string) *models.UserToken {
	t.Helper()

	userUUID, err := uuid.Parse(userID)
	require.NoError(t, err, "Invalid user ID: %s", userID)

	var token models.UserToken
	err = h.DB.Joins("JOIN oauth_providers ON oauth_providers.id = user_tokens.provider_id").
		Where("user_tokens.user_id = ? AND oauth_providers.provider_type = ?", userUUID, providerType).
		First(&token).Error

	if err == gorm.ErrRecordNotFound {
		return nil
	}
	require.NoError(t, err, "Failed to get stored token")
	return &token
}

// CreateOAuthSession creates a test OAuth session in Redis
func (h *TestHelpers) CreateOAuthSession(t *testing.T, userID, orgID, provider string) string {
	t.Helper()
	
	sessionID := uuid.New().String()
	// Note: In a real implementation, you would store this in Redis
	// For tests, we'll assume the session service handles this
	return sessionID
}

// GetRedisKey retrieves a value from Redis (mock implementation)
func (h *TestHelpers) GetRedisKey(t *testing.T, key string) interface{} {
	t.Helper()
	// Mock implementation - in real tests you would check Redis
	return nil
}

// expectN8NWebhookCall verifies that the N8N webhook was called the expected number of times
func expectN8NWebhookCall(t *testing.T, mockN8N *MockN8NServer, expectedCalls int) {
	t.Helper()
	assert.Equal(t, expectedCalls, mockN8N.CallCount(), 
		"Expected %d N8N webhook calls, but got %d", expectedCalls, mockN8N.CallCount())
}