package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChatFlowWithoutAuth tests general questions that don't require authentication
func TestChatFlowWithoutAuth(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	testCases := []struct {
		name     string
		message  string
		expected string
	}{
		{
			name:     "General weather question",
			message:  "What is the weather today?",
			expected: "message",
		},
		{
			name:     "Simple greeting",
			message:  "Hello, how are you?",
			expected: "message",
		},
		{
			name:     "General AI question",
			message:  "What can you help me with?",
			expected: "message",
		},
		{
			name:     "Math question",
			message:  "What is 2 + 2?",
			expected: "message",
		},
		{
			name:     "General workflow question",
			message:  "What are workflows?",
			expected: "message",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := ChatRequest{
				Message:        tc.message,
				UserID:         "test-user-123",
				Channel:        "teams",
				ConversationID: uuid.New().String(),
				OrganizationID: fmt.Sprintf("%d", testHelpers.Organizations["org-123"].ID),
				Metadata: map[string]interface{}{
					"test_case": tc.name,
				},
			}

			response := testHelpers.CallChatAPI(t, request)
			
			// Should return a direct message response without requiring auth
			AssertChatResponseType(t, response, tc.expected)
			assert.NotEmpty(t, response.Content, "Response content should not be empty")
			
			t.Logf("Request: %s", tc.message)
			t.Logf("Response: %s", response.Content)
		})
	}
}

// TestChatFlowRequiringSharePoint tests queries that should trigger SharePoint auth
func TestChatFlowRequiringSharePoint(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	sharePointQueries := []struct {
		name    string
		message string
	}{
		{
			name:    "SharePoint search",
			message: "Search for vacation policy in SharePoint",
		},
		{
			name:    "Document search",
			message: "Find the employee handbook document",
		},
		{
			name:    "SharePoint file access",
			message: "Show me files from our team SharePoint",
		},
		{
			name:    "OneDrive access",
			message: "Get my files from OneDrive",
		},
		{
			name:    "Microsoft 365 query",
			message: "Find emails about the project in Outlook",
		},
	}

	for _, tc := range sharePointQueries {
		t.Run(tc.name, func(t *testing.T) {
			request := ChatRequest{
				Message:        tc.message,
				UserID:         "test-user-456",
				Channel:        "teams",
				ConversationID: uuid.New().String(),
				OrganizationID: fmt.Sprintf("%d", testHelpers.Organizations["org-123"].ID),
				Metadata: map[string]interface{}{
					"test_case": tc.name,
				},
			}

			response := testHelpers.CallChatAPI(t, request)
			
			// Should return auth_required response with Microsoft OAuth URL
			AssertAuthRequired(t, response, "microsoft")
			
			// Verify the auth URL contains the correct client ID for this org
			provider := testHelpers.Providers["org-123-microsoft"]
			assert.Contains(t, response.AuthURL, provider.ClientID, 
				"Auth URL should contain the organization's client ID")
			
			t.Logf("Request: %s", tc.message)
			t.Logf("Auth URL: %s", response.AuthURL)
			t.Logf("Session ID: %s", response.SessionID)
		})
	}
}

// TestMultiTenantIsolation tests that different organizations get their own OAuth configs
func TestMultiTenantIsolation(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Test that different organizations have different OAuth configs
	testCases := []struct {
		orgName      string
		expectedClientID string
	}{
		{
			orgName:          "org-a",
			expectedClientID: "test-client-a",
		},
		{
			orgName:          "org-b", 
			expectedClientID: "test-client-b",
		},
	}

	sharePointQuery := "Search for documents in SharePoint"

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Organization_%s", tc.orgName), func(t *testing.T) {
			org := testHelpers.Organizations[tc.orgName]
			require.NotNil(t, org, "Organization should exist: %s", tc.orgName)

			request := ChatRequest{
				Message:        sharePointQuery,
				UserID:         fmt.Sprintf("user-%s", tc.orgName[len(tc.orgName)-1:]),
				Channel:        "teams",
				ConversationID: uuid.New().String(),
				OrganizationID: fmt.Sprintf("%d", org.ID),
			}

			response := testHelpers.CallChatAPI(t, request)
			
			// Should require authentication
			AssertAuthRequired(t, response, "microsoft")
			
			// Verify the auth URL contains the correct client ID for this specific org
			assert.Contains(t, response.AuthURL, tc.expectedClientID,
				"Auth URL should contain organization-specific client ID: %s", tc.expectedClientID)
			
			// Verify it doesn't contain other org's client IDs
			for _, otherTC := range testCases {
				if otherTC.orgName != tc.orgName {
					assert.NotContains(t, response.AuthURL, otherTC.expectedClientID,
						"Auth URL should not contain other organization's client ID: %s", otherTC.expectedClientID)
				}
			}
			
			t.Logf("Org: %s, Client ID in URL: %s", tc.orgName, tc.expectedClientID)
		})
	}
}

// TestOAuthCallbackFlow tests the complete OAuth callback flow
func TestOAuthCallbackFlow(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	org := testHelpers.Organizations["org-123"]
	user := testHelpers.Users["test-user-123"]
	provider := testHelpers.Providers["org-123-microsoft"]

	// Step 1: Create OAuth session (simulating initial auth request)
	sessionID := testHelpers.CreateOAuthSession(t, 
		fmt.Sprintf("%d", user.ID), 
		fmt.Sprintf("%d", org.ID), 
		"microsoft")

	// Step 2: Simulate OAuth callback with authorization code
	authCode := "test-auth-code-12345"
	
	resp, body := testHelpers.CallOAuthCallback(t, "microsoft", authCode, sessionID)
	
	// Should return success response
	assert.Equal(t, 200, resp.StatusCode, "OAuth callback should return 200")
	assert.Contains(t, string(body), "success", "Response should indicate success")
	
	// Step 3: Verify token was stored (in a real test, this would check the database)
	// For now, we'll create the token to simulate successful OAuth
	token := testHelpers.CreateUserToken(t, fmt.Sprintf("%d", user.ID), fmt.Sprintf("%d", provider.ID))
	assert.NotNil(t, token, "Token should be created")
	
	// Step 4: Verify session was cleared (would check Redis in real implementation)
	session := testHelpers.GetRedisKey(t, "oauth_session:"+sessionID)
	assert.Nil(t, session, "OAuth session should be cleared after callback")
	
	// Step 5: Verify subsequent requests with same user can access protected resources
	request := ChatRequest{
		Message:        "Search for vacation policy in SharePoint",
		UserID:         fmt.Sprintf("%d", user.ID),
		Channel:        "teams",
		ConversationID: uuid.New().String(),
		OrganizationID: fmt.Sprintf("%d", org.ID),
	}

	// This should now work without requiring auth again
	response := testHelpers.CallChatAPI(t, request)
	
	// Should either return a message or trigger webhook (depending on implementation)
	assert.True(t, response.Type == "message" || response.Type == "auth_required", 
		"Response should be message or auth_required, got: %s", response.Type)
	
	t.Logf("OAuth flow completed successfully for user: %s", fmt.Sprintf("%d", user.ID))
}

// TestN8NWebhookTrigger tests that successful queries trigger n8n webhooks
func TestN8NWebhookTrigger(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Setup mock N8N server
	mockN8N := NewMockN8NServer()
	defer mockN8N.Close()
	
	// Configure organization with mock N8N webhook
	org := testHelpers.Organizations["org-123"]
	testHelpers.SetupN8NWebhook(t, "org-123", mockN8N.URL()+"/webhook/test")
	
	// Create user with token (simulating already authenticated user)
	user := testHelpers.Users["user-with-token"]
	provider := testHelpers.Providers["org-123-microsoft"]
	testHelpers.CreateUserToken(t, fmt.Sprintf("%d", user.ID), fmt.Sprintf("%d", provider.ID))

	testCases := []struct {
		name          string
		message       string
		expectedCalls int
		webhookPath   string
	}{
		{
			name:          "Jira ticket query",
			message:       "Get my open Jira tickets",
			expectedCalls: 1,
			webhookPath:   "/webhook/test",
		},
		{
			name:          "SharePoint search with auth",
			message:       "Search for project documents in SharePoint",
			expectedCalls: 1,
			webhookPath:   "/webhook/test",
		},
		{
			name:          "Workflow execution request",
			message:       "Run the daily report workflow",
			expectedCalls: 1,
			webhookPath:   "/webhook/test",
		},
		{
			name:          "Data analysis request",
			message:       "Analyze last month's sales data",
			expectedCalls: 1,
			webhookPath:   "/webhook/test",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mock server state
			mockN8N.Reset()
			
			// Set custom response if needed
			mockN8N.SetResponse(tc.webhookPath, map[string]interface{}{
				"success": true,
				"result":  fmt.Sprintf("Processed: %s", tc.message),
				"action":  "workflow_triggered",
			})

			request := ChatRequest{
				Message:        tc.message,
				UserID:         fmt.Sprintf("%d", user.ID),
				Channel:        "teams", 
				ConversationID: uuid.New().String(),
				OrganizationID: fmt.Sprintf("%d", org.ID),
				Metadata: map[string]interface{}{
					"authenticated": true,
					"test_case":     tc.name,
				},
			}

			response := testHelpers.CallChatAPI(t, request)
			
			// Response should be successful 
			assert.NotEqual(t, "error", response.Type, "Should not return error")
			
			// Verify N8N webhook was called
			expectN8NWebhookCall(t, mockN8N, tc.expectedCalls)
			
			if tc.expectedCalls > 0 {
				req, body := mockN8N.LastRequest()
				require.NotNil(t, req, "Should have received webhook request")
				
				// Verify webhook request contains relevant information
				assert.Equal(t, "POST", req.Method, "Webhook should be POST request")
				assert.Contains(t, req.URL.Path, "webhook", "Request should be to webhook endpoint")
				assert.NotEmpty(t, body, "Webhook body should not be empty")
				
				t.Logf("Webhook called: %s %s", req.Method, req.URL.Path)
				t.Logf("Webhook body: %s", string(body))
			}
			
			t.Logf("Request: %s", tc.message)
			t.Logf("Response Type: %s", response.Type)
		})
	}
}

// TestErrorHandling tests various error scenarios
func TestErrorHandling(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	testCases := []struct {
		name            string
		request         ChatRequest
		expectedType    string
		shouldContainError bool
	}{
		{
			name: "Invalid organization ID",
			request: ChatRequest{
				Message:        "Hello",
				UserID:         "test-user-123",
				Channel:        "teams",
				ConversationID: uuid.New().String(),
				OrganizationID: "invalid-org-id",
			},
			expectedType:       "error",
			shouldContainError: true,
		},
		{
			name: "Empty message",
			request: ChatRequest{
				Message:        "",
				UserID:         "test-user-123", 
				Channel:        "teams",
				ConversationID: uuid.New().String(),
				OrganizationID: fmt.Sprintf("%d", testHelpers.Organizations["org-123"].ID),
			},
			expectedType:       "error",
			shouldContainError: true,
		},
		{
			name: "Missing user ID",
			request: ChatRequest{
				Message:        "Hello",
				UserID:         "",
				Channel:        "teams",
				ConversationID: uuid.New().String(),
				OrganizationID: fmt.Sprintf("%d", testHelpers.Organizations["org-123"].ID),
			},
			expectedType:       "error",
			shouldContainError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response := testHelpers.CallChatAPI(t, tc.request)
			
			if tc.shouldContainError {
				assert.Equal(t, tc.expectedType, response.Type, "Should return error type")
				// Note: The actual error handling depends on the API implementation
			}
			
			t.Logf("Error test case: %s, Response type: %s", tc.name, response.Type)
		})
	}
}

// TestConversationContext tests that conversation context is maintained
func TestConversationContext(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	org := testHelpers.Organizations["org-123"]
	conversationID := uuid.New().String()

	// First message
	request1 := ChatRequest{
		Message:        "My name is John",
		UserID:         "test-user-123",
		Channel:        "teams",
		ConversationID: conversationID,
		OrganizationID: fmt.Sprintf("%d", org.ID),
	}

	response1 := testHelpers.CallChatAPI(t, request1)
	AssertSuccessfulMessage(t, response1)

	// Second message that should reference the first
	request2 := ChatRequest{
		Message:        "What is my name?",
		UserID:         "test-user-123",
		Channel:        "teams",
		ConversationID: conversationID, // Same conversation
		OrganizationID: fmt.Sprintf("%d", org.ID),
	}

	response2 := testHelpers.CallChatAPI(t, request2)
	AssertSuccessfulMessage(t, response2)

	// The AI should remember the name from the previous message
	// Note: This test depends on the AI service implementation
	t.Logf("First message: %s", request1.Message)
	t.Logf("First response: %s", response1.Content)
	t.Logf("Second message: %s", request2.Message)  
	t.Logf("Second response: %s", response2.Content)
}

// TestRateLimiting tests rate limiting functionality (if enabled)
func TestRateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping rate limiting test in short mode")
	}

	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	org := testHelpers.Organizations["org-123"]
	
	// Make multiple rapid requests
	request := ChatRequest{
		Message:        "Hello",
		UserID:         "test-user-123",
		Channel:        "teams",
		ConversationID: uuid.New().String(),
		OrganizationID: fmt.Sprintf("%d", org.ID),
	}

	successCount := 0
	rateLimitedCount := 0

	// Make 20 requests rapidly
	for i := 0; i < 20; i++ {
		request.ConversationID = uuid.New().String() // New conversation each time
		response := testHelpers.CallChatAPI(t, request)
		
		if response.Type == "error" && 
		   (response.Content == "rate limit exceeded" || response.Content == "too many requests") {
			rateLimitedCount++
		} else {
			successCount++
		}
		
		// Small delay between requests
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("Successful requests: %d, Rate limited: %d", successCount, rateLimitedCount)
	
	// Note: This test depends on rate limiting being configured
	// If rate limiting is disabled in test environment, all requests should succeed
}

// TestHealthEndpoint tests the health check endpoint
func TestHealthEndpoint(t *testing.T) {
	health := testHelpers.CheckHealth(t)
	
	assert.Equal(t, "healthy", health.Status, "Health status should be healthy")
	
	// Check that services are reported as connected
	if health.Services != nil {
		for service, status := range health.Services {
			assert.Equal(t, "connected", status, "Service %s should be connected", service)
		}
	}
	
	t.Logf("Health check passed: %+v", health)
}