package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/workoflow/ai-orchestrator-api/internal/ai"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
	"gorm.io/gorm"
)

// WorkflowTestSuite provides a comprehensive test suite for workflow orchestration
type WorkflowTestSuite struct {
	suite.Suite
	db             *gorm.DB
	n8nMock        *MockN8NServer
	n8nClient      *services.N8NClient
	intentDetector *ai.IntentDetector
	testOrg        *models.Organization
	testUser       *models.User
	testWebhook    *models.N8NWebhook
	testProvider   *models.OAuthProvider
	testToken      *models.UserToken
}

// SetupSuite initializes the test suite
func (suite *WorkflowTestSuite) SetupSuite() {
	suite.db = testDB
	suite.intentDetector = ai.NewIntentDetector()
	
	// Create mock N8N server
	suite.n8nMock = NewMockN8NServer()
	
	// Initialize N8N client with test config
	suite.n8nClient = services.NewN8NClient(testConfig)
}

// TearDownSuite cleans up after the test suite
func (suite *WorkflowTestSuite) TearDownSuite() {
	if suite.n8nMock != nil {
		suite.n8nMock.Close()
	}
}

// SetupTest sets up each individual test
func (suite *WorkflowTestSuite) SetupTest() {
	// Clean up existing test data
	suite.cleanupTestData()
	
	// Reset mock server
	suite.n8nMock.Reset()
	
	// Create test organization
	suite.testOrg = &models.Organization{
		Name:        "Test Workflow Org",
		Slug:        "test-workflow-org",
		Description: "Test organization for workflow testing",
		Settings:    models.JSON{"theme": "light"},
	}
	err := suite.db.Create(suite.testOrg).Error
	require.NoError(suite.T(), err, "Failed to create test organization")
	
	// Create test user
	suite.testUser = &models.User{
		OrganizationID: suite.testOrg.ID,
		Email:          "workflow-test@example.com",
		FirstName:      "Workflow",
		LastName:       "Tester",
		Role:           "user",
		IsActive:       true,
		IsVerified:     true,
		Settings:       models.JSON{"language": "en"},
	}
	err = suite.db.Create(suite.testUser).Error
	require.NoError(suite.T(), err, "Failed to create test user")
	
	// Create OAuth provider
	suite.testProvider = &models.OAuthProvider{
		OrganizationID: suite.testOrg.ID,
		ProviderType:   models.ProviderTypeMicrosoft,
		ClientID:       "test-client-id",
		ClientSecret:   "test-client-secret",
		Enabled:        true,
		Scopes:         []string{"User.Read", "Files.Read.All"},
	}
	err = suite.db.Create(suite.testProvider).Error
	require.NoError(suite.T(), err, "Failed to create OAuth provider")
	
	// Create N8N webhook configuration
	suite.testWebhook = &models.N8NWebhook{
		OrganizationID: suite.testOrg.ID,
		WorkflowName:   "Test Workflow",
		WorkflowID:     "test-workflow-123",
		WebhookPath:    "/webhook/test-workflow",
		N8NBaseURL:     suite.n8nMock.URL(),
		AuthMethod:     "bearer",
		AuthToken:      "test-auth-token",
		Active:         true,
		Description:    "Test workflow for E2E testing",
		Tags:           []string{"test", "e2e"},
	}
	err = suite.db.Create(suite.testWebhook).Error
	require.NoError(suite.T(), err, "Failed to create test webhook")
	
	// Create test OAuth token
	refreshToken := "test-refresh-token"
	expiresAt := time.Now().Add(time.Hour)
	suite.testToken = &models.UserToken{
		UserID:       suite.testUser.ID,
		ProviderID:   suite.testProvider.ID,
		AccessToken:  "test-access-token",
		RefreshToken: &refreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    &expiresAt,
		Scopes:       []string{"User.Read", "Files.Read.All"},
		Metadata:     models.JSON{"test": true},
	}
	err = suite.db.Create(suite.testToken).Error
	require.NoError(suite.T(), err, "Failed to create test token")
}

// TestN8NWebhookTrigger tests successful webhook calls to N8N
func (suite *WorkflowTestSuite) TestN8NWebhookTrigger() {
	// Set up expected response from N8N mock
	expectedResponse := map[string]interface{}{
		"execution_id": "exec_123456",
		"success":      true,
		"status":       "running",
		"message":      "Workflow started successfully",
		"data": map[string]interface{}{
			"workflow_id":  suite.testWebhook.WorkflowID,
			"started_at":   time.Now().Format(time.RFC3339),
			"triggered_by": "user",
		},
	}
	suite.n8nMock.SetResponse("/webhook/test-workflow", expectedResponse)
	
	// Create webhook request
	webhookRequest := &services.N8NWebhookRequest{
		WorkflowID:     suite.testWebhook.WorkflowID,
		WebhookPath:    suite.testWebhook.WebhookPath,
		Method:         "POST",
		Headers:        map[string]string{"Content-Type": "application/json"},
		Parameters:     map[string]interface{}{"test": true},
		Body: map[string]interface{}{
			"user_id":         suite.testUser.ID,
			"organization_id": suite.testOrg.ID,
			"message":         "Execute test workflow",
			"context": map[string]interface{}{
				"intent":     "workflow_execution",
				"confidence": 0.95,
			},
		},
		UserID:         suite.testUser.ID,
		OrgID:          suite.testOrg.ID,
		ConversationID: "conv_123",
		RequestID:      "req_123",
	}
	
	// Execute webhook
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	response, err := suite.n8nClient.ExecuteWebhook(ctx, suite.testWebhook, webhookRequest)
	
	// Assertions
	require.NoError(suite.T(), err, "Webhook execution should not fail")
	assert.True(suite.T(), response.Success, "Webhook should return success")
	assert.Equal(suite.T(), http.StatusOK, response.StatusCode, "Should return 200 status")
	assert.NotEmpty(suite.T(), response.ExecutionID, "Should return execution ID")
	assert.Equal(suite.T(), "exec_123456", response.ExecutionID, "Should return expected execution ID")
	assert.Equal(suite.T(), 1, suite.n8nMock.CallCount(), "Should call N8N webhook once")
	
	// Verify request details
	lastRequest, lastBody := suite.n8nMock.LastRequest()
	assert.Equal(suite.T(), "POST", lastRequest.Method, "Should use POST method")
	assert.Equal(suite.T(), "/webhook/test-workflow", lastRequest.URL.Path, "Should call correct webhook path")
	assert.Contains(suite.T(), lastRequest.Header.Get("Authorization"), "Bearer", "Should include auth header")
	
	// Verify request body contains expected data
	var requestBody map[string]interface{}
	err = json.Unmarshal(lastBody, &requestBody)
	require.NoError(suite.T(), err, "Should be able to parse request body")
	assert.Equal(suite.T(), "Execute test workflow", requestBody["message"])
	assert.Equal(suite.T(), float64(suite.testUser.ID), requestBody["user_id"])
}

// TestWorkflowExecutionWithContext tests context passing to workflows
func (suite *WorkflowTestSuite) TestWorkflowExecutionWithContext() {
	// Set up mock response with context data
	suite.n8nMock.SetResponse("/webhook/test-workflow", map[string]interface{}{
		"execution_id":     "exec_context_123",
		"success":          true,
		"context_received": true,
	})
	
	// Create conversation context
	conversation := &models.Conversation{
		UserID:                 suite.testUser.ID,
		ExternalConversationID: stringPtr("teams-conv-123"),
		Status:                 models.ConversationStatusActive,
		Context: models.JSON{
			"previous_messages": []map[string]interface{}{
				{"role": "user", "content": "Hello"},
				{"role": "assistant", "content": "Hi! How can I help you?"},
			},
			"user_preferences": map[string]interface{}{
				"language": "en",
				"timezone": "UTC",
			},
			"session_data": map[string]interface{}{
				"authenticated": true,
				"permissions":   []string{"workflow.execute", "data.read"},
			},
		},
		MessageCount: 2,
	}
	
	err := suite.db.Create(conversation).Error
	require.NoError(suite.T(), err, "Failed to create test conversation")
	
	// Create webhook request with rich context
	webhookRequest := &services.N8NWebhookRequest{
		WorkflowID:  suite.testWebhook.WorkflowID,
		WebhookPath: suite.testWebhook.WebhookPath,
		Method:      "POST",
		Body: map[string]interface{}{
			"user_id":         suite.testUser.ID,
			"organization_id": suite.testOrg.ID,
			"conversation_id": conversation.ID,
			"message":         "Run workflow with full context",
			"context": map[string]interface{}{
				"intent":               "workflow_execution",
				"confidence":           0.9,
				"conversation_history": conversation.Context,
				"user_context": map[string]interface{}{
					"user_id":        suite.testUser.ID,
					"email":          suite.testUser.Email,
					"role":           suite.testUser.Role,
					"authenticated":  true,
					"available_tools": []string{"microsoft_graph", "sharepoint", "teams"},
				},
				"execution_context": map[string]interface{}{
					"trigger_type":    "user_request",
					"execution_mode":  "interactive",
					"timeout_seconds": 300,
				},
			},
		},
		UserID:         suite.testUser.ID,
		OrgID:          suite.testOrg.ID,
		ConversationID: fmt.Sprintf("%d", conversation.ID),
		RequestID:      "req_context_123",
	}
	
	// Execute webhook
	ctx := context.Background()
	response, err := suite.n8nClient.ExecuteWebhook(ctx, suite.testWebhook, webhookRequest)
	
	// Assertions
	require.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)
	assert.NotEmpty(suite.T(), response.ExecutionID)
	
	// Verify context was passed correctly
	_, lastBody := suite.n8nMock.LastRequest()
	var requestBody map[string]interface{}
	err = json.Unmarshal(lastBody, &requestBody)
	require.NoError(suite.T(), err)
	
	contextData := requestBody["context"].(map[string]interface{})
	assert.Equal(suite.T(), "workflow_execution", contextData["intent"])
	assert.Equal(suite.T(), 0.9, contextData["confidence"])
	assert.NotNil(suite.T(), contextData["conversation_history"])
	assert.NotNil(suite.T(), contextData["user_context"])
	assert.NotNil(suite.T(), contextData["execution_context"])
	
	userContext := contextData["user_context"].(map[string]interface{})
	assert.Equal(suite.T(), suite.testUser.Email, userContext["email"])
	assert.Equal(suite.T(), true, userContext["authenticated"])
}

// TestIntentDetectionAndToolSelection tests AI intent detection
func (suite *WorkflowTestSuite) TestIntentDetectionAndToolSelection() {
	testCases := []struct {
		name               string
		message            string
		expectedIntent     string
		minConfidence      float32
		expectedTools      []string
		shouldTriggerN8N   bool
	}{
		{
			name:               "Workflow execution intent",
			message:            "Run the data processing workflow",
			expectedIntent:     "workflow_execution",
			minConfidence:      0.7,
			expectedTools:      []string{"n8n", "workflow_engine"},
			shouldTriggerN8N:   true,
		},
		{
			name:               "Workflow management intent",
			message:            "Create a new automation for email processing",
			expectedIntent:     "workflow_management",
			minConfidence:      0.6,
			expectedTools:      []string{"n8n", "workflow_builder"},
			shouldTriggerN8N:   false,
		},
		{
			name:               "Data query intent",
			message:            "Show me the execution logs from last week",
			expectedIntent:     "data_query",
			minConfidence:      0.6,
			expectedTools:      []string{"database", "analytics"},
			shouldTriggerN8N:   false,
		},
		{
			name:               "N8N specific execution",
			message:            "Trigger the n8n webhook for customer onboarding",
			expectedIntent:     "workflow_execution",
			minConfidence:      0.8,
			expectedTools:      []string{"n8n", "webhook"},
			shouldTriggerN8N:   true,
		},
		{
			name:               "Help request",
			message:            "How do I create a workflow?",
			expectedIntent:     "help_guidance",
			minConfidence:      0.5,
			expectedTools:      []string{"documentation", "guidance"},
			shouldTriggerN8N:   false,
		},
		{
			name:               "General conversation",
			message:            "Hello, how are you?",
			expectedIntent:     "general",
			minConfidence:      0.3,
			expectedTools:      []string{},
			shouldTriggerN8N:   false,
		},
	}
	
	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			// Detect intent
			intent, confidence := suite.intentDetector.DetectIntent(tc.message)
			
			// Assertions
			assert.Equal(t, tc.expectedIntent, intent, "Should detect correct intent")
			assert.GreaterOrEqual(t, confidence, tc.minConfidence, "Should have sufficient confidence")
			
			// Get intent details
			intentDetails := suite.intentDetector.GetIntentDetails(intent)
			assert.Equal(t, intent, intentDetails.Name)
			assert.NotEmpty(t, intentDetails.Keywords, "Should have keywords defined")
			
			// Extract entities
			entities := suite.intentDetector.ExtractEntities(tc.message, intent)
			if intent == "workflow_execution" {
				// Should extract workflow-related entities
				if strings.Contains(tc.message, "workflow") {
					t.Logf("Extracted entities: %+v", entities)
				}
			}
			
			// Test tool selection logic (this would be part of the orchestration service)
			selectedTools := selectToolsForIntent(intent, confidence)
			for _, expectedTool := range tc.expectedTools {
				if len(tc.expectedTools) > 0 {
					assert.Contains(t, selectedTools, expectedTool, "Should select expected tool: %s", expectedTool)
				}
			}
			
			// Test N8N triggering logic
			shouldTrigger := shouldTriggerWorkflow(intent, confidence)
			assert.Equal(t, tc.shouldTriggerN8N, shouldTrigger, "Should correctly determine N8N trigger necessity")
		})
	}
}

// TestWorkflowStatusTracking tests execution status monitoring
func (suite *WorkflowTestSuite) TestWorkflowStatusTracking() {
	// Set up mock N8N execution status endpoint
	executionID := "exec_status_test_123"
	statusResponses := []map[string]interface{}{
		{
			"id":          executionID,
			"workflow_id": suite.testWebhook.WorkflowID,
			"status":      "running",
			"started_at":  time.Now().Add(-2 * time.Minute).Format(time.RFC3339),
			"data":        map[string]interface{}{"progress": "25%"},
		},
		{
			"id":          executionID,
			"workflow_id": suite.testWebhook.WorkflowID,
			"status":      "running",
			"started_at":  time.Now().Add(-2 * time.Minute).Format(time.RFC3339),
			"data":        map[string]interface{}{"progress": "75%"},
		},
		{
			"id":          executionID,
			"workflow_id": suite.testWebhook.WorkflowID,
			"status":      "success",
			"started_at":  time.Now().Add(-2 * time.Minute).Format(time.RFC3339),
			"stopped_at":  time.Now().Format(time.RFC3339),
			"data":        map[string]interface{}{"result": "completed successfully"},
		},
	}
	
	callCount := 0
	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/executions/") {
			responseIndex := callCount % len(statusResponses)
			callCount++
			
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(statusResponses[responseIndex])
		}
	}))
	defer statusServer.Close()
	
	// Update webhook to use status server URL
	suite.testWebhook.N8NBaseURL = statusServer.URL
	
	// Test status tracking
	ctx := context.Background()
	
	// Initial status check (running)
	status1, err := suite.n8nClient.GetExecutionStatus(ctx, suite.testWebhook, executionID)
	require.NoError(suite.T(), err, "Should get execution status")
	assert.Equal(suite.T(), "running", status1.Status)
	assert.Equal(suite.T(), executionID, status1.ID)
	assert.NotNil(suite.T(), status1.StartedAt)
	assert.Nil(suite.T(), status1.StoppedAt)
	
	// Second status check (still running, more progress)
	status2, err := suite.n8nClient.GetExecutionStatus(ctx, suite.testWebhook, executionID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "running", status2.Status)
	
	// Final status check (completed)
	status3, err := suite.n8nClient.GetExecutionStatus(ctx, suite.testWebhook, executionID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "success", status3.Status)
	assert.NotNil(suite.T(), status3.StoppedAt)
	
	// Verify progression
	assert.Equal(suite.T(), executionID, status1.ID)
	assert.Equal(suite.T(), executionID, status2.ID)
	assert.Equal(suite.T(), executionID, status3.ID)
	
	assert.Equal(suite.T(), suite.testWebhook.WorkflowID, status1.WorkflowID)
	assert.Equal(suite.T(), suite.testWebhook.WorkflowID, status2.WorkflowID)
	assert.Equal(suite.T(), suite.testWebhook.WorkflowID, status3.WorkflowID)
}

// TestWorkflowErrorHandling tests failed workflow scenarios
func (suite *WorkflowTestSuite) TestWorkflowErrorHandling() {
	errorTestCases := []struct {
		name               string
		mockStatusCode     int
		mockResponse       interface{}
		expectSuccess      bool
		expectedError      string
	}{
		{
			name:           "Server error (500)",
			mockStatusCode: 500,
			mockResponse:   map[string]interface{}{"error": "Internal server error"},
			expectSuccess:  false,
			expectedError:  "HTTP 500",
		},
		{
			name:           "Bad request (400)",
			mockStatusCode: 400,
			mockResponse:   map[string]interface{}{"error": "Invalid request format"},
			expectSuccess:  false,
			expectedError:  "HTTP 400",
		},
		{
			name:           "Authentication failure (401)",
			mockStatusCode: 401,
			mockResponse:   map[string]interface{}{"error": "Unauthorized"},
			expectSuccess:  false,
			expectedError:  "HTTP 401",
		},
		{
			name:           "Workflow not found (404)",
			mockStatusCode: 404,
			mockResponse:   map[string]interface{}{"error": "Workflow not found"},
			expectSuccess:  false,
			expectedError:  "HTTP 404",
		},
		{
			name:           "Timeout (503)",
			mockStatusCode: 503,
			mockResponse:   map[string]interface{}{"error": "Service unavailable"},
			expectSuccess:  false,
			expectedError:  "HTTP 503",
		},
	}
	
	for _, tc := range errorTestCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			// Create error mock server
			errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.mockStatusCode)
				json.NewEncoder(w).Encode(tc.mockResponse)
			}))
			defer errorServer.Close()
			
			// Create webhook config pointing to error server
			errorWebhook := &models.N8NWebhook{
				OrganizationID: suite.testOrg.ID,
				WorkflowName:   "Error Test Workflow",
				WorkflowID:     "error-workflow-123",
				WebhookPath:    "/webhook/error-test",
				N8NBaseURL:     errorServer.URL,
				AuthMethod:     "bearer",
				AuthToken:      "test-token",
				Active:         true,
			}
			
			// Create webhook request
			webhookRequest := &services.N8NWebhookRequest{
				WorkflowID:     errorWebhook.WorkflowID,
				WebhookPath:    errorWebhook.WebhookPath,
				Method:         "POST",
				Body:           map[string]interface{}{"test": "error_scenario"},
				UserID:         suite.testUser.ID,
				OrgID:          suite.testOrg.ID,
				ConversationID: "conv_error_123",
				RequestID:      "req_error_123",
			}
			
			// Execute webhook and expect error
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			response, err := suite.n8nClient.ExecuteWebhook(ctx, errorWebhook, webhookRequest)
			
			if tc.expectSuccess {
				require.NoError(t, err, "Should not return error for success case")
				assert.True(t, response.Success, "Response should indicate success")
			} else {
				require.NoError(t, err, "HTTP errors should not cause Go errors, but should be reflected in response")
				assert.False(t, response.Success, "Response should indicate failure")
				assert.Contains(t, response.Error, tc.expectedError, "Should contain expected error message")
				assert.Equal(t, tc.mockStatusCode, response.StatusCode, "Should return expected status code")
			}
		})
	}
}

// TestMultipleWorkflowExecution tests concurrent workflows
func (suite *WorkflowTestSuite) TestMultipleWorkflowExecution() {
	numConcurrentWorkflows := 5
	
	// Set up multiple webhook configurations
	webhooks := make([]*models.N8NWebhook, numConcurrentWorkflows)
	for i := 0; i < numConcurrentWorkflows; i++ {
		webhook := &models.N8NWebhook{
			OrganizationID: suite.testOrg.ID,
			WorkflowName:   fmt.Sprintf("Concurrent Workflow %d", i+1),
			WorkflowID:     fmt.Sprintf("concurrent-workflow-%d", i+1),
			WebhookPath:    fmt.Sprintf("/webhook/concurrent-%d", i+1),
			N8NBaseURL:     suite.n8nMock.URL(),
			AuthMethod:     "bearer",
			AuthToken:      "test-token",
			Active:         true,
		}
		
		err := suite.db.Create(webhook).Error
		require.NoError(suite.T(), err, "Failed to create webhook %d", i+1)
		webhooks[i] = webhook
		
		// Set up mock response for each webhook
		suite.n8nMock.SetResponse(webhook.WebhookPath, map[string]interface{}{
			"execution_id": fmt.Sprintf("exec_concurrent_%d", i+1),
			"success":      true,
			"workflow_id":  webhook.WorkflowID,
			"started_at":   time.Now().Format(time.RFC3339),
		})
	}
	
	// Execute workflows concurrently
	var wg sync.WaitGroup
	results := make(chan *services.N8NWebhookResponse, numConcurrentWorkflows)
	errors := make(chan error, numConcurrentWorkflows)
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	for i, webhook := range webhooks {
		wg.Add(1)
		go func(idx int, wh *models.N8NWebhook) {
			defer wg.Done()
			
			request := &services.N8NWebhookRequest{
				WorkflowID:     wh.WorkflowID,
				WebhookPath:    wh.WebhookPath,
				Method:         "POST",
				Body: map[string]interface{}{
					"workflow_index": idx,
					"test_data":      fmt.Sprintf("concurrent_test_%d", idx),
				},
				UserID:         suite.testUser.ID,
				OrgID:          suite.testOrg.ID,
				ConversationID: fmt.Sprintf("conv_concurrent_%d", idx),
				RequestID:      fmt.Sprintf("req_concurrent_%d", idx),
			}
			
			response, err := suite.n8nClient.ExecuteWebhook(ctx, wh, request)
			if err != nil {
				errors <- err
				return
			}
			
			results <- response
		}(i, webhook)
	}
	
	// Wait for all workflows to complete
	wg.Wait()
	close(results)
	close(errors)
	
	// Check for errors
	var executionErrors []error
	for err := range errors {
		executionErrors = append(executionErrors, err)
	}
	assert.Empty(suite.T(), executionErrors, "No workflows should fail: %v", executionErrors)
	
	// Verify all workflows succeeded
	var successfulResponses []*services.N8NWebhookResponse
	for response := range results {
		successfulResponses = append(successfulResponses, response)
	}
	
	assert.Len(suite.T(), successfulResponses, numConcurrentWorkflows, "All workflows should complete successfully")
	
	for i, response := range successfulResponses {
		assert.True(suite.T(), response.Success, "Workflow %d should succeed", i+1)
		assert.NotEmpty(suite.T(), response.ExecutionID, "Workflow %d should have execution ID", i+1)
		assert.Equal(suite.T(), http.StatusOK, response.StatusCode, "Workflow %d should return 200", i+1)
	}
	
	// Verify all webhooks were called
	assert.Equal(suite.T(), numConcurrentWorkflows, suite.n8nMock.CallCount(), "All webhooks should be called")
}

// TestWorkflowWithOAuthTokens tests token passing to N8N
func (suite *WorkflowTestSuite) TestWorkflowWithOAuthTokens() {
	// Set up mock response that expects OAuth tokens
	suite.n8nMock.SetResponse("/webhook/test-workflow", map[string]interface{}{
		"execution_id":    "exec_oauth_123",
		"success":         true,
		"tokens_received": true,
		"authenticated":   true,
	})
	
	// Create webhook request with OAuth token context
	webhookRequest := &services.N8NWebhookRequest{
		WorkflowID:  suite.testWebhook.WorkflowID,
		WebhookPath: suite.testWebhook.WebhookPath,
		Method:      "POST",
		Headers: map[string]string{
			"Content-Type":   "application/json",
			"X-User-Context": "authenticated",
		},
		Body: map[string]interface{}{
			"user_id":         suite.testUser.ID,
			"organization_id": suite.testOrg.ID,
			"message":         "Execute workflow with OAuth tokens",
			"oauth_context": map[string]interface{}{
				"provider": "microsoft",
				"tokens": map[string]interface{}{
					"access_token":  suite.testToken.AccessToken,
					"refresh_token": *suite.testToken.RefreshToken,
					"expires_at":    suite.testToken.ExpiresAt.Format(time.RFC3339),
					"scopes":        suite.testToken.Scopes,
				},
				"user_info": map[string]interface{}{
					"user_id":         suite.testUser.ID,
					"email":           suite.testUser.Email,
					"organization_id": suite.testUser.OrganizationID,
				},
			},
			"available_services": []string{
				"microsoft_graph",
				"sharepoint",
				"outlook",
				"teams",
				"onedrive",
			},
		},
		UserID:         suite.testUser.ID,
		OrgID:          suite.testOrg.ID,
		ConversationID: "conv_oauth_123",
		RequestID:      "req_oauth_123",
	}
	
	// Execute webhook
	ctx := context.Background()
	response, err := suite.n8nClient.ExecuteWebhook(ctx, suite.testWebhook, webhookRequest)
	
	// Assertions
	require.NoError(suite.T(), err, "Webhook execution should succeed")
	assert.True(suite.T(), response.Success, "Should return success")
	assert.Equal(suite.T(), http.StatusOK, response.StatusCode)
	assert.NotEmpty(suite.T(), response.ExecutionID)
	
	// Verify OAuth tokens were passed correctly
	_, lastBody := suite.n8nMock.LastRequest()
	var requestBody map[string]interface{}
	err = json.Unmarshal(lastBody, &requestBody)
	require.NoError(suite.T(), err)
	
	oauthContext := requestBody["oauth_context"].(map[string]interface{})
	assert.Equal(suite.T(), "microsoft", oauthContext["provider"])
	
	tokens := oauthContext["tokens"].(map[string]interface{})
	assert.Equal(suite.T(), suite.testToken.AccessToken, tokens["access_token"])
	assert.Equal(suite.T(), *suite.testToken.RefreshToken, tokens["refresh_token"])
	assert.Equal(suite.T(), suite.testToken.Scopes, tokens["scopes"])
	
	availableServices := requestBody["available_services"].([]interface{})
	assert.Contains(suite.T(), availableServices, "microsoft_graph")
	assert.Contains(suite.T(), availableServices, "sharepoint")
	assert.Contains(suite.T(), availableServices, "outlook")
}

// TestWorkflowRetryMechanism tests retry on failure
func (suite *WorkflowTestSuite) TestWorkflowRetryMechanism() {
	callCount := 0
	retryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		
		w.Header().Set("Content-Type", "application/json")
		
		// Fail first two attempts, succeed on third
		if callCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Temporary server error",
				"attempt": callCount,
			})
		} else {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"execution_id": "exec_retry_success",
				"success":      true,
				"attempts":     callCount,
				"message":      "Succeeded after retries",
			})
		}
	}))
	defer retryServer.Close()
	
	// Create webhook config with retry server
	retryWebhook := &models.N8NWebhook{
		OrganizationID: suite.testOrg.ID,
		WorkflowName:   "Retry Test Workflow",
		WorkflowID:     "retry-workflow-123",
		WebhookPath:    "/webhook/retry-test",
		N8NBaseURL:     retryServer.URL,
		AuthMethod:     "bearer",
		AuthToken:      "test-token",
		Active:         true,
	}
	
	// Create webhook request
	webhookRequest := &services.N8NWebhookRequest{
		WorkflowID:     retryWebhook.WorkflowID,
		WebhookPath:    retryWebhook.WebhookPath,
		Method:         "POST",
		Body: map[string]interface{}{
			"test_scenario": "retry_mechanism",
			"user_id":       suite.testUser.ID,
		},
		UserID:         suite.testUser.ID,
		OrgID:          suite.testOrg.ID,
		ConversationID: "conv_retry_123",
		RequestID:      "req_retry_123",
	}
	
	// Execute webhook with retry logic
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	response, err := suite.n8nClient.ExecuteWebhook(ctx, retryWebhook, webhookRequest)
	
	// Assertions
	require.NoError(suite.T(), err, "Should eventually succeed after retries")
	assert.True(suite.T(), response.Success, "Should succeed after retries")
	assert.Equal(suite.T(), http.StatusOK, response.StatusCode, "Final response should be 200")
	assert.NotEmpty(suite.T(), response.ExecutionID, "Should have execution ID")
	
	// Verify retry attempts were made (should be 3 attempts total)
	assert.Equal(suite.T(), 3, callCount, "Should make 3 attempts (initial + 2 retries)")
	
	// Parse response data to verify retry information
	responseData, ok := response.Data.(map[string]interface{})
	require.True(suite.T(), ok, "Response data should be a map")
	assert.Equal(suite.T(), float64(3), responseData["attempts"], "Should report 3 attempts")
	assert.Equal(suite.T(), "Succeeded after retries", responseData["message"])
}

// Helper functions for intent detection testing

func selectToolsForIntent(intent string, confidence float32) []string {
	toolMap := map[string][]string{
		"workflow_execution":  {"n8n", "workflow_engine"},
		"workflow_management": {"n8n", "workflow_builder"},
		"data_query":          {"database", "analytics"},
		"help_guidance":       {"documentation", "guidance"},
		"system_status":       {"monitoring", "health_check"},
		"authentication":      {"oauth", "token_manager"},
		"general":             {},
	}
	
	if tools, exists := toolMap[intent]; exists && confidence >= 0.5 {
		return tools
	}
	
	return []string{}
}

func shouldTriggerWorkflow(intent string, confidence float32) bool {
	triggerIntents := map[string]float32{
		"workflow_execution": 0.6,
		"data_query":         0.7, // Higher threshold for data queries
	}
	
	if threshold, exists := triggerIntents[intent]; exists {
		return confidence >= threshold
	}
	
	return false
}


// cleanupTestData removes all test data from the database
func (suite *WorkflowTestSuite) cleanupTestData() {
	// Delete in reverse order of dependencies
	suite.db.Where("1 = 1").Delete(&models.UserToken{})
	suite.db.Where("1 = 1").Delete(&models.Conversation{})
	suite.db.Where("1 = 1").Delete(&models.N8NWebhook{})
	suite.db.Where("1 = 1").Delete(&models.OAuthProvider{})
	suite.db.Where("1 = 1").Delete(&models.User{})
	suite.db.Where("1 = 1").Delete(&models.Organization{})
}

// TestWorkflowTestSuite runs the workflow test suite
func TestWorkflowTestSuite(t *testing.T) {
	suite.Run(t, new(WorkflowTestSuite))
}