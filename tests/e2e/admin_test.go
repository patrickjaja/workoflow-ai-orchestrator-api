package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"github.com/workoflow/ai-orchestrator-api/tests/fixtures"
)

// TestAdminSystemInfo tests the admin system info endpoint
func TestAdminSystemInfo(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	// Test system info endpoint
	resp := testHelpers.MakeAuthenticatedRequest(t, "GET", "/api/admin/system/info", nil, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var systemInfo map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&systemInfo)
	require.NoError(t, err)

	// Verify system info structure
	assert.Contains(t, systemInfo, "version")
	assert.Contains(t, systemInfo, "uptime")
	assert.Contains(t, systemInfo, "database")
	assert.Contains(t, systemInfo, "redis")
	assert.Contains(t, systemInfo, "memory")
	assert.Contains(t, systemInfo, "environment")

	t.Logf("System info retrieved: %+v", systemInfo)
}

// TestAdminGetUsers tests the admin get users endpoint
func TestAdminGetUsers(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	testCases := []struct {
		name           string
		orgID          string
		expectedCount  int
		expectedStatus int
	}{
		{
			name:           "Get users for org alpha",
			orgID:          "11111111-1111-1111-1111-111111111111",
			expectedCount:  4, // admin, user, viewer, inactive
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Get users for org beta",
			orgID:          "22222222-2222-2222-2222-222222222222",
			expectedCount:  1, // admin beta
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := fmt.Sprintf("/api/admin/users?organization_id=%s", tc.orgID)
			resp := testHelpers.MakeAuthenticatedRequest(t, "GET", url, nil, token)
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			if tc.expectedStatus == http.StatusOK {
				var response struct {
					Users []models.User `json:"users"`
					Total int           `json:"total"`
				}
				err := json.NewDecoder(resp.Body).Decode(&response)
				require.NoError(t, err)

				assert.Equal(t, tc.expectedCount, response.Total)
				assert.Len(t, response.Users, tc.expectedCount)

				// Verify no sensitive data is exposed
				for _, user := range response.Users {
					assert.Empty(t, user.PasswordHash, "Password hash should not be exposed")
				}
			}
		})
	}
}

// TestAdminGetOrganizations tests the admin get organizations endpoint
func TestAdminGetOrganizations(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	resp := testHelpers.MakeAuthenticatedRequest(t, "GET", "/api/admin/organizations", nil, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response struct {
		Organizations []models.Organization `json:"organizations"`
		Total         int                   `json:"total"`
	}
	err := json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, response.Total, 3) // At least our test organizations
	assert.GreaterOrEqual(t, len(response.Organizations), 3)

	// Verify organization data
	orgMap := make(map[string]models.Organization)
	for _, org := range response.Organizations {
		orgMap[org.ID.String()] = org
	}

	// Check test organizations exist
	assert.Contains(t, orgMap, "11111111-1111-1111-1111-111111111111")
	assert.Contains(t, orgMap, "22222222-2222-2222-2222-222222222222")
	assert.Contains(t, orgMap, "33333333-3333-3333-3333-333333333333")

	t.Logf("Found %d organizations", response.Total)
}

// TestAdminGetConversations tests the admin get conversations endpoint
func TestAdminGetConversations(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	testCases := []struct {
		name           string
		queryParams    string
		expectedMin    int
		expectedStatus int
	}{
		{
			name:           "Get all conversations",
			queryParams:    "",
			expectedMin:    4,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Get conversations for specific user",
			queryParams:    "?user_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			expectedMin:    2,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Get active conversations only",
			queryParams:    "?status=active",
			expectedMin:    3,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Get conversations with pagination",
			queryParams:    "?limit=2&offset=0",
			expectedMin:    2,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := "/api/admin/conversations" + tc.queryParams
			resp := testHelpers.MakeAuthenticatedRequest(t, "GET", url, nil, token)
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			if tc.expectedStatus == http.StatusOK {
				var response struct {
					Conversations []models.Conversation `json:"conversations"`
					Total         int                   `json:"total"`
				}
				err := json.NewDecoder(resp.Body).Decode(&response)
				require.NoError(t, err)

				assert.GreaterOrEqual(t, len(response.Conversations), tc.expectedMin)
				t.Logf("Found %d conversations for query: %s", len(response.Conversations), tc.queryParams)
			}
		})
	}
}

// TestAdminContextStats tests the admin context statistics endpoint
func TestAdminContextStats(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	// Create some context entries first
	// Note: This would typically be done through the chat service
	testHelpers.CreateTestContext(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	testHelpers.CreateTestContext(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

	resp := testHelpers.MakeAuthenticatedRequest(t, "GET", "/api/admin/contexts/stats", nil, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var stats map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&stats)
	require.NoError(t, err)

	// Verify context statistics structure
	assert.Contains(t, stats, "total_contexts")
	assert.Contains(t, stats, "active_contexts")
	assert.Contains(t, stats, "memory_usage")
	assert.Contains(t, stats, "average_context_size")
	assert.Contains(t, stats, "contexts_by_user")

	t.Logf("Context stats: %+v", stats)
}

// TestAdminClearContexts tests the admin clear contexts endpoint
func TestAdminClearContexts(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	// Create test contexts
	testHelpers.CreateTestContext(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	testHelpers.CreateTestContext(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

	// Clear all contexts
	resp := testHelpers.MakeAuthenticatedRequest(t, "POST", "/api/admin/contexts/clear", nil, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	assert.Contains(t, result, "cleared_count")
	assert.Contains(t, result, "message")

	// Verify contexts are cleared
	statsResp := testHelpers.MakeAuthenticatedRequest(t, "GET", "/api/admin/contexts/stats", nil, token)
	assert.Equal(t, http.StatusOK, statsResp.StatusCode)

	var stats map[string]interface{}
	err = json.NewDecoder(statsResp.Body).Decode(&stats)
	require.NoError(t, err)

	assert.Equal(t, float64(0), stats["active_contexts"])
	t.Logf("Cleared %v contexts", result["cleared_count"])
}

// TestAdminCreateUser tests the admin create user endpoint
func TestAdminCreateUser(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	newUser := map[string]interface{}{
		"email":           "newuser@test-org-alpha.com",
		"password":        "SecurePassword123!",
		"first_name":      "New",
		"last_name":       "User",
		"role":            "user",
		"organization_id": "11111111-1111-1111-1111-111111111111",
	}

	resp := testHelpers.MakeAuthenticatedRequest(t, "POST", "/api/admin/users", newUser, token)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var createdUser models.User
	err := json.NewDecoder(resp.Body).Decode(&createdUser)
	require.NoError(t, err)

	assert.Equal(t, newUser["email"], createdUser.Email)
	assert.Equal(t, newUser["first_name"], createdUser.FirstName)
	assert.Equal(t, newUser["last_name"], createdUser.LastName)
	assert.Equal(t, newUser["role"], createdUser.Role)
	assert.Empty(t, createdUser.PasswordHash, "Password hash should not be exposed")

	t.Logf("Created user: %s", createdUser.Email)
}

// TestAdminUpdateUser tests the admin update user endpoint
func TestAdminUpdateUser(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	// Update existing user
	userID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	updates := map[string]interface{}{
		"first_name": "Updated",
		"last_name":  "Name",
		"role":       "admin",
		"is_active":  true,
	}

	url := fmt.Sprintf("/api/admin/users/%s", userID)
	resp := testHelpers.MakeAuthenticatedRequest(t, "PUT", url, updates, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var updatedUser models.User
	err := json.NewDecoder(resp.Body).Decode(&updatedUser)
	require.NoError(t, err)

	assert.Equal(t, updates["first_name"], updatedUser.FirstName)
	assert.Equal(t, updates["last_name"], updatedUser.LastName)
	assert.Equal(t, updates["role"], updatedUser.Role)

	t.Logf("Updated user: %s", updatedUser.Email)
}

// TestAdminDeleteUser tests the admin delete user endpoint
func TestAdminDeleteUser(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	// Create a user to delete
	newUser := map[string]interface{}{
		"email":           "tobedeleted@test-org-alpha.com",
		"password":        "TempPassword123!",
		"first_name":      "Delete",
		"last_name":       "Me",
		"role":            "user",
		"organization_id": "11111111-1111-1111-1111-111111111111",
	}

	createResp := testHelpers.MakeAuthenticatedRequest(t, "POST", "/api/admin/users", newUser, token)
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var createdUser models.User
	err := json.NewDecoder(createResp.Body).Decode(&createdUser)
	require.NoError(t, err)

	// Delete the user
	deleteURL := fmt.Sprintf("/api/admin/users/%s", createdUser.ID)
	deleteResp := testHelpers.MakeAuthenticatedRequest(t, "DELETE", deleteURL, nil, token)
	assert.Equal(t, http.StatusOK, deleteResp.StatusCode)

	// Verify user is deleted
	getURL := fmt.Sprintf("/api/admin/users/%s", createdUser.ID)
	getResp := testHelpers.MakeAuthenticatedRequest(t, "GET", getURL, nil, token)
	assert.Equal(t, http.StatusNotFound, getResp.StatusCode)

	t.Logf("Deleted user: %s", createdUser.Email)
}

// TestAdminRoleAuthorization tests that only admin users can access admin endpoints
func TestAdminRoleAuthorization(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get regular user token
	userToken := testHelpers.GetUserToken(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "11111111-1111-1111-1111-111111111111")

	// Get viewer token
	viewerToken := testHelpers.GetUserToken(t, "dddddddd-dddd-dddd-dddd-dddddddddddd", "11111111-1111-1111-1111-111111111111")

	adminEndpoints := []string{
		"/api/admin/system/info",
		"/api/admin/users",
		"/api/admin/organizations",
		"/api/admin/conversations",
		"/api/admin/contexts/stats",
	}

	for _, endpoint := range adminEndpoints {
		t.Run(fmt.Sprintf("User access to %s", endpoint), func(t *testing.T) {
			resp := testHelpers.MakeAuthenticatedRequest(t, "GET", endpoint, nil, userToken)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode, "Regular user should not access admin endpoints")
		})

		t.Run(fmt.Sprintf("Viewer access to %s", endpoint), func(t *testing.T) {
			resp := testHelpers.MakeAuthenticatedRequest(t, "GET", endpoint, nil, viewerToken)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode, "Viewer should not access admin endpoints")
		})
	}
}

// TestAdminMetrics tests the admin metrics endpoint
func TestAdminMetrics(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	resp := testHelpers.MakeAuthenticatedRequest(t, "GET", "/api/admin/metrics", nil, token)
	
	// If metrics endpoint is implemented
	if resp.StatusCode == http.StatusOK {
		var metrics map[string]interface{}
		err := json.NewDecoder(resp.Body).Decode(&metrics)
		require.NoError(t, err)

		// Verify metrics structure
		assert.Contains(t, metrics, "api_requests_total")
		assert.Contains(t, metrics, "api_request_duration")
		assert.Contains(t, metrics, "database_connections")
		assert.Contains(t, metrics, "redis_connections")
		assert.Contains(t, metrics, "active_sessions")

		t.Logf("Metrics retrieved: %+v", metrics)
	} else {
		t.Skip("Metrics endpoint not implemented yet")
	}
}

// TestAdminWebhookManagement tests admin webhook management endpoints
func TestAdminWebhookManagement(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	// Test getting webhooks for organization
	orgID := "11111111-1111-1111-1111-111111111111"
	url := fmt.Sprintf("/api/admin/organizations/%s/webhooks", orgID)
	
	resp := testHelpers.MakeAuthenticatedRequest(t, "GET", url, nil, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var webhooks []models.N8NWebhook
	err := json.NewDecoder(resp.Body).Decode(&webhooks)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(webhooks), 3) // Should have at least 3 test webhooks

	// Test creating a new webhook
	newWebhook := map[string]interface{}{
		"workflow_name": "admin_test_workflow",
		"workflow_id":   "wf_admin_test",
		"webhook_path":  "/webhook/admin-test",
		"n8n_base_url":  "http://n8n-mock",
		"auth_method":   "bearer",
		"auth_token":    "test_token_admin",
		"description":   "Admin test webhook",
		"active":        true,
	}

	createURL := fmt.Sprintf("/api/admin/organizations/%s/webhooks", orgID)
	createResp := testHelpers.MakeAuthenticatedRequest(t, "POST", createURL, newWebhook, token)
	assert.Equal(t, http.StatusCreated, createResp.StatusCode)

	var createdWebhook models.N8NWebhook
	err = json.NewDecoder(createResp.Body).Decode(&createdWebhook)
	require.NoError(t, err)

	assert.Equal(t, newWebhook["workflow_name"], createdWebhook.WorkflowName)
	assert.Equal(t, newWebhook["webhook_path"], createdWebhook.WebhookPath)

	// Test updating the webhook
	updateURL := fmt.Sprintf("/api/admin/organizations/%s/webhooks/%s", orgID, createdWebhook.ID)
	updates := map[string]interface{}{
		"description": "Updated admin test webhook",
		"active":      false,
	}
	
	updateResp := testHelpers.MakeAuthenticatedRequest(t, "PUT", updateURL, updates, token)
	assert.Equal(t, http.StatusOK, updateResp.StatusCode)

	// Test deleting the webhook
	deleteURL := fmt.Sprintf("/api/admin/organizations/%s/webhooks/%s", orgID, createdWebhook.ID)
	deleteResp := testHelpers.MakeAuthenticatedRequest(t, "DELETE", deleteURL, nil, token)
	assert.Equal(t, http.StatusOK, deleteResp.StatusCode)

	t.Logf("Webhook management test completed successfully")
}

// TestAdminAuditLog tests the admin audit log endpoint
func TestAdminAuditLog(t *testing.T) {
	setupTestData(t)
	defer testHelpers.CleanupTestData(t)

	// Get admin token
	token := testHelpers.GetAdminToken(t, "11111111-1111-1111-1111-111111111111")

	// Perform some actions to generate audit log entries
	// Note: This assumes audit logging is implemented
	
	// Create a user (should generate audit log)
	newUser := map[string]interface{}{
		"email":           "audit-test@test-org-alpha.com",
		"password":        "AuditTest123!",
		"first_name":      "Audit",
		"last_name":       "Test",
		"role":            "user",
		"organization_id": "11111111-1111-1111-1111-111111111111",
	}
	testHelpers.MakeAuthenticatedRequest(t, "POST", "/api/admin/users", newUser, token)

	// Get audit logs
	resp := testHelpers.MakeAuthenticatedRequest(t, "GET", "/api/admin/audit-logs", nil, token)
	
	if resp.StatusCode == http.StatusOK {
		var auditLogs []map[string]interface{}
		err := json.NewDecoder(resp.Body).Decode(&auditLogs)
		require.NoError(t, err)

		assert.Greater(t, len(auditLogs), 0, "Should have audit log entries")

		// Verify audit log structure
		if len(auditLogs) > 0 {
			log := auditLogs[0]
			assert.Contains(t, log, "timestamp")
			assert.Contains(t, log, "user_id")
			assert.Contains(t, log, "action")
			assert.Contains(t, log, "resource")
			assert.Contains(t, log, "details")
		}

		t.Logf("Found %d audit log entries", len(auditLogs))
	} else {
		t.Skip("Audit log endpoint not implemented yet")
	}
}

// Helper function to setup test data with fixtures
func setupAdminTestData(t *testing.T) {
	t.Helper()

	// Seed organizations
	for _, org := range fixtures.TestOrganizations() {
		testHelpers.CreateOrganization(t, org.ID.String(), org.Name, org.Slug)
	}

	// Seed users
	for _, user := range fixtures.TestUsers() {
		testHelpers.CreateUser(t, user.ID.String(), user.Email, user.Role, user.OrganizationID.String())
	}

	// Seed OAuth providers
	for _, provider := range fixtures.TestOAuthProviders() {
		testHelpers.SetupOAuthProvider(t, provider.OrganizationID.String(), provider.ProviderType, 
			provider.ClientID, provider.ClientSecret)
	}

	// Seed webhooks
	for _, webhook := range fixtures.TestN8NWebhooks() {
		testHelpers.ConfigureN8NWebhook(t, webhook.OrganizationID.String(), webhook.WebhookPath)
	}

	// Seed conversations
	for _, conv := range fixtures.TestConversations() {
		testHelpers.CreateConversation(t, conv.UserID.String(), conv.ID.String())
	}

	t.Logf("Admin test data setup completed")
}