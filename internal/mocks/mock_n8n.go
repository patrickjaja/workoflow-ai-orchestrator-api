package mocks

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
)

// MockN8NClient implements N8NClientInterface for testing
type MockN8NClient struct {
	// Configuration for mock responses
	ShouldError           bool
	ErrorMessage          string
	MockExecutionID       string
	MockStatusCode        int
	MockData             interface{}
	MockExecutionStatus  string
	ExecuteWebhookDelay  time.Duration
	
	// Call tracking
	ExecuteWebhookCalls    []ExecuteWebhookCall
	GetStatusCalls        []GetStatusCall
	GetWorkflowInfoCalls  []GetWorkflowInfoCall
	TestWebhookCalls      []TestWebhookCall
	ValidateConfigCalls   []ValidateConfigCall
	GetHealthStatusCalls  []GetHealthStatusCall
	TotalCalls           int
}

type ExecuteWebhookCall struct {
	WebhookConfig *models.N8NWebhook
	Request       *services.N8NWebhookRequest
	Timestamp     time.Time
}

type GetStatusCall struct {
	WebhookConfig *models.N8NWebhook
	ExecutionID   string
	Timestamp     time.Time
}

type GetWorkflowInfoCall struct {
	WebhookConfig *models.N8NWebhook
	Timestamp     time.Time
}

type TestWebhookCall struct {
	WebhookConfig *models.N8NWebhook
	Timestamp     time.Time
}

type ValidateConfigCall struct {
	WebhookConfig *models.N8NWebhook
	Timestamp     time.Time
}

type GetHealthStatusCall struct {
	BaseURL   string
	Timestamp time.Time
}

// NewMockN8NClient creates a new mock N8N client
func NewMockN8NClient() *MockN8NClient {
	return &MockN8NClient{
		MockExecutionID:     "exec_123456789",
		MockStatusCode:      200,
		MockData:           map[string]interface{}{"status": "success", "message": "Workflow executed successfully"},
		MockExecutionStatus: "success",
	}
}

// ExecuteWebhook mocks webhook execution
func (m *MockN8NClient) ExecuteWebhook(ctx context.Context, webhookConfig *models.N8NWebhook, request *services.N8NWebhookRequest) (*services.N8NWebhookResponse, error) {
	m.ExecuteWebhookCalls = append(m.ExecuteWebhookCalls, ExecuteWebhookCall{
		WebhookConfig: webhookConfig,
		Request:       request,
		Timestamp:     time.Now(),
	})
	m.TotalCalls++
	
	// Simulate execution delay
	if m.ExecuteWebhookDelay > 0 {
		select {
		case <-time.After(m.ExecuteWebhookDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	
	if m.ShouldError {
		return nil, errors.New(m.ErrorMessage)
	}
	
	// Generate response based on request
	response := &services.N8NWebhookResponse{
		Success:     m.MockStatusCode >= 200 && m.MockStatusCode < 300,
		StatusCode:  m.MockStatusCode,
		Data:        m.generateMockResponseData(webhookConfig, request),
		Headers:     map[string]string{
			"Content-Type": "application/json",
			"X-N8N-Execution-Id": m.MockExecutionID,
		},
		ExecutionID: m.MockExecutionID,
		Duration:    time.Duration(100 + (time.Now().UnixNano() % 400)) * time.Millisecond, // Random 100-500ms
		Metadata: map[string]interface{}{
			"webhook_id":      webhookConfig.ID,
			"workflow_name":   webhookConfig.WorkflowName,
			"request_id":      request.RequestID,
			"conversation_id": request.ConversationID,
			"executed_at":     time.Now(),
			"mock":           true,
		},
	}
	
	if !response.Success {
		response.Error = fmt.Sprintf("HTTP %d: Mock error response", m.MockStatusCode)
	}
	
	return response, nil
}

// GetExecutionStatus mocks execution status retrieval
func (m *MockN8NClient) GetExecutionStatus(ctx context.Context, webhookConfig *models.N8NWebhook, executionID string) (*services.N8NExecutionStatus, error) {
	m.GetStatusCalls = append(m.GetStatusCalls, GetStatusCall{
		WebhookConfig: webhookConfig,
		ExecutionID:   executionID,
		Timestamp:     time.Now(),
	})
	m.TotalCalls++
	
	if m.ShouldError {
		return nil, errors.New(m.ErrorMessage)
	}
	
	startTime := time.Now().Add(-5 * time.Minute)
	var stopTime *time.Time
	
	if m.MockExecutionStatus != "running" {
		t := startTime.Add(2 * time.Minute)
		stopTime = &t
	}
	
	return &services.N8NExecutionStatus{
		ID:         executionID,
		WorkflowID: webhookConfig.WorkflowID,
		Status:     m.MockExecutionStatus,
		StartedAt:  &startTime,
		StoppedAt:  stopTime,
		Data: map[string]interface{}{
			"mock":        true,
			"workflow_id": webhookConfig.WorkflowID,
			"executed_by": "mock_system",
			"node_count":  3,
			"success_nodes": 3,
			"output":      "Mock workflow execution completed successfully",
		},
	}, nil
}

// GetWorkflowInfo mocks workflow information retrieval
func (m *MockN8NClient) GetWorkflowInfo(ctx context.Context, webhookConfig *models.N8NWebhook) (*services.N8NWorkflowInfo, error) {
	m.GetWorkflowInfoCalls = append(m.GetWorkflowInfoCalls, GetWorkflowInfoCall{
		WebhookConfig: webhookConfig,
		Timestamp:     time.Now(),
	})
	m.TotalCalls++
	
	if m.ShouldError {
		return nil, errors.New(m.ErrorMessage)
	}
	
	return &services.N8NWorkflowInfo{
		ID:        webhookConfig.WorkflowID,
		Name:      webhookConfig.WorkflowName,
		Active:    true,
		Tags:      []string{"mock", "test", "automation"},
		CreatedAt: time.Now().Add(-24 * time.Hour),
		UpdatedAt: time.Now().Add(-1 * time.Hour),
		Nodes: []services.N8NNodeInfo{
			{
				ID:       "node_1",
				Name:     "Webhook",
				Type:     "n8n-nodes-base.webhook",
				Position: [2]float64{100, 200},
				Parameters: map[string]interface{}{
					"path": webhookConfig.WebhookPath,
					"httpMethod": "POST",
				},
			},
			{
				ID:       "node_2",
				Name:     "Process Data",
				Type:     "n8n-nodes-base.function",
				Position: [2]float64{300, 200},
				Parameters: map[string]interface{}{
					"functionCode": "// Mock function code\nreturn items;",
				},
			},
			{
				ID:       "node_3",
				Name:     "Response",
				Type:     "n8n-nodes-base.respondToWebhook",
				Position: [2]float64{500, 200},
				Parameters: map[string]interface{}{
					"responseBody": "Success",
				},
			},
		},
		Connections: map[string]interface{}{
			"Webhook": map[string]interface{}{
				"main": [][]map[string]interface{}{
					{
						{"node": "Process Data", "type": "main", "index": 0},
					},
				},
			},
			"Process Data": map[string]interface{}{
				"main": [][]map[string]interface{}{
					{
						{"node": "Response", "type": "main", "index": 0},
					},
				},
			},
		},
		Settings: map[string]interface{}{
			"timezone": "America/New_York",
			"saveExecutionProgress": true,
			"saveDataErrorExecution": "all",
			"saveDataSuccessExecution": "all",
		},
	}, nil
}

// TestWebhook mocks webhook testing
func (m *MockN8NClient) TestWebhook(ctx context.Context, webhookConfig *models.N8NWebhook) (*services.N8NWebhookResponse, error) {
	m.TestWebhookCalls = append(m.TestWebhookCalls, TestWebhookCall{
		WebhookConfig: webhookConfig,
		Timestamp:     time.Now(),
	})
	m.TotalCalls++
	
	if m.ShouldError {
		return nil, errors.New(m.ErrorMessage)
	}
	
	// Create a test request
	testRequest := &services.N8NWebhookRequest{
		WorkflowID:  webhookConfig.WorkflowID,
		WebhookPath: webhookConfig.WebhookPath,
		Method:      "GET",
		Headers:     map[string]string{},
		Parameters: map[string]interface{}{
			"test":      true,
			"timestamp": time.Now().Unix(),
		},
		RequestID: fmt.Sprintf("test_%d", time.Now().UnixNano()),
	}
	
	return m.ExecuteWebhook(ctx, webhookConfig, testRequest)
}

// ValidateWebhookConfig mocks webhook configuration validation
func (m *MockN8NClient) ValidateWebhookConfig(webhookConfig *models.N8NWebhook) error {
	m.ValidateConfigCalls = append(m.ValidateConfigCalls, ValidateConfigCall{
		WebhookConfig: webhookConfig,
		Timestamp:     time.Now(),
	})
	m.TotalCalls++
	
	if m.ShouldError {
		return errors.New(m.ErrorMessage)
	}
	
	// Mock validation logic
	if webhookConfig.N8NBaseURL == "" {
		return errors.New("n8n base URL is required")
	}
	
	if webhookConfig.WebhookPath == "" {
		return errors.New("webhook path is required")
	}
	
	if webhookConfig.AuthMethod != "" && webhookConfig.AuthToken == "" {
		return errors.New("auth token is required when auth method is specified")
	}
	
	return nil
}

// GetHealthStatus mocks health status check
func (m *MockN8NClient) GetHealthStatus(ctx context.Context, baseURL string) (bool, error) {
	m.GetHealthStatusCalls = append(m.GetHealthStatusCalls, GetHealthStatusCall{
		BaseURL:   baseURL,
		Timestamp: time.Now(),
	})
	m.TotalCalls++
	
	if m.ShouldError {
		return false, errors.New(m.ErrorMessage)
	}
	
	return true, nil // Mock n8n as healthy
}

// generateMockResponseData generates contextual mock response data
func (m *MockN8NClient) generateMockResponseData(webhookConfig *models.N8NWebhook, request *services.N8NWebhookRequest) interface{} {
	if m.MockData != nil {
		return m.MockData
	}
	
	// Generate response based on workflow name
	switch webhookConfig.WorkflowName {
	case "send_email":
		return map[string]interface{}{
			"message":     "Email sent successfully",
			"message_id":  fmt.Sprintf("msg_%d", time.Now().UnixNano()),
			"recipient":   request.Parameters["recipient"],
			"subject":     request.Parameters["subject"],
			"sent_at":     time.Now(),
		}
		
	case "create_ticket":
		return map[string]interface{}{
			"message":    "Ticket created successfully",
			"ticket_id":  fmt.Sprintf("TK-%d", 1000+time.Now().UnixNano()%9000),
			"title":      request.Parameters["title"],
			"priority":   request.Parameters["priority"],
			"created_at": time.Now(),
			"status":     "open",
		}
		
	case "data_sync":
		return map[string]interface{}{
			"message":        "Data synchronization completed",
			"sync_id":        fmt.Sprintf("sync_%d", time.Now().UnixNano()),
			"records_synced": 42,
			"source":         request.Parameters["source"],
			"destination":    request.Parameters["destination"],
			"sync_time":      time.Now(),
		}
		
	default:
		return map[string]interface{}{
			"message":       "Mock workflow executed successfully",
			"execution_id":  m.MockExecutionID,
			"workflow_name": webhookConfig.WorkflowName,
			"timestamp":     time.Now(),
			"mock":         true,
		}
	}
}

// Helper methods for testing

// SetError configures the mock to return an error
func (m *MockN8NClient) SetError(shouldError bool, errorMessage string) {
	m.ShouldError = shouldError
	m.ErrorMessage = errorMessage
}

// SetExecutionID configures the mock execution ID
func (m *MockN8NClient) SetExecutionID(executionID string) {
	m.MockExecutionID = executionID
}

// SetStatusCode configures the mock status code
func (m *MockN8NClient) SetStatusCode(statusCode int) {
	m.MockStatusCode = statusCode
}

// SetData configures the mock response data
func (m *MockN8NClient) SetData(data interface{}) {
	m.MockData = data
}

// SetExecutionStatus configures the mock execution status
func (m *MockN8NClient) SetExecutionStatus(status string) {
	m.MockExecutionStatus = status
}

// SetDelay configures execution delay
func (m *MockN8NClient) SetDelay(delay time.Duration) {
	m.ExecuteWebhookDelay = delay
}

// GetCallCount returns the total number of calls made
func (m *MockN8NClient) GetCallCount() int {
	return m.TotalCalls
}

// GetLastExecuteWebhookCall returns the last ExecuteWebhook call
func (m *MockN8NClient) GetLastExecuteWebhookCall() *ExecuteWebhookCall {
	if len(m.ExecuteWebhookCalls) == 0 {
		return nil
	}
	return &m.ExecuteWebhookCalls[len(m.ExecuteWebhookCalls)-1]
}

// GetExecuteWebhookCalls returns all ExecuteWebhook calls
func (m *MockN8NClient) GetExecuteWebhookCalls() []ExecuteWebhookCall {
	return m.ExecuteWebhookCalls
}

// Reset clears all call tracking
func (m *MockN8NClient) Reset() {
	m.ExecuteWebhookCalls = []ExecuteWebhookCall{}
	m.GetStatusCalls = []GetStatusCall{}
	m.GetWorkflowInfoCalls = []GetWorkflowInfoCall{}
	m.TestWebhookCalls = []TestWebhookCall{}
	m.ValidateConfigCalls = []ValidateConfigCall{}
	m.GetHealthStatusCalls = []GetHealthStatusCall{}
	m.TotalCalls = 0
	m.ShouldError = false
	m.ErrorMessage = ""
}

// Predefined scenarios for testing

// SetupSuccessfulExecutionScenario configures the mock for successful execution
func (m *MockN8NClient) SetupSuccessfulExecutionScenario() {
	m.MockStatusCode = 200
	m.MockExecutionStatus = "success"
	m.MockData = map[string]interface{}{
		"message": "Workflow executed successfully",
		"status":  "completed",
	}
}

// SetupFailedExecutionScenario configures the mock for failed execution
func (m *MockN8NClient) SetupFailedExecutionScenario() {
	m.MockStatusCode = 500
	m.MockExecutionStatus = "error"
	m.MockData = map[string]interface{}{
		"error":   "Workflow execution failed",
		"status":  "failed",
	}
}

// SetupRunningExecutionScenario configures the mock for running execution
func (m *MockN8NClient) SetupRunningExecutionScenario() {
	m.MockStatusCode = 202
	m.MockExecutionStatus = "running"
	m.MockData = map[string]interface{}{
		"message": "Workflow execution started",
		"status":  "running",
	}
}