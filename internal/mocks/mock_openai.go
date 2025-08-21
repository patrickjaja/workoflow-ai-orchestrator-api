package mocks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/workoflow/ai-orchestrator-api/internal/services"
)

// MockAIService implements AIServiceInterface for testing
type MockAIService struct {
	// Configuration for mock responses
	ShouldError         bool
	ErrorMessage        string
	MockResponse        string
	MockIntent          string
	MockConfidence      float32
	MockActions         []services.AIAction
	ProcessMessageDelay time.Duration
	
	// Call tracking
	ProcessMessageCalls    []services.ChatRequest
	SummaryCalls          []string
	ValidationCalls       []ValidationCall
	TotalCalls            int
}

type ValidationCall struct {
	WorkflowName string
	Parameters   map[string]interface{}
}

// NewMockAIService creates a new mock AI service
func NewMockAIService() *MockAIService {
	return &MockAIService{
		MockResponse:   "I'm a mock AI assistant. I can help you with workflow orchestration tasks.",
		MockIntent:     "general",
		MockConfidence: 0.8,
		MockActions:    []services.AIAction{},
	}
}

// ProcessMessage mocks AI message processing
func (m *MockAIService) ProcessMessage(ctx context.Context, req *services.ChatRequest) (*services.AIResponse, error) {
	m.ProcessMessageCalls = append(m.ProcessMessageCalls, *req)
	m.TotalCalls++
	
	// Simulate processing delay
	if m.ProcessMessageDelay > 0 {
		select {
		case <-time.After(m.ProcessMessageDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	
	if m.ShouldError {
		return nil, errors.New(m.ErrorMessage)
	}
	
	// Generate response based on input
	response := m.generateMockResponse(req.Message)
	
	return &services.AIResponse{
		Text:       response.Text,
		Intent:     response.Intent,
		Confidence: response.Confidence,
		Actions:    response.Actions,
		Context:    req.Context,
		Metadata: map[string]interface{}{
			"mock":          true,
			"request_id":    fmt.Sprintf("mock_%d", time.Now().UnixNano()),
			"model":         "mock-gpt-4",
			"usage_tokens":  100,
			"created_at":    time.Now(),
			"conversation_id": req.ConversationID,
		},
	}, nil
}

// GetConversationSummary mocks conversation summary generation
func (m *MockAIService) GetConversationSummary(ctx context.Context, conversationID string) (string, error) {
	m.SummaryCalls = append(m.SummaryCalls, conversationID)
	m.TotalCalls++
	
	if m.ShouldError {
		return "", errors.New(m.ErrorMessage)
	}
	
	return fmt.Sprintf("Mock conversation summary for conversation %s: This is a test conversation about workflow orchestration and AI assistance.", conversationID), nil
}

// ValidateWorkflowParameters mocks workflow parameter validation
func (m *MockAIService) ValidateWorkflowParameters(ctx context.Context, workflowName string, parameters map[string]interface{}) (bool, []string, error) {
	m.ValidationCalls = append(m.ValidationCalls, ValidationCall{
		WorkflowName: workflowName,
		Parameters:   parameters,
	})
	m.TotalCalls++
	
	if m.ShouldError {
		return false, nil, errors.New(m.ErrorMessage)
	}
	
	// Simple mock validation logic
	var errors []string
	
	// Check for required parameters based on workflow name
	switch workflowName {
	case "send_email":
		if _, ok := parameters["recipient"]; !ok {
			errors = append(errors, "recipient is required")
		}
		if _, ok := parameters["subject"]; !ok {
			errors = append(errors, "subject is required")
		}
	case "create_ticket":
		if _, ok := parameters["title"]; !ok {
			errors = append(errors, "title is required")
		}
		if _, ok := parameters["priority"]; !ok {
			errors = append(errors, "priority is required")
		}
	case "data_sync":
		if _, ok := parameters["source"]; !ok {
			errors = append(errors, "source is required")
		}
		if _, ok := parameters["destination"]; !ok {
			errors = append(errors, "destination is required")
		}
	}
	
	return len(errors) == 0, errors, nil
}

// generateMockResponse generates contextual mock responses
func (m *MockAIService) generateMockResponse(message string) *services.AIResponse {
	message = strings.ToLower(message)
	
	response := &services.AIResponse{
		Confidence: m.MockConfidence,
	}
	
	// Generate intent and response based on message content
	switch {
	case strings.Contains(message, "execute") || strings.Contains(message, "run") || strings.Contains(message, "trigger"):
		response.Intent = "workflow_execution"
		response.Text = "I can help you execute a workflow. Please specify which workflow you'd like to run and provide any required parameters."
		response.Actions = []services.AIAction{
			{
				Type:   "workflow_execution",
				Target: "n8n_webhook",
				Parameters: map[string]interface{}{
					"workflow_name": "extracted_from_message",
					"confirmation_required": true,
				},
				Priority: 1,
			},
		}
		
	case strings.Contains(message, "create") || strings.Contains(message, "configure") || strings.Contains(message, "setup"):
		response.Intent = "workflow_management"
		response.Text = "I can assist you with creating or configuring workflows. What type of workflow would you like to set up?"
		response.Actions = []services.AIAction{
			{
				Type:   "workflow_management",
				Target: "workflow_config",
				Parameters: map[string]interface{}{
					"action": "create",
				},
				Priority: 2,
			},
		}
		
	case strings.Contains(message, "show") || strings.Contains(message, "status") || strings.Contains(message, "history"):
		response.Intent = "data_query"
		response.Text = "I can help you retrieve information about your workflows, executions, or data. What specific information are you looking for?"
		response.Actions = []services.AIAction{
			{
				Type:   "data_retrieval",
				Target: "database",
				Parameters: map[string]interface{}{
					"query_type": "status_check",
				},
				Priority: 3,
			},
		}
		
	case strings.Contains(message, "help") || strings.Contains(message, "how") || strings.Contains(message, "what"):
		response.Intent = "help_guidance"
		response.Text = "I'm here to help! I can assist you with workflow execution, management, and data queries. You can ask me to run workflows, check their status, or help configure new automations."
		
	case strings.Contains(message, "hello") || strings.Contains(message, "hi") || strings.Contains(message, "hey"):
		response.Intent = "general"
		response.Text = "Hello! I'm your AI workflow orchestration assistant. I can help you execute workflows, manage automations, and query your data. How can I assist you today?"
		
	default:
		response.Intent = m.MockIntent
		response.Text = m.MockResponse
		response.Actions = m.MockActions
	}
	
	return response
}

// Helper methods for testing

// SetError configures the mock to return an error
func (m *MockAIService) SetError(shouldError bool, errorMessage string) {
	m.ShouldError = shouldError
	m.ErrorMessage = errorMessage
}

// SetResponse configures the mock response
func (m *MockAIService) SetResponse(response string, intent string, confidence float32) {
	m.MockResponse = response
	m.MockIntent = intent
	m.MockConfidence = confidence
}

// SetActions configures mock actions
func (m *MockAIService) SetActions(actions []services.AIAction) {
	m.MockActions = actions
}

// SetDelay configures processing delay
func (m *MockAIService) SetDelay(delay time.Duration) {
	m.ProcessMessageDelay = delay
}

// GetCallCount returns the total number of calls made
func (m *MockAIService) GetCallCount() int {
	return m.TotalCalls
}

// GetLastProcessMessageCall returns the last ProcessMessage call
func (m *MockAIService) GetLastProcessMessageCall() *services.ChatRequest {
	if len(m.ProcessMessageCalls) == 0 {
		return nil
	}
	return &m.ProcessMessageCalls[len(m.ProcessMessageCalls)-1]
}

// GetProcessMessageCalls returns all ProcessMessage calls
func (m *MockAIService) GetProcessMessageCalls() []services.ChatRequest {
	return m.ProcessMessageCalls
}

// GetSummaryCalls returns all summary calls
func (m *MockAIService) GetSummaryCalls() []string {
	return m.SummaryCalls
}

// GetValidationCalls returns all validation calls
func (m *MockAIService) GetValidationCalls() []ValidationCall {
	return m.ValidationCalls
}

// Reset clears all call tracking
func (m *MockAIService) Reset() {
	m.ProcessMessageCalls = []services.ChatRequest{}
	m.SummaryCalls = []string{}
	m.ValidationCalls = []ValidationCall{}
	m.TotalCalls = 0
	m.ShouldError = false
	m.ErrorMessage = ""
}

// Predefined mock responses for common scenarios

// SetupWorkflowExecutionScenario configures the mock for workflow execution testing
func (m *MockAIService) SetupWorkflowExecutionScenario() {
	m.MockIntent = "workflow_execution"
	m.MockResponse = "I'll help you execute the requested workflow. Please confirm the parameters."
	m.MockConfidence = 0.9
	m.MockActions = []services.AIAction{
		{
			Type:   "workflow_execution",
			Target: "n8n_webhook",
			Parameters: map[string]interface{}{
				"workflow_name": "test_workflow",
				"requires_confirmation": true,
			},
			Priority: 1,
		},
	}
}

// SetupDataQueryScenario configures the mock for data query testing
func (m *MockAIService) SetupDataQueryScenario() {
	m.MockIntent = "data_query"
	m.MockResponse = "I can help you retrieve that information. Let me check the current status."
	m.MockConfidence = 0.85
	m.MockActions = []services.AIAction{
		{
			Type:   "data_retrieval",
			Target: "database",
			Parameters: map[string]interface{}{
				"query_type": "execution_history",
			},
			Priority: 2,
		},
	}
}

// SetupErrorScenario configures the mock to simulate errors
func (m *MockAIService) SetupErrorScenario(errorMessage string) {
	m.ShouldError = true
	m.ErrorMessage = errorMessage
}