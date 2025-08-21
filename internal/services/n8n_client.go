package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/workoflow/ai-orchestrator-api/internal/config"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
)

type N8NClient struct {
	config     *config.Config
	httpClient *http.Client
}

type N8NWebhookRequest struct {
	WorkflowID   string                 `json:"workflow_id"`
	WebhookPath  string                 `json:"webhook_path"`
	Method       string                 `json:"method"`
	Headers      map[string]string      `json:"headers"`
	Parameters   map[string]interface{} `json:"parameters"`
	Body         interface{}            `json:"body"`
	UserID       uint                   `json:"user_id"`
	OrgID        uint                   `json:"organization_id"`
	ConversationID string               `json:"conversation_id"`
	RequestID    string                 `json:"request_id"`
}

type N8NWebhookResponse struct {
	Success    bool                   `json:"success"`
	StatusCode int                    `json:"status_code"`
	Data       interface{}            `json:"data"`
	Error      string                 `json:"error,omitempty"`
	Headers    map[string]string      `json:"headers"`
	ExecutionID string                `json:"execution_id,omitempty"`
	Duration   time.Duration          `json:"duration"`
	Metadata   map[string]interface{} `json:"metadata"`
}

type N8NExecutionStatus struct {
	ID         string                 `json:"id"`
	WorkflowID string                 `json:"workflow_id"`
	Status     string                 `json:"status"` // running, success, error, canceled
	StartedAt  *time.Time             `json:"started_at"`
	StoppedAt  *time.Time             `json:"stopped_at"`
	Data       map[string]interface{} `json:"data"`
	Error      string                 `json:"error,omitempty"`
}

type N8NWorkflowInfo struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Active      bool                   `json:"active"`
	Tags        []string               `json:"tags"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Nodes       []N8NNodeInfo          `json:"nodes"`
	Connections map[string]interface{} `json:"connections"`
	Settings    map[string]interface{} `json:"settings"`
}

type N8NNodeInfo struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Position [2]float64             `json:"position"`
	Parameters map[string]interface{} `json:"parameters"`
}

func NewN8NClient(cfg *config.Config) *N8NClient {
	return &N8NClient{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.N8N.DefaultTimeout,
		},
	}
}

func (c *N8NClient) ExecuteWebhook(ctx context.Context, webhookConfig *models.N8NWebhook, request *N8NWebhookRequest) (*N8NWebhookResponse, error) {
	startTime := time.Now()

	// Build the webhook URL
	webhookURL, err := c.buildWebhookURL(webhookConfig, request)
	if err != nil {
		return nil, fmt.Errorf("failed to build webhook URL: %w", err)
	}

	// Prepare request body
	var bodyReader io.Reader
	if request.Body != nil {
		bodyBytes, err := json.Marshal(request.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, request.Method, webhookURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "AI-Orchestrator/1.0")
	
	// Add custom headers
	for key, value := range request.Headers {
		httpReq.Header.Set(key, value)
	}

	// Add authentication if configured
	if webhookConfig.AuthMethod != "" {
		err = c.addAuthentication(httpReq, webhookConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to add authentication: %w", err)
		}
	}

	// Execute request with retry logic
	response, err := c.executeWithRetry(ctx, httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute webhook: %w", err)
	}
	defer response.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response
	var responseData interface{}
	if len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, &responseData); err != nil {
			// If JSON parsing fails, store as string
			responseData = string(responseBody)
		}
	}

	// Build response headers map
	responseHeaders := make(map[string]string)
	for key, values := range response.Header {
		if len(values) > 0 {
			responseHeaders[key] = values[0]
		}
	}

	duration := time.Since(startTime)

	webhookResponse := &N8NWebhookResponse{
		Success:    response.StatusCode >= 200 && response.StatusCode < 300,
		StatusCode: response.StatusCode,
		Data:       responseData,
		Headers:    responseHeaders,
		Duration:   duration,
		Metadata: map[string]interface{}{
			"webhook_id":      webhookConfig.ID,
			"workflow_name":   webhookConfig.WorkflowName,
			"request_id":      request.RequestID,
			"conversation_id": request.ConversationID,
			"executed_at":     startTime,
		},
	}

	if !webhookResponse.Success {
		webhookResponse.Error = fmt.Sprintf("HTTP %d: %s", response.StatusCode, string(responseBody))
	}

	// Try to extract execution ID from response
	if execData, ok := responseData.(map[string]interface{}); ok {
		if execID, exists := execData["execution_id"]; exists {
			if execIDStr, ok := execID.(string); ok {
				webhookResponse.ExecutionID = execIDStr
			}
		}
	}

	return webhookResponse, nil
}

func (c *N8NClient) GetExecutionStatus(ctx context.Context, webhookConfig *models.N8NWebhook, executionID string) (*N8NExecutionStatus, error) {
	if webhookConfig.N8NBaseURL == "" || executionID == "" {
		return nil, fmt.Errorf("n8n base URL and execution ID are required")
	}

	// Build execution status URL
	statusURL := fmt.Sprintf("%s/api/v1/executions/%s", 
		strings.TrimSuffix(webhookConfig.N8NBaseURL, "/"), 
		executionID)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create status request: %w", err)
	}

	// Add authentication
	if err := c.addAuthentication(req, webhookConfig); err != nil {
		return nil, fmt.Errorf("failed to add authentication: %w", err)
	}

	// Execute request
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution status: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("failed to get execution status: HTTP %d: %s", response.StatusCode, string(body))
	}

	var status N8NExecutionStatus
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode execution status: %w", err)
	}

	return &status, nil
}

func (c *N8NClient) GetWorkflowInfo(ctx context.Context, webhookConfig *models.N8NWebhook) (*N8NWorkflowInfo, error) {
	if webhookConfig.N8NBaseURL == "" || webhookConfig.WorkflowID == "" {
		return nil, fmt.Errorf("n8n base URL and workflow ID are required")
	}

	// Build workflow info URL
	workflowURL := fmt.Sprintf("%s/api/v1/workflows/%s", 
		strings.TrimSuffix(webhookConfig.N8NBaseURL, "/"), 
		webhookConfig.WorkflowID)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", workflowURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create workflow request: %w", err)
	}

	// Add authentication
	if err := c.addAuthentication(req, webhookConfig); err != nil {
		return nil, fmt.Errorf("failed to add authentication: %w", err)
	}

	// Execute request
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow info: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("failed to get workflow info: HTTP %d: %s", response.StatusCode, string(body))
	}

	var workflowInfo N8NWorkflowInfo
	if err := json.NewDecoder(response.Body).Decode(&workflowInfo); err != nil {
		return nil, fmt.Errorf("failed to decode workflow info: %w", err)
	}

	return &workflowInfo, nil
}

func (c *N8NClient) TestWebhook(ctx context.Context, webhookConfig *models.N8NWebhook) (*N8NWebhookResponse, error) {
	testRequest := &N8NWebhookRequest{
		WorkflowID:  webhookConfig.WorkflowID,
		WebhookPath: webhookConfig.WebhookPath,
		Method:      "GET",
		Headers:     map[string]string{},
		Parameters:  map[string]interface{}{
			"test": true,
			"timestamp": time.Now().Unix(),
		},
		RequestID: fmt.Sprintf("test_%d", time.Now().UnixNano()),
	}

	return c.ExecuteWebhook(ctx, webhookConfig, testRequest)
}

func (c *N8NClient) buildWebhookURL(webhookConfig *models.N8NWebhook, request *N8NWebhookRequest) (string, error) {
	baseURL := webhookConfig.N8NBaseURL
	if baseURL == "" {
		return "", fmt.Errorf("n8n base URL is required")
	}

	baseURL = strings.TrimSuffix(baseURL, "/")
	
	// Build webhook path
	var webhookPath string
	if webhookConfig.WebhookPath != "" {
		webhookPath = webhookConfig.WebhookPath
	} else if request.WebhookPath != "" {
		webhookPath = request.WebhookPath
	} else {
		return "", fmt.Errorf("webhook path is required")
	}

	if !strings.HasPrefix(webhookPath, "/") {
		webhookPath = "/" + webhookPath
	}

	// Combine base URL with webhook path
	webhookURL := baseURL + webhookPath

	// Add query parameters
	if len(request.Parameters) > 0 {
		u, err := url.Parse(webhookURL)
		if err != nil {
			return "", fmt.Errorf("invalid webhook URL: %w", err)
		}

		query := u.Query()
		for key, value := range request.Parameters {
			if str, ok := value.(string); ok {
				query.Set(key, str)
			} else if valueStr := fmt.Sprintf("%v", value); valueStr != "" {
				query.Set(key, valueStr)
			}
		}
		u.RawQuery = query.Encode()
		webhookURL = u.String()
	}

	return webhookURL, nil
}

func (c *N8NClient) addAuthentication(req *http.Request, webhookConfig *models.N8NWebhook) error {
	switch webhookConfig.AuthMethod {
	case "bearer":
		if webhookConfig.AuthToken != "" {
			req.Header.Set("Authorization", "Bearer "+webhookConfig.AuthToken)
		}
	case "basic":
		if webhookConfig.AuthToken != "" {
			req.Header.Set("Authorization", "Basic "+webhookConfig.AuthToken)
		}
	case "header":
		if webhookConfig.AuthHeaderName != "" && webhookConfig.AuthToken != "" {
			req.Header.Set(webhookConfig.AuthHeaderName, webhookConfig.AuthToken)
		}
	case "query":
		if webhookConfig.AuthHeaderName != "" && webhookConfig.AuthToken != "" {
			// Add auth as query parameter
			query := req.URL.Query()
			query.Set(webhookConfig.AuthHeaderName, webhookConfig.AuthToken)
			req.URL.RawQuery = query.Encode()
		}
	}
	return nil
}

func (c *N8NClient) executeWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error
	maxRetries := c.config.N8N.MaxRetries

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Clone request body for retry attempts
		var bodyReader io.Reader
		if req.Body != nil {
			if req.GetBody != nil {
				var err error
				bodyReader, err = req.GetBody()
				if err != nil {
					return nil, fmt.Errorf("failed to get request body for retry: %w", err)
				}
			}
		}

		// Create new request for retry
		retryReq := req.Clone(ctx)
		if bodyReader != nil {
			retryReq.Body = io.NopCloser(bodyReader)
		}

		response, err := c.httpClient.Do(retryReq)
		if err == nil {
			// Success or non-retryable error (based on status code)
			if response.StatusCode < 500 || attempt == maxRetries {
				return response, nil
			}
			response.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", response.StatusCode)
		} else {
			lastErr = err
		}

		// Wait before retry (exponential backoff)
		if attempt < maxRetries {
			backoffDuration := time.Duration(attempt+1) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoffDuration):
				// Continue to next attempt
			}
		}
	}

	return nil, fmt.Errorf("all retry attempts failed, last error: %w", lastErr)
}

func (c *N8NClient) ValidateWebhookConfig(webhookConfig *models.N8NWebhook) error {
	if webhookConfig.N8NBaseURL == "" {
		return fmt.Errorf("n8n base URL is required")
	}

	if webhookConfig.WebhookPath == "" {
		return fmt.Errorf("webhook path is required")
	}

	// Validate URL format
	if _, err := url.Parse(webhookConfig.N8NBaseURL); err != nil {
		return fmt.Errorf("invalid n8n base URL: %w", err)
	}

	// Validate auth configuration
	if webhookConfig.AuthMethod != "" {
		switch webhookConfig.AuthMethod {
		case "bearer", "basic":
			if webhookConfig.AuthToken == "" {
				return fmt.Errorf("auth token is required for %s auth method", webhookConfig.AuthMethod)
			}
		case "header", "query":
			if webhookConfig.AuthHeaderName == "" {
				return fmt.Errorf("auth header name is required for %s auth method", webhookConfig.AuthMethod)
			}
			if webhookConfig.AuthToken == "" {
				return fmt.Errorf("auth token is required for %s auth method", webhookConfig.AuthMethod)
			}
		default:
			return fmt.Errorf("unsupported auth method: %s", webhookConfig.AuthMethod)
		}
	}

	return nil
}

func (c *N8NClient) GetHealthStatus(ctx context.Context, baseURL string) (bool, error) {
	if baseURL == "" {
		return false, fmt.Errorf("base URL is required")
	}

	healthURL := strings.TrimSuffix(baseURL, "/") + "/healthz"

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create health check request: %w", err)
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("health check failed: %w", err)
	}
	defer response.Body.Close()

	return response.StatusCode == http.StatusOK, nil
}