package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
	"gorm.io/gorm"
)

type WorkflowHandler struct {
	db          *gorm.DB
	chatService *services.ChatService
	n8nClient   *services.N8NClient
}

type ExecuteWorkflowRequest struct {
	WorkflowName   string                 `json:"workflow_name" binding:"required"`
	Parameters     map[string]interface{} `json:"parameters"`
	ConversationID string                 `json:"conversation_id"`
	Confirm        bool                   `json:"confirm"`
}

type WorkflowListResponse struct {
	Workflows []WorkflowInfo `json:"workflows"`
	Total     int            `json:"total"`
}

type WorkflowInfo struct {
	ID           uint                   `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Active       bool                   `json:"active"`
	WebhookPath  string                 `json:"webhook_path"`
	WorkflowID   string                 `json:"workflow_id"`
	N8NBaseURL   string                 `json:"n8n_base_url,omitempty"`
	AuthMethod   string                 `json:"auth_method,omitempty"`
	CreatedAt    string                 `json:"created_at"`
	UpdatedAt    string                 `json:"updated_at"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
}

type CreateWebhookRequest struct {
	WorkflowName     string `json:"workflow_name" binding:"required"`
	Description      string `json:"description"`
	WorkflowID       string `json:"workflow_id" binding:"required"`
	WebhookPath      string `json:"webhook_path" binding:"required"`
	N8NBaseURL       string `json:"n8n_base_url" binding:"required"`
	AuthMethod       string `json:"auth_method"`
	AuthToken        string `json:"auth_token"`
	AuthHeaderName   string `json:"auth_header_name"`
	Active           bool   `json:"active"`
}

type UpdateWebhookRequest struct {
	WorkflowName     string `json:"workflow_name"`
	Description      string `json:"description"`
	WorkflowID       string `json:"workflow_id"`
	WebhookPath      string `json:"webhook_path"`
	N8NBaseURL       string `json:"n8n_base_url"`
	AuthMethod       string `json:"auth_method"`
	AuthToken        string `json:"auth_token"`
	AuthHeaderName   string `json:"auth_header_name"`
	Active           *bool  `json:"active"`
}

func NewWorkflowHandler(db *gorm.DB, chatService *services.ChatService, n8nClient *services.N8NClient) *WorkflowHandler {
	return &WorkflowHandler{
		db:          db,
		chatService: chatService,
		n8nClient:   n8nClient,
	}
}

// @Summary Execute workflow
// @Description Execute a workflow with the specified parameters
// @Tags Workflows
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ExecuteWorkflowRequest true "Workflow execution request"
// @Success 200 {object} services.WorkflowExecutionResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /workflows/execute [post]
func (h *WorkflowHandler) ExecuteWorkflow(c *gin.Context) {
	userID, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	var req ExecuteWorkflowRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
		})
		return
	}

	// Create workflow execution request
	execReq := &services.WorkflowExecutionRequest{
		WorkflowName:   req.WorkflowName,
		Parameters:     req.Parameters,
		ConversationID: req.ConversationID,
		UserID:         userID.(uint),
		OrganizationID: orgID.(uint),
		Confirm:        req.Confirm,
	}

	// Execute workflow
	response, err := h.chatService.ExecuteWorkflow(c.Request.Context(), execReq)
	if err != nil {
		if err.Error() == "workflow not found or inactive" {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "Workflow not found",
				Message: "The specified workflow was not found or is inactive",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to execute workflow",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Get workflow execution status
// @Description Get the status of a workflow execution
// @Tags Workflows
// @Produce json
// @Security BearerAuth
// @Param execution_id path string true "Execution ID"
// @Success 200 {object} services.WorkflowExecutionResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /workflows/executions/{execution_id} [get]
func (h *WorkflowHandler) GetExecutionStatus(c *gin.Context) {
	userID, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	executionID := c.Param("execution_id")
	if executionID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: "Execution ID is required",
		})
		return
	}

	// Get execution status
	response, err := h.chatService.GetWorkflowStatus(
		c.Request.Context(),
		userID.(uint),
		orgID.(uint),
		executionID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get execution status",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// @Summary List workflows
// @Description Get list of available workflows for the organization
// @Tags Workflows
// @Produce json
// @Security BearerAuth
// @Param active query bool false "Filter by active status"
// @Success 200 {object} WorkflowListResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /workflows [get]
func (h *WorkflowHandler) ListWorkflows(c *gin.Context) {
	_, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	// Parse active filter
	var activeFilter *bool
	if activeStr := c.Query("active"); activeStr != "" {
		if active, err := strconv.ParseBool(activeStr); err == nil {
			activeFilter = &active
		}
	}

	// Query workflows
	var webhooks []models.N8NWebhook
	query := h.db.Where("organization_id = ?", orgID)
	
	if activeFilter != nil {
		query = query.Where("active = ?", *activeFilter)
	}

	err := query.Find(&webhooks).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to list workflows",
			Message: err.Error(),
		})
		return
	}

	// Convert to response format
	var workflows []WorkflowInfo
	for _, webhook := range webhooks {
		workflows = append(workflows, WorkflowInfo{
			ID:          webhook.ID,
			Name:        webhook.WorkflowName,
			Description: webhook.Description,
			Active:      webhook.Active,
			WebhookPath: webhook.WebhookPath,
			WorkflowID:  webhook.WorkflowID,
			AuthMethod:  webhook.AuthMethod,
			CreatedAt:   webhook.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:   webhook.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	c.JSON(http.StatusOK, WorkflowListResponse{
		Workflows: workflows,
		Total:     len(workflows),
	})
}

// @Summary Get workflow details
// @Description Get details of a specific workflow
// @Tags Workflows
// @Produce json
// @Security BearerAuth
// @Param workflow_id path string true "Workflow ID"
// @Success 200 {object} WorkflowInfo
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /workflows/{workflow_id} [get]
func (h *WorkflowHandler) GetWorkflow(c *gin.Context) {
	_, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	workflowIDStr := c.Param("workflow_id")
	workflowID, err := strconv.ParseUint(workflowIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: "Invalid workflow ID",
		})
		return
	}

	// Get workflow
	var webhook models.N8NWebhook
	err = h.db.Where("id = ? AND organization_id = ?", uint(workflowID), orgID).First(&webhook).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "Not found",
				Message: "Workflow not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get workflow",
			Message: err.Error(),
		})
		return
	}

	// Get additional workflow info from n8n if available
	var parameters map[string]interface{}
	if h.n8nClient != nil {
		if workflowInfo, err := h.n8nClient.GetWorkflowInfo(c.Request.Context(), &webhook); err == nil {
			parameters = map[string]interface{}{
				"nodes":       len(workflowInfo.Nodes),
				"active":      workflowInfo.Active,
				"tags":        workflowInfo.Tags,
				"updated_at":  workflowInfo.UpdatedAt,
			}
		}
	}

	workflow := WorkflowInfo{
		ID:          webhook.ID,
		Name:        webhook.WorkflowName,
		Description: webhook.Description,
		Active:      webhook.Active,
		WebhookPath: webhook.WebhookPath,
		WorkflowID:  webhook.WorkflowID,
		N8NBaseURL:  webhook.N8NBaseURL,
		AuthMethod:  webhook.AuthMethod,
		CreatedAt:   webhook.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   webhook.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		Parameters:  parameters,
	}

	c.JSON(http.StatusOK, workflow)
}

// @Summary Create webhook configuration
// @Description Create a new webhook configuration for n8n workflow
// @Tags Workflows
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateWebhookRequest true "Webhook creation request"
// @Success 201 {object} WorkflowInfo
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /workflows [post]
func (h *WorkflowHandler) CreateWebhook(c *gin.Context) {
	_, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	var req CreateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
		})
		return
	}

	// Create webhook model
	webhook := models.N8NWebhook{
		OrganizationID: orgID.(uint),
		WorkflowName:   req.WorkflowName,
		Description:    req.Description,
		WorkflowID:     req.WorkflowID,
		WebhookPath:    req.WebhookPath,
		N8NBaseURL:     req.N8NBaseURL,
		AuthMethod:     req.AuthMethod,
		AuthToken:      req.AuthToken,
		AuthHeaderName: req.AuthHeaderName,
		Active:         req.Active,
	}

	// Validate webhook configuration
	if err := h.n8nClient.ValidateWebhookConfig(&webhook); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid webhook configuration",
			Message: err.Error(),
		})
		return
	}

	// Save to database
	err := h.db.Create(&webhook).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to create webhook",
			Message: err.Error(),
		})
		return
	}

	// Return created webhook
	workflowInfo := WorkflowInfo{
		ID:          webhook.ID,
		Name:        webhook.WorkflowName,
		Description: webhook.Description,
		Active:      webhook.Active,
		WebhookPath: webhook.WebhookPath,
		WorkflowID:  webhook.WorkflowID,
		N8NBaseURL:  webhook.N8NBaseURL,
		AuthMethod:  webhook.AuthMethod,
		CreatedAt:   webhook.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   webhook.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	c.JSON(http.StatusCreated, workflowInfo)
}

// @Summary Update webhook configuration
// @Description Update an existing webhook configuration
// @Tags Workflows
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param workflow_id path string true "Workflow ID"
// @Param request body UpdateWebhookRequest true "Webhook update request"
// @Success 200 {object} WorkflowInfo
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /workflows/{workflow_id} [put]
func (h *WorkflowHandler) UpdateWebhook(c *gin.Context) {
	_, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	workflowIDStr := c.Param("workflow_id")
	workflowID, err := strconv.ParseUint(workflowIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: "Invalid workflow ID",
		})
		return
	}

	var req UpdateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
		})
		return
	}

	// Get existing webhook
	var webhook models.N8NWebhook
	err = h.db.Where("id = ? AND organization_id = ?", uint(workflowID), orgID).First(&webhook).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "Not found",
				Message: "Workflow not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get workflow",
			Message: err.Error(),
		})
		return
	}

	// Update fields
	if req.WorkflowName != "" {
		webhook.WorkflowName = req.WorkflowName
	}
	if req.Description != "" {
		webhook.Description = req.Description
	}
	if req.WorkflowID != "" {
		webhook.WorkflowID = req.WorkflowID
	}
	if req.WebhookPath != "" {
		webhook.WebhookPath = req.WebhookPath
	}
	if req.N8NBaseURL != "" {
		webhook.N8NBaseURL = req.N8NBaseURL
	}
	if req.AuthMethod != "" {
		webhook.AuthMethod = req.AuthMethod
	}
	if req.AuthToken != "" {
		webhook.AuthToken = req.AuthToken
	}
	if req.AuthHeaderName != "" {
		webhook.AuthHeaderName = req.AuthHeaderName
	}
	if req.Active != nil {
		webhook.Active = *req.Active
	}

	// Validate updated configuration
	if err := h.n8nClient.ValidateWebhookConfig(&webhook); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid webhook configuration",
			Message: err.Error(),
		})
		return
	}

	// Save changes
	err = h.db.Save(&webhook).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to update webhook",
			Message: err.Error(),
		})
		return
	}

	// Return updated webhook
	workflowInfo := WorkflowInfo{
		ID:          webhook.ID,
		Name:        webhook.WorkflowName,
		Description: webhook.Description,
		Active:      webhook.Active,
		WebhookPath: webhook.WebhookPath,
		WorkflowID:  webhook.WorkflowID,
		N8NBaseURL:  webhook.N8NBaseURL,
		AuthMethod:  webhook.AuthMethod,
		CreatedAt:   webhook.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   webhook.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	c.JSON(http.StatusOK, workflowInfo)
}

// @Summary Delete webhook configuration
// @Description Delete a webhook configuration
// @Tags Workflows
// @Produce json
// @Security BearerAuth
// @Param workflow_id path string true "Workflow ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /workflows/{workflow_id} [delete]
func (h *WorkflowHandler) DeleteWebhook(c *gin.Context) {
	_, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	workflowIDStr := c.Param("workflow_id")
	workflowID, err := strconv.ParseUint(workflowIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: "Invalid workflow ID",
		})
		return
	}

	// Delete webhook
	result := h.db.Where("id = ? AND organization_id = ?", uint(workflowID), orgID).Delete(&models.N8NWebhook{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to delete webhook",
			Message: result.Error.Error(),
		})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "Not found",
			Message: "Workflow not found",
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Webhook deleted successfully",
	})
}

// @Summary Test webhook
// @Description Test a webhook configuration
// @Tags Workflows
// @Produce json
// @Security BearerAuth
// @Param workflow_id path string true "Workflow ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /workflows/{workflow_id}/test [post]
func (h *WorkflowHandler) TestWebhook(c *gin.Context) {
	_, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	workflowIDStr := c.Param("workflow_id")
	workflowID, err := strconv.ParseUint(workflowIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: "Invalid workflow ID",
		})
		return
	}

	// Get webhook
	var webhook models.N8NWebhook
	err = h.db.Where("id = ? AND organization_id = ?", uint(workflowID), orgID).First(&webhook).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "Not found",
				Message: "Workflow not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get workflow",
			Message: err.Error(),
		})
		return
	}

	// Test webhook
	response, err := h.n8nClient.TestWebhook(c.Request.Context(), &webhook)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Webhook test failed",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      response.Success,
		"status_code":  response.StatusCode,
		"response":     response.Data,
		"duration":     response.Duration,
		"execution_id": response.ExecutionID,
		"error":        response.Error,
	})
}