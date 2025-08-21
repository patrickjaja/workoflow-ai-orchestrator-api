package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/workoflow/ai-orchestrator-api/internal/models"
)

type ChatService struct {
	db         *gorm.DB
	aiService  *AIService
	n8nClient  *N8NClient
	tenantService *TenantService
}

type ChatMessage struct {
	ID             string                 `json:"id"`
	ConversationID string                 `json:"conversation_id"`
	UserID         uint                   `json:"user_id"`
	Role           string                 `json:"role"` // user, assistant, system
	Content        string                 `json:"content"`
	Intent         string                 `json:"intent,omitempty"`
	Confidence     float32                `json:"confidence,omitempty"`
	Actions        []AIAction             `json:"actions,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

type ChatSessionInfo struct {
	ConversationID string                 `json:"conversation_id"`
	SessionID      string                 `json:"session_id"`
	UserID         uint                   `json:"user_id"`
	OrganizationID uint                   `json:"organization_id"`
	Status         string                 `json:"status"`
	CreatedAt      time.Time              `json:"created_at"`
	LastActivity   time.Time              `json:"last_activity"`
	MessageCount   int                    `json:"message_count"`
	Context        map[string]interface{} `json:"context,omitempty"`
}

type WorkflowExecutionRequest struct {
	WorkflowName   string                 `json:"workflow_name"`
	Parameters     map[string]interface{} `json:"parameters"`
	ConversationID string                 `json:"conversation_id"`
	UserID         uint                   `json:"user_id"`
	OrganizationID uint                   `json:"organization_id"`
	Confirm        bool                   `json:"confirm"`
}

type WorkflowExecutionResponse struct {
	ExecutionID    string                 `json:"execution_id"`
	Status         string                 `json:"status"`
	WorkflowName   string                 `json:"workflow_name"`
	StartedAt      time.Time              `json:"started_at"`
	Data           interface{}            `json:"data,omitempty"`
	Error          string                 `json:"error,omitempty"`
	Metadata       map[string]interface{} `json:"metadata"`
}

func NewChatService(db *gorm.DB, aiService *AIService, n8nClient *N8NClient, tenantService *TenantService) *ChatService {
	return &ChatService{
		db:            db,
		aiService:     aiService,
		n8nClient:     n8nClient,
		tenantService: tenantService,
	}
}


func (cs *ChatService) SendMessage(ctx context.Context, userID uint, orgID uint, conversationID, message string) (*ChatMessage, error) {
	// Validate conversation access
	conversation, err := cs.getOrCreateConversation(ctx, userID, conversationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get conversation: %w", err)
	}

	// Prepare AI request
	aiRequest := &ChatRequest{
		Message:         message,
		ConversationID:  fmt.Sprintf("%d", conversation.ID),
		UserID:          userID,
		OrganizationID:  orgID,
		SessionID:       fmt.Sprintf("%d", conversation.ID), // Use conversation ID as session ID
		Context: map[string]interface{}{
			"user_id":         userID,
			"organization_id": orgID,
		},
	}

	// Get AI response
	aiResponse, err := cs.aiService.ProcessMessage(ctx, aiRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to process AI message: %w", err)
	}

	// Create assistant message
	assistantMessage := &ChatMessage{
		ID:             uuid.New().String(),
		ConversationID: fmt.Sprintf("%d", conversation.ID),
		UserID:         userID,
		Role:           "assistant",
		Content:        aiResponse.Text,
		Intent:         aiResponse.Intent,
		Confidence:     aiResponse.Confidence,
		Actions:        aiResponse.Actions,
		Context:        aiResponse.Context,
		Metadata:       aiResponse.Metadata,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Update conversation
	now := time.Now()
	conversation.LastMessageAt = &now
	conversation.MessageCount++
	conversation.UpdatedAt = now
	
	err = cs.db.Save(conversation).Error
	if err != nil {
		return nil, fmt.Errorf("failed to update conversation: %w", err)
	}

	// Handle actions if present
	if len(aiResponse.Actions) > 0 {
		err = cs.handleActions(ctx, conversation, aiResponse.Actions)
		if err != nil {
			// Log error but don't fail the chat
			fmt.Printf("Warning: failed to handle actions: %v\n", err)
		}
	}

	return assistantMessage, nil
}

func (cs *ChatService) GetConversationHistory(ctx context.Context, userID uint, orgID uint, conversationID string, limit int) ([]ChatMessage, error) {
	// Convert IDs to UUID for database query
	userUUID, err := uuid.Parse(fmt.Sprintf("%08x-0000-0000-0000-000000000000", userID))
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}
	
	convUUID, err := uuid.Parse(conversationID)
	if err != nil {
		return nil, fmt.Errorf("invalid conversation ID: %w", err)
	}
	
	// Validate access
	var conversation models.Conversation
	err = cs.db.Where("id = ? AND user_id = ?", convUUID, userUUID).First(&conversation).Error
	if err != nil {
		return nil, fmt.Errorf("conversation not found or access denied")
	}

	// Get conversation history from AI context manager
	history, err := cs.aiService.contextManager.GetConversationHistory(conversationID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get conversation history: %w", err)
	}

	// Convert to chat messages
	var messages []ChatMessage
	for i, msg := range history {
		messages = append(messages, ChatMessage{
			ID:             fmt.Sprintf("%s_%d", conversationID, i),
			ConversationID: conversationID,
			UserID:         userID,
			Role:           msg.Role,
			Content:        msg.Content,
			Intent:         msg.Intent,
			Metadata:       msg.Metadata,
			CreatedAt:      msg.Timestamp,
			UpdatedAt:      msg.Timestamp,
		})
	}

	return messages, nil
}

func (cs *ChatService) GetConversation(ctx context.Context, userID uint, orgID uint, conversationID string) (*ChatSessionInfo, error) {
	// Convert IDs to UUID for database query
	userUUID, err := uuid.Parse(fmt.Sprintf("%08x-0000-0000-0000-000000000000", userID))
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}
	
	convUUID, err := uuid.Parse(conversationID)
	if err != nil {
		return nil, fmt.Errorf("invalid conversation ID: %w", err)
	}
	
	var conversation models.Conversation
	err = cs.db.Where("id = ? AND user_id = ?", convUUID, userUUID).First(&conversation).Error
	if err != nil {
		return nil, fmt.Errorf("conversation not found or access denied")
	}

	// Get context from AI service
	contextData, err := cs.aiService.contextManager.GetContext(conversationID)
	if err != nil {
		contextData = make(map[string]interface{})
	}

	lastActivity := conversation.CreatedAt
	if conversation.LastMessageAt != nil {
		lastActivity = *conversation.LastMessageAt
	}

	return &ChatSessionInfo{
		ConversationID: fmt.Sprintf("%d", conversation.ID),
		SessionID:      fmt.Sprintf("%d", conversation.ID),
		UserID:         userID,
		OrganizationID: orgID,
		Status:         string(conversation.Status),
		CreatedAt:      conversation.CreatedAt,
		LastActivity:   lastActivity,
		MessageCount:   conversation.MessageCount,
		Context:        contextData,
	}, nil
}

func (cs *ChatService) ListConversations(ctx context.Context, userID uint, orgID uint, limit, offset int) ([]ChatSessionInfo, error) {
	// Convert user ID to UUID
	userUUID, err := uuid.Parse(fmt.Sprintf("%08x-0000-0000-0000-000000000000", userID))
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}
	
	var conversations []models.Conversation
	query := cs.db.Where("user_id = ?", userUUID)
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err = query.Order("updated_at DESC").Find(&conversations).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list conversations: %w", err)
	}

	var result []ChatSessionInfo
	for _, conv := range conversations {
		lastActivity := conv.CreatedAt
		if conv.LastMessageAt != nil {
			lastActivity = *conv.LastMessageAt
		}
		
		result = append(result, ChatSessionInfo{
			ConversationID: fmt.Sprintf("%d", conv.ID),
			SessionID:      fmt.Sprintf("%d", conv.ID),
			UserID:         userID,
			OrganizationID: orgID,
			Status:         string(conv.Status),
			CreatedAt:      conv.CreatedAt,
			LastActivity:   lastActivity,
			MessageCount:   conv.MessageCount,
		})
	}

	return result, nil
}

func (cs *ChatService) ExecuteWorkflow(ctx context.Context, request *WorkflowExecutionRequest) (*WorkflowExecutionResponse, error) {
	// Validate user access
	user, err := cs.tenantService.GetUser(ctx, request.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Find webhook configuration
	var webhook models.N8NWebhook
	err = cs.db.Where("workflow_name = ? AND organization_id = ? AND active = ?", 
		request.WorkflowName, user.OrganizationID, true).First(&webhook).Error
	if err != nil {
		return nil, fmt.Errorf("workflow not found or inactive: %w", err)
	}

	// Validate parameters if AI service is available
	if cs.aiService != nil {
		valid, errors, err := cs.aiService.ValidateWorkflowParameters(ctx, request.WorkflowName, request.Parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to validate parameters: %w", err)
		}
		if !valid {
			return nil, fmt.Errorf("invalid parameters: %v", errors)
		}
	}

	// Create webhook request
	webhookRequest := &N8NWebhookRequest{
		WorkflowID:     webhook.WorkflowID,
		WebhookPath:    webhook.WebhookPath,
		Method:         "POST",
		Headers:        map[string]string{},
		Parameters:     request.Parameters,
		Body: map[string]interface{}{
			"user_id":         request.UserID,
			"organization_id": request.OrganizationID,
			"conversation_id": request.ConversationID,
			"workflow_name":   request.WorkflowName,
			"parameters":      request.Parameters,
			"timestamp":       time.Now(),
		},
		UserID:         request.UserID,
		OrgID:          request.OrganizationID,
		ConversationID: request.ConversationID,
		RequestID:      uuid.New().String(),
	}

	// Execute webhook
	startTime := time.Now()
	webhookResponse, err := cs.n8nClient.ExecuteWebhook(ctx, &webhook, webhookRequest)
	if err != nil {
		return &WorkflowExecutionResponse{
			ExecutionID:  webhookRequest.RequestID,
			Status:       "error",
			WorkflowName: request.WorkflowName,
			StartedAt:    startTime,
			Error:        err.Error(),
			Metadata: map[string]interface{}{
				"webhook_id": webhook.ID,
				"duration":   time.Since(startTime),
			},
		}, nil
	}

	status := "success"
	if !webhookResponse.Success {
		status = "error"
	}

	return &WorkflowExecutionResponse{
		ExecutionID:  webhookResponse.ExecutionID,
		Status:       status,
		WorkflowName: request.WorkflowName,
		StartedAt:    startTime,
		Data:         webhookResponse.Data,
		Error:        webhookResponse.Error,
		Metadata: map[string]interface{}{
			"webhook_id":   webhook.ID,
			"status_code":  webhookResponse.StatusCode,
			"duration":     webhookResponse.Duration,
			"request_id":   webhookRequest.RequestID,
		},
	}, nil
}

func (cs *ChatService) GetWorkflowStatus(ctx context.Context, userID uint, orgID uint, executionID string) (*WorkflowExecutionResponse, error) {
	// Find the webhook that was used (this is simplified - in practice you'd track executions)
	var webhook models.N8NWebhook
	err := cs.db.Where("organization_id = ? AND active = ?", orgID, true).First(&webhook).Error
	if err != nil {
		return nil, fmt.Errorf("failed to find webhook configuration: %w", err)
	}

	// Get execution status from n8n
	status, err := cs.n8nClient.GetExecutionStatus(ctx, &webhook, executionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution status: %w", err)
	}

	var startedAt time.Time
	if status.StartedAt != nil {
		startedAt = *status.StartedAt
	}

	return &WorkflowExecutionResponse{
		ExecutionID:  status.ID,
		Status:       status.Status,
		WorkflowName: webhook.WorkflowName,
		StartedAt:    startedAt,
		Data:         status.Data,
		Error:        status.Error,
		Metadata: map[string]interface{}{
			"workflow_id": status.WorkflowID,
		},
	}, nil
}

func (cs *ChatService) GetConversationSummary(ctx context.Context, userID uint, orgID uint, conversationID string) (string, error) {
	// Convert IDs to UUID
	userUUID, err := uuid.Parse(fmt.Sprintf("%08x-0000-0000-0000-000000000000", userID))
	if err != nil {
		return "", fmt.Errorf("invalid user ID: %w", err)
	}
	
	convUUID, err := uuid.Parse(conversationID)
	if err != nil {
		return "", fmt.Errorf("invalid conversation ID: %w", err)
	}
	
	// Validate access
	var conversation models.Conversation
	err = cs.db.Where("id = ? AND user_id = ?", convUUID, userUUID).First(&conversation).Error
	if err != nil {
		return "", fmt.Errorf("conversation not found or access denied")
	}

	// Get summary from AI service
	summary, err := cs.aiService.GetConversationSummary(ctx, conversationID)
	if err != nil {
		return "", fmt.Errorf("failed to generate summary: %w", err)
	}

	return summary, nil
}

func (cs *ChatService) getOrCreateConversation(ctx context.Context, userID uint, conversationID string) (*models.Conversation, error) {
	var conversation models.Conversation
	var err error
	
	if conversationID != "" {
		// Try to parse conversationID as uint
		var convID uint
		if _, err := fmt.Sscanf(conversationID, "%d", &convID); err == nil {
			// Try to find existing conversation
			err = cs.db.Where("id = ? AND user_id = ?", convID, userID).First(&conversation).Error
			if err == nil {
				return &conversation, nil
			} else if err != gorm.ErrRecordNotFound {
				return nil, fmt.Errorf("failed to query conversation: %w", err)
			}
		}
	}

	// Create new conversation
	conversation = models.Conversation{
		UserID:           userID,
		Status:           models.ConversationStatusActive,
		MessageCount:     0,
	}

	err = cs.db.Create(&conversation).Error
	if err != nil {
		return nil, fmt.Errorf("failed to create conversation: %w", err)
	}

	return &conversation, nil
}

func (cs *ChatService) handleActions(ctx context.Context, conversation *models.Conversation, actions []AIAction) error {
	for _, action := range actions {
		switch action.Type {
		case "workflow_execution":
			err := cs.handleWorkflowAction(ctx, conversation, action)
			if err != nil {
				fmt.Printf("Failed to handle workflow action: %v\n", err)
			}
		case "workflow_management":
			err := cs.handleWorkflowManagementAction(ctx, conversation, action)
			if err != nil {
				fmt.Printf("Failed to handle workflow management action: %v\n", err)
			}
		case "data_retrieval":
			err := cs.handleDataAction(ctx, conversation, action)
			if err != nil {
				fmt.Printf("Failed to handle data action: %v\n", err)
			}
		}
	}
	return nil
}

func (cs *ChatService) handleWorkflowAction(ctx context.Context, conversation *models.Conversation, action AIAction) error {
	// This would typically create a pending action for user confirmation
	actionData := map[string]interface{}{
		"type":        "workflow_execution",
		"description": "Execute workflow based on AI suggestion",
		"parameters":  action.Parameters,
	}

	return cs.aiService.contextManager.UpdateContext(fmt.Sprintf("%d", conversation.ID), map[string]interface{}{
		"pending_action": actionData,
	})
}

func (cs *ChatService) handleWorkflowManagementAction(ctx context.Context, conversation *models.Conversation, action AIAction) error {
	// Handle workflow configuration changes
	return nil
}

func (cs *ChatService) handleDataAction(ctx context.Context, conversation *models.Conversation, action AIAction) error {
	// Handle data retrieval requests
	return nil
}

func (cs *ChatService) ClearConversation(ctx context.Context, userID uint, orgID uint, conversationID string) error {
	// Convert IDs to UUID
	userUUID, err := uuid.Parse(fmt.Sprintf("%08x-0000-0000-0000-000000000000", userID))
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	
	convUUID, err := uuid.Parse(conversationID)
	if err != nil {
		return fmt.Errorf("invalid conversation ID: %w", err)
	}
	
	// Validate access
	var conversation models.Conversation
	err = cs.db.Where("id = ? AND user_id = ?", convUUID, userUUID).First(&conversation).Error
	if err != nil {
		return fmt.Errorf("conversation not found or access denied")
	}

	// Clear conversation context
	err = cs.aiService.contextManager.DeleteContext(conversationID)
	if err != nil {
		return fmt.Errorf("failed to clear conversation context: %w", err)
	}

	// Reset conversation in database
	conversation.MessageCount = 0
	now := time.Now()
	conversation.LastMessageAt = &now
	conversation.UpdatedAt = now
	
	return cs.db.Save(&conversation).Error
}

func (cs *ChatService) DeleteConversation(ctx context.Context, userID uint, orgID uint, conversationID string) error {
	// Convert IDs to UUID
	userUUID, err := uuid.Parse(fmt.Sprintf("%08x-0000-0000-0000-000000000000", userID))
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	
	convUUID, err := uuid.Parse(conversationID)
	if err != nil {
		return fmt.Errorf("invalid conversation ID: %w", err)
	}
	
	// Validate access and delete
	result := cs.db.Where("id = ? AND user_id = ?", convUUID, userUUID).Delete(&models.Conversation{})
	
	if result.Error != nil {
		return fmt.Errorf("failed to delete conversation: %w", result.Error)
	}
	
	if result.RowsAffected == 0 {
		return fmt.Errorf("conversation not found or access denied")
	}

	// Clear from context manager
	return cs.aiService.contextManager.DeleteContext(conversationID)
}