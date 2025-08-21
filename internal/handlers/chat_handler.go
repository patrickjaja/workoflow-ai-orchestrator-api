package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
)

type ChatHandler struct {
	chatService   *services.ChatService
	tenantService *services.TenantService
}

type SendMessageRequest struct {
	Message        string `json:"message" binding:"required"`
	ConversationID string `json:"conversation_id"`
}

type SendMessageResponse struct {
	Message        *services.ChatMessage `json:"message"`
	ConversationID string                `json:"conversation_id"`
	Actions        []string              `json:"suggested_actions,omitempty"`
}

type ConversationListResponse struct {
	Conversations []services.ChatSessionInfo `json:"conversations"`
	Total         int                        `json:"total"`
	Page          int                        `json:"page"`
	Limit         int                        `json:"limit"`
}

type ConversationHistoryResponse struct {
	Messages       []services.ChatMessage `json:"messages"`
	ConversationID string                 `json:"conversation_id"`
	Total          int                    `json:"total"`
}

func NewChatHandler(chatService *services.ChatService, tenantService *services.TenantService) *ChatHandler {
	return &ChatHandler{
		chatService:   chatService,
		tenantService: tenantService,
	}
}

// @Summary Send chat message
// @Description Send a message to the AI assistant
// @Tags Chat
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body SendMessageRequest true "Message request"
// @Success 200 {object} SendMessageResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /chat/messages [post]
func (h *ChatHandler) SendMessage(c *gin.Context) {
	userID, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	var req SendMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
		})
		return
	}

	// Generate conversation ID if not provided
	if req.ConversationID == "" {
		req.ConversationID = uuid.New().String()
	}

	// Send message to chat service
	message, err := h.chatService.SendMessage(
		c.Request.Context(),
		userID.(uint),
		orgID.(uint),
		req.ConversationID,
		req.Message,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to process message",
			Message: err.Error(),
		})
		return
	}

	// Build suggested actions based on message actions
	var suggestedActions []string
	if message.Actions != nil {
		for _, action := range message.Actions {
			switch action.Type {
			case "workflow_execution":
				suggestedActions = append(suggestedActions, "Execute workflow")
			case "workflow_management":
				suggestedActions = append(suggestedActions, "Manage workflows")
			case "data_retrieval":
				suggestedActions = append(suggestedActions, "View data")
			}
		}
	}

	c.JSON(http.StatusOK, SendMessageResponse{
		Message:        message,
		ConversationID: req.ConversationID,
		Actions:        suggestedActions,
	})
}

// @Summary Get conversation history
// @Description Get message history for a conversation
// @Tags Chat
// @Produce json
// @Security BearerAuth
// @Param conversation_id path string true "Conversation ID"
// @Param limit query int false "Limit number of messages"
// @Success 200 {object} ConversationHistoryResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /chat/conversations/{conversation_id}/messages [get]
func (h *ChatHandler) GetConversationHistory(c *gin.Context) {
	userID, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	conversationID := c.Param("conversation_id")
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: "Conversation ID is required",
		})
		return
	}

	// Parse limit parameter
	limit := 50 // default
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	// Get conversation history
	messages, err := h.chatService.GetConversationHistory(
		c.Request.Context(),
		userID.(uint),
		orgID.(uint),
		conversationID,
		limit,
	)
	if err != nil {
		if err.Error() == "conversation not found or access denied" {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "Not found",
				Message: "Conversation not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get conversation history",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, ConversationHistoryResponse{
		Messages:       messages,
		ConversationID: conversationID,
		Total:          len(messages),
	})
}

// @Summary List conversations
// @Description Get list of user's conversations
// @Tags Chat
// @Produce json
// @Security BearerAuth
// @Param limit query int false "Limit number of conversations"
// @Param offset query int false "Offset for pagination"
// @Success 200 {object} ConversationListResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /chat/conversations [get]
func (h *ChatHandler) ListConversations(c *gin.Context) {
	userID, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	// Parse pagination parameters
	limit := 20 // default
	offset := 0 // default
	page := 1   // default

	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	if pageStr := c.Query("page"); pageStr != "" {
		if parsedPage, err := strconv.Atoi(pageStr); err == nil && parsedPage > 0 {
			page = parsedPage
			offset = (page - 1) * limit
		}
	}

	// Get conversations
	conversations, err := h.chatService.ListConversations(
		c.Request.Context(),
		userID.(uint),
		orgID.(uint),
		limit,
		offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to list conversations",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, ConversationListResponse{
		Conversations: conversations,
		Total:         len(conversations),
		Page:          page,
		Limit:         limit,
	})
}

// @Summary Get conversation details
// @Description Get details of a specific conversation
// @Tags Chat
// @Produce json
// @Security BearerAuth
// @Param conversation_id path string true "Conversation ID"
// @Success 200 {object} services.ChatSessionInfo
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /chat/conversations/{conversation_id} [get]
func (h *ChatHandler) GetConversation(c *gin.Context) {
	userID, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	conversationID := c.Param("conversation_id")
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: "Conversation ID is required",
		})
		return
	}

	// Get conversation
	conversation, err := h.chatService.GetConversation(
		c.Request.Context(),
		userID.(uint),
		orgID.(uint),
		conversationID,
	)
	if err != nil {
		if err.Error() == "conversation not found or access denied" {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "Not found",
				Message: "Conversation not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get conversation",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, conversation)
}

// @Summary Clear conversation
// @Description Clear all messages from a conversation
// @Tags Chat
// @Produce json
// @Security BearerAuth
// @Param conversation_id path string true "Conversation ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /chat/conversations/{conversation_id}/clear [post]
func (h *ChatHandler) ClearConversation(c *gin.Context) {
	userID, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	conversationID := c.Param("conversation_id")
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: "Conversation ID is required",
		})
		return
	}

	// Clear conversation
	err := h.chatService.ClearConversation(
		c.Request.Context(),
		userID.(uint),
		orgID.(uint),
		conversationID,
	)
	if err != nil {
		if err.Error() == "conversation not found or access denied" {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "Not found",
				Message: "Conversation not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to clear conversation",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Conversation cleared successfully",
	})
}

// @Summary Delete conversation
// @Description Delete a conversation permanently
// @Tags Chat
// @Produce json
// @Security BearerAuth
// @Param conversation_id path string true "Conversation ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /chat/conversations/{conversation_id} [delete]
func (h *ChatHandler) DeleteConversation(c *gin.Context) {
	userID, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	conversationID := c.Param("conversation_id")
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: "Conversation ID is required",
		})
		return
	}

	// Delete conversation
	err := h.chatService.DeleteConversation(
		c.Request.Context(),
		userID.(uint),
		orgID.(uint),
		conversationID,
	)
	if err != nil {
		if err.Error() == "conversation not found or access denied" {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "Not found",
				Message: "Conversation not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to delete conversation",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Conversation deleted successfully",
	})
}

// @Summary Get conversation summary
// @Description Get AI-generated summary of conversation
// @Tags Chat
// @Produce json
// @Security BearerAuth
// @Param conversation_id path string true "Conversation ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /chat/conversations/{conversation_id}/summary [get]
func (h *ChatHandler) GetConversationSummary(c *gin.Context) {
	userID, userExists := c.Get("user_id")
	orgID, orgExists := c.Get("organization_id")
	
	if !userExists || !orgExists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	conversationID := c.Param("conversation_id")
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: "Conversation ID is required",
		})
		return
	}

	// Get conversation summary
	summary, err := h.chatService.GetConversationSummary(
		c.Request.Context(),
		userID.(uint),
		orgID.(uint),
		conversationID,
	)
	if err != nil {
		if err.Error() == "conversation not found or access denied" {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error:   "Not found",
				Message: "Conversation not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get conversation summary",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"conversation_id": conversationID,
		"summary":         summary,
		"generated_at":    "now", // Could add actual timestamp
	})
}

// @Summary Execute workflow
// @Description Execute a workflow with given parameters
// @Tags Chat
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /workflows/execute [post]
func (h *ChatHandler) ExecuteWorkflow(c *gin.Context) {
	// Mock workflow execution for test server
	c.JSON(http.StatusOK, gin.H{
		"execution_id": "mock-execution-123",
		"status":       "started",
		"workflow":     "test_workflow",
	})
}

// @Summary Get workflow execution status
// @Description Get the status of a workflow execution
// @Tags Chat
// @Produce json
// @Security BearerAuth
// @Param execution_id path string true "Execution ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /workflows/executions/{execution_id}/status [get]
func (h *ChatHandler) GetWorkflowStatus(c *gin.Context) {
	executionID := c.Param("execution_id")
	
	// Mock workflow status for test server
	c.JSON(http.StatusOK, gin.H{
		"execution_id": executionID,
		"status":       "completed",
		"workflow":     "test_workflow",
		"result":       "Mock workflow completed successfully",
	})
}