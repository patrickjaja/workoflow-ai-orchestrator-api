package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
)

type SimpleChatHandler struct {
	chatService *services.SimpleChatService
}

type SimpleSendMessageRequest struct {
	Message        string `json:"message" binding:"required"`
	ConversationID string `json:"conversation_id"`
}

type SimpleSendMessageResponse struct {
	Message        *services.SimpleChatMessage `json:"message"`
	ConversationID string                      `json:"conversation_id"`
}

func NewSimpleChatHandler(chatService *services.SimpleChatService) *SimpleChatHandler {
	return &SimpleChatHandler{
		chatService: chatService,
	}
}

// SendMessage handles sending a message to the AI
func (h *SimpleChatHandler) SendMessage(c *gin.Context) {
	var req SimpleSendMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
		})
		return
	}

	// For now, use a dummy user ID - in real implementation this would come from auth
	userID := uuid.New().String()

	// Generate conversation ID if not provided
	if req.ConversationID == "" {
		req.ConversationID = uuid.New().String()
	}

	// Send message to chat service
	message, err := h.chatService.SendMessage(
		c.Request.Context(),
		userID,
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

	c.JSON(http.StatusOK, SimpleSendMessageResponse{
		Message:        message,
		ConversationID: req.ConversationID,
	})
}

// GetConversationHistory gets message history for a conversation
func (h *SimpleChatHandler) GetConversationHistory(c *gin.Context) {
	conversationID := c.Param("conversation_id")
	if conversationID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: "Conversation ID is required",
		})
		return
	}

	// For now, use a dummy user ID - in real implementation this would come from auth
	userID := uuid.New().String()

	// Get conversation history
	messages, err := h.chatService.GetConversationHistory(
		c.Request.Context(),
		userID,
		conversationID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get conversation history",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"messages":        messages,
		"conversation_id": conversationID,
		"total":           len(messages),
	})
}

// HealthCheck provides a simple health check endpoint
func (h *SimpleChatHandler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "simple-chat",
		"timestamp": "now",
	})
}