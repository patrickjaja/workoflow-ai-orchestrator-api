package services

import (
	"context"
	"fmt"
	"time"

	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"gorm.io/gorm"
)

// SimpleChatService provides basic chat functionality with AI
type SimpleChatService struct {
	db        *gorm.DB
	aiService *AIService
}

// SimpleChatMessage represents a simplified chat message
type SimpleChatMessage struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversation_id"`
	UserID         string    `json:"user_id"`
	Role           string    `json:"role"`
	Content        string    `json:"content"`
	CreatedAt      time.Time `json:"created_at"`
}

// NewSimpleChatService creates a new simplified chat service
func NewSimpleChatService(db *gorm.DB, aiService *AIService) *SimpleChatService {
	return &SimpleChatService{
		db:        db,
		aiService: aiService,
	}
}

// SendMessage sends a message and returns AI response
func (s *SimpleChatService) SendMessage(ctx context.Context, userIDStr, conversationIDStr, message string) (*SimpleChatMessage, error) {
	// Parse user ID
	var userID uint
	if _, err := fmt.Sscanf(userIDStr, "%d", &userID); err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Get or create conversation
	conversation, err := s.getOrCreateConversation(ctx, userID, conversationIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to get conversation: %w", err)
	}

	// Process message with AI
	aiRequest := &ChatRequest{
		Message:        message,
		ConversationID: fmt.Sprintf("%d", conversation.ID),
		UserID:         0, // We'll use string IDs for now
		Context: map[string]interface{}{
			"user_id": userIDStr,
		},
	}

	aiResponse, err := s.aiService.ProcessMessage(ctx, aiRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to process message: %w", err)
	}

	// Create message record
	messageRecord := &models.Message{
		ConversationID: conversation.ID,
		Role:           "assistant",
		Content:        aiResponse.Text,
	}

	err = s.db.Create(messageRecord).Error
	if err != nil {
		return nil, fmt.Errorf("failed to create message: %w", err)
	}

	// Update conversation
	now := time.Now()
	conversation.LastMessageAt = &now
	conversation.MessageCount++
	conversation.UpdatedAt = now

	err = s.db.Save(conversation).Error
	if err != nil {
		return nil, fmt.Errorf("failed to update conversation: %w", err)
	}

	return &SimpleChatMessage{
		ID:             fmt.Sprintf("%d", messageRecord.ID),
		ConversationID: fmt.Sprintf("%d", conversation.ID),
		UserID:         userIDStr,
		Role:           messageRecord.Role,
		Content:        messageRecord.Content,
		CreatedAt:      messageRecord.CreatedAt,
	}, nil
}

// GetConversationHistory returns conversation message history
func (s *SimpleChatService) GetConversationHistory(ctx context.Context, userIDStr, conversationIDStr string) ([]SimpleChatMessage, error) {
	var userID uint
	if _, err := fmt.Sscanf(userIDStr, "%d", &userID); err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	var conversationID uint
	if _, err := fmt.Sscanf(conversationIDStr, "%d", &conversationID); err != nil {
		return nil, fmt.Errorf("invalid conversation ID: %w", err)
	}

	// Check if user has access to conversation
	var conversation models.Conversation
	err := s.db.Where("id = ? AND user_id = ?", conversationID, userID).First(&conversation).Error
	if err != nil {
		return nil, fmt.Errorf("conversation not found or access denied")
	}

	// Get messages
	var messages []models.Message
	err = s.db.Where("conversation_id = ?", conversationID).
		Order("created_at ASC").Find(&messages).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get messages: %w", err)
	}

	// Convert to response format
	var result []SimpleChatMessage
	for _, msg := range messages {
		result = append(result, SimpleChatMessage{
			ID:             fmt.Sprintf("%d", msg.ID),
			ConversationID: fmt.Sprintf("%d", msg.ConversationID),
			UserID:         userIDStr,
			Role:           msg.Role,
			Content:        msg.Content,
			CreatedAt:      msg.CreatedAt,
		})
	}

	return result, nil
}

// getOrCreateConversation gets an existing conversation or creates a new one
func (s *SimpleChatService) getOrCreateConversation(ctx context.Context, userID uint, conversationIDStr string) (*models.Conversation, error) {
	var conversation models.Conversation
	var conversationID uint

	// Try to parse conversation ID if provided
	if conversationIDStr != "" {
		if _, err := fmt.Sscanf(conversationIDStr, "%d", &conversationID); err == nil {
			// Try to find existing conversation
			err := s.db.Where("id = ? AND user_id = ?", conversationID, userID).First(&conversation).Error
			if err == nil {
				return &conversation, nil
			} else if err != gorm.ErrRecordNotFound {
				return nil, fmt.Errorf("failed to query conversation: %w", err)
			}
		}
	}

	// Create new conversation
	conversation = models.Conversation{
		UserID:       userID,
		Status:       models.ConversationStatusActive,
		MessageCount: 0,
	}

	err := s.db.Create(&conversation).Error
	if err != nil {
		return nil, fmt.Errorf("failed to create conversation: %w", err)
	}

	return &conversation, nil
}