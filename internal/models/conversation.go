package models

import (
	"time"

	"gorm.io/gorm"
)

type ConversationStatus string

const (
	ConversationStatusActive    ConversationStatus = "active"
	ConversationStatusCompleted ConversationStatus = "completed"
	ConversationStatusFailed    ConversationStatus = "failed"
)

type Conversation struct {
	ID                     uint               `gorm:"primaryKey" json:"id"`
	UserID                 uint               `gorm:"not null" json:"user_id"`
	ExternalConversationID *string            `gorm:"type:varchar(255)" json:"external_conversation_id,omitempty"`
	Status                 ConversationStatus `gorm:"type:varchar(50);default:'active'" json:"status"`
	Context                JSON               `gorm:"type:jsonb" json:"context,omitempty"`
	Summary                *string            `gorm:"type:text" json:"summary,omitempty"`
	LastMessageAt          *time.Time         `json:"last_message_at,omitempty"`
	MessageCount           int                `gorm:"default:0" json:"message_count"`
	Metadata               JSON               `gorm:"type:jsonb" json:"metadata,omitempty"`
	CreatedAt              time.Time          `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt              time.Time          `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt              gorm.DeletedAt     `gorm:"index" json:"-"`
	
	User     User      `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Messages []Message `gorm:"foreignKey:ConversationID" json:"messages,omitempty"`
}

func (c *Conversation) BeforeCreate(tx *gorm.DB) error {
	// GORM will auto-assign ID for uint primary key
	if c.Status == "" {
		c.Status = ConversationStatusActive
	}
	return nil
}

func (c *Conversation) TableName() string {
	return "conversations"
}

type Message struct {
	ID             uint           `gorm:"primaryKey" json:"id"`
	ConversationID uint           `gorm:"not null" json:"conversation_id"`
	Role           string         `gorm:"type:varchar(50);not null" json:"role" validate:"required,oneof=user assistant system"`
	Content        string         `gorm:"type:text;not null" json:"content" validate:"required"`
	TokenCount     *int           `json:"token_count,omitempty"`
	Metadata       JSON           `gorm:"type:jsonb" json:"metadata,omitempty"`
	CreatedAt      time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
	
	Conversation Conversation `gorm:"foreignKey:ConversationID" json:"conversation,omitempty"`
}

func (m *Message) BeforeCreate(tx *gorm.DB) error {
	// GORM will auto-assign ID for uint primary key
	return nil
}

func (m *Message) TableName() string {
	return "messages"
}