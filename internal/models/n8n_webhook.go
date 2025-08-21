package models

import (
	"time"

	"gorm.io/gorm"
)

type N8NWebhook struct {
	ID               uint           `gorm:"primaryKey" json:"id"`
	OrganizationID   uint           `gorm:"not null" json:"organization_id"`
	WorkflowName     string         `gorm:"type:varchar(255);not null" json:"workflow_name" validate:"required,min=1,max=255"`
	WorkflowID       string         `gorm:"type:varchar(255);not null" json:"workflow_id" validate:"required"`
	WebhookPath      string         `gorm:"type:text;not null" json:"webhook_path" validate:"required"`
	N8NBaseURL       string         `gorm:"type:text;not null" json:"n8n_base_url" validate:"required,url"`
	AuthMethod       string         `gorm:"type:varchar(50)" json:"auth_method"`
	AuthToken        string         `gorm:"type:text" json:"-"`
	AuthHeaderName   string         `gorm:"type:varchar(255)" json:"auth_header_name"`
	Active           bool           `gorm:"default:true" json:"active"`
	Description      string         `gorm:"type:text" json:"description"`
	Tags             []string       `gorm:"type:text" json:"tags"`
	CreatedAt        time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt        time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`
	
	Organization Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}

func (n *N8NWebhook) BeforeCreate(tx *gorm.DB) error {
	// GORM will auto-assign ID for uint primary key
	return nil
}

func (n *N8NWebhook) BeforeUpdate(tx *gorm.DB) error {
	// No special logic needed for updates
	return nil
}

func (n *N8NWebhook) TableName() string {
	return "n8n_webhooks"
}