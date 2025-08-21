package models

import (
	"time"

	"gorm.io/gorm"
)

type Organization struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	Name        string         `gorm:"type:varchar(255);not null" json:"name" validate:"required,min=1,max=255"`
	Slug        string         `gorm:"type:varchar(100);unique;not null" json:"slug" validate:"required"`
	Description string         `gorm:"type:text" json:"description"`
	Settings    JSON           `gorm:"type:jsonb" json:"settings"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	
	Users         []User         `gorm:"foreignKey:OrganizationID" json:"users,omitempty"`
	OAuthProviders []OAuthProvider `gorm:"foreignKey:OrganizationID" json:"oauth_providers,omitempty"`
	N8NWebhooks   []N8NWebhook   `gorm:"foreignKey:OrganizationID" json:"n8n_webhooks,omitempty"`
}

func (o *Organization) BeforeCreate(tx *gorm.DB) error {
	// GORM will auto-assign ID for uint primary key
	return nil
}

func (o *Organization) TableName() string {
	return "organizations"
}