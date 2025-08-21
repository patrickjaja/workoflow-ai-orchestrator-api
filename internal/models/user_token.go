package models

import (
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

type UserToken struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	UserID       uint           `gorm:"not null" json:"user_id"`
	ProviderID   uint           `gorm:"not null" json:"provider_id"`
	AccessToken  string         `gorm:"type:text;not null" json:"-"`
	RefreshToken *string        `gorm:"type:text" json:"-"`
	TokenType    string         `gorm:"type:varchar(50);default:'Bearer'" json:"token_type"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	Scopes       pq.StringArray `gorm:"type:text[]" json:"scopes,omitempty"`
	Metadata     JSON           `gorm:"type:jsonb" json:"metadata,omitempty"`
	CreatedAt    time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt    time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
	
	User     User          `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Provider OAuthProvider `gorm:"foreignKey:ProviderID" json:"provider,omitempty"`
}

func (ut *UserToken) BeforeCreate(tx *gorm.DB) error {
	// GORM will auto-assign ID for uint primary key
	return nil
}

func (ut *UserToken) TableName() string {
	return "user_tokens"
}

func (ut *UserToken) IsExpired() bool {
	if ut.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*ut.ExpiresAt)
}

func (ut *UserToken) NeedsRefresh() bool {
	if ut.ExpiresAt == nil {
		return false
	}
	return time.Now().Add(5 * time.Minute).After(*ut.ExpiresAt)
}