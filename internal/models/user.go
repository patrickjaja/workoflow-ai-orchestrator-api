package models

import (
	"time"

	"gorm.io/gorm"
)

type ChannelType string

const (
	ChannelTypeTeams ChannelType = "teams"
	ChannelTypeSlack ChannelType = "slack"
	ChannelTypeWeb   ChannelType = "web"
)

type User struct {
	ID             uint           `gorm:"primaryKey" json:"id"`
	UUID           string         `gorm:"type:varchar(100);unique" json:"uuid"`
	OrganizationID uint           `gorm:"not null" json:"organization_id"`
	Email          string         `gorm:"type:varchar(255);not null;unique" json:"email" validate:"required,email"`
	PasswordHash   string         `gorm:"type:varchar(255)" json:"-"`
	FirstName      string         `gorm:"type:varchar(100)" json:"first_name"`
	LastName       string         `gorm:"type:varchar(100)" json:"last_name"`
	Role           string         `gorm:"type:varchar(50);default:user" json:"role"`
	IsActive       bool           `gorm:"default:true" json:"is_active"`
	IsVerified     bool           `gorm:"default:false" json:"is_verified"`
	Settings       JSON           `gorm:"type:json" json:"settings"`
	LastLoginAt    *time.Time     `json:"last_login_at"`
	ExternalID     *string        `gorm:"type:varchar(255)" json:"external_id"`
	CreatedAt      time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt      time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
	
	Organization  Organization   `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
	UserTokens    []UserToken    `gorm:"foreignKey:UserID" json:"tokens,omitempty"`
	Conversations []Conversation `gorm:"foreignKey:UserID" json:"conversations,omitempty"`
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	// GORM will auto-assign ID for uint primary key
	return nil
}

func (u *User) TableName() string {
	return "users"
}