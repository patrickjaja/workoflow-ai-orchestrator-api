package models

import (
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

type ProviderType string

const (
	ProviderTypeMicrosoft ProviderType = "microsoft"
	ProviderTypeAtlassian ProviderType = "atlassian"
	ProviderTypeSlack     ProviderType = "slack"
	ProviderTypeGoogle    ProviderType = "google"
	ProviderTypeGitHub    ProviderType = "github"
)

type OAuthProvider struct {
	ID               uint           `gorm:"primaryKey" json:"id"`
	OrganizationID   uint           `gorm:"not null" json:"organization_id"`
	ProviderType     ProviderType   `gorm:"type:varchar(50);not null" json:"provider_type" validate:"required,oneof=microsoft atlassian slack google github"`
	ClientID         string         `gorm:"type:text;not null" json:"-"`
	ClientSecret     string         `gorm:"type:text;not null" json:"-"`
	TenantID         *string        `gorm:"type:varchar(255)" json:"tenant_id,omitempty"`
	AdditionalConfig JSON           `gorm:"type:jsonb" json:"additional_config,omitempty"`
	Scopes           pq.StringArray `gorm:"type:text[]" json:"scopes,omitempty"`
	Enabled          bool           `gorm:"default:true" json:"enabled"`
	CreatedAt        time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt        time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`
	
	Organization Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
	UserTokens   []UserToken  `gorm:"foreignKey:ProviderID" json:"user_tokens,omitempty"`
}

func (op *OAuthProvider) BeforeCreate(tx *gorm.DB) error {
	// GORM will auto-assign ID for uint primary key
	return nil
}

func (op *OAuthProvider) TableName() string {
	return "oauth_providers"
}

func (op *OAuthProvider) GetOAuth2Endpoint() (authURL, tokenURL string) {
	switch op.ProviderType {
	case ProviderTypeMicrosoft:
		if op.TenantID != nil && *op.TenantID != "" {
			authURL = "https://login.microsoftonline.com/" + *op.TenantID + "/oauth2/v2.0/authorize"
			tokenURL = "https://login.microsoftonline.com/" + *op.TenantID + "/oauth2/v2.0/token"
		} else {
			authURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
			tokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
		}
	case ProviderTypeGoogle:
		authURL = "https://accounts.google.com/o/oauth2/v2/auth"
		tokenURL = "https://oauth2.googleapis.com/token"
	case ProviderTypeGitHub:
		authURL = "https://github.com/login/oauth/authorize"
		tokenURL = "https://github.com/login/oauth/access_token"
	case ProviderTypeSlack:
		authURL = "https://slack.com/oauth/v2/authorize"
		tokenURL = "https://slack.com/api/oauth.v2.access"
	case ProviderTypeAtlassian:
		authURL = "https://auth.atlassian.com/authorize"
		tokenURL = "https://auth.atlassian.com/oauth/token"
	}
	return
}

func (op *OAuthProvider) GetDefaultScopes() []string {
	if len(op.Scopes) > 0 {
		return op.Scopes
	}
	
	switch op.ProviderType {
	case ProviderTypeMicrosoft:
		return []string{
			"openid",
			"profile",
			"email",
			"offline_access",
			"User.Read",
			"Files.Read.All",
			"Sites.Read.All",
		}
	case ProviderTypeGoogle:
		return []string{
			"openid",
			"profile",
			"email",
			"https://www.googleapis.com/auth/drive.readonly",
		}
	case ProviderTypeGitHub:
		return []string{
			"user:email",
			"read:user",
			"repo",
		}
	case ProviderTypeSlack:
		return []string{
			"channels:read",
			"chat:write",
			"users:read",
			"team:read",
		}
	case ProviderTypeAtlassian:
		return []string{
			"read:jira-work",
			"read:jira-user",
			"read:confluence-content.all",
		}
	default:
		return []string{}
	}
}