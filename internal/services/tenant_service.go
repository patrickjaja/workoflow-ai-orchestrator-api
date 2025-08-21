package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/workoflow/ai-orchestrator-api/internal/database"
	"github.com/workoflow/ai-orchestrator-api/internal/models"

	"gorm.io/gorm"
)

type TenantService struct {
	db database.Database
}

func NewTenantService(db database.Database) *TenantService {
	return &TenantService{
		db: db,
	}
}

func (s *TenantService) CreateOrganization(ctx context.Context, org *models.Organization) error {
	return s.db.DB().WithContext(ctx).Create(org).Error
}

func (s *TenantService) GetOrganization(ctx context.Context, orgID uint) (*models.Organization, error) {
	var org models.Organization
	err := s.db.DB().WithContext(ctx).Where("id = ?", orgID).First(&org).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, err
	}
	return &org, nil
}

func (s *TenantService) GetOrganizationBySlug(ctx context.Context, slug string) (*models.Organization, error) {
	var org models.Organization
	err := s.db.DB().WithContext(ctx).Where("slug = ?", slug).First(&org).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, err
	}
	return &org, nil
}

func (s *TenantService) CreateUser(ctx context.Context, user *models.User) error {
	org, err := s.GetOrganization(ctx, user.OrganizationID)
	if err != nil {
		return fmt.Errorf("invalid organization: %w", err)
	}
	
	user.OrganizationID = org.ID
	return s.db.DB().WithContext(ctx).Create(user).Error
}

func (s *TenantService) GetUser(ctx context.Context, userID uint) (*models.User, error) {
	var user models.User
	err := s.db.DB().WithContext(ctx).
		Preload("Organization").
		Where("id = ?", userID).
		First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func (s *TenantService) GetOrCreateUser(ctx context.Context, orgID uint, externalID, channelType string, email *string) (*models.User, error) {
	var user models.User
	var emailStr string
	if email != nil {
		emailStr = *email
	} else {
		// Generate a unique email based on external ID and channel for users without email
		emailStr = fmt.Sprintf("%s+%s@external.local", externalID, channelType)
	}
	
	// First try to find by email and organization
	err := s.db.DB().WithContext(ctx).
		Where("organization_id = ? AND email = ?", orgID, emailStr).
		First(&user).Error

	if err == nil {
		return &user, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	
	// Create new user
	user = models.User{
		OrganizationID: orgID,
		Email:          emailStr,
		FirstName:      externalID, // Use external ID as first name for now
		Role:           "user",
		IsActive:       true,
		IsVerified:     false,
	}
	
	if err := s.db.DB().WithContext(ctx).Create(&user).Error; err != nil {
		return nil, err
	}
	
	return &user, nil
}

func (s *TenantService) CreateOAuthProvider(ctx context.Context, provider *models.OAuthProvider) error {
	org, err := s.GetOrganization(ctx, provider.OrganizationID)
	if err != nil {
		return fmt.Errorf("invalid organization: %w", err)
	}
	
	provider.OrganizationID = org.ID
	return s.db.DB().WithContext(ctx).Create(provider).Error
}

func (s *TenantService) GetOAuthProvider(ctx context.Context, orgID uint, providerType string) (*models.OAuthProvider, error) {
	var provider models.OAuthProvider
	err := s.db.DB().WithContext(ctx).
		Where("organization_id = ? AND provider_type = ? AND enabled = ?", orgID, providerType, true).
		First(&provider).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("OAuth provider not found or not enabled")
		}
		return nil, err
	}
	return &provider, nil
}

func (s *TenantService) UpdateOAuthProvider(ctx context.Context, providerID uint, updates map[string]interface{}) error {
	return s.db.DB().WithContext(ctx).
		Model(&models.OAuthProvider{}).
		Where("id = ?", providerID).
		Updates(updates).Error
}

func (s *TenantService) DeleteOAuthProvider(ctx context.Context, providerID uint) error {
	return s.db.DB().WithContext(ctx).
		Where("id = ?", providerID).
		Delete(&models.OAuthProvider{}).Error
}

func (s *TenantService) ListOAuthProviders(ctx context.Context, orgID uint) ([]models.OAuthProvider, error) {
	var providers []models.OAuthProvider
	err := s.db.DB().WithContext(ctx).
		Where("organization_id = ?", orgID).
		Find(&providers).Error
	return providers, err
}

func (s *TenantService) CreateN8NWebhook(ctx context.Context, webhook *models.N8NWebhook) error {
	org, err := s.GetOrganization(ctx, webhook.OrganizationID)
	if err != nil {
		return fmt.Errorf("invalid organization: %w", err)
	}
	
	webhook.OrganizationID = org.ID
	return s.db.DB().WithContext(ctx).Create(webhook).Error
}

func (s *TenantService) GetDefaultN8NWebhook(ctx context.Context, orgID uint) (*models.N8NWebhook, error) {
	var webhook models.N8NWebhook
	err := s.db.DB().WithContext(ctx).
		Where("organization_id = ? AND is_default = ? AND enabled = ?", orgID, true, true).
		First(&webhook).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("default webhook not found")
		}
		return nil, err
	}
	return &webhook, nil
}

// UserHasAccessToOrganization checks if user has access to organization - wrapper method
func (s *TenantService) UserHasAccessToOrganization(userID uint, orgID uint) (bool, error) {
	ctx := context.Background()
	
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return false, err
	}
	
	// Check if user belongs to the organization
	return user.OrganizationID == orgID, nil
}

func (s *TenantService) ListN8NWebhooks(ctx context.Context, orgID uint) ([]models.N8NWebhook, error) {
	var webhooks []models.N8NWebhook
	err := s.db.DB().WithContext(ctx).
		Where("organization_id = ?", orgID).
		Find(&webhooks).Error
	return webhooks, err
}

func (s *TenantService) UpdateN8NWebhook(ctx context.Context, webhookID uint, updates map[string]interface{}) error {
	return s.db.DB().WithContext(ctx).
		Model(&models.N8NWebhook{}).
		Where("id = ?", webhookID).
		Updates(updates).Error
}

func (s *TenantService) DeleteN8NWebhook(ctx context.Context, webhookID uint) error {
	return s.db.DB().WithContext(ctx).
		Where("id = ?", webhookID).
		Delete(&models.N8NWebhook{}).Error
}

func (s *TenantService) ValidateOrganizationAccess(ctx context.Context, userID uint, orgID uint) error {
	var count int64
	err := s.db.DB().WithContext(ctx).
		Model(&models.User{}).
		Where("id = ? AND organization_id = ?", userID, orgID).
		Count(&count).Error
	
	if err != nil {
		return err
	}
	
	if count == 0 {
		return fmt.Errorf("user does not belong to organization")
	}
	
	return nil
}