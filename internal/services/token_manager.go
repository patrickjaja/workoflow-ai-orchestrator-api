package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/workoflow/ai-orchestrator-api/internal/database"
	"github.com/workoflow/ai-orchestrator-api/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type TokenManager struct {
	db         database.Database
	encryption *EncryptionService
	redis      database.RedisClient
}

func NewTokenManager(db database.Database, encryption *EncryptionService, redis database.RedisClient) *TokenManager {
	return &TokenManager{
		db:         db,
		encryption: encryption,
		redis:      redis,
	}
}

func (tm *TokenManager) GetDecryptedToken(ctx context.Context, userID uint, providerType string) (string, error) {
	var userToken models.UserToken
	err := tm.db.DB().WithContext(ctx).
		Joins("JOIN oauth_providers ON oauth_providers.id = user_tokens.provider_id").
		Where("user_tokens.user_id = ? AND oauth_providers.provider_type = ? AND user_tokens.deleted_at IS NULL", userID, providerType).
		Preload("Provider").
		First(&userToken).Error
	
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("no token found for provider %s", providerType)
		}
		return "", fmt.Errorf("failed to retrieve token: %w", err)
	}
	
	if userToken.IsExpired() {
		return "", fmt.Errorf("token expired for provider %s", providerType)
	}
	
	decryptedToken, err := tm.encryption.Decrypt(userToken.AccessToken)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt token: %w", err)
	}
	
	return decryptedToken, nil
}

func (tm *TokenManager) GetAllUserTokens(ctx context.Context, userID uint) ([]models.UserToken, error) {
	var tokens []models.UserToken
	err := tm.db.DB().WithContext(ctx).
		Where("user_id = ? AND deleted_at IS NULL", userID).
		Preload("Provider").
		Find(&tokens).Error
	
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user tokens: %w", err)
	}
	
	return tokens, nil
}

func (tm *TokenManager) StoreToken(ctx context.Context, userID uint, providerID uint, accessToken, refreshToken string, expiresAt *time.Time) error {
	encryptedAccess, err := tm.encryption.Encrypt(accessToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}
	
	var encryptedRefresh *string
	if refreshToken != "" {
		encrypted, err := tm.encryption.Encrypt(refreshToken)
		if err != nil {
			return fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
		encryptedRefresh = &encrypted
	}
	
	userToken := models.UserToken{
		UserID:       userID,
		ProviderID:   providerID,
		AccessToken:  encryptedAccess,
		RefreshToken: encryptedRefresh,
		ExpiresAt:    expiresAt,
	}
	
	err = tm.db.DB().WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}, {Name: "provider_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"access_token", "refresh_token", "expires_at", "updated_at"}),
		}).
		Create(&userToken).Error
	
	if err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}
	
	return nil
}

func (tm *TokenManager) DeleteToken(ctx context.Context, userID uint, providerType string) error {
	result := tm.db.DB().WithContext(ctx).
		Exec(`
			UPDATE user_tokens 
			SET deleted_at = NOW() 
			FROM oauth_providers 
			WHERE user_tokens.provider_id = oauth_providers.id 
			AND user_tokens.user_id = ? 
			AND oauth_providers.provider_type = ?
			AND user_tokens.deleted_at IS NULL
		`, userID, providerType)
	
	if result.Error != nil {
		return fmt.Errorf("failed to delete token: %w", result.Error)
	}
	
	if result.RowsAffected == 0 {
		return fmt.Errorf("no token found to delete")
	}
	
	return nil
}

func (tm *TokenManager) HasValidToken(ctx context.Context, userID uint, providerType string) bool {
	var count int64
	tm.db.DB().WithContext(ctx).
		Model(&models.UserToken{}).
		Joins("JOIN oauth_providers ON oauth_providers.id = user_tokens.provider_id").
		Where("user_tokens.user_id = ? AND oauth_providers.provider_type = ? AND user_tokens.deleted_at IS NULL", userID, providerType).
		Where("user_tokens.expires_at IS NULL OR user_tokens.expires_at > NOW()").
		Count(&count)
	
	return count > 0
}

func (tm *TokenManager) GetRequiredProviders(ctx context.Context, tools []string) []string {
	providerMap := map[string][]string{
		"microsoft": {"sharepoint", "teams", "outlook", "onedrive"},
		"atlassian": {"jira", "confluence"},
		"slack":     {"slack"},
		"google":    {"drive", "calendar", "gmail"},
		"github":    {"github", "git"},
	}
	
	requiredProviders := make(map[string]bool)
	
	for _, tool := range tools {
		for provider, supportedTools := range providerMap {
			for _, supportedTool := range supportedTools {
				if tool == supportedTool {
					requiredProviders[provider] = true
					break
				}
			}
		}
	}
	
	result := make([]string, 0, len(requiredProviders))
	for provider := range requiredProviders {
		result = append(result, provider)
	}
	
	return result
}

func (tm *TokenManager) GetMissingProviders(ctx context.Context, userID uint, requiredProviders []string) []string {
	missingProviders := []string{}
	
	for _, provider := range requiredProviders {
		if !tm.HasValidToken(ctx, userID, provider) {
			missingProviders = append(missingProviders, provider)
		}
	}
	
	return missingProviders
}