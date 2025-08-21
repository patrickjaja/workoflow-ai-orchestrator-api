package mocks

import (
	"context"

	"github.com/workoflow/ai-orchestrator-api/internal/ai"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
)

// External service interfaces for mocking

// AIServiceInterface defines the interface for AI services
type AIServiceInterface interface {
	ProcessMessage(ctx context.Context, req *services.ChatRequest) (*services.AIResponse, error)
	GetConversationSummary(ctx context.Context, conversationID string) (string, error)
	ValidateWorkflowParameters(ctx context.Context, workflowName string, parameters map[string]interface{}) (bool, []string, error)
}

// N8NClientInterface defines the interface for N8N client
type N8NClientInterface interface {
	ExecuteWebhook(ctx context.Context, webhookConfig *models.N8NWebhook, request *services.N8NWebhookRequest) (*services.N8NWebhookResponse, error)
	GetExecutionStatus(ctx context.Context, webhookConfig *models.N8NWebhook, executionID string) (*services.N8NExecutionStatus, error)
	GetWorkflowInfo(ctx context.Context, webhookConfig *models.N8NWebhook) (*services.N8NWorkflowInfo, error)
	TestWebhook(ctx context.Context, webhookConfig *models.N8NWebhook) (*services.N8NWebhookResponse, error)
	ValidateWebhookConfig(webhookConfig *models.N8NWebhook) error
	GetHealthStatus(ctx context.Context, baseURL string) (bool, error)
}

// ChatServiceInterface defines the interface for chat services
type ChatServiceInterface interface {
	SendMessage(ctx context.Context, userID, orgID uint, conversationID, message string) (*services.ChatMessage, error)
	GetConversationHistory(ctx context.Context, userID, orgID uint, conversationID string, limit int) ([]services.ChatMessage, error)
	GetConversation(ctx context.Context, userID, orgID uint, conversationID string) (*services.ChatSessionInfo, error)
	ListConversations(ctx context.Context, userID, orgID uint, limit, offset int) ([]services.ChatSessionInfo, error)
	ExecuteWorkflow(ctx context.Context, request *services.WorkflowExecutionRequest) (*services.WorkflowExecutionResponse, error)
	GetWorkflowStatus(ctx context.Context, userID, orgID uint, executionID string) (*services.WorkflowExecutionResponse, error)
	GetConversationSummary(ctx context.Context, userID, orgID uint, conversationID string) (string, error)
	ClearConversation(ctx context.Context, userID, orgID uint, conversationID string) error
	DeleteConversation(ctx context.Context, userID, orgID uint, conversationID string) error
}

// ContextManagerInterface defines the interface for context management
type ContextManagerInterface interface {
	GetContext(conversationID string) (map[string]interface{}, error)
	UpdateContext(conversationID string, updates map[string]interface{}) error
	DeleteContext(conversationID string) error
	GetPendingActions(conversationID string) ([]ai.PendingAction, error)
	ConfirmAction(conversationID, actionID string) error
	CancelAction(conversationID, actionID string) error
	GetConversationHistory(conversationID string, limit int) ([]ai.ConversationMessage, error)
	SetVariable(conversationID, key string, value interface{}) error
	GetVariable(conversationID, key string) (interface{}, bool)
	GetContextStats() map[string]interface{}
	ExportContext(conversationID string) ([]byte, error)
	ImportContext(conversationID string, data []byte) error
}

// OAuthServiceInterface defines the interface for OAuth services
type OAuthServiceInterface interface {
	GetAuthURL(provider string, state string, organizationID uint) (string, error)
	ExchangeCode(provider string, code string, state string) (*services.OAuthTokenResponse, error)
	RefreshToken(provider string, refreshToken string) (*services.OAuthTokenResponse, error)
	GetUserInfo(provider string, accessToken string) (*services.OAuthUserInfo, error)
	ValidateProvider(provider string) error
}

// TenantServiceInterface defines the interface for tenant services
type TenantServiceInterface interface {
	GetUser(userID uint) (*models.User, error)
	GetOrganization(orgID uint) (*models.Organization, error)
	UserHasAccessToOrganization(userID, orgID uint) (bool, error)
	CreateUser(user *models.User) error
	UpdateUser(user *models.User) error
	DeleteUser(userID uint) error
	CreateOrganization(org *models.Organization) error
	UpdateOrganization(org *models.Organization) error
	DeleteOrganization(orgID uint) error
}

// JWTServiceInterface defines the interface for JWT services
type JWTServiceInterface interface {
	GenerateAccessToken(userID, organizationID uint, email, role string) (string, error)
	GenerateRefreshToken(userID uint) (string, error)
	ValidateAccessToken(tokenString string) (*services.AccessTokenClaims, error)
	ValidateRefreshToken(tokenString string) (*services.RefreshTokenClaims, error)
	RefreshAccessToken(refreshTokenString string) (string, error)
	RevokeToken(tokenString string) error
	GetTokenClaims(tokenString string) (*services.AccessTokenClaims, error)
}

// EncryptionServiceInterface defines the interface for encryption services
type EncryptionServiceInterface interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
	EncryptBytes(plaintext []byte) ([]byte, error)
	DecryptBytes(ciphertext []byte) ([]byte, error)
	HashPassword(password string) (string, error)
	VerifyPassword(password, hashedPassword string) error
	GenerateAPIKey(length int) string
	GenerateSecureToken(length int) string
}

// TokenManagerInterface defines the interface for token management
type TokenManagerInterface interface {
	StoreUserToken(userToken *models.UserToken) error
	GetUserToken(userID uint, provider string) (*models.UserToken, error)
	UpdateUserToken(userToken *models.UserToken) error
	DeleteUserToken(userID uint, provider string) error
	RefreshUserToken(userID uint, provider string) (*models.UserToken, error)
	ValidateUserToken(userID uint, provider string) (bool, error)
	GetUserTokens(userID uint) ([]*models.UserToken, error)
	CleanupExpiredTokens() error
}

// WebhookServiceInterface defines interface for webhook management
type WebhookServiceInterface interface {
	CreateWebhook(webhook *models.N8NWebhook) error
	GetWebhook(webhookID uint) (*models.N8NWebhook, error)
	GetWebhookByName(organizationID uint, name string) (*models.N8NWebhook, error)
	UpdateWebhook(webhook *models.N8NWebhook) error
	DeleteWebhook(webhookID uint) error
	ListWebhooks(organizationID uint, limit, offset int) ([]*models.N8NWebhook, error)
	TestWebhook(webhookID uint) error
}

// DatabaseInterface defines interface for database operations
type DatabaseInterface interface {
	// Generic CRUD operations
	Create(value interface{}) error
	Save(value interface{}) error
	Delete(value interface{}, conditions ...interface{}) error
	Find(dest interface{}, conditions ...interface{}) error
	First(dest interface{}, conditions ...interface{}) error
	Where(query interface{}, args ...interface{}) DatabaseInterface
	Preload(query string, args ...interface{}) DatabaseInterface
	Order(value interface{}) DatabaseInterface
	Limit(limit int) DatabaseInterface
	Offset(offset int) DatabaseInterface
	Count(count *int64) error
	
	// Transaction operations
	Begin() DatabaseInterface
	Commit() error
	Rollback() error
	
	// Migration operations
	Migrate(dst ...interface{}) error
	
	// Raw SQL operations
	Exec(sql string, values ...interface{}) error
	Raw(sql string, values ...interface{}) DatabaseInterface
	Scan(dest interface{}) error
}