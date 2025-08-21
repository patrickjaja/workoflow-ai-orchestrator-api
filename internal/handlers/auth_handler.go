package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"github.com/workoflow/ai-orchestrator-api/internal/config"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
)

type LoginRequest struct {
	Provider string `json:"provider" binding:"required"`
}

type LoginResponse struct {
	AuthURL   string `json:"auth_url"`
	SessionID string `json:"session_id"`
	State     string `json:"state"`
}

type CallbackRequest struct {
	Code      string `json:"code" binding:"required"`
	State     string `json:"state" binding:"required"`
	Provider  string `json:"provider" binding:"required"`
	SessionID string `json:"session_id" binding:"required"`
}

type TokenResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int      `json:"expires_in"`
	TokenType    string   `json:"token_type"`
	User         UserInfo `json:"user"`
}

type UserInfo struct {
	ID             uint   `json:"id"`
	Email          string `json:"email"`
	Name           string `json:"name"`
	OrganizationID uint   `json:"organization_id"`
	Role           string `json:"role"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// AuthHandler provides comprehensive auth functionality
type AuthHandler struct {
	db            *gorm.DB
	jwtService    *services.JWTService
	oauthService  *services.OAuthService
	tenantService *services.TenantService
	config        *config.Config
}

// SimpleAuthHandler provides basic auth functionality for compilation
type SimpleAuthHandler struct {
	oauthService  *services.OAuthService
	jwtService    *services.JWTService
	tenantService *services.TenantService
}

func NewAuthHandler(db *gorm.DB, jwtService *services.JWTService, oauthService *services.OAuthService, tenantService *services.TenantService, config *config.Config) *AuthHandler {
	return &AuthHandler{
		db:            db,
		jwtService:    jwtService,
		oauthService:  oauthService,
		tenantService: tenantService,
		config:        config,
	}
}

func NewSimpleAuthHandler(oauthService *services.OAuthService, jwtService *services.JWTService, tenantService *services.TenantService) *SimpleAuthHandler {
	return &SimpleAuthHandler{
		oauthService:  oauthService,
		jwtService:    jwtService,
		tenantService: tenantService,
	}
}

// AuthHandler methods - OAuth flow methods
func (h *AuthHandler) GetProviders(c *gin.Context) {
	// Return available OAuth providers for testing
	providers := map[string]interface{}{
		"providers": []string{"google", "github", "microsoft"},
		"enabled":   true,
	}
	c.JSON(http.StatusOK, providers)
}

func (h *AuthHandler) InitiateOAuth(c *gin.Context) {
	provider := c.Param("provider")
	orgSlug := c.GetHeader("X-Organization-Slug")
	
	if orgSlug == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing organization slug",
			"message": "X-Organization-Slug header is required",
		})
		return
	}
	
	// Get organization by slug
	org, err := h.tenantService.GetOrganizationBySlug(c.Request.Context(), orgSlug)
	if err != nil {
		// Log the error for debugging
		fmt.Printf("Error getting organization by slug '%s': %v\n", orgSlug, err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Organization not found",
			"message": err.Error(),
		})
		return
	}
	
	// Generate OAuth URL - using a temporary user ID for now
	// In production, this would be the actual authenticated user or a session-based approach
	userID := uint(1) // Temporary - would get from session/context
	authURL, sessionID, err := h.oauthService.GetAuthURL(c.Request.Context(), userID, org.ID, provider)
	if err != nil {
		// Log the error for debugging
		fmt.Printf("Error generating auth URL for org %d, provider %s: %v\n", org.ID, provider, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate auth URL",
			"message": err.Error(),
		})
		return
	}
	
	// Generate state for CSRF protection
	state := sessionID // Using sessionID as state for simplicity
	
	// Use custom JSON encoder that doesn't escape HTML
	response := LoginResponse{
		AuthURL:   authURL,
		SessionID: sessionID,
		State:     state,
	}
	
	encoder := json.NewEncoder(c.Writer)
	encoder.SetEscapeHTML(false)
	c.Header("Content-Type", "application/json")
	c.Status(http.StatusOK)
	encoder.Encode(response)
}

func (h *AuthHandler) HandleOAuthCallback(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")
	
	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required parameters",
			"message": "code and state are required",
		})
		return
	}
	
	// Complete OAuth flow and get user info
	userInfo, err := h.oauthService.CompleteOAuth(c.Request.Context(), provider, code, state, state)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Failed to complete OAuth flow",
			"message": err.Error(),
		})
		return
	}
	
	// Generate JWT for the authenticated user
	accessToken, err := h.jwtService.GenerateAccessToken(1, userInfo.OrganizationID, userInfo.Email, userInfo.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate access token",
			"message": err.Error(),
		})
		return
	}
	
	// Return success with user info and token
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"token_type": "Bearer",
		"expires_in": 3600,
		"user": userInfo,
		"message": "Successfully authenticated with SharePoint",
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}
	
	// Mock refresh token response
	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  "new-mock-access-token",
		RefreshToken: "new-mock-refresh-token",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		User: UserInfo{
			ID:             1,
			Email:          "test@example.com",
			Name:           "Test User",
			OrganizationID: 1,
			Role:           "admin",
		},
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

func (h *AuthHandler) GetProfile(c *gin.Context) {
	// Mock user profile response
	c.JSON(http.StatusOK, UserInfo{
		ID:             1,
		Email:          "test@example.com",
		Name:           "Test User",
		OrganizationID: 1,
		Role:           "admin",
	})
}

func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	// Mock profile update
	c.JSON(http.StatusOK, map[string]string{"message": "Profile updated successfully"})
}

// Login provides a basic login endpoint
func (h *SimpleAuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
		})
		return
	}

	// Simplified OAuth initiation
	authURL, sessionID, state, err := h.oauthService.InitiateOAuth(c.Request.Context(), req.Provider)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to initiate OAuth",
			Message: err.Error(),
		})
		return
	}

	// Use custom JSON encoder that doesn't escape HTML
	response := LoginResponse{
		AuthURL:   authURL,
		SessionID: sessionID,
		State:     state,
	}
	
	encoder := json.NewEncoder(c.Writer)
	encoder.SetEscapeHTML(false)
	c.Header("Content-Type", "application/json")
	c.Status(http.StatusOK)
	encoder.Encode(response)
}

// Callback handles OAuth callback
func (h *SimpleAuthHandler) Callback(c *gin.Context) {
	var req CallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
		})
		return
	}

	// Complete OAuth flow
	user, err := h.oauthService.CompleteOAuth(c.Request.Context(), req.Provider, req.Code, req.State, req.SessionID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "OAuth authentication failed",
			Message: err.Error(),
		})
		return
	}

	// Generate JWT tokens with proper parameters
	userID := uint(1) // Convert from string ID - in real implementation this would be proper conversion
	accessToken, err := h.jwtService.GenerateAccessToken(userID, user.OrganizationID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to generate access token",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: "refresh-token-placeholder", // Would generate proper refresh token
		ExpiresIn:    86400,                       // 24 hours
		TokenType:    "Bearer",
		User: UserInfo{
			ID:             userID,
			Email:          user.Email,
			Name:           user.Name,
			OrganizationID: user.OrganizationID,
			Role:           user.Role,
		},
	})
}

// RefreshToken handles token refresh
func (h *SimpleAuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
		})
		return
	}

	// Basic refresh token validation
	claims, err := h.jwtService.ValidateRefreshTokenWrapper(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "Invalid refresh token",
			Message: err.Error(),
		})
		return
	}

	// Get user with context
	user, err := h.tenantService.GetUser(context.Background(), claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "User not found",
			Message: err.Error(),
		})
		return
	}

	// Generate new access token
	accessToken, err := h.jwtService.GenerateAccessToken(claims.UserID, claims.OrganizationID, user.Email, "user")
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to generate access token",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: req.RefreshToken, // Keep same refresh token for simplicity
		ExpiresIn:    86400,
		TokenType:    "Bearer",
		User: UserInfo{
			ID:             user.ID,
			Email:          user.Email,
			Name:           "User Name", // Basic placeholder
			OrganizationID: user.OrganizationID,
			Role:           "user",
		},
	})
}

// Logout handles user logout
func (h *SimpleAuthHandler) Logout(c *gin.Context) {
	// In a real implementation, you would invalidate the token
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully logged out",
	})
}

// GetProfile gets user profile
func (h *SimpleAuthHandler) GetProfile(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userIDStr, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "User not authenticated",
			Message: "No user ID in context",
		})
		return
	}

	userID, err := strconv.ParseUint(userIDStr.(string), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid user ID",
			Message: err.Error(),
		})
		return
	}

	// Get user
	user, err := h.tenantService.GetUser(context.Background(), uint(userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get user",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, UserInfo{
		ID:             user.ID,
		Email:          user.Email,
		Name:           "User Name", // Basic placeholder
		OrganizationID: user.OrganizationID,
		Role:           "user",
	})
}