package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
)

type AuthMiddleware struct {
	jwtService *services.JWTService
}

func NewAuthMiddleware(jwtService *services.JWTService) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService: jwtService,
	}
}

// RequireAuth middleware validates JWT token and sets user context
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authorization header is required",
			})
			c.Abort()
			return
		}

		// Check if it's a Bearer token
		tokenParts := strings.SplitN(authHeader, " ", 2)
		if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		token := tokenParts[1]

		// Validate token
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", claims.UserID)
		c.Set("organization_id", claims.OrganizationID)
		c.Set("token_claims", claims)

		c.Next()
	})
}

// OptionalAuth middleware validates JWT token if present but doesn't require it
func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// No token provided, continue without setting user context
			c.Next()
			return
		}

		// Check if it's a Bearer token
		tokenParts := strings.SplitN(authHeader, " ", 2)
		if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
			// Invalid format, continue without setting user context
			c.Next()
			return
		}

		token := tokenParts[1]

		// Validate token
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			// Invalid token, continue without setting user context
			c.Next()
			return
		}

		// Set user context
		c.Set("user_id", claims.UserID)
		c.Set("organization_id", claims.OrganizationID)
		c.Set("token_claims", claims)

		c.Next()
	})
}

// RequireRole middleware checks if user has required role
func (m *AuthMiddleware) RequireRole(requiredRole string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		claims, exists := c.Get("token_claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		tokenClaims, ok := claims.(*services.AccessTokenClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Invalid token claims",
			})
			c.Abort()
			return
		}

		// Check if user has required role
		if !hasRole(tokenClaims.Role, requiredRole) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Insufficient permissions",
			})
			c.Abort()
			return
		}

		c.Next()
	})
}

// RequireAnyRole middleware checks if user has any of the required roles
func (m *AuthMiddleware) RequireAnyRole(requiredRoles ...string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		claims, exists := c.Get("token_claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		tokenClaims, ok := claims.(*services.AccessTokenClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Invalid token claims",
			})
			c.Abort()
			return
		}

		// Check if user has any of the required roles
		hasAnyRole := false
		for _, role := range requiredRoles {
			if hasRole(tokenClaims.Role, role) {
				hasAnyRole = true
				break
			}
		}

		if !hasAnyRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Insufficient permissions",
			})
			c.Abort()
			return
		}

		c.Next()
	})
}

// hasRole checks if user role matches or is higher than required role
func hasRole(userRole, requiredRole string) bool {
	// Define role hierarchy
	roleHierarchy := map[string]int{
		"admin":  100,
		"user":   10,
		"viewer": 1,
	}

	userLevel, userExists := roleHierarchy[userRole]
	requiredLevel, requiredExists := roleHierarchy[requiredRole]

	if !userExists || !requiredExists {
		return userRole == requiredRole
	}

	return userLevel >= requiredLevel
}

// ValidateApiKey middleware for API key authentication (alternative to JWT)
func (m *AuthMiddleware) ValidateApiKey() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Get API key from header or query parameter
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}

		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "API key is required",
			})
			c.Abort()
			return
		}

		// TODO: Implement API key validation logic
		// This would typically involve checking against a database of valid API keys
		// For now, this is a placeholder
		if !isValidApiKey(apiKey) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Invalid API key",
			})
			c.Abort()
			return
		}

		// Set context from API key (you would get this from database)
		// For now, this is a placeholder
		c.Set("api_key", apiKey)
		c.Set("auth_method", "api_key")

		c.Next()
	})
}

// isValidApiKey checks if the provided API key is valid
func isValidApiKey(apiKey string) bool {
	// TODO: Implement actual API key validation
	// This is a placeholder implementation
	return len(apiKey) >= 32 // Simple length check for now
}