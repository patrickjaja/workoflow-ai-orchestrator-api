package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
	"github.com/workoflow/ai-orchestrator-api/pkg/utils"
)

// JWTMiddleware handles JWT authentication
type JWTMiddleware struct {
	jwtService *services.JWTService
}

// NewJWTMiddleware creates a new JWT middleware
func NewJWTMiddleware(jwtService *services.JWTService) *JWTMiddleware {
	return &JWTMiddleware{
		jwtService: jwtService,
	}
}

// AuthRequired enforces JWT authentication
func (m *JWTMiddleware) AuthRequired() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			utils.SendErrorResponse(c, http.StatusUnauthorized, "Authorization header is required", nil)
			c.Abort()
			return
		}

		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			utils.SendErrorResponse(c, http.StatusUnauthorized, "Invalid or expired token", err)
			c.Abort()
			return
		}

		// Set user context in both Gin context and request context
		m.setUserContext(c, claims)
		
		c.Next()
	})
}

// AuthOptional validates JWT if present but doesn't require it
func (m *JWTMiddleware) AuthOptional() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			c.Next()
			return
		}

		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			// Invalid token, continue without setting user context
			c.Next()
			return
		}

		// Set user context
		m.setUserContext(c, claims)
		
		c.Next()
	})
}

// RequireRole checks if the authenticated user has the required role
func (m *JWTMiddleware) RequireRole(role string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		claims := m.getClaims(c)
		if claims == nil {
			utils.SendErrorResponse(c, http.StatusUnauthorized, "Authentication required", nil)
			c.Abort()
			return
		}

		if !m.hasRole(claims.Role, role) {
			utils.SendErrorResponse(c, http.StatusForbidden, "Insufficient permissions", nil)
			c.Abort()
			return
		}

		c.Next()
	})
}

// RequireAnyRole checks if the authenticated user has any of the required roles
func (m *JWTMiddleware) RequireAnyRole(roles ...string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		claims := m.getClaims(c)
		if claims == nil {
			utils.SendErrorResponse(c, http.StatusUnauthorized, "Authentication required", nil)
			c.Abort()
			return
		}

		hasAnyRole := false
		for _, role := range roles {
			if m.hasRole(claims.Role, role) {
				hasAnyRole = true
				break
			}
		}

		if !hasAnyRole {
			utils.SendErrorResponse(c, http.StatusForbidden, "Insufficient permissions", nil)
			c.Abort()
			return
		}

		c.Next()
	})
}

// AdminRequired ensures the user has admin role
func (m *JWTMiddleware) AdminRequired() gin.HandlerFunc {
	return m.RequireRole("admin")
}

// extractToken extracts the JWT token from the Authorization header
func (m *JWTMiddleware) extractToken(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// setUserContext sets user information in both Gin and request context
func (m *JWTMiddleware) setUserContext(c *gin.Context, claims *services.AccessTokenClaims) {
	// Set in Gin context for handlers
	c.Set("user_id", claims.UserID)
	c.Set("organization_id", claims.OrganizationID)
	c.Set("user_email", claims.Email)
	c.Set("user_role", claims.Role)
	c.Set("token_claims", claims)

	// Create enhanced request context
	ctx := c.Request.Context()
	ctx = context.WithValue(ctx, "user_id", claims.UserID)
	ctx = context.WithValue(ctx, "organization_id", claims.OrganizationID)
	ctx = context.WithValue(ctx, "user_email", claims.Email)
	ctx = context.WithValue(ctx, "user_role", claims.Role)
	
	// Generate request ID if not present
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		ctx = context.WithValue(ctx, "request_id", requestID)
	}

	// Update request context
	c.Request = c.Request.WithContext(ctx)
}

// getClaims retrieves token claims from context
func (m *JWTMiddleware) getClaims(c *gin.Context) *services.AccessTokenClaims {
	claims, exists := c.Get("token_claims")
	if !exists {
		return nil
	}

	tokenClaims, ok := claims.(*services.AccessTokenClaims)
	if !ok {
		return nil
	}

	return tokenClaims
}

// hasRole checks if user role is sufficient for required role
func (m *JWTMiddleware) hasRole(userRole, requiredRole string) bool {
	// Define role hierarchy (higher number = more permissions)
	roleHierarchy := map[string]int{
		"super_admin": 1000,
		"admin":       100,
		"moderator":   50,
		"user":        10,
		"viewer":      1,
	}

	userLevel, userExists := roleHierarchy[userRole]
	requiredLevel, requiredExists := roleHierarchy[requiredRole]

	// If roles don't exist in hierarchy, do exact match
	if !userExists || !requiredExists {
		return userRole == requiredRole
	}

	return userLevel >= requiredLevel
}

// GetUserID helper function to get user ID from context
func GetUserID(c *gin.Context) uint {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(uint); ok {
			return id
		}
	}
	return 0
}

// GetOrganizationID helper function to get organization ID from context
func GetOrganizationID(c *gin.Context) uint {
	if orgID, exists := c.Get("organization_id"); exists {
		if id, ok := orgID.(uint); ok {
			return id
		}
	}
	return 0
}

// GetUserEmail helper function to get user email from context
func GetUserEmail(c *gin.Context) string {
	if email, exists := c.Get("user_email"); exists {
		if emailStr, ok := email.(string); ok {
			return emailStr
		}
	}
	return ""
}

// GetUserRole helper function to get user role from context
func GetUserRole(c *gin.Context) string {
	if role, exists := c.Get("user_role"); exists {
		if roleStr, ok := role.(string); ok {
			return roleStr
		}
	}
	return ""
}

// IsAuthenticated checks if user is authenticated
func IsAuthenticated(c *gin.Context) bool {
	return GetUserID(c) != 0
}

// IsAdmin checks if user has admin role
func IsAdmin(c *gin.Context) bool {
	role := GetUserRole(c)
	return role == "admin" || role == "super_admin"
}