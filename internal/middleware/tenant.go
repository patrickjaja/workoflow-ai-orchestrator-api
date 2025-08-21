package middleware

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
	"github.com/workoflow/ai-orchestrator-api/pkg/utils"
)

// TenantMiddleware handles tenant context and validation
type TenantMiddleware struct {
	tenantService *services.TenantService
}

// NewTenantMiddleware creates a new tenant middleware
func NewTenantMiddleware(tenantService *services.TenantService) *TenantMiddleware {
	return &TenantMiddleware{
		tenantService: tenantService,
	}
}

// ResolveTenant resolves tenant information and sets it in context
func (m *TenantMiddleware) ResolveTenant() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Try to get tenant from different sources
		tenantID := m.extractTenantID(c)
		
		if tenantID != 0 {
			// Validate tenant and set in context
			err := m.setTenantContext(c, tenantID)
			if err != nil {
				utils.SendErrorResponse(c, http.StatusBadRequest, "Invalid tenant", err)
				c.Abort()
				return
			}
		}
		
		c.Next()
	})
}

// RequireTenant ensures a valid tenant is present
func (m *TenantMiddleware) RequireTenant() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		tenantID := GetTenantID(c)
		if tenantID == 0 {
			utils.SendErrorResponse(c, http.StatusBadRequest, "Tenant context required", nil)
			c.Abort()
			return
		}
		
		c.Next()
	})
}

// ValidateTenantAccess ensures the authenticated user has access to the tenant
func (m *TenantMiddleware) ValidateTenantAccess() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		userID := GetUserID(c)
		tenantID := GetTenantID(c)
		
		if userID == 0 {
			utils.SendErrorResponse(c, http.StatusUnauthorized, "Authentication required", nil)
			c.Abort()
			return
		}
		
		if tenantID == 0 {
			utils.SendErrorResponse(c, http.StatusBadRequest, "Tenant context required", nil)
			c.Abort()
			return
		}
		
		// Check if user has access to the tenant
		hasAccess, err := m.tenantService.UserHasAccessToOrganization(userID, tenantID)
		if err != nil {
			utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to validate tenant access", err)
			c.Abort()
			return
		}
		
		if !hasAccess {
			utils.SendErrorResponse(c, http.StatusForbidden, "Access denied to tenant", nil)
			c.Abort()
			return
		}
		
		c.Next()
	})
}

// EnforceTenantIsolation ensures that tenant-scoped resources are properly isolated
func (m *TenantMiddleware) EnforceTenantIsolation() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Extract user's organization from token claims
		userOrgID := GetOrganizationID(c)
		tenantID := GetTenantID(c)
		
		// If tenant ID is specified, ensure it matches user's organization
		if tenantID != 0 && userOrgID != 0 && tenantID != userOrgID {
			utils.SendErrorResponse(c, http.StatusForbidden, "Tenant isolation violation", nil)
			c.Abort()
			return
		}
		
		// If no tenant ID specified but user is authenticated, use their org
		if tenantID == 0 && userOrgID != 0 {
			m.setTenantContext(c, userOrgID)
		}
		
		c.Next()
	})
}

// extractTenantID extracts tenant ID from various sources
func (m *TenantMiddleware) extractTenantID(c *gin.Context) uint {
	// 1. Try path parameter
	if tenantParam := c.Param("tenant_id"); tenantParam != "" {
		if id, err := strconv.ParseUint(tenantParam, 10, 32); err == nil {
			return uint(id)
		}
	}
	
	// 2. Try query parameter
	if tenantQuery := c.Query("tenant_id"); tenantQuery != "" {
		if id, err := strconv.ParseUint(tenantQuery, 10, 32); err == nil {
			return uint(id)
		}
	}
	
	// 3. Try organization_id parameter (common alias)
	if orgParam := c.Param("organization_id"); orgParam != "" {
		if id, err := strconv.ParseUint(orgParam, 10, 32); err == nil {
			return uint(id)
		}
	}
	
	// 4. Try organization_id query
	if orgQuery := c.Query("organization_id"); orgQuery != "" {
		if id, err := strconv.ParseUint(orgQuery, 10, 32); err == nil {
			return uint(id)
		}
	}
	
	// 5. Try header
	if tenantHeader := c.GetHeader("X-Tenant-ID"); tenantHeader != "" {
		if id, err := strconv.ParseUint(tenantHeader, 10, 32); err == nil {
			return uint(id)
		}
	}
	
	// 6. Fall back to user's organization if authenticated
	return GetOrganizationID(c)
}

// setTenantContext validates and sets tenant context
func (m *TenantMiddleware) setTenantContext(c *gin.Context, tenantID uint) error {
	// Validate tenant exists
	org, err := m.tenantService.GetOrganization(context.Background(), tenantID)
	if err != nil {
		return err
	}
	
	// Set tenant context in Gin
	c.Set("tenant_id", tenantID)
	c.Set("tenant_name", org.Name)
	c.Set("tenant_slug", org.Slug)
	
	// Set in request context for deeper calls
	ctx := c.Request.Context()
	ctx = context.WithValue(ctx, "tenant_id", tenantID)
	ctx = context.WithValue(ctx, "tenant_name", org.Name)
	ctx = context.WithValue(ctx, "tenant_slug", org.Slug)
	
	c.Request = c.Request.WithContext(ctx)
	
	return nil
}

// Helper functions

// GetTenantID gets tenant ID from context
func GetTenantID(c *gin.Context) uint {
	if tenantID, exists := c.Get("tenant_id"); exists {
		if id, ok := tenantID.(uint); ok {
			return id
		}
	}
	return 0
}

// GetTenantName gets tenant name from context
func GetTenantName(c *gin.Context) string {
	if tenantName, exists := c.Get("tenant_name"); exists {
		if name, ok := tenantName.(string); ok {
			return name
		}
	}
	return ""
}

// GetTenantSlug gets tenant slug from context
func GetTenantSlug(c *gin.Context) string {
	if tenantSlug, exists := c.Get("tenant_slug"); exists {
		if slug, ok := tenantSlug.(string); ok {
			return slug
		}
	}
	return ""
}

// IsTenantContext checks if tenant context is available
func IsTenantContext(c *gin.Context) bool {
	return GetTenantID(c) != 0
}

// RequireTenantScope ensures operations are scoped to a specific tenant
func (m *TenantMiddleware) RequireTenantScope(allowedScopes ...string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		tenantID := GetTenantID(c)
		if tenantID == 0 {
			utils.SendErrorResponse(c, http.StatusBadRequest, "Tenant scope required", nil)
			c.Abort()
			return
		}
		
		// If specific scopes are defined, validate them
		if len(allowedScopes) > 0 {
			userRole := GetUserRole(c)
			validScope := false
			
			for _, scope := range allowedScopes {
				if userRole == scope || scope == "*" {
					validScope = true
					break
				}
			}
			
			if !validScope {
				utils.SendErrorResponse(c, http.StatusForbidden, "Insufficient scope for tenant operation", nil)
				c.Abort()
				return
			}
		}
		
		c.Next()
	})
}