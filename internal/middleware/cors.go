package middleware

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/workoflow/ai-orchestrator-api/internal/config"
)

// CORSMiddleware configures Cross-Origin Resource Sharing
func CORSMiddleware(cfg *config.Config) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Check if origin is allowed
		if isAllowedOrigin(origin, cfg.CORS.AllowedOrigins) {
			c.Header("Access-Control-Allow-Origin", origin)
		} else if len(cfg.CORS.AllowedOrigins) > 0 && cfg.CORS.AllowedOrigins[0] == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		}

		// Set allowed methods
		if len(cfg.CORS.AllowedMethods) > 0 {
			methods := ""
			for i, method := range cfg.CORS.AllowedMethods {
				if i > 0 {
					methods += ", "
				}
				methods += method
			}
			c.Header("Access-Control-Allow-Methods", methods)
		} else {
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
		}

		// Set allowed headers
		if len(cfg.CORS.AllowedHeaders) > 0 {
			headers := ""
			for i, header := range cfg.CORS.AllowedHeaders {
				if i > 0 {
					headers += ", "
				}
				headers += header
			}
			c.Header("Access-Control-Allow-Headers", headers)
		} else {
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-API-Key")
		}

		// Set exposed headers
		if len(cfg.CORS.ExposeHeaders) > 0 {
			exposedHeaders := ""
			for i, header := range cfg.CORS.ExposeHeaders {
				if i > 0 {
					exposedHeaders += ", "
				}
				exposedHeaders += header
			}
			c.Header("Access-Control-Expose-Headers", exposedHeaders)
		}

		// Set credentials
		if cfg.CORS.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		// Set max age
		if cfg.CORS.MaxAge > 0 {
			c.Header("Access-Control-Max-Age", fmt.Sprintf("%d", cfg.CORS.MaxAge))
		}

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})
}

// isAllowedOrigin checks if the origin is in the allowed list
func isAllowedOrigin(origin string, allowedOrigins []string) bool {
	if len(allowedOrigins) == 0 {
		return false
	}

	for _, allowedOrigin := range allowedOrigins {
		if allowedOrigin == "*" || allowedOrigin == origin {
			return true
		}
		
		// Support wildcard subdomains (e.g., *.example.com)
		if len(allowedOrigin) > 2 && allowedOrigin[:2] == "*." {
			domain := allowedOrigin[2:]
			if len(origin) > len(domain) && origin[len(origin)-len(domain):] == domain {
				// Check if it's a subdomain (has a dot before the domain)
				beforeDomain := origin[:len(origin)-len(domain)]
				if len(beforeDomain) > 0 && beforeDomain[len(beforeDomain)-1] == '.' {
					return true
				}
			}
		}
	}

	return false
}

