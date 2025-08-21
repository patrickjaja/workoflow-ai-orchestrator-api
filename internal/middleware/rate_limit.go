package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	ginlimiter "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"github.com/workoflow/ai-orchestrator-api/internal/config"
)

// RateLimitWrapper wraps the rate limiting functionality
type RateLimitWrapper struct {
	cfg *config.Config
}

// NewRateLimitMiddleware creates a new rate limit middleware wrapper
func NewRateLimitMiddleware(cfg *config.Config) *RateLimitWrapper {
	return &RateLimitWrapper{cfg: cfg}
}

// RateLimit returns the rate limiting middleware
func (rlw *RateLimitWrapper) RateLimit() gin.HandlerFunc {
	return RateLimitMiddleware(rlw.cfg)
}

// RateLimitMiddleware creates a rate limiting middleware
func RateLimitMiddleware(cfg *config.Config) gin.HandlerFunc {
	if !cfg.RateLimit.Enabled {
		// Return a no-op middleware if rate limiting is disabled
		return gin.HandlerFunc(func(c *gin.Context) {
			c.Next()
		})
	}

	// Create rate limiter
	rate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  int64(cfg.RateLimit.RequestsPerMinute),
	}

	// Use in-memory store for simplicity
	// In production, you might want to use Redis for distributed rate limiting
	store := memory.NewStore()

	// Create limiter instance
	rateLimiter := limiter.New(store, rate)

	// Return Gin middleware
	return ginlimiter.NewMiddleware(rateLimiter)
}

// CustomRateLimitMiddleware creates a custom rate limiting middleware with more control
func CustomRateLimitMiddleware(cfg *config.Config) gin.HandlerFunc {
	if !cfg.RateLimit.Enabled {
		return gin.HandlerFunc(func(c *gin.Context) {
			c.Next()
		})
	}

	// Create rate limiter
	rate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  int64(cfg.RateLimit.RequestsPerMinute),
	}

	store := memory.NewStore()
	rateLimiter := limiter.New(store, rate)

	return gin.HandlerFunc(func(c *gin.Context) {
		// Get client identifier (IP address or user ID)
		key := getClientKey(c)

		// Check rate limit
		context, err := rateLimiter.Get(c.Request.Context(), key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Rate limit error",
				"message": "Failed to check rate limit",
			})
			c.Abort()
			return
		}

		// Add rate limit headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", context.Limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", context.Remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", context.Reset))

		// Check if limit exceeded
		if context.Reached {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":     "Rate limit exceeded",
				"message":   "Too many requests. Please try again later.",
				"limit":     context.Limit,
				"remaining": context.Remaining,
				"reset":     context.Reset,
			})
			c.Abort()
			return
		}

		c.Next()
	})
}

// APIKeyRateLimitMiddleware applies different rate limits based on API key tier
func APIKeyRateLimitMiddleware(cfg *config.Config) gin.HandlerFunc {
	if !cfg.RateLimit.Enabled {
		return gin.HandlerFunc(func(c *gin.Context) {
			c.Next()
		})
	}

	// Different rate limits for different tiers
	tiers := map[string]limiter.Rate{
		"free": {
			Period: 1 * time.Minute,
			Limit:  int64(cfg.RateLimit.RequestsPerMinute / 4), // 25% of normal limit
		},
		"premium": {
			Period: 1 * time.Minute,
			Limit:  int64(cfg.RateLimit.RequestsPerMinute * 2), // 200% of normal limit
		},
		"enterprise": {
			Period: 1 * time.Minute,
			Limit:  int64(cfg.RateLimit.RequestsPerMinute * 5), // 500% of normal limit
		},
	}

	store := memory.NewStore()
	limiters := make(map[string]*limiter.Limiter)

	// Create limiters for each tier
	for tier, rate := range tiers {
		limiters[tier] = limiter.New(store, rate)
	}

	return gin.HandlerFunc(func(c *gin.Context) {
		// Determine user tier (from API key, user role, etc.)
		tier := getUserTier(c)
		
		// Get appropriate limiter
		rateLimiter, exists := limiters[tier]
		if !exists {
			// Default to free tier if tier not found
			rateLimiter = limiters["free"]
		}

		// Get client key
		key := getClientKey(c)

		// Check rate limit
		context, err := rateLimiter.Get(c.Request.Context(), key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Rate limit error",
				"message": "Failed to check rate limit",
			})
			c.Abort()
			return
		}

		// Add headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", context.Limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", context.Remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", context.Reset))
		c.Header("X-RateLimit-Tier", tier)

		// Check if limit exceeded
		if context.Reached {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":     "Rate limit exceeded",
				"message":   fmt.Sprintf("Rate limit exceeded for %s tier", tier),
				"tier":      tier,
				"limit":     context.Limit,
				"remaining": context.Remaining,
				"reset":     context.Reset,
			})
			c.Abort()
			return
		}

		c.Next()
	})
}

// BurstRateLimitMiddleware implements burst protection
func BurstRateLimitMiddleware(cfg *config.Config) gin.HandlerFunc {
	if !cfg.RateLimit.Enabled {
		return gin.HandlerFunc(func(c *gin.Context) {
			c.Next()
		})
	}

	// Short-term burst protection (e.g., max 10 requests per 10 seconds)
	burstRate := limiter.Rate{
		Period: 10 * time.Second,
		Limit:  int64(cfg.RateLimit.Burst),
	}

	// Long-term rate limit (normal rate)
	normalRate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  int64(cfg.RateLimit.RequestsPerMinute),
	}

	store := memory.NewStore()
	burstLimiter := limiter.New(store, burstRate)
	normalLimiter := limiter.New(store, normalRate)

	return gin.HandlerFunc(func(c *gin.Context) {
		key := getClientKey(c)

		// Check burst limit first
		burstContext, err := burstLimiter.Get(c.Request.Context(), key+":burst")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Rate limit error",
				"message": "Failed to check burst limit",
			})
			c.Abort()
			return
		}

		if burstContext.Reached {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":     "Burst limit exceeded",
				"message":   "Too many requests in a short period",
				"type":      "burst",
				"limit":     burstContext.Limit,
				"remaining": burstContext.Remaining,
				"reset":     burstContext.Reset,
			})
			c.Abort()
			return
		}

		// Check normal rate limit
		normalContext, err := normalLimiter.Get(c.Request.Context(), key+":normal")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Rate limit error",
				"message": "Failed to check rate limit",
			})
			c.Abort()
			return
		}

		// Add headers for normal rate limit
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", normalContext.Limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", normalContext.Remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", normalContext.Reset))

		// Add headers for burst limit
		c.Header("X-BurstLimit-Limit", fmt.Sprintf("%d", burstContext.Limit))
		c.Header("X-BurstLimit-Remaining", fmt.Sprintf("%d", burstContext.Remaining))
		c.Header("X-BurstLimit-Reset", fmt.Sprintf("%d", burstContext.Reset))

		if normalContext.Reached {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":     "Rate limit exceeded",
				"message":   "Rate limit exceeded",
				"type":      "normal",
				"limit":     normalContext.Limit,
				"remaining": normalContext.Remaining,
				"reset":     normalContext.Reset,
			})
			c.Abort()
			return
		}

		c.Next()
	})
}

// getClientKey determines the key to use for rate limiting
func getClientKey(c *gin.Context) string {
	// Try to get user ID first (for authenticated users)
	if userID, exists := c.Get("user_id"); exists {
		return fmt.Sprintf("user:%v", userID)
	}

	// Try to get API key
	if apiKey := c.GetHeader("X-API-Key"); apiKey != "" {
		return fmt.Sprintf("api_key:%s", apiKey)
	}

	// Fall back to IP address
	return fmt.Sprintf("ip:%s", c.ClientIP())
}

// getUserTier determines the user's rate limit tier
func getUserTier(c *gin.Context) string {
	// Check if user is authenticated
	if claims, exists := c.Get("token_claims"); exists {
		// You would implement logic here to determine tier based on user role, subscription, etc.
		// For now, return based on role
		if tokenClaims, ok := claims.(interface{ GetRole() string }); ok {
			switch tokenClaims.GetRole() {
			case "admin":
				return "enterprise"
			case "premium":
				return "premium"
			default:
				return "free"
			}
		}
	}

	// Check API key header for tier information
	if apiKey := c.GetHeader("X-API-Key"); apiKey != "" {
		// You would look up the API key in database to determine tier
		// For now, simple logic based on key length or prefix
		if len(apiKey) > 64 {
			return "enterprise"
		} else if len(apiKey) > 32 {
			return "premium"
		}
	}

	return "free"
}