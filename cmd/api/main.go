package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/workoflow/ai-orchestrator-api/internal/ai"
	"github.com/workoflow/ai-orchestrator-api/internal/config"
	"github.com/workoflow/ai-orchestrator-api/internal/database"
	"github.com/workoflow/ai-orchestrator-api/internal/handlers"
	"github.com/workoflow/ai-orchestrator-api/internal/middleware"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
	"github.com/workoflow/ai-orchestrator-api/pkg/utils"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set gin mode based on environment
	if cfg.App.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else if cfg.App.Env == "test" {
		gin.SetMode(gin.TestMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Initialize logger
	err = utils.InitLogger(&utils.LogConfig{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
		Output: cfg.Log.Output,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	logger := utils.GetLogger()
	logger.Info("Starting AI Orchestrator API", utils.LogFields{
		"version":     "1.0.1",
		"environment": cfg.App.Env,
		"port":        cfg.App.Port,
	})

	// Initialize database
	dbConn, err := database.Connect(&cfg.Database)
	if err != nil {
		logger.Fatal("Failed to connect to database", err)
	}

	// Get the underlying gorm.DB for migrations and other operations
	db := dbConn.DB()

	// Run migrations
	err = database.Migrate(db)
	if err != nil {
		logger.Fatal("Failed to run migrations", err)
	}
	logger.Info("Database migrations completed successfully", nil)

	// Initialize Redis if configured
	var redisClient database.RedisClient
	if cfg.Redis.URL != "" {
		redisClient, err = database.InitializeRedis(cfg.Redis)
		if err != nil {
			logger.Warn("Redis not available, continuing without session persistence", utils.LogFields{
				"error": err.Error(),
			})
			// Don't fail, just continue without Redis
			redisClient = nil
		} else {
			logger.Info("Redis connected successfully", utils.LogFields{
				"url": cfg.Redis.URL,
			})
		}
	}

	// Initialize services
	services, err := initializeServices(cfg, db, redisClient)
	if err != nil {
		logger.Fatal("Failed to initialize services", err)
	}

	// Initialize handlers
	handlers := initializeHandlers(cfg, db, services)

	// Initialize middleware
	middlewares := initializeMiddleware(services)

	// Setup router
	router := setupRouter(cfg, handlers, middlewares)

	// Create server
	srv := &http.Server{
		Addr:           fmt.Sprintf(":%d", cfg.App.Port),
		Handler:        router,
		ReadTimeout:    time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:    time.Duration(cfg.Server.IdleTimeout) * time.Second,
		MaxHeaderBytes: cfg.Server.MaxHeaderBytes,
	}

	// Setup graceful shutdown
	go func() {
		logger.Info("Server starting", utils.LogFields{
			"addr": srv.Addr,
		})
		
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", err)
	}

	logger.Info("Server stopped gracefully")
}

// ServiceContainer holds all initialized services
type ServiceContainer struct {
	AIService         *services.AIService
	N8NClient         *services.N8NClient
	ChatService       *services.ChatService
	JWTService        *services.JWTService
	OAuthService      *services.OAuthService
	TenantService     *services.TenantService
	EncryptionService *services.EncryptionService
	TokenManager      *services.TokenManager
	ContextManager    *ai.ContextManager
}

// HandlerContainer holds all initialized handlers
type HandlerContainer struct {
	AuthHandler   *handlers.AuthHandler
	ChatHandler   *handlers.ChatHandler
	HealthHandler *handlers.HealthHandler
	AdminHandler  *handlers.AdminHandler
}

// MiddlewareContainer holds all initialized middleware
type MiddlewareContainer struct {
	JWTMiddleware    *middleware.JWTMiddleware
	TenantMiddleware *middleware.TenantMiddleware
}

func initializeServices(cfg *config.Config, db *gorm.DB, redisClient database.RedisClient) (*ServiceContainer, error) {
	logger := utils.GetLogger()
	
	// Initialize core services
	jwtService := services.NewJWTService(cfg.Security.JWTSecret, cfg.Security.JWTExpiry)
	encryptionService := services.NewEncryptionService(cfg.Security.EncryptionKey)
	dbAdapter := database.NewGormAdapter(db)
	tenantService := services.NewTenantService(dbAdapter)
	tokenManager := services.NewTokenManager(dbAdapter, encryptionService, redisClient)
	
	// Initialize AI service with real OpenAI/Azure OpenAI
	aiService, err := services.NewAIService(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AI service: %w", err)
	}
	
	// Initialize N8N client
	n8nClient := services.NewN8NClient(cfg)
	
	// Initialize OAuth service
	oauthService := services.NewOAuthService(dbAdapter, encryptionService, redisClient, cfg.OAuth)
	
	// Initialize context manager
	contextManager := ai.NewContextManager()
	
	// Initialize chat service
	chatService := services.NewChatService(db, aiService, n8nClient, tenantService)
	
	logger.Info("Services initialized successfully", utils.LogFields{
		"ai_service_enabled":    aiService != nil,
		"n8n_client_enabled":    n8nClient != nil,
		"oauth_service":         true,
		"redis_enabled":         redisClient != nil,
		"database_connected":    db != nil,
	})

	return &ServiceContainer{
		AIService:         aiService,
		N8NClient:         n8nClient,
		ChatService:       chatService,
		JWTService:        jwtService,
		OAuthService:      oauthService,
		TenantService:     tenantService,
		EncryptionService: encryptionService,
		TokenManager:      tokenManager,
		ContextManager:    contextManager,
	}, nil
}

func initializeHandlers(cfg *config.Config, db *gorm.DB, services *ServiceContainer) *HandlerContainer {
	return &HandlerContainer{
		AuthHandler:   handlers.NewAuthHandler(db, services.JWTService, services.OAuthService, services.TenantService, cfg),
		ChatHandler:   handlers.NewChatHandler(services.ChatService, services.TenantService),
		HealthHandler: handlers.NewHealthHandler(db),
		AdminHandler:  handlers.NewAdminHandler(db, services.AIService, services.ContextManager, services.TenantService),
	}
}

func initializeMiddleware(services *ServiceContainer) *MiddlewareContainer {
	return &MiddlewareContainer{
		JWTMiddleware:    middleware.NewJWTMiddleware(services.JWTService),
		TenantMiddleware: middleware.NewTenantMiddleware(services.TenantService),
	}
}

func setupRouter(cfg *config.Config, handlers *HandlerContainer, middlewares *MiddlewareContainer) *gin.Engine {
	router := gin.New()

	// Global middleware
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// Security middleware
	router.Use(func(c *gin.Context) {
		utils.SetSecurityHeaders(c)
		c.Next()
	})

	// CORS configuration
	corsConfig := cors.Config{
		AllowOrigins:     cfg.CORS.AllowedOrigins,
		AllowMethods:     cfg.CORS.AllowedMethods,
		AllowHeaders:     cfg.CORS.AllowedHeaders,
		ExposeHeaders:    cfg.CORS.ExposeHeaders,
		AllowCredentials: cfg.CORS.AllowCredentials,
		MaxAge:           time.Duration(cfg.CORS.MaxAge) * time.Second,
	}
	
	// Default CORS config if not specified
	if len(corsConfig.AllowOrigins) == 0 {
		corsConfig.AllowOrigins = []string{"*"}
	}
	if len(corsConfig.AllowMethods) == 0 {
		corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	}
	if len(corsConfig.AllowHeaders) == 0 {
		corsConfig.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization", "X-Request-ID", "X-Organization-Slug"}
	}

	router.Use(cors.New(corsConfig))

	// Rate limiting middleware
	if cfg.RateLimit.Enabled {
		router.Use(middleware.NewRateLimitMiddleware(cfg).RateLimit())
	}

	// Health endpoints (no auth required)
	router.GET("/health", handlers.HealthHandler.Health)
	router.GET("/ready", handlers.HealthHandler.Readiness)
	router.GET("/live", handlers.HealthHandler.Liveness)

	// API documentation
	router.Static("/docs", "./docs")
	router.GET("/", func(c *gin.Context) {
		utils.JSONResponse(c, http.StatusOK, gin.H{
			"name":        cfg.App.Name,
			"version":     "1.0.1",
			"environment": cfg.App.Env,
			"status":      "running",
			"timestamp":   time.Now(),
			"docs":        "/docs",
		})
	})

	// API routes
	api := router.Group("/api")
	
	// Public authentication routes
	auth := api.Group("/auth")
	{
		auth.GET("/providers", handlers.AuthHandler.GetProviders)
		auth.GET("/:provider/login", handlers.AuthHandler.InitiateOAuth)
		auth.POST("/refresh", handlers.AuthHandler.RefreshToken)
		auth.POST("/logout", middlewares.JWTMiddleware.AuthOptional(), handlers.AuthHandler.Logout)
	}
	
	// OAuth callback routes (both paths for compatibility)
	api.GET("/oauth/callback/:provider", handlers.AuthHandler.HandleOAuthCallback)
	auth.GET("/:provider/callback", handlers.AuthHandler.HandleOAuthCallback)

	// Protected routes
	protected := api.Group("/")
	protected.Use(middlewares.JWTMiddleware.AuthRequired())
	protected.Use(middlewares.TenantMiddleware.ResolveTenant())
	protected.Use(middlewares.TenantMiddleware.ValidateTenantAccess())
	protected.Use(middlewares.TenantMiddleware.EnforceTenantIsolation())
	{
		// Chat endpoints
		chat := protected.Group("/chat")
		{
			chat.POST("/", handlers.ChatHandler.SendMessage)
			chat.GET("/conversations", handlers.ChatHandler.ListConversations)
			chat.GET("/conversations/:conversation_id", handlers.ChatHandler.GetConversation)
			chat.GET("/conversations/:conversation_id/history", handlers.ChatHandler.GetConversationHistory)
			chat.GET("/conversations/:conversation_id/summary", handlers.ChatHandler.GetConversationSummary)
			chat.DELETE("/conversations/:conversation_id", handlers.ChatHandler.DeleteConversation)
			chat.POST("/conversations/:conversation_id/clear", handlers.ChatHandler.ClearConversation)
		}

		// User profile endpoints
		profile := protected.Group("/profile")
		{
			profile.GET("/", handlers.AuthHandler.GetProfile)
		}

		// Admin endpoints (admin role required)
		admin := protected.Group("/admin")
		admin.Use(middlewares.JWTMiddleware.RequireRole("admin"))
		{
			admin.GET("/system/info", handlers.AdminHandler.GetSystemInfo)
			admin.GET("/users", handlers.AdminHandler.GetUsers)
			admin.GET("/organizations", handlers.AdminHandler.GetOrganizations)
			admin.GET("/conversations", handlers.AdminHandler.GetConversations)
			admin.GET("/contexts/stats", handlers.AdminHandler.GetContextStats)
			admin.POST("/contexts/clear", handlers.AdminHandler.ClearContexts)
		}
	}

	return router
}