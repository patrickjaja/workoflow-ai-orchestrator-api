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

	"github.com/workoflow/ai-orchestrator-api/internal/config"
	"github.com/workoflow/ai-orchestrator-api/internal/database"
	"github.com/workoflow/ai-orchestrator-api/internal/handlers"
	"github.com/workoflow/ai-orchestrator-api/internal/middleware"
	"github.com/workoflow/ai-orchestrator-api/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		logrus.Warn("No .env file found, using system environment variables")
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup logger
	logger := logrus.New()
	if cfg.Log.Level == "debug" {
		logger.SetLevel(logrus.DebugLevel)
	}
	if cfg.Log.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{})
	}

	logger.Info("Starting AI Orchestrator API")

	// Initialize database
	db, err := database.Initialize(cfg)
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}

	// Run database migrations
	if err := database.RunMigrations(db); err != nil {
		logger.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize services
	encryptionService := services.NewEncryptionService(cfg.Security.EncryptionKey)
	jwtService := services.NewJWTService(cfg.Security.JWTSecret, cfg.Security.JWTExpiry, cfg.Security.RefreshExpiry)
	tenantService := services.NewTenantService(db)
	tokenManager := services.NewTokenManager(db, encryptionService)
	oauthService := services.NewOAuthService(db, encryptionService, cfg)
	
	aiService, err := services.NewAIService(cfg)
	if err != nil {
		logger.Fatalf("Failed to initialize AI service: %v", err)
	}
	
	n8nClient := services.NewN8NClient(cfg)
	
	chatService := services.NewChatService(db, aiService, n8nClient, tenantService)

	// Setup router
	router := setupRouter(cfg, logger, db, jwtService, chatService, oauthService, tenantService, n8nClient)

	// Create HTTP server
	srv := &http.Server{
		Addr:           fmt.Sprintf(":%d", cfg.App.Port),
		Handler:        router,
		ReadTimeout:    time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:    time.Duration(cfg.Server.IdleTimeout) * time.Second,
		MaxHeaderBytes: cfg.Server.MaxHeaderBytes,
	}

	// Start server in goroutine
	go func() {
		logger.Infof("Server starting on port %d in %s mode", cfg.App.Port, cfg.App.Env)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Handle graceful shutdown
	gracefulShutdown(srv, logger)
}

func setupRouter(
	cfg *config.Config,
	logger *logrus.Logger,
	db *gorm.DB,
	jwtService *services.JWTService,
	chatService *services.ChatService,
	oauthService *services.OAuthService,
	tenantService *services.TenantService,
	n8nClient *services.N8NClient,
) *gin.Engine {
	// Set Gin mode based on environment
	if cfg.App.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Global middleware
	router.Use(middleware.StructuredLogger(logger, cfg))
	router.Use(gin.Recovery())
	router.Use(middleware.CORSMiddleware(cfg))
	
	// Rate limiting middleware
	if cfg.RateLimit.Enabled {
		router.Use(middleware.CustomRateLimitMiddleware(cfg))
	}

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(oauthService, jwtService, tenantService)
	chatHandler := handlers.NewChatHandler(chatService)
	workflowHandler := handlers.NewWorkflowHandler(db, chatService, n8nClient)
	authMiddleware := middleware.NewAuthMiddleware(jwtService)

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   "1.0.0",
		})
	})

	// API routes
	api := router.Group("/api")
	{
		// Authentication routes (public)
		auth := api.Group("/auth")
		{
			auth.POST("/login", authHandler.Login)
			auth.POST("/callback", authHandler.Callback)
			auth.POST("/refresh", authHandler.RefreshToken)
			auth.GET("/providers", authHandler.GetProviders)
			
			// Protected auth routes
			auth.POST("/logout", authMiddleware.RequireAuth(), authHandler.Logout)
			auth.GET("/me", authMiddleware.RequireAuth(), authHandler.Me)
			auth.GET("/validate", authMiddleware.RequireAuth(), authHandler.ValidateToken)
			auth.GET("/organization", authMiddleware.RequireAuth(), authHandler.GetOrganization)
		}

		// Chat routes (protected)
		chat := api.Group("/chat")
		chat.Use(authMiddleware.RequireAuth())
		{
			chat.POST("/messages", chatHandler.SendMessage)
			chat.GET("/conversations", chatHandler.ListConversations)
			chat.GET("/conversations/:conversation_id", chatHandler.GetConversation)
			chat.GET("/conversations/:conversation_id/messages", chatHandler.GetConversationHistory)
			chat.POST("/conversations/:conversation_id/clear", chatHandler.ClearConversation)
			chat.DELETE("/conversations/:conversation_id", chatHandler.DeleteConversation)
			chat.GET("/conversations/:conversation_id/summary", chatHandler.GetConversationSummary)
		}

		// Workflow routes (protected)
		workflows := api.Group("/workflows")
		workflows.Use(authMiddleware.RequireAuth())
		{
			workflows.GET("", workflowHandler.ListWorkflows)
			workflows.POST("", authMiddleware.RequireAnyRole("admin"), workflowHandler.CreateWebhook)
			workflows.GET("/:workflow_id", workflowHandler.GetWorkflow)
			workflows.PUT("/:workflow_id", authMiddleware.RequireAnyRole("admin"), workflowHandler.UpdateWebhook)
			workflows.DELETE("/:workflow_id", authMiddleware.RequireAnyRole("admin"), workflowHandler.DeleteWebhook)
			workflows.POST("/:workflow_id/test", workflowHandler.TestWebhook)
			
			workflows.POST("/execute", workflowHandler.ExecuteWorkflow)
			workflows.GET("/executions/:execution_id", workflowHandler.GetExecutionStatus)
		}
	}

	// Add 404 handler
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "The requested endpoint was not found",
		})
	})

	return router
}

func gracefulShutdown(srv *http.Server, logger *logrus.Logger) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server shutdown complete")