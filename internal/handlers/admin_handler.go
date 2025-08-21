package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/workoflow/ai-orchestrator-api/internal/ai"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
	"github.com/workoflow/ai-orchestrator-api/pkg/utils"
)

type AdminHandler struct {
	db             *gorm.DB
	aiService      *services.AIService
	contextManager *ai.ContextManager
	tenantService  *services.TenantService
}

type AdminStats struct {
	TotalUsers         int64                  `json:"total_users"`
	TotalOrganizations int64                  `json:"total_organizations"`
	TotalConversations int64                  `json:"total_conversations"`
	TotalWebhooks      int64                  `json:"total_webhooks"`
	ActiveSessions     int                    `json:"active_sessions"`
	ContextStats       map[string]interface{} `json:"context_stats"`
}

type SystemInfo struct {
	Version     string                 `json:"version"`
	Environment string                 `json:"environment"`
	Uptime      string                 `json:"uptime"`
	Stats       AdminStats             `json:"stats"`
	Config      map[string]interface{} `json:"config"`
}

func NewAdminHandler(db *gorm.DB, aiService *services.AIService, contextManager *ai.ContextManager, tenantService *services.TenantService) *AdminHandler {
	return &AdminHandler{
		db:             db,
		aiService:      aiService,
		contextManager: contextManager,
		tenantService:  tenantService,
	}
}

// GetSystemInfo godoc
// @Summary Get system information and statistics
// @Description Get comprehensive system information including statistics
// @Tags admin
// @Accept json
// @Produce json
// @Success 200 {object} SystemInfo
// @Failure 401 {object} utils.SendErrorResponse
// @Failure 403 {object} utils.SendErrorResponse
// @Failure 500 {object} utils.SendErrorResponse
// @Security BearerAuth
// @Router /admin/system/info [get]
func (h *AdminHandler) GetSystemInfo(c *gin.Context) {
	stats, err := h.getSystemStats()
	if err != nil {
		utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to get system stats", err)
		return
	}

	systemInfo := SystemInfo{
		Version:     "1.0.0",
		Environment: "development", // Should come from config
		Uptime:      "N/A",         // Would need to track startup time
		Stats:       *stats,
		Config: map[string]interface{}{
			"database_configured": h.db != nil,
			"ai_service_enabled":  h.aiService != nil,
			"context_manager_enabled": h.contextManager != nil,
		},
	}

	utils.JSONResponse(c, http.StatusOK, systemInfo)
}

// GetUsers godoc
// @Summary List all users (admin only)
// @Description Get a paginated list of all users in the system
// @Tags admin
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {array} models.User
// @Failure 401 {object} utils.SendErrorResponse
// @Failure 403 {object} utils.SendErrorResponse
// @Failure 500 {object} utils.SendErrorResponse
// @Security BearerAuth
// @Router /admin/users [get]
func (h *AdminHandler) GetUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	var users []models.User
	var total int64

	// Count total users
	err := h.db.Model(&models.User{}).Count(&total).Error
	if err != nil {
		utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to count users", err)
		return
	}

	// Get paginated users
	err = h.db.Preload("Organization").
		Offset(offset).
		Limit(limit).
		Order("created_at DESC").
		Find(&users).Error
	
	if err != nil {
		utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to fetch users", err)
		return
	}

	// Clean sensitive data
	for i := range users {
		users[i].PasswordHash = ""
	}

	utils.JSONResponse(c, http.StatusOK, gin.H{
		"users":       users,
		"total":       total,
		"page":        page,
		"limit":       limit,
		"total_pages": (total + int64(limit) - 1) / int64(limit),
	})
}

// GetOrganizations godoc
// @Summary List all organizations (admin only)
// @Description Get a paginated list of all organizations in the system
// @Tags admin
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {array} models.Organization
// @Failure 401 {object} utils.SendErrorResponse
// @Failure 403 {object} utils.SendErrorResponse
// @Failure 500 {object} utils.SendErrorResponse
// @Security BearerAuth
// @Router /admin/organizations [get]
func (h *AdminHandler) GetOrganizations(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	var orgs []models.Organization
	var total int64

	// Count total organizations
	err := h.db.Model(&models.Organization{}).Count(&total).Error
	if err != nil {
		utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to count organizations", err)
		return
	}

	// Get paginated organizations
	err = h.db.Offset(offset).
		Limit(limit).
		Order("created_at DESC").
		Find(&orgs).Error
	
	if err != nil {
		utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to fetch organizations", err)
		return
	}

	utils.JSONResponse(c, http.StatusOK, gin.H{
		"organizations": orgs,
		"total":        total,
		"page":         page,
		"limit":        limit,
		"total_pages":  (total + int64(limit) - 1) / int64(limit),
	})
}

// GetConversations godoc
// @Summary List all conversations (admin only)
// @Description Get a paginated list of all conversations in the system
// @Tags admin
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {array} models.Conversation
// @Failure 401 {object} utils.SendErrorResponse
// @Failure 403 {object} utils.SendErrorResponse
// @Failure 500 {object} utils.SendErrorResponse
// @Security BearerAuth
// @Router /admin/conversations [get]
func (h *AdminHandler) GetConversations(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	var conversations []models.Conversation
	var total int64

	// Count total conversations
	err := h.db.Model(&models.Conversation{}).Count(&total).Error
	if err != nil {
		utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to count conversations", err)
		return
	}

	// Get paginated conversations
	err = h.db.Preload("User").
		Offset(offset).
		Limit(limit).
		Order("updated_at DESC").
		Find(&conversations).Error
	
	if err != nil {
		utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to fetch conversations", err)
		return
	}

	utils.JSONResponse(c, http.StatusOK, gin.H{
		"conversations": conversations,
		"total":        total,
		"page":         page,
		"limit":        limit,
		"total_pages":  (total + int64(limit) - 1) / int64(limit),
	})
}

// ClearContexts godoc
// @Summary Clear all conversation contexts (admin only)
// @Description Clear all conversation contexts from memory - use with caution
// @Tags admin
// @Accept json
// @Produce json
// @Success 200 {object} utils.SuccessResponse
// @Failure 401 {object} utils.SendErrorResponse
// @Failure 403 {object} utils.SendErrorResponse
// @Failure 500 {object} utils.SendErrorResponse
// @Security BearerAuth
// @Router /admin/contexts/clear [post]
func (h *AdminHandler) ClearContexts(c *gin.Context) {
	// This is a dangerous operation, so we should require explicit confirmation
	confirm := c.Query("confirm")
	if confirm != "true" {
		utils.SendErrorResponse(c, http.StatusBadRequest, "This operation requires confirmation", nil)
		return
	}

	// Get all conversation IDs and clear them
	var conversations []models.Conversation
	err := h.db.Select("id").Find(&conversations).Error
	if err != nil {
		utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to get conversations", err)
		return
	}

	cleared := 0
	for _, conv := range conversations {
		err := h.contextManager.DeleteContext(fmt.Sprintf("%d", conv.ID))
		if err == nil {
			cleared++
		}
	}

	utils.SendSuccessResponse(c, gin.H{
		"message":           "Contexts cleared",
		"contexts_cleared":  cleared,
		"total_conversations": len(conversations),
	})
}

// GetContextStats godoc
// @Summary Get context manager statistics
// @Description Get detailed statistics about the context manager
// @Tags admin
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} utils.SendErrorResponse
// @Failure 403 {object} utils.SendErrorResponse
// @Security BearerAuth
// @Router /admin/contexts/stats [get]
func (h *AdminHandler) GetContextStats(c *gin.Context) {
	if h.contextManager == nil {
		utils.SendErrorResponse(c, http.StatusServiceUnavailable, "Context manager not available", nil)
		return
	}

	stats := h.contextManager.GetContextStats()
	utils.JSONResponse(c, http.StatusOK, stats)
}

func (h *AdminHandler) getSystemStats() (*AdminStats, error) {
	stats := &AdminStats{}

	// Count users
	err := h.db.Model(&models.User{}).Count(&stats.TotalUsers).Error
	if err != nil {
		return nil, err
	}

	// Count organizations
	err = h.db.Model(&models.Organization{}).Count(&stats.TotalOrganizations).Error
	if err != nil {
		return nil, err
	}

	// Count conversations
	err = h.db.Model(&models.Conversation{}).Count(&stats.TotalConversations).Error
	if err != nil {
		return nil, err
	}

	// Count webhooks
	err = h.db.Model(&models.N8NWebhook{}).Count(&stats.TotalWebhooks).Error
	if err != nil {
		return nil, err
	}

	// Get active sessions (simplified - would need session tracking)
	stats.ActiveSessions = 0

	// Get context stats if available
	if h.contextManager != nil {
		stats.ContextStats = h.contextManager.GetContextStats()
	}

	return stats, nil
}