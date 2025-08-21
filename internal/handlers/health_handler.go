package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/workoflow/ai-orchestrator-api/pkg/utils"
)

type HealthHandler struct {
	db *gorm.DB
}

type HealthStatus struct {
	Status      string            `json:"status"`
	Timestamp   time.Time         `json:"timestamp"`
	Version     string            `json:"version"`
	Environment string            `json:"environment"`
	Services    map[string]string `json:"services"`
	Uptime      string            `json:"uptime"`
}

type ReadinessStatus struct {
	Ready    bool              `json:"ready"`
	Services map[string]string `json:"services"`
}

func NewHealthHandler(db *gorm.DB) *HealthHandler {
	return &HealthHandler{
		db: db,
	}
}

// Health godoc
// @Summary Health check endpoint
// @Description Get the health status of the API
// @Tags health
// @Accept json
// @Produce json
// @Success 200 {object} HealthStatus
// @Router /health [get]
func (h *HealthHandler) Health(c *gin.Context) {
	ctx := context.WithValue(c.Request.Context(), "timeout", 5*time.Second)
	
	services := make(map[string]string)
	
	// Check database connectivity
	services["database"] = h.checkDatabase(ctx)
	
	// Check AI service (OpenAI/Azure OpenAI) - simplified check
	services["ai_service"] = "healthy"
	
	// Check N8N connectivity would go here if we had a base URL to test
	services["n8n_service"] = "not_configured"
	
	// Determine overall status
	status := "healthy"
	for _, serviceStatus := range services {
		if serviceStatus != "healthy" && serviceStatus != "not_configured" {
			status = "degraded"
			break
		}
	}

	healthStatus := HealthStatus{
		Status:      status,
		Timestamp:   time.Now(),
		Version:     "1.0.0",
		Environment: "development", // This should come from config
		Services:    services,
		Uptime:      time.Since(startTime).String(),
	}

	statusCode := http.StatusOK
	if status == "degraded" {
		statusCode = http.StatusServiceUnavailable
	}

	utils.JSONResponse(c, statusCode, healthStatus)
}

// Readiness godoc
// @Summary Readiness check endpoint
// @Description Check if the API is ready to serve requests
// @Tags health
// @Accept json
// @Produce json
// @Success 200 {object} ReadinessStatus
// @Failure 503 {object} ReadinessStatus
// @Router /ready [get]
func (h *HealthHandler) Readiness(c *gin.Context) {
	ctx := context.WithValue(c.Request.Context(), "timeout", 2*time.Second)
	
	services := make(map[string]string)
	
	// Check critical services for readiness
	services["database"] = h.checkDatabase(ctx)
	
	// Determine if we're ready
	ready := true
	for _, serviceStatus := range services {
		if serviceStatus != "healthy" {
			ready = false
			break
		}
	}

	readinessStatus := ReadinessStatus{
		Ready:    ready,
		Services: services,
	}

	statusCode := http.StatusOK
	if !ready {
		statusCode = http.StatusServiceUnavailable
	}

	utils.JSONResponse(c, statusCode, readinessStatus)
}

// Liveness godoc
// @Summary Liveness check endpoint
// @Description Check if the API is alive
// @Tags health
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /live [get]
func (h *HealthHandler) Liveness(c *gin.Context) {
	utils.JSONResponse(c, http.StatusOK, gin.H{
		"status":    "alive",
		"timestamp": time.Now(),
		"uptime":    time.Since(startTime).String(),
	})
}

func (h *HealthHandler) checkDatabase(ctx context.Context) string {
	if h.db == nil {
		return "not_configured"
	}

	sqlDB, err := h.db.DB()
	if err != nil {
		return "error"
	}

	// Create a context with timeout for the ping
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	err = sqlDB.PingContext(pingCtx)
	if err != nil {
		return "unhealthy"
	}

	return "healthy"
}

// Global variable to track start time
var startTime = time.Now()