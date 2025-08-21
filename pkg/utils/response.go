package utils

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// APIResponse represents a standard API response structure
type APIResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     interface{} `json:"error,omitempty"`
	Meta      interface{} `json:"meta,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// ErrorDetail represents detailed error information
type ErrorDetail struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Field   string      `json:"field,omitempty"`
	Value   interface{} `json:"value,omitempty"`
}

// PaginationMeta represents pagination metadata
type PaginationMeta struct {
	Page        int  `json:"page"`
	Limit       int  `json:"limit"`
	Total       int  `json:"total"`
	TotalPages  int  `json:"total_pages"`
	HasNext     bool `json:"has_next"`
	HasPrevious bool `json:"has_previous"`
}

// Success sends a successful JSON response
func Success(c *gin.Context, statusCode int, message string, data interface{}) {
	response := APIResponse{
		Success:   true,
		Message:   message,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	c.JSON(statusCode, response)
}

// SuccessWithMeta sends a successful JSON response with metadata
func SuccessWithMeta(c *gin.Context, statusCode int, message string, data interface{}, meta interface{}) {
	response := APIResponse{
		Success:   true,
		Message:   message,
		Data:      data,
		Meta:      meta,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	c.JSON(statusCode, response)
}

// Error sends an error JSON response
func Error(c *gin.Context, statusCode int, message string, err interface{}) {
	response := APIResponse{
		Success:   false,
		Message:   message,
		Error:     err,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	c.JSON(statusCode, response)
}

// ErrorWithCode sends an error JSON response with error code
func ErrorWithCode(c *gin.Context, statusCode int, code, message string) {
	errorDetail := ErrorDetail{
		Code:    code,
		Message: message,
	}

	response := APIResponse{
		Success:   false,
		Message:   message,
		Error:     errorDetail,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	c.JSON(statusCode, response)
}

// ValidationError sends a validation error response
func ValidationError(c *gin.Context, errors []ErrorDetail) {
	response := APIResponse{
		Success:   false,
		Message:   "Validation failed",
		Error:     errors,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	c.JSON(http.StatusBadRequest, response)
}

// InternalServerError sends a 500 internal server error response
func InternalServerError(c *gin.Context, message string) {
	Error(c, http.StatusInternalServerError, message, nil)
}

// BadRequest sends a 400 bad request response
func BadRequest(c *gin.Context, message string) {
	Error(c, http.StatusBadRequest, message, nil)
}

// Unauthorized sends a 401 unauthorized response
func Unauthorized(c *gin.Context, message string) {
	Error(c, http.StatusUnauthorized, message, nil)
}

// Forbidden sends a 403 forbidden response
func Forbidden(c *gin.Context, message string) {
	Error(c, http.StatusForbidden, message, nil)
}

// NotFound sends a 404 not found response
func NotFound(c *gin.Context, message string) {
	Error(c, http.StatusNotFound, message, nil)
}

// Conflict sends a 409 conflict response
func Conflict(c *gin.Context, message string) {
	Error(c, http.StatusConflict, message, nil)
}

// TooManyRequests sends a 429 too many requests response
func TooManyRequests(c *gin.Context, message string) {
	Error(c, http.StatusTooManyRequests, message, nil)
}

// Created sends a 201 created response
func Created(c *gin.Context, message string, data interface{}) {
	Success(c, http.StatusCreated, message, data)
}

// NoContent sends a 204 no content response
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// OK sends a 200 OK response with data
func OK(c *gin.Context, data interface{}) {
	Success(c, http.StatusOK, "Success", data)
}

// OKWithMessage sends a 200 OK response with custom message
func OKWithMessage(c *gin.Context, message string, data interface{}) {
	Success(c, http.StatusOK, message, data)
}

// Paginated sends a paginated response
func Paginated(c *gin.Context, data interface{}, page, limit, total int) {
	totalPages := (total + limit - 1) / limit
	
	meta := PaginationMeta{
		Page:        page,
		Limit:       limit,
		Total:       total,
		TotalPages:  totalPages,
		HasNext:     page < totalPages,
		HasPrevious: page > 1,
	}

	SuccessWithMeta(c, http.StatusOK, "Success", data, meta)
}

// HealthCheck sends a health check response
func HealthCheck(c *gin.Context, status string, services map[string]interface{}) {
	response := map[string]interface{}{
		"status":    status,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"services":  services,
	}

	statusCode := http.StatusOK
	if status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, response)
}

// StreamingResponse sets up headers for streaming response
func StreamingResponse(c *gin.Context, contentType string) {
	c.Header("Content-Type", contentType)
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Headers", "Cache-Control")
}

// JSONStream writes JSON data to streaming response
func JSONStream(c *gin.Context, data interface{}) error {
	c.SSEvent("data", data)
	c.Writer.Flush()
	return nil
}

// CustomResponse sends a custom response structure
func CustomResponse(c *gin.Context, statusCode int, response interface{}) {
	c.JSON(statusCode, response)
}

// RedirectTemporary sends a 302 temporary redirect
func RedirectTemporary(c *gin.Context, url string) {
	c.Redirect(http.StatusFound, url)
}

// RedirectPermanent sends a 301 permanent redirect
func RedirectPermanent(c *gin.Context, url string) {
	c.Redirect(http.StatusMovedPermanently, url)
}

// File sends a file response
func File(c *gin.Context, filepath string) {
	c.File(filepath)
}

// Attachment sends a file as attachment
func Attachment(c *gin.Context, filepath, filename string) {
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.File(filepath)
}

// JSON sends a JSON response with custom status code
func JSON(c *gin.Context, statusCode int, data interface{}) {
	c.JSON(statusCode, data)
}

// XML sends an XML response
func XML(c *gin.Context, statusCode int, data interface{}) {
	c.XML(statusCode, data)
}

// HTML sends an HTML response
func HTML(c *gin.Context, statusCode int, name string, data interface{}) {
	c.HTML(statusCode, name, data)
}

// String sends a plain text response
func String(c *gin.Context, statusCode int, format string, values ...interface{}) {
	c.String(statusCode, format, values...)
}

// Data sends raw data response
func Data(c *gin.Context, statusCode int, contentType string, data []byte) {
	c.Data(statusCode, contentType, data)
}

// ErrorFromGinError converts gin.Error to APIResponse
func ErrorFromGinError(c *gin.Context, statusCode int, ginErr error) {
	Error(c, statusCode, ginErr.Error(), nil)
}

// MultiError sends multiple errors response
func MultiError(c *gin.Context, statusCode int, message string, errors []error) {
	errorStrings := make([]string, len(errors))
	for i, err := range errors {
		errorStrings[i] = err.Error()
	}

	Error(c, statusCode, message, errorStrings)
}

// SetSecurityHeaders sets common security headers
func SetSecurityHeaders(c *gin.Context) {
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.Header("X-XSS-Protection", "1; mode=block")
	c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
	c.Header("Content-Security-Policy", "default-src 'self'")
}

// SetCacheHeaders sets cache control headers
func SetCacheHeaders(c *gin.Context, maxAge int) {
	if maxAge > 0 {
		c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	} else {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
	}
}

// Additional response helpers for specific use cases

// ErrorResponse represents a structured error response
type ErrorResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message"`
	Error     interface{} `json:"error,omitempty"`
	Code      string      `json:"code,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// SuccessResponse represents a structured success response  
type SuccessResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// JSONResponse sends a structured JSON response
func JSONResponse(c *gin.Context, statusCode int, data interface{}) {
	c.JSON(statusCode, data)
}

// SendErrorResponse sends a structured error response
func SendErrorResponse(c *gin.Context, statusCode int, message string, err error) {
	errorData := &ErrorResponse{
		Success:   false,
		Message:   message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	
	if err != nil {
		errorData.Error = err.Error()
	}
	
	c.JSON(statusCode, errorData)
}

// SendSuccessResponse sends a structured success response
func SendSuccessResponse(c *gin.Context, data interface{}) {
	response := &SuccessResponse{
		Success:   true,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	
	c.JSON(http.StatusOK, response)
}

