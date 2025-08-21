package middleware

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/workoflow/ai-orchestrator-api/internal/config"
)

// RequestLogger creates a logging middleware for HTTP requests
func RequestLogger(logger *logrus.Logger) gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		fields := logrus.Fields{
			"timestamp":    param.TimeStamp.Format(time.RFC3339),
			"method":       param.Method,
			"path":         param.Path,
			"status":       param.StatusCode,
			"latency":      param.Latency,
			"client_ip":    param.ClientIP,
			"user_agent":   param.Request.UserAgent(),
			"request_id":   param.Keys["request_id"],
		}

		// Add user info if available
		if userID, exists := param.Keys["user_id"]; exists {
			fields["user_id"] = userID
		}

		if orgID, exists := param.Keys["organization_id"]; exists {
			fields["organization_id"] = orgID
		}

		// Log level based on status code
		switch {
		case param.StatusCode >= 500:
			logger.WithFields(fields).Error("HTTP Request")
		case param.StatusCode >= 400:
			logger.WithFields(fields).Warn("HTTP Request")
		default:
			logger.WithFields(fields).Info("HTTP Request")
		}

		return ""
	})
}

// StructuredLogger creates a structured logging middleware
func StructuredLogger(logger *logrus.Logger, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		startTime := time.Now()

		// Generate request ID
		requestID := generateRequestID()
		c.Set("request_id", requestID)

		// Log request
		if cfg.Log.Level == "debug" {
			logRequest(logger, c, requestID)
		}

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(startTime)

		// Log response
		logResponse(logger, c, requestID, latency)
	}
}

// DetailedLogger logs detailed request and response information
func DetailedLogger(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		requestID := generateRequestID()
		c.Set("request_id", requestID)

		// Log request details
		fields := logrus.Fields{
			"request_id":  requestID,
			"method":      c.Request.Method,
			"url":         c.Request.URL.String(),
			"headers":     sanitizeHeaders(c.Request.Header),
			"client_ip":   c.ClientIP(),
			"user_agent":  c.Request.UserAgent(),
		}

		// Add user context if available
		if userID, exists := c.Get("user_id"); exists {
			fields["user_id"] = userID
		}

		if orgID, exists := c.Get("organization_id"); exists {
			fields["organization_id"] = orgID
		}

		// Log request body for certain methods (be careful with sensitive data)
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			if body, err := captureRequestBody(c); err == nil {
				fields["request_body"] = sanitizeBody(body)
			}
		}

		logger.WithFields(fields).Info("Request started")

		// Capture response
		responseWriter := &responseCapture{ResponseWriter: c.Writer, body: &bytes.Buffer{}}
		c.Writer = responseWriter

		c.Next()

		// Log response details
		latency := time.Since(startTime)
		responseFields := logrus.Fields{
			"request_id":     requestID,
			"status":         responseWriter.Status(),
			"latency":        latency,
			"response_size":  responseWriter.Size(),
			"response_body":  sanitizeBody(responseWriter.body.String()),
		}

		// Add error information if present
		if len(c.Errors) > 0 {
			responseFields["errors"] = c.Errors.String()
		}

		// Log level based on status and latency
		switch {
		case responseWriter.Status() >= 500:
			logger.WithFields(responseFields).Error("Request completed with server error")
		case responseWriter.Status() >= 400:
			logger.WithFields(responseFields).Warn("Request completed with client error")
		case latency > 5*time.Second:
			logger.WithFields(responseFields).Warn("Request completed slowly")
		default:
			logger.WithFields(responseFields).Info("Request completed")
		}
	}
}

// ErrorLogger logs detailed error information
func ErrorLogger(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Log errors if any occurred
		if len(c.Errors) > 0 {
			requestID, _ := c.Get("request_id")
			userID, _ := c.Get("user_id")
			orgID, _ := c.Get("organization_id")

			for _, err := range c.Errors {
				fields := logrus.Fields{
					"request_id":      requestID,
					"method":          c.Request.Method,
					"path":            c.Request.URL.Path,
					"error":           err.Error(),
					"error_type":      err.Type,
					"client_ip":       c.ClientIP(),
					"user_agent":      c.Request.UserAgent(),
				}

				if userID != nil {
					fields["user_id"] = userID
				}

				if orgID != nil {
					fields["organization_id"] = orgID
				}

				switch err.Type {
				case gin.ErrorTypePublic:
					logger.WithFields(fields).Warn("Public error occurred")
				case gin.ErrorTypeBind:
					logger.WithFields(fields).Warn("Binding error occurred")
				case gin.ErrorTypeRender:
					logger.WithFields(fields).Error("Render error occurred")
				default:
					logger.WithFields(fields).Error("Error occurred")
				}
			}
		}
	}
}

// responseCapture captures response data for logging
type responseCapture struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (r *responseCapture) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// logRequest logs incoming request details
func logRequest(logger *logrus.Logger, c *gin.Context, requestID string) {
	fields := logrus.Fields{
		"request_id": requestID,
		"method":     c.Request.Method,
		"url":        c.Request.URL.String(),
		"headers":    sanitizeHeaders(c.Request.Header),
		"client_ip":  c.ClientIP(),
		"user_agent": c.Request.UserAgent(),
	}

	logger.WithFields(fields).Debug("Incoming request")
}

// logResponse logs response details
func logResponse(logger *logrus.Logger, c *gin.Context, requestID string, latency time.Duration) {
	fields := logrus.Fields{
		"request_id": requestID,
		"method":     c.Request.Method,
		"path":       c.Request.URL.Path,
		"status":     c.Writer.Status(),
		"latency":    latency,
		"size":       c.Writer.Size(),
	}

	// Add user context
	if userID, exists := c.Get("user_id"); exists {
		fields["user_id"] = userID
	}

	if orgID, exists := c.Get("organization_id"); exists {
		fields["organization_id"] = orgID
	}

	// Add error count
	if len(c.Errors) > 0 {
		fields["error_count"] = len(c.Errors)
	}

	logger.WithFields(fields).Info("Request completed")
}

// captureRequestBody captures request body while preserving it for the handler
func captureRequestBody(c *gin.Context) (string, error) {
	if c.Request.Body == nil {
		return "", nil
	}

	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return "", err
	}

	// Restore the body for the handler
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	return string(bodyBytes), nil
}

// sanitizeHeaders removes sensitive headers from logging
func sanitizeHeaders(headers map[string][]string) map[string][]string {
	sanitized := make(map[string][]string)
	sensitiveHeaders := map[string]bool{
		"authorization": true,
		"cookie":        true,
		"x-api-key":     true,
		"x-auth-token":  true,
	}

	for key, values := range headers {
		lowerKey := fmt.Sprintf("%s", key)
		if sensitiveHeaders[lowerKey] {
			sanitized[key] = []string{"[REDACTED]"}
		} else {
			sanitized[key] = values
		}
	}

	return sanitized
}

// sanitizeBody removes or masks sensitive data from request/response bodies
func sanitizeBody(body string) string {
	if len(body) == 0 {
		return body
	}

	// Limit body size in logs
	if len(body) > 1000 {
		return body[:1000] + "... [TRUNCATED]"
	}

	// TODO: Add logic to mask sensitive fields like passwords, tokens, etc.
	// For now, just return the body as-is for non-sensitive endpoints
	return body
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// SecurityLogger logs security-related events
func SecurityLogger(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Log security events
		if c.Writer.Status() == 401 {
			fields := logrus.Fields{
				"event":         "unauthorized_access",
				"method":        c.Request.Method,
				"path":          c.Request.URL.Path,
				"client_ip":     c.ClientIP(),
				"user_agent":    c.Request.UserAgent(),
				"auth_header":   c.GetHeader("Authorization") != "",
				"api_key":       c.GetHeader("X-API-Key") != "",
			}

			logger.WithFields(fields).Warn("Unauthorized access attempt")
		}

		if c.Writer.Status() == 403 {
			fields := logrus.Fields{
				"event":           "forbidden_access",
				"method":          c.Request.Method,
				"path":            c.Request.URL.Path,
				"client_ip":       c.ClientIP(),
				"user_agent":      c.Request.UserAgent(),
			}

			if userID, exists := c.Get("user_id"); exists {
				fields["user_id"] = userID
			}

			logger.WithFields(fields).Warn("Forbidden access attempt")
		}

		if c.Writer.Status() == 429 {
			fields := logrus.Fields{
				"event":       "rate_limit_exceeded",
				"method":      c.Request.Method,
				"path":        c.Request.URL.Path,
				"client_ip":   c.ClientIP(),
				"user_agent":  c.Request.UserAgent(),
			}

			if userID, exists := c.Get("user_id"); exists {
				fields["user_id"] = userID
			}

			logger.WithFields(fields).Warn("Rate limit exceeded")
		}
	}
}