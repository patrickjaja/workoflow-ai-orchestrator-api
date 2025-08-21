package utils

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var (
	logger *logrus.Logger
)

// LogConfig represents logger configuration
type LogConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"` // json or text
	Output string `json:"output"` // stdout, stderr, or file path
}

// LogFields represents structured log fields
type LogFields map[string]interface{}

// Logger interface for abstraction
type Logger interface {
	Debug(msg string, fields ...LogFields)
	Info(msg string, fields ...LogFields)
	Warn(msg string, fields ...LogFields)
	Error(msg string, err error, fields ...LogFields)
	Fatal(msg string, err error, fields ...LogFields)
	WithFields(fields LogFields) Logger
	WithContext(ctx context.Context) Logger
}

// AppLogger implements Logger interface using logrus
type AppLogger struct {
	entry *logrus.Entry
}

// InitLogger initializes the global logger
func InitLogger(config *LogConfig) error {
	logger = logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
		logger.Warnf("Invalid log level '%s', defaulting to info", config.Level)
	}
	logger.SetLevel(level)

	// Set formatter
	switch strings.ToLower(config.Format) {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "caller",
			},
		})
	case "text", "":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
			ForceColors:     false,
		})
	default:
		return fmt.Errorf("unsupported log format: %s", config.Format)
	}

	// Set output
	switch strings.ToLower(config.Output) {
	case "stdout", "":
		logger.SetOutput(os.Stdout)
	case "stderr":
		logger.SetOutput(os.Stderr)
	default:
		// Assume it's a file path
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		logger.SetOutput(file)
	}

	// Enable caller reporting
	logger.SetReportCaller(true)

	return nil
}

// GetLogger returns a new AppLogger instance
func GetLogger() Logger {
	if logger == nil {
		// Fallback to standard logger
		log.Println("Warning: Logger not initialized, using fallback")
		InitLogger(&LogConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		})
	}

	return &AppLogger{
		entry: logger.WithFields(logrus.Fields{}),
	}
}

// GetLoggerWithFields returns a logger with predefined fields
func GetLoggerWithFields(fields LogFields) Logger {
	return GetLogger().WithFields(fields)
}

// Debug logs a debug message
func (l *AppLogger) Debug(msg string, fields ...LogFields) {
	entry := l.entry
	if len(fields) > 0 {
		entry = entry.WithFields(logrus.Fields(fields[0]))
	}
	entry.Debug(msg)
}

// Info logs an info message
func (l *AppLogger) Info(msg string, fields ...LogFields) {
	entry := l.entry
	if len(fields) > 0 {
		entry = entry.WithFields(logrus.Fields(fields[0]))
	}
	entry.Info(msg)
}

// Warn logs a warning message
func (l *AppLogger) Warn(msg string, fields ...LogFields) {
	entry := l.entry
	if len(fields) > 0 {
		entry = entry.WithFields(logrus.Fields(fields[0]))
	}
	entry.Warn(msg)
}

// Error logs an error message
func (l *AppLogger) Error(msg string, err error, fields ...LogFields) {
	entry := l.entry
	if err != nil {
		entry = entry.WithError(err)
	}
	if len(fields) > 0 {
		entry = entry.WithFields(logrus.Fields(fields[0]))
	}
	entry.Error(msg)
}

// Fatal logs a fatal message and exits
func (l *AppLogger) Fatal(msg string, err error, fields ...LogFields) {
	entry := l.entry
	if err != nil {
		entry = entry.WithError(err)
	}
	if len(fields) > 0 {
		entry = entry.WithFields(logrus.Fields(fields[0]))
	}
	entry.Fatal(msg)
}

// WithFields returns a logger with additional fields
func (l *AppLogger) WithFields(fields LogFields) Logger {
	return &AppLogger{
		entry: l.entry.WithFields(logrus.Fields(fields)),
	}
}

// WithContext returns a logger with context information
func (l *AppLogger) WithContext(ctx context.Context) Logger {
	entry := l.entry

	// Add request ID if available
	if requestID := GetRequestID(ctx); requestID != "" {
		entry = entry.WithField("request_id", requestID)
	}

	// Add user ID if available
	if userID := GetUserID(ctx); userID != 0 {
		entry = entry.WithField("user_id", userID)
	}

	// Add organization ID if available
	if orgID := GetOrganizationID(ctx); orgID != 0 {
		entry = entry.WithField("organization_id", orgID)
	}

	// Add trace ID if available
	if traceID := GetTraceID(ctx); traceID != "" {
		entry = entry.WithField("trace_id", traceID)
	}

	return &AppLogger{entry: entry}
}

// LogRequest logs an HTTP request
func LogRequest(c *gin.Context, start time.Time) {
	logger := GetLogger().WithFields(LogFields{
		"method":     c.Request.Method,
		"path":       c.Request.URL.Path,
		"query":      c.Request.URL.RawQuery,
		"ip":         c.ClientIP(),
		"user_agent": c.Request.UserAgent(),
		"status":     c.Writer.Status(),
		"latency":    time.Since(start).String(),
		"size":       c.Writer.Size(),
	})

	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		logger = logger.WithFields(LogFields{"request_id": requestID})
	}

	message := fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path)

	// Log level based on status code
	status := c.Writer.Status()
	if status >= 500 {
		logger.Error(message, nil)
	} else if status >= 400 {
		logger.Warn(message)
	} else {
		logger.Info(message)
	}
}

// LogError logs an error with context
func LogError(ctx context.Context, msg string, err error, fields ...LogFields) {
	logger := GetLogger().WithContext(ctx)
	if len(fields) > 0 {
		logger = logger.WithFields(fields[0])
	}
	logger.Error(msg, err)
}

// LogInfo logs an info message with context
func LogInfo(ctx context.Context, msg string, fields ...LogFields) {
	logger := GetLogger().WithContext(ctx)
	if len(fields) > 0 {
		logger = logger.WithFields(fields[0])
	}
	logger.Info(msg)
}

// LogDebug logs a debug message with context
func LogDebug(ctx context.Context, msg string, fields ...LogFields) {
	logger := GetLogger().WithContext(ctx)
	if len(fields) > 0 {
		logger = logger.WithFields(fields[0])
	}
	logger.Debug(msg)
}

// LogWarn logs a warning message with context
func LogWarn(ctx context.Context, msg string, fields ...LogFields) {
	logger := GetLogger().WithContext(ctx)
	if len(fields) > 0 {
		logger = logger.WithFields(fields[0])
	}
	logger.Warn(msg)
}

// Context helper functions

// GetRequestID extracts request ID from context
func GetRequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if val := ctx.Value("request_id"); val != nil {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// GetUserID extracts user ID from context
func GetUserID(ctx context.Context) uint {
	if ctx == nil {
		return 0
	}
	if val := ctx.Value("user_id"); val != nil {
		if id, ok := val.(uint); ok {
			return id
		}
	}
	return 0
}

// GetOrganizationID extracts organization ID from context
func GetOrganizationID(ctx context.Context) uint {
	if ctx == nil {
		return 0
	}
	if val := ctx.Value("organization_id"); val != nil {
		if id, ok := val.(uint); ok {
			return id
		}
	}
	return 0
}

// GetTraceID extracts trace ID from context
func GetTraceID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if val := ctx.Value("trace_id"); val != nil {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// GetCaller returns information about the calling function
func GetCaller(skip int) (file string, line int, fn string) {
	pc, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return "unknown", 0, "unknown"
	}
	
	function := runtime.FuncForPC(pc)
	if function == nil {
		return file, line, "unknown"
	}
	
	return file, line, function.Name()
}

// Structured logging helpers

// LogSQL logs SQL queries and their execution time
func LogSQL(query string, duration time.Duration, err error, fields ...LogFields) {
	logger := GetLogger()
	logFields := LogFields{
		"query":    query,
		"duration": duration.String(),
	}
	
	if len(fields) > 0 {
		for k, v := range fields[0] {
			logFields[k] = v
		}
	}

	if err != nil {
		logger.WithFields(logFields).Error("SQL query failed", err)
	} else {
		logger.WithFields(logFields).Debug("SQL query executed")
	}
}

// LogHTTPCall logs external HTTP calls
func LogHTTPCall(method, url string, statusCode int, duration time.Duration, err error, fields ...LogFields) {
	logger := GetLogger()
	logFields := LogFields{
		"method":      method,
		"url":         url,
		"status_code": statusCode,
		"duration":    duration.String(),
	}
	
	if len(fields) > 0 {
		for k, v := range fields[0] {
			logFields[k] = v
		}
	}

	message := fmt.Sprintf("HTTP %s %s", method, url)

	if err != nil {
		logger.WithFields(logFields).Error(message, err)
	} else if statusCode >= 400 {
		logger.WithFields(logFields).Warn(message)
	} else {
		logger.WithFields(logFields).Info(message)
	}
}

// LogAICall logs AI service calls
func LogAICall(provider, model string, tokenCount int, duration time.Duration, err error, fields ...LogFields) {
	logger := GetLogger()
	logFields := LogFields{
		"provider":    provider,
		"model":       model,
		"token_count": tokenCount,
		"duration":    duration.String(),
	}
	
	if len(fields) > 0 {
		for k, v := range fields[0] {
			logFields[k] = v
		}
	}

	message := fmt.Sprintf("AI call to %s (%s)", provider, model)

	if err != nil {
		logger.WithFields(logFields).Error(message, err)
	} else {
		logger.WithFields(logFields).Info(message)
	}
}