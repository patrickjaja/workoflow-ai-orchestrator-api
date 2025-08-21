package utils

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// ValidateEmail validates email address format
func ValidateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ValidatePassword validates password strength
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	if len(password) > 128 {
		return fmt.Errorf("password must not exceed 128 characters")
	}

	var (
		hasMinLen  = false
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	if len(password) >= 8 {
		hasMinLen = true
	}

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasMinLen {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}

	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// ValidateURL validates URL format
func ValidateURL(url string) bool {
	urlRegex := regexp.MustCompile(`^https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(:[0-9]+)?(/.*)?$`)
	return urlRegex.MatchString(url)
}

// ValidateWebhookPath validates n8n webhook path format
func ValidateWebhookPath(path string) error {
	if path == "" {
		return fmt.Errorf("webhook path cannot be empty")
	}

	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("webhook path must start with /")
	}

	// Check for valid characters (alphanumeric, hyphens, underscores, slashes)
	validPathRegex := regexp.MustCompile(`^[a-zA-Z0-9\-_/]+$`)
	if !validPathRegex.MatchString(path) {
		return fmt.Errorf("webhook path contains invalid characters")
	}

	// Check for double slashes
	if strings.Contains(path, "//") {
		return fmt.Errorf("webhook path cannot contain double slashes")
	}

	return nil
}

// ValidateWorkflowName validates workflow name format
func ValidateWorkflowName(name string) error {
	if name == "" {
		return fmt.Errorf("workflow name cannot be empty")
	}

	if len(name) < 3 {
		return fmt.Errorf("workflow name must be at least 3 characters long")
	}

	if len(name) > 100 {
		return fmt.Errorf("workflow name must not exceed 100 characters")
	}

	// Allow alphanumeric characters, spaces, hyphens, and underscores
	validNameRegex := regexp.MustCompile(`^[a-zA-Z0-9\s\-_]+$`)
	if !validNameRegex.MatchString(name) {
		return fmt.Errorf("workflow name contains invalid characters")
	}

	return nil
}

// ValidateOrganizationDomain validates organization domain format
func ValidateOrganizationDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("organization domain cannot be empty")
	}

	// Basic domain validation
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format")
	}

	if len(domain) > 253 {
		return fmt.Errorf("domain name too long")
	}

	return nil
}

// ValidateJSONString validates if string is valid JSON
func ValidateJSONString(jsonStr string) error {
	if jsonStr == "" {
		return nil // Empty string is considered valid
	}

	// Simple JSON validation - check for balanced braces and brackets
	braceCount := 0
	bracketCount := 0
	inString := false
	escaped := false

	for i, char := range jsonStr {
		if escaped {
			escaped = false
			continue
		}

		if char == '\\' && inString {
			escaped = true
			continue
		}

		if char == '"' {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		switch char {
		case '{':
			braceCount++
		case '}':
			braceCount--
			if braceCount < 0 {
				return fmt.Errorf("unmatched closing brace at position %d", i)
			}
		case '[':
			bracketCount++
		case ']':
			bracketCount--
			if bracketCount < 0 {
				return fmt.Errorf("unmatched closing bracket at position %d", i)
			}
		}
	}

	if braceCount != 0 {
		return fmt.Errorf("unmatched braces in JSON")
	}

	if bracketCount != 0 {
		return fmt.Errorf("unmatched brackets in JSON")
	}

	if inString {
		return fmt.Errorf("unclosed string in JSON")
	}

	return nil
}

// ValidateAPIKey validates API key format
func ValidateAPIKey(apiKey string) error {
	if apiKey == "" {
		return fmt.Errorf("API key cannot be empty")
	}

	if len(apiKey) < 32 {
		return fmt.Errorf("API key must be at least 32 characters long")
	}

	if len(apiKey) > 128 {
		return fmt.Errorf("API key must not exceed 128 characters")
	}

	// API key should contain only alphanumeric characters and specific symbols
	validKeyRegex := regexp.MustCompile(`^[a-zA-Z0-9\-_\.]+$`)
	if !validKeyRegex.MatchString(apiKey) {
		return fmt.Errorf("API key contains invalid characters")
	}

	return nil
}

// ValidateConversationID validates conversation ID format
func ValidateConversationID(id string) error {
	if id == "" {
		return fmt.Errorf("conversation ID cannot be empty")
	}

	// UUID format or alphanumeric with hyphens
	uuidRegex := regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
	alphanumericRegex := regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)

	if !uuidRegex.MatchString(id) && !alphanumericRegex.MatchString(id) {
		return fmt.Errorf("invalid conversation ID format")
	}

	if len(id) > 100 {
		return fmt.Errorf("conversation ID too long")
	}

	return nil
}

// ValidatePaginationParams validates pagination parameters
func ValidatePaginationParams(page, limit int) error {
	if page < 1 {
		return fmt.Errorf("page must be at least 1")
	}

	if limit < 1 {
		return fmt.Errorf("limit must be at least 1")
	}

	if limit > 1000 {
		return fmt.Errorf("limit must not exceed 1000")
	}

	return nil
}

// SanitizeInput sanitizes user input by removing potentially harmful characters
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Trim whitespace
	input = strings.TrimSpace(input)
	
	// Remove control characters except tabs and newlines
	var sanitized strings.Builder
	for _, char := range input {
		if unicode.IsControl(char) && char != '\t' && char != '\n' && char != '\r' {
			continue
		}
		sanitized.WriteRune(char)
	}
	
	return sanitized.String()
}

// ValidateRequestSize validates request body size
func ValidateRequestSize(size int64, maxSize int64) error {
	if size > maxSize {
		return fmt.Errorf("request body too large: %d bytes (max: %d bytes)", size, maxSize)
	}
	return nil
}

// ValidateContentType validates HTTP content type
func ValidateContentType(contentType string, allowedTypes []string) error {
	if contentType == "" {
		return fmt.Errorf("content type is required")
	}

	// Extract main type (remove charset, etc.)
	mainType := strings.Split(contentType, ";")[0]
	mainType = strings.TrimSpace(mainType)

	for _, allowed := range allowedTypes {
		if mainType == allowed {
			return nil
		}
	}

	return fmt.Errorf("unsupported content type: %s", mainType)
}

// ValidateHTTPMethod validates HTTP method
func ValidateHTTPMethod(method string) error {
	allowedMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	
	method = strings.ToUpper(method)
	
	for _, allowed := range allowedMethods {
		if method == allowed {
			return nil
		}
	}
	
	return fmt.Errorf("unsupported HTTP method: %s", method)
}

// ValidateAuthMethod validates authentication method
func ValidateAuthMethod(method string) error {
	allowedMethods := []string{"bearer", "basic", "header", "query", ""}
	
	method = strings.ToLower(method)
	
	for _, allowed := range allowedMethods {
		if method == allowed {
			return nil
		}
	}
	
	return fmt.Errorf("unsupported auth method: %s", method)
}

// ValidateRole validates user role
func ValidateRole(role string) error {
	allowedRoles := []string{"admin", "user", "viewer"}
	
	role = strings.ToLower(role)
	
	for _, allowed := range allowedRoles {
		if role == allowed {
			return nil
		}
	}
	
	return fmt.Errorf("invalid role: %s", role)
}