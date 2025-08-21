package handlers

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	Code      string `json:"code,omitempty"`
	Details   interface{} `json:"details,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// SuccessResponse represents a standard success response
type SuccessResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ValidationError represents validation error details
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

// PaginationResponse represents pagination metadata
type PaginationResponse struct {
	Total       int  `json:"total"`
	Page        int  `json:"page"`
	Limit       int  `json:"limit"`
	HasNext     bool `json:"has_next"`
	HasPrevious bool `json:"has_previous"`
}

// ListResponse represents a generic list response with pagination
type ListResponse struct {
	Data       interface{}         `json:"data"`
	Pagination *PaginationResponse `json:"pagination,omitempty"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status    string                 `json:"status"`
	Version   string                 `json:"version"`
	Timestamp string                 `json:"timestamp"`
	Services  map[string]interface{} `json:"services,omitempty"`
}