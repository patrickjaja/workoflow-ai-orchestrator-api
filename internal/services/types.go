package services

// OAuth related types
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
}

type OAuthUserInfo struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	Name           string `json:"name,omitempty"`
	Username       string `json:"username,omitempty"`
	Avatar         string `json:"avatar,omitempty"`
	Picture        string `json:"picture,omitempty"`
	Provider       string `json:"provider,omitempty"`
	OrganizationID uint   `json:"organization_id,omitempty"`
	Role           string `json:"role,omitempty"`
}

// JWT token claims types
type AccessTokenClaims struct {
	UserID         uint   `json:"user_id"`
	OrganizationID uint   `json:"organization_id"`
	Email          string `json:"email,omitempty"`
	Role           string `json:"role,omitempty"`
	IsAdmin        bool   `json:"is_admin,omitempty"`
	ExpiresAt      int64  `json:"exp"`
	IssuedAt       int64  `json:"iat"`
	NotBefore      int64  `json:"nbf"`
	Issuer         string `json:"iss"`
	Subject        string `json:"sub"`
	JwtID          string `json:"jti"`
}

type RefreshTokenClaims struct {
	UserID         uint   `json:"user_id"`
	OrganizationID uint   `json:"organization_id"`
	ExpiresAt      int64  `json:"exp"`
	IssuedAt       int64  `json:"iat"`
	NotBefore      int64  `json:"nbf"`
	Issuer         string `json:"iss"`
	Subject        string `json:"sub"`
	JwtID          string `json:"jti"`
}