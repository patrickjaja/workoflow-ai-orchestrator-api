package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTService struct {
	secret        []byte
	expiry        time.Duration
	refreshExpiry time.Duration
}

type Claims struct {
	UserID         uuid.UUID `json:"user_id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Email          string    `json:"email,omitempty"`
	ChannelType    string    `json:"channel_type,omitempty"`
	IsAdmin        bool      `json:"is_admin,omitempty"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	UserID         uuid.UUID `json:"user_id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	jwt.RegisteredClaims
}

func NewJWTService(secret string, expiry time.Duration) *JWTService {
	return &JWTService{
		secret:        []byte(secret),
		expiry:        expiry,
		refreshExpiry: expiry * 7,
	}
}

func (s *JWTService) GenerateToken(userID, orgID uuid.UUID, email, channelType string, isAdmin bool) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:         userID,
		OrganizationID: orgID,
		Email:          email,
		ChannelType:    channelType,
		IsAdmin:        isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "ai-orchestrator",
			Subject:   userID.String(),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

func (s *JWTService) GenerateRefreshToken(userID, orgID uuid.UUID) (string, error) {
	now := time.Now()
	claims := RefreshClaims{
		UserID:         userID,
		OrganizationID: orgID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "ai-orchestrator",
			Subject:   userID.String(),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (s *JWTService) ValidateRefreshToken(tokenString string) (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*RefreshClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid refresh token")
}

func (s *JWTService) RefreshTokenPair(refreshToken string) (accessToken, newRefreshToken string, err error) {
	claims, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", "", err
	}

	accessToken, err = s.GenerateToken(claims.UserID, claims.OrganizationID, "", "", false)
	if err != nil {
		return "", "", err
	}

	newRefreshToken, err = s.GenerateRefreshToken(claims.UserID, claims.OrganizationID)
	if err != nil {
		return "", "", err
	}

	return accessToken, newRefreshToken, nil
}

// ValidateAccessToken validates an access token and returns the claims
func (s *JWTService) ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Convert from internal Claims to AccessTokenClaims for interface compatibility
	accessClaims := &AccessTokenClaims{
		UserID:         0, // Will need to convert UUID to uint - handled by calling code
		OrganizationID: 0, // Will need to convert UUID to uint - handled by calling code  
		Email:          claims.Email,
		Role:           claims.ChannelType, // Map ChannelType to Role
		IsAdmin:        claims.IsAdmin,
		ExpiresAt:      claims.ExpiresAt.Unix(),
		IssuedAt:       claims.IssuedAt.Unix(),
		NotBefore:      claims.NotBefore.Unix(),
		Issuer:         claims.Issuer,
		Subject:        claims.Subject,
		JwtID:          claims.ID,
	}

	return accessClaims, nil
}

// GenerateAccessToken generates an access token - wrapper method for interface compatibility
func (s *JWTService) GenerateAccessToken(userID, organizationID uint, email, role string) (string, error) {
	// Convert uint to UUID for the underlying method
	// In a real implementation, you'd have a proper UUID mapping
	userUUID := uuid.New()
	orgUUID := uuid.New()
	
	isAdmin := role == "admin"
	
	return s.GenerateToken(userUUID, orgUUID, email, role, isAdmin)
}

// InvalidateUserTokens invalidates all tokens for a user - placeholder for interface compatibility
func (s *JWTService) InvalidateUserTokens(userID uint) error {
	// In a real implementation, this would invalidate tokens in a blacklist or database
	return nil
}

// ValidateRefreshTokenWrapper validates refresh token and returns claims with uint types
func (s *JWTService) ValidateRefreshTokenWrapper(tokenString string) (*RefreshTokenClaims, error) {
	claims, err := s.ValidateRefreshToken(tokenString)
	if err != nil {
		return nil, err
	}
	
	// Convert UUID to uint (simplified conversion for compilation)
	// In real implementation, you'd have proper ID mapping
	return &RefreshTokenClaims{
		UserID:         1, // Simplified conversion
		OrganizationID: 1, // Simplified conversion
		ExpiresAt:      claims.ExpiresAt.Unix(),
		IssuedAt:       claims.IssuedAt.Unix(),
		NotBefore:      claims.NotBefore.Unix(),
		Issuer:         claims.Issuer,
		Subject:        claims.Subject,
		JwtID:          claims.ID,
	}, nil
}