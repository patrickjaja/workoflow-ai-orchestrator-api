package models

import (
	"encoding/json"
	"fmt"
	"time"
)

type OAuthSession struct {
	ID             string                 `json:"id"`
	UserID         uint                   `json:"user_id"`
	OrganizationID uint                   `json:"organization_id"`
	Provider       string                 `json:"provider"`
	State          string                 `json:"state"`
	RedirectURI    string                 `json:"redirect_uri,omitempty"`
	Scopes         []string               `json:"scopes,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	ExpiresAt      time.Time              `json:"expires_at"`
}

func NewOAuthSession(userID, orgID uint, provider string, ttl time.Duration) *OAuthSession {
	now := time.Now()
	return &OAuthSession{
		ID:             fmt.Sprintf("%d", time.Now().UnixNano()),
		UserID:         userID,
		OrganizationID: orgID,
		Provider:       provider,
		State:          fmt.Sprintf("%d", time.Now().UnixNano()),
		CreatedAt:      now,
		ExpiresAt:      now.Add(ttl),
		Metadata:       make(map[string]interface{}),
	}
}

func (s *OAuthSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

func (s *OAuthSession) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

func OAuthSessionFromJSON(data []byte) (*OAuthSession, error) {
	var session OAuthSession
	err := json.Unmarshal(data, &session)
	return &session, err
}

type ChatSession struct {
	ID               string                 `json:"id"`
	UserID           uint                   `json:"user_id"`
	OrganizationID   uint                   `json:"organization_id"`
	ConversationID   uint                   `json:"conversation_id"`
	WaitingForAuth   bool                   `json:"waiting_for_auth"`
	RequiredProvider string                 `json:"required_provider,omitempty"`
	PendingIntent    *Intent                `json:"pending_intent,omitempty"`
	Context          map[string]interface{} `json:"context,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

type Intent struct {
	Type            string                 `json:"type"`
	RequiredTools   []string               `json:"required_tools"`
	Confidence      float64                `json:"confidence"`
	ExtractedParams map[string]interface{} `json:"extracted_params,omitempty"`
}

func NewChatSession(userID, orgID, conversationID uint) *ChatSession {
	now := time.Now()
	return &ChatSession{
		ID:             fmt.Sprintf("%d", time.Now().UnixNano()),
		UserID:         userID,
		OrganizationID: orgID,
		ConversationID: conversationID,
		Context:        make(map[string]interface{}),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func (s *ChatSession) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

func ChatSessionFromJSON(data []byte) (*ChatSession, error) {
	var session ChatSession
	err := json.Unmarshal(data, &session)
	return &session, err
}