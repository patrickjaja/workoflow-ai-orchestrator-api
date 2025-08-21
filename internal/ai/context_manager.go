package ai

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type ContextManager struct {
	contexts map[string]*ConversationContext
	mutex    sync.RWMutex
	maxAge   time.Duration
}

type ConversationContext struct {
	ID                 string                 `json:"id"`
	UserID             uint                   `json:"user_id"`
	OrganizationID     uint                   `json:"organization_id"`
	SessionID          string                 `json:"session_id"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
	LastActivity       time.Time              `json:"last_activity"`
	MessageCount       int                    `json:"message_count"`
	ConversationState  string                 `json:"conversation_state"`
	CurrentIntent      string                 `json:"current_intent"`
	IntentHistory      []string               `json:"intent_history"`
	ConversationTopic  string                 `json:"conversation_topic"`
	ActiveWorkflows    []string               `json:"active_workflows"`
	PendingActions     []PendingAction        `json:"pending_actions"`
	UserPreferences    map[string]interface{} `json:"user_preferences"`
	ConversationMemory []ConversationMessage  `json:"conversation_history"`
	Variables          map[string]interface{} `json:"variables"`
	Metadata           map[string]interface{} `json:"metadata"`
}

type ConversationMessage struct {
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	Intent    string    `json:"intent,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type PendingAction struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	Status      string                 `json:"status"` // pending, confirmed, cancelled, expired
}

func NewContextManager() *ContextManager {
	cm := &ContextManager{
		contexts: make(map[string]*ConversationContext),
		maxAge:   24 * time.Hour, // Context expires after 24 hours
	}
	
	// Start cleanup routine
	go cm.cleanupRoutine()
	
	return cm
}

func (cm *ContextManager) GetContext(conversationID string) (map[string]interface{}, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	context, exists := cm.contexts[conversationID]
	if !exists {
		// Return empty context for new conversations
		return map[string]interface{}{
			"conversation_id": conversationID,
			"created_at":      time.Now(),
			"message_count":   0,
			"variables":       make(map[string]interface{}),
			"conversation_history": []ConversationMessage{},
		}, nil
	}

	// Check if context is expired
	if time.Since(context.LastActivity) > cm.maxAge {
		delete(cm.contexts, conversationID)
		return map[string]interface{}{
			"conversation_id": conversationID,
			"created_at":      time.Now(),
			"message_count":   0,
			"variables":       make(map[string]interface{}),
			"conversation_history": []ConversationMessage{},
		}, nil
	}

	// Convert to map for easy handling
	contextMap := cm.contextToMap(context)
	return contextMap, nil
}

func (cm *ContextManager) UpdateContext(conversationID string, updates map[string]interface{}) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	context, exists := cm.contexts[conversationID]
	if !exists {
		context = &ConversationContext{
			ID:                conversationID,
			CreatedAt:         time.Now(),
			ConversationState: "active",
			Variables:         make(map[string]interface{}),
			Metadata:          make(map[string]interface{}),
			UserPreferences:   make(map[string]interface{}),
			ConversationMemory: []ConversationMessage{},
			IntentHistory:     []string{},
			ActiveWorkflows:   []string{},
			PendingActions:    []PendingAction{},
		}
		cm.contexts[conversationID] = context
	}

	// Update basic fields
	context.UpdatedAt = time.Now()
	context.LastActivity = time.Now()

	// Apply updates
	for key, value := range updates {
		switch key {
		case "user_id":
			if userID, ok := value.(uint); ok {
				context.UserID = userID
			}
		case "organization_id":
			if orgID, ok := value.(uint); ok {
				context.OrganizationID = orgID
			}
		case "session_id":
			if sessionID, ok := value.(string); ok {
				context.SessionID = sessionID
			}
		case "conversation_state":
			if state, ok := value.(string); ok {
				context.ConversationState = state
			}
		case "current_intent":
			if intent, ok := value.(string); ok {
				context.CurrentIntent = intent
				// Add to history if different from last
				if len(context.IntentHistory) == 0 || context.IntentHistory[len(context.IntentHistory)-1] != intent {
					context.IntentHistory = append(context.IntentHistory, intent)
					// Keep only last 10 intents
					if len(context.IntentHistory) > 10 {
						context.IntentHistory = context.IntentHistory[1:]
					}
				}
			}
		case "conversation_topic":
			if topic, ok := value.(string); ok {
				context.ConversationTopic = topic
			}
		case "last_message":
			if message, ok := value.(string); ok {
				context.MessageCount++
				context.ConversationMemory = append(context.ConversationMemory, ConversationMessage{
					Role:      "user",
					Content:   message,
					Timestamp: time.Now(),
					Intent:    context.CurrentIntent,
				})
				// Keep only last 20 messages
				if len(context.ConversationMemory) > 20 {
					context.ConversationMemory = context.ConversationMemory[1:]
				}
			}
		case "last_response":
			if response, ok := value.(string); ok {
				context.ConversationMemory = append(context.ConversationMemory, ConversationMessage{
					Role:      "assistant",
					Content:   response,
					Timestamp: time.Now(),
				})
				// Keep only last 20 messages
				if len(context.ConversationMemory) > 20 {
					context.ConversationMemory = context.ConversationMemory[1:]
				}
			}
		case "variables":
			if vars, ok := value.(map[string]interface{}); ok {
				for varKey, varValue := range vars {
					context.Variables[varKey] = varValue
				}
			}
		case "active_workflow":
			if workflow, ok := value.(string); ok {
				// Add to active workflows if not already present
				found := false
				for _, w := range context.ActiveWorkflows {
					if w == workflow {
						found = true
						break
					}
				}
				if !found {
					context.ActiveWorkflows = append(context.ActiveWorkflows, workflow)
				}
			}
		case "pending_action":
			if actionData, ok := value.(map[string]interface{}); ok {
				action := PendingAction{
					ID:          fmt.Sprintf("action_%d", time.Now().UnixNano()),
					CreatedAt:   time.Now(),
					ExpiresAt:   time.Now().Add(30 * time.Minute), // Actions expire in 30 minutes
					Status:      "pending",
				}
				
				if actionType, ok := actionData["type"].(string); ok {
					action.Type = actionType
				}
				if description, ok := actionData["description"].(string); ok {
					action.Description = description
				}
				if params, ok := actionData["parameters"].(map[string]interface{}); ok {
					action.Parameters = params
				}
				
				context.PendingActions = append(context.PendingActions, action)
			}
		case "user_preference":
			if prefData, ok := value.(map[string]interface{}); ok {
				for prefKey, prefValue := range prefData {
					context.UserPreferences[prefKey] = prefValue
				}
			}
		default:
			// Store in metadata
			context.Metadata[key] = value
		}
	}

	// Clean up expired pending actions
	cm.cleanupExpiredActions(context)

	return nil
}

func (cm *ContextManager) DeleteContext(conversationID string) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	delete(cm.contexts, conversationID)
	return nil
}

func (cm *ContextManager) GetPendingActions(conversationID string) ([]PendingAction, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	context, exists := cm.contexts[conversationID]
	if !exists {
		return []PendingAction{}, nil
	}

	// Filter out expired actions
	var validActions []PendingAction
	now := time.Now()
	for _, action := range context.PendingActions {
		if action.Status == "pending" && now.Before(action.ExpiresAt) {
			validActions = append(validActions, action)
		}
	}

	return validActions, nil
}

func (cm *ContextManager) ConfirmAction(conversationID, actionID string) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	context, exists := cm.contexts[conversationID]
	if !exists {
		return fmt.Errorf("conversation context not found")
	}

	for i, action := range context.PendingActions {
		if action.ID == actionID {
			if action.Status != "pending" {
				return fmt.Errorf("action is not in pending state")
			}
			if time.Now().After(action.ExpiresAt) {
				return fmt.Errorf("action has expired")
			}
			
			context.PendingActions[i].Status = "confirmed"
			return nil
		}
	}

	return fmt.Errorf("action not found")
}

func (cm *ContextManager) CancelAction(conversationID, actionID string) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	context, exists := cm.contexts[conversationID]
	if !exists {
		return fmt.Errorf("conversation context not found")
	}

	for i, action := range context.PendingActions {
		if action.ID == actionID {
			context.PendingActions[i].Status = "cancelled"
			return nil
		}
	}

	return fmt.Errorf("action not found")
}

func (cm *ContextManager) GetConversationHistory(conversationID string, limit int) ([]ConversationMessage, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	context, exists := cm.contexts[conversationID]
	if !exists {
		return []ConversationMessage{}, nil
	}

	history := context.ConversationMemory
	if limit > 0 && len(history) > limit {
		history = history[len(history)-limit:]
	}

	return history, nil
}

func (cm *ContextManager) SetVariable(conversationID, key string, value interface{}) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	context, exists := cm.contexts[conversationID]
	if !exists {
		context = &ConversationContext{
			ID:        conversationID,
			CreatedAt: time.Now(),
			Variables: make(map[string]interface{}),
		}
		cm.contexts[conversationID] = context
	}

	context.Variables[key] = value
	context.UpdatedAt = time.Now()
	context.LastActivity = time.Now()

	return nil
}

func (cm *ContextManager) GetVariable(conversationID, key string) (interface{}, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	context, exists := cm.contexts[conversationID]
	if !exists {
		return nil, false
	}

	value, exists := context.Variables[key]
	return value, exists
}

func (cm *ContextManager) contextToMap(context *ConversationContext) map[string]interface{} {
	return map[string]interface{}{
		"conversation_id":    context.ID,
		"user_id":           context.UserID,
		"organization_id":   context.OrganizationID,
		"session_id":        context.SessionID,
		"created_at":        context.CreatedAt,
		"updated_at":        context.UpdatedAt,
		"last_activity":     context.LastActivity,
		"message_count":     context.MessageCount,
		"conversation_state": context.ConversationState,
		"current_intent":    context.CurrentIntent,
		"intent_history":    context.IntentHistory,
		"conversation_topic": context.ConversationTopic,
		"active_workflows":  context.ActiveWorkflows,
		"pending_actions":   context.PendingActions,
		"user_preferences":  context.UserPreferences,
		"conversation_history": context.ConversationMemory,
		"variables":         context.Variables,
		"metadata":          context.Metadata,
	}
}

func (cm *ContextManager) cleanupExpiredActions(context *ConversationContext) {
	now := time.Now()
	var validActions []PendingAction

	for _, action := range context.PendingActions {
		if action.Status == "pending" && now.After(action.ExpiresAt) {
			// Mark as expired
			action.Status = "expired"
		}
		// Keep only pending and confirmed actions, remove expired and cancelled
		if action.Status == "pending" || action.Status == "confirmed" {
			validActions = append(validActions, action)
		}
	}

	context.PendingActions = validActions
}

func (cm *ContextManager) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cm.cleanup()
		}
	}
}

func (cm *ContextManager) cleanup() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	now := time.Now()
	for conversationID, context := range cm.contexts {
		// Remove contexts that haven't been active for more than maxAge
		if now.Sub(context.LastActivity) > cm.maxAge {
			delete(cm.contexts, conversationID)
		} else {
			// Clean up expired actions within active contexts
			cm.cleanupExpiredActions(context)
		}
	}
}

func (cm *ContextManager) GetContextStats() map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	totalContexts := len(cm.contexts)
	activeContexts := 0
	totalMessages := 0
	totalPendingActions := 0

	for _, context := range cm.contexts {
		if time.Since(context.LastActivity) < 1*time.Hour {
			activeContexts++
		}
		totalMessages += context.MessageCount
		for _, action := range context.PendingActions {
			if action.Status == "pending" {
				totalPendingActions++
			}
		}
	}

	return map[string]interface{}{
		"total_contexts":       totalContexts,
		"active_contexts":      activeContexts,
		"total_messages":       totalMessages,
		"total_pending_actions": totalPendingActions,
		"cleanup_threshold":    cm.maxAge.String(),
	}
}

func (cm *ContextManager) ExportContext(conversationID string) ([]byte, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	context, exists := cm.contexts[conversationID]
	if !exists {
		return nil, fmt.Errorf("conversation context not found")
	}

	return json.Marshal(context)
}

func (cm *ContextManager) ImportContext(conversationID string, data []byte) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	var context ConversationContext
	if err := json.Unmarshal(data, &context); err != nil {
		return fmt.Errorf("failed to unmarshal context: %w", err)
	}

	context.ID = conversationID
	context.UpdatedAt = time.Now()
	context.LastActivity = time.Now()

	cm.contexts[conversationID] = &context
	return nil
}