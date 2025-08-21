package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sashabaranov/go-openai"
	"github.com/workoflow/ai-orchestrator-api/internal/ai"
	"github.com/workoflow/ai-orchestrator-api/internal/config"
)

type AIService struct {
	client          *openai.Client
	config          *config.Config
	intentDetector  *ai.IntentDetector
	contextManager  *ai.ContextManager
}

type AIResponse struct {
	Text        string                 `json:"text"`
	Intent      string                 `json:"intent"`
	Confidence  float32                `json:"confidence"`
	Actions     []AIAction             `json:"actions,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type AIAction struct {
	Type        string                 `json:"type"`
	Target      string                 `json:"target"`
	Parameters  map[string]interface{} `json:"parameters"`
	Priority    int                    `json:"priority"`
}

type ChatRequest struct {
	Message         string                 `json:"message"`
	ConversationID  string                 `json:"conversation_id"`
	Context         map[string]interface{} `json:"context,omitempty"`
	SessionID       string                 `json:"session_id"`
	UserID          uint                   `json:"user_id"`
	OrganizationID  uint                   `json:"organization_id"`
}

func NewAIService(cfg *config.Config) (*AIService, error) {
	var client *openai.Client
	
	// Check if Azure OpenAI is enabled
	if cfg.OpenAI.Azure.Enabled {
		if cfg.OpenAI.Azure.APIKey == "" {
			return nil, fmt.Errorf("Azure OpenAI API key is required when Azure OpenAI is enabled")
		}
		if cfg.OpenAI.Azure.Endpoint == "" {
			return nil, fmt.Errorf("Azure OpenAI endpoint is required when Azure OpenAI is enabled")
		}
		if cfg.OpenAI.Azure.DeploymentName == "" {
			return nil, fmt.Errorf("Azure OpenAI deployment name is required when Azure OpenAI is enabled")
		}
		
		// Create Azure OpenAI client configuration
		azureConfig := openai.DefaultAzureConfig(cfg.OpenAI.Azure.APIKey, cfg.OpenAI.Azure.Endpoint)
		azureConfig.APIVersion = cfg.OpenAI.Azure.APIVersion
		client = openai.NewClientWithConfig(azureConfig)
	} else {
		// Use standard OpenAI
		if cfg.OpenAI.APIKey == "" {
			return nil, fmt.Errorf("OpenAI API key is required")
		}
		client = openai.NewClient(cfg.OpenAI.APIKey)
	}
	
	intentDetector := ai.NewIntentDetector()
	contextManager := ai.NewContextManager()

	return &AIService{
		client:         client,
		config:         cfg,
		intentDetector: intentDetector,
		contextManager: contextManager,
	}, nil
}

func (s *AIService) ProcessMessage(ctx context.Context, req *ChatRequest) (*AIResponse, error) {
	// Detect intent from the message
	intent, confidence := s.intentDetector.DetectIntent(req.Message)
	
	// Get conversation context
	conversationContext, err := s.contextManager.GetContext(req.ConversationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get conversation context: %w", err)
	}

	// Merge request context with conversation context
	fullContext := s.mergeContexts(conversationContext, req.Context)

	// Build messages for OpenAI
	messages := s.buildMessages(req.Message, fullContext, intent)

	// Determine which model/deployment to use
	modelName := s.config.OpenAI.Model
	if s.config.OpenAI.Azure.Enabled && s.config.OpenAI.Azure.DeploymentName != "" {
		modelName = s.config.OpenAI.Azure.DeploymentName
	}

	// Call OpenAI (works with both standard OpenAI and Azure OpenAI)
	response, err := s.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:       modelName,
		Messages:    messages,
		MaxTokens:   s.config.OpenAI.MaxTokens,
		Temperature: s.config.OpenAI.Temperature,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create chat completion: %w", err)
	}

	if len(response.Choices) == 0 {
		return nil, fmt.Errorf("no response choices received from OpenAI")
	}

	aiResponse := &AIResponse{
		Text:       response.Choices[0].Message.Content,
		Intent:     intent,
		Confidence: confidence,
		Context:    fullContext,
		Metadata: map[string]interface{}{
			"model":         response.Model,
			"usage_tokens":  response.Usage.TotalTokens,
			"created_at":    time.Now(),
			"request_id":    response.ID,
		},
	}

	// Extract actions if any
	actions := s.extractActions(aiResponse.Text, intent)
	aiResponse.Actions = actions

	// Update conversation context
	err = s.contextManager.UpdateContext(req.ConversationID, map[string]interface{}{
		"last_message":    req.Message,
		"last_response":   aiResponse.Text,
		"last_intent":     intent,
		"last_confidence": confidence,
		"timestamp":       time.Now(),
	})
	if err != nil {
		// Log error but don't fail the request
		fmt.Printf("Warning: failed to update conversation context: %v\n", err)
	}

	return aiResponse, nil
}

func (s *AIService) buildMessages(userMessage string, context map[string]interface{}, intent string) []openai.ChatCompletionMessage {
	messages := []openai.ChatCompletionMessage{
		{
			Role: openai.ChatMessageRoleSystem,
			Content: s.buildSystemPrompt(context, intent),
		},
	}

	// Add conversation history if available
	if history, ok := context["conversation_history"].([]interface{}); ok {
		for _, item := range history {
			if msg, ok := item.(map[string]interface{}); ok {
				role := "user"
				if r, exists := msg["role"].(string); exists {
					role = r
				}
				content := ""
				if c, exists := msg["content"].(string); exists {
					content = c
				}

				var messageRole string
				switch role {
				case "assistant":
					messageRole = openai.ChatMessageRoleAssistant
				default:
					messageRole = openai.ChatMessageRoleUser
				}

				messages = append(messages, openai.ChatCompletionMessage{
					Role:    messageRole,
					Content: content,
				})
			}
		}
	}

	// Add current user message
	messages = append(messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: userMessage,
	})

	return messages
}

func (s *AIService) buildSystemPrompt(context map[string]interface{}, intent string) string {
	prompt := `You are an AI assistant for a workflow orchestration system. You help users manage and execute workflows through natural language interactions.

Your capabilities include:
- Understanding user intents and providing helpful responses
- Triggering workflow executions via n8n webhooks
- Managing workflow configurations and parameters
- Providing guidance on workflow best practices
- Analyzing workflow performance and results

Current context:`

	// Add context information
	if userInfo, ok := context["user_info"]; ok {
		prompt += fmt.Sprintf("\nUser: %v", userInfo)
	}

	if orgInfo, ok := context["organization_info"]; ok {
		prompt += fmt.Sprintf("\nOrganization: %v", orgInfo)
	}

	if workflowInfo, ok := context["available_workflows"]; ok {
		prompt += fmt.Sprintf("\nAvailable workflows: %v", workflowInfo)
	}

	// Add intent-specific instructions
	switch intent {
	case "workflow_execution":
		prompt += `

Focus on helping the user execute workflows. If they want to run a workflow, identify:
1. Which workflow they want to run
2. What parameters are needed
3. Provide clear confirmation before execution`

	case "workflow_management":
		prompt += `

Focus on helping the user manage their workflows. This includes:
1. Listing available workflows
2. Creating or modifying workflow configurations
3. Managing workflow permissions and settings`

	case "data_query":
		prompt += `

Focus on helping the user query and analyze their workflow data. This includes:
1. Workflow execution history
2. Performance metrics
3. Error analysis and troubleshooting`

	case "general":
		prompt += `

Provide general assistance and guidance about the workflow orchestration system. Be helpful and informative.`
	}

	prompt += `

Always respond in a helpful, professional manner. If you need to trigger a workflow, clearly explain what will happen before proceeding.`

	return prompt
}

func (s *AIService) extractActions(response string, intent string) []AIAction {
	actions := []AIAction{}

	// Simple action extraction based on intent and response content
	switch intent {
	case "workflow_execution":
		if strings.Contains(strings.ToLower(response), "execute") ||
		   strings.Contains(strings.ToLower(response), "run") {
			actions = append(actions, AIAction{
				Type:       "workflow_execution",
				Target:     "n8n_webhook",
				Parameters: map[string]interface{}{
					"extracted_from": "ai_response",
					"confidence":     "medium",
				},
				Priority: 1,
			})
		}

	case "workflow_management":
		if strings.Contains(strings.ToLower(response), "create") ||
		   strings.Contains(strings.ToLower(response), "modify") {
			actions = append(actions, AIAction{
				Type:       "workflow_management",
				Target:     "workflow_config",
				Parameters: map[string]interface{}{
					"action": "config_update",
				},
				Priority: 2,
			})
		}

	case "data_query":
		actions = append(actions, AIAction{
			Type:       "data_retrieval",
			Target:     "database",
			Parameters: map[string]interface{}{
				"query_type": "analytics",
			},
			Priority: 3,
		})
	}

	return actions
}

func (s *AIService) mergeContexts(base, additional map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Copy base context
	for k, v := range base {
		result[k] = v
	}

	// Override with additional context
	for k, v := range additional {
		result[k] = v
	}

	return result
}

func (s *AIService) GetConversationSummary(ctx context.Context, conversationID string) (string, error) {
	context, err := s.contextManager.GetContext(conversationID)
	if err != nil {
		return "", fmt.Errorf("failed to get conversation context: %w", err)
	}

	// Extract conversation history
	history, ok := context["conversation_history"].([]interface{})
	if !ok || len(history) == 0 {
		return "No conversation history available.", nil
	}

	// Build summary request
	messages := []openai.ChatCompletionMessage{
		{
			Role: openai.ChatMessageRoleSystem,
			Content: "Provide a concise summary of the following conversation, highlighting key topics, decisions, and actions taken:",
		},
	}

	// Add conversation history
	for _, item := range history {
		if msg, ok := item.(map[string]interface{}); ok {
			content := ""
			if c, exists := msg["content"].(string); exists {
				content = c
			}
			messages = append(messages, openai.ChatCompletionMessage{
				Role:    openai.ChatMessageRoleUser,
				Content: content,
			})
		}
	}

	// Determine which model/deployment to use
	modelName := s.config.OpenAI.Model
	if s.config.OpenAI.Azure.Enabled && s.config.OpenAI.Azure.DeploymentName != "" {
		modelName = s.config.OpenAI.Azure.DeploymentName
	}

	response, err := s.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:       modelName,
		Messages:    messages,
		MaxTokens:   500, // Limit for summary
		Temperature: 0.3, // Lower temperature for more focused summary
	})

	if err != nil {
		return "", fmt.Errorf("failed to create summary: %w", err)
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("no summary generated")
	}

	return response.Choices[0].Message.Content, nil
}

func (s *AIService) ValidateWorkflowParameters(ctx context.Context, workflowName string, parameters map[string]interface{}) (bool, []string, error) {
	// Build validation prompt
	prompt := fmt.Sprintf(`Validate the following parameters for workflow "%s":
Parameters: %v

Please respond with:
1. "VALID" or "INVALID"
2. List any missing or incorrect parameters
3. Suggestions for fixes if applicable

Format your response as JSON:
{
  "valid": true/false,
  "errors": ["error1", "error2"],
  "suggestions": ["suggestion1", "suggestion2"]
}`, workflowName, parameters)

	// Determine which model/deployment to use
	modelName := s.config.OpenAI.Model
	if s.config.OpenAI.Azure.Enabled && s.config.OpenAI.Azure.DeploymentName != "" {
		modelName = s.config.OpenAI.Azure.DeploymentName
	}

	response, err := s.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: modelName,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
		MaxTokens:   1000,
		Temperature: 0.1, // Very low temperature for precise validation
	})

	if err != nil {
		return false, nil, fmt.Errorf("failed to validate parameters: %w", err)
	}

	if len(response.Choices) == 0 {
		return false, nil, fmt.Errorf("no validation response received")
	}

	// For now, return basic validation
	// In a real implementation, you would parse the JSON response
	return true, []string{}, nil
}