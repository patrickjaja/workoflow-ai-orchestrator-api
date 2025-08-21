package ai

import (
	"regexp"
	"strings"
)

type IntentDetector struct {
	patterns map[string][]*regexp.Regexp
	weights  map[string]float32
}

type Intent struct {
	Name       string  `json:"name"`
	Confidence float32 `json:"confidence"`
	Keywords   []string `json:"keywords"`
}

func NewIntentDetector() *IntentDetector {
	detector := &IntentDetector{
		patterns: make(map[string][]*regexp.Regexp),
		weights:  make(map[string]float32),
	}

	detector.initializePatterns()
	return detector
}

func (id *IntentDetector) initializePatterns() {
	// Workflow execution patterns
	id.patterns["workflow_execution"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(run|execute|start|trigger|launch)\b.*\b(workflow|flow|process|job)\b`),
		regexp.MustCompile(`(?i)\b(execute|run)\b`),
		regexp.MustCompile(`(?i)\btrigger\b.*\bn8n\b`),
		regexp.MustCompile(`(?i)\bstart\b.*\b(automation|process)\b`),
		regexp.MustCompile(`(?i)\blaunch\b.*\b(pipeline|workflow)\b`),
	}

	// Workflow management patterns
	id.patterns["workflow_management"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(create|build|make|setup)\b.*\b(workflow|automation)\b`),
		regexp.MustCompile(`(?i)\b(modify|update|edit|change)\b.*\b(workflow|flow)\b`),
		regexp.MustCompile(`(?i)\b(configure|config)\b.*\b(workflow|n8n)\b`),
		regexp.MustCompile(`(?i)\b(list|show|display)\b.*\b(workflows|automations)\b`),
		regexp.MustCompile(`(?i)\b(delete|remove)\b.*\b(workflow|automation)\b`),
	}

	// Data query patterns
	id.patterns["data_query"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(show|display|get|fetch|retrieve)\b.*\b(data|results|logs|history)\b`),
		regexp.MustCompile(`(?i)\b(analyze|analysis)\b.*\b(data|performance|metrics)\b`),
		regexp.MustCompile(`(?i)\b(status|state)\b.*\b(workflow|execution|job)\b`),
		regexp.MustCompile(`(?i)\b(report|summary)\b.*\b(execution|workflow|results)\b`),
		regexp.MustCompile(`(?i)\b(error|failed|failure)\b.*\b(analysis|log|report)\b`),
		regexp.MustCompile(`(?i)\bwhat\s+(happened|went\s+wrong)\b`),
	}

	// Help and guidance patterns
	id.patterns["help_guidance"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(help|assist|guide|support)\b`),
		regexp.MustCompile(`(?i)\b(how\s+to|how\s+do\s+i|how\s+can\s+i)\b`),
		regexp.MustCompile(`(?i)\b(tutorial|documentation|docs|guide)\b`),
		regexp.MustCompile(`(?i)\b(explain|describe|tell\s+me)\b`),
		regexp.MustCompile(`(?i)\bwhat\s+(is|are|does|can)\b`),
	}

	// System status patterns
	id.patterns["system_status"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(system|service|api)\b.*\b(status|health|availability)\b`),
		regexp.MustCompile(`(?i)\bis\b.*\b(running|working|online|available)\b`),
		regexp.MustCompile(`(?i)\b(check|verify)\b.*\b(system|service|connection)\b`),
		regexp.MustCompile(`(?i)\b(uptime|downtime|maintenance)\b`),
	}

	// Authentication patterns
	id.patterns["authentication"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(login|signin|authenticate|auth)\b`),
		regexp.MustCompile(`(?i)\b(logout|signout|disconnect)\b`),
		regexp.MustCompile(`(?i)\b(token|session|credential)\b.*\b(refresh|renew|update)\b`),
		regexp.MustCompile(`(?i)\b(permission|access|authorize)\b`),
	}

	// General conversation patterns
	id.patterns["general"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(hello|hi|hey|greetings)\b`),
		regexp.MustCompile(`(?i)\b(thank\s+you|thanks|appreciate)\b`),
		regexp.MustCompile(`(?i)\b(goodbye|bye|see\s+you)\b`),
		regexp.MustCompile(`(?i)\b(yes|no|okay|ok|sure)\b`),
	}

	// Set confidence weights for different intent types
	id.weights["workflow_execution"] = 1.0
	id.weights["workflow_management"] = 0.9
	id.weights["data_query"] = 0.8
	id.weights["help_guidance"] = 0.7
	id.weights["system_status"] = 0.6
	id.weights["authentication"] = 0.8
	id.weights["general"] = 0.3
}

func (id *IntentDetector) DetectIntent(message string) (string, float32) {
	message = strings.TrimSpace(message)
	if message == "" {
		return "general", 0.1
	}

	intentScores := make(map[string]float32)
	
	// Calculate scores for each intent
	for intent, patterns := range id.patterns {
		score := float32(0.0)
		matchCount := 0

		for _, pattern := range patterns {
			if pattern.MatchString(message) {
				matchCount++
				score += id.weights[intent]
			}
		}

		// Normalize score based on pattern count and base weight
		if matchCount > 0 {
			score = score / float32(len(patterns)) * float32(matchCount) * 1.5
			intentScores[intent] = score
		}
	}

	// Additional scoring based on keywords
	id.addKeywordScoring(message, intentScores)

	// Find the highest scoring intent
	bestIntent := "general"
	bestScore := float32(0.0)

	for intent, score := range intentScores {
		if score > bestScore {
			bestScore = score
			bestIntent = intent
		}
	}

	// Normalize confidence to 0-1 range
	confidence := bestScore
	if confidence > 1.0 {
		confidence = 1.0
	}

	// Minimum confidence threshold
	if confidence < 0.3 {
		return "general", confidence
	}

	return bestIntent, confidence
}

func (id *IntentDetector) addKeywordScoring(message string, scores map[string]float32) {
	messageLower := strings.ToLower(message)

	// Workflow execution keywords
	executionKeywords := []string{
		"run", "execute", "start", "trigger", "launch", "fire", "invoke", 
		"activate", "begin", "initiate", "process", "go",
	}
	
	// Workflow management keywords
	managementKeywords := []string{
		"create", "build", "make", "setup", "configure", "modify", "update", 
		"edit", "change", "delete", "remove", "list", "show", "manage",
	}

	// Data query keywords
	queryKeywords := []string{
		"show", "display", "get", "fetch", "retrieve", "find", "search", 
		"analyze", "report", "status", "history", "logs", "results",
	}

	// Help keywords
	helpKeywords := []string{
		"help", "assist", "guide", "support", "how", "what", "explain", 
		"tutorial", "documentation", "teach", "learn",
	}

	// Count keyword matches and boost scores
	for _, keyword := range executionKeywords {
		if strings.Contains(messageLower, keyword) {
			scores["workflow_execution"] += 0.2
		}
	}

	for _, keyword := range managementKeywords {
		if strings.Contains(messageLower, keyword) {
			scores["workflow_management"] += 0.2
		}
	}

	for _, keyword := range queryKeywords {
		if strings.Contains(messageLower, keyword) {
			scores["data_query"] += 0.2
		}
	}

	for _, keyword := range helpKeywords {
		if strings.Contains(messageLower, keyword) {
			scores["help_guidance"] += 0.2
		}
	}

	// Context-specific boosting
	if strings.Contains(messageLower, "n8n") {
		scores["workflow_execution"] += 0.3
		scores["workflow_management"] += 0.2
	}

	if strings.Contains(messageLower, "webhook") {
		scores["workflow_execution"] += 0.3
	}

	if strings.Contains(messageLower, "automation") {
		scores["workflow_management"] += 0.2
		scores["workflow_execution"] += 0.1
	}
}

func (id *IntentDetector) GetIntentDetails(intent string) *Intent {
	details := map[string]*Intent{
		"workflow_execution": {
			Name:       "workflow_execution",
			Confidence: 0.0, // Will be set by detection
			Keywords:   []string{"run", "execute", "start", "trigger", "launch", "n8n", "workflow"},
		},
		"workflow_management": {
			Name:       "workflow_management",
			Confidence: 0.0,
			Keywords:   []string{"create", "build", "configure", "manage", "modify", "update", "list"},
		},
		"data_query": {
			Name:       "data_query",
			Confidence: 0.0,
			Keywords:   []string{"show", "display", "get", "analyze", "report", "status", "logs"},
		},
		"help_guidance": {
			Name:       "help_guidance",
			Confidence: 0.0,
			Keywords:   []string{"help", "assist", "guide", "how", "what", "explain", "tutorial"},
		},
		"system_status": {
			Name:       "system_status",
			Confidence: 0.0,
			Keywords:   []string{"system", "status", "health", "running", "uptime", "service"},
		},
		"authentication": {
			Name:       "authentication",
			Confidence: 0.0,
			Keywords:   []string{"login", "logout", "token", "auth", "permission", "access"},
		},
		"general": {
			Name:       "general",
			Confidence: 0.0,
			Keywords:   []string{"hello", "hi", "thanks", "goodbye", "yes", "no", "okay"},
		},
	}

	if detail, exists := details[intent]; exists {
		return detail
	}

	return &Intent{
		Name:       "unknown",
		Confidence: 0.0,
		Keywords:   []string{},
	}
}

func (id *IntentDetector) ExtractEntities(message string, intent string) map[string][]string {
	entities := make(map[string][]string)
	messageLower := strings.ToLower(message)

	switch intent {
	case "workflow_execution":
		// Extract workflow names
		workflowPattern := regexp.MustCompile(`(?i)\b(?:workflow|flow)\s+["']([^"']+)["']|\b(?:workflow|flow)\s+(\w+)`)
		matches := workflowPattern.FindAllStringSubmatch(message, -1)
		
		var workflowNames []string
		for _, match := range matches {
			if match[1] != "" {
				workflowNames = append(workflowNames, match[1])
			} else if match[2] != "" {
				workflowNames = append(workflowNames, match[2])
			}
		}
		if len(workflowNames) > 0 {
			entities["workflow_names"] = workflowNames
		}

		// Extract parameters
		paramPattern := regexp.MustCompile(`(?i)\bwith\s+(.+?)(?:\s+(?:and|,)|\s*$)`)
		paramMatches := paramPattern.FindAllStringSubmatch(message, -1)
		
		var parameters []string
		for _, match := range paramMatches {
			parameters = append(parameters, strings.TrimSpace(match[1]))
		}
		if len(parameters) > 0 {
			entities["parameters"] = parameters
		}

	case "data_query":
		// Extract time ranges
		timePattern := regexp.MustCompile(`(?i)\b(?:last|past)\s+(\d+)\s+(minutes?|hours?|days?|weeks?|months?)`)
		timeMatches := timePattern.FindAllStringSubmatch(message, -1)
		
		var timeRanges []string
		for _, match := range timeMatches {
			timeRanges = append(timeRanges, match[1]+" "+match[2])
		}
		if len(timeRanges) > 0 {
			entities["time_ranges"] = timeRanges
		}

		// Extract data types
		dataTypes := []string{}
		if strings.Contains(messageLower, "log") || strings.Contains(messageLower, "logs") {
			dataTypes = append(dataTypes, "logs")
		}
		if strings.Contains(messageLower, "error") || strings.Contains(messageLower, "errors") {
			dataTypes = append(dataTypes, "errors")
		}
		if strings.Contains(messageLower, "execution") || strings.Contains(messageLower, "run") {
			dataTypes = append(dataTypes, "executions")
		}
		if len(dataTypes) > 0 {
			entities["data_types"] = dataTypes
		}
	}

	return entities
}