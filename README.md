# 🚀 AI Orchestrator API

A powerful multi-tenant middleware for AI orchestration, designed to connect various input channels (MS Teams, Slack, Web) with backend systems through intelligent routing and n8n workflow integration.

## 📋 Overview

This Go-based API serves as the central intelligence layer that:
- **Manages multi-tenant OAuth integrations** per organization
- **Routes requests intelligently** using LangChain and OpenAI
- **Integrates with n8n workflows** for backend system orchestration
- **Provides secure token management** with encryption at rest
- **Supports multiple channels** (Teams, Slack, Web interfaces)

## 🏗️ Architecture

```
Input Channels (Teams/Slack/Web)
              ↓
    AI Orchestrator API (This App)
         ├── LangChain/OpenAI
         ├── PostgreSQL (Multi-tenant data)
         ├── Redis (Session cache)
         └── n8n Workflows
              ↓
    External Systems (Jira, SharePoint, etc.)
```

## 🚀 Quick Start

### Prerequisites
- Go 1.21+
- Docker & Docker Compose
- PostgreSQL 15+ (or use Docker)
- Redis (optional, or use Docker)

### Installation

1. **Clone and setup:**
```bash
# Clone the repository
cd workoflow-ai-orchestrator-api

# Copy environment variables
cp .env.example .env

# Edit .env with your configuration
nano .env
```

2. **Configure your OpenAI API key in .env:**
```env
OPENAI_API_KEY=sk-your-openai-api-key
```

3. **Start with Docker Compose:**
```bash
docker-compose up -d
```

This will start:
- PostgreSQL database
- Redis cache
- AI Orchestrator API
- n8n workflow engine (optional)

4. **Or run locally:**
```bash
# Install dependencies
go mod tidy

# Run database migrations
go run cmd/migrate/main.go up

# Start the server
go run cmd/simple-api/main.go
```

## 📡 API Endpoints

### Health Check
```bash
GET /health
```

### Chat Interface
```bash
POST /api/chat
Content-Type: application/json

{
  "message": "Search for vacation policy in SharePoint",
  "user_id": "user-123",
  "organization_id": "org-456"
}
```

### Get Conversation History
```bash
GET /api/chat/{conversation_id}/history
```

### OAuth Management (Full Version)
```bash
GET /api/oauth/callback/{provider}
POST /api/admin/organizations/{org_id}/providers
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_PORT` | Server port | 8080 |
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | Optional |
| `OPENAI_API_KEY` | OpenAI API key for LangChain | Required |
| `ENCRYPTION_KEY` | 32-character key for token encryption | Required |
| `JWT_SECRET` | Secret for JWT signing | Required |
| `N8N_WEBHOOK_URL` | Default n8n webhook endpoint | Optional |

### OAuth Provider Setup

Each organization can configure their own OAuth credentials:

```sql
-- Example: Add Microsoft OAuth for an organization
INSERT INTO oauth_providers (
  organization_id,
  provider_type,
  client_id,
  client_secret,
  tenant_id
) VALUES (
  'org-uuid',
  'microsoft',
  'encrypted-client-id',
  'encrypted-client-secret',
  'tenant-id'
);
```

## 🧪 Testing

### Run unit tests:
```bash
go test ./...
```

### Run with coverage:
```bash
go test -cover ./...
```

### Test the API:
```bash
# Health check
curl http://localhost:8080/health

# Send a chat message
curl -X POST http://localhost:8080/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hello, AI!",
    "user_id": "test-user",
    "organization_id": "test-org"
  }'
```

## 🐳 Docker Deployment

### Build the image:
```bash
docker build -t ai-orchestrator:latest .
```

### Run with Docker Compose:
```bash
docker-compose up -d
```

### View logs:
```bash
docker-compose logs -f api
```

## 📊 Database Schema

The application uses a multi-tenant PostgreSQL database with the following main tables:
- `organizations` - Tenant organizations
- `users` - Users per organization/channel
- `oauth_providers` - OAuth configurations per org
- `user_tokens` - Encrypted OAuth tokens
- `n8n_webhooks` - Webhook configurations
- `conversations` - Chat conversations
- `messages` - Conversation messages

## 🔒 Security Features

- **JWT Authentication** for API access
- **AES Encryption** for sensitive data at rest
- **Multi-tenant isolation** at database level
- **Rate limiting** per organization
- **CORS configuration** for web clients
- **Audit logging** for compliance

## 🤝 Integration with n8n

The API integrates with n8n for workflow automation:

1. Configure n8n webhook URL in environment
2. Set up workflows in n8n that receive:
   - User context
   - Intent data
   - OAuth tokens (decrypted)
3. n8n workflows can then interact with external systems

## 📚 API Flow Example

1. **User sends message** via Teams/Slack/Web
2. **API receives request** and validates JWT
3. **LangChain analyzes intent** (e.g., "search SharePoint")
4. **Check user tokens** for required provider (Microsoft)
5. **If no token**: Return OAuth URL for authentication
6. **If token exists**: Forward to n8n workflow
7. **n8n executes workflow** with user's token
8. **Return response** to user

## 🛠️ Development

### Project Structure:
```
.
├── cmd/
│   ├── simple-api/     # Simplified API server
│   └── api.disabled/    # Full-featured API (complex)
├── internal/
│   ├── ai/             # AI/LangChain integration
│   ├── config/         # Configuration management
│   ├── database/       # Database layer
│   ├── handlers/       # HTTP handlers
│   ├── middleware/     # HTTP middleware
│   ├── models/         # Data models
│   └── services/       # Business logic
├── migrations/         # Database migrations
├── docker/            # Docker configurations
└── pkg/               # Shared utilities
```

### Adding a New OAuth Provider:

1. Add provider type to `models/oauth_provider.go`
2. Implement OAuth endpoints in provider model
3. Add default scopes for the provider
4. Test the OAuth flow

## 📈 Monitoring

The application provides:
- Health check endpoint at `/health`
- Structured JSON logging
- OpenTelemetry support (planned)
- Prometheus metrics (planned)

## 🚨 Troubleshooting

### Database connection issues:
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# View database logs
docker-compose logs postgres
```

### OpenAI API errors:
- Verify API key is correct
- Check rate limits
- Ensure model name is valid

### OAuth issues:
- Verify redirect URLs match configuration
- Check provider credentials are encrypted properly
- Ensure scopes are correct for the provider

## 📝 License

[Your License Here]

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📧 Support

For issues and questions:
- Create an issue on GitHub
- Contact the development team

---

Built with ❤️ using Go, LangChain, and n8n