# CLI Usage Guide

This guide demonstrates how to use the make commands for managing the AI Orchestrator API.

## Quick Start

### 1. Setup Development Environment

```bash
# Start database services
make db-up

# Run database migrations
make db-migrate

# Start the API server
make run
```

### 2. Organization Management

#### Create Organization with OAuth

```bash
# Microsoft OAuth
make app-org-create \
  NAME="My Organization" \
  SLUG="my-org" \
  PROVIDER="microsoft" \
  CLIENT_ID="your-microsoft-client-id" \
  CLIENT_SECRET="your-microsoft-client-secret" \
  TENANT_ID="your-microsoft-tenant-id" \
  REDIRECT_URL="http://localhost:8080/api/oauth/callback/microsoft"

# Google OAuth
make app-org-create \
  NAME="My Organization" \
  SLUG="my-org" \
  PROVIDER="google" \
  CLIENT_ID="your-google-client-id" \
  CLIENT_SECRET="your-google-client-secret" \
  REDIRECT_URL="http://localhost:8080/api/oauth/callback/google"

# GitHub OAuth
make app-org-create \
  NAME="My Organization" \
  SLUG="my-org" \
  PROVIDER="github" \
  CLIENT_ID="your-github-client-id" \
  CLIENT_SECRET="your-github-client-secret" \
  REDIRECT_URL="http://localhost:8080/api/oauth/callback/github"
```

#### List Organizations

```bash
# List all organizations
make app-org-list

# Show specific organization details
make app-org-show SLUG="my-org"

# Show organizations in database (raw data)
make app-db-show-orgs
```

#### Delete Organization

```bash
# Delete organization (requires confirmation)
make app-org-delete SLUG="my-org" --confirm
```

### 3. User Management

#### Create User

```bash
# Create admin user
make app-user-create \
  ORG_SLUG="my-org" \
  EMAIL="admin@example.com" \
  FIRST_NAME="Admin" \
  LAST_NAME="User" \
  ROLE="admin"

# Create regular user
make app-user-create \
  ORG_SLUG="my-org" \
  EMAIL="user@example.com" \
  FIRST_NAME="Regular" \
  LAST_NAME="User" \
  ROLE="user"
```

#### List Users

```bash
# Show users for specific organization
make app-db-show-users ORG_SLUG="my-org"
```

### 4. OAuth Configuration

#### Add OAuth Provider to Existing Organization

```bash
make app-oauth-add \
  ORG_SLUG="my-org" \
  PROVIDER="google" \
  CLIENT_ID="your-google-client-id" \
  CLIENT_SECRET="your-google-client-secret"
```

#### Test OAuth Configuration

```bash
# Test OAuth provider configuration
make app-oauth-test \
  ORG_SLUG="my-org" \
  PROVIDER="microsoft"

# Get OAuth authorization URL
make app-oauth-get-url \
  ORG_SLUG="my-org" \
  PROVIDER="microsoft"

# Test complete OAuth flow
make app-oauth-flow-test \
  ORG_SLUG="my-org" \
  PROVIDER="microsoft"
```

### 5. Database Operations

#### Basic Operations

```bash
# Start database
make db-up

# Run migrations
make db-migrate

# Rollback migration
make db-rollback

# Reset database (destructive!)
make db-reset

# Connect to PostgreSQL
make db-psql
```

#### Database Information

```bash
# List all tables
make db-tables

# Show table structure
make db-table-info TABLE=organizations
make db-table-info TABLE=users
make db-table-info TABLE=oauth_providers

# Show migration status
make db-migration-status

# Check database connection
make app-db-status
```

### 6. Development Workflow

#### Start Development Environment

```bash
# Start all services (database, redis, etc.)
make dev

# Build and run the application
make build
make run

# Stop development environment
make dev-stop

# Reset development environment
make dev-reset
```

## Complete Example: Setting Up a New Organization

Here's a complete example of setting up a new organization with OAuth and users:

```bash
# 1. Ensure database is running and migrated
make db-up
make db-migrate

# 2. Create organization with Microsoft OAuth
make app-org-create \
  NAME="WorkoFlow Demo" \
  SLUG="workoflow-demo" \
  PROVIDER="microsoft" \
  CLIENT_ID="your-microsoft-client-id-here" \
  CLIENT_SECRET="your-microsoft-client-secret-here" \
  TENANT_ID="your-microsoft-tenant-id-here" \
  REDIRECT_URL="http://localhost:8080/api/oauth/callback/microsoft"

# 3. Create admin user
make app-user-create \
  ORG_SLUG="workoflow-demo" \
  EMAIL="admin@workoflow.com" \
  FIRST_NAME="Admin" \
  LAST_NAME="User" \
  ROLE="admin"

# 4. Create regular users
make app-user-create \
  ORG_SLUG="workoflow-demo" \
  EMAIL="john.doe@workoflow.com" \
  FIRST_NAME="John" \
  LAST_NAME="Doe" \
  ROLE="user"

# 5. Test OAuth configuration
make app-oauth-test \
  ORG_SLUG="workoflow-demo" \
  PROVIDER="microsoft"

# 6. Verify setup
make app-org-show SLUG="workoflow-demo"
make app-db-show-users ORG_SLUG="workoflow-demo"

# 7. Start the API server
make run
```

## Testing

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests
make test-integration

# Run tests with coverage
make test-coverage

# Run benchmark tests
make test-benchmark
```

## Docker Operations

```bash
# Build Docker image
make docker-build

# Run in Docker
make docker-run

# Start all services with Docker Compose
make docker-up

# Stop Docker services
make docker-down

# View logs
make docker-logs

# Clean up Docker resources
make docker-clean
```

## Monitoring and Debugging

```bash
# View application logs
make logs

# View database logs
make logs-db

# View Redis logs
make logs-redis

# Check application health
make health

# Check server status
make status
```

## Code Quality

```bash
# Run linter
make lint

# Format code
make format

# Run security scan
make security

# Run go vet
make vet
```

## Cleanup

```bash
# Stop the server
make stop

# Clean build artifacts
make clean

# Reset database
make db-reset

# Clean Docker resources
make docker-clean
```

## Tips

1. **Environment Variables**: Copy `.env.example` to `.env` and configure your settings
2. **Database URL**: The default DATABASE_URL is configured for local PostgreSQL
3. **Encryption Key**: Generate a secure 32-character encryption key for production
4. **OAuth Credentials**: Never commit real OAuth credentials to version control
5. **Logs**: Check `logs/api-server.log` for detailed application logs

## Troubleshooting

### Database Connection Issues
```bash
# Check database status
make app-db-status

# Restart database
make db-up
```

### Migration Issues
```bash
# Check migration status
make db-migration-status

# Rollback and retry
make db-rollback
make db-migrate
```

### Server Issues
```bash
# Check if server is running
make status

# Restart server
make restart
```

For more information, see the main README.md file.