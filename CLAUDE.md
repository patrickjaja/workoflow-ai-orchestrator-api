# CLAUDE.md - Project Configuration

## Debugging and Logs

### How to Monitor Server Logs
When the API server is running, logs are written to both:
1. **Console (stdout)** - visible in the terminal where `make run` is executed
2. **Log file** - `logs/api-server.log` for persistent debugging

To monitor logs in real-time:
```bash
# Watch log file (most recent entries)
tail -f logs/api-server.log

# Get last N lines of logs
tail -n 50 logs/api-server.log

# Search for specific patterns in logs
rg "error|failed|warning" logs/api-server.log
```

### Logging Best Practices
1. **ALWAYS write important messages to log files** - Don't just use `fmt.Printf` to stdout
2. **Dual logging** - Write to both stdout AND log file for debugging visibility
3. **Structured logging** - Use JSON format for log files to maintain consistency
4. **Check logs during testing** - Always monitor `logs/api-server.log` when testing features
5. **Log levels** - Use appropriate levels: error, warning, info, debug

## Important Rules

### Production-Ready Solutions Rule
NEVER implement workarounds or temporary fixes. Always provide production-ready, final solutions.
DO NOT use conditional error handling to bypass issues - fix the root cause.
ALWAYS solve problems at their source rather than masking symptoms.
When encountering errors, identify and fix the underlying issue completely.

### Code Quality Rule
NEVER implement *Fixed or alternative solutions for backward compatibility. Always provide the ultimate solution.
DO NOT create parallel implementations with suffixes like "_fixed", "_new", "_v2", etc.
ALWAYS remove unused code, deprecated implementations, and redundant files.
When fixing an issue, replace the existing implementation rather than creating an alternative version.

### Security and Git Push Rule
ALWAYS check for secrets and sensitive data before committing and pushing to GitHub:
1. Search for hardcoded credentials, API keys, tokens, passwords, and secrets
2. Replace any found secrets with placeholder values (e.g., "your-api-key-here")
3. Ensure .gitignore properly excludes all sensitive files (.env, *.key, *.pem, etc.)
4. Run a final check with: `git diff --cached | grep -E "secret|password|token|key|credential"`
5. NEVER push real credentials, even in documentation or example files
GitHub has push protection that will reject commits containing secrets - prevent this by checking first!

### Application and Process Management Rule
The user will ALWAYS start and manage blocking/non-terminating processes (commands that run indefinitely and don't return control to the terminal) such as:
- Application servers (`make run`, `go run`, etc.)
- Docker containers (`docker-compose up` without `-d`, etc.)
- Database services that run in foreground
- Development servers (`npm run dev`, `yarn dev`, etc.)
- Any command that blocks the terminal indefinitely

ALWAYS ask the user to start/restart these processes when needed. NEVER attempt to start them directly.
Note: Non-blocking commands that complete and return (like `make build`, `make test`, `docker-compose up -d`) are OK to run.

### Database Operations Rule
NEVER use direct database access commands (psql, docker exec with SQL).
ALWAYS use or create appropriate Makefile commands for database operations.
Database operations should be parameterized and controlled through make commands.

### Database Migration Rule
Since the project is not live yet, maintain a single consolidated migration file (1_initial_schema.up.sql).
DO NOT create new migration files for schema changes - update the existing initial schema file instead.
This keeps the schema clean and simple during development.

### Documentation Maintenance Rules
1. **Make Commands**: When adding or modifying Makefile commands, ALWAYS update the "Available Make Commands" section in this file
2. **Project Structure**: When adding new top-level directories, ALWAYS update the "Project Structure" section in this file
3. Keep all documentation in this file current and synchronized with actual implementation
4. **Changelog Updates**: ALWAYS update CHANGELOG.md when:
   - Completing a significant feature or enhancement
   - Fixing bugs or issues
   - Making breaking changes
   - Adding new dependencies or removing existing ones
   - Modifying API endpoints or their behavior
   - Implementing security improvements
   - Making infrastructure or deployment changes
   Group all changes by the current date (YYYY-MM-DD format) under the [Unreleased] section

## Project Structure

```
├── bin/            # Compiled binaries
├── cmd/            # Main applications (api, migrate, seed)
├── CONCEPT/        # Project concepts and design documents
├── docker/         # Docker-related files
├── docs/           # Documentation
├── internal/       # Private application code
│   ├── ai/         # AI and LangChain integration
│   ├── config/     # Configuration management
│   ├── database/   # Database connection and migrations
│   ├── handlers/   # HTTP request handlers
│   ├── middleware/ # HTTP middleware
│   ├── models/     # Data models
│   └── services/   # Business logic services
├── logs/           # Application logs
├── migrations/     # Database migration files
├── pkg/            # Public packages
├── scripts/        # Utility scripts
└── tests/          # Test files
    ├── e2e/        # End-to-end tests
    └── integration/ # Integration tests
```

## Available Make Commands

### Application Management
- `make build` - Build the application
- `make run` - Run the application locally
- `make stop` - Stop the running application server
- `make restart` - Restart the application server (stop then run)
- `make status` - Check if the application server is running
- `make install` - Install Go dependencies
- `make clean` - Clean build artifacts

### Database Operations
- `make db-up` - Start database services
- `make db-migrate` - Run database migrations
- `make db-rollback` - Rollback database migration
- `make db-reset` - Reset database (drop and recreate)
- `make db-psql` - Connect to PostgreSQL database
- `make db-table-info TABLE=tablename` - Show table structure
- `make db-tables` - List all database tables
- `make db-migration-status` - Show migration status

### Organization & User Management
- `make app-org-create NAME="..." SLUG="..." PROVIDER="..." CLIENT_ID="..." CLIENT_SECRET="..." TENANT_ID="..." REDIRECT_URL="..."` - Create organization with OAuth
- `make app-user-create ORG_SLUG="..." EMAIL="..." FIRST_NAME="..." LAST_NAME="..." ROLE="..."` - Create user
- `make app-oauth-add ORG_SLUG="..." PROVIDER="..." CLIENT_ID="..." CLIENT_SECRET="..." TENANT_ID="..."` - Add OAuth provider
- `make app-org-list` - List all organizations
- `make app-org-show SLUG="..."` - Show organization details
- `make app-org-delete SLUG="..." --confirm` - Delete organization
- `make app-db-show-orgs` - Show organizations in database
- `make app-db-show-users ORG_SLUG="..."` - Show users for organization

### OAuth Testing
- `make app-oauth-test ORG_SLUG="..." PROVIDER="..."` - Test OAuth configuration
- `make app-oauth-get-url ORG_SLUG="..." PROVIDER="..."` - Get OAuth authorization URL
- `make app-oauth-flow-test ORG_SLUG="..." PROVIDER="..."` - Test complete OAuth flow

### Docker Operations
- `make docker-build` - Build Docker image
- `make docker-run` - Run application in Docker
- `make docker-up` - Start all services with Docker Compose
- `make docker-down` - Stop all Docker services
- `make docker-logs` - Show Docker service logs
- `make docker-clean` - Clean Docker images and volumes

### Development
- `make dev` - Start development environment
- `make dev-stop` - Stop development environment
- `make dev-reset` - Reset development environment
- `make run-migrate` - Run database migrations

### Testing
- `make test` - Run unit tests
- `make test-unit` - Run unit tests only
- `make test-integration` - Run integration tests
- `make test-coverage` - Run tests with coverage
- `make test-benchmark` - Run benchmark tests
- `make quick-test` - Run quick tests (unit tests only)
- `make ci-test` - Run all tests for CI
- `make ci-build` - Build for CI

### Code Quality
- `make lint` - Run linter
- `make format` - Format Go code
- `make vet` - Run go vet
- `make security` - Run security scan

### Monitoring & Debugging
- `make logs` - Show application logs
- `make logs-db` - Show database logs
- `make logs-redis` - Show Redis logs
- `make health` - Check application health
- `make app-db-status` - Check database connection status

### Help
- `make help` - Show all available commands