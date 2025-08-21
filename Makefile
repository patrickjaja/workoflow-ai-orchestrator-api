# Makefile for AI Orchestrator API

# Variables
GO_VERSION := 1.24
APP_NAME := ai-orchestrator-api
BUILD_DIR := ./bin
DOCKER_IMAGE := $(APP_NAME)
DOCKER_TAG := latest
TEST_TIMEOUT := 10m

# Colors for output
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
RESET := \033[0m

.PHONY: help
help: ## Show this help message
	@echo "$(BLUE)AI Orchestrator API - Available Commands:$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# Development Commands
.PHONY: install
install: ## Install Go dependencies
	@echo "$(BLUE)Installing dependencies...$(RESET)"
	go mod download
	go mod tidy

.PHONY: build
build: ## Build the application
	@echo "$(BLUE)Building application...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o $(BUILD_DIR)/$(APP_NAME) ./cmd/api/main.go
	@echo "$(GREEN)Build complete: $(BUILD_DIR)/$(APP_NAME)$(RESET)"

.PHONY: run
run: ## Run the application locally
	@echo "$(BLUE)Starting application...$(RESET)"
	@if [ -f .env ]; then \
		export $$(cat .env | grep -v '^#' | xargs) && go run ./cmd/api/main.go; \
	else \
		go run ./cmd/api/main.go; \
	fi

.PHONY: stop
stop: ## Stop the running application server
	@echo "$(BLUE)Stopping application server...$(RESET)"
	@-pkill -TERM -f "go run ./cmd/api/main.go" 2>/dev/null && echo "$(GREEN)Stopped go run process$(RESET)" || echo "$(YELLOW)No go run process found$(RESET)"
	@-pkill -TERM -f "$(APP_NAME)" 2>/dev/null && echo "$(GREEN)Stopped $(APP_NAME) process$(RESET)" || true
	@sleep 1
	@echo "$(GREEN)Server stop command completed$(RESET)"

.PHONY: restart
restart: stop run ## Restart the application server

.PHONY: status
status: ## Check if the application server is running
	@echo "$(BLUE)Checking application status...$(RESET)"
	@FOUND=0; \
	if pgrep -f "go run ./cmd/api/main.go" > /dev/null 2>&1; then \
		PIDS=$$(pgrep -f "go run ./cmd/api/main.go"); \
		for PID in $$PIDS; do \
			if ps -p $$PID -o comm= | grep -q "go"; then \
				echo "$(GREEN)✓ Application is running (go run)$(RESET)"; \
				echo "  PID: $$PID"; \
				FOUND=1; \
				break; \
			fi; \
		done; \
	fi; \
	if [ $$FOUND -eq 0 ] && pgrep -x "$(APP_NAME)" > /dev/null 2>&1; then \
		echo "$(GREEN)✓ Application is running (binary)$(RESET)"; \
		pgrep -x "$(APP_NAME)" | xargs -I {} echo "  PID: {}"; \
	elif [ $$FOUND -eq 0 ]; then \
		echo "$(YELLOW)✗ Application is not running$(RESET)"; \
	fi
	@if curl -s --connect-timeout 2 http://localhost:8080/health > /dev/null 2>&1; then \
		echo "$(GREEN)✓ Health endpoint is responding$(RESET)"; \
	else \
		echo "$(YELLOW)✗ Health endpoint is not responding$(RESET)"; \
	fi

.PHONY: run-migrate
run-migrate: ## Run database migrations
	@echo "$(BLUE)Running database migrations...$(RESET)"
	go run ./cmd/migrate up

.PHONY: clean
clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	rm -rf $(BUILD_DIR)
	go clean -cache
	go clean -modcache

# Testing Commands
.PHONY: test
test: ## Run unit tests
	@echo "$(BLUE)Running unit tests...$(RESET)"
	go test -v -race -timeout=$(TEST_TIMEOUT) ./...

.PHONY: test-unit
test-unit: ## Run unit tests only
	@echo "$(BLUE)Running unit tests...$(RESET)"
	go test -v -race -timeout=$(TEST_TIMEOUT) -short ./internal/... ./pkg/...

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "$(BLUE)Running integration tests...$(RESET)"
	go test -v -race -timeout=$(TEST_TIMEOUT) ./tests/integration/...

.PHONY: test-e2e
test-e2e: ## Run E2E tests
	@echo "$(BLUE)Running E2E tests...$(RESET)"
	@echo "$(YELLOW)Starting test environment...$(RESET)"
	docker-compose -f docker-compose.test.yml up -d --build
	@echo "$(YELLOW)Waiting for services to be ready...$(RESET)"
	sleep 30
	@echo "$(BLUE)Running E2E tests...$(RESET)"
	go test -v -timeout=$(TEST_TIMEOUT) ./tests/e2e/... || (echo "$(RED)E2E tests failed$(RESET)" && $(MAKE) test-e2e-down && exit 1)
	@echo "$(GREEN)E2E tests completed successfully$(RESET)"
	$(MAKE) test-e2e-down

.PHONY: test-e2e-up
test-e2e-up: ## Start E2E test environment
	@echo "$(BLUE)Starting E2E test environment...$(RESET)"
	docker-compose -f docker-compose.test.yml up -d --build
	@echo "$(YELLOW)Waiting for services to be ready...$(RESET)"
	sleep 30
	@echo "$(GREEN)E2E test environment is ready$(RESET)"
	@echo "$(YELLOW)Run 'make test-e2e-run' to execute tests$(RESET)"

.PHONY: test-e2e-run
test-e2e-run: ## Run E2E tests (assumes environment is already up)
	@echo "$(BLUE)Running E2E tests...$(RESET)"
	go test -v -timeout=$(TEST_TIMEOUT) ./tests/e2e/...

.PHONY: test-e2e-down
test-e2e-down: ## Stop E2E test environment
	@echo "$(BLUE)Stopping E2E test environment...$(RESET)"
	docker-compose -f docker-compose.test.yml down -v
	docker-compose -f docker-compose.test.yml rm -f

.PHONY: test-e2e-logs
test-e2e-logs: ## Show E2E test environment logs
	docker-compose -f docker-compose.test.yml logs -f

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	@echo "$(BLUE)Running tests with coverage...$(RESET)"
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(RESET)"

.PHONY: test-benchmark
test-benchmark: ## Run benchmark tests
	@echo "$(BLUE)Running benchmark tests...$(RESET)"
	go test -v -bench=. -benchmem ./...

# Docker Commands
.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(RESET)"
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "$(GREEN)Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)$(RESET)"

.PHONY: docker-run
docker-run: ## Run application in Docker
	@echo "$(BLUE)Running application in Docker...$(RESET)"
	docker run --rm -p 8080:8080 --env-file .env $(DOCKER_IMAGE):$(DOCKER_TAG)

.PHONY: docker-up
docker-up: ## Start all services with Docker Compose
	@echo "$(BLUE)Starting all services...$(RESET)"
	docker-compose up -d --build
	@echo "$(GREEN)All services started$(RESET)"

.PHONY: docker-down
docker-down: ## Stop all Docker services
	@echo "$(BLUE)Stopping all services...$(RESET)"
	docker-compose down -v
	docker-compose rm -f

.PHONY: docker-logs
docker-logs: ## Show Docker service logs
	docker-compose logs -f

.PHONY: docker-clean
docker-clean: ## Clean Docker images and volumes
	@echo "$(BLUE)Cleaning Docker resources...$(RESET)"
	docker-compose down -v --remove-orphans
	docker system prune -f
	docker volume prune -f

# Development Tools
.PHONY: lint
lint: ## Run linter
	@echo "$(BLUE)Running linter...$(RESET)"
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "$(YELLOW)Installing golangci-lint...$(RESET)"; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	}
	golangci-lint run

.PHONY: format
format: ## Format Go code
	@echo "$(BLUE)Formatting Go code...$(RESET)"
	go fmt ./...
	@command -v goimports >/dev/null 2>&1 || { \
		echo "$(YELLOW)Installing goimports...$(RESET)"; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	}
	goimports -w .

.PHONY: vet
vet: ## Run go vet
	@echo "$(BLUE)Running go vet...$(RESET)"
	go vet ./...

.PHONY: security
security: ## Run security scan
	@echo "$(BLUE)Running security scan...$(RESET)"
	@command -v gosec >/dev/null 2>&1 || { \
		echo "$(YELLOW)Installing gosec...$(RESET)"; \
		go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
	}
	gosec ./...

# Database Commands
.PHONY: db-up
db-up: ## Start database services
	@echo "$(BLUE)Starting database services...$(RESET)"
	docker-compose up -d postgres redis

.PHONY: db-migrate
db-migrate: db-up ## Run database migrations
	@echo "$(BLUE)Running database migrations...$(RESET)"
	sleep 5  # Wait for database to be ready
	go run ./cmd/migrate up

.PHONY: db-rollback
db-rollback: ## Rollback database migration
	@echo "$(BLUE)Rolling back database migration...$(RESET)"
	go run ./cmd/migrate down

.PHONY: db-reset
db-reset: ## Reset database (drop and recreate)
	@echo "$(BLUE)Resetting database...$(RESET)"
	docker-compose down -v
	docker-compose up -d postgres redis
	@echo "$(BLUE)Waiting for database to be ready...$(RESET)"
	sleep 10
	$(MAKE) db-migrate

.PHONY: db-psql
db-psql: ## Connect to PostgreSQL database
	@echo "$(BLUE)Connecting to PostgreSQL...$(RESET)"
	docker-compose exec postgres psql -U postgres -d ai_orchestrator

.PHONY: db-table-info
db-table-info: ## Show table structure (use TABLE=tablename)
	@echo "$(BLUE)Showing structure for table: $(TABLE)$(RESET)"
	@docker-compose exec postgres psql -U postgres -d ai_orchestrator -c "\d $(TABLE)"

.PHONY: db-tables
db-tables: ## List all database tables
	@echo "$(BLUE)Listing all tables...$(RESET)"
	@docker-compose exec postgres psql -U postgres -d ai_orchestrator -c "\dt"

.PHONY: db-migration-status
db-migration-status: ## Show migration status
	@echo "$(BLUE)Migration status:$(RESET)"
	@docker-compose exec postgres psql -U postgres -d ai_orchestrator -c "SELECT * FROM schema_migrations;"

# Monitoring and Debugging
.PHONY: logs
logs: ## Show application logs
	docker-compose logs -f api

.PHONY: logs-db
logs-db: ## Show database logs
	docker-compose logs -f postgres

.PHONY: logs-redis
logs-redis: ## Show Redis logs
	docker-compose logs -f redis

.PHONY: health
health: ## Check application health
	@echo "$(BLUE)Checking application health...$(RESET)"
	@curl -s http://localhost:8080/health | jq . || echo "$(RED)Health check failed$(RESET)"

# CI/CD Commands
.PHONY: ci-test
ci-test: ## Run all tests for CI
	@echo "$(BLUE)Running CI test suite...$(RESET)"
	$(MAKE) lint
	$(MAKE) vet
	$(MAKE) security
	$(MAKE) test-unit
	$(MAKE) test-integration
	$(MAKE) test-e2e

.PHONY: ci-build
ci-build: ## Build for CI
	@echo "$(BLUE)Running CI build...$(RESET)"
	$(MAKE) install
	$(MAKE) build
	$(MAKE) docker-build

# Quick Development Commands
.PHONY: dev
dev: ## Start development environment
	@echo "$(BLUE)Starting development environment...$(RESET)"
	$(MAKE) docker-up
	@echo "$(GREEN)Development environment started$(RESET)"
	@echo "$(YELLOW)API: http://localhost:8080$(RESET)"
	@echo "$(YELLOW)N8N: http://localhost:5678$(RESET)"
	@echo "$(YELLOW)PostgreSQL: localhost:5432$(RESET)"
	@echo "$(YELLOW)Redis: localhost:6379$(RESET)"

.PHONY: dev-stop
dev-stop: ## Stop development environment
	@echo "$(BLUE)Stopping development environment...$(RESET)"
	$(MAKE) docker-down

.PHONY: dev-reset
dev-reset: ## Reset development environment
	@echo "$(BLUE)Resetting development environment...$(RESET)"
	$(MAKE) docker-down
	$(MAKE) docker-clean
	$(MAKE) dev

.PHONY: quick-test
quick-test: ## Run quick tests (unit tests only)
	@echo "$(BLUE)Running quick tests...$(RESET)"
	go test -short -race ./...

# Application CLI Commands
.PHONY: app-org-create
app-org-create: ## Create organization with OAuth provider (use NAME, SLUG, PROVIDER, CLIENT_ID, CLIENT_SECRET, TENANT_ID, REDIRECT_URL)
	@echo "$(BLUE)Creating organization...$(RESET)"
	@go run ./cmd/seed org-create \
		--name="$(NAME)" \
		--slug="$(SLUG)" \
		--description="$(DESCRIPTION)" \
		--provider="$(PROVIDER)" \
		--client-id="$(CLIENT_ID)" \
		--client-secret="$(CLIENT_SECRET)" \
		--tenant-id="$(TENANT_ID)" \
		--redirect-url="$(REDIRECT_URL)"

.PHONY: app-user-create
app-user-create: ## Create user for organization (use ORG_SLUG, EMAIL, FIRST_NAME, LAST_NAME, ROLE)
	@echo "$(BLUE)Creating user...$(RESET)"
	@go run ./cmd/seed user-create \
		--org-slug="$(ORG_SLUG)" \
		--email="$(EMAIL)" \
		--first-name="$(FIRST_NAME)" \
		--last-name="$(LAST_NAME)" \
		--role="$(ROLE)"

.PHONY: app-oauth-add
app-oauth-add: ## Add OAuth provider to existing organization (use ORG_SLUG, PROVIDER, CLIENT_ID, CLIENT_SECRET, TENANT_ID)
	@echo "$(BLUE)Adding OAuth provider...$(RESET)"
	@go run ./cmd/seed oauth-add \
		--org-slug="$(ORG_SLUG)" \
		--provider="$(PROVIDER)" \
		--client-id="$(CLIENT_ID)" \
		--client-secret="$(CLIENT_SECRET)" \
		--tenant-id="$(TENANT_ID)" \
		--redirect-url="$(REDIRECT_URL)"

.PHONY: app-org-list
app-org-list: ## List all organizations and their OAuth providers
	@echo "$(BLUE)Listing organizations...$(RESET)"
	@go run ./cmd/seed org-list

.PHONY: app-org-show
app-org-show: ## Show organization details (use SLUG)
	@echo "$(BLUE)Showing organization details...$(RESET)"
	@go run ./cmd/seed org-show --slug="$(SLUG)"

.PHONY: app-org-delete
app-org-delete: ## Delete organization (use SLUG, requires --confirm)
	@echo "$(BLUE)Deleting organization...$(RESET)"
	@go run ./cmd/seed org-delete --slug="$(SLUG)" --confirm

.PHONY: app-oauth-test
app-oauth-test: ## Test OAuth configuration (use ORG_SLUG, PROVIDER)
	@echo "$(BLUE)Testing OAuth configuration...$(RESET)"
	@go run ./cmd/seed oauth-test \
		--org-slug="$(ORG_SLUG)" \
		--provider="$(PROVIDER)"

.PHONY: app-db-status
app-db-status: ## Check database connection status
	@echo "$(BLUE)Checking database status...$(RESET)"
	@go run ./cmd/seed db-status

# OAuth Testing Commands
.PHONY: app-oauth-get-url
app-oauth-get-url: ## Get OAuth authorization URL (use ORG_SLUG, PROVIDER)
	@echo "$(BLUE)Getting OAuth authorization URL...$(RESET)"
	@echo "Organization: $(ORG_SLUG)"
	@echo "Provider: $(PROVIDER)"
	@echo ""
	@curl -s -X GET "http://localhost:8080/api/v1/auth/$(PROVIDER)/login" \
		-H "X-Organization-Slug: $(ORG_SLUG)" | jq . || echo "$(RED)Failed to get auth URL. Is the server running?$(RESET)"

.PHONY: app-oauth-flow-test
app-oauth-flow-test: ## Test complete OAuth flow (use ORG_SLUG, PROVIDER)
	@echo "$(BLUE)Testing OAuth flow for $(PROVIDER) in organization $(ORG_SLUG)...$(RESET)"
	@echo ""
	@echo "1. Getting auth URL..."
	@curl -s -X GET "http://localhost:8080/api/v1/auth/$(PROVIDER)/login" \
		-H "X-Organization-Slug: $(ORG_SLUG)" | jq . || echo "$(RED)Failed to get auth URL$(RESET)"
	@echo ""
	@echo "2. Open the 'auth_url' from above in your browser"
	@echo "3. Complete authentication with $(PROVIDER)"
	@echo "4. You'll be redirected to: http://localhost:8080/api/oauth/callback/$(PROVIDER)"
	@echo ""
	@echo "$(YELLOW)Note: Make sure the API server is running (make run)$(RESET)"

# Database inspection commands
.PHONY: app-db-show-orgs
app-db-show-orgs: ## Show organizations in database
	@echo "$(BLUE)Fetching organizations from database...$(RESET)"
	@docker exec -it $$(docker-compose ps -q postgres) psql -U postgres -d ai_orchestrator -t -c \
		"SELECT o.id, o.name, o.slug, COUNT(DISTINCT op.id) as oauth_providers, COUNT(DISTINCT u.id) as users \
		 FROM organizations o \
		 LEFT JOIN oauth_providers op ON o.id = op.organization_id \
		 LEFT JOIN users u ON o.id = u.organization_id \
		 GROUP BY o.id, o.name, o.slug \
		 ORDER BY o.created_at DESC;" 2>/dev/null || echo "$(RED)Database not running. Start with: make db-up$(RESET)"

.PHONY: app-db-show-users
app-db-show-users: ## Show users for organization (use ORG_SLUG)
	@echo "$(BLUE)Fetching users for organization $(ORG_SLUG)...$(RESET)"
	@docker exec -it $$(docker-compose ps -q postgres) psql -U postgres -d ai_orchestrator -t -c \
		"SELECT u.id, u.email, u.first_name, u.last_name, u.role, u.is_active, u.is_verified \
		 FROM users u \
		 JOIN organizations o ON u.organization_id = o.id \
		 WHERE o.slug = '$(ORG_SLUG)' \
		 ORDER BY u.created_at DESC;" 2>/dev/null || echo "$(RED)Database not running or organization not found$(RESET)"

# Default target
.DEFAULT_GOAL := help