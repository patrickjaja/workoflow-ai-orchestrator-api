# E2E Testing Documentation

This document describes the comprehensive End-to-End (E2E) testing framework for the AI Orchestrator API, based on the requirements from the CONCEPT document.

## Overview

The E2E testing framework validates the complete multi-tenant AI orchestration platform, including:

- Multi-tenant OAuth management
- AI integration with LangChain
- N8N webhook triggering
- Database isolation
- Complete chat flow scenarios

## Test Architecture

### Test Structure

```
tests/e2e/
├── setup_test.go      # Test environment setup and configuration
├── helpers_test.go    # Utility functions and test helpers
└── chat_test.go      # Main E2E test scenarios
```

### Test Environment

The tests use a dedicated test environment with:

- **Test Database**: PostgreSQL running on port 5433
- **Test Redis**: Redis running on port 6380
- **Mock N8N Server**: Nginx-based mock for webhook testing
- **Test API Server**: API running on port 8080

## Required Test Scenarios (from CONCEPT document)

### ✅ 1. TestChatFlowWithoutAuth
**Purpose**: Test general questions without requiring authentication

**Scenarios**:
- Weather questions
- Simple greetings
- General AI questions
- Math questions
- Workflow information

**Expected**: Direct response without auth requirement

### ✅ 2. TestChatFlowRequiringSharePoint
**Purpose**: Test SharePoint queries that trigger auth flow

**Scenarios**:
- SharePoint document search
- OneDrive access
- Microsoft 365 queries
- Employee handbook requests

**Expected**: Auth required response with Microsoft OAuth URL

### ✅ 3. TestMultiTenantIsolation
**Purpose**: Verify different organizations have different OAuth configs

**Test Flow**:
1. Create multiple organizations with different OAuth configs
2. Make identical SharePoint requests from different orgs
3. Verify each org gets their own OAuth URL with correct client_id
4. Ensure no cross-tenant data leakage

**Expected**: Each org gets organization-specific OAuth URL

### ✅ 4. TestOAuthCallbackFlow
**Purpose**: Test complete OAuth callback flow

**Test Flow**:
1. Create OAuth session
2. Simulate OAuth callback with authorization code
3. Verify token storage
4. Verify session cleanup
5. Test subsequent authenticated requests

**Expected**: Token stored, session cleared, subsequent requests work

### ✅ 5. TestN8NWebhookTrigger
**Purpose**: Test successful queries trigger n8n webhooks

**Test Flow**:
1. Setup mock N8N server
2. Configure organization with N8N webhook
3. Create authenticated user with tokens
4. Send queries requiring tool execution
5. Verify N8N webhook calls

**Expected**: N8N webhook called with correct parameters

## Running Tests

### Prerequisites

1. Docker and Docker Compose installed
2. Go 1.24+ installed
3. OpenAI API key (optional, can use mock)

### Quick Start

```bash
# Run all E2E tests
make test-e2e

# Start test environment only
make test-e2e-up

# Run tests against existing environment
make test-e2e-run

# Stop test environment
make test-e2e-down

# Show test logs
make test-e2e-logs
```

### Manual Testing

```bash
# Start test environment
docker-compose -f docker-compose.test.yml up -d --build

# Wait for services to be ready (30 seconds)
sleep 30

# Run tests
go test -v ./tests/e2e/...

# Cleanup
docker-compose -f docker-compose.test.yml down -v
```

### Environment Variables

The test environment supports these environment variables:

```bash
# Database
DATABASE_URL=postgres://postgres:postgres@localhost:5433/ai_orchestrator_test?sslmode=disable

# Redis
REDIS_URL=redis://localhost:6380

# OpenAI (optional for testing)
OPENAI_API_KEY=your-openai-key-or-test-key

# Test Configuration
APP_ENV=test
LOG_LEVEL=debug
```

## Test Helpers and Utilities

### TestHelpers Class

The `TestHelpers` class provides utilities for:

- **Organization Setup**: `SetupTestOrganization()`
- **User Management**: `SetupTestUser()`
- **OAuth Providers**: OAuth provider configuration
- **N8N Webhooks**: `SetupN8NWebhook()`
- **API Calls**: `CallChatAPI()`, `CallOAuthCallback()`
- **Data Cleanup**: `CleanupTestData()`

### Mock N8N Server

The `MockN8NServer` provides:

- **Webhook Simulation**: Receives and logs webhook calls
- **Custom Responses**: Set custom responses for specific endpoints
- **Call Tracking**: Count and inspect webhook calls
- **Request Logging**: Access to last request details

### Assertions

Common assertion helpers:

- `AssertChatResponseType()`: Check response type
- `AssertAuthRequired()`: Verify auth requirement
- `AssertSuccessfulMessage()`: Verify successful response
- `AssertContainsURL()`: Check URL components

## Test Data Management

### Database Setup

Tests use PostgreSQL with auto-migrations for these models:

- Organizations (multi-tenant isolation)
- Users (per organization)
- OAuth Providers (per organization)
- User Tokens (encrypted)
- N8N Webhooks (per organization)
- Conversations (context management)
- Sessions (OAuth flow)

### Test Data Lifecycle

1. **Setup**: `TestMain()` initializes database and services
2. **Per Test**: `setupTestData()` creates fresh test data
3. **Cleanup**: `CleanupTestData()` removes test data after each test
4. **Teardown**: `cleanup()` closes connections and resources

## Configuration Files

### docker-compose.test.yml

Test-specific Docker Compose configuration with:

- Isolated test database (port 5433)
- Isolated test Redis (port 6380)
- Mock N8N server
- Test-optimized settings

### Makefile Commands

The Makefile provides comprehensive test commands:

```bash
make test           # All tests
make test-unit      # Unit tests only
make test-integration # Integration tests
make test-e2e       # E2E tests with environment setup
make test-coverage  # Tests with coverage report
```

## Debugging Tests

### View Logs

```bash
# API logs
make logs

# Database logs
make logs-db

# Redis logs
make logs-redis

# All test environment logs
make test-e2e-logs
```

### Database Access

```bash
# Connect to test database
docker-compose -f docker-compose.test.yml exec postgres-test psql -U postgres -d ai_orchestrator_test
```

### Health Checks

```bash
# Check API health
make health

# Or manually
curl http://localhost:8080/health
```

## CI/CD Integration

The tests are designed for CI/CD with:

- **Timeout Protection**: Tests timeout after 10 minutes
- **Environment Isolation**: Each test run uses fresh containers
- **Parallel Execution**: Tests can run in parallel
- **Exit Codes**: Proper exit codes for CI systems

### CI Command

```bash
make ci-test  # Runs linting, security, and all tests
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Wait longer for database startup (increase sleep time)
   - Check DATABASE_URL configuration
   - Verify PostgreSQL container health

2. **Redis Connection Failed**
   - Check REDIS_URL configuration
   - Verify Redis container health

3. **API Not Ready**
   - Increase `WaitForService` timeout
   - Check API container logs
   - Verify health endpoint

4. **Tests Timing Out**
   - Increase TEST_TIMEOUT in Makefile
   - Check for infinite loops or deadlocks
   - Review service startup times

### Debug Mode

Run tests with verbose output:

```bash
go test -v -timeout=20m ./tests/e2e/...
```

Add debug logs to test environment:

```bash
LOG_LEVEL=debug make test-e2e
```

## Performance Considerations

- **Parallel Tests**: Tests run in parallel where safe
- **Resource Limits**: Test containers use minimal resources
- **Cleanup**: Automatic cleanup prevents resource leaks
- **Mocking**: External services are mocked to avoid rate limits

## Security Testing

The E2E tests include security validations:

- **Multi-tenant Isolation**: Verify no cross-tenant data access
- **Token Encryption**: Verify tokens are encrypted at rest
- **OAuth Security**: Verify proper OAuth flow security
- **Rate Limiting**: Test rate limiting functionality (if enabled)

## Future Enhancements

Potential improvements to the test framework:

1. **Performance Tests**: Add load testing scenarios
2. **Chaos Testing**: Test failure scenarios
3. **Integration Tests**: Test real OAuth providers (staging)
4. **UI Tests**: Add browser-based testing
5. **Monitoring**: Add metrics and monitoring validation

## Contributing

When adding new E2E tests:

1. Follow the existing test structure
2. Use the TestHelpers utilities
3. Clean up test data properly
4. Add appropriate assertions
5. Update this documentation
6. Ensure tests are deterministic and can run in parallel

## Support

For issues with the E2E testing framework:

1. Check the troubleshooting section
2. Review test logs
3. Verify environment configuration
4. Check Docker container health