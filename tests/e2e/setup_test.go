package e2e_test

import (
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/workoflow/ai-orchestrator-api/internal/config"
	"github.com/workoflow/ai-orchestrator-api/internal/database"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	testDB      *gorm.DB
	testHelpers *TestHelpers
	testConfig  *config.Config
)

const (
	testBaseURL = "http://localhost:8080" // Use port 8080 for test server
)

// TestMain sets up and tears down the test environment
func TestMain(m *testing.M) {
	var err error
	
	// Setup test environment
	log.Println("Setting up E2E test environment...")
	
	// Load test configuration
	testConfig, err = setupTestConfig()
	if err != nil {
		log.Fatalf("Failed to setup test config: %v", err)
	}
	
	// Wait for database to be available
	log.Println("Waiting for database to be available...")
	testDB, err = waitForDatabase(testConfig, 30*time.Second)
	if err != nil {
		log.Fatalf("Failed to connect to test database: %v", err)
	}
	
	// Run database migrations
	log.Println("Running database migrations...")
	err = runMigrations(testDB)
	if err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	
	// Initialize test helpers
	testHelpers = NewTestHelpers(testBaseURL, testDB)
	
	// Wait for API server to be available (test server)
	log.Println("Waiting for API server to be available...")
	// Note: For now we'll skip this, but in real E2E tests you'd start the test server
	// and wait for it to be available
	
	log.Println("Test environment ready!")
	
	// Run tests
	exitCode := m.Run()
	
	// Cleanup
	log.Println("Cleaning up test environment...")
	cleanup()
	
	os.Exit(exitCode)
}

// setupTestConfig creates a test configuration
func setupTestConfig() (*config.Config, error) {
	cfg := &config.Config{
		App: config.AppConfig{
			Env:  "test",
			Port: 8080,
			Name: "ai-orchestrator-api-test",
		},
		Database: config.DatabaseConfig{
			URL:                      ":memory:", // Use in-memory SQLite for tests
			MaxConnections:           10,
			MaxIdleConnections:       2,
			ConnectionLifetime: 300 * time.Second,
		},
		Redis: config.RedisConfig{
			URL:        getEnvOrDefault("REDIS_URL", "redis://localhost:6380"),
			MaxRetries: 3,
			PoolSize:   5,
		},
		Security: config.SecurityConfig{
			EncryptionKey: "test-encryption-key-32-chars-here",
			JWTSecret:     "test-jwt-secret-key-here-64-chars-long-for-testing-purposes",
			JWTExpiry:     1 * time.Hour,
			RefreshExpiry: 1 * 24 * time.Hour,
		},
		OpenAI: config.OpenAIConfig{
			APIKey:      getEnvOrDefault("OPENAI_API_KEY", "test-key"),
			Model:       "gpt-3.5-turbo",
			MaxTokens:   1000,
			Temperature: 0.7,
		},
		OAuth: config.OAuthConfig{
			RedirectBaseURL: "http://localhost:8080",
			SessionTimeout:  5 * time.Minute,
		},
		Log: config.LogConfig{
			Level:  "debug",
			Format: "json",
			Output: "stdout",
		},
	}
	
	return cfg, nil
}

// waitForDatabase waits for the database to become available
func waitForDatabase(cfg *config.Config, timeout time.Duration) (*gorm.DB, error) {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		gormConfig := &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		}
		
		db, err := gorm.Open(sqlite.Open(cfg.Database.URL), gormConfig)
		if err == nil {
			// Test the connection
			sqlDB, err := db.DB()
			if err == nil {
				err = sqlDB.Ping()
				if err == nil {
					return db, nil
				}
			}
		}
		
		log.Printf("Database not ready, waiting... (%v)", err)
		time.Sleep(2 * time.Second)
	}
	
	return nil, fmt.Errorf("database not available within timeout")
}

// runMigrations runs database migrations
func runMigrations(db *gorm.DB) error {
	// Use the database package migration function
	return database.Migrate(db)
}

// cleanup cleans up the test environment
func cleanup() {
	if testDB != nil {
		sqlDB, err := testDB.DB()
		if err == nil {
			sqlDB.Close()
		}
	}
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// TestSetupValidation validates that the test setup is working correctly
func TestSetupValidation(t *testing.T) {
	// Test database connection
	sqlDB, err := testDB.DB()
	if err != nil {
		t.Fatalf("Failed to get database instance: %v", err)
	}
	
	err = sqlDB.Ping()
	if err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}
	
	// Test API health endpoint (skip for now since we're not running the server)
	// health := testHelpers.CheckHealth(t)
	// if health.Status != "healthy" {
	// 	t.Fatalf("API health check failed: %s", health.Status)
	// }
	
	t.Log("Test setup validation passed!")
}

// setupTestData creates common test data used across tests
func setupTestData(t *testing.T) {
	t.Helper()
	
	// Create test organization
	org := &models.Organization{
		Name:        "Test Organization",
		Slug:        "test-org",
		Description: "Test organization for E2E testing",
		Settings:    models.JSON{"theme": "light"},
	}
	if err := testDB.Create(org).Error; err != nil {
		t.Fatalf("Failed to create test organization: %v", err)
	}
	
	// Create test user
	user := &models.User{
		Email:          "test@example.com",
		PasswordHash:   "$2a$12$test.hash.for.testing",
		FirstName:      "Test",
		LastName:       "User",
		Role:           "admin",
		IsActive:       true,
		IsVerified:     true,
		OrganizationID: org.ID,
		Settings:       models.JSON{"language": "en"},
	}
	if err := testDB.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	
	t.Logf("Created test data: org_id=%d, user_id=%d", org.ID, user.ID)
}

// Helper functions for common test scenarios

// createTestToken creates a test JWT token for authentication
func createTestToken(t *testing.T) string {
	t.Helper()
	
	// This would create a valid JWT token for testing
	// For now, return a placeholder that matches the test server's /test/auth/token endpoint
	return "test_jwt_token_placeholder"
}