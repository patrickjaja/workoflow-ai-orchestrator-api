package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/workoflow/ai-orchestrator-api/internal/config"
	"github.com/workoflow/ai-orchestrator-api/internal/database"
	"github.com/workoflow/ai-orchestrator-api/internal/models"
	"github.com/workoflow/ai-orchestrator-api/internal/services"
	"gorm.io/gorm"
)

type CLI struct {
	db         *gorm.DB
	encryption *services.EncryptionService
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found: %v", err)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	db, err := database.Initialize(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize encryption service
	encryption := services.NewEncryptionService(cfg.Security.EncryptionKey)

	cli := &CLI{
		db:         db.DB(),
		encryption: encryption,
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	// Pass remaining arguments to command handlers
	args := os.Args[2:]

	switch command {
	case "org-create":
		cli.createOrganization(args)
	case "user-create":
		cli.createUser(args)
	case "oauth-add":
		cli.addOAuthProvider(args)
	case "org-list":
		cli.listOrganizations()
	case "org-show":
		cli.showOrganization(args)
	case "org-delete":
		cli.deleteOrganization(args)
	case "oauth-test":
		cli.testOAuth(args)
	case "db-status":
		cli.checkDatabaseStatus()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("AI Orchestrator API - Seed CLI")
	fmt.Println()
	fmt.Println("Usage: seed <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  org-create    Create a new organization with OAuth provider")
	fmt.Println("  user-create   Create a new user for an organization")
	fmt.Println("  oauth-add     Add OAuth provider to existing organization")
	fmt.Println("  org-list      List all organizations")
	fmt.Println("  org-show      Show organization details")
	fmt.Println("  org-delete    Delete an organization")
	fmt.Println("  oauth-test    Test OAuth configuration")
	fmt.Println("  db-status     Check database connection status")
	fmt.Println()
	fmt.Println("Use 'seed <command> -h' for command-specific help")
}

func (cli *CLI) createOrganization(args []string) {
	var (
		name         string
		slug         string
		description  string
		provider     string
		clientID     string
		clientSecret string
		tenantID     string
		redirectURL  string
	)

	fs := flag.NewFlagSet("org-create", flag.ExitOnError)
	fs.StringVar(&name, "name", "", "Organization name (required)")
	fs.StringVar(&slug, "slug", "", "Organization slug (required)")
	fs.StringVar(&description, "description", "", "Organization description")
	fs.StringVar(&provider, "provider", "", "OAuth provider type (microsoft, google, github)")
	fs.StringVar(&clientID, "client-id", "", "OAuth client ID")
	fs.StringVar(&clientSecret, "client-secret", "", "OAuth client secret")
	fs.StringVar(&tenantID, "tenant-id", "", "Tenant ID (for Microsoft)")
	fs.StringVar(&redirectURL, "redirect-url", "", "OAuth redirect URL")

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if name == "" || slug == "" {
		fmt.Println("Error: --name and --slug are required")
		fs.Usage()
		os.Exit(1)
	}

	// Check if organization already exists
	var existingOrg models.Organization
	if err := cli.db.Where("slug = ?", slug).First(&existingOrg).Error; err == nil {
		// Organization exists, update it
		existingOrg.Name = name
		existingOrg.Description = description
		existingOrg.UpdatedAt = time.Now()
		
		if err := cli.db.Save(&existingOrg).Error; err != nil {
			log.Fatalf("Failed to update organization: %v", err)
		}
		
		fmt.Printf("✅ Organization updated successfully!\n")
		fmt.Printf("   ID: %d\n", existingOrg.ID)
		fmt.Printf("   Name: %s\n", existingOrg.Name)
		fmt.Printf("   Slug: %s\n", existingOrg.Slug)
		
		// Add/update OAuth provider if specified
		if provider != "" && clientID != "" && clientSecret != "" {
			if err := cli.addOAuthProviderToOrg(existingOrg.ID, provider, clientID, clientSecret, tenantID, redirectURL); err != nil {
				log.Printf("Warning: Failed to add/update OAuth provider: %v", err)
			} else {
				fmt.Printf("\n✅ OAuth provider '%s' added/updated successfully!\n", provider)
				if redirectURL != "" {
					fmt.Printf("   Redirect URL: %s\n", redirectURL)
				} else {
					fmt.Printf("   Default Redirect URL: http://localhost:8080/api/oauth/callback/%s\n", provider)
				}
			}
		}
	} else {
		// Create new organization
		org := &models.Organization{
			Name:        name,
			Slug:        slug,
			Description: description,
			Settings:    models.JSON{},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		if err := cli.db.Create(org).Error; err != nil {
			log.Fatalf("Failed to create organization: %v", err)
		}

		fmt.Printf("✅ Organization created successfully!\n")
		fmt.Printf("   ID: %d\n", org.ID)
		fmt.Printf("   Name: %s\n", org.Name)
		fmt.Printf("   Slug: %s\n", org.Slug)

		// Add OAuth provider if specified
		if provider != "" && clientID != "" && clientSecret != "" {
			if err := cli.addOAuthProviderToOrg(org.ID, provider, clientID, clientSecret, tenantID, redirectURL); err != nil {
				log.Printf("Warning: Failed to add OAuth provider: %v", err)
			} else {
				fmt.Printf("\n✅ OAuth provider '%s' added successfully!\n", provider)
				if redirectURL != "" {
					fmt.Printf("   Redirect URL: %s\n", redirectURL)
				} else {
					fmt.Printf("   Default Redirect URL: http://localhost:8080/api/oauth/callback/%s\n", provider)
				}
			}
		}
	}
}

func (cli *CLI) createUser(args []string) {
	var (
		orgSlug   string
		email     string
		firstName string
		lastName  string
		role      string
		password  string
	)

	fs := flag.NewFlagSet("user-create", flag.ExitOnError)
	fs.StringVar(&orgSlug, "org-slug", "", "Organization slug (required)")
	fs.StringVar(&email, "email", "", "User email (required)")
	fs.StringVar(&firstName, "first-name", "", "User first name")
	fs.StringVar(&lastName, "last-name", "", "User last name")
	fs.StringVar(&role, "role", "user", "User role (admin, user)")
	fs.StringVar(&password, "password", "", "User password (optional, for local auth)")

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if orgSlug == "" || email == "" {
		fmt.Println("Error: --org-slug and --email are required")
		fs.Usage()
		os.Exit(1)
	}

	// Find organization
	var org models.Organization
	if err := cli.db.Where("slug = ?", orgSlug).First(&org).Error; err != nil {
		fmt.Printf("Error: Organization with slug '%s' not found\n", orgSlug)
		os.Exit(1)
	}

	// Check if user already exists (unique key is org_id + email)
	var existingUser models.User
	if err := cli.db.Where("email = ? AND organization_id = ?", email, org.ID).First(&existingUser).Error; err == nil {
		// User exists, update it
		if firstName != "" {
			existingUser.FirstName = firstName
		}
		if lastName != "" {
			existingUser.LastName = lastName
		}
		if role != "" {
			existingUser.Role = role
		}
		if password != "" {
			// In production, use proper password hashing
			existingUser.PasswordHash = fmt.Sprintf("hashed_%s", password)
		}
		existingUser.UpdatedAt = time.Now()
		
		if err := cli.db.Save(&existingUser).Error; err != nil {
			log.Fatalf("Failed to update user: %v", err)
		}
		
		fmt.Printf("✅ User updated successfully!\n")
		fmt.Printf("   ID: %d\n", existingUser.ID)
		fmt.Printf("   Email: %s\n", existingUser.Email)
		fmt.Printf("   Name: %s %s\n", existingUser.FirstName, existingUser.LastName)
		fmt.Printf("   Role: %s\n", existingUser.Role)
		fmt.Printf("   Organization: %s\n", org.Name)
	} else {
		// Create new user
		user := &models.User{
			Email:          email,
			FirstName:      firstName,
			LastName:       lastName,
			Role:           role,
			OrganizationID: org.ID,
			IsActive:       true,
			IsVerified:     true,
			Settings:       models.JSON{},
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}

		// Hash password if provided
		if password != "" {
			// In production, use proper password hashing
			user.PasswordHash = fmt.Sprintf("hashed_%s", password)
		}

		if err := cli.db.Create(user).Error; err != nil {
			log.Fatalf("Failed to create user: %v", err)
		}

		fmt.Printf("✅ User created successfully!\n")
		fmt.Printf("   ID: %d\n", user.ID)
		fmt.Printf("   Email: %s\n", user.Email)
		fmt.Printf("   Name: %s %s\n", user.FirstName, user.LastName)
		fmt.Printf("   Role: %s\n", user.Role)
		fmt.Printf("   Organization: %s\n", org.Name)
	}
}

func (cli *CLI) addOAuthProvider(args []string) {
	var (
		orgSlug      string
		provider     string
		clientID     string
		clientSecret string
		tenantID     string
		redirectURL  string
	)

	fs := flag.NewFlagSet("oauth-add", flag.ExitOnError)
	fs.StringVar(&orgSlug, "org-slug", "", "Organization slug (required)")
	fs.StringVar(&provider, "provider", "", "OAuth provider type (required)")
	fs.StringVar(&clientID, "client-id", "", "OAuth client ID (required)")
	fs.StringVar(&clientSecret, "client-secret", "", "OAuth client secret (required)")
	fs.StringVar(&tenantID, "tenant-id", "", "Tenant ID (for Microsoft)")
	fs.StringVar(&redirectURL, "redirect-url", "", "OAuth redirect URL")

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if orgSlug == "" || provider == "" || clientID == "" || clientSecret == "" {
		fmt.Println("Error: --org-slug, --provider, --client-id, and --client-secret are required")
		fs.Usage()
		os.Exit(1)
	}

	// Find organization
	var org models.Organization
	if err := cli.db.Where("slug = ?", orgSlug).First(&org).Error; err != nil {
		fmt.Printf("Error: Organization with slug '%s' not found\n", orgSlug)
		os.Exit(1)
	}

	if err := cli.addOAuthProviderToOrg(org.ID, provider, clientID, clientSecret, tenantID, redirectURL); err != nil {
		log.Fatalf("Failed to add/update OAuth provider: %v", err)
	}

	fmt.Printf("✅ OAuth provider '%s' added/updated successfully for organization '%s'!\n", provider, org.Name)
	if redirectURL != "" {
		fmt.Printf("   Redirect URL: %s\n", redirectURL)
	} else {
		fmt.Printf("   Default Redirect URL: http://localhost:8080/api/oauth/callback/%s\n", provider)
	}
}

func (cli *CLI) addOAuthProviderToOrg(orgID uint, provider, clientID, clientSecret, tenantID, redirectURL string) error {
	// Check if provider already exists
	var existingProvider models.OAuthProvider
	err := cli.db.Where("organization_id = ? AND provider_type = ?", orgID, provider).First(&existingProvider).Error
	
	isUpdate := err == nil // Provider exists, we'll update it

	// Encrypt credentials
	encryptedClientID, err := cli.encryption.Encrypt(clientID)
	if err != nil {
		return fmt.Errorf("failed to encrypt client ID: %w", err)
	}

	encryptedClientSecret, err := cli.encryption.Encrypt(clientSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt client secret: %w", err)
	}

	// Set default scopes based on provider
	scopes := cli.getDefaultScopes(provider)

	// Prepare additional config
	additionalConfig := models.JSON{}
	if redirectURL != "" {
		additionalConfig["redirect_url"] = redirectURL
	}

	// Convert tenant ID to pointer if provided
	var tenantIDPtr *string
	if tenantID != "" {
		tenantIDPtr = &tenantID
	}

	if isUpdate {
		// Update existing provider
		existingProvider.ClientID = encryptedClientID
		existingProvider.ClientSecret = encryptedClientSecret
		existingProvider.TenantID = tenantIDPtr
		existingProvider.AdditionalConfig = additionalConfig
		existingProvider.Scopes = scopes
		existingProvider.UpdatedAt = time.Now()
		
		return cli.db.Save(&existingProvider).Error
	} else {
		// Create new OAuth provider
		oauthProvider := &models.OAuthProvider{
			OrganizationID:   orgID,
			ProviderType:     models.ProviderType(provider),
			ClientID:         encryptedClientID,
			ClientSecret:     encryptedClientSecret,
			TenantID:         tenantIDPtr,
			AdditionalConfig: additionalConfig,
			Scopes:           scopes,
			Enabled:          true,
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		}

		return cli.db.Create(oauthProvider).Error
	}
}

func (cli *CLI) getDefaultScopes(provider string) []string {
	switch provider {
	case "microsoft":
		return []string{
			"User.Read",
			"Files.Read.All",
			"Sites.Read.All",
			"offline_access",
		}
	case "google":
		return []string{
			"openid",
			"email",
			"profile",
			"https://www.googleapis.com/auth/drive.readonly",
		}
	case "github":
		return []string{
			"user",
			"repo",
			"read:org",
		}
	default:
		return []string{}
	}
}

func (cli *CLI) listOrganizations() {
	var organizations []models.Organization
	if err := cli.db.Find(&organizations).Error; err != nil {
		log.Fatalf("Failed to list organizations: %v", err)
	}

	if len(organizations) == 0 {
		fmt.Println("No organizations found.")
		return
	}

	fmt.Println("Organizations:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-5s %-30s %-20s %-25s\n", "ID", "Name", "Slug", "Created At")
	fmt.Println(strings.Repeat("-", 80))

	for _, org := range organizations {
		// Count OAuth providers
		var providerCount int64
		cli.db.Model(&models.OAuthProvider{}).Where("organization_id = ?", org.ID).Count(&providerCount)

		// Count users
		var userCount int64
		cli.db.Model(&models.User{}).Where("organization_id = ?", org.ID).Count(&userCount)

		fmt.Printf("%-5d %-30s %-20s %-25s\n",
			org.ID,
			truncate(org.Name, 30),
			org.Slug,
			org.CreatedAt.Format("2006-01-02 15:04:05"),
		)
		fmt.Printf("      Users: %d, OAuth Providers: %d\n", userCount, providerCount)
	}
}

func (cli *CLI) showOrganization(args []string) {
	var slug string
	fs := flag.NewFlagSet("org-show", flag.ExitOnError)
	fs.StringVar(&slug, "slug", "", "Organization slug (required)")

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if slug == "" {
		fmt.Println("Error: --slug is required")
		fs.Usage()
		os.Exit(1)
	}

	// Find organization
	var org models.Organization
	if err := cli.db.Where("slug = ?", slug).First(&org).Error; err != nil {
		fmt.Printf("Error: Organization with slug '%s' not found\n", slug)
		os.Exit(1)
	}

	// Get OAuth providers
	var providers []models.OAuthProvider
	cli.db.Where("organization_id = ?", org.ID).Find(&providers)

	// Get users
	var users []models.User
	cli.db.Where("organization_id = ?", org.ID).Find(&users)

	fmt.Println("Organization Details:")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("ID:          %d\n", org.ID)
	fmt.Printf("Name:        %s\n", org.Name)
	fmt.Printf("Slug:        %s\n", org.Slug)
	fmt.Printf("Description: %s\n", org.Description)
	fmt.Printf("Created:     %s\n", org.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Updated:     %s\n", org.UpdatedAt.Format("2006-01-02 15:04:05"))

	fmt.Printf("\nOAuth Providers (%d):\n", len(providers))
	if len(providers) > 0 {
		fmt.Println(strings.Repeat("-", 60))
		for _, p := range providers {
			fmt.Printf("  • %s (ID: %d)\n", p.ProviderType, p.ID)
			fmt.Printf("    Enabled: %v\n", p.Enabled)
			if p.TenantID != nil && *p.TenantID != "" {
				fmt.Printf("    Tenant ID: %s\n", *p.TenantID)
			}
			fmt.Printf("    Scopes: %s\n", strings.Join(p.Scopes, ", "))
		}
	} else {
		fmt.Println("  No OAuth providers configured")
	}

	fmt.Printf("\nUsers (%d):\n", len(users))
	if len(users) > 0 {
		fmt.Println(strings.Repeat("-", 60))
		for _, u := range users {
			fmt.Printf("  • %s (ID: %d)\n", u.Email, u.ID)
			fmt.Printf("    Name: %s %s\n", u.FirstName, u.LastName)
			fmt.Printf("    Role: %s\n", u.Role)
			fmt.Printf("    Active: %v, Verified: %v\n", u.IsActive, u.IsVerified)
		}
	} else {
		fmt.Println("  No users found")
	}
}

func (cli *CLI) deleteOrganization(args []string) {
	var (
		slug    string
		confirm bool
	)

	fs := flag.NewFlagSet("org-delete", flag.ExitOnError)
	fs.StringVar(&slug, "slug", "", "Organization slug (required)")
	fs.BoolVar(&confirm, "confirm", false, "Confirm deletion")

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if slug == "" {
		fmt.Println("Error: --slug is required")
		fs.Usage()
		os.Exit(1)
	}

	if !confirm {
		fmt.Printf("Error: Please confirm deletion of organization '%s' with --confirm flag\n", slug)
		os.Exit(1)
	}

	// Find organization
	var org models.Organization
	if err := cli.db.Where("slug = ?", slug).First(&org).Error; err != nil {
		fmt.Printf("Error: Organization with slug '%s' not found\n", slug)
		os.Exit(1)
	}

	// Delete organization (cascade will handle related records)
	if err := cli.db.Delete(&org).Error; err != nil {
		log.Fatalf("Failed to delete organization: %v", err)
	}

	fmt.Printf("✅ Organization '%s' deleted successfully!\n", org.Name)
}

func (cli *CLI) testOAuth(args []string) {
	var (
		orgSlug  string
		provider string
	)

	fs := flag.NewFlagSet("oauth-test", flag.ExitOnError)
	fs.StringVar(&orgSlug, "org-slug", "", "Organization slug (required)")
	fs.StringVar(&provider, "provider", "", "OAuth provider type (required)")

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if orgSlug == "" || provider == "" {
		fmt.Println("Error: --org-slug and --provider are required")
		fs.Usage()
		os.Exit(1)
	}

	// Find organization
	var org models.Organization
	if err := cli.db.Where("slug = ?", orgSlug).First(&org).Error; err != nil {
		fmt.Printf("Error: Organization with slug '%s' not found\n", orgSlug)
		os.Exit(1)
	}

	// Find OAuth provider
	var oauthProvider models.OAuthProvider
	if err := cli.db.Where("organization_id = ? AND provider_type = ?", org.ID, provider).First(&oauthProvider).Error; err != nil {
		fmt.Printf("Error: OAuth provider '%s' not found for organization '%s'\n", provider, orgSlug)
		os.Exit(1)
	}

	fmt.Printf("OAuth Configuration Test:\n")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Organization: %s\n", org.Name)
	fmt.Printf("Provider:     %s\n", oauthProvider.ProviderType)
	fmt.Printf("Enabled:      %v\n", oauthProvider.Enabled)

	// Test decryption
	_, err := cli.encryption.Decrypt(oauthProvider.ClientID)
	if err != nil {
		fmt.Printf("❌ Failed to decrypt client ID: %v\n", err)
	} else {
		fmt.Printf("✅ Client ID encryption: OK\n")
	}

	_, err = cli.encryption.Decrypt(oauthProvider.ClientSecret)
	if err != nil {
		fmt.Printf("❌ Failed to decrypt client secret: %v\n", err)
	} else {
		fmt.Printf("✅ Client secret encryption: OK\n")
	}

	if oauthProvider.TenantID != nil && *oauthProvider.TenantID != "" {
		fmt.Printf("✅ Tenant ID configured: %s\n", *oauthProvider.TenantID)
	}

	fmt.Printf("\nScopes configured: %s\n", strings.Join(oauthProvider.Scopes, ", "))

	// Generate OAuth URL
	authURL, tokenURL := oauthProvider.GetOAuth2Endpoint()
	fmt.Printf("\nOAuth Endpoints:\n")
	fmt.Printf("  Auth URL:  %s\n", authURL)
	fmt.Printf("  Token URL: %s\n", tokenURL)

	redirectURL := fmt.Sprintf("http://localhost:8080/api/oauth/callback/%s", provider)
	if config, ok := oauthProvider.AdditionalConfig["redirect_url"]; ok {
		redirectURL = config.(string)
	}
	fmt.Printf("  Redirect:  %s\n", redirectURL)

	fmt.Printf("\n✅ OAuth configuration appears to be valid!\n")
	fmt.Printf("\nTo test the full OAuth flow:\n")
	fmt.Printf("1. Start the API server: make run\n")
	fmt.Printf("2. Get auth URL: curl http://localhost:8080/api/auth/%s/login -H \"X-Organization-Slug: %s\"\n", provider, orgSlug)
	fmt.Printf("3. Open the auth URL in your browser\n")
	fmt.Printf("4. Complete authentication\n")
	fmt.Printf("5. You'll be redirected to: %s\n", redirectURL)
}

func (cli *CLI) checkDatabaseStatus() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sqlDB, err := cli.db.DB()
	if err != nil {
		fmt.Printf("❌ Failed to get database connection: %v\n", err)
		os.Exit(1)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		fmt.Printf("❌ Database connection failed: %v\n", err)
		os.Exit(1)
	}

	// Get database stats
	stats := sqlDB.Stats()

	fmt.Println("Database Status:")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("✅ Connection: OK\n")
	fmt.Printf("   Open Connections:    %d\n", stats.OpenConnections)
	fmt.Printf("   In Use:              %d\n", stats.InUse)
	fmt.Printf("   Idle:                %d\n", stats.Idle)
	fmt.Printf("   Max Open Connections: %d\n", stats.MaxOpenConnections)

	// Check tables
	var tables []string
	cli.db.Raw("SELECT tablename FROM pg_tables WHERE schemaname = 'public'").Scan(&tables)
	fmt.Printf("\nTables (%d):\n", len(tables))
	for _, table := range tables {
		var count int64
		cli.db.Table(table).Count(&count)
		fmt.Printf("  • %-30s %d records\n", table, count)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}