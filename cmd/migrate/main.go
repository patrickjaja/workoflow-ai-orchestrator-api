package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/workoflow/ai-orchestrator-api/internal/config"
	"github.com/workoflow/ai-orchestrator-api/internal/database"
)

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found: %v", err)
	}

	// Parse command line arguments
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	command := args[0]

	switch command {
	case "up":
		runMigrations(cfg.Database.URL)
	case "create":
		if len(args) < 2 {
			fmt.Println("Error: migration name required")
			fmt.Println("Usage: go run cmd/migrate/main.go create <migration_name>")
			os.Exit(1)
		}
		createMigration(args[1])
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func runMigrations(databaseURL string) {
	fmt.Println("Running database migrations...")
	
	if err := database.RunMigrations(databaseURL); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	
	fmt.Println("Migrations completed successfully!")
}

func createMigration(name string) {
	fmt.Printf("Creating migration: %s\n", name)
	
	if err := database.CreateMigration(name); err != nil {
		log.Fatalf("Failed to create migration: %v", err)
	}
}

func printUsage() {
	fmt.Println(`Usage: go run cmd/migrate/main.go <command> [arguments]

Commands:
  up                Run all pending migrations
  create <name>     Create a new migration with the specified name

Examples:
  go run cmd/migrate/main.go up
  go run cmd/migrate/main.go create add_users_table`)
}