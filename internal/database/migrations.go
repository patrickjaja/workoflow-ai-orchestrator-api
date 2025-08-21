package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

func RunMigrations(databaseURL string) error {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return fmt.Errorf("failed to open database connection: %w", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	migrationsPath := filepath.Join(pwd, "migrations")
	
	if _, err := os.Stat(migrationsPath); os.IsNotExist(err) {
		if err := os.MkdirAll(migrationsPath, 0755); err != nil {
			return fmt.Errorf("failed to create migrations directory: %w", err)
		}
	}

	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", migrationsPath),
		"postgres",
		driver,
	)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

func CreateMigration(name string) error {
	pwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	migrationsPath := filepath.Join(pwd, "migrations")
	
	if _, err := os.Stat(migrationsPath); os.IsNotExist(err) {
		if err := os.MkdirAll(migrationsPath, 0755); err != nil {
			return fmt.Errorf("failed to create migrations directory: %w", err)
		}
	}

	timestamp := time.Now().Unix()
	upFile := filepath.Join(migrationsPath, fmt.Sprintf("%d_%s.up.sql", timestamp, name))
	downFile := filepath.Join(migrationsPath, fmt.Sprintf("%d_%s.down.sql", timestamp, name))

	if err := os.WriteFile(upFile, []byte("-- Add your UP migration here\n"), 0644); err != nil {
		return fmt.Errorf("failed to create up migration file: %w", err)
	}

	if err := os.WriteFile(downFile, []byte("-- Add your DOWN migration here\n"), 0644); err != nil {
		return fmt.Errorf("failed to create down migration file: %w", err)
	}

	fmt.Printf("Created migration files:\n  %s\n  %s\n", upFile, downFile)
	return nil
}