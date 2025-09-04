package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dimajoyti/hackai/pkg/config"
	"github.com/dimajoyti/hackai/pkg/database"
	"github.com/dimajoyti/hackai/pkg/logger"
)

func main() {
	var (
		command = flag.String("command", "migrate", "Command to run: migrate, rollback, status, create")
		version = flag.String("version", "", "Target version for rollback")
		name    = flag.String("name", "", "Migration name for create command")
		help    = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log, err := logger.New(logger.Config{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	})
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	// Connect to database
	db, err := database.New(&cfg.Database, log)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Create migration manager
	migrationManager := database.NewMigrationManager(db.DB, log)

	// Execute command
	switch *command {
	case "migrate":
		if err := runMigrations(migrationManager); err != nil {
			fmt.Printf("Migration failed: %v\n", err)
			os.Exit(1)
		}
	case "rollback":
		if *version == "" {
			fmt.Println("Version is required for rollback command")
			os.Exit(1)
		}
		if err := rollbackToVersion(migrationManager, *version); err != nil {
			fmt.Printf("Rollback failed: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := showStatus(migrationManager); err != nil {
			fmt.Printf("Failed to get status: %v\n", err)
			os.Exit(1)
		}
	case "create":
		if *name == "" {
			fmt.Println("Name is required for create command")
			os.Exit(1)
		}
		if err := createMigration(*name); err != nil {
			fmt.Printf("Failed to create migration: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", *command)
		showHelp()
		os.Exit(1)
	}
}

func showHelp() {
	fmt.Println("Database Migration Tool")
	fmt.Println("Usage: database-migration [options]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  migrate   - Run all pending migrations")
	fmt.Println("  rollback  - Rollback to a specific version")
	fmt.Println("  status    - Show migration status")
	fmt.Println("  create    - Create a new migration file")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -command string")
	fmt.Println("        Command to run (default \"migrate\")")
	fmt.Println("  -version string")
	fmt.Println("        Target version for rollback")
	fmt.Println("  -name string")
	fmt.Println("        Migration name for create command")
	fmt.Println("  -help")
	fmt.Println("        Show this help message")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  database-migration -command migrate")
	fmt.Println("  database-migration -command rollback -version 002")
	fmt.Println("  database-migration -command status")
	fmt.Println("  database-migration -command create -name \"add_user_preferences\"")
}

func runMigrations(manager *database.MigrationManager) error {
	fmt.Println("Running database migrations...")

	if err := manager.RunMigrations(); err != nil {
		return err
	}

	fmt.Println("✅ All migrations completed successfully")
	return nil
}

func rollbackToVersion(manager *database.MigrationManager, version string) error {
	fmt.Printf("Rolling back to version %s...\n", version)

	if err := manager.RollbackToVersion(version); err != nil {
		return err
	}

	fmt.Printf("✅ Successfully rolled back to version %s\n", version)
	return nil
}

func showStatus(manager *database.MigrationManager) error {
	fmt.Println("Migration Status")
	fmt.Println("================")

	status, err := manager.GetMigrationStatus()
	if err != nil {
		return err
	}

	fmt.Printf("Current Version: %v\n", status["current_version"])
	fmt.Printf("Applied Migrations: %v\n", status["applied_count"])
	fmt.Printf("Pending Migrations: %v\n", status["pending_count"])

	if lastMigration := status["last_migration_at"]; lastMigration != nil {
		if t, ok := lastMigration.(*time.Time); ok {
			fmt.Printf("Last Migration: %s\n", t.Format("2006-01-02 15:04:05"))
		}
	}

	if pending := status["pending_migrations"]; pending != nil {
		if versions, ok := pending.([]string); ok && len(versions) > 0 {
			fmt.Println("\nPending Migrations:")
			for _, version := range versions {
				fmt.Printf("  - %s\n", version)
			}
		}
	}

	// Get detailed migration list
	applied, err := manager.GetAppliedMigrations()
	if err != nil {
		return err
	}

	if len(applied) > 0 {
		fmt.Println("\nApplied Migrations:")
		for _, migration := range applied {
			appliedAt := "Unknown"
			if migration.AppliedAt != nil {
				appliedAt = migration.AppliedAt.Format("2006-01-02 15:04:05")
			}
			fmt.Printf("  ✅ %s - %s (applied: %s)\n", migration.Version, migration.Name, appliedAt)
		}
	}

	pending, err := manager.GetPendingMigrations()
	if err != nil {
		return err
	}

	if len(pending) > 0 {
		fmt.Println("\nPending Migrations:")
		for _, migration := range pending {
			fmt.Printf("  ⏳ %s - %s\n", migration.Version, migration.Name)
		}
	}

	return nil
}

func createMigration(name string) error {
	// Generate version number based on current time
	version := time.Now().Format("20060102150405")

	// Create migration file content
	content := fmt.Sprintf(`-- Migration: %s
-- Version: %s
-- Created: %s

-- Up migration
-- Add your SQL statements here

-- Down migration (rollback)
-- Add rollback SQL statements here
`, name, version, time.Now().Format("2006-01-02 15:04:05"))

	// Create migrations directory if it doesn't exist
	if err := os.MkdirAll("migrations", 0755); err != nil {
		return fmt.Errorf("failed to create migrations directory: %w", err)
	}

	// Write migration file
	filename := fmt.Sprintf("migrations/%s_%s.sql", version, name)
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write migration file: %w", err)
	}

	fmt.Printf("✅ Created migration file: %s\n", filename)
	fmt.Println("Please edit the file to add your SQL statements.")

	return nil
}
