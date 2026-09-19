package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/zaman-hridoy/ecommerce-api/internal/config"
)


func main() {
	direction := flag.String(
		"direction",
		"up",
		"migration direction: up or down",
	)

	forceVersion := flag.Int("force", -1, "force migration version without running migrations")

	flag.Parse()

	cfg := config.MustLoad()

	m, err := migrate.New(
		"file://migrations",
		cfg.DatabaseURL,
	)

	if err != nil {
		log.Fatalf("create migrate instance: %v", err)
	}

	defer func() {
		sourceErr, dbErr := m.Close()

		if sourceErr != nil {
			log.Printf("close migration source: %v", sourceErr)
		}

		if dbErr != nil {
			log.Printf("close migration database: %v", dbErr)
		}
	}()


	if *forceVersion >= 0 {
		if err := m.Force(*forceVersion); err != nil {
			log.Fatalf("force migration version: %v", err)
		}

		fmt.Printf("migration version forced to %d\n", *forceVersion)
		return
	}

	switch *direction {
	case "up":
		if err := m.Up(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				fmt.Println("no migrations to apply")
				return
			}

			log.Fatalf("run migrations: %v", err)
		}

		fmt.Println("migrations applied successfully")

	case "down":
		if err := m.Steps(-1); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				fmt.Println("no migration to rollback")
				return
			}

			log.Fatalf("rollback migration: %v", err)
		}

		fmt.Println("migration rolled back successfully")
	
	default:
		fmt.Fprintf(os.Stderr, "invalid direction: %s\n", *direction)
		os.Exit(1)
	}
}