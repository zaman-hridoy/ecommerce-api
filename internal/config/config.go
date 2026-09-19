package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type config struct {
	Port string
	DatabaseURL string
	Env string
}

func MustLoad() *config {
	// .env is optional.
	_ = godotenv.Load()

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	env := os.Getenv("ENV")
	if env == "" {
		log.Fatal("ENV is required")
	}

	return &config{
		Port: port,
		DatabaseURL: databaseURL,
		Env: env,
	}
}