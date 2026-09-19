package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/zaman-hridoy/ecommerce-api/internal/auth"
	"github.com/zaman-hridoy/ecommerce-api/internal/config"
	"github.com/zaman-hridoy/ecommerce-api/internal/db"
	"github.com/zaman-hridoy/ecommerce-api/internal/handlers"
	"github.com/zaman-hridoy/ecommerce-api/internal/user"
)

func main() {
	cfg := config.MustLoad()

	logger := slog.New(
		slog.NewJSONHandler(
			os.Stdout,
			&slog.HandlerOptions{
				Level: slog.LevelInfo,
				AddSource: true,
			},
		),
	)

	slog.SetDefault(logger)

	database, err := db.Connect(cfg.DatabaseURL)
	if err != nil {
		logger.Error("failed to connect database", "error", err)
		os.Exit(1)
	}

	defer database.Close()
	logger.Info("Database connected.")

	userRepo := user.NewRepository(database)
	sessionRepo := auth.NewSessionRepository(database)
	refresRepo := auth.NewRefreshRepository(database)
	authService := auth.NewService(userRepo, sessionRepo, refresRepo)
	authHandler := auth.NewHandler(authService, logger, cfg.Env == "production")
	userHandler := user.NewHandler(userRepo, logger)


	//mux
	mux := http.NewServeMux()

	// routes
	mux.HandleFunc("GET /api/v1/health", handlers.Health)

	// auth routes
	mux.HandleFunc("POST /api/v1/auth/register", authHandler.Register)
	mux.HandleFunc("POST /api/v1/auth/login", authHandler.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", authHandler.Refresh)
	mux.Handle("POST /api/v1/auth/logout", authService.Middleware(
		http.HandlerFunc(authHandler.Logout),
	))
	mux.Handle("GET /api/v1/me", authService.Middleware(http.HandlerFunc(userHandler.Me)))


	server := http.Server{
		Addr: ":" + cfg.Port,
		Handler: mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout: 60 * time.Second,
	}


	// start server
	logger.Info("Server is running", "port: ", cfg.Port)
	if err := server.ListenAndServe(); err != nil {
		logger.Error("server stopped", "error", err)
	}
}