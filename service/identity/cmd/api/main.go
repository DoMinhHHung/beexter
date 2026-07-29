package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/config"
	"github.com/DoMinhHHung/beexter/service/identity/internal/httpapi"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/postgres"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/redisclient"
)

func main() {
	logger := slog.New(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}),
	)

	if err := run(logger); err != nil {
		logger.Error(
			"application stopped unexpectedly",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	applicationContext, stopSignal := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stopSignal()

	databaseContext, cancelDatabase := context.WithTimeout(
		applicationContext,
		cfg.PostgreSQL.ConnectTimeout,
	)

	database, err := postgres.Open(
		databaseContext,
		cfg.PostgreSQL.URL,
	)
	cancelDatabase()

	if err != nil {
		return fmt.Errorf("open PostgreSQL: %w", err)
	}
	defer database.Close()

	redisContext, cancelRedis := context.WithTimeout(
		applicationContext,
		cfg.Redis.ConnectTimeout,
	)

	cache, err := redisclient.Open(redisContext, cfg.Redis)
	cancelRedis()

	if err != nil {
		return fmt.Errorf("open Redis: %w", err)
	}

	defer func() {
		if err := cache.Close(); err != nil {
			logger.Warn(
				"failed to close Redis client",
				slog.String("error", err.Error()),
			)
		}
	}()

	handler := httpapi.NewRouter(logger, database, cache)

	server := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverError := make(chan error, 1)

	go func() {
		logger.Info(
			"http server started",
			slog.String("address", server.Addr),
		)

		serverError <- server.ListenAndServe()
	}()

	select {
	case <-applicationContext.Done():
		stopSignal()
		logger.Info("shutdown signal received")

	case err := <-serverError:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return fmt.Errorf("serve HTTP: %w", err)
	}

	shutdownContext, cancelShutdown := context.WithTimeout(
		context.Background(),
		cfg.HTTP.ShutdownTimeout,
	)
	defer cancelShutdown()

	if err := server.Shutdown(shutdownContext); err != nil {
		closeErr := server.Close()
		if closeErr != nil {
			return errors.Join(
				fmt.Errorf("shutdown HTTP server: %w", err),
				fmt.Errorf("force close HTTP server: %w", closeErr),
			)
		}

		return fmt.Errorf("shutdown HTTP server: %w", err)
	}

	serveErr := <-serverError
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("HTTP server stopped unexpectedly: %w", serveErr)
	}

	logger.Info("http server stopped gracefully")

	return nil
}
