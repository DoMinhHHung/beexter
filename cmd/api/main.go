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

	"github.com/DoMinhHHung/beexter/internal/config"
	"github.com/DoMinhHHung/beexter/internal/transport/httpapi"
)

var errDependenciesNotConfigured = errors.New("database and redis checks are not configured")

func main() {
	if err := run(); err != nil {
		slog.Error("application stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.LogLevel),
	}))
	slog.SetDefault(logger)

	handler := httpapi.NewHandler(func(context.Context) error {
		return errDependenciesNotConfigured
	})

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("http server starting", "addr", cfg.HTTPAddr)
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-signalCtx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		shutdownErr := fmt.Errorf("graceful HTTP shutdown: %w", err)
		if closeErr := server.Close(); closeErr != nil {
			return errors.Join(shutdownErr, fmt.Errorf("force close HTTP server: %w", closeErr))
		}
		return shutdownErr
	}

	if err := <-serverErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP server stopped unexpectedly: %w", err)
	}

	logger.Info("http server stopped")
	return nil
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
