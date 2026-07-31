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

	"github.com/DoMinhHHung/beexster/service/profile/internal/config"
	"github.com/DoMinhHHung/beexster/service/profile/internal/httpapi"
	"github.com/DoMinhHHung/beexster/service/profile/internal/platform/postgres"
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 15 * time.Second
	httpWriteTimeout      = 15 * time.Second
	httpIdleTimeout       = 60 * time.Second
	httpMaxHeaderBytes    = 1 << 20
)

func main() {
	if err := run(); err != nil {
		bootstrapLogger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		bootstrapLogger.Error(
			"profile service stopped",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	applicationContext, stopApplication := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stopApplication()

	connectContext, cancelConnect := context.WithTimeout(
		applicationContext,
		cfg.PostgreSQL.ConnectTimeout,
	)
	pool, err := postgres.Open(connectContext, cfg.PostgreSQL.URL)
	cancelConnect()
	if err != nil {
		return fmt.Errorf("initialize PostgreSQL: %w", err)
	}
	defer pool.Close()

	handler, err := httpapi.New(
		logger,
		pool,
		cfg.PostgreSQL.OperationTimeout,
	)
	if err != nil {
		return fmt.Errorf("construct HTTP API: %w", err)
	}

	server := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("profile service listening", slog.String("addr", cfg.HTTP.Addr))
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-applicationContext.Done():
	}

	shutdownContext, cancelShutdown := context.WithTimeout(
		context.Background(),
		cfg.HTTP.ShutdownTimeout,
	)
	defer cancelShutdown()

	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}

	if err := <-serverErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP during shutdown: %w", err)
	}

	logger.Info("profile service stopped gracefully")
	return nil
}
