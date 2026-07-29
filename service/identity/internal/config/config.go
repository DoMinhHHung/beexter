package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	defaultHTTPPort        = 8080
	defaultShutdownTimeout = 10 * time.Second
)

type Config struct {
	HTTPAddr        string
	ShutdownTimeout time.Duration
}

func Load() (Config, error) {
	port, err := readInt("HTTP_PORT", defaultHTTPPort)
	if err != nil {
		return Config{}, fmt.Errorf("read HTTP_PORT: %w", err)
	}

	if port < 1 || port > 65535 {
		return Config{}, fmt.Errorf("HTTP_PORT must be between 1 and 65535")
	}

	shutdownTimeout, err := readDuration(
		"HTTP_SHUTDOWN_TIMEOUT",
		defaultShutdownTimeout,
	)
	if err != nil {
		return Config{}, fmt.Errorf("read HTTP_SHUTDOWN_TIMEOUT: %w", err)
	}

	if shutdownTimeout <= 0 {
		return Config{}, fmt.Errorf("HTTP_SHUTDOWN_TIMEOUT must be greater than zero")
	}

	return Config{
		HTTPAddr:        fmt.Sprintf(":%d", port),
		ShutdownTimeout: shutdownTimeout,
	}, nil
}

func readInt(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}

	return parsed, nil
}

func readDuration(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", key, err)
	}

	return parsed, nil
}
