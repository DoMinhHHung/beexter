package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	defaultHTTPAddr        = ":8080"
	defaultLogLevel        = "INFO"
	defaultShutdownTimeout = 10 * time.Second
)

type Config struct {
	HTTPAddr        string
	LogLevel        string
	ShutdownTimeout time.Duration
}

func Load() (Config, error) {
	shutdownTimeout, err := positiveDuration("SHUTDOWN_TIMEOUT", defaultShutdownTimeout)
	if err != nil {
		return Config{}, err
	}

	logLevel := strings.ToUpper(valueOrDefault("LOG_LEVEL", defaultLogLevel))
	switch logLevel {
	case "DEBUG", "INFO", "WARN", "ERROR":
	default:
		return Config{}, fmt.Errorf("LOG_LEVEL must be one of DEBUG, INFO, WARN, ERROR")
	}

	return Config{
		HTTPAddr:        valueOrDefault("HTTP_ADDR", defaultHTTPAddr),
		LogLevel:        logLevel,
		ShutdownTimeout: shutdownTimeout,
	}, nil
}

func valueOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func positiveDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}

	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	return value, nil
}
