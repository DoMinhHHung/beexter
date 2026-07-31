package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPostgreSQLConnectTimeout   = 5 * time.Second
	defaultPostgreSQLOperationTimeout = 2 * time.Second
	defaultHTTPShutdownTimeout        = 10 * time.Second

	minimumConnectTimeout   = 100 * time.Millisecond
	maximumConnectTimeout   = time.Minute
	minimumOperationTimeout = 50 * time.Millisecond
	maximumOperationTimeout = 10 * time.Second
	minimumShutdownTimeout  = time.Second
	maximumShutdownTimeout  = 2 * time.Minute
)

type LookupEnv func(string) (string, bool)

type Config struct {
	HTTP       HTTPConfig
	PostgreSQL PostgreSQLConfig
	LogLevel   slog.Level
}

type HTTPConfig struct {
	Addr            string
	ShutdownTimeout time.Duration
}

type PostgreSQLConfig struct {
	URL              string
	ConnectTimeout   time.Duration
	OperationTimeout time.Duration
}

func LoadFromEnv() (Config, error) {
	return Load(os.LookupEnv)
}

func Load(lookup LookupEnv) (Config, error) {
	if lookup == nil {
		return Config{}, fmt.Errorf("environment lookup is required")
	}

	httpAddr, err := requiredString(lookup, "HTTP_ADDR")
	if err != nil {
		return Config{}, err
	}
	if err := validateHTTPAddr(httpAddr); err != nil {
		return Config{}, err
	}

	databaseURL, err := requiredString(lookup, "DATABASE_DIRECT_URL")
	if err != nil {
		return Config{}, err
	}
	if err := validateDatabaseURL(databaseURL); err != nil {
		return Config{}, err
	}

	connectTimeout, err := duration(
		lookup,
		"POSTGRES_CONNECT_TIMEOUT",
		defaultPostgreSQLConnectTimeout,
		minimumConnectTimeout,
		maximumConnectTimeout,
	)
	if err != nil {
		return Config{}, err
	}

	operationTimeout, err := duration(
		lookup,
		"POSTGRES_OPERATION_TIMEOUT",
		defaultPostgreSQLOperationTimeout,
		minimumOperationTimeout,
		maximumOperationTimeout,
	)
	if err != nil {
		return Config{}, err
	}

	shutdownTimeout, err := duration(
		lookup,
		"HTTP_SHUTDOWN_TIMEOUT",
		defaultHTTPShutdownTimeout,
		minimumShutdownTimeout,
		maximumShutdownTimeout,
	)
	if err != nil {
		return Config{}, err
	}

	logLevel, err := parseLogLevel(lookup)
	if err != nil {
		return Config{}, err
	}

	return Config{
		HTTP: HTTPConfig{
			Addr:            httpAddr,
			ShutdownTimeout: shutdownTimeout,
		},
		PostgreSQL: PostgreSQLConfig{
			URL:              databaseURL,
			ConnectTimeout:   connectTimeout,
			OperationTimeout: operationTimeout,
		},
		LogLevel: logLevel,
	}, nil
}

func requiredString(lookup LookupEnv, key string) (string, error) {
	value, ok := lookup(key)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return value, nil
}

func validateHTTPAddr(addr string) error {
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("HTTP_ADDR must use host:port format")
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("HTTP_ADDR port must be between 1 and 65535")
	}
	return nil
}

func validateDatabaseURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("DATABASE_DIRECT_URL is invalid")
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return fmt.Errorf("DATABASE_DIRECT_URL must use postgres or postgresql scheme")
	}
	if parsed.Host == "" || strings.Trim(parsed.Path, "/") == "" {
		return fmt.Errorf("DATABASE_DIRECT_URL must include host and database name")
	}
	return nil
}

func duration(
	lookup LookupEnv,
	key string,
	defaultValue time.Duration,
	minimum time.Duration,
	maximum time.Duration,
) (time.Duration, error) {
	value, ok := lookup(key)
	if !ok || strings.TrimSpace(value) == "" {
		return defaultValue, nil
	}

	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration", key)
	}
	if parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf(
			"%s must be between %s and %s",
			key,
			minimum,
			maximum,
		)
	}
	return parsed, nil
}

func parseLogLevel(lookup LookupEnv) (slog.Level, error) {
	value, ok := lookup("LOG_LEVEL")
	if !ok || strings.TrimSpace(value) == "" {
		return slog.LevelInfo, nil
	}

	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("LOG_LEVEL must be debug, info, warn, or error")
	}
}
