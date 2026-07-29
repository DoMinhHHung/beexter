package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPPort               = 8080
	defaultHTTPShutdownTimeout    = 10 * time.Second
	defaultDatabaseConnectTimeout = 5 * time.Second
	defaultRedisConnectTimeout    = 3 * time.Second
	defaultRedisDB                = 0
)

type Config struct {
	HTTP       HTTPConfig
	PostgreSQL PostgreSQLConfig
	Redis      RedisConfig
}

type HTTPConfig struct {
	Addr            string
	ShutdownTimeout time.Duration
}

type PostgreSQLConfig struct {
	URL            string
	ConnectTimeout time.Duration
}

type RedisConfig struct {
	Addr           string
	Username       string
	Password       string
	DB             int
	ConnectTimeout time.Duration
}

func Load() (Config, error) {
	httpPort, err := readInt("HTTP_PORT", defaultHTTPPort)
	if err != nil {
		return Config{}, fmt.Errorf("read HTTP_PORT: %w", err)
	}

	if httpPort < 1 || httpPort > 65535 {
		return Config{}, fmt.Errorf("HTTP_PORT must be between 1 and 65535")
	}

	shutdownTimeout, err := readDuration(
		"HTTP_SHUTDOWN_TIMEOUT",
		defaultHTTPShutdownTimeout,
	)
	if err != nil {
		return Config{}, fmt.Errorf("read HTTP_SHUTDOWN_TIMEOUT: %w", err)
	}

	if shutdownTimeout <= 0 {
		return Config{}, fmt.Errorf(
			"HTTP_SHUTDOWN_TIMEOUT must be greater than zero",
		)
	}

	databaseURL, err := requiredString("DATABASE_URL")
	if err != nil {
		return Config{}, err
	}

	databaseConnectTimeout, err := readDuration(
		"DATABASE_CONNECT_TIMEOUT",
		defaultDatabaseConnectTimeout,
	)
	if err != nil {
		return Config{}, fmt.Errorf("read DATABASE_CONNECT_TIMEOUT: %w", err)
	}

	if databaseConnectTimeout <= 0 {
		return Config{}, fmt.Errorf(
			"DATABASE_CONNECT_TIMEOUT must be greater than zero",
		)
	}

	redisAddr, err := requiredString("REDIS_ADDR")
	if err != nil {
		return Config{}, err
	}

	redisDB, err := readInt("REDIS_DB", defaultRedisDB)
	if err != nil {
		return Config{}, fmt.Errorf("read REDIS_DB: %w", err)
	}

	if redisDB < 0 {
		return Config{}, fmt.Errorf("REDIS_DB must not be negative")
	}

	redisConnectTimeout, err := readDuration(
		"REDIS_CONNECT_TIMEOUT",
		defaultRedisConnectTimeout,
	)
	if err != nil {
		return Config{}, fmt.Errorf("read REDIS_CONNECT_TIMEOUT: %w", err)
	}

	if redisConnectTimeout <= 0 {
		return Config{}, fmt.Errorf(
			"REDIS_CONNECT_TIMEOUT must be greater than zero",
		)
	}

	return Config{
		HTTP: HTTPConfig{
			Addr:            fmt.Sprintf(":%d", httpPort),
			ShutdownTimeout: shutdownTimeout,
		},
		PostgreSQL: PostgreSQLConfig{
			URL:            databaseURL,
			ConnectTimeout: databaseConnectTimeout,
		},
		Redis: RedisConfig{
			Addr:           redisAddr,
			Username:       strings.TrimSpace(os.Getenv("REDIS_USERNAME")),
			Password:       os.Getenv("REDIS_PASSWORD"),
			DB:             redisDB,
			ConnectTimeout: redisConnectTimeout,
		},
	}, nil
}

func requiredString(key string) (string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}

	return value, nil
}

func readInt(key string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
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
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", key, err)
	}

	return parsed, nil
}
