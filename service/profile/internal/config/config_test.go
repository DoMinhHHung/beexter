package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLoadValidConfiguration(t *testing.T) {
	t.Parallel()

	values := validEnvironment()
	values["POSTGRES_CONNECT_TIMEOUT"] = "3s"
	values["POSTGRES_OPERATION_TIMEOUT"] = "750ms"
	values["HTTP_SHUTDOWN_TIMEOUT"] = "12s"
	values["LOG_LEVEL"] = "debug"

	cfg, err := Load(mapLookup(values))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTP.Addr != "127.0.0.1:8080" {
		t.Fatalf("HTTP address = %q", cfg.HTTP.Addr)
	}
	if cfg.HTTP.ShutdownTimeout != 12*time.Second {
		t.Fatalf("shutdown timeout = %s", cfg.HTTP.ShutdownTimeout)
	}
	if cfg.PostgreSQL.ConnectTimeout != 3*time.Second {
		t.Fatalf("connect timeout = %s", cfg.PostgreSQL.ConnectTimeout)
	}
	if cfg.PostgreSQL.OperationTimeout != 750*time.Millisecond {
		t.Fatalf("operation timeout = %s", cfg.PostgreSQL.OperationTimeout)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Fatalf("log level = %s", cfg.LogLevel)
	}
}

func TestLoadUsesSafeDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load(mapLookup(validEnvironment()))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.PostgreSQL.ConnectTimeout != defaultPostgreSQLConnectTimeout {
		t.Fatalf("connect timeout = %s", cfg.PostgreSQL.ConnectTimeout)
	}
	if cfg.PostgreSQL.OperationTimeout != defaultPostgreSQLOperationTimeout {
		t.Fatalf("operation timeout = %s", cfg.PostgreSQL.OperationTimeout)
	}
	if cfg.HTTP.ShutdownTimeout != defaultHTTPShutdownTimeout {
		t.Fatalf("shutdown timeout = %s", cfg.HTTP.ShutdownTimeout)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Fatalf("log level = %s", cfg.LogLevel)
	}
}

func TestLoadRequiresStartupConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  string
	}{
		{name: "HTTP address", key: "HTTP_ADDR"},
		{name: "PostgreSQL URL", key: "DATABASE_DIRECT_URL"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values := validEnvironment()
			delete(values, test.key)

			_, err := Load(mapLookup(values))
			if err == nil || !strings.Contains(err.Error(), test.key+" is required") {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}

func TestLoadRejectsInvalidDurationsAndBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "malformed connect timeout", key: "POSTGRES_CONNECT_TIMEOUT", value: "soon"},
		{name: "connect timeout too small", key: "POSTGRES_CONNECT_TIMEOUT", value: "10ms"},
		{name: "connect timeout too large", key: "POSTGRES_CONNECT_TIMEOUT", value: "2m"},
		{name: "operation timeout too small", key: "POSTGRES_OPERATION_TIMEOUT", value: "1ms"},
		{name: "operation timeout too large", key: "POSTGRES_OPERATION_TIMEOUT", value: "11s"},
		{name: "shutdown timeout too small", key: "HTTP_SHUTDOWN_TIMEOUT", value: "500ms"},
		{name: "shutdown timeout too large", key: "HTTP_SHUTDOWN_TIMEOUT", value: "3m"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values := validEnvironment()
			values[test.key] = test.value

			_, err := Load(mapLookup(values))
			if err == nil || !strings.Contains(err.Error(), test.key) {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}

func TestLoadRejectsInvalidAddressAndLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "HTTP address", key: "HTTP_ADDR", value: "localhost"},
		{name: "HTTP port", key: "HTTP_ADDR", value: "localhost:70000"},
		{name: "log level", key: "LOG_LEVEL", value: "verbose"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values := validEnvironment()
			values[test.key] = test.value

			if _, err := Load(mapLookup(values)); err == nil {
				t.Fatal("Load() error = nil")
			}
		})
	}
}

func TestLoadDoesNotExposeDatabaseCredentials(t *testing.T) {
	t.Parallel()

	values := validEnvironment()
	values["DATABASE_DIRECT_URL"] = "postgres://profile:super-secret@localhost"

	_, err := Load(mapLookup(values))
	if err == nil {
		t.Fatal("Load() error = nil")
	}
	if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), values["DATABASE_DIRECT_URL"]) {
		t.Fatalf("error exposes database credentials: %v", err)
	}
}

func validEnvironment() map[string]string {
	return map[string]string{
		"HTTP_ADDR":           "127.0.0.1:8080",
		"DATABASE_DIRECT_URL": "postgres://profile:secret@127.0.0.1:5432/profile?sslmode=disable",
	}
}

func mapLookup(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
