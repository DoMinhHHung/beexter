package config

import (
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("APP_ENV", "")
	t.Setenv("HTTP_ADDRESS", "")
	t.Setenv("HTTP_READ_HEADER_TIMEOUT", "")
	t.Setenv("HTTP_READ_TIMEOUT", "")
	t.Setenv("HTTP_WRITE_TIMEOUT", "")
	t.Setenv("HTTP_IDLE_TIMEOUT", "")
	t.Setenv("HTTP_SHUTDOWN_TIMEOUT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Environment != defaultEnvironment {
		t.Fatalf("Environment = %q, want %q", cfg.Environment, defaultEnvironment)
	}
	if cfg.HTTP.Address != defaultHTTPAddress {
		t.Fatalf("HTTP.Address = %q, want %q", cfg.HTTP.Address, defaultHTTPAddress)
	}
	if cfg.HTTP.ShutdownTimeout != defaultShutdownTimeout {
		t.Fatalf("HTTP.ShutdownTimeout = %s, want %s", cfg.HTTP.ShutdownTimeout, defaultShutdownTimeout)
	}
}

func TestLoad_RejectsInvalidDuration(t *testing.T) {
	t.Setenv("HTTP_READ_TIMEOUT", "invalid")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoad_ReadsDuration(t *testing.T) {
	t.Setenv("HTTP_READ_TIMEOUT", "3s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTP.ReadTimeout != 3*time.Second {
		t.Fatalf("HTTP.ReadTimeout = %s, want 3s", cfg.HTTP.ReadTimeout)
	}
}
