package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("SHUTDOWN_TIMEOUT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}
	if cfg.LogLevel != "INFO" {
		t.Fatalf("LogLevel = %q, want %q", cfg.LogLevel, "INFO")
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Fatalf("ShutdownTimeout = %s, want %s", cfg.ShutdownTimeout, 10*time.Second)
	}
}

func TestLoadRejectsInvalidShutdownTimeout(t *testing.T) {
	t.Setenv("SHUTDOWN_TIMEOUT", "not-a-duration")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsInvalidLogLevel(t *testing.T) {
	t.Setenv("LOG_LEVEL", "TRACE")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}
