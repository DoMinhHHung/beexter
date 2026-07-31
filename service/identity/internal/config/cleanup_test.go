package config

import (
	"testing"
	"time"
)

func TestLoadCleanupLocksLoginAttemptRetention(t *testing.T) {
	for _, key := range []string{
		"CLEANUP_INTERVAL",
		"CLEANUP_DATABASE_TIMEOUT",
		"CLEANUP_BATCH_SIZE",
		"CLEANUP_TOKEN_RETENTION",
		"CLEANUP_OUTBOX_RETENTION",
	} {
		t.Setenv(key, "")
	}
	config, err := LoadCleanup()
	if err != nil {
		t.Fatalf("load cleanup: %v", err)
	}
	if config.LoginAttemptRetention != 30*24*time.Hour || config.BatchSize != 1000 {
		t.Fatalf("unexpected cleanup defaults: %+v", config)
	}
}

func TestLoadCleanupRejectsExcessiveBatch(t *testing.T) {
	t.Setenv("CLEANUP_BATCH_SIZE", "10001")
	if _, err := LoadCleanup(); err == nil {
		t.Fatal("expected batch-size error")
	}
}
