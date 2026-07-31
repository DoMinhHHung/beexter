package postgres

import (
	"context"
	"strings"
	"testing"
)

func TestOpenSanitizesInvalidConfiguration(t *testing.T) {
	t.Parallel()

	const databaseURL = "postgres://profile:super-secret@%invalid/profile"
	pool, err := Open(context.Background(), databaseURL)
	if pool != nil {
		pool.Close()
		t.Fatal("Open() returned a pool for invalid configuration")
	}
	if err == nil {
		t.Fatal("Open() error = nil")
	}
	if !strings.Contains(err.Error(), ErrInvalidConfiguration.Error()) {
		t.Fatalf("Open() error = %v", err)
	}
	if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), databaseURL) {
		t.Fatalf("Open() error exposes credentials: %v", err)
	}
}
