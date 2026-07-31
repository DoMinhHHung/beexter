//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexster/service/profile/internal/platform/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

const integrationDatabaseName = "profile_test"

var integrationPool *pgxpool.Pool

func TestMain(m *testing.M) {
	if os.Getenv("PROFILE_INTEGRATION_TEST") != "1" {
		fmt.Fprintln(os.Stderr, "PROFILE_INTEGRATION_TEST=1 is required; integration tests never skip silently")
		os.Exit(1)
	}

	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_DIRECT_URL"))
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_DIRECT_URL is required for integration tests")
		os.Exit(1)
	}
	if err := validateIsolatedDatabaseURL(databaseURL); err != nil {
		fmt.Fprintf(os.Stderr, "unsafe integration database configuration: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	pool, err := postgres.Open(ctx, databaseURL)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect to required PostgreSQL integration database: %v\n", err)
		os.Exit(1)
	}
	integrationPool = pool

	if err := verifyCurrentDatabase(); err != nil {
		pool.Close()
		fmt.Fprintf(os.Stderr, "verify isolated PostgreSQL integration database: %v\n", err)
		os.Exit(1)
	}

	exitCode := m.Run()
	pool.Close()
	os.Exit(exitCode)
}

func TestConnectsToIsolatedPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := integrationPool.Ping(ctx); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
}

func TestValidateIsolatedDatabaseURL(t *testing.T) {
	tests := []struct {
		name        string
		databaseURL string
		wantError   bool
	}{
		{
			name:        "loopback profile test database",
			databaseURL: "postgres://postgres:secret@127.0.0.1:5432/profile_test?sslmode=disable",
		},
		{
			name:        "wrong database name",
			databaseURL: "postgres://postgres:secret@127.0.0.1:5432/profile",
			wantError:   true,
		},
		{
			name:        "remote host",
			databaseURL: "postgres://postgres:secret@database.internal:5432/profile_test",
			wantError:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateIsolatedDatabaseURL(test.databaseURL)
			if test.wantError && err == nil {
				t.Fatal("validateIsolatedDatabaseURL() error = nil")
			}
			if !test.wantError && err != nil {
				t.Fatalf("validateIsolatedDatabaseURL() error = %v", err)
			}
		})
	}
}

func TestProfileSchemaMigrationUpAndDownFromEmptyDatabase(t *testing.T) {
	resetProfileSchema(t)
	t.Cleanup(func() {
		resetProfileSchema(t)
	})

	executeMigration(t, "000001_create_profile_schema.up.sql")
	if !schemaExists(t, "profile") {
		t.Fatal("profile schema does not exist after up migration")
	}

	executeMigration(t, "000001_create_profile_schema.down.sql")
	if schemaExists(t, "profile") {
		t.Fatal("profile schema still exists after down migration")
	}
}

func validateIsolatedDatabaseURL(databaseURL string) error {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return fmt.Errorf("database URL is invalid")
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return fmt.Errorf("database URL must use postgres or postgresql scheme")
	}
	hostname := parsed.Hostname()
	if hostname != "127.0.0.1" && hostname != "localhost" && hostname != "::1" {
		return fmt.Errorf("database host must be loopback")
	}
	if strings.Trim(parsed.Path, "/") != integrationDatabaseName {
		return fmt.Errorf("database name must be exactly %q", integrationDatabaseName)
	}
	return nil
}

func verifyCurrentDatabase() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var databaseName string
	if err := integrationPool.QueryRow(ctx, "SELECT current_database()").Scan(&databaseName); err != nil {
		return fmt.Errorf("query current database: %w", err)
	}
	if databaseName != integrationDatabaseName {
		return fmt.Errorf("connected database must be exactly %q", integrationDatabaseName)
	}
	return nil
}

func resetProfileSchema(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := integrationPool.Exec(ctx, "DROP SCHEMA IF EXISTS profile CASCADE"); err != nil {
		t.Fatalf("reset profile schema: %v", err)
	}
}

func executeMigration(t *testing.T, name string) {
	t.Helper()

	migration, err := os.ReadFile(filepath.Join(migrationsDirectory(t), name))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := integrationPool.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("execute migration %s: %v", name, err)
	}
}

func migrationsDirectory(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "migrations"))
}

func schemaExists(t *testing.T, schema string) bool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var exists bool
	if err := integrationPool.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)",
		schema,
	).Scan(&exists); err != nil {
		t.Fatalf("query schema %q: %v", schema, err)
	}
	return exists
}
