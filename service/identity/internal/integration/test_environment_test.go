//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const (
	integrationDatabaseName = "identity_test"
	integrationSetupTimeout = 30 * time.Second
)

func TestMain(m *testing.M) {
	os.Exit(runIntegrationSuite(m))
}

func runIntegrationSuite(m *testing.M) int {
	if !integrationTestsEnabled() {
		if runningInCI() {
			fmt.Fprintln(
				os.Stderr,
				"integration setup: IDENTITY_INTEGRATION_TEST must be 1 in CI",
			)
			return 1
		}

		return m.Run()
	}

	databaseURL := configuredIntegrationDatabaseURL()
	if databaseURL == "" {
		fmt.Fprintln(
			os.Stderr,
			"integration setup: DATABASE_DIRECT_URL or DATABASE_URL is required",
		)
		return 1
	}

	redisAddress := strings.TrimSpace(os.Getenv("REDIS_ADDR"))
	if redisAddress == "" {
		fmt.Fprintln(os.Stderr, "integration setup: REDIS_ADDR is required")
		return 1
	}

	redisDatabase, err := configuredIntegrationRedisDatabase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration setup: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), integrationSetupTimeout)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration setup: open PostgreSQL")
		return 1
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "integration setup: ping PostgreSQL")
		return 1
	}

	var databaseName string
	if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil {
		fmt.Fprintln(os.Stderr, "integration setup: inspect PostgreSQL database")
		return 1
	}
	if databaseName != integrationDatabaseName {
		fmt.Fprintf(
			os.Stderr,
			"integration setup: refusing to reset database %q; expected %q\n",
			databaseName,
			integrationDatabaseName,
		)
		return 1
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddress,
		Username: os.Getenv("REDIS_USERNAME"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       redisDatabase,
	})
	if err := redisClient.Ping(ctx).Err(); err != nil {
		_ = redisClient.Close()
		fmt.Fprintln(os.Stderr, "integration setup: ping Redis")
		return 1
	}
	if err := redisClient.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "integration setup: close Redis")
		return 1
	}

	if err := resetIntegrationSchema(ctx, pool); err != nil {
		fmt.Fprintf(os.Stderr, "integration setup: %v\n", err)
		return 1
	}

	exitCode := m.Run()

	cleanupContext, cleanupCancel := context.WithTimeout(
		context.Background(),
		integrationSetupTimeout,
	)
	defer cleanupCancel()
	if _, err := pool.Exec(
		cleanupContext,
		`DROP SCHEMA IF EXISTS identity CASCADE`,
	); err != nil {
		fmt.Fprintln(os.Stderr, "integration cleanup: drop identity schema")
		return 1
	}

	return exitCode
}

func requireIntegrationTests(t *testing.T) {
	t.Helper()

	if integrationTestsEnabled() {
		return
	}
	if runningInCI() {
		t.Fatal("IDENTITY_INTEGRATION_TEST must be 1 in CI")
	}

	t.Skip("set IDENTITY_INTEGRATION_TEST=1 and use isolated PostgreSQL/Redis instances")
}

func integrationTestsEnabled() bool {
	return strings.TrimSpace(os.Getenv("IDENTITY_INTEGRATION_TEST")) == "1"
}

func runningInCI() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("CI")), "true")
}

func configuredIntegrationDatabaseURL() string {
	if directURL := strings.TrimSpace(os.Getenv("DATABASE_DIRECT_URL")); directURL != "" {
		return directURL
	}

	return strings.TrimSpace(os.Getenv("DATABASE_URL"))
}

func requireIntegrationDatabaseURL(t *testing.T) string {
	t.Helper()

	databaseURL := configuredIntegrationDatabaseURL()
	if databaseURL == "" {
		t.Fatal("DATABASE_DIRECT_URL or DATABASE_URL is required")
	}

	return databaseURL
}

func requireIntegrationRedisAddress(t *testing.T) string {
	t.Helper()

	address := strings.TrimSpace(os.Getenv("REDIS_ADDR"))
	if address == "" {
		t.Fatal("REDIS_ADDR is required")
	}

	return address
}

func configuredIntegrationRedisDatabase() (int, error) {
	rawDatabase := strings.TrimSpace(os.Getenv("REDIS_DB"))
	if rawDatabase == "" {
		return 0, nil
	}

	database, err := strconv.Atoi(rawDatabase)
	if err != nil || database < 0 {
		return 0, fmt.Errorf("REDIS_DB must be a non-negative integer")
	}

	return database, nil
}

func requireIntegrationRedisDatabase(t *testing.T) int {
	t.Helper()

	database, err := configuredIntegrationRedisDatabase()
	if err != nil {
		t.Fatal(err)
	}

	return database
}

func resetIntegrationSchema(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS identity CASCADE`); err != nil {
		return fmt.Errorf("drop identity schema: %w", err)
	}

	for _, migrationName := range []string{
		"000001_create_identity_schema.up.sql",
		"000002_refactor_identity_subject_model.up.sql",
	} {
		migration, err := readMigration(migrationName)
		if err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, migration); err != nil {
			return fmt.Errorf("apply migration %s: %w", migrationName, err)
		}
	}

	return nil
}

func readMigration(name string) (string, error) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate integration test source")
	}

	migrationPath := filepath.Join(
		filepath.Dir(sourceFile),
		"..",
		"..",
		"migrations",
		name,
	)
	rawMigration, err := os.ReadFile(migrationPath)
	if err != nil {
		return "", fmt.Errorf("read migration %s: %w", name, err)
	}

	return string(rawMigration), nil
}
