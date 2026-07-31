//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIdentitySubjectModelMigration(t *testing.T) {
	if strings.TrimSpace(os.Getenv("IDENTITY_INTEGRATION_TEST")) != "1" {
		t.Skip("set IDENTITY_INTEGRATION_TEST=1 and use an isolated PostgreSQL instance")
	}

	databaseURL := integrationDatabaseURL()
	if databaseURL == "" {
		t.Skip("DATABASE_DIRECT_URL or DATABASE_URL is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping PostgreSQL: %v", err)
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin rollback-only migration test: %v", err)
	}
	defer func() {
		rollbackContext, rollbackCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer rollbackCancel()
		if rollbackErr := tx.Rollback(rollbackContext); rollbackErr != nil &&
			!errors.Is(rollbackErr, pgx.ErrTxClosed) {
			t.Errorf("rollback migration test: %v", rollbackErr)
		}
	}()

	if _, err := tx.Exec(ctx, `DROP SCHEMA IF EXISTS identity CASCADE`); err != nil {
		t.Fatalf("drop isolated identity schema: %v", err)
	}
	if _, err := tx.Exec(ctx, migrationBody(t, "000001_create_identity_schema.up.sql")); err != nil {
		t.Fatalf("apply initial migration: %v", err)
	}

	roles := []string{"ADMIN", "VICE_ADMIN", "CLIENT", "JOB_SEEKER", "AGENCY"}
	for index, role := range roles {
		id := fmt.Sprintf("0198f124-659f-7cb%d-a441-dc7eea17507%d", index, index)
		email := strings.ToLower(role) + "@example.test"
		if _, err := tx.Exec(
			ctx,
			`INSERT INTO identity.identities
				(id, email, password_hash, role, status, created_at, updated_at)
			 VALUES ($1, $2, '$argon2id$fixture', $3, 'active', $4, $4)`,
			id,
			email,
			role,
			time.Now().UTC(),
		); err != nil {
			t.Fatalf("seed %s identity: %v", role, err)
		}
	}

	if _, err := tx.Exec(ctx, migrationBody(t, "000002_refactor_identity_subject_model.up.sql")); err != nil {
		t.Fatalf("apply subject-model migration: %v", err)
	}

	var oldRoleColumnCount int
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*) FROM information_schema.columns
		 WHERE table_schema = 'identity'
		   AND table_name = 'identities'
		   AND column_name = 'role'`,
	).Scan(&oldRoleColumnCount); err != nil {
		t.Fatalf("inspect old role column: %v", err)
	}
	if oldRoleColumnCount != 0 {
		t.Fatalf("old role column still exists: count=%d", oldRoleColumnCount)
	}

	rows, err := tx.Query(
		ctx,
		`SELECT email, platform_role
		 FROM identity.identities
		 ORDER BY email`,
	)
	if err != nil {
		t.Fatalf("query migrated identities: %v", err)
	}
	defer rows.Close()

	want := map[string]*string{
		"admin@example.test":      stringPointer("ADMIN"),
		"vice_admin@example.test": stringPointer("VICE_ADMIN"),
		"client@example.test":     nil,
		"job_seeker@example.test": nil,
		"agency@example.test":     nil,
	}
	seen := make(map[string]bool, len(want))
	for rows.Next() {
		var (
			email        string
			platformRole sql.NullString
		)
		if err := rows.Scan(&email, &platformRole); err != nil {
			t.Fatalf("scan migrated identity: %v", err)
		}

		expected, ok := want[email]
		if !ok {
			t.Fatalf("unexpected migrated identity %q", email)
		}
		seen[email] = true
		if expected == nil && platformRole.Valid {
			t.Fatalf("expected %s platform role to be NULL, got %q", email, platformRole.String)
		}
		if expected != nil && (!platformRole.Valid || platformRole.String != *expected) {
			t.Fatalf("expected %s platform role %q, got %+v", email, *expected, platformRole)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migrated identities: %v", err)
	}
	if len(seen) != len(want) {
		t.Fatalf("expected %d migrated identities, saw %d", len(want), len(seen))
	}

	if _, err := tx.Exec(ctx, `SAVEPOINT irreversible_down_test`); err != nil {
		t.Fatalf("create down-migration savepoint: %v", err)
	}
	_, downErr := tx.Exec(
		ctx,
		migrationBody(t, "000002_refactor_identity_subject_model.down.sql"),
	)
	if downErr == nil || !strings.Contains(
		downErr.Error(),
		"intentionally irreversible",
	) {
		t.Fatalf("expected explicit irreversible down-migration error, got %v", downErr)
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT irreversible_down_test`); err != nil {
		t.Fatalf("recover from expected down-migration failure: %v", err)
	}

	_, err = tx.Exec(
		ctx,
		`INSERT INTO identity.identities
			(id, email, password_hash, platform_role, status, created_at, updated_at)
		 VALUES ('0198f124-659f-7cbd-a441-dc7eea175099', 'invalid@example.test',
			'$argon2id$fixture', 'AGENCY', 'active', $1, $1)`,
		time.Now().UTC(),
	)
	if err == nil {
		t.Fatal("expected PostgreSQL to reject an invalid platform role")
	}
}

func integrationDatabaseURL() string {
	if directURL := strings.TrimSpace(os.Getenv("DATABASE_DIRECT_URL")); directURL != "" {
		return directURL
	}
	return strings.TrimSpace(os.Getenv("DATABASE_URL"))
}

func migrationBody(t *testing.T, name string) string {
	t.Helper()

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration test source")
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
		t.Fatalf("read migration %s: %v", name, err)
	}

	trimmed := strings.TrimSpace(string(rawMigration))
	if !strings.HasPrefix(trimmed, "BEGIN;") || !strings.HasSuffix(trimmed, "COMMIT;") {
		t.Fatalf("migration %s must use an explicit transaction", name)
	}
	trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "BEGIN;"))
	trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, "COMMIT;"))
	return trimmed
}

func stringPointer(value string) *string {
	return &value
}
