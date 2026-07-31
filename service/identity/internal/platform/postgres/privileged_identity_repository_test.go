package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	appcreateidentity "github.com/DoMinhHHung/beexter/service/identity/internal/application/createidentity"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const privilegedActorTestID = identity.ID(
	"0198f124-659f-7cbd-a441-dc7eea175073",
)

func TestAuthorizePrivilegedActor(t *testing.T) {
	t.Parallel()

	verifiedAt := time.Date(2026, time.July, 31, 1, 0, 0, 0, time.UTC)
	deletedAt := verifiedAt.Add(time.Hour)

	tests := []struct {
		name         string
		platformRole sql.NullString
		status       string
		verifiedAt   *time.Time
		deletedAt    *time.Time
		scanErr      error
		expectAllow  bool
	}{
		{
			name:         "active verified admin",
			platformRole: sql.NullString{String: "ADMIN", Valid: true},
			status:       string(identity.StatusActive),
			verifiedAt:   &verifiedAt,
			expectAllow:  true,
		},
		{
			name:         "demoted admin with stale claim",
			platformRole: sql.NullString{String: "VICE_ADMIN", Valid: true},
			status:       string(identity.StatusActive),
			verifiedAt:   &verifiedAt,
		},
		{
			name:         "ordinary identity",
			platformRole: sql.NullString{},
			status:       string(identity.StatusActive),
			verifiedAt:   &verifiedAt,
		},
		{
			name:         "inactive admin",
			platformRole: sql.NullString{String: "ADMIN", Valid: true},
			status:       string(identity.StatusInactive),
			verifiedAt:   &verifiedAt,
		},
		{
			name:         "unverified admin",
			platformRole: sql.NullString{String: "ADMIN", Valid: true},
			status:       string(identity.StatusActive),
		},
		{
			name:         "deleted admin",
			platformRole: sql.NullString{String: "ADMIN", Valid: true},
			status:       string(identity.StatusActive),
			verifiedAt:   &verifiedAt,
			deletedAt:    &deletedAt,
		},
		{
			name:         "invalid persisted platform role",
			platformRole: sql.NullString{String: "AGENCY", Valid: true},
			status:       string(identity.StatusActive),
			verifiedAt:   &verifiedAt,
		},
		{name: "actor not found", scanErr: pgx.ErrNoRows},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			querier := privilegedActorQuerierStub{
				queryRow: func(
					_ context.Context,
					query string,
					args ...any,
				) pgx.Row {
					if query != lockPrivilegedActorSQL {
						t.Fatalf("unexpected query: %s", query)
					}
					if len(args) != 1 || args[0] != privilegedActorTestID.String() {
						t.Fatalf("unexpected query args: %v", args)
					}

					return privilegedActorRowStub{scan: func(dest ...any) error {
						if test.scanErr != nil {
							return test.scanErr
						}
						*dest[0].(*sql.NullString) = test.platformRole
						*dest[1].(*string) = test.status
						*dest[2].(**time.Time) = test.verifiedAt
						*dest[3].(**time.Time) = test.deletedAt
						return nil
					}}
				},
			}

			err := authorizePrivilegedActor(
				context.Background(),
				querier,
				privilegedActorTestID,
			)
			if test.expectAllow {
				if err != nil {
					t.Fatalf("authorize actor: %v", err)
				}
				return
			}

			if !errors.Is(err, appcreateidentity.ErrActorForbidden) {
				t.Fatalf("expected forbidden actor, got %v", err)
			}
		})
	}
}

func TestPrivilegedIdentityAuthorizationUsesRowLock(t *testing.T) {
	t.Parallel()

	for _, fragment := range []string{
		"platform_role",
		"status",
		"email_verified_at",
		"deleted_at",
		"FOR UPDATE",
	} {
		if !strings.Contains(lockPrivilegedActorSQL, fragment) {
			t.Fatalf("actor authorization query must contain %q", fragment)
		}
	}
}

func TestPrivilegedIdentityRepositoryUsesTransactionalRecords(t *testing.T) {
	t.Parallel()

	if strings.Contains(insertPrivilegedOutboxEventSQL, "created_by") {
		t.Fatal("repository must not assume a schema column that does not exist")
	}

	if !strings.Contains(insertPrivilegedIdentitySQL, "platform_role") ||
		strings.Contains(insertPrivilegedIdentitySQL, "\n    role,") {
		t.Fatal("privileged insert must use platform_role only")
	}

	for _, query := range []string{
		insertPrivilegedIdentitySQL,
		insertPrivilegedVerificationTokenSQL,
		insertPrivilegedOutboxEventSQL,
	} {
		if !strings.Contains(query, "$1") {
			t.Fatal("all privileged identity SQL must be parameterized")
		}
	}
}

type privilegedActorQuerierStub struct {
	queryRow func(context.Context, string, ...any) pgx.Row
}

func (s privilegedActorQuerierStub) QueryRow(
	ctx context.Context,
	query string,
	args ...any,
) pgx.Row {
	return s.queryRow(ctx, query, args...)
}

type privilegedActorRowStub struct {
	scan func(...any) error
}

func (s privilegedActorRowStub) Scan(dest ...any) error {
	return s.scan(dest...)
}
