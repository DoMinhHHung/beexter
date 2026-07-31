package postgres

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func TestPlatformRoleFromNullString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		raw      sql.NullString
		expected identity.PlatformRole
		invalid  bool
	}{
		{name: "null ordinary identity", expected: identity.PlatformRoleNone},
		{name: "admin", raw: sql.NullString{String: "ADMIN", Valid: true}, expected: identity.PlatformRoleAdmin},
		{name: "vice admin", raw: sql.NullString{String: "VICE_ADMIN", Valid: true}, expected: identity.PlatformRoleViceAdmin},
		{name: "non-null empty", raw: sql.NullString{String: "", Valid: true}, invalid: true},
		{name: "lowercase admin", raw: sql.NullString{String: "admin", Valid: true}, invalid: true},
		{name: "padded admin", raw: sql.NullString{String: " ADMIN ", Valid: true}, invalid: true},
		{name: "legacy client", raw: sql.NullString{String: "CLIENT", Valid: true}, invalid: true},
		{name: "unknown", raw: sql.NullString{String: "UNKNOWN", Valid: true}, invalid: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			role, err := platformRoleFromNullString(test.raw)
			if test.invalid {
				if !errors.Is(err, ErrInvalidPersistedIdentity) {
					t.Fatalf("expected invalid persisted identity, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("map platform role: %v", err)
			}
			if role != test.expected {
				t.Fatalf("expected %q, got %q", test.expected, role)
			}
		})
	}
}

func TestIdentityReadQueriesUsePlatformRole(t *testing.T) {
	t.Parallel()

	queries := map[string]string{
		"login":   findIdentityForLoginSQL,
		"me":      findMeIdentitySQL,
		"refresh": findIdentityForRefreshSQL,
	}

	for name, query := range queries {
		if !strings.Contains(query, "platform_role") {
			t.Fatalf("%s query must select platform_role", name)
		}
		if strings.Contains(query, "\n    role,") {
			t.Fatalf("%s query must not select the removed role column", name)
		}
	}
}
