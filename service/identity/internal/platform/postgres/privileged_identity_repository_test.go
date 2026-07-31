package postgres

import (
	"strings"
	"testing"
)

func TestPrivilegedIdentityRepositoryUsesExistingVerificationOutboxType(t *testing.T) {
	t.Parallel()

	if strings.Contains(insertPrivilegedOutboxEventSQL, "created_by") {
		t.Fatal("repository must not assume a schema column that does not exist")
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
