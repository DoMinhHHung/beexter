package postgres

import (
	"strings"
	"testing"
)

func TestSignupInsertStoresNullPlatformRole(t *testing.T) {
	t.Parallel()

	if !strings.Contains(insertIdentitySQL, "platform_role") {
		t.Fatal("signup insert must address platform_role")
	}
	if !strings.Contains(insertIdentitySQL, "NULL") {
		t.Fatal("ordinary signup must persist a NULL platform_role")
	}
	if strings.Contains(insertIdentitySQL, "\n    role,") {
		t.Fatal("signup insert must not use the removed role column")
	}
}
