package identity

import "testing"

func TestCanCreateRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		actor   Role
		target  Role
		allowed bool
	}{
		{name: "admin creates vice admin", actor: RoleAdmin, target: RoleViceAdmin, allowed: true},
		{name: "admin creates agency", actor: RoleAdmin, target: RoleAgency, allowed: true},
		{name: "vice admin creates agency", actor: RoleViceAdmin, target: RoleAgency, allowed: true},
		{name: "vice admin cannot create vice admin", actor: RoleViceAdmin, target: RoleViceAdmin},
		{name: "admin cannot create admin", actor: RoleAdmin, target: RoleAdmin},
		{name: "admin cannot create client", actor: RoleAdmin, target: RoleClient},
		{name: "admin cannot create job seeker", actor: RoleAdmin, target: RoleJobSeeker},
		{name: "agency cannot create roles", actor: RoleAgency, target: RoleAgency},
		{name: "client cannot create roles", actor: RoleClient, target: RoleAgency},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if actual := CanCreateRole(test.actor, test.target); actual != test.allowed {
				t.Fatalf("expected allowed=%t, got %t", test.allowed, actual)
			}
		})
	}
}

func TestParseRoleNormalizesInput(t *testing.T) {
	t.Parallel()

	role, err := ParseRole(" vice_admin ")
	if err != nil {
		t.Fatalf("parse role: %v", err)
	}

	if role != RoleViceAdmin {
		t.Fatalf("expected %q, got %q", RoleViceAdmin, role)
	}
}

func TestParseRoleRejectsUnknownRole(t *testing.T) {
	t.Parallel()

	if _, err := ParseRole("SUPER_ADMIN"); err == nil {
		t.Fatal("expected unknown role to be rejected")
	}
}
