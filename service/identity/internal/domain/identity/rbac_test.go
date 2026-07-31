package identity

import "testing"

func TestPlatformRoleState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		role         PlatformRole
		assigned     bool
		valid        bool
		validOrEmpty bool
	}{
		{name: "ordinary", role: PlatformRoleNone, validOrEmpty: true},
		{name: "admin", role: PlatformRoleAdmin, assigned: true, valid: true, validOrEmpty: true},
		{name: "vice admin", role: PlatformRoleViceAdmin, assigned: true, valid: true, validOrEmpty: true},
		{name: "client", role: PlatformRole("CLIENT")},
		{name: "job seeker", role: PlatformRole("JOB_SEEKER")},
		{name: "agency", role: PlatformRole("AGENCY")},
		{name: "unknown", role: PlatformRole("UNKNOWN")},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := test.role.IsAssigned(); got != test.assigned {
				t.Fatalf("expected IsAssigned=%t, got %t", test.assigned, got)
			}
			if got := test.role.IsValid(); got != test.valid {
				t.Fatalf("expected IsValid=%t, got %t", test.valid, got)
			}
			if got := test.role.IsValidOrEmpty(); got != test.validOrEmpty {
				t.Fatalf("expected IsValidOrEmpty=%t, got %t", test.validOrEmpty, got)
			}
		})
	}
}

func TestParsePlatformRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		raw      string
		expected PlatformRole
		invalid  bool
	}{
		{name: "admin", raw: " ADMIN ", expected: PlatformRoleAdmin},
		{name: "trims vice admin", raw: " VICE_ADMIN ", expected: PlatformRoleViceAdmin},
		{name: "ordinary", raw: "", expected: PlatformRoleNone},
		{name: "whitespace is not assignable", raw: "   ", invalid: true},
		{name: "lowercase admin", raw: "admin", invalid: true},
		{name: "lowercase vice admin", raw: "vice_admin", invalid: true},
		{name: "client", raw: "CLIENT", invalid: true},
		{name: "job seeker", raw: "JOB_SEEKER", invalid: true},
		{name: "agency", raw: "AGENCY", invalid: true},
		{name: "unknown", raw: "SUPER_ADMIN", invalid: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			role, err := ParsePlatformRole(test.raw)
			if test.invalid {
				if err == nil {
					t.Fatal("expected parse error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parse platform role: %v", err)
			}
			if role != test.expected {
				t.Fatalf("expected %q, got %q", test.expected, role)
			}
		})
	}
}

func TestCanCreatePlatformRole(t *testing.T) {
	t.Parallel()

	roles := []PlatformRole{
		PlatformRoleNone,
		PlatformRoleAdmin,
		PlatformRoleViceAdmin,
		PlatformRole("CLIENT"),
		PlatformRole("JOB_SEEKER"),
		PlatformRole("AGENCY"),
		PlatformRole("UNKNOWN"),
	}

	for _, actor := range roles {
		for _, target := range roles {
			expected := actor == PlatformRoleAdmin && target == PlatformRoleViceAdmin
			if got := CanCreatePlatformRole(actor, target); got != expected {
				t.Fatalf(
					"actor %q target %q: expected allowed=%t, got %t",
					actor,
					target,
					expected,
					got,
				)
			}
		}
	}
}
