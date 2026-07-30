package identity

import (
	"strings"
	"testing"
)

func TestNormalizeAndValidateEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         string
		expectedEmail string
		expectError   bool
	}{
		{
			name:          "normalizes email",
			input:         "  User@Example.COM  ",
			expectedEmail: "user@example.com",
		},
		{
			name:        "empty email",
			input:       "   ",
			expectError: true,
		},
		{
			name:        "display name is rejected",
			input:       "User <user@example.com>",
			expectError: true,
		},
		{
			name:        "invalid email",
			input:       "not-an-email",
			expectError: true,
		},
		{
			name:        "trailing newline is rejected",
			input:       "user@example.com\n",
			expectError: true,
		},
		{
			name:        "leading carriage return is rejected",
			input:       "\ruser@example.com",
			expectError: true,
		},
		{
			name:        "embedded newline is rejected",
			input:       "user@example.com\nattacker@example.com",
			expectError: true,
		},
		{
			name:        "email exceeding maximum length",
			input:       strings.Repeat("a", maxEmailLength) + "@example.com",
			expectError: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			email, err := NormalizeAndValidateEmail(test.input)

			if test.expectError {
				if err == nil {
					t.Fatal("expected validation error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if email != test.expectedEmail {
				t.Fatalf(
					"expected email %q, got %q",
					test.expectedEmail,
					email,
				)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		password    string
		expectError bool
	}{
		{
			name:     "valid password",
			password: "Secure1!",
		},
		{
			name:        "empty password",
			password:    "",
			expectError: true,
		},
		{
			name:        "too short",
			password:    "Sec1!",
			expectError: true,
		},
		{
			name:        "missing uppercase",
			password:    "secure1!",
			expectError: true,
		},
		{
			name:        "missing lowercase",
			password:    "SECURE1!",
			expectError: true,
		},
		{
			name:        "missing digit",
			password:    "Secure!!",
			expectError: true,
		},
		{
			name:        "missing special character",
			password:    "Secure12",
			expectError: true,
		},
		{
			name:        "space is not a special character",
			password:    "Secure1 ",
			expectError: true,
		},
		{
			name:        "password exceeding maximum length",
			password:    "A1!" + strings.Repeat("a", maxPasswordLength),
			expectError: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := ValidatePassword(test.password)

			if test.expectError {
				if err == nil {
					t.Fatal("expected validation error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParsePublicRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		expectedRole Role
		expectError  bool
	}{
		{
			name:         "client",
			input:        "client",
			expectedRole: RoleClient,
		},
		{
			name:         "job seeker",
			input:        " JOB_SEEKER ",
			expectedRole: RoleJobSeeker,
		},
		{
			name:        "agency is forbidden",
			input:       "AGENCY",
			expectError: true,
		},
		{
			name:        "admin is forbidden",
			input:       "ADMIN",
			expectError: true,
		},
		{
			name:        "vice admin is forbidden",
			input:       "VICE_ADMIN",
			expectError: true,
		},
		{
			name:        "unknown role is rejected",
			input:       "UNKNOWN",
			expectError: true,
		},
		{
			name:        "empty role is rejected",
			input:       "   ",
			expectError: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			role, err := ParsePublicRole(test.input)

			if test.expectError {
				if err == nil {
					t.Fatal("expected validation error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if role != test.expectedRole {
				t.Fatalf(
					"expected role %q, got %q",
					test.expectedRole,
					role,
				)
			}
		})
	}
}

func TestRoleIsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		role     Role
		expected bool
	}{
		{role: RoleClient, expected: true},
		{role: RoleJobSeeker, expected: true},
		{role: RoleAgency, expected: true},
		{role: RoleAdmin, expected: true},
		{role: RoleViceAdmin, expected: true},
		{role: Role("UNKNOWN"), expected: false},
		{role: Role(""), expected: false},
	}

	for _, test := range tests {
		test := test

		t.Run(string(test.role), func(t *testing.T) {
			t.Parallel()

			actual := test.role.IsValid()

			if actual != test.expected {
				t.Fatalf(
					"expected IsValid=%t, got %t",
					test.expected,
					actual,
				)
			}
		})
	}
}

func TestRoleIsPublic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		role     Role
		expected bool
	}{
		{role: RoleClient, expected: true},
		{role: RoleJobSeeker, expected: true},
		{role: RoleAgency, expected: false},
		{role: RoleAdmin, expected: false},
		{role: RoleViceAdmin, expected: false},
		{role: Role("UNKNOWN"), expected: false},
	}

	for _, test := range tests {
		test := test

		t.Run(string(test.role), func(t *testing.T) {
			t.Parallel()

			actual := test.role.IsPublic()

			if actual != test.expected {
				t.Fatalf(
					"expected IsPublic=%t, got %t",
					test.expected,
					actual,
				)
			}
		})
	}
}
