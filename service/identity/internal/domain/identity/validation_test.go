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
