package ratelimit

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

const testKeySecret = "0123456789abcdef0123456789abcdef"

func TestNewKeyBuilder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		secret      string
		expectError bool
	}{
		{
			name:   "valid secret",
			secret: testKeySecret,
		},
		{
			name:        "empty secret",
			secret:      "",
			expectError: true,
		},
		{
			name:        "short secret",
			secret:      "short-secret",
			expectError: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			builder, err := NewKeyBuilder(test.secret)

			if test.expectError {
				if !errors.Is(err, ErrInvalidKeySecret) {
					t.Fatalf(
						"expected ErrInvalidKeySecret, got %v",
						err,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if builder == nil {
				t.Fatal("expected key builder")
			}
		})
	}
}

func TestKeyBuilderForEmail(t *testing.T) {
	t.Parallel()

	builder, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}

	firstKey, err := builder.ForEmail(
		ActionLogin,
		" User@Example.COM ",
	)
	if err != nil {
		t.Fatalf("build first email key: %v", err)
	}

	secondKey, err := builder.ForEmail(
		ActionLogin,
		"user@example.com",
	)
	if err != nil {
		t.Fatalf("build second email key: %v", err)
	}

	if firstKey != secondKey {
		t.Fatalf(
			"expected normalized emails to produce the same key:\n%s\n%s",
			firstKey,
			secondKey,
		)
	}

	expectedPrefix := "rate_limit:login:email:"
	if !strings.HasPrefix(firstKey, expectedPrefix) {
		t.Fatalf(
			"expected key prefix %q, got %q",
			expectedPrefix,
			firstKey,
		)
	}

	if strings.Contains(firstKey, "user@example.com") {
		t.Fatal("rate-limit key must not contain raw email")
	}

	digest := strings.TrimPrefix(firstKey, expectedPrefix)

	if len(digest) != sha256HexLength {
		t.Fatalf(
			"expected %d-character digest, got %d",
			sha256HexLength,
			len(digest),
		)
	}
}

func TestKeyBuilderUsesSecretForEmailKey(t *testing.T) {
	t.Parallel()

	firstBuilder, err := NewKeyBuilder(
		"0123456789abcdef0123456789abcdef",
	)
	if err != nil {
		t.Fatalf("create first key builder: %v", err)
	}

	secondBuilder, err := NewKeyBuilder(
		"abcdef0123456789abcdef0123456789",
	)
	if err != nil {
		t.Fatalf("create second key builder: %v", err)
	}

	firstKey, err := firstBuilder.ForEmail(
		ActionSignup,
		"user@example.com",
	)
	if err != nil {
		t.Fatalf("build first key: %v", err)
	}

	secondKey, err := secondBuilder.ForEmail(
		ActionSignup,
		"user@example.com",
	)
	if err != nil {
		t.Fatalf("build second key: %v", err)
	}

	if firstKey == secondKey {
		t.Fatal("different secrets must produce different keys")
	}
}

func TestKeyBuilderForIP(t *testing.T) {
	t.Parallel()

	builder, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}

	tests := []struct {
		name        string
		ipAddress   netip.Addr
		expectedKey string
	}{
		{
			name:        "IPv4",
			ipAddress:   netip.MustParseAddr("192.0.2.10"),
			expectedKey: "rate_limit:login:ip:192.0.2.10",
		},
		{
			name:        "IPv6",
			ipAddress:   netip.MustParseAddr("2001:db8::10"),
			expectedKey: "rate_limit:login:ip:2001:db8::10",
		},
		{
			name: "IPv4-mapped IPv6 is canonicalized",
			ipAddress: netip.MustParseAddr(
				"::ffff:192.0.2.10",
			),
			expectedKey: "rate_limit:login:ip:192.0.2.10",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			key, err := builder.ForIP(
				ActionLogin,
				test.ipAddress,
			)
			if err != nil {
				t.Fatalf("build IP key: %v", err)
			}

			if key != test.expectedKey {
				t.Fatalf(
					"expected key %q, got %q",
					test.expectedKey,
					key,
				)
			}
		})
	}
}

func TestKeyBuilderRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	builder, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}

	tests := []struct {
		name          string
		build         func() (string, error)
		expectedError error
	}{
		{
			name: "invalid action",
			build: func() (string, error) {
				return builder.ForIP(
					Action("unknown"),
					netip.MustParseAddr("192.0.2.1"),
				)
			},
			expectedError: ErrInvalidAction,
		},
		{
			name: "invalid IP address",
			build: func() (string, error) {
				return builder.ForIP(
					ActionLogin,
					netip.Addr{},
				)
			},
			expectedError: ErrInvalidSubject,
		},
		{
			name: "invalid email",
			build: func() (string, error) {
				return builder.ForEmail(
					ActionLogin,
					"not-an-email",
				)
			},
			expectedError: ErrInvalidSubject,
		},
		{
			name: "uninitialized builder",
			build: func() (string, error) {
				var nilBuilder *KeyBuilder

				return nilBuilder.ForEmail(
					ActionLogin,
					"user@example.com",
				)
			},
			expectedError: ErrInvalidKeySecret,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := test.build()

			if !errors.Is(err, test.expectedError) {
				t.Fatalf(
					"expected error %v, got %v",
					test.expectedError,
					err,
				)
			}
		})
	}
}

func TestActionIsValid(t *testing.T) {
	t.Parallel()

	validActions := []Action{
		ActionLogin,
		ActionSignup,
		ActionForgotPassword,
		ActionResendVerification,
		ActionResetPassword,
		ActionChangePassword,
	}

	for _, action := range validActions {
		action := action

		t.Run(string(action), func(t *testing.T) {
			t.Parallel()

			if !action.IsValid() {
				t.Fatalf(
					"expected action %q to be valid",
					action,
				)
			}
		})
	}

	if Action("unknown").IsValid() {
		t.Fatal("expected unknown action to be invalid")
	}
}

const sha256HexLength = 64
