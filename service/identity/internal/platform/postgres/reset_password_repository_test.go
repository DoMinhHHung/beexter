package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	appresetpassword "github.com/DoMinhHHung/beexster/service/identity/internal/application/resetpassword"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

var resetRepositoryTestNow = time.Date(
	2026,
	time.July,
	30,
	10,
	0,
	0,
	0,
	time.UTC,
)

func TestValidatePasswordResetState(t *testing.T) {
	t.Parallel()

	usedAt := resetRepositoryTestNow
	revokedAt := resetRepositoryTestNow
	deletedAt := resetRepositoryTestNow

	tests := []struct {
		name        string
		state       passwordResetState
		expectedErr error
	}{
		{
			name: "valid",
			state: passwordResetState{
				expiresAt: resetRepositoryTestNow.Add(time.Minute),
				status:    string(identity.StatusActive),
			},
		},
		{
			name: "used",
			state: passwordResetState{
				expiresAt: resetRepositoryTestNow.Add(time.Minute),
				usedAt:    &usedAt,
				status:    string(identity.StatusActive),
			},
			expectedErr: appresetpassword.ErrTokenAlreadyUsed,
		},
		{
			name: "revoked",
			state: passwordResetState{
				expiresAt: resetRepositoryTestNow.Add(time.Minute),
				revokedAt: &revokedAt,
				status:    string(identity.StatusActive),
			},
			expectedErr: appresetpassword.ErrTokenRevoked,
		},
		{
			name: "expires exactly now",
			state: passwordResetState{
				expiresAt: resetRepositoryTestNow,
				status:    string(identity.StatusActive),
			},
			expectedErr: appresetpassword.ErrTokenExpired,
		},
		{
			name: "inactive",
			state: passwordResetState{
				expiresAt: resetRepositoryTestNow.Add(time.Minute),
				status:    string(identity.StatusInactive),
			},
			expectedErr: appresetpassword.ErrAccountInactive,
		},
		{
			name: "soft deleted",
			state: passwordResetState{
				expiresAt: resetRepositoryTestNow.Add(time.Minute),
				status:    string(identity.StatusInactive),
				deletedAt: &deletedAt,
			},
			expectedErr: appresetpassword.ErrAccountInactive,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validatePasswordResetState(
				test.state,
				resetRepositoryTestNow,
			)
			if test.expectedErr == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}

			if !errors.Is(err, test.expectedErr) {
				t.Fatalf(
					"expected error %v, got %v",
					test.expectedErr,
					err,
				)
			}
		})
	}
}

func TestSessionRevocationReusesPasswordResetOutboxEvent(t *testing.T) {
	t.Parallel()

	requiredFragments := []string{
		"identity.password_reset_requested",
		"session_revocation",
		"session_cutoff",
		"processed_at = NULL",
	}
	for _, fragment := range requiredFragments {
		if !strings.Contains(
			reopenPasswordResetOutboxForSessionRevocationSQL,
			fragment,
		) {
			t.Fatalf("expected Outbox SQL to contain %q", fragment)
		}
	}

	if strings.Contains(
		reopenPasswordResetOutboxForSessionRevocationSQL,
		"identity.refresh_sessions_revocation_requested",
	) {
		t.Fatal("reset-password must not introduce a new Outbox event type")
	}
}
