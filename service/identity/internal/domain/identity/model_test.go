package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
)

func TestIdentityCanAuthenticate(t *testing.T) {
	t.Parallel()

	deletedAt := time.Now().UTC()

	tests := []struct {
		name         string
		identity     Identity
		expectedCode domain.ErrorCode
	}{
		{
			name: "active and verified",
			identity: Identity{
				Status:        StatusActive,
				EmailVerified: true,
			},
		},
		{
			name: "email is not verified",
			identity: Identity{
				Status:        StatusActive,
				EmailVerified: false,
			},
			expectedCode: domain.ErrEmailNotVerified,
		},
		{
			name: "inactive account",
			identity: Identity{
				Status:        StatusInactive,
				EmailVerified: true,
			},
			expectedCode: domain.ErrAccountInactive,
		},
		{
			name: "soft-deleted account",
			identity: Identity{
				Status:        StatusActive,
				EmailVerified: true,
				DeletedAt:     &deletedAt,
			},
			expectedCode: domain.ErrAccountInactive,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.identity.CanAuthenticate()

			if test.expectedCode == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				return
			}

			var domainError *domain.Error

			if !errors.As(err, &domainError) {
				t.Fatalf(
					"expected domain error, got %v",
					err,
				)
			}

			if domainError.Code != test.expectedCode {
				t.Fatalf(
					"expected code %q, got %q",
					test.expectedCode,
					domainError.Code,
				)
			}
		})
	}
}
