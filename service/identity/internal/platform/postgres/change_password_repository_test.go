package postgres

import (
	"errors"
	"testing"
	"time"

	appchangepassword "github.com/DoMinhHHung/beexster/service/identity/internal/application/changepassword"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

func TestValidateChangePasswordState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state changePasswordState
		err   error
	}{
		{
			name: "active",
			state: changePasswordState{
				passwordHash: "$argon2id$hash",
				status:       string(identity.StatusActive),
			},
		},
		{
			name: "inactive",
			state: changePasswordState{
				passwordHash: "$argon2id$hash",
				status:       string(identity.StatusInactive),
			},
			err: appchangepassword.ErrAccountInactive,
		},
		{
			name: "soft deleted",
			state: changePasswordState{
				passwordHash: "$argon2id$hash",
				status:       string(identity.StatusInactive),
				deletedAt:    changePasswordTimePointer(time.Now()),
			},
			err: appchangepassword.ErrAccountInactive,
		},
		{
			name: "empty hash",
			state: changePasswordState{
				status: string(identity.StatusActive),
			},
			err: ErrChangePasswordStateConflict,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateChangePasswordState(test.state)
			if !errors.Is(err, test.err) {
				t.Fatalf("expected %v, got %v", test.err, err)
			}
		})
	}
}

func changePasswordTimePointer(value time.Time) *time.Time {
	return &value
}
