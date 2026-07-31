package identity

import (
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

type Status string

const (
	StatusActive   Status = "active"
	StatusInactive Status = "inactive"
)

type Identity struct {
	ID              ID
	Email           string
	PasswordHash    string
	PlatformRole    PlatformRole
	Status          Status
	EmailVerified   bool
	SoftDeleteCount uint8
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       *time.Time
}

func (i Identity) IsSoftDeleted() bool {
	return i.DeletedAt != nil
}

func (i Identity) CanAuthenticate() error {
	if i.IsSoftDeleted() || i.Status != StatusActive {
		return domain.NewError(domain.ErrAccountInactive)
	}

	if !i.EmailVerified {
		return domain.NewError(domain.ErrEmailNotVerified)
	}

	return nil
}
