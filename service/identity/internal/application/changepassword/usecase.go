package changepassword

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	maxRequestIDLength     = 128
	maxCurrentPasswordRune = 128
)

var (
	ErrDependencyMissing = errors.New("change-password dependency is missing")
	ErrIdentityNotFound  = errors.New("change-password identity was not found")
	ErrAccountInactive   = errors.New("change-password account is inactive")
	ErrCredentialChanged = errors.New("password credential changed concurrently")
)

type Input struct {
	UserID          identity.ID
	CurrentPassword string
	NewPassword     string
	IPAddress       netip.Addr
	RequestID       string
}

type Output struct {
	PasswordChanged bool
}

type Credential struct {
	PasswordHash string
	Status       identity.Status
	DeletedAt    *time.Time
}

type ChangeParams struct {
	IdentityID           identity.ID
	ExpectedPasswordHash string
	NewPasswordHash      string
	ChangedAt            time.Time
}

type Repository interface {
	LoadCredential(
		ctx context.Context,
		identityID identity.ID,
	) (Credential, error)

	ChangePassword(
		ctx context.Context,
		params ChangeParams,
	) error
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password string, encodedHash string) (bool, error)
}

type RateLimiter interface {
	AllowChangePasswordIP(
		ctx context.Context,
		requestID string,
		ipAddress netip.Addr,
	) (bool, error)

	AllowChangePasswordIdentity(
		ctx context.Context,
		requestID string,
		identityID identity.ID,
	) (bool, error)
}

type SessionRevoker interface {
	RevokeCreatedAtOrBefore(
		ctx context.Context,
		userID identity.ID,
		cutoff time.Time,
	) error
}

type UseCase struct {
	repository     Repository
	hasher         PasswordHasher
	rateLimiter    RateLimiter
	sessionRevoker SessionRevoker
	now            func() time.Time
}

func New(
	repository Repository,
	hasher PasswordHasher,
	rateLimiter RateLimiter,
	sessionRevoker SessionRevoker,
	now func() time.Time,
) (*UseCase, error) {
	if repository == nil ||
		hasher == nil ||
		rateLimiter == nil ||
		sessionRevoker == nil ||
		now == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{
		repository:     repository,
		hasher:         hasher,
		rateLimiter:    rateLimiter,
		sessionRevoker: sessionRevoker,
		now:            now,
	}, nil
}

func (u *UseCase) Execute(
	ctx context.Context,
	input Input,
) (Output, error) {
	if u == nil ||
		u.repository == nil ||
		u.hasher == nil ||
		u.rateLimiter == nil ||
		u.sessionRevoker == nil ||
		u.now == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			ErrDependencyMissing,
		)
	}
	if ctx == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("change-password context is required"),
		)
	}

	if input.UserID.IsZero() ||
		!input.IPAddress.IsValid() ||
		input.RequestID == "" ||
		len(input.RequestID) > maxRequestIDLength ||
		strings.IndexFunc(input.RequestID, unicode.IsSpace) >= 0 {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	ipAddress := input.IPAddress.Unmap()
	allowed, err := u.rateLimiter.AllowChangePasswordIP(
		ctx,
		input.RequestID,
		ipAddress,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check change-password IP rate limit: %w", err),
		)
	}
	if !allowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	allowed, err = u.rateLimiter.AllowChangePasswordIdentity(
		ctx,
		input.RequestID,
		input.UserID,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check change-password identity rate limit: %w", err),
		)
	}
	if !allowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	if err := validateCurrentPassword(input.CurrentPassword); err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}
	if err := identity.ValidatePassword(input.NewPassword); err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}

	credential, err := u.repository.LoadCredential(ctx, input.UserID)
	if err != nil {
		return Output{}, mapRepositoryError(err)
	}
	if credential.Status != identity.StatusActive || credential.DeletedAt != nil {
		return Output{}, domain.NewError(domain.ErrAccountInactive)
	}

	currentMatches, err := u.hasher.Verify(
		input.CurrentPassword,
		credential.PasswordHash,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("verify current password: %w", err),
		)
	}
	if !currentMatches {
		return Output{}, domain.NewError(domain.ErrInvalidCredentials)
	}

	newMatchesCurrent, err := u.hasher.Verify(
		input.NewPassword,
		credential.PasswordHash,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("compare new password with current hash: %w", err),
		)
	}
	if newMatchesCurrent {
		return Output{}, domain.WrapError(
			domain.ErrInvalidInput,
			errors.New("new password must differ from current password"),
		)
	}

	newPasswordHash, err := u.hasher.Hash(input.NewPassword)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("hash new password: %w", err),
		)
	}

	changedAt := u.now().UTC().Truncate(time.Second)
	if changedAt.IsZero() {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("change-password clock returned zero time"),
		)
	}

	// Set a Redis revocation fence before changing the database credential.
	// This both revokes existing refresh sessions and rejects an in-flight
	// login that started before changedAt but attempts to save its session later.
	if err := u.sessionRevoker.RevokeCreatedAtOrBefore(
		ctx,
		input.UserID,
		changedAt,
	); err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("revoke refresh sessions before password change: %w", err),
		)
	}

	if err := u.repository.ChangePassword(
		ctx,
		ChangeParams{
			IdentityID:           input.UserID,
			ExpectedPasswordHash: credential.PasswordHash,
			NewPasswordHash:      newPasswordHash,
			ChangedAt:            changedAt,
		},
	); err != nil {
		return Output{}, mapRepositoryError(err)
	}

	return Output{PasswordChanged: true}, nil
}

func validateCurrentPassword(password string) error {
	if password == "" {
		return errors.New("current password is required")
	}
	if !utf8.ValidString(password) {
		return errors.New("current password contains invalid UTF-8")
	}
	if utf8.RuneCountInString(password) > maxCurrentPasswordRune {
		return errors.New("current password exceeds maximum length")
	}
	return nil
}

func mapRepositoryError(err error) error {
	switch {
	case errors.Is(err, ErrIdentityNotFound):
		return domain.NewError(domain.ErrTokenInvalid)
	case errors.Is(err, ErrAccountInactive):
		return domain.NewError(domain.ErrAccountInactive)
	case errors.Is(err, ErrCredentialChanged):
		return domain.NewError(domain.ErrInvalidCredentials)
	default:
		return domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("change password: %w", err),
		)
	}
}
