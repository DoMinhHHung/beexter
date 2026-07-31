package deleteaccount

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
	ErrDependencyMissing = errors.New("delete-account dependency is missing")
	ErrIdentityNotFound  = errors.New("delete-account identity was not found")
	ErrAccountInactive   = errors.New("delete-account identity is inactive")
	ErrCredentialChanged = errors.New("delete-account credential changed concurrently")
)

type Input struct {
	UserID          identity.ID
	CurrentPassword string
	IPAddress       netip.Addr
	RequestID       string
}

type Output struct {
	Deleted         bool
	HardDeleted     bool
	SoftDeleteCount uint8
}

type Credential struct {
	PasswordHash    string
	Status          identity.Status
	DeletedAt       *time.Time
	SoftDeleteCount uint8
}

type DeleteParams struct {
	IdentityID           identity.ID
	ExpectedPasswordHash string
	DeletedAt            time.Time
}

type DeleteResult struct {
	HardDeleted     bool
	SoftDeleteCount uint8
}

type Repository interface {
	LoadCredential(ctx context.Context, identityID identity.ID) (Credential, error)
	DeleteAccount(ctx context.Context, params DeleteParams) (DeleteResult, error)
}

type PasswordVerifier interface {
	Verify(password string, encodedHash string) (bool, error)
}

type RateLimiter interface {
	AllowDeleteAccountIP(
		ctx context.Context,
		requestID string,
		ipAddress netip.Addr,
	) (bool, error)
	AllowDeleteAccountIdentity(
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
	passwords      PasswordVerifier
	rateLimiter    RateLimiter
	sessionRevoker SessionRevoker
	now            func() time.Time
}

func New(
	repository Repository,
	passwords PasswordVerifier,
	rateLimiter RateLimiter,
	sessionRevoker SessionRevoker,
	now func() time.Time,
) (*UseCase, error) {
	if repository == nil || passwords == nil || rateLimiter == nil ||
		sessionRevoker == nil || now == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{
		repository:     repository,
		passwords:      passwords,
		rateLimiter:    rateLimiter,
		sessionRevoker: sessionRevoker,
		now:            now,
	}, nil
}

func (u *UseCase) Execute(ctx context.Context, input Input) (Output, error) {
	if u == nil || u.repository == nil || u.passwords == nil ||
		u.rateLimiter == nil || u.sessionRevoker == nil || u.now == nil {
		return Output{}, domain.WrapError(domain.ErrInternal, ErrDependencyMissing)
	}
	if ctx == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("delete-account context is required"),
		)
	}
	if input.UserID.IsZero() || !input.IPAddress.IsValid() ||
		input.RequestID == "" || len(input.RequestID) > maxRequestIDLength ||
		strings.IndexFunc(input.RequestID, unicode.IsSpace) >= 0 {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	allowed, err := u.rateLimiter.AllowDeleteAccountIP(
		ctx,
		input.RequestID,
		input.IPAddress.Unmap(),
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check delete-account IP rate limit: %w", err),
		)
	}
	if !allowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	allowed, err = u.rateLimiter.AllowDeleteAccountIdentity(
		ctx,
		input.RequestID,
		input.UserID,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check delete-account identity rate limit: %w", err),
		)
	}
	if !allowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	if err := validateCurrentPassword(input.CurrentPassword); err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}

	credential, err := u.repository.LoadCredential(ctx, input.UserID)
	if err != nil {
		return Output{}, mapRepositoryError(err)
	}
	if credential.Status != identity.StatusActive || credential.DeletedAt != nil {
		return Output{}, domain.NewError(domain.ErrAccountInactive)
	}

	matches, err := u.passwords.Verify(
		input.CurrentPassword,
		credential.PasswordHash,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("verify current password before account deletion: %w", err),
		)
	}
	if !matches {
		return Output{}, domain.NewError(domain.ErrInvalidCredentials)
	}

	deletedAt := u.now().UTC().Truncate(time.Second)
	if deletedAt.IsZero() {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("delete-account clock returned zero time"),
		)
	}

	// Fence sessions before changing persistent state. Authentication also
	// reloads the identity from PostgreSQL, so existing access tokens stop
	// authorizing immediately after the transaction commits.
	if err := u.sessionRevoker.RevokeCreatedAtOrBefore(
		ctx,
		input.UserID,
		deletedAt,
	); err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("revoke sessions before account deletion: %w", err),
		)
	}

	result, err := u.repository.DeleteAccount(
		ctx,
		DeleteParams{
			IdentityID:           input.UserID,
			ExpectedPasswordHash: credential.PasswordHash,
			DeletedAt:            deletedAt,
		},
	)
	if err != nil {
		return Output{}, mapRepositoryError(err)
	}

	return Output{
		Deleted:         true,
		HardDeleted:     result.HardDeleted,
		SoftDeleteCount: result.SoftDeleteCount,
	}, nil
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
			fmt.Errorf("delete account: %w", err),
		)
	}
}
