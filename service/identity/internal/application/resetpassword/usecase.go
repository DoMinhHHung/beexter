package resetpassword

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/google/uuid"
)

const (
	maxRequestIDLength          = 128
	sessionRevocationGuardDelay = 5 * time.Second
)

var (
	ErrDependencyMissing = errors.New(
		"reset-password dependency is missing",
	)
	ErrTokenNotFound = errors.New(
		"password-reset token was not found",
	)
	ErrTokenAlreadyUsed = errors.New(
		"password-reset token was already used",
	)
	ErrTokenRevoked = errors.New(
		"password-reset token was revoked",
	)
	ErrTokenExpired = errors.New(
		"password-reset token expired",
	)
	ErrAccountInactive = errors.New(
		"password-reset account is inactive",
	)
)

type Input struct {
	Token       string
	NewPassword string
	IPAddress   netip.Addr
	RequestID   string
}

type Output struct {
	PasswordReset bool
}

type ResetParams struct {
	IdentityID                   identity.ID
	PasswordResetTokenID         string
	PasswordHash                 string
	ResetAt                      time.Time
	SessionRevocationAvailableAt time.Time
}

type Repository interface {
	ResolveTarget(
		ctx context.Context,
		tokenID string,
		checkedAt time.Time,
	) (identity.ID, error)

	Reset(
		ctx context.Context,
		params ResetParams,
	) error
}

type PasswordHasher interface {
	Hash(password string) (string, error)
}

type RateLimiter interface {
	AllowResetPasswordIP(
		ctx context.Context,
		requestID string,
		ipAddress netip.Addr,
	) (bool, error)
}

type SessionRevoker interface {
	RevokeAll(
		ctx context.Context,
		userID identity.ID,
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
			errors.New("reset-password context is required"),
		)
	}

	if !input.IPAddress.IsValid() ||
		input.RequestID == "" ||
		len(input.RequestID) > maxRequestIDLength ||
		strings.IndexFunc(input.RequestID, unicode.IsSpace) >= 0 {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	ipAddress := input.IPAddress.Unmap()
	allowed, err := u.rateLimiter.AllowResetPasswordIP(
		ctx,
		input.RequestID,
		ipAddress,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check reset-password IP rate limit: %w", err),
		)
	}
	if !allowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	tokenID, err := validateTokenID(input.Token)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrTokenInvalid,
			err,
		)
	}

	if err := identity.ValidatePassword(input.NewPassword); err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInvalidInput,
			err,
		)
	}

	resetAt := u.now().UTC()
	if resetAt.IsZero() {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("reset-password clock returned zero time"),
		)
	}

	identityID, err := u.repository.ResolveTarget(
		ctx,
		tokenID,
		resetAt,
	)
	if err != nil {
		return Output{}, mapRepositoryError(err)
	}

	passwordHash, err := u.hasher.Hash(input.NewPassword)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("hash reset password: %w", err),
		)
	}

	// Revoke current refresh sessions before changing the password. This makes
	// reset fail closed while Redis is unavailable. The transaction below also
	// reopens the password-reset Outbox item for delayed cleanup, catching
	// sessions created by an in-flight login that started before this reset.
	if err := u.sessionRevoker.RevokeAll(ctx, identityID); err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("revoke refresh sessions before password reset: %w", err),
		)
	}

	err = u.repository.Reset(
		ctx,
		ResetParams{
			IdentityID:           identityID,
			PasswordResetTokenID: tokenID,
			PasswordHash:         passwordHash,
			ResetAt:              resetAt,
			SessionRevocationAvailableAt: resetAt.Add(
				sessionRevocationGuardDelay,
			),
		},
	)
	if err != nil {
		return Output{}, mapRepositoryError(err)
	}

	return Output{PasswordReset: true}, nil
}

func validateTokenID(rawToken string) (string, error) {
	if rawToken == "" {
		return "", errors.New("password-reset token is required")
	}

	parsedToken, err := uuid.Parse(rawToken)
	if err != nil {
		return "", fmt.Errorf("parse password-reset token: %w", err)
	}

	if parsedToken.Version() != 7 ||
		parsedToken.Variant() != uuid.RFC4122 ||
		parsedToken.String() != rawToken {
		return "", errors.New(
			"password-reset token must be a canonical UUID v7",
		)
	}

	return rawToken, nil
}

func mapRepositoryError(err error) error {
	switch {
	case errors.Is(err, ErrTokenNotFound),
		errors.Is(err, ErrTokenAlreadyUsed),
		errors.Is(err, ErrTokenRevoked),
		errors.Is(err, ErrAccountInactive):
		return domain.NewError(domain.ErrTokenInvalid)

	case errors.Is(err, ErrTokenExpired):
		return domain.NewError(domain.ErrTokenExpired)

	default:
		return domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("reset password: %w", err),
		)
	}
}
