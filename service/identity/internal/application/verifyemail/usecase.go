package verifyemail

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/google/uuid"
)

var (
	ErrDependencyMissing = errors.New(
		"verify-email dependency is missing",
	)

	ErrTokenNotFound = errors.New(
		"email verification token was not found",
	)

	ErrTokenAlreadyUsed = errors.New(
		"email verification token was already used",
	)

	ErrTokenRevoked = errors.New(
		"email verification token was revoked",
	)

	ErrTokenExpired = errors.New(
		"email verification token expired",
	)

	ErrAccountInactive = errors.New(
		"identity account is inactive",
	)
)

type Input struct {
	Token string
}

type Output struct {
	IdentityID    identity.ID
	EmailVerified bool
	Reactivated   bool
}

type Result struct {
	IdentityID  identity.ID
	Reactivated bool
}

type Repository interface {
	Verify(
		ctx context.Context,
		tokenID string,
		verifiedAt time.Time,
	) (Result, error)
}

type UseCase struct {
	repository Repository
	now        func() time.Time
}

func New(
	repository Repository,
	now func() time.Time,
) (*UseCase, error) {
	if repository == nil || now == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{
		repository: repository,
		now:        now,
	}, nil
}

func (u *UseCase) Execute(
	ctx context.Context,
	input Input,
) (Output, error) {
	if u == nil ||
		u.repository == nil ||
		u.now == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			ErrDependencyMissing,
		)
	}

	if ctx == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("verify-email context is required"),
		)
	}

	tokenID, err := validateTokenID(input.Token)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrTokenInvalid,
			err,
		)
	}

	verifiedAt := u.now().UTC()
	if verifiedAt.IsZero() {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("verify-email clock returned zero time"),
		)
	}

	result, err := u.repository.Verify(
		ctx,
		tokenID,
		verifiedAt,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrTokenNotFound),
			errors.Is(err, ErrTokenAlreadyUsed),
			errors.Is(err, ErrTokenRevoked):
			return Output{}, domain.NewError(
				domain.ErrTokenInvalid,
			)

		case errors.Is(err, ErrTokenExpired):
			return Output{}, domain.NewError(
				domain.ErrTokenExpired,
			)

		case errors.Is(err, ErrAccountInactive):
			return Output{}, domain.NewError(
				domain.ErrAccountInactive,
			)

		default:
			return Output{}, domain.WrapError(
				domain.ErrInternal,
				fmt.Errorf(
					"verify email address: %w",
					err,
				),
			)
		}
	}

	return Output{
		IdentityID:    result.IdentityID,
		EmailVerified: true,
		Reactivated:   result.Reactivated,
	}, nil
}

func validateTokenID(rawToken string) (string, error) {
	if rawToken == "" {
		return "", errors.New(
			"verification token is required",
		)
	}

	parsedToken, err := uuid.Parse(rawToken)
	if err != nil {
		return "", fmt.Errorf(
			"parse verification token: %w",
			err,
		)
	}

	if parsedToken.Version() != 7 {
		return "", errors.New(
			"verification token must be UUID v7",
		)
	}

	if parsedToken.Variant() != uuid.RFC4122 {
		return "", errors.New(
			"verification token has invalid UUID variant",
		)
	}

	if parsedToken.String() != rawToken {
		return "", errors.New(
			"verification token must use canonical lowercase representation",
		)
	}

	return rawToken, nil
}
