package authenticate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const maxAccessTokenLength = 4096

var (
	ErrDependencyMissing = errors.New("authentication dependency is missing")
	ErrIdentityNotFound  = errors.New("authenticated identity was not found")
)

type Input struct {
	AccessToken string
}

type Repository interface {
	FindByID(
		ctx context.Context,
		identityID identity.ID,
	) (identity.Identity, error)
}

type AccessTokenVerifier interface {
	Verify(
		rawToken string,
		now time.Time,
	) (appauth.VerifiedAccessToken, error)
}

type UseCase struct {
	repository   Repository
	accessTokens AccessTokenVerifier
	now          func() time.Time
}

func New(
	repository Repository,
	accessTokens AccessTokenVerifier,
	now func() time.Time,
) (*UseCase, error) {
	if repository == nil || accessTokens == nil || now == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{
		repository:   repository,
		accessTokens: accessTokens,
		now:          now,
	}, nil
}

func (u *UseCase) Execute(
	ctx context.Context,
	input Input,
) (appauth.Principal, error) {
	if u == nil ||
		u.repository == nil ||
		u.accessTokens == nil ||
		u.now == nil {
		return appauth.Principal{}, domain.WrapError(
			domain.ErrInternal,
			ErrDependencyMissing,
		)
	}

	if ctx == nil {
		return appauth.Principal{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("authentication context is required"),
		)
	}

	rawToken := strings.TrimSpace(input.AccessToken)
	if rawToken == "" || len(rawToken) > maxAccessTokenLength {
		return appauth.Principal{}, domain.NewError(
			domain.ErrTokenInvalid,
		)
	}

	now := u.now().UTC().Truncate(time.Second)
	if now.IsZero() {
		return appauth.Principal{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("authentication clock returned zero time"),
		)
	}

	claims, err := u.accessTokens.Verify(rawToken, now)
	if err != nil {
		switch {
		case errors.Is(err, appauth.ErrAccessTokenExpired):
			return appauth.Principal{}, domain.NewError(
				domain.ErrTokenExpired,
			)

		case errors.Is(err, appauth.ErrAccessTokenInvalid):
			return appauth.Principal{}, domain.NewError(
				domain.ErrTokenInvalid,
			)

		default:
			return appauth.Principal{}, domain.WrapError(
				domain.ErrInternal,
				fmt.Errorf("verify access token: %w", err),
			)
		}
	}

	account, err := u.repository.FindByID(ctx, claims.Subject)
	if errors.Is(err, ErrIdentityNotFound) {
		return appauth.Principal{}, domain.NewError(
			domain.ErrTokenInvalid,
		)
	}

	if err != nil {
		return appauth.Principal{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("find authenticated identity: %w", err),
		)
	}

	if err := account.CanAuthenticate(); err != nil {
		var domainError *domain.Error
		if errors.As(err, &domainError) {
			return appauth.Principal{}, domain.NewError(
				domainError.Code,
			)
		}

		return appauth.Principal{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check authenticated identity state: %w", err),
		)
	}

	// Roles and verification state may change after a token is issued. A
	// mismatch invalidates the token instead of authorizing stale claims.
	if claims.Role != account.Role ||
		claims.EmailVerified != account.EmailVerified {
		return appauth.Principal{}, domain.NewError(
			domain.ErrTokenInvalid,
		)
	}

	return appauth.Principal{
		UserID:         account.ID,
		DeviceID:       claims.DeviceID,
		Role:           account.Role,
		EmailVerified:  account.EmailVerified,
		AccessTokenJTI: claims.JTI,
		IssuedAt:       claims.IssuedAt,
		ExpiresAt:      claims.ExpiresAt,
	}, nil
}
