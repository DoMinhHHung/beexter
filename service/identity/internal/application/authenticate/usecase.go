package authenticate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

const maxAccessTokenLength = 4096

var (
	ErrDependencyMissing = errors.New("authentication dependency is missing")
)

type Input struct {
	AccessToken string
}

type AccessTokenVerifier interface {
	Verify(
		rawToken string,
		now time.Time,
	) (appauth.VerifiedAccessToken, error)
}

type UseCase struct {
	accessTokens AccessTokenVerifier
	now          func() time.Time
}

func New(
	accessTokens AccessTokenVerifier,
	now func() time.Time,
) (*UseCase, error) {
	if accessTokens == nil || now == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{
		accessTokens: accessTokens,
		now:          now,
	}, nil
}

func (u *UseCase) Execute(
	ctx context.Context,
	input Input,
) (appauth.Principal, error) {
	if u == nil ||
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

	now := u.now().UTC()
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

	return appauth.Principal{
		UserID:         claims.Subject,
		DeviceID:       claims.DeviceID,
		PlatformRole:   claims.PlatformRole,
		AccessTokenJTI: claims.JTI,
		IssuedAt:       claims.IssuedAt,
		ExpiresAt:      claims.ExpiresAt,
	}, nil
}
