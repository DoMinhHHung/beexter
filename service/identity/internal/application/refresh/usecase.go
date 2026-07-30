package refresh

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	maxRefreshTokenLength = 4096
	maxUserAgentRunes     = 512
)

var (
	ErrDependencyMissing = errors.New("refresh dependency is missing")
	ErrIdentityNotFound  = errors.New("identity was not found")
)

type Input struct {
	RefreshToken string
	IPAddress    netip.Addr
	UserAgent    string
}

type Output struct {
	AccessToken           string
	RefreshToken          string
	TokenType             string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
	DeviceID              string
}

type Repository interface {
	FindByID(
		ctx context.Context,
		identityID identity.ID,
	) (identity.Identity, error)
}

type RefreshTokenCodec interface {
	Decode(
		rawToken string,
		now time.Time,
	) (appauth.RefreshTokenClaims, error)

	Encode(claims appauth.RefreshTokenClaims) (string, error)
}

type AccessTokenIssuer interface {
	Issue(
		claims appauth.AccessTokenClaims,
	) (token string, expiresAt time.Time, err error)
}

type SessionStore interface {
	Rotate(
		ctx context.Context,
		rotation appauth.Rotation,
	) error

	RevokeAll(
		ctx context.Context,
		userID identity.ID,
	) error
}

type UUIDGenerator interface {
	GenerateString() (string, error)
}

type UseCase struct {
	repository    Repository
	refreshTokens RefreshTokenCodec
	accessTokens  AccessTokenIssuer
	sessions      SessionStore
	ids           UUIDGenerator
	now           func() time.Time
}

func New(
	repository Repository,
	refreshTokens RefreshTokenCodec,
	accessTokens AccessTokenIssuer,
	sessions SessionStore,
	ids UUIDGenerator,
	now func() time.Time,
) (*UseCase, error) {
	if repository == nil ||
		refreshTokens == nil ||
		accessTokens == nil ||
		sessions == nil ||
		ids == nil ||
		now == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{
		repository:    repository,
		refreshTokens: refreshTokens,
		accessTokens:  accessTokens,
		sessions:      sessions,
		ids:           ids,
		now:           now,
	}, nil
}

func (u *UseCase) Execute(
	ctx context.Context,
	input Input,
) (Output, error) {
	if u == nil ||
		u.repository == nil ||
		u.refreshTokens == nil ||
		u.accessTokens == nil ||
		u.sessions == nil ||
		u.ids == nil ||
		u.now == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			ErrDependencyMissing,
		)
	}

	if ctx == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("refresh context is required"),
		)
	}

	if !input.IPAddress.IsValid() ||
		input.RefreshToken == "" ||
		len(input.RefreshToken) > maxRefreshTokenLength {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	now := u.now().UTC().Truncate(time.Second)
	if now.IsZero() {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("refresh clock returned zero time"),
		)
	}

	claims, err := u.refreshTokens.Decode(
		input.RefreshToken,
		now,
	)
	if err != nil {
		switch {
		case errors.Is(err, appauth.ErrRefreshTokenExpired):
			return Output{}, domain.NewError(domain.ErrTokenExpired)

		case errors.Is(err, appauth.ErrRefreshTokenInvalid):
			return Output{}, domain.NewError(domain.ErrTokenInvalid)

		default:
			return Output{}, domain.WrapError(
				domain.ErrInternal,
				fmt.Errorf("decode refresh token: %w", err),
			)
		}
	}

	account, err := u.repository.FindByID(ctx, claims.UserID)
	if errors.Is(err, ErrIdentityNotFound) {
		if revokeErr := u.sessions.RevokeAll(ctx, claims.UserID); revokeErr != nil {
			return Output{}, domain.WrapError(
				domain.ErrInternal,
				errors.Join(
					ErrIdentityNotFound,
					fmt.Errorf("revoke orphaned sessions: %w", revokeErr),
				),
			)
		}

		return Output{}, domain.NewError(domain.ErrTokenInvalid)
	}

	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("find identity for refresh: %w", err),
		)
	}

	if err := account.CanAuthenticate(); err != nil {
		if revokeErr := u.sessions.RevokeAll(ctx, account.ID); revokeErr != nil {
			return Output{}, domain.WrapError(
				domain.ErrInternal,
				errors.Join(
					err,
					fmt.Errorf("revoke inactive identity sessions: %w", revokeErr),
				),
			)
		}

		var domainError *domain.Error
		if errors.As(err, &domainError) {
			return Output{}, domain.NewError(domainError.Code)
		}

		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check refresh identity state: %w", err),
		)
	}

	replacementTokenID, err := u.ids.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate replacement refresh-token ID: %w", err),
		)
	}

	accessTokenJTI, err := u.ids.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate access-token JTI: %w", err),
		)
	}

	accessToken, accessExpiresAt, err := u.accessTokens.Issue(
		appauth.AccessTokenClaims{
			Subject:       account.ID,
			Role:          account.Role,
			EmailVerified: account.EmailVerified,
			IssuedAt:      now,
			JTI:           accessTokenJTI,
		},
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("issue refreshed access token: %w", err),
		)
	}

	refreshExpiresAt := now.Add(appauth.RefreshTokenTTL)
	replacementRefreshToken, err := u.refreshTokens.Encode(
		appauth.RefreshTokenClaims{
			UserID:    account.ID,
			DeviceID:  claims.DeviceID,
			TokenID:   replacementTokenID,
			IssuedAt:  now,
			ExpiresAt: refreshExpiresAt,
		},
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("encode replacement refresh token: %w", err),
		)
	}

	err = u.sessions.Rotate(
		ctx,
		appauth.Rotation{
			UserID:             account.ID,
			DeviceID:           claims.DeviceID,
			PresentedTokenID:   claims.TokenID,
			ReplacementTokenID: replacementTokenID,
			UserAgent:          normalizeUserAgent(input.UserAgent),
			IPAddress:          input.IPAddress.Unmap(),
			ExpiresAt:          refreshExpiresAt,
			LastUsedAt:         now,
		},
	)
	if err != nil {
		if errors.Is(err, appauth.ErrRefreshTokenReuse) {
			return Output{}, domain.NewError(
				domain.ErrTokenReuseDetected,
			)
		}

		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("rotate refresh session: %w", err),
		)
	}

	return Output{
		AccessToken:           accessToken,
		RefreshToken:          replacementRefreshToken,
		TokenType:             "Bearer",
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshTokenExpiresAt: refreshExpiresAt,
		DeviceID:              claims.DeviceID,
	}, nil
}

func normalizeUserAgent(rawUserAgent string) string {
	userAgent := strings.TrimSpace(rawUserAgent)
	if userAgent == "" {
		return "unknown"
	}

	if !utf8.ValidString(userAgent) {
		return "unknown"
	}

	runes := []rune(userAgent)
	if len(runes) > maxUserAgentRunes {
		return string(runes[:maxUserAgentRunes])
	}

	return userAgent
}
