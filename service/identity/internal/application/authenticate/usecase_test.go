package authenticate

import (
	"context"
	"errors"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	authTestUserID = identity.ID(
		"0198f124-659f-7cbd-a441-dc7eea175073",
	)
	authTestDeviceID = "0198f124-659f-7cbd-a441-dc7eea175074"
	authTestJTI      = "0198f124-659f-7cbd-a441-dc7eea175075"
)

var authTestNow = time.Date(
	2026,
	time.July,
	30,
	13,
	0,
	0,
	0,
	time.UTC,
)

func TestUseCaseAuthenticatesCurrentIdentity(t *testing.T) {
	t.Parallel()

	useCase := newAuthenticationUseCase(
		t,
		&fakeRepository{
			find: func(
				_ context.Context,
				identityID identity.ID,
			) (identity.Identity, error) {
				if identityID != authTestUserID {
					t.Fatalf("unexpected identity ID %q", identityID)
				}

				return activeIdentity(), nil
			},
		},
		&fakeVerifier{
			verify: func(
				rawToken string,
				now time.Time,
			) (appauth.VerifiedAccessToken, error) {
				if rawToken != "access-token" {
					t.Fatalf("unexpected access token %q", rawToken)
				}

				if !now.Equal(authTestNow) {
					t.Fatalf("unexpected verification time %s", now)
				}

				return validVerifiedClaims(), nil
			},
		},
	)

	principal, err := useCase.Execute(
		context.Background(),
		Input{AccessToken: "access-token"},
	)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	if principal.UserID != authTestUserID ||
		principal.DeviceID != authTestDeviceID ||
		principal.Role != identity.RoleClient ||
		!principal.EmailVerified ||
		principal.AccessTokenJTI != authTestJTI {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}

func TestUseCaseMapsExpiredToken(t *testing.T) {
	t.Parallel()

	useCase := newAuthenticationUseCase(
		t,
		&fakeRepository{find: returnActiveIdentity},
		&fakeVerifier{
			verify: func(
				string,
				time.Time,
			) (appauth.VerifiedAccessToken, error) {
				return appauth.VerifiedAccessToken{},
					appauth.ErrAccessTokenExpired
			},
		},
	)

	_, err := useCase.Execute(
		context.Background(),
		Input{AccessToken: "access-token"},
	)

	assertAuthenticationDomainCode(t, err, domain.ErrTokenExpired)
}

func TestUseCaseRejectsStaleRoleClaim(t *testing.T) {
	t.Parallel()

	claims := validVerifiedClaims()
	claims.Role = identity.RoleJobSeeker

	useCase := newAuthenticationUseCase(
		t,
		&fakeRepository{find: returnActiveIdentity},
		&fakeVerifier{
			verify: func(
				string,
				time.Time,
			) (appauth.VerifiedAccessToken, error) {
				return claims, nil
			},
		},
	)

	_, err := useCase.Execute(
		context.Background(),
		Input{AccessToken: "access-token"},
	)

	assertAuthenticationDomainCode(t, err, domain.ErrTokenInvalid)
}

func TestUseCaseRejectsInactiveIdentity(t *testing.T) {
	t.Parallel()

	account := activeIdentity()
	account.Status = identity.StatusInactive

	useCase := newAuthenticationUseCase(
		t,
		&fakeRepository{
			find: func(
				context.Context,
				identity.ID,
			) (identity.Identity, error) {
				return account, nil
			},
		},
		&fakeVerifier{
			verify: func(
				string,
				time.Time,
			) (appauth.VerifiedAccessToken, error) {
				return validVerifiedClaims(), nil
			},
		},
	)

	_, err := useCase.Execute(
		context.Background(),
		Input{AccessToken: "access-token"},
	)

	assertAuthenticationDomainCode(t, err, domain.ErrAccountInactive)
}

func newAuthenticationUseCase(
	t *testing.T,
	repository Repository,
	verifier AccessTokenVerifier,
) *UseCase {
	t.Helper()

	useCase, err := New(
		repository,
		verifier,
		func() time.Time { return authTestNow },
	)
	if err != nil {
		t.Fatalf("create authentication use case: %v", err)
	}

	return useCase
}

func activeIdentity() identity.Identity {
	return identity.Identity{
		ID:            authTestUserID,
		Email:         "user@example.com",
		Role:          identity.RoleClient,
		Status:        identity.StatusActive,
		EmailVerified: true,
	}
}

func returnActiveIdentity(
	context.Context,
	identity.ID,
) (identity.Identity, error) {
	return activeIdentity(), nil
}

func validVerifiedClaims() appauth.VerifiedAccessToken {
	return appauth.VerifiedAccessToken{
		Subject:       authTestUserID,
		DeviceID:      authTestDeviceID,
		Role:          identity.RoleClient,
		EmailVerified: true,
		IssuedAt:      authTestNow.Add(-time.Minute),
		ExpiresAt:     authTestNow.Add(59 * time.Minute),
		JTI:           authTestJTI,
	}
}

func assertAuthenticationDomainCode(
	t *testing.T,
	err error,
	expected domain.ErrorCode,
) {
	t.Helper()

	var domainError *domain.Error
	if !errors.As(err, &domainError) {
		t.Fatalf("expected domain error, got %v", err)
	}

	if domainError.Code != expected {
		t.Fatalf(
			"expected code %q, got %q",
			expected,
			domainError.Code,
		)
	}
}

type fakeRepository struct {
	find func(
		context.Context,
		identity.ID,
	) (identity.Identity, error)
}

func (f *fakeRepository) FindByID(
	ctx context.Context,
	identityID identity.ID,
) (identity.Identity, error) {
	return f.find(ctx, identityID)
}

type fakeVerifier struct {
	verify func(
		string,
		time.Time,
	) (appauth.VerifiedAccessToken, error)
}

func (f *fakeVerifier) Verify(
	rawToken string,
	now time.Time,
) (appauth.VerifiedAccessToken, error) {
	return f.verify(rawToken, now)
}
