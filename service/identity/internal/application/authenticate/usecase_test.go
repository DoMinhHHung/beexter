package authenticate

import (
	"context"
	"errors"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

const (
	authTestUserID   = identity.ID("0198f124-659f-7cbd-a441-dc7eea175073")
	authTestDeviceID = "0198f124-659f-7cbd-a441-dc7eea175074"
	authTestJTI      = "0198f124-659f-7cbd-a441-dc7eea175075"
)

var authTestNow = time.Date(2026, time.July, 30, 13, 0, 0, 0, time.UTC)

func TestUseCaseAuthenticatesFromVerifiedTokenWithoutRepository(t *testing.T) {
	t.Parallel()

	verifier := &fakeVerifier{
		verify: func(rawToken string, now time.Time) (appauth.VerifiedAccessToken, error) {
			if rawToken != "access-token" {
				t.Fatalf("unexpected access token %q", rawToken)
			}
			if !now.Equal(authTestNow) {
				t.Fatalf("unexpected verification time %s", now)
			}

			claims := validVerifiedClaims()
			claims.PlatformRole = identity.PlatformRoleAdmin
			return claims, nil
		},
	}

	useCase := newAuthenticationUseCase(t, verifier)
	principal, err := useCase.Execute(
		context.Background(),
		Input{AccessToken: " access-token "},
	)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	if principal.UserID != authTestUserID ||
		principal.DeviceID != authTestDeviceID ||
		principal.PlatformRole != identity.PlatformRoleAdmin ||
		principal.AccessTokenJTI != authTestJTI ||
		!principal.IssuedAt.Equal(authTestNow.Add(-time.Minute)) ||
		!principal.ExpiresAt.Equal(authTestNow.Add(14*time.Minute)) {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}

func TestUseCaseOrdinaryPrincipalHasNoPlatformRole(t *testing.T) {
	t.Parallel()

	useCase := newAuthenticationUseCase(t, &fakeVerifier{
		verify: func(string, time.Time) (appauth.VerifiedAccessToken, error) {
			return validVerifiedClaims(), nil
		},
	})

	principal, err := useCase.Execute(
		context.Background(),
		Input{AccessToken: "access-token"},
	)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if principal.PlatformRole != identity.PlatformRoleNone {
		t.Fatalf("unexpected platform role %q", principal.PlatformRole)
	}
}

func TestUseCasePreservesSubSecondVerificationClock(t *testing.T) {
	t.Parallel()

	wantNow := authTestNow.Add(750 * time.Millisecond)
	verifier := &fakeVerifier{
		verify: func(_ string, now time.Time) (appauth.VerifiedAccessToken, error) {
			if !now.Equal(wantNow) {
				t.Fatalf("verification time = %s, want %s", now, wantNow)
			}
			return validVerifiedClaims(), nil
		},
	}
	useCase, err := New(verifier, func() time.Time { return wantNow })
	if err != nil {
		t.Fatalf("create authentication use case: %v", err)
	}

	if _, err := useCase.Execute(
		context.Background(),
		Input{AccessToken: "access-token"},
	); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
}

func TestUseCaseMapsVerifierErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		verifyErr error
		wantCode  domain.ErrorCode
	}{
		{name: "invalid", verifyErr: appauth.ErrAccessTokenInvalid, wantCode: domain.ErrTokenInvalid},
		{name: "expired", verifyErr: appauth.ErrAccessTokenExpired, wantCode: domain.ErrTokenExpired},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			useCase := newAuthenticationUseCase(t, &fakeVerifier{
				verify: func(string, time.Time) (appauth.VerifiedAccessToken, error) {
					return appauth.VerifiedAccessToken{}, test.verifyErr
				},
			})

			_, err := useCase.Execute(
				context.Background(),
				Input{AccessToken: "access-token"},
			)
			assertAuthenticationDomainCode(t, err, test.wantCode)
		})
	}
}

func TestUseCaseRejectsBlankAndOversizedTokensBeforeVerification(t *testing.T) {
	t.Parallel()

	verifier := &fakeVerifier{
		verify: func(string, time.Time) (appauth.VerifiedAccessToken, error) {
			t.Fatal("verifier must not be called")
			return appauth.VerifiedAccessToken{}, nil
		},
	}
	useCase := newAuthenticationUseCase(t, verifier)

	for _, rawToken := range []string{"   ", string(make([]byte, maxAccessTokenLength+1))} {
		_, err := useCase.Execute(context.Background(), Input{AccessToken: rawToken})
		assertAuthenticationDomainCode(t, err, domain.ErrTokenInvalid)
	}
}

func newAuthenticationUseCase(t *testing.T, verifier AccessTokenVerifier) *UseCase {
	t.Helper()

	useCase, err := New(verifier, func() time.Time { return authTestNow })
	if err != nil {
		t.Fatalf("create authentication use case: %v", err)
	}
	return useCase
}

func validVerifiedClaims() appauth.VerifiedAccessToken {
	return appauth.VerifiedAccessToken{
		Subject:   authTestUserID,
		DeviceID:  authTestDeviceID,
		IssuedAt:  authTestNow.Add(-time.Minute),
		ExpiresAt: authTestNow.Add(14 * time.Minute),
		JTI:       authTestJTI,
	}
}

func assertAuthenticationDomainCode(t *testing.T, err error, expected domain.ErrorCode) {
	t.Helper()

	var domainError *domain.Error
	if !errors.As(err, &domainError) {
		t.Fatalf("expected domain error, got %v", err)
	}
	if domainError.Code != expected {
		t.Fatalf("expected code %q, got %q", expected, domainError.Code)
	}
}

type fakeVerifier struct {
	verify func(string, time.Time) (appauth.VerifiedAccessToken, error)
}

func (f *fakeVerifier) Verify(rawToken string, now time.Time) (appauth.VerifiedAccessToken, error) {
	return f.verify(rawToken, now)
}
