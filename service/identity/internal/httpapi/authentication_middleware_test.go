package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	authenticateapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/authenticate"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const middlewareTestDeviceID = "0198f124-659f-7cbd-a441-dc7eea175074"

func TestAuthenticationMiddlewareInjectsPrincipal(t *testing.T) {
	t.Parallel()

	authenticator := &stubAuthenticator{
		execute: func(
			_ context.Context,
			input authenticateapp.Input,
		) (appauth.Principal, error) {
			if input.AccessToken != "access-token" {
				t.Fatalf("unexpected access token %q", input.AccessToken)
			}

			return middlewarePrincipal(), nil
		},
	}

	nextCalled := false
	next := http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		nextCalled = true

		principal, ok := authenticatedPrincipalFromContext(r.Context())
		if !ok || principal.DeviceID != middlewareTestDeviceID {
			t.Fatalf("unexpected principal: %+v", principal)
		}

		w.WriteHeader(http.StatusNoContent)
	})

	handler := applyMiddleware(
		testLogger(),
		authenticationMiddleware(
			testLogger(),
			authenticator,
			next,
		),
	)

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", response.Code)
	}

	if !nextCalled {
		t.Fatal("expected protected handler to run")
	}
}

func TestAuthenticationMiddlewareRejectsMissingToken(t *testing.T) {
	t.Parallel()

	handler := applyMiddleware(
		testLogger(),
		authenticationMiddleware(
			testLogger(),
			&stubAuthenticator{
				execute: func(
					context.Context,
					authenticateapp.Input,
				) (appauth.Principal, error) {
					t.Fatal("authenticator must not be called")
					return appauth.Principal{}, nil
				},
			},
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("protected handler must not run")
			}),
		),
	)

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", response.Code)
	}

	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestBearerTokenRejectsMultipleHeaders(t *testing.T) {
	t.Parallel()

	_, err := bearerToken([]string{
		"Bearer first",
		"Bearer second",
	})
	if err == nil {
		t.Fatal("expected multiple Authorization headers to be rejected")
	}
}

func middlewarePrincipal() appauth.Principal {
	return appauth.Principal{
		UserID: identity.ID(
			"0198f124-659f-7cbd-a441-dc7eea175073",
		),
		DeviceID:       middlewareTestDeviceID,
		PlatformRole:   identity.PlatformRoleNone,
		AccessTokenJTI: "0198f124-659f-7cbd-a441-dc7eea175075",
		IssuedAt:       time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC),
		ExpiresAt:      time.Date(2026, time.July, 30, 12, 15, 0, 0, time.UTC),
	}
}

type stubAuthenticator struct {
	execute func(
		context.Context,
		authenticateapp.Input,
	) (appauth.Principal, error)
}

func (s *stubAuthenticator) Execute(
	ctx context.Context,
	input authenticateapp.Input,
) (appauth.Principal, error) {
	return s.execute(ctx, input)
}
