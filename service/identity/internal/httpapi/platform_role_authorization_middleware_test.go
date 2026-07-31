package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

func TestPlatformRoleAuthorizationMiddlewareAllowsAdmin(t *testing.T) {
	t.Parallel()

	nextCalled := false
	handler := platformRoleAuthorizationMiddleware(
		testLogger(),
		[]identity.PlatformRole{identity.PlatformRoleAdmin},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	request := requestWithPlatformRole(identity.PlatformRoleAdmin)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, response.Code)
	}
	if !nextCalled {
		t.Fatal("expected next handler to run")
	}
}

func TestPlatformRoleAuthorizationMiddlewareRejectsNonAdmin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		platformRole identity.PlatformRole
	}{
		{name: "vice admin", platformRole: identity.PlatformRoleViceAdmin},
		{name: "ordinary identity", platformRole: identity.PlatformRoleNone},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			nextCalled := false
			handler := platformRoleAuthorizationMiddleware(
				testLogger(),
				[]identity.PlatformRole{identity.PlatformRoleAdmin},
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					nextCalled = true
				}),
			)

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, requestWithPlatformRole(test.platformRole))

			if response.Code != http.StatusForbidden {
				t.Fatalf("expected status %d, got %d", http.StatusForbidden, response.Code)
			}
			if nextCalled {
				t.Fatal("next handler must not run for forbidden platform role")
			}

			var payload errorResponse
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if payload.Error.Code != string(domain.ErrForbidden) {
				t.Fatalf("expected code %q, got %q", domain.ErrForbidden, payload.Error.Code)
			}
		})
	}
}

func requestWithPlatformRole(platformRole identity.PlatformRole) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/identities", nil)
	return request.WithContext(context.WithValue(
		request.Context(),
		authenticatedPrincipalContextKey{},
		appauth.Principal{
			UserID:       identity.ID("0198f124-659f-7cbd-a441-dc7eea175073"),
			PlatformRole: platformRole,
		},
	))
}
