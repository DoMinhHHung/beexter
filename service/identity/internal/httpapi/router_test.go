package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	authenticateapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/authenticate"
	appcreateidentity "github.com/DoMinhHHung/beexter/service/identity/internal/application/createidentity"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func TestHealthHandler(t *testing.T) {
	t.Parallel()

	handler := NewRouter(
		testLogger(),
		nil,
		nil,
		RouterDependencies{},
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/health",
		nil,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			response.Code,
		)
	}

	var payload statusResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Status != "ok" {
		t.Fatalf("expected status ok, got %q", payload.Status)
	}

	if response.Header().Get("X-Request-ID") == "" {
		t.Error("expected X-Request-ID response header")
	}
}

func TestAdminIdentityRouteRejectsViceAdminClaim(t *testing.T) {
	t.Parallel()

	handler := NewRouter(
		testLogger(),
		nil,
		nil,
		RouterDependencies{
			Authenticator: &stubAuthenticator{execute: func(
				context.Context,
				authenticateapp.Input,
			) (appauth.Principal, error) {
				return appauth.Principal{
					UserID:       identity.ID("0198f124-659f-7cbd-a441-dc7eea175073"),
					PlatformRole: identity.PlatformRoleViceAdmin,
				}, nil
			}},
			CreatePrivilegedIdentity: &stubCreatePrivilegedIdentityExecutor{
				execute: func(
					context.Context,
					appcreateidentity.Input,
				) (appcreateidentity.Output, error) {
					t.Fatal("privileged identity executor must not be called")
					return appcreateidentity.Output{}, nil
				},
			},
		},
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/admin/identities",
		strings.NewReader(
			`{"email":"viceadmin@example.com","password":"Secure1!","platform_role":"VICE_ADMIN"}`,
		),
	)
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusForbidden,
			response.Code,
			response.Body.String(),
		)
	}
}
