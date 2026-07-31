package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func TestRoleAuthorizationMiddlewareAllowsConfiguredRole(t *testing.T) {
	t.Parallel()

	nextCalled := false
	handler := roleAuthorizationMiddleware(
		testLogger(),
		[]identity.Role{identity.RoleAdmin, identity.RoleViceAdmin},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	request := httptest.NewRequest(http.MethodPost, "/v1/admin/identities", nil)
	request = request.WithContext(context.WithValue(
		request.Context(),
		authenticatedPrincipalContextKey{},
		appauth.Principal{
			UserID: identity.ID("0198f124-659f-7cbd-a441-dc7eea175073"),
			Role:   identity.RoleViceAdmin,
		},
	))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, response.Code)
	}
	if !nextCalled {
		t.Fatal("expected next handler to run")
	}
}

func TestRoleAuthorizationMiddlewareRejectsForbiddenRole(t *testing.T) {
	t.Parallel()

	nextCalled := false
	handler := roleAuthorizationMiddleware(
		testLogger(),
		[]identity.Role{identity.RoleAdmin, identity.RoleViceAdmin},
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			nextCalled = true
		}),
	)

	request := httptest.NewRequest(http.MethodPost, "/v1/admin/identities", nil)
	request = request.WithContext(context.WithValue(
		request.Context(),
		authenticatedPrincipalContextKey{},
		appauth.Principal{
			UserID: identity.ID("0198f124-659f-7cbd-a441-dc7eea175073"),
			Role:   identity.RoleClient,
		},
	))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, response.Code)
	}
	if nextCalled {
		t.Fatal("next handler must not run for forbidden role")
	}

	var payload errorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if payload.Error.Code != string(domain.ErrForbidden) {
		t.Fatalf("expected code %q, got %q", domain.ErrForbidden, payload.Error.Code)
	}
}
