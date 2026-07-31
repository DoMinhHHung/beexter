package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	sessionmanagementapp "github.com/DoMinhHHung/beexster/service/identity/internal/application/sessionmanagement"
)

func TestLogoutCurrentHandler(t *testing.T) {
	t.Parallel()

	called := false
	manager := &stubSessionManager{
		logoutCurrent: func(
			_ context.Context,
			principal appauth.Principal,
		) error {
			called = true
			if principal.DeviceID != middlewareTestDeviceID {
				t.Fatalf("unexpected principal: %+v", principal)
			}
			return nil
		},
	}

	handler := withPrincipal(
		middlewarePrincipal(),
		logoutCurrentHandler(testLogger(), manager),
	)

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", response.Code)
	}

	if !called {
		t.Fatal("expected logout-current call")
	}
}

func TestLogoutAllHandler(t *testing.T) {
	t.Parallel()

	called := false
	manager := &stubSessionManager{
		logoutAll: func(
			_ context.Context,
			principal appauth.Principal,
		) error {
			called = true
			if principal.UserID != middlewarePrincipal().UserID {
				t.Fatalf("unexpected principal: %+v", principal)
			}
			return nil
		},
	}

	handler := withPrincipal(
		middlewarePrincipal(),
		logoutAllHandler(testLogger(), manager),
	)

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", response.Code)
	}

	if !called {
		t.Fatal("expected logout-all call")
	}
}

func TestListSessionsHandlerDoesNotExposeToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 30, 13, 0, 0, 0, time.UTC)
	manager := &stubSessionManager{
		list: func(
			context.Context,
			appauth.Principal,
		) ([]sessionmanagementapp.Session, error) {
			return []sessionmanagementapp.Session{
				{
					DeviceID:   middlewareTestDeviceID,
					UserAgent:  "test-agent",
					IPAddress:  "192.0.2.10",
					CreatedAt:  now,
					ExpiresAt:  now.Add(7 * 24 * time.Hour),
					LastUsedAt: now,
					Current:    true,
				},
			}, nil
		},
	}

	handler := withPrincipal(
		middlewarePrincipal(),
		listSessionsHandler(testLogger(), manager),
	)

	request := httptest.NewRequest(http.MethodGet, "/v1/me/sessions", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
	}

	rawBody := response.Body.String()
	if strings.Contains(rawBody, `"token"`) {
		t.Fatalf("session response exposed token field: %s", rawBody)
	}

	var payload sessionsResponse
	if err := json.Unmarshal([]byte(rawBody), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(payload.Data.Sessions) != 1 ||
		!payload.Data.Sessions[0].Current {
		t.Fatalf("unexpected sessions response: %+v", payload)
	}
}

func TestRevokeSessionHandlerUsesPathDeviceID(t *testing.T) {
	t.Parallel()

	var receivedDeviceID string
	manager := &stubSessionManager{
		revoke: func(
			_ context.Context,
			_ appauth.Principal,
			deviceID string,
		) error {
			receivedDeviceID = deviceID
			return nil
		},
	}

	handler := withPrincipal(
		middlewarePrincipal(),
		revokeSessionHandler(testLogger(), manager),
	)

	request := httptest.NewRequest(
		http.MethodDelete,
		"/v1/me/sessions/"+middlewareTestDeviceID,
		nil,
	)
	request.SetPathValue("device_id", middlewareTestDeviceID)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", response.Code)
	}

	if receivedDeviceID != middlewareTestDeviceID {
		t.Fatalf("unexpected device ID %q", receivedDeviceID)
	}
}

func withPrincipal(
	principal appauth.Principal,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(
			r.Context(),
			authenticatedPrincipalContextKey{},
			principal,
		)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type stubSessionManager struct {
	logoutCurrent func(context.Context, appauth.Principal) error
	logoutAll     func(context.Context, appauth.Principal) error
	list          func(
		context.Context,
		appauth.Principal,
	) ([]sessionmanagementapp.Session, error)
	revoke func(context.Context, appauth.Principal, string) error
}

func (s *stubSessionManager) LogoutCurrent(
	ctx context.Context,
	principal appauth.Principal,
) error {
	if s.logoutCurrent == nil {
		return nil
	}
	return s.logoutCurrent(ctx, principal)
}

func (s *stubSessionManager) LogoutAll(
	ctx context.Context,
	principal appauth.Principal,
) error {
	if s.logoutAll == nil {
		return nil
	}
	return s.logoutAll(ctx, principal)
}

func (s *stubSessionManager) List(
	ctx context.Context,
	principal appauth.Principal,
) ([]sessionmanagementapp.Session, error) {
	if s.list == nil {
		return nil, nil
	}
	return s.list(ctx, principal)
}

func (s *stubSessionManager) Revoke(
	ctx context.Context,
	principal appauth.Principal,
	deviceID string,
) error {
	if s.revoke == nil {
		return nil
	}
	return s.revoke(ctx, principal, deviceID)
}
