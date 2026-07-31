package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	applogin "github.com/DoMinhHHung/beexter/service/identity/internal/application/login"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func TestLoginHandlerReturnsTokens(t *testing.T) {
	t.Parallel()

	executor := &stubLoginExecutor{
		execute: func(
			_ context.Context,
			input applogin.Input,
		) (applogin.Output, error) {
			if input.Email != "user@example.com" ||
				input.Password != "Secure1!" ||
				input.IPAddress.String() != "192.0.2.10" ||
				input.UserAgent != "test-agent" ||
				input.RequestID == "" {
				t.Fatalf("unexpected login input: %+v", input)
			}

			return applogin.Output{
				AccessToken:           "access-token",
				RefreshToken:          "refresh-token",
				TokenType:             "Bearer",
				AccessTokenExpiresAt:  time.Date(2026, time.July, 30, 13, 0, 0, 500_000_000, time.UTC),
				RefreshTokenExpiresAt: time.Date(2026, time.August, 6, 12, 0, 0, 750_000_000, time.UTC),
				DeviceID:              "0198f124-659f-7cbd-a441-dc7eea175072",
				User: applogin.User{
					ID:            identity.ID("0198f124-659f-7cbd-a441-dc7eea175073"),
					Email:         "user@example.com",
					PlatformRole:  identity.PlatformRoleNone,
					EmailVerified: true,
				},
			}, nil
		},
	}

	handler := applyMiddleware(
		testLogger(),
		loginHandler(testLogger(), executor),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(
			`{"email":"user@example.com","password":"Secure1!"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "test-agent")
	request.RemoteAddr = "192.0.2.10:54321"

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusOK,
			response.Code,
			response.Body.String(),
		)
	}

	responseBody := response.Body.Bytes()
	var payload loginResponse
	if err := json.Unmarshal(responseBody, &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Data.AccessToken != "access-token" ||
		payload.Data.RefreshToken != "refresh-token" ||
		payload.Data.TokenType != "Bearer" ||
		payload.Data.AccessTokenExpiresAt != "2026-07-30T13:00:00.5Z" ||
		payload.Data.RefreshTokenExpiresAt != "2026-08-06T12:00:00.75Z" ||
		payload.Data.User.Email != "user@example.com" {
		t.Fatalf("unexpected response: %+v", payload)
	}

	var rawPayload map[string]any
	if err := json.Unmarshal(responseBody, &rawPayload); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	data := rawPayload["data"].(map[string]any)
	user := data["user"].(map[string]any)
	if _, exists := user["role"]; exists {
		t.Fatal("login response must not contain legacy role")
	}
	if _, exists := user["platform_role"]; exists {
		t.Fatal("ordinary login response must omit platform_role")
	}
}

func TestLoginHandlerReturnsAssignedPlatformRole(t *testing.T) {
	t.Parallel()

	executor := &stubLoginExecutor{execute: func(
		context.Context,
		applogin.Input,
	) (applogin.Output, error) {
		return applogin.Output{
			AccessToken:           "access-token",
			RefreshToken:          "refresh-token",
			TokenType:             "Bearer",
			AccessTokenExpiresAt:  time.Date(2026, time.July, 30, 13, 0, 0, 0, time.UTC),
			RefreshTokenExpiresAt: time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC),
			DeviceID:              "0198f124-659f-7cbd-a441-dc7eea175072",
			User: applogin.User{
				ID:            identity.ID("0198f124-659f-7cbd-a441-dc7eea175073"),
				Email:         "admin@example.com",
				PlatformRole:  identity.PlatformRoleAdmin,
				EmailVerified: true,
			},
		}, nil
	}}

	handler := applyMiddleware(testLogger(), loginHandler(testLogger(), executor))
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"email":"admin@example.com","password":"Secure1!"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.10:54321"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload loginResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Data.User.PlatformRole != string(identity.PlatformRoleAdmin) {
		t.Fatalf("unexpected platform role %q", payload.Data.User.PlatformRole)
	}
}

func TestLoginHandlerMapsInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := applyMiddleware(
		testLogger(),
		loginHandler(
			testLogger(),
			&stubLoginExecutor{
				execute: func(
					context.Context,
					applogin.Input,
				) (applogin.Output, error) {
					return applogin.Output{}, domain.NewError(
						domain.ErrInvalidCredentials,
					)
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(
			`{"email":"user@example.com","password":"wrong"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.10:54321"

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusUnauthorized,
			response.Code,
		)
	}

	var payload errorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Error.Code != string(domain.ErrInvalidCredentials) {
		t.Fatalf("unexpected error code %q", payload.Error.Code)
	}
}

type stubLoginExecutor struct {
	execute func(
		context.Context,
		applogin.Input,
	) (applogin.Output, error)
}

func (s *stubLoginExecutor) Execute(
	ctx context.Context,
	input applogin.Input,
) (applogin.Output, error) {
	return s.execute(ctx, input)
}
