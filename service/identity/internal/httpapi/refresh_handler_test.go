package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apprefresh "github.com/DoMinhHHung/beexster/service/identity/internal/application/refresh"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
)

func TestRefreshHandlerRotatesTokens(t *testing.T) {
	t.Parallel()

	executor := &stubRefreshExecutor{
		execute: func(
			_ context.Context,
			input apprefresh.Input,
		) (apprefresh.Output, error) {
			if input.RefreshToken != "old-token" ||
				input.IPAddress.String() != "192.0.2.10" ||
				input.UserAgent != "test-agent" {
				t.Fatalf("unexpected input: %+v", input)
			}

			return apprefresh.Output{
				AccessToken:           "new-access",
				RefreshToken:          "new-refresh",
				TokenType:             "Bearer",
				AccessTokenExpiresAt:  time.Date(2026, 7, 30, 13, 0, 0, 500_000_000, time.UTC),
				RefreshTokenExpiresAt: time.Date(2026, 8, 6, 12, 0, 0, 750_000_000, time.UTC),
				DeviceID:              "0198f124-659f-7cbd-a441-dc7eea175074",
			}, nil
		},
	}

	handler := applyMiddleware(
		testLogger(),
		refreshHandler(testLogger(), executor),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/refresh",
		strings.NewReader(`{"refresh_token":"old-token"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "test-agent")
	request.RemoteAddr = "192.0.2.10:54321"

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, response.Code, response.Body.String())
	}

	var payload refreshResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Data.RefreshToken != "new-refresh" ||
		payload.Data.AccessToken != "new-access" ||
		payload.Data.AccessTokenExpiresAt != "2026-07-30T13:00:00.5Z" ||
		payload.Data.RefreshTokenExpiresAt != "2026-08-06T12:00:00.75Z" {
		t.Fatalf("unexpected response: %+v", payload)
	}
}

func TestRefreshHandlerMapsReuse(t *testing.T) {
	t.Parallel()

	handler := applyMiddleware(
		testLogger(),
		refreshHandler(
			testLogger(),
			&stubRefreshExecutor{
				execute: func(
					context.Context,
					apprefresh.Input,
				) (apprefresh.Output, error) {
					return apprefresh.Output{}, domain.NewError(
						domain.ErrTokenReuseDetected,
					)
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/refresh",
		strings.NewReader(`{"refresh_token":"reused-token"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.10:54321"

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, response.Code)
	}
}

func TestRefreshHandlerMapsAuthoritativeAccountRejection(t *testing.T) {
	t.Parallel()

	for _, code := range []domain.ErrorCode{
		domain.ErrEmailNotVerified,
		domain.ErrAccountInactive,
	} {
		code := code
		t.Run(string(code), func(t *testing.T) {
			t.Parallel()

			handler := applyMiddleware(
				testLogger(),
				refreshHandler(
					testLogger(),
					&stubRefreshExecutor{
						execute: func(
							context.Context,
							apprefresh.Input,
						) (apprefresh.Output, error) {
							return apprefresh.Output{}, domain.NewError(code)
						},
					},
				),
			)

			request := httptest.NewRequest(
				http.MethodPost,
				"/v1/auth/refresh",
				strings.NewReader(`{"refresh_token":"inactive-account-token"}`),
			)
			request.Header.Set("Content-Type", "application/json")
			request.RemoteAddr = "192.0.2.10:54321"
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
		})
	}
}

type stubRefreshExecutor struct {
	execute func(
		context.Context,
		apprefresh.Input,
	) (apprefresh.Output, error)
}

func (s *stubRefreshExecutor) Execute(
	ctx context.Context,
	input apprefresh.Input,
) (apprefresh.Output, error) {
	return s.execute(ctx, input)
}
