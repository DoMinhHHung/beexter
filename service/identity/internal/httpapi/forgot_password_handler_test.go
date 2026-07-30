package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appforgotpassword "github.com/DoMinhHHung/beexter/service/identity/internal/application/forgotpassword"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

func TestForgotPasswordHandlerAcceptsRequest(t *testing.T) {
	t.Parallel()

	executor := &stubForgotPasswordExecutor{
		execute: func(
			_ context.Context,
			input appforgotpassword.Input,
		) (appforgotpassword.Output, error) {
			if input.Email != "User@Example.COM" {
				t.Fatalf("unexpected email %q", input.Email)
			}
			if input.Locale != "ja" {
				t.Fatalf("expected locale ja, got %q", input.Locale)
			}
			if input.IPAddress.String() != "192.0.2.10" {
				t.Fatalf("unexpected IP %s", input.IPAddress)
			}
			if input.RequestID == "" {
				t.Fatal("expected request ID")
			}
			return appforgotpassword.Output{Accepted: true}, nil
		},
	}

	handler := applyMiddleware(
		testLogger(),
		forgotPasswordHandler(testLogger(), executor),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/forgot-password",
		strings.NewReader(`{"email":"User@Example.COM"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept-Language", "ja-JP, en;q=0.8")
	request.RemoteAddr = "192.0.2.10:54321"

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusAccepted,
			response.Code,
			response.Body.String(),
		)
	}

	var payload forgotPasswordResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.Data.Accepted {
		t.Fatal("expected accepted=true")
	}
}

func TestForgotPasswordHandlerMapsRateLimit(t *testing.T) {
	t.Parallel()

	handler := applyMiddleware(
		testLogger(),
		forgotPasswordHandler(
			testLogger(),
			&stubForgotPasswordExecutor{
				execute: func(
					context.Context,
					appforgotpassword.Input,
				) (appforgotpassword.Output, error) {
					return appforgotpassword.Output{},
						domain.NewError(domain.ErrRateLimited)
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/forgot-password",
		strings.NewReader(`{"email":"user@example.com"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.10:54321"

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusTooManyRequests {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusTooManyRequests,
			response.Code,
		)
	}
}

type stubForgotPasswordExecutor struct {
	execute func(
		context.Context,
		appforgotpassword.Input,
	) (appforgotpassword.Output, error)
}

func (s *stubForgotPasswordExecutor) Execute(
	ctx context.Context,
	input appforgotpassword.Input,
) (appforgotpassword.Output, error) {
	return s.execute(ctx, input)
}
