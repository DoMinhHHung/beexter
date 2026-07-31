package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appsignup "github.com/DoMinhHHung/beexter/service/identity/internal/application/signup"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func TestSignupHandlerCreatesIdentity(t *testing.T) {
	t.Parallel()

	executor := &stubSignupExecutor{
		execute: func(
			_ context.Context,
			input appsignup.Input,
		) (appsignup.Output, error) {
			if input.Email != "User@Example.COM" {
				t.Fatalf(
					"unexpected email: %q",
					input.Email,
				)
			}

			if input.Password != "Secure1!" {
				t.Fatal("unexpected password")
			}

			if input.IPAddress.String() != "192.0.2.10" {
				t.Fatalf(
					"unexpected IP address: %s",
					input.IPAddress,
				)
			}

			if input.RequestID == "" {
				t.Fatal("expected request ID")
			}

			return appsignup.Output{
				ID: identity.ID(
					"0198f124-659f-7cbd-a441-dc7eea175073",
				),
				Email: "user@example.com",
			}, nil
		},
	}

	handler := applyMiddleware(
		testLogger(),
		signupHandler(testLogger(), executor),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/signup",
		strings.NewReader(
			`{"email":"User@Example.COM","password":"Secure1!"}`,
		),
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)
	request.RemoteAddr = "192.0.2.10:54321"

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusCreated,
			response.Code,
			response.Body.String(),
		)
	}

	var payload signupResponse

	responseBody := response.Body.Bytes()
	if err := json.Unmarshal(responseBody, &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Data.ID !=
		"0198f124-659f-7cbd-a441-dc7eea175073" {
		t.Fatalf(
			"unexpected identity ID: %q",
			payload.Data.ID,
		)
	}

	if payload.Data.Email != "user@example.com" {
		t.Fatalf(
			"unexpected email: %q",
			payload.Data.Email,
		)
	}

	if payload.Data.EmailVerified {
		t.Fatal("new signup must not be email verified")
	}

	var rawPayload map[string]map[string]any
	if err := json.Unmarshal(responseBody, &rawPayload); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	if _, exists := rawPayload["data"]["role"]; exists {
		t.Fatal("signup response must not contain legacy role")
	}
	if _, exists := rawPayload["data"]["platform_role"]; exists {
		t.Fatal("signup response must not contain platform_role")
	}
}

func TestSignupHandlerRejectsLegacyRole(t *testing.T) {
	t.Parallel()

	handler := applyMiddleware(
		testLogger(),
		signupHandler(
			testLogger(),
			&stubSignupExecutor{
				execute: func(
					context.Context,
					appsignup.Input,
				) (appsignup.Output, error) {
					t.Fatal("executor must not be called")
					return appsignup.Output{}, nil
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/signup",
		strings.NewReader(
			`{"email":"user@example.com","password":"Secure1!","role":"CLIENT"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.10:54321"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusBadRequest,
			response.Code,
			response.Body.String(),
		)
	}
}

func TestSignupHandlerRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	handler := applyMiddleware(
		testLogger(),
		signupHandler(
			testLogger(),
			&stubSignupExecutor{
				execute: func(
					context.Context,
					appsignup.Input,
				) (appsignup.Output, error) {
					t.Fatal("executor must not be called")
					return appsignup.Output{}, nil
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/signup",
		strings.NewReader(`{"email":`),
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)
	request.RemoteAddr = "192.0.2.10:54321"

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusBadRequest,
			response.Code,
		)
	}
}

func TestSignupHandlerMapsDuplicateEmail(t *testing.T) {
	t.Parallel()

	handler := applyMiddleware(
		testLogger(),
		signupHandler(
			testLogger(),
			&stubSignupExecutor{
				execute: func(
					context.Context,
					appsignup.Input,
				) (appsignup.Output, error) {
					return appsignup.Output{},
						domain.NewError(
							domain.ErrEmailAlreadyExists,
						)
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/signup",
		strings.NewReader(
			`{"email":"user@example.com","password":"Secure1!"}`,
		),
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)
	request.RemoteAddr = "192.0.2.10:54321"

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusConflict,
			response.Code,
		)
	}

	var payload errorResponse

	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Error.Code !=
		string(domain.ErrEmailAlreadyExists) {
		t.Fatalf(
			"unexpected error code: %q",
			payload.Error.Code,
		)
	}
}

type stubSignupExecutor struct {
	execute func(
		context.Context,
		appsignup.Input,
	) (appsignup.Output, error)
}

func (s *stubSignupExecutor) Execute(
	ctx context.Context,
	input appsignup.Input,
) (appsignup.Output, error) {
	return s.execute(ctx, input)
}
