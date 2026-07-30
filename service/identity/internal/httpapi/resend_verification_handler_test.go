package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appresendverification "github.com/DoMinhHHung/beexter/service/identity/internal/application/resendverification"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

func TestResendVerificationHandlerAcceptsRequest(
	t *testing.T,
) {
	t.Parallel()

	executor := &stubResendVerificationExecutor{
		execute: func(
			_ context.Context,
			input appresendverification.Input,
		) (
			appresendverification.Output,
			error,
		) {
			if input.Email != "User@Example.COM" {
				t.Fatalf(
					"unexpected email %q",
					input.Email,
				)
			}

			if input.IPAddress.String() !=
				"192.0.2.10" {
				t.Fatalf(
					"unexpected IP address %s",
					input.IPAddress,
				)
			}

			if input.RequestID == "" {
				t.Fatal(
					"expected generated request ID",
				)
			}

			return appresendverification.Output{
				Accepted: true,
			}, nil
		},
	}

	handler := applyMiddleware(
		testLogger(),
		resendVerificationHandler(
			testLogger(),
			executor,
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/resend-verification",
		strings.NewReader(
			`{"email":"User@Example.COM"}`,
		),
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)
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

	var payload resendVerificationResponse

	if err := json.NewDecoder(
		response.Body,
	).Decode(&payload); err != nil {
		t.Fatalf(
			"decode response: %v",
			err,
		)
	}

	if !payload.Data.Accepted {
		t.Fatal(
			"expected accepted=true",
		)
	}
}

func TestResendVerificationHandlerRejectsUnknownField(
	t *testing.T,
) {
	t.Parallel()

	executorCalled := false

	handler := applyMiddleware(
		testLogger(),
		resendVerificationHandler(
			testLogger(),
			&stubResendVerificationExecutor{
				execute: func(
					context.Context,
					appresendverification.Input,
				) (
					appresendverification.Output,
					error,
				) {
					executorCalled = true

					return appresendverification.Output{
						Accepted: true,
					}, nil
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/resend-verification",
		strings.NewReader(
			`{"email":"user@example.com","otp":"123456"}`,
		),
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

	if executorCalled {
		t.Fatal(
			"executor must not run for invalid JSON contract",
		)
	}
}

func TestResendVerificationHandlerMapsRateLimit(
	t *testing.T,
) {
	t.Parallel()

	handler := applyMiddleware(
		testLogger(),
		resendVerificationHandler(
			testLogger(),
			&stubResendVerificationExecutor{
				execute: func(
					context.Context,
					appresendverification.Input,
				) (
					appresendverification.Output,
					error,
				) {
					return appresendverification.Output{},
						domain.NewError(
							domain.ErrRateLimited,
						)
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/resend-verification",
		strings.NewReader(
			`{"email":"user@example.com"}`,
		),
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)
	request.RemoteAddr = "192.0.2.10:54321"

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code !=
		http.StatusTooManyRequests {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusTooManyRequests,
			response.Code,
		)
	}

	var payload errorResponse

	if err := json.NewDecoder(
		response.Body,
	).Decode(&payload); err != nil {
		t.Fatalf(
			"decode error response: %v",
			err,
		)
	}

	if payload.Error.Code !=
		string(domain.ErrRateLimited) {
		t.Fatalf(
			"unexpected error code %q",
			payload.Error.Code,
		)
	}
}

type stubResendVerificationExecutor struct {
	execute func(
		context.Context,
		appresendverification.Input,
	) (
		appresendverification.Output,
		error,
	)
}

func (s *stubResendVerificationExecutor) Execute(
	ctx context.Context,
	input appresendverification.Input,
) (
	appresendverification.Output,
	error,
) {
	return s.execute(ctx, input)
}
