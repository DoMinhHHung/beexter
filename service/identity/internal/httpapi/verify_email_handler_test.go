package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appverifyemail "github.com/DoMinhHHung/beexter/service/identity/internal/application/verifyemail"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const handlerVerificationTokenID = "0198f124-659f-7cbd-a441-dc7eea175073"

func TestVerifyEmailHandler(t *testing.T) {
	t.Parallel()

	executor := &stubVerifyEmailExecutor{
		execute: func(
			_ context.Context,
			input appverifyemail.Input,
		) (appverifyemail.Output, error) {
			if input.Token !=
				handlerVerificationTokenID {
				t.Fatalf(
					"unexpected token %q",
					input.Token,
				)
			}

			return appverifyemail.Output{
				IdentityID: identity.ID(
					"0198f124-659f-7cbd-a441-dc7eea175074",
				),
				EmailVerified: true,
			}, nil
		},
	}

	handler := applyMiddleware(
		testLogger(),
		verifyEmailHandler(
			testLogger(),
			executor,
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/verify-email",
		strings.NewReader(
			`{"token":"`+
				handlerVerificationTokenID+
				`"}`,
		),
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)

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

	var payload verifyEmailResponse

	if err := json.NewDecoder(
		response.Body,
	).Decode(&payload); err != nil {
		t.Fatalf(
			"decode response: %v",
			err,
		)
	}

	if !payload.Data.EmailVerified {
		t.Fatal(
			"expected email_verified=true",
		)
	}
}

func TestVerifyEmailHandlerRejectsUnknownJSONField(
	t *testing.T,
) {
	t.Parallel()

	executorCalled := false

	handler := applyMiddleware(
		testLogger(),
		verifyEmailHandler(
			testLogger(),
			&stubVerifyEmailExecutor{
				execute: func(
					context.Context,
					appverifyemail.Input,
				) (
					appverifyemail.Output,
					error,
				) {
					executorCalled = true

					return appverifyemail.Output{},
						nil
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/verify-email",
		strings.NewReader(
			`{"token":"`+
				handlerVerificationTokenID+
				`","otp":"123456"}`,
		),
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)

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

func TestVerifyEmailHandlerMapsExpiredToken(
	t *testing.T,
) {
	t.Parallel()

	handler := applyMiddleware(
		testLogger(),
		verifyEmailHandler(
			testLogger(),
			&stubVerifyEmailExecutor{
				execute: func(
					context.Context,
					appverifyemail.Input,
				) (
					appverifyemail.Output,
					error,
				) {
					return appverifyemail.Output{},
						domain.NewError(
							domain.ErrTokenExpired,
						)
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/verify-email",
		strings.NewReader(
			`{"token":"`+
				handlerVerificationTokenID+
				`"}`,
		),
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)

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

	if err := json.NewDecoder(
		response.Body,
	).Decode(&payload); err != nil {
		t.Fatalf(
			"decode error response: %v",
			err,
		)
	}

	if payload.Error.Code !=
		string(domain.ErrTokenExpired) {
		t.Fatalf(
			"unexpected error code %q",
			payload.Error.Code,
		)
	}
}

type stubVerifyEmailExecutor struct {
	execute func(
		context.Context,
		appverifyemail.Input,
	) (appverifyemail.Output, error)
}

func (s *stubVerifyEmailExecutor) Execute(
	ctx context.Context,
	input appverifyemail.Input,
) (appverifyemail.Output, error) {
	return s.execute(ctx, input)
}
