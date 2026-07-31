package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appresetpassword "github.com/DoMinhHHung/beexster/service/identity/internal/application/resetpassword"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
)

const handlerPasswordResetTokenID = "0198f124-659f-7cbd-a441-dc7eea175073"

func TestResetPasswordHandler(t *testing.T) {
	t.Parallel()

	executor := &stubResetPasswordExecutor{
		execute: func(
			_ context.Context,
			input appresetpassword.Input,
		) (appresetpassword.Output, error) {
			if input.Token != handlerPasswordResetTokenID {
				t.Fatalf("unexpected token %q", input.Token)
			}
			if input.NewPassword != "Secure2!" {
				t.Fatalf("unexpected password %q", input.NewPassword)
			}
			if input.IPAddress.String() != "192.0.2.10" {
				t.Fatalf("unexpected IP address %s", input.IPAddress)
			}
			if input.RequestID == "" {
				t.Fatal("expected request ID")
			}

			return appresetpassword.Output{
				PasswordReset: true,
			}, nil
		},
	}

	handler := applyMiddleware(
		testLogger(),
		resetPasswordHandler(testLogger(), executor),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/reset-password",
		strings.NewReader(
			`{"token":"`+
				handlerPasswordResetTokenID+
				`","new_password":"Secure2!"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
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

	var payload resetPasswordResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.Data.PasswordReset {
		t.Fatal("expected password_reset=true")
	}
}

func TestResetPasswordHandlerRejectsUnknownField(t *testing.T) {
	t.Parallel()

	executorCalled := false
	handler := applyMiddleware(
		testLogger(),
		resetPasswordHandler(
			testLogger(),
			&stubResetPasswordExecutor{
				execute: func(
					context.Context,
					appresetpassword.Input,
				) (appresetpassword.Output, error) {
					executorCalled = true
					return appresetpassword.Output{}, nil
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/reset-password",
		strings.NewReader(
			`{"token":"`+
				handlerPasswordResetTokenID+
				`","new_password":"Secure2!","otp":"123456"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
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
		t.Fatal("executor must not run for invalid JSON contract")
	}
}

func TestResetPasswordHandlerMapsExpiredToken(t *testing.T) {
	t.Parallel()

	handler := applyMiddleware(
		testLogger(),
		resetPasswordHandler(
			testLogger(),
			&stubResetPasswordExecutor{
				execute: func(
					context.Context,
					appresetpassword.Input,
				) (appresetpassword.Output, error) {
					return appresetpassword.Output{},
						domain.NewError(domain.ErrTokenExpired)
				},
			},
		),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/reset-password",
		strings.NewReader(
			`{"token":"`+
				handlerPasswordResetTokenID+
				`","new_password":"Secure2!"}`,
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
		t.Fatalf("decode error response: %v", err)
	}
	if payload.Error.Code != string(domain.ErrTokenExpired) {
		t.Fatalf("unexpected error code %q", payload.Error.Code)
	}
}

type stubResetPasswordExecutor struct {
	execute func(
		context.Context,
		appresetpassword.Input,
	) (appresetpassword.Output, error)
}

func (s *stubResetPasswordExecutor) Execute(
	ctx context.Context,
	input appresetpassword.Input,
) (appresetpassword.Output, error) {
	return s.execute(ctx, input)
}
